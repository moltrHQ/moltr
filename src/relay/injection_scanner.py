"""Moltr Relay Injection Scanner — deterministic, regex-based.

Scans relay message content for prompt injection attempts BEFORE
delivery to the target agent.

Design principles:
  - NO LLM involved. A regex cannot be prompt-injected.
  - Hardcoded baseline patterns in Python (cannot be disabled via config).
  - YAML config can only ADD patterns, never remove baseline ones.
  - Pure function: text in → InjectionScanResult out. No state, no side effects.

Why no LLM?
  An LLM-based filter that receives a prompt injection becomes the attack.
  Deterministic pattern matching is the only safe approach at this layer.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    import yaml as _yaml
except ImportError:
    _yaml = None

logger = logging.getLogger("moltr.relay.injection")


@dataclass
class InjectionScanResult:
    """Result of a relay injection scan."""
    flagged: bool = False
    pattern_name: str = ""
    matched_text: str = ""
    severity: str = ""  # "high" | "medium"


# ---------------------------------------------------------------------------
# Hardcoded baseline patterns — these CANNOT be disabled via YAML config.
# YAML config can only extend this list with additional patterns.
# ---------------------------------------------------------------------------

_BASELINE: list[tuple[str, str, str]] = [
    # (name, regex, severity)

    # Classic ignore-instructions family
    ("ignore_instructions",
     r"ignore\s+(?:all\s+)?(?:previous|prior|your|the|my)?\s*(?:instructions?|rules?|directives?|guidelines?|system\s+prompt)",
     "high"),

    # Override / overwrite instructions
    ("override_instructions",
     r"(?:override|overwrite)\s+(?:all\s+)?(?:previous|prior|your|the)?\s*(?:instructions?|rules?|system\s+prompt|training)",
     "high"),

    # Forget instructions
    ("forget_instructions",
     r"forget\s+(?:all\s+)?(?:previous|prior|your|the|everything\s+(?:you\s+)?(?:were\s+)?)?(?:instructions?|rules?|training|told)",
     "high"),

    # Disregard instructions
    ("disregard_instructions",
     r"disregard\s+(?:all\s+)?(?:previous|prior|your|the)?\s*(?:instructions?|rules?|context|guidelines?)",
     "high"),

    # "You are now [X] mode / character"
    ("you_are_now",
     r"you\s+are\s+now\s+(?:a|an|the|in)?\s*\w+",
     "medium"),

    # Persona switching: "act as", "behave as"
    ("act_as",
     r"(?:act|behave|respond|operate)\s+as\s+(?:if\s+you\s+(?:are|were)\s+)?(?:a|an|the)?\s*\w+",
     "medium"),

    # Pretend to be
    ("pretend",
     r"pretend\s+(?:you\s+are|you\s+were|to\s+be)\s+",
     "medium"),

    # Jailbreak keywords
    ("jailbreak",
     r"\bjailbreak\b|DAN\s+mode|do\s+anything\s+now|developer\s+mode\s+enabled",
     "high"),

    # Bypass safety / guardrails
    ("bypass_safety",
     r"bypass\s+(?:all\s+)?(?:safety|security|content|restrictions?|filters?|guardrails?|policies|moderation)",
     "high"),

    # Reveal system prompt
    ("reveal_system_prompt",
     r"(?:reveal|print|show|output|display|repeat|dump|leak)\s+(?:your|the)\s+(?:system|hidden|secret|real|original|initial|actual|full)\s+(?:prompt|instructions?|context|rules?|configuration|config)",
     "high"),

    # "New instructions:" injection
    ("new_instructions_injection",
     r"(?:new\s+instructions?|new\s+system\s+prompt|new\s+directives?|updated\s+instructions?)\s*[:\-]",
     "high"),

    # "From now on you will / always"
    ("from_now_on",
     r"from\s+(?:now|this\s+(?:point|moment))\s+(?:on|forward)\s*,?\s*(?:you|always|never|do|stop|start)",
     "medium"),

    # Token smuggling via hidden/system tags
    ("system_tag_injection",
     r"<\s*(?:system|instruction|prompt|context|override)\s*>|"
     r"\[INST\]|\[\/INST\]|\|\s*(?:system|SYSTEM)\s*\|",
     "high"),

    # Role-play escape attempts
    ("roleplay_escape",
     r"(?:in\s+this\s+)?(?:role[\s-]?play|scenario|story|fiction|hypothetical)\s*[,:]\s*"
     r"(?:you\s+(?:are|play|can|will|have\s+no)|there\s+are\s+no\s+(?:rules|restrictions))",
     "medium"),

    # Sudo / root override patterns
    ("sudo_override",
     r"(?:sudo|root|admin|superuser|god\s+mode)\s*(?:mode|access|override|enabled|:)",
     "medium"),
]


class InjectionScanner:
    """
    Deterministic prompt injection detector for relay messages.

    Operates on raw text only. No network calls, no LLM, no state.
    The hardcoded baseline cannot be disabled by config injection.
    """

    def __init__(self, extra_patterns_file: Optional[Path] = None) -> None:
        # Compile baseline (always active)
        self._patterns: list[dict] = []
        for name, regex, severity in _BASELINE:
            try:
                self._patterns.append({
                    "name": name,
                    "regex": re.compile(regex, re.IGNORECASE | re.UNICODE),
                    "severity": severity,
                })
            except re.error as e:
                logger.error("[InjectionScanner] Baseline pattern compile error (%s): %s", name, e)

        # Load additional YAML patterns (extends, never replaces baseline)
        if extra_patterns_file and extra_patterns_file.exists():
            self._load_extra(extra_patterns_file)

        logger.info(
            "[InjectionScanner] Ready: %d patterns (%d baseline)",
            len(self._patterns), len(_BASELINE),
        )

    def _load_extra(self, path: Path) -> None:
        """Load additional patterns from YAML. Silently skips invalid entries."""
        if _yaml is None:
            logger.warning("[InjectionScanner] PyYAML not available — skipping extra patterns")
            return
        try:
            data = _yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except Exception as e:
            logger.error("[InjectionScanner] Failed to load extra patterns: %s", e)
            return

        added = 0
        for p in data.get("patterns", []):
            name = p.get("name", "")
            regex = p.get("regex", "")
            severity = p.get("severity", "medium")
            if not name or not regex:
                continue
            try:
                self._patterns.append({
                    "name": name,
                    "regex": re.compile(regex, re.IGNORECASE | re.UNICODE),
                    "severity": severity,
                })
                added += 1
            except re.error as e:
                logger.warning("[InjectionScanner] Invalid extra pattern '%s': %s", name, e)

        if added:
            logger.info("[InjectionScanner] Loaded %d extra patterns from %s", added, path)

    def scan(self, text: str) -> InjectionScanResult:
        """
        Scan text for prompt injection patterns.

        Returns InjectionScanResult(flagged=True, ...) on first match.
        Checks HIGH severity patterns first, then MEDIUM.
        """
        if not text or not text.strip():
            return InjectionScanResult()

        # Two passes: high severity first
        for severity in ("high", "medium"):
            for pattern in self._patterns:
                if pattern["severity"] != severity:
                    continue
                match = pattern["regex"].search(text)
                if match:
                    matched = match.group(0)[:80]
                    logger.warning(
                        "[InjectionScanner] FLAGGED pattern='%s' severity=%s match='%s'",
                        pattern["name"], severity, matched,
                    )
                    return InjectionScanResult(
                        flagged=True,
                        pattern_name=pattern["name"],
                        matched_text=matched,
                        severity=severity,
                    )

        return InjectionScanResult()

    @property
    def pattern_count(self) -> int:
        return len(self._patterns)
