"""Moltr Relay Injection Scanner — deterministic, multi-layer, no LLM.

Scan pipeline per message (in order):
  1. Unicode normalization  — homoglyphs (Cyrillic/Greek 'а') → ASCII equivalent
  2. Raw pattern scan       — 24+ regex patterns (baseline hardcoded + YAML extras)
  3. Deobfuscation scan     — base64 / hex / ROT13 / URL-encoding decoded & re-scanned

Design principles:
  - NO LLM involved. A regex cannot be prompt-injected.
  - Hardcoded baseline patterns in Python (cannot be disabled via config).
  - YAML config can only ADD patterns, never remove baseline ones.
  - Pure function: text in → InjectionScanResult out. No state, no side effects.

Why no LLM at this layer:
  An LLM-based filter that receives a prompt injection *becomes* the attack.
  Deterministic pattern matching is the only safe approach here.
  (See docs for the two-layer architecture that adds an LLM classifier safely.)
"""
from __future__ import annotations

import base64
import codecs
import logging
import re
import unicodedata
import urllib.parse
from dataclasses import dataclass
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
    severity: str = ""          # "high" | "medium"
    decoded_via: str = ""       # "" = raw | "homoglyph" | "base64" | "hex" | "rot13" | "url"


# ---------------------------------------------------------------------------
# Homoglyph mapping — common visual lookalikes → ASCII canonical form
# Covers most Cyrillic, Greek, and fullwidth variants used in attacks.
# ---------------------------------------------------------------------------

_HOMOGLYPHS: dict[str, str] = {
    # Cyrillic → Latin
    "\u0430": "a",  # а
    "\u0435": "e",  # е
    "\u043e": "o",  # о
    "\u0440": "r",  # р
    "\u0441": "c",  # с
    "\u0443": "y",  # у
    "\u0445": "x",  # х
    "\u0456": "i",  # і (Ukrainian)
    "\u04cf": "l",  # ӏ
    # Greek → Latin
    "\u03b1": "a",  # α
    "\u03b5": "e",  # ε
    "\u03bf": "o",  # ο
    "\u03c1": "p",  # ρ
    "\u03c5": "u",  # υ
    "\u03bd": "v",  # ν
    # Fullwidth Latin (U+FF01–FF5E offset +0xFEE0)
    **{chr(0xFF01 + i): chr(0x21 + i) for i in range(94)},
    # Mathematical bold/italic letters (common in Unicode injection)
    "\U0001d41a": "a", "\U0001d41b": "b", "\U0001d41c": "c",
    "\U0001d41d": "d", "\U0001d41e": "e", "\U0001d41f": "f",
    "\U0001d420": "g", "\U0001d421": "h", "\U0001d422": "i",
    "\U0001d423": "j", "\U0001d424": "k", "\U0001d425": "l",
    "\U0001d426": "m", "\U0001d427": "n", "\U0001d428": "o",
    "\U0001d429": "p", "\U0001d42a": "q", "\U0001d42b": "r",
    "\U0001d42c": "s", "\U0001d42d": "t", "\U0001d42e": "u",
    "\U0001d42f": "v", "\U0001d430": "w", "\U0001d431": "x",
    "\U0001d432": "y", "\U0001d433": "z",
}

_HOMOGLYPH_TABLE = str.maketrans(_HOMOGLYPHS)


# ---------------------------------------------------------------------------
# Hardcoded baseline patterns — CANNOT be disabled via YAML config.
# YAML config can only extend this list with additional patterns.
# ---------------------------------------------------------------------------

_BASELINE: list[tuple[str, str, str]] = [
    # (name, regex, severity)

    ("ignore_instructions",
     r"ignore\s+(?:all\s+)?(?:previous|prior|your|the|my)?\s*(?:instructions?|rules?|directives?|guidelines?|system\s+prompt)",
     "high"),

    ("override_instructions",
     r"(?:override|overwrite)\s+(?:all\s+)?(?:previous|prior|your|the)?\s*(?:instructions?|rules?|system\s+prompt|training)",
     "high"),

    ("forget_instructions",
     r"forget\s+(?:all\s+)?(?:previous|prior|your|the|everything\s+(?:you\s+)?(?:were\s+)?)?(?:instructions?|rules?|training|told)",
     "high"),

    ("disregard_instructions",
     r"disregard\s+(?:all\s+)?(?:previous|prior|your|the)?\s*(?:instructions?|rules?|context|guidelines?)",
     "high"),

    ("you_are_now",
     r"you\s+are\s+now\s+(?:a|an|the|in)?\s*\w+",
     "medium"),

    ("act_as",
     r"(?:act|behave|respond|operate)\s+as\s+(?:if\s+you\s+(?:are|were)\s+)?(?:a|an|the)?\s*\w+",
     "medium"),

    ("pretend",
     r"pretend\s+(?:you\s+are|you\s+were|to\s+be)\s+",
     "medium"),

    ("jailbreak",
     r"\bjailbreak\b|DAN\s+mode|do\s+anything\s+now|developer\s+mode\s+enabled",
     "high"),

    ("bypass_safety",
     r"bypass\s+(?:all\s+)?(?:safety|security|content|restrictions?|filters?|guardrails?|policies|moderation)",
     "high"),

    ("reveal_system_prompt",
     r"(?:reveal|print|show|output|display|repeat|dump|leak)\s+(?:your|the)\s+(?:system|hidden|secret|real|original|initial|actual|full)\s+(?:prompt|instructions?|context|rules?|configuration|config)",
     "high"),

    ("new_instructions_injection",
     r"(?:new\s+instructions?|new\s+system\s+prompt|new\s+directives?|updated\s+instructions?)\s*[:\-]",
     "high"),

    ("from_now_on",
     r"from\s+(?:now|this\s+(?:point|moment))\s+(?:on|forward)\s*,?\s*(?:you|always|never|do|stop|start)",
     "medium"),

    ("system_tag_injection",
     r"<\s*(?:system|instruction|prompt|context|override)\s*>|"
     r"\[INST\]|\[\/INST\]|\|\s*(?:system|SYSTEM)\s*\|",
     "high"),

    ("roleplay_escape",
     r"(?:in\s+this\s+)?(?:role[\s-]?play|scenario|story|fiction|hypothetical)\s*[,:]\s*"
     r"(?:you\s+(?:are|play|can|will|have\s+no)|there\s+are\s+no\s+(?:rules|restrictions))",
     "medium"),

    ("sudo_override",
     r"(?:sudo|root|admin|superuser|god\s+mode)\s*(?:mode|access|override|enabled|:)",
     "medium"),
]


class InjectionScanner:
    """
    Multi-layer prompt injection detector for relay messages.

    Pipeline: homoglyph normalization → raw regex scan → deobfuscation scan.
    No LLM, no network, no state. Pure deterministic function.
    """

    def __init__(self, extra_patterns_file: Optional[Path] = None) -> None:
        self._patterns: list[dict] = []

        # Compile baseline (always active)
        for name, regex, severity in _BASELINE:
            try:
                self._patterns.append({
                    "name": name,
                    "regex": re.compile(regex, re.IGNORECASE | re.UNICODE),
                    "severity": severity,
                })
            except re.error as e:
                logger.error("[InjectionScanner] Baseline compile error (%s): %s", name, e)

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

    # ── Public API ────────────────────────────────────────────────────────────

    def scan(self, text: str) -> InjectionScanResult:
        """
        Full multi-layer scan:
          1. Homoglyph normalization → raw pattern scan
          2. Deobfuscation (base64/hex/ROT13/URL) → pattern scan on each decoded variant

        Returns InjectionScanResult(flagged=True) on first match across all layers.
        """
        if not text or not text.strip():
            return InjectionScanResult()

        # Layer 1: normalize homoglyphs, then scan raw text
        normalized = self._normalize(text)
        result = self._match_patterns(normalized)
        if result.flagged:
            # Mark homoglyph if normalized differs from original
            if normalized != text:
                result.decoded_via = "homoglyph+raw"
            return result

        # Layer 2: deobfuscated variants
        for method, decoded in self._deobfuscate(text):
            result = self._match_patterns(decoded)
            if result.flagged:
                result.decoded_via = method
                logger.warning(
                    "[InjectionScanner] FLAGGED (obfuscated) method=%s pattern=%s match='%s'",
                    method, result.pattern_name, result.matched_text,
                )
                return result

        return InjectionScanResult()

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _normalize(self, text: str) -> str:
        """
        Normalize text for pattern matching:
          1. Unicode NFKC normalization (e.g. fullwidth → ASCII, ligatures → letters)
          2. Custom homoglyph table (Cyrillic/Greek visual lookalikes → ASCII)
        """
        try:
            text = unicodedata.normalize("NFKC", text)
        except Exception:
            pass
        return text.translate(_HOMOGLYPH_TABLE)

    def _match_patterns(self, text: str) -> InjectionScanResult:
        """Run all compiled patterns against text. High severity checked first."""
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

    def _deobfuscate(self, text: str) -> list[tuple[str, str]]:
        """
        Generate decoded variants of the text for scanning.
        Returns list of (method_name, decoded_text).
        Only returns variants that differ meaningfully from the input.
        """
        results: list[tuple[str, str]] = []

        # ── Base64 ────────────────────────────────────────────────────────────
        b64_re = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
        for m in b64_re.finditer(text):
            try:
                decoded = base64.b64decode(m.group() + "==").decode("utf-8", errors="ignore")
                if len(decoded) >= 8 and decoded != m.group():
                    results.append(("base64", decoded))
            except Exception:
                pass

        # ── Hex ───────────────────────────────────────────────────────────────
        hex_re = re.compile(r"(?:[0-9a-fA-F]{2}){8,}")
        for m in hex_re.finditer(text):
            try:
                decoded = bytes.fromhex(m.group()).decode("utf-8", errors="ignore")
                if len(decoded) >= 8 and decoded != m.group():
                    results.append(("hex", decoded))
            except Exception:
                pass

        # ── ROT13 ─────────────────────────────────────────────────────────────
        try:
            rot = codecs.decode(text, "rot_13")
            if rot != text:
                results.append(("rot13", rot))
        except Exception:
            pass

        # ── URL encoding ──────────────────────────────────────────────────────
        try:
            url_dec = urllib.parse.unquote(text)
            if url_dec != text:
                results.append(("url", url_dec))
        except Exception:
            pass

        return results

    @property
    def pattern_count(self) -> int:
        return len(self._patterns)
