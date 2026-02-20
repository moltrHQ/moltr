"""Moltr Relay Injection Scanner — deterministic, multi-layer, no LLM.

Normalization pipeline (applied before ANY pattern check):
  1. Invisible character stripping  — ZWS, ZWJ, BOM, Soft Hyphen, etc.
  2. Unicode NFKC normalization     — fullwidth, ligatures, composed forms
  3. Homoglyph mapping              — Cyrillic/Greek/Math lookalikes → ASCII
  4. Dotted obfuscation collapse    — "i.g.n.o.r.e" → "ignore"

Scan pipeline (after normalization):
  Stage A: Structural pre-check     — base64 blobs, hex runs, ZWS density
  Stage B: Keyword pattern scan     — 24+ regex (baseline hardcoded + YAML)
  Stage C: Deobfuscation re-scan   — base64/hex/ROT13/URL decoded, re-checked

Design constraints:
  - NO LLM. A regex cannot be prompt-injected.
  - Hardcoded baseline cannot be disabled via YAML/config.
  - YAML only adds patterns, never removes baseline.
  - Pure function: text in → InjectionScanResult out. Zero side effects.
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


# ── Result type ───────────────────────────────────────────────────────────────

@dataclass
class InjectionScanResult:
    """Result of a relay injection scan."""
    flagged: bool = False
    pattern_name: str = ""
    matched_text: str = ""
    severity: str = ""       # "high" | "medium" | "structural"
    decoded_via: str = ""    # "" | "homoglyph" | "dotted" | "base64" | "hex" | "rot13" | "url"


# ── Invisible character removal ───────────────────────────────────────────────
#
# These are the characters an attacker inserts between letters to break regex
# matching while the text still looks (almost) identical to a human reader.
# Example: "i​g​n​o​r​e" (with U+200B between every letter) = invisible to eye.

_INVISIBLE_PATTERN = re.compile(
    "["
    "\u00ad"        # Soft Hyphen
    "\u034f"        # Combining Grapheme Joiner
    "\u115f\u1160"  # Hangul Fillers
    "\u17b4\u17b5"  # Khmer Vowel Fillers
    "\u180b-\u180f" # Mongolian Free Variation Selectors
    "\u200b-\u200f" # ZWS, ZWNJ, ZWJ, LRM, RLM
    "\u202a-\u202f" # Directional formatting marks
    "\u2060-\u2064" # Word Joiner, Invisible operators
    "\u206a-\u206f" # Inhibit/Nominal/National Digit overrides
    "\u3164"        # Hangul Filler
    "\ufeff"        # BOM / Zero-Width No-Break Space
    "\uffa0"        # Halfwidth Hangul Filler
    "\ufe00-\ufe0f" # Variation Selectors
    "]"
)


# ── Homoglyph mapping ─────────────────────────────────────────────────────────
#
# Visual lookalikes that bypass regex without Unicode normalization.
# An attacker replaces Latin 'a' with Cyrillic 'а' (U+0430) — identical visually.
# After this mapping all characters are canonical ASCII equivalents.

_HOMOGLYPHS: dict[str, str] = {
    # ── Cyrillic → Latin ──────────────────────────────────────────────────────
    "\u0430": "a",   # а
    "\u0435": "e",   # е
    "\u043e": "o",   # о
    "\u0440": "r",   # р
    "\u0441": "c",   # с
    "\u0443": "y",   # у
    "\u0445": "x",   # х
    "\u0456": "i",   # і  (Ukrainian)
    "\u0406": "I",   # І  (Ukrainian capital)
    "\u04cf": "l",   # ӏ
    "\u0410": "A",   # А
    "\u0412": "B",   # В
    "\u0415": "E",   # Е
    "\u041a": "K",   # К
    "\u041c": "M",   # М
    "\u041d": "H",   # Н
    "\u041e": "O",   # О
    "\u0420": "P",   # Р
    "\u0421": "C",   # С
    "\u0422": "T",   # Т
    "\u0425": "X",   # Х
    # ── Greek → Latin ─────────────────────────────────────────────────────────
    "\u03b1": "a",   # α
    "\u03b2": "b",   # β (also used as 6 in leet)
    "\u03b5": "e",   # ε
    "\u03bf": "o",   # ο
    "\u03c1": "p",   # ρ
    "\u03c5": "u",   # υ
    "\u03bd": "v",   # ν
    "\u03b9": "i",   # ι
    "\u0391": "A",   # Α
    "\u0392": "B",   # Β
    "\u0395": "E",   # Ε
    "\u0396": "Z",   # Ζ
    "\u0397": "H",   # Η
    "\u0399": "I",   # Ι
    "\u039a": "K",   # Κ
    "\u039c": "M",   # Μ
    "\u039d": "N",   # Ν
    "\u039f": "O",   # Ο
    "\u03a1": "P",   # Ρ
    "\u03a4": "T",   # Τ
    "\u03a5": "Y",   # Υ
    "\u03a7": "X",   # Χ
    # ── Leet speak (digits as letters) ───────────────────────────────────────
    # Only map when character is used as a letter substitution.
    # Careful: 0/1/3 etc. are also legitimate numbers — we normalize them
    # here but they will still match in word context correctly.
    "0": "o",   # 0 → o  ("ign0re")
    "1": "i",   # 1 → i  ("1gnore")
    "3": "e",   # 3 → e  ("instruct1ons")
    "4": "a",   # 4 → a  ("4ct")
    "5": "s",   # 5 → s  ("in5tructions")
    "7": "t",   # 7 → t  ("ins7ructions")
    "@": "a",   # @ → a  ("@ct as")
    "$": "s",   # $ → s  ("in$tructions")
    # ── Fullwidth Latin (U+FF01–FF5E, offset +0xFEE0) ────────────────────────
    **{chr(0xFF01 + i): chr(0x21 + i) for i in range(94)},
    # ── Mathematical bold/italic letters (Unicode injection via math blocks) ──
    **{chr(0x1D41A + i): chr(ord("a") + i) for i in range(26)},  # bold lower
    **{chr(0x1D400 + i): chr(ord("A") + i) for i in range(26)},  # bold upper
    **{chr(0x1D434 + i): chr(ord("A") + i) for i in range(26)},  # italic upper
    **{chr(0x1D44E + i): chr(ord("a") + i) for i in range(26)},  # italic lower
}

_HOMOGLYPH_TABLE = str.maketrans(_HOMOGLYPHS)


# ── Dotted obfuscation ────────────────────────────────────────────────────────
#
# "i.g.n.o.r.e"  →  "ignore"
# "P-R-O-M-P-T"  →  "PROMPT"
# "b_y_p_a_s_s"  →  "bypass"
#
# Rule: 3+ single letters separated by the SAME character (. - _)
# A minimum of 3 letters is required to avoid collapsing e.g. "e.g." or "U.S."

_DOTTED_RE = re.compile(
    r"(?<![a-zA-Z])"       # not preceded by a letter (word boundary)
    r"([a-zA-Z])"          # first letter (group 1)
    r"([.\-_])"            # separator (group 2)
    r"(?:[a-zA-Z]\2)+"     # one or more: letter + SAME separator
    r"[a-zA-Z]"            # final letter
    r"(?![a-zA-Z])",       # not followed by a letter
    re.IGNORECASE,
)


def _collapse_dotted(m: re.Match) -> str:
    """Remove separator from a dotted-obfuscation match."""
    return m.group(0).replace(m.group(2), "")


# ── Baseline patterns ─────────────────────────────────────────────────────────
#
# These are compiled into the scanner at startup and CANNOT be disabled
# via YAML config. YAML config can only extend this list.
# All patterns apply AFTER full normalization (invisible chars stripped,
# homoglyphs replaced, dotted sequences collapsed).

_BASELINE: list[tuple[str, str, str]] = [
    # (name, regex, severity)

    ("ignore_instructions",
     r"ignore\s*(?:all\s*)?(?:previous|prior|your|the|my)?\s*"
     r"(?:instructions?|rules?|directives?|guidelines?|system\s*prompt)",
     "high"),

    ("override_instructions",
     r"(?:override|overwrite)\s*(?:all\s*)?(?:previous|prior|your|the)?\s*"
     r"(?:instructions?|rules?|system\s*prompt|training)",
     "high"),

    ("forget_instructions",
     r"forget\s*(?:all\s*)?(?:previous|prior|your|the|everything\s*(?:you\s*)?(?:were\s*)?)?"
     r"(?:instructions?|rules?|training|told)",
     "high"),

    ("disregard_instructions",
     r"disregard\s*(?:all\s*)?(?:previous|prior|your|the)?\s*"
     r"(?:instructions?|rules?|context|guidelines?)",
     "high"),

    ("you_are_now",
     r"you\s*are\s*now\s*(?:a|an|the|in)?\s*\w+",
     "medium"),

    ("act_as",
     r"(?:act|behave|respond|operate)\s*as\s*(?:if\s*you\s*(?:are|were)\s*)?(?:a|an|the)?\s*\w+",
     "medium"),

    ("pretend",
     r"pretend\s*(?:you\s*are|you\s*were|to\s*be)\s+",
     "medium"),

    ("jailbreak",
     r"\bjailbreak\b|dan\s*mode|do\s*anything\s*now|developer\s*mode\s*enabled",
     "high"),

    ("bypass_safety",
     r"bypass\s*(?:all\s*)?(?:safety|security|content|restrictions?|filters?|guardrails?|policies|moderation)",
     "high"),

    ("reveal_system_prompt",
     r"(?:reveal|print|show|output|display|repeat|dump|leak)\s+"
     r"(?:your|the)\s+(?:system|hidden|secret|real|original|initial|actual|full)\s+"
     r"(?:prompt|instructions?|context|rules?|configuration|config)",
     "high"),

    ("new_instructions_injection",
     r"(?:new\s*instructions?|new\s*system\s*prompt|new\s*directives?|updated\s*instructions?)\s*[:\-]",
     "high"),

    ("from_now_on",
     r"from\s*(?:now|this\s*(?:point|moment))\s*(?:on|forward)\s*,?\s*"
     r"(?:you|always|never|do|stop|start)",
     "medium"),

    ("system_tag_injection",
     r"<\s*(?:system|instruction|prompt|context|override)\s*>"
     r"|\[inst\]|\[\/inst\]|\|\s*system\s*\|",
     "high"),

    ("roleplay_escape",
     r"(?:in\s*this\s*)?(?:role[\s\-]*play|scenario|story|fiction|hypothetical)\s*[,:]\s*"
     r"(?:you\s*(?:are|play|can|will|have\s*no)|there\s*are\s*no\s*(?:rules|restrictions))",
     "medium"),

    ("sudo_override",
     r"(?:sudo|root|admin|superuser|god\s*mode)\s*(?:mode|access|override|enabled|:)",
     "medium"),
]


# ── Structural pre-check patterns ─────────────────────────────────────────────
#
# Stage A: detect suspicious STRUCTURE before checking keywords.
# These catch obfuscated content even when keywords aren't visible.

_STRUCTURAL: list[tuple[str, str, str]] = [
    # Dense base64 blob — may hide injection payload
    ("structural_b64_blob",
     r"(?:[A-Za-z0-9+/]{4}){12,}={0,2}",   # 48+ chars of base64
     "medium"),

    # Long hex run — may hide encoded instructions
    ("structural_hex_run",
     r"(?:[0-9a-fA-F]{2}){16,}",            # 32+ hex chars
     "medium"),

    # Excessive inter-character spacing / punctuation (residual after collapse)
    # If dotted collapse failed, this catches remaining patterns
    ("structural_spaced_letters",
     r"(?:[a-zA-Z]\s){6,}[a-zA-Z]",         # "i g n o r e ..." spaced
     "medium"),
]


class InjectionScanner:
    """
    Multi-layer prompt injection scanner for relay messages.

    Full pipeline per message:
      normalize() → structural check → keyword scan → deobfuscation re-scan

    No LLM. No network. No state. Deterministic pure function.
    """

    def __init__(self, extra_patterns_file: Optional[Path] = None) -> None:
        self._keyword_patterns: list[dict] = []
        self._structural_patterns: list[dict] = []

        # Compile baseline keyword patterns
        for name, regex, severity in _BASELINE:
            try:
                self._keyword_patterns.append({
                    "name": name,
                    "regex": re.compile(regex, re.IGNORECASE | re.UNICODE),
                    "severity": severity,
                })
            except re.error as e:
                logger.error("[InjectionScanner] Baseline compile error (%s): %s", name, e)

        # Compile structural patterns
        for name, regex, severity in _STRUCTURAL:
            try:
                self._structural_patterns.append({
                    "name": name,
                    "regex": re.compile(regex, re.IGNORECASE | re.UNICODE),
                    "severity": severity,
                })
            except re.error as e:
                logger.error("[InjectionScanner] Structural compile error (%s): %s", name, e)

        # Load additional YAML keyword patterns (extends, never replaces baseline)
        if extra_patterns_file and extra_patterns_file.exists():
            self._load_extra(extra_patterns_file)

        logger.info(
            "[InjectionScanner] Ready: %d keyword + %d structural patterns (%d baseline)",
            len(self._keyword_patterns), len(self._structural_patterns), len(_BASELINE),
        )

    def _load_extra(self, path: Path) -> None:
        if _yaml is None:
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
                self._keyword_patterns.append({
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
        Full multi-layer scan. Returns on first match across all stages.

        Stage A: structural (base64/hex blobs, spaced letters)
        Stage B: keyword patterns on normalized text
        Stage C: deobfuscated variants (base64/hex/ROT13/URL decoded)
        """
        if not text or not text.strip():
            return InjectionScanResult()

        # ── Normalize first — always, before any check ────────────────────────
        normalized, normalization_applied = self._normalize(text)

        # ── Stage A: Structural pre-check ─────────────────────────────────────
        # Run on RAW text (before normalization strips obfuscation signals)
        struct_result = self._check_structural(text)
        if struct_result.flagged:
            return struct_result

        # ── Stage B: Keyword scan on normalized text ──────────────────────────
        kw_result = self._match_keywords(normalized)
        if kw_result.flagged:
            if normalization_applied:
                kw_result.decoded_via = "normalized"
            return kw_result

        # ── Stage C: Deobfuscation scan ───────────────────────────────────────
        for method, decoded in self._deobfuscate(text):
            # Normalize decoded content too
            decoded_norm, _ = self._normalize(decoded)
            result = self._match_keywords(decoded_norm)
            if result.flagged:
                result.decoded_via = method
                logger.warning(
                    "[InjectionScanner] FLAGGED (obfuscated) method=%s pattern=%s match='%s'",
                    method, result.pattern_name, result.matched_text,
                )
                return result

        return InjectionScanResult()

    # ── Normalization ─────────────────────────────────────────────────────────

    def _normalize(self, text: str) -> tuple[str, bool]:
        """
        Full normalization pipeline. Returns (normalized_text, was_modified).

        Steps (in order):
          1. Strip invisible characters (ZWS, ZWJ, BOM, soft hyphen, etc.)
          2. Unicode NFKC (fullwidth → ASCII, ligatures, composed forms)
          3. Homoglyph table (Cyrillic/Greek/math/leet → ASCII canonical)
          4. Dotted obfuscation collapse (i.g.n.o.r.e → ignore)
        """
        original = text

        # Step 1: Invisible characters
        text = _INVISIBLE_PATTERN.sub("", text)

        # Step 2: Unicode NFKC
        try:
            text = unicodedata.normalize("NFKC", text)
        except Exception:
            pass

        # Step 3: Homoglyphs (including leet speak digits)
        text = text.translate(_HOMOGLYPH_TABLE)

        # Step 4: Dotted obfuscation (P.r.o.m.p.t → Prompt)
        text = _DOTTED_RE.sub(_collapse_dotted, text)

        return text, (text != original)

    # ── Pattern matching ──────────────────────────────────────────────────────

    def _check_structural(self, text: str) -> InjectionScanResult:
        """Stage A: structural patterns on raw text. High before medium."""
        for severity in ("high", "medium"):
            for pattern in self._structural_patterns:
                if pattern["severity"] != severity:
                    continue
                match = pattern["regex"].search(text)
                if match:
                    matched = match.group(0)[:60]
                    logger.warning(
                        "[InjectionScanner] STRUCTURAL pattern='%s' severity=%s",
                        pattern["name"], severity,
                    )
                    return InjectionScanResult(
                        flagged=True,
                        pattern_name=pattern["name"],
                        matched_text=matched,
                        severity=severity,
                        decoded_via="structural",
                    )
        return InjectionScanResult()

    def _match_keywords(self, text: str) -> InjectionScanResult:
        """Stage B: keyword patterns on (normalized) text. High before medium."""
        for severity in ("high", "medium"):
            for pattern in self._keyword_patterns:
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
        Stage C: generate decoded variants for re-scanning.
        Returns [(method_name, decoded_text), ...].
        """
        results: list[tuple[str, str]] = []

        # Base64
        b64_re = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
        for m in b64_re.finditer(text):
            try:
                decoded = base64.b64decode(m.group() + "==").decode("utf-8", errors="ignore")
                if len(decoded) >= 8 and decoded != m.group():
                    results.append(("base64", decoded))
            except Exception:
                pass

        # Hex
        hex_re = re.compile(r"(?:[0-9a-fA-F]{2}){8,}")
        for m in hex_re.finditer(text):
            try:
                decoded = bytes.fromhex(m.group()).decode("utf-8", errors="ignore")
                if len(decoded) >= 8:
                    results.append(("hex", decoded))
            except Exception:
                pass

        # ROT13
        try:
            rot = codecs.decode(text, "rot_13")
            if rot != text:
                results.append(("rot13", rot))
        except Exception:
            pass

        # URL encoding
        try:
            url_dec = urllib.parse.unquote(text)
            if url_dec != text:
                results.append(("url", url_dec))
        except Exception:
            pass

        return results

    @property
    def pattern_count(self) -> int:
        return len(self._keyword_patterns) + len(self._structural_patterns)
