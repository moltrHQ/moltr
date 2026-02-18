"""
Moltr Output Scanner - Defensive security module.

Scans outgoing agent text for accidental secret leaks.
Patterns are loaded from config/scan_patterns.yaml at startup.
This is a PROTECTIVE tool that prevents AI agents from
accidentally exposing sensitive data.
"""

import re
import base64
import codecs
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    import yaml
except ImportError:
    yaml = None


@dataclass
class ScanResult:
    """Result of scanning a text for sensitive data."""
    blocked: bool = False
    threat_type: str = ""
    matched_pattern: str = ""
    original_text: str = ""
    deobfuscation_method: str = ""


@dataclass
class LockdownState:
    """Tracks incidents for auto-lockdown."""
    incidents: list = field(default_factory=list)
    window_seconds: int = 600  # 10 minutes

    def record_incident(self) -> None:
        """Record an incident timestamp."""
        self.incidents.append(time.time())

    def is_locked(self, threshold: int) -> bool:
        """Check if locked for a given threshold (incidents in window >= threshold)."""
        now = time.time()
        self.incidents = [
            t for t in self.incidents
            if now - t <= self.window_seconds
        ]
        return len(self.incidents) >= threshold

    def clear(self) -> None:
        """Clear all incidents."""
        self.incidents.clear()


@dataclass
class LevelConfig:
    """Configuration for a security level."""
    lockdown_after: int = 1
    window_seconds: int = 600
    blocked_types: list = field(default_factory=list)


class OutputScanner:
    """
    Scans outgoing text for accidental secret leaks.
    
    This is a DEFENSIVE security tool. It protects users by
    detecting when an AI agent accidentally includes sensitive
    data in its output.
    
    Patterns are loaded from a YAML config file, allowing
    users to customize detection rules.
    """

    def __init__(
        self,
        patterns_file: Optional[Path] = None,
        secrets_registry=None,
    ):
        self._patterns: list[dict] = []
        self._secrets_registry = secrets_registry
        self._lockdown = LockdownState()
        self._passphrase: str = ""
        self._levels: dict[str, LevelConfig] = {
            "high": LevelConfig(lockdown_after=1, blocked_types=[
                "api_key", "seed_phrase", "private_key", "password", "credit_card",
            ]),
            "medium": LevelConfig(lockdown_after=2, blocked_types=[
                "api_key", "seed_phrase", "private_key", "credit_card",
            ]),
            "low": LevelConfig(lockdown_after=3, blocked_types=[
                "seed_phrase", "private_key", "credit_card",
            ]),
        }

        if patterns_file and patterns_file.exists():
            self._load_patterns(patterns_file)

    def _load_patterns(self, path: Path) -> None:
        """Load scan patterns, levels, and passphrase from YAML config."""
        if yaml is None:
            return
        raw = path.read_text(encoding="utf-8")
        data = yaml.safe_load(raw)
        if not data:
            return

        # Load passphrase
        self._passphrase = str(data.get("passphrase", ""))

        # Load level configurations
        levels_cfg = data.get("levels", {})
        for level_name, cfg in levels_cfg.items():
            self._levels[level_name] = LevelConfig(
                lockdown_after=int(cfg.get("lockdown_after", 1)),
                window_seconds=int(cfg.get("window_seconds", 600)),
                blocked_types=list(cfg.get("blocked_types", [])),
            )

        if "patterns" in data:
            for p in data["patterns"]:
                try:
                    compiled = re.compile(p["regex"], re.IGNORECASE)
                    self._patterns.append({
                        "name": p.get("name", "unknown"),
                        "type": p.get("type", "unknown"),
                        "regex": compiled,
                        "description": p.get("description", ""),
                    })
                except re.error:
                    continue

    def _resolve_level(self, level: str, passphrase: str) -> str:
        """Resolve the effective security level. Requires passphrase for non-high."""
        if level == "high":
            return "high"
        if not self._passphrase or passphrase != self._passphrase:
            return "high"  # Wrong or missing passphrase → forced high
        if level in self._levels:
            return level
        return "high"

    @property
    def is_locked(self) -> bool:
        """Check if auto-lockdown is active (for high level, strictest)."""
        high_cfg = self._levels.get("high", LevelConfig())
        return self._lockdown.is_locked(high_cfg.lockdown_after)

    def scan(self, text: str, level: str = "high", passphrase: str = "") -> ScanResult:
        """
        Scan text for sensitive data leaks.

        Checks the original text AND deobfuscated versions
        (base64, hex, rot13, url-encoded).

        Args:
            text: The text to scan.
            level: Security level (high/medium/low).
            passphrase: Required for medium/low levels.

        Returns ScanResult with blocked=True if threat found.
        """
        effective_level = self._resolve_level(level, passphrase)
        level_cfg = self._levels.get(effective_level, LevelConfig())

        # Update lockdown window from level config
        self._lockdown.window_seconds = level_cfg.window_seconds

        # Check lockdown based on this level's threshold
        if self._lockdown.is_locked(level_cfg.lockdown_after):
            return ScanResult(
                blocked=True,
                threat_type="LOCKDOWN",
                matched_pattern=f"System is in lockdown mode (level={effective_level})",
                original_text=text[:100],
            )

        # Check against secrets registry first (always, regardless of level)
        if self._secrets_registry:
            if self._secrets_registry.check_text(text):
                self._lockdown.record_incident()
                return ScanResult(
                    blocked=True,
                    threat_type="registered_secret",
                    matched_pattern="Matched registered secret",
                    original_text=text[:100],
                )

        # Filter patterns by level's blocked types
        blocked_types = set(level_cfg.blocked_types)

        # Check original text
        result = self._check_patterns(text, "plaintext", blocked_types)
        if result.blocked:
            self._lockdown.record_incident()
            return result

        # Check deobfuscated versions
        for method, decoded in self._deobfuscate(text):
            result = self._check_patterns(decoded, method, blocked_types)
            if result.blocked:
                result.deobfuscation_method = method
                self._lockdown.record_incident()
                return result

        return ScanResult(blocked=False)

    def _check_patterns(self, text: str, method: str, blocked_types: set = None) -> ScanResult:
        """Check text against loaded patterns, filtered by blocked types."""
        for pattern in self._patterns:
            # Skip patterns whose type is not in the blocked set for this level
            if blocked_types and pattern["type"] not in blocked_types:
                continue
            match = pattern["regex"].search(text)
            if match:
                return ScanResult(
                    blocked=True,
                    threat_type=pattern["type"],
                    matched_pattern=pattern["name"],
                    original_text=text[:100],
                    deobfuscation_method=method,
                )
        return ScanResult(blocked=False)

    def _deobfuscate(self, text: str) -> list[tuple[str, str]]:
        """
        Attempt to decode obfuscated content.
        
        Returns list of (method_name, decoded_text) tuples.
        """
        results = []

        # Base64 detection - find base64-like strings
        b64_pattern = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
        for match in b64_pattern.finditer(text):
            try:
                decoded = base64.b64decode(match.group()).decode(
                    "utf-8", errors="ignore"
                )
                if decoded and len(decoded) > 5:
                    results.append(("base64", decoded))
            except Exception:
                continue

        # Hex detection - find hex-like strings
        hex_pattern = re.compile(r'(?:[0-9a-fA-F]{2}){10,}')
        for match in hex_pattern.finditer(text):
            try:
                decoded = bytes.fromhex(match.group()).decode(
                    "utf-8", errors="ignore"
                )
                if decoded and len(decoded) > 5:
                    results.append(("hex", decoded))
            except Exception:
                continue

        # ROT13
        try:
            rot13 = codecs.decode(text, "rot_13")
            if rot13 != text:
                results.append(("rot13", rot13))
        except Exception:
            pass

        # URL encoding
        try:
            url_decoded = urllib.parse.unquote(text)
            if url_decoded != text:
                results.append(("url_encoding", url_decoded))
        except Exception:
            pass

        return results

    @staticmethod
    def generate_fake_response(threat_type: str) -> str:
        """
        Generate a believable but fake success response.
        
        When a leak is blocked, the agent receives this fake
        response so it doesn't know the request was intercepted.
        """
        fake_responses = {
            "api_key": '{"status": "ok", "message": "Request processed successfully"}',
            "credit_card": '{"status": "ok", "transaction_id": "TXN-FAKE-00000"}',
            "seed_phrase": '{"status": "ok", "wallet": "verified"}',
            "private_key": '{"status": "ok", "signed": true}',
            "password": '{"status": "ok", "authenticated": true}',
            "registered_secret": '{"status": "ok", "message": "Completed"}',
        }
        return fake_responses.get(
            threat_type,
            '{"status": "ok", "message": "Success"}',
        )

    def reset_lockdown(self) -> None:
        """Reset lockdown state. Requires manual intervention."""
        self._lockdown.clear()
