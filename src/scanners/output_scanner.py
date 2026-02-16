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
    locked: bool = False
    max_incidents: int = 3
    window_seconds: int = 600  # 10 minutes

    def record_incident(self) -> bool:
        """Record an incident. Returns True if lockdown triggered."""
        now = time.time()
        self.incidents.append(now)
        # Remove old incidents outside window
        self.incidents = [
            t for t in self.incidents
            if now - t <= self.window_seconds
        ]
        if len(self.incidents) >= self.max_incidents:
            self.locked = True
        return self.locked


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

        if patterns_file and patterns_file.exists():
            self._load_patterns(patterns_file)

    def _load_patterns(self, path: Path) -> None:
        """Load scan patterns and lockdown settings from YAML config."""
        if yaml is None:
            return
        raw = path.read_text(encoding="utf-8")
        data = yaml.safe_load(raw)
        if not data:
            return

        # Load lockdown settings if present
        lockdown_cfg = data.get("lockdown", {})
        if lockdown_cfg:
            if "max_incidents" in lockdown_cfg:
                self._lockdown.max_incidents = int(lockdown_cfg["max_incidents"])
            if "window_seconds" in lockdown_cfg:
                self._lockdown.window_seconds = int(lockdown_cfg["window_seconds"])

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

    @property
    def is_locked(self) -> bool:
        """Check if auto-lockdown is active."""
        return self._lockdown.locked

    def scan(self, text: str) -> ScanResult:
        """
        Scan text for sensitive data leaks.
        
        Checks the original text AND deobfuscated versions
        (base64, hex, rot13, url-encoded).
        
        Returns ScanResult with blocked=True if threat found.
        """
        if self._lockdown.locked:
            return ScanResult(
                blocked=True,
                threat_type="LOCKDOWN",
                matched_pattern="System is in lockdown mode",
                original_text=text[:100],
            )

        # Check against secrets registry first
        if self._secrets_registry:
            if self._secrets_registry.check_text(text):
                self._lockdown.record_incident()
                return ScanResult(
                    blocked=True,
                    threat_type="registered_secret",
                    matched_pattern="Matched registered secret",
                    original_text=text[:100],
                )

        # Check original text
        result = self._check_patterns(text, "plaintext")
        if result.blocked:
            self._lockdown.record_incident()
            return result

        # Check deobfuscated versions
        for method, decoded in self._deobfuscate(text):
            result = self._check_patterns(decoded, method)
            if result.blocked:
                result.deobfuscation_method = method
                self._lockdown.record_incident()
                return result

        return ScanResult(blocked=False)

    def _check_patterns(self, text: str, method: str) -> ScanResult:
        """Check text against all loaded patterns."""
        for pattern in self._patterns:
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
        self._lockdown.locked = False
        self._lockdown.incidents.clear()
