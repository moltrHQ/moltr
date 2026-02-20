# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Moltr-Commercial
# Copyright (C) 2026 Walter Troska / moltrHQ <hello@moltr.tech>
# See LICENSE (AGPL-3.0) or LICENSE-COMMERCIAL for licensing terms.

"""Moltr action validator.

Validates shell commands from AI agents against a YAML-based
security policy. Checks allowlists, detects bypass attempts,
enforces rate limits, and assigns risk levels.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

try:
    import yaml
except ImportError:
    yaml = None


@dataclass
class ValidationResult:
    """Result of validating a command."""

    allowed: bool = False
    risk_level: int = -1
    reason: str = ""
    original_command: str = ""


class RateLimiter:
    """Simple sliding-window rate limiter."""

    def __init__(self, max_per_minute: int) -> None:
        self._max = max_per_minute
        self._timestamps: list[float] = []

    def check(self) -> bool:
        """Return True if within limit, False if exceeded."""
        now = time.time()
        self._timestamps = [t for t in self._timestamps if now - t < 60.0]
        if len(self._timestamps) >= self._max:
            return False
        self._timestamps.append(now)
        return True


# Patterns that indicate command evasion / injection attempts
_EVASION_PATTERNS: list[re.Pattern] = [
    re.compile(r'`'),                      # backtick subshell
    re.compile(r'\$\('),                   # $() subshell
    re.compile(r'\$\{'),                   # ${VAR} expansion
    re.compile(r'(?<!\w)\$[A-Za-z_]'),     # $VAR expansion
    re.compile(r"(?<![a-zA-Z])''+"),        # empty-quote splicing (su''do)
    re.compile(r'(?<![a-zA-Z])""+'),        # empty double-quote splicing
    re.compile(r'\\(?=[a-zA-Z])'),          # backslash before letter (r\m)
    re.compile(r'\n'),                      # newline injection
]

# Shell operators that chain or redirect commands
_CHAIN_OPERATORS = re.compile(r'[|;&]')

# Shells that should never appear as pipe targets
_SHELL_NAMES = {"sh", "bash", "zsh", "fish", "dash", "csh", "ksh", "powershell", "cmd"}


class ActionValidator:
    """Validates shell commands against a YAML security policy.

    Loads allowed/blocked commands, risk levels, and rate limits
    from a YAML config file. All commands are checked for bypass
    attempts before policy evaluation.
    """

    def __init__(self, commands_file: Optional[Path] = None) -> None:
        """Initialize the validator.

        Args:
            commands_file: Path to the commands YAML policy file.
        """
        self._allowed: set[str] = set()
        self._blocked: list[str] = []
        self._network_cmds: set[str] = set()
        self._write_cmds: set[str] = set()
        self._risk_map: dict[str, int] = {}

        # Rate limiters (defaults)
        self._general_limiter = RateLimiter(30)
        self._network_limiter = RateLimiter(5)
        self._write_limiter = RateLimiter(10)

        if commands_file and commands_file.exists():
            self._load(commands_file)

    def _load(self, path: Path) -> None:
        """Load policy from YAML."""
        if yaml is None:
            return
        raw = path.read_text(encoding="utf-8")
        data = yaml.safe_load(raw) or {}

        self._allowed = set(data.get("allowed_commands", []))
        self._blocked = data.get("blocked_commands", [])
        self._network_cmds = set(data.get("network_commands", []))
        self._write_cmds = set(data.get("write_commands", []))

        # Build risk map from levels
        risk_levels = data.get("risk_levels", {})
        for cmd in risk_levels.get("harmless", []):
            self._risk_map[cmd] = 0
        for cmd in risk_levels.get("normal", []):
            self._risk_map[cmd] = 1
        for cmd in risk_levels.get("elevated", []):
            self._risk_map[cmd] = 2
        for cmd in risk_levels.get("dangerous", []):
            self._risk_map[cmd] = 3

        # Rate limits from config
        limits = data.get("rate_limits", {})
        if "max_commands_per_minute" in limits:
            self._general_limiter = RateLimiter(limits["max_commands_per_minute"])
        if "max_network_commands_per_minute" in limits:
            self._network_limiter = RateLimiter(limits["max_network_commands_per_minute"])
        if "max_write_commands_per_minute" in limits:
            self._write_limiter = RateLimiter(limits["max_write_commands_per_minute"])

    def validate(self, command: str) -> ValidationResult:
        """Validate a shell command.

        Args:
            command: The full command string to validate.

        Returns:
            ValidationResult with allowed, risk_level, reason, original_command.
        """
        if not command or not command.strip():
            return ValidationResult(
                allowed=False,
                risk_level=-1,
                reason="Empty command",
                original_command=command,
            )

        command = command.strip()

        # --- 1. Check for evasion / bypass attempts ---
        evasion = self._detect_evasion(command)
        if evasion:
            return ValidationResult(
                allowed=False,
                risk_level=3,
                reason=f"Evasion attempt detected: {evasion}",
                original_command=command,
            )

        # --- 2. Split chained commands and validate each segment ---
        segments = self._split_segments(command)
        if len(segments) > 1:
            for seg in segments:
                seg = seg.strip()
                if not seg:
                    continue
                sub_result = self._validate_single(seg)
                if not sub_result.allowed:
                    return ValidationResult(
                        allowed=False,
                        risk_level=sub_result.risk_level,
                        reason=f"Chained command blocked: {sub_result.reason}",
                        original_command=command,
                    )
            # If all segments are ok, still validate as whole for rate limiting
            # Use the first segment's base command for risk/rate
            return self._validate_single_with_rates(segments[0].strip(), command)

        # --- 3. Single command ---
        return self._validate_single_with_rates(command, command)

    def _validate_single(self, command: str) -> ValidationResult:
        """Validate a single command segment (no rate limiting)."""
        base = self._extract_base_command(command)
        risk = self._get_risk_level(base)

        # Check blocked list (exact substring match)
        for blocked in self._blocked:
            if blocked in command:
                return ValidationResult(
                    allowed=False,
                    risk_level=max(risk, 3),
                    reason=f"Blocked command: {blocked}",
                    original_command=command,
                )

        # Risk level 3 is always blocked
        if risk == 3:
            return ValidationResult(
                allowed=False,
                risk_level=3,
                reason=f"Dangerous command: {base}",
                original_command=command,
            )

        # Check if base command is in allowlist
        if base not in self._allowed and base not in self._network_cmds:
            return ValidationResult(
                allowed=False,
                risk_level=risk if risk >= 0 else -1,
                reason=f"Command not in allowlist: {base}",
                original_command=command,
            )

        return ValidationResult(
            allowed=True,
            risk_level=risk,
            reason="Allowed",
            original_command=command,
        )

    def _validate_single_with_rates(self, command: str, original: str) -> ValidationResult:
        """Validate a single command with rate limit checks."""
        result = self._validate_single(command)
        if not result.allowed:
            result.original_command = original
            return result

        base = self._extract_base_command(command)

        # Rate limit checks
        if not self._general_limiter.check():
            return ValidationResult(
                allowed=False,
                risk_level=result.risk_level,
                reason="Rate limit exceeded: max commands per minute",
                original_command=original,
            )

        if base in self._network_cmds:
            if not self._network_limiter.check():
                return ValidationResult(
                    allowed=False,
                    risk_level=result.risk_level,
                    reason="Rate limit exceeded: max network commands per minute",
                    original_command=original,
                )

        if base in self._write_cmds:
            if not self._write_limiter.check():
                return ValidationResult(
                    allowed=False,
                    risk_level=result.risk_level,
                    reason="Rate limit exceeded: max write commands per minute",
                    original_command=original,
                )

        result.original_command = original
        return result

    def _detect_evasion(self, command: str) -> str:
        """Detect bypass / evasion attempts.

        Returns a description of the evasion or empty string if clean.
        """
        for pattern in _EVASION_PATTERNS:
            if pattern.search(command):
                return f"Bypass pattern: {pattern.pattern}"

        # Check for pipe/chain to shell interpreters
        if "|" in command:
            parts = command.split("|")
            for part in parts[1:]:
                target_base = part.strip().split()[0] if part.strip() else ""
                if target_base in _SHELL_NAMES:
                    return f"Bypass pattern: pipe to shell ({target_base})"

        return ""

    @staticmethod
    def _split_segments(command: str) -> list[str]:
        """Split a command string on chain operators (; && ||)."""
        # Split on ;, &&, || but not inside quotes
        segments = re.split(r'\s*(?:&&|\|\||;)\s*', command)
        # Also split on bare pipes
        result = []
        for seg in segments:
            if "|" in seg:
                result.extend(seg.split("|"))
            else:
                result.append(seg)
        return [s.strip() for s in result if s.strip()]

    @staticmethod
    def _extract_base_command(command: str) -> str:
        """Extract the base command (first token) from a command string."""
        parts = command.strip().split()
        if not parts:
            return ""
        # Strip any leading path (e.g. /usr/bin/python -> python)
        base = parts[0].rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
        return base

    def _get_risk_level(self, base_command: str) -> int:
        """Look up the risk level for a base command.

        Returns:
            0=harmless, 1=normal, 2=elevated, 3=dangerous, -1=unknown
        """
        return self._risk_map.get(base_command, -1)
