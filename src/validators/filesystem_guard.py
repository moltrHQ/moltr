# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Moltr-Commercial
# Copyright (C) 2026 Walter Troska / moltrHQ <hello@moltr.tech>
# See LICENSE (AGPL-3.0) or LICENSE-COMMERCIAL for licensing terms.

"""Moltr filesystem guard.

Monitors honeypot files, enforces path allowlists,
checks file integrity via SHA-256 baselines, and
detects symlink attacks.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    import yaml
except ImportError:
    yaml = None


@dataclass
class AccessResult:
    """Result of a filesystem access check."""

    blocked: bool = False
    is_honeypot: bool = False
    reason: str = ""
    path: str = ""
    operation: str = ""


@dataclass
class IntegrityViolation:
    """A detected file integrity violation."""

    filepath: str = ""
    expected_hash: str = ""
    actual_hash: str = ""
    violation_type: str = ""  # "modified" | "deleted"


class FilesystemGuard:
    """Filesystem access control and integrity monitor.

    Enforces path allowlists, monitors honeypot files,
    verifies file integrity, and detects symlink attacks.
    """

    def __init__(
        self,
        paths_file: Optional[Path] = None,
        project_root: Optional[Path] = None,
    ) -> None:
        """Initialize the filesystem guard.

        Args:
            paths_file: Path to the paths YAML allowlist.
            project_root: Root directory of the project (for relative paths).
        """
        self._project_root = Path(project_root) if project_root else Path.cwd()
        self._allowed_paths: list[str] = []
        self._blocked_paths: list[str] = []
        self._honeypots: list[Path] = []
        self._honeypot_names: set[str] = set()  # filename-based fallback
        self._baseline: dict[str, str] = {}  # filepath -> sha256 hex

        if paths_file and paths_file.exists():
            self._load(paths_file)

    def _load(self, path: Path) -> None:
        """Load path allowlist/blocklist from YAML."""
        if yaml is None:
            return
        raw = path.read_text(encoding="utf-8")
        data = yaml.safe_load(raw) or {}
        self._allowed_paths = data.get("allowed_paths", [])
        self._blocked_paths = data.get("blocked_paths", [])

    # -----------------------------------------------------------------
    # Honeypot monitoring
    # -----------------------------------------------------------------

    def register_honeypot(self, filepath: Path) -> None:
        """Register a file as a honeypot.

        Args:
            filepath: Path to the honeypot file.
        """
        filepath = Path(filepath).resolve()
        if filepath not in self._honeypots:
            self._honeypots.append(filepath)
        # Also track by filename for path-agnostic matching
        self._honeypot_names.add(filepath.name)

    def get_honeypots(self) -> list[Path]:
        """Return all registered honeypot paths."""
        return list(self._honeypots)

    # -----------------------------------------------------------------
    # Integrity monitoring
    # -----------------------------------------------------------------

    def create_baseline(self, paths: list[Path]) -> None:
        """Compute and store SHA-256 hashes for the given files.

        Args:
            paths: List of files to baseline.
        """
        for p in paths:
            p = Path(p)
            if p.is_file():
                self._baseline[str(p)] = self._sha256(p)

    def get_baseline(self) -> dict[str, str]:
        """Return the current baseline (filepath -> hash)."""
        return dict(self._baseline)

    def check_integrity(self) -> list[IntegrityViolation]:
        """Verify all baselined files against their stored hashes.

        Returns:
            List of integrity violations found.
        """
        violations: list[IntegrityViolation] = []
        for filepath, expected in self._baseline.items():
            p = Path(filepath)
            if not p.exists():
                violations.append(IntegrityViolation(
                    filepath=filepath,
                    expected_hash=expected,
                    actual_hash="",
                    violation_type="deleted",
                ))
            else:
                actual = self._sha256(p)
                if actual != expected:
                    violations.append(IntegrityViolation(
                        filepath=filepath,
                        expected_hash=expected,
                        actual_hash=actual,
                        violation_type="modified",
                    ))
        return violations

    # -----------------------------------------------------------------
    # Path checking
    # -----------------------------------------------------------------

    def check_path(self, filepath: Path, operation: str = "read") -> AccessResult:
        """Check if a file access is allowed.

        Args:
            filepath: The target file path.
            operation: Access type ('read', 'write', 'delete', 'execute').

        Returns:
            AccessResult with blocked, is_honeypot, reason.
        """
        filepath = Path(filepath)
        str_path = str(filepath)

        # --- 1. Honeypot check ---
        try:
            resolved = filepath.resolve()
        except OSError:
            resolved = filepath

        # Check by resolved absolute path OR by filename (path-agnostic fallback)
        is_honeypot_path = (resolved in self._honeypots) or (filepath.name in self._honeypot_names)
        if is_honeypot_path:
            return AccessResult(
                blocked=True,
                is_honeypot=True,
                reason=f"Honeypot file accessed: {filepath.name}",
                path=str_path,
                operation=operation,
            )

        # --- 2. Symlink detection ---
        if filepath.is_symlink():
            try:
                link_target = filepath.resolve()
                if not self._is_within_allowed(link_target):
                    return AccessResult(
                        blocked=True,
                        is_honeypot=False,
                        reason=f"Symlink attack detected: {filepath} -> {link_target}",
                        path=str_path,
                        operation=operation,
                    )
            except OSError:
                return AccessResult(
                    blocked=True,
                    is_honeypot=False,
                    reason=f"Symlink could not be resolved: {filepath}",
                    path=str_path,
                    operation=operation,
                )

        # --- 3. Blocked paths check ---
        if self._is_blocked(filepath):
            return AccessResult(
                blocked=True,
                is_honeypot=False,
                reason=f"Path is blocked: {filepath}",
                path=str_path,
                operation=operation,
            )

        # --- 4. Allowlist check ---
        if not self._is_within_allowed(filepath):
            return AccessResult(
                blocked=True,
                is_honeypot=False,
                reason=f"Path not in allowed directories: {filepath}",
                path=str_path,
                operation=operation,
            )

        return AccessResult(
            blocked=False,
            is_honeypot=False,
            reason="Allowed",
            path=str_path,
            operation=operation,
        )

    def _is_blocked(self, filepath: Path) -> bool:
        """Check if a path matches any blocked pattern."""
        str_path = str(filepath)
        name = filepath.name

        for blocked in self._blocked_paths:
            # Check filename match (e.g. ".env", "credentials.json")
            if name == blocked or name == blocked.rstrip("/"):
                return True
            # Check path contains blocked pattern
            if blocked in str_path:
                return True

        return False

    def _is_within_allowed(self, filepath: Path) -> bool:
        """Check if a path is within any allowed directory."""
        # Resolve relative to project root
        try:
            resolved = filepath.resolve()
        except OSError:
            return False

        project = self._project_root.resolve()

        for allowed in self._allowed_paths:
            # Convert relative allowed paths to absolute
            if allowed.startswith("./"):
                allowed_abs = (project / allowed[2:]).resolve()
            elif allowed.startswith("/") or (len(allowed) > 1 and allowed[1] == ":"):
                allowed_abs = Path(allowed).resolve()
            else:
                allowed_abs = (project / allowed).resolve()

            try:
                resolved.relative_to(allowed_abs)
                return True
            except ValueError:
                continue

        return False

    @staticmethod
    def _sha256(filepath: Path) -> str:
        """Compute SHA-256 hash of a file."""
        h = hashlib.sha256()
        h.update(filepath.read_bytes())
        return h.hexdigest()
