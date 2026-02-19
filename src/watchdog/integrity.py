"""Moltr integrity watchdog.

Monitors file integrity and system state to detect
unauthorized modifications to Moltr's own source code,
configuration, and honeypot files.

Uses SHA-256 baselines with periodic verification.
Alerts via AlertManager when tampering is detected.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

logger = logging.getLogger("moltr.watchdog")


@dataclass
class IntegrityViolation:
    """Represents a detected integrity violation."""

    filepath: str
    expected_hash: str
    actual_hash: str
    violation_type: str  # "modified", "deleted", "added"
    detected_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "filepath": self.filepath,
            "expected_hash": self.expected_hash,
            "actual_hash": self.actual_hash,
            "violation_type": self.violation_type,
            "detected_at": self.detected_at,
        }


class IntegrityWatchdog:
    """File and system integrity monitor.

    Computes and tracks SHA-256 checksums of critical files to detect
    unauthorized modifications. Supports on-demand and scheduled scans.
    """

    def __init__(
        self,
        project_root: str | Path | None = None,
        on_violation: Optional[Callable[[list["IntegrityViolation"]], None]] = None,
        hmac_key: Optional[str] = None,
    ) -> None:
        """Initialize the integrity watchdog.

        Args:
            project_root: Root directory for resolving relative paths.
            on_violation: Callback invoked with violations list when tampering is detected.
            hmac_key: Secret key for HMAC-protecting baselines. Load from ENV for security.
        """
        self._project_root = Path(project_root) if project_root else Path(".")
        self._baselines: dict[str, str] = {}  # filepath -> sha256
        self._watched_paths: set[str] = set()
        self._violations: list[IntegrityViolation] = []
        self._last_check: Optional[float] = None
        self._baseline_created_at: Optional[float] = None
        self._on_violation = on_violation
        self._hmac_key = (hmac_key or os.environ.get("MOLTR_WATCHDOG_HMAC_KEY", "")).encode()
        self._baseline_hmac: Optional[str] = None
        self._updating = False  # Lock flag for update_baseline_for
        self._scheduler_thread: Optional[threading.Thread] = None
        self._scheduler_running = False

    @staticmethod
    def _hash_file(filepath: Path) -> Optional[str]:
        """Compute SHA-256 hash of a single file.

        Args:
            filepath: Path to the file to hash.

        Returns:
            Hex-encoded SHA-256 hash, or None if file is unreadable.
        """
        try:
            sha256 = hashlib.sha256()
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except (OSError, PermissionError) as e:
            logger.warning("Cannot hash %s: %s", filepath, e)
            return None

    def _resolve_path(self, path: str | Path) -> Path:
        """Resolve a path relative to project root."""
        p = Path(path)
        if not p.is_absolute():
            p = self._project_root / p
        return p.resolve()

    def _collect_files(self, path: Path) -> list[Path]:
        """Collect all files under a path (recursively for directories)."""
        if path.is_file():
            return [path]
        if path.is_dir():
            files = []
            for item in sorted(path.rglob("*")):
                if item.is_file() and not item.name.startswith("."):
                    files.append(item)
            return files
        return []

    def _compute_baseline_hmac(self) -> str:
        """Compute HMAC over all baselines to detect baseline tampering."""
        if not self._hmac_key:
            return ""
        # Deterministic: sort by key, concat key+hash
        data = "".join(
            f"{k}:{v}" for k, v in sorted(self._baselines.items())
        ).encode()
        return hmac.new(self._hmac_key, data, hashlib.sha256).hexdigest()

    def _verify_baseline_hmac(self) -> bool:
        """Verify the baseline hasn't been tampered with."""
        if not self._hmac_key or not self._baseline_hmac:
            return True  # No HMAC configured or no baseline yet
        return self._compute_baseline_hmac() == self._baseline_hmac

    def start_scheduler(self, interval_seconds: int = 60) -> None:
        """Start a background thread that runs verify_integrity periodically.

        Args:
            interval_seconds: Seconds between integrity checks.
        """
        if self._scheduler_running:
            return

        self._scheduler_running = True

        def _run():
            logger.info("Watchdog scheduler started (interval: %ds)", interval_seconds)
            while self._scheduler_running:
                time.sleep(interval_seconds)
                if not self._scheduler_running:
                    break
                try:
                    violations = self.verify_integrity()
                    if violations and self._on_violation:
                        self._on_violation(violations)
                except Exception as e:
                    logger.error("Watchdog scheduler error: %s", e)

        self._scheduler_thread = threading.Thread(
            target=_run, daemon=True, name="moltr-watchdog"
        )
        self._scheduler_thread.start()

    def stop_scheduler(self) -> None:
        """Stop the background integrity check scheduler."""
        self._scheduler_running = False
        if self._scheduler_thread:
            self._scheduler_thread.join(timeout=5)
            self._scheduler_thread = None
            logger.info("Watchdog scheduler stopped")

    def create_baseline(self, paths: list[str | Path]) -> dict[str, str]:
        """Create integrity baselines (checksums) for the given paths.

        Args:
            paths: List of file/directory paths to baseline.

        Returns:
            Dictionary mapping file paths to their SHA-256 checksums.
        """
        self._baselines.clear()
        self._watched_paths.clear()

        for path in paths:
            resolved = self._resolve_path(path)
            self._watched_paths.add(str(resolved))
            files = self._collect_files(resolved)

            for filepath in files:
                file_hash = self._hash_file(filepath)
                if file_hash is not None:
                    key = str(filepath)
                    self._baselines[key] = file_hash

        self._baseline_created_at = time.time()
        self._baseline_hmac = self._compute_baseline_hmac()
        logger.info(
            "Baseline created: %d files across %d paths%s",
            len(self._baselines),
            len(paths),
            " (HMAC protected)" if self._hmac_key else "",
        )
        return dict(self._baselines)

    def verify_integrity(self) -> list[IntegrityViolation]:
        """Verify all monitored files against their baselines.

        Returns:
            List of detected integrity violations since last baseline.
        """
        if not self._baselines:
            logger.warning("No baselines set — run create_baseline() first")
            return []

        # Skip check if an update is in progress (prevent false positives)
        if self._updating:
            logger.debug("Skipping integrity check — baseline update in progress")
            return []

        # Verify baseline itself hasn't been tampered with
        if not self._verify_baseline_hmac():
            logger.critical("BASELINE TAMPERING DETECTED — HMAC mismatch!")
            tamper_violation = IntegrityViolation(
                filepath="<baseline>",
                expected_hash=self._baseline_hmac or "",
                actual_hash=self._compute_baseline_hmac(),
                violation_type="baseline_tampered",
            )
            self._violations.append(tamper_violation)
            if self._on_violation:
                self._on_violation([tamper_violation])
            return [tamper_violation]

        violations: list[IntegrityViolation] = []
        now = time.time()

        # Check existing baselined files
        for filepath, expected_hash in self._baselines.items():
            path = Path(filepath)

            if not path.exists():
                violations.append(IntegrityViolation(
                    filepath=filepath,
                    expected_hash=expected_hash,
                    actual_hash="",
                    violation_type="deleted",
                    detected_at=now,
                ))
                continue

            actual_hash = self._hash_file(path)
            if actual_hash is None:
                violations.append(IntegrityViolation(
                    filepath=filepath,
                    expected_hash=expected_hash,
                    actual_hash="unreadable",
                    violation_type="modified",
                    detected_at=now,
                ))
            elif actual_hash != expected_hash:
                violations.append(IntegrityViolation(
                    filepath=filepath,
                    expected_hash=expected_hash,
                    actual_hash=actual_hash,
                    violation_type="modified",
                    detected_at=now,
                ))

        # Check for new files in watched directories
        for watched in self._watched_paths:
            watched_path = Path(watched)
            if not watched_path.is_dir():
                continue
            for filepath in self._collect_files(watched_path):
                key = str(filepath)
                if key not in self._baselines:
                    file_hash = self._hash_file(filepath) or "unknown"
                    violations.append(IntegrityViolation(
                        filepath=key,
                        expected_hash="",
                        actual_hash=file_hash,
                        violation_type="added",
                        detected_at=now,
                    ))

        self._last_check = now
        self._violations.extend(violations)

        if violations:
            logger.warning(
                "Integrity check: %d violation(s) detected!", len(violations)
            )
            # Invoke alert callback
            if self._on_violation:
                self._on_violation(violations)
        else:
            logger.debug("Integrity check: all %d files OK", len(self._baselines))

        return violations

    def add_watch(self, filepath: str | Path) -> None:
        """Add a file or directory to the watch list and baseline it.

        Args:
            filepath: Path to monitor for changes.
        """
        resolved = self._resolve_path(filepath)
        self._watched_paths.add(str(resolved))

        files = self._collect_files(resolved)
        added = 0
        for f in files:
            key = str(f)
            if key not in self._baselines:
                file_hash = self._hash_file(f)
                if file_hash is not None:
                    self._baselines[key] = file_hash
                    added += 1

        logger.info("Added watch: %s (%d new files)", resolved, added)

    def remove_watch(self, filepath: str | Path) -> None:
        """Remove a file or directory from the watch list.

        Args:
            filepath: Path to stop monitoring.
        """
        resolved = self._resolve_path(filepath)
        self._watched_paths.discard(str(resolved))

        # Remove baselines for files under this path
        prefix = str(resolved)
        to_remove = [k for k in self._baselines if k.startswith(prefix)]
        for k in to_remove:
            del self._baselines[k]

        logger.info("Removed watch: %s (%d files)", resolved, len(to_remove))

    def get_report(self) -> dict[str, Any]:
        """Generate an integrity status report.

        Returns:
            Report with baseline info, last check time, and violations.
        """
        return {
            "baseline_created_at": self._baseline_created_at,
            "last_check": self._last_check,
            "files_monitored": len(self._baselines),
            "watched_paths": list(self._watched_paths),
            "total_violations": len(self._violations),
            "recent_violations": [
                v.to_dict() for v in self._violations[-20:]
            ],
        }

    def update_baseline_for(self, filepath: str | Path) -> Optional[str]:
        """Update the baseline for a single file (after legitimate change).

        Args:
            filepath: Path to re-baseline.

        Returns:
            New hash, or None if file is unreadable.
        """
        self._updating = True
        try:
            resolved = self._resolve_path(filepath)
            key = str(resolved)
            file_hash = self._hash_file(resolved)
            if file_hash is not None:
                self._baselines[key] = file_hash
                self._baseline_hmac = self._compute_baseline_hmac()
                logger.info("Baseline updated: %s", key)
            return file_hash
        finally:
            self._updating = False
