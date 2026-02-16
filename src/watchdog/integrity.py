"""Moltr integrity watchdog.

Monitors file integrity and system state to detect
unauthorized modifications by AI agents.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional


class IntegrityWatchdog:
    """File and system integrity monitor.

    Computes and tracks checksums of critical files to detect
    unauthorized modifications. Supports scheduled and on-demand scans.
    """

    def __init__(self, config: Any = None) -> None:
        """Initialize the integrity watchdog.

        Args:
            config: MoltrConfig instance with watchdog settings.
        """
        pass

    def create_baseline(self, paths: list[str | Path]) -> dict[str, str]:
        """Create integrity baselines (checksums) for the given paths.

        Args:
            paths: List of file/directory paths to baseline.

        Returns:
            Dictionary mapping file paths to their SHA-256 checksums.
        """
        pass

    def verify_integrity(self) -> list[IntegrityViolation]:
        """Verify all monitored files against their baselines.

        Returns:
            List of detected integrity violations.
        """
        pass

    def add_watch(self, filepath: str | Path) -> None:
        """Add a file or directory to the watch list.

        Args:
            filepath: Path to monitor for changes.
        """
        pass

    def remove_watch(self, filepath: str | Path) -> None:
        """Remove a file or directory from the watch list.

        Args:
            filepath: Path to stop monitoring.
        """
        pass

    def get_report(self) -> dict[str, Any]:
        """Generate an integrity status report.

        Returns:
            Report with baseline info, last check time, and violations.
        """
        pass


class IntegrityViolation:
    """Represents a detected integrity violation.

    Contains information about what changed, when, and the expected
    vs actual checksums.
    """

    def __init__(
        self,
        filepath: str = "",
        expected_hash: str = "",
        actual_hash: str = "",
        violation_type: str = "modified",
    ) -> None:
        """Initialize an integrity violation record.

        Args:
            filepath: Path of the affected file.
            expected_hash: Expected SHA-256 checksum.
            actual_hash: Actual SHA-256 checksum found.
            violation_type: Type of violation ('modified', 'deleted', 'added').
        """
        pass
