"""Moltr - Entry Point.

Main entry point for the Moltr security proxy.
Initializes all security components and provides a unified API
for scanning, validating, and monitoring AI agent actions.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from src.core.secrets_registry import SecretsRegistry
from src.scanners.output_scanner import OutputScanner, ScanResult
from src.validators.action_validator import ActionValidator, ValidationResult
from src.validators.network_firewall import NetworkFirewall, FirewallVerdict
from src.validators.filesystem_guard import FilesystemGuard, AccessResult
from src.killswitches.killswitch import KillSwitch, EscalationLevel, KillSwitchEvent
from src.watchdog.integrity import IntegrityWatchdog, IntegrityViolation
from src.alerts.manager import Severity
from src.alerts.telegram import TelegramAlert

logger = logging.getLogger("moltr")


class Moltr:
    """Main Moltr security proxy orchestrator.

    Coordinates all security components to intercept, validate,
    and monitor AI agent actions in real-time.
    """

    def __init__(
        self,
        config_path: str | Path = "config/default.yaml",
        secrets_storage: str = "secrets.json",
        project_root: str | Path | None = None,
    ) -> None:
        """Initialize Moltr with the given configuration.

        Args:
            config_path: Path to the YAML configuration file.
            secrets_storage: Path to the encrypted secrets JSON file.
            project_root: Root directory of the project for path resolution.
        """
        self._config_path = Path(config_path)
        self._project_root = Path(project_root) if project_root else Path(".")

        # Initialize all security modules
        self._output_scanner = OutputScanner(
            patterns_file=Path("config/scan_patterns.yaml"),
        )
        self._secrets_registry = SecretsRegistry(
            storage_path=secrets_storage,
        )
        self._action_validator = ActionValidator(
            commands_file=Path("config/allowlists/commands.yaml"),
        )
        self._network_firewall = NetworkFirewall(
            domains_file=Path("config/allowlists/domains.yaml"),
            output_scanner=self._output_scanner,
        )
        self._filesystem_guard = FilesystemGuard(
            paths_file=Path("config/allowlists/paths.yaml"),
            project_root=self._project_root,
        )
        self._killswitch = KillSwitch()
        self._telegram = TelegramAlert()

        self._watchdog = IntegrityWatchdog(
            project_root=self._project_root,
            on_violation=self._handle_integrity_violation,
        )

        # Create initial baseline for critical paths (no honeypots dir — API traps used instead)
        self._watchdog.create_baseline([
            self._project_root / "config",
            self._project_root / "src",
        ])

        # Start auto-check scheduler (every 60 seconds)
        self._watchdog.start_scheduler(interval_seconds=60)

        logger.info("Moltr initialized with config: %s", self._config_path)

    # -----------------------------------------------------------------
    # Central API
    # -----------------------------------------------------------------

    def scan_output(self, text: str, level: str = "high", passphrase: str = "") -> ScanResult:
        """Scan agent output text for sensitive data leaks.

        Args:
            text: The output text to scan.
            level: Security level (high/medium/low).
            passphrase: Required for medium/low levels.

        Returns:
            ScanResult indicating whether the text was blocked.
        """
        return self._output_scanner.scan(text, level=level, passphrase=passphrase)

    def validate_command(self, command: str) -> ValidationResult:
        """Validate a shell command against the security policy.

        Args:
            command: The shell command to validate.

        Returns:
            ValidationResult indicating whether the command is allowed.
        """
        return self._action_validator.validate(command)

    def check_url(self, url: str, payload: str = "") -> FirewallVerdict:
        """Check an outbound URL against the network firewall.

        Args:
            url: The URL to check.
            payload: Optional request payload for inspection.

        Returns:
            FirewallVerdict indicating whether the request is allowed.
        """
        return self._network_firewall.check(url, payload)

    def check_path(self, path: str, operation: str = "read") -> AccessResult:
        """Check a filesystem path against the access policy.

        Args:
            path: The file path to check.
            operation: The intended operation (read/write/delete).

        Returns:
            AccessResult indicating whether access is blocked.
        """
        return self._filesystem_guard.check_path(path, operation)

    # -----------------------------------------------------------------
    # Status & control
    # -----------------------------------------------------------------

    def get_status(self) -> dict[str, Any]:
        """Return the status of all security modules.

        Returns:
            Dictionary mapping module names to their current state.
        """
        ks_status = self._killswitch.get_status()
        wd_report = self._watchdog.get_report()
        return {
            "output_scanner": {
                "enabled": True,
                "is_locked": self._output_scanner.is_locked,
            },
            "action_validator": {"enabled": True},
            "network_firewall": {"enabled": True},
            "filesystem_guard": {"enabled": True},
            "killswitch": {
                "is_locked_down": ks_status.is_locked_down,
                "active_levels": [lvl.name for lvl in ks_status.active_levels],
                "highest_level": (
                    ks_status.highest_level.name
                    if ks_status.highest_level
                    else None
                ),
            },
            "integrity_watchdog": {
                "enabled": True,
                "files_monitored": wd_report["files_monitored"],
                "last_check": wd_report["last_check"],
                "total_violations": wd_report["total_violations"],
            },
        }

    def emergency_stop(self, reason: str = "") -> None:
        """Trigger an emergency lockdown of all systems.

        Args:
            reason: Human-readable reason for the emergency stop.
        """
        self._killswitch.trigger(EscalationLevel.LOCKDOWN, reason=reason)
        logger.critical("EMERGENCY STOP: %s", reason)

    def _handle_integrity_violation(self, violations: list[IntegrityViolation]) -> None:
        """Handle detected integrity violations — alert and optionally lockdown.

        Args:
            violations: List of detected violations.
        """
        summary = ", ".join(
            f"{v.violation_type}: {Path(v.filepath).name}" for v in violations[:5]
        )
        if len(violations) > 5:
            summary += f" (+{len(violations) - 5} more)"

        logger.critical("INTEGRITY VIOLATION: %s", summary)

        # Send Telegram alert if configured
        if self._telegram.is_configured:
            self._telegram.send(
                severity=Severity.CRITICAL,
                title="Integrity Violation Detected",
                message=f"{len(violations)} file(s) tampered:\n{summary}",
            )

    def get_killswitch_log(self) -> list[KillSwitchEvent]:
        """Return the kill switch event log.

        Returns:
            List of KillSwitchEvent in chronological order.
        """
        return self._killswitch.get_log()

    def verify_integrity(self) -> list[IntegrityViolation]:
        """Run an integrity check on all monitored files.

        Returns:
            List of detected integrity violations.
        """
        return self._watchdog.verify_integrity()

    def get_integrity_report(self) -> dict[str, Any]:
        """Return the integrity watchdog status report.

        Returns:
            Report with baseline info, monitored files, and violations.
        """
        return self._watchdog.get_report()
