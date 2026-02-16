"""Moltr Telegram alert channel.

Sends security alerts and status reports to a Telegram chat.
Falls back to logging if Telegram is not configured.
"""

from __future__ import annotations

import json
import logging
import urllib.request
import urllib.error
from typing import Any

from src.alerts.manager import (
    AlertChannel,
    Severity,
    SEVERITY_EMOJI,
    utc_timestamp,
)

logger = logging.getLogger("moltr.telegram")

# Re-export so existing imports still work
__all__ = ["TelegramAlert", "Severity"]


class TelegramAlert(AlertChannel):
    """Telegram notification channel for Moltr security alerts.

    Sends formatted alerts to a Telegram chat via the Bot API.
    If bot_token or chat_id are empty, all send methods return False
    and log a warning instead of crashing.
    """

    def __init__(self, bot_token: str = "", chat_id: str = "") -> None:
        """Initialize the Telegram alert channel.

        Args:
            bot_token: Telegram Bot API token.
            chat_id: Target chat/group ID for alerts.
        """
        self._bot_token = bot_token
        self._chat_id = chat_id

    @property
    def name(self) -> str:
        """Return the channel name."""
        return "telegram"

    @property
    def is_configured(self) -> bool:
        """Whether Telegram credentials are set."""
        return bool(self._bot_token) and bool(self._chat_id)

    # -----------------------------------------------------------------
    # AlertChannel interface
    # -----------------------------------------------------------------

    def send(self, severity: Severity, title: str, message: str) -> bool:
        """Send an alert via Telegram.

        Args:
            severity: Alert severity level.
            title: Short alert title.
            message: Detailed alert message.

        Returns:
            True if sent successfully, False otherwise.
        """
        if not self.is_configured:
            logger.warning("Telegram not configured, skipping: %s", title)
            return False
        text = self.format_alert(severity, f"{title}\n{message}")
        return self._send_message(text)

    # -----------------------------------------------------------------
    # Formatting
    # -----------------------------------------------------------------

    @staticmethod
    def format_alert(severity: Severity, message: str) -> str:
        """Format a security alert message.

        Args:
            severity: Alert severity level.
            message: Alert message text.

        Returns:
            Formatted message string with emoji, severity, timestamp.
        """
        emoji = SEVERITY_EMOJI.get(severity, "")
        ts = utc_timestamp()
        return (
            f"{emoji} [{severity.value}] Moltr Security Alert\n"
            f"Time: {ts}\n"
            f"\n"
            f"{message}"
        )

    @staticmethod
    def format_incident_report(scan_result: Any) -> str:
        """Format a scan result into an incident report.

        Args:
            scan_result: A ScanResult object from the OutputScanner.

        Returns:
            Formatted incident report string.
        """
        ts = utc_timestamp()
        return (
            f"\U0001f6a8 Moltr Incident Report\n"
            f"Time: {ts}\n"
            f"Threat Type: {scan_result.threat_type}\n"
            f"Matched Pattern: {scan_result.matched_pattern}\n"
            f"Blocked: {scan_result.blocked}\n"
            f"Preview: {str(scan_result.original_text)[:80]}..."
        )

    @staticmethod
    def format_status(status_dict: dict[str, Any]) -> str:
        """Format a status dictionary into a status message.

        Args:
            status_dict: Module status dictionary from Moltr.get_status().

        Returns:
            Formatted status message string.
        """
        ts = utc_timestamp()
        lines = [f"\U0001f4ca Moltr Status Report", f"Time: {ts}", ""]
        for module, state in status_dict.items():
            lines.append(f"  {module}: {state}")
        return "\n".join(lines)

    # -----------------------------------------------------------------
    # Send methods
    # -----------------------------------------------------------------

    def send_alert(self, severity: Severity, message: str) -> bool:
        """Send a security alert to Telegram.

        Args:
            severity: Alert severity level.
            message: Alert message text.

        Returns:
            True if sent successfully, False otherwise.
        """
        if not self.is_configured:
            logger.warning("Telegram not configured, skipping alert: %s", message)
            return False
        text = self.format_alert(severity, message)
        return self._send_message(text)

    def send_incident_report(self, scan_result: Any) -> bool:
        """Send an incident report to Telegram.

        Args:
            scan_result: A ScanResult from the OutputScanner.

        Returns:
            True if sent successfully, False otherwise.
        """
        if not self.is_configured:
            logger.warning("Telegram not configured, skipping incident report")
            return False
        text = self.format_incident_report(scan_result)
        return self._send_message(text)

    def send_status(self, status_dict: dict[str, Any]) -> bool:
        """Send a status report to Telegram.

        Args:
            status_dict: Module status dictionary.

        Returns:
            True if sent successfully, False otherwise.
        """
        if not self.is_configured:
            logger.warning("Telegram not configured, skipping status report")
            return False
        text = self.format_status(status_dict)
        return self._send_message(text)

    def _send_message(self, text: str) -> bool:
        """Send a message via Telegram Bot API using urllib.

        Args:
            text: The message text to send.

        Returns:
            True if the API call succeeded.
        """
        url = f"https://api.telegram.org/bot{self._bot_token}/sendMessage"
        payload = json.dumps({
            "chat_id": self._chat_id,
            "text": text,
            "parse_mode": "HTML",
        }).encode("utf-8")

        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status == 200
        except (urllib.error.URLError, urllib.error.HTTPError, OSError) as exc:
            logger.error("Telegram send failed: %s", exc)
            return False
