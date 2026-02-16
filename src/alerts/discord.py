"""Moltr Discord alert channel.

Sends security alerts to a Discord channel via webhook.
Uses Discord embed format for rich formatting.
"""

from __future__ import annotations

import json
import logging
import urllib.request
import urllib.error

from src.alerts.manager import (
    AlertChannel,
    Severity,
    SEVERITY_EMOJI,
    SEVERITY_COLOR,
    utc_timestamp,
)

logger = logging.getLogger("moltr.discord")


class DiscordAlert(AlertChannel):
    """Discord notification channel using webhooks.

    Sends formatted alerts as Discord embed messages.
    If webhook_url is empty, send() returns False and logs a warning.
    """

    def __init__(self, webhook_url: str = "") -> None:
        """Initialize the Discord alert channel.

        Args:
            webhook_url: Discord webhook URL.
        """
        self._webhook_url = webhook_url

    @property
    def name(self) -> str:
        """Return the channel name."""
        return "discord"

    @property
    def is_configured(self) -> bool:
        """Whether the Discord webhook URL is set."""
        return bool(self._webhook_url)

    def send(self, severity: Severity, title: str, message: str) -> bool:
        """Send an alert to Discord via webhook.

        Args:
            severity: Alert severity level.
            title: Short alert title.
            message: Detailed alert message.

        Returns:
            True if sent successfully, False otherwise.
        """
        if not self.is_configured:
            logger.warning("Discord not configured, skipping: %s", title)
            return False
        payload = self.format_payload(severity, title, message)
        return self._post_webhook(payload)

    @staticmethod
    def format_payload(
        severity: Severity, title: str, message: str
    ) -> dict:
        """Build a Discord webhook payload with an embed.

        Args:
            severity: Alert severity level.
            title: Short alert title.
            message: Detailed alert message.

        Returns:
            Dictionary suitable for JSON-encoding as a Discord webhook payload.
        """
        emoji = SEVERITY_EMOJI.get(severity, "")
        color = SEVERITY_COLOR.get(severity, 0x808080)
        ts = utc_timestamp()

        return {
            "embeds": [
                {
                    "title": f"{emoji} [{severity.value}] {title}",
                    "description": message,
                    "color": color,
                    "footer": {
                        "text": f"Moltr Security | {ts}",
                    },
                }
            ]
        }

    def _post_webhook(self, payload: dict) -> bool:
        """POST JSON payload to the Discord webhook URL.

        Args:
            payload: The Discord message payload.

        Returns:
            True if the webhook responded with 2xx.
        """
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self._webhook_url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return 200 <= resp.status < 300
        except (urllib.error.URLError, urllib.error.HTTPError, OSError) as exc:
            logger.error("Discord send failed: %s", exc)
            return False
