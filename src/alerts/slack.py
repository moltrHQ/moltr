"""Moltr Slack alert channel.

Sends security alerts to a Slack channel via incoming webhook.
No SDK required - uses simple HTTP POST with urllib.
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

logger = logging.getLogger("moltr.slack")


# Severity -> Slack color (hex string without #)
_SLACK_COLOR: dict[Severity, str] = {
    Severity.INFO: "#3498DB",
    Severity.WARNING: "#F39C12",
    Severity.CRITICAL: "#E74C3C",
    Severity.LOCKDOWN: "#8B0000",
}


class SlackAlert(AlertChannel):
    """Slack notification channel using incoming webhooks.

    Sends formatted alerts as Slack Block Kit messages.
    If webhook_url is empty, send() returns False and logs a warning.
    """

    def __init__(self, webhook_url: str = "") -> None:
        """Initialize the Slack alert channel.

        Args:
            webhook_url: Slack incoming webhook URL.
        """
        self._webhook_url = webhook_url

    @property
    def name(self) -> str:
        """Return the channel name."""
        return "slack"

    @property
    def is_configured(self) -> bool:
        """Whether the Slack webhook URL is set."""
        return bool(self._webhook_url)

    def send(self, severity: Severity, title: str, message: str) -> bool:
        """Send an alert to Slack via webhook.

        Args:
            severity: Alert severity level.
            title: Short alert title.
            message: Detailed alert message.

        Returns:
            True if sent successfully, False otherwise.
        """
        if not self.is_configured:
            logger.warning("Slack not configured, skipping: %s", title)
            return False
        payload = self.format_payload(severity, title, message)
        return self._post_webhook(payload)

    @staticmethod
    def format_payload(
        severity: Severity, title: str, message: str
    ) -> dict:
        """Build a Slack Block Kit payload.

        Args:
            severity: Alert severity level.
            title: Short alert title.
            message: Detailed alert message.

        Returns:
            Dictionary suitable for JSON-encoding as a Slack webhook payload.
        """
        emoji = SEVERITY_EMOJI.get(severity, "")
        color = _SLACK_COLOR.get(severity, "#808080")
        ts = utc_timestamp()

        return {
            "attachments": [
                {
                    "color": color,
                    "blocks": [
                        {
                            "type": "header",
                            "text": {
                                "type": "plain_text",
                                "text": f"{emoji} [{severity.value}] {title}",
                            },
                        },
                        {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": message,
                            },
                        },
                        {
                            "type": "context",
                            "elements": [
                                {
                                    "type": "mrkdwn",
                                    "text": f"Moltr Security | {ts}",
                                }
                            ],
                        },
                    ],
                }
            ]
        }

    def _post_webhook(self, payload: dict) -> bool:
        """POST JSON payload to the Slack webhook URL.

        Args:
            payload: The Slack message payload.

        Returns:
            True if the webhook responded with 200.
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
                return resp.status == 200
        except (urllib.error.URLError, urllib.error.HTTPError, OSError) as exc:
            logger.error("Slack send failed: %s", exc)
            return False
