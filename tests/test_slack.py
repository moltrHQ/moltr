"""Tests for the Moltr Slack alert channel.

Tests payload formatting (Block Kit), graceful handling when
not configured, and webhook posting with mocked HTTP.
"""

from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest

from src.alerts.manager import Severity
from src.alerts.slack import SlackAlert


# -------------------------------------------------------------------------
# Formatting
# -------------------------------------------------------------------------
class TestSlackFormatting:
    """Tests for Slack Block Kit payload formatting."""

    def test_payload_has_attachments(self) -> None:
        """Payload should contain an attachments array."""
        payload = SlackAlert.format_payload(
            Severity.WARNING, "Test Title", "Test message"
        )
        assert "attachments" in payload
        assert len(payload["attachments"]) == 1

    def test_payload_has_blocks(self) -> None:
        """Attachment should contain blocks."""
        payload = SlackAlert.format_payload(
            Severity.INFO, "Title", "Message"
        )
        blocks = payload["attachments"][0]["blocks"]
        assert len(blocks) >= 2

    def test_header_block_contains_severity(self) -> None:
        """Header block should contain the severity label."""
        payload = SlackAlert.format_payload(
            Severity.CRITICAL, "Alert", "Details"
        )
        header = payload["attachments"][0]["blocks"][0]
        assert header["type"] == "header"
        assert "CRITICAL" in header["text"]["text"]

    def test_header_block_contains_title(self) -> None:
        """Header block should contain the title."""
        payload = SlackAlert.format_payload(
            Severity.INFO, "Server Down", "Check logs"
        )
        header = payload["attachments"][0]["blocks"][0]
        assert "Server Down" in header["text"]["text"]

    def test_section_block_contains_message(self) -> None:
        """Section block should contain the message text."""
        payload = SlackAlert.format_payload(
            Severity.WARNING, "Title", "Detailed message here"
        )
        section = payload["attachments"][0]["blocks"][1]
        assert section["type"] == "section"
        assert "Detailed message here" in section["text"]["text"]

    def test_context_block_has_timestamp(self) -> None:
        """Context block should contain a timestamp."""
        payload = SlackAlert.format_payload(
            Severity.INFO, "Title", "Msg"
        )
        context = payload["attachments"][0]["blocks"][2]
        assert context["type"] == "context"
        assert "Moltr Security" in context["elements"][0]["text"]

    def test_color_varies_by_severity(self) -> None:
        """Each severity should produce a different color."""
        colors = set()
        for sev in Severity:
            payload = SlackAlert.format_payload(sev, "T", "M")
            colors.add(payload["attachments"][0]["color"])
        assert len(colors) == 4

    def test_warning_emoji_in_header(self) -> None:
        """WARNING severity should include the warning emoji."""
        payload = SlackAlert.format_payload(
            Severity.WARNING, "Warn", "Msg"
        )
        header_text = payload["attachments"][0]["blocks"][0]["text"]["text"]
        assert "\u26a0\ufe0f" in header_text


# -------------------------------------------------------------------------
# Graceful handling
# -------------------------------------------------------------------------
class TestSlackGraceful:
    """Tests for Slack behavior when not configured."""

    def test_not_configured_without_url(self) -> None:
        """SlackAlert without webhook URL should not be configured."""
        alert = SlackAlert(webhook_url="")
        assert alert.is_configured is False

    def test_configured_with_url(self) -> None:
        """SlackAlert with webhook URL should be configured."""
        alert = SlackAlert(webhook_url="https://hooks.slack.com/test")
        assert alert.is_configured is True

    def test_send_without_config_returns_false(self) -> None:
        """send() should return False when not configured."""
        alert = SlackAlert(webhook_url="")
        result = alert.send(Severity.INFO, "Test", "Msg")
        assert result is False

    def test_channel_name(self) -> None:
        """name property should return 'slack'."""
        alert = SlackAlert()
        assert alert.name == "slack"


# -------------------------------------------------------------------------
# Send with mocked HTTP
# -------------------------------------------------------------------------
class TestSlackSend:
    """Tests for Slack send with mocked webhook."""

    def test_send_calls_webhook(self) -> None:
        """send() should POST to the webhook URL."""
        alert = SlackAlert(webhook_url="https://hooks.slack.com/test")
        with patch.object(alert, "_post_webhook", return_value=True) as mock_post:
            result = alert.send(Severity.WARNING, "Alert", "Details")
            assert result is True
            mock_post.assert_called_once()

    def test_send_failure_returns_false(self) -> None:
        """send() should return False if webhook fails."""
        alert = SlackAlert(webhook_url="https://hooks.slack.com/test")
        with patch.object(alert, "_post_webhook", return_value=False):
            result = alert.send(Severity.CRITICAL, "Fail", "Error")
            assert result is False
