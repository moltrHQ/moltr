"""Tests for the Moltr Discord alert channel.

Tests embed formatting, color mapping by severity, graceful
handling when not configured, and webhook posting with mocked HTTP.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from src.alerts.manager import Severity, SEVERITY_COLOR
from src.alerts.discord import DiscordAlert


# -------------------------------------------------------------------------
# Formatting (embeds)
# -------------------------------------------------------------------------
class TestDiscordFormatting:
    """Tests for Discord embed payload formatting."""

    def test_payload_has_embeds(self) -> None:
        """Payload should contain an embeds array."""
        payload = DiscordAlert.format_payload(
            Severity.WARNING, "Test Title", "Test message"
        )
        assert "embeds" in payload
        assert len(payload["embeds"]) == 1

    def test_embed_title_contains_severity(self) -> None:
        """Embed title should contain the severity label."""
        payload = DiscordAlert.format_payload(
            Severity.CRITICAL, "Alert", "Details"
        )
        assert "CRITICAL" in payload["embeds"][0]["title"]

    def test_embed_title_contains_title(self) -> None:
        """Embed title should contain the alert title."""
        payload = DiscordAlert.format_payload(
            Severity.INFO, "Server Check", "All good"
        )
        assert "Server Check" in payload["embeds"][0]["title"]

    def test_embed_description_contains_message(self) -> None:
        """Embed description should contain the message."""
        payload = DiscordAlert.format_payload(
            Severity.WARNING, "Title", "Detailed message here"
        )
        assert payload["embeds"][0]["description"] == "Detailed message here"

    def test_embed_has_footer_with_timestamp(self) -> None:
        """Embed should have a footer with Moltr branding and timestamp."""
        payload = DiscordAlert.format_payload(
            Severity.INFO, "Title", "Msg"
        )
        footer = payload["embeds"][0]["footer"]["text"]
        assert "Moltr Security" in footer

    def test_color_matches_severity(self) -> None:
        """Each severity should map to the correct embed color."""
        for sev in Severity:
            payload = DiscordAlert.format_payload(sev, "T", "M")
            expected = SEVERITY_COLOR[sev]
            assert payload["embeds"][0]["color"] == expected

    def test_lockdown_emoji_in_title(self) -> None:
        """LOCKDOWN severity should include the skull emoji."""
        payload = DiscordAlert.format_payload(
            Severity.LOCKDOWN, "Lock", "Down"
        )
        assert "\u2620\ufe0f" in payload["embeds"][0]["title"]


# -------------------------------------------------------------------------
# Graceful handling
# -------------------------------------------------------------------------
class TestDiscordGraceful:
    """Tests for Discord behavior when not configured."""

    def test_not_configured_without_url(self) -> None:
        """DiscordAlert without webhook URL should not be configured."""
        alert = DiscordAlert(webhook_url="")
        assert alert.is_configured is False

    def test_configured_with_url(self) -> None:
        """DiscordAlert with webhook URL should be configured."""
        alert = DiscordAlert(webhook_url="https://discord.com/api/webhooks/test")
        assert alert.is_configured is True

    def test_send_without_config_returns_false(self) -> None:
        """send() should return False when not configured."""
        alert = DiscordAlert(webhook_url="")
        result = alert.send(Severity.INFO, "Test", "Msg")
        assert result is False

    def test_channel_name(self) -> None:
        """name property should return 'discord'."""
        alert = DiscordAlert()
        assert alert.name == "discord"


# -------------------------------------------------------------------------
# Send with mocked HTTP
# -------------------------------------------------------------------------
class TestDiscordSend:
    """Tests for Discord send with mocked webhook."""

    def test_send_calls_webhook(self) -> None:
        """send() should POST to the webhook URL."""
        alert = DiscordAlert(webhook_url="https://discord.com/api/webhooks/test")
        with patch.object(alert, "_post_webhook", return_value=True) as mock_post:
            result = alert.send(Severity.CRITICAL, "Alert", "Details")
            assert result is True
            mock_post.assert_called_once()

    def test_send_failure_returns_false(self) -> None:
        """send() should return False if webhook fails."""
        alert = DiscordAlert(webhook_url="https://discord.com/api/webhooks/test")
        with patch.object(alert, "_post_webhook", return_value=False):
            result = alert.send(Severity.WARNING, "Fail", "Error")
            assert result is False
