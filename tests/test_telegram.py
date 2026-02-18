"""Tests for the Moltr Telegram alert service.

Tests message formatting, severity emojis, and graceful
handling when Telegram is not configured.
Uses unittest.mock for Telegram API calls.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.alerts.telegram import TelegramAlert, Severity


# -------------------------------------------------------------------------
# Message formatting
# -------------------------------------------------------------------------
class TestMessageFormatting:
    """Tests for alert message formatting."""

    def test_format_alert_contains_severity(self) -> None:
        """Formatted message should contain the severity label."""
        alert = TelegramAlert(bot_token="fake", chat_id="123")
        msg = alert.format_alert(Severity.WARNING, "Test warning message")
        assert "WARNING" in msg

    def test_format_alert_contains_message(self) -> None:
        """Formatted message should contain the actual message."""
        alert = TelegramAlert(bot_token="fake", chat_id="123")
        msg = alert.format_alert(Severity.INFO, "Something happened")
        assert "Something happened" in msg

    def test_format_alert_contains_timestamp(self) -> None:
        """Formatted message should contain a timestamp."""
        alert = TelegramAlert(bot_token="fake", chat_id="123")
        msg = alert.format_alert(Severity.CRITICAL, "Critical event")
        # Should contain date-like pattern (YYYY- or HH:)
        assert ":" in msg or "-" in msg

    def test_format_incident_report(self) -> None:
        """Incident reports should contain threat type and details."""
        alert = TelegramAlert(bot_token="fake", chat_id="123")
        scan_result = MagicMock()
        scan_result.blocked = True
        scan_result.threat_type = "api_key"
        scan_result.matched_pattern = "OpenAI API Key"
        scan_result.original_text = "some leaked text..."
        msg = alert.format_incident_report(scan_result)
        assert "api_key" in msg
        assert "OpenAI API Key" in msg


# -------------------------------------------------------------------------
# Severity emojis
# -------------------------------------------------------------------------
class TestSeverityEmojis:
    """Tests for severity level emoji mapping."""

    def test_info_emoji(self) -> None:
        """INFO should have a blue circle emoji."""
        alert = TelegramAlert(bot_token="fake", chat_id="123")
        msg = alert.format_alert(Severity.INFO, "Info message")
        assert "\U0001f535" in msg  # blue circle

    def test_warning_emoji(self) -> None:
        """WARNING should have a yellow/orange warning emoji."""
        alert = TelegramAlert(bot_token="fake", chat_id="123")
        msg = alert.format_alert(Severity.WARNING, "Warning message")
        assert "\u26a0\ufe0f" in msg  # warning sign

    def test_critical_emoji(self) -> None:
        """CRITICAL should have a red circle emoji."""
        alert = TelegramAlert(bot_token="fake", chat_id="123")
        msg = alert.format_alert(Severity.CRITICAL, "Critical message")
        assert "\U0001f534" in msg  # red circle

    def test_lockdown_emoji(self) -> None:
        """LOCKDOWN should have a skull emoji."""
        alert = TelegramAlert(bot_token="fake", chat_id="123")
        msg = alert.format_alert(Severity.LOCKDOWN, "Lockdown triggered")
        assert "\u2620\ufe0f" in msg  # skull and crossbones


# -------------------------------------------------------------------------
# Graceful handling when not configured
# -------------------------------------------------------------------------
class TestGracefulHandling:
    """Tests for behavior when Telegram is not configured."""

    def test_no_token_does_not_crash(self) -> None:
        """Creating TelegramAlert without token should not crash."""
        alert = TelegramAlert(bot_token="", chat_id="")
        assert alert.is_configured is False

    def test_send_alert_without_config_returns_false(self) -> None:
        """send_alert should return False when not configured."""
        alert = TelegramAlert(bot_token="", chat_id="")
        result = alert.send_alert(Severity.INFO, "Test")
        assert result is False

    def test_send_incident_without_config_returns_false(self) -> None:
        """send_incident_report should return False when not configured."""
        alert = TelegramAlert(bot_token="", chat_id="")
        scan_result = MagicMock()
        result = alert.send_incident_report(scan_result)
        assert result is False

    def test_send_status_without_config_returns_false(self) -> None:
        """send_status should return False when not configured."""
        alert = TelegramAlert(bot_token="", chat_id="")
        result = alert.send_status({"module": "ok"})
        assert result is False

    def test_configured_with_token_and_chat_id(self) -> None:
        """TelegramAlert with token and chat_id should report as configured."""
        alert = TelegramAlert(bot_token="fake-token", chat_id="12345")
        assert alert.is_configured is True


# -------------------------------------------------------------------------
# Send methods (mocked API calls)
# -------------------------------------------------------------------------
class TestSendMethods:
    """Tests for send methods with mocked Telegram API."""

    def test_send_alert_calls_api(self) -> None:
        """send_alert should call the Telegram send method."""
        alert = TelegramAlert(bot_token="fake-token", chat_id="12345")
        with patch.object(alert, "_send_message", return_value=True) as mock_send:
            result = alert.send_alert(Severity.WARNING, "Test alert")
            assert result is True
            mock_send.assert_called_once()

    def test_send_incident_report_calls_api(self) -> None:
        """send_incident_report should call the Telegram send method."""
        alert = TelegramAlert(bot_token="fake-token", chat_id="12345")
        scan_result = MagicMock()
        scan_result.blocked = True
        scan_result.threat_type = "api_key"
        scan_result.matched_pattern = "Test Pattern"
        scan_result.original_text = "leaked..."
        with patch.object(alert, "_send_message", return_value=True) as mock_send:
            result = alert.send_incident_report(scan_result)
            assert result is True
            mock_send.assert_called_once()

    def test_send_status_calls_api(self) -> None:
        """send_status should call the Telegram send method."""
        alert = TelegramAlert(bot_token="fake-token", chat_id="12345")
        with patch.object(alert, "_send_message", return_value=True) as mock_send:
            result = alert.send_status({"scanner": "ok", "firewall": "ok"})
            assert result is True
            mock_send.assert_called_once()

    def test_send_failure_returns_false(self) -> None:
        """If _send_message fails, send_alert should return False."""
        alert = TelegramAlert(bot_token="fake-token", chat_id="12345")
        with patch.object(alert, "_send_message", return_value=False):
            result = alert.send_alert(Severity.CRITICAL, "Test")
            assert result is False
