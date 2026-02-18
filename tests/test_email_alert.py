"""Tests for the Moltr email alert channel.

Tests subject/body formatting, graceful handling when not configured,
and SMTP sending with mocked smtplib.
"""

from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest

from src.alerts.manager import Severity
from src.alerts.email import EmailAlert


# -------------------------------------------------------------------------
# Formatting
# -------------------------------------------------------------------------
class TestEmailFormatting:
    """Tests for email subject and body formatting."""

    def test_subject_contains_severity(self) -> None:
        """Subject should contain the severity label."""
        subject = EmailAlert.format_subject(Severity.CRITICAL, "Breach Detected")
        assert "CRITICAL" in subject

    def test_subject_contains_title(self) -> None:
        """Subject should contain the alert title."""
        subject = EmailAlert.format_subject(Severity.INFO, "Status OK")
        assert "Status OK" in subject

    def test_subject_has_moltr_prefix(self) -> None:
        """Subject should include 'Moltr' branding."""
        subject = EmailAlert.format_subject(Severity.WARNING, "Test")
        assert "Moltr" in subject

    def test_body_contains_severity(self) -> None:
        """Body should contain the severity."""
        body = EmailAlert.format_body(Severity.WARNING, "Title", "Details here")
        assert "WARNING" in body

    def test_body_contains_title(self) -> None:
        """Body should contain the title."""
        body = EmailAlert.format_body(Severity.INFO, "My Title", "Message")
        assert "My Title" in body

    def test_body_contains_message(self) -> None:
        """Body should contain the message."""
        body = EmailAlert.format_body(Severity.CRITICAL, "T", "Detailed info")
        assert "Detailed info" in body

    def test_body_contains_timestamp(self) -> None:
        """Body should contain a timestamp."""
        body = EmailAlert.format_body(Severity.INFO, "T", "M")
        assert "UTC" in body

    def test_body_has_separator(self) -> None:
        """Body should contain visual separators."""
        body = EmailAlert.format_body(Severity.INFO, "T", "M")
        assert "=" * 40 in body


# -------------------------------------------------------------------------
# Graceful handling
# -------------------------------------------------------------------------
class TestEmailGraceful:
    """Tests for email behavior when not configured."""

    def test_not_configured_without_host(self) -> None:
        """EmailAlert without SMTP host should not be configured."""
        alert = EmailAlert(smtp_host="", sender="a@b.com", recipients=["c@d.com"])
        assert alert.is_configured is False

    def test_not_configured_without_sender(self) -> None:
        """EmailAlert without sender should not be configured."""
        alert = EmailAlert(smtp_host="smtp.example.com", sender="", recipients=["a@b.com"])
        assert alert.is_configured is False

    def test_not_configured_without_recipients(self) -> None:
        """EmailAlert without recipients should not be configured."""
        alert = EmailAlert(smtp_host="smtp.example.com", sender="a@b.com", recipients=[])
        assert alert.is_configured is False

    def test_configured_with_all_fields(self) -> None:
        """EmailAlert with host, sender, and recipients should be configured."""
        alert = EmailAlert(
            smtp_host="smtp.example.com",
            sender="alert@moltr.io",
            recipients=["admin@moltr.io"],
        )
        assert alert.is_configured is True

    def test_send_without_config_returns_false(self) -> None:
        """send() should return False when not configured."""
        alert = EmailAlert()
        result = alert.send(Severity.INFO, "Test", "Msg")
        assert result is False

    def test_channel_name(self) -> None:
        """name property should return 'email'."""
        alert = EmailAlert()
        assert alert.name == "email"


# -------------------------------------------------------------------------
# Send with mocked SMTP
# -------------------------------------------------------------------------
class TestEmailSend:
    """Tests for email send with mocked SMTP."""

    def test_send_calls_smtp(self) -> None:
        """send() should call _send_email."""
        alert = EmailAlert(
            smtp_host="smtp.example.com",
            sender="alert@moltr.io",
            recipients=["admin@moltr.io"],
        )
        with patch.object(alert, "_send_email", return_value=True) as mock_send:
            result = alert.send(Severity.WARNING, "Alert", "Details")
            assert result is True
            mock_send.assert_called_once()

    def test_send_failure_returns_false(self) -> None:
        """send() should return False if _send_email fails."""
        alert = EmailAlert(
            smtp_host="smtp.example.com",
            sender="alert@moltr.io",
            recipients=["admin@moltr.io"],
        )
        with patch.object(alert, "_send_email", return_value=False):
            result = alert.send(Severity.CRITICAL, "Fail", "Error")
            assert result is False

    def test_smtp_called_with_correct_args(self) -> None:
        """_send_email should use smtplib.SMTP with correct host/port."""
        alert = EmailAlert(
            smtp_host="mail.test.com",
            smtp_port=465,
            username="user",
            password="pass",
            sender="from@test.com",
            recipients=["to@test.com"],
        )
        mock_server = MagicMock()
        mock_server.__enter__ = MagicMock(return_value=mock_server)
        mock_server.__exit__ = MagicMock(return_value=False)

        with patch("src.alerts.email.smtplib.SMTP", return_value=mock_server) as mock_smtp:
            result = alert._send_email("Subject", "Body")
            mock_smtp.assert_called_once_with("mail.test.com", 465, timeout=10)
            mock_server.starttls.assert_called_once()
            mock_server.login.assert_called_once_with("user", "pass")
            mock_server.sendmail.assert_called_once()
            assert result is True
