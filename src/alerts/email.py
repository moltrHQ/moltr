"""Moltr email alert channel.

Sends security alerts via SMTP using Python's smtplib (stdlib).
Supports TLS/STARTTLS connections.
"""

from __future__ import annotations

import logging
import smtplib
from email.mime.text import MIMEText

from src.alerts.manager import (
    AlertChannel,
    Severity,
    SEVERITY_EMOJI,
    utc_timestamp,
)

logger = logging.getLogger("moltr.email")


class EmailAlert(AlertChannel):
    """Email notification channel using SMTP.

    Sends formatted alerts as plain-text emails.
    If any required field is empty, send() returns False.
    """

    def __init__(
        self,
        smtp_host: str = "",
        smtp_port: int = 587,
        username: str = "",
        password: str = "",
        sender: str = "",
        recipients: list[str] | None = None,
    ) -> None:
        """Initialize the email alert channel.

        Args:
            smtp_host: SMTP server hostname.
            smtp_port: SMTP server port (default 587 for STARTTLS).
            username: SMTP authentication username.
            password: SMTP authentication password.
            sender: Sender email address (From header).
            recipients: List of recipient email addresses.
        """
        self._smtp_host = smtp_host
        self._smtp_port = smtp_port
        self._username = username
        self._password = password
        self._sender = sender
        self._recipients = recipients or []

    @property
    def name(self) -> str:
        """Return the channel name."""
        return "email"

    @property
    def is_configured(self) -> bool:
        """Whether SMTP credentials and recipients are set."""
        return bool(
            self._smtp_host
            and self._sender
            and self._recipients
        )

    def send(self, severity: Severity, title: str, message: str) -> bool:
        """Send an alert email.

        Args:
            severity: Alert severity level.
            title: Short alert title (used in subject).
            message: Detailed alert message (email body).

        Returns:
            True if sent successfully, False otherwise.
        """
        if not self.is_configured:
            logger.warning("Email not configured, skipping: %s", title)
            return False
        subject = self.format_subject(severity, title)
        body = self.format_body(severity, title, message)
        return self._send_email(subject, body)

    @staticmethod
    def format_subject(severity: Severity, title: str) -> str:
        """Format the email subject line.

        Args:
            severity: Alert severity level.
            title: Short alert title.

        Returns:
            Formatted subject string.
        """
        emoji = SEVERITY_EMOJI.get(severity, "")
        return f"{emoji} [Moltr {severity.value}] {title}"

    @staticmethod
    def format_body(
        severity: Severity, title: str, message: str
    ) -> str:
        """Format the email body.

        Args:
            severity: Alert severity level.
            title: Short alert title.
            message: Detailed alert message.

        Returns:
            Formatted plain-text email body.
        """
        ts = utc_timestamp()
        return (
            f"Moltr Security Alert\n"
            f"{'=' * 40}\n"
            f"Severity: {severity.value}\n"
            f"Title: {title}\n"
            f"Time: {ts}\n"
            f"{'=' * 40}\n"
            f"\n"
            f"{message}\n"
            f"\n"
            f"-- \n"
            f"Moltr Security Proxy"
        )

    def _send_email(self, subject: str, body: str) -> bool:
        """Send an email via SMTP.

        Args:
            subject: Email subject line.
            body: Email body text.

        Returns:
            True if the email was sent successfully.
        """
        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = subject
        msg["From"] = self._sender
        msg["To"] = ", ".join(self._recipients)

        try:
            with smtplib.SMTP(self._smtp_host, self._smtp_port, timeout=10) as server:
                server.starttls()
                if self._username and self._password:
                    server.login(self._username, self._password)
                server.sendmail(self._sender, self._recipients, msg.as_string())
            return True
        except (smtplib.SMTPException, OSError) as exc:
            logger.error("Email send failed: %s", exc)
            return False
