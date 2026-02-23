# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Moltr-Commercial
# Copyright (C) 2026 Walter Troska / moltrHQ <hello@moltr.tech>
# See LICENSE (AGPL-3.0) or LICENSE-COMMERCIAL for licensing terms.

"""SafeSkills transactional email service.

SMTP via IONOS (smtp.ionos.de:587, STARTTLS).
Pattern identical to src/alerts/email.py.

Three email types:
  send_verification_email  — email-verify link
  send_password_reset_email — password-reset link
  send_api_key_email        — API key delivery (shown once)
"""

from __future__ import annotations

import logging
import os
import smtplib
from email.mime.text import MIMEText

logger = logging.getLogger("safeskills.email")

_SMTP_HOST = os.environ.get("SAFESKILLS_SMTP_HOST", "smtp.ionos.de")
_SMTP_PORT = int(os.environ.get("SAFESKILLS_SMTP_PORT", "587"))
_SMTP_USER = os.environ.get("SAFESKILLS_SMTP_USER", "")
_SMTP_PASS = os.environ.get("SAFESKILLS_SMTP_PASS", "")
_FROM_EMAIL = os.environ.get("SAFESKILLS_FROM_EMAIL", "hello@safeskills.dev")
_BASE_URL   = os.environ.get("SAFESKILLS_BASE_URL", "https://safeskills.dev")


def _send(to: str, subject: str, body: str) -> bool:
    """Send a plain-text email via STARTTLS. Returns True on success."""
    if not (_SMTP_USER and _SMTP_PASS):
        logger.warning("[Email] SMTP credentials not configured — skipping '%s' to %s", subject, to)
        return False
    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"]    = _FROM_EMAIL
    msg["To"]      = to
    try:
        with smtplib.SMTP(_SMTP_HOST, _SMTP_PORT, timeout=10) as server:
            server.starttls()
            server.login(_SMTP_USER, _SMTP_PASS)
            server.sendmail(_FROM_EMAIL, [to], msg.as_string())
        logger.info("[Email] Sent '%s' to %s", subject, to)
        return True
    except (smtplib.SMTPException, OSError) as exc:
        logger.error("[Email] Send failed to %s: %s", to, exc)
        return False


def send_verification_email(to: str, token: str) -> bool:
    """Send email-verification link. Token expires in 24 h."""
    link = f"{_BASE_URL}/api/v1/account/verify-email?token={token}"
    body = (
        f"Willkommen bei SafeSkills!\n\n"
        f"Bitte verifiziere deine E-Mail-Adresse:\n\n"
        f"  {link}\n\n"
        f"Dieser Link ist 24 Stunden gültig.\n\n"
        f"Falls du dich nicht bei SafeSkills registriert hast, ignoriere diese E-Mail.\n\n"
        f"-- SafeSkills Team\n"
        f"   {_BASE_URL}"
    )
    return _send(to, "SafeSkills — E-Mail-Adresse bestätigen", body)


def send_password_reset_email(to: str, token: str) -> bool:
    """Send password-reset link. Token expires in 2 h."""
    link = f"{_BASE_URL}/reset-password?token={token}"
    body = (
        f"Du hast ein Passwort-Reset für dein SafeSkills-Konto angefordert.\n\n"
        f"Klicke hier um ein neues Passwort zu setzen:\n\n"
        f"  {link}\n\n"
        f"Dieser Link ist 2 Stunden gültig.\n\n"
        f"Falls du keinen Reset angefordert hast, ignoriere diese E-Mail.\n"
        f"Dein Passwort bleibt unverändert.\n\n"
        f"-- SafeSkills Team\n"
        f"   {_BASE_URL}"
    )
    return _send(to, "SafeSkills — Passwort zurücksetzen", body)


def send_api_key_email(to: str, plaintext_key: str, tier: str) -> bool:
    """Send API key to customer. Key shown exactly once — never stored in plaintext."""
    body = (
        f"Dein SafeSkills API-Key ({tier} Tier) ist bereit.\n\n"
        f"API-Key:\n"
        f"  {plaintext_key}\n\n"
        f"WICHTIG: Dieser Key wird dir nur einmal zugesandt und nicht erneut angezeigt.\n"
        f"Speichere ihn sicher (z.B. in einem Passwort-Manager).\n\n"
        f"Verwendung (HTTP Header):\n"
        f"  X-API-Key: {plaintext_key}\n\n"
        f"Dokumentation: {_BASE_URL}/docs\n"
        f"Account-Dashboard: {_BASE_URL}/account\n\n"
        f"-- SafeSkills Team\n"
        f"   {_BASE_URL}"
    )
    return _send(to, f"SafeSkills — Dein API-Key ({tier} Tier)", body)
