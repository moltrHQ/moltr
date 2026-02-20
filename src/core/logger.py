# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Moltr-Commercial
# Copyright (C) 2026 Walter Troska / moltrHQ <hello@moltr.tech>
# See LICENSE (AGPL-3.0) or LICENSE-COMMERCIAL for licensing terms.

"""Moltr structured logging.

Provides a centralized, structured logger for all Moltr components
with support for different log levels and output formats.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Optional

# Patterns to redact from log context values
_SENSITIVE_PATTERNS = re.compile(
    r"(?i)"
    r"(?:sk-[a-zA-Z0-9\-_]{20,})"          # OpenAI/Anthropic keys
    r"|(?:AKIA[0-9A-Z]{16})"                 # AWS keys
    r"|(?:gh[ps]_[A-Za-z0-9]{36,})"          # GitHub tokens
    r"|(?:[0-9]{8,10}:AA[A-Za-z0-9_\-]{33})" # Telegram bot tokens
    r"|(?:eyJ[A-Za-z0-9_\-]{50,})"           # JWTs
)

_SENSITIVE_KEYS = frozenset({
    "password", "passwd", "pwd", "secret", "token", "api_key",
    "apikey", "access_key", "private_key", "codephrase", "passphrase",
    "authorization", "credential", "fernet_key", "hmac_key",
})


def _redact_value(key: str, value: Any) -> Any:
    """Redact sensitive values in log context."""
    if isinstance(value, str):
        # Redact if key name is sensitive
        if key.lower() in _SENSITIVE_KEYS:
            return "[REDACTED]"
        # Redact known secret patterns in the value
        if _SENSITIVE_PATTERNS.search(value):
            return _SENSITIVE_PATTERNS.sub("[REDACTED]", value)
    return value


class MoltrLogger:
    """Structured logger for Moltr security events.

    Wraps Python logging with structured output, correlation IDs,
    and security-event-specific formatting.
    """

    def __init__(
        self,
        name: str = "moltr",
        level: str = "INFO",
        log_dir: Optional[Path] = None,
        max_bytes: int = 10 * 1024 * 1024,  # 10 MB
        backup_count: int = 5,
    ) -> None:
        """Initialize the logger.

        Args:
            name: Logger name / component identifier.
            level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
            log_dir: Directory for log files. If None, only logs to stdout.
            max_bytes: Max size per log file before rotation (default 10 MB).
            backup_count: Number of rotated log files to keep (default 5).
        """
        self._name = name
        self._logger = logging.getLogger(f"moltr.{name}")
        self._logger.setLevel(getattr(logging, level.upper(), logging.INFO))
        self._security_file_handler: Optional[logging.Handler] = None

        fmt = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        # Only add handlers if logger has none (prevent duplicates)
        if not self._logger.handlers:
            # Console handler (always)
            console = logging.StreamHandler()
            console.setFormatter(fmt)
            self._logger.addHandler(console)

            # Rotating file handler (if log_dir provided)
            if log_dir:
                log_dir = Path(log_dir)
                log_dir.mkdir(parents=True, exist_ok=True)

                file_handler = RotatingFileHandler(
                    log_dir / f"moltr-{name}.log",
                    maxBytes=max_bytes,
                    backupCount=backup_count,
                    encoding="utf-8",
                )
                file_handler.setFormatter(fmt)
                self._logger.addHandler(file_handler)

                # Dedicated security events JSONL file
                self._security_file_handler = RotatingFileHandler(
                    log_dir / "security_events.jsonl",
                    maxBytes=max_bytes,
                    backupCount=backup_count,
                    encoding="utf-8",
                )
                self._security_file_handler.setFormatter(logging.Formatter("%(message)s"))
                self._security_file_handler.setLevel(logging.WARNING)

    def info(self, message: str, **context: Any) -> None:
        """Log an informational message.

        Args:
            message: The log message.
            **context: Additional structured context fields.
        """
        self._log(logging.INFO, message, context)

    def warning(self, message: str, **context: Any) -> None:
        """Log a warning message.

        Args:
            message: The log message.
            **context: Additional structured context fields.
        """
        self._log(logging.WARNING, message, context)

    def error(self, message: str, **context: Any) -> None:
        """Log an error message.

        Args:
            message: The log message.
            **context: Additional structured context fields.
        """
        self._log(logging.ERROR, message, context)

    def security_event(self, event_type: str, severity: str, details: dict[str, Any]) -> None:
        """Log a structured security event.

        Args:
            event_type: Type of security event (e.g. 'blocked_request', 'honeypot_access').
            severity: Severity level (low, medium, high, critical).
            details: Event-specific detail fields.
        """
        # Redact sensitive data in details
        safe_details = {k: _redact_value(k, v) for k, v in details.items()}

        event = {
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "component": self._name,
            "event_type": event_type,
            "severity": severity.upper(),
            **safe_details,
        }
        level = {
            "low": logging.INFO,
            "medium": logging.WARNING,
            "high": logging.ERROR,
            "critical": logging.CRITICAL,
        }.get(severity.lower(), logging.WARNING)

        json_line = json.dumps(event, ensure_ascii=False, default=str)
        self._logger.log(level, json_line)

        # Write to dedicated security events file
        if self._security_file_handler:
            record = logging.LogRecord(
                name="security", level=level, pathname="", lineno=0,
                msg=json_line, args=(), exc_info=None,
            )
            self._security_file_handler.emit(record)

    def _log(self, level: int, message: str, context: dict[str, Any]) -> None:
        """Internal log helper that appends structured context with redaction."""
        if context:
            safe_ctx = {k: _redact_value(k, v) for k, v in context.items()}
            ctx_str = " ".join(f"{k}={v!r}" for k, v in safe_ctx.items())
            self._logger.log(level, "%s | %s", message, ctx_str)
        else:
            self._logger.log(level, message)
