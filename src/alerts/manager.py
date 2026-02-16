"""Moltr alert manager and base channel.

Provides the abstract AlertChannel base class and the AlertManager
that dispatches alerts to all configured channels simultaneously.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from enum import Enum
from typing import Any

logger = logging.getLogger("moltr.alerts")


class Severity(Enum):
    """Alert severity levels."""

    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"
    LOCKDOWN = "LOCKDOWN"


# Severity -> emoji mapping (shared across channels)
SEVERITY_EMOJI: dict[Severity, str] = {
    Severity.INFO: "\U0001f535",        # blue circle
    Severity.WARNING: "\u26a0\ufe0f",   # warning sign
    Severity.CRITICAL: "\U0001f534",    # red circle
    Severity.LOCKDOWN: "\u2620\ufe0f",  # skull and crossbones
}

# Severity -> color mapping (for Discord embeds, Slack sidebars)
SEVERITY_COLOR: dict[Severity, int] = {
    Severity.INFO: 0x3498DB,       # blue
    Severity.WARNING: 0xF39C12,    # orange
    Severity.CRITICAL: 0xE74C3C,   # red
    Severity.LOCKDOWN: 0x8B0000,   # dark red
}


def utc_timestamp() -> str:
    """Return the current UTC timestamp as a formatted string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


class AlertChannel(ABC):
    """Abstract base class for alert channels.

    All concrete alert channels (Telegram, Slack, Discord, Email)
    must implement this interface.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the channel name (e.g. 'telegram', 'slack')."""

    @property
    @abstractmethod
    def is_configured(self) -> bool:
        """Whether this channel has valid credentials/config."""

    @abstractmethod
    def send(self, severity: Severity, title: str, message: str) -> bool:
        """Send an alert through this channel.

        Args:
            severity: Alert severity level.
            title: Short alert title.
            message: Detailed alert message.

        Returns:
            True if sent successfully, False otherwise.
        """


class AlertManager:
    """Dispatches alerts to all registered channels.

    Channels that are not configured are silently skipped.
    """

    def __init__(self) -> None:
        self._channels: list[AlertChannel] = []

    def register(self, channel: AlertChannel) -> None:
        """Register an alert channel.

        Args:
            channel: An AlertChannel implementation to add.
        """
        self._channels.append(channel)

    @property
    def channels(self) -> list[AlertChannel]:
        """Return the list of registered channels."""
        return list(self._channels)

    def send_alert(
        self, severity: Severity, title: str, message: str
    ) -> dict[str, bool]:
        """Send an alert to all configured channels.

        Unconfigured channels are skipped (result = False).

        Args:
            severity: Alert severity level.
            title: Short alert title.
            message: Detailed alert message.

        Returns:
            Dictionary mapping channel names to send success/failure.
        """
        results: dict[str, bool] = {}
        for channel in self._channels:
            if not channel.is_configured:
                logger.warning(
                    "Channel '%s' not configured, skipping", channel.name
                )
                results[channel.name] = False
                continue
            try:
                results[channel.name] = channel.send(severity, title, message)
            except Exception as exc:
                logger.error(
                    "Channel '%s' failed: %s", channel.name, exc
                )
                results[channel.name] = False
        return results
