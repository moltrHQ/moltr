# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Moltr-Commercial
# Copyright (C) 2026 Walter Troska / moltrHQ <hello@moltr.tech>
# See LICENSE (AGPL-3.0) or LICENSE-COMMERCIAL for licensing terms.

"""Moltr kill switch manager.

Provides 5 escalation levels for emergency response:
PAUSE, NETWORK_CUT, LOCKDOWN, WIPE, EMERGENCY.
Each trigger and reset is logged with timestamp and reason.
Reset requires a codephrase set during initialization.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from enum import IntEnum
from typing import Optional


class EscalationLevel(IntEnum):
    """Kill switch escalation levels, ordered by severity."""

    PAUSE = 1       # Agent paused
    NETWORK_CUT = 2 # Network disconnected
    LOCKDOWN = 3    # All actions blocked
    WIPE = 4        # Credentials deleted
    EMERGENCY = 5   # Container stopped


@dataclass
class KillSwitchEvent:
    """A logged kill switch event."""

    timestamp: float
    action: str       # "trigger" | "reset"
    level: EscalationLevel
    reason: str


@dataclass
class KillSwitchStatus:
    """Current kill switch status."""

    active_levels: set[EscalationLevel]
    is_locked_down: bool
    highest_level: Optional[EscalationLevel]


class KillSwitch:
    """Kill switch manager with 5 escalation levels.

    Each level can be triggered independently. Reset requires
    a codephrase that was set during initialization.
    All events are logged with timestamps.
    """

    def __init__(self, reset_codephrase: str = "") -> None:
        """Initialize the kill switch.

        Args:
            reset_codephrase: Secret phrase required to reset levels.
        """
        self._codephrase = reset_codephrase
        self._active: set[EscalationLevel] = set()
        self._log: list[KillSwitchEvent] = []

    def trigger(self, level: EscalationLevel, reason: str = "") -> None:
        """Activate a kill switch level.

        Args:
            level: The escalation level to activate.
            reason: Human-readable reason for the trigger.
        """
        self._active.add(level)
        self._log.append(KillSwitchEvent(
            timestamp=time.time(),
            action="trigger",
            level=level,
            reason=reason,
        ))

    def reset(self, level: EscalationLevel, codephrase: str = "") -> bool:
        """Deactivate a kill switch level.

        Args:
            level: The escalation level to deactivate.
            codephrase: Must match the codephrase set at init.

        Returns:
            True if reset succeeded, False if codephrase was wrong.
        """
        if codephrase != self._codephrase:
            return False

        self._active.discard(level)
        self._log.append(KillSwitchEvent(
            timestamp=time.time(),
            action="reset",
            level=level,
            reason=f"Reset by operator",
        ))
        return True

    def get_status(self) -> KillSwitchStatus:
        """Return the current kill switch status.

        Returns:
            KillSwitchStatus with active levels, lockdown flag, highest level.
        """
        highest = max(self._active) if self._active else None
        is_locked = any(
            lvl >= EscalationLevel.LOCKDOWN for lvl in self._active
        )
        return KillSwitchStatus(
            active_levels=set(self._active),
            is_locked_down=is_locked,
            highest_level=highest,
        )

    def get_log(self) -> list[KillSwitchEvent]:
        """Return all logged events.

        Returns:
            List of KillSwitchEvent in chronological order.
        """
        return list(self._log)
