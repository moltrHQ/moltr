# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Moltr-Commercial
# Copyright (C) 2026 Walter Troska / moltrHQ <hello@moltr.tech>
# See LICENSE (AGPL-3.0) or LICENSE-COMMERCIAL for licensing terms.

"""Server-side refresh token store with inactivity timeout and KillSwitch integration."""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field

logger = logging.getLogger("moltr.auth")

INACTIVITY_TIMEOUT = 30 * 60  # 30 minutes


@dataclass
class RefreshSession:
    """A tracked refresh token session."""

    token_id: str
    username: str
    created_at: float
    last_activity: float
    revoked: bool = False


class SessionStore:
    """In-memory store for refresh token sessions."""

    def __init__(self, inactivity_timeout: int = INACTIVITY_TIMEOUT) -> None:
        self._sessions: dict[str, RefreshSession] = {}
        self._lock = threading.Lock()
        self._inactivity_timeout = inactivity_timeout

    def create(self, token_id: str, username: str) -> RefreshSession:
        """Register a new refresh token session."""
        now = time.time()
        session = RefreshSession(
            token_id=token_id,
            username=username,
            created_at=now,
            last_activity=now,
        )
        with self._lock:
            self._sessions[token_id] = session
        return session

    def validate(self, token_id: str) -> RefreshSession | None:
        """Check if a refresh token is still valid. Returns session or None.

        Note: Returns a snapshot copy — use validate_and_touch() for refresh flows
        to avoid a TOCTOU race between validate and touch.
        """
        with self._lock:
            session = self._sessions.get(token_id)
            if session is None:
                return None
            if session.revoked:
                return None
            if time.time() - session.last_activity > self._inactivity_timeout:
                session.revoked = True
                logger.info("Session %s expired (inactivity)", token_id[:8])
                return None
            # Return a snapshot so callers can't mutate live session state
            from dataclasses import replace
            return replace(session)

    def validate_and_touch(self, token_id: str) -> RefreshSession | None:
        """Atomically validate and update last_activity in one lock acquisition.

        Use this in refresh flows instead of validate() + touch() to eliminate
        the TOCTOU window between the two calls.
        """
        with self._lock:
            session = self._sessions.get(token_id)
            if session is None:
                return None
            if session.revoked:
                return None
            now = time.time()
            if now - session.last_activity > self._inactivity_timeout:
                session.revoked = True
                logger.info("Session %s expired (inactivity)", token_id[:8])
                return None
            session.last_activity = now
            from dataclasses import replace
            return replace(session)

    def touch(self, token_id: str) -> None:
        """Update last activity timestamp for a session."""
        with self._lock:
            session = self._sessions.get(token_id)
            if session and not session.revoked:
                session.last_activity = time.time()

    def revoke(self, token_id: str) -> None:
        """Revoke a specific refresh token."""
        with self._lock:
            session = self._sessions.get(token_id)
            if session:
                session.revoked = True
                logger.info("Session %s revoked", token_id[:8])

    def invalidate_all(self) -> int:
        """Invalidate ALL active sessions (KillSwitch LOCKDOWN+). Returns count."""
        count = 0
        with self._lock:
            for session in self._sessions.values():
                if not session.revoked:
                    session.revoked = True
                    count += 1
        if count:
            logger.critical("ALL %d sessions invalidated (KillSwitch)", count)
        return count

    def active_count(self) -> int:
        """Return count of active (non-revoked, non-expired) sessions."""
        now = time.time()
        with self._lock:
            return sum(
                1
                for s in self._sessions.values()
                if not s.revoked and now - s.last_activity <= self._inactivity_timeout
            )

    def cleanup(self) -> int:
        """Remove expired and revoked sessions from memory. Returns count removed."""
        now = time.time()
        removed = 0
        with self._lock:
            to_remove = [
                tid
                for tid, s in self._sessions.items()
                if s.revoked or now - s.last_activity > self._inactivity_timeout * 2
            ]
            for tid in to_remove:
                del self._sessions[tid]
                removed += 1
        return removed


# Singleton instance
session_store = SessionStore()
