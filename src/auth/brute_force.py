# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Moltr-Commercial
# Copyright (C) 2026 Walter Troska / moltrHQ <hello@moltr.tech>
# See LICENSE (AGPL-3.0) or LICENSE-COMMERCIAL for licensing terms.

"""Brute-force protection for login endpoint."""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field

logger = logging.getLogger("moltr.auth")

MAX_ATTEMPTS_PER_MINUTE = 5
LOCKOUT_ATTEMPTS = 10
LOCKOUT_DURATION = 15 * 60  # 15 minutes
PROGRESSIVE_DELAY_START = 3  # Start delays after this many failures


@dataclass
class LoginAttemptTracker:
    """Tracks failed login attempts for a single IP."""

    ip: str
    attempts: list[float] = field(default_factory=list)
    total_failures: int = 0
    locked_until: float = 0.0


class BruteForceGuard:
    """Guards login endpoint against brute-force attacks."""

    def __init__(
        self,
        max_per_minute: int = MAX_ATTEMPTS_PER_MINUTE,
        lockout_after: int = LOCKOUT_ATTEMPTS,
        lockout_seconds: int = LOCKOUT_DURATION,
    ) -> None:
        self._trackers: dict[str, LoginAttemptTracker] = {}
        self._lock = threading.Lock()
        self._max_per_minute = max_per_minute
        self._lockout_after = lockout_after
        self._lockout_seconds = lockout_seconds

    def check_allowed(self, ip: str) -> tuple[bool, str, float]:
        """Check if a login attempt is allowed.

        Returns: (allowed, reason, delay_seconds)
        """
        now = time.time()

        with self._lock:
            tracker = self._trackers.get(ip)
            if tracker is None:
                return True, "", 0.0

            # Check lockout
            if tracker.locked_until > now:
                remaining = tracker.locked_until - now
                return False, f"Account locked for {int(remaining)}s", 0.0

            # Clean old attempts (older than 60s)
            tracker.attempts = [t for t in tracker.attempts if now - t < 60]

            # Check rate limit
            if len(tracker.attempts) >= self._max_per_minute:
                return False, "Too many attempts, try again in 1 minute", 0.0

            # Calculate progressive delay
            delay = 0.0
            if tracker.total_failures >= PROGRESSIVE_DELAY_START:
                excess = tracker.total_failures - PROGRESSIVE_DELAY_START
                delay = min(2 ** excess, 30.0)  # 1, 2, 4, 8, 16, 30 max

            return True, "", delay

    def record_failure(self, ip: str) -> None:
        """Record a failed login attempt."""
        now = time.time()

        with self._lock:
            tracker = self._trackers.get(ip)
            if tracker is None:
                tracker = LoginAttemptTracker(ip=ip)
                self._trackers[ip] = tracker

            tracker.attempts.append(now)
            tracker.total_failures += 1

            if tracker.total_failures >= self._lockout_after:
                tracker.locked_until = now + self._lockout_seconds
                logger.warning(
                    "IP %s locked out for %ds after %d failed attempts",
                    self._pseudonymize_ip(ip),
                    self._lockout_seconds,
                    tracker.total_failures,
                )

    def record_success(self, ip: str) -> None:
        """Reset tracker on successful login."""
        with self._lock:
            self._trackers.pop(ip, None)

    def cleanup(self) -> int:
        """Remove stale trackers. Returns count removed."""
        now = time.time()
        removed = 0
        with self._lock:
            to_remove = [
                ip
                for ip, t in self._trackers.items()
                if t.locked_until < now and not t.attempts
            ]
            for ip in to_remove:
                del self._trackers[ip]
                removed += 1
        return removed

    @staticmethod
    def _pseudonymize_ip(ip: str) -> str:
        """Pseudonymize IP for logging (null last octet)."""
        parts = ip.split(".")
        if len(parts) == 4:
            parts[-1] = "0"
            return ".".join(parts)
        return ip


# Singleton instance
brute_force_guard = BruteForceGuard()
