"""Moltr Relay Registry — in-memory bot registry with PBKDF2 key hashing.

Each bot is identified by a bot_id (alphanumeric slug) and authenticated
with a relay_key (stored as PBKDF2-HMAC-SHA256 hash, never in plaintext).
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Optional

FREE_TIER_DAILY_LIMIT = 100   # messages per 24h
MAX_MESSAGE_SIZE_FREE = 2 * 1024   # 2 KB
MAX_MESSAGE_SIZE_PAID = 64 * 1024  # 64 KB


@dataclass
class RelayMessage:
    """A message queued for delivery via Moltr Relay."""
    msg_id: str
    from_bot: str
    to_bot: str
    content: str
    task_ref: Optional[str]
    created_at: float = field(default_factory=time.time)


@dataclass
class BotRecord:
    """Registration record for a relay-connected bot."""
    bot_id: str
    key_hash: str    # PBKDF2-HMAC-SHA256 hex
    key_salt: str    # random salt (hex)
    tier: str = "free"
    registered_at: float = field(default_factory=time.time)
    daily_count: int = 0
    daily_reset: float = field(default_factory=time.time)
    inbox: list = field(default_factory=list)  # list[RelayMessage]

    def check_key(self, relay_key: str) -> bool:
        """Constant-time key verification using stored PBKDF2 hash."""
        salt = bytes.fromhex(self.key_salt)
        dk = hashlib.pbkdf2_hmac("sha256", relay_key.encode(), salt, 100_000)
        return secrets.compare_digest(dk.hex(), self.key_hash)

    def check_and_increment_quota(self) -> bool:
        """Check daily quota and increment counter. Returns True if allowed."""
        now = time.time()
        if now - self.daily_reset > 86_400:
            self.daily_count = 0
            self.daily_reset = now
        if self.tier == "free" and self.daily_count >= FREE_TIER_DAILY_LIMIT:
            return False
        self.daily_count += 1
        return True

    @property
    def quota_remaining(self) -> int | str:
        if self.tier != "free":
            return "unlimited"
        return max(0, FREE_TIER_DAILY_LIMIT - self.daily_count)


class BotRegistry:
    """Thread-safe in-memory registry of registered relay bots."""

    def __init__(self) -> None:
        self._bots: dict[str, BotRecord] = {}
        self._lock = asyncio.Lock()

    async def register(self, bot_id: str, tier: str = "free") -> str:
        """Register (or re-register) a bot. Returns plaintext relay key."""
        relay_key = secrets.token_urlsafe(32)
        salt = os.urandom(16)
        dk = hashlib.pbkdf2_hmac("sha256", relay_key.encode(), salt, 100_000)
        record = BotRecord(
            bot_id=bot_id,
            key_hash=dk.hex(),
            key_salt=salt.hex(),
            tier=tier,
        )
        async with self._lock:
            self._bots[bot_id] = record
        return relay_key

    async def authenticate(self, bot_id: str, relay_key: str) -> Optional[BotRecord]:
        """Verify bot_id + relay_key. Returns BotRecord or None."""
        async with self._lock:
            record = self._bots.get(bot_id)
        if not record:
            return None
        if not record.check_key(relay_key):
            return None
        return record

    async def deliver(self, msg: RelayMessage) -> bool:
        """Append message to target bot inbox. Returns False if unknown target."""
        async with self._lock:
            target = self._bots.get(msg.to_bot)
            if not target:
                return False
            target.inbox.append(msg)
            # Cap inbox at 200 messages (oldest dropped)
            if len(target.inbox) > 200:
                target.inbox = target.inbox[-200:]
            return True

    async def drain_inbox(self, bot_id: str) -> list[RelayMessage]:
        """Atomically drain and return all messages from bot's inbox."""
        async with self._lock:
            record = self._bots.get(bot_id)
            if not record:
                return []
            msgs = list(record.inbox)
            record.inbox.clear()
            return msgs

    async def get_record(self, bot_id: str) -> Optional[BotRecord]:
        async with self._lock:
            return self._bots.get(bot_id)

    @property
    def bot_count(self) -> int:
        return len(self._bots)


# Module-level singleton
registry = BotRegistry()
