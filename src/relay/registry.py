"""Moltr Relay Registry — bot registry with PBKDF2 key hashing.

In-memory store for fast access, PostgreSQL for persistence.
If RELAY_DB_URL is not set, falls back to pure in-memory (dev mode).

Bot registrations survive restarts. Inbox messages are ephemeral (in-memory).
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("moltr.relay.registry")

FREE_TIER_DAILY_LIMIT = 100    # messages per 24h
MAX_MESSAGE_SIZE_FREE = 2 * 1024    # 2 KB
MAX_MESSAGE_SIZE_PAID = 64 * 1024   # 64 KB

# PostgreSQL connection pool (asyncpg), None if no DB configured
_pool = None


async def init_db() -> None:
    """Connect to PostgreSQL and create schema. Called once at startup."""
    global _pool
    db_url = os.environ.get("RELAY_DB_URL", "")
    if not db_url:
        logger.info("[Relay] No RELAY_DB_URL set — running in-memory only (dev mode)")
        return
    try:
        import asyncpg
        _pool = await asyncpg.create_pool(db_url, min_size=1, max_size=5)
        async with _pool.acquire() as conn:
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS relay_bots (
                    bot_id       TEXT PRIMARY KEY,
                    key_hash     TEXT NOT NULL,
                    key_salt     TEXT NOT NULL,
                    tier         TEXT NOT NULL DEFAULT 'free',
                    registered_at DOUBLE PRECISION NOT NULL,
                    daily_count  INTEGER NOT NULL DEFAULT 0,
                    daily_reset  DOUBLE PRECISION NOT NULL
                )
            """)
        logger.info("[Relay] PostgreSQL connected, schema ready")
    except Exception as e:
        logger.error("[Relay] DB init failed: %s — falling back to in-memory", e)
        _pool = None


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class RelayMessage:
    """A message queued for delivery (ephemeral, in-memory only)."""
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
    inbox: list = field(default_factory=list)  # list[RelayMessage] — in-memory only

    def check_key(self, relay_key: str) -> bool:
        """Constant-time key verification using PBKDF2 hash."""
        salt = bytes.fromhex(self.key_salt)
        dk = hashlib.pbkdf2_hmac("sha256", relay_key.encode(), salt, 100_000)
        return secrets.compare_digest(dk.hex(), self.key_hash)

    def check_and_increment_quota(self) -> bool:
        """Check daily quota and increment. Returns True if allowed."""
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


# ── Registry ─────────────────────────────────────────────────────────────────

class BotRegistry:
    """Thread-safe bot registry. In-memory for speed, PostgreSQL for durability."""

    def __init__(self) -> None:
        self._bots: dict[str, BotRecord] = {}
        self._lock = asyncio.Lock()

    async def load_from_db(self) -> None:
        """Load all registered bots from PostgreSQL into memory."""
        if not _pool:
            return
        try:
            async with _pool.acquire() as conn:
                rows = await conn.fetch("SELECT * FROM relay_bots")
            async with self._lock:
                for row in rows:
                    self._bots[row["bot_id"]] = BotRecord(
                        bot_id=row["bot_id"],
                        key_hash=row["key_hash"],
                        key_salt=row["key_salt"],
                        tier=row["tier"],
                        registered_at=row["registered_at"],
                        daily_count=row["daily_count"],
                        daily_reset=row["daily_reset"],
                    )
            logger.info("[Relay] Loaded %d bot(s) from PostgreSQL", len(rows))
        except Exception as e:
            logger.error("[Relay] Failed to load bots from DB: %s", e)

    async def register(self, bot_id: str, tier: str = "free") -> str:
        """Register (or re-register) a bot. Returns plaintext relay key."""
        relay_key = secrets.token_urlsafe(32)
        salt = os.urandom(16)
        dk = hashlib.pbkdf2_hmac("sha256", relay_key.encode(), salt, 100_000)
        now = time.time()
        record = BotRecord(
            bot_id=bot_id,
            key_hash=dk.hex(),
            key_salt=salt.hex(),
            tier=tier,
            registered_at=now,
            daily_reset=now,
        )
        async with self._lock:
            self._bots[bot_id] = record

        # Persist to DB
        if _pool:
            try:
                async with _pool.acquire() as conn:
                    await conn.execute("""
                        INSERT INTO relay_bots
                            (bot_id, key_hash, key_salt, tier, registered_at, daily_count, daily_reset)
                        VALUES ($1, $2, $3, $4, $5, $6, $7)
                        ON CONFLICT (bot_id) DO UPDATE SET
                            key_hash=EXCLUDED.key_hash,
                            key_salt=EXCLUDED.key_salt,
                            tier=EXCLUDED.tier,
                            registered_at=EXCLUDED.registered_at,
                            daily_count=0,
                            daily_reset=EXCLUDED.daily_reset
                    """, bot_id, dk.hex(), salt.hex(), tier, now, 0, now)
            except Exception as e:
                logger.error("[Relay] DB persist failed for %s: %s", bot_id, e)

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
        """Append message to target bot inbox (in-memory). Returns False if unknown."""
        async with self._lock:
            target = self._bots.get(msg.to_bot)
            if not target:
                return False
            target.inbox.append(msg)
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

    async def set_tier(self, bot_id: str, tier: str) -> bool:
        """Update the tier of an existing bot. Returns False if bot not found."""
        valid_tier = tier.lower() if tier.lower() in ("free", "paid") else "free"
        async with self._lock:
            record = self._bots.get(bot_id)
            if not record:
                return False
            record.tier = valid_tier

        # Persist to DB
        if _pool:
            try:
                async with _pool.acquire() as conn:
                    await conn.execute(
                        "UPDATE relay_bots SET tier=$1 WHERE bot_id=$2",
                        valid_tier, bot_id,
                    )
            except Exception as e:
                logger.error("[Relay] DB tier-update failed for %s: %s", bot_id, e)

        logger.info("[Relay] Tier updated: %s → %s", bot_id, valid_tier)
        return True

    @property
    def bot_count(self) -> int:
        return len(self._bots)


def get_pool():
    """Return the active asyncpg pool (or None in dev/in-memory mode)."""
    return _pool


# Module-level singleton
registry = BotRegistry()
