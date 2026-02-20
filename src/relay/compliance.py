"""Moltr Relay Compliance Layer — persistent message store + owner accounts.

Provides:
  - relay_owners: owner accounts with tier, max_bots
  - relay_messages: persistent message log with TTL (DSGVO Art. 17)
  - relay_flags: flagged messages (Kontrollinstanz)
  - relay_kontrollinstanz: webhook registrations for compliance AI

Encryption: if RELAY_ENCRYPT_AT_REST=true, message content is encrypted
using Fernet (RELAY_FERNET_KEY or MOLTR_FERNET_KEY fallback).

Ada's recommendation (2026-02-20): TLS-in-transit + PostgreSQL disk encryption
suffices for standard relay messages (no highly sensitive PII). App-layer
encryption (Fernet) is optional — enable via RELAY_ENCRYPT_AT_REST=true when
strict compliance (ISO 27001, BSI IT-Grundschutz) or PII content is involved.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
import time
from typing import Any, Optional

logger = logging.getLogger("moltr.relay.compliance")

# PostgreSQL pool (shared from registry.init_db())
_pool = None

# Fernet encryption (optional, off by default per Ada's recommendation)
_encrypt = False
_fernet = None

# Message TTL per tier (DSGVO-compliant retention limits)
_TTL_FREE = 7 * 86_400       # 7 days
_TTL_PRO = 30 * 86_400       # 30 days
_TTL_ENTERPRISE = 365 * 86_400  # 1 year


# ── Initialisation ────────────────────────────────────────────────────────────

async def init_compliance_db(pool) -> None:
    """Create compliance tables and configure encryption. Called once at startup."""
    global _pool, _encrypt, _fernet
    _pool = pool

    if not pool:
        logger.info("[Compliance] No DB pool — running without persistence")
        return

    # Optional Fernet encryption (Ada: off by default, enable for strict compliance)
    if os.environ.get("RELAY_ENCRYPT_AT_REST", "false").lower() == "true":
        fernet_key = os.environ.get("RELAY_FERNET_KEY") or os.environ.get("MOLTR_FERNET_KEY")
        if fernet_key:
            try:
                from cryptography.fernet import Fernet
                key_bytes = fernet_key.encode() if isinstance(fernet_key, str) else fernet_key
                _fernet = Fernet(key_bytes)
                _encrypt = True
                logger.info("[Compliance] Encryption at rest ENABLED (Fernet)")
            except Exception as e:
                logger.error("[Compliance] Fernet init failed: %s — encryption disabled", e)
        else:
            logger.warning("[Compliance] RELAY_ENCRYPT_AT_REST=true but no key set — disabled")

    try:
        async with pool.acquire() as conn:
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS relay_owners (
                    id           SERIAL PRIMARY KEY,
                    owner_token  TEXT UNIQUE NOT NULL,
                    name         TEXT NOT NULL,
                    address      TEXT NOT NULL,
                    email        TEXT UNIQUE NOT NULL,
                    tier         TEXT NOT NULL DEFAULT 'free',
                    max_bots     INTEGER NOT NULL DEFAULT 2,
                    created_at   DOUBLE PRECISION NOT NULL,
                    deleted_at   DOUBLE PRECISION
                )
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS relay_messages (
                    id                SERIAL PRIMARY KEY,
                    msg_id            TEXT UNIQUE NOT NULL,
                    from_bot          TEXT NOT NULL,
                    to_bot            TEXT NOT NULL,
                    content           TEXT NOT NULL,
                    content_encrypted BOOLEAN NOT NULL DEFAULT FALSE,
                    flagged           BOOLEAN NOT NULL DEFAULT FALSE,
                    created_at        DOUBLE PRECISION NOT NULL,
                    expires_at        DOUBLE PRECISION NOT NULL
                )
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS relay_flags (
                    id         SERIAL PRIMARY KEY,
                    msg_id     TEXT NOT NULL,
                    flagged_by TEXT NOT NULL,
                    reason     TEXT NOT NULL,
                    created_at DOUBLE PRECISION NOT NULL
                )
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS relay_kontrollinstanz (
                    id          SERIAL PRIMARY KEY,
                    webhook_id  TEXT UNIQUE NOT NULL,
                    webhook_url TEXT NOT NULL,
                    owner_token TEXT,
                    created_at  DOUBLE PRECISION NOT NULL,
                    active      BOOLEAN NOT NULL DEFAULT TRUE
                )
            """)
            # Add owner association to relay_bots (non-breaking ALTER)
            await conn.execute("""
                ALTER TABLE relay_bots
                    ADD COLUMN IF NOT EXISTS owner_token TEXT
            """)
        logger.info("[Compliance] DB tables ready (encrypt_at_rest=%s)", _encrypt)
    except Exception as e:
        logger.error("[Compliance] Table init failed: %s", e)


# ── Encryption helpers ────────────────────────────────────────────────────────

def _enc(text: str) -> tuple[str, bool]:
    """Encrypt if configured. Returns (stored_value, was_encrypted)."""
    if _fernet and _encrypt:
        return _fernet.encrypt(text.encode()).decode(), True
    return text, False


def _dec(text: str, encrypted: bool) -> str:
    """Decrypt if needed."""
    if encrypted and _fernet:
        try:
            return _fernet.decrypt(text.encode()).decode()
        except Exception:
            return "[DECRYPTION_ERROR]"
    return text


# ── Core functions ────────────────────────────────────────────────────────────

async def persist_message(msg: Any, ttl_seconds: int = _TTL_FREE) -> None:
    """Persist a relay message. Notifies SSE listeners and webhooks."""
    if not _pool:
        return

    content_stored, encrypted = _enc(msg.content)
    now = time.time()

    try:
        async with _pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO relay_messages
                    (msg_id, from_bot, to_bot, content, content_encrypted, created_at, expires_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                ON CONFLICT (msg_id) DO NOTHING
            """, msg.msg_id, msg.from_bot, msg.to_bot,
                content_stored, encrypted, now, now + ttl_seconds)
    except Exception as e:
        logger.error("[Compliance] persist_message failed: %s", e)

    # Notify SSE + Kontrollinstanz (fire-and-forget)
    msg_data = {
        "msg_id": msg.msg_id,
        "from": msg.from_bot,
        "to": msg.to_bot,
        "content": msg.content,  # always plaintext to SSE
        "ts": now,
        "flagged": False,
    }
    _broadcast_sse(msg_data)
    asyncio.create_task(_notify_webhooks(msg_data))


async def get_messages(
    owner_token: Optional[str] = None,
    is_admin: bool = False,
    limit: int = 100,
) -> list[dict]:
    """Fetch non-expired messages. Admin sees all; owner sees own bots only."""
    if not _pool:
        return []
    try:
        now = time.time()
        async with _pool.acquire() as conn:
            if is_admin:
                rows = await conn.fetch(
                    "SELECT * FROM relay_messages WHERE expires_at > $1 "
                    "ORDER BY created_at DESC LIMIT $2",
                    now, limit,
                )
            elif owner_token:
                rows = await conn.fetch("""
                    SELECT m.* FROM relay_messages m
                    WHERE m.expires_at > $1
                      AND (
                        m.from_bot IN (SELECT bot_id FROM relay_bots WHERE owner_token=$2)
                        OR m.to_bot IN (SELECT bot_id FROM relay_bots WHERE owner_token=$2)
                      )
                    ORDER BY m.created_at DESC LIMIT $3
                """, now, owner_token, limit)
            else:
                return []

        return [
            {
                "msg_id": row["msg_id"],
                "from": row["from_bot"],
                "to": row["to_bot"],
                "content": _dec(row["content"], row["content_encrypted"]),
                "flagged": row["flagged"],
                "created_at": row["created_at"],
                "expires_at": row["expires_at"],
            }
            for row in rows
        ]
    except Exception as e:
        logger.error("[Compliance] get_messages failed: %s", e)
        return []


async def register_owner(name: str, address: str, email: str, tier: str = "free") -> dict:
    """Register a new owner account. Returns owner_token (return once, store securely)."""
    owner_token = secrets.token_urlsafe(32)
    now = time.time()
    max_bots = {"free": 2, "pro": 20, "enterprise": 999}.get(tier, 2)

    if _pool:
        async with _pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO relay_owners
                    (owner_token, name, address, email, tier, max_bots, created_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
            """, owner_token, name, address, email, tier, max_bots, now)

    return {"owner_token": owner_token, "tier": tier, "max_bots": max_bots}


async def get_owner_by_token(owner_token: str) -> Optional[dict]:
    """Look up a non-deleted owner by token."""
    if not _pool:
        return None
    try:
        async with _pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM relay_owners WHERE owner_token=$1 AND deleted_at IS NULL",
                owner_token,
            )
        return dict(row) if row else None
    except Exception as e:
        logger.error("[Compliance] get_owner_by_token failed: %s", e)
        return None


async def link_bot(owner_token: str, bot_id: str, relay_key: str) -> bool:
    """Associate a registered bot with an owner (verifies relay_key)."""
    from src.relay.registry import registry
    record = await registry.authenticate(bot_id, relay_key)
    if not record:
        return False
    if not _pool:
        return False
    try:
        async with _pool.acquire() as conn:
            result = await conn.execute(
                "UPDATE relay_bots SET owner_token=$1 WHERE bot_id=$2",
                owner_token, bot_id,
            )
        return result.endswith("1")
    except Exception as e:
        logger.error("[Compliance] link_bot failed: %s", e)
        return False


async def delete_owner_data(owner_token: str) -> int:
    """DSGVO Art. 17 — Right to erasure. Returns count of deleted messages."""
    if not _pool:
        return 0
    try:
        async with _pool.acquire() as conn:
            bot_rows = await conn.fetch(
                "SELECT bot_id FROM relay_bots WHERE owner_token=$1", owner_token
            )
            bot_ids = [r["bot_id"] for r in bot_rows]
            deleted = 0
            if bot_ids:
                result = await conn.execute("""
                    DELETE FROM relay_messages
                    WHERE from_bot = ANY($1::text[]) OR to_bot = ANY($1::text[])
                """, bot_ids)
                try:
                    deleted = int(result.split()[-1])
                except Exception:
                    pass
                await conn.execute(
                    "UPDATE relay_bots SET owner_token=NULL WHERE owner_token=$1",
                    owner_token,
                )
            await conn.execute(
                "UPDATE relay_owners SET deleted_at=$1 WHERE owner_token=$2",
                time.time(), owner_token,
            )
        logger.info(
            "[Compliance] DSGVO erasure: ...%s — %d messages deleted",
            owner_token[-8:], deleted,
        )
        return deleted
    except Exception as e:
        logger.error("[Compliance] delete_owner_data failed: %s", e)
        return 0


async def flag_message(msg_id: str, flagged_by: str, reason: str) -> bool:
    """Flag a message for review."""
    if not _pool:
        return False
    try:
        async with _pool.acquire() as conn:
            result = await conn.execute(
                "UPDATE relay_messages SET flagged=TRUE WHERE msg_id=$1", msg_id
            )
            if not result.endswith("1"):
                return False
            await conn.execute(
                "INSERT INTO relay_flags (msg_id, flagged_by, reason, created_at) "
                "VALUES ($1,$2,$3,$4)",
                msg_id, flagged_by, reason, time.time(),
            )
        return True
    except Exception as e:
        logger.error("[Compliance] flag_message failed: %s", e)
        return False


async def register_kontrollinstanz(
    webhook_url: str,
    owner_token: Optional[str] = None,
) -> str:
    """Register a Kontrollinstanz webhook URL. Returns webhook_id."""
    webhook_id = secrets.token_urlsafe(16)
    if _pool:
        async with _pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO relay_kontrollinstanz
                    (webhook_id, webhook_url, owner_token, created_at)
                VALUES ($1, $2, $3, $4)
            """, webhook_id, webhook_url, owner_token, time.time())
    return webhook_id


async def get_active_webhooks() -> list[str]:
    """Get all active Kontrollinstanz webhook URLs."""
    if not _pool:
        return []
    try:
        async with _pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT webhook_url FROM relay_kontrollinstanz WHERE active=TRUE"
            )
        return [r["webhook_url"] for r in rows]
    except Exception as e:
        logger.error("[Compliance] get_active_webhooks failed: %s", e)
        return []


# ── SSE Broadcast ─────────────────────────────────────────────────────────────

_sse_queues: list[asyncio.Queue] = []


def _broadcast_sse(msg_data: dict) -> None:
    """Push message to all active SSE listener queues (sync, best-effort)."""
    for q in list(_sse_queues):
        try:
            q.put_nowait(msg_data)
        except asyncio.QueueFull:
            pass


def register_sse_queue(q: asyncio.Queue) -> None:
    _sse_queues.append(q)


def unregister_sse_queue(q: asyncio.Queue) -> None:
    try:
        _sse_queues.remove(q)
    except ValueError:
        pass


# ── Kontrollinstanz webhook notifier ──────────────────────────────────────────

async def _notify_webhooks(msg_data: dict) -> None:
    """POST message to all active Kontrollinstanz webhooks (fire-and-forget)."""
    urls = await get_active_webhooks()
    if not urls:
        return
    payload = json.dumps(msg_data).encode()
    loop = asyncio.get_event_loop()
    for url in urls:
        try:
            await loop.run_in_executor(None, _post_webhook, url, payload)
        except Exception as e:
            logger.debug("[Compliance] Webhook %s failed: %s", url[:50], e)


def _post_webhook(url: str, payload: bytes) -> None:
    import urllib.request
    req = urllib.request.Request(
        url, data=payload,
        headers={"Content-Type": "application/json", "X-Moltr-Relay": "1"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5):
            pass
    except Exception:
        pass
