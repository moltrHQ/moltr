# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Moltr-Commercial
# Copyright (C) 2026 Walter Troska / moltrHQ <hello@moltr.tech>
# See LICENSE (AGPL-3.0) or LICENSE-COMMERCIAL for licensing terms.

"""SafeSkills Account Store — User accounts with PostgreSQL via asyncpg.

Pattern mirrors src/relay/registry.py:
- Module-level asyncpg pool (_pool)
- init_account_db() creates schema, called once from server.py lifespan
- AccountStore singleton for all account operations
- safeskills_accounts: persistent user data
- safeskills_tokens: one-time tokens (email-verify, password-reset)
"""

from __future__ import annotations

import hashlib
import logging
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

logger = logging.getLogger("safeskills.account_store")

# asyncpg connection pool — None if DB not configured
_pool = None


async def init_account_db() -> None:
    """Connect to PostgreSQL and create schema. Called once at startup."""
    global _pool
    db_url = os.environ.get("SAFESKILLS_DB_URL") or os.environ.get("RELAY_DB_URL", "")
    if not db_url:
        logger.warning("[AccountStore] No SAFESKILLS_DB_URL set — account features disabled")
        return
    try:
        import asyncpg
        _pool = await asyncpg.create_pool(db_url, min_size=1, max_size=5)
        async with _pool.acquire() as conn:
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS safeskills_accounts (
                    id                         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    email                      TEXT UNIQUE NOT NULL,
                    password_hash              TEXT NOT NULL,
                    email_verified             BOOLEAN NOT NULL DEFAULT FALSE,
                    created_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    stripe_customer_id         TEXT,
                    stripe_subscription_id     TEXT,
                    stripe_subscription_status TEXT,
                    tier                       TEXT NOT NULL DEFAULT 'free',
                    api_key_prefix             TEXT,
                    refresh_token_jti_hash     TEXT
                )
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS safeskills_tokens (
                    token_hash   TEXT PRIMARY KEY,
                    account_id   UUID NOT NULL
                                 REFERENCES safeskills_accounts(id) ON DELETE CASCADE,
                    token_type   TEXT NOT NULL,
                    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    expires_at   TIMESTAMPTZ NOT NULL,
                    used         BOOLEAN NOT NULL DEFAULT FALSE
                )
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_ss_tokens_account
                ON safeskills_tokens(account_id)
            """)
        logger.info("[AccountStore] PostgreSQL connected, schema ready")
    except Exception as exc:
        logger.error("[AccountStore] DB init failed: %s — account features disabled", exc)
        _pool = None


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


# Sentinel for update_stripe: distinguishes "don't update" from "set to NULL"
_UNSET = object()


@dataclass
class AccountRecord:
    id: str
    email: str
    password_hash: str
    email_verified: bool
    created_at: datetime
    stripe_customer_id: Optional[str]
    stripe_subscription_id: Optional[str]
    stripe_subscription_status: Optional[str]
    tier: str
    api_key_prefix: Optional[str]
    refresh_token_jti_hash: Optional[str]


def _row_to_account(row) -> AccountRecord:
    return AccountRecord(
        id=str(row["id"]),
        email=row["email"],
        password_hash=row["password_hash"],
        email_verified=row["email_verified"],
        created_at=row["created_at"],
        stripe_customer_id=row.get("stripe_customer_id"),
        stripe_subscription_id=row.get("stripe_subscription_id"),
        stripe_subscription_status=row.get("stripe_subscription_status"),
        tier=row["tier"],
        api_key_prefix=row.get("api_key_prefix"),
        refresh_token_jti_hash=row.get("refresh_token_jti_hash"),
    )


class AccountStore:
    """User account operations backed by PostgreSQL."""

    def is_available(self) -> bool:
        return _pool is not None

    def _require_pool(self):
        if not _pool:
            raise RuntimeError("Account database not configured (SAFESKILLS_DB_URL missing)")

    # ── Account CRUD ──────────────────────────────────────────────────────────

    async def create_account(self, email: str, password_hash: str) -> Optional[AccountRecord]:
        """Insert new account. Returns None on duplicate email or DB error."""
        self._require_pool()
        try:
            async with _pool.acquire() as conn:
                row = await conn.fetchrow(
                    """
                    INSERT INTO safeskills_accounts (email, password_hash)
                    VALUES ($1, $2)
                    RETURNING *
                    """,
                    email.lower().strip(), password_hash,
                )
            return _row_to_account(row) if row else None
        except Exception:
            # Most likely a unique-constraint violation (duplicate email)
            return None

    async def get_by_email(self, email: str) -> Optional[AccountRecord]:
        self._require_pool()
        async with _pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM safeskills_accounts WHERE email = $1",
                email.lower().strip(),
            )
        return _row_to_account(row) if row else None

    async def get_by_id(self, account_id: str) -> Optional[AccountRecord]:
        self._require_pool()
        async with _pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM safeskills_accounts WHERE id = $1::uuid",
                account_id,
            )
        return _row_to_account(row) if row else None

    async def get_by_stripe_customer(self, stripe_customer_id: str) -> Optional[AccountRecord]:
        self._require_pool()
        async with _pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM safeskills_accounts WHERE stripe_customer_id = $1",
                stripe_customer_id,
            )
        return _row_to_account(row) if row else None

    async def get_by_stripe_subscription(self, stripe_subscription_id: str) -> Optional[AccountRecord]:
        self._require_pool()
        async with _pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM safeskills_accounts WHERE stripe_subscription_id = $1",
                stripe_subscription_id,
            )
        return _row_to_account(row) if row else None

    async def verify_email(self, account_id: str) -> bool:
        self._require_pool()
        async with _pool.acquire() as conn:
            result = await conn.execute(
                "UPDATE safeskills_accounts SET email_verified = TRUE WHERE id = $1::uuid",
                account_id,
            )
        return result != "UPDATE 0"

    async def update_password(self, account_id: str, password_hash: str) -> bool:
        self._require_pool()
        async with _pool.acquire() as conn:
            result = await conn.execute(
                "UPDATE safeskills_accounts SET password_hash = $1 WHERE id = $2::uuid",
                password_hash, account_id,
            )
        return result != "UPDATE 0"

    async def update_refresh_jti(self, account_id: str, jti_hash: Optional[str]) -> None:
        """Store SHA-256 hash of refresh JTI (never plaintext)."""
        self._require_pool()
        async with _pool.acquire() as conn:
            await conn.execute(
                "UPDATE safeskills_accounts SET refresh_token_jti_hash = $1 WHERE id = $2::uuid",
                jti_hash, account_id,
            )

    async def update_stripe(
        self,
        account_id: str,
        *,
        stripe_customer_id: Optional[str] = _UNSET,
        stripe_subscription_id: Optional[str] = _UNSET,
        stripe_subscription_status: Optional[str] = _UNSET,
        tier: Optional[str] = _UNSET,
        api_key_prefix: Optional[str] = _UNSET,
    ) -> bool:
        """Partial update of Stripe-related fields.

        Pass a value to update it (including None to clear to NULL).
        Omit a parameter or use the _UNSET sentinel to leave it unchanged.
        This allows explicitly setting a field to NULL (api_key_prefix=None) vs
        leaving it untouched (api_key_prefix not passed = _UNSET default).
        """
        self._require_pool()
        fields, vals = [], []
        idx = 1
        for col, val in [
            ("stripe_customer_id", stripe_customer_id),
            ("stripe_subscription_id", stripe_subscription_id),
            ("stripe_subscription_status", stripe_subscription_status),
            ("tier", tier),
            ("api_key_prefix", api_key_prefix),
        ]:
            if val is not _UNSET:
                fields.append(f"{col} = ${idx}")
                vals.append(val)
                idx += 1
        if not fields:
            return False
        vals.append(account_id)
        async with _pool.acquire() as conn:
            result = await conn.execute(
                f"UPDATE safeskills_accounts SET {', '.join(fields)} WHERE id = ${idx}::uuid",
                *vals,
            )
        return result != "UPDATE 0"

    # ── One-time tokens (email-verify + password-reset) ───────────────────────

    async def create_token(
        self, account_id: str, token_type: str, ttl_hours: int = 24
    ) -> str:
        """Generate and persist a one-time token. Returns plaintext (shown once)."""
        self._require_pool()
        plaintext = secrets.token_urlsafe(32)
        token_hash = _sha256(plaintext)
        expires_at = datetime.now(timezone.utc) + timedelta(hours=ttl_hours)
        async with _pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO safeskills_tokens (token_hash, account_id, token_type, expires_at)
                VALUES ($1, $2::uuid, $3, $4)
                """,
                token_hash, account_id, token_type, expires_at,
            )
        return plaintext

    async def consume_token(self, plaintext: str, token_type: str) -> Optional[str]:
        """Verify and atomically consume a one-time token using FOR UPDATE.

        Returns account_id string on success, None on failure (not found,
        already used, wrong type, or expired).
        """
        self._require_pool()
        token_hash = _sha256(plaintext)
        async with _pool.acquire() as conn:
            async with conn.transaction():
                row = await conn.fetchrow(
                    """
                    SELECT * FROM safeskills_tokens
                    WHERE token_hash = $1 AND token_type = $2
                    FOR UPDATE
                    """,
                    token_hash, token_type,
                )
                if not row:
                    return None
                if row["used"]:
                    return None
                if row["expires_at"] < datetime.now(timezone.utc):
                    return None
                await conn.execute(
                    "UPDATE safeskills_tokens SET used = TRUE WHERE token_hash = $1",
                    token_hash,
                )
                return str(row["account_id"])


# Module-level singleton
account_store = AccountStore()
