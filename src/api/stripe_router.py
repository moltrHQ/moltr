# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Moltr-Commercial
# Copyright (C) 2026 Walter Troska / moltrHQ <hello@moltr.tech>
# See LICENSE (AGPL-3.0) or LICENSE-COMMERCIAL for licensing terms.

"""Stripe webhook router — /api/v1/stripe/

CRITICAL: await request.body() BEFORE any parsing — Stripe signature
validates over the raw bytes. Any JSON parsing first corrupts the check.

Handled events:
  checkout.session.completed      → provision API key, send email
  customer.subscription.updated   → update tier + key tier
  customer.subscription.deleted   → revoke key, downgrade to free
"""

from __future__ import annotations

import logging
import os
from typing import Optional

import stripe
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from src.api.account_store import AccountStore
from src.api.email_service import send_api_key_email
from src.api.key_store import KeyStore
from src.api.tiers import Tier

logger = logging.getLogger("safeskills.stripe_router")

# ── Module-level store references ─────────────────────────────────────────────

_account_store: Optional[AccountStore] = None
_key_store: Optional[KeyStore] = None


def init_stripe_router(account_store: AccountStore, key_store: KeyStore) -> None:
    global _account_store, _key_store
    _account_store = account_store
    _key_store = key_store


# ── Price → Tier mapping ──────────────────────────────────────────────────────

def _price_to_tier(price_id: str) -> Optional[str]:
    """Map a Stripe price ID to a SafeSkills tier string.

    Returns None for unknown or empty price IDs.
    Guard against empty env vars: only include entries where the key is non-empty.
    """
    if not price_id:
        return None
    mapping: dict[str, str] = {}
    if p := os.environ.get("STRIPE_PRICE_VERIFIED", ""):
        mapping[p] = "verified"
    if p := os.environ.get("STRIPE_PRICE_PRO", ""):
        mapping[p] = "pro"
    return mapping.get(price_id)


# ── Router ────────────────────────────────────────────────────────────────────

stripe_router = APIRouter(prefix="/api/v1/stripe", tags=["stripe"])


@stripe_router.post("/webhook")
async def stripe_webhook(request: Request):
    """Stripe webhook endpoint. No auth — validated via STRIPE_WEBHOOK_SECRET."""
    webhook_secret = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
    stripe_key     = os.environ.get("STRIPE_SECRET_KEY", "")

    if not stripe_key:
        logger.error("[Stripe] STRIPE_SECRET_KEY not set — webhook disabled")
        return JSONResponse(status_code=503, content={"detail": "Stripe not configured"})

    stripe.api_key = stripe_key

    # CRITICAL: read raw body BEFORE any framework parsing
    raw_body = await request.body()
    sig_header = request.headers.get("stripe-signature", "")

    if webhook_secret:
        try:
            event = stripe.Webhook.construct_event(raw_body, sig_header, webhook_secret)
        except stripe.error.SignatureVerificationError as exc:
            logger.warning("[Stripe] Webhook signature verification failed: %s", exc)
            return JSONResponse(status_code=400, content={"detail": "Invalid signature"})
        except Exception as exc:
            logger.error("[Stripe] Webhook parse error: %s", exc)
            return JSONResponse(status_code=400, content={"detail": "Webhook parse error"})
    else:
        logger.warning("[Stripe] STRIPE_WEBHOOK_SECRET not set — skipping signature check (dev mode)")
        try:
            import json
            event_data = json.loads(raw_body)
            event = stripe.Event.construct_from(event_data, stripe_key)
        except Exception as exc:
            logger.error("[Stripe] Webhook JSON parse error: %s", exc)
            return JSONResponse(status_code=400, content={"detail": "Invalid JSON"})

    event_type = event["type"]
    logger.info("[Stripe] Event received: %s (id: %s)", event_type, event.get("id", "?")[:16])

    if event_type == "checkout.session.completed":
        await _handle_checkout_completed(event["data"]["object"])

    elif event_type == "customer.subscription.updated":
        await _handle_subscription_updated(event["data"]["object"])

    elif event_type == "customer.subscription.deleted":
        await _handle_subscription_deleted(event["data"]["object"])

    else:
        logger.debug("[Stripe] Unhandled event type: %s", event_type)

    return {"received": True}


# ── Event handlers ────────────────────────────────────────────────────────────

async def _handle_checkout_completed(session) -> None:
    """checkout.session.completed — provision API key for new subscriber."""
    if not (_account_store and _key_store):
        logger.error("[Stripe] Stores not initialized — cannot handle checkout.session.completed")
        return

    stripe_customer_id   = session.get("customer")
    stripe_subscription_id = session.get("subscription")
    metadata             = session.get("metadata") or {}
    tier_str             = metadata.get("tier", "")
    account_id           = metadata.get("account_id", "")

    if not tier_str:
        logger.warning("[Stripe] checkout.session.completed: no tier in metadata")
        return

    # Look up account — prefer metadata account_id for speed
    account = None
    if account_id:
        account = await _account_store.get_by_id(account_id)
    if not account and stripe_customer_id:
        account = await _account_store.get_by_stripe_customer(stripe_customer_id)
    if not account:
        logger.error("[Stripe] checkout.session.completed: account not found (customer=%s)", stripe_customer_id)
        return

    # Revoke existing key if present
    if account.api_key_prefix:
        revoked = _key_store.revoke(account.api_key_prefix)
        logger.info("[Stripe] Revoked old key prefix=%s for account %s", account.api_key_prefix, account.id[:8])

    # Create new key
    tier_enum = _str_to_tier(tier_str)
    plaintext_key, key_entry = _key_store.create(tier_enum, account.email)

    # Update account in DB
    await _account_store.update_stripe(
        account.id,
        stripe_customer_id=stripe_customer_id,
        stripe_subscription_id=str(stripe_subscription_id) if stripe_subscription_id else None,
        stripe_subscription_status="active",
        tier=tier_str,
        api_key_prefix=key_entry.key_prefix,
    )

    # Send key via email (shown exactly once)
    send_api_key_email(account.email, plaintext_key, tier_str)
    logger.info(
        "[Stripe] Provisioned %s key for account %s (prefix=%s)",
        tier_str, account.id[:8], key_entry.key_prefix,
    )


async def _handle_subscription_updated(subscription) -> None:
    """customer.subscription.updated — sync tier and key tier."""
    if not (_account_store and _key_store):
        return

    subscription_id     = subscription.get("id")
    new_status          = subscription.get("status", "")
    items               = subscription.get("items", {}).get("data", [])

    account = await _account_store.get_by_stripe_subscription(subscription_id)
    if not account:
        logger.warning("[Stripe] subscription.updated: no account for sub %s", subscription_id)
        return

    # Determine new tier from price
    new_tier_str = account.tier
    if items:
        price_id  = items[0].get("price", {}).get("id", "")
        mapped    = _price_to_tier(price_id)
        if mapped:
            new_tier_str = mapped

    updates: dict = {"stripe_subscription_status": new_status}

    if new_tier_str != account.tier:
        updates["tier"] = new_tier_str
        # Update key tier in-place if key exists
        if account.api_key_prefix:
            _key_store.update_tier(account.api_key_prefix, new_tier_str)
            logger.info(
                "[Stripe] Tier changed %s → %s for account %s (prefix=%s)",
                account.tier, new_tier_str, account.id[:8], account.api_key_prefix,
            )

    await _account_store.update_stripe(account.id, **updates)
    logger.info("[Stripe] subscription.updated: account %s status=%s tier=%s",
                account.id[:8], new_status, new_tier_str)


async def _handle_subscription_deleted(subscription) -> None:
    """customer.subscription.deleted — revoke key, downgrade to free."""
    if not (_account_store and _key_store):
        return

    subscription_id = subscription.get("id")

    account = await _account_store.get_by_stripe_subscription(subscription_id)
    if not account:
        logger.warning("[Stripe] subscription.deleted: no account for sub %s", subscription_id)
        return

    # Revoke key
    if account.api_key_prefix:
        _key_store.revoke(account.api_key_prefix)
        logger.info("[Stripe] Revoked key prefix=%s (subscription canceled)", account.api_key_prefix)

    await _account_store.update_stripe(
        account.id,
        stripe_subscription_status="canceled",
        tier="free",
        api_key_prefix=None,  # explicitly clear to NULL — no active key
    )
    logger.info("[Stripe] Downgraded account %s to free (subscription deleted)", account.id[:8])


# ── Helpers ───────────────────────────────────────────────────────────────────

def _str_to_tier(tier_str: str) -> Tier:
    mapping = {
        "verified":   Tier.VERIFIED,
        "pro":        Tier.PRO,
        "enterprise": Tier.ENTERPRISE,
    }
    return mapping.get(tier_str.lower(), Tier.FREE)
