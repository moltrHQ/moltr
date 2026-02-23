# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Moltr-Commercial
# Copyright (C) 2026 Walter Troska / moltrHQ <hello@moltr.tech>

"""SafeSkills API Key Management Router

Admin endpoints for creating, listing, and revoking API keys.
All endpoints require the master MOLTR_API_KEY (admin access).

Endpoints:
  POST   /api/v1/admin/keys              — create new key
  GET    /api/v1/admin/keys              — list all keys
  GET    /api/v1/admin/keys/{prefix}     — inspect one key
  DELETE /api/v1/admin/keys/{prefix}     — revoke a key
  GET    /api/v1/admin/keys/tiers        — show tier limits + features
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel

from src.api._limiter import limiter
from src.api.tiers import RATE_LIMITS, TIER_FEATURES, Tier

logger = logging.getLogger("moltr.api.keys")

key_router = APIRouter(prefix="/api/v1/admin", tags=["SafeSkills Key Management"])

# Injected via init_key_router()
_key_store = None


# ── Models ────────────────────────────────────────────────────────────────────

class CreateKeyRequest(BaseModel):
    tier: str   # "free" | "verified" | "pro" | "enterprise"
    owner: str


class CreateKeyResponse(BaseModel):
    key: str        # plaintext — shown ONCE, never stored
    key_prefix: str
    tier: str
    owner: str
    warning: str


# ── Init ──────────────────────────────────────────────────────────────────────

def init_key_router(key_store) -> None:
    global _key_store
    _key_store = key_store
    logger.info("[KeyRouter] Ready")


# ── Endpoints ─────────────────────────────────────────────────────────────────

@key_router.post("/keys", response_model=CreateKeyResponse)
@limiter.limit("20/minute")
async def create_key(request: Request, req: CreateKeyRequest, response: Response):
    """Create a new API key. The plaintext key is returned ONCE — store it securely."""
    try:
        tier = Tier(req.tier)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid tier '{req.tier}'. Valid: {[t.value for t in Tier]}",
        )

    if not req.owner.strip():
        raise HTTPException(status_code=400, detail="owner must not be empty")

    plaintext, entry = _key_store.create(tier, req.owner.strip())

    logger.info("[KeyRouter] Created %s key for %r", tier.value, req.owner)

    return CreateKeyResponse(
        key=plaintext,
        key_prefix=entry.key_prefix,
        tier=tier.value,
        owner=entry.owner,
        warning="Store this key securely — it will not be shown again.",
    )


@key_router.get("/keys")
@limiter.limit("30/minute")
async def list_keys(request: Request, response: Response):
    """List all API keys (hashes not included)."""
    keys = _key_store.list_keys()
    return {
        "total": len(keys),
        "keys": [k.to_public_dict() for k in keys],
    }


@key_router.get("/keys/tiers")
async def list_tiers(response: Response):
    """Show tier limits and features — useful for pricing page generation."""
    result = {}
    for tier in Tier:
        result[tier.value] = {
            "rate_limits": {
                endpoint: limits.get(tier, "—")
                for endpoint, limits in RATE_LIMITS.items()
            },
            "features": TIER_FEATURES.get(tier, {}),
        }
    return result


@key_router.get("/keys/{key_prefix}")
@limiter.limit("30/minute")
async def get_key(key_prefix: str, request: Request, response: Response):
    """Get details for a key by its prefix."""
    entry = _key_store.get_by_prefix(key_prefix)
    if not entry:
        raise HTTPException(status_code=404, detail=f"No key with prefix '{key_prefix}'")
    return entry.to_public_dict()


@key_router.delete("/keys/{key_prefix}")
@limiter.limit("10/minute")
async def revoke_key(key_prefix: str, request: Request, response: Response):
    """Revoke a key immediately. Active requests using this key will fail on next check."""
    revoked = _key_store.revoke(key_prefix)
    if not revoked:
        raise HTTPException(status_code=404, detail=f"No key with prefix '{key_prefix}'")
    logger.info("[KeyRouter] Key revoked: %s", key_prefix)
    return {"revoked": True, "key_prefix": key_prefix}
