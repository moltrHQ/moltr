# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Moltr-Commercial
# Copyright (C) 2026 Walter Troska / moltrHQ <hello@moltr.tech>

"""SafeSkills Tier Definitions

Defines available tiers, their rate limits, and feature access.
Used by auth middleware and endpoint decorators.
"""

from __future__ import annotations

from enum import Enum

from fastapi import Depends, HTTPException, Request


class Tier(str, Enum):
    FREE       = "free"
    VERIFIED   = "verified"
    PRO        = "pro"
    ENTERPRISE = "enterprise"


# Tier ordering for comparison (index = rank)
TIER_ORDER = [Tier.FREE, Tier.VERIFIED, Tier.PRO, Tier.ENTERPRISE]


def tier_rank(tier: Tier) -> int:
    try:
        return TIER_ORDER.index(tier)
    except ValueError:
        return 0


# ── Rate Limits ───────────────────────────────────────────────────────────────
# Format: slowapi limit string — "N/period"

RATE_LIMITS: dict[str, dict[Tier, str]] = {
    "registry_list": {
        Tier.FREE:       "60/minute",
        Tier.VERIFIED:   "120/minute",
        Tier.PRO:        "300/minute",
        Tier.ENTERPRISE: "1000/minute",
    },
    "registry_search": {
        Tier.FREE:       "20/minute",
        Tier.VERIFIED:   "60/minute",
        Tier.PRO:        "200/minute",
        Tier.ENTERPRISE: "1000/minute",
    },
    "certify": {
        Tier.FREE:       "0/minute",    # blocked at feature level
        Tier.VERIFIED:   "10/minute",
        Tier.PRO:        "30/minute",
        Tier.ENTERPRISE: "100/minute",
    },
    "verify": {
        Tier.FREE:       "120/minute",
        Tier.VERIFIED:   "300/minute",
        Tier.PRO:        "600/minute",
        Tier.ENTERPRISE: "1000/minute",
    },
    "skillcheck_scan": {
        Tier.FREE:       "30/minute",
        Tier.VERIFIED:   "60/minute",
        Tier.PRO:        "200/minute",
        Tier.ENTERPRISE: "1000/minute",
    },
    "skillcheck_search": {
        Tier.FREE:       "10/minute",
        Tier.VERIFIED:   "20/minute",
        Tier.PRO:        "60/minute",
        Tier.ENTERPRISE: "300/minute",
    },
}


def tier_limit(endpoint_key: str):
    """
    Return a FastAPI Dependency that enforces tier-based rate limits in-process.

    slowapi 0.1.9 does not support request-aware callable limits, so we implement
    per-tier enforcement as a Dependency instead of a decorator argument.

    Uses a simple sliding-window counter per (ip, tier, endpoint) key.
    Replace with Redis-backed counting for production multi-instance deploys.
    """
    from collections import defaultdict
    from time import monotonic

    # {(ip, tier): [timestamps]}
    _windows: dict = defaultdict(list)

    def _check(request: Request):
        tier: Tier = getattr(request.state, "tier", Tier.FREE)
        limits = RATE_LIMITS.get(endpoint_key, {})
        limit_str = limits.get(tier, limits.get(Tier.FREE, "20/minute"))

        count, period = _parse_limit(limit_str)
        if count == 0:
            # Rate of 0 means blocked at feature level — skip here, require_tier handles it
            return

        ip = request.client.host if request.client else "unknown"
        key = (ip, tier.value, endpoint_key)
        now = monotonic()
        window = _windows[key]

        # Remove timestamps outside the window
        _windows[key] = [t for t in window if now - t < period]
        if len(_windows[key]) >= count:
            raise HTTPException(
                status_code=429,
                detail={
                    "error": "rate_limit_exceeded",
                    "limit": limit_str,
                    "tier": tier.value,
                    "retry_after": f"{period}s",
                },
            )
        _windows[key].append(now)

    return Depends(_check)


def _parse_limit(limit_str: str) -> tuple[int, float]:
    """Parse '20/minute' → (20, 60.0). Supports second, minute, hour, day."""
    PERIODS = {"second": 1, "minute": 60, "hour": 3600, "day": 86400}
    try:
        count_str, period_str = limit_str.split("/")
        return int(count_str), float(PERIODS.get(period_str.strip(), 60))
    except Exception:
        return 20, 60.0


# ── Feature Access ────────────────────────────────────────────────────────────

TIER_FEATURES: dict[Tier, dict[str, bool]] = {
    Tier.FREE:       {"certify": False, "private_registry": False, "audit_log": False},
    Tier.VERIFIED:   {"certify": True,  "private_registry": False, "audit_log": False},
    Tier.PRO:        {"certify": True,  "private_registry": True,  "audit_log": True},
    Tier.ENTERPRISE: {"certify": True,  "private_registry": True,  "audit_log": True},
}


def require_tier(min_tier: Tier):
    """FastAPI dependency — raises 403 if request tier is below min_tier."""
    def _check(request: Request):
        tier: Tier = getattr(request.state, "tier", Tier.FREE)
        if tier_rank(tier) < tier_rank(min_tier):
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "tier_required",
                    "message": f"This feature requires {min_tier.value} tier or higher.",
                    "your_tier": tier.value,
                    "required_tier": min_tier.value,
                    "upgrade_url": "https://safeskills.dev/pricing",
                },
            )
    return _check
