# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Moltr-Commercial
# Copyright (C) 2026 Walter Troska / moltrHQ <hello@moltr.tech>
# See LICENSE (AGPL-3.0) or LICENSE-COMMERCIAL for licensing terms.

"""SafeSkills Account API router — /api/v1/account/

Separate JWT secret (SAFESKILLS_JWT_SECRET) — strictly isolated from
MOLTR_JWT_SECRET (dashboard). account_type: "account" claim prevents
token-type confusion.

Endpoints:
  POST /register           — create account + send verification email
  POST /login              — JWT access token + httpOnly refresh cookie
  POST /refresh            — rotate JTI, return new access token
  POST /logout             — revoke JTI, delete cookie
  GET  /verify-email       — consume email-verify token, redirect
  POST /forgot-password    — send reset email (no enumeration)
  POST /reset-password     — set new password via reset token
  GET  /me                 — profile + tier + key prefix (Bearer)
  POST /subscribe          — Stripe Checkout Session URL (Bearer)
  GET  /portal             — Stripe Customer Portal URL (Bearer)
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import re
import secrets
import time
from typing import Optional

import jwt
import stripe
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, field_validator

from src.api._limiter import limiter
from src.api.account_store import AccountStore, AccountRecord
from src.api.email_service import (
    send_api_key_email,
    send_password_reset_email,
    send_verification_email,
)
from src.api.key_store import KeyStore
from src.api.tiers import Tier
from src.auth.password import hash_password, verify_password, MIN_PASSWORD_LENGTH

logger = logging.getLogger("safeskills.account_router")

# ── Module-level store references (set via init_account_router) ───────────────

_account_store: Optional[AccountStore] = None
_key_store: Optional[KeyStore] = None


def init_account_router(account_store: AccountStore, key_store: KeyStore) -> None:
    global _account_store, _key_store
    _account_store = account_store
    _key_store = key_store


# ── JWT helpers (SAFESKILLS_JWT_SECRET — never MOLTR_JWT_SECRET) ──────────────

_ALGORITHM = "HS256"
_ACCESS_EXPIRE = 15 * 60  # 15 min

_SS_JWT_SECRET: str = os.environ.get("SAFESKILLS_JWT_SECRET", "")
if not _SS_JWT_SECRET:
    _SS_JWT_SECRET = secrets.token_urlsafe(48)
    logger.warning(
        "[Account] SAFESKILLS_JWT_SECRET not set — using ephemeral secret (tokens invalidated on restart)"
    )

_COOKIE_NAME    = "ss_refresh"
_COOKIE_SECURE  = os.environ.get("SS_COOKIE_SECURE", "true").lower() == "true"
_COOKIE_SAMESITE = "lax"
_BASE_URL        = os.environ.get("SAFESKILLS_BASE_URL", "https://safeskills.dev")

_STRIPE_PRICE_VERIFIED = os.environ.get("STRIPE_PRICE_VERIFIED", "")
_STRIPE_PRICE_PRO      = os.environ.get("STRIPE_PRICE_PRO", "")

# Pre-computed at module load — prevents timing-based email enumeration in login.
# Using a fixed bcrypt hash avoids bcrypt work per request while still taking ~same
# time as a real verify_password() call when the account doesn't exist.
_DUMMY_BCRYPT_HASH = hash_password("safeskills-dummy-account-filler-2026")


def _create_access_token(account_id: str, email: str, tier: str) -> str:
    now = time.time()
    payload = {
        "sub": account_id,
        "email": email,
        "tier": tier,
        "account_type": "account",  # type-confusion guard vs admin tokens
        "type": "access",
        "iat": int(now),
        "exp": int(now + _ACCESS_EXPIRE),
    }
    return jwt.encode(payload, _SS_JWT_SECRET, algorithm=_ALGORITHM)


def _create_refresh_token(account_id: str) -> tuple[str, str]:
    """Return (jti, token_string). JTI stored as SHA-256 hash in DB."""
    jti = secrets.token_urlsafe(32)
    payload = {
        "sub": account_id,
        "jti": jti,
        "account_type": "account",
        "type": "refresh",
        "iat": int(time.time()),
    }
    return jti, jwt.encode(payload, _SS_JWT_SECRET, algorithm=_ALGORITHM)


def _decode_refresh_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(
            token, _SS_JWT_SECRET, algorithms=[_ALGORITHM],
            options={"verify_exp": False},
        )
        if payload.get("type") != "refresh" or payload.get("account_type") != "account":
            return None
        return payload
    except jwt.InvalidTokenError:
        return None


def _verify_access_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, _SS_JWT_SECRET, algorithms=[_ALGORITHM])
        if payload.get("type") != "access" or payload.get("account_type") != "account":
            return None
        return payload
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None


def _jti_hash(jti: str) -> str:
    return hashlib.sha256(jti.encode()).hexdigest()


# ── Auth dependency ───────────────────────────────────────────────────────────

_bearer = HTTPBearer(auto_error=False)


async def get_current_account(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> AccountRecord:
    """FastAPI dependency — validates Bearer JWT, returns AccountRecord."""
    if not credentials:
        raise HTTPException(status_code=401, detail="Not authenticated",
                            headers={"WWW-Authenticate": "Bearer"})
    payload = _verify_access_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token",
                            headers={"WWW-Authenticate": "Bearer"})
    account = await _account_store.get_by_id(payload["sub"])
    if not account:
        raise HTTPException(status_code=401, detail="Account not found",
                            headers={"WWW-Authenticate": "Bearer"})
    return account


# ── Validation ────────────────────────────────────────────────────────────────

_EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")


def _validate_email(email: str) -> bool:
    return bool(_EMAIL_RE.match(email)) and len(email) <= 254


# ── Pydantic models ───────────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    email: str
    password: str

    @field_validator("email")
    @classmethod
    def email_valid(cls, v: str) -> str:
        if not _validate_email(v.strip()):
            raise ValueError("Invalid email address")
        return v.strip().lower()

    @field_validator("password")
    @classmethod
    def password_strong(cls, v: str) -> str:
        if len(v) < MIN_PASSWORD_LENGTH:
            raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters")
        return v


class LoginRequest(BaseModel):
    email: str
    password: str


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def pw_strong(cls, v: str) -> str:
        if len(v) < MIN_PASSWORD_LENGTH:
            raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters")
        return v


class SubscribeRequest(BaseModel):
    tier: str  # "verified" or "pro"

    @field_validator("tier")
    @classmethod
    def tier_valid(cls, v: str) -> str:
        if v.lower() not in ("verified", "pro"):
            raise ValueError("tier must be 'verified' or 'pro'")
        return v.lower()


class ForgotPasswordRequest(BaseModel):
    email: str


# ── Router ────────────────────────────────────────────────────────────────────

account_router = APIRouter(prefix="/api/v1/account", tags=["account"])

_SAME_REGISTER_MSG = (
    "If this email address is not already registered, "
    "a verification link has been sent."
)
_SAME_FORGOT_MSG = (
    "If an account exists for this email address, "
    "a password reset link has been sent."
)


@account_router.post("/register")
@limiter.limit("5/minute")
async def register(req: RegisterRequest, request: Request):
    """Create account. Returns identical message whether email exists or not (no enumeration)."""
    if not _account_store.is_available():
        return JSONResponse(status_code=503, content={"detail": "Account service unavailable"})

    pw_hash = hash_password(req.password)
    account = await _account_store.create_account(req.email, pw_hash)

    if account:
        token = await _account_store.create_token(account.id, "email_verify", ttl_hours=24)
        send_verification_email(account.email, token)
        logger.info("[Account] Registered: %s", req.email)
    else:
        logger.debug("[Account] Register: email already exists (suppressed): %s", req.email)

    return {"detail": _SAME_REGISTER_MSG}


@account_router.post("/login")
@limiter.limit("10/minute")
async def login(req: LoginRequest, request: Request, response: Response):
    """Authenticate. Returns access token + sets httpOnly refresh cookie."""
    if not _account_store.is_available():
        return JSONResponse(status_code=503, content={"detail": "Account service unavailable"})

    account = await _account_store.get_by_email(req.email)

    if account is None:
        # Constant-time guard: one bcrypt check regardless of whether account exists.
        # _DUMMY_BCRYPT_HASH is pre-computed at module load — no extra bcrypt work here.
        verify_password("dummy_password", _DUMMY_BCRYPT_HASH)
        return JSONResponse(status_code=401, content={"detail": "Invalid credentials"})

    if not verify_password(req.password, account.password_hash):
        return JSONResponse(status_code=401, content={"detail": "Invalid credentials"})

    if not account.email_verified:
        return JSONResponse(
            status_code=403,
            content={"detail": "Email address not verified. Please check your inbox."},
        )

    # Issue tokens
    access_token = _create_access_token(account.id, account.email, account.tier)
    jti, refresh_token = _create_refresh_token(account.id)

    # Store JTI hash (never plaintext)
    await _account_store.update_refresh_jti(account.id, _jti_hash(jti))

    response.set_cookie(
        key=_COOKIE_NAME,
        value=refresh_token,
        httponly=True,
        secure=_COOKIE_SECURE,
        samesite=_COOKIE_SAMESITE,
        path="/api/v1/account",
    )
    logger.info("[Account] Login: %s", account.email)
    return {"access_token": access_token, "token_type": "bearer"}


@account_router.post("/refresh")
@limiter.limit("30/minute")
async def refresh(request: Request, response: Response):
    """Rotate refresh JTI and issue new access token."""
    if not _account_store.is_available():
        return JSONResponse(status_code=503, content={"detail": "Account service unavailable"})

    cookie = request.cookies.get(_COOKIE_NAME)
    if not cookie:
        return JSONResponse(status_code=401, content={"detail": "No refresh token"})

    payload = _decode_refresh_token(cookie)
    if not payload:
        response.delete_cookie(_COOKIE_NAME, path="/api/v1/account")
        return JSONResponse(status_code=401, content={"detail": "Invalid refresh token"})

    account = await _account_store.get_by_id(payload["sub"])
    if not account:
        response.delete_cookie(_COOKIE_NAME, path="/api/v1/account")
        return JSONResponse(status_code=401, content={"detail": "Account not found"})

    # Verify stored JTI hash matches
    stored_hash = account.refresh_token_jti_hash
    presented_jti = payload.get("jti", "")
    if not stored_hash or not secrets.compare_digest(stored_hash, _jti_hash(presented_jti)):
        response.delete_cookie(_COOKIE_NAME, path="/api/v1/account")
        return JSONResponse(status_code=401, content={"detail": "Session expired or revoked"})

    # Rotate: generate new JTI
    new_jti, new_refresh_token = _create_refresh_token(account.id)
    await _account_store.update_refresh_jti(account.id, _jti_hash(new_jti))

    response.set_cookie(
        key=_COOKIE_NAME,
        value=new_refresh_token,
        httponly=True,
        secure=_COOKIE_SECURE,
        samesite=_COOKIE_SAMESITE,
        path="/api/v1/account",
    )

    access_token = _create_access_token(account.id, account.email, account.tier)
    return {"access_token": access_token, "token_type": "bearer"}


@account_router.post("/logout")
async def logout(request: Request, response: Response):
    """Revoke refresh JTI and clear cookie."""
    cookie = request.cookies.get(_COOKIE_NAME)
    if cookie and _account_store.is_available():
        payload = _decode_refresh_token(cookie)
        if payload:
            account = await _account_store.get_by_id(payload.get("sub", ""))
            if account:
                await _account_store.update_refresh_jti(account.id, None)

    response.delete_cookie(_COOKIE_NAME, path="/api/v1/account")
    return {"detail": "Logged out"}


@account_router.get("/verify-email")
async def verify_email(token: str, request: Request):
    """Consume email-verification token, redirect to dashboard."""
    if not _account_store.is_available():
        return JSONResponse(status_code=503, content={"detail": "Account service unavailable"})

    account_id = await _account_store.consume_token(token, "email_verify")
    if not account_id:
        return RedirectResponse(f"{_BASE_URL}/account?verified=false")

    await _account_store.verify_email(account_id)
    logger.info("[Account] Email verified for account %s", account_id[:8])
    return RedirectResponse(f"{_BASE_URL}/account?verified=true")


@account_router.post("/forgot-password")
@limiter.limit("3/minute")
async def forgot_password(req: ForgotPasswordRequest, request: Request):
    """Send password-reset email. Always returns same message (no enumeration)."""
    if _account_store.is_available() and _validate_email(req.email):
        account = await _account_store.get_by_email(req.email)
        if account:
            token = await _account_store.create_token(account.id, "password_reset", ttl_hours=2)
            send_password_reset_email(account.email, token)

    return {"detail": _SAME_FORGOT_MSG}


@account_router.post("/reset-password")
@limiter.limit("5/minute")
async def reset_password(req: ResetPasswordRequest, request: Request):
    """Set new password via password-reset token."""
    if not _account_store.is_available():
        return JSONResponse(status_code=503, content={"detail": "Account service unavailable"})

    account_id = await _account_store.consume_token(req.token, "password_reset")
    if not account_id:
        return JSONResponse(status_code=400, content={"detail": "Invalid or expired reset token"})

    new_hash = hash_password(req.new_password)
    await _account_store.update_password(account_id, new_hash)
    # Invalidate active sessions by clearing JTI
    await _account_store.update_refresh_jti(account_id, None)

    logger.info("[Account] Password reset for account %s", account_id[:8])
    return {"detail": "Password updated. Please log in again."}


@account_router.get("/me")
async def get_me(account: AccountRecord = Depends(get_current_account)):
    """Return profile, tier, key prefix, and subscription status."""
    return {
        "id": account.id,
        "email": account.email,
        "email_verified": account.email_verified,
        "tier": account.tier,
        "api_key_prefix": account.api_key_prefix,
        "stripe_subscription_status": account.stripe_subscription_status,
        "created_at": account.created_at.isoformat() if account.created_at else None,
    }


@account_router.post("/subscribe")
async def subscribe(
    req: SubscribeRequest,
    request: Request,
    account: AccountRecord = Depends(get_current_account),
):
    """Create Stripe Checkout Session. Returns checkout URL for redirect."""
    if not _account_store.is_available():
        return JSONResponse(status_code=503, content={"detail": "Account service unavailable"})

    stripe_key = os.environ.get("STRIPE_SECRET_KEY", "")
    if not stripe_key:
        return JSONResponse(status_code=503, content={"detail": "Payment service unavailable"})

    price_id = _STRIPE_PRICE_VERIFIED if req.tier == "verified" else _STRIPE_PRICE_PRO
    if not price_id:
        return JSONResponse(
            status_code=503,
            content={"detail": f"Stripe price for tier '{req.tier}' not configured"},
        )

    stripe.api_key = stripe_key

    # Create or reuse Stripe Customer
    stripe_customer_id = account.stripe_customer_id
    if not stripe_customer_id:
        try:
            customer = await asyncio.to_thread(
                stripe.Customer.create,
                email=account.email,
                metadata={"account_id": account.id},
            )
            stripe_customer_id = customer.id
            await _account_store.update_stripe(account.id, stripe_customer_id=stripe_customer_id)
            logger.info("[Account] Stripe customer created: %s for %s", customer.id[:12], account.email)
        except stripe.StripeError as exc:
            logger.error("[Account] Stripe customer create failed: %s", exc)
            return JSONResponse(status_code=502, content={"detail": "Payment service error"})

    try:
        session = await asyncio.to_thread(
            stripe.checkout.Session.create,
            customer=stripe_customer_id,
            payment_method_types=["card"],
            line_items=[{"price": price_id, "quantity": 1}],
            mode="subscription",
            success_url=f"{_BASE_URL}/account?checkout=success",
            cancel_url=f"{_BASE_URL}/pricing",
            metadata={"account_id": account.id, "tier": req.tier},
        )
    except stripe.StripeError as exc:
        logger.error("[Account] Stripe checkout create failed: %s", exc)
        return JSONResponse(status_code=502, content={"detail": "Payment service error"})

    return {"checkout_url": session.url}


@account_router.get("/portal")
async def customer_portal(
    request: Request,
    account: AccountRecord = Depends(get_current_account),
):
    """Return Stripe Customer Portal URL for subscription management."""
    if not _account_store.is_available():
        return JSONResponse(status_code=503, content={"detail": "Account service unavailable"})

    stripe_key = os.environ.get("STRIPE_SECRET_KEY", "")
    if not stripe_key:
        return JSONResponse(status_code=503, content={"detail": "Payment service unavailable"})

    if not account.stripe_customer_id:
        return JSONResponse(
            status_code=400,
            content={"detail": "No active subscription found. Please subscribe first."},
        )

    stripe.api_key = stripe_key
    try:
        portal = await asyncio.to_thread(
            stripe.billing_portal.Session.create,
            customer=account.stripe_customer_id,
            return_url=f"{_BASE_URL}/account",
        )
    except stripe.StripeError as exc:
        logger.error("[Account] Stripe portal create failed: %s", exc)
        return JSONResponse(status_code=502, content={"detail": "Payment service error"})

    return {"portal_url": portal.url}
