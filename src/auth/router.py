# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Moltr-Commercial
# Copyright (C) 2026 Walter Troska / moltrHQ <hello@moltr.tech>
# See LICENSE (AGPL-3.0) or LICENSE-COMMERCIAL for licensing terms.

"""Dashboard authentication API router — /api/v1/auth/."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import time

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .brute_force import brute_force_guard
from .jwt_handler import (
    create_access_token,
    create_refresh_token,
    decode_refresh_token,
    verify_access_token,
)
from .models import AuthError, LoginRequest, SessionInfo, TokenResponse
from .password import verify_password
from .session_store import session_store

logger = logging.getLogger("moltr.auth")

auth_router = APIRouter(prefix="/api/v1/auth", tags=["auth"])

# Dashboard user credentials loaded from env
_DASHBOARD_USER = os.environ.get("MOLTR_DASHBOARD_USER", "admin")
_DASHBOARD_PASS_HASH = os.environ.get("MOLTR_DASHBOARD_PASS_HASH", "")

# Refresh token cookie config
COOKIE_NAME = "moltr_refresh"
COOKIE_SECURE = os.environ.get("MOLTR_COOKIE_SECURE", "true").lower() == "true"
# SameSite: "strict" | "lax" | "none" — "lax" works across subdomains, "none" requires secure=true
COOKIE_SAMESITE = os.environ.get("MOLTR_COOKIE_SAMESITE", "lax")

# Trusted proxy IPs/CIDRs (comma-separated). X-Forwarded-For is only trusted if the
# direct connection comes from one of these addresses. Example: "127.0.0.1,10.0.0.0/8"
_TRUSTED_PROXY_RAW = os.environ.get("MOLTR_TRUSTED_PROXY", "")
_TRUSTED_PROXIES: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
for _entry in _TRUSTED_PROXY_RAW.split(","):
    _entry = _entry.strip()
    if _entry:
        try:
            _TRUSTED_PROXIES.append(ipaddress.ip_network(_entry, strict=False))
        except ValueError:
            logging.getLogger("moltr.auth").warning("Invalid MOLTR_TRUSTED_PROXY entry: %s", _entry)

_bearer_scheme = HTTPBearer(auto_error=False)


def _is_trusted_proxy(ip: str) -> bool:
    """Return True if the given IP belongs to a configured trusted proxy."""
    if not _TRUSTED_PROXIES:
        return False
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _TRUSTED_PROXIES)
    except ValueError:
        return False


def _get_client_ip(request: Request) -> str:
    """Extract real client IP — only trusts X-Forwarded-For behind a verified proxy.

    Without MOLTR_TRUSTED_PROXY configured, the header is ignored to prevent
    attackers from spoofing their IP and bypassing brute-force protection.
    """
    direct_ip = request.client.host if request.client else "unknown"
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded and _is_trusted_proxy(direct_ip):
        return forwarded.split(",")[0].strip()
    return direct_ip


def _pseudonymize_ip(ip: str) -> str:
    """Null last octet for log output."""
    parts = ip.split(".")
    if len(parts) == 4:
        parts[-1] = "0"
        return ".".join(parts)
    return ip


@auth_router.post("/login", response_model=TokenResponse)
async def login(req: LoginRequest, request: Request, response: Response):
    """Authenticate with username + password, get access + refresh tokens."""
    client_ip = _get_client_ip(request)

    # Brute-force check
    allowed, reason, delay = brute_force_guard.check_allowed(client_ip)
    if not allowed:
        logger.warning("Login blocked for %s: %s", _pseudonymize_ip(client_ip), reason)
        return JSONResponse(
            status_code=429,
            content=AuthError(detail=reason, retry_after=60).model_dump(),
        )

    # Progressive delay
    if delay > 0:
        await asyncio.sleep(delay)

    # Verify credentials
    if not _DASHBOARD_PASS_HASH:
        logger.error("MOLTR_DASHBOARD_PASS_HASH not set — login disabled")
        return JSONResponse(
            status_code=503,
            content=AuthError(detail="Dashboard login not configured").model_dump(),
        )

    if req.username != _DASHBOARD_USER or not verify_password(req.password, _DASHBOARD_PASS_HASH):
        brute_force_guard.record_failure(client_ip)
        logger.warning(
            "Failed login from %s (user: %s)",
            _pseudonymize_ip(client_ip),
            req.username,
        )
        return JSONResponse(
            status_code=401,
            content=AuthError(detail="Invalid credentials").model_dump(),
        )

    # Success — reset brute-force tracker
    brute_force_guard.record_success(client_ip)

    # Create tokens
    access_token = create_access_token(subject=req.username)
    token_id, refresh_token = create_refresh_token(subject=req.username)
    session_store.create(token_id, req.username)

    # Set refresh token as httpOnly cookie
    response.set_cookie(
        key=COOKIE_NAME,
        value=refresh_token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE,
        path="/api/v1/auth",
    )

    logger.info("Login success: %s from %s", req.username, _pseudonymize_ip(client_ip))
    return TokenResponse(access_token=access_token)


@auth_router.post("/refresh", response_model=TokenResponse)
async def refresh(request: Request, response: Response):
    """Refresh the access token using the httpOnly refresh cookie."""
    refresh_cookie = request.cookies.get(COOKIE_NAME)
    if not refresh_cookie:
        return JSONResponse(
            status_code=401,
            content=AuthError(detail="No refresh token").model_dump(),
        )

    payload = decode_refresh_token(refresh_cookie)
    if not payload:
        return JSONResponse(
            status_code=401,
            content=AuthError(detail="Invalid refresh token").model_dump(),
        )

    token_id = payload.get("jti", "")
    # validate_and_touch() is atomic — eliminates TOCTOU between validate + touch
    session = session_store.validate_and_touch(token_id)
    if not session:
        # Clear the invalid cookie
        response.delete_cookie(key=COOKIE_NAME, path="/api/v1/auth")
        return JSONResponse(
            status_code=401,
            content=AuthError(detail="Session expired or revoked").model_dump(),
        )

    # Issue new access token
    access_token = create_access_token(subject=session.username)
    return TokenResponse(access_token=access_token)


@auth_router.post("/logout")
async def logout(request: Request, response: Response):
    """Logout — revoke refresh token and clear cookie."""
    refresh_cookie = request.cookies.get(COOKIE_NAME)
    if refresh_cookie:
        payload = decode_refresh_token(refresh_cookie)
        if payload:
            token_id = payload.get("jti", "")
            session_store.revoke(token_id)

    response.delete_cookie(key=COOKIE_NAME, path="/api/v1/auth")
    return {"detail": "Logged out"}


@auth_router.get("/sessions", response_model=SessionInfo)
async def get_sessions(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
):
    """Get active session count (requires valid access token)."""
    if not credentials or not verify_access_token(credentials.credentials):
        return JSONResponse(status_code=401, content={"detail": "Not authenticated"})
    return SessionInfo(active_sessions=session_store.active_count())


# === Dependency for protected dashboard endpoints ===


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
) -> str:
    """FastAPI dependency — validates access token, returns username."""
    if not credentials:
        raise _auth_exception()

    payload = verify_access_token(credentials.credentials)
    if not payload:
        raise _auth_exception()

    return payload["sub"]


def _auth_exception():
    from fastapi import HTTPException

    return HTTPException(
        status_code=401,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )
