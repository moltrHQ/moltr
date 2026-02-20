# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Moltr-Commercial
# Copyright (C) 2026 Walter Troska / moltrHQ <hello@moltr.tech>
# See LICENSE (AGPL-3.0) or LICENSE-COMMERCIAL for licensing terms.

"""JWT token creation and verification."""

from __future__ import annotations

import os
import secrets
import time
from typing import Any

import jwt

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE = 15 * 60  # 15 minutes in seconds

# Secret key loaded from env or auto-generated at startup
_JWT_SECRET: str = os.environ.get("MOLTR_JWT_SECRET", "")
if not _JWT_SECRET:
    _JWT_SECRET = secrets.token_urlsafe(48)


def _get_secret() -> str:
    return _JWT_SECRET


def create_access_token(subject: str, extra: dict[str, Any] | None = None) -> str:
    """Create a short-lived JWT access token (15 min)."""
    now = time.time()
    payload = {
        "sub": subject,
        "iat": int(now),
        "exp": int(now + ACCESS_TOKEN_EXPIRE),
        "type": "access",
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, _get_secret(), algorithm=ALGORITHM)


def verify_access_token(token: str) -> dict[str, Any] | None:
    """Verify and decode an access token. Returns payload or None."""
    try:
        payload = jwt.decode(token, _get_secret(), algorithms=[ALGORITHM])
        if payload.get("type") != "access":
            return None
        return payload
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None


def create_refresh_token(subject: str) -> tuple[str, str]:
    """Create a refresh token. Returns (token_id, token_string)."""
    token_id = secrets.token_urlsafe(32)
    now = time.time()
    payload = {
        "sub": subject,
        "jti": token_id,
        "iat": int(now),
        "type": "refresh",
    }
    token = jwt.encode(payload, _get_secret(), algorithm=ALGORITHM)
    return token_id, token


def decode_refresh_token(token: str) -> dict[str, Any] | None:
    """Decode a refresh token WITHOUT verifying expiry (we handle that server-side)."""
    try:
        payload = jwt.decode(
            token, _get_secret(), algorithms=[ALGORITHM],
            options={"verify_exp": False},
        )
        if payload.get("type") != "refresh":
            return None
        return payload
    except jwt.InvalidTokenError:
        return None
