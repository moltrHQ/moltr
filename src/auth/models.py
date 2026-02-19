"""Pydantic models for Dashboard authentication."""

from __future__ import annotations

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    """Login request body."""

    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1)


class TokenResponse(BaseModel):
    """Response after successful login or token refresh."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int = 900  # 15 minutes


class AuthError(BaseModel):
    """Auth error response."""

    detail: str
    retry_after: int | None = None


class SessionInfo(BaseModel):
    """Info about active dashboard sessions."""

    active_sessions: int
