"""Tests for the Dashboard authentication module."""

from __future__ import annotations

import time

import pytest

from src.auth.password import MIN_PASSWORD_LENGTH, hash_password, verify_password
from src.auth.jwt_handler import (
    create_access_token,
    create_refresh_token,
    decode_refresh_token,
    verify_access_token,
)
from src.auth.session_store import SessionStore
from src.auth.brute_force import BruteForceGuard


# ===================== Password Tests =====================


class TestPassword:
    def test_hash_and_verify(self) -> None:
        pw = "supersecurepassword123"
        hashed = hash_password(pw)
        assert hashed != pw
        assert verify_password(pw, hashed) is True

    def test_wrong_password_fails(self) -> None:
        hashed = hash_password("correctpassword1")
        assert verify_password("wrongpassword12", hashed) is False

    def test_min_length_enforced(self) -> None:
        with pytest.raises(ValueError, match="at least"):
            hash_password("short")

    def test_exact_min_length(self) -> None:
        pw = "a" * MIN_PASSWORD_LENGTH
        hashed = hash_password(pw)
        assert verify_password(pw, hashed) is True


# ===================== JWT Tests =====================


class TestJWT:
    def test_access_token_roundtrip(self) -> None:
        token = create_access_token("admin")
        payload = verify_access_token(token)
        assert payload is not None
        assert payload["sub"] == "admin"
        assert payload["type"] == "access"

    def test_access_token_with_extra(self) -> None:
        token = create_access_token("admin", extra={"role": "admin"})
        payload = verify_access_token(token)
        assert payload is not None
        assert payload["role"] == "admin"

    def test_invalid_access_token(self) -> None:
        assert verify_access_token("garbage.token.here") is None

    def test_refresh_token_roundtrip(self) -> None:
        token_id, token = create_refresh_token("admin")
        assert token_id
        assert token
        payload = decode_refresh_token(token)
        assert payload is not None
        assert payload["sub"] == "admin"
        assert payload["jti"] == token_id
        assert payload["type"] == "refresh"

    def test_refresh_token_not_valid_as_access(self) -> None:
        _, token = create_refresh_token("admin")
        assert verify_access_token(token) is None

    def test_access_token_not_valid_as_refresh(self) -> None:
        token = create_access_token("admin")
        assert decode_refresh_token(token) is None


# ===================== Session Store Tests =====================


class TestSessionStore:
    def test_create_and_validate(self) -> None:
        store = SessionStore()
        session = store.create("tok1", "admin")
        assert session.username == "admin"
        assert store.validate("tok1") is not None

    def test_unknown_token_returns_none(self) -> None:
        store = SessionStore()
        assert store.validate("nonexistent") is None

    def test_revoke(self) -> None:
        store = SessionStore()
        store.create("tok2", "admin")
        store.revoke("tok2")
        assert store.validate("tok2") is None

    def test_inactivity_timeout(self) -> None:
        store = SessionStore(inactivity_timeout=1)  # 1 second
        store.create("tok3", "admin")
        time.sleep(1.1)
        assert store.validate("tok3") is None

    def test_touch_resets_timeout(self) -> None:
        store = SessionStore(inactivity_timeout=2)
        store.create("tok4", "admin")
        time.sleep(1)
        store.touch("tok4")
        time.sleep(1)
        assert store.validate("tok4") is not None

    def test_invalidate_all(self) -> None:
        store = SessionStore()
        store.create("a", "admin")
        store.create("b", "admin")
        store.create("c", "viewer")
        count = store.invalidate_all()
        assert count == 3
        assert store.validate("a") is None
        assert store.validate("b") is None
        assert store.validate("c") is None

    def test_active_count(self) -> None:
        store = SessionStore()
        store.create("x", "admin")
        store.create("y", "admin")
        assert store.active_count() == 2
        store.revoke("x")
        assert store.active_count() == 1

    def test_cleanup_removes_revoked(self) -> None:
        store = SessionStore()
        store.create("z1", "admin")
        store.create("z2", "admin")
        store.revoke("z1")
        removed = store.cleanup()
        assert removed == 1
        assert store.validate("z2") is not None


# ===================== Brute Force Tests =====================


class TestBruteForce:
    def test_allows_first_attempt(self) -> None:
        guard = BruteForceGuard()
        allowed, reason, delay = guard.check_allowed("1.2.3.4")
        assert allowed is True
        assert delay == 0.0

    def test_blocks_after_rate_limit(self) -> None:
        guard = BruteForceGuard(max_per_minute=2)
        guard.record_failure("10.0.0.1")
        guard.record_failure("10.0.0.1")
        allowed, reason, _ = guard.check_allowed("10.0.0.1")
        assert allowed is False
        assert "Too many" in reason

    def test_lockout_after_max_failures(self) -> None:
        guard = BruteForceGuard(max_per_minute=100, lockout_after=3, lockout_seconds=60)
        for _ in range(3):
            guard.record_failure("10.0.0.2")
        allowed, reason, _ = guard.check_allowed("10.0.0.2")
        assert allowed is False
        assert "locked" in reason.lower()

    def test_progressive_delay(self) -> None:
        guard = BruteForceGuard(max_per_minute=100, lockout_after=100)
        # First 3 failures: no delay
        for _ in range(3):
            guard.record_failure("10.0.0.3")
        _, _, delay = guard.check_allowed("10.0.0.3")
        assert delay == 1.0  # 2^0

        guard.record_failure("10.0.0.3")
        _, _, delay = guard.check_allowed("10.0.0.3")
        assert delay == 2.0  # 2^1

    def test_success_resets_tracker(self) -> None:
        guard = BruteForceGuard(max_per_minute=100, lockout_after=100)
        guard.record_failure("10.0.0.4")
        guard.record_failure("10.0.0.4")
        guard.record_success("10.0.0.4")
        allowed, _, delay = guard.check_allowed("10.0.0.4")
        assert allowed is True
        assert delay == 0.0

    def test_different_ips_independent(self) -> None:
        guard = BruteForceGuard(max_per_minute=1)
        guard.record_failure("10.0.0.5")
        allowed_5, _, _ = guard.check_allowed("10.0.0.5")
        allowed_6, _, _ = guard.check_allowed("10.0.0.6")
        assert allowed_5 is False
        assert allowed_6 is True

    def test_pseudonymize_ip(self) -> None:
        assert BruteForceGuard._pseudonymize_ip("192.168.1.123") == "192.168.1.0"
        assert BruteForceGuard._pseudonymize_ip("::1") == "::1"


# ===================== Integration Test: Auth Router via TestClient =====================


class TestAuthRouter:
    """Test the auth API endpoints via FastAPI TestClient."""

    @pytest.fixture(autouse=True)
    def setup_env(self, monkeypatch) -> None:
        """Set up env vars for dashboard auth."""
        from src.auth.password import hash_password

        pw_hash = hash_password("testpassword12")
        monkeypatch.setenv("MOLTR_DASHBOARD_USER", "testadmin")
        monkeypatch.setenv("MOLTR_DASHBOARD_PASS_HASH", pw_hash)
        monkeypatch.setenv("MOLTR_COOKIE_SECURE", "false")  # TestClient uses http

    @pytest.fixture
    def client(self, setup_env):
        # Import fresh to pick up env changes
        import importlib
        import src.auth.router as router_mod

        importlib.reload(router_mod)
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        app = FastAPI()
        app.include_router(router_mod.auth_router)
        return TestClient(app)

    def test_login_success(self, client) -> None:
        resp = client.post(
            "/api/v1/auth/login",
            json={"username": "testadmin", "password": "testpassword12"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        # Check refresh cookie is set
        assert "moltr_refresh" in resp.cookies

    def test_login_wrong_password(self, client) -> None:
        resp = client.post(
            "/api/v1/auth/login",
            json={"username": "testadmin", "password": "wrongpassword1"},
        )
        assert resp.status_code == 401

    def test_login_wrong_user(self, client) -> None:
        resp = client.post(
            "/api/v1/auth/login",
            json={"username": "nobody", "password": "testpassword12"},
        )
        assert resp.status_code == 401

    def test_refresh_token(self, client) -> None:
        # Login first
        login_resp = client.post(
            "/api/v1/auth/login",
            json={"username": "testadmin", "password": "testpassword12"},
        )
        assert login_resp.status_code == 200

        # Refresh
        refresh_resp = client.post("/api/v1/auth/refresh")
        assert refresh_resp.status_code == 200
        assert "access_token" in refresh_resp.json()

    def test_logout(self, client) -> None:
        # Login
        client.post(
            "/api/v1/auth/login",
            json={"username": "testadmin", "password": "testpassword12"},
        )
        # Logout
        resp = client.post("/api/v1/auth/logout")
        assert resp.status_code == 200

        # Refresh should fail now
        refresh_resp = client.post("/api/v1/auth/refresh")
        assert refresh_resp.status_code == 401

    def test_sessions_requires_auth(self, client) -> None:
        resp = client.get("/api/v1/auth/sessions")
        assert resp.status_code == 401

    def test_sessions_with_token(self, client) -> None:
        login_resp = client.post(
            "/api/v1/auth/login",
            json={"username": "testadmin", "password": "testpassword12"},
        )
        token = login_resp.json()["access_token"]
        resp = client.get(
            "/api/v1/auth/sessions",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        assert resp.json()["active_sessions"] >= 1
