"""E2E tests for Dashboard API (Tag 7).

Tests the complete auth → dashboard flow:
- Login, token issuance, protected endpoints, logout
- KillSwitch proxy endpoints (trigger/reset/log/export)
- Integrity proxy endpoints (report/check)
- WORM export checksum integrity
"""

from __future__ import annotations

import hashlib
import json
import os

import pytest
from fastapi.testclient import TestClient

# ── Test Setup ────────────────────────────────────────────────────────────────

PASS_PLAIN = "SuperSecure1234!"
PASS_HASH: str = ""

@pytest.fixture(scope="module", autouse=True)
def set_env(tmp_path_factory):
    """Set required env vars and wire moltr before importing server."""
    import bcrypt
    global PASS_HASH
    PASS_HASH = bcrypt.hashpw(PASS_PLAIN.encode(), bcrypt.gensalt()).decode()
    os.environ.setdefault("MOLTR_JWT_SECRET", "test-jwt-secret-for-pytest-only")
    os.environ.setdefault("MOLTR_API_KEY", "")
    # Patch module-level cached vars (read at import time in auth/router.py)
    import src.auth.router as _auth_router
    _orig_user = _auth_router._DASHBOARD_USER
    _orig_hash = _auth_router._DASHBOARD_PASS_HASH
    _auth_router._DASHBOARD_USER = "testadmin"
    _auth_router._DASHBOARD_PASS_HASH = PASS_HASH
    # Reset brute force guard — previous test files may have locked the testclient IP
    from src.auth.brute_force import brute_force_guard
    brute_force_guard._trackers.clear()
    yield
    _auth_router._DASHBOARD_USER = _orig_user
    _auth_router._DASHBOARD_PASS_HASH = _orig_hash


@pytest.fixture(scope="module")
def client():
    from src.api.server import app
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c


@pytest.fixture(scope="module")
def auth_client(client):
    """Client with a valid access token already set."""
    res = client.post("/api/v1/auth/login", json={"username": "testadmin", "password": PASS_PLAIN})
    assert res.status_code == 200
    token = res.json()["access_token"]
    client.headers.update({"Authorization": f"Bearer {token}"})
    return client


# ── Auth Flow ──────────────────────────────────────────────────────────────────

class TestDashboardAuth:
    def test_login_success(self, client):
        res = client.post("/api/v1/auth/login", json={"username": "testadmin", "password": PASS_PLAIN})
        assert res.status_code == 200
        data = res.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"

    def test_login_wrong_password(self, client):
        res = client.post("/api/v1/auth/login", json={"username": "testadmin", "password": "wrongpass"})
        assert res.status_code == 401

    def test_login_wrong_user(self, client):
        res = client.post("/api/v1/auth/login", json={"username": "hacker", "password": PASS_PLAIN})
        assert res.status_code == 401

    def test_protected_without_token(self, client):
        res = client.get("/api/v1/dashboard/killswitch/log")
        assert res.status_code == 401

    def test_protected_with_invalid_token(self, client):
        res = client.get(
            "/api/v1/dashboard/killswitch/log",
            headers={"Authorization": "Bearer not-a-real-token"},
        )
        assert res.status_code == 401


# ── KillSwitch Proxy ───────────────────────────────────────────────────────────

class TestDashboardKillSwitch:
    def test_log_empty(self, auth_client):
        res = auth_client.get("/api/v1/dashboard/killswitch/log")
        assert res.status_code == 200
        data = res.json()
        assert "events" in data
        assert "status" in data
        assert isinstance(data["events"], list)

    def test_trigger_pause(self, auth_client):
        res = auth_client.post(
            "/api/v1/dashboard/killswitch/trigger",
            json={"level": "pause", "reason": "pytest test"},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["triggered"] is True
        assert data["level"] == "PAUSE"

    def test_trigger_wipe_without_confirm(self, auth_client):
        res = auth_client.post(
            "/api/v1/dashboard/killswitch/trigger",
            json={"level": "wipe", "reason": "no confirm prefix"},
        )
        assert res.status_code == 400

    def test_trigger_invalid_level(self, auth_client):
        res = auth_client.post(
            "/api/v1/dashboard/killswitch/trigger",
            json={"level": "ultramax", "reason": "test"},
        )
        assert res.status_code == 400

    def test_reset_wrong_codephrase(self, auth_client):
        res = auth_client.post(
            "/api/v1/dashboard/killswitch/reset",
            json={"level": "pause", "codephrase": "wrongphrase"},
        )
        assert res.status_code == 403

    def test_log_has_triggered_event(self, auth_client):
        res = auth_client.get("/api/v1/dashboard/killswitch/log")
        assert res.status_code == 200
        events = res.json()["events"]
        assert any(e["level"] == "PAUSE" for e in events)

    def test_export_json(self, auth_client):
        res = auth_client.get("/api/v1/dashboard/killswitch/export")
        assert res.status_code == 200
        assert "application/json" in res.headers["content-type"]
        assert "attachment" in res.headers.get("content-disposition", "")
        data = res.json()
        assert "sha256" in data
        assert "events" in data
        assert isinstance(data["total_events"], int)

    def test_export_checksum_valid(self, auth_client):
        res = auth_client.get("/api/v1/dashboard/killswitch/export")
        data = res.json()
        reported_checksum = data.pop("sha256")
        content_bytes = json.dumps(data, sort_keys=True, ensure_ascii=False).encode()
        expected = hashlib.sha256(content_bytes).hexdigest()
        assert reported_checksum == expected


# ── Integrity Proxy ────────────────────────────────────────────────────────────

class TestDashboardIntegrity:
    def test_report(self, auth_client):
        res = auth_client.get("/api/v1/dashboard/integrity/report")
        assert res.status_code == 200
        data = res.json()
        assert "files_monitored" in data
        assert "total_violations" in data
        assert "recent_violations" in data

    def test_check(self, auth_client):
        res = auth_client.get("/api/v1/dashboard/integrity/check")
        assert res.status_code == 200
        data = res.json()
        assert "violations" in data
        assert "clean" in data
        assert isinstance(data["violations_count"], int)

    def test_status(self, auth_client):
        res = auth_client.get("/api/v1/dashboard/status")
        assert res.status_code == 200
        data = res.json()
        assert "killswitch" in data


# ── MIM — Moltr Interop Manifest ───────────────────────────────────────────────

class TestMIMManifest:
    """Tests for the Moltr Interop Manifest (MIM) v1.0 endpoint."""

    def test_mim_endpoint_accessible_without_api_key(self, client):
        """MIM endpoint must be public — no API key required."""
        res = client.get("/.well-known/moltr-manifest.json")
        assert res.status_code == 200

    def test_mim_content_type_is_json(self, client):
        res = client.get("/.well-known/moltr-manifest.json")
        assert "application/json" in res.headers.get("content-type", "")

    def test_mim_version_field(self, client):
        data = client.get("/.well-known/moltr-manifest.json").json()
        assert data["mim"] == "1.0"

    def test_mim_vendor_field(self, client):
        data = client.get("/.well-known/moltr-manifest.json").json()
        assert data["vendor"] == "moltr-security"

    def test_mim_has_honeypots_section(self, client):
        data = client.get("/.well-known/moltr-manifest.json").json()
        assert "honeypots" in data
        hp = data["honeypots"]
        assert "files" in hp
        assert "endpoints" in hp
        assert "directories" in hp

    def test_mim_api_traps_declared(self, client):
        data = client.get("/.well-known/moltr-manifest.json").json()
        endpoints = data["honeypots"]["endpoints"]
        assert "/internal/credentials" in endpoints
        assert "/admin/backup-keys" in endpoints
        assert "/internal/keys" in endpoints
        assert "/v1/secrets" in endpoints
        assert "/config/database" in endpoints

    def test_mim_has_scanner_hints(self, client):
        data = client.get("/.well-known/moltr-manifest.json").json()
        assert "scanner_hints" in data
        hints = data["scanner_hints"]
        assert "ignore_patterns" in hints
        assert "false_positive_notice" in hints
        assert len(hints["false_positive_notice"]) > 0

    def test_mim_has_traps_section(self, client):
        data = client.get("/.well-known/moltr-manifest.json").json()
        assert "traps" in data
        assert "description" in data["traps"]

    def test_mim_cache_header(self, client):
        res = client.get("/.well-known/moltr-manifest.json")
        assert "max-age=3600" in res.headers.get("cache-control", "")

    def test_mim_version_header(self, client):
        res = client.get("/.well-known/moltr-manifest.json")
        assert res.headers.get("x-mim-version") == "1.0"

    def test_mim_generated_field_is_iso8601(self, client):
        from datetime import datetime
        data = client.get("/.well-known/moltr-manifest.json").json()
        assert "generated" in data
        # Should parse without error
        datetime.fromisoformat(data["generated"].replace("Z", "+00:00"))

    def test_legacy_manifest_still_works(self, client):
        """Legacy /honeypots/manifest endpoint remains functional."""
        res = client.get("/honeypots/manifest")
        assert res.status_code == 200
        data = res.json()
        assert "traps" in data
        assert "mim_endpoint" in data
        assert data["mim_endpoint"] == "/.well-known/moltr-manifest.json"
