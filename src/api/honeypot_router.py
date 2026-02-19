"""Moltr API Honeypot Traps.

Fake endpoints that look like real internal/admin routes.
Any access triggers an immediate CRITICAL alert + forensic log entry.
No files on disk — zero false positives from filesystem scanners.

Manifest at GET /honeypots/manifest describes all traps for scanner allowlisting.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

logger = logging.getLogger("moltr.honeypot")

honeypot_router = APIRouter(tags=["honeypot"])

# Injected at startup by server.py
_moltr = None


def set_moltr_for_honeypots(instance) -> None:
    global _moltr
    _moltr = instance


# ---------------------------------------------------------------------------
# Fake response payloads — look real enough to attract attackers
# ---------------------------------------------------------------------------

_FAKE_CREDENTIALS = {
    "database": {
        "host": "db-prod-01.internal",
        "port": 5432,
        "user": "svc_moltr_prod",
        "password": "xK9#mP2$vL5nQ8wR3jF6",
        "database": "moltr_production",
    },
    "redis": {
        "host": "cache-01.internal",
        "port": 6379,
        "auth": "r3d1s_S3cur3_T0k3n",
    },
    "admin": {
        "user": "moltr_admin",
        "password": "Pr0d_Adm1n#2025_Secure!",
        "mfa_secret": "JBSWY3DPEHPK3PXP",
    },
}

_FAKE_BACKUP_KEYS = {
    "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
    "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "backup_enc_key": "bkp_7f3a9c2d1e8b4f6a0c5d2e9b3f7a1c4d",
    "ssh_backup_user": "backup_svc",
    "ssh_backup_host": "backup-01.internal",
}

_FAKE_SECRETS = {
    "jwt_secret": "super-secret-jwt-key-do-not-share",
    "api_keys": {
        "stripe": "sk_live_FAKE000000000000000000",
        "sendgrid": "SG.FAKE_KEY_DO_NOT_USE.EXAMPLE",
        "twilio": "SKxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    },
    "encryption_key": "moltr_enc_v1_FAKE_32bytekeyhere!!",
}

_FAKE_DB_CONFIG = {
    "production": {
        "adapter": "postgresql",
        "host": "db-prod-01.internal",
        "port": 5432,
        "database": "moltr_production",
        "username": "moltr_app",
        "password": "P4ssw0rd_Pr0d_2025!",
        "pool": 5,
    },
    "replica": {
        "host": "db-replica-01.internal",
        "port": 5432,
        "database": "moltr_production",
        "username": "moltr_readonly",
        "password": "R34dOnly_2025#Secure",
    },
}

# ---------------------------------------------------------------------------
# Alert helper
# ---------------------------------------------------------------------------

def _fire_alert(request: Request, trap_name: str) -> str:
    """Fire CRITICAL alert for honeypot access. Returns incident ID."""
    incident_id = str(uuid.uuid4())[:8].upper()
    ip = request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or (
        request.client.host if request.client else "unknown"
    )
    ua = request.headers.get("user-agent", "unknown")
    ts = datetime.now(timezone.utc).isoformat()

    logger.critical(
        "HONEYPOT TRIGGERED | trap=%s | ip=%s | ua=%s | id=%s | ts=%s",
        trap_name, ip, ua[:80], incident_id, ts,
    )

    if _moltr is not None:
        try:
            from src.alerts.manager import Severity
            _moltr._telegram.send_alert(
                title="🍯 Honeypot Triggered",
                message=(
                    f"**Trap:** `{trap_name}`\n"
                    f"**IP:** `{ip}`\n"
                    f"**UA:** `{ua[:80]}`\n"
                    f"**ID:** `{incident_id}`\n"
                    f"**Time:** {ts}"
                ),
                severity=Severity.CRITICAL,
            )
        except Exception as e:
            logger.error("Alert dispatch failed: %s", e)

    return incident_id


def _trap_response(data: dict, incident_id: str) -> JSONResponse:
    """Return convincing fake data so attacker doesn't immediately know it's a trap."""
    return JSONResponse(
        content=data,
        headers={"X-Request-ID": incident_id},
    )


# ---------------------------------------------------------------------------
# Honeypot endpoints
# ---------------------------------------------------------------------------

@honeypot_router.get("/internal/credentials")
@honeypot_router.post("/internal/credentials")
async def trap_credentials(request: Request):
    iid = _fire_alert(request, "/internal/credentials")
    return _trap_response(_FAKE_CREDENTIALS, iid)


@honeypot_router.get("/admin/backup-keys")
@honeypot_router.post("/admin/backup-keys")
async def trap_backup_keys(request: Request):
    iid = _fire_alert(request, "/admin/backup-keys")
    return _trap_response(_FAKE_BACKUP_KEYS, iid)


@honeypot_router.get("/internal/keys")
@honeypot_router.post("/internal/keys")
async def trap_internal_keys(request: Request):
    iid = _fire_alert(request, "/internal/keys")
    return _trap_response(_FAKE_SECRETS, iid)


@honeypot_router.get("/v1/secrets")
@honeypot_router.post("/v1/secrets")
async def trap_secrets(request: Request):
    iid = _fire_alert(request, "/v1/secrets")
    return _trap_response(_FAKE_SECRETS, iid)


@honeypot_router.get("/config/database")
@honeypot_router.post("/config/database")
async def trap_db_config(request: Request):
    iid = _fire_alert(request, "/config/database")
    return _trap_response(_FAKE_DB_CONFIG, iid)


# ---------------------------------------------------------------------------
# Manifest endpoint — for scanners that support allowlisting
# ---------------------------------------------------------------------------

@honeypot_router.get("/honeypots/manifest")
async def honeypot_manifest(request: Request):
    """Public manifest listing all honeypot traps.

    Security scanners can fetch this to exclude honeypot endpoints
    from credential-leak alerts.
    """
    return JSONResponse({
        "version": "1",
        "description": (
            "Moltr Security honeypot API trap registry. "
            "These endpoints serve FAKE data for intrusion detection. "
            "Do NOT flag as real credential leaks."
        ),
        "reference": "https://github.com/moltrHQ/moltr",
        "traps": [
            "/internal/credentials",
            "/admin/backup-keys",
            "/internal/keys",
            "/v1/secrets",
            "/config/database",
        ],
    })
