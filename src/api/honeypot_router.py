"""Moltr API Honeypot Traps.

Fake endpoints that look like real internal/admin routes.
Any access triggers an immediate CRITICAL alert + forensic log entry.
No files on disk — zero false positives from filesystem scanners.

Manifest at GET /honeypots/manifest describes all traps for scanner allowlisting.
MIM-compliant manifest at GET /.well-known/moltr-manifest.json (open standard).
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

logger = logging.getLogger("moltr.honeypot")
mim_logger = logging.getLogger("moltr.mim")

honeypot_router = APIRouter(tags=["honeypot"])

# Injected at startup by server.py
_moltr = None

# API trap paths declared in this module
_API_TRAPS = [
    "/internal/credentials",
    "/admin/backup-keys",
    "/internal/keys",
    "/v1/secrets",
    "/config/database",
]

# Honeypot file paths relative to project root (set at startup)
_HONEYPOT_DIR: Path | None = None


def set_honeypot_dir(path: Path) -> None:
    global _HONEYPOT_DIR
    _HONEYPOT_DIR = Path(path)


def set_moltr_for_honeypots(instance) -> None:
    global _moltr
    _moltr = instance


# ---------------------------------------------------------------------------
# Fake response payloads — look real enough to attract attackers
# ---------------------------------------------------------------------------

# NOTE: All values below are INTENTIONALLY FAKE honeypot data.
# gitleaks:allow — these are decoy credentials, not real secrets.
_FAKE_CREDENTIALS = {
    "database": {
        "host": "db-prod-01.internal",
        "port": 5432,
        "user": "svc_moltr_prod",
        "password": "xK9#mP2$vL5nQ8wR3jF6",  # gitleaks:allow
        "database": "moltr_production",
    },
    "redis": {
        "host": "cache-01.internal",
        "port": 6379,
        "auth": "r3d1s_S3cur3_T0k3n",  # gitleaks:allow
    },
    "admin": {
        "user": "moltr_admin",
        "password": "Pr0d_Adm1n#2025_Secure!",  # gitleaks:allow
        "mfa_secret": "JBSWY3DPEHPK3PXP",  # gitleaks:allow
    },
}

_FAKE_BACKUP_KEYS = {
    "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",  # gitleaks:allow
    "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",  # gitleaks:allow
    "backup_enc_key": "bkp_7f3a9c2d1e8b4f6a0c5d2e9b3f7a1c4d",  # gitleaks:allow
    "ssh_backup_user": "backup_svc",
    "ssh_backup_host": "backup-01.internal",
}

_FAKE_SECRETS = {
    "jwt_secret": "super-secret-jwt-key-do-not-share",  # gitleaks:allow
    "api_keys": {
        "stripe": "sk_live_FAKE000000000000000000",  # gitleaks:allow
        "sendgrid": "SG.FAKE_KEY_DO_NOT_USE.EXAMPLE",  # gitleaks:allow
        "twilio": "SKxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",  # gitleaks:allow
    },
    "encryption_key": "moltr_enc_v1_FAKE_32bytekeyhere!!",  # gitleaks:allow
}

_FAKE_DB_CONFIG = {
    "production": {
        "adapter": "postgresql",
        "host": "db-prod-01.internal",
        "port": 5432,
        "database": "moltr_production",
        "username": "moltr_app",
        "password": "P4ssw0rd_Pr0d_2025!",  # gitleaks:allow
        "pool": 5,
    },
    "replica": {
        "host": "db-replica-01.internal",
        "port": 5432,
        "database": "moltr_production",
        "username": "moltr_readonly",
        "password": "R34dOnly_2025#Secure",  # gitleaks:allow
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
    """Legacy manifest listing all honeypot traps (simple format).

    Security scanners can fetch this to exclude honeypot endpoints
    from credential-leak alerts. For MIM-compliant consumers, prefer
    GET /.well-known/moltr-manifest.json instead.
    """
    return JSONResponse({
        "version": "1",
        "description": (
            "Moltr Security honeypot API trap registry. "
            "These endpoints serve FAKE data for intrusion detection. "
            "Do NOT flag as real credential leaks."
        ),
        "reference": "https://github.com/moltrHQ/moltr",
        "mim_endpoint": "/.well-known/moltr-manifest.json",
        "traps": _API_TRAPS,
    })


# ---------------------------------------------------------------------------
# MIM — Moltr Interop Manifest (open standard, CC0)
# Spec: docs/mim-spec.md | https://github.com/moltrHQ/moltr
# ---------------------------------------------------------------------------

def _build_mim_manifest() -> dict:
    """Build a MIM v1.0 compliant manifest from current honeypot configuration."""
    now = datetime.now(timezone.utc).isoformat()

    # Collect honeypot files
    honeypot_files: list[str] = []
    honeypot_dirs: list[str] = []
    ignore_patterns: list[str] = []

    if _HONEYPOT_DIR and _HONEYPOT_DIR.exists():
        rel = str(_HONEYPOT_DIR.name)  # e.g. "honeypots"
        honeypot_dirs.append(f"{rel}/")
        ignore_patterns.append(f"{rel}/**")
        for f in _HONEYPOT_DIR.iterdir():
            if f.is_file() and not f.name.startswith("."):
                honeypot_files.append(f"{rel}/{f.name}")

    return {
        "mim": "1.0",
        "vendor": "moltr-security",
        "generated": now,
        "spec": "https://github.com/moltrHQ/moltr/blob/main/docs/mim-spec.md",
        "honeypots": {
            "files": honeypot_files,
            "endpoints": _API_TRAPS,
            "directories": honeypot_dirs,
        },
        "traps": {
            "description": (
                "All declared resources are intentional intrusion detection traps. "
                "Files contain fake credentials; endpoints return fake data. "
                "Accessing any of them triggers a CRITICAL security alert."
            ),
            "contact": os.environ.get("MOLTR_SECURITY_CONTACT", "security@moltr.tech"),
        },
        "scanner_hints": {
            "ignore_patterns": ignore_patterns,
            "false_positive_notice": (
                "Credentials and keys in declared honeypot paths are deliberately fake. "
                "Do not alert on them — they are monitored traps, not leaks."
            ),
        },
    }


@honeypot_router.get("/.well-known/moltr-manifest.json")
async def mim_manifest(request: Request):
    """Moltr Interop Manifest (MIM) v1.0 — open standard endpoint.

    Security scanners and AI agent frameworks can fetch this manifest to
    identify declared honeypots and avoid false positive alerts.

    Spec: https://github.com/moltrHQ/moltr/blob/main/docs/mim-spec.md
    License: CC0 (public domain — implement freely)
    """
    ip = request.client.host if request.client else "unknown"
    ua = request.headers.get("user-agent", "unknown")
    mim_logger.info(
        "MIM manifest fetched | ip=%s | ua=%s | path=%s",
        ip, ua[:80], request.url.path,
    )

    manifest = _build_mim_manifest()
    return JSONResponse(
        content=manifest,
        headers={
            "Cache-Control": "public, max-age=3600",
            "X-MIM-Version": "1.0",
            "X-MIM-Spec": "https://github.com/moltrHQ/moltr/blob/main/docs/mim-spec.md",
        },
    )
