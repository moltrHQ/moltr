# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Moltr-Commercial
# Copyright (C) 2026 Walter Troska / moltrHQ <hello@moltr.tech>
# See LICENSE (AGPL-3.0) or LICENSE-COMMERCIAL for licensing terms.

"""Moltr Security API Server.

FastAPI server that exposes Moltr security checks as HTTP endpoints.
Runs as a standalone service managed by PM2.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

# Load .env from project root (needed on Windows where PM2 env injection is unreliable)
load_dotenv(PROJECT_ROOT / ".env")
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.moltr import Moltr
from src.killswitches.killswitch import EscalationLevel
from src.auth.router import auth_router
from src.auth.session_store import session_store
from src.api.dashboard_router import dashboard_router, set_moltr
from src.api.honeypot_router import honeypot_router, set_moltr_for_honeypots, set_honeypot_dir
from src.relay.router import relay_router, set_moltr_for_relay, init_injection_scanner
from src.relay.audit import init_audit
from src.relay.registry import init_db, registry, get_pool
from src.relay.compliance import init_compliance_db
from src.relay.compliance_router import compliance_router
from src.dungeoncore.router import dungeoncore_router
from src.api.skillcheck_router import skillcheck_router, init_skillcheck
from src.api.registry_router import registry_router, init_registry

# --------------- Logging ---------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("moltr.api")

# --------------- Incident Logger (forensic) ---------------

LOGS_DIR = PROJECT_ROOT / "logs"
LOGS_DIR.mkdir(exist_ok=True)
init_audit(LOGS_DIR)

incident_logger = logging.getLogger("moltr.forensic")
incident_logger.setLevel(logging.WARNING)
incident_handler = logging.FileHandler(
    LOGS_DIR / "moltr-forensic.log", encoding="utf-8"
)
incident_handler.setFormatter(logging.Formatter("%(message)s"))
incident_logger.addHandler(incident_handler)
incident_logger.propagate = False


def log_incident(
    request: Request,
    check_type: str,
    reason: str,
    details: dict,
) -> str:
    """Log a forensic incident record for blocked actions. Returns incident ID."""
    incident_id = str(uuid.uuid4())
    record = {
        "incident_id": incident_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "incident_type": check_type,
        "severity": "CRITICAL",
        "source_ip": request.client.host if request.client else "unknown",
        "source_port": request.client.port if request.client else 0,
        "action_taken": "BLOCKED",
        "reason": reason,
        "blocked_content": _truncate_content(details),
        "raw_request": {
            "endpoint": str(request.url),
            "method": request.method,
            "user_agent": request.headers.get("user-agent", "unknown"),
            "content_type": request.headers.get("content-type", "unknown"),
        },
        "server": {
            "hostname": os.environ.get("COMPUTERNAME", "unknown"),
            "pid": os.getpid(),
        },
    }
    incident_logger.warning(json.dumps(record, ensure_ascii=False))
    logger.warning("INCIDENT %s: [%s] %s (IP: %s)", incident_id[:8], check_type, reason, record["source_ip"])
    return incident_id


def _truncate_content(details: dict) -> dict:
    """Truncate long values for forensic log (keep under 500 chars per field)."""
    truncated = {}
    for key, value in details.items():
        if isinstance(value, str) and len(value) > 500:
            truncated[key] = value[:500] + "...[TRUNCATED]"
        else:
            truncated[key] = value
    return truncated

# --------------- Moltr Instance ---------------

moltr = Moltr(
    config_path=PROJECT_ROOT / "config" / "default.yaml",
    secrets_storage=str(PROJECT_ROOT / "secrets.json"),
    project_root=str(PROJECT_ROOT),
)

# Set KillSwitch codephrase from environment (required for reset)
KILLSWITCH_CODEPHRASE = os.environ.get("MOLTR_KILLSWITCH_CODEPHRASE", "")
if KILLSWITCH_CODEPHRASE:
    moltr._killswitch._codephrase = KILLSWITCH_CODEPHRASE
    logger.info("KillSwitch codephrase loaded from environment")
else:
    logger.warning("MOLTR_KILLSWITCH_CODEPHRASE not set — KillSwitch reset will accept empty codephrase")

logger.info("Moltr security modules initialized")

# Wire moltr instance into dashboard, honeypot, and relay routers
set_moltr(moltr)
set_moltr_for_honeypots(moltr)
honeypot_dir = PROJECT_ROOT / "honeypots"
set_honeypot_dir(honeypot_dir)
set_moltr_for_relay(moltr)
init_injection_scanner(PROJECT_ROOT / "config")
init_skillcheck(PROJECT_ROOT / "config")
init_registry(PROJECT_ROOT / "config")

# Register honeypot files in filesystem guard for is_honeypot detection
if honeypot_dir.exists():
    _hp_count = 0
    for _hp_file in honeypot_dir.iterdir():
        if _hp_file.is_file():
            moltr._filesystem_guard.register_honeypot(_hp_file)
            _hp_count += 1
    logger.info("Registered %d honeypot files in filesystem guard", _hp_count)

# --------------- FastAPI App ---------------

# --------------- Rate Limiting ---------------

limiter = Limiter(key_func=get_remote_address)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup: connect to DB, load relay bot registrations, init compliance tables."""
    await init_db()
    await registry.load_from_db()
    await init_compliance_db(get_pool())
    yield


app = FastAPI(
    title="Moltr Security API",
    description="Security proxy for AI agent actions",
    version="0.2.0",
    lifespan=lifespan,
)
app.state.limiter = limiter

# Register routers
app.include_router(auth_router)
app.include_router(dashboard_router)
app.include_router(honeypot_router)
app.include_router(relay_router)
app.include_router(compliance_router)
app.include_router(dungeoncore_router)
app.include_router(skillcheck_router)
app.include_router(registry_router)


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    logger.warning("RATE LIMIT from %s on %s", request.client.host if request.client else "unknown", request.url.path)
    return JSONResponse(
        status_code=429,
        content={"detail": "Rate limit exceeded. Try again later.", "retry_after": str(exc.detail)},
    )

# --------------- API Key Authentication ---------------

MOLTR_API_KEY = os.environ.get("MOLTR_API_KEY", "")

# Endpoints that don't require API key authentication
PUBLIC_PATHS = {
    "/health", "/docs", "/openapi.json",
    "/api/v1/auth/login",
    "/api/v1/auth/refresh",
    "/.well-known/moltr-manifest.json",
    "/honeypots/manifest",
    "/dungeoncore/status",  # Session-Status ist public (kein Secret)
    "/api/v1/skillcheck/health",  # SkillCheck health — public für Agent-Discovery
    "/api/v1/registry/health",   # Registry health — public
}


@app.middleware("http")
async def api_key_auth(request: Request, call_next):
    """Require API key for all endpoints except health/docs."""
    if not MOLTR_API_KEY:
        # No key configured → allow all (backwards compatible)
        return await call_next(request)

    if request.url.path in PUBLIC_PATHS:
        return await call_next(request)

    # Dashboard SPA + static assets are public (auth handled by JWT in dashboard)
    if request.url.path.startswith("/dashboard"):
        return await call_next(request)

    # Dashboard API endpoints use JWT auth (not X-API-Key)
    if request.url.path.startswith("/api/v1/dashboard"):
        return await call_next(request)

    # Honeypot traps are intentionally public (attacker bait)
    if request.url.path.startswith("/internal/") or \
       request.url.path.startswith("/admin/backup") or \
       request.url.path.startswith("/v1/secrets") or \
       request.url.path.startswith("/config/database"):
        return await call_next(request)

    # Relay endpoints use their own X-Relay-Bot/X-Relay-Key auth (not global X-API-Key)
    if request.url.path.startswith("/relay/"):
        return await call_next(request)

    # Registry is public — agents discover skills without authentication
    if request.url.path.startswith("/api/v1/registry/"):
        return await call_next(request)

    # Accept key via header or query param
    key = request.headers.get("X-API-Key") or request.query_params.get("api_key")
    if not key:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            key = auth[7:]

    if key != MOLTR_API_KEY:
        logger.warning("AUTH DENIED from %s for %s", request.client.host if request.client else "unknown", request.url.path)
        return JSONResponse(status_code=401, content={"detail": "Invalid or missing API key"})

    return await call_next(request)

# --------------- Request/Response Models ---------------


class UrlCheckRequest(BaseModel):
    """Check an outbound URL against the network firewall."""
    url: str
    payload: str = ""


class CommandCheckRequest(BaseModel):
    """Validate a shell command against the security policy."""
    command: str


class PathCheckRequest(BaseModel):
    """Check a filesystem path against the access policy."""
    path: str
    operation: str = "read"


class OutputScanRequest(BaseModel):
    """Scan AI agent output for secret leaks."""
    text: str
    level: str = "high"
    passphrase: str = ""


class MoltrResponse(BaseModel):
    """Standard response for security check endpoints."""
    allowed: bool
    reason: str = ""
    details: dict = {}


# --------------- Endpoints ---------------


@app.get("/health")
@limiter.limit("60/minute")
async def health(request: Request):
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.get("/status")
@limiter.limit("30/minute")
async def status(request: Request):
    return moltr.get_status()


@app.post("/check/url", response_model=MoltrResponse)
@limiter.limit("120/minute")
async def check_url(req: UrlCheckRequest, request: Request):
    result = moltr.check_url(req.url, req.payload)
    allowed = result.allowed
    logger.info(
        "%s URL %s (%s)",
        "ALLOW" if allowed else "BLOCK",
        req.url,
        result.reason,
    )
    if not allowed:
        log_incident(request, "url", result.reason, {
            "url": req.url,
            "payload_length": len(req.payload),
            "domain": result.domain,
            "matched_rule": result.matched_rule,
        })
    return MoltrResponse(
        allowed=allowed,
        reason=result.reason,
        details={
            "domain": result.domain,
            "matched_rule": result.matched_rule,
        },
    )


@app.post("/check/command", response_model=MoltrResponse)
@limiter.limit("120/minute")
async def check_command(req: CommandCheckRequest, request: Request):
    result = moltr.validate_command(req.command)
    allowed = result.allowed
    logger.info(
        "%s CMD '%s' (%s)",
        "ALLOW" if allowed else "BLOCK",
        req.command[:80],
        result.reason,
    )
    if not allowed:
        log_incident(request, "command", result.reason, {
            "command": req.command,
            "risk_level": result.risk_level,
        })
    return MoltrResponse(
        allowed=allowed,
        reason=result.reason,
        details={
            "risk_level": result.risk_level,
            "original_command": result.original_command,
        },
    )


@app.post("/check/path", response_model=MoltrResponse)
@limiter.limit("120/minute")
async def check_path(req: PathCheckRequest, request: Request):
    result = moltr.check_path(req.path, req.operation)
    blocked = result.blocked
    logger.info(
        "%s PATH %s [%s] (%s)",
        "BLOCK" if blocked else "ALLOW",
        req.path,
        req.operation,
        result.reason,
    )
    if blocked:
        log_incident(request, "path", result.reason, {
            "path": req.path,
            "operation": req.operation,
            "is_honeypot": result.is_honeypot,
        })
    return MoltrResponse(
        allowed=not blocked,
        reason=result.reason,
        details={
            "is_honeypot": result.is_honeypot,
            "path": str(result.path),
            "operation": result.operation,
        },
    )


@app.post("/scan/output", response_model=MoltrResponse)
@limiter.limit("60/minute")
async def scan_output(req: OutputScanRequest, request: Request):
    result = moltr.scan_output(req.text, level=req.level, passphrase=req.passphrase)
    blocked = result.blocked
    logger.info(
        "%s OUTPUT scan [%s] (%s)",
        "BLOCK" if blocked else "ALLOW",
        req.level,
        result.threat_type if blocked else "clean",
    )
    if blocked:
        log_incident(request, "output", result.threat_type, {
            "matched_pattern": result.matched_pattern,
            "deobfuscation_method": result.deobfuscation_method,
            "text_preview": req.text[:500],
            "text_length": len(req.text),
        })
    return MoltrResponse(
        allowed=not blocked,
        reason=result.threat_type if blocked else "clean",
        details={
            "matched_pattern": result.matched_pattern,
            "deobfuscation_method": result.deobfuscation_method,
        },
    )


# --------------- KillSwitch Endpoints ---------------

VALID_LEVELS = {lvl.name.lower(): lvl for lvl in EscalationLevel}


class KillSwitchTriggerRequest(BaseModel):
    """Trigger a kill switch escalation level."""
    level: str  # pause, network_cut, lockdown, wipe, emergency
    reason: str = ""


class KillSwitchResetRequest(BaseModel):
    """Reset a kill switch level (requires codephrase)."""
    level: str
    codephrase: str


@app.post("/killswitch/trigger")
@limiter.limit("3/minute")
async def killswitch_trigger(req: KillSwitchTriggerRequest, request: Request):
    level_name = req.level.lower()
    if level_name not in VALID_LEVELS:
        return JSONResponse(status_code=400, content={
            "detail": f"Invalid level. Valid: {', '.join(VALID_LEVELS.keys())}",
        })

    level = VALID_LEVELS[level_name]

    # Safety: WIPE and EMERGENCY require "CONFIRM:" prefix in reason
    if level >= EscalationLevel.WIPE and not req.reason.upper().startswith("CONFIRM:"):
        return JSONResponse(status_code=400, content={
            "detail": f"Level {level.name} requires reason to start with 'CONFIRM: ' as safety check.",
        })

    # Idempotency: check if level is already active
    already_active = level in moltr._killswitch.get_status().active_levels

    moltr._killswitch.trigger(level, reason=req.reason)
    source_ip = request.client.host if request.client else "unknown"
    logger.critical("KILLSWITCH TRIGGERED: Level %s — %s (IP: %s)%s",
                    level.name, req.reason, source_ip,
                    " [already active]" if already_active else "")

    # LOCKDOWN+ invalidates all active dashboard sessions
    if level >= EscalationLevel.LOCKDOWN:
        killed = session_store.invalidate_all()
        if killed:
            logger.critical("KILLSWITCH SESSION-KILL: %d dashboard sessions invalidated", killed)

    log_incident(request, "killswitch_trigger", f"Level {level.name}: {req.reason}", {
        "level": level.name,
        "level_value": level.value,
        "source_ip": source_ip,
        "already_active": already_active,
    })

    return {
        "triggered": True,
        "already_active": already_active,
        "level": level.name,
        "reason": req.reason,
        "status": _format_killswitch_status(),
    }


@app.post("/killswitch/reset")
@limiter.limit("5/minute")
async def killswitch_reset(req: KillSwitchResetRequest, request: Request):
    level_name = req.level.lower()
    if level_name not in VALID_LEVELS:
        return JSONResponse(status_code=400, content={
            "detail": f"Invalid level. Valid: {', '.join(VALID_LEVELS.keys())}",
        })

    level = VALID_LEVELS[level_name]
    success = moltr._killswitch.reset(level, codephrase=req.codephrase)

    source_ip = request.client.host if request.client else "unknown"

    if not success:
        logger.warning("KILLSWITCH RESET DENIED: Level %s — wrong codephrase (IP: %s)",
                       level.name, source_ip)
        log_incident(request, "killswitch_reset_denied", f"Level {level.name}: wrong codephrase", {
            "level": level.name,
            "source_ip": source_ip,
        })
        return JSONResponse(status_code=403, content={
            "detail": "Invalid codephrase. Reset denied.",
        })

    logger.info("KILLSWITCH RESET: Level %s (IP: %s)", level.name, source_ip)

    return {
        "reset": True,
        "level": level.name,
        "status": _format_killswitch_status(),
    }


@app.get("/killswitch/log")
@limiter.limit("30/minute")
async def killswitch_log(request: Request, limit: int = 50, offset: int = 0):
    all_events = moltr.get_killswitch_log()
    total = len(all_events)
    events = all_events[offset:offset + limit]
    return {
        "events": [
            {
                "timestamp": e.timestamp,
                "action": e.action,
                "level": e.level.name,
                "reason": e.reason,
            }
            for e in events
        ],
        "total": total,
        "limit": limit,
        "offset": offset,
        "status": _format_killswitch_status(),
    }


# --------------- Integrity Watchdog Endpoints ---------------


@app.post("/scan/lockdown/reset")
@limiter.limit("10/minute")
async def scan_lockdown_reset(request: Request):
    """Reset the output scanner lockdown state (requires API key)."""
    moltr._output_scanner.reset_lockdown()
    logger.info("Output scanner lockdown reset by %s", request.client.host if request.client else "unknown")
    return {"reset": True, "is_locked": moltr._output_scanner.is_locked}


@app.get("/scan/lockdown/status")
@limiter.limit("30/minute")
async def scan_lockdown_status(request: Request):
    """Check the current output scanner lockdown state."""
    return {"is_locked": moltr._output_scanner.is_locked}


@app.get("/integrity/check")
@limiter.limit("10/minute")
async def integrity_check(request: Request):
    """Run an integrity verification and return violations."""
    violations = moltr.verify_integrity()
    return {
        "violations": [v.to_dict() for v in violations],
        "violations_count": len(violations),
        "clean": len(violations) == 0,
    }


@app.get("/integrity/report")
@limiter.limit("30/minute")
async def integrity_report(request: Request):
    """Return the full integrity watchdog report."""
    return moltr.get_integrity_report()


# --------------- Helper Functions ---------------


def _format_killswitch_status() -> dict:
    """Format the current killswitch status for API responses."""
    ks = moltr._killswitch.get_status()
    return {
        "is_locked_down": ks.is_locked_down,
        "active_levels": [lvl.name for lvl in ks.active_levels],
        "highest_level": ks.highest_level.name if ks.highest_level else None,
    }


# --------------- CSP Middleware ---------------

# Strict CSP for API endpoints
_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "frame-ancestors 'none';"
)

# Relaxed CSP for served HTML pages (console, register) that use inline scripts + Google Fonts
_CSP_HTML = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "img-src 'self' data:; "
    "font-src 'self' https://fonts.gstatic.com; "
    "connect-src 'self'; "
    "frame-ancestors 'none';"
)

_HTML_PATHS = {"/relay/console", "/relay/register"}


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Add security headers to all responses."""
    response = await call_next(request)
    csp = _CSP_HTML if request.url.path in _HTML_PATHS else _CSP
    response.headers["Content-Security-Policy"] = csp
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


# --------------- Dashboard Static Files ---------------

STATIC_DIR = PROJECT_ROOT / "static"

if STATIC_DIR.exists():
    # Serve built React SPA under /dashboard/
    app.mount("/dashboard", StaticFiles(directory=STATIC_DIR, html=True), name="dashboard")
    logger.info("Dashboard static files mounted at /dashboard/")
else:
    logger.warning("Dashboard static dir not found (%s) — run: cd dashboard && npm run build", STATIC_DIR)


# SPA fallback: any /dashboard/* URL that doesn't match a file serves index.html
@app.get("/dashboard/{full_path:path}", include_in_schema=False)
async def spa_fallback(full_path: str):
    index = STATIC_DIR / "index.html"
    if index.exists():
        return FileResponse(index)
    return JSONResponse(status_code=503, content={"detail": "Dashboard not built. Run: cd dashboard && npm run build"})
