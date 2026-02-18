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
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

# Load .env from project root (needed on Windows where PM2 env injection is unreliable)
load_dotenv(PROJECT_ROOT / ".env")
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.moltr import Moltr

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

logger.info("Moltr security modules initialized")

# --------------- FastAPI App ---------------

app = FastAPI(
    title="Moltr Security API",
    description="Security proxy for AI agent actions",
    version="0.1.0",
)

# --------------- API Key Authentication ---------------

MOLTR_API_KEY = os.environ.get("MOLTR_API_KEY", "")

# Endpoints that don't require authentication
PUBLIC_PATHS = {"/health", "/docs", "/openapi.json"}


@app.middleware("http")
async def api_key_auth(request: Request, call_next):
    """Require API key for all endpoints except health/docs."""
    if not MOLTR_API_KEY:
        # No key configured → allow all (backwards compatible)
        return await call_next(request)

    if request.url.path in PUBLIC_PATHS:
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
    url: str
    payload: str = ""


class CommandCheckRequest(BaseModel):
    command: str


class PathCheckRequest(BaseModel):
    path: str
    operation: str = "read"


class OutputScanRequest(BaseModel):
    text: str
    level: str = "high"
    passphrase: str = ""


class MoltrResponse(BaseModel):
    allowed: bool
    reason: str = ""
    details: dict = {}


# --------------- Endpoints ---------------


@app.get("/health")
async def health():
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.get("/status")
async def status():
    return moltr.get_status()


@app.post("/check/url", response_model=MoltrResponse)
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
