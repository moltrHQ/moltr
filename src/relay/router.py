"""Moltr Relay Router — secure inter-agent message broker.

Public HTTP + WebSocket endpoints.
All outgoing message content is scanned by Moltr OutputScanner.
Bot-level auth: X-Relay-Bot + X-Relay-Key headers (separate from global X-API-Key).

Endpoints:
    POST  /relay/register           — register a bot, get a relay_key
    POST  /relay/send               — send a message to another bot
    GET   /relay/inbox/{bot_id}     — poll + drain inbox
    WS    /relay/ws/{bot_id}        — real-time delivery stream
    GET   /relay/status             — public status (no auth)
"""

from __future__ import annotations

import logging
import os
import re
import secrets
import time
from typing import Any, Optional

from fastapi import APIRouter, Header, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

from src.relay.registry import (
    RelayMessage,
    BotRegistry,
    FREE_TIER_DAILY_LIMIT,
    MAX_MESSAGE_SIZE_FREE,
    MAX_MESSAGE_SIZE_PAID,
    registry,
)
from src.relay.audit import log_relay_event
from src.relay import compliance as _compliance
from src.relay.injection_scanner import InjectionScanner

logger = logging.getLogger("moltr.relay")

relay_router = APIRouter(prefix="/relay", tags=["Moltr Relay"])

# Injected by server.py at startup (same pattern as dashboard_router / honeypot_router)
_moltr: Any = None
_relay_start_time = time.time()

# WebSocket connection pool: bot_id → set[WebSocket]
_ws_connections: dict[str, set[WebSocket]] = {}

# ── YAML Kaffeefilter (relay-level Defense in Depth) ──────────────────────────
_RELAY_ALLOWED_TYPES = frozenset({"task", "ping", "query", "response"})


def _yaml_schema_check(raw: str) -> tuple[bool, str]:
    """YAML Kaffeefilter on relay level (Defense in Depth, per Ada brainstorming).

    Only accepts YAML with:
    - type ∈ {task, ping, query, response}
    - non-empty content field (inline or block-scalar)

    Returns (ok, reason). No external yaml dependency needed.
    """
    if not raw or not raw.strip():
        return False, "empty content"

    # Simple flat key:value parser — skip indented block-scalar body lines
    fields: dict[str, str] = {}
    for line in raw.splitlines():
        if line.startswith((" ", "\t")):
            continue
        colon = line.find(":")
        if colon < 0:
            continue
        key = line[:colon].strip()
        val = line[colon + 1:].strip().strip("'\"")
        if key:
            fields[key] = val

    msg_type = fields.get("type", "")
    if msg_type not in _RELAY_ALLOWED_TYPES:
        return False, f"invalid type: '{msg_type}'"

    # Check content field — support inline value and block scalar (|, >)
    raw_content_val = fields.get("content", "")
    if raw_content_val and raw_content_val not in ("|", ">", "|-", ">-"):
        return True, "ok"

    # Block scalar: look for indented lines following "content: |"
    m = re.search(r"^content:\s*[|>-]{1,2}\s*\n((?:[ \t]+.+\n?)+)", raw, re.MULTILINE)
    if not m or not m.group(1).strip():
        return False, "missing or empty content"

    return True, "ok"


def set_moltr_for_relay(moltr_instance: Any) -> None:
    """Inject the Moltr instance for OutputScanner access."""
    global _moltr
    _moltr = moltr_instance


# ── Injection Scanner (deterministic, regex-only, no LLM) ─────────────────────
_injection_scanner = InjectionScanner(
    extra_patterns_file=None,  # will be set by _init_injection_scanner()
)
# RELAY_INJECTION_BLOCK=true → block and reject; default=false → flag and deliver
_INJECTION_BLOCK_MODE = os.environ.get("RELAY_INJECTION_BLOCK", "false").lower() == "true"


# ── Credential-Leak-Scanner (OutputScanner — Block 4a) ────────────────────────
# RELAY_CREDENTIAL_SCAN=false to disable entirely (default: true)
_CREDENTIAL_SCAN_ENABLED = os.environ.get("RELAY_CREDENTIAL_SCAN", "true").lower() != "false"

# Block = critical credentials (API keys, private keys) → 403
_CRED_PATTERNS_BLOCK: list[tuple[re.Pattern, str]] = [
    (re.compile(r"sk-proj-[A-Za-z0-9\-_]{40,}"),                    "openai_api_key"),
    (re.compile(r"sk-ant-api[0-9]{2}-[A-Za-z0-9\-_]{40,}"),         "anthropic_api_key"),
    (re.compile(r"AKIA[0-9A-Z]{16}"),                                "aws_access_key"),
    (re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),        "private_key_header"),
    (re.compile(r"ghp_[A-Za-z0-9]{36}"),                            "github_pat"),
]
# Warn = suspicious high-entropy strings → flag and deliver
_CRED_PATTERNS_WARN: list[tuple[re.Pattern, str]] = [
    (re.compile(r"[A-Za-z0-9+/]{60,}={0,2}"),                       "high_entropy_base64"),
]


def _scan_for_credentials(content: str) -> tuple[bool, str, str]:
    """Scan relay payload for credential leaks before delivery.

    Returns (is_clean, severity, pattern_name).
    - is_clean=True  → no credentials found
    - severity="block" → critical, reject with 403
    - severity="warn"  → suspicious, flag and deliver
    """
    for pattern, name in _CRED_PATTERNS_BLOCK:
        if pattern.search(content):
            return False, "block", name
    for pattern, name in _CRED_PATTERNS_WARN:
        if pattern.search(content):
            return False, "warn", name
    return True, "", ""


def init_injection_scanner(config_dir) -> None:
    """Load extra injection patterns from config dir. Called once at startup."""
    global _injection_scanner
    from pathlib import Path
    extra = Path(config_dir) / "relay_injection_patterns.yaml"
    _injection_scanner = InjectionScanner(extra_patterns_file=extra)
    logger.info(
        "[Relay] InjectionScanner ready: %d patterns (block_mode=%s)",
        _injection_scanner.pattern_count, _INJECTION_BLOCK_MODE,
    )


# ── Request Models ────────────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    bot_id: str
    tier: str = "free"
    admin_secret: str = ""


class SendRequest(BaseModel):
    to: str
    content: str
    task_ref: Optional[str] = None


# ── Auth helper ───────────────────────────────────────────────────────────────

async def _auth(bot_id: Optional[str], relay_key: Optional[str]):
    """Authenticate X-Relay-Bot + X-Relay-Key. Returns BotRecord or raises 401."""
    if not bot_id or not relay_key:
        raise HTTPException(
            status_code=401,
            detail="Missing X-Relay-Bot or X-Relay-Key header",
        )
    record = await registry.authenticate(bot_id, relay_key)
    if not record:
        raise HTTPException(status_code=401, detail="Invalid bot credentials")
    return record


# ── Endpoints ─────────────────────────────────────────────────────────────────

@relay_router.post("/register")
async def relay_register(req: RegisterRequest):
    """Register a bot with Moltr Relay. Returns a one-time relay_key.

    The relay_key is returned ONCE and stored hashed. Keep it secret.
    Re-registering the same bot_id invalidates the previous key.
    Paid tier requires a valid admin_secret — otherwise silently downgraded to free.
    """
    import os as _os
    _admin_secret = _os.environ.get("RELAY_ADMIN_SECRET", "")

    bot_id = req.bot_id.strip().lower()
    requested_tier = req.tier.lower() if req.tier.lower() in ("free", "paid") else "free"

    # Paid-Tier Gate: only allow if admin_secret matches
    if requested_tier == "paid":
        if not _admin_secret or req.admin_secret != _admin_secret:
            requested_tier = "free"
            logger.warning(
                "[Relay] Paid-tier denied for %s — invalid admin_secret (downgraded to free)", bot_id
            )
            log_relay_event("tier_downgrade", bot_id=bot_id, reason="invalid_admin_secret")

    tier = requested_tier

    if not bot_id or len(bot_id) > 64:
        raise HTTPException(status_code=400, detail="bot_id must be 1-64 characters")
    if not all(c.isalnum() or c in "-_." for c in bot_id):
        raise HTTPException(
            status_code=400,
            detail="bot_id must be alphanumeric with -._ only",
        )

    relay_key = await registry.register(bot_id, tier=tier)
    log_relay_event("register", bot_id=bot_id, tier=tier)
    logger.info("[Relay] Registered bot: %s (tier: %s)", bot_id, tier)

    return {
        "bot_id": bot_id,
        "relay_key": relay_key,
        "tier": tier,
        "daily_limit": FREE_TIER_DAILY_LIMIT if tier == "free" else "unlimited",
        "max_message_size": "2KB" if tier == "free" else "64KB",
        "message": "Store your relay_key securely — it cannot be recovered.",
    }


@relay_router.post("/send")
async def relay_send(
    req: SendRequest,
    x_relay_bot: Optional[str] = Header(None),
    x_relay_key: Optional[str] = Header(None),
):
    """Send a message to another registered bot.

    Message content is scanned by Moltr OutputScanner before delivery.
    Blocked messages (prompt injection, secrets) are rejected with 403.
    """
    record = await _auth(x_relay_bot, x_relay_key)

    # ── Size check ────────────────────────────────────────────────────────────
    max_size = MAX_MESSAGE_SIZE_FREE if record.tier == "free" else MAX_MESSAGE_SIZE_PAID
    if len(req.content.encode()) > max_size:
        raise HTTPException(
            status_code=413,
            detail=f"Message exceeds {max_size // 1024}KB size limit for {record.tier} tier",
        )

    # ── Quota check ───────────────────────────────────────────────────────────
    if not record.check_and_increment_quota():
        log_relay_event("quota_exceeded", from_bot=record.bot_id, to_bot=req.to)
        raise HTTPException(
            status_code=429,
            detail=f"Daily limit of {FREE_TIER_DAILY_LIMIT} messages reached (free tier)",
        )

    # ── Moltr OutputScanner ───────────────────────────────────────────────────
    if _moltr:
        scan = _moltr.scan_output(req.content, level="high")
        if scan.blocked:
            log_relay_event(
                "blocked",
                from_bot=record.bot_id,
                to_bot=req.to,
                threat=scan.threat_type,
                pattern=scan.matched_pattern,
            )
            logger.warning(
                "[Relay] BLOCKED %s → %s: %s", record.bot_id, req.to, scan.threat_type
            )
            raise HTTPException(
                status_code=403,
                detail=f"Message blocked by Moltr Security: {scan.threat_type}",
            )

    # ── YAML Kaffeefilter (relay-level Defense in Depth) ──────────────────────
    schema_ok, schema_reason = _yaml_schema_check(req.content)
    if not schema_ok:
        log_relay_event(
            "schema_rejected",
            from_bot=record.bot_id,
            to_bot=req.to,
            reason=schema_reason,
        )
        logger.warning(
            "[Relay] YAML schema rejected %s → %s: %s",
            record.bot_id, req.to, schema_reason,
        )
        raise HTTPException(
            status_code=422,
            detail=f"Message rejected by YAML schema filter: {schema_reason}",
        )

    # msg_id generated early so scan events can reference it
    msg_id = secrets.token_hex(8)

    # ── Credential-Leak-Scanner ───────────────────────────────────────────────
    if _CREDENTIAL_SCAN_ENABLED:
        cred_clean, cred_severity, cred_pattern = _scan_for_credentials(req.content)
        if not cred_clean:
            log_relay_event(
                "credential_leak",
                msg_id=msg_id,
                from_bot=record.bot_id,
                to_bot=req.to,
                severity=cred_severity,
                pattern=cred_pattern,
            )
            logger.warning(
                "[Relay] CREDENTIAL LEAK %s → %s | pattern=%s severity=%s",
                record.bot_id, req.to, cred_pattern, cred_severity,
            )
            if cred_severity == "block":
                raise HTTPException(
                    status_code=403,
                    detail=f"Message blocked: credential leak detected (pattern={cred_pattern})",
                )
            # severity="warn": flag and deliver (same as injection flag-and-deliver)

    # ── Prepare message ───────────────────────────────────────────────────────
    msg = RelayMessage(
        msg_id=msg_id,
        from_bot=record.bot_id,
        to_bot=req.to,
        content=req.content,
        task_ref=req.task_ref,
    )

    # ── Injection Scanner (deterministic regex, no LLM) ───────────────────────
    inj = _injection_scanner.scan(req.content)
    if inj.flagged:
        log_relay_event(
            "injection_flagged",
            msg_id=msg_id,
            from_bot=record.bot_id,
            to_bot=req.to,
            pattern=inj.pattern_name,
            severity=inj.severity,
            decoded_via=inj.decoded_via or "raw",
        )
        logger.warning(
            "[Relay] INJECTION FLAGGED %s → %s | pattern=%s severity=%s",
            record.bot_id, req.to, inj.pattern_name, inj.severity,
        )
        if _INJECTION_BLOCK_MODE:
            raise HTTPException(
                status_code=403,
                detail=f"Message blocked: prompt injection detected (pattern={inj.pattern_name}, via={inj.decoded_via or 'raw'})",
            )
        # Flag-and-deliver mode (default): deliver but persist as flagged

    # ── Deliver ───────────────────────────────────────────────────────────────
    delivered = await registry.deliver(msg)
    if not delivered:
        raise HTTPException(status_code=404, detail=f"Target bot '{req.to}' not registered")

    # WebSocket push (best-effort, non-blocking)
    await _ws_push(req.to, msg)

    # Compliance: persist message + notify SSE + webhooks (best-effort)
    import asyncio as _asyncio
    _asyncio.create_task(_compliance.persist_message(
        msg,
        flagged=inj.flagged,
        flag_reason=f"injection:{inj.pattern_name}" if inj.flagged else "",
    ))

    log_relay_event(
        "send",
        msg_id=msg_id,
        from_bot=record.bot_id,
        to_bot=req.to,
        content_len=len(req.content),
        task_ref=req.task_ref,
    )
    logger.info(
        "[Relay] %s → %s (msg_id: %s, %d bytes)",
        record.bot_id, req.to, msg_id, len(req.content),
    )

    return {
        "ok": True,
        "msg_id": msg_id,
        "from": record.bot_id,
        "to": req.to,
        "quota_remaining": record.quota_remaining,
    }


@relay_router.get("/inbox/{bot_id}")
async def relay_inbox(
    bot_id: str,
    x_relay_bot: Optional[str] = Header(None),
    x_relay_key: Optional[str] = Header(None),
):
    """Poll and drain the inbox for a bot. Returns all pending messages."""
    record = await _auth(x_relay_bot, x_relay_key)

    if record.bot_id != bot_id:
        raise HTTPException(status_code=403, detail="Cannot read another bot's inbox")

    messages = await registry.drain_inbox(bot_id)
    log_relay_event("inbox_poll", bot_id=bot_id, count=len(messages))

    return {
        "bot_id": bot_id,
        "count": len(messages),
        "messages": [
            {
                "msg_id": m.msg_id,
                "from": m.from_bot,
                "content": m.content,
                "task_ref": m.task_ref,
                "created_at": m.created_at,
            }
            for m in messages
        ],
    }


@relay_router.websocket("/ws/{bot_id}")
async def relay_ws(websocket: WebSocket, bot_id: str, key: str = ""):
    """WebSocket stream for real-time message delivery.

    Connect with: ws://relay.moltr.tech/relay/ws/{bot_id}?key=<relay_key>
    Pending inbox messages are flushed immediately on connect.
    Subsequent messages are pushed as JSON as they arrive.
    Send "ping" to receive "pong" (keep-alive).
    """
    if not key:
        await websocket.close(code=4001, reason="Missing ?key= query param")
        return

    record = await registry.authenticate(bot_id, key)
    if not record:
        await websocket.close(code=4001, reason="Invalid bot credentials")
        return

    await websocket.accept()

    _ws_connections.setdefault(bot_id, set()).add(websocket)
    log_relay_event("ws_connect", bot_id=bot_id)
    logger.info("[Relay] WebSocket connected: %s", bot_id)

    try:
        # Flush pending inbox immediately on connect
        pending = await registry.drain_inbox(bot_id)
        for msg in pending:
            await websocket.send_json(_msg_to_dict(msg))

        # Keep connection alive — handle ping/pong
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")

    except WebSocketDisconnect:
        pass
    finally:
        _ws_connections.get(bot_id, set()).discard(websocket)
        if bot_id in _ws_connections and not _ws_connections[bot_id]:
            del _ws_connections[bot_id]
        log_relay_event("ws_disconnect", bot_id=bot_id)
        logger.info("[Relay] WebSocket disconnected: %s", bot_id)


class SetTierRequest(BaseModel):
    bot_id: str
    tier: str


@relay_router.post("/admin/set-tier")
async def admin_set_tier(
    req: SetTierRequest,
    x_admin_secret: Optional[str] = Header(None),
):
    """Admin endpoint: forcibly set the tier for any registered bot.

    Requires X-Admin-Secret header matching RELAY_ADMIN_SECRET env var.
    """
    import os as _os
    _admin_secret = _os.environ.get("RELAY_ADMIN_SECRET", "")
    if not _admin_secret or x_admin_secret != _admin_secret:
        raise HTTPException(status_code=403, detail="Invalid admin secret")

    ok = await registry.set_tier(req.bot_id, req.tier)
    if not ok:
        raise HTTPException(status_code=404, detail=f"Bot '{req.bot_id}' not registered")

    log_relay_event("admin_set_tier", bot_id=req.bot_id, tier=req.tier)
    return {"ok": True, "bot_id": req.bot_id, "tier": req.tier}


@relay_router.get("/status")
async def relay_status():
    """Public status endpoint — no authentication required."""
    uptime_s = int(time.time() - _relay_start_time)
    return {
        "service": "Moltr Relay",
        "version": "1.0.0",
        "status": "operational",
        "bots_registered": registry.bot_count,
        "ws_active": sum(len(s) for s in _ws_connections.values()),
        "uptime_seconds": uptime_s,
        "tiers": {
            "free": {
                "daily_limit": FREE_TIER_DAILY_LIMIT,
                "max_message_size": "2KB",
                "scan": "OutputScanner (high)",
            },
            "paid": {
                "daily_limit": "unlimited",
                "max_message_size": "64KB",
                "scan": "OutputScanner (high)",
            },
        },
    }


# ── Internal helpers ──────────────────────────────────────────────────────────

def _msg_to_dict(msg: RelayMessage) -> dict:
    return {
        "msg_id": msg.msg_id,
        "from": msg.from_bot,
        "content": msg.content,
        "task_ref": msg.task_ref,
        "created_at": msg.created_at,
    }


async def _ws_push(bot_id: str, msg: RelayMessage) -> None:
    """Push message to all active WebSocket connections for a bot (best-effort)."""
    conns = _ws_connections.get(bot_id, set())
    if not conns:
        return
    payload = _msg_to_dict(msg)
    dead: set[WebSocket] = set()
    for ws in list(conns):
        try:
            await ws.send_json(payload)
        except Exception:
            dead.add(ws)
    for ws in dead:
        conns.discard(ws)
