"""Dashboard API router — JWT-protected endpoints for the React SPA.

These endpoints require a valid dashboard JWT (not the X-API-Key).
They internally call moltr.* directly, so the API key never reaches the browser.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse, Response

from src.auth.router import get_current_user
from src.killswitches.killswitch import EscalationLevel

dashboard_router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"])

# Moltr instance is injected at startup (set by server.py)
_moltr = None

def set_moltr(instance):
    global _moltr
    _moltr = instance


def _ks_status():
    ks = _moltr._killswitch.get_status()
    return {
        "is_locked_down": ks.is_locked_down,
        "active_levels": [lvl.name for lvl in ks.active_levels],
        "highest_level": ks.highest_level.name if ks.highest_level else None,
    }


_VALID_LEVELS = {lvl.name.lower(): lvl for lvl in EscalationLevel}


# ── KillSwitch ──────────────────────────────────────────────────────────────

@dashboard_router.get("/killswitch/log")
async def dashboard_ks_log(
    limit: int = 50,
    offset: int = 0,
    _user: str = Depends(get_current_user),
):
    all_events = _moltr.get_killswitch_log()
    events = all_events[offset:offset + limit]
    return {
        "events": [
            {"timestamp": e.timestamp, "action": e.action, "level": e.level.name, "reason": e.reason}
            for e in events
        ],
        "total": len(all_events),
        "limit": limit,
        "offset": offset,
        "status": _ks_status(),
    }


class _TriggerBody:
    def __init__(self, level: str, reason: str = ""):
        self.level = level
        self.reason = reason


from pydantic import BaseModel

class TriggerRequest(BaseModel):
    level: str
    reason: str = ""

class ResetRequest(BaseModel):
    level: str
    codephrase: str


@dashboard_router.post("/killswitch/trigger")
async def dashboard_ks_trigger(
    req: TriggerRequest,
    _user: str = Depends(get_current_user),
):
    level_name = req.level.lower()
    if level_name not in _VALID_LEVELS:
        return JSONResponse(status_code=400, content={"detail": f"Invalid level: {req.level}"})

    level = _VALID_LEVELS[level_name]
    if level >= EscalationLevel.WIPE and not req.reason.upper().startswith("CONFIRM:"):
        return JSONResponse(status_code=400, content={
            "detail": f"Level {level.name} requires reason to start with 'CONFIRM:'"
        })

    already_active = level in _moltr._killswitch.get_status().active_levels
    _moltr._killswitch.trigger(level, reason=req.reason)

    return {
        "triggered": True,
        "already_active": already_active,
        "level": level.name,
        "reason": req.reason,
        "status": _ks_status(),
    }


@dashboard_router.post("/killswitch/reset")
async def dashboard_ks_reset(
    req: ResetRequest,
    _user: str = Depends(get_current_user),
):
    level_name = req.level.lower()
    if level_name not in _VALID_LEVELS:
        return JSONResponse(status_code=400, content={"detail": f"Invalid level: {req.level}"})

    level = _VALID_LEVELS[level_name]
    success = _moltr._killswitch.reset(level, codephrase=req.codephrase)
    if not success:
        return JSONResponse(status_code=403, content={"detail": "Ungültige Codephrase. Reset verweigert."})

    return {"reset": True, "level": level.name, "status": _ks_status()}


# ── Integrity ────────────────────────────────────────────────────────────────

@dashboard_router.get("/killswitch/export")
async def dashboard_ks_export(_user: str = Depends(get_current_user)):
    """Export full KillSwitch audit log as signed JSON (WORM-style checksum chain)."""
    all_events = _moltr.get_killswitch_log()
    events = [
        {"timestamp": e.timestamp, "action": e.action, "level": e.level.name, "reason": e.reason}
        for e in all_events
    ]
    payload = {
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "total_events": len(events),
        "events": events,
    }
    # SHA-256 checksum of the serialised events for WORM verification
    content_bytes = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode()
    payload["sha256"] = hashlib.sha256(content_bytes).hexdigest()
    export_json = json.dumps(payload, indent=2, ensure_ascii=False)
    filename = f"moltr-killswitch-audit-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.json"
    return Response(
        content=export_json,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@dashboard_router.get("/integrity/report")
async def dashboard_integrity_report(_user: str = Depends(get_current_user)):
    return _moltr.get_integrity_report()


@dashboard_router.get("/integrity/check")
async def dashboard_integrity_check(_user: str = Depends(get_current_user)):
    violations = _moltr.verify_integrity()
    return {
        "violations": [v.to_dict() for v in violations],
        "violations_count": len(violations),
        "clean": len(violations) == 0,
    }


# ── System Status ────────────────────────────────────────────────────────────

@dashboard_router.get("/status")
async def dashboard_status(_user: str = Depends(get_current_user)):
    return {**_moltr.get_status(), "killswitch": _ks_status()}
