"""Dungeoncore FastAPI Router.

Endpoints:
  GET  /dungeoncore/status   — Session-Status (kein Auth nötig)
  GET  /dungeoncore/keys     — Alle Keys (API-Key erforderlich)
  GET  /dungeoncore/keys/{name} — Einzelner Key (API-Key erforderlich)

Phase 1: Liest aus ~/.moltr/session.json (muss vorher via moltr-dc unlock befüllt werden)
Phase 2: In-Memory Store Daemon (kein Disk-Write)
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from .store import read_session, session_status

dungeoncore_router = APIRouter(prefix="/dungeoncore", tags=["dungeoncore"])


def _check_auth(request: Request) -> None:
    """Prüft X-API-Key Header. Wirft 401 bei fehlendem/falschem Key."""
    import os
    expected = os.getenv("MOLTR_API_KEY", "")
    provided = request.headers.get("X-API-Key", "")
    if not expected or provided != expected:
        raise HTTPException(status_code=401, detail="Unauthorized")


@dungeoncore_router.get("/status")
async def get_status() -> JSONResponse:
    """Dungeoncore Session-Status (kein API-Key nötig)."""
    status = session_status()
    return JSONResponse(status)


@dungeoncore_router.get("/keys")
async def get_all_keys(request: Request) -> JSONResponse:
    """Alle Keys aus der aktiven Session.

    Erfordert X-API-Key Header.
    Gibt 423 zurück wenn Dungeoncore nicht entsperrt ist.
    """
    _check_auth(request)
    keys = read_session()
    if keys is None:
        raise HTTPException(
            status_code=423,
            detail="Dungeoncore ist gesperrt. Bitte zuerst 'moltr-dc unlock' ausführen.",
        )
    return JSONResponse({"keys": keys, "count": len(keys)})


@dungeoncore_router.get("/keys/{key_name}")
async def get_key(key_name: str, request: Request) -> JSONResponse:
    """Einzelnen Key aus der aktiven Session.

    Erfordert X-API-Key Header.
    Gibt 423 zurück wenn gesperrt, 404 wenn Key nicht vorhanden.
    """
    _check_auth(request)
    keys = read_session()
    if keys is None:
        raise HTTPException(
            status_code=423,
            detail="Dungeoncore ist gesperrt.",
        )
    key_name_upper = key_name.upper()
    if key_name_upper not in keys:
        raise HTTPException(status_code=404, detail=f"Key '{key_name_upper}' nicht gefunden.")
    return JSONResponse({"key": key_name_upper, "value": keys[key_name_upper]})
