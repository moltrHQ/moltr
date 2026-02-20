"""Session Store — entschlüsselte Keys temporär auf Disk halten.

Phase 1: Keys werden in ~/.moltr/session.json gespeichert (mit Expiry).
Phase 2: In-Memory-Daemon via FastAPI-Endpoint (kein Disk-Write).

Die session.json ist Owner-only (chmod 600) und hat ein Ablaufdatum.
Agenten lesen direkt aus session.json oder via GET /dungeoncore/keys.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .config import SESSION_FILE, ensure_moltr_dir

DEFAULT_DURATION_HOURS = 8


def write_session(keys: dict, duration_hours: int = DEFAULT_DURATION_HOURS) -> None:
    """Schreibt entschlüsselte Keys in die Session-Datei."""
    ensure_moltr_dir()
    expires_at = (
        datetime.now(timezone.utc) + timedelta(hours=duration_hours)
    ).isoformat()
    session = {
        "keys": keys,
        "expires_at": expires_at,
        "duration_hours": duration_hours,
        "unlocked_at": datetime.now(timezone.utc).isoformat(),
    }
    with open(SESSION_FILE, "w", encoding="utf-8") as f:
        json.dump(session, f, indent=2)
    try:
        SESSION_FILE.chmod(0o600)
    except NotImplementedError:
        pass


def read_session() -> dict | None:
    """Gibt die Keys zurück wenn Session gültig, sonst None."""
    if not SESSION_FILE.exists():
        return None
    with open(SESSION_FILE, encoding="utf-8") as f:
        session = json.load(f)
    expires_at = datetime.fromisoformat(session["expires_at"])
    if datetime.now(timezone.utc) > expires_at:
        clear_session()
        return None
    return session["keys"]


def clear_session() -> bool:
    """Löscht die Session (lock)."""
    if SESSION_FILE.exists():
        SESSION_FILE.unlink()
        return True
    return False


def session_status() -> dict:
    """Gibt Status der aktuellen Session zurück."""
    if not SESSION_FILE.exists():
        return {"unlocked": False}
    with open(SESSION_FILE, encoding="utf-8") as f:
        session = json.load(f)
    expires_at = datetime.fromisoformat(session["expires_at"])
    now = datetime.now(timezone.utc)
    if now > expires_at:
        clear_session()
        return {"unlocked": False}
    remaining = expires_at - now
    total_secs = int(remaining.total_seconds())
    hours, remainder = divmod(total_secs, 3600)
    minutes = remainder // 60
    return {
        "unlocked": True,
        "expires_at": session["expires_at"],
        "remaining": f"{hours}h {minutes}m",
        "key_count": len(session.get("keys", {})),
        "unlocked_at": session.get("unlocked_at"),
    }
