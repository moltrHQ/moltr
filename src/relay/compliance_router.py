"""Moltr Relay Compliance Router — owner accounts, SSE console, DSGVO.

Endpoints:
    POST   /relay/owners/register                    — create owner account
    POST   /relay/owners/link-bot                    — associate bot with owner
    GET    /relay/console                            — web console HTML
    GET    /relay/console/stream                     — SSE real-time message stream
    GET    /relay/console/messages                   — historical messages query
    DELETE /relay/owners/data                        — DSGVO Art. 17 erasure
    POST   /relay/admin/flag/{msg_id}                — flag message for review
    POST   /relay/admin/kontrollinstanz/register     — register compliance webhook
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Optional

from fastapi import APIRouter, Header, HTTPException, Query
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel

from src.relay.compliance import (
    delete_owner_data,
    flag_message,
    get_messages,
    get_owner_by_token,
    link_bot,
    register_kontrollinstanz,
    register_owner,
    register_sse_queue,
    unregister_sse_queue,
)

logger = logging.getLogger("moltr.relay.compliance")
compliance_router = APIRouter(prefix="/relay", tags=["Relay Compliance"])


# ── Auth helpers ──────────────────────────────────────────────────────────────

def _admin_secret() -> str:
    return os.environ.get("RELAY_ADMIN_SECRET", "")


def _console_admin_token() -> str:
    return os.environ.get("CONSOLE_ADMIN_TOKEN", "")


def _is_admin(token: str) -> bool:
    t = _console_admin_token()
    return bool(t) and token == t


# ── Request models ────────────────────────────────────────────────────────────

class OwnerRegisterRequest(BaseModel):
    name: str
    address: str
    email: str
    tier: str = "free"


class LinkBotRequest(BaseModel):
    owner_token: str
    bot_id: str
    relay_key: str


class FlagRequest(BaseModel):
    reason: str
    flagged_by: str = "kontrollinstanz"


class KontrollinstanzRegisterRequest(BaseModel):
    webhook_url: str
    owner_token: Optional[str] = None


# ── Endpoints ─────────────────────────────────────────────────────────────────

@compliance_router.post("/owners/register")
async def owner_register(req: OwnerRegisterRequest):
    """Register a new owner account. Returns owner_token — store it securely."""
    if not req.name.strip() or not req.address.strip() or not req.email.strip():
        raise HTTPException(status_code=400, detail="name, address and email required")
    if len(req.name) > 200 or len(req.address) > 500 or len(req.email) > 200:
        raise HTTPException(status_code=400, detail="Field too long")
    if req.tier not in ("free", "pro", "enterprise"):
        req.tier = "free"
    try:
        result = await register_owner(req.name, req.address, req.email, req.tier)
    except Exception as e:
        if "unique" in str(e).lower():
            raise HTTPException(status_code=409, detail="Email already registered")
        raise HTTPException(status_code=500, detail="Registration failed")
    return {
        **result,
        "message": "Store your owner_token securely — it authenticates all console and DSGVO requests.",
    }


@compliance_router.post("/owners/link-bot")
async def owner_link_bot(req: LinkBotRequest):
    """Associate a registered relay bot with an owner account."""
    owner = await get_owner_by_token(req.owner_token)
    if not owner:
        raise HTTPException(status_code=401, detail="Invalid owner_token")
    ok = await link_bot(req.owner_token, req.bot_id, req.relay_key)
    if not ok:
        raise HTTPException(status_code=404, detail="Bot not found or invalid relay_key")
    return {"ok": True, "bot_id": req.bot_id, "owner": owner["name"]}


@compliance_router.get("/console", response_class=HTMLResponse, include_in_schema=False)
async def console_html():
    """Serve the Relay Console web interface."""
    return HTMLResponse(_CONSOLE_HTML)


@compliance_router.get("/console/stream")
async def console_sse(
    owner_token: str = Query(""),
    admin_token: str = Query(""),
    x_owner_token: Optional[str] = Header(None),
    x_admin_token: Optional[str] = Header(None),
):
    """SSE stream of relay messages in real-time.

    Admin sees all messages. Owner sees only messages from/to their bots.
    Auth: ?admin_token=... or X-Admin-Token header | ?owner_token=... or X-Owner-Token header
    """
    eff_admin = admin_token or x_admin_token or ""
    eff_owner = owner_token or x_owner_token or ""
    is_admin_auth = _is_admin(eff_admin)

    if not is_admin_auth:
        if not eff_owner:
            raise HTTPException(status_code=401, detail="Provide owner_token or admin_token")
        owner_data = await get_owner_by_token(eff_owner)
        if not owner_data:
            raise HTTPException(status_code=401, detail="Invalid owner_token")

    # Load last 50 messages as history
    history = await get_messages(
        owner_token=eff_owner if not is_admin_auth else None,
        is_admin=is_admin_auth,
        limit=50,
    )

    async def event_gen():
        q: asyncio.Queue = asyncio.Queue(maxsize=200)
        register_sse_queue(q)
        try:
            # Send history as first event
            yield "event: history\ndata: " + json.dumps(history) + "\n\n"
            while True:
                try:
                    msg = await asyncio.wait_for(q.get(), timeout=25)
                    yield "data: " + json.dumps(msg) + "\n\n"
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            unregister_sse_queue(q)

    return StreamingResponse(
        event_gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@compliance_router.get("/console/messages")
async def console_messages(
    owner_token: str = Query(""),
    admin_token: str = Query(""),
    limit: int = Query(100, ge=1, le=500),
    x_owner_token: Optional[str] = Header(None),
    x_admin_token: Optional[str] = Header(None),
):
    """Historical message query. Admin sees all; owner sees own bots only."""
    eff_admin = admin_token or x_admin_token or ""
    eff_owner = owner_token or x_owner_token or ""
    is_admin_auth = _is_admin(eff_admin)

    if not is_admin_auth:
        if not eff_owner:
            raise HTTPException(status_code=401, detail="Provide owner_token or admin_token")
        owner = await get_owner_by_token(eff_owner)
        if not owner:
            raise HTTPException(status_code=401, detail="Invalid owner_token")

    messages = await get_messages(
        owner_token=eff_owner if not is_admin_auth else None,
        is_admin=is_admin_auth,
        limit=limit,
    )
    return {"count": len(messages), "messages": messages}


@compliance_router.delete("/owners/data")
async def dsgvo_delete(
    owner_token: str = Query(""),
    x_owner_token: Optional[str] = Header(None),
):
    """DSGVO Art. 17 — Right to erasure. Deletes all messages and deactivates account."""
    eff_owner = owner_token or x_owner_token or ""
    if not eff_owner:
        raise HTTPException(status_code=400, detail="owner_token required")
    owner = await get_owner_by_token(eff_owner)
    if not owner:
        raise HTTPException(status_code=404, detail="Owner not found or already deleted")
    deleted = await delete_owner_data(eff_owner)
    return {"ok": True, "deleted_messages": deleted, "account": "deactivated"}


@compliance_router.post("/admin/flag/{msg_id}")
async def admin_flag(
    msg_id: str,
    req: FlagRequest,
    x_admin_secret: Optional[str] = Header(None),
    x_owner_token: Optional[str] = Header(None),
):
    """Flag a message for review. Requires X-Admin-Secret or X-Owner-Token."""
    if x_admin_secret:
        if x_admin_secret != _admin_secret():
            raise HTTPException(status_code=403, detail="Invalid admin secret")
    elif x_owner_token:
        owner = await get_owner_by_token(x_owner_token)
        if not owner:
            raise HTTPException(status_code=401, detail="Invalid owner_token")
    else:
        raise HTTPException(status_code=401, detail="Provide X-Admin-Secret or X-Owner-Token")

    ok = await flag_message(msg_id, req.flagged_by, req.reason)
    if not ok:
        raise HTTPException(status_code=404, detail="Message not found")
    return {"ok": True, "msg_id": msg_id, "flagged_by": req.flagged_by}


@compliance_router.post("/admin/kontrollinstanz/register")
async def kontrollinstanz_register(
    req: KontrollinstanzRegisterRequest,
    x_admin_secret: Optional[str] = Header(None),
):
    """Register a Kontrollinstanz compliance webhook. Admin-only."""
    if not x_admin_secret or x_admin_secret != _admin_secret():
        raise HTTPException(status_code=403, detail="Invalid admin secret")
    if not req.webhook_url.startswith("https://"):
        raise HTTPException(status_code=400, detail="webhook_url must use HTTPS")
    webhook_id = await register_kontrollinstanz(req.webhook_url, req.owner_token)
    return {"ok": True, "webhook_id": webhook_id, "webhook_url": req.webhook_url}


# ── Web Console HTML ──────────────────────────────────────────────────────────

_CONSOLE_HTML = """<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OpenRelay — Agent Console</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Outfit:wght@300;400;600;700&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #0a0a0f;
    --surface: #0f0f1a;
    --surface2: #14141f;
    --border: #1e1e2e;
    --cyan: #00f5ff;
    --magenta: #ff00aa;
    --yellow: #ffd700;
    --green: #00ff88;
    --red: #ff4466;
    --text: #e0e0ff;
    --muted: #6060a0;
    --font-mono: 'JetBrains Mono', monospace;
    --font-sans: 'Outfit', sans-serif;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: var(--font-sans); min-height: 100vh; }

  /* Header */
  header {
    display: flex; align-items: center; gap: 16px;
    padding: 16px 24px;
    border-bottom: 1px solid var(--border);
    background: var(--surface);
  }
  .logo { font-family: var(--font-mono); font-size: 1.1rem; color: var(--cyan); font-weight: 700; }
  .logo span { color: var(--magenta); }
  .status-dot {
    width: 8px; height: 8px; border-radius: 50%;
    background: var(--muted); margin-left: auto;
    transition: background 0.3s;
  }
  .status-dot.live { background: var(--green); box-shadow: 0 0 8px var(--green); }
  .status-text { font-size: 0.8rem; color: var(--muted); font-family: var(--font-mono); }

  /* Auth panel */
  #auth-panel {
    max-width: 480px; margin: 80px auto; padding: 32px;
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 12px;
  }
  #auth-panel h2 { font-size: 1.3rem; margin-bottom: 8px; color: var(--cyan); }
  #auth-panel p { font-size: 0.85rem; color: var(--muted); margin-bottom: 24px; }
  .input-group { margin-bottom: 16px; }
  .input-group label { display: block; font-size: 0.8rem; color: var(--muted); margin-bottom: 6px; font-family: var(--font-mono); }
  .input-group input {
    width: 100%; padding: 10px 14px;
    background: var(--surface2); border: 1px solid var(--border);
    border-radius: 6px; color: var(--text); font-family: var(--font-mono); font-size: 0.85rem;
    outline: none; transition: border-color 0.2s;
  }
  .input-group input:focus { border-color: var(--cyan); }
  .btn {
    padding: 10px 24px; border-radius: 6px; font-family: var(--font-sans);
    font-size: 0.9rem; font-weight: 600; cursor: pointer; border: none;
    transition: opacity 0.2s;
  }
  .btn:hover { opacity: 0.85; }
  .btn-primary { background: var(--cyan); color: #000; }
  .btn-danger { background: var(--red); color: #fff; font-size: 0.78rem; padding: 6px 14px; }
  .btn-ghost { background: transparent; border: 1px solid var(--border); color: var(--muted); font-size: 0.78rem; padding: 6px 14px; }
  #auth-error { color: var(--red); font-size: 0.8rem; margin-top: 8px; display: none; }

  /* Console */
  #console-panel { display: none; height: calc(100vh - 57px); display: none; flex-direction: column; }
  #console-panel.active { display: flex; }

  /* Toolbar */
  .toolbar {
    display: flex; align-items: center; gap: 12px; padding: 10px 20px;
    border-bottom: 1px solid var(--border); background: var(--surface);
    flex-wrap: wrap;
  }
  .filter-input {
    padding: 6px 12px; background: var(--surface2);
    border: 1px solid var(--border); border-radius: 5px;
    color: var(--text); font-family: var(--font-mono); font-size: 0.8rem;
    outline: none; width: 160px;
  }
  .filter-input:focus { border-color: var(--cyan); }
  .count-badge {
    font-family: var(--font-mono); font-size: 0.75rem; color: var(--muted);
    margin-left: auto;
  }
  .badge {
    padding: 2px 8px; border-radius: 4px; font-size: 0.7rem; font-family: var(--font-mono);
    font-weight: 600;
  }
  .badge-cyan { background: rgba(0,245,255,0.12); color: var(--cyan); }
  .badge-magenta { background: rgba(255,0,170,0.12); color: var(--magenta); }
  .badge-red { background: rgba(255,68,102,0.15); color: var(--red); }
  .badge-green { background: rgba(0,255,136,0.12); color: var(--green); }

  /* Message list */
  #msg-list {
    flex: 1; overflow-y: auto; padding: 12px 20px;
    display: flex; flex-direction: column; gap: 8px;
  }
  #msg-list::-webkit-scrollbar { width: 6px; }
  #msg-list::-webkit-scrollbar-track { background: var(--surface); }
  #msg-list::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }

  .msg-card {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 8px; padding: 12px 16px;
    transition: border-color 0.2s;
    animation: slideIn 0.2s ease;
  }
  .msg-card:hover { border-color: rgba(0,245,255,0.25); }
  .msg-card.flagged { border-color: var(--red); background: rgba(255,68,102,0.05); }
  @keyframes slideIn { from { opacity: 0; transform: translateY(-6px); } to { opacity: 1; transform: none; } }

  .msg-header {
    display: flex; align-items: center; gap: 8px;
    margin-bottom: 6px; flex-wrap: wrap;
  }
  .msg-from { color: var(--cyan); font-family: var(--font-mono); font-size: 0.82rem; font-weight: 700; }
  .msg-arrow { color: var(--muted); font-size: 0.75rem; }
  .msg-to { color: var(--magenta); font-family: var(--font-mono); font-size: 0.82rem; font-weight: 700; }
  .msg-time { color: var(--muted); font-size: 0.72rem; font-family: var(--font-mono); margin-left: auto; }
  .msg-content {
    font-family: var(--font-mono); font-size: 0.8rem; color: var(--text);
    white-space: pre-wrap; word-break: break-word;
    max-height: 120px; overflow: hidden;
    position: relative; cursor: pointer;
  }
  .msg-content.expanded { max-height: none; }
  .msg-content::after {
    content: ''; position: absolute; bottom: 0; left: 0; right: 0;
    height: 30px;
    background: linear-gradient(transparent, var(--surface));
    pointer-events: none;
  }
  .msg-content.expanded::after { display: none; }
  .msg-footer { display: flex; align-items: center; gap: 8px; margin-top: 8px; }
  .msg-id { font-size: 0.68rem; color: var(--muted); font-family: var(--font-mono); }

  /* Empty state */
  #empty-state {
    flex: 1; display: flex; flex-direction: column; align-items: center; justify-content: center;
    color: var(--muted); gap: 12px;
  }
  #empty-state .icon { font-size: 2.5rem; opacity: 0.4; }
  #empty-state p { font-size: 0.9rem; }

  /* Notify bar */
  #notify-bar {
    position: fixed; top: 16px; right: 16px;
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 8px; padding: 10px 16px;
    font-size: 0.82rem; font-family: var(--font-mono);
    display: none; z-index: 1000;
  }
  #notify-bar.show { display: block; animation: fadeIn 0.2s; }
  @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }

  .separator { color: var(--muted); }
</style>
</head>
<body>

<header>
  <div class="logo">Open<span>Relay</span> Console</div>
  <div class="status-text" id="status-text">Nicht verbunden</div>
  <div class="status-dot" id="status-dot"></div>
</header>

<!-- Auth Panel -->
<div id="auth-panel">
  <h2>Console Zugang</h2>
  <p>Admin-Token für alle Nachrichten oder Owner-Token für eigene Bots.</p>
  <div class="input-group">
    <label>ADMIN TOKEN oder OWNER TOKEN</label>
    <input type="password" id="token-input" placeholder="Token eingeben..." autocomplete="off">
  </div>
  <div class="input-group">
    <label>TOKEN TYP</label>
    <select id="token-type" style="width:100%;padding:10px 14px;background:var(--surface2);border:1px solid var(--border);border-radius:6px;color:var(--text);font-family:var(--font-mono);font-size:0.85rem;outline:none;">
      <option value="admin">Admin (alle Nachrichten)</option>
      <option value="owner">Owner (eigene Bots)</option>
    </select>
  </div>
  <button class="btn btn-primary" onclick="connect()">Verbinden</button>
  <div id="auth-error">Ungültiger Token.</div>
</div>

<!-- Console Panel -->
<div id="console-panel">
  <div class="toolbar">
    <input class="filter-input" id="filter-from" placeholder="Von Bot..." oninput="applyFilter()">
    <input class="filter-input" id="filter-to" placeholder="An Bot..." oninput="applyFilter()">
    <button class="btn btn-ghost" onclick="clearMessages()">Leeren</button>
    <button class="btn btn-danger" onclick="disconnect()">Trennen</button>
    <div class="count-badge"><span id="msg-count">0</span> Nachrichten</div>
  </div>
  <div id="msg-list">
    <div id="empty-state">
      <div class="icon">⬡</div>
      <p>Warte auf Nachrichten...</p>
    </div>
  </div>
</div>

<div id="notify-bar"></div>

<script>
let evtSource = null;
let messages = [];
let tokenValue = '';
let tokenType = 'admin';

function connect() {
  tokenValue = document.getElementById('token-input').value.trim();
  tokenType = document.getElementById('token-type').value;
  if (!tokenValue) return;

  const paramKey = tokenType === 'admin' ? 'admin_token' : 'owner_token';
  const url = `/relay/console/stream?${paramKey}=${encodeURIComponent(tokenValue)}`;

  evtSource = new EventSource(url);

  evtSource.addEventListener('history', (e) => {
    const hist = JSON.parse(e.data);
    hist.reverse().forEach(m => addMessage(m, false));
    if (hist.length > 0) showEmptyState(false);
  });

  evtSource.onmessage = (e) => {
    if (e.data.startsWith(':')) return;
    try {
      const msg = JSON.parse(e.data);
      addMessage(msg, true);
      showEmptyState(false);
    } catch {}
  };

  evtSource.onerror = () => {
    setStatus(false);
    const err = document.getElementById('auth-error');
    if (messages.length === 0) {
      err.textContent = 'Verbindung fehlgeschlagen — Token prüfen.';
      err.style.display = 'block';
      disconnect(false);
    }
  };

  evtSource.onopen = () => {
    setStatus(true);
    document.getElementById('auth-panel').style.display = 'none';
    document.getElementById('console-panel').classList.add('active');
    document.getElementById('auth-error').style.display = 'none';
  };
}

function disconnect(resetUI = true) {
  if (evtSource) { evtSource.close(); evtSource = null; }
  setStatus(false);
  if (resetUI) {
    messages = [];
    document.getElementById('msg-list').innerHTML = '<div id="empty-state"><div class="icon">⬡</div><p>Warte auf Nachrichten...</p></div>';
    document.getElementById('console-panel').classList.remove('active');
    document.getElementById('auth-panel').style.display = 'block';
    document.getElementById('msg-count').textContent = '0';
  }
}

function setStatus(live) {
  document.getElementById('status-dot').className = 'status-dot' + (live ? ' live' : '');
  document.getElementById('status-text').textContent = live ? 'Live' : 'Nicht verbunden';
}

function addMessage(msg, isNew) {
  messages.push(msg);
  document.getElementById('msg-count').textContent = messages.length;

  const filterFrom = document.getElementById('filter-from').value.toLowerCase();
  const filterTo = document.getElementById('filter-to').value.toLowerCase();
  if (filterFrom && !msg.from.toLowerCase().includes(filterFrom)) return;
  if (filterTo && !msg.to.toLowerCase().includes(filterTo)) return;

  const ts = new Date(msg.ts * 1000).toLocaleTimeString('de-DE', {hour:'2-digit',minute:'2-digit',second:'2-digit'});
  const flagged = msg.flagged ? ' flagged' : '';
  const content = escapeHtml(msg.content || '').replace(/\\n/g, '\n');

  const card = document.createElement('div');
  card.className = 'msg-card' + flagged;
  card.dataset.msgId = msg.msg_id;
  card.innerHTML = `
    <div class="msg-header">
      <span class="msg-from">${escapeHtml(msg.from)}</span>
      <span class="msg-arrow">→</span>
      <span class="msg-to">${escapeHtml(msg.to)}</span>
      ${msg.flagged ? '<span class="badge badge-red">⚑ Flagged</span>' : ''}
      <span class="msg-time">${ts}</span>
    </div>
    <div class="msg-content" onclick="toggleExpand(this)">${content}</div>
    <div class="msg-footer">
      <span class="msg-id">${msg.msg_id}</span>
      <button class="btn btn-ghost" onclick="flagMsg('${msg.msg_id}',this)" style="margin-left:auto">⚑ Flag</button>
    </div>
  `;

  const list = document.getElementById('msg-list');
  if (isNew) {
    list.insertBefore(card, list.firstChild);
    notify('Neue Nachricht: ' + escapeHtml(msg.from) + ' → ' + escapeHtml(msg.to));
  } else {
    list.appendChild(card);
  }
}

function toggleExpand(el) {
  el.classList.toggle('expanded');
}

function flagMsg(msgId, btn) {
  const paramKey = tokenType === 'admin' ? 'admin_token' : 'owner_token';
  const headerKey = tokenType === 'admin' ? 'X-Admin-Secret' : 'X-Owner-Token';
  const adminSecret = tokenType === 'admin' ? document.getElementById('token-input').value : '';
  const ownerToken = tokenType === 'owner' ? tokenValue : '';

  const headers = {'Content-Type':'application/json'};
  if (tokenType === 'admin') headers['X-Admin-Secret'] = document.getElementById('token-input').value;
  else headers['X-Owner-Token'] = tokenValue;

  fetch(`/relay/admin/flag/${msgId}`, {
    method: 'POST',
    headers,
    body: JSON.stringify({reason: 'Manuelle Markierung via Console', flagged_by: 'console'})
  }).then(r => {
    if (r.ok) {
      const card = document.querySelector(`[data-msg-id="${msgId}"]`);
      if (card) card.classList.add('flagged');
      btn.textContent = '✓ Geflaggt';
      btn.disabled = true;
    }
  });
}

function applyFilter() {
  const list = document.getElementById('msg-list');
  list.innerHTML = '';
  document.getElementById('empty-state')?.remove();
  const shown = messages.filter(m => {
    const filterFrom = document.getElementById('filter-from').value.toLowerCase();
    const filterTo = document.getElementById('filter-to').value.toLowerCase();
    if (filterFrom && !m.from.toLowerCase().includes(filterFrom)) return false;
    if (filterTo && !m.to.toLowerCase().includes(filterTo)) return false;
    return true;
  });
  if (shown.length === 0) showEmptyState(true);
  shown.reverse().forEach(m => addMessage(m, false));
}

function clearMessages() {
  messages = [];
  document.getElementById('msg-list').innerHTML = '';
  document.getElementById('msg-count').textContent = '0';
  showEmptyState(true);
}

function showEmptyState(show) {
  let el = document.getElementById('empty-state');
  if (show && !el) {
    el = document.createElement('div');
    el.id = 'empty-state';
    el.innerHTML = '<div class="icon">⬡</div><p>Keine Nachrichten.</p>';
    document.getElementById('msg-list').appendChild(el);
  } else if (!show && el) {
    el.remove();
  }
}

function notify(text) {
  const bar = document.getElementById('notify-bar');
  bar.textContent = text;
  bar.className = 'show';
  setTimeout(() => { bar.className = ''; }, 3000);
}

function escapeHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// Enter key in token field
document.getElementById('token-input').addEventListener('keydown', e => {
  if (e.key === 'Enter') connect();
});
</script>
</body>
</html>"""
