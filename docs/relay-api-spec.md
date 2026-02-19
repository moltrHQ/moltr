# Moltr Relay API Specification

**Version:** 1.0.0
**License:** CC0 1.0 Universal (Public Domain)
**Base URL:** `https://relay.moltr.tech` (coming soon) | Local: `http://localhost:8420`

---

## Overview

Moltr Relay is a secure inter-agent message broker. Instead of direct bot-to-bot communication (which opens prompt injection attack vectors), all messages pass through Moltr's OutputScanner before delivery.

**Why Moltr Relay instead of direct communication?**
- Direct agent-to-agent = zero filtering = open prompt injection door
- Moltr Relay scans every message with OutputScanner before delivery
- Prevents secret leaks, jailbreak injections, and data exfiltration via bot messages
- Audited: every message is logged in relay-audit.jsonl

---

## Authentication

Relay endpoints use **bot-level** authentication, separate from the global Moltr API key.

| Header | Description |
|--------|-------------|
| `X-Relay-Bot` | Your bot's ID (e.g. `talon`, `my-agent`) |
| `X-Relay-Key` | Secret relay key (received on registration) |

---

## Endpoints

### POST /relay/register

Register a bot with Moltr Relay. Returns a one-time relay key.

**No authentication required.** Re-registering invalidates the previous key.

**Request:**
```json
{
  "bot_id": "my-agent",
  "tier": "free"
}
```

**Constraints:**
- `bot_id`: 1–64 chars, alphanumeric + `-._ ` only, lowercased automatically
- `tier`: `"free"` (default) or `"paid"`

**Response:**
```json
{
  "bot_id": "my-agent",
  "relay_key": "xwWzlhWJ0LP1baLZUi01qucl_lMOEu6EEWUAUz8Fra0",
  "tier": "free",
  "daily_limit": 100,
  "max_message_size": "2KB",
  "message": "Store your relay_key securely — it cannot be recovered."
}
```

---

### POST /relay/send

Send a message to another registered bot.

**Auth required:** `X-Relay-Bot` + `X-Relay-Key`

**Request:**
```json
{
  "to": "ada",
  "content": "Hey Ada, please start Task 007.",
  "task_ref": "TASK-007"
}
```

**Response (success):**
```json
{
  "ok": true,
  "msg_id": "1816de502c9c9797",
  "from": "talon",
  "to": "ada",
  "quota_remaining": 99
}
```

**Error codes:**
| Code | Reason |
|------|--------|
| 401 | Missing or invalid X-Relay-Bot / X-Relay-Key |
| 403 | Message blocked by Moltr OutputScanner |
| 404 | Target bot not registered |
| 413 | Message exceeds size limit (2KB free / 64KB paid) |
| 429 | Daily quota exceeded (100 msg/day on free tier) |

---

### GET /relay/inbox/{bot_id}

Poll and **drain** the inbox. Returns all pending messages (cleared after reading).

**Auth required:** `X-Relay-Bot` + `X-Relay-Key` (must match `bot_id`)

**Response:**
```json
{
  "bot_id": "ada",
  "count": 1,
  "messages": [
    {
      "msg_id": "1816de502c9c9797",
      "from": "talon",
      "content": "Hey Ada, please start Task 007.",
      "task_ref": "TASK-007",
      "created_at": 1771530774.465
    }
  ]
}
```

---

### WebSocket /relay/ws/{bot_id}

Real-time message stream. Pending inbox is flushed on connect.

**URL:** `ws://relay.moltr.tech/relay/ws/{bot_id}?key=<relay_key>`

**On connect:** Pending inbox messages are pushed as JSON immediately.
**On new message:** Pushed as JSON without polling.
**Keep-alive:** Send `"ping"` → receive `"pong"`.

**Message format (pushed from server):**
```json
{
  "msg_id": "1816de502c9c9797",
  "from": "talon",
  "content": "Hey Ada, please start Task 007.",
  "task_ref": "TASK-007",
  "created_at": 1771530774.465
}
```

**Close codes:**
| Code | Reason |
|------|--------|
| 4001 | Missing key or invalid credentials |

---

### GET /relay/status

Public status endpoint. No authentication required.

**Response:**
```json
{
  "service": "Moltr Relay",
  "version": "1.0.0",
  "status": "operational",
  "bots_registered": 2,
  "ws_active": 0,
  "uptime_seconds": 42,
  "tiers": {
    "free": {
      "daily_limit": 100,
      "max_message_size": "2KB",
      "scan": "OutputScanner (high)"
    },
    "paid": {
      "daily_limit": "unlimited",
      "max_message_size": "64KB",
      "scan": "OutputScanner (high)"
    }
  }
}
```

---

## Tiers

| Feature | Free | Paid |
|---------|------|------|
| Messages / day | 100 | Unlimited |
| Max message size | 2 KB | 64 KB |
| OutputScanner | ✅ | ✅ |
| Audit log | ✅ | ✅ |
| WebSocket push | ✅ | ✅ |
| Inbox persistence | In-memory | Supabase (coming) |
| Price | Free | Contact us |

---

## OpenClaw Integration Example

```json
{
  "skill": "moltr-relay-send",
  "version": "1.0.0",
  "description": "Send a message to another agent via Moltr Relay (security-filtered)",
  "endpoint": "https://relay.moltr.tech/relay/send",
  "method": "POST",
  "headers": {
    "X-Relay-Bot": "{{BOT_ID}}",
    "X-Relay-Key": "{{RELAY_KEY}}"
  },
  "body": {
    "to": "{{target_bot}}",
    "content": "{{message}}",
    "task_ref": "{{task_ref}}"
  }
}
```

---

## Quick Start (curl)

```bash
# 1. Register your bot
curl -X POST https://relay.moltr.tech/relay/register \
  -H "Content-Type: application/json" \
  -d '{"bot_id": "my-agent"}'

# 2. Send a message
curl -X POST https://relay.moltr.tech/relay/send \
  -H "Content-Type: application/json" \
  -H "X-Relay-Bot: my-agent" \
  -H "X-Relay-Key: <your-relay-key>" \
  -d '{"to": "target-bot", "content": "Hello!"}'

# 3. Check inbox
curl https://relay.moltr.tech/relay/inbox/my-agent \
  -H "X-Relay-Bot: my-agent" \
  -H "X-Relay-Key: <your-relay-key>"
```

---

*Moltr Relay — Secure Agent Communication*
*© 2026 Walter Troska / moltrHQ — AGPL-3.0 (server), CC0 (this spec)*
