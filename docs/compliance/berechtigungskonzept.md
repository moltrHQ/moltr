# Berechtigungskonzept – Moltr Security

**Rechtsgrundlage:** Art. 5 Abs. 2 DSGVO (Rechenschaftspflicht), Art. 32 DSGVO (Sicherheit der Verarbeitung)

---

## 1. Rollenkonzept

### 1.1 Rollen-Definitionen

| Rolle | Beschreibung | Berechtigungsstufe |
|-------|-------------|-------------------|
| **admin** | Vollzugriff, Dashboard-Admin | 100 |
| **operator** | Überwachung, KillSwitch bedienen | 75 |
| **viewer** | Nur Lesen, keine Änderungen | 25 |
| **system** | Interne Prozesse, keine menschliche Interaktion | 50 |

### 1.2 Role-Hierarchie

```
admin (100)
  ├── operator (75)
  │     └── viewer (25)
  └── system (50)
```

Höhere Rollen erben alle Rechte der niedrigeren Rollen.

---

## 2. Zugriffsmatrix

### 2.1 Dashboard-API Endpoints

| Endpoint | admin | operator | viewer | system |
|----------|-------|----------|--------|--------|
| `GET /health` | ✅ | ✅ | ✅ | ✅ |
| `GET /status` | ✅ | ✅ | ✅ | ❌ |
| `GET /dashboard/` | ✅ | ✅ | ✅ | ❌ |
| `POST /killswitch/trigger` | ✅ | ✅ | ❌ | ❌ |
| `POST /killswitch/reset` | ✅ | ❌ | ❌ | ❌ |
| `GET /killswitch/log` | ✅ | ✅ | ❌ | ❌ |
| `GET /integrity/check` | ✅ | ✅ | ✅ | ❌ |
| `POST /check/*` | ✅ | ✅ | ❌ | ✅ |
| `GET /api/v1/auth/sessions` | ✅ | ✅ | ❌ | ❌ |

### 2.2 Moltr-Security-Checks

| Check-Typ | admin | operator | viewer | system |
|-----------|-------|----------|--------|--------|
| URL-Check | ✅ | ✅ | ❌ | ✅ |
| Command-Check | ✅ | ✅ | ❌ | ✅ |
| Path-Check | ✅ | ✅ | ❌ | ✅ |
| Output-Scan | ✅ | ✅ | ❌ | ✅ |
| Alert-Konfiguration | ✅ | ✅ | ❌ | ❌ |

---

## 3. Least-Privilege-Prinzip

### 3.1 Grundsatz

Jeder Benutzer / Prozess erhält nur die minimalen Rechte, die zur Aufgabenerfüllung notwendig sind.

### 3.2 Umsetzung

| Prinzip | Implementierung |
|---------|---------------|
| **Default: Kein Zugriff** | Whitelist statt Blacklist |
| **Trennung der Aufgaben** | Admin != Operator != Viewer |
| **Zeitlich begrenzte Rechte** | Session-Timeout 30 Min |
| **Prozess-spezifische Rechte** | API-Keys mit minimalen Scopes |

### 3.3 Beispiele

```python
# Falsch: Zu viele Rechte
api_key = "sk-xxx"  # Kann ALLES

# Richtig: Scoped API-Key
# Berechtigung: POST /check/* nur, kein Admin-Zugriff
scoped_key = {
    "key": "sk-xxx",
    "scopes": ["check:url", "check:command", "check:path"],
    "rate_limit": 100
}
```

---

## 4. JWT-Scopes

### 4.1 Scope-Definitionen

| Scope | Beschreibung | Endpoints |
|-------|-------------|-----------|
| `status:read` | Status anzeigen | GET /status, GET /integrity/* |
| `check:*` | Security-Checks | POST /check/*, POST /scan/* |
| `killswitch:read` | KillSwitch-Status | GET /killswitch/log |
| `killswitch:trigger` | KillSwitch auslösen | POST /killswitch/trigger |
| `killswitch:reset` | KillSwitch zurücksetzen | POST /killswitch/reset |
| `admin:*` | Admin-Funktionen | Alles andere |

### 4.2 Rollen-zu-Scope-Mapping

| Rolle | Scopes |
|-------|--------|
| **admin** | `*` (alle) |
| **operator** | `status:read`, `check:*`, `killswitch:read`, `killswitch:trigger` |
| **viewer** | `status:read` |
| **system** | `check:*` |

### 4.3 JWT-Payload-Beispiel

```json
{
  "sub": "hiro",
  "role": "operator",
  "scopes": [
    "status:read",
    "check:url",
    "check:command",
    "check:path",
    "killswitch:read",
    "killswitch:trigger"
  ],
  "exp": 1708364400,
  "iat": 1708360800
}
```

### 4.4 Scope-Validierung

```python
def require_scope(required_scope: str):
    """Decorator für Scope-Validierung."""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            token = get_token_from_request()
            if required_scope not in token.get("scopes", []):
                raise HTTPException(403, "Insufficient permissions")
            return await func(*args, **kwargs)
        return wrapper
    return decorator

@require_scope("killswitch:trigger")
async def trigger_killswitch(req: KillSwitchRequest):
    ...
```

---

## 5. Technische Implementierung

### 5.1 Session-Store (Bestehend)

```python
# session_store.py
class SessionStore:
    def create(self, token_id: str, username: str, role: str, scopes: list[str]):
        session = RefreshSession(
            token_id=token_id,
            username=username,
            role=role,
            scopes=scopes,  # NEU: Scopes speichern
            created_at=time.time(),
            last_activity=time.time(),
        )
        ...
```

### 5.2 Middleware für Scope-Checks

```python
# auth/middleware.py
async def verify_scope(request: Request, required_scope: str):
    """Prüfe ob Token die erforderlichen Scopes hat."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(401)
    
    token = verify_access_token(auth[7:])
    if not token:
        raise HTTPException(401)
    
    scopes = token.get("scopes", [])
    if required_scope not in scopes and "*" not in scopes:
        raise HTTPException(403, f"Scope '{required_scope}' required")
```

---

## 6. Audit & Monitoring

### 6.1 Zugriffs-Logging

| Feld | Beispiel |
|------|----------|
| timestamp | 2026-02-19T17:30:00Z |
| user | hiro |
| role | operator |
| action | killswitch:trigger |
| resource | /killswitch/trigger |
| result | success |
| ip | 192.168.1.100 |

### 6.2 Alerts

- [ ] 3 fehlgeschlagene Auth-Versuche → Alert an Admin
- [ ] Admin-Aktion ohne vorherige Admin-Login → Alert
- [ ] Unusual Access Pattern → Alert

---

## 7. Passwort-Anforderungen

| Anforderung | Wert |
|-------------|------|
| Mindestlänge | 12 Zeichen |
| Komplexität | Groß-, Kleinbuchstaben, Zahlen, Sonderzeichen |
| Änderungsintervall | 90 Tage |
| Historie | Letzte 10 Passwörter nicht wiederverwendbar |
| 2FA | Pflicht für admin-Rolle |

---

## 8. Rechtliche Hinweise

⚠️ **Dieses Berechtigungskonzept ist eine technische Orientierungshilfe und keine Rechtsberatung.**

**Änderungen:**
- 2026-02-19: Initiale Version für Moltr Security
