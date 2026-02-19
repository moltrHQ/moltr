# Technisch-Organisatorische Maßnahmen (TOMs)
## Moltr Security Shield — Art. 32 DSGVO

**Stand:** 2026-02-19
**Version:** 1.0
**Verantwortlich:** Walter Troska, moltrHQ
**Geltungsbereich:** Alle Komponenten des Moltr Security Shield (moltr-security v1.x)

> Diese TOMs dokumentieren die gemäß Art. 32 DSGVO getroffenen technischen und organisatorischen
> Maßnahmen zum Schutz personenbezogener Daten, die durch den Betrieb des Moltr Security Shield
> verarbeitet werden.

---

## 1. Pseudonymisierung und Verschlüsselung (Art. 32 Abs. 1 lit. a)

### 1.1 Datenverschlüsselung

| Maßnahme | Implementierung | Status |
|----------|----------------|--------|
| Verschlüsselung von Secrets at rest | Fernet (AES-128-CBC + HMAC-SHA256) via `MOLTR_FERNET_KEY` | ✅ Implementiert |
| TLS/HTTPS für alle API-Verbindungen | Reverse Proxy (Caddy/nginx) mit TLS 1.2+ Pflicht | ✅ Pflicht (Deployment-Doku) |
| HMAC-Schutz der Integrity-Baseline | SHA-256 HMAC via `MOLTR_WATCHDOG_HMAC_KEY` | ✅ Implementiert |
| JWT-Signierung | HS256 via `MOLTR_JWT_SECRET` (mind. 64 Zeichen empfohlen) | ✅ Implementiert |
| Passwort-Hashing | bcrypt (cost factor 12) — keine Klartext-Passwörter | ✅ Implementiert |

### 1.2 Pseudonymisierung

| Maßnahme | Implementierung | Status |
|----------|----------------|--------|
| IP-Adressen in Logs | Letztes Oktett auf `.0` gesetzt (`_pseudonymize_ip()`) | ✅ Implementiert |
| Session-IDs in Logs | Nur erste 8 Zeichen des Token-ID geloggt | ✅ Implementiert |
| Forensic Logs | UUIDs statt Klarnamen, keine Passwörter/Tokens in Logs | ✅ Implementiert |

---

## 2. Vertraulichkeit, Integrität, Verfügbarkeit (Art. 32 Abs. 1 lit. b)

### 2.1 Zugriffskontrolle

| Maßnahme | Implementierung | Status |
|----------|----------------|--------|
| API-Authentifizierung | X-API-Key Header (Bearer-Token-Äquivalent) | ✅ Implementiert |
| Dashboard-Authentifizierung | JWT Access Token (15 min) + httpOnly Refresh Cookie (30 min Inactivity) | ✅ Implementiert |
| Brute-Force-Schutz Login | 5 Versuche/min, progressive Delays, Lockout nach 10 Fehlversuchen (15 min) | ✅ Implementiert |
| Rollenbasierter Zugriff | Trennung API-Client vs. Dashboard-User (unterschiedliche Auth-Mechanismen) | ✅ Implementiert |
| KillSwitch-Schutz | CONFIRM:-Prefix + Codephrase für destruktive Aktionen | ✅ Implementiert |

### 2.2 Netzwerksicherheit

| Maßnahme | Implementierung | Status |
|----------|----------------|--------|
| API nur via Reverse Proxy | FastAPI bindet auf `0.0.0.0:8420`; Firewall/Caddy schützt extern | ✅ Deployment-Doku |
| X-Forwarded-For Verifikation | Nur bei konfiguriertem `MOLTR_TRUSTED_PROXY` vertraut | ✅ Implementiert |
| Rate-Limiting (API) | slowapi: /health 60/min, /scan 60/min, /check/* 120/min | ✅ Implementiert |
| Rate-Limiting (KillSwitch) | trigger 3/min, reset 5/min | ✅ Implementiert |
| Network-Firewall-Modul | Domain-Allowlist für ausgehende Verbindungen von AI-Agents | ✅ Implementiert |

### 2.3 Integrität

| Maßnahme | Implementierung | Status |
|----------|----------------|--------|
| IntegrityWatchdog | SHA-256 Baseline für 54 Dateien (config/ + src/) | ✅ Implementiert |
| Automatische Prüfung | Background-Thread alle 60 Sekunden | ✅ Implementiert |
| Tamper-Alert | Telegram-Benachrichtigung bei erkannter Manipulation | ✅ Implementiert |
| WORM Audit-Log | KillSwitch-Events: append-only JSONL + SHA-256 Export-Checksum | ✅ Implementiert |
| Honeypot-Traps | API-Endpunkte die sofort CRITICAL-Alert auslösen bei Zugriff | ✅ Implementiert |

### 2.4 Verfügbarkeit

| Maßnahme | Implementierung | Status |
|----------|----------------|--------|
| Prozess-Management | PM2 mit Autorestart (unbegrenzte Neustarts) | ✅ Implementiert |
| Health-Endpoint | GET /health gibt Systemstatus zurück | ✅ Implementiert |
| Log-Rotation | RotatingFileHandler: 10 MB pro Datei, 5 Backups | ✅ Implementiert |
| Graceful Error Handling | Alle Endpoints mit Try/Except, kein Absturz bei Einzelfehler | ✅ Implementiert |
| Docker-Deployment | Containerisiert, restart: unless-stopped | ✅ Implementiert |

---

## 3. Belastbarkeit der Systeme (Art. 32 Abs. 1 lit. b)

### 3.1 Ausfallsicherheit

| Maßnahme | Details |
|----------|---------|
| KillSwitch Fail-Safe | Bei Lockdown werden ALLE Sessions sofort invalidiert — kein Window for Bypass |
| OutputScanner Fail-Safe | Bei Fehler im Scanner: blockiert statt durchlässt (Fail-Closed) |
| Provider-Fallback (Agent) | Anthropic → Groq → OpenAI bei Credit-Erschöpfung oder Ausfall |
| Watchdog-Scheduler | Läuft in eigenem Thread, unabhängig vom API-Server |

### 3.2 Backup-Strategie

| Datenkategorie | Backup-Empfehlung | Hinweis |
|---------------|-------------------|---------|
| `.env` (Schlüssel) | Sicher verschlüsselt extern ablegen (z.B. Passwort-Manager) | Kein Git-Commit! |
| `secrets.json` | Tägliches verschlüsseltes Backup | Enthält Fernet-verschlüsselte Secrets |
| `logs/` | 7 Tage Retention, dann löschen (siehe Löschkonzept) | DSGVO-Konform |
| KillSwitch JSONL | WORM-Archiv 1 Jahr (Security-Logs), dann löschen | Rechtsgrundlage: lit. f |

---

## 4. Wiederherstellbarkeit (Art. 32 Abs. 1 lit. c)

| Maßnahme | Implementierung |
|----------|----------------|
| Integrity-Baseline Wiederherstellung | `POST /integrity/baseline` reaktiviert Watchdog nach Deployment | ✅ |
| KillSwitch Reset | `POST /killswitch/reset` mit Codephrase entriegelt Lockdown | ✅ |
| Session-Wiederherstellung | Neue Login-Session nach KillSwitch-Reset sofort möglich | ✅ |
| Config-Reload | `MoltrConfig.reload()` mit Fallback auf letzte gültige Config | ✅ |
| Passwort-Reset | Via direktem `bcrypt_hash.py`-Script + ENV-Variable setzen | Dokumentiert |

---

## 5. Regelmäßige Überprüfung (Art. 32 Abs. 1 lit. d)

| Maßnahme | Turnus | Verantwortlich |
|----------|--------|----------------|
| Penetrationstest (intern) | Vierteljährlich | Walter Troska |
| DSGVO-Review dieser TOMs | Jährlich oder bei wesentlichen Änderungen | Walter Troska |
| Dependency-Updates | Monatlich (`pip-audit`, `npm audit`) | Automatisiert (geplant) |
| Integrity-Check manuell | Bei jedem Deployment | Automatisch via Watchdog |
| Brute-Force Log Review | Monatlich | Walter Troska |
| API-Key-Rotation | Empfohlen: alle 90 Tage | Walter Troska |

---

## 6. Organisatorische Maßnahmen

### 6.1 Zugangs- und Zugriffskontrolle

- **Physischer Zugang:** VPS ausschließlich über SSH mit Public-Key-Authentifizierung (kein Passwort-Login)
- **Fernzugriff:** Nur über gesicherte Verbindung (VPN oder SSH-Tunnel empfohlen)
- **Secrets-Management:** Alle Schlüssel in `.env`-Datei, niemals in Versionskontrolle
- **GitHub:** Repository `moltrHQ/moltr` ist öffentlich (AGPL-3.0); `.env`-Dateien in `.gitignore`
- **Minimalprinzip:** Produktions-API-Keys werden nur für notwendige Dienste ausgestellt

### 6.2 Mitarbeiter und Auftragnehmer

- Aktuell: Einzelperson (Walter Troska) + KI-gestützte Entwicklung
- Bei Erweiterung um Mitarbeiter: Vertraulichkeitsverpflichtung und Schulung Pflicht
- KI-Systeme (Claude, OpenClaw/Ada) erhalten keine dauerhaften Zugangsdaten — nur Session-basiert

### 6.3 Incident-Prozess

Siehe separates Dokument: [`incident-response.md`](./incident-response.md)

### 6.4 Auftragsverarbeitungsverträge (AVVs)

| Anbieter | Dienst | AVV-Status |
|----------|--------|------------|
| ip-projects.de | Windows VPS Hosting | Zu prüfen / abzuschließen |
| IONOS | Linux Server Hosting | Zu prüfen / abzuschließen |
| Supabase (US) | Datenbank (Agent-Memory) | Standardvertragsklauseln prüfen |
| Anthropic (US) | LLM-API | DPA vorhanden (api.anthropic.com/privacy) |
| Groq (US) | LLM-API (Fallback) | DPA zu prüfen |
| Telegram (UAE/UK) | Benachrichtigungen | Kein Angemessenheitsbeschluss → minimale Datenweitergabe |

---

## 7. Telegram-Alert Datenschutz

Telegram-Alerts enthalten:
- **Honeypot-Alerts:** IP (pseudonymisiert), User-Agent (max. 80 Zeichen), Incident-ID
- **Integrity-Alerts:** Dateiname + Verletzungstyp (keine Dateiinhalte)
- **KillSwitch-Alerts:** Level + Reason (kein personenbezogenes Datum wenn Reason allgemein)

**Maßnahme:** Alert-Texte werden so formuliert, dass keine personalisierten Daten übertragen werden. IP-Adressen werden VOR der Telegram-Übermittlung pseudonymisiert (letztes Oktett = 0).

---

## 8. Änderungshistorie

| Datum | Version | Änderung |
|-------|---------|----------|
| 2026-02-19 | 1.0 | Initiale Version erstellt |

---

*Moltr Security Shield — Made in Vienna*
*Copyright 2026 Walter Troska / moltrHQ | AGPL-3.0*
