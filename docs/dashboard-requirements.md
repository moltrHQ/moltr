# Moltr Security Dashboard — Anforderungsdokument

**Version:** 1.2 | **Datum:** 2026-02-19 | **Autoren:** Talon + Ada (DSGVO-Review) + Hiro (Final Review)

---

## Ziel

Ein Security-Dashboard das den Status aller Moltr-Module auf einen Blick zeigt, KillSwitch-Steuerung ermoeglicht und Integritaetspruefungen durchfuehrt. Remote-faehig, DSGVO-konform, responsive.

## Scope (Free Tier — Phase 1)

| View | Funktion |
|------|----------|
| **Overview** | System Health, aktive Threats, Watchdog-Status, KillSwitch-Level, letzte 10 Events |
| **KillSwitch** | Level-Anzeige, Trigger mit Confirmation-Modal, Reset mit Codephrase, Event-History |
| **Integrity** | Monitored Files, Violations, Manual Check, Re-Baseline mit Confirmation |

**Nicht in Phase 1:** WebSocket Live Events, Audit Log Volltextsuche, Charts, Advanced Filter.

## Technische Anforderungen

| Aspekt | Entscheidung |
|--------|-------------|
| **Frontend** | React + Vite + Tailwind, CSS-Variablen fuer Branding |
| **Build** | `vite build` → statische Files → FastAPI `StaticFiles` Mount (kein Vite Dev Server in Produktion) |
| **Backend** | FastAPI (bestehend), neue Dashboard-Endpoints unter `/api/v1/` |
| **API-Versionierung** | `/api/v1/` von Tag 1, damit Phase 2 (Small Tier) keine Endpoints bricht |
| **Hosting** | Embedded in FastAPI (Self-Hosted), EU-Server (ip-projects.de) |
| **Remote** | HTTPS via Reverse Proxy (Caddy) |
| **Caddy → FastAPI** | Localhost (127.0.0.1:8420), kein externer Zugriff auf den unverschluesselten Port. Unix Socket als Alternative fuer shared VPS evaluieren |
| **CORS** | Same-Origin (Frontend + API auf gleichem Host/Port via FastAPI Mount) — keine Cross-Origin-Anfragen noetig |
| **CSP-Headers** | Strict Content Security Policy: `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'` — kein eval(), kein Inline-Script |
| **Responsive** | Ja — echtes Responsive Design, mobile-first |

## Rechtsgrundlage (Art. 6 DSGVO)

**Berechtigtes Interesse (Art. 6 Abs. 1 lit. f)** — Security Monitoring zum Schutz der IT-Infrastruktur und der Nutzer vor Bedrohungen.

**Interessenabwaegung:**
- Interesse des Verantwortlichen: Schutz der IT-Systeme, Erkennung von Angriffen, Compliance-Nachweis
- Interesse der Betroffenen: Moeglichst wenig Datenverarbeitung
- Ergebnis: Ueberwiegt zugunsten des Verantwortlichen, da nur technische Metadaten (IPs, Timestamps) verarbeitet werden, pseudonymisiert gespeichert und nach definierten Fristen geloescht

**Vollstaendige Dokumentation:** `docs/compliance/rechtsgrundlage.md` (inkl. detaillierter Interessenabwaegung und Bewertung aller Datenkategorien)

## Auth-Konzept

### Token-Management
- **JWT Access Token:** 15 Min Laufzeit, im Memory (nicht LocalStorage)
- **Refresh Token:** httpOnly Secure Cookie, SameSite=Strict
- **Refresh Token Invalidierung:** Bei Inaktivitaet > 30 Min wird der Refresh Token serverseitig invalidiert

### Brute-Force-Schutz (Sprint 1)
- **Rate-Limiting auf Login-Endpoint:** Max. 5 Versuche pro Minute pro IP
- **Progressive Delays:** Nach 3 Fehlversuchen steigt die Wartezeit exponentiell (1s, 2s, 4s, 8s...)
- **Account-Lockout:** Nach 10 Fehlversuchen wird der Account fuer 15 Minuten gesperrt
- **Logging:** Jeder fehlgeschlagene Login-Versuch wird mit pseudonymisierter IP geloggt

### KillSwitch-Session-Interaktion
- **LOCKDOWN/WIPE/EMERGENCY:** Alle aktiven Refresh Tokens werden sofort serverseitig invalidiert
- **PAUSE/NETWORK_CUT:** Sessions bleiben aktiv (Dashboard wird fuer Monitoring benoetigt)
- **Implementierung:** Serverseitige Token-Blacklist (In-Memory Set), wird bei KillSwitch-Trigger Level >= LOCKDOWN geflusht

### Weitere Auth-Features
- **Login:** Username + Passwort (gehasht mit bcrypt, min. 12 Zeichen)
- **KillSwitch:** Separater Codephrase fuer Trigger/Reset (besteht schon)
- **RBAC geplant (Small Tier):** Admin (voll) vs. Viewer (read-only)
- **Optional (Enterprise):** IP-Whitelisting, Geo-Fencing, 2FA

## DSGVO-Compliance (von Tag 0)

### Daten-Retention
- **Hot Storage:** 90 Tage, verschluesseltes JSON-Lines Format, schnell durchsuchbar
- **Cold Storage:** 1 Jahr, encrypted JSON-Lines, separater Speicherort (`/data/archive/`), Zugriff nur fuer Admin
- **Rechtsgrundlage Cold Storage:** Branchenuebliche Aufbewahrungsfrist fuer Security-Logs gemaess Art. 6 Abs. 1 lit. f DSGVO, dokumentiert im Loeschkonzept (`docs/compliance/loeschkonzept.md`)
- **Auto-Loeschung:** Cronjob nach Ablauf, auch in Backups
- **Konfigurierbar:** Retention-Dauer in default.yaml

### Pseudonymisierung
- **IP-Adressen:** Letzte Oktetten nullen in Logs (z.B. 192.168.1.0)
- **User-IDs:** SHA-256 gehasht in Audit-Eintraegen
- **Keine Klartextnamen** in Logs oder Dashboard-Events

### Betroffenenrechte (Art. 12-23)
- **Auskunft (Art. 15):** Admin-Endpoint zum Abrufen aller Daten zu einer pseudonymisierten ID
- **Loeschung (Art. 17):** Admin-Endpoint zum sofortigen Loeschen aller Daten einer ID
- **Datenexport (Art. 20):** JSON-Export aller personenbezogenen Daten
- **Prozess:** Betroffenenanfragen per Email an Datenschutz-Kontakt, Bearbeitung innerhalb 30 Tagen

### Export
- **Audit-Log Export:** CSV + JSON
- **Zeitraum-Filter** beim Export
- **Pflicht fuer Compliance**, nicht optional

### Alerting
- **Telegram-Alerts:** Existieren bereits (AlertManager). Datenminimierung: max. 80 Zeichen Preview, keine IP-Adressen, keine User-IDs
- **Drittlandtransfer:** Telegram (Dubai/UK), kein Angemessenheitsbeschluss. Absicherung ueber Art. 49 Abs. 1 lit. d DSGVO + strikte Datenminimierung. Langfristiges Ziel: Migration zu Self-Hosted Dashboard-Notifications
- **Dashboard-Notifications:** Badge/Counter auf Overview bei neuen Events
- **Email-Alerts (Enterprise):** Geplant

### WORM Audit-Log (KillSwitch)
- **Implementierung:** Append-Only Logfile mit SHA-256 Checksum-Chain (jeder Eintrag enthaelt Hash des vorherigen)
- **Tamper Detection:** Beim Lesen wird die Chain verifiziert — Manipulation wird erkannt
- **Backup:** Taeglicher rsync auf separaten Speicherort (oder separaten Server bei Enterprise)
- **Immutabilitaet:** Dateirechte read-only nach Schreibvorgang (`chmod 444`), separate Partition mit `append-only` Flag evaluieren

### Pflichtdokumente (als Markdown im Repo, `docs/compliance/`)
- [x] Verzeichnis der Verarbeitungstaetigkeiten (Art. 30) — **Tag 0** ✓
- [x] Datenschutz-Folgenabschaetzung DSFA (Art. 35) — **Tag 0 Entwurf** ✓
- [x] Logging Policy — **Tag 0** ✓
- [x] Rechtsgrundlage-Dokumentation (Art. 6) — **Tag 0** ✓
- [ ] Loeschkonzept (Art. 17)
- [ ] Berechtigungskonzept (Art. 25)
- [ ] TOMs (Art. 32)
- [ ] Incident Response Plan (Art. 33, 72h Meldefrist)
- [ ] AVV mit ip-projects.de pruefen/abschliessen (Art. 28)

### IntegrityWatchdog DSGVO
- Watchdog vergleicht nur SHA-256 Hashes — liest keine Dateiinhalte
- Alerts enthalten nur: Dateiname, Hash-Mismatch, Timestamp
- Keine personenbezogenen Daten im Watchdog-Pfad

### KillSwitch DSGVO
- Jede Aktivierung: Immutables Audit-Log (WORM mit Checksum-Chain)
- Bestaetigungsdialog mit Grund-Angabe (existiert: `reason` Pflichtfeld)
- WIPE/EMERGENCY: Doppel-Bestaetigung (existiert: `CONFIRM:` Prefix)
- **LOCKDOWN+ invalidiert alle aktiven Dashboard-Sessions**

## Meilensteine (7 Tage — Qualitaet vor Speed)

| Tag | Deliverable |
|-----|-------------|
| **Tag 0** | Logging Policy + DSFA Entwurf + Rechtsgrundlage-Doku + Verarbeitungsverzeichnis ✓ |
| **Tag 1** | Auth-Layer (JWT + httpOnly Refresh + Brute-Force-Schutz + KillSwitch-Session-Kill) |
| **Tag 2** | Dashboard Scaffold (React + Vite Build + FastAPI Mount + CSP Headers), API `/api/v1/` Endpoints |
| **Tag 3** | Overview View (System Health, Events, Status-Anzeigen) |
| **Tag 4** | **KillSwitch View** — Trigger + Confirmation-Modal + Codephrase-Reset (funktional ueber HTTPS) |
| **Tag 5** | Integrity View + Audit-Log Export (CSV/JSON) |
| **Tag 6** | Responsive Polish, WORM Checksum-Chain, Backup-Setup |
| **Tag 7** | End-to-End Testing, Compliance-Dokumente finalisieren, Deployment-Dokumentation |

## Self-Hosted Deployment

```bash
# Docker-Compose (DSGVO-Goldstandard: Daten verlassen nie die Infrastruktur)
docker compose up -d
# Zugriff via https://your-server:8420/dashboard
```

## Aenderungshistorie

| Version | Datum | Aenderungen |
|---------|-------|------------|
| 1.0 | 2026-02-19 | Erstfassung |
| 1.1 | 2026-02-19 | Ada DSGVO-Review: Rechtsgrundlage, httpOnly Cookie, Betroffenenrechte, Tag 0 Compliance |
| 1.2 | 2026-02-19 | Hiro Final Review: Auth-Hardening (Rate-Limit, Lockout, Session-Kill bei KillSwitch), API-Versionierung, CSP-Headers, CORS-Dokumentation, WORM-Backup-Strategie, Frontend-Build-Pipeline, Caddy-FastAPI Sicherheit, Timeline auf 7 Tage gestreckt |
