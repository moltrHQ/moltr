# Logging Policy — Moltr Security Shield

**Version:** 1.0 | **Datum:** 2026-02-19 | **Verantwortlich:** Walter Troska (moltrHQ)

---

## 1. Zweck

Diese Policy definiert, welche Daten von Moltr Security Shield protokolliert werden, warum, wie lange und wer Zugriff hat. Rechtsgrundlage: Art. 6 Abs. 1 lit. f DSGVO (berechtigtes Interesse an IT-Sicherheit).

## 2. Protokollierte Daten

### 2.1 API-Zugriffslog (`logs/moltr-api.log`)

| Feld | Beispiel | Personenbezug |
|------|---------|---------------|
| Timestamp | 2026-02-19 14:30:00 | Nein |
| Source IP | 127.0.0.1 | Ja (Art. 4 Nr. 1) |
| Source Port | 55886 | Nein |
| HTTP-Methode + Endpoint | POST /check/command | Nein |
| HTTP-Statuscode | 200 | Nein |

**Pseudonymisierung (geplant):** IP-Adressen werden auf /24 gekuerzt (letztes Oktett genullt).

### 2.2 Forensic Incident Log (`logs/moltr-forensic.log`)

Wird NUR bei geblockten Requests geschrieben. Enthaelt:

| Feld | Personenbezug | Massnahme |
|------|---------------|-----------|
| Incident-UUID | Nein | — |
| Timestamp (UTC) | Nein | — |
| Source IP + Port | Ja | Pseudonymisierung (letztes Oktett nullen) |
| User-Agent | Indirekt | Speicherung fuer Security-Analyse |
| Hostname des Servers | Nein | — |
| Incident-Type + Severity | Nein | — |
| Blocked Content (max. 500 Zeichen) | Potenziell ja | Minimierung auf notwendige Kontextinformation |
| Matched Pattern/Rule | Nein | — |

**Wichtig:** `text_preview` kann Nutzerinhalte enthalten, wenn ein KI-Agent Nutzernachrichten weiterleitet und diese einen False-Positive ausloesen. Daher wird dieses Feld auf maximal 500 Zeichen begrenzt und nach Ablauf der Aufbewahrungsfrist geloescht.

### 2.3 Security Events (`logs/security_events.jsonl`)

Strukturierte Events vom MoltrLogger mit automatischer Sensitive-Data-Redaction:
- API-Keys, Tokens, Passwoerter werden zu `[REDACTED]` ersetzt
- Rotation: 10 MB pro Datei, maximal 5 Backups (ca. 60 MB gesamt)

### 2.4 Error Log (`logs/moltr-error.log`)

Python-Fehlermeldungen und Stack-Traces. Kann indirekt personenbezogene Daten enthalten (Dateipfade mit Benutzernamen). Wird ueber PM2 verwaltet.

## 3. Was NICHT geloggt wird

- Inhalte erfolgreicher Requests (nur geblockte Inhalte werden geloggt)
- Passwoerter, Codephrasen oder API-Keys im Klartext
- Nutzeridentitaeten (kein Login-System, nur IP-basierte Zuordnung)
- Vollstaendige Request-Bodies bei erlaubten Anfragen

## 4. Aufbewahrungsfristen

| Log-Typ | Hot Storage | Cold Storage | Auto-Loeschung |
|---------|-------------|--------------|----------------|
| API-Zugriffslog | 90 Tage | — | Ja (Cronjob) |
| Forensic Incident Log | 90 Tage | 1 Jahr (encrypted) | Ja (Cronjob) |
| Security Events JSONL | Rotation (60 MB) | — | Automatisch durch Rotation |
| Error Log | 30 Tage | — | Ja (Cronjob) |

**Cold Storage:** Verschluesseltes JSON-Lines Format in `/data/archive/`, Zugriff nur fuer Administrator.

## 5. Zugriffskontrolle

| Rolle | Zugriff |
|-------|---------|
| System-Administrator | Vollzugriff (Server-Shell) |
| API-Nutzer (mit API-Key) | Kein Zugriff auf Logs |
| Dashboard-Admin (geplant) | Audit-Log lesen, Export (CSV/JSON) |
| Dashboard-Viewer (geplant) | Kein Zugriff auf Logs |

## 6. Technische Schutzmassnahmen

- **Verschluesselung:** TLS fuer API-Kommunikation (via Reverse Proxy)
- **Redaction:** Automatische Erkennung und Maskierung sensitiver Patterns im MoltrLogger
- **HMAC-Schutz:** IntegrityWatchdog-Baselines sind HMAC-geschuetzt
- **Zugriffsbeschraenkung:** Logs nur auf Server-Dateisystem, kein oeffentlicher Zugang
- **Cold Storage:** AES-256 verschluesseltes Archiv

## 7. Umsetzungsstatus

- [x] MoltrLogger mit Sensitive-Data-Redaction implementiert
- [x] RotatingFileHandler fuer Security Events
- [ ] IP-Pseudonymisierung in Forensic Log (naechster Sprint)
- [ ] Automatische Loeschung per Cronjob (naechster Sprint)
- [ ] Cold Storage Archivierung (Dashboard Phase 1)

## 8. Aenderungshistorie

| Datum | Version | Aenderung |
|-------|---------|-----------|
| 2026-02-19 | 1.0 | Erstfassung |
