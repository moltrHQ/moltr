# Incident Response Plan
## Moltr Security Shield — Art. 33/34 DSGVO

**Stand:** 2026-02-19
**Version:** 1.0
**Verantwortlich:** Walter Troska, moltrHQ
**Meldefrist:** 72 Stunden (Art. 33 DSGVO)

---

## 1. Incident-Klassifizierung

| Stufe | Bezeichnung | Kriterien | Beispiele |
|-------|-------------|-----------|----------|
| **P1** | Kritisch | Datenpanne mit hohem Risiko für Betroffene, aktiver Angriff, Systemkompromittierung | Honeypot getriggert + tatsächlicher Datenzugriff, API-Key-Leak, Ransomware |
| **P2** | Hoch | Sicherheitsverletzung ohne bestätigten Datenzugriff, IntegrityWatchdog-Alarm | Datei-Manipulation erkannt, Brute-Force-Lockout, KillSwitch EMERGENCY getriggert |
| **P3** | Mittel | Anomalie, Verdacht ohne Bestätigung, Verfügbarkeitsausfall | Ungewöhnliches Traffic-Muster, Dienstausfall >1h, Zertifikats-Ablauf |
| **P4** | Niedrig | Einzelne Rate-Limit-Überschreitungen, fehlgeschlagene Logins, geplante Wartung | 5 fehlgeschlagene Login-Versuche, 429-Responses |

---

## 2. Erkennung und Alarmierung

### 2.1 Automatische Erkennung

| Signal | Quelle | Aktion |
|--------|--------|--------|
| Honeypot-Trigger | `honeypot_router.py` | CRITICAL-Log + Telegram-Alert (sofort) |
| Integrity-Verletzung | `IntegrityWatchdog` | CRITICAL-Log + Telegram-Alert (sofort) |
| KillSwitch LOCKDOWN | `killswitch.py` | Alle Sessions invalidiert, WORM-Log-Eintrag |
| Brute-Force-Lockout | `brute_force.py` | WARNING-Log (kein Auto-Alert — manuelles Review) |
| OutputScanner-Block | `output_scanner.py` | BLOCK-Response + Forensic JSONL |
| Unbekannte Endpoint-Zugriffe | FastAPI 404-Logs | Manuelles Log-Review |

### 2.2 Manuelle Erkennung

- Tägliches Log-Review (`logs/moltr.log`, `logs/security_events.jsonl`)
- Wöchentliches KillSwitch-Log-Review (`GET /killswitch/log`)
- Integrity-Check bei jedem Deployment (`GET /integrity/check`)

---

## 3. Response-Ablauf

### Phase 1: Erkennung & Eingrenzung (0–1 Stunde)

```
1. Incident bestätigen
   → Honeypot/Watchdog-Alert verifizieren
   → Ist es ein False Positive? (Honeypot-Manifest: GET /honeypots/manifest)

2. Sofortige Eingrenzung
   → Bei P1/P2: KillSwitch LOCKDOWN auslösen
     POST /killswitch/trigger { level: "LOCKDOWN", reason: "Incident YYYY-MM-DD-XXX" }
   → API-Key widerrufen und neu generieren (.env → MOLTR_API_KEY)
   → Verdächtige IPs auf Firewall-Ebene sperren

3. Beweise sichern
   → logs/ sichern (readonly-Kopie)
   → security_events.jsonl sichern
   → KillSwitch Audit-Log exportieren (GET /api/v1/dashboard/killswitch/export)
   → Honeypot-Incident-ID dokumentieren (in Log: "id=XXXXXXXX")
```

### Phase 2: Analyse (1–12 Stunden)

```
4. Schadensausmaß bestimmen
   → Welche Daten waren zugänglich?
   → Welche Endpoints wurden aufgerufen?
   → Zeitraum der Kompromittierung bestimmen

5. Angriffsvektor identifizieren
   → IP-Adressen aus Logs analysieren
   → User-Agent-Pattern prüfen
   → Korrelation mit anderen Log-Quellen (Reverse-Proxy-Logs, SSH-Logs)

6. Personenbezogene Daten betroffen?
   → Waren Logs mit pseudonymisierten IPs zugänglich?
   → Waren Secrets (Fernet-verschlüsselt) betroffen?
   → Waren Session-Tokens kompromittiert?
```

### Phase 3: Meldung (innerhalb 72 Stunden nach Kenntnis)

```
7. Meldepflicht prüfen (Art. 33 DSGVO)
   → Datenpanne mit Risiko für natürliche Personen?
   → JA → Meldung an Aufsichtsbehörde (siehe Abschnitt 5)
   → NEIN → Interne Dokumentation ausreicht

8. Betroffene informieren (Art. 34 DSGVO)
   → Nur wenn HOHES Risiko für Betroffene
   → Über welchen Kanal? (Telegram, E-Mail, Website)
   → Inhalt: Was passiert, welche Daten, was tun (Passwort ändern etc.)
```

### Phase 4: Wiederherstellung (12–72 Stunden)

```
9. Systeme bereinigen
   → Kompromittierte Schlüssel rotieren:
     - MOLTR_API_KEY (neu generieren)
     - MOLTR_JWT_SECRET (neu generieren, invalidiert alle Sessions)
     - MOLTR_FERNET_KEY (nur wenn Secrets-Datei betroffen)
   → Integrity-Baseline neu aufbauen: POST /integrity/baseline

10. KillSwitch entsperren (wenn bereit)
    POST /killswitch/reset { level: "LOCKDOWN", codephrase: "..." }

11. Dienst wiederherstellen
    → PM2 restart moltr-security
    → Health-Check: GET /health
    → Funktionstest aller kritischen Endpoints
```

### Phase 5: Nachbereitung (innerhalb 1 Woche)

```
12. Post-Mortem erstellen
    → Was ist passiert? (Timeline)
    → Was wurde behoben?
    → Was wird langfristig verbessert?
    → TOMs aktualisieren (dieses Dokument)

13. Lessons Learned umsetzen
    → Code-Fixes committen und deployen
    → Monitoring-Regeln anpassen
    → Team informieren / schulen
```

---

## 4. Incident-Dokumentation

Für jeden P1/P2-Incident wird ein Incident-Report erstellt:

**Dateiname:** `docs/incidents/YYYY-MM-DD-XXX-incident.md`

**Mindestinhalt:**

```markdown
# Incident YYYY-MM-DD-XXX

**Datum Erkennung:** YYYY-MM-DD HH:MM UTC
**Datum Meldung DSB:** YYYY-MM-DD HH:MM UTC (wenn zutreffend)
**Schweregrad:** P1 / P2 / P3 / P4
**Status:** Offen / In Bearbeitung / Abgeschlossen

## Zusammenfassung
[1-2 Sätze was passiert ist]

## Timeline
- HH:MM — Ersterkennung (Quelle: Honeypot/Watchdog/Manuell)
- HH:MM — Eingrenzung (KillSwitch LOCKDOWN)
- HH:MM — Aufsichtsbehörde informiert (wenn zutreffend)
- HH:MM — System wiederhergestellt

## Betroffene Daten
[Welche Datenkategorien, geschätzte Menge, Betroffene]

## Ursache
[Root Cause Analysis]

## Maßnahmen
[Was wurde getan, was wird langfristig geändert]

## Meldepflicht
[ ] Meldepflicht geprüft
[ ] Meldung an Aufsichtsbehörde (Art. 33) → Datum:
[ ] Betroffene informiert (Art. 34) → Datum:
[ ] Nicht meldepflichtig — Begründung:
```

---

## 5. Kontakte und Meldestellen

### Interne Kontakte

| Rolle | Person | Erreichbarkeit |
|-------|--------|---------------|
| Verantwortlicher | Walter Troska | dergeldesel@gmail.com |
| Technische Umsetzung | Walter Troska | Telegram: @Hiro_K_me |

### Aufsichtsbehörden (Art. 33 DSGVO)

**Österreich (primär):**
Datenschutzbehörde (DSB)
Barichgasse 40–42, 1030 Wien
Tel: +43 1 52 152-0
E-Mail: dsb@dsb.gv.at
Online-Meldung: https://www.dsb.gv.at

**Deutschland (falls zutreffend):**
Je nach Bundesland der Niederlassung — zuständiger Landesdatenschutzbeauftragter

**Online-Meldung EU:** https://www.edpb.europa.eu/our-work-tools/our-documents/other/national-data-protection-authorities_en

---

## 6. Schlüssel-Rotation Checkliste

Bei Incident mit Schlüssel-Kompromittierung:

```
[ ] MOLTR_API_KEY: python -c "import secrets; print(secrets.token_urlsafe(32))"
[ ] MOLTR_JWT_SECRET: python -c "import secrets; print(secrets.token_urlsafe(64))"
[ ] MOLTR_FERNET_KEY: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
[ ] MOLTR_WATCHDOG_HMAC_KEY: python -c "import secrets; print(secrets.token_urlsafe(32))"
[ ] MOLTR_KILLSWITCH_CODEPHRASE: Neues sicheres Passwort wählen
[ ] MOLTR_DASHBOARD_PASS_HASH: Neues Passwort + bcrypt neu hashen
[ ] .env aktualisieren
[ ] PM2 restart moltr-security
[ ] Integrity-Baseline neu aufbauen
[ ] Alle aktiven Sessions sind durch JWT_SECRET-Rotation automatisch invalidiert ✓
```

---

## 7. Änderungshistorie

| Datum | Version | Änderung |
|-------|---------|----------|
| 2026-02-19 | 1.0 | Initiale Version erstellt |

---

*Moltr Security Shield — Made in Vienna*
*Copyright 2026 Walter Troska / moltrHQ | AGPL-3.0*
