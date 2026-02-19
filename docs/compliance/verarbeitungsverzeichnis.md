# Verzeichnis der Verarbeitungstaetigkeiten (Art. 30 DSGVO)

**Version:** 1.0 | **Datum:** 2026-02-19 | **Verantwortlicher:** Walter Troska, moltrHQ

---

## Angaben zum Verantwortlichen

| Feld | Wert |
|------|------|
| Name | Walter Troska |
| Organisation | moltrHQ |
| Kontakt | hello@moltr.tech |
| Datenschutz-Kontakt | hello@moltr.tech |
| Sitz | Deutschland (EU) |

---

## Verarbeitungstaetigkeit 1: API-Zugriffskontrolle

| Feld | Beschreibung |
|------|-------------|
| **Bezeichnung** | Sicherheitspruefung eingehender API-Requests |
| **Zweck** | Schutz der IT-Infrastruktur vor schaedlichen Befehlen, Pfadzugriffen und URLs |
| **Rechtsgrundlage** | Art. 6 Abs. 1 lit. f DSGVO (berechtigtes Interesse) |
| **Kategorien betroffener Personen** | Nutzer der geschuetzten KI-Agenten (indirekt) |
| **Kategorien personenbezogener Daten** | IP-Adressen, User-Agent, Timestamps |
| **Empfaenger** | Keine Weitergabe an Dritte |
| **Drittlandtransfer** | Nein (Self-Hosted, EU-Server ip-projects.de) |
| **Loeschfrist** | 90 Tage Hot, 1 Jahr Cold Storage |
| **TOMs** | API-Key-Authentifizierung, Rate-Limiting, TLS |

## Verarbeitungstaetigkeit 2: Output-Scanning

| Feld | Beschreibung |
|------|-------------|
| **Bezeichnung** | Scanning von KI-Ausgaben auf Credentials und sensible Daten |
| **Zweck** | Verhinderung von Credential-Leaks durch KI-Agenten |
| **Rechtsgrundlage** | Art. 6 Abs. 1 lit. f DSGVO (berechtigtes Interesse) |
| **Kategorien betroffener Personen** | Nutzer der KI-Agenten, deren Anfragen verarbeitet werden |
| **Kategorien personenbezogener Daten** | Potenziell Nutzerinhalte (max. 500 Zeichen bei Blockierung im Forensic Log) |
| **Empfaenger** | Keine Weitergabe (nur lokales Log) |
| **Drittlandtransfer** | Nein |
| **Loeschfrist** | 90 Tage (Forensic Log) |
| **TOMs** | Sensitive-Data-Redaction, Minimierung auf 500 Zeichen, Rotation |

## Verarbeitungstaetigkeit 3: Integritaetsueberwachung

| Feld | Beschreibung |
|------|-------------|
| **Bezeichnung** | SHA-256 Hash-Vergleich ueberwachter Systemdateien |
| **Zweck** | Erkennung unautorisierter Dateimanipulationen |
| **Rechtsgrundlage** | Art. 6 Abs. 1 lit. f DSGVO (berechtigtes Interesse) |
| **Kategorien betroffener Personen** | Keine (nur Systemdateien, keine personenbezogenen Daten) |
| **Kategorien personenbezogener Daten** | Keine (nur Dateinamen und SHA-256 Hashes) |
| **Empfaenger** | Keine |
| **Drittlandtransfer** | Nein |
| **Loeschfrist** | Nur In-Memory, entfaellt bei Neustart |
| **TOMs** | HMAC-geschuetzte Baselines, kein Lesen von Dateiinhalten |

## Verarbeitungstaetigkeit 4: KillSwitch-Protokollierung

| Feld | Beschreibung |
|------|-------------|
| **Bezeichnung** | Protokollierung von KillSwitch-Aktivierungen und -Resets |
| **Zweck** | Revisionssichere Nachvollziehbarkeit kritischer Sicherheitsmassnahmen |
| **Rechtsgrundlage** | Art. 6 Abs. 1 lit. f DSGVO (berechtigtes Interesse), Art. 32 DSGVO (Sicherheitsmassnahmen) |
| **Kategorien betroffener Personen** | Administratoren, die den KillSwitch bedienen |
| **Kategorien personenbezogener Daten** | IP-Adresse des Ausloesers (im Forensic Log), Timestamp, Begruendung |
| **Empfaenger** | Keine |
| **Drittlandtransfer** | Nein |
| **Loeschfrist** | In-Memory (Laufzeit) + 1 Jahr im Forensic Log |
| **TOMs** | Codephrase-Authentifizierung, Bestaetigungsdialog, WORM-Prinzip |

## Verarbeitungstaetigkeit 5: Security-Alerting

| Feld | Beschreibung |
|------|-------------|
| **Bezeichnung** | Benachrichtigung bei Sicherheitsvorfaellen via Telegram |
| **Zweck** | Sofortige Information des Administrators bei Bedrohungen |
| **Rechtsgrundlage** | Art. 6 Abs. 1 lit. f DSGVO (berechtigtes Interesse) |
| **Kategorien betroffener Personen** | Nutzer, deren Inhalte einen Alert ausloesen (indirekt) |
| **Kategorien personenbezogener Daten** | Dateinamen, max. 80 Zeichen Textvorschau bei Output-Scan-Alerts |
| **Empfaenger** | Telegram Messenger Inc. (Technischer Dienstleister) |
| **Drittlandtransfer** | Ja — Telegram (Sitz: Dubai/UK, Server weltweit). Massnahme: Minimierung der uebertragenen Daten, keine vollstaendigen Nutzerinhalte |
| **Loeschfrist** | Nicht steuerbar (Telegram-seitig) |
| **TOMs** | Datenminimierung (nur 80 Zeichen Preview), TLS-Verschluesselung, Bot-Token-Authentifizierung |

---

## Regelmaessige Ueberpruefung

Dieses Verzeichnis wird bei jeder wesentlichen Aenderung der Datenverarbeitung aktualisiert, mindestens jedoch halbjaehrlich.

| Datum | Version | Aenderung |
|-------|---------|-----------|
| 2026-02-19 | 1.0 | Erstfassung |
