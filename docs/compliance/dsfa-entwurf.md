# Datenschutz-Folgenabschaetzung (DSFA) — Entwurf

**Gemaess Art. 35 DSGVO** | **Version:** 1.0 | **Datum:** 2026-02-19

---

## 1. Systembeschreibung

**Moltr Security Shield** ist ein Security-Proxy fuer KI-Agenten. Er prueft eingehende Befehle, URLs, Dateipfade und KI-Ausgaben auf Sicherheitsrisiken, bevor sie ausgefuehrt werden.

| Aspekt | Beschreibung |
|--------|-------------|
| Betreiber | Walter Troska, moltrHQ |
| System | FastAPI-basierter Security-Proxy, Port 8420 |
| Hosting | Self-Hosted auf EU-Server (ip-projects.de, Deutschland) |
| Nutzer | KI-Agenten (Talon, Ada) + deren Endnutzer (indirekt) |
| Datenfluss | Agent → Moltr API → Pruefung → Erlaubt/Geblockt → Agent |

## 2. Notwendigkeit der DSFA

Eine DSFA ist erforderlich, da:
- **Systematische Ueberwachung** von Systemdateien (IntegrityWatchdog, 54 Dateien alle 60 Sekunden)
- **Automatisierte Einzelentscheidungen** ueber Blockierung/Erlaubnis von Befehlen
- **KillSwitch** kann gesamte Systemfunktionalitaet lahmlegen (hohes Eingriffsrisiko)
- Potenziell **personenbezogene Daten in KI-Ausgaben** (Nutzerinhalte)

## 3. Bewertung der Verhaeltnismaessigkeit

### 3.1 Ist die Verarbeitung notwendig?
**Ja.** Ohne Security-Proxy koennen KI-Agenten:
- Systemdateien manipulieren oder loeschen
- Credentials im Klartext ausgeben
- Schaedliche Befehle ausfuehren
- Netzwerkzugriffe auf malicious Domains durchfuehren

### 3.2 Gibt es mildere Mittel?
Das System ist bereits auf Datenminimierung ausgelegt:
- Nur **geblockte** Requests werden detailliert geloggt (nicht alle)
- Text-Preview begrenzt auf 500 Zeichen (Forensic) bzw. 80 Zeichen (Telegram)
- IntegrityWatchdog vergleicht nur Hashes, liest keine Dateiinhalte
- KillSwitch-Events enthalten keine Nutzerinhalte
- Sensitive-Data-Redaction im Logger aktiv

### 3.3 Interessenabwaegung
| Interesse | Gewichtung |
|-----------|-----------|
| Schutz der IT-Infrastruktur vor KI-bedingten Sicherheitsrisiken | Hoch |
| Schutz der Endnutzer vor Credential-Leaks | Hoch |
| Minimierung der Datenverarbeitung (Betroffeneninteresse) | Mittel — adressiert durch technische Massnahmen |
| **Ergebnis** | Ueberwiegt zugunsten des Verantwortlichen |

## 4. Identifizierte Risiken und Massnahmen

### Risiko 1: IP-Adressen im Forensic Log (MITTEL)

| Aspekt | Bewertung |
|--------|----------|
| Eintrittswahrscheinlichkeit | Hoch (bei jedem geblockten Request) |
| Schwere | Gering (nur IP, keine weiteren Identifizierungsmerkmale) |
| Gesamtrisiko | MITTEL |
| **Massnahme** | IP-Pseudonymisierung (letztes Oktett nullen), Loeschfrist 90 Tage |
| Status | Geplant (naechster Sprint) |

### Risiko 2: Nutzerinhalte im Text-Preview (MITTEL-HOCH)

| Aspekt | Bewertung |
|--------|----------|
| Eintrittswahrscheinlichkeit | Mittel (nur bei False-Positives auf Nutzertext) |
| Schwere | Mittel (max. 500 Zeichen, koennten persoenliche Informationen enthalten) |
| Gesamtrisiko | MITTEL-HOCH |
| **Massnahmen** | 1) Begrenzung auf 500 Zeichen 2) Loeschfrist 90 Tage 3) Sensitive-Data-Redaction pruefen ob auf Preview anwendbar |
| Status | Teilweise umgesetzt (Begrenzung ja, Loeschung geplant) |

### Risiko 3: Telegram-Drittlandtransfer (MITTEL)

| Aspekt | Bewertung |
|--------|----------|
| Eintrittswahrscheinlichkeit | Hoch (bei jedem Alert) |
| Schwere | Gering (max. 80 Zeichen, ueberwiegend technische Metadaten) |
| Gesamtrisiko | MITTEL |
| **Massnahmen** | 1) Datenminimierung (80 Zeichen) 2) Keine vollstaendigen Nutzerinhalte 3) Keine IP-Adressen in Alerts 4) Dokumentation als Drittlandtransfer |
| Status | Umgesetzt (Datenminimierung), Dokumentation in diesem Dokument |

### Risiko 4: KillSwitch-Missbrauch (MITTEL)

| Aspekt | Bewertung |
|--------|----------|
| Eintrittswahrscheinlichkeit | Gering (API-Key + Rate-Limiting + Codephrase) |
| Schwere | Hoch (System-Stillstand moeglich) |
| Gesamtrisiko | MITTEL |
| **Massnahmen** | 1) API-Key-Authentifizierung 2) Rate-Limiting (3/min Trigger, 5/min Reset) 3) WIPE/EMERGENCY benoetigt "CONFIRM:" Prefix 4) Codephrase fuer Reset 5) Immutables Audit-Log |
| Status | Vollstaendig umgesetzt |

### Risiko 5: Fehlende Log-Rotation fuer Forensic Log (HOCH)

| Aspekt | Bewertung |
|--------|----------|
| Eintrittswahrscheinlichkeit | Hoch (Logs wachsen unbegrenzt) |
| Schwere | Mittel (Verstoess gegen Speicherbegrenzung Art. 5 Abs. 1 lit. e) |
| Gesamtrisiko | HOCH |
| **Massnahme** | Implementierung von Log-Rotation + automatischer Loeschung per Cronjob |
| Status | **Offen — Prioritaet 1** |

## 5. Restrisikobewertung

Nach Umsetzung aller geplanten Massnahmen:

| Risiko | Vorher | Nachher |
|--------|--------|---------|
| IP im Forensic Log | MITTEL | GERING (pseudonymisiert + geloescht) |
| Nutzerinhalt im Preview | MITTEL-HOCH | GERING (begrenzt + geloescht + redacted) |
| Telegram-Drittlandtransfer | MITTEL | GERING-MITTEL (minimiert, dokumentiert) |
| KillSwitch-Missbrauch | MITTEL | GERING (mehrschichtige Absicherung) |
| Fehlende Log-Rotation | HOCH | BEHOBEN |

**Gesamtbewertung:** Nach Umsetzung der geplanten Massnahmen ist das Restrisiko **vertretbar**. Die Verarbeitung kann unter den definierten Bedingungen erfolgen.

## 6. Konsultation der Aufsichtsbehoerde

Eine Konsultation nach Art. 36 DSGVO ist **nicht erforderlich**, da das Restrisiko nach Umsetzung der Massnahmen vertretbar ist.

## 7. Ueberpruefungsplan

| Zeitpunkt | Anlass |
|-----------|--------|
| Nach Umsetzung der IP-Pseudonymisierung | Risiko 1 neu bewerten |
| Nach Implementierung der Log-Rotation | Risiko 5 als behoben markieren |
| Bei Einfuehrung des Dashboards | Neue Verarbeitungen bewerten (Auth, Session-Daten) |
| Halbjaehrlich | Regelmaessige Ueberpruefung |

---

| Datum | Version | Aenderung |
|-------|---------|-----------|
| 2026-02-19 | 1.0 | Erstfassung (Entwurf) |
