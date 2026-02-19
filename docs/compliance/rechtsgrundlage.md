# Rechtsgrundlage der Datenverarbeitung

**Gemaess Art. 6 DSGVO** | **Version:** 1.0 | **Datum:** 2026-02-19

---

## 1. Anwendbare Rechtsgrundlage

**Art. 6 Abs. 1 lit. f DSGVO — Berechtigtes Interesse**

Die Verarbeitung personenbezogener Daten durch Moltr Security Shield ist zur Wahrung der berechtigten Interessen des Verantwortlichen erforderlich.

## 2. Berechtigtes Interesse

### Interessen des Verantwortlichen

1. **Schutz der IT-Infrastruktur** vor Schaeden durch KI-Agenten (Command Injection, Dateimanipulation, unerlaubte Netzwerkzugriffe)
2. **Schutz vor Credential-Leaks** durch automatische Erkennung und Blockierung von API-Keys, Tokens, Passwoertern in KI-Ausgaben
3. **Integritaetssicherung** der Systemdateien durch kontinuierliche Hash-Ueberwachung
4. **Notfall-Reaktionsfaehigkeit** durch KillSwitch-Mechanismus bei akuten Bedrohungen
5. **Compliance-Nachweis** durch revisionssichere Protokollierung von Sicherheitsvorfaellen

### Interessen der Betroffenen

1. Moeglichst wenig Verarbeitung personenbezogener Daten
2. Keine Weitergabe an Dritte
3. Zeitlich begrenzte Speicherung
4. Transparenz ueber die Verarbeitung

## 3. Interessenabwaegung

### Verarbeitete Datenkategorien und Bewertung

| Datenkategorie | Eingriffstiefe | Erforderlichkeit | Bewertung |
|----------------|---------------|-------------------|-----------|
| IP-Adressen (pseudonymisiert) | Gering | Hoch (Angriffserkennung) | Vertretbar |
| User-Agent | Gering | Mittel (Forensik) | Vertretbar |
| Text-Preview (max. 500 Zeichen) | Mittel | Hoch (Vorfallsanalyse) | Vertretbar mit Minimierung |
| Timestamps | Keine | Hoch (Chronologie) | Unproblematisch |
| Dateipfade (Hash-Vergleich) | Keine | Hoch (Integritaet) | Unproblematisch |

### Schutzfaktoren zugunsten der Betroffenen

- **Datenminimierung:** Nur geblockte Requests werden detailliert geloggt
- **Pseudonymisierung:** IP-Adressen werden gekuerzt (geplant)
- **Zweckbindung:** Daten werden ausschliesslich fuer Security-Analyse verwendet
- **Speicherbegrenzung:** Definierte Loeschfristen (90 Tage Hot, 1 Jahr Cold)
- **Zugriffsbeschraenkung:** Nur Administrator hat Zugriff auf Logs
- **Self-Hosting:** Daten verlassen die eigene Infrastruktur nicht (Ausnahme: Telegram-Alerts)
- **Sensitive-Data-Redaction:** Automatische Maskierung von Credentials in Logs

### Ergebnis

Die Abwaegung faellt **zugunsten des Verantwortlichen** aus, da:

1. Die verarbeiteten Daten ueberwiegend technische Metadaten sind (IP, Timestamp, User-Agent)
2. Nutzerinhalte nur bei Security-Vorfaellen und begrenzt (500 Zeichen) gespeichert werden
3. Umfangreiche technische Schutzmassnahmen implementiert sind
4. Die alternative — keine Sicherheitspruefung — zu erheblich groesseren Risiken fuehrt (Credential-Leaks, Systemkompromittierung)
5. Die Verarbeitung transparent dokumentiert ist

## 4. Nicht anwendbare Rechtsgrundlagen

| Rechtsgrundlage | Grund der Nichtanwendung |
|-----------------|------------------------|
| Art. 6 Abs. 1 lit. a (Einwilligung) | Unpraktikabel bei automatisierter Security-Pruefung |
| Art. 6 Abs. 1 lit. b (Vertragserfuellung) | Kein Vertrag mit den indirekt Betroffenen |
| Art. 6 Abs. 1 lit. c (Rechtliche Verpflichtung) | Keine gesetzliche Pflicht zur Log-Speicherung |
| Art. 6 Abs. 1 lit. d (Lebenswichtige Interessen) | Nicht einschlaegig |
| Art. 6 Abs. 1 lit. e (Oeffentliches Interesse) | Privatwirtschaftliches Projekt |

## 5. Besondere Hinweise

### Telegram-Alerting (Drittlandtransfer)

Fuer Security-Alerts via Telegram gilt zusaetzlich:
- **Rechtsgrundlage Drittlandtransfer:** Art. 49 Abs. 1 lit. d DSGVO (zur Geltendmachung berechtigter Interessen erforderlich, wenn keine andere Grundlage greift)
- **Massnahme:** Datenminimierung (max. 80 Zeichen technische Metadaten)
- **Langfristiges Ziel:** Migration zu Self-Hosted Alerting (Dashboard-Notifications)

### Erweiterung fuer Dashboard

Bei Einfuehrung des Security Dashboards wird diese Rechtsgrundlage um folgende Aspekte erweitert:
- Session-Daten (JWT, Refresh Tokens)
- Audit-Log-Zugriffe
- Diese Erweiterung wird vor Dashboard-Launch dokumentiert

---

| Datum | Version | Aenderung |
|-------|---------|-----------|
| 2026-02-19 | 1.0 | Erstfassung |
