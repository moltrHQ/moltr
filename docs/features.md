# Moltr Ecosystem — Features & Status

**Stand:** 2026-02-19
**Gesamtfortschritt:** ~58%

> Diese Datei dient als zentrale Feature-Uebersicht fuer das gesamte Moltr-Oekosystem.
> Kann direkt an Claude gefuettert werden um Webseite, Fortschrittsbalken und Projektdetails zu aktualisieren.

---

## Legende

| Symbol | Bedeutung |
|--------|-----------|
| DONE | Implementiert und getestet |
| IMPL | Implementiert, noch nicht produktiv getestet |
| WIP | In Arbeit |
| PLAN | Geplant, Design vorhanden |
| IDEA | Konzeptidee, noch kein Design |

---

## 1. Moltr Security Shield

> **Idee:** Externe Security-Schicht die jeden AI-Agent schuetzt — unabhaengig vom LLM-Provider. Wie eine Firewall, aber fuer KI-Output.

| # | Feature | Status | Kommentar |
|---|---------|--------|-----------|
| 1.1 | OutputScanner (Secret Detection) | DONE | 17 Patterns, Deobfuskation, 43 Unit-Tests. Scannt KI-Antworten auf geleakte API-Keys, Tokens, etc. |
| 1.2 | ActionValidator (Command Check) | DONE | Allowlist/Blocklist, Injection-Erkennung. Verhindert dass KI gefaehrliche Shell-Befehle ausfuehrt. |
| 1.3 | NetworkFirewall (URL Check) | DONE | Domain-basierte Zugriffskontrolle. Blockiert Zugriffe auf nicht-gewhitelistete Domains. |
| 1.4 | FilesystemGuard (Path Check) | DONE | Pfad-basierte Zugriffskontrolle + Honeypots. Schuetzt Systemverzeichnisse und sensible Dateien. |
| 1.5 | KillSwitch + Lockdown | DONE | Notfall-Abschaltung. Nach X Leaks wird JEDER Output geblockt bis zum manuellen Reset. |
| 1.6 | AlertManager | DONE | Benachrichtigungssystem fuer Security-Events. |
| 1.7 | Forensic Incident Logging | DONE | JSONL-Logs mit UUID, Timestamp, Request-Details. Lueckenloser Audit-Trail. |
| 1.8 | HTTP API (FastAPI) | DONE | Port 8420, 6 Endpoints. Jeder Agent kann Moltr ueber HTTP nutzen. |
| 1.9 | API-Authentifizierung | DONE | X-API-Key Header, Bearer Token, Query-Param. Schuetzt die Security-API selbst. |
| 1.10 | Security Levels (high/medium/low) | DONE | Konfigurierbar pro Bot/Agent. High = streng, Low = permissiv. |
| 1.11 | Docker-Deployment | DONE | Dockerfile + docker-compose.yml. Laeuft ueberall. |
| 1.12 | Rate-Limiting | DONE | 30 cmd/min, 10 writes/min, 5 network/min. Verhindert Brute-Force durch KI. |
| 1.13 | 313 Unit-Tests | DONE | Vollstaendige Testabdeckung der Security-Module inkl. Integration-Tests und Core-Tests. |
| 1.14 | HTTP API Rate-Limiting | DONE | slowapi-basiert. Alle Endpoints mit individuellen Limits. 429-Response bei Ueberschreitung. |
| 1.15 | KillSwitch API-Endpoints | DONE | POST /killswitch/trigger + /reset + GET /log. WIPE/EMERGENCY braucht CONFIRM-Prefix. Codephrase aus ENV. |
| 1.16 | IntegrityWatchdog | DONE | SHA-256 Baselines, 54 Dateien, Auto-Scheduler (60s), HMAC-geschuetzte Baseline, Telegram-Alerts bei Tampering. |
| 1.17 | Integrity API-Endpoints | DONE | GET /integrity/check + /report. On-Demand Integritaetspruefung. |

**Fortschritt Moltr Security: 100%** (Kern fertig + Hardening, wird kontinuierlich erweitert)

---

## 2. Talon Agent

> **Idee:** Eigener Agent-Kern mit der Philosophie "Weniger Iterationen, mehr Tiefe". Kein CLI-Wrapper, kein OpenClaw-Klon. Provider-unabhaengig, token-effizient, mit Security by Design.

### Phase 1-3: Foundation (DONE)

| # | Feature | Status | Kommentar |
|---|---------|--------|-----------|
| 2.1 | Direct Anthropic SDK | DONE | Kein CLI-Subprocess mehr. Direkte API-Calls = schneller, zuverlaessiger, kein CLI-Abo noetig. |
| 2.2 | Adaptive Triage | DONE | Regelbasierte Klassifikation: Quick/Standard/Deep. 0 Tokens fuer die Entscheidung, pure Heuristik. |
| 2.3 | Depth-Config (Model + Tokens) | DONE | Jedes Depth-Level hat eigenes Modell + Token-Budget. Quick = guenstig, Deep = maechtig. |
| 2.4 | Capability Tiers | DONE | Android-artiges Permission-System: chat/tools/files/terminal/computer. Sensible Tiers brauchen Opt-In. |
| 2.5 | Consent-Tracking (Supabase) | DONE | Rechtssicherheit: User-Zustimmung wird mit Audit-Trail gespeichert. DSGVO-ready. |
| 2.6 | Tool Definitions | DONE | Provider-agnostische Tool-Definitionen fuer bash, read_file, write_file. |
| 2.7 | Feature-Flag Rollback | DONE | TALON_ENABLED=true/false schaltet zwischen Talon und Legacy-CLI um. Null-Risk-Deployment. |

### Phase 4-5: Intelligence (DONE)

| # | Feature | Status | Kommentar |
|---|---------|--------|-----------|
| 2.8 | Smart Memory (Supabase) | DONE | Semantic Retrieval: nur relevante Fakten/Ziele pro Anfrage im Kontext. Spart ~60% Tokens. |
| 2.9 | Streaming (Deep Mode) | DONE | Progressive Telegram-Message-Edits. User sieht die Antwort entstehen statt 30s zu warten. |
| 2.10 | Self-Reflection | DONE | Haiku prueft Deep-Mode-Antworten auf Qualitaet. Schlechte Antworten werden automatisch verbessert. |
| 2.11 | Timeout-Handling | DONE | Konfigurierbar via ENV. Graceful Degradation statt Endlos-Hang. |

### Phase 6: Multi-Provider Layer (IMPL)

> **Idee:** Wer nur auf einen Provider angewiesen ist, ist verwundbar. Multi-Provider = Resilienz + Kostenoptimierung.

| # | Feature | Status | Kommentar |
|---|---------|--------|-----------|
| 2.12 | Provider-Adapter Interface | IMPL | Gemeinsames Interface fuer alle LLMs. Einmal implementieren, ueberall nutzen. |
| 2.13 | Anthropic Adapter | IMPL | Extrahiert aus core.ts. SDK-Wrapper mit Streaming-Support. |
| 2.14 | Groq Adapter | IMPL | Nutzt groq-sdk. Llama 3.3 70B = sub-second Antworten fuer Quick Mode. |
| 2.15 | OpenAI Adapter | IMPL | Pure fetch() — kein SDK noetig. GPT-4o als Backup-Provider. |
| 2.16 | Provider Registry + Routing | IMPL | Automatisches Routing per Depth-Level. Fallback-Chain: Primaer → Anthropic → Error. |
| 2.17 | ENV-Overrides | IMPL | TALON_QUICK_PROVIDER, TALON_STANDARD_MODEL, etc. Volle Kontrolle ohne Code-Aenderung. |
| 2.18 | /providers Command | IMPL | Telegram-Command zeigt Provider-Status + aktuelles Routing. |
| 2.19 | Provider-agnostischer Core | IMPL | core.ts, types.ts, tools.ts komplett refactored. Keine Anthropic-Types mehr im Core. |

### Phase 7: ToS-Compliance Engine (IMPL)

> **Idee:** OpenClaw dockt parasitaer ans CLI-Abo an → Account-Sperrung. Talon prueft ToS automatisch VOR Provider-Aktivierung.

| # | Feature | Status | Kommentar |
|---|---------|--------|-----------|
| 2.20 | Automatische ToS-Analyse | IMPL | Haiku analysiert Provider-ToS-Seiten: ERLAUBT/EINGESCHRAENKT/VERBOTEN/UNKLAR. |
| 2.21 | User-Acknowledgement Flow | IMPL | User muss bestaetigen bevor Nicht-Anthropic-Provider aktiv wird. Audit in Supabase. |
| 2.22 | 30-Tage-Cache + Auto-Refresh | IMPL | Ergebnis wird gecacht. Nach 30 Tagen automatische Neu-Pruefung. |
| 2.23 | Anthropic Pre-Approved | IMPL | Unser Primaer-Provider braucht keinen Check. Immer verfuegbar. |

### Phase 8: TalonHub Skill Marketplace (IMPL)

> **Idee:** OpenClaws ClawHub hat ~900 malicious Skills. TalonHub: signiert, verifiziert, sandboxed, bezahlt. Qualitaet statt Quantitaet.

| # | Feature | Status | Kommentar |
|---|---------|--------|-----------|
| 2.24 | Skill-Paket-Format | IMPL | Manifest + Code + Signatur + Checksum. Alles in einem JSON-Paket. |
| 2.25 | SHA-256 Checksum (Integritaet) | IMPL | Stellt sicher dass das Paket nicht manipuliert wurde. |
| 2.26 | Ed25519 Signatur (Authentizitaet) | IMPL | Nur TalonHub kann gueltig signieren. Unsigned = ABGELEHNT. |
| 2.27 | Sandboxed Execution | IMPL | Blocked globals (process, require, Bun), permission-gated APIs, 30s Timeout. |
| 2.28 | Permission-System (Android-Stil) | IMPL | 7 Permissions: network, files, memory, telegram. User genehmigt explizit. |
| 2.29 | Moltr Output-Scan auf Skills | IMPL | Skill-Output durchlaeuft Moltr Security. Geleakte Secrets = blockiert. |
| 2.30 | Skill Lifecycle Management | IMPL | Install, Approve, Run, Remove, Info. Komplett via Telegram steuerbar. |
| 2.31 | Supabase-Persistenz | IMPL | Skills + Permissions ueberleben Bot-Neustarts. Re-Verifikation beim Laden. |
| 2.32 | /skill Commands | IMPL | 6 Telegram-Commands: list, install, approve, run, remove, info. |

### Zukunft: Blockchain & Token (IDEA)

> **Idee:** Eigener Krypto-Token als Zahlungsmittel fuer TalonHub + Community-Support. Skill-Ownership auf der Blockchain.

| # | Feature | Status | Kommentar |
|---|---------|--------|-----------|
| 2.33 | Moltr/Talon Token | IDEA | Eigener Utility-Token. Community kann Entwicklung supporten, Creator werden bezahlt. |
| 2.34 | On-Chain Skill-Zahlungen | IDEA | Skill-Kauf via Token. Keine Kreditkarten-Gebuehren, global, transparent. |
| 2.35 | Blockchain Skill-Registry | IDEA | Skill-Ownership unveraenderlich auf der Chain. Aehnlich wie TON-Telefonnummern. |
| 2.36 | Token-Guthaben fuer Creator | IDEA | Alternative zur Cash-Auszahlung: API-Credits statt Bargeld. |

**Fortschritt Talon Agent: ~70%** (Core + Intelligence + Multi-Provider fertig, Testing + TalonHub-Backend offen)

---

## 3. Telegram Bot (Moltr Agent)

> **Idee:** Persoenlicher AI-Assistent via Telegram. Immer erreichbar, voice-faehig, mit Workspace und Security.

| # | Feature | Status | Kommentar |
|---|---------|--------|-----------|
| 3.1 | Telegram Bot (grammY) | DONE | Text, Voice, Dokumente, Bilder. Telegram als primaeerer Channel. |
| 3.2 | Voice Transcription (Groq Whisper) | DONE | Sprachnachrichten → Text → KI → Text → Sprache (TTS). Natuerliche Kommunikation. |
| 3.3 | Text-to-Speech (OpenAI) | DONE | Bot antwortet optional als Sprachnachricht. |
| 3.4 | Workspace (Dateiverwaltung) | DONE | Upload, Download, Ordnerstruktur. Passwort-geschuetzt mit Lockdown. |
| 3.5 | Datei-Konvertierung (docx, pdf) | DONE | Automatische Konvertierung wenn Bot [FILE:name.docx] sendet. |
| 3.6 | Heartbeat Scheduler | DONE | Zeitgesteuerte Tasks (Erinnerungen, Checks). Hot-Reload aus HEARTBEAT.md. |
| 3.7 | MCP-Server Integration | DONE | Exa (Websuche), Email (IONOS), Playwright (Browser), Email-Marketing. |
| 3.8 | Memory System (Supabase) | DONE | Facts, Goals, Recent Messages, Semantic Search. Persistent ueber Neustarts. |
| 3.9 | Quarantine (Datei-Scan) | DONE | Hochgeladene Dateien werden auf Malware-Patterns geprueft. |
| 3.10 | Auto-Delete + Purge | DONE | Sensitiv-markierte Nachrichten werden automatisch geloescht. /purge fuer Bulk. |
| 3.11 | Panic Mode | DONE | Erkennt Prompt-Injection-Versuche und blockiert sofort. |
| 3.12 | Deduplication | DONE | Verhindert doppelte Verarbeitung bei PM2-Neustarts. |
| 3.13 | Multi-User Support | DONE | Mehrere autorisierte Telegram-User-IDs. |

**Fortschritt Telegram Bot: 100%** (Feature-complete, wird mit Talon-Features erweitert)

---

## 4. Marketing Bot

> **Idee:** Separater Bot fuer Marketing-Aufgaben. Eigener Workspace, eigene Credentials, medium Security Level.

| # | Feature | Status | Kommentar |
|---|---------|--------|-----------|
| 4.1 | Shared relay.ts Architektur | DONE | Gleiche Codebasis wie Hauptbot, eigenes CONFIG_DIR. |
| 4.2 | Marketing Workspace | DONE | Eigener Workspace-Ordner fuer Marketing-Materialien. |
| 4.3 | Medium Security Level | DONE | Credentials-Handling erlaubt (fuer Social-Media-Logins etc.). |
| 4.4 | Account-Erstellung (Playwright) | DONE | Bot kann via Browser Accounts erstellen und Content posten. |

**Fortschritt Marketing Bot: 100%**

---

## 5. Infrastruktur

| # | Feature | Status | Kommentar |
|---|---------|--------|-----------|
| 5.1 | Windows VPS (ip-projects.de) | DONE | Server 2022, 8 Threads, 16 GB DDR5 RAM, 120 GB NVMe, PM2, Bun, Python 3.11. |
| 5.2 | PM2 Process Management | DONE | 4 Services: claude-relay, moltr-marketing, moltr-security, openclaw-gateway. Autorestart. |
| 5.3 | GitHub (moltrHQ) | DONE | Repos: moltr, openclaw. PAT im Credential Manager. |
| 5.4 | Supabase (Datenbank) | DONE | Messages, Facts, Goals, Capabilities, Skills. |
| 5.5 | Linux Server (Debian 12) | DONE | Docker-ready, Node 22, 2GB Swap. Fuer zukuenftiges Deployment. |
| 5.6 | Docker Deployment | PLAN | Moltr Security als Container. Bot-Container geplant. |
| 5.7 | WSL2/Nested Virtualization | BLOCKIERT | IONOS supportet kein Nested Virt. Workaround: Linux Server nutzen. |
| 5.8 | Konsolidierte Ordnerstruktur | DONE | Alles unter Desktop/MoltrHQ Codebase. clawguard eliminiert. |

---

## 6. Geplante Features (Roadmap)

| # | Feature | Status | Kommentar |
|---|---------|--------|-----------|
| 6.1 | TalonHub Backend (Server) | PLAN | REST-API zum Hochladen, Signieren, Verteilen von Skills. Revenue-Sharing Backend. |
| 6.2 | Echtzeit Voice Streaming | PLAN | Agent antwortet waehrend er noch denkt. Unterbrechbar. |
| 6.3 | Telefon-Integration (Twilio/SIP) | IDEA | Duplex-Gespraeche, Emotionserkennung. |
| 6.4 | Google/Gemini Provider | PLAN | Vierter Provider-Adapter. |
| 6.5 | WhatsApp Channel | IDEA | Zweiter Messaging-Channel neben Telegram. |
| 6.6 | Moltr Security Dashboard | PLAN | React SPA + WebSocket. 5 Views: Overview, Live Events, Audit, KillSwitch, Integrity. Architecture designed. |
| 6.7 | EU-Marke "Moltr" | PLAN | ~850 EUR, KMU-Foerderung moeglich (~213 EUR). |
| 6.8 | Blockchain Token | IDEA | Eigener Utility-Token fuer TalonHub + Community-Support. |
| 6.9 | Tool Execution in Talon | IMPL | bash, read_file, write_file implementiert. Moltr Security Pre-Check + Output-Scan. Max 10 Iterationen. Capability-Tier-gated. |
| 6.10 | Lokale Netzwerk-Erkennung (mDNS) | IDEA | Talon bewirbt sich im LAN via mDNS (Bonjour/RFC 6762) als `talon-[hostname].local`. Andere Geraete finden ihn automatisch ohne IP-Eingabe. Dashboard-Toggle: standardmaessig AUS, opt-in. Windows-safe: windowsHide:true fuer alle child_process-Calls. Inspiriert durch OpenClaw/@homebridge/ciao — aber sauber implementiert. |

---

## 7. MIM — Moltr Interop Manifest Standard

> **Idee:** Wir setzen den offenen Standard gegen Security-Tool-Konflikte. Kein proprietaerer Lock-in — CC0, jeder kann ihn implementieren. Moltr ist der Declarant, alle anderen Tools koennen Consumers werden.

**Spec-Dokument:** `docs/mim-spec.md`

| # | Feature | Status | Kommentar |
|---|---------|--------|-----------|
| 7.1 | MIM Spec v1.0 | DONE | Vollstaendige Spezifikation. CC0 lizenziert. Discovery via `/.well-known/moltr-manifest.json`. |
| 7.2 | MIM Endpoint in Moltr | PLAN | `GET /.well-known/moltr-manifest.json` automatisch aus Honeypot-Config generieren. Kein Auth noetig. |
| 7.3 | MIM Consumer-Logik | PLAN | Moltr selbst liest MIM anderer Tools vor Scans. Verhindert gegenseitige False Positives. |
| 7.4 | OpenClaw MIM Plugin | PLAN | Heartbeat-Skill der MIM-Manifest prueft und Findings gemaess Manifest supprimiert. |
| 7.5 | PicoClaw MIM Support | PLAN | PR / Issue im PicoClaw-Repo. Go HTTP-Client + JSON-Parser ist trivial. |
| 7.6 | NanoClaw MIM Support | PLAN | PR / Issue im NanoClaw-Repo. Container-native Discovery. |
| 7.7 | MIM Registry (GitHub) | PLAN | Oeffentliche Liste aller MIM-kompatiblen Tools. Community-driven. |

---

## 8. Compatibility Test Lab

> **Idee:** Reproduzierbarer Beweis dass Moltr + alle gaengigen Agent-Frameworks konfliktfrei koexistieren — mit und ohne MIM. Linux-Server als isolierte Testumgebung.

**Ziel:** Zeigen dass Security-Tool-Konflikte kein Schicksal sind, sondern ein geloestes Problem.
**Server:** IONOS Linux (87.106.41.66), Debian 12, Docker 28.5.2

| # | Test | Status | Kommentar |
|---|------|--------|-----------|
| 8.1 | OpenClaw × Moltr (3 Durchgaenge) | PLAN | Bekannter Konflikt: Honeypot-False-Positive erwartet. Baseline fuer Vergleich. |
| 8.2 | NanoClaw × Moltr (3 Durchgaenge) | PLAN | Container-native → andere Scan-Mechanismen. Konflikt-Verhalten unbekannt. |
| 8.3 | PicoClaw × Moltr (3 Durchgaenge) | PLAN | Go-binary, minimale Deps. Ressourcenarm. Konflikt-Verhalten unbekannt. |
| 8.4 | OpenClaw × Moltr + MIM (3 Durchgaenge) | PLAN | Gleicher Test, diesmal mit MIM-Endpoint. Erwartetes Ergebnis: kein Konflikt. |
| 8.5 | NanoClaw × Moltr + MIM (3 Durchgaenge) | PLAN | MIM via Container-Netzwerk erreichbar. |
| 8.6 | PicoClaw × Moltr + MIM (3 Durchgaenge) | PLAN | MIM via HTTP. PicoClaw muss Discovery implementieren. |
| 8.7 | Test-Runbook | PLAN | Dokumentiertes Verfahren: Setup, Durchfuehrung, Auswertung, Reset. Reproduzierbar. |
| 8.8 | Ergebnis-Report | PLAN | Veroeffentlichung der Testergebnisse. Grundlage fuer MIM-Adoption-Gespraeche. |

**Test-Matrix Uebersicht:**

| Variante | RAM | Sprache | Ohne MIM | Mit MIM |
|----------|-----|---------|----------|---------|
| OpenClaw | ~1GB | Node.js | Bekannter Konflikt | TBD |
| NanoClaw | Container | Python/SDK | TBD | TBD |
| PicoClaw | <10MB | Go | TBD | TBD |

---

## Zusammenfassung fuer Webseite

```
Moltr Security Shield:  ████████████████████ 100%  — Production-ready (v1.0.0)
Talon Agent:            ██████████████░░░░░░  70%  — Multi-Provider + Skills implementiert
Telegram Bot:           ████████████████████ 100%  — Feature-complete
Marketing Bot:          ████████████████████ 100%  — Laeuft
Infrastruktur:          ████████████████░░░░  80%  — Docker + Linux Server offen
MIM Standard:           ████░░░░░░░░░░░░░░░░  20%  — Spec fertig, Endpoint + Tests offen
TalonHub Backend:       ░░░░░░░░░░░░░░░░░░░░   0%  — Geplant
Blockchain/Token:       ░░░░░░░░░░░░░░░░░░░░   0%  — Konzeptidee

Gesamt:                 █████████████░░░░░░░  60%
```

---

*Moltr Security Shield — Made in Vienna*
*AGPL-3.0 | github.com/moltrHQ*
