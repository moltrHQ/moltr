# PROGRESS.md — Moltr Security Shield

**Letztes Update:** 2026-02-20

---

## Session 2026-02-20 — YAML Kaffeefilter + WebSocket + Dungeoncore

### Was wurde gemacht

1. **YAML Schema-Filter** (src/relay/router.py)
   - `_yaml_schema_check()` auf Relay-Level: nur type ∈ {task,ping,query,response} + non-empty content
   - 422 bei ungültigem Schema, geloggt als "schema_rejected"

2. **WebSocket-Fix für IONOS**
   - `uvicorn[standard]>=0.27.0` (websockets-Bibliothek fehlte)
   - Pure-ASGI-Klassen statt `@app.middleware("http")` (Starlette 0.52 Inkompatibilität)

3. **Dungeoncore implementiert** (src/dungeoncore/)
   - AES-256-GCM Verschlüsselung (PBKDF2, 600k Iterationen)
   - CLI: init, unlock, lock, status, add, get, list, remove
   - FastAPI: GET /dungeoncore/status (public) + /keys (auth)
   - Auto-Import Scanner: 6 .env Dateien, ~18 kritische Keys

4. **Injection Scanner (src/relay/injection_scanner.py)** — vollständige Neufassung:
   - Normalisierungspipeline: Invisible Chars → NFKC → Homoglyphs → Dotted Collapse
   - Stage A: Structural (Base64/Hex/SpacedLetters/ManyShot/TagBlock)
   - Stage B: 24+ Baseline-Patterns (hardcoded, YAML-erweiterbar)
   - Stage C: Base64/Hex/ROT(1-25)/URL Deobfuskation + Re-Scan
   - relay_injection_patterns.yaml: DE/FR/ES/RU + Relay-spezifische Patterns
   - Knowledge Base: docs/prompt-injection-wissensdatenbank.md (1784 Zeilen, 60+ Techniken)

5. **Kritische Bugfixes (2026-02-20 Session 3):**
   - `forget_instructions`: fehlendes `\s*` nach Modifier-Gruppe (MISS behoben)
   - ROT-Deobfuskation: range(1,26) statt [1,3,5,7,18,25] → dekodiert jetzt korrekt
   - `variable_storage_attack`: `in\s+` statt `in(?:\s+a)?` ohne Spacing
   - `structural_tag_block_encoding` zu Stage A (Raw-Text, vor Normalisierung)

---

## Aktueller Stand

### GitHub
- **Remote:** https://github.com/moltrHQ/moltr, Branch: main
- **Letzter Commit:** 4a0c6c2 — fix: variable_storage_attack pattern regex bug

### IONOS Docker
- **Status:** Online ✅ (Port 8420)
- **Letzter Deploy:** 2026-02-20 nach commit 4a0c6c2
- **docker-compose up -d --build** via SSH zu 87.106.41.66

### Injection Scanner
- **48 total patterns** (24 Baseline + ~14 YAML + 5 Structural)
- **Live-Test 10/10** — alle Angriffsvektoren FLAGGED ✅
- **Flag-and-Deliver-Modus:** Standard (Injection geloggt, trotzdem delivered)
- **Hard-Block:** `RELAY_INJECTION_BLOCK=true` in .env (deaktiviert)

---

## Offene TODOs

### Injection Scanner
- [ ] Many-Shot Längen-Check (>10.000 Zeichen als LOW-Signal)
- [ ] LLM Classifier Tier 3 (BYOK — user approved, nicht gebaut)
- [ ] Crescendo Multi-Turn Detection (Session-Level, Regex nicht möglich)
- [ ] Canary Token Awareness (defensiv, System-Prompt Sentinel)

### Relay
- [x] Paid-Tier-Enforcement — `RegisterRequest admin_secret` Gate ✅ (router.py)
      + `POST /relay/admin/set-tier` Endpoint ✅ (router.py)
- [x] `RELAY_ADMIN_SECRET` in .env ✅ + `.env.example` erstellt ✅ (2026-02-20)
- [x] IONOS Deploy — commit 489b53f, `docker compose up -d --build` ✅ (2026-02-20)
- [x] **Credential-Leak-Scanner (Block 4a)** ✅ (2026-02-20 — commit fdb64fa)
      - `_scan_for_credentials()` in router.py (Block-Patterns: 5, Warn-Patterns: 1)
      - Block: openai_api_key, anthropic_api_key, aws_access_key, private_key_header, github_pat
      - Warn: high_entropy_base64 (>=60 Zeichen)
      - `RELAY_CREDENTIAL_SCAN=true` (default, in .env.example dokumentiert)
      - Defense-in-Depth: Credential-Scanner greift wenn _moltr=None (standalone Relay)
      - IONOS deployed + Live-Tests bestätigt

### Dungeoncore
- [ ] Re-Init nötig — TestImport überschrieben echten DC (1 Key, falsch)
      `python dungeoncore.py init --force` → Auto-Import → alle 18 Keys
- [ ] Agenten-Integration Phase 2 (Keys aus session.json — Plan: breezy-giggling-lake.md)
- [ ] Backup/Export — verschlüsselter Export der .gpg Datei

### OpenRelay Landing Page
- [ ] Pricing/Docs/About Sections fehlen
      Datei: moltr-workspace/projekte/relay-landing/index.html (712 Zeilen, Ada-Build)
