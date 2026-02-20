"""Dungeoncore Key-Inventory.

Liest alle .env Dateien im Ökosystem und zeigt welche Keys
kritisch sind und in den Dungeoncore gehören.

Aufruf: python dc-inventory.py
"""

import os
from pathlib import Path

BASE = Path("C:/Users/Administrator/Desktop/MoltrHQ Codebase")

ENV_FILES = [
    (BASE / "claude-telegram-bot" / ".env",    "Kai (@moltr_assistant_bot)"),
    (BASE / "talon-agent" / ".env",             "Talon (@Talon_Terminal_Bot)"),
    (BASE / "moltr-marketing-bot" / ".env",     "Moltr Marketing Bot"),
    (BASE / "moltr-security" / ".env",          "Moltr Security Shield"),
    (BASE / "talon-trader" / ".env",            "Talon Trader"),
    (BASE / "moltr-backup" / ".env",            "Backup System"),
]

CRITICAL_KEYS = {
    "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GROQ_API_KEY", "MINIMAX_API_KEY",
    "TELEGRAM_BOT_TOKEN", "SUPABASE_ANON_KEY", "SUPABASE_KEY",
    "MOLTR_API_KEY", "ADA_RELAY_KEY", "TALON_RELAY_KEY",
    "BYBIT_API_KEY", "BYBIT_API_SECRET",
    "TALONHUB_PRIVATE_KEY", "JWT_SECRET_KEY",
}

NOT_CRITICAL = {
    "PORT", "HOST", "LOG_LEVEL", "WORKSPACE_PATH", "PROJECT_DIR", "RELAY_DIR",
    "TELEGRAM_CHAT_ID", "TELEGRAM_USER_ID", "USER_NAME", "USER_TIMEZONE",
    "MEMORY_MESSAGES", "TALON_ENABLED", "VOICE_PROVIDER", "BACKUP_ROOT",
    "MOLTR_RELAY_URL", "RELAY_URL", "SUPABASE_URL", "BOT_BRIDGE_SUPABASE_URL",
    "ADA_RELAY_BOT_ID", "TALON_RELAY_BOT_ID",
    "EXA_API_KEY", "IONOS_EMAIL_USER",  # semi-critical, consider adding
}

print("\n" + "=" * 60)
print("  DUNGEONCORE KEY-INVENTORY")
print("=" * 60)

all_critical: dict[str, list[str]] = {}  # key → list of sources

for env_file, label in ENV_FILES:
    if not env_file.exists():
        print(f"\n  [{label}] — nicht gefunden: {env_file}")
        continue

    print(f"\n  [{label}]")
    with open(env_file, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            is_critical = key in CRITICAL_KEYS or (
                any(k in key for k in ["KEY", "SECRET", "TOKEN", "PASS", "PASSWORD"])
                and key not in NOT_CRITICAL
            )
            marker = "  [KRITISCH]" if is_critical else "          "
            preview = value[:6] + "..." if len(value) > 6 else value
            print(f"    {marker} {key} = {preview}")

            if is_critical:
                all_critical.setdefault(key, []).append(label)

print("\n" + "=" * 60)
print("  ZUSAMMENFASSUNG: Keys fuer den Dungeoncore")
print("=" * 60)
print(f"\n  {len(all_critical)} kritische Keys gefunden:\n")
for key in sorted(all_critical.keys()):
    sources = ", ".join(all_critical[key])
    print(f"  - {key}")
    print(f"      Verwendet in: {sources}")

print(f"""
NAECHSTE SCHRITTE:
  1. python dungeoncore.py init
  2. Name eingeben (Enter fuer Default 'Dungeoncore')
  3. Passphrase waehlen (offline aufschreiben!)
  4. Keys oben eingeben: KEY_NAME=wert

Danach:
  - Sende /dc-status an @Talon_Terminal_Bot zum Pruefen
  - Sende /unlock fuer naechste Sessions
""")
