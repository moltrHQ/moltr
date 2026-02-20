# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Moltr-Commercial
# Copyright (C) 2026 Walter Troska / moltrHQ <hello@moltr.tech>
# See LICENSE (AGPL-3.0) or LICENSE-COMMERCIAL for licensing terms.

"""Dungeoncore CLI — verschlüsselter Key-Tresor für das Moltr-Ökosystem.

Befehle:
  moltr-dc init          Dungeon einrichten (Setup-Wizard)
  moltr-dc unlock        Dungeon entsperren (Keys in Session laden)
  moltr-dc lock          Dungeon sperren (Session löschen)
  moltr-dc status        Status anzeigen
  moltr-dc add KEY       Key hinzufügen
  moltr-dc get KEY       Key abrufen
  moltr-dc list          Alle Key-Namen auflisten
  moltr-dc remove KEY    Key entfernen
"""

from __future__ import annotations

import argparse
import getpass
import json
import locale as _locale
import os
import sys
from pathlib import Path

# Sicherstellen dass src/ im Pfad ist
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.dungeoncore.config import (
    CONFIG_FILE,
    MOLTR_DIR,
    create_config,
    get_config,
    get_dungeon_name,
    get_dungeon_path,
    update_last_unlock,
)
from src.dungeoncore.crypto import decrypt, encrypt
from src.dungeoncore.store import (
    DEFAULT_DURATION_HOURS,
    clear_session,
    read_session,
    session_status,
    write_session,
)

# ─── Farben (einfach, ohne externe Abhängigkeit) ───────────────────────────

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def _ok(msg: str) -> None:
    print(f"{GREEN}[OK]{RESET} {msg}")


def _warn(msg: str) -> None:
    print(f"{YELLOW}[!]{RESET} {msg}")


def _err(msg: str) -> None:
    print(f"{RED}[ERR]{RESET} {msg}", file=sys.stderr)


def _header(title: str) -> None:
    width = 42
    border = "=" * width
    print(f"\n{CYAN}+{border}+")
    print(f"| {BOLD}{title.center(width - 2)}{RESET}{CYAN} |")
    print(f"+{border}+{RESET}\n")


# ─── Spracherkennung & Übersetzungen ─────────────────────────────────────

def _detect_lang() -> str:
    """Erkennt Systemsprache. Gibt 'de' oder 'en' zurück."""
    # 1) Python locale
    try:
        lang_code = _locale.getlocale()[0] or ""
        if lang_code.lower().startswith("de"):
            return "de"
    except Exception:
        pass
    # 2) Umgebungsvariablen
    for env_var in ("LANG", "LANGUAGE", "LC_ALL", "LC_MESSAGES"):
        val = os.environ.get(env_var, "")
        if val.lower().startswith("de"):
            return "de"
    # 3) Windows-Registry (winreg ist auf Windows immer verfügbar)
    try:
        import winreg  # type: ignore
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Control Panel\International")
        lang_val, _ = winreg.QueryValueEx(key, "LocaleName")
        if str(lang_val).lower().startswith("de"):
            return "de"
        winreg.CloseKey(key)
    except Exception:
        pass
    return "en"


LANG = _detect_lang()

_STRINGS: dict = {
    "de": {
        "setup_title":    "MOLTR DUNGEONCORE SETUP",
        "welcome":        "Willkommen! Hier richtest du deinen verschluesselten Key-Tresor ein.\n",
        "name_flavor":    (
            f"  {CYAN}Der Dungeoncore behuetet deine wertvollen Schaetze -- deine Keys.{RESET}\n"
            f"  Soll er 'Dungeoncore' heissen, oder willst du ihm einen anderen Namen geben?\n"
        ),
        "name_prompt":    "  Name [{{default}}]: ",
        "pass_intro":     "  Passphrase (mind. 12 Zeichen):",
        "pass_short":     "Passphrase zu kurz (mind. 12 Zeichen). Bitte nochmal.",
        "pass_mismatch":  "Passphrasen stimmen nicht ueberein. Nochmal.",
        "pass_confirm":   "  Passphrase bestaetigen: ",
        "pass_prompt":    "  Passphrase: ",
        "auto_scan":      "  Soll ich deine .env Dateien automatisch scannen? [J/n]: ",
        "creating":       "  Erstelle Dungeoncore...",
        "done":           "Dungeoncore '{{name}}' bereit!",
        "offline_warn1":  "WICHTIG: Notiere deine Passphrase offline!",
        "offline_warn2":  "         Ohne sie sind alle Keys unwiederbringlich verloren.",
        "scan_files":     "Scanne .env Dateien...",
        "no_env":         "Keine .env Dateien gefunden.",
        "keys_found":     "{{n}} kritische Keys gefunden.",
        "select_hint":    "  Welche importieren?",
        "select_opts":    "  [Enter] = Alle  |  [1,3,5] = Auswahl  |  [n] = Keine (manuell)",
        "extra_keys":     "  Noch weitere Keys manuell hinzufuegen? (leer = nein)",
        "manual_format":  "  Format: KEY_NAME=wert  |  Leerzeile = fertig",
        "already_exists": "Dungeoncore '{{name}}' existiert bereits.",
        "use_force":      "Benutze --force um einen neuen zu erstellen (ueberschreibt!).",
        "keys_imported":  "{{key}} importiert",
        "invalid_input":  "Ungueltige Eingabe -- alle Keys importiert.",
        "invalid_format": "Format: KEY_NAME=wert -- uebersprungen.",
        "key_saved":      "{{key}} gespeichert",
    },
    "en": {
        "setup_title":    "MOLTR DUNGEONCORE SETUP",
        "welcome":        "Welcome! Let's set up your encrypted key vault.\n",
        "name_flavor":    (
            f"  {CYAN}The Dungeoncore guards your precious treasures -- your keys.{RESET}\n"
            f"  Shall it be called 'Dungeoncore', or do you want to give it another name?\n"
        ),
        "name_prompt":    "  Name [{{default}}]: ",
        "pass_intro":     "  Passphrase (min. 12 characters):",
        "pass_short":     "Passphrase too short (min. 12 chars). Please try again.",
        "pass_mismatch":  "Passphrases don't match. Try again.",
        "pass_confirm":   "  Confirm passphrase: ",
        "pass_prompt":    "  Passphrase: ",
        "auto_scan":      "  Should I auto-scan your .env files? [Y/n]: ",
        "creating":       "  Creating Dungeoncore...",
        "done":           "Dungeoncore '{{name}}' ready!",
        "offline_warn1":  "IMPORTANT: Write down your passphrase offline!",
        "offline_warn2":  "           Without it, all your keys are lost forever.",
        "scan_files":     "Scanning .env files...",
        "no_env":         "No .env files found.",
        "keys_found":     "{{n}} critical keys found.",
        "select_hint":    "  Which keys to import?",
        "select_opts":    "  [Enter] = All  |  [1,3,5] = Select  |  [n] = None (manual)",
        "extra_keys":     "  Add more keys manually? (empty = done)",
        "manual_format":  "  Format: KEY_NAME=value  |  empty line = done",
        "already_exists": "Dungeoncore '{{name}}' already exists.",
        "use_force":      "Use --force to create a new one (overwrites!).",
        "keys_imported":  "{{key}} imported",
        "invalid_input":  "Invalid input -- imported all keys.",
        "invalid_format": "Format: KEY_NAME=value -- skipped.",
        "key_saved":      "{{key}} saved",
    },
}


def _t(sid: str, **kwargs) -> str:
    """Gibt den übersetzten String zurück."""
    s = _STRINGS.get(LANG, _STRINGS["en"]).get(sid, _STRINGS["en"].get(sid, f"[{sid}]"))
    # Doppel-Klammern für Felder die erst bei Aufruf befüllt werden
    s = s.replace("{{", "{").replace("}}", "}")
    if kwargs:
        s = s.format(**kwargs)
    return s


# ─── Hilfsfunktionen ──────────────────────────────────────────────────────

def _load_dungeon(passphrase: str) -> dict:
    """Lädt und entschlüsselt den Dungeon. Gibt Keys zurück."""
    path = get_dungeon_path()
    if not path or not path.exists():
        _err("Kein Dungeoncore gefunden. Führe zuerst 'moltr-dc init' aus.")
        sys.exit(1)
    with open(path, "rb") as f:
        raw = f.read()
    return decrypt(raw, passphrase)


def _save_dungeon(keys: dict, passphrase: str) -> None:
    """Verschlüsselt Keys und speichert den Dungeon."""
    path = get_dungeon_path()
    if not path:
        _err("Kein Dungeoncore konfiguriert.")
        sys.exit(1)
    path.parent.mkdir(parents=True, exist_ok=True)
    encrypted = encrypt(keys, passphrase)
    with open(path, "wb") as f:
        f.write(encrypted)
    try:
        path.chmod(0o600)
    except NotImplementedError:
        pass


def _ask_passphrase(confirm: bool = False) -> str:
    """Fragt die Passphrase ab (mit optionaler Bestätigung).

    Fällt auf input() zurück wenn stdin kein Terminal ist (z.B. Tests).
    """
    _getpass = getpass.getpass if sys.stdin.isatty() else input
    while True:
        passphrase = _getpass(_t("pass_prompt"))
        if len(passphrase) < 12:
            _warn(_t("pass_short"))
            continue
        if confirm:
            passphrase2 = _getpass(_t("pass_confirm"))
            if passphrase != passphrase2:
                _err(_t("pass_mismatch"))
                continue
        return passphrase


# ─── Auto-Import & Manual Input ───────────────────────────────────────────

# Keys die eindeutig kritisch sind (Namen die immer importiert werden sollen)
_CRITICAL_PATTERNS = (
    "API_KEY", "API_SECRET", "BOT_TOKEN", "SECRET_KEY",
    "PASS", "PASSWORD", "PRIVATE_KEY", "FERNET_KEY",
    "HMAC_KEY", "JWT_SECRET", "ANON_KEY", "RELAY_KEY",
)

# Keys die zwar das Muster matchen aber NICHT kritisch sind
_NOT_CRITICAL = {
    "TELEGRAM_USER_ID", "TELEGRAM_CHAT_ID", "SUPABASE_URL",
    "BOT_BRIDGE_SUPABASE_URL", "RELAY_URL", "MOLTR_RELAY_URL",
    "TALONHUB_PUBLIC_KEY",  # public key = kein Secret
}

def _is_critical(key: str) -> bool:
    if key in _NOT_CRITICAL:
        return False
    return any(p in key for p in _CRITICAL_PATTERNS)


def _scan_env_files() -> dict[str, dict[str, str]]:
    """Scannt bekannte .env Dateien und gibt gefundene kritische Keys zurück.

    Returns: { "Label": { "KEY_NAME": "value", ... } }
    """
    base = Path("C:/Users/Administrator/Desktop/MoltrHQ Codebase")
    candidates = [
        (base / "claude-telegram-bot" / ".env",  "Kai (@moltr_assistant_bot)"),
        (base / "talon-agent" / ".env",           "Talon (@Talon_Terminal_Bot)"),
        (base / "moltr-security" / ".env",        "Moltr Security"),
        (base / "talon-trader" / ".env",           "Talon Trader"),
        (base / "moltr-backup" / ".env",           "Backup"),
        (base / "moltr-marketing-bot" / ".env",    "Marketing Bot"),
    ]
    result: dict[str, dict[str, str]] = {}
    for path, label in candidates:
        if not path.exists():
            continue
        found: dict[str, str] = {}
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                if _is_critical(key) and value.strip():
                    found[key] = value.strip()
        if found:
            result[label] = found
    return result


def _auto_import_keys() -> dict[str, str]:
    """Scannt .env Dateien, zeigt kritische Keys zur Auswahl, importiert gewaehlte."""
    print(f"\n  {CYAN}{_t('scan_files')}{RESET}\n")
    all_envs = _scan_env_files()

    if not all_envs:
        _warn(_t("no_env"))
        return _manual_key_input()

    # Deduplizieren: gleicher Key aus mehreren Dateien → letzter Wert gewinnt
    numbered: list[tuple[str, str, str]] = []  # (num, key, value)
    seen: dict[str, str] = {}

    for label, keys in all_envs.items():
        print(f"  [{label}]")
        for key, value in keys.items():
            if key not in seen:
                seen[key] = value
                n = len(numbered) + 1
                numbered.append((str(n), key, value))
                preview = value[:8] + "..." if len(value) > 8 else value
                print(f"    {YELLOW}[{n:2}]{RESET} {key} = {preview}")
        print()

    total = len(numbered)
    print(f"  {_t('keys_found', n=total)}\n")
    print(_t("select_hint"))
    opts = _t("select_opts")
    opts = opts.replace("[Enter]", f"{YELLOW}[Enter]{RESET}")
    opts = opts.replace("[1,3,5]", f"{YELLOW}[1,3,5]{RESET}")
    opts = opts.replace("[n]", f"{YELLOW}[n]{RESET}")
    print(opts + "\n")

    choice = input("  > ").strip().lower()

    if choice in ("n", "none", "keine", "nein"):
        return _manual_key_input()

    if choice in ("", "alle", "all", "a", "y", "yes", "j", "ja"):
        selected = {k: v for _, k, v in numbered}
    else:
        try:
            indices = {int(x.strip()) for x in choice.replace(",", " ").split() if x.strip()}
        except ValueError:
            _warn(_t("invalid_input"))
            indices = set(range(1, total + 1))
        selected = {k: v for n, k, v in numbered if int(n) in indices}

    print()
    for key in selected:
        _ok(_t("keys_imported", key=key))

    # Nachtraegliche manuelle Ergaenzung
    print(f"\n{_t('extra_keys')}\n")
    extra = _manual_key_input()
    selected.update(extra)

    return selected


def _manual_key_input() -> dict[str, str]:
    """Interaktive manuelle Key-Eingabe."""
    keys: dict[str, str] = {}
    print(f"{_t('manual_format')}\n")
    while True:
        entry = input("  > ").strip()
        if not entry:
            break
        if "=" not in entry:
            _warn(_t("invalid_format"))
            continue
        key_name, _, value = entry.partition("=")
        key_name = key_name.strip().upper()
        value = value.strip()
        if not key_name:
            continue
        keys[key_name] = value
        _ok(_t("key_saved", key=key_name))
    return keys


# ─── Befehle ──────────────────────────────────────────────────────────────

def cmd_init(args: argparse.Namespace) -> None:
    """Setup-Wizard: Dungeon erstellen."""
    _header(_t("setup_title"))

    # Prüfen ob bereits vorhanden
    if get_config() and not args.force:
        name = get_dungeon_name()
        _warn(_t("already_exists", name=name))
        _warn(_t("use_force"))
        sys.exit(1)

    print(_t("welcome"))

    # Nerdiger Naming-Prompt
    default_name = "Dungeoncore"
    print(_t("name_flavor"))
    name_prompt = _t("name_prompt", default=default_name)
    name_input = input(name_prompt).strip()
    name = name_input if name_input else default_name

    # Sonderzeichen prüfen
    if not all(c.isalnum() or c in "-_" for c in name):
        _err("Only letters, digits, - and _ allowed." if LANG == "en" else "Nur Buchstaben, Zahlen, - und _ erlaubt.")
        sys.exit(1)
    if len(name) > 32:
        _err("Name too long (max. 32 chars)." if LANG == "en" else "Name zu lang (max. 32 Zeichen).")
        sys.exit(1)

    dungeon_path = MOLTR_DIR / f"{name}.gpg"
    print()

    # Passphrase setzen
    print(_t("pass_intro"))
    passphrase = _ask_passphrase(confirm=True)
    print()

    # Keys: Auto-Import anbieten
    keys: dict[str, str] = {}
    auto = input(_t("auto_scan")).strip().lower()
    if auto in ("", "j", "ja", "y", "yes"):
        keys = _auto_import_keys()
    else:
        print(f"\n  {CYAN}{'Keys manually' if LANG == 'en' else 'Keys manuell eingeben'}{RESET}\n")
        keys = _manual_key_input()

    # Datei schreiben
    print()
    print(_t("creating"))
    MOLTR_DIR.mkdir(exist_ok=True)
    encrypted = encrypt(keys, passphrase)
    with open(dungeon_path, "wb") as f:
        f.write(encrypted)
    try:
        dungeon_path.chmod(0o600)
    except NotImplementedError:
        pass

    # Config schreiben
    create_config(name, dungeon_path)

    print()
    _ok(_t("done", name=name))
    print(f"   {'File' if LANG == 'en' else 'Datei'}:   {dungeon_path}")
    print(f"   Config: {CONFIG_FILE}")
    print(f"   Keys:   {len(keys)} {'stored' if LANG == 'en' else 'gespeichert'}")
    print()
    _warn(_t("offline_warn1"))
    _warn(_t("offline_warn2"))
    print()


def cmd_unlock(args: argparse.Namespace) -> None:
    """Dungeon entsperren — Keys in Session laden."""
    name = get_dungeon_name()
    print(f"\n  {CYAN}Dungeoncore '{name}' entsperren{RESET}\n")

    # Passphrase aus Umgebungsvariable (für nicht-interaktiven Aufruf z.B. via Telegram)
    passphrase = os.environ.get("DUNGEONCORE_PASSPHRASE", "")
    if not passphrase:
        _getpass = getpass.getpass if sys.stdin.isatty() else input
        passphrase = _getpass("  Passphrase: ")
    print()

    try:
        keys = _load_dungeon(passphrase)
    except ValueError as e:
        _err(str(e))
        sys.exit(1)

    duration = getattr(args, "duration", DEFAULT_DURATION_HOURS)
    write_session(keys, duration_hours=duration)
    update_last_unlock()

    _ok(f"Dungeoncore entsperrt — {len(keys)} Keys geladen")
    _ok(f"Session läuft ab in {duration}h")
    print(f"\n   {YELLOW}Agenten können jetzt Keys via ~/.moltr/session.json lesen{RESET}")
    print(f"   {YELLOW}oder via GET http://localhost:8420/dungeoncore/keys (Phase 2){RESET}\n")


def cmd_lock(_args: argparse.Namespace) -> None:
    """Dungeon sperren — Session löschen."""
    if clear_session():
        _ok("Dungeoncore gesperrt — Session gelöscht")
    else:
        _warn("Kein aktiver Dungeoncore gefunden.")


def cmd_status(_args: argparse.Namespace) -> None:
    """Status anzeigen."""
    _header("DUNGEONCORE STATUS")

    config = get_config()
    if not config:
        _warn("Kein Dungeoncore eingerichtet. Starte mit 'moltr-dc init'.")
        return

    name = config.get("dungeoncore_name", "?")
    path = Path(config.get("dungeoncore_path", ""))
    last_unlock = config.get("last_unlock") or "nie"

    print(f"  Name:          {BOLD}{name}{RESET}")
    print(f"  Datei:         {path}")
    exists_str = "JA" if path.exists() else "NEIN (FEHLT!)"
    print(f"  Existiert:     {exists_str}")
    print(f"  Letzter Unlock: {last_unlock}")
    print()

    status = session_status()
    if status["unlocked"]:
        print(f"  Session:       {GREEN}ENTSPERRT{RESET}")
        print(f"  Keys geladen:  {status['key_count']}")
        print(f"  Laeuft ab:     {status['expires_at']}")
        print(f"  Verbleibend:   {status['remaining']}")
    else:
        print(f"  Session:       {RED}GESPERRT{RESET}")
    print()


def cmd_add(args: argparse.Namespace) -> None:
    """Key hinzufügen oder aktualisieren."""
    _getpass = getpass.getpass if sys.stdin.isatty() else input
    passphrase = _getpass("  Passphrase: ")
    try:
        keys = _load_dungeon(passphrase)
    except ValueError as e:
        _err(str(e))
        sys.exit(1)

    key_name = args.key.upper()
    if args.value:
        value = args.value
    else:
        _gp = getpass.getpass if sys.stdin.isatty() else input
        value = _gp(f"  Wert fuer {key_name}: ")

    action = "aktualisiert" if key_name in keys else "hinzugefügt"
    keys[key_name] = value
    _save_dungeon(keys, passphrase)
    _ok(f"'{key_name}' {action}")

    # Session aktualisieren falls aktiv
    if session_status()["unlocked"]:
        session_keys = read_session() or {}
        session_keys[key_name] = value
        status = session_status()
        write_session(session_keys, duration_hours=status.get("duration_hours", DEFAULT_DURATION_HOURS))
        _ok("Session aktualisiert")


def cmd_get(args: argparse.Namespace) -> None:
    """Key abrufen — erst aus Session, sonst nach Passphrase fragen."""
    key_name = args.key.upper()

    # Aus Session lesen (kein Passwort nötig wenn entsperrt)
    session_keys = read_session()
    if session_keys is not None:
        if key_name in session_keys:
            print(session_keys[key_name])
            return
        _warn(f"'{key_name}' nicht im Dungeoncore.")
        sys.exit(1)

    # Session gesperrt — Passphrase nötig
    _getpass = getpass.getpass if sys.stdin.isatty() else input
    passphrase = _getpass("  Passphrase: ")
    try:
        keys = _load_dungeon(passphrase)
    except ValueError as e:
        _err(str(e))
        sys.exit(1)

    if key_name not in keys:
        _warn(f"'{key_name}' nicht im Dungeoncore.")
        sys.exit(1)
    print(keys[key_name])


def cmd_list(args: argparse.Namespace) -> None:
    """Alle Key-Namen auflisten (keine Werte)."""
    # Aus Session wenn verfügbar
    session_keys = read_session()
    if session_keys is not None:
        keys = session_keys
        source = "Session (entsperrt)"
    else:
        _getpass = getpass.getpass if sys.stdin.isatty() else input
        passphrase = _getpass("  Passphrase: ")
        try:
            keys = _load_dungeon(passphrase)
        except ValueError as e:
            _err(str(e))
            sys.exit(1)
        source = "Dungeoncore (Passphrase)"

    name = get_dungeon_name()
    print(f"\n  {CYAN}Keys in '{name}'{RESET} [{source}]:\n")
    if not keys:
        _warn("Keine Keys gespeichert.")
    else:
        for k in sorted(keys.keys()):
            print(f"  - {k}")
    print()


def cmd_remove(args: argparse.Namespace) -> None:
    """Key entfernen."""
    _getpass = getpass.getpass if sys.stdin.isatty() else input
    passphrase = _getpass("  Passphrase: ")
    try:
        keys = _load_dungeon(passphrase)
    except ValueError as e:
        _err(str(e))
        sys.exit(1)

    key_name = args.key.upper()
    if key_name not in keys:
        _warn(f"'{key_name}' nicht gefunden.")
        sys.exit(1)

    confirm = input(f"  '{key_name}' wirklich löschen? [j/N]: ").strip().lower()
    if confirm != "j":
        print("  Abgebrochen.")
        return

    del keys[key_name]
    _save_dungeon(keys, passphrase)
    _ok(f"'{key_name}' entfernt")

    # Session aktualisieren
    if session_status()["unlocked"]:
        session_keys = read_session() or {}
        session_keys.pop(key_name, None)
        status = session_status()
        write_session(session_keys, duration_hours=status.get("duration_hours", DEFAULT_DURATION_HOURS))


# ─── CLI Entry Point ──────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="moltr-dc",
        description="Dungeoncore — verschlüsselter Key-Tresor",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # init
    p_init = sub.add_parser("init", help="Dungeoncore einrichten")
    p_init.add_argument("--force", action="store_true", help="Bestehenden Dungeon überschreiben")

    # unlock
    p_unlock = sub.add_parser("unlock", help="Dungeoncore entsperren")
    p_unlock.add_argument(
        "--duration", type=int, default=DEFAULT_DURATION_HOURS,
        metavar="STUNDEN", help=f"Session-Dauer in Stunden (default: {DEFAULT_DURATION_HOURS})"
    )

    # lock
    sub.add_parser("lock", help="Dungeoncore sperren")

    # status
    sub.add_parser("status", help="Status anzeigen")

    # add
    p_add = sub.add_parser("add", help="Key hinzufügen")
    p_add.add_argument("key", help="Key-Name (z.B. ANTHROPIC_API_KEY)")
    p_add.add_argument("value", nargs="?", help="Wert (wird sonst interaktiv abgefragt)")

    # get
    p_get = sub.add_parser("get", help="Key abrufen")
    p_get.add_argument("key", help="Key-Name")

    # list
    sub.add_parser("list", help="Alle Key-Namen auflisten")

    # remove
    p_remove = sub.add_parser("remove", help="Key entfernen")
    p_remove.add_argument("key", help="Key-Name")

    args = parser.parse_args()

    commands = {
        "init": cmd_init,
        "unlock": cmd_unlock,
        "lock": cmd_lock,
        "status": cmd_status,
        "add": cmd_add,
        "get": cmd_get,
        "list": cmd_list,
        "remove": cmd_remove,
    }
    commands[args.command](args)


if __name__ == "__main__":
    main()
