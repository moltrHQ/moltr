# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Moltr-Commercial
# Copyright (C) 2026 Walter Troska / moltrHQ <hello@moltr.tech>
# See LICENSE (AGPL-3.0) or LICENSE-COMMERCIAL for licensing terms.

"""Config-Management für Dungeoncore (~/.moltr/config.json)."""

from __future__ import annotations

import json
import stat
from datetime import datetime, timezone
from pathlib import Path

MOLTR_DIR = Path.home() / ".moltr"
CONFIG_FILE = MOLTR_DIR / "config.json"
SESSION_FILE = MOLTR_DIR / "session.json"


def ensure_moltr_dir() -> None:
    """Erstellt ~/.moltr mit restriktiven Berechtigungen."""
    MOLTR_DIR.mkdir(exist_ok=True)
    try:
        MOLTR_DIR.chmod(0o700)
    except NotImplementedError:
        pass  # Windows ignoriert chmod gracefully


def get_config() -> dict | None:
    if not CONFIG_FILE.exists():
        return None
    with open(CONFIG_FILE, encoding="utf-8") as f:
        return json.load(f)


def save_config(config: dict) -> None:
    ensure_moltr_dir()
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    try:
        CONFIG_FILE.chmod(0o600)
    except NotImplementedError:
        pass


def create_config(name: str, path: Path) -> dict:
    config = {
        "dungeoncore_name": name,
        "dungeoncore_path": str(path),
        "created": datetime.now(timezone.utc).isoformat(),
        "last_unlock": None,
    }
    save_config(config)
    return config


def get_dungeon_path() -> Path | None:
    config = get_config()
    if not config:
        return None
    return Path(config["dungeoncore_path"])


def get_dungeon_name() -> str:
    config = get_config()
    if not config:
        return "Dungeoncore"
    return config.get("dungeoncore_name", "Dungeoncore")


def update_last_unlock() -> None:
    config = get_config()
    if config:
        config["last_unlock"] = datetime.now(timezone.utc).isoformat()
        save_config(config)
