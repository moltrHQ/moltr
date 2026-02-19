"""Moltr configuration loader and manager.

Loads YAML configuration files and provides typed access
to all Moltr settings.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Optional

try:
    import yaml
except ImportError:
    yaml = None

logger = logging.getLogger("moltr.config")


class MoltrConfig:
    """Central configuration manager for Moltr.

    Loads and validates configuration from YAML files,
    merges defaults with overrides, and provides typed access.
    """

    # Required top-level keys in config
    _REQUIRED_KEYS = {"moltr", "scanners", "validators", "killswitch"}

    def __init__(self, config_path: str | Path = "config/default.yaml") -> None:
        """Load configuration from the given YAML file.

        Args:
            config_path: Path to the main configuration YAML.
        """
        self._config_path = Path(config_path)
        self._data: dict[str, Any] = {}
        self._load()

    def _load(self) -> None:
        """Load the YAML config file into _data."""
        if yaml is None:
            logger.warning("PyYAML not installed — config not loaded")
            return
        if not self._config_path.exists():
            logger.warning("Config file not found: %s", self._config_path)
            return
        raw = self._config_path.read_text(encoding="utf-8")
        self._data = yaml.safe_load(raw) or {}

    def get(self, key: str, default: Any = None) -> Any:
        """Retrieve a configuration value by dotted key path.

        Args:
            key: Dotted key path (e.g. 'scanners.output.max_length').
            default: Fallback value if key is not found.

        Returns:
            The configuration value or the default.
        """
        parts = key.split(".")
        current: Any = self._data
        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return default
        return current

    def load_allowlist(self, name: str) -> list[str]:
        """Load a named allowlist from config/allowlists/.

        Args:
            name: Allowlist name (e.g. 'domains', 'commands', 'paths').

        Returns:
            List of allowed entries. Returns empty list if file not found.
        """
        if yaml is None:
            return []
        # Resolve relative to config file's parent directory
        allowlist_dir = self._config_path.parent / "allowlists"
        allowlist_file = allowlist_dir / f"{name}.yaml"
        if not allowlist_file.exists():
            logger.warning("Allowlist not found: %s", allowlist_file)
            return []
        raw = allowlist_file.read_text(encoding="utf-8")
        data = yaml.safe_load(raw) or {}
        # The primary key is typically 'allowed_<name>' or just the entries
        for candidate_key in [f"allowed_{name}", name, "entries"]:
            if candidate_key in data:
                result = data[candidate_key]
                return list(result) if isinstance(result, list) else []
        return []

    def reload(self) -> None:
        """Hot-reload configuration from disk.

        Validates the new config before applying. On validation failure,
        keeps the previous config and logs an error.
        """
        old_data = self._data.copy()
        self._load()
        try:
            self.validate()
            logger.info("Configuration reloaded from %s", self._config_path)
        except ValueError as e:
            logger.error("Config reload failed validation: %s — keeping previous config", e)
            self._data = old_data

    def validate(self) -> bool:
        """Validate the current configuration for completeness and consistency.

        Returns:
            True if configuration is valid.

        Raises:
            ValueError: If configuration is invalid.
        """
        if not self._data:
            raise ValueError("Configuration is empty or not loaded")

        missing = self._REQUIRED_KEYS - set(self._data.keys())
        if missing:
            raise ValueError(f"Missing required config sections: {', '.join(sorted(missing))}")

        # Validate mode
        mode = self.get("moltr.mode", "")
        if mode not in ("enforce", "monitor", "disabled"):
            raise ValueError(f"Invalid mode: {mode!r} (expected enforce/monitor/disabled)")

        # Validate log level
        log_level = self.get("moltr.log_level", "")
        if log_level not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
            raise ValueError(f"Invalid log_level: {log_level!r}")

        return True
