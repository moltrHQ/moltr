"""Moltr configuration loader and manager.

Loads YAML configuration files and provides typed access
to all Moltr settings.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional


class MoltrConfig:
    """Central configuration manager for Moltr.

    Loads and validates configuration from YAML files,
    merges defaults with overrides, and provides typed access.
    """

    def __init__(self, config_path: str | Path = "config/default.yaml") -> None:
        """Load configuration from the given YAML file.

        Args:
            config_path: Path to the main configuration YAML.
        """
        pass

    def get(self, key: str, default: Any = None) -> Any:
        """Retrieve a configuration value by dotted key path.

        Args:
            key: Dotted key path (e.g. 'scanners.output.max_length').
            default: Fallback value if key is not found.

        Returns:
            The configuration value or the default.
        """
        pass

    def load_allowlist(self, name: str) -> list[str]:
        """Load a named allowlist from config/allowlists/.

        Args:
            name: Allowlist name (e.g. 'domains', 'commands', 'paths').

        Returns:
            List of allowed entries.
        """
        pass

    def reload(self) -> None:
        """Hot-reload configuration from disk."""
        pass

    def validate(self) -> bool:
        """Validate the current configuration for completeness and consistency.

        Returns:
            True if configuration is valid.

        Raises:
            ValueError: If configuration is invalid.
        """
        pass
