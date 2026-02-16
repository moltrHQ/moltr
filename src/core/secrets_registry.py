"""Moltr secrets registry.

Tracks known secrets with Fernet encryption.
User registers secrets at setup time; they are encrypted
and stored in a JSON file for later comparison.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from cryptography.fernet import Fernet


class SecretsRegistry:
    """Registry for tracking secrets with Fernet encryption.

    Secrets are encrypted at rest and only decrypted in memory
    when checking text for leaks.
    """

    def __init__(self, storage_path: str = "secrets.json") -> None:
        """Initialize the secrets registry.

        If the storage file exists, loads the existing key and secrets.
        Otherwise creates a new Fernet key and empty store.

        Args:
            storage_path: Path to the encrypted JSON storage file.
        """
        self._storage_path = Path(storage_path)
        self._secrets: dict[str, bytes] = {}  # name -> encrypted value
        self._fernet: Fernet

        if self._storage_path.exists():
            self._load()
        else:
            self._key = Fernet.generate_key()
            self._fernet = Fernet(self._key)

    def add_secret(self, name: str, value: str) -> None:
        """Register a secret. It is encrypted and persisted to disk.

        Args:
            name: Human-readable identifier for the secret.
            value: The raw secret value to protect.
        """
        encrypted = self._fernet.encrypt(value.encode("utf-8"))
        self._secrets[name] = encrypted
        self._save()

    def check_text(self, text: str) -> bool:
        """Check if any registered secret appears in the given text.

        Args:
            text: The text to scan for leaked secrets.

        Returns:
            True if any registered secret is found in the text.
        """
        for encrypted in self._secrets.values():
            decrypted = self._fernet.decrypt(encrypted).decode("utf-8")
            if decrypted in text:
                return True
        return False

    def list_secrets(self) -> list[str]:
        """Return the names of all registered secrets.

        Returns:
            List of secret names (not values).
        """
        return list(self._secrets.keys())

    def _get_decrypted_values(self) -> list[str]:
        """Decrypt and return all secret values (internal use only).

        Returns:
            List of decrypted secret values.
        """
        values = []
        for encrypted in self._secrets.values():
            values.append(self._fernet.decrypt(encrypted).decode("utf-8"))
        return values

    def _save(self) -> None:
        """Persist the encrypted secrets and key to disk."""
        data = {
            "key": self._key.decode("utf-8"),
            "secrets": {
                name: enc.decode("utf-8") for name, enc in self._secrets.items()
            },
        }
        self._storage_path.write_text(json.dumps(data), encoding="utf-8")

    def _load(self) -> None:
        """Load encrypted secrets and key from disk."""
        raw = self._storage_path.read_text(encoding="utf-8")
        data = json.loads(raw)
        self._key = data["key"].encode("utf-8")
        self._fernet = Fernet(self._key)
        self._secrets = {
            name: enc.encode("utf-8") for name, enc in data["secrets"].items()
        }
