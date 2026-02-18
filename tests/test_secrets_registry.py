"""Tests for the Moltr secrets registry."""

from __future__ import annotations

import json
import os
import tempfile

import pytest

from src.core.secrets_registry import SecretsRegistry


@pytest.fixture
def tmp_storage(tmp_path):
    """Provide a temporary file path for secrets storage."""
    return tmp_path / "secrets.json"


@pytest.fixture
def registry(tmp_storage):
    """Provide a fresh SecretsRegistry with temp storage."""
    return SecretsRegistry(storage_path=str(tmp_storage))


class TestSecretsRegistry:
    """Tests for SecretsRegistry."""

    def test_add_secret(self, registry: SecretsRegistry) -> None:
        """Adding a secret should store it successfully."""
        registry.add_secret("openai_key", "sk-proj-abc123def456")
        names = registry.list_secrets()
        assert "openai_key" in names

    def test_add_multiple_secrets(self, registry: SecretsRegistry) -> None:
        """Multiple secrets should be stored independently."""
        registry.add_secret("aws_key", "AKIAIOSFODNN7EXAMPLE")
        registry.add_secret("github_token", "ghp_abcdef1234567890abcdef1234567890abcd")
        names = registry.list_secrets()
        assert "aws_key" in names
        assert "github_token" in names
        assert len(names) == 2

    def test_check_text_detects_registered_secret(self, registry: SecretsRegistry) -> None:
        """check_text should detect a registered secret in text."""
        registry.add_secret("db_pass", "SuperSecret123!")
        assert registry.check_text("The password is SuperSecret123! don't share") is True

    def test_check_text_no_match(self, registry: SecretsRegistry) -> None:
        """check_text should return False when no secrets match."""
        registry.add_secret("db_pass", "SuperSecret123!")
        assert registry.check_text("This is a completely normal text") is False

    def test_secrets_encrypted_on_disk(self, registry: SecretsRegistry, tmp_storage) -> None:
        """Stored secrets should be encrypted, not plaintext."""
        registry.add_secret("my_key", "plaintext_secret_value")
        raw = tmp_storage.read_text()
        assert "plaintext_secret_value" not in raw

    def test_persistence_across_instances(self, tmp_storage) -> None:
        """Secrets should persist when creating a new registry with same storage."""
        reg1 = SecretsRegistry(storage_path=str(tmp_storage))
        reg1.add_secret("persistent_key", "persist_value_123")

        reg2 = SecretsRegistry(storage_path=str(tmp_storage))
        assert "persistent_key" in reg2.list_secrets()
        assert reg2.check_text("The value is persist_value_123") is True

    def test_list_secrets_returns_names_only(self, registry: SecretsRegistry) -> None:
        """list_secrets should return only names, not values."""
        registry.add_secret("api_key", "sk-secret-value")
        names = registry.list_secrets()
        assert "api_key" in names
        assert "sk-secret-value" not in names

    def test_empty_registry(self, registry: SecretsRegistry) -> None:
        """An empty registry should return empty list and no matches."""
        assert registry.list_secrets() == []
        assert registry.check_text("anything") is False
