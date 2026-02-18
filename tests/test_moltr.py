"""Tests for the Moltr entry point / orchestrator.

Tests initialization, central API methods, status reporting,
and emergency stop.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from src.moltr import Moltr


# Helper: synthetic test strings that match pattern formats
def _make_openai_style_key() -> str:
    return "sk-" + "a1b2c3d4e5f6g7h8i9j0" * 2


@pytest.fixture
def moltr(tmp_path):
    """Provide a Moltr instance with temp storage."""
    return Moltr(
        config_path=Path("config/default.yaml"),
        secrets_storage=str(tmp_path / "secrets.json"),
        project_root=tmp_path,
    )


# -------------------------------------------------------------------------
# Initialization
# -------------------------------------------------------------------------
class TestInitialization:
    """Tests for Moltr startup and module initialization."""

    def test_moltr_initializes(self, moltr: Moltr) -> None:
        """Moltr should initialize without errors."""
        assert moltr is not None

    def test_all_modules_present(self, moltr: Moltr) -> None:
        """All sub-modules should be accessible after init."""
        status = moltr.get_status()
        assert "output_scanner" in status
        assert "action_validator" in status
        assert "network_firewall" in status
        assert "filesystem_guard" in status
        assert "killswitch" in status


# -------------------------------------------------------------------------
# scan_output
# -------------------------------------------------------------------------
class TestScanOutput:
    """Tests for the scan_output central API."""

    def test_clean_text_passes(self, moltr: Moltr) -> None:
        """Normal text should not be blocked."""
        result = moltr.scan_output("Hello, everything is fine.")
        assert result.blocked is False

    def test_dangerous_text_blocked(self, moltr: Moltr) -> None:
        """Text with API key patterns should be blocked."""
        result = moltr.scan_output(f"Key: {_make_openai_style_key()}")
        assert result.blocked is True

    def test_private_key_header_blocked(self, moltr: Moltr) -> None:
        """Text with private key headers should be blocked."""
        result = moltr.scan_output("-----BEGIN RSA PRIVATE KEY-----\ndata\n-----END RSA PRIVATE KEY-----")
        assert result.blocked is True


# -------------------------------------------------------------------------
# validate_command
# -------------------------------------------------------------------------
class TestValidateCommand:
    """Tests for the validate_command central API."""

    def test_allowed_command(self, moltr: Moltr) -> None:
        """Allowed commands should pass."""
        result = moltr.validate_command("ls -la")
        assert result.allowed is True

    def test_sudo_blocked(self, moltr: Moltr) -> None:
        """sudo should be blocked."""
        result = moltr.validate_command("sudo rm -rf /")
        assert result.allowed is False

    def test_blocked_command(self, moltr: Moltr) -> None:
        """Dangerous commands should be blocked."""
        result = moltr.validate_command("kill -9 1")
        assert result.allowed is False


# -------------------------------------------------------------------------
# check_url
# -------------------------------------------------------------------------
class TestCheckURL:
    """Tests for the check_url central API."""

    def test_allowed_domain(self, moltr: Moltr) -> None:
        """Allowed domains should pass."""
        result = moltr.check_url("https://github.com/user/repo")
        assert result.allowed is True

    def test_unknown_domain_blocked(self, moltr: Moltr) -> None:
        """Unknown domains should be blocked."""
        result = moltr.check_url("https://evil-server.com/steal")
        assert result.allowed is False

    def test_private_ip_blocked(self, moltr: Moltr) -> None:
        """Private IPs should be blocked."""
        result = moltr.check_url("http://192.168.1.1/admin")
        assert result.allowed is False


# -------------------------------------------------------------------------
# check_path
# -------------------------------------------------------------------------
class TestCheckPath:
    """Tests for the check_path central API."""

    def test_allowed_path(self, moltr: Moltr, tmp_path) -> None:
        """Paths within allowed directories should pass."""
        f = tmp_path / "src" / "module.py"
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("code")
        result = moltr.check_path(str(f), operation="read")
        assert result.blocked is False

    def test_blocked_path(self, moltr: Moltr, tmp_path) -> None:
        """.env files should be blocked."""
        result = moltr.check_path(str(tmp_path / ".env"), operation="read")
        assert result.blocked is True


# -------------------------------------------------------------------------
# get_status
# -------------------------------------------------------------------------
class TestGetStatus:
    """Tests for the get_status method."""

    def test_status_is_dict(self, moltr: Moltr) -> None:
        """get_status should return a dictionary."""
        status = moltr.get_status()
        assert isinstance(status, dict)

    def test_status_contains_module_states(self, moltr: Moltr) -> None:
        """Status should contain state info for each module."""
        status = moltr.get_status()
        assert "output_scanner" in status
        assert "killswitch" in status
        # Killswitch should report not locked initially
        assert status["killswitch"]["is_locked_down"] is False


# -------------------------------------------------------------------------
# emergency_stop
# -------------------------------------------------------------------------
class TestEmergencyStop:
    """Tests for the emergency_stop method."""

    def test_emergency_stop_activates_lockdown(self, moltr: Moltr) -> None:
        """emergency_stop should trigger LOCKDOWN level."""
        moltr.emergency_stop(reason="Test emergency")
        status = moltr.get_status()
        assert status["killswitch"]["is_locked_down"] is True

    def test_emergency_stop_logged(self, moltr: Moltr) -> None:
        """emergency_stop should be recorded in killswitch log."""
        moltr.emergency_stop(reason="Test emergency")
        log = moltr.get_killswitch_log()
        assert len(log) >= 1
        assert log[-1].reason == "Test emergency"
