"""Tests for the Moltr kill switch manager.

Tests 5 escalation levels, trigger/reset with codephrase,
and event logging.
"""

from __future__ import annotations

import pytest

from src.killswitches.killswitch import KillSwitch, EscalationLevel


@pytest.fixture
def ks():
    """Provide a fresh KillSwitch with a test codephrase."""
    return KillSwitch(reset_codephrase="test-reset-phrase-42")


# -------------------------------------------------------------------------
# Escalation levels
# -------------------------------------------------------------------------
class TestEscalationLevels:
    """Tests for the 5 escalation levels."""

    def test_level_enum_values(self) -> None:
        """All 5 escalation levels should be defined."""
        assert EscalationLevel.PAUSE.value == 1
        assert EscalationLevel.NETWORK_CUT.value == 2
        assert EscalationLevel.LOCKDOWN.value == 3
        assert EscalationLevel.WIPE.value == 4
        assert EscalationLevel.EMERGENCY.value == 5

    def test_levels_are_ordered(self) -> None:
        """Higher levels should have higher numeric values."""
        assert EscalationLevel.PAUSE.value < EscalationLevel.NETWORK_CUT.value
        assert EscalationLevel.NETWORK_CUT.value < EscalationLevel.LOCKDOWN.value
        assert EscalationLevel.LOCKDOWN.value < EscalationLevel.WIPE.value
        assert EscalationLevel.WIPE.value < EscalationLevel.EMERGENCY.value


# -------------------------------------------------------------------------
# Trigger
# -------------------------------------------------------------------------
class TestTrigger:
    """Tests for triggering kill switch levels."""

    def test_trigger_pause(self, ks: KillSwitch) -> None:
        """Triggering PAUSE should set that level active."""
        ks.trigger(EscalationLevel.PAUSE, reason="Test pause")
        status = ks.get_status()
        assert EscalationLevel.PAUSE in status.active_levels

    def test_trigger_network_cut(self, ks: KillSwitch) -> None:
        """Triggering NETWORK_CUT should set that level active."""
        ks.trigger(EscalationLevel.NETWORK_CUT, reason="Suspicious network activity")
        status = ks.get_status()
        assert EscalationLevel.NETWORK_CUT in status.active_levels

    def test_trigger_lockdown(self, ks: KillSwitch) -> None:
        """Triggering LOCKDOWN should set that level active."""
        ks.trigger(EscalationLevel.LOCKDOWN, reason="Honeypot accessed")
        status = ks.get_status()
        assert EscalationLevel.LOCKDOWN in status.active_levels

    def test_trigger_wipe(self, ks: KillSwitch) -> None:
        """Triggering WIPE should set that level active."""
        ks.trigger(EscalationLevel.WIPE, reason="Secret exfiltration detected")
        status = ks.get_status()
        assert EscalationLevel.WIPE in status.active_levels

    def test_trigger_emergency(self, ks: KillSwitch) -> None:
        """Triggering EMERGENCY should set that level active."""
        ks.trigger(EscalationLevel.EMERGENCY, reason="Critical breach")
        status = ks.get_status()
        assert EscalationLevel.EMERGENCY in status.active_levels

    def test_multiple_levels_active(self, ks: KillSwitch) -> None:
        """Multiple levels can be active simultaneously."""
        ks.trigger(EscalationLevel.PAUSE, reason="First")
        ks.trigger(EscalationLevel.NETWORK_CUT, reason="Second")
        status = ks.get_status()
        assert EscalationLevel.PAUSE in status.active_levels
        assert EscalationLevel.NETWORK_CUT in status.active_levels

    def test_trigger_with_reason(self, ks: KillSwitch) -> None:
        """Trigger reason should be stored in the log."""
        ks.trigger(EscalationLevel.LOCKDOWN, reason="Honeypot breach")
        log = ks.get_log()
        assert len(log) >= 1
        assert log[-1].reason == "Honeypot breach"


# -------------------------------------------------------------------------
# Status
# -------------------------------------------------------------------------
class TestStatus:
    """Tests for get_status."""

    def test_initial_status_clean(self, ks: KillSwitch) -> None:
        """Initial status should have no active levels."""
        status = ks.get_status()
        assert len(status.active_levels) == 0
        assert status.is_locked_down is False

    def test_lockdown_flag(self, ks: KillSwitch) -> None:
        """is_locked_down should be True when LOCKDOWN or higher is active."""
        ks.trigger(EscalationLevel.LOCKDOWN, reason="Test")
        assert ks.get_status().is_locked_down is True

    def test_pause_is_not_lockdown(self, ks: KillSwitch) -> None:
        """PAUSE alone should not set is_locked_down."""
        ks.trigger(EscalationLevel.PAUSE, reason="Test")
        assert ks.get_status().is_locked_down is False

    def test_highest_level(self, ks: KillSwitch) -> None:
        """highest_level should return the maximum active level."""
        ks.trigger(EscalationLevel.PAUSE, reason="First")
        ks.trigger(EscalationLevel.LOCKDOWN, reason="Second")
        assert ks.get_status().highest_level == EscalationLevel.LOCKDOWN


# -------------------------------------------------------------------------
# Reset with codephrase
# -------------------------------------------------------------------------
class TestReset:
    """Tests for resetting kill switch levels."""

    def test_reset_with_correct_codephrase(self, ks: KillSwitch) -> None:
        """Reset with correct codephrase should deactivate the level."""
        ks.trigger(EscalationLevel.PAUSE, reason="Test")
        success = ks.reset(EscalationLevel.PAUSE, codephrase="test-reset-phrase-42")
        assert success is True
        assert EscalationLevel.PAUSE not in ks.get_status().active_levels

    def test_reset_with_wrong_codephrase(self, ks: KillSwitch) -> None:
        """Reset with wrong codephrase should fail."""
        ks.trigger(EscalationLevel.LOCKDOWN, reason="Test")
        success = ks.reset(EscalationLevel.LOCKDOWN, codephrase="wrong-phrase")
        assert success is False
        assert EscalationLevel.LOCKDOWN in ks.get_status().active_levels

    def test_reset_specific_level_only(self, ks: KillSwitch) -> None:
        """Reset should only deactivate the specified level."""
        ks.trigger(EscalationLevel.PAUSE, reason="First")
        ks.trigger(EscalationLevel.NETWORK_CUT, reason="Second")
        ks.reset(EscalationLevel.PAUSE, codephrase="test-reset-phrase-42")
        status = ks.get_status()
        assert EscalationLevel.PAUSE not in status.active_levels
        assert EscalationLevel.NETWORK_CUT in status.active_levels

    def test_reset_inactive_level_ok(self, ks: KillSwitch) -> None:
        """Resetting an already inactive level should succeed without error."""
        success = ks.reset(EscalationLevel.PAUSE, codephrase="test-reset-phrase-42")
        assert success is True

    def test_reset_logged(self, ks: KillSwitch) -> None:
        """Reset events should appear in the log."""
        ks.trigger(EscalationLevel.PAUSE, reason="Trigger")
        ks.reset(EscalationLevel.PAUSE, codephrase="test-reset-phrase-42")
        log = ks.get_log()
        reset_events = [e for e in log if e.action == "reset"]
        assert len(reset_events) >= 1


# -------------------------------------------------------------------------
# Logging
# -------------------------------------------------------------------------
class TestLogging:
    """Tests for kill switch event logging."""

    def test_trigger_logged(self, ks: KillSwitch) -> None:
        """Each trigger should be logged with timestamp and reason."""
        ks.trigger(EscalationLevel.PAUSE, reason="Test trigger")
        log = ks.get_log()
        assert len(log) == 1
        assert log[0].action == "trigger"
        assert log[0].level == EscalationLevel.PAUSE
        assert log[0].reason == "Test trigger"
        assert log[0].timestamp > 0

    def test_multiple_events_logged(self, ks: KillSwitch) -> None:
        """Multiple triggers should all be logged in order."""
        ks.trigger(EscalationLevel.PAUSE, reason="First")
        ks.trigger(EscalationLevel.LOCKDOWN, reason="Second")
        ks.reset(EscalationLevel.PAUSE, codephrase="test-reset-phrase-42")
        log = ks.get_log()
        assert len(log) == 3
        assert log[0].action == "trigger"
        assert log[1].action == "trigger"
        assert log[2].action == "reset"

    def test_empty_log_initially(self, ks: KillSwitch) -> None:
        """Log should be empty when no events have occurred."""
        assert len(ks.get_log()) == 0
