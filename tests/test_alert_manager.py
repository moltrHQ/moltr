"""Tests for the Moltr AlertManager and AlertChannel base class.

Tests channel registration, dispatching to all configured channels,
skipping unconfigured channels, and error handling.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from src.alerts.manager import AlertChannel, AlertManager, Severity


# -------------------------------------------------------------------------
# Concrete stub for testing
# -------------------------------------------------------------------------
class _StubChannel(AlertChannel):
    """Minimal AlertChannel implementation for testing."""

    def __init__(self, channel_name: str, configured: bool, succeed: bool = True):
        self._name = channel_name
        self._configured = configured
        self._succeed = succeed
        self.sent: list[tuple] = []

    @property
    def name(self) -> str:
        return self._name

    @property
    def is_configured(self) -> bool:
        return self._configured

    def send(self, severity: Severity, title: str, message: str) -> bool:
        self.sent.append((severity, title, message))
        return self._succeed


# -------------------------------------------------------------------------
# AlertChannel base class
# -------------------------------------------------------------------------
class TestAlertChannelBase:
    """Tests for the abstract AlertChannel."""

    def test_cannot_instantiate_abstract(self) -> None:
        """AlertChannel should not be instantiable directly."""
        with pytest.raises(TypeError):
            AlertChannel()  # type: ignore[abstract]

    def test_stub_implements_interface(self) -> None:
        """A concrete subclass should be instantiable."""
        ch = _StubChannel("test", configured=True)
        assert ch.name == "test"
        assert ch.is_configured is True


# -------------------------------------------------------------------------
# AlertManager registration
# -------------------------------------------------------------------------
class TestRegistration:
    """Tests for channel registration."""

    def test_register_single_channel(self) -> None:
        """Manager should accept a single channel."""
        mgr = AlertManager()
        ch = _StubChannel("test", configured=True)
        mgr.register(ch)
        assert len(mgr.channels) == 1

    def test_register_multiple_channels(self) -> None:
        """Manager should accept multiple channels."""
        mgr = AlertManager()
        mgr.register(_StubChannel("a", configured=True))
        mgr.register(_StubChannel("b", configured=True))
        mgr.register(_StubChannel("c", configured=False))
        assert len(mgr.channels) == 3

    def test_channels_returns_copy(self) -> None:
        """channels property should return a copy, not the internal list."""
        mgr = AlertManager()
        mgr.register(_StubChannel("x", configured=True))
        channels = mgr.channels
        channels.clear()
        assert len(mgr.channels) == 1


# -------------------------------------------------------------------------
# AlertManager dispatching
# -------------------------------------------------------------------------
class TestDispatching:
    """Tests for alert dispatching to channels."""

    def test_send_to_all_configured(self) -> None:
        """All configured channels should receive the alert."""
        mgr = AlertManager()
        ch1 = _StubChannel("telegram", configured=True)
        ch2 = _StubChannel("slack", configured=True)
        mgr.register(ch1)
        mgr.register(ch2)

        results = mgr.send_alert(Severity.WARNING, "Test", "Message")

        assert results["telegram"] is True
        assert results["slack"] is True
        assert len(ch1.sent) == 1
        assert len(ch2.sent) == 1

    def test_skip_unconfigured_channels(self) -> None:
        """Unconfigured channels should be skipped (result = False)."""
        mgr = AlertManager()
        ch_ok = _StubChannel("slack", configured=True)
        ch_bad = _StubChannel("email", configured=False)
        mgr.register(ch_ok)
        mgr.register(ch_bad)

        results = mgr.send_alert(Severity.INFO, "Test", "Msg")

        assert results["slack"] is True
        assert results["email"] is False
        assert len(ch_ok.sent) == 1
        assert len(ch_bad.sent) == 0

    def test_empty_manager_returns_empty_dict(self) -> None:
        """Manager with no channels should return empty dict."""
        mgr = AlertManager()
        results = mgr.send_alert(Severity.CRITICAL, "X", "Y")
        assert results == {}

    def test_send_failure_reported(self) -> None:
        """A channel that returns False should be reflected in results."""
        mgr = AlertManager()
        ch = _StubChannel("discord", configured=True, succeed=False)
        mgr.register(ch)

        results = mgr.send_alert(Severity.CRITICAL, "Fail", "Msg")
        assert results["discord"] is False

    def test_exception_in_channel_caught(self) -> None:
        """If a channel raises, manager should catch and return False."""
        mgr = AlertManager()
        ch = _StubChannel("broken", configured=True)

        # Make send() raise an exception
        def _boom(*args):
            raise RuntimeError("connection lost")
        ch.send = _boom  # type: ignore[assignment]

        mgr.register(ch)
        results = mgr.send_alert(Severity.LOCKDOWN, "Err", "Boom")
        assert results["broken"] is False

    def test_severity_and_message_forwarded(self) -> None:
        """The exact severity, title, and message should reach the channel."""
        mgr = AlertManager()
        ch = _StubChannel("test", configured=True)
        mgr.register(ch)

        mgr.send_alert(Severity.LOCKDOWN, "Emergency", "All locked")

        sev, title, msg = ch.sent[0]
        assert sev is Severity.LOCKDOWN
        assert title == "Emergency"
        assert msg == "All locked"
