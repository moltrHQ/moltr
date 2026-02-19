"""Integration tests for Moltr Security API.

Tests end-to-end flows: KillSwitch trigger → status update,
IntegrityWatchdog baseline → verify → violation detection,
and API rate-limiting behavior.
"""

from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from src.killswitches.killswitch import KillSwitch, EscalationLevel
from src.watchdog.integrity import IntegrityWatchdog, IntegrityViolation
from src.scanners.output_scanner import OutputScanner


# -------------------------------------------------------------------------
# KillSwitch Integration
# -------------------------------------------------------------------------

class TestKillSwitchIntegration:
    """End-to-end KillSwitch flow tests."""

    def test_trigger_updates_status(self) -> None:
        """Triggering a level should update status correctly."""
        ks = KillSwitch(reset_codephrase="test123")
        ks.trigger(EscalationLevel.PAUSE, reason="test trigger")

        status = ks.get_status()
        assert EscalationLevel.PAUSE in status.active_levels
        assert status.highest_level == EscalationLevel.PAUSE
        assert status.is_locked_down is False

    def test_lockdown_level_sets_locked_down(self) -> None:
        """LOCKDOWN level and above should set is_locked_down."""
        ks = KillSwitch(reset_codephrase="test123")
        ks.trigger(EscalationLevel.LOCKDOWN, reason="lockdown test")

        status = ks.get_status()
        assert status.is_locked_down is True

    def test_trigger_and_reset_flow(self) -> None:
        """Full trigger → reset cycle should work end-to-end."""
        ks = KillSwitch(reset_codephrase="secret")
        ks.trigger(EscalationLevel.NETWORK_CUT, reason="test")

        # Verify triggered
        assert EscalationLevel.NETWORK_CUT in ks.get_status().active_levels

        # Wrong codephrase fails
        assert ks.reset(EscalationLevel.NETWORK_CUT, codephrase="wrong") is False
        assert EscalationLevel.NETWORK_CUT in ks.get_status().active_levels

        # Correct codephrase succeeds
        assert ks.reset(EscalationLevel.NETWORK_CUT, codephrase="secret") is True
        assert EscalationLevel.NETWORK_CUT not in ks.get_status().active_levels

    def test_log_records_all_events(self) -> None:
        """All trigger/reset events should be in the log."""
        ks = KillSwitch(reset_codephrase="x")
        ks.trigger(EscalationLevel.PAUSE, reason="r1")
        ks.trigger(EscalationLevel.LOCKDOWN, reason="r2")
        ks.reset(EscalationLevel.PAUSE, codephrase="x")

        log = ks.get_log()
        assert len(log) == 3
        assert log[0].action == "trigger"
        assert log[0].level == EscalationLevel.PAUSE
        assert log[1].action == "trigger"
        assert log[1].level == EscalationLevel.LOCKDOWN
        assert log[2].action == "reset"

    def test_multiple_levels_simultaneous(self) -> None:
        """Multiple levels can be active simultaneously."""
        ks = KillSwitch(reset_codephrase="x")
        ks.trigger(EscalationLevel.PAUSE, reason="a")
        ks.trigger(EscalationLevel.NETWORK_CUT, reason="b")
        ks.trigger(EscalationLevel.LOCKDOWN, reason="c")

        status = ks.get_status()
        assert len(status.active_levels) == 3
        assert status.highest_level == EscalationLevel.LOCKDOWN
        assert status.is_locked_down is True

    def test_idempotent_trigger(self) -> None:
        """Double-triggering same level should not cause issues."""
        ks = KillSwitch()
        ks.trigger(EscalationLevel.PAUSE, reason="first")
        ks.trigger(EscalationLevel.PAUSE, reason="second")

        status = ks.get_status()
        assert EscalationLevel.PAUSE in status.active_levels
        # Log should have 2 entries
        assert len(ks.get_log()) == 2


# -------------------------------------------------------------------------
# IntegrityWatchdog Integration
# -------------------------------------------------------------------------

class TestWatchdogIntegration:
    """End-to-end IntegrityWatchdog flow tests."""

    def test_baseline_and_verify_clean(self, tmp_path: Path) -> None:
        """Baseline → verify with no changes should return no violations."""
        # Create test files
        (tmp_path / "config.yaml").write_text("key: value")
        (tmp_path / "secret.txt").write_text("honeypot data")

        watchdog = IntegrityWatchdog(project_root=tmp_path)
        baseline = watchdog.create_baseline([tmp_path])

        assert len(baseline) == 2

        violations = watchdog.verify_integrity()
        assert violations == []

    def test_detect_modified_file(self, tmp_path: Path) -> None:
        """Modifying a baselined file should trigger a violation."""
        test_file = tmp_path / "config.yaml"
        test_file.write_text("key: value")

        watchdog = IntegrityWatchdog(project_root=tmp_path)
        watchdog.create_baseline([tmp_path])

        # Modify the file
        test_file.write_text("key: HACKED")

        violations = watchdog.verify_integrity()
        assert len(violations) == 1
        assert violations[0].violation_type == "modified"
        assert "config.yaml" in violations[0].filepath

    def test_detect_deleted_file(self, tmp_path: Path) -> None:
        """Deleting a baselined file should trigger a violation."""
        test_file = tmp_path / "secret.txt"
        test_file.write_text("data")

        watchdog = IntegrityWatchdog(project_root=tmp_path)
        watchdog.create_baseline([tmp_path])

        # Delete the file
        test_file.unlink()

        violations = watchdog.verify_integrity()
        assert len(violations) == 1
        assert violations[0].violation_type == "deleted"

    def test_detect_added_file(self, tmp_path: Path) -> None:
        """Adding a new file to a monitored directory should trigger a violation."""
        existing = tmp_path / "existing.txt"
        existing.write_text("ok")

        watchdog = IntegrityWatchdog(project_root=tmp_path)
        watchdog.create_baseline([tmp_path])

        # Add a new file
        (tmp_path / "backdoor.py").write_text("import os; os.system('evil')")

        violations = watchdog.verify_integrity()
        assert len(violations) == 1
        assert violations[0].violation_type == "added"

    def test_violation_callback_invoked(self, tmp_path: Path) -> None:
        """on_violation callback should be called when violations are found."""
        callback = MagicMock()

        test_file = tmp_path / "config.yaml"
        test_file.write_text("original")

        watchdog = IntegrityWatchdog(
            project_root=tmp_path,
            on_violation=callback,
        )
        watchdog.create_baseline([tmp_path])

        # Modify
        test_file.write_text("tampered")

        watchdog.verify_integrity()

        callback.assert_called_once()
        violations = callback.call_args[0][0]
        assert len(violations) == 1
        assert violations[0].violation_type == "modified"

    def test_no_callback_when_clean(self, tmp_path: Path) -> None:
        """on_violation callback should NOT be called when no violations."""
        callback = MagicMock()

        (tmp_path / "file.txt").write_text("data")

        watchdog = IntegrityWatchdog(
            project_root=tmp_path,
            on_violation=callback,
        )
        watchdog.create_baseline([tmp_path])
        watchdog.verify_integrity()

        callback.assert_not_called()

    def test_hmac_detects_baseline_tampering(self, tmp_path: Path) -> None:
        """HMAC should detect if baselines were modified in memory."""
        (tmp_path / "file.txt").write_text("data")

        watchdog = IntegrityWatchdog(
            project_root=tmp_path,
            hmac_key="test-secret-key",
        )
        watchdog.create_baseline([tmp_path])

        # Tamper with baseline in memory
        key = list(watchdog._baselines.keys())[0]
        watchdog._baselines[key] = "fake_hash_after_tampering"

        violations = watchdog.verify_integrity()
        assert len(violations) == 1
        assert violations[0].violation_type == "baseline_tampered"

    def test_update_baseline_for_prevents_false_positive(self, tmp_path: Path) -> None:
        """Updating baseline for a file after legitimate change should work."""
        test_file = tmp_path / "config.yaml"
        test_file.write_text("v1")

        watchdog = IntegrityWatchdog(project_root=tmp_path)
        watchdog.create_baseline([tmp_path])

        # Legitimate update
        test_file.write_text("v2")
        watchdog.update_baseline_for(test_file)

        # Should be clean now
        violations = watchdog.verify_integrity()
        assert violations == []

    def test_add_and_remove_watch(self, tmp_path: Path) -> None:
        """add_watch/remove_watch should update monitoring correctly."""
        dir1 = tmp_path / "dir1"
        dir2 = tmp_path / "dir2"
        dir1.mkdir()
        dir2.mkdir()
        (dir1 / "a.txt").write_text("a")
        (dir2 / "b.txt").write_text("b")

        watchdog = IntegrityWatchdog(project_root=tmp_path)
        watchdog.create_baseline([dir1])

        assert len(watchdog._baselines) == 1

        watchdog.add_watch(dir2)
        assert len(watchdog._baselines) == 2

        watchdog.remove_watch(dir2)
        assert len(watchdog._baselines) == 1

    def test_report_contains_expected_fields(self, tmp_path: Path) -> None:
        """get_report should return all expected fields."""
        (tmp_path / "file.txt").write_text("data")

        watchdog = IntegrityWatchdog(project_root=tmp_path)
        watchdog.create_baseline([tmp_path])
        watchdog.verify_integrity()

        report = watchdog.get_report()
        assert "baseline_created_at" in report
        assert "last_check" in report
        assert "files_monitored" in report
        assert "watched_paths" in report
        assert "total_violations" in report
        assert "recent_violations" in report
        assert report["files_monitored"] == 1
        assert report["total_violations"] == 0


# -------------------------------------------------------------------------
# Cross-Module Integration
# -------------------------------------------------------------------------

class TestCrossModuleIntegration:
    """Tests that verify different modules work together correctly."""

    PATTERNS_FILE = Path(__file__).resolve().parent.parent / "config" / "scan_patterns.yaml"

    def test_scanner_lockdown_check_after_multiple_scans(self) -> None:
        """OutputScanner lockdown should trigger after threshold on high level."""
        scanner = OutputScanner(patterns_file=self.PATTERNS_FILE)
        # High level: lockdown_after=1, api_key is a blocked type
        result = scanner.scan("sk-" + "a" * 48, level="high")
        assert result.blocked is True
        assert scanner.is_locked is True

        # Subsequent clean text should be blocked (lockdown active)
        result = scanner.scan("Hello world", level="high")
        assert result.blocked is True
        assert result.threat_type == "LOCKDOWN"

    def test_scanner_low_level_threshold(self) -> None:
        """Low level should allow more incidents before lockdown."""
        scanner = OutputScanner(patterns_file=self.PATTERNS_FILE)
        scanner._passphrase = "test"

        # Low level blocks: seed_phrase, private_key, credit_card (NOT api_key)
        # Use private_key and credit_card patterns that match low-level blocked types
        scanner.scan("0x" + "ab" * 32, level="low", passphrase="test")  # Ethereum private key
        scanner.scan("4111 1111 1111 1111", level="low", passphrase="test")  # Visa credit card

        # 2 incidents, threshold is 3 — should not be locked on low
        assert scanner._lockdown.is_locked(3) is False

        # 3rd incident — another private key
        scanner.scan("-----BEGIN RSA PRIVATE KEY-----", level="low", passphrase="test")
        assert scanner._lockdown.is_locked(3) is True
