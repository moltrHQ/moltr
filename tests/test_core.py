"""Tests for Moltr core modules: MoltrLogger and MoltrConfig."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from src.core.logger import MoltrLogger, _redact_value
from src.core.config import MoltrConfig


# -------------------------------------------------------------------------
# MoltrLogger Tests
# -------------------------------------------------------------------------

class TestMoltrLogger:
    """Tests for the structured MoltrLogger."""

    def test_creates_logger_with_name(self) -> None:
        """Logger should create a Python logger with moltr. prefix."""
        log = MoltrLogger(name="test")
        assert log._logger.name == "moltr.test"

    def test_default_level_is_info(self) -> None:
        """Default log level should be INFO."""
        log = MoltrLogger()
        assert log._logger.level == logging.INFO

    def test_custom_level(self) -> None:
        """Custom log level should be respected."""
        log = MoltrLogger(level="DEBUG")
        assert log._logger.level == logging.DEBUG

    def test_info_logs_message(self, caplog) -> None:
        """info() should produce a log record at INFO level."""
        log = MoltrLogger(name="test_info")
        with caplog.at_level(logging.INFO, logger="moltr.test_info"):
            log.info("Test message")
        assert "Test message" in caplog.text

    def test_warning_logs_message(self, caplog) -> None:
        """warning() should produce a log record at WARNING level."""
        log = MoltrLogger(name="test_warn")
        with caplog.at_level(logging.WARNING, logger="moltr.test_warn"):
            log.warning("Warn msg")
        assert "Warn msg" in caplog.text

    def test_error_logs_message(self, caplog) -> None:
        """error() should produce a log record at ERROR level."""
        log = MoltrLogger(name="test_err")
        with caplog.at_level(logging.ERROR, logger="moltr.test_err"):
            log.error("Error msg")
        assert "Error msg" in caplog.text

    def test_context_fields_in_log(self, caplog) -> None:
        """Context kwargs should appear in the log output."""
        log = MoltrLogger(name="test_ctx")
        with caplog.at_level(logging.INFO, logger="moltr.test_ctx"):
            log.info("With context", ip="1.2.3.4", action="scan")
        assert "ip=" in caplog.text
        assert "1.2.3.4" in caplog.text

    def test_security_event_json(self, caplog) -> None:
        """security_event() should log JSON with required fields."""
        log = MoltrLogger(name="test_sec")
        with caplog.at_level(logging.WARNING, logger="moltr.test_sec"):
            log.security_event(
                event_type="honeypot_access",
                severity="high",
                details={"path": "/secrets.txt", "ip": "10.0.0.1"},
            )
        # Parse the JSON from the log
        record_text = caplog.text
        assert "honeypot_access" in record_text
        assert "HIGH" in record_text

    def test_security_event_severity_mapping(self, caplog) -> None:
        """Severity levels should map to appropriate Python log levels."""
        log = MoltrLogger(name="test_sev")
        with caplog.at_level(logging.DEBUG, logger="moltr.test_sev"):
            log.security_event("test", "low", {})
            log.security_event("test", "critical", {})
        records = [r for r in caplog.records if r.name == "moltr.test_sev"]
        assert records[0].levelno == logging.INFO
        assert records[1].levelno == logging.CRITICAL

    def test_no_duplicate_handlers(self) -> None:
        """Creating multiple MoltrLoggers with same name should not add duplicate handlers."""
        log1 = MoltrLogger(name="dedup_test")
        handler_count = len(log1._logger.handlers)
        log2 = MoltrLogger(name="dedup_test")
        assert len(log2._logger.handlers) == handler_count

    def test_redacts_sensitive_key(self) -> None:
        """Context with sensitive key names should be redacted."""
        assert _redact_value("password", "my-secret-pw") == "[REDACTED]"
        assert _redact_value("api_key", "sk-something") == "[REDACTED]"
        assert _redact_value("token", "abc123") == "[REDACTED]"
        assert _redact_value("codephrase", "test") == "[REDACTED]"

    def test_redacts_sensitive_patterns(self) -> None:
        """Values containing API key patterns should be redacted."""
        assert "[REDACTED]" in _redact_value("text", "key is sk-proj-abcdefghijklmnopqrst")
        assert "[REDACTED]" in _redact_value("info", "found AKIA1234567890ABCDEF")

    def test_does_not_redact_safe_values(self) -> None:
        """Non-sensitive values should pass through unchanged."""
        assert _redact_value("ip", "192.168.1.1") == "192.168.1.1"
        assert _redact_value("action", "scan") == "scan"
        assert _redact_value("count", 42) == 42

    def test_redaction_in_context_log(self, caplog) -> None:
        """Sensitive context values should be redacted in log output."""
        log = MoltrLogger(name="test_redact")
        with caplog.at_level(logging.INFO, logger="moltr.test_redact"):
            log.info("User login", password="secret123", ip="1.2.3.4")
        assert "[REDACTED]" in caplog.text
        assert "secret123" not in caplog.text
        assert "1.2.3.4" in caplog.text

    def test_redaction_in_security_event(self, caplog) -> None:
        """Sensitive details in security events should be redacted."""
        log = MoltrLogger(name="test_sec_redact")
        with caplog.at_level(logging.WARNING, logger="moltr.test_sec_redact"):
            log.security_event("leak", "high", {
                "api_key": "sk-ant-secret-token-value",
                "path": "/etc/passwd",
            })
        assert "[REDACTED]" in caplog.text
        assert "sk-ant-secret-token-value" not in caplog.text
        assert "/etc/passwd" in caplog.text

    def test_file_output(self, tmp_path: Path) -> None:
        """Logger with log_dir should create rotating log files."""
        log = MoltrLogger(name="file_test", log_dir=tmp_path)
        log.info("Test file output")
        log.security_event("test", "high", {"action": "scan"})

        log_file = tmp_path / "moltr-file_test.log"
        sec_file = tmp_path / "security_events.jsonl"
        assert log_file.exists()
        assert sec_file.exists()
        assert "Test file output" in log_file.read_text(encoding="utf-8")
        sec_content = sec_file.read_text(encoding="utf-8")
        assert "test" in sec_content


# -------------------------------------------------------------------------
# MoltrConfig Tests
# -------------------------------------------------------------------------

CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "default.yaml"


class TestMoltrConfig:
    """Tests for the MoltrConfig configuration manager."""

    def test_loads_config(self) -> None:
        """Config should load successfully from default.yaml."""
        cfg = MoltrConfig(config_path=CONFIG_PATH)
        assert cfg._data != {}

    def test_get_top_level_key(self) -> None:
        """get() with simple key should return the section."""
        cfg = MoltrConfig(config_path=CONFIG_PATH)
        moltr = cfg.get("moltr")
        assert isinstance(moltr, dict)
        assert "version" in moltr

    def test_get_dotted_key(self) -> None:
        """get() with dotted key should traverse nested dicts."""
        cfg = MoltrConfig(config_path=CONFIG_PATH)
        assert cfg.get("moltr.mode") == "enforce"
        assert cfg.get("moltr.log_level") == "INFO"

    def test_get_deep_dotted_key(self) -> None:
        """get() should handle deeply nested keys."""
        cfg = MoltrConfig(config_path=CONFIG_PATH)
        assert cfg.get("scanners.output.enabled") is True

    def test_get_missing_key_returns_default(self) -> None:
        """get() for non-existent key should return the default."""
        cfg = MoltrConfig(config_path=CONFIG_PATH)
        assert cfg.get("nonexistent.key") is None
        assert cfg.get("nonexistent.key", "fallback") == "fallback"

    def test_load_allowlist_domains(self) -> None:
        """load_allowlist('domains') should return the domain list."""
        cfg = MoltrConfig(config_path=CONFIG_PATH)
        domains = cfg.load_allowlist("domains")
        assert isinstance(domains, list)
        assert len(domains) > 0
        assert "api.telegram.org" in domains

    def test_load_allowlist_commands(self) -> None:
        """load_allowlist('commands') should return entries."""
        cfg = MoltrConfig(config_path=CONFIG_PATH)
        commands = cfg.load_allowlist("commands")
        assert isinstance(commands, list)

    def test_load_allowlist_nonexistent(self) -> None:
        """load_allowlist for non-existent file should return empty list."""
        cfg = MoltrConfig(config_path=CONFIG_PATH)
        result = cfg.load_allowlist("doesnotexist")
        assert result == []

    def test_reload(self) -> None:
        """reload() should re-read config from disk."""
        cfg = MoltrConfig(config_path=CONFIG_PATH)
        original_mode = cfg.get("moltr.mode")
        cfg.reload()
        assert cfg.get("moltr.mode") == original_mode

    def test_validate_valid_config(self) -> None:
        """validate() should return True for a valid config."""
        cfg = MoltrConfig(config_path=CONFIG_PATH)
        assert cfg.validate() is True

    def test_validate_empty_config(self) -> None:
        """validate() should raise ValueError for empty config."""
        cfg = MoltrConfig(config_path="nonexistent.yaml")
        with pytest.raises(ValueError, match="empty"):
            cfg.validate()

    def test_validate_missing_sections(self, tmp_path: Path) -> None:
        """validate() should raise ValueError for missing required sections."""
        bad_config = tmp_path / "bad.yaml"
        bad_config.write_text("moltr:\n  version: '1.0'\n")
        cfg = MoltrConfig(config_path=bad_config)
        with pytest.raises(ValueError, match="Missing required"):
            cfg.validate()

    def test_config_nonexistent_file(self) -> None:
        """Config with non-existent file should have empty data."""
        cfg = MoltrConfig(config_path="/nonexistent/config.yaml")
        assert cfg._data == {}

    def test_reload_keeps_old_config_on_invalid(self, tmp_path: Path) -> None:
        """reload() should keep previous config if new config is invalid."""
        # Create a valid config first
        valid_config = tmp_path / "config.yaml"
        valid_config.write_text(
            "moltr:\n  version: '1.0'\n  mode: enforce\n  log_level: INFO\n"
            "scanners:\n  output:\n    enabled: true\n"
            "validators:\n  actions:\n    enabled: true\n"
            "killswitch:\n  enabled: true\n"
        )
        cfg = MoltrConfig(config_path=valid_config)
        assert cfg.get("moltr.mode") == "enforce"

        # Overwrite with invalid config
        valid_config.write_text("moltr:\n  version: '1.0'\n")
        cfg.reload()

        # Should still have the old valid config
        assert cfg.get("moltr.mode") == "enforce"

    def test_reload_applies_valid_changes(self, tmp_path: Path) -> None:
        """reload() should apply changes from a valid new config."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "moltr:\n  version: '1.0'\n  mode: enforce\n  log_level: INFO\n"
            "scanners:\n  output:\n    enabled: true\n"
            "validators:\n  actions:\n    enabled: true\n"
            "killswitch:\n  enabled: true\n"
        )
        cfg = MoltrConfig(config_path=config_file)
        assert cfg.get("moltr.mode") == "enforce"

        # Update to valid new config with monitor mode
        config_file.write_text(
            "moltr:\n  version: '1.1'\n  mode: monitor\n  log_level: DEBUG\n"
            "scanners:\n  output:\n    enabled: false\n"
            "validators:\n  actions:\n    enabled: true\n"
            "killswitch:\n  enabled: true\n"
        )
        cfg.reload()
        assert cfg.get("moltr.mode") == "monitor"
        assert cfg.get("moltr.log_level") == "DEBUG"
