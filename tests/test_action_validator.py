"""Tests for the Moltr action validator.

Tests command allowlist/blocklist, bypass detection,
rate limiting, and risk level assignment.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from src.validators.action_validator import ActionValidator, ValidationResult


COMMANDS_FILE = Path("config/allowlists/commands.yaml")


@pytest.fixture
def validator():
    """Provide a fresh ActionValidator loaded with production config."""
    return ActionValidator(commands_file=COMMANDS_FILE)


# -------------------------------------------------------------------------
# Allowed commands
# -------------------------------------------------------------------------
class TestAllowedCommands:
    """Tests that permitted commands pass validation."""

    def test_simple_ls(self, validator: ActionValidator) -> None:
        """'ls' should be allowed."""
        result = validator.validate("ls")
        assert result.allowed is True

    def test_ls_with_args(self, validator: ActionValidator) -> None:
        """'ls -la /tmp' should be allowed (base command is 'ls')."""
        result = validator.validate("ls -la /tmp")
        assert result.allowed is True

    def test_python(self, validator: ActionValidator) -> None:
        """'python script.py' should be allowed."""
        result = validator.validate("python script.py")
        assert result.allowed is True

    def test_git(self, validator: ActionValidator) -> None:
        """'git status' should be allowed."""
        result = validator.validate("git status")
        assert result.allowed is True

    def test_pip_install(self, validator: ActionValidator) -> None:
        """'pip install requests' should be allowed."""
        result = validator.validate("pip install requests")
        assert result.allowed is True

    def test_echo(self, validator: ActionValidator) -> None:
        """'echo hello' should be allowed."""
        result = validator.validate("echo hello")
        assert result.allowed is True

    def test_mkdir(self, validator: ActionValidator) -> None:
        """'mkdir new_dir' should be allowed."""
        result = validator.validate("mkdir new_dir")
        assert result.allowed is True

    def test_cat_file(self, validator: ActionValidator) -> None:
        """'cat file.txt' should be allowed."""
        result = validator.validate("cat file.txt")
        assert result.allowed is True

    def test_npm_install(self, validator: ActionValidator) -> None:
        """'npm install' should be allowed."""
        result = validator.validate("npm install")
        assert result.allowed is True


# -------------------------------------------------------------------------
# Blocked commands
# -------------------------------------------------------------------------
class TestBlockedCommands:
    """Tests that forbidden commands are blocked."""

    def test_rm_rf(self, validator: ActionValidator) -> None:
        """'rm -rf /' should be blocked."""
        result = validator.validate("rm -rf /")
        assert result.allowed is False
        assert result.risk_level == 3

    def test_sudo(self, validator: ActionValidator) -> None:
        """'sudo anything' should be blocked."""
        result = validator.validate("sudo apt install something")
        assert result.allowed is False

    def test_ssh(self, validator: ActionValidator) -> None:
        """'ssh user@host' should be blocked."""
        result = validator.validate("ssh user@host")
        assert result.allowed is False

    def test_kill(self, validator: ActionValidator) -> None:
        """'kill -9 1234' should be blocked."""
        result = validator.validate("kill -9 1234")
        assert result.allowed is False

    def test_killall(self, validator: ActionValidator) -> None:
        """'killall process' should be blocked."""
        result = validator.validate("killall nginx")
        assert result.allowed is False

    def test_chmod_777(self, validator: ActionValidator) -> None:
        """'chmod 777 file' should be blocked."""
        result = validator.validate("chmod 777 /etc/passwd")
        assert result.allowed is False

    def test_dd(self, validator: ActionValidator) -> None:
        """'dd if=/dev/zero' should be blocked."""
        result = validator.validate("dd if=/dev/zero of=/dev/sda")
        assert result.allowed is False

    def test_nc(self, validator: ActionValidator) -> None:
        """'nc' (netcat) should be blocked."""
        result = validator.validate("nc -l 4444")
        assert result.allowed is False

    def test_unknown_command_blocked(self, validator: ActionValidator) -> None:
        """Commands not in any list should be blocked by default."""
        result = validator.validate("some_unknown_binary --flag")
        assert result.allowed is False


# -------------------------------------------------------------------------
# Bypass / evasion attempts
# -------------------------------------------------------------------------
class TestBypassDetection:
    """Tests that command obfuscation and evasion attempts are caught."""

    def test_backtick_injection(self, validator: ActionValidator) -> None:
        """Backtick subshell injection should be detected and blocked."""
        result = validator.validate("echo `rm -rf /`")
        assert result.allowed is False
        assert "bypass" in result.reason.lower() or "evasion" in result.reason.lower()

    def test_dollar_subshell(self, validator: ActionValidator) -> None:
        """$() subshell injection should be detected and blocked."""
        result = validator.validate("echo $(sudo reboot)")
        assert result.allowed is False

    def test_pipe_to_blocked(self, validator: ActionValidator) -> None:
        """Piping to a blocked command should be detected."""
        result = validator.validate("echo test | sudo rm -rf /")
        assert result.allowed is False

    def test_semicolon_chaining(self, validator: ActionValidator) -> None:
        """Semicolon chaining with blocked commands should be detected."""
        result = validator.validate("ls; rm -rf /")
        assert result.allowed is False

    def test_and_chaining(self, validator: ActionValidator) -> None:
        """&& chaining with blocked commands should be detected."""
        result = validator.validate("echo ok && sudo reboot")
        assert result.allowed is False

    def test_or_chaining(self, validator: ActionValidator) -> None:
        """|| chaining with blocked commands should be detected."""
        result = validator.validate("false || kill -9 1")
        assert result.allowed is False

    def test_backslash_evasion(self, validator: ActionValidator) -> None:
        r"""Backslash-escaped commands like 'r\m' should be detected."""
        result = validator.validate("r\\m -rf /")
        assert result.allowed is False

    def test_quotes_evasion(self, validator: ActionValidator) -> None:
        """Quote-split evasion like su''do should be detected."""
        result = validator.validate("su''do reboot")
        assert result.allowed is False

    def test_variable_expansion(self, validator: ActionValidator) -> None:
        """Variable expansion evasion like $CMD should be detected."""
        result = validator.validate("$CMD -rf /")
        assert result.allowed is False

    def test_env_variable_evasion(self, validator: ActionValidator) -> None:
        """${VAR} style variable expansion should be detected."""
        result = validator.validate("${HOME}/../bin/rm -rf /")
        assert result.allowed is False

    def test_newline_injection(self, validator: ActionValidator) -> None:
        r"""Newline injection (\n) should be detected."""
        result = validator.validate("echo safe\nrm -rf /")
        assert result.allowed is False

    def test_pipe_to_sh(self, validator: ActionValidator) -> None:
        """Piping to sh/bash should be blocked."""
        result = validator.validate("echo 'rm -rf /' | sh")
        assert result.allowed is False


# -------------------------------------------------------------------------
# Risk levels
# -------------------------------------------------------------------------
class TestRiskLevels:
    """Tests for correct risk level assignment."""

    def test_harmless_level_0(self, validator: ActionValidator) -> None:
        """Read-only commands should be risk level 0."""
        result = validator.validate("ls -la")
        assert result.risk_level == 0

    def test_cat_level_0(self, validator: ActionValidator) -> None:
        """'cat' should be risk level 0."""
        result = validator.validate("cat README.md")
        assert result.risk_level == 0

    def test_echo_level_0(self, validator: ActionValidator) -> None:
        """'echo' should be risk level 0."""
        result = validator.validate("echo hello")
        assert result.risk_level == 0

    def test_python_level_1(self, validator: ActionValidator) -> None:
        """'python' should be risk level 1."""
        result = validator.validate("python test.py")
        assert result.risk_level == 1

    def test_git_level_1(self, validator: ActionValidator) -> None:
        """'git' should be risk level 1."""
        result = validator.validate("git status")
        assert result.risk_level == 1

    def test_npm_level_1(self, validator: ActionValidator) -> None:
        """'npm' should be risk level 1."""
        result = validator.validate("npm test")
        assert result.risk_level == 1

    def test_dangerous_level_3(self, validator: ActionValidator) -> None:
        """Dangerous commands should be risk level 3."""
        result = validator.validate("sudo reboot")
        assert result.risk_level == 3

    def test_rm_level_3(self, validator: ActionValidator) -> None:
        """'rm' should be risk level 3."""
        result = validator.validate("rm file.txt")
        assert result.risk_level == 3

    def test_kill_level_3(self, validator: ActionValidator) -> None:
        """'kill' should be risk level 3."""
        result = validator.validate("kill 1234")
        assert result.risk_level == 3


# -------------------------------------------------------------------------
# Rate limiting
# -------------------------------------------------------------------------
class TestRateLimiting:
    """Tests for command rate limiting."""

    def test_within_rate_limit(self, validator: ActionValidator) -> None:
        """Commands within rate limit should be allowed."""
        for _ in range(5):
            result = validator.validate("ls")
            assert result.allowed is True

    def test_exceeds_general_rate_limit(self, validator: ActionValidator) -> None:
        """Exceeding 30 commands/minute should be blocked."""
        for _ in range(30):
            validator.validate("ls")
        result = validator.validate("ls")
        assert result.allowed is False
        assert "rate" in result.reason.lower()

    def test_network_rate_limit(self, validator: ActionValidator) -> None:
        """Exceeding 5 network commands/minute should be blocked."""
        for _ in range(5):
            validator.validate("ping localhost")
        result = validator.validate("ping localhost")
        assert result.allowed is False
        assert "rate" in result.reason.lower()

    def test_write_rate_limit(self, validator: ActionValidator) -> None:
        """Exceeding 10 write commands/minute should be blocked."""
        for _ in range(10):
            validator.validate("mkdir dir_" + str(_))
        result = validator.validate("mkdir dir_overflow")
        assert result.allowed is False
        assert "rate" in result.reason.lower()


# -------------------------------------------------------------------------
# ValidationResult
# -------------------------------------------------------------------------
class TestValidationResult:
    """Tests for ValidationResult dataclass."""

    def test_allowed_result(self) -> None:
        """An allowed result should report correctly."""
        result = ValidationResult(allowed=True, risk_level=0, reason="Allowed", original_command="ls")
        assert result.allowed is True
        assert result.risk_level == 0

    def test_blocked_result(self) -> None:
        """A blocked result should report correctly."""
        result = ValidationResult(allowed=False, risk_level=3, reason="Blocked: dangerous", original_command="rm -rf /")
        assert result.allowed is False
        assert result.risk_level == 3
        assert "rm -rf /" in result.original_command

    def test_empty_command(self, validator: ActionValidator) -> None:
        """Empty command should be blocked."""
        result = validator.validate("")
        assert result.allowed is False
