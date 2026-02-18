"""Tests for the Moltr filesystem guard.

Tests honeypot monitoring, SHA-256 integrity checking,
path allowlist enforcement, and symlink attack detection.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from src.validators.filesystem_guard import FilesystemGuard


PATHS_FILE = Path("config/allowlists/paths.yaml")


@pytest.fixture
def guard(tmp_path):
    """Provide a fresh FilesystemGuard with temp honeypots."""
    return FilesystemGuard(paths_file=PATHS_FILE, project_root=tmp_path)


@pytest.fixture
def honeypot_dir(tmp_path):
    """Create a temporary honeypot directory with fake files."""
    hp = tmp_path / "honeypots"
    hp.mkdir()
    (hp / "passwords.txt").write_text("fake_secret_123")
    (hp / "wallet_seed.txt").write_text("fake seed phrase here")
    return hp


@pytest.fixture
def guard_with_honeypots(tmp_path, honeypot_dir):
    """Provide a FilesystemGuard with registered honeypots."""
    g = FilesystemGuard(paths_file=PATHS_FILE, project_root=tmp_path)
    g.register_honeypot(honeypot_dir / "passwords.txt")
    g.register_honeypot(honeypot_dir / "wallet_seed.txt")
    return g


# -------------------------------------------------------------------------
# Honeypot monitoring
# -------------------------------------------------------------------------
class TestHoneypotMonitoring:
    """Tests for honeypot file access detection."""

    def test_register_honeypot(self, guard: FilesystemGuard, honeypot_dir) -> None:
        """Registering a honeypot should add it to the watch list."""
        path = honeypot_dir / "passwords.txt"
        guard.register_honeypot(path)
        assert path in guard.get_honeypots()

    def test_honeypot_access_triggers_alarm(self, guard_with_honeypots, honeypot_dir) -> None:
        """Accessing a honeypot file should return blocked=True with alarm."""
        result = guard_with_honeypots.check_path(
            honeypot_dir / "passwords.txt", operation="read"
        )
        assert result.blocked is True
        assert result.is_honeypot is True

    def test_non_honeypot_not_flagged(self, guard_with_honeypots, tmp_path) -> None:
        """Accessing a normal file should NOT trigger honeypot alarm."""
        normal = tmp_path / "src" / "app.py"
        normal.parent.mkdir(parents=True, exist_ok=True)
        normal.write_text("print('hello')")
        result = guard_with_honeypots.check_path(normal, operation="read")
        assert result.is_honeypot is False


# -------------------------------------------------------------------------
# Integrity monitoring (SHA-256)
# -------------------------------------------------------------------------
class TestIntegrityMonitoring:
    """Tests for SHA-256 integrity checking."""

    def test_baseline_creation(self, guard: FilesystemGuard, tmp_path) -> None:
        """Creating a baseline should store SHA-256 hashes."""
        f = tmp_path / "important.conf"
        f.write_text("config_value=42")
        guard.create_baseline([f])
        assert len(guard.get_baseline()) == 1

    def test_integrity_ok_when_unchanged(self, guard: FilesystemGuard, tmp_path) -> None:
        """Files that haven't changed should pass integrity check."""
        f = tmp_path / "stable.conf"
        f.write_text("unchanged_content")
        guard.create_baseline([f])
        violations = guard.check_integrity()
        assert len(violations) == 0

    def test_integrity_violation_on_modification(self, guard: FilesystemGuard, tmp_path) -> None:
        """Modified files should be reported as violations."""
        f = tmp_path / "tampered.conf"
        f.write_text("original")
        guard.create_baseline([f])
        f.write_text("tampered_by_agent")
        violations = guard.check_integrity()
        assert len(violations) == 1
        assert violations[0].filepath == str(f)
        assert violations[0].violation_type == "modified"

    def test_integrity_violation_on_deletion(self, guard: FilesystemGuard, tmp_path) -> None:
        """Deleted files should be reported as violations."""
        f = tmp_path / "deleted.conf"
        f.write_text("will be deleted")
        guard.create_baseline([f])
        f.unlink()
        violations = guard.check_integrity()
        assert len(violations) == 1
        assert violations[0].violation_type == "deleted"


# -------------------------------------------------------------------------
# Path allowlist
# -------------------------------------------------------------------------
class TestPathAllowlist:
    """Tests for path allowlist enforcement."""

    def test_allowed_path_read(self, guard: FilesystemGuard, tmp_path) -> None:
        """Reading from allowed paths should be permitted."""
        allowed = tmp_path / "src" / "module.py"
        allowed.parent.mkdir(parents=True, exist_ok=True)
        allowed.write_text("code")
        result = guard.check_path(allowed, operation="read")
        assert result.blocked is False

    def test_allowed_path_write(self, guard: FilesystemGuard, tmp_path) -> None:
        """Writing to allowed paths should be permitted."""
        allowed = tmp_path / "src" / "new_file.py"
        allowed.parent.mkdir(parents=True, exist_ok=True)
        result = guard.check_path(allowed, operation="write")
        assert result.blocked is False

    def test_blocked_env_file(self, guard: FilesystemGuard, tmp_path) -> None:
        """.env files should be blocked."""
        env = tmp_path / ".env"
        result = guard.check_path(env, operation="read")
        assert result.blocked is True

    def test_blocked_system_path(self, guard: FilesystemGuard) -> None:
        """System paths like /etc/shadow should be blocked."""
        result = guard.check_path(Path("/etc/shadow"), operation="read")
        assert result.blocked is True

    def test_blocked_git_directory(self, guard: FilesystemGuard, tmp_path) -> None:
        """.git/ directory should be blocked."""
        git_file = tmp_path / ".git" / "config"
        result = guard.check_path(git_file, operation="read")
        assert result.blocked is True

    def test_blocked_credentials_file(self, guard: FilesystemGuard, tmp_path) -> None:
        """credentials.json should be blocked."""
        creds = tmp_path / "credentials.json"
        result = guard.check_path(creds, operation="read")
        assert result.blocked is True

    def test_outside_project_blocked(self, guard: FilesystemGuard) -> None:
        """Paths entirely outside the project should be blocked."""
        result = guard.check_path(Path("/var/log/syslog"), operation="read")
        assert result.blocked is True


# -------------------------------------------------------------------------
# Symlink attack detection
# -------------------------------------------------------------------------
class TestSymlinkDetection:
    """Tests for symlink attack prevention."""

    def test_symlink_to_outside_blocked(self, guard: FilesystemGuard, tmp_path) -> None:
        """Symlinks pointing outside allowed directories should be blocked."""
        # Create a symlink inside src/ pointing to /etc/passwd
        src_dir = tmp_path / "src"
        src_dir.mkdir(exist_ok=True)
        link = src_dir / "sneaky_link"
        try:
            link.symlink_to("/etc/passwd")
        except OSError:
            pytest.skip("Cannot create symlinks (requires privileges on Windows)")
        result = guard.check_path(link, operation="read")
        assert result.blocked is True
        assert "symlink" in result.reason.lower()

    def test_symlink_within_allowed_ok(self, guard: FilesystemGuard, tmp_path) -> None:
        """Symlinks within allowed directories should be permitted."""
        src_dir = tmp_path / "src"
        src_dir.mkdir(exist_ok=True)
        target = src_dir / "real_file.py"
        target.write_text("code")
        link = src_dir / "link_to_real.py"
        try:
            link.symlink_to(target)
        except OSError:
            pytest.skip("Cannot create symlinks (requires privileges on Windows)")
        result = guard.check_path(link, operation="read")
        assert result.blocked is False

    def test_non_symlink_passes(self, guard: FilesystemGuard, tmp_path) -> None:
        """Regular files should not be flagged as symlink attacks."""
        f = tmp_path / "src" / "normal.py"
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("normal")
        result = guard.check_path(f, operation="read")
        assert result.blocked is False


# -------------------------------------------------------------------------
# Access result dataclass
# -------------------------------------------------------------------------
class TestAccessResult:
    """Tests for the AccessResult returned by check_path."""

    def test_allowed_result_fields(self, guard: FilesystemGuard, tmp_path) -> None:
        """Allowed result should have correct fields."""
        f = tmp_path / "src" / "ok.py"
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("ok")
        result = guard.check_path(f, operation="read")
        assert result.blocked is False
        assert result.is_honeypot is False
        assert result.reason != ""
