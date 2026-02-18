"""Tests for the Moltr output scanner.

Tests pattern detection, deobfuscation, rate-limiting and lockdown.
All test secrets are synthetic strings constructed to match pattern
formats without containing real credentials.
"""

from __future__ import annotations

import base64
import codecs
import urllib.parse
from pathlib import Path

import pytest

from src.scanners.output_scanner import OutputScanner, ScanResult, LockdownState
from src.core.secrets_registry import SecretsRegistry


# -------------------------------------------------------------------------
# Helpers: synthetic test strings that match pattern formats
# -------------------------------------------------------------------------

def _make_openai_style_key() -> str:
    """Build a synthetic string matching the sk-[A-Za-z0-9]{32,} pattern."""
    # 'sk-' prefix + 40 alphanumeric filler chars
    return "sk-" + "a1b2c3d4e5f6g7h8i9j0" * 2


def _make_aws_style_key() -> str:
    """Build a synthetic string matching the AKIA[0-9A-Z]{16} pattern."""
    # 'AKIA' prefix + 16 uppercase alphanumeric filler chars
    return "AKIA" + "TESTFILLER0XYZAB"


def _make_github_style_token() -> str:
    """Build a synthetic string matching the ghp_[A-Za-z0-9]{36} pattern."""
    # 'ghp_' prefix + 36 alphanumeric filler chars
    return "ghp_" + "abcdef1234567890" * 2 + "abcd"


def _make_slack_style_token() -> str:
    """Build a synthetic string matching the xox[bpras]-[A-Za-z0-9-]{10,} pattern."""
    return "xoxb-" + "1234567890AB-CDEF123456"


def _make_anthropic_style_key() -> str:
    """Build a synthetic string matching the sk-ant-[A-Za-z0-9-]{20,} pattern."""
    return "sk-ant-" + "testkey012345678901234"


PATTERNS_FILE = Path("config/scan_patterns.yaml")


@pytest.fixture
def tmp_storage(tmp_path):
    """Provide a temporary file path for secrets storage."""
    return tmp_path / "secrets.json"


@pytest.fixture
def registry(tmp_storage):
    """Provide a fresh SecretsRegistry."""
    return SecretsRegistry(storage_path=str(tmp_storage))


@pytest.fixture
def scanner(registry):
    """Provide an OutputScanner loaded with production patterns."""
    return OutputScanner(patterns_file=PATTERNS_FILE, secrets_registry=registry)


# -------------------------------------------------------------------------
# API Key Detection
# -------------------------------------------------------------------------
class TestAPIKeyDetection:
    """Tests for detecting various API key formats via YAML patterns."""

    def test_detect_openai_style_key(self, scanner: OutputScanner) -> None:
        """Strings matching the OpenAI key pattern should be detected."""
        text = f"Found: {_make_openai_style_key()}"
        result = scanner.scan(text)
        assert result.blocked is True
        assert result.threat_type == "api_key"

    def test_detect_aws_style_key(self, scanner: OutputScanner) -> None:
        """Strings matching the AWS key pattern should be detected."""
        text = f"Key: {_make_aws_style_key()}"
        result = scanner.scan(text)
        assert result.blocked is True
        assert result.threat_type == "api_key"

    def test_detect_github_style_token(self, scanner: OutputScanner) -> None:
        """Strings matching the GitHub token pattern should be detected."""
        text = f"Token: {_make_github_style_token()}"
        result = scanner.scan(text)
        assert result.blocked is True
        assert result.threat_type == "api_key"

    def test_detect_slack_style_token(self, scanner: OutputScanner) -> None:
        """Strings matching the Slack token pattern should be detected."""
        text = f"Slack: {_make_slack_style_token()}"
        result = scanner.scan(text)
        assert result.blocked is True
        assert result.threat_type == "api_key"

    def test_detect_anthropic_style_key(self, scanner: OutputScanner) -> None:
        """Strings matching the Anthropic key pattern should be detected."""
        text = f"Key: {_make_anthropic_style_key()}"
        result = scanner.scan(text)
        assert result.blocked is True
        assert result.threat_type == "api_key"


# -------------------------------------------------------------------------
# Credit Card Detection
# -------------------------------------------------------------------------
class TestCreditCardDetection:
    """Tests for credit card number detection via regex patterns."""

    def test_detect_visa_pattern(self, scanner: OutputScanner) -> None:
        """16-digit strings starting with 4 should be flagged as Visa."""
        # Synthetic Visa-format number: 4 + 15 digits
        text = "Card: 4111222233334444"
        result = scanner.scan(text)
        assert result.blocked is True
        assert result.threat_type == "credit_card"

    def test_detect_mastercard_pattern(self, scanner: OutputScanner) -> None:
        """16-digit strings starting with 51-55 should be flagged as Mastercard."""
        # Synthetic Mastercard-format number: 51 + 14 digits
        text = "Card: 5111222233334444"
        result = scanner.scan(text)
        assert result.blocked is True
        assert result.threat_type == "credit_card"

    def test_detect_card_with_spaces(self, scanner: OutputScanner) -> None:
        """Credit card patterns with spaces should be detected."""
        text = "Card: 4111 2222 3333 4444"
        result = scanner.scan(text)
        assert result.blocked is True
        assert result.threat_type == "credit_card"

    def test_detect_card_with_dashes(self, scanner: OutputScanner) -> None:
        """Credit card patterns with dashes should be detected."""
        text = "Card: 4111-2222-3333-4444"
        result = scanner.scan(text)
        assert result.blocked is True
        assert result.threat_type == "credit_card"


# -------------------------------------------------------------------------
# Private Key Detection
# -------------------------------------------------------------------------
class TestPrivateKeyDetection:
    """Tests for private key header detection."""

    def test_detect_rsa_private_key_header(self, scanner: OutputScanner) -> None:
        """RSA private key PEM headers should be detected."""
        text = "-----BEGIN RSA PRIVATE KEY-----\nSomeFakeContent\n-----END RSA PRIVATE KEY-----"
        result = scanner.scan(text)
        assert result.blocked is True
        assert result.threat_type == "private_key"

    def test_detect_generic_private_key_header(self, scanner: OutputScanner) -> None:
        """Generic private key PEM headers should be detected."""
        text = "-----BEGIN PRIVATE KEY-----\nSomeFakeContent\n-----END PRIVATE KEY-----"
        result = scanner.scan(text)
        assert result.blocked is True
        assert result.threat_type == "private_key"

    def test_detect_ethereum_style_key(self, scanner: OutputScanner) -> None:
        """64-char hex strings with 0x prefix should be detected."""
        # Synthetic: 0x + 64 hex chars
        text = "Key: 0x" + "ab12cd34" * 8
        result = scanner.scan(text)
        assert result.blocked is True
        assert result.threat_type == "private_key"


# -------------------------------------------------------------------------
# Password / Credential Detection
# -------------------------------------------------------------------------
class TestCredentialDetection:
    """Tests for password and credential pattern detection."""

    def test_detect_password_assignment(self, scanner: OutputScanner) -> None:
        """'password = value' patterns should be detected."""
        text = 'Config: password = MyTestPass123!'
        result = scanner.scan(text)
        assert result.blocked is True
        assert result.threat_type == "password"

    def test_detect_connection_string(self, scanner: OutputScanner) -> None:
        """Database connection strings should be detected."""
        text = "DB: postgres://user:testpass@localhost:5432/mydb"
        result = scanner.scan(text)
        assert result.blocked is True
        assert result.threat_type == "password"

    def test_detect_email_password_combo(self, scanner: OutputScanner) -> None:
        """Email:password combinations should be detected."""
        text = "Creds: testuser@example.com:TestP4ssw0rd"
        result = scanner.scan(text)
        assert result.blocked is True
        assert result.threat_type == "password"


# -------------------------------------------------------------------------
# BIP39 Seed Phrase Detection
# -------------------------------------------------------------------------
class TestBIP39Detection:
    """Tests for crypto seed phrase detection."""

    def test_detect_12_word_seed(self, scanner: OutputScanner) -> None:
        """12 consecutive BIP39 words should be detected."""
        # Use words from the YAML wordlist subset (abandon through annual)
        words = "abandon ability able about above absent absorb abstract absurd abuse access accident"
        text = f"Recovery: {words}"
        result = scanner.scan(text)
        assert result.blocked is True
        assert result.threat_type == "seed_phrase"

    def test_short_bip39_sequence_ignored(self, scanner: OutputScanner) -> None:
        """Fewer than 12 BIP39 words in normal text should NOT trigger."""
        text = "I will abandon the abstract ability to add an account"
        result = scanner.scan(text)
        assert result.blocked is False


# -------------------------------------------------------------------------
# Deobfuscation: Base64, Hex, ROT13, URL-Encoding
# -------------------------------------------------------------------------
class TestDeobfuscation:
    """Tests for detecting secrets hidden via encoding."""

    def test_detect_base64_encoded_secret(self, scanner: OutputScanner) -> None:
        """Secrets encoded in Base64 should be decoded and detected."""
        secret = _make_openai_style_key()
        encoded = base64.b64encode(secret.encode()).decode()
        text = f"Encoded: {encoded}"
        result = scanner.scan(text)
        assert result.blocked is True
        assert result.deobfuscation_method == "base64"

    def test_detect_hex_encoded_secret(self, scanner: OutputScanner) -> None:
        """Secrets encoded in hex should be decoded and detected."""
        secret = _make_aws_style_key()
        encoded = secret.encode().hex()
        text = f"Hex: {encoded}"
        result = scanner.scan(text)
        assert result.blocked is True
        assert result.deobfuscation_method == "hex"

    def test_detect_rot13_encoded_secret(self, scanner: OutputScanner) -> None:
        """Secrets encoded in ROT13 should be decoded and detected."""
        secret = _make_aws_style_key()
        encoded = codecs.encode(secret, "rot_13")
        text = f"Obfuscated: {encoded}"
        result = scanner.scan(text)
        assert result.blocked is True
        assert result.deobfuscation_method == "rot13"

    def test_detect_url_encoded_secret(self, scanner: OutputScanner) -> None:
        """Secrets that are URL-encoded should be decoded and detected."""
        # Use a connection string pattern — the :// and @ get URL-encoded,
        # hiding the pattern from plaintext matching but not from URL decoding.
        secret = "postgres://admin:secretpass@dbhost:5432/prod"
        encoded = urllib.parse.quote(secret, safe="")
        text = f"Data: {encoded}"
        result = scanner.scan(text)
        assert result.blocked is True
        assert result.deobfuscation_method == "url_encoding"


# -------------------------------------------------------------------------
# Registered Secrets from SecretsRegistry
# -------------------------------------------------------------------------
class TestRegisteredSecrets:
    """Tests for detecting secrets registered in the SecretsRegistry."""

    def test_detect_registered_secret(self, scanner: OutputScanner, registry: SecretsRegistry) -> None:
        """Registered custom secrets should be detected in output."""
        registry.add_secret("db_password", "MyCustomS3cretValue!")
        result = scanner.scan("Connecting with MyCustomS3cretValue! now")
        assert result.blocked is True
        assert result.threat_type == "registered_secret"

    def test_registered_secret_not_in_clean_text(self, scanner: OutputScanner, registry: SecretsRegistry) -> None:
        """Registered secrets should not match unrelated text."""
        registry.add_secret("db_password", "MyCustomS3cretValue!")
        result = scanner.scan("Everything is working fine today")
        assert result.blocked is False


# -------------------------------------------------------------------------
# False Positive Avoidance
# -------------------------------------------------------------------------
class TestFalsePositives:
    """Tests ensuring normal text does not trigger false positives."""

    def test_normal_text_passes(self, scanner: OutputScanner) -> None:
        """Normal conversational text should not be blocked."""
        text = "The project is going well. We deployed version 2.3 yesterday."
        result = scanner.scan(text)
        assert result.blocked is False

    def test_skype_not_detected_as_key(self, scanner: OutputScanner) -> None:
        """Short 'sk-' words like 'sk-ype' should not trigger (too short for pattern)."""
        text = "Das Meeting ist um sk-ype geplant"
        result = scanner.scan(text)
        assert result.blocked is False

    def test_short_hex_not_flagged(self, scanner: OutputScanner) -> None:
        """Short hex values in normal code should not be flagged."""
        text = "Color: #ff5733 and status code 0x1A"
        result = scanner.scan(text)
        assert result.blocked is False

    def test_empty_text(self, scanner: OutputScanner) -> None:
        """Empty text should return a clean result."""
        result = scanner.scan("")
        assert result.blocked is False

    def test_normal_numbers_not_credit_card(self, scanner: OutputScanner) -> None:
        """Random digit sequences that don't match card prefixes should pass."""
        text = "Tracking number: 9876543210987654"
        result = scanner.scan(text)
        # Doesn't start with 4 or 51-55, so not matched by Visa/MC patterns
        assert result.threat_type != "credit_card"


# -------------------------------------------------------------------------
# Fake Response Generator
# -------------------------------------------------------------------------
class TestFakeResponseGenerator:
    """Tests for the static fake response generator."""

    def test_fake_response_for_api_key(self) -> None:
        """Fake response for api_key threats should be a JSON-like string."""
        resp = OutputScanner.generate_fake_response("api_key")
        assert "ok" in resp
        assert len(resp) > 0

    def test_fake_response_for_credit_card(self) -> None:
        """Fake response for credit_card threats should be a JSON-like string."""
        resp = OutputScanner.generate_fake_response("credit_card")
        assert "ok" in resp

    def test_fake_response_for_unknown_type(self) -> None:
        """Unknown threat types should still get a generic fake response."""
        resp = OutputScanner.generate_fake_response("unknown_thing")
        assert "ok" in resp
        assert len(resp) > 0


# -------------------------------------------------------------------------
# Rate Limiting & Auto-Lockdown
# -------------------------------------------------------------------------
class TestRateLimitingAndLockdown:
    """Tests for rate limiting and auto-lockdown mechanism."""

    def test_lockdown_after_three_incidents(self, scanner: OutputScanner) -> None:
        """After 3 detections within window, is_locked should be True."""
        scanner.scan(f"A: {_make_openai_style_key()}")
        scanner.scan(f"B: {_make_aws_style_key()}")
        scanner.scan(f"C: {_make_github_style_token()}")
        assert scanner.is_locked is True

    def test_no_lockdown_below_threshold(self, scanner: OutputScanner) -> None:
        """Fewer than 3 detections should not trigger lockdown."""
        scanner.scan(f"A: {_make_openai_style_key()}")
        scanner.scan(f"B: {_make_aws_style_key()}")
        assert scanner.is_locked is False

    def test_lockdown_blocks_all_output(self, scanner: OutputScanner) -> None:
        """Once locked down, even clean text should be blocked."""
        scanner.scan(f"A: {_make_openai_style_key()}")
        scanner.scan(f"B: {_make_aws_style_key()}")
        scanner.scan(f"C: {_make_github_style_token()}")
        assert scanner.is_locked is True

        result = scanner.scan("This is perfectly normal text")
        assert result.blocked is True
        assert result.threat_type == "LOCKDOWN"

    def test_reset_lockdown(self, scanner: OutputScanner) -> None:
        """reset_lockdown should clear the lockdown state."""
        scanner.scan(f"A: {_make_openai_style_key()}")
        scanner.scan(f"B: {_make_aws_style_key()}")
        scanner.scan(f"C: {_make_github_style_token()}")
        assert scanner.is_locked is True

        scanner.reset_lockdown()
        assert scanner.is_locked is False

        result = scanner.scan("Normal text after reset")
        assert result.blocked is False


# -------------------------------------------------------------------------
# LockdownState unit tests
# -------------------------------------------------------------------------
class TestLockdownState:
    """Unit tests for the LockdownState dataclass."""

    def test_initial_state(self) -> None:
        """Fresh LockdownState should not be locked."""
        state = LockdownState()
        assert state.locked is False
        assert state.incidents == []

    def test_record_below_threshold(self) -> None:
        """Recording fewer incidents than max should not lock."""
        state = LockdownState(max_incidents=3)
        state.record_incident()
        state.record_incident()
        assert state.locked is False

    def test_record_at_threshold_locks(self) -> None:
        """Recording max_incidents should trigger lockdown."""
        state = LockdownState(max_incidents=3)
        state.record_incident()
        state.record_incident()
        result = state.record_incident()
        assert result is True
        assert state.locked is True


# -------------------------------------------------------------------------
# ScanResult
# -------------------------------------------------------------------------
class TestScanResult:
    """Tests for ScanResult dataclass."""

    def test_clean_result(self) -> None:
        """A clean ScanResult should not be blocked."""
        result = ScanResult(blocked=False)
        assert result.blocked is False
        assert result.threat_type == ""

    def test_blocked_result(self) -> None:
        """A blocked ScanResult should contain threat info."""
        result = ScanResult(
            blocked=True,
            threat_type="api_key",
            matched_pattern="OpenAI API Key",
        )
        assert result.blocked is True
        assert result.threat_type == "api_key"
        assert result.matched_pattern == "OpenAI API Key"

    def test_deobfuscation_method_recorded(self) -> None:
        """Deobfuscation method should be recorded in result."""
        result = ScanResult(
            blocked=True,
            threat_type="api_key",
            deobfuscation_method="base64",
        )
        assert result.deobfuscation_method == "base64"


# -------------------------------------------------------------------------
# Scanner without patterns file
# -------------------------------------------------------------------------
class TestScannerWithoutPatterns:
    """Tests for scanner behavior when no pattern file is loaded."""

    def test_no_patterns_file_no_crash(self) -> None:
        """Scanner should work without a patterns file (no detections)."""
        scanner = OutputScanner(patterns_file=None)
        result = scanner.scan("some random text")
        assert result.blocked is False

    def test_nonexistent_patterns_file(self) -> None:
        """Scanner should handle a non-existent patterns file gracefully."""
        scanner = OutputScanner(patterns_file=Path("nonexistent.yaml"))
        result = scanner.scan("some random text")
        assert result.blocked is False
