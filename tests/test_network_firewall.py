"""Tests for the Moltr network firewall.

Tests domain allowlist/blocklist, wildcard matching, IP blocking,
DNS rebinding prevention, URL parsing, and payload inspection.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from src.validators.network_firewall import NetworkFirewall, FirewallVerdict


DOMAINS_FILE = Path("config/allowlists/domains.yaml")


@pytest.fixture
def firewall():
    """Provide a fresh NetworkFirewall loaded with production config."""
    return NetworkFirewall(domains_file=DOMAINS_FILE)


# -------------------------------------------------------------------------
# Allowed domains
# -------------------------------------------------------------------------
class TestAllowedDomains:
    """Tests that permitted domains pass the firewall."""

    def test_bybit_testnet(self, firewall: NetworkFirewall) -> None:
        """api-testnet.bybit.com should be allowed."""
        verdict = firewall.check("https://api-testnet.bybit.com/v5/order")
        assert verdict.allowed is True

    def test_openrouter(self, firewall: NetworkFirewall) -> None:
        """openrouter.ai should be allowed."""
        verdict = firewall.check("https://openrouter.ai/api/v1/chat")
        assert verdict.allowed is True

    def test_telegram(self, firewall: NetworkFirewall) -> None:
        """api.telegram.org should be allowed."""
        verdict = firewall.check("https://api.telegram.org/bot123/sendMessage")
        assert verdict.allowed is True

    def test_pypi(self, firewall: NetworkFirewall) -> None:
        """pypi.org should be allowed."""
        verdict = firewall.check("https://pypi.org/simple/requests/")
        assert verdict.allowed is True

    def test_pythonhosted(self, firewall: NetworkFirewall) -> None:
        """files.pythonhosted.org should be allowed."""
        verdict = firewall.check("https://files.pythonhosted.org/packages/some-package.whl")
        assert verdict.allowed is True

    def test_github(self, firewall: NetworkFirewall) -> None:
        """github.com should be allowed."""
        verdict = firewall.check("https://github.com/user/repo")
        assert verdict.allowed is True

    def test_raw_githubusercontent(self, firewall: NetworkFirewall) -> None:
        """raw.githubusercontent.com should be allowed."""
        verdict = firewall.check("https://raw.githubusercontent.com/user/repo/main/file.txt")
        assert verdict.allowed is True

    def test_npmjs(self, firewall: NetworkFirewall) -> None:
        """registry.npmjs.org should be allowed."""
        verdict = firewall.check("https://registry.npmjs.org/express")
        assert verdict.allowed is True


# -------------------------------------------------------------------------
# Blocked domains
# -------------------------------------------------------------------------
class TestBlockedDomains:
    """Tests that non-allowed domains are blocked."""

    def test_unknown_domain_blocked(self, firewall: NetworkFirewall) -> None:
        """Domains not in the allowlist should be blocked."""
        verdict = firewall.check("https://evil-server.com/exfiltrate")
        assert verdict.allowed is False

    def test_pastebin_blocked(self, firewall: NetworkFirewall) -> None:
        """pastebin.com should be explicitly blocked."""
        verdict = firewall.check("https://pastebin.com/raw/abc123")
        assert verdict.allowed is False

    def test_ngrok_blocked(self, firewall: NetworkFirewall) -> None:
        """ngrok.io should be explicitly blocked."""
        verdict = firewall.check("https://abc123.ngrok.io/tunnel")
        assert verdict.allowed is False

    def test_webhook_site_blocked(self, firewall: NetworkFirewall) -> None:
        """webhook.site should be explicitly blocked."""
        verdict = firewall.check("https://webhook.site/some-uuid")
        assert verdict.allowed is False

    def test_transfer_sh_blocked(self, firewall: NetworkFirewall) -> None:
        """transfer.sh should be explicitly blocked."""
        verdict = firewall.check("https://transfer.sh/upload")
        assert verdict.allowed is False

    def test_metadata_endpoint_blocked(self, firewall: NetworkFirewall) -> None:
        """Cloud metadata endpoint 169.254.169.254 should be blocked."""
        verdict = firewall.check("http://169.254.169.254/latest/meta-data/")
        assert verdict.allowed is False


# -------------------------------------------------------------------------
# Wildcard matching
# -------------------------------------------------------------------------
class TestWildcardMatching:
    """Tests for wildcard domain support (*.example.com)."""

    def test_wildcard_github_subdomain(self, firewall: NetworkFirewall) -> None:
        """*.github.com should match any subdomain of github.com."""
        verdict = firewall.check("https://api.github.com/repos")
        assert verdict.allowed is True

    def test_wildcard_openrouter_subdomain(self, firewall: NetworkFirewall) -> None:
        """*.openrouter.ai should match subdomains."""
        verdict = firewall.check("https://api.openrouter.ai/v1/models")
        assert verdict.allowed is True

    def test_wildcard_does_not_match_base(self, firewall: NetworkFirewall) -> None:
        """*.example.com should NOT match example.com itself (only subdomains)."""
        # We have github.com explicitly, so test with a hypothetical
        fw = NetworkFirewall()
        fw._allowed_domains = []
        fw._allowed_wildcards = [".onlywild.com"]
        fw._blocked_domains = []
        fw._blocked_wildcards = []
        verdict = fw.check("https://onlywild.com/path")
        assert verdict.allowed is False

    def test_wildcard_ngrok_blocked(self, firewall: NetworkFirewall) -> None:
        """*.ngrok.io in blocklist should block all subdomains."""
        verdict = firewall.check("https://random-tunnel.ngrok.io/data")
        assert verdict.allowed is False


# -------------------------------------------------------------------------
# Direct IP access blocking
# -------------------------------------------------------------------------
class TestIPBlocking:
    """Tests that direct IP access is always blocked."""

    def test_public_ip_blocked(self, firewall: NetworkFirewall) -> None:
        """Direct access to a public IP should be blocked."""
        verdict = firewall.check("http://93.184.216.34/page")
        assert verdict.allowed is False
        assert "ip" in verdict.reason.lower()

    def test_ip_with_port_blocked(self, firewall: NetworkFirewall) -> None:
        """IP:port access should be blocked."""
        verdict = firewall.check("http://93.184.216.34:8080/api")
        assert verdict.allowed is False

    def test_ipv6_blocked(self, firewall: NetworkFirewall) -> None:
        """IPv6 addresses should be blocked."""
        verdict = firewall.check("http://[::1]/path")
        assert verdict.allowed is False


# -------------------------------------------------------------------------
# DNS rebinding / private network blocking
# -------------------------------------------------------------------------
class TestDNSRebinding:
    """Tests for blocking private/local IP ranges."""

    def test_localhost_blocked(self, firewall: NetworkFirewall) -> None:
        """localhost should be blocked."""
        verdict = firewall.check("http://localhost/admin")
        assert verdict.allowed is False

    def test_127_0_0_1_blocked(self, firewall: NetworkFirewall) -> None:
        """127.0.0.1 should be blocked."""
        verdict = firewall.check("http://127.0.0.1:8080/")
        assert verdict.allowed is False

    def test_0_0_0_0_blocked(self, firewall: NetworkFirewall) -> None:
        """0.0.0.0 should be blocked."""
        verdict = firewall.check("http://0.0.0.0/")
        assert verdict.allowed is False

    def test_10_x_blocked(self, firewall: NetworkFirewall) -> None:
        """10.x.x.x private range should be blocked."""
        verdict = firewall.check("http://10.0.0.1/internal")
        assert verdict.allowed is False

    def test_172_16_blocked(self, firewall: NetworkFirewall) -> None:
        """172.16.x.x private range should be blocked."""
        verdict = firewall.check("http://172.16.0.1/internal")
        assert verdict.allowed is False

    def test_192_168_blocked(self, firewall: NetworkFirewall) -> None:
        """192.168.x.x private range should be blocked."""
        verdict = firewall.check("http://192.168.1.1/router")
        assert verdict.allowed is False

    def test_metadata_ip_blocked(self, firewall: NetworkFirewall) -> None:
        """169.254.169.254 (cloud metadata) should be blocked."""
        verdict = firewall.check("http://169.254.169.254/latest/meta-data/")
        assert verdict.allowed is False


# -------------------------------------------------------------------------
# URL parsing
# -------------------------------------------------------------------------
class TestURLParsing:
    """Tests for correct URL parsing with ports, paths, and query strings."""

    def test_url_with_port(self, firewall: NetworkFirewall) -> None:
        """URLs with ports should extract the domain correctly."""
        verdict = firewall.check("https://pypi.org:443/simple/")
        assert verdict.allowed is True

    def test_url_with_path(self, firewall: NetworkFirewall) -> None:
        """URLs with long paths should extract the domain correctly."""
        verdict = firewall.check("https://github.com/user/repo/tree/main/src/file.py")
        assert verdict.allowed is True

    def test_url_with_query(self, firewall: NetworkFirewall) -> None:
        """URLs with query parameters should extract the domain correctly."""
        verdict = firewall.check("https://pypi.org/search/?q=requests&o=")
        assert verdict.allowed is True

    def test_bare_domain(self, firewall: NetworkFirewall) -> None:
        """Bare domain without protocol should still work."""
        verdict = firewall.check("github.com")
        assert verdict.allowed is True

    def test_domain_with_trailing_slash(self, firewall: NetworkFirewall) -> None:
        """Domain with trailing slash should work."""
        verdict = firewall.check("https://github.com/")
        assert verdict.allowed is True


# -------------------------------------------------------------------------
# Payload inspection (large payloads > 1KB forwarded to OutputScanner)
# -------------------------------------------------------------------------
class TestPayloadInspection:
    """Tests for large payload inspection."""

    def test_small_payload_not_inspected(self, firewall: NetworkFirewall) -> None:
        """Payloads under 1KB should not be forwarded to scanner."""
        verdict = firewall.check("https://github.com/api", payload="small data")
        assert verdict.allowed is True

    def test_large_payload_inspected_clean(self, firewall: NetworkFirewall) -> None:
        """Large clean payloads should pass after inspection."""
        large_payload = "x" * 2000  # 2KB of harmless data
        verdict = firewall.check("https://github.com/api", payload=large_payload)
        assert verdict.allowed is True

    def test_large_payload_with_secret_blocked(self, firewall: NetworkFirewall) -> None:
        """Large payloads containing secrets should be blocked."""
        # Create a firewall with a mock output scanner that flags secrets
        mock_scanner = MagicMock()
        mock_result = MagicMock()
        mock_result.blocked = True
        mock_result.threat_type = "api_key"
        mock_scanner.scan.return_value = mock_result

        fw = NetworkFirewall(domains_file=DOMAINS_FILE, output_scanner=mock_scanner)
        large_payload = "x" * 2000
        verdict = fw.check("https://github.com/api", payload=large_payload)
        assert verdict.allowed is False
        assert "payload" in verdict.reason.lower()


# -------------------------------------------------------------------------
# FirewallVerdict
# -------------------------------------------------------------------------
class TestFirewallVerdict:
    """Tests for FirewallVerdict dataclass."""

    def test_allowed_verdict(self) -> None:
        """An allowed verdict should report correctly."""
        v = FirewallVerdict(allowed=True, domain="github.com", reason="Allowed", matched_rule="github.com")
        assert v.allowed is True
        assert v.domain == "github.com"

    def test_blocked_verdict(self) -> None:
        """A blocked verdict should contain reason."""
        v = FirewallVerdict(allowed=False, domain="evil.com", reason="Not in allowlist")
        assert v.allowed is False
        assert "evil.com" in v.domain

    def test_default_verdict_is_blocked(self) -> None:
        """Default FirewallVerdict should be blocked."""
        v = FirewallVerdict()
        assert v.allowed is False
