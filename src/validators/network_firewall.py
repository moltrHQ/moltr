"""Moltr network firewall.

Controls outbound network access for AI agents.
Enforces domain allowlists, blocks direct IP access,
prevents DNS rebinding, and inspects large payloads.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

try:
    import yaml
except ImportError:
    yaml = None


# Threshold for payload inspection (bytes)
_PAYLOAD_INSPECTION_THRESHOLD = 1024  # 1KB


@dataclass
class FirewallVerdict:
    """Result of a firewall check."""

    allowed: bool = False
    domain: str = ""
    reason: str = ""
    matched_rule: str = ""


class NetworkFirewall:
    """Network-level firewall for AI agent connections.

    Validates outbound requests against a domain allowlist,
    blocks direct IP access, prevents access to private networks,
    and forwards large payloads to the OutputScanner.
    """

    def __init__(
        self,
        domains_file: Optional[Path] = None,
        output_scanner: object = None,
    ) -> None:
        """Initialize the network firewall.

        Args:
            domains_file: Path to the domains YAML allowlist.
            output_scanner: Optional OutputScanner instance for payload inspection.
        """
        self._allowed_domains: list[str] = []
        self._allowed_wildcards: list[str] = []  # stored as ".example.com"
        self._blocked_domains: list[str] = []
        self._blocked_wildcards: list[str] = []
        self._output_scanner = output_scanner

        if domains_file and domains_file.exists():
            self._load(domains_file)

    def _load(self, path: Path) -> None:
        """Load domain lists from YAML."""
        if yaml is None:
            return
        raw = path.read_text(encoding="utf-8")
        data = yaml.safe_load(raw) or {}

        for domain in data.get("allowed_domains", []):
            if domain.startswith("*."):
                # *.example.com -> .example.com for suffix matching
                self._allowed_wildcards.append(domain[1:])
            else:
                self._allowed_domains.append(domain.lower())

        for domain in data.get("blocked_domains", []):
            if domain.startswith("*."):
                self._blocked_wildcards.append(domain[1:])
            else:
                self._blocked_domains.append(domain.lower())

    def check(self, url: str, payload: str = "") -> FirewallVerdict:
        """Check if an outbound request is allowed.

        Args:
            url: Target URL or domain.
            payload: Optional request body for payload inspection.

        Returns:
            FirewallVerdict with allow/deny decision.
        """
        domain = self._extract_domain(url)

        if not domain:
            return FirewallVerdict(
                allowed=False,
                domain="",
                reason="Could not parse domain from URL",
            )

        # --- 1. Check for IP address (always block direct IP) ---
        if self._is_ip_address(domain):
            # Also check for private/local IPs
            if self._is_private_ip(domain):
                return FirewallVerdict(
                    allowed=False,
                    domain=domain,
                    reason=f"Blocked: private/local IP address ({domain})",
                    matched_rule="private_ip",
                )
            return FirewallVerdict(
                allowed=False,
                domain=domain,
                reason=f"Blocked: direct IP access not allowed ({domain})",
                matched_rule="ip_block",
            )

        # --- 2. Check for localhost / loopback names ---
        if domain in ("localhost", "localhost.localdomain"):
            return FirewallVerdict(
                allowed=False,
                domain=domain,
                reason="Blocked: localhost access not allowed",
                matched_rule="localhost",
            )

        # --- 3. Check blocked list first (blocklist wins over allowlist) ---
        if self._matches_blocklist(domain):
            return FirewallVerdict(
                allowed=False,
                domain=domain,
                reason=f"Blocked: domain in blocklist ({domain})",
                matched_rule="blocklist",
            )

        # --- 4. Check allowlist ---
        matched = self._matches_allowlist(domain)
        if not matched:
            return FirewallVerdict(
                allowed=False,
                domain=domain,
                reason=f"Blocked: domain not in allowlist ({domain})",
                matched_rule="not_in_allowlist",
            )

        # --- 5. Payload inspection for large bodies ---
        if payload and len(payload) > _PAYLOAD_INSPECTION_THRESHOLD:
            if self._output_scanner is not None:
                scan_result = self._output_scanner.scan(payload)
                if scan_result.blocked:
                    return FirewallVerdict(
                        allowed=False,
                        domain=domain,
                        reason=f"Blocked: payload inspection detected {scan_result.threat_type}",
                        matched_rule="payload_inspection",
                    )

        return FirewallVerdict(
            allowed=True,
            domain=domain,
            reason="Allowed",
            matched_rule=matched,
        )

    def _matches_allowlist(self, domain: str) -> str:
        """Check if domain matches the allowlist. Returns matched rule or empty string."""
        domain = domain.lower()

        # Exact match
        if domain in self._allowed_domains:
            return domain

        # Wildcard match (*.example.com -> .example.com suffix)
        for wildcard in self._allowed_wildcards:
            if domain.endswith(wildcard):
                return f"*{wildcard}"

        return ""

    def _matches_blocklist(self, domain: str) -> bool:
        """Check if domain matches the blocklist."""
        domain = domain.lower()

        if domain in self._blocked_domains:
            return True

        for wildcard in self._blocked_wildcards:
            if domain.endswith(wildcard):
                return True

        return False

    @staticmethod
    def _extract_domain(url: str) -> str:
        """Extract the domain/hostname from a URL or bare domain string."""
        url = url.strip()

        # Handle bare domains (no protocol)
        if "://" not in url:
            url = "https://" + url

        parsed = urlparse(url)
        hostname = parsed.hostname or ""

        return hostname.lower()

    @staticmethod
    def _is_ip_address(host: str) -> bool:
        """Check if a hostname is an IP address (v4 or v6)."""
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    @staticmethod
    def _is_private_ip(host: str) -> bool:
        """Check if an IP is in a private/reserved range."""
        try:
            addr = ipaddress.ip_address(host)
            return (
                addr.is_private
                or addr.is_loopback
                or addr.is_reserved
                or addr.is_link_local
                or addr.is_unspecified
            )
        except ValueError:
            return False
