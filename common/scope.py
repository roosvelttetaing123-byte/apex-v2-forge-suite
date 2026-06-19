"""Scope enforcer — blocks all out-of-scope targets before any request is sent."""
from __future__ import annotations

import ipaddress
import logging
import re
from urllib.parse import urlparse

log = logging.getLogger(__name__)


class ScopeViolation(Exception):
    """Raised when a target is outside the defined scope."""


class Scope:
    """Hard scope enforcer. All modules must call check() before any outbound action."""

    def __init__(
        self,
        targets: list[str],
        excluded: list[str] | None = None,
        strict: bool = True,
    ) -> None:
        """Initialize scope with allowed targets and optional exclusions.

        Args:
            targets:  List of in-scope IPs, CIDRs, domains, or URLs.
            excluded: List of explicitly excluded targets.
            strict:   If True, raise on violation. If False, return bool only.
        """
        self.strict = strict
        self._networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._domains:  list[str] = []
        self._excluded_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._excluded_domains:  list[str] = []

        for t in targets:
            self._add_target(t, self._networks, self._domains)
        for e in (excluded or []):
            self._add_target(e, self._excluded_networks, self._excluded_domains)

    def _add_target(
        self,
        target: str,
        networks: list,
        domains: list,
    ) -> None:
        """Parse target into network or domain and add to respective list."""
        target = target.strip()
        if not target:
            return
        # Try CIDR / bare IP first — before URL-parsing which strips the prefix length
        if "://" not in target:
            try:
                networks.append(ipaddress.ip_network(target, strict=False))
                return
            except ValueError:
                pass
        # URL or domain target
        parsed = urlparse(target if "://" in target else f"https://{target}")
        host = parsed.hostname or target
        try:
            networks.append(ipaddress.ip_network(host, strict=False))
        except ValueError:
            domains.append(host.lower().lstrip("*."))

    def check(self, target: str) -> bool:
        """Check whether a target is in scope.

        Args:
            target: IP address, hostname, or URL to check.

        Returns:
            True if in scope.

        Raises:
            ScopeViolation: If strict=True and target is out of scope.
        """
        parsed = urlparse(target if "://" in target else f"https://{target}")
        host = (parsed.hostname or target).lower()

        in_scope = self._is_allowed(host)

        if in_scope and self._is_excluded(host):
            self._handle_violation(target, "explicitly excluded")
            return False

        if not in_scope:
            self._handle_violation(target, "not in scope")
            return False

        return True

    def _is_allowed(self, host: str) -> bool:
        """Return True if host matches any in-scope entry."""
        if not self._networks and not self._domains:
            return True  # No scope defined = allow all (for single-target mode)
        return self._matches_ip(host, self._networks) or self._matches_domain(host, self._domains)

    def _is_excluded(self, host: str) -> bool:
        """Return True if host matches any excluded entry."""
        return self._matches_ip(host, self._excluded_networks) or \
               self._matches_domain(host, self._excluded_domains)

    def _matches_ip(
        self,
        host: str,
        networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network],
    ) -> bool:
        try:
            addr = ipaddress.ip_address(host)
            return any(addr in net for net in networks)
        except ValueError:
            return False

    def _matches_domain(self, host: str, domains: list[str]) -> bool:
        host = host.lower()
        for d in domains:
            if host == d or host.endswith(f".{d}"):
                return True
        return False

    def _handle_violation(self, target: str, reason: str) -> None:
        log.warning("OUT_OF_SCOPE: %s (%s)", target, reason, extra={"target": target})
        if self.strict:
            raise ScopeViolation(f"Target out of scope: {target} ({reason})")

    def check_url(self, url: str) -> bool:
        """Convenience wrapper for URL targets."""
        return self.check(url)

    def check_ip(self, ip: str) -> bool:
        """Convenience wrapper for IP address targets."""
        return self.check(ip)


class TestScope:
    """Unit tests for scope enforcer."""

    def test_cidr_in_scope(self) -> None:
        s = Scope(["10.0.0.0/24"])
        assert s.check("10.0.0.1") is True
        assert s.check("10.0.0.255") is True

    def test_cidr_out_of_scope(self) -> None:
        s = Scope(["10.0.0.0/24"], strict=False)
        assert s.check("10.0.1.1") is False

    def test_domain_in_scope(self) -> None:
        s = Scope(["example.com"])
        assert s.check("example.com") is True
        assert s.check("sub.example.com") is True

    def test_domain_out_of_scope(self) -> None:
        s = Scope(["example.com"], strict=False)
        assert s.check("evil.com") is False

    def test_exclusion(self) -> None:
        s = Scope(["10.0.0.0/24"], excluded=["10.0.0.1"], strict=False)
        assert s.check("10.0.0.1") is False
        assert s.check("10.0.0.2") is True

    def test_strict_raises(self) -> None:
        s = Scope(["10.0.0.0/24"], strict=True)
        try:
            s.check("192.168.1.1")
            assert False, "Should have raised"
        except ScopeViolation:
            pass

    def test_empty_scope_allows_all(self) -> None:
        s = Scope([])
        assert s.check("1.2.3.4") is True
