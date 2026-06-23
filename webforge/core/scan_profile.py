"""Scan profiles — predefined module sets for common scan scenarios.

Usage:
    python webforge.py --target https://target.com --profile quick
    python webforge.py --target https://target.com --profile api
    python webforge.py --target https://target.com --profile compliance
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ScanProfile:
    """Canned scan configuration — module list + recommended settings."""

    name: str
    description: str
    modules: list[str]
    max_workers: int = 10
    rate_limit: float = 10.0
    verify_findings: bool = True
    browser_render: bool = False
    estimated_minutes: str = "varies"
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "modules": self.modules,
            "max_workers": self.max_workers,
            "rate_limit": self.rate_limit,
            "verify_findings": self.verify_findings,
            "browser_render": self.browser_render,
            "estimated_minutes": self.estimated_minutes,
            "tags": self.tags,
        }


# ── Profile definitions ──────────────────────────────────────────────────────

PROFILES: dict[str, ScanProfile] = {
    "quick": ScanProfile(
        name="quick",
        description=(
            "Fast triage scan — SSL/TLS, security headers, critical injection "
            "checks, and git exposure. No fuzzing, no brute-force."
        ),
        modules=[
            # Recon (lightweight)
            "tech_detect", "robots_sitemap", "git_exposure",
            # SSL
            "ssl_audit", "cert_inspect", "hsts_check",
            # Headers
            "header_audit", "cors_check", "csp_audit", "cookie_audit",
            "clickjacking",
            # Top injection (error-based only — fast)
            "sqli_scanner", "xss_scanner", "ssti_scanner",
        ],
        max_workers=15,
        rate_limit=20.0,
        verify_findings=False,  # Skip FPReducer re-probes for speed
        estimated_minutes="5–10",
        tags=["fast", "triage", "ci-friendly"],
    ),

    "standard": ScanProfile(
        name="standard",
        description=(
            "Full blackbox assessment — all recon, headers, injection, auth, "
            "access control, API, file ops, and business logic. Excludes "
            "whitebox source analysis."
        ),
        modules=[
            # Phase 1 — Recon
            "tech_detect", "cms_detect", "dir_fuzzer", "vhost_enum",
            "js_analyzer", "link_crawler", "robots_sitemap", "api_discover",
            "param_discover", "subdomain_takeover", "git_exposure",
            # Phase 2 — SSL
            "ssl_audit", "cert_inspect", "hsts_check",
            # Phase 3 — Headers
            "header_audit", "cors_check", "csp_audit", "cookie_audit",
            "sri_check", "clickjacking",
            # Phase 4 — Injection
            "sqli_scanner", "xss_scanner", "xxe_scanner", "ssti_scanner",
            "cmd_inject", "ldap_inject", "nosql_inject", "jsonp_inject",
            "host_header_inject", "crlf_inject", "parameter_pollution",
            "log4shell_scanner",
            # Phase 5 — Auth
            "session_audit", "password_policy", "jwt_audit", "oauth_check",
            "login_brute", "mfa_bypass", "totp_bypass",
            # Phase 6 — Access Control
            "idor_scanner", "priv_esc", "path_traversal", "forced_browse",
            "403_bypass", "mass_assignment",
            # Phase 7 — API
            "rest_audit", "graphql_audit", "soap_audit", "api_rate_check",
            # Phase 8 — File
            "ssrf_scanner", "lfi_rfi", "upload_bypass",
            # Phase 9 — Business Logic
            "open_redirect", "price_tamper", "workflow_bypass", "race_condition",
            # Phase 10 — Advanced
            "websocket_audit", "http2_audit", "http_smuggling", "cache_poison",
            "cache_deception", "prototype_poll", "deserialization",
            "email_security", "account_takeover", "zip_slip",
        ],
        max_workers=10,
        rate_limit=10.0,
        estimated_minutes="30–60",
        tags=["full", "blackbox", "pentest"],
    ),

    "full": ScanProfile(
        name="full",
        description=(
            "Everything — standard + whitebox source analysis. Requires "
            "--source path and typically --mode whitebox."
        ),
        modules=[
            # All standard modules
            "tech_detect", "cms_detect", "dir_fuzzer", "vhost_enum",
            "js_analyzer", "link_crawler", "robots_sitemap", "api_discover",
            "param_discover", "subdomain_takeover", "git_exposure",
            "ssl_audit", "cert_inspect", "hsts_check",
            "header_audit", "cors_check", "csp_audit", "cookie_audit",
            "sri_check", "clickjacking",
            "sqli_scanner", "xss_scanner", "xxe_scanner", "ssti_scanner",
            "cmd_inject", "ldap_inject", "nosql_inject", "jsonp_inject",
            "host_header_inject", "crlf_inject", "parameter_pollution",
            "log4shell_scanner",
            "session_audit", "password_policy", "jwt_audit", "oauth_check",
            "login_brute", "mfa_bypass", "totp_bypass",
            "idor_scanner", "priv_esc", "path_traversal", "forced_browse",
            "403_bypass", "mass_assignment",
            "rest_audit", "graphql_audit", "soap_audit", "api_rate_check",
            "ssrf_scanner", "lfi_rfi", "upload_bypass",
            "open_redirect", "price_tamper", "workflow_bypass", "race_condition",
            "websocket_audit", "http2_audit", "http_smuggling", "cache_poison",
            "cache_deception", "prototype_poll", "deserialization",
            "email_security", "account_takeover", "zip_slip",
            # Phase 11 — Whitebox
            "source_audit", "secret_scan", "dep_audit", "config_audit",
            "code_flow",
        ],
        max_workers=8,
        rate_limit=8.0,
        estimated_minutes="60–120",
        tags=["exhaustive", "whitebox", "audit"],
    ),

    "api": ScanProfile(
        name="api",
        description=(
            "API-focused assessment — REST, GraphQL, SOAP auditing plus "
            "injection, auth, and rate limiting. Ideal for headless services."
        ),
        modules=[
            "tech_detect", "api_discover", "param_discover",
            "ssl_audit", "cert_inspect", "hsts_check",
            "header_audit", "cors_check", "csp_audit", "cookie_audit",
            "sqli_scanner", "xss_scanner", "xxe_scanner", "ssti_scanner",
            "cmd_inject", "nosql_inject", "jsonp_inject",
            "host_header_inject", "crlf_inject", "log4shell_scanner",
            "session_audit", "jwt_audit", "oauth_check",
            "idor_scanner", "mass_assignment",
            "rest_audit", "graphql_audit", "soap_audit", "api_rate_check",
            "ssrf_scanner",
        ],
        max_workers=10,
        rate_limit=15.0,
        estimated_minutes="15–30",
        tags=["api", "rest", "graphql", "soap"],
    ),

    "compliance": ScanProfile(
        name="compliance",
        description=(
            "Compliance-oriented scan — SSL/TLS, security headers, cookie "
            "audit, config audit, and secret scanning. Maps to PCI-DSS, "
            "OWASP Top 10, and ISO 27001."
        ),
        modules=[
            "tech_detect", "robots_sitemap",
            "ssl_audit", "cert_inspect", "hsts_check",
            "header_audit", "cors_check", "csp_audit", "cookie_audit",
            "sri_check", "clickjacking",
            "session_audit", "password_policy",
            "secret_scan", "config_audit", "dep_audit",
        ],
        max_workers=5,
        rate_limit=5.0,
        estimated_minutes="10–20",
        tags=["compliance", "pci-dss", "owasp", "iso27001"],
    ),

    "stealth": ScanProfile(
        name="stealth",
        description=(
            "Low-and-slow — reduced rate, minimal active probing. "
            "Passive recon + lightweight header/SSL checks only. "
            "Designed to fly under WAF/IDS radar."
        ),
        modules=[
            "tech_detect", "robots_sitemap", "js_analyzer", "git_exposure",
            "ssl_audit", "cert_inspect", "hsts_check",
            "header_audit", "cors_check", "csp_audit", "cookie_audit",
        ],
        max_workers=2,
        rate_limit=1.0,
        verify_findings=False,  # Fewer requests = stealthier
        estimated_minutes="15–30",
        tags=["stealth", "low-profile", "evasive"],
    ),
}


def get_profile(name: str) -> ScanProfile:
    """Return a profile by name or raise ValueError."""
    profile = PROFILES.get(name.lower())
    if profile is None:
        available = ", ".join(sorted(PROFILES.keys()))
        raise ValueError(f"Unknown scan profile '{name}'. Available: {available}")
    return profile


def list_profiles() -> list[dict[str, Any]]:
    """Return all profiles as dicts for CLI listing or API response."""
    return [p.to_dict() for p in PROFILES.values()]


def describe_profiles() -> None:
    """Print profiles to stdout for --list-profiles."""
    print(f"\nWebForge Scan Profiles ({len(PROFILES)} available)")
    print("=" * 60)
    for name, prof in PROFILES.items():
        verify_tag = "✅" if prof.verify_findings else "⚡"
        print(f"\n  {name.upper()} — {prof.description[:80]}...")
        print(f"    Modules: {len(prof.modules)} | Workers: {prof.max_workers} "
              f"| Rate: {prof.rate_limit} req/s | ETA: {prof.estimated_minutes} | Verify: {verify_tag}")
        print(f"    Tags: {', '.join(prof.tags)}")


def validate_profile(profile: ScanProfile, available_modules: set[str]) -> list[str]:
    """Return list of module names in the profile that don't exist in the registry.

    Call this at startup to catch typos in profile definitions.
    """
    return [m for m in profile.modules if m not in available_modules]


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestScanProfile:
    def test_get_profile(self) -> None:
        p = get_profile("quick")
        assert p.name == "quick"
        assert len(p.modules) >= 10

    def test_all_profiles_have_modules(self) -> None:
        for name, prof in PROFILES.items():
            assert len(prof.modules) > 0, f"Profile '{name}' has no modules"

    def test_unknown_profile_raises(self) -> None:
        try:
            get_profile("nonexistent")
            assert False, "Should have raised"
        except ValueError:
            pass

    def test_serialization(self) -> None:
        data = get_profile("api").to_dict()
        assert "modules" in data
        assert isinstance(data["modules"], list)
        assert "verify_findings" in data

    def test_stealth_low_rate(self) -> None:
        p = get_profile("stealth")
        assert p.rate_limit <= 2.0
        assert p.max_workers <= 3

    def test_list_profiles(self) -> None:
        profiles = list_profiles()
        assert len(profiles) >= 5
        assert all("name" in p for p in profiles)

    def test_quick_skips_verification(self) -> None:
        p = get_profile("quick")
        assert p.verify_findings is False

    def test_standard_verifies(self) -> None:
        p = get_profile("standard")
        assert p.verify_findings is True

    def test_stealth_skips_verification(self) -> None:
        p = get_profile("stealth")
        assert p.verify_findings is False

    def test_validate_profile_clean(self) -> None:
        p = get_profile("quick")
        available = set(p.modules)  # All modules exist in themselves
        assert validate_profile(p, available) == []

    def test_validate_profile_catches_typo(self) -> None:
        from dataclasses import replace
        p = get_profile("quick")
        bad = replace(p, modules=[*p.modules, "nonexistent_module"])
        available = set(p.modules)
        invalid = validate_profile(bad, available)
        assert "nonexistent_module" in invalid
