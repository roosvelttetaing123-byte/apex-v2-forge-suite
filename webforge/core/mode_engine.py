"""Mode engine — selects correct module set and phase order per scan mode."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

PHASES: list[tuple[int, str, list[str]]] = [
    (1,  "Reconnaissance",    ["tech_detect","cms_detect","dir_fuzzer","vhost_enum","js_analyzer",
                               "link_crawler","robots_sitemap","api_discover","param_discover",
                               "subdomain_takeover","git_exposure"]),
    (2,  "SSL/TLS Audit",     ["ssl_audit","cert_inspect","hsts_check"]),
    (3,  "Security Headers",  ["header_audit","cors_check","csp_audit","cookie_audit","sri_check","clickjacking"]),
    (4,  "Injection",         ["sqli_scanner","xss_scanner","xxe_scanner","ssti_scanner","cmd_inject",
                               "ldap_inject","nosql_inject","jsonp_inject","host_header_inject",
                               "crlf_inject","parameter_pollution","log4shell_scanner"]),
    (5,  "Authentication",    ["session_audit","password_policy","jwt_audit","oauth_check",
                               "login_brute","mfa_bypass","totp_bypass"]),
    (6,  "Access Control",    ["idor_scanner","priv_esc","path_traversal","forced_browse",
                               "403_bypass","mass_assignment"]),
    (7,  "API Security",      ["rest_audit","graphql_audit","soap_audit","api_rate_check"]),
    (8,  "File Operations",   ["ssrf_scanner","lfi_rfi","upload_bypass"]),
    (9,  "Business Logic",    ["open_redirect","price_tamper","workflow_bypass","race_condition"]),
    (10, "Advanced Attacks",  ["websocket_audit","http2_audit","http_smuggling","cache_poison",
                               "cache_deception","prototype_poll","deserialization","email_security",
                               "account_takeover","zip_slip"]),
    (11, "Whitebox Analysis", ["source_audit","secret_scan","dep_audit","config_audit","code_flow"]),
    (12, "Reporting",         ["html_report","pdf_report","json_export","csv_export"]),
]

# Modules requiring authenticated session
AUTH_REQUIRED = {
    "idor_scanner","priv_esc","forced_browse","rest_audit","graphql_audit",
    "api_rate_check","price_tamper","workflow_bypass","race_condition","mass_assignment",
}

# Modules only for whitebox mode
WHITEBOX_ONLY = {"source_audit","secret_scan","dep_audit","config_audit","code_flow"}

# Module → confirm gate required
CONFIRM_GATE_MODULES = {"login_brute","upload_bypass","race_condition"}


@dataclass
class PhaseConfig:
    number:   int
    name:     str
    modules:  list[str]
    enabled:  bool = True


def get_phases(
    mode: str,
    include_modules: list[str] | None = None,
    skip_modules: list[str] | None = None,
    has_session: bool = False,
) -> list[PhaseConfig]:
    """Build the ordered list of phases for the given mode.

    Args:
        mode:            blackbox | greybox | whitebox
        include_modules: If set, only run these modules (filter applied within phase order)
        skip_modules:    Modules to skip entirely
        has_session:     Whether an authenticated session is available

    Returns:
        Ordered list of PhaseConfig objects.
    """
    skip = set(skip_modules or [])
    only = set(include_modules) if include_modules else None

    result: list[PhaseConfig] = []
    for num, name, mods in PHASES:
        filtered: list[str] = []
        for m in mods:
            if m in skip:
                continue
            if only and m not in only:
                continue
            if m in WHITEBOX_ONLY and mode != "whitebox":
                continue
            if m in AUTH_REQUIRED and not has_session and mode == "blackbox":
                continue
            filtered.append(m)

        if filtered:
            result.append(PhaseConfig(number=num, name=name, modules=filtered))

    return result


def describe_phases(mode: str) -> None:
    """Print phase plan to stdout."""
    phases = get_phases(mode)
    print(f"\nWebForge — Mode: {mode.upper()} — {sum(len(p.modules) for p in phases)} modules")
    for p in phases:
        print(f"  Phase {p.number:2d}/{len(PHASES)}: {p.name}")
        for m in p.modules:
            gate = " [CONFIRM GATE]" if m in CONFIRM_GATE_MODULES else ""
            print(f"              • {m}{gate}")


class TestModeEngine:
    def test_blackbox_excludes_whitebox(self) -> None:
        phases = get_phases("blackbox")
        all_mods = [m for p in phases for m in p.modules]
        assert "source_audit" not in all_mods

    def test_whitebox_includes_all(self) -> None:
        phases = get_phases("whitebox", has_session=True)
        all_mods = [m for p in phases for m in p.modules]
        assert "source_audit" in all_mods

    def test_skip_modules(self) -> None:
        phases = get_phases("blackbox", skip_modules=["sqli_scanner","xss_scanner"])
        all_mods = [m for p in phases for m in p.modules]
        assert "sqli_scanner" not in all_mods
        assert "xss_scanner" not in all_mods

    def test_phase_order(self) -> None:
        phases = get_phases("greybox", has_session=True)
        numbers = [p.number for p in phases]
        assert numbers == sorted(numbers)
