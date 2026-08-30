#!/usr/bin/env python3
"""Forge Suite APEX — Unified Launcher.

Single entry point for all frameworks, the dashboard, C2 server,
intelligence pipeline, and payload generation.

Scanning:
  python3 forge.py net --target 10.0.0.0/24 --mode internal
  python3 forge.py web --target https://example.com
  python3 forge.py web --targets targets.txt --parallel 5
  python3 forge.py ad  --target dc01.corp.local --domain corp.local
  python3 forge.py ai  --target https://api.openai.com/v1/chat/completions

Dashboard:
  python3 forge.py dashboard
  python3 forge.py dashboard --tui
  python3 forge.py dashboard --attach results_dir/

C2 Framework:
  python3 forge.py c2 server --port 8443
  python3 forge.py c2 connect --server team.local:8443

Intelligence:
  python3 forge.py intel sync --all
  python3 forge.py intel search "Apache 2.4"

Payload Generation:
  python3 forge.py payload --type reverse_tcp --lhost 10.0.0.5 --format exe

Session Import:
  python3 forge.py import-session nbc.json
  python3 forge.py import-session edc.json
"""
import argparse
import asyncio
import getpass
import os
import socket
import signal
import sys
import subprocess
import logging
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlparse

from common.auth_prompt import require_authorization
from common.action_authorization import (
    AUTHORIZATION_DB_ENV,
    AUTHORIZATION_ENVELOPES_ENV,
    AuthorizationContext,
    AuthorizationOutcome,
    AuthorizationReason,
    ConfirmationMethod,
    OperatorRole,
    SafetyMode,
    authorization_runtime_environment,
    consume_authorization,
    default_authorization_db_path,
    derive_authorization,
    encode_authorization_envelopes,
    issue_authorization,
    module_set_binding,
    open_authorization_session,
    protected_credential_reference,
    redact_authorization_value,
    record_boundary_denial,
    record_authorization_denial,
)
from common.confirm_gate import (
    LAUNCH_ACTION_ENV,
    LAUNCH_CONFIRMATIONS_ENV,
    LAUNCH_JOB_ID_ENV,
    ActionConfirmation,
    decide_action,
    encode_launch_confirmations,
    load_launch_confirmations,
    load_launch_expectation,
    select_launch_confirmation,
)
from common.credential_boundary import (
    CredentialReference,
    ProtectedCredentialBundle,
    minimal_child_environment,
    wipe_mapping,
)
from common.scope import ScopeDecision, ScopeReason, decision_for_reason
from common.outbound_policy import _normalized_proxy_origin
from common.version import VERSION

log = logging.getLogger("forge")

BANNER = rf"""
  ██████╗ ██████╗ ██████╗  ██████╗ ███████╗    ███████╗██╗   ██╗██╗████████╗███████╗
  ██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝    ██╔════╝██║   ██║██║╚══██╔══╝██╔════╝
  █████╗  ██║   ██║██████╔╝██║  ███╗█████╗      ███████╗██║   ██║██║   ██║   █████╗
  ██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝      ╚════██║██║   ██║██║   ██║   ██╔══╝
  ██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗    ███████║╚██████╔╝██║   ██║   ███████╗
  ╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝    ╚══════╝ ╚═════╝ ╚═╝   ╚═╝   ╚══════╝

                          v{VERSION} APEX — Offensive Platform
"""

BASE_DIR = Path(__file__).resolve().parent

TRUTHY_ENV = {"1", "true", "yes", "on"}

# ── Framework registry ────────────────────────────────────────────────

FRAMEWORKS = {
    "net":  ("netforge", "netforge/netforge.py",  "Network Pentest + Red Team"),
    "web":  ("webforge", "webforge/webforge.py",  "Web Application Security"),
    "ad":   ("adforge",  "adforge/adforge.py",    "Active Directory Attack & Audit"),
    "ai":   ("aiforge",  "aiforge/aiforge.py",    "AI/LLM Red Teaming"),
}

ALIASES = {
    "netforge": "net", "network": "net",
    "webforge": "web", "website": "web",
    "adforge":  "ad",  "activedirectory": "ad",
    "aiforge":  "ai",  "llm": "ai",
}

_FORWARDED_PROXY_OPTIONS = frozenset(
    {"--proxy", "--http-proxy", "--https-proxy"}
)

_FORWARDED_VALUE_OPTIONS_BY_FRAMEWORK: dict[str, frozenset[str]] = {
    "web": frozenset(
        {
            "--mode", "--engagement", "--tester", "--config", "--output",
            "--report-format", "--rate", "--workers", "--proxy",
            "--username", "--password", "--token", "--cookie", "--session",
            "--source-root", "--modules", "--skip-modules", "--jwt-token",
            "--browser", "--login-url", "--login-script", "--auth-type",
            "--header-name", "--auth-state", "--api-schema",
            "--graphql-schema-url", "--profile", "--collab-domain",
            "--dashboard-url", "--control-file", "--reference-slice",
        }
    ),
    "net": frozenset(
        {
            "--mode", "--engagement", "--tester", "--interface", "--rate",
            "--workers", "--opsec", "--modules", "--skip-modules",
            "--bf-delay", "--bf-max", "--bf-timeout", "--output",
            "--report-format", "--attacker-ip", "--collab-domain",
            "--dashboard-url", "--control-file", "--ssh-user", "--ssh-pass",
            "--ssh-key", "--ssh-port", "--snmp-user", "--snmp-auth-pass",
            "--snmp-priv-pass", "--snmp-auth-proto", "--snmp-priv-proto",
            "--winrm-user", "--winrm-pass", "--winrm-port",
        }
    ),
    "ai": frozenset(
        {
            "--mode", "--engagement", "--tester", "--config", "--output",
            "--report-format", "--rate", "--api-key", "--api-type",
            "--model-name", "--system-prompt", "--model-info", "--proxy",
            "--modules", "--skip-modules", "--max-tokens", "--temperature",
            "--dashboard-url",
        }
    ),
    "ad": frozenset(
        {
            "--dc", "--domain", "--mode", "--username", "--password",
            "--hash", "--ticket", "--engagement", "--tester", "--modules",
            "--skip-modules", "--spray-delay", "--spray-max-rounds",
            "--output", "--report-format", "--dashboard-url",
        }
    ),
}

_FORWARDED_FLAG_OPTIONS_BY_FRAMEWORK: dict[str, frozenset[str]] = {
    "web": frozenset(
        {
            "--sso", "--browser-render", "--no-screenshot", "--list-modules",
            "--list-profiles", "--verbose", "--quiet", "--version", "--help",
            "-h",
        }
    ),
    "net": frozenset(
        {
            "--capture", "--stealth", "--red-team", "--verbose",
            "--winrm-ssl", "--version", "--help", "-h",
        }
    ),
    "ai": frozenset(
        {
            "--no-dos", "--no-destructive", "--allow-destructive",
            "--list-modules", "--verbose", "--quiet", "--version", "--help",
            "-h",
        }
    ),
    "ad": frozenset(
        {
            "--dcsync", "--bloodhound", "--autopilot", "--verbose",
            "--version", "--help", "-h",
        }
    ),
}


def _is_proxy_option_lookalike(option_name: str) -> bool:
    """Recognize unknown long options that could disguise proxy material."""
    normalized = str(option_name).strip().lower()
    if not normalized.startswith("--") or normalized in _FORWARDED_PROXY_OPTIONS:
        return False
    return "proxy" in normalized or any(
        known.startswith(normalized) or normalized.startswith(known)
        for known in _FORWARDED_PROXY_OPTIONS
    )


def _contains_inline_url_credentials(value: str) -> bool:
    """Return whether an argv item embeds userinfo in an absolute URL."""
    rendered = str(value).strip()
    if rendered.startswith("--") and "=" in rendered:
        rendered = rendered.split("=", 1)[1].strip()
    if "://" not in rendered:
        return False
    try:
        parsed = urlparse(rendered)
    except ValueError:
        # Malformed credential-bearing URLs are still unsafe process metadata.
        return "@" in rendered
    return parsed.username is not None or parsed.password is not None


# ══════════════════════════════════════════════════════════════════════
# ARGUMENT PARSER
# ══════════════════════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    """Construct the full CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="forge",
        allow_abbrev=False,
        description=f"Forge Suite v{VERSION} APEX — Unified Offensive Security Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  forge.py net --target 10.0.0.0/24 --mode internal
  forge.py web --target https://example.com --dashboard
  forge.py web --targets targets.txt --parallel 5
  forge.py dashboard --tui
  forge.py c2 server --port 8443
  forge.py intel sync --all
  forge.py payload --type reverse_tcp --lhost 10.0.0.5 --format exe
        """,
    )
    parser.add_argument("--version", action="version", version=f"Forge Suite v{VERSION}")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # ── Scan frameworks (net, web, ad, ai) ─────────────────────────
    for key, (name, script, desc) in FRAMEWORKS.items():
        fw_parser = subparsers.add_parser(
            key,
            help=desc,
            add_help=False,
            allow_abbrev=False,
        )
        _add_common_scan_args(fw_parser)

    # ── Dashboard ──────────────────────────────────────────────────
    dash = subparsers.add_parser("dashboard", help="Launch the War Room dashboard")
    dash.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    dash.add_argument("--port", type=_port, default=1337, help="Bind port (default: 1337)")
    dash.add_argument("--tui", action="store_true", help="Launch Rich terminal TUI instead of web")
    dash.add_argument(
        "--no-auth",
        action="store_true",
        help="Deprecated: unauthenticated dashboard mode is disabled",
    )
    dash.add_argument("--attach", metavar="DIR", help="Attach to a running/completed engagement")
    dash.add_argument("--replay", metavar="DIR", help="Replay a completed engagement")

    # ── C2 Framework ──────────────────────────────────────────────
    c2 = subparsers.add_parser("c2", help="Command & Control framework")
    c2_sub = c2.add_subparsers(dest="c2_action", help="C2 actions")

    c2_server = c2_sub.add_parser("server", help="Start the C2 team server")
    c2_server.add_argument("--bind", default="0.0.0.0", help="Bind address")
    c2_server.add_argument("--port", type=_port, default=8443, help="Server port")
    c2_server.add_argument("--password", help="Team server password")
    c2_server.add_argument("--dashboard", action="store_true", help="Launch dashboard alongside C2")
    c2_server.add_argument("--profile", default="generic_cdn",
                            help="Malleable C2 profile (office365/amazon/slack/cloudfront/generic_cdn or .yaml path)")
    c2_server.add_argument("--red-team", action="store_true",
                            help="Confirm this is for an authorized engagement")

    c2_connect = c2_sub.add_parser("connect", help="Connect to a team server as operator")
    c2_connect.add_argument("--server", required=True, help="Team server address (host:port)")
    c2_connect.add_argument("--user", default="operator", help="Operator username")
    c2_connect.add_argument("--password", help="Team server password")

    c2_listener = c2_sub.add_parser("listener", help="Manage listeners")
    c2_listener.add_argument("action", choices=["add", "remove", "list"], help="Listener action")
    c2_listener.add_argument("--type", choices=["https", "http", "dns", "tcp", "smb"],
                              help="Listener type")
    c2_listener.add_argument("--port", type=_port, help="Listener port")
    c2_listener.add_argument("--host", help="Listener bind host")
    c2_listener.add_argument("--profile", help="Malleable C2 profile name or .yaml path")
    c2_listener.add_argument("--red-team", action="store_true",
                             help="Confirm this is for an authorized engagement")

    c2_payload = c2_sub.add_parser("payload", help="Generate C2 payload/beacon")
    c2_payload.add_argument("--type", default="beacon_https", help="Payload type")
    c2_payload.add_argument("--lhost", required=True, help="Callback host")
    c2_payload.add_argument("--lport", type=_port, default=443, help="Callback port")
    c2_payload.add_argument("--format", default="exe", help="Output format")
    c2_payload.add_argument("--arch", default="x64", choices=["x86", "x64", "arm64"])
    c2_payload.add_argument("--output", "-o", help="Output file path")
    c2_payload.add_argument("--red-team", action="store_true",
                            help="Confirm this payload is for an authorized engagement")

    # ── Intelligence Pipeline ─────────────────────────────────────
    intel = subparsers.add_parser("intel", help="Intelligence pipeline management")
    intel_sub = intel.add_subparsers(dest="intel_action", help="Intel actions")

    intel_sync = intel_sub.add_parser("sync", help="Sync intelligence sources")
    intel_sync.add_argument("--all", action="store_true", dest="sync_all", help="Sync all sources")
    intel_sync.add_argument("--cve", action="store_true", help="Sync CVE database")
    intel_sync.add_argument("--exploits", action="store_true", help="Sync Exploit-DB")
    intel_sync.add_argument("--nuclei", action="store_true", help="Sync Nuclei templates")
    intel_sync.add_argument("--techniques", action="store_true", help="Sync ATT&CK techniques")
    intel_sync.add_argument("--since", help="Only sync entries since date (YYYY-MM-DD)")

    intel_search = intel_sub.add_parser("search", help="Search local intelligence")
    intel_search.add_argument("query", nargs="?", help="Search query")
    intel_search.add_argument("--cve", help="Search by CVE ID (e.g., CVE-2024-1234)")
    intel_search.add_argument("--product", help="Search by product name")
    intel_search.add_argument("--severity", choices=["critical", "high", "medium", "low"])
    intel_search.add_argument("--limit", type=_positive_int, default=20, help="Max results")

    intel_status = intel_sub.add_parser("status", help="Show intel sync status")

    # ── Autonomous VAPT ───────────────────────────────────────────
    auto_p = subparsers.add_parser("auto", help="Fully autonomous AI-driven VAPT engagement")
    auto_p.add_argument("--target", "-t", required=True, help="Target (URL, IP, CIDR)")
    auto_p.add_argument("--frameworks", default="netforge,webforge",
                         help="Comma-separated frameworks (default: netforge,webforge)")
    auto_p.add_argument("--opsec", default="standard",
                         choices=["stealth", "standard", "noisy"],
                         help="OPSEC level (default: standard)")
    auto_p.add_argument("--max-time", type=_positive_int, default=3600,
                         help="Max engagement duration in seconds (default: 3600)")
    auto_p.add_argument("--max-findings", type=_positive_int, default=100,
                         help="Stop after N findings (default: 100)")
    auto_p.add_argument("--brain-key", metavar="KEY",
                         help="Anthropic API key (overrides ANTHROPIC_API_KEY env var)")
    auto_p.add_argument("--no-stop-on-critical", action="store_true",
                         help="Don't stop on first critical finding")
    auto_p.add_argument("--no-fn-sweep", action="store_true",
                         help="Disable false-negative sweep between phases")
    auto_p.add_argument("--output-dir", "-o", metavar="DIR", help="Results output directory")

    # ── ForgeCollab OOB Server ─────────────────────────────────────
    collab = subparsers.add_parser("collab", help="ForgeCollab OOB testing infrastructure")
    collab_sub = collab.add_subparsers(dest="collab_action", help="Collab actions")

    collab_start = collab_sub.add_parser("start", help="Start ForgeCollab OOB server")
    collab_start.add_argument("--domain", default="",
                               help="Collab domain (e.g., collab.example.com)")
    collab_start.add_argument("--listen", default="0.0.0.0", help="Bind address")
    collab_start.add_argument("--http-port", type=_port, default=8888, help="HTTP listener port")
    collab_start.add_argument("--dns-port", type=_optional_port, default=53, help="DNS port (0 to disable)")
    collab_start.add_argument("--smtp-port", type=_optional_port, default=25, help="SMTP port (0 to disable)")
    collab_start.add_argument("--api-port", type=_port, default=8889, help="API port")
    collab_start.add_argument("--response-ip", default=None, help="IP for DNS responses")
    collab_start.add_argument("--local", action="store_true",
                               help="Local mode (HTTP only, no DNS/SMTP)")

    collab_gen = collab_sub.add_parser("token", help="Generate a test OOB token")
    collab_gen.add_argument("--module", default="manual", help="Module name")
    collab_gen.add_argument("--vuln-type", default="ssrf", help="Vulnerability type")
    collab_gen.add_argument("--target", default="", help="Target URL")

    # ── Passive scan agent ─────────────────────────────────────────
    agent = subparsers.add_parser("agent", help="Run a passive distributed scan agent")
    agent.add_argument("--dashboard-url", required=True, help="Dashboard base URL")
    agent.add_argument("--agent-id", default=socket.gethostname(), help="Stable agent id")
    agent.add_argument("--name", default="", help="Display name")
    agent.add_argument("--engines", default="webforge,netforge", help="Comma-separated engine capabilities")
    agent.add_argument("--scope", required=True, help="Comma-separated authorized scope entries")
    agent.add_argument("--exclude", action="append", default=[], metavar="ENTRY",
                       help="Explicitly excluded host, URL, IP, or CIDR (repeatable)")
    agent.add_argument("--token", default="", help="Registration token")
    agent.add_argument("--interval", type=float, default=5.0, help="Poll interval seconds")
    agent.add_argument("--once", action="store_true", help="Process at most one job and exit")
    agent.add_argument("--allow-active-scans", action="store_true", help="Permit non-dry-run queued jobs to launch scanners")
    agent.add_argument("--mtls-subject", default="", help="Client certificate subject when terminated by a proxy")
    agent.add_argument("--client-cert", default="", help="Client certificate PEM for dashboard HTTPS")
    agent.add_argument("--client-key", default="", help="Client private key PEM for --client-cert")
    agent.add_argument("--ca-cert", default="", help="CA bundle PEM for dashboard TLS verification")
    agent.add_argument("--insecure-tls", action="store_true", help="Disable dashboard TLS verification for labs")

    # ── Session Import ────────────────────────────────────────────
    import_sess = subparsers.add_parser(
        "import-session",
        help="Import a completed engagement session JSON into the forge brain",
    )
    import_sess.add_argument(
        "session_file",
        help="Path to session JSON (e.g. nbc.json, edc.json)",
    )
    import_sess.add_argument(
        "--db",
        metavar="PATH",
        help="Engagement DB path (default: engagement.db)",
    )

    # ── Payload Generation ────────────────────────────────────────
    payload = subparsers.add_parser("payload", help="Standalone payload generation")
    payload.add_argument("--type", default="reverse_tcp", help="Payload type")
    payload.add_argument("--lhost", help="Callback host")
    payload.add_argument("--lport", type=_port, default=4444, help="Callback port")
    payload.add_argument("--format", default="exe",
                          choices=["exe", "dll", "elf", "ps1", "hta", "vba", "msi",
                                   "iso", "raw", "c", "cs", "py", "sh", "lnk", "zip", "one"],
                          help="Output format")
    payload.add_argument("--arch", default="x64", choices=["x86", "x64", "arm64"])
    payload.add_argument("--encode", choices=["xor", "aes", "rc4", "polymorphic", "uuid", "b64", "chain", "none"],
                          default="none", help="Encoding/encryption method")
    payload.add_argument("--iterations", type=_positive_int, default=1, help="Encoding iterations")
    payload.add_argument("--output", "-o", help="Output file path")
    payload.add_argument("--env-key", default="", help="Environmental keying: only execute on this domain")
    payload.add_argument("--kill-date", default="", help="Kill date ISO string (YYYY-MM-DD)")
    payload.add_argument("--sleep", type=_positive_int, default=60, dest="sleep_seconds", help="Beacon sleep interval")
    payload.add_argument("--jitter", type=_percent, default=30, dest="jitter_percent", help="Sleep jitter percent")
    payload.add_argument("--no-sandbox-detect", action="store_false", dest="sandbox_detect",
                          default=False,
                          help="Disable sandbox detection checks")
    payload.add_argument("--no-amsi-bypass", action="store_false", dest="amsi_bypass",
                          default=False,
                          help="Disable AMSI bypass code")
    payload.add_argument("--no-etw-bypass", action="store_false", dest="etw_bypass",
                          default=False,
                          help="Disable ETW bypass code")
    payload.add_argument("--sleep-mask", action="store_true", help="Enable sleep masking (beacon only)")
    payload.add_argument("--indirect-syscalls", action="store_true", help="Use indirect syscalls in loader")
    payload.add_argument("--ppid-spoof", action="store_true", help="Enable PPID spoofing")
    payload.add_argument("--byovd", action="store_true", help="Show BYOVD driver reference table")
    payload.add_argument("--red-team", action="store_true",
                          help="Confirm this payload is for an authorized engagement")
    payload.add_argument("--list", action="store_true", dest="list_payloads",
                          help="List available payload types")

    return parser


def _add_common_scan_args(parser: argparse.ArgumentParser) -> None:
    """Add common scan arguments shared by all frameworks."""
    # Target specification
    target_group = parser.add_argument_group("target")
    target_group.add_argument("--target", "--url", "-t", help="Single target (URL, IP, CIDR)")
    target_group.add_argument("--targets", "-T", metavar="FILE",
                               help="Multi-target file (one target per line)")
    target_group.add_argument("--parallel", type=_positive_int, default=3,
                               help="Max parallel targets (default: 3)")
    target_group.add_argument("--resume", metavar="DIR",
                               help="Resume a previous multi-target scan")
    target_group.add_argument("--scope", action="append", default=[], metavar="ENTRY",
                              help="Explicitly authorized host, URL, IP, or CIDR (repeatable)")
    target_group.add_argument("--exclude", action="append", default=[], metavar="ENTRY",
                              help="Explicitly excluded host, URL, IP, or CIDR (repeatable)")

    parser.add_argument("--dry-run", action="store_true",
                        help="Return a local plan without launching a framework")
    parser.add_argument("--auto-confirm", action="store_true",
                        help="Explicitly confirm this exact CLI launch and module gates")

    # Dashboard integration
    dash_group = parser.add_argument_group("dashboard")
    dash_group.add_argument("--dashboard", action="store_true",
                             help="Launch live dashboard alongside scan")
    dash_group.add_argument("--dashboard-port", type=_port, default=1337,
                             help="Dashboard port (default: 1337)")
    dash_group.add_argument("--dashboard-tui", action="store_true",
                             help="Use terminal TUI dashboard instead of web")

    # Scheduling
    sched_group = parser.add_argument_group("scheduling")
    sched_group.add_argument("--schedule", metavar="SPEC",
                              help="Schedule scan (HH:MM, daily:HH:MM, weekly:DAY:HH:MM)")
    sched_group.add_argument("--continuous", action="store_true",
                              help="Continuous monitoring mode")
    sched_group.add_argument("--interval", default="24h",
                              help="Interval for continuous mode (default: 24h)")

    # Intel
    parser.add_argument("--auto-update", action="store_true",
                         help="Auto-sync intel databases before scan")
    parser.add_argument("--offline", action="store_true",
                         help="Offline mode — use cached intel only")

    # Output
    parser.add_argument("--output-dir", "-o", metavar="DIR",
                         help="Results output directory")


def _positive_int(value: str) -> int:
    """argparse type for positive integers."""
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return parsed


def _port(value: str) -> int:
    """argparse type for TCP/UDP ports."""
    parsed = _positive_int(value)
    if parsed > 65535:
        raise argparse.ArgumentTypeError("must be between 1 and 65535")
    return parsed


def _optional_port(value: str) -> int:
    """argparse type for ports where 0 means disabled."""
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed < 0 or parsed > 65535:
        raise argparse.ArgumentTypeError("must be between 0 and 65535")
    return parsed


def _percent(value: str) -> int:
    """argparse type for percentage values."""
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed < 0 or parsed > 100:
        raise argparse.ArgumentTypeError("must be between 0 and 100")
    return parsed


def _read_targets_file(path_value: str) -> list[str]:
    """Load a target file with comments and blank lines removed."""
    path = Path(path_value).expanduser()
    if not path.is_absolute():
        path = BASE_DIR / path
    if not path.exists():
        raise FileNotFoundError(f"Target file not found: {path}")
    if not path.is_file():
        raise ValueError(f"Target path is not a file: {path}")
    targets: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        value = line.strip()
        if value and not value.startswith("#"):
            targets.append(value)
    return targets


def _validate_target_value(target: str) -> str:
    """Validate a target enough to catch common CLI mistakes early."""
    value = target.strip()
    if not value:
        raise ValueError("target cannot be empty")
    if any(ch.isspace() for ch in value):
        raise ValueError("target contains whitespace")
    parsed = urlparse(value if "://" in value else f"https://{value}")
    if "://" in value and parsed.scheme not in {"http", "https"}:
        raise ValueError(f"unsupported URL scheme for scan target: {parsed.scheme}")
    host = parsed.hostname if parsed.hostname else value.split("/", 1)[0]
    if not host:
        raise ValueError("missing target host")
    return value


def _validate_common_scan_inputs(args: argparse.Namespace) -> list[str]:
    """Return normalized target values after validating common scan inputs."""
    target = getattr(args, "target", None)
    targets_file = getattr(args, "targets", None)
    resume_dir = getattr(args, "resume", None)

    specified = sum(1 for item in (target, targets_file, resume_dir) if item)
    if specified == 0:
        raise ValueError("Use --target <target>, --targets <file>, or --resume <dir>")
    if specified > 1:
        raise ValueError("Use only one of --target, --targets, or --resume")

    if getattr(args, "parallel", 1) > 100:
        raise ValueError("--parallel is capped at 100")

    if resume_dir:
        resume_path = Path(resume_dir).expanduser()
        if not resume_path.exists() or not resume_path.is_dir():
            raise ValueError(f"Resume directory not found: {resume_path}")
        return []

    if target:
        return [_validate_target_value(target)]

    targets = [
        _validate_target_value(item)
        for item in _read_targets_file(cast(str, targets_file))
    ]
    if not targets:
        raise ValueError(f"Target file has no usable targets: {targets_file}")
    return targets


def _validate_kill_date(kill_date: str) -> None:
    """Validate payload kill-date formatting when provided."""
    if not kill_date:
        return
    try:
        datetime.strptime(kill_date, "%Y-%m-%d")
    except ValueError as exc:
        raise ValueError("--kill-date must use YYYY-MM-DD") from exc


# ══════════════════════════════════════════════════════════════════════
# COMMAND HANDLERS
# ══════════════════════════════════════════════════════════════════════

def _print_scan_denial(decision: ScopeDecision) -> None:
    """Print a stable launch denial without echoing target secrets."""
    print(f"  [!] Launch denied [{decision.reason_code}]: {decision.reason}")


def _audit_scan_denial(
    args: argparse.Namespace,
    framework_key: str,
    decision: ScopeDecision,
    *,
    target: Any = None,
) -> None:
    """Persist one safe denial for a unified-CLI active scan request."""
    engine = FRAMEWORKS[framework_key][0]
    session = open_authorization_session()
    try:
        record_boundary_denial(
            session=session,
            reason_code=decision.reason_code,
            action_kind=str(getattr(args, "_launch_action", "scan") or "scan"),
            engine=engine,
            target=(target if target is not None else getattr(args, "target", None)),
            allowed_scope=getattr(args, "scope", []),
            excluded_scope=getattr(args, "exclude", []),
            tenant_id=os.environ.get("FORGE_TENANT_ID", "default"),
            engagement_id=getattr(args, "engagement", "preflight"),
            run_id="preflight-run",
            job_id=getattr(args, "_launch_job_id", "preflight-job"),
            operator_id=getpass.getuser().strip() or "operator",
            operator_role=OperatorRole.OPERATOR,
            safety_mode=(
                SafetyMode.HIGH_RISK
                if framework_key == "ai"
                else SafetyMode.ACTIVE
            ),
        )
    finally:
        session.close()


def _deny_legacy_active_action(
    action_kind: str,
    target: str,
    *,
    safety_mode: SafetyMode = SafetyMode.ACTIVE,
) -> int:
    """Audit and fail closed for active CLI families not yet envelope-enabled."""
    operator_id = getpass.getuser().strip() or "operator"
    context = AuthorizationContext(
        tenant_id=os.environ.get("FORGE_TENANT_ID", "default").strip() or "default",
        engagement_id="platform-control",
        run_id=f"run-{uuid.uuid4().hex}",
        job_id=f"job-{uuid.uuid4().hex}",
        operator_id=operator_id,
        operator_role=OperatorRole.OPERATOR,
        action_kind=action_kind,
        engine="forge",
        module_id=action_kind,
        requested_target=target or "local-control-plane",
        resolved_target=target or "local-control-plane",
        allowed_scope=[],
        excluded_scope=[],
        safety_mode=safety_mode,
        high_risk_approval_required=(safety_mode is SafetyMode.HIGH_RISK),
        confirmation_method=ConfirmationMethod.NONE,
    )
    try:
        session = open_authorization_session()
        try:
            decision = record_authorization_denial(
                session=session,
                context=context,
                reason_code=AuthorizationReason.LEGACY_NOT_AUTHORIZED,
                outcome=AuthorizationOutcome.UNKNOWN_NOT_AUTHORIZED,
            )
        finally:
            session.close()
    except Exception:
        print("  [!] Active action denied [audit_persistence_failed].")
        return 1
    print(f"  [!] Active action denied [{decision.reason_code}]: {decision.reason}")
    return 1


def _normalize_framework_targets(framework_key: str, targets: list[str]) -> list[str]:
    """Normalize targets exactly as the selected child does before binding."""
    if framework_key != "web":
        return targets
    return [
        value if value.startswith(("http://", "https://")) else f"https://{value}"
        for value in targets
    ]


def _forwarded_module_values(arguments: list[str]) -> list[str]:
    """Extract an explicit --modules selection without trusting it as authority."""
    for index, value in enumerate(arguments):
        if value == "--modules" and index + 1 < len(arguments):
            return [item.strip() for item in arguments[index + 1].split(",") if item.strip()]
        if value.startswith("--modules="):
            return [item.strip() for item in value.split("=", 1)[1].split(",") if item.strip()]
    return []


def _forwarded_option_values(
    arguments: list[str],
    option_names: dict[str, str],
) -> dict[str, str]:
    """Extract bounded child options without treating them as authority."""
    values: dict[str, str] = {}
    index = 0
    while index < len(arguments):
        item = arguments[index]
        matched = False
        for option, field in option_names.items():
            if item == option and index + 1 < len(arguments):
                values[field] = arguments[index + 1]
                index += 2
                matched = True
                break
            if item.startswith(option + "="):
                values[field] = item.split("=", 1)[1]
                index += 1
                matched = True
                break
        if not matched:
            index += 1
    return {key: value for key, value in values.items() if value}


def _forwarded_credential_reference(
    framework_key: str,
    arguments: list[str],
) -> str:
    option_sets = {
        "web": {
            "--auth-type": "auth_type",
            "--username": "username",
            "--password": "password",
            "--token": "token",
            "--cookie": "cookie",
            "--session": "session",
            "--auth-state": "auth_state",
        },
        "net": {
            "--ssh-user": "ssh_user",
            "--ssh-pass": "ssh_pass",
            "--ssh-key": "ssh_key",
            "--snmp-user": "snmp_user",
            "--snmp-auth-pass": "snmp_auth_pass",
            "--snmp-priv-pass": "snmp_priv_pass",
            "--winrm-user": "winrm_user",
            "--winrm-pass": "winrm_pass",
        },
        "ad": {
            "--username": "username",
            "--password": "password",
            "--hash": "hash",
            "--ticket": "ticket",
        },
        "ai": {"--api-key": "api_key"},
    }
    values = _forwarded_option_values(arguments, option_sets[framework_key])
    if framework_key == "web":
        values.setdefault("password", os.environ.get("FORGE_PASSWORD", ""))
        values.setdefault("token", os.environ.get("FORGE_TOKEN", ""))
        values.setdefault("cookie", os.environ.get("FORGE_COOKIE_JAR", ""))
        values = {key: value for key, value in values.items() if value}
        if not any(
            values.get(key)
            for key in ("username", "password", "token", "cookie", "session", "auth_state")
        ):
            return ""
    return protected_credential_reference(values)


_PROTECTED_FORWARDED_OPTIONS: dict[str, dict[str, str]] = {
    "web": {
        "--password": "password",
        "--token": "token",
        "--cookie": "cookie",
    },
    "net": {
        "--ssh-pass": "ssh_pass",
        "--snmp-auth-pass": "snmp_auth_pass",
        "--snmp-priv-pass": "snmp_priv_pass",
        "--winrm-pass": "winrm_pass",
    },
    "ad": {
        "--password": "password",
        "--hash": "hash",
        "--ticket": "ticket",
    },
    "ai": {"--api-key": "api_key"},
}


def _extract_protected_forwarded_credentials(
    framework_key: str,
    arguments: list[str],
) -> tuple[list[str], dict[str, str]]:
    """Remove secret-bearing options from child argv and return their values."""
    protected = _PROTECTED_FORWARDED_OPTIONS.get(framework_key, {})
    sanitized: list[str] = []
    values: dict[str, str] = {}
    index = 0
    while index < len(arguments):
        item = str(arguments[index])
        option, separator, inline_value = item.partition("=")
        field = protected.get(option)
        if field is None:
            sanitized.append(item)
            index += 1
            continue
        if separator:
            values[field] = inline_value
            index += 1
            continue
        if index + 1 >= len(arguments):
            raise ValueError("protected option requires a value")
        values[field] = str(arguments[index + 1])
        index += 2

    if framework_key == "web":
        legacy_environment = {
            "password": os.environ.get("FORGE_PASSWORD", ""),
            "token": os.environ.get("FORGE_TOKEN", ""),
            "cookie": os.environ.get("FORGE_COOKIE_JAR", ""),
        }
        for field, value in legacy_environment.items():
            if value and field not in values:
                values[field] = value
    return sanitized, {key: value for key, value in values.items() if value}


def _safe_command_display(command: list[str]) -> str:
    """Render child argv without exposing credential-bearing option values."""
    sensitive = {
        "--password",
        "--token",
        "--cookie",
        "--api-key",
        "--hash",
        "--ticket",
        "--ssh-pass",
        "--ssh-key",
        "--snmp-auth-pass",
        "--snmp-priv-pass",
        "--winrm-pass",
        "--proxy",
        "--http-proxy",
        "--https-proxy",
    }
    rendered: list[str] = []
    redact_next = False
    for item in command:
        rendered_item = str(item)
        if redact_next:
            rendered.append("<redacted>")
            redact_next = False
            continue
        if item in sensitive:
            rendered.append(item)
            redact_next = True
            continue
        abbreviated_name = rendered_item.split("=", 1)[0]
        abbreviated_sensitive = (
            abbreviated_name.startswith("--")
            and abbreviated_name not in sensitive
            and (
                _is_proxy_option_lookalike(abbreviated_name)
                or any(
                    name.startswith(abbreviated_name)
                    or abbreviated_name.startswith(name)
                    for name in sensitive
                )
            )
        )
        if abbreviated_sensitive:
            if "=" in rendered_item:
                rendered.append(f"{abbreviated_name}=<redacted>")
            else:
                rendered.append(abbreviated_name)
                redact_next = True
            continue
        if _contains_inline_url_credentials(rendered_item):
            if rendered_item.startswith("--") and "=" in rendered_item:
                rendered.append(f"{abbreviated_name}=<redacted>")
            else:
                rendered.append("<redacted>")
            continue
        option = next(
            (name for name in sensitive if item.startswith(name + "=")),
            None,
        )
        if option is not None:
            rendered.append(f"{option}=<redacted>")
            continue
        rendered.append(str(redact_authorization_value(item)))
    return " ".join(rendered)


def _validate_forwarded_options(
    arguments: list[str],
    framework_key: str,
) -> None:
    """Strictly parse child-only options before constructing child argv."""
    value_options = _FORWARDED_VALUE_OPTIONS_BY_FRAMEWORK.get(framework_key)
    flag_options = _FORWARDED_FLAG_OPTIONS_BY_FRAMEWORK.get(framework_key)
    if value_options is None or flag_options is None:
        raise ValueError("framework has no forwarded-option policy")

    index = 0
    while index < len(arguments):
        argument = str(arguments[index])
        option_name, separator, inline_value = argument.partition("=")
        if _is_proxy_option_lookalike(option_name):
            # Reject abbreviations, suffix/prefix lookalikes, and other
            # proxy-named unknown options before child argv exists.
            raise ValueError("proxy option lookalikes are prohibited")
        if _contains_inline_url_credentials(argument):
            # Unknown forwarded arguments cannot be used as an alternate
            # carrier for proxy URL userinfo into process metadata.
            raise ValueError("inline URL credentials are prohibited")
        if option_name in flag_options:
            if separator:
                raise ValueError("flag option cannot contain a value")
            index += 1
            continue
        if option_name not in value_options:
            raise ValueError("forwarded option is unsupported")
        if separator:
            if not inline_value:
                raise ValueError("forwarded option value cannot be empty")
            index += 1
            continue
        if index + 1 >= len(arguments):
            raise ValueError("forwarded option requires a value")
        value = str(arguments[index + 1])
        if value.startswith("-"):
            raise ValueError("forwarded option requires an explicit value")
        if _contains_inline_url_credentials(value):
            raise ValueError("inline URL credentials are prohibited")
        index += 2

    values = _forwarded_option_values(
        arguments,
        {
            "--proxy": "proxy",
            "--http-proxy": "http_proxy",
            "--https-proxy": "https_proxy",
        },
    )
    for value in values.values():
        _normalized_proxy_origin(value)


def _prepare_scan_confirmations(
    args: argparse.Namespace,
    framework_key: str,
    targets: list[str],
    *,
    dry_run: bool,
    auto_confirm: bool,
) -> tuple[ScopeDecision, list[ActionConfirmation], list[Any]]:
    """Authorize one exact target batch before any launch side effect.

    Every target is scope- and confirmation-validated before an allow is
    persisted.  The parent decisions, their single-use consumptions, and all
    derived engine envelopes then share one transaction so a later target or
    persistence failure cannot leave a partially authorized batch.
    """
    if not targets:
        return decision_for_reason(ScopeReason.MALFORMED_TARGET), [], []

    args._authorization_denied_target = targets[0]
    engine = FRAMEWORKS[framework_key][0]
    module_binding = str(getattr(args, "_module_binding", ""))
    allowed_scope = getattr(args, "scope", None)
    excluded_scope = getattr(args, "exclude", None)
    inherited = load_launch_confirmations()
    if not dry_run and os.environ.get(LAUNCH_CONFIRMATIONS_ENV) and not inherited:
        return decision_for_reason(ScopeReason.INVALID_CONFIRMATION), [], []
    inherited_expectation = load_launch_expectation() if inherited else None
    if inherited and inherited_expectation is None:
        return decision_for_reason(ScopeReason.INVALID_CONFIRMATION), [], []
    expected_job_id, expected_action = inherited_expectation or (
        f"forge-cli-{uuid.uuid4().hex}",
        "scan",
    )
    if expected_action != "scan":
        return decision_for_reason(ScopeReason.ACTION_MISMATCH), [], []
    args._launch_job_id = expected_job_id
    args._launch_action = expected_action
    prepared: list[ActionConfirmation] = []
    prepared_contexts: list[tuple[str, ActionConfirmation, AuthorizationContext]] = []
    authorizations: list[Any] = []
    tenant_id = os.environ.get("FORGE_TENANT_ID", "default").strip() or "default"
    operator_id = getpass.getuser().strip() or "operator"
    engagement_id = str(getattr(args, "engagement", "default") or "default")
    credential_reference = str(getattr(args, "_credential_reference", "") or "")
    run_id = f"run-{uuid.uuid4().hex}"
    safety_mode = (
        SafetyMode.HIGH_RISK if framework_key == "ai" else SafetyMode.ACTIVE
    )

    # Phase one is deliberately persistence-free.  A mismatch anywhere in a
    # multi-target request must not leave earlier targets authorized.
    for target in targets:
        scope_decision = decide_action(
            target=target,
            allowed_scope=allowed_scope,
            excluded_scope=excluded_scope,
            confirmation=None,
            job_id=expected_job_id,
            engine=engine,
            action="scan",
            require_confirmation=False,
        )
        if not scope_decision.allowed:
            args._authorization_denied_target = target
            return scope_decision, [], []
        if dry_run:
            continue

        confirmation = select_launch_confirmation(
            inherited,
            target=target,
            engine=engine,
            action=expected_action,
            job_id=expected_job_id,
        )
        if confirmation is None and len(inherited) == 1:
            confirmation = inherited[0]
        if confirmation is None and inherited:
            args._authorization_denied_target = target
            return decision_for_reason(ScopeReason.MISSING_CONFIRMATION), [], []
        if confirmation is None:
            if not auto_confirm:
                try:
                    require_authorization(target, engine)
                except SystemExit:
                    args._authorization_denied_target = target
                    denial_session = open_authorization_session()
                    try:
                        record_boundary_denial(
                            session=denial_session,
                            reason_code=ScopeReason.MISSING_CONFIRMATION.value,
                            action_kind=expected_action,
                            engine=engine,
                            target=target,
                            allowed_scope=allowed_scope or [],
                            excluded_scope=excluded_scope or [],
                            tenant_id=tenant_id,
                            engagement_id=engagement_id,
                            run_id=run_id,
                            job_id=expected_job_id,
                            operator_id=operator_id,
                            operator_role=OperatorRole.OPERATOR,
                            safety_mode=safety_mode,
                        )
                    finally:
                        denial_session.close()
                    raise
            confirmation = ActionConfirmation.create(
                job_id=expected_job_id,
                target=target,
                engine=engine,
                action=expected_action,
            )

        action_decision = decide_action(
            target=target,
            allowed_scope=allowed_scope,
            excluded_scope=excluded_scope,
            confirmation=confirmation,
            job_id=expected_job_id,
            engine=engine,
            action=expected_action,
        )
        if not action_decision.allowed:
            args._authorization_denied_target = target
            return action_decision, [], []
        prepared.append(confirmation)

        base_context = AuthorizationContext(
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            run_id=run_id,
            job_id=expected_job_id,
            operator_id=operator_id,
            operator_role=OperatorRole.OPERATOR,
            action_kind=expected_action,
            engine=engine,
            module_id=module_binding,
            requested_target=target,
            resolved_target=target,
            allowed_scope=allowed_scope or [],
            excluded_scope=excluded_scope or [],
            safety_mode=safety_mode,
            credential_approval_required=bool(credential_reference),
            high_risk_approval_required=(framework_key == "ai"),
            credential_reference=credential_reference,
            confirmation_method=(
                ConfirmationMethod.INHERITED
                if inherited
                else ConfirmationMethod.CLI_FLAG
                if auto_confirm
                else ConfirmationMethod.CLI_PROMPT
            ),
            confirmed_by=operator_id,
        )
        prepared_contexts.append((target, confirmation, base_context))

    if dry_run:
        return scope_decision, prepared, authorizations

    auth_session = open_authorization_session()
    try:
        for target, confirmation, base_context in prepared_contexts:
            issued = issue_authorization(
                session=auth_session,
                context=base_context,
                confirmation=confirmation,
                commit=False,
            )
            if not issued.allowed:
                auth_session.rollback()
                args._authorization_denied_target = target
                return ScopeDecision(
                    allowed=False,
                    reason_code=issued.reason_code,
                    reason=issued.reason,
                ), [], []
            consumed = consume_authorization(
                session=auth_session,
                envelope=issued.envelope,
                expected=base_context,
                boundary="cli.launch",
                commit=False,
            )
            if not consumed.allowed:
                auth_session.rollback()
                args._authorization_denied_target = target
                return ScopeDecision(
                    allowed=False,
                    reason_code=consumed.reason_code,
                    reason=consumed.reason,
                ), [], []
            engine_context = AuthorizationContext(
                **{
                    **base_context.__dict__,
                    "action_kind": "engine.execute",
                    "parent_decision_id": issued.envelope.decision_id,
                    "confirmation_method": ConfirmationMethod.INHERITED,
                }
            )
            derived = derive_authorization(
                session=auth_session,
                parent_envelope=issued.envelope,
                context=engine_context,
                parent_boundary="cli.launch",
                commit=False,
            )
            if not derived.allowed:
                auth_session.rollback()
                args._authorization_denied_target = target
                return ScopeDecision(
                    allowed=False,
                    reason_code=derived.reason_code,
                    reason=derived.reason,
                ), [], []
            authorizations.append(derived.envelope)
        auth_session.commit()
    except Exception:
        auth_session.rollback()
        raise
    finally:
        auth_session.close()
    return scope_decision, prepared, authorizations


def handle_scan(
    args: argparse.Namespace,
    framework_key: str,
    extra_args: list[str] | None = None,
) -> int:
    """Handle a scan framework command (net, web, ad, ai).

    Dispatches to the framework script, optionally launching the
    dashboard alongside and setting up multi-target orchestration.

    Returns:
        Exit code.
    """
    name, script_path, desc = FRAMEWORKS[framework_key]
    full_path = BASE_DIR / script_path

    if not full_path.exists():
        print(f"  [!] Framework script not found: {full_path}")
        print(f"  [*] Is the suite properly installed?")
        return 1

    # Validate target specification
    known_args = vars(args)
    target = known_args.get("target")
    targets_file = known_args.get("targets")
    resume_dir = known_args.get("resume")

    try:
        normalized_targets = _validate_common_scan_inputs(args)
    except (FileNotFoundError, ValueError) as exc:
        _audit_scan_denial(
            args,
            framework_key,
            decision_for_reason(ScopeReason.MALFORMED_TARGET),
        )
        print(f"  [!] Invalid scan options ({type(exc).__name__})")
        return 1
    normalized_targets = _normalize_framework_targets(framework_key, normalized_targets)
    if target and normalized_targets:
        args.target = normalized_targets[0]

    forwarded = list(extra_args or [])
    try:
        _validate_forwarded_options(forwarded, framework_key)
        forwarded, protected_values = _extract_protected_forwarded_credentials(
            framework_key,
            forwarded,
        )
    except ValueError:
        print(
            "  [!] Forwarded scan options are unsupported or contain inline "
            "credentials; execution denied."
        )
        return 1
    if protected_values and framework_key not in {"web", "net"}:
        print(
            "  [!] This engine has no protected credential handoff adapter; "
            "execution denied."
        )
        return 1
    args._module_binding = module_set_binding(_forwarded_module_values(forwarded))
    dry_run = bool(known_args.get("dry_run") or "--dry-run" in forwarded)
    handoff_reference = (
        CredentialReference.create("pipe")
        if protected_values and not dry_run
        else None
    )
    credential_bundle = (
        ProtectedCredentialBundle(
            protected_values,
            ttl_seconds=60,
            reference=handoff_reference,
        )
        if handoff_reference is not None
        else None
    )
    dry_run_credential_reference = (
        protected_credential_reference(protected_values)
        if protected_values
        else ""
    )
    if credential_bundle is None:
        wipe_mapping(protected_values)
    args._credential_reference = (
        handoff_reference.value
        if handoff_reference is not None
        else dry_run_credential_reference
        or _forwarded_credential_reference(framework_key, forwarded)
    )
    auto_confirm = bool(known_args.get("auto_confirm") or "--auto-confirm" in forwarded)
    try:
        decision, confirmations, authorizations = _prepare_scan_confirmations(
            args,
            framework_key,
            normalized_targets,
            dry_run=dry_run,
            auto_confirm=auto_confirm,
        )
    except Exception:
        if credential_bundle is not None:
            credential_bundle.wipe()
        raise
    if not decision.allowed:
        if credential_bundle is not None:
            credential_bundle.wipe()
        _audit_scan_denial(
            args,
            framework_key,
            decision,
            target=getattr(
                args,
                "_authorization_denied_target",
                normalized_targets[0] if normalized_targets else target,
            ),
        )
        _print_scan_denial(decision)
        return 1

    if dry_run:
        print(f"  [*] DRY RUN — {name} launch plan (no subprocess created)")
        print("  [*] Authorized: false (scope match is not execution approval)")
        for planned_target in normalized_targets:
            print(f"  [*] Target: {planned_target}")
        return 0

    # Build framework command — start with known args, then append any
    # framework-specific flags that forge.py's parser didn't recognise
    framework_args = _build_framework_args(args, framework_key)
    if forwarded:
        framework_args.extend(forwarded)
    cmd = [sys.executable, str(full_path)] + framework_args
    # A scan child receives a minimal runtime environment rather than a copy
    # of every operator/deployment variable.  In particular, arbitrary
    # provider credentials and connection strings must not cross this
    # boundary; credential material is handed over separately through the
    # one-shot protected pipe below.
    child_env = minimal_child_environment(
        os.environ,
        allowlist={
            "FORGE_TENANT_ID",
            "FORGE_ENABLE_HIGH_RISK",
            "FORGE_KILL_SWITCH",
        },
    )
    child_env[LAUNCH_CONFIRMATIONS_ENV] = encode_launch_confirmations(confirmations)
    child_env[LAUNCH_JOB_ID_ENV] = args._launch_job_id
    child_env[LAUNCH_ACTION_ENV] = args._launch_action
    child_env[AUTHORIZATION_ENVELOPES_ENV] = encode_authorization_envelopes(authorizations)
    child_env[AUTHORIZATION_DB_ENV] = str(default_authorization_db_path())
    runtime_environments = [
        authorization_runtime_environment(envelope)
        for envelope in authorizations
    ]
    if not runtime_environments or any(
        item != runtime_environments[0] for item in runtime_environments[1:]
    ):
        if credential_bundle is not None:
            credential_bundle.wipe()
        print("  [!] Authorization runtime handoff is inconsistent; execution denied.")
        return 1
    child_env.update(runtime_environments[0])

    # Dashboard co-launch
    dashboard_proc = None
    if known_args.get("dashboard"):
        dashboard_proc = _launch_dashboard_background(
            port=known_args.get("dashboard_port", 1337),
            tui=known_args.get("dashboard_tui", False),
        )

    # Log the launch
    print(f"  [*] Launching {name} — {desc}")
    if targets_file:
        print(
            f"  [*] Multi-target mode: {targets_file} "
            f"({len(normalized_targets)} targets, parallel={known_args.get('parallel', 3)})"
        )
    if known_args.get("schedule"):
        print(f"  [*] Scheduled: {known_args['schedule']}")
    if known_args.get("continuous"):
        print(f"  [*] Continuous monitoring: interval={known_args.get('interval', '24h')}")
    if dashboard_proc:
        port = known_args.get("dashboard_port", 1337)
        print(f"  [*] Dashboard: https://localhost:{port}  (accept self-signed cert)")
    print(f"  [*] {_safe_command_display(cmd)}")
    print()

    # Execute
    try:
        if credential_bundle is not None:
            with credential_bundle.open_pipe() as handoff:
                result = subprocess.run(
                    cmd,
                    cwd=str(BASE_DIR),
                    env={**child_env, **handoff.env},
                    pass_fds=handoff.pass_fds,
                )
        else:
            result = subprocess.run(cmd, cwd=str(BASE_DIR), env=child_env)
        return result.returncode
    except KeyboardInterrupt:
        print("\n  [!] Interrupted by user")
        return 130
    finally:
        if credential_bundle is not None:
            credential_bundle.wipe()
        if dashboard_proc:
            _stop_background_dashboard(dashboard_proc)


def _build_framework_args(args: argparse.Namespace, framework_key: str) -> list[str]:
    """Build the argument list to pass to the framework script.

    Translates our unified CLI args into the framework-specific format.
    """
    known = vars(args)
    result = []

    # Target args — pass through directly
    if known.get("target"):
        target_flag = "--dc" if framework_key == "ad" else "--target"
        result.extend([target_flag, known["target"]])
    if known.get("targets"):
        result.extend(["--targets", known["targets"]])
    if known.get("parallel") and known["parallel"] != 3:
        result.extend(["--parallel", str(known["parallel"])])
    if known.get("resume"):
        result.extend(["--resume", known["resume"]])

    for scope_entry in known.get("scope") or []:
        result.extend(["--scope", scope_entry])
    for excluded_entry in known.get("exclude") or []:
        result.extend(["--exclude", excluded_entry])
    if known.get("auto_confirm"):
        result.append("--auto-confirm")

    # Schedule args
    if known.get("schedule"):
        result.extend(["--schedule", known["schedule"]])
    if known.get("continuous"):
        result.append("--continuous")
    if known.get("interval") and known["interval"] != "24h":
        result.extend(["--interval", known["interval"]])

    # Intel args
    if known.get("auto_update"):
        result.append("--auto-update")
    if known.get("offline"):
        result.append("--offline")

    # Output
    if known.get("output_dir"):
        result.extend(["--output", known["output_dir"]])

    # Pass the requested dashboard destination through so the engine can report
    # its current fail-closed control-plane authorization state truthfully.
    if known.get("dashboard"):
        port = known.get("dashboard_port", 1337)
        result.extend(["--dashboard-url", f"https://localhost:{port}"])

    return result


def handle_dashboard(args: argparse.Namespace) -> int:
    """Handle the dashboard command — launch standalone dashboard.

    Returns:
        Exit code.
    """
    tui_mode = args.tui
    attach_dir = args.attach
    replay_dir = args.replay

    if tui_mode:
        return _launch_tui_dashboard(attach_dir=attach_dir)
    else:
        return _launch_web_dashboard(
            host=args.host,
            port=args.port,
            auth=not args.no_auth,
            attach_dir=attach_dir,
            replay_dir=replay_dir,
        )


def _launch_web_dashboard(
    host: str = "127.0.0.1",
    port: int = 1337,
    auth: bool = True,
    attach_dir: str | None = None,
    replay_dir: str | None = None,
) -> int:
    """Launch the web dashboard server."""
    if not auth:
        print("  [!] Dashboard authentication is mandatory; --no-auth is disabled.")
        return 1

    try:
        from common.dashboard.server import DashboardServer
        from common.dashboard.event_bus import EventBus
        from common.dashboard.state_store import StateStore
    except ImportError as e:
        print(f"  [!] Dashboard dependencies missing ({type(e).__name__})")
        print(f"  [*] Run: pip install fastapi uvicorn[standard] websockets")
        return 1

    tenant_id = os.environ.get("FORGE_TENANT_ID", "default").strip() or "default"
    bus = EventBus(run_id="dashboard")
    store = StateStore(
        bus,
        framework="forge",
        target="",
        tenant_id=tenant_id,
    )

    # Attach to existing engagement if requested
    if attach_dir:
        print(f"  [*] Attaching to engagement: {attach_dir}")
        # TODO: Load state from engagement DB

    server = DashboardServer(
        event_bus=bus,
        state_store=store,
        host=host,
        port=port,
        auth=auth,
    )

    # Force UTF-8 output on Windows (BANNER contains Unicode block chars)
    import sys as _sys
    if hasattr(_sys.stdout, "reconfigure"):
        try:
            _sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    print(BANNER)
    print(f"  [*] War Room Dashboard starting...")
    print(f"  [*] URL: https://localhost:{port}  (accept self-signed cert in browser)")
    print()

    try:
        asyncio.run(server.start())
    except KeyboardInterrupt:
        print("\n  [*] Dashboard shutdown.")
    return 0


def _launch_tui_dashboard(attach_dir: str | None = None) -> int:
    """Launch the Rich terminal TUI dashboard."""
    try:
        from common.dashboard.tui.war_room_tui import WarRoomTUI, launch_tui
        from common.dashboard.event_bus import EventBus
        from common.dashboard.state_store import StateStore
    except ImportError as e:
        print(f"  [!] TUI dependencies missing ({type(e).__name__})")
        print(f"  [*] Run: pip install rich")
        return 1

    tenant_id = os.environ.get("FORGE_TENANT_ID", "default").strip() or "default"
    bus = EventBus(run_id="tui")
    store = StateStore(
        bus,
        framework="forge",
        target="",
        tenant_id=tenant_id,
    )

    if attach_dir:
        print(f"  [*] Attaching to engagement: {attach_dir}")

    launch_tui(event_bus=bus, state_store=store)
    return 0


def _launch_dashboard_background(
    port: int = 1337,
    tui: bool = False,
) -> subprocess.Popen | None:
    """Launch the dashboard as a background process.

    Used when --dashboard flag is passed to a scan command.
    Returns the subprocess handle for cleanup.
    """
    if tui:
        # TUI runs in the same terminal — can't background
        return None

    if not any(
        os.environ.get(name, "").strip()
        for name in (
            "FORGE_DASHBOARD_PASSWORD",
            "FORGE_DASHBOARD_PASSWORD_HASH",
            "FORGE_SSO_ISSUER",
        )
    ):
        log.warning(
            "Background dashboard not started: configure dashboard password/hash or SSO"
        )
        return None

    cmd = [
        sys.executable, str(BASE_DIR / "forge.py"),
        "dashboard",
        "--host", "127.0.0.1",
        "--port", str(port),
    ]
    try:
        pidfd_open = getattr(os, "pidfd_open", None)
        pidfd_signal = getattr(signal, "pidfd_send_signal", None)
        if os.name == "posix" and (
            not callable(pidfd_open) or not callable(pidfd_signal)
        ):
            log.warning(
                "Background dashboard not started: PID-safe control unavailable"
            )
            return None
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=str(BASE_DIR),
            env=minimal_child_environment(
                os.environ,
                allowlist={
                    "FORGE_TENANT_ID",
                    "FORGE_DASHBOARD_PASSWORD",
                    "FORGE_DASHBOARD_PASSWORD_HASH",
                    "FORGE_DASHBOARD_USER",
                    "FORGE_DASHBOARD_ROLE",
                    "FORGE_DASHBOARD_TOTP_SECRET",
                    "FORGE_DASHBOARD_PUBLIC_HOST",
                    "FORGE_DASHBOARD_ALLOWED_HOSTS",
                    "FORGE_DASHBOARD_TLS_CERT",
                    "FORGE_DASHBOARD_TLS_KEY",
                    "FORGE_SSO_ENABLED",
                    "FORGE_SSO_ISSUER",
                    "FORGE_SSO_AUTH_URL",
                    "FORGE_SSO_TOKEN_URL",
                    "FORGE_SSO_USERINFO_URL",
                    "FORGE_SSO_JWKS_URI",
                    "FORGE_SSO_CLIENT_ID",
                    "FORGE_SSO_CLIENT_SECRET",
                    "FORGE_SSO_PROVIDER_NAME",
                    "FORGE_SSO_REDIRECT_URI",
                    "FORGE_SSO_SCOPES",
                    "FORGE_SSO_DEFAULT_ROLE",
                    "FORGE_SSO_ALLOWED_DOMAINS",
                    "FORGE_SSO_ADMIN_EMAILS",
                    "FORGE_SSO_OPERATOR_GROUPS",
                    "FORGE_SSO_VIEWER_GROUPS",
                    "FORGE_SSO_PKCE",
                    "FORGE_KILL_SWITCH",
                    "FORGE_AGENT_LEASE_SECONDS",
                    "FORGE_AGENT_LEASE_MAX_SECONDS",
                    "FORGE_AGENT_REGISTRATION_TOKEN",
                },
            ),
        )
        process_pid = getattr(proc, "pid", None)
        if os.name == "posix" and isinstance(process_pid, int):
            assert callable(pidfd_open)
            setattr(proc, "_forge_pidfd", int(pidfd_open(process_pid, 0)))
        return proc
    except Exception as e:
        log.warning(
            "Failed to launch background dashboard (%s)",
            type(e).__name__,
        )
        return None


def _stop_background_dashboard(process: subprocess.Popen[Any]) -> None:
    """Stop the CLI-owned dashboard only through a stable OS capability."""

    pidfd = getattr(process, "_forge_pidfd", None)
    try:
        if isinstance(pidfd, int):
            signal.pidfd_send_signal(pidfd, signal.SIGTERM)
        elif os.name == "nt":
            process.send_signal(signal.SIGTERM)
        elif not isinstance(getattr(process, "pid", None), int):
            # Unit-test doubles have no OS process identity.
            getattr(process, "terminate")()
        else:
            log.warning(
                "Refusing to stop background dashboard without PID capability"
            )
    finally:
        if isinstance(pidfd, int):
            os.close(pidfd)
            setattr(process, "_forge_pidfd", None)


def handle_c2(args: argparse.Namespace) -> int:
    """Handle C2 framework commands.

    Returns:
        Exit code.
    """
    action = args.c2_action
    if not action:
        print("  [!] No C2 action specified.")
        print("  [*] Available: server, connect, listener, payload")
        print("  [*] Run: python3 forge.py c2 --help")
        return 1

    if action == "server":
        return _handle_c2_server(args)
    elif action == "connect":
        return _handle_c2_connect(args)
    elif action == "listener":
        return _handle_c2_listener(args)
    elif action == "payload":
        return _handle_c2_payload(args)
    return 1


def _handle_c2_server(args: argparse.Namespace) -> int:
    """Start the C2 team server."""
    return _deny_legacy_active_action(
        "c2.server",
        f"{args.bind}:{args.port}",
        safety_mode=SafetyMode.HIGH_RISK,
    )


def _handle_c2_connect(args: argparse.Namespace) -> int:
    """Connect to a C2 team server."""
    return _deny_legacy_active_action(
        "c2.connect",
        str(args.server),
        safety_mode=SafetyMode.HIGH_RISK,
    )


def _handle_c2_listener(args: argparse.Namespace) -> int:
    """Manage C2 listeners."""
    return _deny_legacy_active_action(
        "c2.listener",
        f"{getattr(args, 'host', '')}:{getattr(args, 'port', '')}",
        safety_mode=SafetyMode.HIGH_RISK,
    )


def _handle_c2_payload(args: argparse.Namespace) -> int:
    """Generate a C2 beacon payload."""
    return _deny_legacy_active_action(
        "c2.payload",
        f"{args.lhost}:{args.lport}",
        safety_mode=SafetyMode.HIGH_RISK,
    )


def handle_intel(args: argparse.Namespace) -> int:
    """Handle intelligence pipeline commands.

    Returns:
        Exit code.
    """
    action = args.intel_action
    if not action:
        print("  [!] No intel action specified.")
        print("  [*] Available: sync, search, status")
        print("  [*] Run: python3 forge.py intel --help")
        return 1

    if action == "sync":
        return _handle_intel_sync(args)
    elif action == "search":
        return _handle_intel_search(args)
    elif action == "status":
        return _handle_intel_status(args)
    return 1


def _handle_intel_sync(args: argparse.Namespace) -> int:
    """Sync intelligence databases."""
    sources = []
    if args.sync_all:
        sources = ["cve", "exploits", "nuclei", "techniques"]
    else:
        if args.cve:
            sources.append("cve")
        if args.exploits:
            sources.append("exploits")
        if args.nuclei:
            sources.append("nuclei")
        if args.techniques:
            sources.append("techniques")
    if not sources:
        print("  [!] No sync sources specified.")
        print("  [*] Use --all, --cve, --exploits, --nuclei, or --techniques")
        return 1
    return _deny_legacy_active_action(
        "intel.sync",
        "intel-update",
        safety_mode=SafetyMode.ACTIVE,
    )


def _handle_intel_search(args: argparse.Namespace) -> int:
    """Search local intelligence."""
    try:
        from common.intel.intel_engine import IntelEngine
    except ImportError:
        print("  [!] Intel engine module not yet available.")
        return 1

    query = args.query or args.cve or args.product
    if not query:
        print("  [!] No search query specified.")
        return 1

    engine = IntelEngine()
    results = engine.search(query=query, limit=args.limit)
    for r in results:
        print(f"  {r}")
    return 0


def _handle_intel_status(args: argparse.Namespace) -> int:
    """Show intel sync status."""
    try:
        from common.intel.intel_engine import IntelEngine
    except ImportError:
        print("  [!] Intel engine module not yet available.")
        return 1

    engine = IntelEngine()
    print(engine.status())
    return 0


def handle_autonomous(args: argparse.Namespace) -> int:
    """Handle the autonomous VAPT command.

    Runs a fully AI-driven engagement from RECON → REPORT.

    Returns:
        Exit code.
    """
    return _deny_legacy_active_action(
        "autonomous.engagement",
        str(getattr(args, "target", "autonomous-target")),
        safety_mode=SafetyMode.HIGH_RISK,
    )


def handle_collab(args: argparse.Namespace) -> int:
    """Handle ForgeCollab OOB server commands.

    Returns:
        Exit code.
    """
    action = getattr(args, "collab_action", None)
    if not action:
        print("  [!] No collab action specified.")
        print("  [*] Available: start, token")
        print("  [*] Run: python3 forge.py collab --help")
        return 1

    if action == "start":
        return _handle_collab_start(args)
    elif action == "token":
        return _handle_collab_token(args)
    return 1


def handle_agent(args: argparse.Namespace) -> int:
    """Run the passive scan-agent worker."""
    try:
        from forge_agent import run_agent
    except ImportError as exc:
        print(f"  [!] Scan agent not available ({type(exc).__name__})")
        return 1
    try:
        return run_agent(args)
    except KeyboardInterrupt:
        print("\n  [*] Scan agent stopped.")
        return 130
    except Exception as exc:
        print(f"  [!] Scan agent failed ({type(exc).__name__})")
        return 1


def _handle_collab_start(args: argparse.Namespace) -> int:
    """Start the ForgeCollab OOB server."""
    return _deny_legacy_active_action(
        "collab.start",
        f"{args.listen}:{args.http_port}",
        safety_mode=SafetyMode.LOCAL_LAB if args.local else SafetyMode.ACTIVE,
    )


def _handle_collab_token(args: argparse.Namespace) -> int:
    """Generate and display a ForgeCollab test token."""
    import uuid as _uuid
    domain = os.environ.get("FORGE_COLLAB_DOMAIN", "collab.forge.local")
    token = _uuid.uuid4().hex[:24]
    print(f"  [*] OOB Token: {token}")
    print(f"  [*] HTTP URL:  http://{token}.{domain}/")
    print(f"  [*] DNS host:  {token}.{domain}")
    print(f"  [*] Email:     {token}@{domain}")
    print(f"  [*] Poll:      http://127.0.0.1:8889/api/callbacks/{token}")
    return 0


def handle_payload(args: argparse.Namespace) -> int:
    """Handle standalone payload generation.

    Returns:
        Exit code.
    """
    # BYOVD driver reference table
    if getattr(args, "byovd", False):
        try:
            from forge_payload.evasion.byovd import print_driver_table
            print(print_driver_table())
        except ImportError:
            print("  [!] BYOVD module not available")
        return 0

    if args.list_payloads:
        try:
            from forge_payload.payload_factory import PayloadFactory
            print(PayloadFactory.list_payloads())
        except ImportError:
            print("  [!] forge_payload/ module not found — check installation")
        return 0

    return _deny_legacy_active_action(
        "payload.generate",
        str(getattr(args, "lhost", "payload-target")),
        safety_mode=SafetyMode.HIGH_RISK,
    )


def _is_high_risk_enabled(args: argparse.Namespace) -> bool:
    """Require both an explicit CLI flag and environment opt-in for high-risk paths."""
    has_cli_ack = bool(getattr(args, "red_team", False))
    has_env_ack = os.environ.get("FORGE_ENABLE_HIGH_RISK", "").strip().lower() in TRUTHY_ENV
    return has_cli_ack and has_env_ack


def _print_high_risk_notice(feature: str) -> None:
    """Explain why a high-risk command is blocked."""
    print(f"  [!] {feature} is disabled by default.")
    print("  [*] Required for authorized engagements: --red-team and FORGE_ENABLE_HIGH_RISK=1")
    print("  [*] Safer audit workflows remain available through: forge.py web|net|ad|ai")


def handle_import_session(args: argparse.Namespace) -> int:
    """Import a session JSON into the forge brain and engagement DB."""
    session_path = Path(args.session_file)
    if not session_path.exists():
        print(f"  [!] Session file not found: {session_path}")
        return 1

    return _deny_legacy_active_action(
        "session.import",
        str(session_path),
        safety_mode=SafetyMode.STANDARD,
    )


# ══════════════════════════════════════════════════════════════════════
# HELP DISPLAY
# ══════════════════════════════════════════════════════════════════════

def print_help():
    """Print the main usage help with all commands."""
    print(BANNER)
    print(f"  Forge Suite v{VERSION} APEX — Offensive Security Platform")
    print("  " + "=" * 55)
    print()
    print("  Usage: python3 forge.py <command> [options]")
    print()
    print("  ─── Scan Frameworks ───────────────────────────────────")
    for key, (name, script, desc) in FRAMEWORKS.items():
        print(f"    {key:10s}  {desc}")
    print()
    print("  ─── Platform Commands ────────────────────────────────")
    print(f"    {'dashboard':10s}  Launch the War Room dashboard")
    print(f"    {'c2':10s}  Active C2 commands blocked pending an authorization adapter")
    print(f"    {'intel':10s}  Local intelligence search/status; network sync blocked")
    print(f"    {'payload':10s}  Reference listing only; generation blocked")
    print(f"    {'import-session':10s}  Blocked pending an authorization adapter")
    print(f"    {'auto':10s}  Blocked pending an authorization adapter")
    print(f"    {'collab':10s}  Token generation only; listener start blocked")
    print(f"    {'agent':10s}  Passive distributed scan agent")
    print()
    print("  ─── Scan Options ─────────────────────────────────────")
    print("    --target <target>      Single target (URL, IP, CIDR)")
    print("    --targets <file>       Multi-target from file")
    print("    --parallel <N>         Max parallel targets (default: 3)")
    print("    --dashboard            Launch dashboard alongside scan")
    print("    --schedule <spec>      Schedule scan (HH:MM, daily:HH:MM)")
    print("    --continuous           Continuous monitoring mode")
    print("    --auto-update          Sync intel before scan")
    print("    --offline              Use cached intel only")
    print()
    print("  ─── Examples ─────────────────────────────────────────")
    print("    python3 forge.py net --target 10.0.0.0/24 --mode internal")
    print("    python3 forge.py web --target https://example.com --dashboard")
    print("    python3 forge.py web --targets targets.txt --parallel 5")
    print("    python3 forge.py net --targets hosts.txt --schedule daily:02:00")
    print("    python3 forge.py dashboard --tui")
    print("    python3 forge.py agent --dashboard-url http://127.0.0.1:1337 --scope 10.0.0.0/24 --once")
    print("    python3 forge.py intel search CVE-2024-1234")
    print("    python3 forge.py collab token")
    print()
    print("  For command-specific help:")
    print("    python3 forge.py dashboard --help")
    print("    python3 forge.py c2 --help")
    print("    python3 forge.py intel --help")
    print("    python3 forge.py payload --help")
    print("    python3 forge.py agent --help")
    print()


# ══════════════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ══════════════════════════════════════════════════════════════════════

def main() -> int:
    """Main entry point for Forge Suite."""
    if len(sys.argv) == 2 and sys.argv[1] == "--version":
        print(f"Forge Suite v{VERSION}")
        return 0
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help", "help"):
        print_help()
        return 0

    command = sys.argv[1].lower()

    # Resolve framework aliases
    if command in ALIASES:
        command = ALIASES[command]

    # Framework scan commands — special handling because frameworks
    # have their own argparse and we pass through unknown args
    if command in FRAMEWORKS:
        parser = build_parser()
        # Parse only known args — unknown args are framework-specific and
        # get forwarded verbatim (e.g. --mode, --red-team, --opsec, --capture)
        args, unknown = parser.parse_known_args()
        return handle_scan(args, command, extra_args=unknown)

    # Platform commands — full argparse parsing
    if command in ("dashboard", "c2", "intel", "payload", "import-session", "auto", "collab", "agent"):
        parser = build_parser()
        args = parser.parse_args()

        if command == "dashboard":
            return handle_dashboard(args)
        elif command == "c2":
            return handle_c2(args)
        elif command == "intel":
            return handle_intel(args)
        elif command == "payload":
            return handle_payload(args)
        elif command == "import-session":
            return handle_import_session(args)
        elif command == "auto":
            return handle_autonomous(args)
        elif command == "collab":
            return handle_collab(args)
        elif command == "agent":
            return handle_agent(args)

    # Unknown command
    print(f"  [!] Unknown command: '{sys.argv[1]}'")
    print(f"  [*] Available: {', '.join(list(FRAMEWORKS.keys()) + ['dashboard', 'c2', 'intel', 'payload', 'import-session', 'auto', 'collab', 'agent'])}")
    print(f"  [*] Run 'python3 forge.py --help' for usage")
    return 1


if __name__ == "__main__":
    sys.exit(main())
