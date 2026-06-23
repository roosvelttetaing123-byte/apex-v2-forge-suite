#!/usr/bin/env python3
"""Forge Suite v5 APEX — Unified Launcher.

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
import os
import sys
import subprocess
import logging
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

log = logging.getLogger("forge")

BANNER = r"""
  ██████╗ ██████╗ ██████╗  ██████╗ ███████╗    ███████╗██╗   ██╗██╗████████╗███████╗
  ██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝    ██╔════╝██║   ██║██║╚══██╔══╝██╔════╝
  █████╗  ██║   ██║██████╔╝██║  ███╗█████╗      ███████╗██║   ██║██║   ██║   █████╗
  ██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝      ╚════██║██║   ██║██║   ██║   ██╔══╝
  ██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗    ███████║╚██████╔╝██║   ██║   ███████╗
  ╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝    ╚══════╝ ╚═════╝ ╚═╝   ╚═╝   ╚══════╝

                          v5.0.0 APEX — Offensive Platform
"""

VERSION = "5.0.0"

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


# ══════════════════════════════════════════════════════════════════════
# ARGUMENT PARSER
# ══════════════════════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    """Construct the full CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="forge",
        description="Forge Suite v5 APEX — Unified Offensive Security Platform",
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
        fw_parser = subparsers.add_parser(key, help=desc, add_help=False)
        _add_common_scan_args(fw_parser)

    # ── Dashboard ──────────────────────────────────────────────────
    dash = subparsers.add_parser("dashboard", help="Launch the War Room dashboard")
    dash.add_argument("--host", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    dash.add_argument("--port", type=_port, default=1337, help="Bind port (default: 1337)")
    dash.add_argument("--tui", action="store_true", help="Launch Rich terminal TUI instead of web")
    dash.add_argument("--no-auth", action="store_true", help="Disable dashboard authentication")
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
        raise ValueError(f"target contains whitespace: {target!r}")
    parsed = urlparse(value if "://" in value else f"https://{value}")
    if "://" in value and parsed.scheme not in {"http", "https"}:
        raise ValueError(f"unsupported URL scheme for scan target: {parsed.scheme}")
    host = parsed.hostname if parsed.hostname else value.split("/", 1)[0]
    if not host:
        raise ValueError(f"missing target host: {target!r}")
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

    targets = [_validate_target_value(item) for item in _read_targets_file(targets_file)]
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
        print(f"  [!] Invalid scan options: {exc}")
        return 1

    # Build framework command — start with known args, then append any
    # framework-specific flags that forge.py's parser didn't recognise
    framework_args = _build_framework_args(args, framework_key)
    if extra_args:
        framework_args.extend(extra_args)
    cmd = [sys.executable, str(full_path)] + framework_args

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
    print(f"  [*] {' '.join(cmd)}")
    print()

    # Execute
    try:
        result = subprocess.run(cmd, cwd=str(BASE_DIR))
        return result.returncode
    except KeyboardInterrupt:
        print("\n  [!] Interrupted by user")
        return 130
    finally:
        if dashboard_proc:
            dashboard_proc.terminate()


def _build_framework_args(args: argparse.Namespace, framework_key: str) -> list[str]:
    """Build the argument list to pass to the framework script.

    Translates our unified CLI args into the framework-specific format.
    """
    known = vars(args)
    result = []

    # Target args — pass through directly
    if known.get("target"):
        result.extend(["--target", known["target"]])
    if known.get("targets"):
        result.extend(["--targets", known["targets"]])
    if known.get("parallel") and known["parallel"] != 3:
        result.extend(["--parallel", str(known["parallel"])])
    if known.get("resume"):
        result.extend(["--resume", known["resume"]])

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

    # Dashboard relay — tell the framework where to stream events.
    # Dashboard always runs HTTPS (self-signed cert); RemoteEventBus skips verify.
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
    host: str = "0.0.0.0",
    port: int = 1337,
    auth: bool = True,
    attach_dir: str | None = None,
    replay_dir: str | None = None,
) -> int:
    """Launch the web dashboard server."""
    if not auth and host not in {"127.0.0.1", "localhost", "::1"}:
        print("  [!] Refusing to disable dashboard authentication on a non-loopback bind address.")
        print("  [*] Use --host 127.0.0.1 with --no-auth, or leave authentication enabled.")
        return 1

    try:
        from common.dashboard.server import DashboardServer
        from common.dashboard.event_bus import EventBus
        from common.dashboard.state_store import StateStore
    except ImportError as e:
        print(f"  [!] Dashboard dependencies missing: {e}")
        print(f"  [*] Run: pip install fastapi uvicorn[standard] websockets")
        return 1

    bus = EventBus(run_id="dashboard")
    store = StateStore(bus, framework="forge", target="")

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
    if not auth:
        print(f"  [*] Authentication DISABLED — no login required")
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
        print(f"  [!] TUI dependencies missing: {e}")
        print(f"  [*] Run: pip install rich")
        return 1

    bus = EventBus(run_id="tui")
    store = StateStore(bus, framework="forge", target="")

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

    cmd = [
        sys.executable, str(BASE_DIR / "forge.py"),
        "dashboard",
        "--host", "127.0.0.1",
        "--port", str(port),
        "--no-auth",
    ]
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=str(BASE_DIR),
        )
        return proc
    except Exception as e:
        log.warning("Failed to launch background dashboard: %s", e)
        return None


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
    if not _is_high_risk_enabled(args):
        _print_high_risk_notice("C2 server")
        return 1

    try:
        from forge_c2.server import C2Server
    except ImportError:
        print("  [!] C2 server module not yet available.")
        print("  [*] The C2 server (forge_c2/server.py) is planned for a future build.")
        return 1

    print(BANNER)
    print(f"  [*] C2 Team Server starting on {args.bind}:{args.port}")
    if args.dashboard:
        print(f"  [*] Dashboard co-launching on port 1337")
    print()

    try:
        server = C2Server(host=args.bind, port=args.port)
        asyncio.run(server.start())
    except KeyboardInterrupt:
        print("\n  [*] C2 server shutdown.")
    return 0


def _handle_c2_connect(args: argparse.Namespace) -> int:
    """Connect to a C2 team server."""
    try:
        from forge_c2.operator_shell import OperatorShell
    except ImportError:
        print("  [!] Operator shell module not yet available.")
        print("  [*] The operator shell (forge_c2/operator_shell.py) is planned for a future build.")
        return 1

    print(f"  [*] Connecting to team server: {args.server}")
    print(f"  [*] Operator: {args.user}")
    try:
        shell = OperatorShell(server=args.server, user=args.user)
        shell.run()
    except KeyboardInterrupt:
        print("\n  [*] Disconnected.")
    return 0


def _handle_c2_listener(args: argparse.Namespace) -> int:
    """Manage C2 listeners."""
    if not _is_high_risk_enabled(args):
        _print_high_risk_notice("C2 listener management")
        return 1

    print(f"  [*] C2 Listener: {args.action}")
    print("  [!] Listener management requires a running C2 server.")
    print("  [*] Start a server first: python3 forge.py c2 server")
    return 1


def _handle_c2_payload(args: argparse.Namespace) -> int:
    """Generate a C2 beacon payload."""
    if not _is_high_risk_enabled(args):
        _print_high_risk_notice("C2 payload generation")
        print("  [*] Usage: FORGE_ENABLE_HIGH_RISK=1 forge.py c2 payload --red-team --type beacon_https --lhost 10.0.0.5 --format exe")
        return 1

    try:
        from forge_payload.payload_factory import PayloadFactory
    except ImportError:
        print("  [!] forge_payload/ module not found — run: pip install -r requirements.txt")
        return 1

    print(f"  [*] Generating C2 payload: type={args.type}")
    print(f"  [*] Callback: {args.lhost}:{args.lport}")
    print(f"  [*] Format: {args.format} | Arch: {args.arch}")
    try:
        output = PayloadFactory().generate(
            payload_type=args.type,
            lhost=args.lhost,
            lport=args.lport,
            fmt=args.format,
            arch=args.arch,
            output_path=getattr(args, "output", "") or "",
        )
    except ValueError as exc:
        print(f"  [!] Unsupported payload option: {exc}")
        print("  [*] Run: forge.py payload --list")
        return 1
    print(f"  [+] Payload written to: {output}")
    return 0


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
    try:
        from common.intel.intel_engine import IntelEngine
    except ImportError:
        print("  [!] Intel engine module not yet available.")
        print("  [*] The intel pipeline (common/intel/) is planned for a future build.")
        return 1

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

    print(f"  [*] Syncing intel sources: {', '.join(sources)}")
    engine = IntelEngine()
    engine.sync(sources=sources, since=args.since)
    return 0


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
    if getattr(args, "brain_key", None):
        os.environ["ANTHROPIC_API_KEY"] = args.brain_key

    try:
        from common.brain.autonomous import AutonomousEngine, EngagementConfig, OpsecLevel
        from common.brain.brain import ForgeBrain
        from common.brain.planner import AttackPlanner
        from common.brain.analyst import FindingAnalyst
        from common.brain.narrator import ReportNarrator
        from common.brain.engagement_bus import EngagementBus
    except ImportError as exc:
        print(f"  [!] Brain modules not available: {exc}")
        return 1

    print(BANNER)
    frameworks = [f.strip() for f in args.frameworks.split(",")]
    opsec = OpsecLevel(args.opsec)

    print(f"  [*] Autonomous VAPT starting")
    print(f"  [*] Target:       {args.target}")
    print(f"  [*] Frameworks:   {', '.join(frameworks)}")
    print(f"  [*] Opsec level:  {opsec.value}")
    print(f"  [*] Max time:     {args.max_time}s")
    print(f"  [*] Brain:        {'AI-powered' if os.environ.get('ANTHROPIC_API_KEY') else 'rule-based (no API key)'}")
    print()

    brain = ForgeBrain()
    planner = AttackPlanner(brain)
    analyst = FindingAnalyst(brain)
    narrator = ReportNarrator(brain)
    eng_bus = EngagementBus.get_instance(brain=brain, planner=planner)

    engine = AutonomousEngine(
        brain=brain,
        planner=planner,
        engagement_bus=eng_bus,
        narrator=narrator,
        analyst=analyst,
    )

    config = EngagementConfig(
        target=args.target,
        frameworks=frameworks,
        opsec_level=opsec,
        stop_on_critical=not getattr(args, "no_stop_on_critical", False),
        max_findings=args.max_findings,
        max_time_seconds=float(args.max_time),
        fn_sweep_enabled=not getattr(args, "no_fn_sweep", False),
    )

    try:
        report = asyncio.run(engine.run_engagement(config))
    except KeyboardInterrupt:
        print("\n  [!] Autonomous engagement aborted by operator")
        return 130

    print(f"\n  [+] Engagement complete: {report.engagement_id}")
    print(f"  [+] Stop reason:  {report.stop_reason.value}")
    print(f"  [+] Duration:     {report.duration_seconds:.0f}s")
    print(f"  [+] Findings:     {report.findings_summary.get('total', 0)}")
    print(f"  [+] Phase:        {report.phase_reached.value}")

    # Write report to file if output dir specified
    output_dir = getattr(args, "output_dir", None)
    if output_dir:
        import json as _json
        import pathlib as _pl
        _pl.Path(output_dir).mkdir(parents=True, exist_ok=True)
        report_path = _pl.Path(output_dir) / f"autonomous_{report.engagement_id}.json"
        with open(report_path, "w") as f:
            _json.dump(report.to_dict(), f, indent=2)
        print(f"  [+] Report saved: {report_path}")

        if report.executive_summary:
            summary_path = _pl.Path(output_dir) / f"executive_summary_{report.engagement_id}.md"
            summary_path.write_text(report.executive_summary)
            print(f"  [+] Executive summary: {summary_path}")

    return 0


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


def _handle_collab_start(args: argparse.Namespace) -> int:
    """Start the ForgeCollab OOB server."""
    try:
        from forge_collab.server import ForgeCollabServer
    except ImportError as exc:
        print(f"  [!] ForgeCollab not available: {exc}")
        return 1

    print(BANNER)
    domain = args.domain or os.environ.get("FORGE_COLLAB_DOMAIN", "collab.forge.local")
    print(f"  [*] ForgeCollab starting — domain: {domain}")
    print(f"  [*] HTTP:  {args.listen}:{args.http_port}")
    if not args.local:
        print(f"  [*] DNS:   {args.listen}:{args.dns_port}")
        print(f"  [*] SMTP:  {args.listen}:{args.smtp_port}")
    print(f"  [*] API:   127.0.0.1:{args.api_port}")
    print(f"  [*] Token: {{token}}.{domain}")
    print()

    server = ForgeCollabServer(
        domain=domain,
        listen_ip=args.listen,
        http_port=args.http_port,
        dns_port=0 if args.local else args.dns_port,
        smtp_port=0 if args.local else args.smtp_port,
        api_port=args.api_port,
        response_ip=args.response_ip,
        local_mode=args.local,
    )
    try:
        asyncio.run(server.run_forever())
    except KeyboardInterrupt:
        print("\n  [*] ForgeCollab stopped.")
    return 0


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

    if not args.lhost:
        print("  [!] Missing required callback host: --lhost")
        print("  [*] Usage: forge.py payload --red-team --type reverse_tcp --lhost 10.0.0.5 --format exe")
        return 1
    try:
        _validate_target_value(args.lhost)
        _validate_kill_date(getattr(args, "kill_date", ""))
    except ValueError as exc:
        print(f"  [!] Invalid payload option: {exc}")
        return 1

    # Require --red-team flag for payload generation
    if not _is_high_risk_enabled(args):
        _print_high_risk_notice("Payload generation")
        print("  [*] Usage: FORGE_ENABLE_HIGH_RISK=1 forge.py payload --red-team --type reverse_tcp --lhost 10.0.0.5 ...")
        return 1

    try:
        from forge_payload.payload_factory import PayloadFactory
    except ImportError:
        print("  [!] forge_payload/ module not found — run: pip install -r requirements.txt")
        return 1

    print(BANNER)
    print(f"  [*] Payload Generation — Forge Suite v5 APEX")
    print(f"  [*] Type:           {args.type}")
    print(f"  [*] Callback:       {args.lhost}:{args.lport}")
    print(f"  [*] Format:         {args.format}")
    print(f"  [*] Arch:           {args.arch}")
    print(f"  [*] Encoding:       {args.encode}")
    if args.encode != "none":
        print(f"  [*] Iterations:     {args.iterations}")
    if getattr(args, "env_key", ""):
        print(f"  [*] Env keying:     {args.env_key}")
    if getattr(args, "kill_date", ""):
        print(f"  [*] Kill date:      {args.kill_date}")
    evasion_flags = []
    if getattr(args, "sandbox_detect", True):
        evasion_flags.append("sandbox-detect")
    if getattr(args, "amsi_bypass", True):
        evasion_flags.append("AMSI-bypass")
    if getattr(args, "etw_bypass", True):
        evasion_flags.append("ETW-bypass")
    if getattr(args, "sleep_mask", False):
        evasion_flags.append("sleep-mask")
    if getattr(args, "indirect_syscalls", False):
        evasion_flags.append("indirect-syscalls")
    if getattr(args, "ppid_spoof", False):
        evasion_flags.append("PPID-spoof")
    if evasion_flags:
        print(f"  [*] Evasion:        {', '.join(evasion_flags)}")
    print()

    factory = PayloadFactory()
    output = factory.generate(
        payload_type=args.type,
        lhost=args.lhost,
        lport=args.lport,
        fmt=args.format,
        arch=args.arch,
        encoder=args.encode,
        iterations=args.iterations,
        output_path=getattr(args, "output", ""),
        env_key=getattr(args, "env_key", ""),
        kill_date=getattr(args, "kill_date", ""),
        sleep_seconds=getattr(args, "sleep_seconds", 60),
        jitter_percent=getattr(args, "jitter_percent", 30),
        sandbox_detect=getattr(args, "sandbox_detect", True),
        amsi_bypass=getattr(args, "amsi_bypass", True),
        etw_bypass=getattr(args, "etw_bypass", True),
        sleep_mask=getattr(args, "sleep_mask", False),
        indirect_syscalls=getattr(args, "indirect_syscalls", False),
        ppid_spoof=getattr(args, "ppid_spoof", False),
    )
    print(f"  [+] Payload written to: {output}")
    return 0


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

    print(BANNER)
    print(f"  [*] Importing session: {session_path}")
    print()

    try:
        from common.brain.brain import ForgeBrain
        from common.brain.engagement_bus import EngagementBus
    except ImportError as exc:
        print(f"  [!] Failed to import brain modules: {exc}")
        return 1

    brain = ForgeBrain()
    db_path = getattr(args, "db", None) or "engagement.db"
    bus = EngagementBus(db_path=db_path, brain=brain)

    async def _run() -> dict:
        return await bus.load_engagement_session(session_path)

    stats = asyncio.run(_run())

    print(f"  [+] Session imported successfully!")
    print(f"      Target:           {stats['target']}")
    print(f"      Findings loaded:  {stats['findings_loaded']}")
    print(f"      Credentials:      {stats['credentials_loaded']}")
    print(f"      Brain events:     {stats['brain_events_seeded']}")
    print(f"      DB:               {db_path}")
    print()
    return 0


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
    print(f"    {'c2':10s}  Command & Control framework")
    print(f"    {'intel':10s}  Intelligence pipeline (CVE sync, search)")
    print(f"    {'payload':10s}  Payload generation factory")
    print(f"    {'import-session':10s}  Import engagement session JSON into brain")
    print(f"    {'auto':10s}  Autonomous AI-driven VAPT engagement (RECON→REPORT)")
    print(f"    {'collab':10s}  ForgeCollab OOB callback server (blind vuln confirmation)")
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
    print("    FORGE_ENABLE_HIGH_RISK=1 python3 forge.py c2 server --red-team --port 8443")
    print("    python3 forge.py intel sync --all")
    print("    FORGE_ENABLE_HIGH_RISK=1 python3 forge.py payload --red-team --type reverse_tcp --lhost 10.0.0.5 --format exe")
    print()
    print("  For command-specific help:")
    print("    python3 forge.py dashboard --help")
    print("    python3 forge.py c2 --help")
    print("    python3 forge.py intel --help")
    print("    python3 forge.py payload --help")
    print()


# ══════════════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ══════════════════════════════════════════════════════════════════════

def main() -> int:
    """Main entry point for Forge Suite."""
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
    if command in ("dashboard", "c2", "intel", "payload", "import-session", "auto", "collab"):
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

    # Unknown command
    print(f"  [!] Unknown command: '{sys.argv[1]}'")
    print(f"  [*] Available: {', '.join(list(FRAMEWORKS.keys()) + ['dashboard', 'c2', 'intel', 'payload', 'import-session', 'auto', 'collab'])}")
    print(f"  [*] Run 'python3 forge.py --help' for usage")
    return 1


if __name__ == "__main__":
    sys.exit(main())
