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
"""
import argparse
import asyncio
import os
import sys
import subprocess
import logging
from pathlib import Path

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
    dash.add_argument("--port", type=int, default=1337, help="Bind port (default: 1337)")
    dash.add_argument("--tui", action="store_true", help="Launch Rich terminal TUI instead of web")
    dash.add_argument("--no-auth", action="store_true", help="Disable dashboard authentication")
    dash.add_argument("--attach", metavar="DIR", help="Attach to a running/completed engagement")
    dash.add_argument("--replay", metavar="DIR", help="Replay a completed engagement")

    # ── C2 Framework ──────────────────────────────────────────────
    c2 = subparsers.add_parser("c2", help="Command & Control framework")
    c2_sub = c2.add_subparsers(dest="c2_action", help="C2 actions")

    c2_server = c2_sub.add_parser("server", help="Start the C2 team server")
    c2_server.add_argument("--bind", default="0.0.0.0", help="Bind address")
    c2_server.add_argument("--port", type=int, default=8443, help="Server port")
    c2_server.add_argument("--password", help="Team server password")
    c2_server.add_argument("--dashboard", action="store_true", help="Launch dashboard alongside C2")

    c2_connect = c2_sub.add_parser("connect", help="Connect to a team server as operator")
    c2_connect.add_argument("--server", required=True, help="Team server address (host:port)")
    c2_connect.add_argument("--user", default="operator", help="Operator username")
    c2_connect.add_argument("--password", help="Team server password")

    c2_listener = c2_sub.add_parser("listener", help="Manage listeners")
    c2_listener.add_argument("action", choices=["add", "remove", "list"], help="Listener action")
    c2_listener.add_argument("--type", choices=["https", "http", "dns", "tcp", "smb"],
                              help="Listener type")
    c2_listener.add_argument("--port", type=int, help="Listener port")
    c2_listener.add_argument("--host", help="Listener bind host")

    c2_payload = c2_sub.add_parser("payload", help="Generate C2 payload/beacon")
    c2_payload.add_argument("--type", default="beacon_https", help="Payload type")
    c2_payload.add_argument("--lhost", required=True, help="Callback host")
    c2_payload.add_argument("--lport", type=int, default=443, help="Callback port")
    c2_payload.add_argument("--format", default="exe", help="Output format")
    c2_payload.add_argument("--arch", default="x64", choices=["x86", "x64", "arm64"])
    c2_payload.add_argument("--output", "-o", help="Output file path")

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
    intel_search.add_argument("--limit", type=int, default=20, help="Max results")

    intel_status = intel_sub.add_parser("status", help="Show intel sync status")

    # ── Payload Generation ────────────────────────────────────────
    payload = subparsers.add_parser("payload", help="Standalone payload generation")
    payload.add_argument("--type", default="reverse_tcp", help="Payload type")
    payload.add_argument("--lhost", required=True, help="Callback host")
    payload.add_argument("--lport", type=int, default=4444, help="Callback port")
    payload.add_argument("--format", default="exe",
                          choices=["exe", "dll", "elf", "ps1", "hta", "vba", "msi", "iso", "raw"],
                          help="Output format")
    payload.add_argument("--arch", default="x64", choices=["x86", "x64", "arm64"])
    payload.add_argument("--encode", choices=["xor", "aes", "polymorphic", "sgn", "none"],
                          default="none", help="Encoding/encryption method")
    payload.add_argument("--iterations", type=int, default=1, help="Encoding iterations")
    payload.add_argument("--output", "-o", help="Output file path")
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
    target_group.add_argument("--parallel", type=int, default=3,
                               help="Max parallel targets (default: 3)")
    target_group.add_argument("--resume", metavar="DIR",
                               help="Resume a previous multi-target scan")

    # Dashboard integration
    dash_group = parser.add_argument_group("dashboard")
    dash_group.add_argument("--dashboard", action="store_true",
                             help="Launch live dashboard alongside scan")
    dash_group.add_argument("--dashboard-port", type=int, default=1337,
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

    # Pipeline / automation
    parser.add_argument("--auto-confirm", action="store_true",
                         help="Skip authorization prompt (pipeline/automation mode)")

    # Output
    parser.add_argument("--output-dir", "-o", metavar="DIR",
                         help="Results output directory")


# ══════════════════════════════════════════════════════════════════════
# COMMAND HANDLERS
# ══════════════════════════════════════════════════════════════════════

def handle_scan(args: argparse.Namespace, framework_key: str) -> int:
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

    if not target and not targets_file and not resume_dir:
        print(f"  [!] No target specified.")
        print(f"  [*] Use --target <target>, --targets <file>, or --resume <dir>")
        return 1

    # Build framework command
    # We pass through all unknown args to the framework script
    framework_args = _build_framework_args(args, framework_key)
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
        print(f"  [*] Multi-target mode: {targets_file} (parallel={known_args.get('parallel', 3)})")
    if known_args.get("schedule"):
        print(f"  [*] Scheduled: {known_args['schedule']}")
    if known_args.get("continuous"):
        print(f"  [*] Continuous monitoring: interval={known_args.get('interval', '24h')}")
    if dashboard_proc:
        port = known_args.get("dashboard_port", 1337)
        print(f"  [*] Dashboard: https://localhost:{port}")
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

    # Pipeline
    if known.get("auto_confirm"):
        result.append("--auto-confirm")

    # Output
    if known.get("output_dir"):
        result.extend(["--output-dir", known["output_dir"]])

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

    print(BANNER)
    print(f"  [*] War Room Dashboard starting...")
    protocol = "https" if auth else "http"
    print(f"  [*] URL: {protocol}://localhost:{port}")
    if not auth:
        print(f"  [*] Authentication DISABLED")
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
    print(f"  [*] C2 Listener: {args.action}")
    print("  [!] Listener management requires a running C2 server.")
    print("  [*] Start a server first: python3 forge.py c2 server")
    return 1


def _handle_c2_payload(args: argparse.Namespace) -> int:
    """Generate a C2 beacon payload."""
    print(f"  [*] Generating C2 payload: type={args.type}")
    print(f"  [*] Callback: {args.lhost}:{args.lport}")
    print(f"  [*] Format: {args.format} | Arch: {args.arch}")
    print("  [!] Payload generation module not yet available.")
    print("  [*] The payload factory (forge_payload/) is planned for a future build.")
    return 1


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


def handle_payload(args: argparse.Namespace) -> int:
    """Handle standalone payload generation.

    Returns:
        Exit code.
    """
    if args.list_payloads:
        try:
            from forge_payload.payload_factory import PayloadFactory
            print(PayloadFactory.list_payloads())
        except ImportError:
            print("  [!] Payload factory not yet available.")
            print("  [*] The payload module (forge_payload/) is planned for a future build.")
        return 0

    try:
        from forge_payload.payload_factory import PayloadFactory
    except ImportError:
        print("  [!] Payload factory module not yet available.")
        print("  [*] The payload module (forge_payload/) is planned for a future build.")
        return 1

    print(BANNER)
    print(f"  [*] Payload Generation")
    print(f"  [*] Type:     {args.type}")
    print(f"  [*] Callback: {args.lhost}:{args.lport}")
    print(f"  [*] Format:   {args.format}")
    print(f"  [*] Arch:     {args.arch}")
    print(f"  [*] Encoding: {args.encode}")
    if args.encode != "none":
        print(f"  [*] Iterations: {args.iterations}")
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
        output_path=args.output,
    )
    print(f"  [+] Payload written to: {output}")
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
    print("    python3 forge.py c2 server --port 8443")
    print("    python3 forge.py intel sync --all")
    print("    python3 forge.py payload --type reverse_tcp --lhost 10.0.0.5 --format exe")
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
        # Parse only known args — rest goes to framework
        args, unknown = parser.parse_known_args()
        return handle_scan(args, command)

    # Platform commands — full argparse parsing
    if command in ("dashboard", "c2", "intel", "payload"):
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

    # Unknown command
    print(f"  [!] Unknown command: '{sys.argv[1]}'")
    print(f"  [*] Available: {', '.join(list(FRAMEWORKS.keys()) + ['dashboard', 'c2', 'intel', 'payload'])}")
    print(f"  [*] Run 'python3 forge.py --help' for usage")
    return 1


if __name__ == "__main__":
    sys.exit(main())
