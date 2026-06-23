#!/usr/bin/env python3
"""
WebForge — Web Application Penetration Testing Framework
=========================================================
Master entry point. Runs ALL modules in PHASE ORDER (phases 1-12).
v5 APEX: EventBus integration, multi-target, pause/resume/abort.

FOR AUTHORIZED PENETRATION TESTING ONLY.

Usage:
  python webforge.py --target https://target.com --mode blackbox
  python webforge.py --target https://target.com --mode greybox --username admin --password Pass123
  python webforge.py --target https://target.com --mode whitebox --source /path/to/src
  python webforge.py --target https://target.com --session session.json
  python webforge.py --target https://target.com --sso
  python webforge.py --target https://target.com --dry-run
  python webforge.py --target https://target.com --resume results/target_20240101/
"""
from __future__ import annotations

import argparse
import asyncio
import importlib
import json
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Allow imports from forge-suite root
sys.path.insert(0, str(Path(__file__).parent.parent))

from common.auth_prompt import require_authorization
from common.config import BaseForgeConfig, load_config
from common.confirm_gate import set_auto_confirm
from common.db import create_db, ScanRunModel
from common.finding import Finding
from common.logger import get_logger, phase_banner, console
from common.netcheck import ask_internet_permission
from common.reporter import BaseReporter
from common.scope import Scope

from webforge.core.browser_detect import print_browser_status
from webforge.core.mode_engine import get_phases, describe_phases, CONFIRM_GATE_MODULES
from webforge.core.scheduler import PhaseScheduler

log = get_logger("webforge")

VERSION = "5.0.0"

MODULE_MAP: dict[str, str] = {
    # Phase 1 — Recon
    "tech_detect":       "webforge.modules.recon.tech_detect",
    "cms_detect":        "webforge.modules.recon.cms_detect",
    "dir_fuzzer":        "webforge.modules.recon.dir_fuzzer",
    "vhost_enum":        "webforge.modules.recon.vhost_enum",
    "js_analyzer":       "webforge.modules.recon.js_analyzer",
    "link_crawler":      "webforge.modules.recon.link_crawler",
    "robots_sitemap":    "webforge.modules.recon.robots_sitemap",
    "api_discover":      "webforge.modules.recon.api_discover",
    "param_discover":    "webforge.modules.recon.param_discover",
    "subdomain_takeover":"webforge.modules.recon.subdomain_takeover",
    "git_exposure":      "webforge.modules.recon.git_exposure",
    # Phase 2 — SSL
    "ssl_audit":         "webforge.modules.ssl.ssl_audit",
    "cert_inspect":      "webforge.modules.ssl.cert_inspect",
    "hsts_check":        "webforge.modules.ssl.hsts_check",
    # Phase 3 — Headers
    "header_audit":      "webforge.modules.headers.header_audit",
    "cors_check":        "webforge.modules.headers.cors_check",
    "csp_audit":         "webforge.modules.headers.csp_audit",
    "cookie_audit":      "webforge.modules.headers.cookie_audit",
    "sri_check":         "webforge.modules.headers.sri_check",
    "clickjacking":      "webforge.modules.headers.clickjacking",
    # Phase 4 — Injection
    "sqli_scanner":      "webforge.modules.injection.sqli_scanner",
    "xss_scanner":       "webforge.modules.injection.xss_scanner",
    "xxe_scanner":       "webforge.modules.injection.xxe_scanner",
    "ssti_scanner":      "webforge.modules.injection.ssti_scanner",
    "cmd_inject":        "webforge.modules.injection.cmd_inject",
    "ldap_inject":       "webforge.modules.injection.ldap_inject",
    "nosql_inject":      "webforge.modules.injection.nosql_inject",
    "jsonp_inject":      "webforge.modules.injection.jsonp_inject",
    "host_header_inject":"webforge.modules.injection.host_header_inject",
    "crlf_inject":       "webforge.modules.injection.crlf_inject",
    "log4shell_scanner": "webforge.modules.injection.log4shell_scanner",
    "parameter_pollution":"webforge.modules.injection.parameter_pollution",
    # Phase 5 — Auth
    "session_audit":     "webforge.modules.auth.session_audit",
    "password_policy":   "webforge.modules.auth.password_policy",
    "jwt_audit":         "webforge.modules.auth.jwt_audit",
    "oauth_check":       "webforge.modules.auth.oauth_check",
    "login_brute":       "webforge.modules.auth.login_brute",
    "mfa_bypass":        "webforge.modules.auth.mfa_bypass",
    "totp_bypass":       "webforge.modules.auth.totp_bypass",
    # Phase 6 — Access Control
    "idor_scanner":      "webforge.modules.access_control.idor_scanner",
    "priv_esc":          "webforge.modules.access_control.priv_esc",
    "path_traversal":    "webforge.modules.access_control.path_traversal",
    "forced_browse":     "webforge.modules.access_control.forced_browse",
    "403_bypass":        "webforge.modules.access_control.403_bypass",
    "mass_assignment":   "webforge.modules.access_control.mass_assignment",
    # Phase 7 — API
    "rest_audit":        "webforge.modules.api.rest_audit",
    "graphql_audit":     "webforge.modules.api.graphql_audit",
    "soap_audit":        "webforge.modules.api.soap_audit",
    "api_rate_check":    "webforge.modules.api.api_rate_check",
    # Phase 8 — File
    "ssrf_scanner":      "webforge.modules.file.ssrf_scanner",
    "lfi_rfi":           "webforge.modules.file.lfi_rfi",
    "upload_bypass":     "webforge.modules.file.upload_bypass",
    # Phase 9 — Business Logic
    "open_redirect":     "webforge.modules.business_logic.open_redirect",
    "price_tamper":      "webforge.modules.business_logic.price_tamper",
    "workflow_bypass":   "webforge.modules.business_logic.workflow_bypass",
    "race_condition":    "webforge.modules.business_logic.race_condition",
    # Phase 10 — Advanced
    "websocket_audit":   "webforge.modules.advanced.websocket_audit",
    "http2_audit":       "webforge.modules.advanced.http2_audit",
    "http_smuggling":    "webforge.modules.advanced.http_smuggling",
    "cache_poison":      "webforge.modules.advanced.cache_poison",
    "cache_deception":   "webforge.modules.advanced.cache_deception",
    "prototype_poll":    "webforge.modules.advanced.prototype_poll",
    "deserialization":   "webforge.modules.advanced.deserialization",
    "email_security":    "webforge.modules.advanced.email_security",
    "account_takeover":  "webforge.modules.advanced.account_takeover",
    "zip_slip":          "webforge.modules.advanced.zip_slip",
    # Phase 11 — Whitebox
    "source_audit":      "webforge.modules.whitebox.source_audit",
    "secret_scan":       "webforge.modules.whitebox.secret_scan",
    "dep_audit":         "webforge.modules.whitebox.dep_audit",
    "config_audit":      "webforge.modules.whitebox.config_audit",
    "code_flow":         "webforge.modules.whitebox.code_flow",
}

CLASS_NAME_MAP: dict[str, str] = {
    "tech_detect":       "TechDetect",
    "cms_detect":        "CmsDetect",
    "dir_fuzzer":        "DirFuzzer",
    "vhost_enum":        "VhostEnum",
    "js_analyzer":       "JsAnalyzer",
    "link_crawler":      "LinkCrawler",
    "robots_sitemap":    "RobotsSitemap",
    "api_discover":      "ApiDiscover",
    "param_discover":    "ParamDiscover",
    "subdomain_takeover":"SubdomainTakeover",
    "git_exposure":      "GitExposure",
    "ssl_audit":         "SslAudit",
    "cert_inspect":      "CertInspect",
    "hsts_check":        "HstsCheck",
    "header_audit":      "HeaderAudit",
    "cors_check":        "CorsCheck",
    "csp_audit":         "CspAudit",
    "cookie_audit":      "CookieAudit",
    "sri_check":         "SriCheck",
    "clickjacking":      "Clickjacking",
    "sqli_scanner":      "SqliScanner",
    "xss_scanner":       "XssScanner",
    "xxe_scanner":       "XxeScanner",
    "ssti_scanner":      "SstiScanner",
    "cmd_inject":        "CmdInject",
    "ldap_inject":       "LdapInject",
    "nosql_inject":      "NoSqlInject",
    "jsonp_inject":      "JsonpInject",
    "host_header_inject":"HostHeaderInject",
    "crlf_inject":       "CrlfInject",
    "log4shell_scanner": "Log4ShellScanner",
    "parameter_pollution":"ParameterPollution",
    "session_audit":     "SessionAudit",
    "password_policy":   "PasswordPolicy",
    "jwt_audit":         "JwtAudit",
    "oauth_check":       "OauthCheck",
    "login_brute":       "LoginBrute",
    "mfa_bypass":        "MfaBypass",
    "totp_bypass":       "TotpBypass",
    "idor_scanner":      "IdorScanner",
    "priv_esc":          "PrivEsc",
    "path_traversal":    "PathTraversal",
    "forced_browse":     "ForcedBrowse",
    "403_bypass":        "FourZeroThreeBypass",
    "mass_assignment":   "MassAssignment",
    "rest_audit":        "RestAudit",
    "graphql_audit":     "GraphqlAudit",
    "soap_audit":        "SoapAudit",
    "api_rate_check":    "ApiRateCheck",
    "ssrf_scanner":      "SsrfScanner",
    "lfi_rfi":           "LfiRfi",
    "upload_bypass":     "UploadBypass",
    "open_redirect":     "OpenRedirect",
    "price_tamper":      "PriceTamper",
    "workflow_bypass":   "WorkflowBypass",
    "race_condition":    "RaceCondition",
    "websocket_audit":   "WebsocketAudit",
    "http2_audit":       "Http2Audit",
    "http_smuggling":    "HttpSmuggling",
    "cache_poison":      "CachePoison",
    "cache_deception":   "CacheDeception",
    "prototype_poll":    "PrototypePoll",
    "deserialization":   "Deserialization",
    "email_security":    "EmailSecurity",
    "account_takeover":  "AccountTakeover",
    "zip_slip":          "ZipSlip",
    "source_audit":      "SourceAudit",
    "secret_scan":       "SecretScan",
    "dep_audit":         "DepAudit",
    "config_audit":      "ConfigAudit",
    "code_flow":         "CodeFlow",
}


# ── EventBus helpers ──────────────────────────────────────────────────

def _get_event_bus(event_bus: Any = None):
    """Safely return EventBus and Event/EventType or None."""
    if event_bus is None:
        return None, None, None
    try:
        from common.dashboard.event_bus import Event, EventType
        return event_bus, Event, EventType
    except ImportError:
        return None, None, None

def _get_eng_bus():
    """Safely return the EngagementBus singleton or None."""
    try:
        from common.brain.engagement_bus import EngagementBus
        return EngagementBus.get_instance()
    except ImportError:
        return None


def _emit(bus: Any, Event: Any, EventType: Any, etype: str, source: str = "webforge", **data: Any) -> None:
    """Fire-and-forget event emission — never crashes the scan."""
    if bus is None:
        return
    try:
        bus.emit(Event(event_type=EventType(etype), data=data, source=source))
    except Exception as exc:
        log.debug("EventBus emission failed (%s): %s", etype, exc)


# ── Pause / Resume / Abort control ───────────────────────────────────

class ScanControl:
    """Async-safe scan control flags."""

    def __init__(self, control_file: str | None = None) -> None:
        self._paused = asyncio.Event()
        self._paused.set()
        self._aborted = False
        self._control_file = Path(control_file) if control_file else None
        self._control_mtime = 0.0

    @property
    def is_paused(self) -> bool:
        self._refresh_file_state()
        return not self._paused.is_set()

    @property
    def is_aborted(self) -> bool:
        self._refresh_file_state()
        return self._aborted

    def pause(self) -> None:
        self._paused.clear()
        log.info("Scan PAUSED by operator")

    def resume(self) -> None:
        self._paused.set()
        log.info("Scan RESUMED by operator")

    def abort(self) -> None:
        self._aborted = True
        self._paused.set()
        log.info("Scan ABORTED by operator")

    async def wait_if_paused(self) -> None:
        while self.is_paused and not self.is_aborted:
            await asyncio.sleep(0.5)

    def _refresh_file_state(self) -> None:
        if not self._control_file:
            return
        try:
            stat = self._control_file.stat()
            if stat.st_mtime <= self._control_mtime:
                return
            self._control_mtime = stat.st_mtime
            data = json.loads(self._control_file.read_text(encoding="utf-8"))
            if data.get("aborted"):
                self.abort()
            elif data.get("paused"):
                self.pause()
            else:
                self.resume()
        except Exception as exc:
            log.debug("Control file refresh failed: %s", exc)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="WebForge — Web Application Penetration Testing Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--target",        default=None,            help="Target URL (e.g. https://target.com)")
    parser.add_argument("--mode",          default="blackbox",
                        choices=["blackbox","greybox","whitebox"],   help="Scan mode (default: blackbox)")
    parser.add_argument("--engagement",    default="engagement",    help="Engagement name for report")
    parser.add_argument("--tester",        default="anonymous",     help="Tester name for report")
    parser.add_argument("--config",        default=None,            help="Path to webforge.yaml config file")
    parser.add_argument("--output",        default=None,            help="Results output directory")
    parser.add_argument("--report-format", default="html,pdf",      help="Comma-separated: html,pdf,json,csv")
    parser.add_argument("--rate",          type=float, default=10.0,help="Requests per second (default: 10)")
    parser.add_argument("--workers",       type=int,   default=10,  help="Concurrent workers (default: 10)")
    parser.add_argument("--proxy",         default=None,            help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--username",      default=None,            help="Login username (greybox/whitebox)")
    parser.add_argument("--password",      default=None,            help="Login password")
    parser.add_argument("--token",         default=None,            help="Bearer/API token")
    parser.add_argument("--cookie",        default=None,            help="Cookie header value (name=value)")
    parser.add_argument("--session",       default=None,            help="Pre-captured session file from session_capture.py")
    parser.add_argument("--sso",           action="store_true",     help="Launch session_capture.py for SSO login first")
    parser.add_argument("--source",        default=None,            help="Path to source code (whitebox mode)")
    parser.add_argument("--modules",       default=None,            help="Comma-separated module list to run")
    parser.add_argument("--skip-modules",  default=None,            help="Comma-separated modules to skip")
    parser.add_argument("--jwt-token",     default=None,            help="JWT token for jwt_audit module")
    parser.add_argument("--scope",         nargs="*", default=[],   help="Additional in-scope hosts/CIDRs")
    parser.add_argument("--dry-run",       action="store_true",     help="Show plan without sending requests")
    parser.add_argument("--resume",        default=None,            help="Resume from results directory")
    parser.add_argument("--auto-confirm",  action="store_true",     help="Skip confirmation gates (pipeline mode)")
    parser.add_argument("--browser",       default=None,
                        choices=["chrome","chromium","firefox"],     help="Force browser for screenshots")
    parser.add_argument("--browser-render", action="store_true",
                        help="Render target with Playwright before scanning to discover SPA routes, forms, and XHR endpoints")
    parser.add_argument("--login-url",     default=None,
                        help="Login URL for browser-based authenticated scanning")
    parser.add_argument("--auth-type",     default=None,
                        choices=["form", "bearer", "cookie"],
                        help="Authentication type (set by dashboard for greybox/whitebox scans)")
    parser.add_argument("--header-name",   default="Authorization",
                        help="Custom header name for bearer token auth (default: Authorization)")
    parser.add_argument("--auth-state",    default=None,
                        help="Playwright storage-state JSON to reuse authenticated browser session")
    parser.add_argument("--no-screenshot", action="store_true",     help="Disable screenshot capture")
    parser.add_argument("--list-modules",  action="store_true",     help="List all available modules and exit")
    parser.add_argument("--profile",       default=None,
                        help="Scan profile: quick, standard, full, api, compliance, stealth")
    parser.add_argument("--list-profiles", action="store_true",     help="List available scan profiles and exit")
    parser.add_argument("--verbose",       action="store_true",     help="Verbose debug output")
    parser.add_argument("--quiet",         action="store_true",     help="Suppress UI output")
    parser.add_argument("--version",       action="version", version=f"WebForge {VERSION}")
    parser.add_argument("--dashboard-url", default=None,
                        help="Live dashboard URL (e.g. http://localhost:1337) — streams events in real time")
    parser.add_argument("--control-file",  default=None,
                        help="JSON control file used by dashboard pause/resume/abort")
    return parser.parse_args()


def setup_results_dir(target: str, engagement: str, resume_path: str | None) -> Path:
    if resume_path:
        return Path(resume_path)
    from urllib.parse import urlparse
    host = urlparse(target).netloc.replace(":", "_").replace("/", "_") or "target"
    ts   = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    path = Path(__file__).parent / "results" / f"{engagement}_{host}_{ts}"
    path.mkdir(parents=True, exist_ok=True)
    (path / "evidence" / "screenshots").mkdir(parents=True, exist_ok=True)
    (path / "evidence" / "http").mkdir(parents=True, exist_ok=True)
    return path


def load_module_class(module_name: str):
    """Dynamically import and return the module class."""
    module_path = MODULE_MAP.get(module_name)
    class_name  = CLASS_NAME_MAP.get(module_name)
    if not module_path or not class_name:
        return None
    try:
        mod = importlib.import_module(module_path)
        return getattr(mod, class_name)
    except Exception as exc:
        log.warning("Could not load module %s: %s", module_name, exc)
        return None


async def prepare_browser_context(
    cfg: BaseForgeConfig,
    args: argparse.Namespace,
    results_dir: Path,
) -> None:
    """Populate cfg.extra with browser-discovered auth/session artifacts."""
    if not (args.browser_render or args.login_url or args.auth_state):
        return

    browser_name = args.browser or "chromium"

    if args.auth_state:
        from webforge.core.auth_recorder import AuthRecorder
        auth = AuthRecorder(results_dir, proxy=cfg.proxy).import_storage_state(Path(args.auth_state))
        cfg.extra["browser_storage_state"] = auth.storage_state_path
        if auth.headers:
            cfg.extra["session_headers"] = {**cfg.extra.get("session_headers", {}), **auth.headers}
        if auth.cookies:
            cfg.extra["session_cookies"] = auth.cookies
        log.info("Loaded browser auth state from %s", args.auth_state)

    if args.login_url:
        from webforge.core.auth_recorder import AuthRecorder
        auth = await AuthRecorder(results_dir, proxy=cfg.proxy).replay_login(
            args.login_url,
            username=args.username or "",
            password=args.password or "",
            browser=browser_name,
        )
        cfg.extra["browser_auth"] = auth.to_dict()
        if auth.storage_state_path:
            cfg.extra["browser_storage_state"] = auth.storage_state_path
        if auth.headers:
            cfg.extra["session_headers"] = {**cfg.extra.get("session_headers", {}), **auth.headers}
        if auth.cookies:
            cfg.extra["session_cookies"] = auth.cookies
        if auth.error:
            log.warning("Browser login did not complete cleanly: %s", auth.error)
        else:
            log.info("Browser login replay completed; storage state exported")

    if args.browser_render:
        from webforge.core.browser_engine import BrowserEngine
        if not BrowserEngine.available():
            log.warning("Playwright unavailable — skipping browser render discovery")
            return
        try:
            async with BrowserEngine(
                results_dir=results_dir,
                browser=browser_name,
                proxy=cfg.proxy,
                storage_state=cfg.extra.get("browser_storage_state"),
            ) as engine:
                snap = await engine.render(cfg.target)
            cfg.extra["browser_snapshot"] = snap.to_dict()
            cfg.extra["found_forms"] = _merge_unique_forms(
                cfg.extra.get("found_forms", []),
                snap.forms,
            )
            cfg.extra["api_endpoints"] = sorted(set(
                cfg.extra.get("api_endpoints", []) + snap.ajax_endpoints
            ))
            cfg.extra["browser_links"] = snap.links
            cfg.extra["js_resources"] = snap.js_resources
            cfg.extra["spa_framework"] = snap.framework
            if snap.storage_state_path:
                cfg.extra["browser_storage_state"] = snap.storage_state_path
            if snap.error:
                log.warning("Browser render discovery failed: %s", snap.error)
            else:
                log.info(
                    "Browser discovery: framework=%s forms=%d ajax=%d links=%d",
                    snap.framework or "unknown",
                    len(snap.forms),
                    len(snap.ajax_endpoints),
                    len(snap.links),
                )
        except Exception as exc:
            log.warning("Browser render discovery unavailable: %s", exc)


def _merge_unique_forms(existing: list[dict], discovered: list[dict]) -> list[dict]:
    seen: set[tuple[str, str, tuple[str, ...]]] = set()
    merged: list[dict] = []
    for form in existing + discovered:
        key = (
            form.get("action", ""),
            form.get("method", "GET"),
            tuple(sorted(form.get("inputs", []))),
        )
        if key not in seen:
            seen.add(key)
            merged.append(form)
    return merged


async def run_scan(
    cfg: BaseForgeConfig,
    args: argparse.Namespace,
    results_dir: Path,
    event_bus: Any = None,
    scan_control: ScanControl | None = None,
) -> dict[str, Any]:
    """Core scan loop — separated from main() so TargetManager can call it.

    Args:
        cfg:          Fully configured BaseForgeConfig.
        args:         Parsed CLI args.
        results_dir:  Where results/reports go.
        event_bus:    Optional EventBus for dashboard events.
        scan_control: Optional ScanControl for pause/resume/abort.

    Returns:
        Summary dict with 'findings', 'errors', 'duration'.
    """
    bus, Event, EventType = _get_event_bus(event_bus)
    ctrl = scan_control or ScanControl(getattr(args, "control_file", None))
    eng_bus = _get_eng_bus()

    # Database
    db_path = results_dir / "webforge.db"
    db_session = create_db(db_path)

    # Scope
    scope_targets = [cfg.target] + (args.scope or [])
    scope = Scope(scope_targets)

    # Scan run record
    run_id = str(uuid.uuid4())
    run = ScanRunModel(
        id=run_id, framework="webforge", target=cfg.target,
        mode=cfg.mode, engagement=cfg.engagement, tester=cfg.tester,
    )
    db_session.add(run)
    db_session.commit()

    # Determine phases
    include = (
        [m.strip() for m in args.modules.split(",")]
        if args.modules
        else cfg.extra.get("profile_modules")  # profile_modules set when --profile used
    )
    skip    = [m.strip() for m in args.skip_modules.split(",")] if args.skip_modules else None
    has_session = bool(
        args.username or args.token or args.session or args.sso
        or cfg.extra.get("password") or cfg.extra.get("token")
        or cfg.extra.get("cookie") or cfg.extra.get("auth_type")
    )
    phases  = get_phases(args.mode, include_modules=include, skip_modules=skip,
                         has_session=has_session)

    total_modules = sum(len(p.modules) for p in phases)
    all_module_names = [m for p in phases for m in p.modules]

    # ── Emit: scan_start ──────────────────────────────────────────────
    _emit(bus, Event, EventType, "scan_start", source="webforge",
          target=cfg.target, mode=cfg.mode, engagement=cfg.engagement,
          tester=cfg.tester, framework="WebForge", modules=all_module_names)

    console.print(f"\n[bold cyan]WebForge v{VERSION}[/bold cyan] — Target: [cyan]{cfg.target}[/cyan]")
    console.print(f"Mode: [yellow]{args.mode}[/yellow] | Phases: {len(phases)} | Modules: {total_modules}")
    if args.dry_run:
        console.print("[bold yellow]DRY RUN MODE — no requests will be sent[/bold yellow]")

    scheduler = PhaseScheduler(workers=args.workers, dry_run=args.dry_run)
    all_findings: list[Finding] = []
    errors: list[str] = []
    start_time = time.monotonic()
    modules_completed = 0  # running counter for overall progress

    for phase in phases:
        # ── Abort check ───────────────────────────────────────────────
        if ctrl.is_aborted:
            _emit(bus, Event, EventType, "scan_aborted", source="webforge",
                  reason="operator", target=cfg.target)
            break

        # ── Pause gate ────────────────────────────────────────────────
        if ctrl.is_paused:
            _emit(bus, Event, EventType, "scan_paused", source="webforge")
            await ctrl.wait_if_paused()
            if ctrl.is_aborted:
                break
            _emit(bus, Event, EventType, "scan_resumed", source="webforge")

        phase_banner(phase.number, 12, phase.name)

        # ── Emit: phase_start ─────────────────────────────────────────
        _emit(bus, Event, EventType, "phase_start", source="webforge",
              number=phase.number, name=phase.name, modules=phase.modules)

        phase_start = time.monotonic()
        tasks = []

        for module_name in phase.modules:
            # ── Abort / pause mid-phase ───────────────────────────────
            if ctrl.is_aborted:
                break
            if ctrl.is_paused:
                _emit(bus, Event, EventType, "scan_paused", source="webforge")
                await ctrl.wait_if_paused()
                if ctrl.is_aborted:
                    break
                _emit(bus, Event, EventType, "scan_resumed", source="webforge")

            cls = load_module_class(module_name)
            if cls is None:
                log.debug("Module not available: %s (not yet built)", module_name)
                _emit(bus, Event, EventType, "module_skip", source=module_name,
                      name=module_name, reason="not built")
                modules_completed += 1
                # Emit progress so dashboard knows we moved forward
                _emit(bus, Event, EventType, "module_progress", source=module_name,
                      name=module_name,
                      progress=round(modules_completed / total_modules * 100) if total_modules else 0)
                continue

            # ── Emit: module_start + progress ─────────────────────────
            _emit(bus, Event, EventType, "module_start", source=module_name,
                  name=module_name, phase=phase.number)
            # Emit progress at start of module (current position in the scan)
            _emit(bus, Event, EventType, "module_progress", source=module_name,
                  name=module_name,
                  progress=round(modules_completed / total_modules * 100) if total_modules else 0)

            mod_instance = cls(
                config=cfg,
                scope=scope,
                db_session=db_session,
                results_dir=results_dir,
                run_id=run_id,
                event_bus=event_bus,
            )

            try:
                result = await mod_instance.run()
                modules_completed += 1

                if result and hasattr(result, "findings"):
                    all_findings.extend(result.findings)

                    # ── Emit: module_complete + each finding ──────────
                    _emit(bus, Event, EventType, "module_complete", source=module_name,
                          name=module_name, findings_count=len(result.findings))

                    for finding in result.findings:
                        fd = finding.to_dict()
                        _emit(bus, Event, EventType, "finding_new", source=module_name,
                              **fd)
                        if eng_bus:
                            await eng_bus.publish("webforge", fd)
                else:
                    _emit(bus, Event, EventType, "module_complete", source=module_name,
                          name=module_name, findings_count=0)

                # Emit progress after module completion
                _emit(bus, Event, EventType, "module_progress", source=module_name,
                      name=module_name,
                      progress=round(modules_completed / total_modules * 100) if total_modules else 0)

            except Exception as exc:
                log.error("Module %s failed: %s", module_name, exc)
                errors.append(f"{module_name}: {exc}")
                modules_completed += 1
                _emit(bus, Event, EventType, "module_fail", source=module_name,
                      name=module_name, error=str(exc))
                # Still emit progress even on failure
                _emit(bus, Event, EventType, "module_progress", source=module_name,
                      name=module_name,
                      progress=round(modules_completed / total_modules * 100) if total_modules else 0)

        # ── Emit: phase_complete ──────────────────────────────────────
        phase_duration = time.monotonic() - phase_start
        _emit(bus, Event, EventType, "phase_complete", source="webforge",
              number=phase.number, name=phase.name, duration=round(phase_duration, 1))

        # ── Session health check (greybox/whitebox only) ──────────────
        if cfg.mode in ("greybox", "whitebox") and getattr(args, "login_url", None):
            try:
                import aiohttp
                from webforge.core.auth_recorder import SessionHealthChecker, AuthRecorder
                _checker = SessionHealthChecker(
                    target=cfg.target,
                    auth_indicator=cfg.extra.get("auth_indicator", ""),
                )
                _hdrs = cfg.extra.get("session_headers", {})
                async with aiohttp.ClientSession(headers=_hdrs) as _hs:
                    if not await _checker.is_healthy(_hs):
                        log.warning(
                            "Session may have expired after phase %d — re-authenticating",
                            phase.number,
                        )
                        _recorder = AuthRecorder(results_dir, proxy=cfg.proxy)
                        _reauth = await _checker.re_authenticate(
                            _recorder, args.login_url,
                            username=args.username or "",
                            password=args.password or "",
                        )
                        if _reauth.authenticated:
                            cfg.extra["session_headers"] = _reauth.headers or {}
                            log.info("Re-authentication successful after phase %d", phase.number)
                        else:
                            log.warning("Re-authentication failed: %s", _reauth.error)
            except Exception as _exc:
                log.debug("Session health check skipped: %s", _exc)

    # Update run record
    run.ended_at = datetime.now(timezone.utc)
    run.status   = "completed"
    db_session.commit()

    elapsed = time.monotonic() - start_time

    # ── Emit: scan_complete ───────────────────────────────────────────
    _emit(bus, Event, EventType, "scan_complete", source="webforge",
          target=cfg.target, findings=len(all_findings), duration=round(elapsed, 1))

    # Generate reports
    phase_banner(12, 12, "Reporting")
    formats = [f.strip() for f in args.report_format.split(",")]
    reporter = BaseReporter(
        findings=[f.to_dict() for f in all_findings],
        results_dir=results_dir,
        engagement=cfg.engagement,
        target=cfg.target,
        tester=cfg.tester,
        framework="WebForge",
        formats=formats,
    )
    report_paths = reporter.generate_all()

    # Final summary
    console.print(f"\n[bold green]═══ SCAN COMPLETE ═══[/bold green]")
    console.print(f"  Duration:  {elapsed:.1f}s")
    console.print(f"  Findings:  {len(all_findings)}")
    console.print(f"  Results:   {results_dir}")
    for fmt, path in report_paths.items():
        console.print(f"  Report ({fmt}): {path}")

    db_session.close()

    return {
        "findings": len(all_findings),
        "errors": errors,
        "duration": round(elapsed, 1),
    }


async def run_for_target(
    target_entry: Any,
    base_args: argparse.Namespace,
    event_bus: Any = None,
    scan_control: ScanControl | None = None,
) -> dict[str, Any]:
    """Entry point for TargetManager multi-target orchestration.

    Args:
        target_entry:  TargetEntry from TargetManager.
        base_args:     Parsed CLI args as template.
        event_bus:     Optional EventBus.
        scan_control:  Optional ScanControl.

    Returns:
        Summary dict.
    """
    import copy
    args = copy.deepcopy(base_args)
    args.target = target_entry.target

    for key, val in target_entry.options.items():
        if hasattr(args, key):
            setattr(args, key, val)

    results_dir = setup_results_dir(args.target, args.engagement, args.resume)
    config_path = Path(args.config) if args.config else Path(__file__).parent / "webforge.yaml"
    cfg = load_config(config_path)
    cfg.target     = args.target
    cfg.engagement = args.engagement
    cfg.tester     = args.tester
    cfg.mode       = args.mode
    cfg.rate.requests_per_second = args.rate
    cfg.workers    = args.workers
    cfg.verbose    = getattr(args, "verbose", False)
    cfg.quiet      = getattr(args, "quiet", False)
    cfg.dry_run    = args.dry_run
    if args.proxy:
        cfg.proxy = args.proxy
        cfg.extra["proxy"] = args.proxy
    if args.username:
        cfg.extra["username"] = args.username
    if args.password:
        cfg.extra["password"] = args.password
    if args.token:
        cfg.extra["token"] = args.token
    if getattr(args, "auth_state", None):
        cfg.extra["browser_storage_state"] = args.auth_state

    await prepare_browser_context(cfg, args, results_dir)
    return await run_scan(cfg, args, results_dir, event_bus, scan_control)


async def main() -> None:
    args = parse_args()

    if args.list_modules:
        describe_phases(args.mode)
        return

    if args.list_profiles:
        from webforge.core.scan_profile import describe_profiles
        describe_profiles()
        return

    if not args.target:
        log.error("--target is required. Use --list-modules or --list-profiles to explore without a target.")
        sys.exit(1)
    if not args.target.startswith(("http://", "https://")):
        args.target = "https://" + args.target

    if not args.auto_confirm:
        require_authorization(args.target, "WebForge")
    set_auto_confirm(args.auto_confirm)
    ask_internet_permission("Wappalyzer DB updates, nuclei templates", force=args.auto_confirm)

    if not args.no_screenshot:
        print_browser_status()

    # SSO pre-login
    if args.sso:
        log.info("SSO mode: launching session_capture.py")
        import subprocess
        sess_file = "session.json"
        subprocess.run([sys.executable, str(Path(__file__).parent / "session_capture.py"),
                       "--target", args.target, "--output", sess_file], check=False)
        args.session = sess_file

    results_dir = setup_results_dir(args.target, args.engagement, args.resume)
    log.info("Results directory: %s", results_dir)

    config_path = Path(args.config) if args.config else Path(__file__).parent / "webforge.yaml"
    cfg = load_config(config_path)
    cfg.target     = args.target
    cfg.engagement = args.engagement
    cfg.tester     = args.tester
    cfg.mode       = args.mode
    cfg.rate.requests_per_second = args.rate
    cfg.workers    = args.workers
    cfg.verbose    = args.verbose
    cfg.quiet      = args.quiet
    cfg.dry_run    = args.dry_run
    if args.proxy:
        cfg.proxy  = args.proxy
        cfg.extra["proxy"] = args.proxy
    if args.username:
        cfg.extra["username"] = args.username
    if args.password:
        cfg.extra["password"] = args.password
    if args.token:
        cfg.extra["token"] = args.token
    if args.jwt_token:
        cfg.extra["jwt_token"] = args.jwt_token
    if args.source:
        cfg.extra["source_path"] = args.source
    if args.cookie:
        cfg.extra["cookie"] = args.cookie

    # ── Dashboard env-based auth (secrets travel via env, never argv) ──
    import os as _os
    _env_auth_type = _os.environ.get("FORGE_AUTH_TYPE", "") or (args.auth_type or "")
    _env_password  = _os.environ.get("FORGE_PASSWORD", "")
    _env_token     = _os.environ.get("FORGE_TOKEN", "")
    _env_cookie    = _os.environ.get("FORGE_COOKIE_JAR", "")

    if _env_auth_type:
        cfg.extra["auth_type"] = _env_auth_type
    if _env_password and not args.password:
        cfg.extra["password"] = _env_password
        args.password = _env_password          # so has_session detects it
    if _env_token and not args.token:
        cfg.extra["token"] = _env_token
        args.token = _env_token
    if _env_cookie:
        cfg.extra["cookie"] = _env_cookie
        if not args.cookie:
            args.cookie = _env_cookie

    # Populate session_headers / session_cookies from env auth
    if _env_auth_type == "bearer" and (args.token or _env_token):
        _hdr_name = getattr(args, "header_name", "Authorization")
        _bearer_val = args.token or _env_token
        _hdr_val = f"Bearer {_bearer_val}" if _hdr_name == "Authorization" else _bearer_val
        cfg.extra.setdefault("session_headers", {})[_hdr_name] = _hdr_val
    if _env_auth_type == "cookie" and _env_cookie:
        cfg.extra.setdefault("session_headers", {})["Cookie"] = _env_cookie
        # Also parse cookie pairs into session_cookies dict
        _cookie_dict = {}
        for _pair in _env_cookie.split(";"):
            _pair = _pair.strip()
            if "=" in _pair:
                _k, _v = _pair.split("=", 1)
                _cookie_dict[_k.strip()] = _v.strip()
        if _cookie_dict:
            cfg.extra.setdefault("session_cookies", {}).update(_cookie_dict)
    if _env_auth_type == "form" and _env_password:
        # Form auth: password is available for auth_recorder login replay
        cfg.extra["password"] = _env_password

    # Apply scan profile (overrides defaults; explicit CLI flags take priority)
    if args.profile:
        from webforge.core.scan_profile import get_profile, validate_profile
        try:
            _profile = get_profile(args.profile)
        except (KeyError, ValueError):
            log.error(
                "Unknown profile '%s'. Use --list-profiles to see available profiles.",
                args.profile,
            )
            sys.exit(1)
        _invalid = validate_profile(_profile, set(MODULE_MAP.keys()))
        if _invalid:
            log.error(
                "Profile '%s' references unknown modules: %s", args.profile, _invalid,
            )
            sys.exit(1)
        if not args.modules:
            cfg.extra["profile_modules"] = _profile.modules
        if args.rate == 10.0:
            cfg.rate.requests_per_second = _profile.rate_limit
        if args.workers == 10:
            cfg.workers = _profile.max_workers
        cfg.verify_findings = _profile.verify_findings
        log.info(
            "Profile '%s' active (%d modules, rate=%.1f req/s, verify=%s)",
            _profile.name, len(_profile.modules),
            _profile.rate_limit, _profile.verify_findings,
        )

    # Load pre-captured session
    if args.session:
        from webforge.core.session_bridge import load_session
        sess_data = load_session(Path(args.session))
        if sess_data:
            cfg.extra["session_data"] = sess_data
            log.info("Loaded pre-captured session from %s", args.session)
            tokens = sess_data.get("detected_tokens", {})
            if tokens.get("bearer"):
                cfg.extra["token"] = tokens["bearer"]
            elif tokens.get("jwt"):
                cfg.extra["token"] = tokens["jwt"]
                cfg.extra["jwt_token"] = tokens["jwt"]

    await prepare_browser_context(cfg, args, results_dir)

    # Wire EventBus — remote when dashboard URL given, local otherwise
    event_bus = None
    if args.dashboard_url:
        try:
            from common.dashboard.event_bus import RemoteEventBus
            event_bus = RemoteEventBus(args.dashboard_url, run_id=str(uuid.uuid4())[:8])
            event_bus.start()
            log.info("Dashboard relay: %s", args.dashboard_url)
        except Exception as exc:
            log.warning("RemoteEventBus init failed: %s — events won't reach dashboard", exc)
    else:
        try:
            from common.dashboard.event_bus import EventBus
            event_bus = EventBus(run_id="webforge")
            event_bus.start()
        except ImportError:
            pass

    await run_scan(cfg, args, results_dir, event_bus=event_bus)

    if event_bus and hasattr(event_bus, "stop"):
        event_bus.stop()


if __name__ == "__main__":
    asyncio.run(main())
