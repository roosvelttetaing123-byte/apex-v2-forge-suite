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

    def __init__(self) -> None:
        self._paused = asyncio.Event()
        self._paused.set()
        self._aborted = False

    @property
    def is_paused(self) -> bool:
        return not self._paused.is_set()

    @property
    def is_aborted(self) -> bool:
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
        await self._paused.wait()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="WebForge — Web Application Penetration Testing Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--target",        required=True,           help="Target URL (e.g. https://target.com)")
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
    parser.add_argument("--no-screenshot", action="store_true",     help="Disable screenshot capture")
    parser.add_argument("--list-modules",  action="store_true",     help="List all available modules and exit")
    parser.add_argument("--verbose",       action="store_true",     help="Verbose debug output")
    parser.add_argument("--quiet",         action="store_true",     help="Suppress UI output")
    parser.add_argument("--version",       action="version", version=f"WebForge {VERSION}")
    parser.add_argument("--dashboard-url", default=None,
                        help="Live dashboard URL (e.g. http://localhost:1337) — streams events in real time")
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
        return getattr(mod, class_name, None)
    except ImportError as exc:
        log.debug("Module not yet available: %s — %s", module_name, exc)
        return None


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
    ctrl = scan_control or ScanControl()
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
    include = [m.strip() for m in args.modules.split(",")] if args.modules else None
    skip    = [m.strip() for m in args.skip_modules.split(",")] if args.skip_modules else None
    has_session = bool(args.username or args.token or args.session or args.sso)
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
                continue

            # ── Emit: module_start ────────────────────────────────────
            _emit(bus, Event, EventType, "module_start", source=module_name,
                  name=module_name, phase=phase.number)

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

            except Exception as exc:
                log.error("Module %s failed: %s", module_name, exc)
                errors.append(f"{module_name}: {exc}")
                _emit(bus, Event, EventType, "module_fail", source=module_name,
                      name=module_name, error=str(exc))

        # ── Emit: phase_complete ──────────────────────────────────────
        phase_duration = time.monotonic() - phase_start
        _emit(bus, Event, EventType, "phase_complete", source="webforge",
              number=phase.number, name=phase.name, duration=round(phase_duration, 1))

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

    return await run_scan(cfg, args, results_dir, event_bus, scan_control)


async def main() -> None:
    args = parse_args()

    if args.list_modules:
        describe_phases(args.mode)
        return

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

    # Wire EventBus — remote when dashboard URL given, local otherwise
    event_bus = None
    if args.dashboard_url:
        try:
            from common.dashboard.event_bus import RemoteEventBus
            event_bus = RemoteEventBus(args.dashboard_url, run_id=run_id if 'run_id' in dir() else "")
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
