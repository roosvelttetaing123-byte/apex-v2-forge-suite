#!/usr/bin/env python3
"""
WebForge — Web Application Penetration Testing Framework
=========================================================
Master entry point. Runs ALL modules in PHASE ORDER (phases 1-12).
v5 APEX: EventBus integration, multi-target, pause/resume/abort.

FOR AUTHORIZED PENETRATION TESTING ONLY.

Usage:
  python webforge.py --target https://target.com --mode blackbox
  python webforge.py --targets targets.txt --parallel 5
  python webforge.py --target https://target.com --mode greybox --username admin --password Pass123
  python webforge.py --target https://target.com --mode whitebox --source-root /path/to/src
  python webforge.py --target https://target.com --session session.json
  python webforge.py --target https://target.com --sso
  python webforge.py --target https://target.com --dry-run
  python webforge.py --target https://target.com --resume results/target_20240101/
"""
from __future__ import annotations

import argparse
import asyncio
import getpass
import importlib
import json
import os
import re
import stat
import sys
import time
import uuid
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Allow imports from forge-suite root
sys.path.insert(0, str(Path(__file__).parent.parent))

from common.auth_prompt import require_authorization
from common.action_authorization import (
    AUTHORIZATION_ENVELOPES_ENV,
    ActionAuthorizationEnvelope,
    AuthorizationContext,
    AuthorizationDecision,
    AuthorizationReason,
    ConfirmationMethod,
    OperatorRole,
    SafetyMode,
    authorization_runtime_environment,
    consume_authorization,
    derive_authorization,
    issue_authorization,
    load_authorization_envelopes,
    load_authorization_runtime_facts,
    module_binding_allows,
    module_set_binding,
    open_authorization_session,
    protected_credential_reference,
    record_boundary_denial,
    redact_authorization_value,
    record_authorization_denial,
    select_authorization_envelope,
    validate_consumed_authorization,
)
from common.config import BaseForgeConfig, load_config
from common.artifact_io import (
    ArtifactBoundaryError,
    absolute_lexical_path,
    atomic_write_bytes,
    open_private_directory,
    prepare_owner_controlled_directory,
)
from common.confirm_gate import (
    LAUNCH_CONFIRMATIONS_ENV,
    ActionConfirmation,
    decide_action,
    load_launch_confirmations,
    load_launch_expectation,
    set_auto_confirm,
)
from common.credential_boundary import (
    CREDENTIAL_REF_ENV,
    CredentialReference,
    resolved_process_credentials,
    wipe_mapping,
)
from common.db import create_db, ScanRunModel
from common.finding import Finding
from common.logger import get_logger, phase_banner, console
from common.netcheck import ask_internet_permission
from common.reporter import BaseReporter
from common.redaction import redact_text, redact_value, redacted_json_dumps
from common.scope import Scope, ScopeDecision, ScopeReason, canonical_target, decision_for_reason, safe_target_display

from webforge.core.browser_detect import print_browser_status
from webforge.core.mode_engine import get_phases, describe_phases, CONFIRM_GATE_MODULES

log = get_logger("webforge")

from common.version import VERSION
AUTH_TYPES = {"form", "bearer", "cookie"}
ENGINE_NAME = "webforge"
DEFAULT_LAUNCH_ACTION = "scan"
ALLOWED_LAUNCH_ACTIONS = {"scan", "retest"}

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
        bus.emit(
            Event(
                event_type=EventType(etype),
                data=redact_authorization_value(data),
                source=source,
            )
        )
    except Exception as exc:
        log.debug(
            "EventBus emission failed (%s, %s)",
            etype,
            type(exc).__name__,
        )


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
            log.debug("Control file refresh failed (%s)", type(exc).__name__)


def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return parsed


def _normalize_target(target: str) -> str:
    value = target.strip()
    if not value.startswith(("http://", "https://")):
        value = "https://" + value
    return value


def _read_targets_file(path_value: str) -> list[str]:
    path = Path(path_value).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    if not path.exists():
        raise FileNotFoundError(f"Target file not found: {path}")
    targets: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        value = line.strip()
        if value and not value.startswith("#"):
            targets.append(_normalize_target(value.split(maxsplit=1)[0]))
    if not targets:
        raise ValueError(f"Target file has no usable targets: {path}")
    return targets


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="WebForge — Web Application Penetration Testing Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        allow_abbrev=False,
    )
    parser.add_argument("--target",        default=None,            help="Target URL (e.g. https://target.com)")
    parser.add_argument("--targets",       default=None,            help="Multi-target file (one target per line)")
    parser.add_argument("--parallel",      type=_positive_int, default=3,
                        help="Max parallel targets for --targets (default: 3)")
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
    parser.add_argument(
        "--source-root",
        dest="source_root",
        default=None,
        help="Approved absolute canonical source root (required for whitebox mode)",
    )
    parser.add_argument("--modules",       default=None,            help="Comma-separated module list to run")
    parser.add_argument(
        "--reference-slice",
        default=None,
        choices=["header-audit-csp-v1"],
        help="Run the exact governed Task 105 header_audit CSP slice",
    )
    parser.add_argument("--skip-modules",  default=None,            help="Comma-separated modules to skip")
    parser.add_argument("--jwt-token",     default=None,            help="JWT token for jwt_audit module")
    parser.add_argument("--scope",         action="append", default=[], metavar="ENTRY",
                        help="Explicitly authorized host, URL, IP, or CIDR (repeatable)")
    parser.add_argument("--exclude",       action="append", default=[], metavar="ENTRY",
                        help="Explicitly excluded host, URL, IP, or CIDR (repeatable)")
    parser.add_argument("--dry-run",       action="store_true",     help="Show plan without sending requests")
    parser.add_argument("--resume",        default=None,            help="Resume from results directory")
    parser.add_argument("--auto-confirm",  action="store_true",     help="Skip confirmation gates (pipeline mode)")
    parser.add_argument("--browser",       default=None,
                        choices=["chrome","chromium","firefox"],     help="Force browser for screenshots")
    parser.add_argument("--browser-render", action="store_true",
                        help="Render target with Playwright before scanning to discover SPA routes, forms, and XHR endpoints")
    parser.add_argument("--login-url",     default=None,
                        help="Login URL for browser-based authenticated scanning")
    parser.add_argument("--login-script",  default=None,
                        help="YAML/JSON Playwright login sequence for complex SSO/form flows")
    parser.add_argument("--auth-type",     default=None,
                        choices=["form", "bearer", "cookie"],
                        help="Authentication type (set by dashboard for greybox/whitebox scans)")
    parser.add_argument("--header-name",   default="Authorization",
                        help="Custom header name for bearer token auth (default: Authorization)")
    parser.add_argument("--auth-state",    default=None,
                        help="Playwright storage-state JSON to reuse authenticated browser session")
    parser.add_argument("--api-schema",    default=None,
                        help="OpenAPI/Swagger/Postman/GraphQL introspection JSON or YAML file")
    parser.add_argument("--graphql-schema-url", default=None,
                        help="Live GraphQL endpoint URL to introspect and add to API test surface")
    parser.add_argument("--no-screenshot", action="store_true",     help="Disable screenshot capture")
    parser.add_argument("--list-modules",  action="store_true",     help="List all available modules and exit")
    parser.add_argument("--profile",       default=None,
                        help="Scan profile: quick, standard, full, api, compliance, stealth")
    parser.add_argument("--list-profiles", action="store_true",     help="List available scan profiles and exit")
    parser.add_argument("--verbose",       action="store_true",     help="Verbose debug output")
    parser.add_argument("--quiet",         action="store_true",     help="Suppress UI output")
    parser.add_argument("--collab-domain", default=None,
                        help="ForgeCollab OOB domain (e.g. collab.example.com) for blind vuln confirmation")
    parser.add_argument("--version",       action="version", version=f"WebForge {VERSION}")
    parser.add_argument("--dashboard-url", default=None,
                        help="Live dashboard URL (e.g. http://localhost:1337) — streams events in real time")
    parser.add_argument("--control-file",  default=None,
                        help="JSON control file used by dashboard pause/resume/abort")
    return parser.parse_args()


def _denied_summary(decision: ScopeDecision, *, dry_run: bool = False) -> dict[str, Any]:
    return {
        "status": "not_authorized",
        "findings": 0,
        "errors": [decision.reason],
        "duration": 0.0,
        "dry_run": dry_run,
        "authorized": False,
        "reason_code": decision.reason_code,
        "reason": decision.reason,
    }


def _authorization_denied_summary(decision: AuthorizationDecision) -> dict[str, Any]:
    return {
        "status": "not_authorized",
        "findings": 0,
        "errors": [decision.reason],
        "duration": 0.0,
        "dry_run": False,
        "authorized": False,
        "reason_code": decision.reason_code,
        "reason": decision.reason,
    }


def _print_launch_denial(decision: ScopeDecision) -> None:
    console.print(
        f"[bold red]Launch denied:[/bold red] reason_code={decision.reason_code}; {decision.reason}"
    )


def _confirmation_for_target(
    confirmations: list[ActionConfirmation],
    target: str,
) -> ActionConfirmation | None:
    """Select one exact WebForge record while preserving its bound action."""
    try:
        expected_target = canonical_target(target)
    except ValueError:
        return None
    exact = [
        record
        for record in confirmations
        if record.engine == ENGINE_NAME and record.target == expected_target
    ]
    if len(exact) == 1:
        return exact[0]
    return confirmations[0] if len(confirmations) == 1 else None


def _authorization_context_from_envelope(
    envelope: ActionAuthorizationEnvelope,
    cfg: BaseForgeConfig,
    *,
    action_kind: str,
    module_id: str | None = None,
) -> AuthorizationContext:
    runtime = cfg.extra.get("authorization_runtime")
    if not isinstance(runtime, Mapping):
        runtime = {}
    try:
        operator_role: OperatorRole | str = OperatorRole(
            str(runtime.get("operator_role", ""))
        )
    except ValueError:
        operator_role = OperatorRole.SYSTEM
    try:
        safety_mode: SafetyMode | str = SafetyMode(
            str(runtime.get("safety_mode", ""))
        )
    except ValueError:
        safety_mode = SafetyMode.LOCAL_LAB
    return AuthorizationContext(
        tenant_id=str(runtime.get("tenant_id") or "runtime-missing-tenant"),
        engagement_id=str(runtime.get("engagement_id") or "runtime-missing-engagement"),
        run_id=str(runtime.get("run_id") or "runtime-missing-run"),
        job_id=str(cfg.extra.get("job_id") or "runtime-missing-job"),
        operator_id=str(runtime.get("operator_id") or "runtime-missing-operator"),
        operator_role=operator_role,
        action_kind=action_kind,
        engine=ENGINE_NAME,
        module_id=envelope.module_id if module_id is None else module_id,
        requested_target=cfg.target,
        resolved_target=cfg.target,
        allowed_scope=cfg.extra.get("allowed_scope", []),
        excluded_scope=cfg.extra.get("excluded_scope", []),
        scope_policy_version=str(
            runtime.get("scope_policy_version") or "runtime-missing-policy"
        ),
        safety_mode=safety_mode,
        credential_approval_required=bool(
            cfg.extra.get("runtime_credential_reference")
        ),
        network_escalation_approval_required=(
            str(cfg.extra.get("launch_action") or "") == "web_to_network"
        ),
        high_risk_approval_required=False,
        confirmation_method=ConfirmationMethod.INHERITED,
        confirmed_by=str(runtime.get("operator_id") or ""),
        credential_reference=str(
            cfg.extra.get("runtime_credential_reference") or ""
        ),
        parent_decision_id=envelope.decision_id,
    )


def _requested_modules(args: argparse.Namespace) -> list[str]:
    return [item.strip() for item in args.modules.split(",") if item.strip()] if args.modules else []


def _credential_values(args: argparse.Namespace) -> dict[str, str]:
    """Return credential inputs actually available to this WebForge process."""
    values = {
        "auth_type": str(getattr(args, "auth_type", "") or ""),
        "username": str(getattr(args, "username", "") or ""),
        "password": str(getattr(args, "password", None) or ""),
        "token": str(getattr(args, "token", None) or ""),
        "cookie": str(getattr(args, "cookie", None) or ""),
        "session": str(getattr(args, "session", "") or ""),
        "auth_state": str(getattr(args, "auth_state", "") or ""),
    }
    credential_keys = (
        "username",
        "password",
        "token",
        "cookie",
        "session",
        "auth_state",
    )
    return values if any(values[key] for key in credential_keys) else {}


def _credential_reference(args: argparse.Namespace) -> str:
    inherited = os.environ.get(CREDENTIAL_REF_ENV, "").strip()
    if inherited:
        try:
            return CredentialReference.parse(inherited).value
        except ValueError:
            return ""
    return protected_credential_reference(_credential_values(args))


def _has_direct_secret_args(args: argparse.Namespace) -> bool:
    return any(
        bool(getattr(args, field, None)) for field in ("password", "token", "cookie")
    )


def _audit_scope_denial(
    args: argparse.Namespace,
    decision: ScopeDecision,
    *,
    target: str | None = None,
) -> None:
    if bool(getattr(args, "dry_run", False)):
        return
    runtime = getattr(args, "_authorization_runtime", None)
    if not isinstance(runtime, Mapping):
        runtime = load_authorization_runtime_facts()
    operator_id = str(
        runtime.get("operator_id")
        or getpass.getuser().strip()
        or "operator"
    )
    session = open_authorization_session()
    try:
        record_boundary_denial(
            session=session,
            reason_code=decision.reason_code,
            action_kind=getattr(args, "_launch_action", DEFAULT_LAUNCH_ACTION),
            engine=ENGINE_NAME,
            target=target if target is not None else getattr(args, "target", None),
            allowed_scope=getattr(args, "scope", []),
            excluded_scope=getattr(args, "exclude", []),
            tenant_id=runtime.get(
                "tenant_id",
                os.environ.get("FORGE_TENANT_ID", "default"),
            ),
            engagement_id=runtime.get(
                "engagement_id",
                getattr(args, "engagement", "preflight"),
            ),
            run_id=runtime.get("run_id", "webforge-preflight-run"),
            job_id=getattr(args, "_launch_job_id", "webforge-preflight-job"),
            operator_id=operator_id,
            operator_role=runtime.get(
                "operator_role",
                OperatorRole.OPERATOR.value,
            ),
            module_id=module_set_binding(_requested_modules(args)),
            scope_policy_version=runtime.get(
                "scope_policy_version",
                "scope-policy-v1",
            ),
            safety_mode=runtime.get("safety_mode", SafetyMode.ACTIVE.value),
            credential_reference=_credential_reference(args),
        )
    finally:
        session.close()


def _prepare_engine_authorizations(
    args: argparse.Namespace,
    targets: list[str],
    confirmations: list[ActionConfirmation],
) -> tuple[ScopeDecision, list[ActionAuthorizationEnvelope]]:
    inherited = load_authorization_envelopes()
    if os.environ.get(AUTHORIZATION_ENVELOPES_ENV) and not inherited:
        denied = decision_for_reason(ScopeReason.INVALID_CONFIRMATION)
        _audit_scope_denial(
            args,
            denied,
            target=(targets[0] if targets else None),
        )
        return denied, []
    job_id = str(getattr(args, "_launch_job_id", ""))
    module_binding = module_set_binding(_requested_modules(args))
    if inherited:
        selected: list[ActionAuthorizationEnvelope] = []
        for target in targets:
            envelope = select_authorization_envelope(
                inherited,
                job_id=job_id,
                engine=ENGINE_NAME,
                action_kind="engine.execute",
                requested_target=target,
                resolved_target=target,
                module_id=module_binding,
            )
            if envelope is None:
                denied = decision_for_reason(ScopeReason.INVALID_CONFIRMATION)
                _audit_scope_denial(args, denied, target=target)
                return denied, []
            selected.append(envelope)
        return decision_for_reason(ScopeReason.ALLOWED), selected

    tenant_id = os.environ.get("FORGE_TENANT_ID", "default").strip() or "default"
    operator_id = getpass.getuser().strip() or "operator"
    credential_reference = _credential_reference(args)
    session = open_authorization_session()
    prepared: list[ActionAuthorizationEnvelope] = []
    run_id = f"run-{uuid.uuid4().hex}"
    try:
        for target in targets:
            confirmation = _confirmation_for_target(confirmations, target)
            if confirmation is None:
                return decision_for_reason(ScopeReason.MISSING_CONFIRMATION), []
            base_context = AuthorizationContext(
                tenant_id=tenant_id,
                engagement_id=str(args.engagement or "default"),
                run_id=run_id,
                job_id=job_id,
                operator_id=operator_id,
                operator_role=OperatorRole.OPERATOR,
                action_kind=str(getattr(args, "_launch_action", DEFAULT_LAUNCH_ACTION)),
                engine=ENGINE_NAME,
                module_id=module_binding,
                requested_target=target,
                resolved_target=target,
                allowed_scope=args.scope,
                excluded_scope=args.exclude,
                safety_mode=SafetyMode.ACTIVE,
                credential_approval_required=bool(credential_reference),
                credential_reference=credential_reference,
                confirmation_method=(
                    ConfirmationMethod.CLI_FLAG
                    if args.auto_confirm
                    else ConfirmationMethod.CLI_PROMPT
                ),
                confirmed_by=operator_id,
            )
            issued = issue_authorization(
                session=session,
                context=base_context,
                confirmation=confirmation,
            )
            consumed = consume_authorization(
                session=session,
                envelope=issued.envelope,
                expected=base_context,
                boundary="webforge.cli",
            )
            if not issued.allowed or not consumed.allowed:
                return decision_for_reason(ScopeReason.INVALID_CONFIRMATION), []
            engine_context = AuthorizationContext(
                **{
                    **base_context.__dict__,
                    "action_kind": "engine.execute",
                    "parent_decision_id": issued.envelope.decision_id,
                    "confirmation_method": ConfirmationMethod.INHERITED,
                }
            )
            derived = derive_authorization(
                session=session,
                parent_envelope=issued.envelope,
                context=engine_context,
                parent_boundary="webforge.cli",
            )
            if not derived.allowed:
                return decision_for_reason(ScopeReason.INVALID_CONFIRMATION), []
            prepared.append(derived.envelope)
    finally:
        session.close()
    if prepared:
        args._authorization_runtime = load_authorization_runtime_facts(
            authorization_runtime_environment(prepared[0])
        )
    return decision_for_reason(ScopeReason.ALLOWED), prepared


def _launch_decision(
    cfg: BaseForgeConfig,
    args: argparse.Namespace,
    *,
    target: str | None = None,
) -> ScopeDecision:
    """Revalidate scope and exact action at the execution boundary."""
    launch_target = target or cfg.target
    allowed_scope = cfg.extra.get("allowed_scope", getattr(args, "scope", None))
    excluded_scope = cfg.extra.get("excluded_scope", getattr(args, "exclude", None))
    confirmation = cfg.extra.get("launch_confirmation")
    action = str(cfg.extra.get("launch_action") or DEFAULT_LAUNCH_ACTION)
    if action not in ALLOWED_LAUNCH_ACTIONS:
        return decision_for_reason(ScopeReason.ACTION_MISMATCH)
    job_id = str(cfg.extra.get("job_id") or "")
    return decide_action(
        target=launch_target,
        allowed_scope=allowed_scope,
        excluded_scope=excluded_scope,
        confirmation=confirmation,
        job_id=job_id,
        engine=ENGINE_NAME,
        action=action,
        require_confirmation=not bool(getattr(args, "dry_run", False)),
    )


def _apply_launch_context(
    cfg: BaseForgeConfig,
    args: argparse.Namespace,
    target: str,
    confirmations: list[ActionConfirmation],
    authorizations: list[ActionAuthorizationEnvelope] | None = None,
) -> None:
    cfg.extra["allowed_scope"] = list(getattr(args, "scope", None) or [])
    cfg.extra["excluded_scope"] = list(getattr(args, "exclude", None) or [])
    requested_modules = _requested_modules(args)
    cfg.extra["authorized_requested_modules"] = requested_modules
    cfg.extra["authorization_module_binding"] = module_set_binding(requested_modules)
    runtime = getattr(args, "_authorization_runtime", None)
    if not isinstance(runtime, Mapping):
        runtime = load_authorization_runtime_facts()
    cfg.extra["authorization_runtime"] = dict(runtime)
    cfg.extra["runtime_credential_reference"] = _credential_reference(args)
    confirmation = _confirmation_for_target(confirmations, target)
    if confirmation is not None:
        cfg.extra["job_id"] = getattr(args, "_launch_job_id", "")
        cfg.extra["launch_action"] = getattr(args, "_launch_action", "")
        cfg.extra["launch_confirmation"] = confirmation
    authorization = select_authorization_envelope(
        authorizations or [],
        job_id=str(getattr(args, "_launch_job_id", "")),
        engine=ENGINE_NAME,
        action_kind="engine.execute",
        requested_target=target,
        resolved_target=target,
        module_id=str(cfg.extra["authorization_module_binding"]),
    )
    if authorization is not None:
        cfg.extra["authorization_envelope"] = authorization


def _consume_engine_authorization(
    cfg: BaseForgeConfig,
) -> AuthorizationDecision:
    envelope = cfg.extra.get("authorization_envelope")
    if isinstance(envelope, dict):
        try:
            envelope = ActionAuthorizationEnvelope.from_value(envelope)
        except (TypeError, ValueError):
            pass
    if not isinstance(envelope, ActionAuthorizationEnvelope):
        expected = AuthorizationContext(
            tenant_id="default",
            engagement_id=str(cfg.engagement or "default"),
            run_id=str(cfg.extra.get("job_id") or "legacy-run"),
            job_id=str(cfg.extra.get("job_id") or "legacy-job"),
            operator_id="legacy-operator",
            operator_role=OperatorRole.OPERATOR,
            action_kind="engine.execute",
            engine=ENGINE_NAME,
            module_id="",
            requested_target=cfg.target,
            resolved_target=cfg.target,
            allowed_scope=cfg.extra.get("allowed_scope", []),
            excluded_scope=cfg.extra.get("excluded_scope", []),
            safety_mode=SafetyMode.ACTIVE,
            confirmation_method=ConfirmationMethod.NONE,
        )
    else:
        expected = _authorization_context_from_envelope(
            envelope,
            cfg,
            action_kind="engine.execute",
            module_id=str(cfg.extra.get("authorization_module_binding", "")),
        )
    session = open_authorization_session()
    try:
        if (
            isinstance(envelope, ActionAuthorizationEnvelope)
            and cfg.extra.get("consumed_engine_authorization") == envelope.decision_id
        ):
            return validate_consumed_authorization(
                session=session,
                envelope=envelope,
                expected=expected,
                boundary="webforge.engine",
            )
        decision = consume_authorization(
            session=session,
            envelope=envelope,
            expected=expected,
            boundary="webforge.engine",
        )
        if decision.allowed:
            cfg.extra["consumed_engine_authorization"] = decision.envelope.decision_id
        return decision
    finally:
        session.close()


def _authorize_module_execution(
    cfg: BaseForgeConfig,
    parent: ActionAuthorizationEnvelope,
    module_name: str,
) -> AuthorizationDecision:
    context = _authorization_context_from_envelope(
        parent,
        cfg,
        action_kind="module.execute",
        module_id=module_name,
    )
    session = open_authorization_session()
    try:
        if not module_binding_allows(
            parent.module_id,
            cfg.extra.get("authorized_requested_modules", []),
            module_name,
        ):
            return record_authorization_denial(
                session=session,
                context=context,
                reason_code=AuthorizationReason.MODULE_MISMATCH,
                parent_decision_id=parent.decision_id,
            )
        derived = derive_authorization(
            session=session,
            parent_envelope=parent,
            context=context,
            parent_boundary="webforge.engine",
        )
        if not derived.allowed:
            return derived
        consumed = consume_authorization(
            session=session,
            envelope=derived.envelope,
            expected=context,
            boundary="webforge.module",
        )
        if consumed.allowed:
            cfg.extra.setdefault("authorized_module_decisions", {})[module_name] = (
                derived.envelope.decision_id
            )
            cfg.extra.setdefault("authorized_module_envelopes", {})[module_name] = (
                derived.envelope
            )
        return consumed
    finally:
        session.close()


def _prepare_cli_confirmations(
    args: argparse.Namespace,
    targets: list[str],
) -> tuple[ScopeDecision, list[ActionConfirmation]]:
    """Preflight every target before browser, worker, event, or module work."""
    inherited = load_launch_confirmations()
    if not args.dry_run and os.environ.get(LAUNCH_CONFIRMATIONS_ENV) and not inherited:
        return decision_for_reason(ScopeReason.INVALID_CONFIRMATION), []

    inherited_expectation = load_launch_expectation() if inherited else None
    if inherited and inherited_expectation is None:
        return decision_for_reason(ScopeReason.INVALID_CONFIRMATION), []
    job_id, expected_action = inherited_expectation or (
        f"webforge-cli-{uuid.uuid4().hex}",
        DEFAULT_LAUNCH_ACTION,
    )
    if expected_action not in ALLOWED_LAUNCH_ACTIONS:
        return decision_for_reason(ScopeReason.ACTION_MISMATCH), []
    args._launch_job_id = job_id
    args._launch_action = expected_action
    prepared: list[ActionConfirmation] = []
    last_decision = decision_for_reason(ScopeReason.MALFORMED_TARGET)
    for target in targets:
        last_decision = decide_action(
            target=target,
            allowed_scope=getattr(args, "scope", None),
            excluded_scope=getattr(args, "exclude", None),
            confirmation=None,
            job_id=job_id,
            engine=ENGINE_NAME,
            action=expected_action,
            require_confirmation=False,
        )
        if not last_decision.allowed:
            return last_decision, []
        if args.dry_run:
            continue

        confirmation = _confirmation_for_target(inherited, target)
        if confirmation is None and inherited:
            return decision_for_reason(ScopeReason.MISSING_CONFIRMATION), []
        if confirmation is None:
            if not args.auto_confirm:
                try:
                    require_authorization(target, "WebForge")
                except SystemExit:
                    _audit_scope_denial(
                        args,
                        decision_for_reason(ScopeReason.MISSING_CONFIRMATION),
                        target=target,
                    )
                    raise
            confirmation = ActionConfirmation.create(
                job_id=job_id,
                target=target,
                engine=ENGINE_NAME,
                action=expected_action,
            )

        last_decision = decide_action(
            target=target,
            allowed_scope=args.scope,
            excluded_scope=args.exclude,
            confirmation=confirmation,
            job_id=job_id,
            engine=ENGINE_NAME,
            action=expected_action,
        )
        if not last_decision.allowed:
            return last_decision, []
        prepared.append(confirmation)
    return last_decision, prepared


def _results_base_dir(output_dir: str | None) -> Path:
    if output_dir:
        return absolute_lexical_path(Path(output_dir).expanduser())
    return absolute_lexical_path(Path(__file__).parent / "results")


def _safe_result_component(value: object, fallback: str) -> str:
    """Return one bounded, redacted filename component with no path syntax."""
    rendered = redact_text(str(value or ""))
    rendered = re.sub(r"[^A-Za-z0-9._-]+", "_", rendered).strip("._-")
    if not rendered or rendered in {".", ".."}:
        rendered = fallback
    return rendered[:80]


def _ensure_owner_only_results_directory(path: Path) -> Path:
    descriptor = -1
    candidate = absolute_lexical_path(path)
    try:
        descriptor = open_private_directory(candidate, create=True)
        if not prepare_owner_controlled_directory(descriptor):
            raise ArtifactBoundaryError("results directory must be owner-controlled")
        os.fchmod(descriptor, 0o700)
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700:
            raise ArtifactBoundaryError("results directory is unavailable")
        return candidate
    except ArtifactBoundaryError:
        raise ValueError("results directory is unavailable") from None
    except Exception:
        raise ValueError("results directory is unavailable") from None
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except Exception:
                pass


def _unique_results_dir(base: Path, dirname: str) -> Path:
    candidate_base = absolute_lexical_path(base)
    base_descriptor = -1
    try:
        base_descriptor = open_private_directory(candidate_base, create=True)
        if not prepare_owner_controlled_directory(base_descriptor):
            raise ArtifactBoundaryError("results directory must be owner-controlled")
        for attempt in range(101):
            suffix = "" if attempt == 0 else f"_{uuid.uuid4().hex[:8]}"
            name = f"{dirname}{suffix}"
            try:
                os.mkdir(name, 0o700, dir_fd=base_descriptor)
            except FileExistsError:
                continue
            child_descriptor = -1
            try:
                child_descriptor = os.open(
                    name,
                    os.O_RDONLY
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0),
                    dir_fd=base_descriptor,
                )
                os.fchmod(child_descriptor, 0o700)
                metadata = os.fstat(child_descriptor)
                if (
                    not stat.S_ISDIR(metadata.st_mode)
                    or stat.S_IMODE(metadata.st_mode) != 0o700
                ):
                    raise ArtifactBoundaryError("results directory is unavailable")
                return candidate_base / name
            finally:
                if child_descriptor >= 0:
                    try:
                        os.close(child_descriptor)
                    except Exception:
                        pass
        raise ArtifactBoundaryError("results directory name is unavailable")
    except ArtifactBoundaryError:
        raise ValueError("results directory is unavailable") from None
    except Exception:
        raise ValueError("results directory is unavailable") from None
    finally:
        if base_descriptor >= 0:
            try:
                os.close(base_descriptor)
            except Exception:
                pass


def setup_results_dir(
    target: str,
    engagement: str,
    resume_path: str | None,
    output_dir: str | None = None,
) -> Path:
    if resume_path:
        return _ensure_owner_only_results_directory(Path(resume_path).expanduser())
    host = _safe_result_component(safe_target_display(target), "target")
    safe_engagement = _safe_result_component(engagement, "engagement")
    ts   = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    path = _unique_results_dir(
        _results_base_dir(output_dir),
        f"{safe_engagement}_{host}_{ts}",
    )
    _ensure_owner_only_results_directory(path / "evidence" / "screenshots")
    _ensure_owner_only_results_directory(path / "evidence" / "http")
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
        log.warning(
            "Could not load module %s (%s)",
            module_name,
            type(exc).__name__,
        )
        return None


async def prepare_browser_context(
    cfg: BaseForgeConfig,
    args: argparse.Namespace,
    results_dir: Path,
) -> None:
    """Populate cfg.extra with browser-discovered auth/session artifacts."""
    if not (
        args.browser_render
        or args.login_url
        or args.auth_state
        or getattr(args, "login_script", None)
    ):
        return

    active_browser_requested = bool(
        args.login_url or getattr(args, "login_script", None) or args.browser_render
    )
    if active_browser_requested:
        cfg.extra["browser_outbound_state"] = "unsupported_policy_proxy"
        log.warning(
            "Active browser login/render disabled: no approved policy-aware loopback proxy is bound"
        )
        # Importing a local storage-state file below remains safe; all active
        # Playwright navigation is deferred until a route-bound module policy
        # exists.
        if not args.auth_state:
            return

    browser_name = args.browser or "chromium"

    if args.auth_state:
        from webforge.core.auth_recorder import AuthRecorder
        auth = AuthRecorder(results_dir, proxy=cfg.proxy).import_storage_state(
            Path(args.auth_state),
            cfg.target,
        )
        _merge_auth_result(cfg, auth)
        log.info("Loaded browser auth state from %s", args.auth_state)

    if active_browser_requested:
        return

    if getattr(args, "login_script", None):
        from webforge.core.auth_recorder import AuthRecorder, parse_login_script
        raw_steps = _load_structured_file(Path(args.login_script))
        if not isinstance(raw_steps, list):
            log.warning("Login script must be a list of steps: %s", args.login_script)
        else:
            auth = await AuthRecorder(results_dir, proxy=cfg.proxy).replay_script(
                parse_login_script(raw_steps),
                browser=browser_name,
                target_url=cfg.target,
            )
            cfg.extra["browser_auth"] = auth.to_dict()
            _merge_auth_result(cfg, auth)
            if auth.error:
                log.warning("Login script did not complete cleanly")
            else:
                log.info("Login script completed; storage state exported")

    if args.login_url:
        from webforge.core.auth_recorder import AuthRecorder
        auth = await AuthRecorder(results_dir, proxy=cfg.proxy).replay_login(
            args.login_url,
            username=args.username or cfg.extra.get("username", ""),
            password=args.password or cfg.extra.get("password", ""),
            browser=browser_name,
            target_url=cfg.target,
        )
        cfg.extra["browser_auth"] = auth.to_dict()
        _merge_auth_result(cfg, auth)
        if auth.error:
            log.warning("Browser login did not complete cleanly")
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
                log.warning("Browser render discovery failed")
            else:
                log.info(
                    "Browser discovery: framework=%s forms=%d ajax=%d links=%d",
                    snap.framework or "unknown",
                    len(snap.forms),
                    len(snap.ajax_endpoints),
                    len(snap.links),
                )
        except Exception as exc:
            log.warning(
                "Browser render discovery unavailable (%s)",
                type(exc).__name__,
            )


def _merge_auth_result(cfg: BaseForgeConfig, auth: Any) -> None:
    """Merge only credentials with revalidated target-origin provenance."""
    if getattr(auth, "storage_state_path", ""):
        cfg.extra["browser_storage_state"] = auth.storage_state_path
    _apply_verified_session_credentials(
        cfg,
        cookies=getattr(auth, "cookies", {}) or {},
        cookie_provenance=getattr(auth, "cookie_provenance", {}) or {},
        tokens=getattr(auth, "tokens", {}) or {},
        token_provenance=getattr(auth, "token_provenance", {}) or {},
        credential_origin=str(getattr(auth, "credential_origin", "")),
    )


def _apply_verified_session_credentials(
    cfg: BaseForgeConfig,
    *,
    cookies: Mapping[str, Any],
    cookie_provenance: Mapping[str, Any],
    tokens: Mapping[str, Any],
    token_provenance: Mapping[str, Any],
    credential_origin: str,
) -> None:
    from common.outbound_policy import normalize_destination
    from webforge.core.auth_recorder import cookie_provenance_matches_target

    try:
        target_origin = normalize_destination(cfg.target).origin
    except Exception:
        return
    if credential_origin != target_origin:
        return
    retained_cookies = {
        str(name): str(value)
        for name, value in cookies.items()
        if cookie_provenance_matches_target(
            cookie_provenance.get(name),
            cfg.target,
        )
    }
    retained_tokens = {
        str(name): str(value)
        for name, value in tokens.items()
        if token_provenance.get(name) == target_origin and value
    }
    jwt = retained_tokens.get("jwt")
    bearer = retained_tokens.get("bearer")
    if jwt and bearer and jwt != bearer:
        retained_tokens.pop("jwt", None)
        retained_tokens.pop("bearer", None)

    if retained_cookies:
        merged_cookies = {
            **(cfg.extra.get("session_cookies", {}) or {}),
            **retained_cookies,
        }
        merged_provenance = {
            **(cfg.extra.get("session_cookie_provenance", {}) or {}),
            **{
                name: dict(cookie_provenance[name])
                for name in retained_cookies
                if isinstance(cookie_provenance.get(name), Mapping)
            },
        }
        cfg.extra["session_cookies"] = merged_cookies
        cfg.extra["session_cookie_provenance"] = merged_provenance
        cfg.extra.setdefault("session_headers", {})["Cookie"] = "; ".join(
            f"{name}={value}" for name, value in sorted(merged_cookies.items())
        )
    if retained_tokens.get("jwt"):
        token = retained_tokens["jwt"]
        cfg.extra["jwt_token"] = token
        cfg.extra.setdefault("token", token)
        cfg.extra.setdefault("session_headers", {})["Authorization"] = f"Bearer {token}"
    elif retained_tokens.get("bearer"):
        token = retained_tokens["bearer"]
        cfg.extra.setdefault("token", token)
        cfg.extra.setdefault("session_headers", {})["Authorization"] = f"Bearer {token}"
    if retained_tokens.get("csrf"):
        csrf = retained_tokens["csrf"]
        cfg.extra.setdefault("session_headers", {})["X-CSRF-Token"] = csrf
        cfg.extra.setdefault("session_headers", {})["X-XSRF-Token"] = csrf
    if retained_cookies or retained_tokens:
        cfg.extra["session_credential_provenance"] = {
            "origin": target_origin,
            "cookies": sorted(retained_cookies),
            "tokens": sorted(retained_tokens),
        }


def _clean_cookie_header(value: str) -> str:
    return re.sub(r"^cookie:\s*", "", value.strip(), flags=re.IGNORECASE)


def _parse_cookie_header(value: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for part in _clean_cookie_header(value).split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        name, cookie_value = part.split("=", 1)
        name = name.strip()
        if name.lower() in {"path", "domain", "expires", "max-age", "secure", "httponly", "samesite"}:
            continue
        parsed[name] = cookie_value.strip()
    return parsed


def _apply_auth_context(
    cfg: BaseForgeConfig,
    args: argparse.Namespace,
    environ: Mapping[str, str] | None = None,
    credential_values: Mapping[str, str] | None = None,
) -> None:
    """Merge CLI metadata and already-authorized provider values into config."""
    env = environ if environ is not None else os.environ
    resolved = credential_values or {}
    raw_auth_type = (
        env.get("FORGE_AUTH_TYPE", "")
        or getattr(args, "auth_type", None)
        or ""
    )
    auth_type = raw_auth_type.strip().lower()
    if auth_type:
        if auth_type in AUTH_TYPES:
            cfg.extra["auth_type"] = auth_type
        else:
            log.warning("Unsupported auth type supplied; ignoring auth-type-specific setup")
            auth_type = ""

    header_name = (getattr(args, "header_name", None) or "Authorization").strip() or "Authorization"

    username = getattr(args, "username", None)
    if username:
        cfg.extra["username"] = username

    password = resolved.get("password") or getattr(args, "password", None)
    if password:
        cfg.extra["password"] = password

    token = resolved.get("token") or getattr(args, "token", None)
    if token:
        cfg.extra["token"] = token
        if auth_type in {"", "bearer"}:
            header_value = f"Bearer {token}" if header_name.lower() == "authorization" else token
            cfg.extra.setdefault("session_headers", {})[header_name] = header_value

    cookie = resolved.get("cookie") or getattr(args, "cookie", None)
    if cookie:
        cookie_header = _clean_cookie_header(str(cookie))
        cfg.extra["cookie"] = cookie_header
        if auth_type in {"", "cookie"}:
            cfg.extra.setdefault("session_headers", {})["Cookie"] = cookie_header
            cookie_dict = _parse_cookie_header(cookie_header)
            if cookie_dict:
                cfg.extra.setdefault("session_cookies", {}).update(cookie_dict)


def _clear_auth_context(cfg: BaseForgeConfig) -> None:
    """Clear in-memory auth values even when later scan/report/event work fails."""
    for key in (
        "password",
        "token",
        "cookie",
        "jwt_token",
        "browser_auth",
        "browser_snapshot",
    ):
        cfg.extra.pop(key, None)
    for key in ("session_headers", "session_cookies"):
        value = cfg.extra.pop(key, None)
        if isinstance(value, dict):
            wipe_mapping(value)


def _apply_captured_session(cfg: BaseForgeConfig, session_data: dict[str, Any]) -> None:
    """Apply only target-bound credentials from legacy session capture output."""
    from common.outbound_policy import normalize_destination
    from webforge.core.auth_recorder import filter_captured_session_credentials

    try:
        credential_origin = normalize_destination(cfg.target).origin
    except Exception:
        return
    (
        cookies,
        cookie_provenance,
        tokens,
        token_provenance,
    ) = filter_captured_session_credentials(session_data, cfg.target)
    _apply_verified_session_credentials(
        cfg,
        cookies=cookies,
        cookie_provenance=cookie_provenance,
        tokens=tokens,
        token_provenance=token_provenance,
        credential_origin=credential_origin,
    )


def _load_structured_file(path: Path) -> Any:
    """Load JSON or YAML config data."""
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in {".yaml", ".yml"}:
        import yaml
        return yaml.safe_load(text)
    return json.loads(text)


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


async def prepare_api_schema_context(cfg: BaseForgeConfig, args: argparse.Namespace) -> None:
    """Populate cfg.extra with endpoints/forms parsed from API schemas."""
    schema_path = getattr(args, "api_schema", None)
    graphql_url = getattr(args, "graphql_schema_url", None)
    if not schema_path and not graphql_url:
        return

    results = []
    if schema_path:
        from webforge.modules.api.schema_import import SchemaImporter
        path = Path(schema_path)
        if not path.exists():
            log.warning("API schema file not found: %s", schema_path)
        else:
            result = SchemaImporter(base_url=cfg.target.rstrip("/")).import_file(path)
            results.append(result)

    if graphql_url:
        from webforge.modules.api.schema_import import SchemaImportResult
        cfg.extra["schema_outbound_state"] = "outbound_policy_unsupported"
        result = SchemaImportResult(
            format="graphql",
            errors=[
                "remote schema introspection not authorized by a module-bound outbound policy"
            ],
        )
        results.append(result)

    for result in results:
        if result.errors:
            log.warning(
                "API schema import (%s) had errors: %s",
                result.format,
                "; ".join(result.errors),
            )
            continue
        _merge_schema_result(cfg, result)
        log.info(
            "API schema imported: format=%s title=%s endpoints=%d auth_schemes=%d",
            result.format,
            result.title or "untitled",
            len(result.endpoints),
            len(result.auth_schemes),
        )


def prepare_collab_context(cfg: BaseForgeConfig, args: argparse.Namespace) -> None:
    """Record explicitly requested OOB work as unsupported without traffic."""
    collab_domain = getattr(args, "collab_domain", None) or os.environ.get(
        "FORGE_COLLAB_DOMAIN",
        "",
    )
    if not collab_domain:
        return
    cfg.extra["collab_outbound_state"] = "outbound_policy_unsupported"
    log.warning("ForgeCollab OOB not tested: outbound_policy_unsupported")


def _merge_schema_result(cfg: BaseForgeConfig, result: Any) -> None:
    """Merge SchemaImportResult into existing WebForge discovery context."""
    from common.outbound_policy import (
        _explicit_scope_port_matches,
        normalize_destination,
    )
    from common.scope import decide_scope

    effective_allowed = (
        cfg.extra.get("allowed_scope", [])
        or cfg.scope
        or [cfg.target]
    )
    allowed_endpoints = []
    try:
        target_origin = normalize_destination(cfg.target).origin
    except Exception:
        target_origin = ""
    for endpoint in result.endpoints:
        try:
            destination = normalize_destination(str(endpoint.url))
        except Exception:
            continue
        decision = decide_scope(
            destination.host,
            effective_allowed,
            cfg.extra.get("excluded_scope", []),
        )
        origin_allowed = (
            destination.origin == target_origin
            or _explicit_scope_port_matches(
                effective_allowed,
                destination=destination,
            )
        )
        if decision.allowed and origin_allowed:
            allowed_endpoints.append(endpoint)
    allowed_forms = []
    for form in result.forms:
        try:
            destination = normalize_destination(str(form.get("action") or cfg.target))
        except Exception:
            continue
        decision = decide_scope(
            destination.host,
            effective_allowed,
            cfg.extra.get("excluded_scope", []),
        )
        origin_allowed = (
            destination.origin == target_origin
            or _explicit_scope_port_matches(
                effective_allowed,
                destination=destination,
            )
        )
        if decision.allowed and origin_allowed:
            allowed_forms.append(form)
    schema_record = result.to_dict()
    schema_record["endpoint_count"] = len(allowed_endpoints)
    schema_record["endpoints"] = [
        endpoint.to_dict() for endpoint in allowed_endpoints
    ]
    cfg.extra["api_schema"] = schema_record
    cfg.extra["api_endpoints"] = _merge_unique_strings(
        cfg.extra.get("api_endpoints", []),
        [endpoint.url for endpoint in allowed_endpoints],
    )
    cfg.extra["found_forms"] = _merge_unique_forms(
        cfg.extra.get("found_forms", []),
        allowed_forms,
    )
    cfg.extra["api_schema_endpoints"] = [
        ep.to_dict() for ep in allowed_endpoints
    ]
    if result.auth_schemes:
        cfg.extra["api_auth_schemes"] = result.auth_schemes


def _merge_unique_strings(existing: list[str], discovered: list[str]) -> list[str]:
    seen: set[str] = set()
    merged: list[str] = []
    for item in existing + discovered:
        if item and item not in seen:
            seen.add(item)
            merged.append(item)
    return merged


def _selected_phases(
    cfg: BaseForgeConfig,
    args: argparse.Namespace,
) -> list[Any]:
    include = (
        [m.strip() for m in args.modules.split(",") if m.strip()]
        if args.modules
        else cfg.extra.get("profile_modules")
    )
    skip = (
        [m.strip() for m in args.skip_modules.split(",") if m.strip()]
        if args.skip_modules
        else None
    )
    has_session = bool(
        args.username or args.token or args.session or args.sso
        or getattr(args, "auth_state", None) or getattr(args, "login_script", None)
        or cfg.extra.get("password") or cfg.extra.get("token")
        or cfg.extra.get("cookie") or cfg.extra.get("auth_type")
        or cfg.extra.get("session_headers") or cfg.extra.get("session_cookies")
        or cfg.extra.get("browser_storage_state")
    )
    return get_phases(
        args.mode,
        include_modules=include,
        skip_modules=skip,
        has_session=has_session,
    )


def _plan_payload(
    cfg: BaseForgeConfig,
    args: argparse.Namespace,
    results_dir: Path,
    phases: list[Any] | None = None,
) -> dict[str, Any]:
    selected = phases if phases is not None else _selected_phases(cfg, args)
    return {
        "status": "planned",
        "dry_run": bool(args.dry_run),
        "authorized": False,
        "target": safe_target_display(cfg.target),
        "mode": cfg.mode,
        "engagement": _safe_result_component(cfg.engagement, "engagement"),
        "tester": redact_text(str(cfg.tester)),
        "results_dir": str(results_dir),
        "module_count": sum(len(p.modules) for p in selected),
        "phases": [
            {
                "number": p.number,
                "name": p.name,
                "modules": list(p.modules),
            }
            for p in selected
        ],
    }


def _write_plan_result(plan: dict[str, Any], results_dir: Path) -> Path:
    path = results_dir / "dry_run_plan.json"
    protected = redact_value(plan)
    payload = redacted_json_dumps(protected, indent=2, default=str).encode("utf-8")
    return atomic_write_bytes(path, payload, mode=0o600)


def _print_plan(plan: dict[str, Any], plan_path: Path | None = None) -> None:
    console.print(
        f"\n[bold cyan]WebForge v{VERSION}[/bold cyan] — Dry-run plan for "
        f"[cyan]{plan['target']}[/cyan]"
    )
    console.print(
        f"Mode: [yellow]{plan['mode']}[/yellow] | "
        f"Phases: {len(plan['phases'])} | Modules: {plan['module_count']}"
    )
    for phase in plan["phases"]:
        console.print(f"  Phase {phase['number']:2d}: {phase['name']}")
        for module_name in phase["modules"]:
            gate = " [yellow][CONFIRM GATE][/yellow]" if module_name in CONFIRM_GATE_MODULES else ""
            console.print(f"    - {module_name}{gate}")
    console.print("[yellow]Authorized: false — scope matching is not execution approval[/yellow]")
    console.print("[bold yellow]DRY RUN MODE — no modules executed and no network traffic sent[/bold yellow]")
    console.print(f"  Results: {plan['results_dir']}")
    if plan_path:
        console.print(f"  Plan:    {plan_path}")


async def dry_run_plan(
    cfg: BaseForgeConfig,
    args: argparse.Namespace,
    results_dir: Path,
) -> dict[str, Any]:
    phases = _selected_phases(cfg, args)
    plan = _plan_payload(cfg, args, results_dir, phases)
    plan_path = _write_plan_result(plan, results_dir)
    _print_plan(plan, plan_path)
    return {
        "status": "completed",
        "findings": 0,
        "errors": [],
        "duration": 0.0,
        "dry_run": True,
        "authorized": False,
        "results_dir": str(results_dir),
        "plan_path": str(plan_path),
        "plan": plan,
    }


def _validate_scan_source_root(
    cfg: BaseForgeConfig,
    args: argparse.Namespace,
) -> str | None:
    """Validate the effective whitebox source root at the engine boundary.

    ``run_scan`` is also called directly by the dashboard and target manager;
    relying on the CLI wrappers to perform this check leaves a confused-deputy
    path where a whitebox run can create a database or execute modules before
    its source boundary is established.  Resolve the value once here, require
    a canonical non-symlink directory, and carry its identity-bound canonical
    Path into module configuration.  If both the programmatic config and
    argument are present they must identify the same root inode.
    """
    from webforge.core.source_root import SourceRootError, canonical_source_root

    cfg_value = cfg.extra.get("source_root")
    arg_value = getattr(args, "source_root", None)

    def _present(value: object) -> bool:
        return value is not None and not (
            isinstance(value, str) and not str.strip(value)
        )

    # A config value is the value already selected by run_for_target/main.  A
    # direct caller may instead provide the CLI-shaped argument, so accept it
    # only when the config has no effective value.
    selected = cfg_value if _present(cfg_value) else arg_value
    mode_values = {
        str(getattr(cfg, "mode", "") or "").strip().lower(),
        str(getattr(args, "mode", "") or "").strip().lower(),
    }
    if not _present(selected):
        if "whitebox" in mode_values:
            return "source_root is required for whitebox mode"
        return None

    try:
        canonical = canonical_source_root(selected)
    except SourceRootError as exc:
        return str(exc)

    # Do not let a second, untrusted spelling silently override the effective
    # root.  This also rejects a symlink/alias in the argument even when a
    # canonical config value was supplied.
    if _present(arg_value) and cfg_value is not None:
        try:
            argument_canonical = canonical_source_root(arg_value)
        except SourceRootError as exc:
            return str(exc)
        if argument_canonical != canonical:
            return "source_root values do not match"

    # Preserve the approved directory identity, not only its pathname.  The
    # concrete Path subclass remains PathLike for modules while detecting a
    # whole-root rename/replacement between engine approval and module use.
    cfg.extra["source_root"] = canonical
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
    source_root_error = _validate_scan_source_root(cfg, args)
    if source_root_error:
        # Keep this boundary before launch authorization consumption, dry-run
        # planning, database creation, and module loading.  In particular,
        # direct callers must not reach a scan DB with a missing/unsafe root.
        return {
            "status": "failed",
            "findings": 0,
            "errors": [source_root_error],
            "duration": 0.0,
            "dry_run": bool(getattr(args, "dry_run", False)),
            "authorized": False,
        }

    launch_decision = _launch_decision(cfg, args)
    if not launch_decision.allowed:
        _audit_scope_denial(args, launch_decision, target=cfg.target)
        _print_launch_denial(launch_decision)
        return _denied_summary(launch_decision, dry_run=bool(args.dry_run))
    if args.dry_run:
        return await dry_run_plan(cfg, args, results_dir)

    authorization_decision = _consume_engine_authorization(cfg)
    if not authorization_decision.allowed:
        log.warning(
            "Engine authorization denied reason_code=%s",
            authorization_decision.reason_code,
        )
        return _authorization_denied_summary(authorization_decision)
    engine_authorization = authorization_decision.envelope

    bus, Event, EventType = _get_event_bus(event_bus)
    ctrl = scan_control or ScanControl(getattr(args, "control_file", None))
    cfg.extra["outbound_cancellation_check"] = lambda: ctrl.is_aborted
    eng_bus = _get_eng_bus()

    # Database
    db_path = results_dir / "webforge.db"
    db_session = create_db(db_path)

    # Scope
    scope = Scope(
        cfg.extra.get("allowed_scope", getattr(args, "scope", None)),
        excluded=cfg.extra.get("excluded_scope", getattr(args, "exclude", None)),
    )

    # Scan run record
    run_id = engine_authorization.run_id
    run = ScanRunModel(
        id=run_id, tenant_id=engine_authorization.tenant_id,
        framework="webforge", target=cfg.target,
        mode=cfg.mode, engagement=cfg.engagement, tester=cfg.tester,
    )
    db_session.add(run)
    db_session.commit()

    # Determine phases
    phases = _selected_phases(cfg, args)

    total_modules = sum(len(p.modules) for p in phases)
    all_module_names = [m for p in phases for m in p.modules]

    # ── Emit: scan_start ──────────────────────────────────────────────
    _emit(bus, Event, EventType, "scan_start", source="webforge",
          target=safe_target_display(cfg.target), mode=cfg.mode, engagement=cfg.engagement,
          tester=cfg.tester, framework="WebForge", modules=all_module_names)

    console.print(
        f"\n[bold cyan]WebForge v{VERSION}[/bold cyan] — Target: "
        f"[cyan]{safe_target_display(cfg.target)}[/cyan]"
    )
    console.print(f"Mode: [yellow]{args.mode}[/yellow] | Phases: {len(phases)} | Modules: {total_modules}")
    if args.dry_run:
        console.print("[bold yellow]DRY RUN MODE — no requests will be sent[/bold yellow]")

    all_findings: list[Finding] = []
    errors: list[str] = []
    for surface, state_key in (
        ("browser", "browser_outbound_state"),
        ("schema", "schema_outbound_state"),
        ("collab", "collab_outbound_state"),
    ):
        state = cfg.extra.get(state_key)
        if state:
            errors.append(f"{surface}: {state}")
    start_time = time.monotonic()
    modules_completed = 0  # running counter for overall progress
    coverage_completed: set[str] = set()
    aborted = False

    for phase in phases:
        # ── Abort check ───────────────────────────────────────────────
        if ctrl.is_aborted:
            aborted = True
            _emit(bus, Event, EventType, "scan_aborted", source="webforge",
                  reason="operator", target=safe_target_display(cfg.target))
            break

        # ── Pause gate ────────────────────────────────────────────────
        if ctrl.is_paused:
            _emit(bus, Event, EventType, "scan_paused", source="webforge")
            await ctrl.wait_if_paused()
            if ctrl.is_aborted:
                aborted = True
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
                aborted = True
                break
            if ctrl.is_paused:
                _emit(bus, Event, EventType, "scan_paused", source="webforge")
                await ctrl.wait_if_paused()
                if ctrl.is_aborted:
                    aborted = True
                    break
                _emit(bus, Event, EventType, "scan_resumed", source="webforge")

            if module_name in MODULE_MAP:
                from common.outbound_policy import evaluate_module_outbound_support
                support = evaluate_module_outbound_support(
                    engine=ENGINE_NAME,
                    module_id=module_name,
                )
                if not support.supported:
                    errors.append(f"{module_name}: {support.reason_code}")
                    _emit(
                        bus, Event, EventType, "module_skip",
                        source=module_name, name=module_name,
                        reason=support.reason_code, outcome=support.outcome,
                    )
                    modules_completed += 1
                    continue

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

            module_authorization = _authorize_module_execution(
                cfg,
                engine_authorization,
                module_name,
            )
            if not module_authorization.allowed:
                reason = module_authorization.reason_code
                errors.append(f"{module_name}: not authorized ({reason})")
                _emit(
                    bus,
                    Event,
                    EventType,
                    "module_skip",
                    source=module_name,
                    name=module_name,
                    reason=reason,
                )
                modules_completed += 1
                continue

            # ── Emit: module_start + progress ─────────────────────────
            _emit(bus, Event, EventType, "module_start", source=module_name,
                  name=module_name, phase=phase.number)
            # Emit progress at start of module (current position in the scan)
            _emit(bus, Event, EventType, "module_progress", source=module_name,
                  name=module_name,
                  progress=round(modules_completed / total_modules * 100) if total_modules else 0)

            module_config = cfg.model_copy(deep=False)
            module_config.extra = dict(cfg.extra)
            mod_instance = cls(
                config=module_config,
                scope=scope,
                db_session=db_session,
                results_dir=results_dir,
                run_id=run_id,
                event_bus=event_bus,
            )

            try:
                result = await mod_instance.run()
                if ctrl.is_aborted:
                    aborted = True
                    modules_completed += 1
                    _emit(
                        bus,
                        Event,
                        EventType,
                        "module_skip",
                        source=module_name,
                        name=module_name,
                        reason="cancelled",
                        outcome="canceled",
                    )
                    break
                module_policy = getattr(mod_instance, "outbound_policy", None)
                if module_policy is not None and module_policy.last_denial_reason:
                    from common.outbound_policy import OutboundDenied
                    raise OutboundDenied(module_policy.last_denial_reason)
                from common.base_module import (
                    merge_module_output_extra,
                    module_result_error_text,
                )
                result_error = module_result_error_text(result)
                if result_error:
                    raise RuntimeError(result_error)
                if result is not None and getattr(result, "skipped", False):
                    reason = str(
                        redact_authorization_value(
                            str(getattr(result, "skip_reason", "") or "not_tested")
                        )
                    )
                    modules_completed += 1
                    _emit(
                        bus,
                        Event,
                        EventType,
                        "module_skip",
                        source=module_name,
                        name=module_name,
                        reason=reason,
                        outcome="not_tested",
                    )
                    _emit(
                        bus,
                        Event,
                        EventType,
                        "module_progress",
                        source=module_name,
                        name=module_name,
                        progress=(
                            round(modules_completed / total_modules * 100)
                            if total_modules
                            else 0
                        ),
                    )
                    continue
                merge_module_output_extra(cfg.extra, module_config.extra)
                coverage_completed.add(module_name)
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
                if ctrl.is_aborted or getattr(exc, "reason_code", "") == "cancelled":
                    aborted = True
                    modules_completed += 1
                    _emit(
                        bus,
                        Event,
                        EventType,
                        "module_skip",
                        source=module_name,
                        name=module_name,
                        reason="cancelled",
                        outcome="canceled",
                    )
                    break
                safe_error = str(redact_authorization_value(str(exc)))
                log.error("Module %s failed: %s", module_name, safe_error)
                errors.append(f"{module_name}: {safe_error}")
                modules_completed += 1
                _emit(bus, Event, EventType, "module_fail", source=module_name,
                      name=module_name, error=safe_error)
                # Still emit progress even on failure
                _emit(bus, Event, EventType, "module_progress", source=module_name,
                      name=module_name,
                      progress=round(modules_completed / total_modules * 100) if total_modules else 0)

        if aborted:
            break

        # ── Emit: phase_complete ──────────────────────────────────────
        phase_duration = time.monotonic() - phase_start
        _emit(bus, Event, EventType, "phase_complete", source="webforge",
              number=phase.number, name=phase.name, duration=round(phase_duration, 1))

        # ── Session health check (greybox/whitebox only) ──────────────
        if cfg.mode in ("greybox", "whitebox") and getattr(args, "login_url", None):
            if not cfg.extra.get("_session_health_policy_reported"):
                reason = "session_health: outbound_policy_unsupported"
                errors.append(reason)
                cfg.extra["_session_health_policy_reported"] = True
                _emit(
                    bus,
                    Event,
                    EventType,
                    "module_skip",
                    source="session_health",
                    name="session_health",
                    reason="outbound_policy_unsupported",
                    outcome="not_tested",
                )

    elapsed = time.monotonic() - start_time
    status = "aborted" if aborted else ("failed" if errors else "completed")

    # Update run record
    completed_at = datetime.now(timezone.utc)
    run.ended_at = completed_at
    run.status   = status
    db_session.commit()

    if aborted:
        _emit(bus, Event, EventType, "scan_aborted", source="webforge",
              reason="operator", target=safe_target_display(cfg.target), findings=len(all_findings),
              duration=round(elapsed, 1))
    elif errors:
        _emit(bus, Event, EventType, "scan_interrupted", source="webforge",
          target=safe_target_display(cfg.target), findings=len(all_findings), errors=errors,
              duration=round(elapsed, 1))
    else:
        _emit(bus, Event, EventType, "scan_complete", source="webforge",
        target=safe_target_display(cfg.target), findings=len(all_findings), duration=round(elapsed, 1))

    # Task 105 locks its report from canonical persistence in the control
    # plane after review/retest. The engine must not create a transient report
    # from its in-memory finding list for that exact reference slice.
    report_paths: dict[str, str] = {}
    if cfg.extra.get("reference_slice") != "header-audit-csp-v1":
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
    status_label = "SCAN ABORTED" if aborted else ("SCAN FAILED" if errors else "SCAN COMPLETE")
    status_style = "yellow" if aborted else ("red" if errors else "green")
    console.print(f"\n[bold {status_style}]═══ {status_label} ═══[/bold {status_style}]")
    console.print(f"  Duration:  {elapsed:.1f}s")
    console.print(f"  Findings:  {len(all_findings)}")
    if errors:
        console.print(f"  Errors:    {len(errors)}")
    console.print(f"  Results:   {results_dir}")
    for fmt, path in report_paths.items():
        console.print(f"  Report ({fmt}): {path}")

    run_truth: dict[str, Any]
    try:
        from common.run_finalization import (
            RunCompletionManifest,
            RunFinalizationError,
            finalize_authorized_run,
        )

        finalized = finalize_authorized_run(
            db_session,
            authorization=engine_authorization,
            framework="webforge",
            target=cfg.target,
            manifest=RunCompletionManifest(
                planned_capabilities=tuple(all_module_names),
                completed_capabilities=tuple(coverage_completed),
                status=status,
                # SQLite's legacy DateTime column reloads without tzinfo after
                # commit.  Preserve the authoritative aware completion value
                # captured at the lifecycle transition for signed run truth.
                completed_at=completed_at,
                engine_version=VERSION,
            ),
        )
        run_truth = {
            "state": "persisted",
            "run_id": finalized.truth.run_id,
            "collection_status": finalized.truth.collection_status.value,
            "coverage_complete": finalized.truth.coverage_complete,
            "delta_state": finalized.delta.get("comparison_state", "inconclusive"),
        }
    except RunFinalizationError as exc:
        run_truth = {"state": "unavailable", "reason_code": exc.reason_code}
        if cfg.extra.get("reference_slice") == "header-audit-csp-v1":
            log.error(
                "Reference run truth unavailable reason_code=%s",
                exc.reason_code,
            )

    db_session.close()

    return {
        "status": status,
        "findings": len(all_findings),
        "errors": errors,
        "duration": round(elapsed, 1),
        "run_truth": run_truth,
    }


async def run_for_target(
    target_entry: Any,
    base_args: argparse.Namespace,
    event_bus: Any = None,
    scan_control: ScanControl | None = None,
    on_results_ready: Callable[[], None] | None = None,
) -> dict[str, Any]:
    """Entry point for TargetManager multi-target orchestration.

    Args:
        target_entry:  TargetEntry from TargetManager.
        base_args:     Parsed CLI args as template.
        event_bus:     Optional EventBus.
        scan_control:  Optional ScanControl.
        on_results_ready: Optional idempotent callback that enables shared
            TargetManager progress artifacts after authorization succeeds.

    Returns:
        Summary dict.
    """
    import copy
    args = copy.deepcopy(base_args)
    args.target = target_entry.target

    # Per-target files may tune performance only. Authorization, target,
    # confirmation, dry-run, and module-gate state remain immutable.
    for key in ("rate", "workers"):
        if key in target_entry.options and hasattr(args, key):
            setattr(args, key, target_entry.options[key])

    confirmations = list(
        getattr(args, "_launch_confirmations", None) or load_launch_confirmations()
    )
    confirmation = _confirmation_for_target(confirmations, args.target)
    launch_action = getattr(args, "_launch_action", DEFAULT_LAUNCH_ACTION)
    launch_job_id = getattr(args, "_launch_job_id", "")
    preflight = decide_action(
        target=args.target,
        allowed_scope=getattr(args, "scope", None),
        excluded_scope=getattr(args, "exclude", None),
        confirmation=confirmation,
        job_id=launch_job_id,
        engine=ENGINE_NAME,
        action=launch_action,
        require_confirmation=not bool(args.dry_run),
    )
    if not preflight.allowed:
        _audit_scope_denial(args, preflight, target=args.target)
        _print_launch_denial(preflight)
        return _denied_summary(preflight, dry_run=bool(args.dry_run))

    # A dry-run is intentionally non-executing but may persist its plan.  For
    # active work, wait until the derived engine envelope is consumed below;
    # the callback is the TargetManager boundary for shared progress files.
    if args.dry_run and on_results_ready is not None:
        on_results_ready()

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
    if getattr(args, "auth_state", None):
        cfg.extra["browser_storage_state"] = args.auth_state

    source_root_arg = getattr(args, "source_root", None)
    if args.mode == "whitebox" and not source_root_arg:
        return {
            "status": "failed",
            "findings": 0,
            "errors": ["source_root is required for whitebox mode"],
            "duration": 0.0,
        }
    if source_root_arg:
        from webforge.core.source_root import SourceRootError, canonical_source_root

        try:
            cfg.extra["source_root"] = canonical_source_root(source_root_arg)
        except SourceRootError as exc:
            log.error("Whitebox source root rejected: %s", exc)
            return {
                "status": "failed",
                "findings": 0,
                "errors": [str(exc)],
                "duration": 0.0,
            }

    authorizations = list(getattr(args, "_authorization_envelopes", []) or [])
    _apply_launch_context(cfg, args, args.target, confirmations, authorizations)
    if not args.dry_run:
        if _has_direct_secret_args(args):
            return {
                "status": "failed",
                "findings": 0,
                "errors": ["credential_reference_required"],
                "duration": 0.0,
            }
        authorization_decision = _consume_engine_authorization(cfg)
        if not authorization_decision.allowed:
            return _authorization_denied_summary(authorization_decision)
        if on_results_ready is not None:
            on_results_ready()

    results_dir = setup_results_dir(args.target, args.engagement, args.resume, args.output)
    if args.dry_run:
        return await run_scan(cfg, args, results_dir, event_bus, scan_control)
    try:
        with resolved_process_credentials() as credentials:
            _apply_auth_context(cfg, args, credential_values=credentials)
            await prepare_browser_context(cfg, args, results_dir)
            await prepare_api_schema_context(cfg, args)
            prepare_collab_context(cfg, args)
            return await run_scan(cfg, args, results_dir, event_bus, scan_control)
    except ValueError as exc:
        return {
            "status": "failed",
            "findings": 0,
            "errors": [str(redact_authorization_value(exc))],
            "duration": 0.0,
        }
    finally:
        _clear_auth_context(cfg)


def _summary_exit_code(summary: Mapping[str, Any] | None) -> int:
    return 0 if summary and summary.get("status") == "completed" else 1


async def main() -> int:
    args = parse_args()
    reference_slice = str(getattr(args, "reference_slice", "") or "")

    if args.list_modules:
        describe_phases(args.mode)
        return 0

    if args.list_profiles:
        from webforge.core.scan_profile import describe_profiles
        describe_profiles()
        return 0

    if bool(args.target) == bool(args.targets):
        log.error("Use exactly one of --target or --targets.")
        sys.exit(1)
    if args.target:
        args.target = _normalize_target(args.target)
    if reference_slice and (
        args.mode != "blackbox"
        or _requested_modules(args) != ["header_audit"]
        or args.targets
    ):
        log.error(
            "Reference slice rejected: exact blackbox header_audit selection required"
        )
        return 1
    if not args.dry_run and _has_direct_secret_args(args):
        log.error(
            "Direct secret-bearing CLI options are disabled; use a protected credential reference"
        )
        return 1

    if args.targets:
        try:
            targets = _read_targets_file(args.targets)
        except (OSError, ValueError) as exc:
            log.error("Target list rejected (%s)", type(exc).__name__)
            sys.exit(1)

        launch_decision, confirmations = _prepare_cli_confirmations(args, targets)
        if not launch_decision.allowed:
            _audit_scope_denial(
                args,
                launch_decision,
                target=(targets[0] if targets else None),
            )
            _print_launch_denial(launch_decision)
            sys.exit(1)
        args._launch_confirmations = confirmations
        if args.dry_run:
            authorizations: list[ActionAuthorizationEnvelope] = []
        else:
            auth_decision, authorizations = _prepare_engine_authorizations(
                args,
                targets,
                confirmations,
            )
            if not auth_decision.allowed:
                _print_launch_denial(auth_decision)
                sys.exit(1)
        args._authorization_envelopes = authorizations
        set_auto_confirm(args.auto_confirm)

        from common.target_manager import TargetManager
        base_dir = _results_base_dir(args.output)
        manager = TargetManager(
            max_parallel=args.parallel,
            results_dir=base_dir,
            defer_results_setup=True,
            safe_target_persistence=bool(args.dry_run),
        )
        manager.add_targets(targets)
        summary = await manager.run_all(
            lambda entry: run_for_target(
                entry,
                args,
                on_results_ready=manager.enable_progress_persistence,
            )
        )
        failed = any(
            target.get("errors") or target.get("state") != "completed"
            for target in summary.get("targets", [])
        )
        label = "MULTI-TARGET FAILED" if failed else "MULTI-TARGET COMPLETE"
        color = "red" if failed else "green"
        console.print(f"\n[bold {color}]═══ {label} ═══[/bold {color}]")
        console.print(f"  Targets:   {summary['total_targets']}")
        console.print(f"  Findings:  {summary['total_findings']}")
        console.print(f"  Results:   {base_dir}")
        return 1 if failed else 0

    launch_decision, confirmations = _prepare_cli_confirmations(args, [args.target])
    if not launch_decision.allowed:
        _audit_scope_denial(args, launch_decision, target=args.target)
        _print_launch_denial(launch_decision)
        sys.exit(1)
    args._launch_confirmations = confirmations
    if args.dry_run:
        authorizations = []
    else:
        auth_decision, authorizations = _prepare_engine_authorizations(
            args,
            [args.target],
            confirmations,
        )
        if not auth_decision.allowed:
            _print_launch_denial(auth_decision)
            sys.exit(1)
    args._authorization_envelopes = authorizations
    set_auto_confirm(args.auto_confirm)

    if not args.no_screenshot and not args.dry_run:
        print_browser_status()

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
    if reference_slice:
        cfg.extra["reference_slice"] = reference_slice
        raw_reference_timeout = os.environ.get(
            "FORGE_REFERENCE_TIMEOUT_SECONDS",
            "30",
        )
        try:
            reference_timeout = int(raw_reference_timeout)
        except ValueError:
            reference_timeout = 0
        if not 5 <= reference_timeout <= 300:
            log.error("Reference slice timeout binding is invalid")
            return 1
        cfg.extra["reference_parent_import"] = True
        cfg.extra["reference_timeout_seconds"] = reference_timeout
    if args.proxy:
        cfg.proxy  = args.proxy
        cfg.extra["proxy"] = args.proxy
    if args.jwt_token:
        cfg.extra["jwt_token"] = args.jwt_token
    source_root_arg = getattr(args, "source_root", None)
    if args.mode == "whitebox" and not source_root_arg:
        log.error("Whitebox source root rejected: source_root is required")
        return 1
    if source_root_arg:
        from webforge.core.source_root import SourceRootError, canonical_source_root

        try:
            cfg.extra["source_root"] = canonical_source_root(source_root_arg)
        except SourceRootError as exc:
            log.error("Whitebox source root rejected: %s", exc)
            return 1

    _apply_launch_context(cfg, args, args.target, confirmations, authorizations)

    if not args.dry_run:
        authorization_decision = _consume_engine_authorization(cfg)
        if not authorization_decision.allowed:
            console.print(
                "[bold red]Engine authorization denied:[/bold red] "
                f"reason_code={authorization_decision.reason_code}; "
                f"{authorization_decision.reason}"
            )
            sys.exit(1)

    results_dir = setup_results_dir(args.target, args.engagement, args.resume, args.output)
    log.info("Results directory: %s", results_dir)

    if not args.dry_run and not reference_slice:
        ask_internet_permission(
            "Wappalyzer DB updates, nuclei templates",
            force=args.auto_confirm,
        )

    # SSO session capture cannot consume the per-navigation resolved-IP permit.
    if args.sso and not args.dry_run:
        log.error("SSO session capture disabled: outbound_policy_unsupported")
        console.print(
            "[bold red]SSO session capture is not tested under the outbound policy.[/bold red]"
        )
        sys.exit(1)

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
        if _profile.browser_render:
            args.browser_render = True
        log.info(
            "Profile '%s' active (%d modules, rate=%.1f req/s, verify=%s)",
            _profile.name, len(_profile.modules),
            _profile.rate_limit, _profile.verify_findings,
        )

    if args.dry_run:
        return _summary_exit_code(await run_scan(cfg, args, results_dir))

    event_bus = None
    try:
        with resolved_process_credentials() as credentials:
            _apply_auth_context(cfg, args, credential_values=credentials)

            # Load pre-captured session
            if args.session:
                from webforge.core.session_bridge import load_session
                sess_data = load_session(Path(args.session))
                if sess_data:
                    log.info("Loaded pre-captured session from %s", args.session)
                    _apply_captured_session(cfg, sess_data)

            await prepare_browser_context(cfg, args, results_dir)
            await prepare_api_schema_context(cfg, args)
            prepare_collab_context(cfg, args)

            # Wire EventBus — remote when dashboard URL given, local otherwise
            if args.dashboard_url:
                try:
                    from common.dashboard.event_bus import RemoteEventBus
                    event_bus = RemoteEventBus(args.dashboard_url, run_id=str(uuid.uuid4())[:8])
                    if event_bus.start():
                        log.info("Dashboard relay active: %s", args.dashboard_url)
                    else:
                        cfg.extra["dashboard_relay_state"] = event_bus.disabled_reason
                        log.warning(
                            "Dashboard relay not authorized: %s",
                            event_bus.disabled_reason,
                        )
                except Exception as exc:
                    log.warning(
                        "RemoteEventBus init failed (%s); events will not reach dashboard",
                        type(exc).__name__,
                    )
            else:
                try:
                    from common.dashboard.event_bus import EventBus
                    event_bus = EventBus(run_id="webforge")
                    event_bus.start()
                except ImportError:
                    pass

            summary = await run_scan(cfg, args, results_dir, event_bus=event_bus)
            return _summary_exit_code(summary)
    except ValueError as exc:
        log.error(
            "Protected credential handoff rejected (%s)",
            type(exc).__name__,
        )
        return 1
    finally:
        _clear_auth_context(cfg)
        if event_bus and hasattr(event_bus, "stop"):
            event_bus.stop()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
