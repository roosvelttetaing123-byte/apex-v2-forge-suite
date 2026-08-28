"""War Room Dashboard — FastAPI + WebSocket server.

Serves the live dashboard UI and provides real-time event streaming
via WebSocket. Integrates with EventBus and StateStore for live
scan visualization, C2 beacon management, and operator controls.

Launch:
    python forge.py dashboard --port 1337
    python forge.py dashboard --attach results_dir/
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import io
import json
import logging
import math
import os
import re
import secrets
import shlex
import socket
import sqlite3
import signal
import stat
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping, NoReturn, cast
from urllib.parse import quote, urlsplit

from sqlalchemy import text as sql_text

log = logging.getLogger("forge.dashboard.server")

# ── Conditional imports (graceful fallback) ───────────────────────────
try:
    from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
    from fastapi import HTTPException, Depends, Query
    from fastapi.responses import HTMLResponse, JSONResponse, FileResponse, Response
    from fastapi.staticfiles import StaticFiles
    from fastapi.templating import Jinja2Templates
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

from common.dashboard.event_bus import (
    Event,
    EventAdmissionError,
    EventAdmissionReason,
    EventCredentialBinding,
    EventCredentialRegistry,
    EventBus,
    EventType,
    IssuedEventCredential,
)
from common.dashboard.state_store import StateStore
from common.confidence_policy import normalise_finding
from common.canonical import (
    FindingStatus as CanonicalFindingStatus,
    RetestStatus as CanonicalRetestStatus,
)
from common.canonical_evidence import (
    CanonicalEvidenceContext,
    CanonicalEvidenceError,
    CanonicalEvidenceReader,
    CanonicalEvidenceService,
    JOB_ATTEMPT_ID_ENV,
)
from common.evidence import (
    ordinary_evidence_artifacts,
    ordinary_evidence_projection,
    ordinary_finding_projection,
)
from common.evidence_custody import CustodyError
from common.action_authorization import (
    AUTHORIZATION_DB_ENV,
    AUTHORIZATION_ENVELOPES_ENV,
    ActionAuthorizationEnvelope,
    AuthorizationContext,
    AuthorizationReason,
    ConfirmationMethod,
    OperatorRole,
    SafetyMode,
    authorization_runtime_environment,
    authorization_runtime_environment_from_facts,
    consume_authorization,
    derive_authorization,
    encode_authorization_envelopes,
    issue_authorization,
    load_authorization_runtime_facts,
    module_set_binding,
    protected_credential_reference,
    record_boundary_denial,
    record_authorization_denial,
    redact_authorization_value,
)
from common.confirm_gate import (
    ActionConfirmation,
    LAUNCH_ACTION_ENV,
    LAUNCH_CONFIRMATIONS_ENV,
    LAUNCH_JOB_ID_ENV,
    decide_action,
    encode_launch_confirmations,
)
from common.credential_boundary import (
    ProtectedCredentialBundle,
    minimal_child_environment,
    wipe_mapping,
)
from common.artifact_io import (
    ArtifactBoundaryError,
    atomic_write_bytes,
    atomic_write_text_stream,
)
from common.scope import (
    ScopeDecision,
    ScopeReason,
    canonical_target,
    decision_for_reason,
    decide_scope,
    safe_target_display,
)
from common.version import PRODUCT_LABEL, VERSION
from common.dashboard.auth import (
    _get_users,
    generate_token,
    validate_token,
    Role,
    TokenPayload,
    get_sso_config,
)
from common.db import (
    AuditLogModel,
    ScanJobModel,
    audit_log_to_dict,
    create_db,
    get_authorization_decision,
    get_scan_job,
    save_audit_log,
    save_scan_job,
    update_scan_job,
)
from common.retest import RetestService, SessionReferenceResolver
from common.job_state import (
    IdempotencyConflict,
    InvalidTransition,
    JobState,
    JobStateError,
    JobStateService,
    LeaseError,
    LeaseUnavailable,
    ObservationReceipt,
    ProcessIdentity,
    ProcessIdentityError,
    RunTruthReceipt,
    TransitionActor,
    WorkState,
)

# ── Paths ─────────────────────────────────────────────────────────────
_DASHBOARD_DIR = Path(__file__).parent
_APEX_DIR = _DASHBOARD_DIR.parent.parent / "apex-ui"
_APEX_DIST_DIR = _APEX_DIR / "dist"
_WEB_DIR = _DASHBOARD_DIR / "web"
_STATIC_DIR = _APEX_DIST_DIR if _APEX_DIST_DIR.exists() else _APEX_DIR
_TEMPLATE_DIR = _APEX_DIST_DIR if _APEX_DIST_DIR.exists() else _APEX_DIR
_JOB_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
_ARTIFACT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$")
_SCAN_FINGERPRINT_INPUT_INVALID = "scan_fingerprint_input_invalid"
_SCAN_RATE_INPUT_INVALID = "scan_rate_input_invalid"
_AGENT_RESULT_SERVER_FIELDS = frozenset(
    {
        "accepted_lease_digest",
        "agent_id",
        "attempt_id",
        "audit",
        "audit_detail",
        "authorization",
        "authorization_decision_id",
        "authorization_id",
        "capability",
        "completed",
        "completed_at",
        "engine",
        "job_id",
        "lease_deadline_at",
        "lease_digest",
        "lease_expires_at",
        "lease_generation",
        "lease_token",
        "lineage",
        "module_binding",
        "operator",
        "operator_id",
        "operator_role",
        "outcome",
        "run_id",
        "severity",
        "status",
        "target",
        "tenant",
        "tenant_id",
        "verified",
        "verification_state",
        "verification_status",
    }
)
_PRIVATE_KEY_BEGIN_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    re.IGNORECASE,
)
_PRIVATE_KEY_END_RE = re.compile(
    r"-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    re.IGNORECASE,
)

PUBLIC_UI_BOOTSTRAP_ROUTES = frozenset(
    {
        "/",
        "/login",
        "/scan-builder",
        "/red-teaming",
        "/c2-console",
        "/mobile",
        "/discovery",
        "/targets",
        "/scans",
        "/scheduling",
        "/reports",
        "/vulnerabilities",
        "/policies",
        "/notifications",
        "/integrations",
        "/team",
        "/activity",
        "/agents",
        "/credential-analysis",
        "/icons.svg",
        "/favicon.svg",
    }
)
_PUBLIC_UI_SCAN_ROUTE = re.compile(r"^/scans/[^/]+$")
_PUBLIC_UI_ASSET_PREFIXES = ("/assets/", "/static/", "/src/")


def classify_public_ui_route(path: str) -> str | None:
    """Classify the immutable shell/assets that precede API authentication."""
    normalized = str(path)
    shell_path = normalized[:-1] if normalized != "/" and normalized.endswith("/") else normalized
    if shell_path in PUBLIC_UI_BOOTSTRAP_ROUTES or _PUBLIC_UI_SCAN_ROUTE.fullmatch(shell_path):
        return "public_spa_shell"
    if normalized in {"/assets", "/static", "/src"} or normalized.startswith(
        _PUBLIC_UI_ASSET_PREFIXES
    ):
        return "public_static_asset"
    return None

# This is the exhaustive, mechanically checked API boundary.  The key is the
# Starlette route template; the value is (authentication class, minimum role).
# A missing row is denied by middleware rather than silently becoming a viewer
# endpoint.  Service routes perform their credential check before request-body
# parsing in the middleware/endpoint boundary.
DASHBOARD_API_ROUTE_POLICY: dict[tuple[str, str], tuple[str, Role | None]] = {
    # Rate-limited authentication/bootstrap surface.
    ("POST", "/api/v1/auth/login"): ("public_bootstrap", None),
    ("GET", "/api/v1/auth/sso/config"): ("public_bootstrap", None),
    ("GET", "/api/v1/auth/sso/start"): ("public_bootstrap", None),
    ("GET", "/api/v1/auth/sso/callback"): ("public_bootstrap", None),
    ("POST", "/api/v1/auth/sso/exchange"): ("public_bootstrap", None),
    ("GET", "/api/v1/health"): ("public_bootstrap", None),

    # Non-dashboard identities.  Remote event ingress is deliberately disabled
    # in its endpoint until a Task-003 control-plane transport exists.
    ("POST", "/api/v1/events/emit"): ("service_credential", None),
    ("POST", "/api/v1/agents/register"): ("service_credential", None),
    ("GET", "/api/v1/agents/{agent_id}/jobs/next"): ("service_credential", None),
    ("POST", "/api/v1/agents/{agent_id}/jobs/{job_id}/lease/renew"): ("service_credential", None),
    ("POST", "/api/v1/agents/{agent_id}/revoke"): ("service_credential", None),
    ("POST", "/api/v1/agents/{agent_id}/jobs/{job_id}/result"): ("service_credential", None),

    # Authenticated read/control plane.
    ("POST", "/api/v1/auth/sso/discover"): ("dashboard_identity", Role.ADMIN),
    ("GET", "/api/v1/tools"): ("dashboard_identity", Role.OPERATOR),
    ("GET", "/api/v1/supervisor"): ("dashboard_identity", Role.OPERATOR),
    ("GET", "/api/v1/state"): ("dashboard_identity", Role.VIEWER),
    ("GET", "/api/v1/findings"): ("dashboard_identity", Role.VIEWER),
    ("POST", "/api/v1/findings/export"): ("dashboard_identity", Role.VIEWER),
    ("GET", "/api/v1/targets"): ("dashboard_identity", Role.VIEWER),
    ("GET", "/api/v1/metrics"): ("dashboard_identity", Role.VIEWER),
    ("GET", "/api/v1/kill-chain"): ("dashboard_identity", Role.VIEWER),
    ("GET", "/api/v1/credentials"): ("dashboard_identity", Role.OPERATOR),
    ("POST", "/api/v1/credentials/analyze"): ("dashboard_identity", Role.OPERATOR),
    ("GET", "/api/v1/sessions"): ("dashboard_identity", Role.OPERATOR),
    ("GET", "/api/v1/timeline"): ("dashboard_identity", Role.VIEWER),
    ("GET", "/api/v1/audit-logs"): ("dashboard_identity", Role.ADMIN),
    ("GET", "/api/v1/agents"): ("dashboard_identity", Role.VIEWER),
    ("POST", "/api/v1/agents/jobs"): ("dashboard_identity", Role.OPERATOR),
    ("POST", "/api/v1/auth/test"): ("dashboard_identity", Role.OPERATOR),
    ("POST", "/api/v1/action-confirmations"): ("dashboard_identity", Role.OPERATOR),
    ("POST", "/api/v1/control/pause"): ("dashboard_identity", Role.OPERATOR),
    ("POST", "/api/v1/control/resume"): ("dashboard_identity", Role.OPERATOR),
    ("POST", "/api/v1/control/abort"): ("dashboard_identity", Role.ADMIN),
    ("POST", "/api/v1/control/kill-switch"): ("dashboard_identity", Role.ADMIN),
    ("POST", "/api/v1/control/skip-module"): ("dashboard_identity", Role.OPERATOR),
    ("POST", "/api/v1/scans/start"): ("dashboard_identity", Role.OPERATOR),
    ("GET", "/api/v1/scans/status"): ("dashboard_identity", Role.VIEWER),
    ("POST", "/api/v1/scans/stop"): ("dashboard_identity", Role.OPERATOR),
    ("GET", "/api/v1/scans/history"): ("dashboard_identity", Role.VIEWER),
    ("POST", "/api/v1/scans/fingerprints/plan"): ("dashboard_identity", Role.OPERATOR),
    ("POST", "/api/v1/scans/fingerprints/record"): ("dashboard_identity", Role.OPERATOR),
    ("POST", "/api/v1/scans/rate-adapt"): ("dashboard_identity", Role.OPERATOR),
    ("GET", "/api/v1/scans/{scan_id}"): ("dashboard_identity", Role.VIEWER),
    ("GET", "/api/v1/scans/{scan_id}/logs"): ("dashboard_identity", Role.VIEWER),
    ("POST", "/api/v1/scans/{scan_id}/pause"): ("dashboard_identity", Role.OPERATOR),
    ("POST", "/api/v1/scans/{scan_id}/resume"): ("dashboard_identity", Role.OPERATOR),
    ("POST", "/api/v1/scans/{scan_id}/cancel"): ("dashboard_identity", Role.OPERATOR),
    ("POST", "/api/v1/scans/{scan_id}/retry"): ("dashboard_identity", Role.OPERATOR),
    ("DELETE", "/api/v1/scans/{scan_id}"): ("dashboard_identity", Role.OPERATOR),
    ("GET", "/api/v1/scan/templates"): ("dashboard_identity", Role.VIEWER),
    ("POST", "/api/v1/scan/templates"): ("dashboard_identity", Role.OPERATOR),
    ("DELETE", "/api/v1/scan/templates/{template_id}"): ("dashboard_identity", Role.OPERATOR),
    ("PATCH", "/api/v1/findings/{finding_id}/status"): ("dashboard_identity", Role.OPERATOR),
    ("POST", "/api/v1/findings/{finding_id}/retest"): ("dashboard_identity", Role.OPERATOR),
    ("POST", "/api/v1/scans/launch"): ("dashboard_identity", Role.OPERATOR),
    ("GET", "/api/v1/reports/latest"): ("dashboard_identity", Role.VIEWER),
    ("GET", "/api/v1/reports/download"): ("dashboard_identity", Role.VIEWER),
    ("GET", "/api/v1/plugins"): ("dashboard_identity", Role.OPERATOR),
    ("GET", "/api/v1/c2/bofs"): ("dashboard_identity", Role.VIEWER),
    ("POST", "/api/v1/c2/bofs/{name}/execute"): ("dashboard_identity", Role.ADMIN),
    ("GET", "/api/v1/c2/profiles"): ("dashboard_identity", Role.VIEWER),
    ("GET", "/api/v1/c2/profiles/{name}"): ("dashboard_identity", Role.VIEWER),
    ("GET", "/api/v1/c2/emulation/process-injection"): ("dashboard_identity", Role.VIEWER),
    ("POST", "/api/v1/c2/emulation/process-injection/plan"): ("dashboard_identity", Role.VIEWER),
    ("GET", "/api/v1/c2/emulation/p2p"): ("dashboard_identity", Role.VIEWER),
    ("GET", "/api/v1/reports"): ("dashboard_identity", Role.VIEWER),
    ("GET", "/api/v1/findings/verification-queue"): ("dashboard_identity", Role.OPERATOR),
}


def _dashboard_route_pattern(route_template: str) -> re.Pattern[str]:
    parts = route_template.split("/")
    rendered = [
        r"[^/]+" if part.startswith("{") and part.endswith("}") else re.escape(part)
        for part in parts
    ]
    return re.compile("^" + "/".join(rendered) + "$" )


_DASHBOARD_API_ROUTE_PATTERNS = tuple(
    (
        method,
        route_template,
        _dashboard_route_pattern(route_template),
        auth_class,
        minimum_role,
    )
    for (method, route_template), (auth_class, minimum_role) in DASHBOARD_API_ROUTE_POLICY.items()
)

# Routes that can mutate dashboard/control-plane truth or initiate a host/network
# boundary.  The agent lease path is intentionally included even though it uses
# GET today; Task 005 owns changing that legacy protocol.
DASHBOARD_MUTATION_ROUTE_TEMPLATES = frozenset(
    {
        ("POST", "/api/v1/auth/login"),
        ("POST", "/api/v1/auth/sso/exchange"),
        ("POST", "/api/v1/auth/sso/discover"),
        ("POST", "/api/v1/agents/register"),
        ("GET", "/api/v1/agents/{agent_id}/jobs/next"),
        ("POST", "/api/v1/agents/{agent_id}/jobs/{job_id}/lease/renew"),
        ("POST", "/api/v1/agents/{agent_id}/revoke"),
        ("POST", "/api/v1/agents/{agent_id}/jobs/{job_id}/result"),
        ("POST", "/api/v1/credentials/analyze"),
        ("POST", "/api/v1/agents/jobs"),
        ("POST", "/api/v1/auth/test"),
        ("POST", "/api/v1/action-confirmations"),
        ("POST", "/api/v1/control/pause"),
        ("POST", "/api/v1/control/resume"),
        ("POST", "/api/v1/control/abort"),
        ("POST", "/api/v1/control/kill-switch"),
        ("POST", "/api/v1/control/skip-module"),
        ("POST", "/api/v1/scans/start"),
        ("POST", "/api/v1/scans/stop"),
        ("POST", "/api/v1/scans/fingerprints/plan"),
        ("POST", "/api/v1/scans/fingerprints/record"),
        ("POST", "/api/v1/scans/rate-adapt"),
        ("DELETE", "/api/v1/scans/{scan_id}"),
        ("POST", "/api/v1/scan/templates"),
        ("DELETE", "/api/v1/scan/templates/{template_id}"),
        ("PATCH", "/api/v1/findings/{finding_id}/status"),
        ("POST", "/api/v1/findings/{finding_id}/retest"),
        ("POST", "/api/v1/scans/launch"),
        ("POST", "/api/v1/c2/bofs/{name}/execute"),
    }
)
_PUBLIC_RATE_LIMIT = 30
_PUBLIC_RATE_WINDOW_SECONDS = 60.0
_WEBSOCKET_CONNECTION_LIMIT = 64
_CANONICAL_RESULT_DATABASE_NAMES = frozenset(
    {"adforge.db", "aiforge.db", "netforge.db", "webforge.db"}
)


def _normalize_dashboard_host(value: Any) -> str:
    """Normalize one configured or parsed dashboard hostname."""
    return str(value or "").strip().lower().strip("[]").rstrip(".")


def _dashboard_host_is_wildcard(value: str) -> bool:
    """Return true for missing, wildcard-DNS, or unspecified bind hosts."""
    if not value or "*" in value:
        return True
    try:
        return ipaddress.ip_address(value).is_unspecified
    except ValueError:
        return False


def _dashboard_allowed_hosts(bind_host: str) -> frozenset[str]:
    """Build the exact HTTP/WebSocket Host allowlist for one dashboard bind."""
    allowed = {"localhost", "127.0.0.1", "::1", "testserver"}
    candidates = [
        bind_host,
        os.environ.get("FORGE_DASHBOARD_PUBLIC_HOST", ""),
        *os.environ.get("FORGE_DASHBOARD_ALLOWED_HOSTS", "").split(","),
    ]
    for candidate in candidates:
        normalized = _normalize_dashboard_host(candidate)
        if not _dashboard_host_is_wildcard(normalized):
            allowed.add(normalized)
    return frozenset(allowed)


def _dashboard_host_header_allowed(
    host_header: Any,
    allowed_hosts: frozenset[str],
) -> bool:
    """Validate one HTTP-style Host header against exact normalized hosts."""
    raw = str(host_header or "").strip()
    if not raw:
        return False
    try:
        parsed = urlsplit(f"//{raw}")
        # Accessing port rejects malformed/non-numeric ports. Host headers do
        # not carry userinfo, paths, query strings, or fragments.
        _ = parsed.port
        if (
            parsed.username is not None
            or parsed.password is not None
            or parsed.path
            or parsed.query
            or parsed.fragment
        ):
            return False
        host = _normalize_dashboard_host(parsed.hostname)
    except (TypeError, ValueError):
        return False
    return bool(host) and host in allowed_hosts


def _dashboard_header_values(headers: Any, name: str) -> tuple[str, ...]:
    """Return every value for one case-insensitive ASGI header."""
    try:
        getlist = getattr(headers, "getlist", None)
        if callable(getlist):
            return tuple(str(value) for value in getlist(name))
        value = headers.get(name)
    except Exception:
        return ()
    return () if value is None else (str(value),)


def dashboard_api_route_policy(
    method: str,
    path: str,
) -> tuple[str, Role | None, str] | None:
    """Resolve a concrete path or route template to its explicit policy row."""
    normalized_method = str(method).upper()
    normalized_path = str(path)
    direct = DASHBOARD_API_ROUTE_POLICY.get((normalized_method, normalized_path))
    if direct is not None:
        return direct[0], direct[1], normalized_path
    for route_method, template, pattern, auth_class, minimum_role in _DASHBOARD_API_ROUTE_PATTERNS:
        if route_method == normalized_method and pattern.fullmatch(normalized_path):
            return auth_class, minimum_role, template
    return None


def classify_dashboard_api_route(method: str, path: str) -> str:
    """Classify one runtime API route for the mechanically tested auth matrix."""
    normalized_method = str(method).upper()
    normalized_path = str(path)
    if normalized_method == "OPTIONS":
        if any(pattern.fullmatch(normalized_path) for _, _, pattern, _, _ in _DASHBOARD_API_ROUTE_PATTERNS):
            return "cors_preflight"
        return "unclassified"
    policy = dashboard_api_route_policy(normalized_method, normalized_path)
    return policy[0] if policy is not None else "unclassified"

# ── UI module ID → real scanner module mapping ─────────────────────────
# Maps ScanBuilder UI IDs to (framework, scanner_module_name).
# None = module not implemented → rejected with 400.
UI_MODULE_MAP: dict[str, tuple[str, str] | None] = {
    # Web modules
    "sqli":          ("web", "sqli_scanner"),
    "xss":           ("web", "xss_scanner"),
    "lfi":           ("web", "lfi_rfi"),
    "ssrf":          ("web", "ssrf_scanner"),
    "xxe":           ("web", "xxe_scanner"),
    "ssti":          ("web", "ssti_scanner"),
    "rce":           ("web", "cmd_inject"),
    "csrf":          ("web", "cookie_audit"),
    "redirect":      ("web", "open_redirect"),
    "dirtraversal":  ("web", "path_traversal"),
    "subdtakeover":  ("web", "subdomain_takeover"),
    "jwt":           ("web", "jwt_audit"),
    "oauth":         ("web", "oauth_check"),
    "massassign":    ("web", "mass_assignment"),
    "deserial":      ("web", "deserialization"),
    "bof":           None,  # not implemented
    # Network modules
    "portscan":      ("net", "port_scanner"),
    "svcfp":         ("net", "service_id"),
    "ssltls":        ("net", "ssl_audit"),
    "smb":           ("net", "smb_audit"),
    "dns":           ("net", "dns_recon"),
    "snmp":          ("net", "snmp_audit"),
    "netsweep":      ("net", "host_discover"),
    "vulsvc":        ("net", "cve_matcher"),
    # API modules
    "apikey":        ("web", "secret_scan"),
    "graphql":       ("web", "graphql_audit"),
    "bola":          ("web", "idor_scanner"),
    "ratelimit":     ("web", "api_rate_check"),
    "cors":          ("web", "cors_check"),
    "parampollu":    ("web", "parameter_pollution"),
    "apiversion":    None,  # not implemented
    # Auth modules
    "bruteforce":    ("web", "login_brute"),
    "defaultcreds":  ("web", "login_brute"),
    "sessfixation":  ("web", "session_audit"),
    "mfabypass":     ("web", "mfa_bypass"),
    "tokenentropy":  ("web", "session_audit"),
    "pwspray":       ("net", "cred_spray"),
    # Cloud modules — YAML check engine covers active_directory + cloud check packs
    "s3":            None,
    "iam":           None,
    "metadata":      ("net", "yaml_check_engine"),  # AWS/Azure/GCP IMDS checks
    "snapshot":      None,
    "serverless":    None,
    "container":     ("net", "kubernetes_audit"),
    # ── AD / ADCS / Kerberos (v5.3) ──────────────────────────────────
    "adcs":          ("net", "win_adcs_audit"),       # ESC1-ESC8 cert template abuse
    "kerberoast":    ("net", "win_kerberos_audit"),   # Kerberoastable + ASREPRoastable
    "adenum":        ("net", "win_ad_enum"),          # Delegation, LAPS, policy, group audit
    # ── Compliance (v5.3) ────────────────────────────────────────────
    "cisbench":      ("net", "linux_cis_audit"),      # CIS Benchmark Linux (runs win_cis_audit via full scan)
    "wincis":        ("net", "win_cis_audit"),        # CIS Benchmark Windows
    "pcidss":        ("net", "linux_pci_audit"),      # PCI DSS v4.0 Linux
    # ── Windows Application Depth (v5.3) ─────────────────────────────
    "iis":           ("net", "win_iis_audit"),        # IIS deep config audit
    "exchange":      ("net", "win_exchange_audit"),   # Exchange ProxyLogon/Shell/NotShell
    "mssqldeep":     ("net", "win_mssql_deep"),       # SQL Server xp_cmdshell, SA, CLR
    # ── macOS (v5.3) ─────────────────────────────────────────────────
    "macos":         ("net", "macos_patch_audit"),    # SIP, Gatekeeper, FileVault, kexts
    "macosusers":    ("net", "macos_user_audit"),     # Admin accounts, NOPASSWD sudo, setuid
}


def _resolve_modules(ui_ids: list[str]) -> tuple[list[str], list[str], list[str]]:
    """Map UI module IDs → (web_scanner_modules, net_scanner_modules, unsupported_ids)."""
    web: list[str] = []
    net: list[str] = []
    bad: list[str] = []
    seen_web: set[str] = set()
    seen_net: set[str] = set()
    for uid in ui_ids:
        entry = UI_MODULE_MAP.get(uid)
        if entry is None:
            bad.append(uid)
        elif entry[0] == "web":
            if entry[1] not in seen_web:
                web.append(entry[1])
                seen_web.add(entry[1])
        elif entry[0] == "net":
            if entry[1] not in seen_net:
                net.append(entry[1])
                seen_net.add(entry[1])
    return web, net, bad


def _clamp_scanbuilder_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    """Clamp numeric ScanBuilder controls before they reach scanner argv."""
    try:
        if isinstance(value, bool):
            raise ValueError
        parsed = int(float(value))
    except (TypeError, ValueError, OverflowError):
        parsed = default
    return max(minimum, min(maximum, parsed))


def _clamp_scanbuilder_float(value: Any, default: float, minimum: float, maximum: float) -> float:
    """Clamp decimal ScanBuilder controls before they reach scanner argv."""
    try:
        if isinstance(value, bool):
            raise ValueError
        parsed = float(value)
        if not math.isfinite(parsed):
            raise ValueError
    except (TypeError, ValueError, OverflowError):
        parsed = default
    return max(minimum, min(maximum, parsed))


def _format_rate_arg(value: float) -> str:
    """Keep subprocess argv stable and human-readable for whole-number rates."""
    return str(int(value)) if float(value).is_integer() else f"{value:.3f}".rstrip("0").rstrip(".")


class DashboardArtifactError(RuntimeError):
    """Fixed, non-sensitive failure for dashboard-managed local artifacts."""


def _artifact_identifier(value: str) -> str:
    """Validate one identifier before it contributes to an artifact filename."""
    if not isinstance(value, str) or not _ARTIFACT_ID_RE.fullmatch(value):
        raise DashboardArtifactError("dashboard artifact identifier is invalid")
    return value


def _close_artifact_descriptor(descriptor: int) -> None:
    """Close a descriptor without masking an artifact boundary's primary result."""
    try:
        os.close(descriptor)
    except OSError:
        pass


def _artifact_path(path: Path) -> Path:
    """Return a lexical absolute path without resolving attacker-controlled links."""
    candidate = Path(os.path.abspath(os.fspath(path)))
    if candidate.name in {"", ".", ".."}:
        raise DashboardArtifactError("dashboard artifact path is invalid")
    return candidate


def _open_artifact_directory(
    path: Path,
    *,
    create: bool,
    created_paths: list[Path] | None = None,
) -> int:
    """Open a directory chain without following links, privately creating gaps.

    Existing directory modes belong to their caller and are left untouched. Every
    directory created by this boundary is tightened through its owned descriptor so
    the service umask cannot weaken or unexpectedly narrow the declared ``0700``
    contract.
    """
    candidate = Path(os.path.abspath(os.fspath(path)))
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptors: list[int] = []
    created: list[tuple[int, str]] = []
    created_absolute: list[Path] = []
    try:
        root = candidate.anchor or os.sep
        descriptors.append(os.open(root, directory_flags))
        components = candidate.parts[1:] if candidate.is_absolute() else candidate.parts
        current_path = Path(root)
        for component in components:
            current_path = current_path / component
            parent_descriptor = descriptors[-1]
            made_directory = False
            try:
                child_descriptor = os.open(
                    component,
                    directory_flags,
                    dir_fd=parent_descriptor,
                )
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(component, 0o700, dir_fd=parent_descriptor)
                    made_directory = True
                except FileExistsError:
                    # A concurrent creator won the race. It is caller-owned, so
                    # validate it below without changing its mode.
                    made_directory = False
                child_descriptor = os.open(
                    component,
                    directory_flags,
                    dir_fd=parent_descriptor,
                )
            descriptors.append(child_descriptor)
            if made_directory:
                created.append((parent_descriptor, component))
                created_absolute.append(current_path)
                os.fchmod(child_descriptor, 0o700)
        result = descriptors.pop()
        for descriptor in reversed(descriptors):
            _close_artifact_descriptor(descriptor)
        if created_paths is not None:
            created_paths.extend(created_absolute)
        return result
    except FileNotFoundError:
        for parent_descriptor, component in reversed(created):
            try:
                os.rmdir(component, dir_fd=parent_descriptor)
            except OSError:
                pass
        for descriptor in reversed(descriptors):
            _close_artifact_descriptor(descriptor)
        raise
    except BaseException:
        for parent_descriptor, component in reversed(created):
            try:
                os.rmdir(component, dir_fd=parent_descriptor)
            except OSError:
                pass
        for descriptor in reversed(descriptors):
            _close_artifact_descriptor(descriptor)
        raise DashboardArtifactError("dashboard artifact directory is unavailable") from None


def _artifact_directory_descriptor_matches(
    descriptor: int,
    directory: Path,
) -> bool:
    """Return whether a lexical directory still names a pinned descriptor."""
    comparison_descriptor = -1
    try:
        comparison_descriptor = _open_artifact_directory(
            directory,
            create=False,
        )
        pinned = os.fstat(descriptor)
        current = os.fstat(comparison_descriptor)
        return (
            stat.S_ISDIR(pinned.st_mode)
            and stat.S_ISDIR(current.st_mode)
            and pinned.st_dev == current.st_dev
            and pinned.st_ino == current.st_ino
        )
    except (DashboardArtifactError, FileNotFoundError, OSError):
        return False
    finally:
        if comparison_descriptor >= 0:
            _close_artifact_descriptor(comparison_descriptor)


def _artifact_read_snapshot_is_stable(
    initial: os.stat_result,
    final: os.stat_result,
    entry: os.stat_result,
    *,
    require_owner: bool,
) -> bool:
    """Return whether a read inode stayed regular, unaliased, and unchanged."""
    initial_identity = (initial.st_dev, initial.st_ino)
    snapshots = (initial, final, entry)
    if any(
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or (metadata.st_dev, metadata.st_ino) != initial_identity
        or (
            require_owner
            and hasattr(os, "getuid")
            and metadata.st_uid != os.getuid()
        )
        for metadata in snapshots
    ):
        return False
    stable_fields = (
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
        "st_mode",
        "st_uid",
        "st_gid",
    )
    return all(
        getattr(final, field) == getattr(initial, field)
        and getattr(entry, field) == getattr(initial, field)
        for field in stable_fields
    )


def _verify_artifact_read_snapshot(
    candidate: Path,
    parent_descriptor: int,
    descriptor: int,
    initial: os.stat_result,
    *,
    require_owner: bool,
) -> None:
    """Reject bytes unless leaf and ancestor identity stayed stable."""
    try:
        final = os.fstat(descriptor)
        entry = os.stat(
            candidate.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
    except OSError:
        raise DashboardArtifactError("dashboard artifact changed during read") from None
    if not _artifact_read_snapshot_is_stable(
        initial,
        final,
        entry,
        require_owner=require_owner,
    ) or not _artifact_directory_descriptor_matches(
        parent_descriptor,
        candidate.parent,
    ):
        raise DashboardArtifactError("dashboard artifact changed during read")


def _cleanup_created_artifact_directories(paths: list[Path]) -> None:
    """Remove newly owned empty directories without following a replaced parent."""
    for path in reversed(paths):
        candidate = Path(os.path.abspath(os.fspath(path)))
        try:
            parent_descriptor = _open_artifact_directory(candidate.parent, create=False)
        except (FileNotFoundError, DashboardArtifactError):
            continue
        try:
            try:
                os.rmdir(candidate.name, dir_fd=parent_descriptor)
            except OSError:
                pass
        finally:
            _close_artifact_descriptor(parent_descriptor)


def _ensure_private_artifact_directory(path: Path) -> None:
    """Ensure a no-follow directory chain and close its validation descriptor."""
    descriptor = _open_artifact_directory(path, create=True)
    _close_artifact_descriptor(descriptor)


def _configured_dashboard_state_root() -> Path | None:
    """Return the explicit writable dashboard state root, when configured."""
    raw_value = os.environ.get("FORGE_DASHBOARD_STATE_DIR", "").strip()
    if not raw_value:
        return None
    candidate = Path(raw_value)
    if not candidate.is_absolute():
        raise ValueError("FORGE_DASHBOARD_STATE_DIR must be an absolute path")
    return Path(os.path.abspath(os.fspath(candidate)))


def _artifact_lstat(path: Path) -> os.stat_result | None:
    """Return no-follow metadata for one artifact, or ``None`` when absent."""
    candidate = _artifact_path(path)
    try:
        parent_descriptor = _open_artifact_directory(candidate.parent, create=False)
    except FileNotFoundError:
        return None
    try:
        try:
            return os.stat(
                candidate.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return None
        except OSError:
            raise DashboardArtifactError("dashboard artifact metadata is unavailable") from None
    finally:
        _close_artifact_descriptor(parent_descriptor)


def _set_regular_artifact_mode(path: Path, mode: int) -> None:
    """Set a dashboard-owned regular artifact mode through a no-follow fd."""
    candidate = _artifact_path(path)
    try:
        parent_descriptor = _open_artifact_directory(candidate.parent, create=False)
    except FileNotFoundError:
        raise DashboardArtifactError("dashboard artifact is absent") from None
    descriptor = -1
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(candidate.name, flags, dir_fd=parent_descriptor)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise DashboardArtifactError("dashboard artifact is not a single-link regular file")
        if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
            raise DashboardArtifactError("dashboard artifact owner is invalid")
        os.fchmod(descriptor, mode)
    except DashboardArtifactError:
        raise
    except BaseException:
        raise DashboardArtifactError("dashboard artifact mode update failed") from None
    finally:
        if descriptor >= 0:
            _close_artifact_descriptor(descriptor)
        _close_artifact_descriptor(parent_descriptor)


def _read_artifact_bytes(
    path: Path,
    *,
    max_bytes: int = 16 * 1024 * 1024,
    required_mode: int | None = None,
) -> bytes:
    """Read one bounded regular artifact through a no-follow descriptor."""
    candidate = _artifact_path(path)
    try:
        parent_descriptor = _open_artifact_directory(candidate.parent, create=False)
    except FileNotFoundError:
        raise
    descriptor = -1
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        try:
            descriptor = os.open(candidate.name, flags, dir_fd=parent_descriptor)
        except FileNotFoundError:
            raise
        except OSError:
            raise DashboardArtifactError("dashboard artifact is unavailable") from None
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size > max_bytes
        ):
            raise DashboardArtifactError("dashboard artifact is not a bounded regular file")
        if required_mode is not None:
            if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
                raise DashboardArtifactError("dashboard artifact owner is invalid")
            if stat.S_IMODE(metadata.st_mode) != required_mode:
                raise DashboardArtifactError("dashboard artifact mode is invalid")
        read_metadata = metadata
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > max_bytes:
            raise DashboardArtifactError("dashboard artifact exceeds its size limit")
        _verify_artifact_read_snapshot(
            candidate,
            parent_descriptor,
            descriptor,
            read_metadata,
            require_owner=required_mode is not None,
        )
        return payload
    except (FileNotFoundError, DashboardArtifactError):
        raise
    except BaseException:
        raise DashboardArtifactError("dashboard artifact read failed") from None
    finally:
        if descriptor >= 0:
            _close_artifact_descriptor(descriptor)
        _close_artifact_descriptor(parent_descriptor)


def _read_artifact_text(
    path: Path,
    *,
    max_bytes: int = 16 * 1024 * 1024,
    required_mode: int | None = None,
) -> str:
    """Read bounded UTF-8 text without exposing decoder or filesystem details."""
    try:
        return _read_artifact_bytes(
            path,
            max_bytes=max_bytes,
            required_mode=required_mode,
        ).decode("utf-8")
    except (FileNotFoundError, DashboardArtifactError):
        raise
    except UnicodeError:
        raise DashboardArtifactError("dashboard artifact is not valid UTF-8") from None


def _read_artifact_tail(path: Path, *, max_bytes: int = 1024 * 1024) -> str:
    """Read only the tail of one regular UTF-8-ish artifact."""
    candidate = _artifact_path(path)
    try:
        parent_descriptor = _open_artifact_directory(candidate.parent, create=False)
    except FileNotFoundError:
        raise
    descriptor = -1
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(candidate.name, flags, dir_fd=parent_descriptor)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise DashboardArtifactError("dashboard artifact is not a single-link regular file")
        if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
            raise DashboardArtifactError("dashboard artifact owner is invalid")
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            raise DashboardArtifactError("dashboard artifact mode is invalid")
        read_metadata = metadata
        start = max(0, metadata.st_size - max_bytes)
        os.lseek(descriptor, start, os.SEEK_SET)
        chunks: list[bytes] = []
        remaining = max_bytes
        while remaining:
            chunk = os.read(descriptor, min(remaining, 256 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        _verify_artifact_read_snapshot(
            candidate,
            parent_descriptor,
            descriptor,
            read_metadata,
            require_owner=True,
        )
        return payload.decode("utf-8", errors="replace")
    except FileNotFoundError:
        raise
    except DashboardArtifactError:
        raise
    except BaseException:
        raise DashboardArtifactError("dashboard artifact tail read failed") from None
    finally:
        if descriptor >= 0:
            _close_artifact_descriptor(descriptor)
        _close_artifact_descriptor(parent_descriptor)


def _atomic_write_artifact(
    path: Path,
    payload: bytes,
    *,
    mode: int = 0o600,
    created_directories: list[Path] | None = None,
) -> None:
    """Atomically replace one artifact through the shared commit boundary."""
    candidate = _artifact_path(path)
    locally_created: list[Path] = []
    parent_descriptor = -1
    committed = False
    try:
        parent_descriptor = _open_artifact_directory(
            candidate.parent,
            create=True,
            created_paths=locally_created,
        )
        _close_artifact_descriptor(parent_descriptor)
        parent_descriptor = -1
        atomic_write_bytes(candidate, payload, mode=mode)
        committed = True
        if created_directories is not None:
            created_directories.extend(locally_created)
    except (ArtifactBoundaryError, DashboardArtifactError):
        raise DashboardArtifactError("dashboard artifact write failed") from None
    except BaseException:
        raise DashboardArtifactError("dashboard artifact write failed") from None
    finally:
        if parent_descriptor >= 0:
            _close_artifact_descriptor(parent_descriptor)
        if not committed:
            _cleanup_created_artifact_directories(locally_created)


def _atomic_write_text_stream(path: Path, writer: Any, *, mode: int = 0o600) -> Any:
    """Commit callback-produced text through the shared commit boundary."""
    candidate = _artifact_path(path)
    locally_created: list[Path] = []
    parent_descriptor = -1
    committed = False
    try:
        parent_descriptor = _open_artifact_directory(
            candidate.parent,
            create=True,
            created_paths=locally_created,
        )
        _close_artifact_descriptor(parent_descriptor)
        parent_descriptor = -1
        result = atomic_write_text_stream(candidate, writer, mode=mode)
        committed = True
        return result
    except (ArtifactBoundaryError, DashboardArtifactError):
        raise DashboardArtifactError("dashboard artifact stream write failed") from None
    except BaseException:
        raise DashboardArtifactError("dashboard artifact stream write failed") from None
    finally:
        if parent_descriptor >= 0:
            _close_artifact_descriptor(parent_descriptor)
        if not committed:
            _cleanup_created_artifact_directories(locally_created)


def _unlink_artifact(path: Path) -> bool:
    """Unlink one directory entry without following it."""
    candidate = _artifact_path(path)
    try:
        parent_descriptor = _open_artifact_directory(candidate.parent, create=False)
    except FileNotFoundError:
        return False
    try:
        try:
            os.unlink(candidate.name, dir_fd=parent_descriptor)
            return True
        except FileNotFoundError:
            return False
        except OSError:
            raise DashboardArtifactError("dashboard artifact removal failed") from None
    finally:
        _close_artifact_descriptor(parent_descriptor)


def _unlink_matching_artifacts(
    directory: Path,
    *,
    prefix: str,
    suffix: str,
) -> list[Path]:
    """Unlink matching entries through one no-follow directory descriptor."""
    if not prefix or "/" in prefix or "\x00" in prefix:
        raise DashboardArtifactError("dashboard artifact prefix is invalid")
    descriptor = _open_artifact_directory(directory, create=False)
    removed: list[Path] = []
    try:
        try:
            entries = os.scandir(descriptor)
        except OSError:
            raise DashboardArtifactError("dashboard artifact directory scan failed") from None
        with entries:
            for entry in entries:
                name = entry.name
                if not name.startswith(prefix) or not name.endswith(suffix):
                    continue
                try:
                    os.unlink(name, dir_fd=descriptor)
                    removed.append(directory / name)
                except FileNotFoundError:
                    continue
                except OSError:
                    raise DashboardArtifactError("dashboard artifact removal failed") from None
        return removed
    finally:
        _close_artifact_descriptor(descriptor)


class _DashboardProcessSupervisor:
    """Linux supervisor that signals only a pidfd-pinned full identity."""

    @staticmethod
    def _boot_id() -> str:
        try:
            return Path("/proc/sys/kernel/random/boot_id").read_text(
                encoding="utf-8"
            ).strip()
        except OSError:
            return ""

    @staticmethod
    def _start_token(pid: int) -> str:
        try:
            stat_line = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
            fields = stat_line.rsplit(")", 1)[1].split()
            return str(fields[19])
        except (IndexError, OSError, ValueError):
            return ""

    @staticmethod
    def _command_digest(pid: int) -> str:
        try:
            command = Path(f"/proc/{pid}/cmdline").read_bytes().rstrip(b"\x00")
        except OSError:
            return ""
        return hashlib.sha256(command).hexdigest() if command else ""

    @staticmethod
    def _launch_nonce_matches(pid: int, launch_nonce: str) -> bool:
        if not launch_nonce or "\x00" in launch_nonce:
            return False
        marker = (
            f"{JOB_ATTEMPT_ID_ENV}_LAUNCH_NONCE={launch_nonce}"
        ).encode()
        try:
            return marker in Path(f"/proc/{pid}/environ").read_bytes().split(
                b"\x00"
            )
        except OSError:
            return False

    @classmethod
    def _identity(cls, pid: int, launch_nonce: str) -> ProcessIdentity | None:
        start_token = cls._start_token(pid)
        boot_id = cls._boot_id()
        command_digest = cls._command_digest(pid)
        if (
            not start_token
            or not boot_id
            or not command_digest
            or not launch_nonce
            or not cls._launch_nonce_matches(pid, launch_nonce)
        ):
            return None
        try:
            return ProcessIdentity(
                pid=pid,
                start_token=start_token,
                command_digest=command_digest,
                boot_id=boot_id,
                launch_nonce=launch_nonce,
            )
        except ProcessIdentityError:
            return None

    @classmethod
    def capture(
        cls,
        proc: subprocess.Popen[str],
        *,
        launch_nonce: str,
    ) -> ProcessIdentity | None:
        pid = getattr(proc, "pid", None)
        if type(pid) is not int or pid <= 0:
            return None
        return cls._identity(pid, launch_nonce)

    @classmethod
    def discover(cls, launch_nonce: str) -> ProcessIdentity | None:
        """Recover an own-UID child that carries the exact launch nonce."""

        if not launch_nonce or "\x00" in launch_nonce:
            return None
        marker = f"{JOB_ATTEMPT_ID_ENV}_LAUNCH_NONCE={launch_nonce}".encode()
        try:
            entries = sorted(Path("/proc").iterdir(), key=lambda item: item.name)
        except OSError:
            return None
        for entry in entries:
            if not entry.name.isdigit():
                continue
            try:
                if hasattr(os, "getuid") and entry.stat().st_uid != os.getuid():
                    continue
                environ = (entry / "environ").read_bytes().split(b"\x00")
            except OSError:
                continue
            if marker not in environ:
                continue
            identity = cls._identity(int(entry.name), launch_nonce)
            if identity is not None:
                return identity
        return None

    @classmethod
    def _matches(cls, identity: ProcessIdentity) -> bool:
        return bool(
            identity.boot_id
            and hmac.compare_digest(cls._boot_id(), identity.boot_id)
            and hmac.compare_digest(
                cls._start_token(identity.pid),
                identity.start_token,
            )
            and hmac.compare_digest(
                cls._command_digest(identity.pid),
                identity.command_digest,
            )
            and cls._launch_nonce_matches(
                identity.pid,
                identity.launch_nonce,
            )
        )

    def is_alive(self, identity: ProcessIdentity) -> bool:
        return self._matches(identity)

    def _signal(self, identity: ProcessIdentity, sig: int) -> None:
        if not self._matches(identity):
            raise ProcessIdentityError("process identity no longer matches")
        pidfd_open = getattr(os, "pidfd_open", None)
        pidfd_signal = getattr(signal, "pidfd_send_signal", None)
        if not callable(pidfd_open) or not callable(pidfd_signal):
            raise ProcessIdentityError("pidfd signaling is unavailable")
        descriptor = pidfd_open(identity.pid)
        try:
            if not self._matches(identity):
                raise ProcessIdentityError("process identity changed before signal")
            pidfd_signal(descriptor, sig)
        finally:
            os.close(descriptor)

    def terminate(self, identity: ProcessIdentity) -> None:
        self._signal(identity, signal.SIGTERM)

    def kill(self, identity: ProcessIdentity) -> None:
        self._signal(identity, signal.SIGKILL)

    def pause(self, identity: ProcessIdentity) -> None:
        self._signal(identity, signal.SIGSTOP)

    def resume(self, identity: ProcessIdentity) -> None:
        self._signal(identity, signal.SIGCONT)


class DashboardServer:
    """War Room dashboard server.

    Manages the FastAPI application, WebSocket connections, and
    integration with the scan engine via EventBus + StateStore.

    Args:
        event_bus:   EventBus instance for receiving scan events.
        state_store: StateStore instance for state snapshots.
        host:        Bind address (default 127.0.0.1).
        port:        Bind port (default 1337).
        auth:        Enable authentication (default True).
    """

    def __init__(
        self,
        event_bus: EventBus | None = None,
        state_store: StateStore | None = None,
        host: str = "127.0.0.1",
        port: int = 1337,
        auth: bool = True,
        retest_session_resolver: SessionReferenceResolver | None = None,
    ) -> None:
        self.tenant_id = os.environ.get("FORGE_TENANT_ID", "default").strip() or "default"
        self.event_bus = event_bus or EventBus(run_id="dashboard")
        self.state_store = state_store or StateStore(
            self.event_bus,
            framework="forge",
            target="",
            tenant_id=self.tenant_id,
        )
        state_tenant = str(getattr(self.state_store, "tenant_id", "") or "")
        if state_tenant != self.tenant_id:
            raise ValueError("dashboard state tenant does not match server tenant")
        self.host = host
        self.port = port
        # The legacy no-auth switch no longer bypasses API or WebSocket
        # identity checks. Keep the argument for call-site compatibility while
        # reporting the effective, fail-closed state truthfully.
        self.auth_enabled = True
        self._retest_session_resolver = retest_session_resolver
        self.auth_disable_requested = not bool(auth)
        if self.auth_disable_requested:
            log.warning("Dashboard no-auth mode is disabled; authentication remains required")
        self._ws_clients: dict[WebSocket, TokenPayload] = {}
        self._ws_capacity_lock = threading.Lock()
        self._ws_reservations: set[WebSocket] = set()
        self._app: Any = None
        self._event_credentials = EventCredentialRegistry(
            authorization_resolver=self._resolve_event_authorization,
            job_state_resolver=self._resolve_event_job_state,
        )
        self._public_rate_lock = threading.Lock()
        self._public_rate_events: dict[tuple[str, str], list[float]] = {}
        self._artifact_state_lock = threading.RLock()
        # Active scan subprocess tracking
        # This is a rebuildable process-handle cache only.  SQLite owns job,
        # attempt, lease, and full process identity.
        self._active_scans: dict[str, dict[str, Any]] = {}
        self._job_state_service: JobStateService | None = None
        self._job_state_service_path: str | None = None
        self._job_process_supervisor = _DashboardProcessSupervisor()
        forge_root = Path(__file__).parent.parent.parent
        self._dashboard_state_root = _configured_dashboard_state_root()
        transient_root = self._dashboard_state_root or forge_root / "tmp"
        self._scan_logs_dir = transient_root / "dashboard_scans"
        self._control_dir = transient_root / "dashboard_controls"
        self._scan_results_dir = transient_root / "dashboard_results"
        _ensure_private_artifact_directory(self._scan_logs_dir)
        _ensure_private_artifact_directory(self._control_dir)
        _ensure_private_artifact_directory(self._scan_results_dir)

        # Subscribe to all events for WebSocket broadcast
        self.event_bus.subscribe(None, self._on_event)

    def _durable_job_state(self) -> JobStateService:
        """Return startup-initialized authority without request-time recovery."""

        path = str(self._scan_jobs_db_path)
        if (
            self._job_state_service is not None
            and self._job_state_service_path == path
            and not getattr(self._job_state_service, "_closed", False)
        ):
            return self._job_state_service
        if self._app is not None:
            raise JobStateError(
                "durable job authority changed or closed after application startup"
            )
        return self._initialize_durable_job_state()

    def _initialize_durable_job_state(self) -> JobStateService:
        """Open and reconcile authority only at an explicit server boundary."""

        path = str(self._scan_jobs_db_path)
        if (
            self._job_state_service is None
            or self._job_state_service_path != path
            or getattr(self._job_state_service, "_closed", False)
        ):
            if self._job_state_service is not None:
                self._job_state_service.close()
            service = JobStateService(
                path,
                clock=lambda: self._agent_now().timestamp(),
                process_supervisor=self._job_process_supervisor,
            )
            self._job_state_service = service
            self._job_state_service_path = path
            self._import_legacy_agent_cache(service)
            service.reconcile(
                tenant_id=self.tenant_id,
                actor=TransitionActor(
                    tenant_id=self.tenant_id,
                    actor_id="dashboard-restart",
                    role="system",
                ),
            )
            for job in service.list_jobs(
                tenant_id=self.tenant_id,
                limit=10_000,
            ):
                job_id = str(job["id"])
                if str(job.get("state") or "") == JobState.ORPHANED.value and any(
                    str(process.get("state") or "")
                    not in {"stopped"}
                    for process in service.list_processes(
                        job_id,
                        tenant_id=self.tenant_id,
                    )
                ):
                    service.cancel_job(
                        job_id,
                        tenant_id=self.tenant_id,
                        actor=TransitionActor(
                            tenant_id=self.tenant_id,
                            actor_id="dashboard-restart",
                            role="system",
                        ),
                        reason="stale child canceled after restart",
                        supervisor=self._job_process_supervisor,
                        sla_seconds=5.0,
                    )
                    job = service.get_job(
                        job_id,
                        tenant_id=self.tenant_id,
                    ) or job
                control_path = self._durable_control_file_path(job)
                if control_path is None:
                    continue
                state = str(job.get("state") or "")
                self._write_control_file(
                    control_path,
                    paused=state == JobState.PAUSED.value,
                    aborted=state
                    in {
                        JobState.CANCELING.value,
                        JobState.CANCELED.value,
                        JobState.PARTIAL.value,
                        JobState.FAILED.value,
                        JobState.EXPIRED.value,
                        JobState.ORPHANED.value,
                    },
                )
                if state == JobState.PAUSED.value:
                    try:
                        self._signal_scan_processes(job_id, "pause")
                    except DashboardArtifactError:
                        service.cancel_job(
                            job_id,
                            tenant_id=self.tenant_id,
                            actor=TransitionActor(
                                tenant_id=self.tenant_id,
                                actor_id="dashboard-restart",
                                role="system",
                            ),
                            reason="restart pause could not be enforced",
                            supervisor=self._job_process_supervisor,
                            sla_seconds=5.0,
                        )
                        self._write_control_file(
                            control_path,
                            paused=False,
                            aborted=True,
                        )
        return self._job_state_service

    def _import_legacy_agent_cache(self, service: JobStateService) -> None:
        """Conservatively import JSON once; never execute a JSON-only job."""

        path = self._agents_path
        try:
            metadata = _artifact_lstat(path)
            if metadata is None:
                return
            raw = _read_artifact_bytes(path, required_mode=0o600)
            source_identity = "sha256:" + hashlib.sha256(raw).hexdigest()
            if service.cache_imported(
                "scan_agents_json",
                source_identity,
                tenant_id=self.tenant_id,
            ):
                return
            data = json.loads(raw.decode("utf-8"))
            if not isinstance(data, dict):
                raise ValueError("legacy agent cache root is invalid")
            agents = data.get("agents")
            jobs = data.get("jobs")
            if not isinstance(agents, dict) or not isinstance(jobs, list):
                raise ValueError("legacy agent cache schema is invalid")
            imported_agents = 0
            imported_jobs = 0
            for raw_agent_id, raw_agent in agents.items():
                if not isinstance(raw_agent_id, str) or not isinstance(raw_agent, dict):
                    continue
                if str(raw_agent.get("tenant_id") or "default") != self.tenant_id:
                    continue
                digest = str(raw_agent.get("credential_digest") or "")
                key_id = str(raw_agent.get("key_id") or "")
                scope = self._scope_entries(raw_agent.get("scope"))
                engines = self._string_list(raw_agent.get("engines"))
                capabilities = self._string_list(raw_agent.get("capabilities"))
                if not digest or not key_id or not scope or not engines or not capabilities:
                    continue
                if service.get_agent(raw_agent_id, tenant_id=self.tenant_id) is not None:
                    continue
                service.register_agent(
                    raw_agent_id,
                    tenant_id=self.tenant_id,
                    key_id=key_id,
                    credential_digest=digest,
                    enrollment_hint_digest=(
                        str(raw_agent.get("enrollment_hint_digest") or "") or None
                    ),
                    mtls_subject_digest=(
                        str(raw_agent.get("mtls_subject_digest") or "") or None
                    ),
                    display_name=str(raw_agent.get("name") or raw_agent_id),
                    host_label=str(raw_agent.get("host") or ""),
                    platform_label=str(raw_agent.get("platform") or ""),
                    version_label=str(raw_agent.get("version") or "legacy"),
                    engines=engines,
                    capabilities=capabilities,
                    scope=scope,
                    excluded_scope=self._scope_entries(
                        raw_agent.get("excluded_scope")
                    ),
                    active_scan_enabled=bool(
                        raw_agent.get("active_scan_enabled", False)
                    ),
                )
                if raw_agent.get("revoked"):
                    service.revoke_agent(
                        raw_agent_id,
                        tenant_id=self.tenant_id,
                    )
                imported_agents += 1
            for raw_job in jobs:
                if not isinstance(raw_job, dict):
                    continue
                if str(raw_job.get("tenant_id") or "default") != self.tenant_id:
                    continue
                agent_id = str(raw_job.get("agent_id") or "")
                if service.get_agent(agent_id, tenant_id=self.tenant_id) is None:
                    continue
                raw_id = str(raw_job.get("id") or "")
                job_id = (
                    raw_id
                    if _JOB_ID_RE.fullmatch(raw_id)
                    else "legacy-job-"
                    + hashlib.sha256(
                        json.dumps(raw_job, sort_keys=True, default=str).encode()
                    ).hexdigest()[:40]
                )
                if service.get_job(job_id, tenant_id=self.tenant_id) is not None:
                    continue
                modules = self._string_list(raw_job.get("modules"))
                created = service.create_job(
                    self._sanitize_agent_result(raw_job),
                    tenant_id=self.tenant_id,
                    job_id=job_id,
                    job_kind=str(raw_job.get("engine") or "legacy_agent_job"),
                    target=str(raw_job.get("target") or "legacy"),
                    assigned_agent_id=agent_id,
                    idempotency_key=f"legacy-agent-job:{job_id}",
                    state=JobState.PLANNED,
                    work_items=modules or ("agent-result",),
                    actor="legacy-cache-import",
                    reason="legacy JSON agent job imported without execution authority",
                )
                service.cancel_job(
                    str(created["id"]),
                    tenant_id=self.tenant_id,
                    actor=TransitionActor(
                        tenant_id=self.tenant_id,
                        actor_id="legacy-cache-import",
                        role="system",
                    ),
                    reason="legacy JSON lease/result authority was not promoted",
                    sla_seconds=0,
                )
                imported_jobs += 1
            service.record_cache_import(
                "scan_agents_json",
                source_identity,
                tenant_id=self.tenant_id,
                result="imported",
                detail={
                    "agents": imported_agents,
                    "jobs": imported_jobs,
                    "jobs_executable": 0,
                },
            )
        except Exception as exc:
            log.warning(
                "Legacy agent cache was not promoted reason=%s",
                type(exc).__name__,
            )

    def _request_credential_bundle(
        self,
        request: Any,
        credential_values: dict[str, str],
        *,
        ttl_seconds: int = 60,
    ) -> ProtectedCredentialBundle:
        """Create and immediately bind a bundle to request-scoped cleanup."""
        bundle = ProtectedCredentialBundle(
            credential_values,
            ttl_seconds=ttl_seconds,
        )
        try:
            bundles = getattr(request.state, "protected_credential_bundles", None)
            if bundles is None:
                bundles = []
                request.state.protected_credential_bundles = bundles
            bundles.append(bundle)
        except BaseException:
            bundle.wipe()
            raise
        return bundle

    @staticmethod
    def _wipe_request_credential_bundles(request: Any) -> None:
        """Wipe every request-owned bundle without masking the primary result."""
        bundles = getattr(request.state, "protected_credential_bundles", None)
        if not isinstance(bundles, list):
            return
        while bundles:
            bundle = bundles.pop()
            try:
                bundle.wipe()
            except BaseException as exc:
                log.debug(
                    "Credential bundle cleanup failed reason=%s",
                    type(exc).__name__,
                )

    def _track_scan_process(self, scan_key: str, info: dict[str, Any]) -> None:
        """Capture subprocess output and emit completion/failure events."""
        scan_key = _artifact_identifier(scan_key)
        proc: subprocess.Popen[str] = info["proc"]
        log_path = self._scan_logs_dir / f"{scan_key}.log"

        def _worker() -> None:
            try:
                def _capture_output(fh: Any) -> int:
                    if isinstance(proc.stdout, io.TextIOBase):
                        private_key_open = False
                        for line in proc.stdout:
                            if private_key_open:
                                if _PRIVATE_KEY_END_RE.search(line):
                                    private_key_open = False
                                continue
                            if _PRIVATE_KEY_BEGIN_RE.search(line):
                                fh.write("<redacted>\n")
                                private_key_open = not bool(
                                    _PRIVATE_KEY_END_RE.search(line)
                                )
                                continue
                            fh.write(str(redact_authorization_value(line)))
                    return proc.wait()

                rc = int(_atomic_write_text_stream(log_path, _capture_output))
            except Exception as exc:
                log.warning(
                    "Scan monitor failed for %s reason=%s",
                    str(redact_authorization_value(scan_key))[:100],
                    type(exc).__name__,
                )
                try:
                    # Log capture is a presentation side effect, not lifecycle
                    # authority. Drain the pipe so a verbose child cannot
                    # deadlock on a full buffer, then reap the exact process
                    # and continue durable exit/finalization.
                    if isinstance(proc.stdout, io.TextIOBase):
                        for _line in proc.stdout:
                            pass
                    rc = int(proc.wait())
                except Exception:
                    return

            info["returncode"] = rc
            durable_attempt_id = str(info.get("durable_attempt_id") or "")
            durable_identity = info.get("durable_process_identity")
            root_scan_id = self._base_scan_id(scan_key)
            if durable_attempt_id and isinstance(durable_identity, Mapping):
                try:
                    self._durable_job_state().record_process_exit(
                        root_scan_id,
                        durable_attempt_id,
                        ProcessIdentity.from_value(durable_identity),
                        worker_id=str(
                            info.get("durable_worker_id") or "dashboard"
                        ),
                        control_boot_id=str(
                            info.get("durable_control_boot_id") or ""
                        ),
                        tenant_id=self.tenant_id,
                        identity_key=scan_key,
                        return_code=rc,
                        reason="dashboard child process exited",
                        actor="dashboard-monitor",
                    )
                    self._finalize_durable_scan_after_exit(root_scan_id)
                except (
                    IdempotencyConflict,
                    InvalidTransition,
                    LeaseError,
                    ProcessIdentityError,
                    KeyError,
                ) as exc:
                    log.warning(
                        "Durable child-exit reconciliation failed reason=%s",
                        type(exc).__name__,
                    )
            durable_job = (
                self._durable_job_state().get_job(
                    root_scan_id,
                    tenant_id=self.tenant_id,
                )
                if durable_attempt_id
                else None
            )
            info["status"] = (
                str(durable_job["state"])
                if durable_job is not None
                else "orphaned"
            )
            event_type = (
                EventType.SCAN_COMPLETE
                if info["status"] == JobState.COMPLETED.value
                else EventType.SCAN_ABORTED
                if info["status"] == JobState.CANCELED.value
                else EventType.SCAN_INTERRUPTED
            )
            self.event_bus.emit_simple(
                event_type,
                source="dashboard",
                scan_id=scan_key,
                scan_type=info.get("type", ""),
                target=safe_target_display(str(info.get("target", ""))),
                returncode=rc,
                log_path=str(log_path),
            )
            self._update_scan_history_status(root_scan_id, info["status"])
            self._sync_scan_job_from_active(root_scan_id, fallback=info["status"])
        threading.Thread(
            target=_worker,
            name=f"ScanMonitor-{scan_key}",
            daemon=True,
        ).start()

    def _on_event(self, event: Event) -> None:
        """Broadcast event to all connected WebSocket clients."""
        # This runs on the EventBus dispatch thread.
        # We need to schedule async sends on the event loop.
        pass  # Handled via async_subscribe in start()

    def issue_event_credential(
        self,
        *,
        authorization: ActionAuthorizationEnvelope,
        module_id: str,
        target: str,
        sender_id: str,
        allowed_event_types: tuple[EventType, ...] | list[EventType],
        ttl_seconds: int = 120,
        max_events: int = 10_000,
    ) -> IssuedEventCredential:
        """Derive one narrower telemetry stream from an existing action envelope.

        RemoteEventBus remains disabled until a distinct Task-003 control-plane
        transport authority is available. This method is the local admission
        contract that such a transport must consume; it creates no network I/O.
        """
        envelope = ActionAuthorizationEnvelope.from_value(authorization)
        if not hmac.compare_digest(envelope.tenant_id, self.tenant_id):
            raise EventAdmissionError(EventAdmissionReason.TENANT_MISMATCH)
        job = self._load_scan_job(envelope.job_id)
        if (
            job is None
            or job.get("authorization_state") != "allow"
            or job.get("status") not in {"pending", "running"}
            or not hmac.compare_digest(
                str(job.get("authorization_decision_id") or ""),
                envelope.decision_id,
            )
        ):
            raise EventAdmissionError(EventAdmissionReason.UNRECORDED_AUTHORIZATION)
        return self._event_credentials.issue(
            authorization=envelope,
            module_id=module_id,
            target=target,
            sender_id=sender_id,
            allowed_event_types=allowed_event_types,
            ttl_seconds=ttl_seconds,
            max_events=max_events,
        )

    def _resolve_event_authorization(
        self,
        decision_id: str,
    ) -> ActionAuthorizationEnvelope | None:
        """Resolve only the canonical, persisted authorization envelope."""
        def _load(session: Any) -> ActionAuthorizationEnvelope | None:
            row = get_authorization_decision(session, decision_id)
            if row is None:
                return None
            try:
                return ActionAuthorizationEnvelope.from_value(
                    json.loads(str(row.envelope_json)),
                )
            except (TypeError, ValueError, json.JSONDecodeError):
                return None

        try:
            return self._with_scan_jobs_session(_load)
        except Exception:
            return None

    def _resolve_event_job_state(
        self,
        binding: EventCredentialBinding,
    ) -> str | None:
        """Return state only for the exact tenant/job/authorization lineage."""
        if not hmac.compare_digest(binding.tenant_id, self.tenant_id):
            return None
        job = self._load_scan_job(binding.job_id)
        if (
            job is None
            or job.get("authorization_state") != "allow"
            or not hmac.compare_digest(
                str(job.get("authorization_decision_id") or ""),
                binding.authorization_decision_id,
            )
        ):
            return None
        return str(job.get("status") or "")

    def _consume_public_rate_limit(
        self,
        *,
        bucket: str,
        client_ip: str,
        limit: int = _PUBLIC_RATE_LIMIT,
        window_seconds: float = _PUBLIC_RATE_WINDOW_SECONDS,
    ) -> bool:
        """Bound unauthenticated bootstrap calls without trusting proxy payloads."""
        if type(limit) is not int or limit <= 0 or window_seconds <= 0:
            return False
        now = time.monotonic()
        key = (bucket[:200], (client_ip or "unknown")[:200])
        with self._public_rate_lock:
            recent = [
                stamp
                for stamp in self._public_rate_events.get(key, [])
                if now - stamp < window_seconds
            ]
            if len(recent) >= limit:
                self._public_rate_events[key] = recent
                return False
            recent.append(now)
            self._public_rate_events[key] = recent
            return True

    def _reserve_websocket(self, websocket: WebSocket) -> bool:
        """Atomically reserve capacity across pending and active handshakes."""
        with self._ws_capacity_lock:
            if websocket in self._ws_reservations:
                return True
            if len(self._ws_reservations) >= _WEBSOCKET_CONNECTION_LIMIT:
                return False
            self._ws_reservations.add(websocket)
            return True

    def _release_websocket(self, websocket: WebSocket) -> None:
        """Release a pending or active connection reservation idempotently."""
        with self._ws_capacity_lock:
            self._ws_reservations.discard(websocket)

    def _websocket_reservation_count(self) -> int:
        """Return a synchronized capacity count for diagnostics and tests."""
        with self._ws_capacity_lock:
            return len(self._ws_reservations)

    async def _expire_websocket_session(self, websocket: WebSocket) -> None:
        """Revoke an expired session without emitting any tenant state."""
        self._ws_clients.pop(websocket, None)
        self._release_websocket(websocket)
        try:
            await websocket.send_json({
                "type": "error",
                "reason_code": "dashboard_session_expired",
            })
        except Exception:
            pass
        try:
            await websocket.close(code=4001)
        except Exception:
            pass

    def _audit_remote_event(
        self,
        *,
        request: Any,
        status: str,
        reason_code: str,
        credential_id: str = "",
        admitted: Any = None,
    ) -> bool:
        """Write a redacted admission record before any accepted event mutation."""
        binding = admitted.binding if admitted is not None else None
        client_ip = ""
        try:
            client_ip = request.client.host if request.client else ""
        except Exception:
            client_ip = ""
        return self._write_audit_log(
            operator=binding.sender_id if binding is not None else "",
            role="service",
            ip=client_ip,
            action="event.admission",
            object_id=(binding.credential_id if binding is not None else credential_id),
            status=status,
            detail={
                "reason_code": reason_code,
                "tenant_id": binding.tenant_id if binding is not None else "",
                "engagement_id": binding.engagement_id if binding is not None else "",
                "run_id": binding.run_id if binding is not None else "",
                "job_id": binding.job_id if binding is not None else "",
                "engine": binding.engine if binding is not None else "",
                "module_id": binding.module_id if binding is not None else "",
                "sender_id": binding.sender_id if binding is not None else "",
                "sequence": admitted.sequence if admitted is not None else None,
            },
        )

    @staticmethod
    def _bounded_public_value(
        value: Any,
        *,
        depth: int = 0,
    ) -> Any:
        """Redact and bound values before they cross an API/WebSocket edge."""
        if depth >= 5:
            return "<truncated>"
        value = redact_authorization_value(value)
        if isinstance(value, Mapping):
            result: dict[str, Any] = {}
            for raw_key, item in list(value.items())[:100]:
                key = str(raw_key)[:100]
                result[key] = DashboardServer._bounded_public_value(
                    item,
                    depth=depth + 1,
                )
            return result
        if isinstance(value, (list, tuple, set)):
            return [
                DashboardServer._bounded_public_value(item, depth=depth + 1)
                for item in list(value)[:200]
            ]
        if isinstance(value, str):
            return value[:2000]
        if value is None or isinstance(value, (bool, int, float)):
            return value
        return str(value)[:500]

    def _allocate_scan_results_dir(self, scan_id: str) -> Path:
        """Allocate one private, server-owned result root for a scan job."""
        candidate = self._scan_results_dir / _artifact_identifier(scan_id)
        if _artifact_lstat(candidate) is not None:
            raise DashboardArtifactError("scan result directory already exists")
        _ensure_private_artifact_directory(candidate)
        return candidate

    @staticmethod
    def _verified_canonical_result_root(value: Any) -> Path:
        """Validate one durable job-bound result root without following links."""
        if not isinstance(value, str) or not value.strip():
            raise DashboardArtifactError("canonical result root is unavailable")
        supplied = Path(value.strip())
        if not supplied.is_absolute():
            raise DashboardArtifactError("canonical result root must be absolute")
        candidate = _artifact_path(supplied)
        descriptor = -1
        try:
            descriptor = _open_artifact_directory(candidate, create=False)
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or (hasattr(os, "getuid") and metadata.st_uid != os.getuid())
                or stat.S_IMODE(metadata.st_mode) & 0o077
            ):
                raise DashboardArtifactError(
                    "canonical result root must be owner-only"
                )
            return candidate
        except FileNotFoundError:
            raise DashboardArtifactError(
                "canonical result root is unavailable"
            ) from None
        finally:
            if descriptor >= 0:
                _close_artifact_descriptor(descriptor)

    @staticmethod
    def _canonical_database_paths(root: Path) -> list[Path]:
        """Discover only bounded, owner-only engine databases below a job root."""
        candidates: list[Path] = []
        visited = 0
        for current, directories, files in os.walk(root, topdown=True, followlinks=False):
            current_path = _artifact_path(Path(current))
            try:
                depth = len(current_path.relative_to(root).parts)
            except ValueError:
                raise DashboardArtifactError(
                    "canonical result traversal escaped its root"
                ) from None
            visited += 1
            if visited > 512:
                raise DashboardArtifactError(
                    "canonical result directory bound exceeded"
                )
            safe_directories: list[str] = []
            if depth < 4:
                for name in sorted(directories):
                    if not _ARTIFACT_ID_RE.fullmatch(name):
                        continue
                    child = current_path / name
                    metadata = _artifact_lstat(child)
                    if metadata is None or not stat.S_ISDIR(metadata.st_mode):
                        continue
                    if (
                        hasattr(os, "getuid")
                        and metadata.st_uid != os.getuid()
                    ) or stat.S_IMODE(metadata.st_mode) & 0o077:
                        raise DashboardArtifactError(
                            "canonical result directory must be owner-only"
                        )
                    safe_directories.append(name)
            directories[:] = safe_directories
            found_database = False
            for name in sorted(set(files) & _CANONICAL_RESULT_DATABASE_NAMES):
                candidate = current_path / name
                metadata = _artifact_lstat(candidate)
                if metadata is None:
                    continue
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_nlink != 1
                    or (hasattr(os, "getuid") and metadata.st_uid != os.getuid())
                    or stat.S_IMODE(metadata.st_mode) & 0o077
                ):
                    raise DashboardArtifactError(
                        "canonical result database must be owner-only"
                    )
                candidates.append(candidate)
                found_database = True
                if len(candidates) > 32:
                    raise DashboardArtifactError(
                        "canonical result database bound exceeded"
                    )
            if found_database:
                directories[:] = []
        return sorted(set(candidates))

    def _canonical_result_roots(self) -> list[Path]:
        roots: set[Path] = set()
        for record in self._load_scan_jobs_read_only(limit=1000):
            if record.get("authorization_state") != "allow":
                continue
            roots.add(self._job_bound_canonical_result_root(record))
        return sorted(roots)

    def _job_bound_canonical_result_root(
        self,
        record: Mapping[str, Any],
    ) -> Path:
        """Resolve only the server-generated root bound to one authorized job."""
        if record.get("authorization_state") != "allow":
            raise DashboardArtifactError(
                "canonical result root requires an authorized job"
            )
        if not all(
            isinstance(record.get(field), str) and record.get(field)
            for field in (
                "authorization_decision_id",
                "authorization_action_id",
            )
        ):
            raise DashboardArtifactError(
                "canonical result root authorization binding is unavailable"
            )
        scan_id = _artifact_identifier(str(record.get("scan_id") or ""))
        raw_root = record.get("results_dir")
        if not isinstance(raw_root, str) or not raw_root.strip():
            raise DashboardArtifactError("canonical result root is unavailable")
        supplied = _artifact_path(Path(raw_root.strip()))
        expected = _artifact_path(self._scan_results_dir / scan_id)
        if supplied != expected:
            raise DashboardArtifactError(
                "canonical result root does not match its durable job"
            )
        return self._verified_canonical_result_root(str(supplied))

    def _canonical_projection_rows(
        self,
        *,
        actor_id: str | None = None,
        roots: list[Path] | None = None,
    ) -> list[dict[str, Any]]:
        """Read verified tenant projections from job-bound canonical stores."""
        selected_roots = self._canonical_result_roots() if roots is None else roots
        by_id: dict[str, dict[str, Any]] = {}
        for root in selected_roots:
            verified_root = self._verified_canonical_result_root(str(root))
            for database_path in self._canonical_database_paths(verified_root):
                custody_root = database_path.parent / "evidence-custody"
                try:
                    session = create_db(database_path)
                    try:
                        finding_count = int(
                            session.execute(
                                sql_text(
                                    "SELECT COUNT(*) FROM canonical_findings "
                                    "WHERE tenant_id=:tenant_id"
                                ),
                                {"tenant_id": self.tenant_id},
                            ).scalar_one()
                        )
                        session.rollback()
                        if finding_count == 0:
                            continue
                        self._verified_canonical_result_root(str(custody_root))
                        reader = CanonicalEvidenceReader(
                            session,
                            custody_root,
                            self.tenant_id,
                            audit_actor_id=actor_id,
                        )
                        rows = reader.list_finding_projections()
                    finally:
                        session.close()
                except Exception as exc:
                    log.warning(
                        "Canonical finding read failed reason=%s",
                        type(exc).__name__,
                    )
                    raise DashboardArtifactError(
                        "canonical finding source failed verification"
                    ) from None
                for row in rows:
                    finding_id = str(row.get("id") or "")
                    if not finding_id:
                        raise DashboardArtifactError(
                            "canonical finding projection is invalid"
                        )
                    previous = by_id.get(finding_id)
                    if previous is not None and previous != row:
                        raise DashboardArtifactError(
                            "canonical finding identity conflicts across stores"
                        )
                    by_id[finding_id] = row
        return sorted(
            by_id.values(),
            key=lambda row: (str(row.get("timestamp") or ""), str(row["id"])),
            reverse=True,
        )

    def _canonical_export(
        self,
        finding_ids: list[str],
        *,
        actor_id: str,
    ) -> bytes:
        """Build one deterministic backend export from persisted projections."""
        requested = sorted(set(finding_ids))
        if not requested or len(requested) > 200:
            raise DashboardArtifactError("finding export selection is invalid")
        if any(
            not isinstance(item, str) or _ARTIFACT_ID_RE.fullmatch(item) is None
            for item in requested
        ):
            raise DashboardArtifactError("finding export selection is invalid")
        available = {
            str(row["id"]): self._public_finding(row)
            for row in self._canonical_projection_rows(actor_id=actor_id)
        }
        if any(finding_id not in available for finding_id in requested):
            raise DashboardArtifactError("canonical finding is unavailable")
        return json.dumps(
            {
                "findings": [available[finding_id] for finding_id in requested],
                "schema_version": "forge-canonical-finding-export-v1",
                "tenant_id": self.tenant_id,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")

    def _public_finding(self, finding: Mapping[str, Any]) -> dict[str, Any]:
        """Serialize one finding after central truth normalization."""
        finding = ordinary_finding_projection(
            normalise_finding(dict(finding))
        )
        allowed = (
            "id",
            "title",
            "severity",
            "module",
            "target",
            "cvss_score",
            "timestamp",
            "url",
            "port",
            "service",
            "description",
            "mitre",
            "confidence",
            "status",
            "vpr_score",
            "vpr_priority",
            "verification_state",
            "proof_type",
            "maturity",
            "finding_key",
            "dedup_key",
            "reproduction_steps",
            "remediation",
            "retest_artifact_id",
            "retest_attempt_id",
            "retest_durable_attempt_id",
            "retest_id",
            "retest_job_id",
            "retest_observation_id",
            "retest_reason_code",
            "retest_state",
            "retest_status",
            "retest_verdict",
            "evidence",
        )
        result: dict[str, Any] = {}
        for key in allowed:
            if key not in finding or key == "evidence":
                continue
            if key == "dedup_key":
                # The ordinary projector validates this versioned identity
                # digest.  Preserve it as an opaque canonical reference rather
                # than treating its hash-shaped bytes as credential material.
                result[key] = finding[key]
            else:
                result[key] = self._bounded_public_value(finding.get(key))
        result["evidence"] = ordinary_evidence_projection(
            finding.get("evidence")
        )
        return result

    def _public_state_snapshot(
        self,
        role: Role,
        *,
        actor_id: str | None = None,
    ) -> dict[str, Any]:
        """Return tenant-bound state with role-aware secret/evidence omission."""
        raw = self.state_store.snapshot()
        safe: dict[str, Any] = {
            key: self._bounded_public_value(raw.get(key))
            for key in (
                "framework",
                "tenant_id",
                "run_id",
                "target",
                "scan_status",
                "scan_mode",
                "engagement",
                "tester",
                "findings_count",
                "modules",
                "phases",
                "targets",
                "kill_chain",
                "metrics",
                "timeline",
            )
        }
        durable_jobs = self._durable_jobs_for_read_projection(limit=1)
        if durable_jobs:
            durable = durable_jobs[0]
            safe["scan_status"] = self._bounded_public_value(
                durable.get("status")
            )
            safe["run_id"] = self._bounded_public_value(durable.get("run_id"))
            if durable.get("target"):
                safe["target"] = self._bounded_public_value(
                    durable.get("target")
                )
        else:
            safe["scan_status"] = None
        safe["findings"] = self._public_findings(
            limit=1000,
            actor_id=actor_id,
        )
        if role in {Role.OPERATOR, Role.ADMIN}:
            safe["credentials"] = [
                {
                    key: self._bounded_public_value(item.get(key))
                    for key in (
                        "id",
                        "cred_type",
                        "account",
                        "target",
                        "discovered_by",
                        "timestamp",
                    )
                    if key in item
                }
                for item in raw.get("credentials", [])[:500]
                if isinstance(item, Mapping)
            ]
            safe["sessions"] = self._bounded_public_value(
                raw.get("sessions", [])[:500],
            )
        else:
            safe["credentials"] = []
            safe["sessions"] = []
        safe["brain_verdicts"] = [
            {
                key: self._bounded_public_value(item.get(key))
                for key in (
                    "finding_id",
                    "verdict",
                    "confidence",
                    "severity_adjustment",
                    "timestamp",
                )
                if key in item
            }
            for item in raw.get("brain_verdicts", [])[:500]
            if isinstance(item, Mapping)
        ]
        safe["chain_actions"] = [
            {
                key: self._bounded_public_value(item.get(key))
                for key in (
                    "chain_type",
                    "source_framework",
                    "target_framework",
                    "target_module",
                    "auto_execute",
                    "timestamp",
                )
                if key in item
            }
            for item in raw.get("chain_actions", [])[:500]
            if isinstance(item, Mapping)
        ]
        return safe

    def _public_findings(
        self,
        *,
        severity: str | None = None,
        limit: int = 100,
        actor_id: str | None = None,
    ) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 1000))
        findings = [
            self._public_finding(item)
            for item in self._canonical_projection_rows(actor_id=actor_id)
            if severity is None
            or str(item.get("severity") or "").lower() == severity.lower()
        ]
        return findings[:limit]

    def _public_event(self, event: Event) -> dict[str, Any]:
        """Serialize an event through a type-specific field allowlist."""
        common_module = {
            "name",
            "phase",
            "progress",
            "findings_count",
            "error",
            "reason",
            "reason_code",
            "tenant_id",
            "engagement_id",
            "job_id",
            "engine",
            "module_id",
            "target_binding",
            "sender_id",
            "authorization_decision_id",
            "sequence",
        }
        lifecycle = {
            "scan_id",
            "scan_type",
            "target",
            "mode",
            "engagement",
            "modules",
            "actual_modules",
            "status",
            "returncode",
        }
        finding = {
            "id",
            "finding_id",
            "title",
            "severity",
            "module",
            "target",
            "cvss_score",
            "url",
            "port",
            "service",
            "description",
            "mitre_attack",
            "confidence",
            "status",
            "vpr_score",
            "vpr_priority",
            "verification_state",
            "proof_type",
            "maturity",
            "action",
            "dry_run",
            "job_id",
            "retest_id",
            "retest_reason_code",
            "retest_state",
            "retest_status",
            "retest_verdict",
        }
        credential = {"type", "account", "target", "module", "discovered_by"}
        control = {
            "command",
            "job_id",
            "agent_id",
            "engine",
            "target",
            "status",
            "dry_run",
        }
        metric = {
            "bytes_out",
            "bytes_in",
            "status_code",
            "duration",
            "reason_code",
        }
        if event.event_type in {
            EventType.MODULE_START,
            EventType.MODULE_PROGRESS,
            EventType.MODULE_COMPLETE,
            EventType.MODULE_FAIL,
            EventType.MODULE_SKIP,
            EventType.PHASE_START,
            EventType.PHASE_COMPLETE,
        }:
            allowed = common_module | {"number", "duration", "modules"}
        elif event.event_type in {
            EventType.SCAN_START,
            EventType.SCAN_COMPLETE,
            EventType.SCAN_INTERRUPTED,
            EventType.SCAN_PAUSED,
            EventType.SCAN_RESUMED,
            EventType.SCAN_ABORTED,
        }:
            allowed = lifecycle
        elif event.event_type in {EventType.FINDING_NEW, EventType.FINDING_UPDATED}:
            allowed = finding
        elif event.event_type is EventType.CREDENTIAL_FOUND:
            allowed = credential
        elif event.event_type is EventType.CONTROL_COMMAND:
            allowed = control
        elif event.event_type in {
            EventType.REQUEST_SENT,
            EventType.REQUEST_ERROR,
            EventType.WAF_BLOCK,
            EventType.RATE_LIMIT_HIT,
        }:
            allowed = metric
        else:
            allowed = set()
        event_data: Mapping[str, Any] = event.data
        if event.event_type in {EventType.FINDING_NEW, EventType.FINDING_UPDATED}:
            if event.data.get("action") == "retest":
                verdict = event.data.get("retest_verdict")
                state = str(event.data.get("retest_state") or "")
                if verdict is not None:
                    try:
                        CanonicalRetestStatus(str(verdict))
                    except ValueError:
                        raise DashboardArtifactError(
                            "canonical retest event verdict is invalid"
                        ) from None
                if state not in {
                    "planned",
                    "authorized",
                    "queued",
                    "running",
                    "terminal",
                    "canceled",
                }:
                    raise DashboardArtifactError(
                        "canonical retest event state is invalid"
                    )
                if (state == "terminal") != (verdict is not None):
                    raise DashboardArtifactError(
                        "canonical retest event mixes lifecycle and verdict truth"
                    )
                expected_status = str(verdict) if verdict is not None else state
                if event.data.get("retest_status") != expected_status:
                    raise DashboardArtifactError(
                        "canonical retest event status is inconsistent"
                    )
            event_data = (
                dict(event.data)
                if event.data.get("action") == "retest"
                else normalise_finding(dict(event.data))
            )
        data = {
            key: self._bounded_public_value(value)
            for key, value in event_data.items()
            if key in allowed
        }
        return {
            "type": "event",
            "event_type": event.event_type.value,
            "data": data,
            "source": self._bounded_public_value(event.source),
            "timestamp": self._bounded_public_value(event.timestamp),
            "event_id": self._bounded_public_value(event.event_id),
            "run_id": self._bounded_public_value(event.run_id),
        }

    def _websocket_origin_allowed(self, websocket: Any) -> bool:
        """Reject DNS-rebinding/cross-origin browser connections by default."""
        allowed_hosts = _dashboard_allowed_hosts(self.host)
        try:
            host_headers = _dashboard_header_values(websocket.headers, "host")
            origin_headers = _dashboard_header_values(websocket.headers, "origin")
        except Exception:
            return False
        if len(host_headers) != 1 or len(origin_headers) > 1:
            return False
        if not _dashboard_host_header_allowed(host_headers[0], allowed_hosts):
            return False
        origin_header = origin_headers[0] if origin_headers else ""
        if not origin_header:
            return True
        try:
            origin = urlsplit(origin_header)
        except Exception:
            return False
        return (
            origin.scheme.lower() in {"http", "https"}
            and _normalize_dashboard_host(origin.hostname) in allowed_hosts
        )

    def create_app(self) -> Any:
        """Create the FastAPI application with all routes."""
        if not HAS_FASTAPI:
            raise ImportError(
                "FastAPI not installed. Run: pip install fastapi uvicorn[standard] websockets"
            )

        # Reconcile durable authority as an explicit server-start action.
        # Authentication and request error paths only use this initialized
        # service; client traffic never triggers recovery timing.
        self._initialize_durable_job_state()

        app = FastAPI(
            title="Forge Suite — War Room",
            description="Real-time offensive security dashboard",
            version=VERSION,
            docs_url=None,
            redoc_url=None,
            openapi_url=None,
        )

        # CORS — allow APEX UI dev server
        try:
            from fastapi.middleware.cors import CORSMiddleware
            app.add_middleware(
                CORSMiddleware,
                allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
                allow_origin_regex=r"^http://(localhost|127\.0\.0\.1):51[0-9]{2}$",
                allow_credentials=False,
                allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
                allow_headers=["Authorization", "Content-Type", "Accept"],
            )
        except ImportError:
            pass  # CORSMiddleware not available

        # Static files. Standalone dashboard serves the built React app from dist/.
        if (_STATIC_DIR / "assets").exists():
            app.mount("/assets", StaticFiles(directory=str(_STATIC_DIR / "assets")), name="assets")
        if (_STATIC_DIR / "icons.svg").exists():
            @app.get("/icons.svg")
            async def icons_svg():
                return FileResponse(str(_STATIC_DIR / "icons.svg"), media_type="image/svg+xml")
        if (_STATIC_DIR / "favicon.svg").exists():
            @app.get("/favicon.svg")
            async def favicon_svg():
                return FileResponse(str(_STATIC_DIR / "favicon.svg"), media_type="image/svg+xml")
        if _STATIC_DIR.exists():
            app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")
        if not _APEX_DIST_DIR.exists() and (_APEX_DIR / "src").exists():
            app.mount("/src", StaticFiles(directory=str(_APEX_DIR / "src")), name="src")

        # Templates
        templates = None
        if _TEMPLATE_DIR.exists():
            templates = Jinja2Templates(directory=str(_TEMPLATE_DIR))

        server = self  # Closure reference

        # ── Helper: extract token ─────────────────────────────────────
        def _get_token(request: Request) -> str | None:
            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                return auth_header[7:]
            return None

        def _client_ip(request: Request) -> str:
            # Proxy identity is not trusted until a separately configured
            # trusted-proxy boundary exists. Client-controlled XFF therefore
            # cannot split rate limits or rewrite audit attribution.
            return request.client.host if request.client else ""

        def _require_auth(request: Request, role: Role = Role.VIEWER) -> TokenPayload:
            payload = getattr(request.state, "dashboard_identity", None)
            if not isinstance(payload, TokenPayload):
                payload = validate_token(_get_token(request) or "")
            if not payload:
                raise HTTPException(
                    status_code=401,
                    detail={"reason_code": "dashboard_auth_required"},
                )
            if not hmac.compare_digest(payload.tenant_id, server.tenant_id):
                raise HTTPException(
                    status_code=403,
                    detail={"reason_code": "dashboard_tenant_forbidden"},
                )
            if not payload.has_role(role):
                raise HTTPException(
                    status_code=403,
                    detail={"reason_code": "dashboard_role_forbidden"},
                )
            return payload

        @app.middleware("http")
        async def _dashboard_api_auth_boundary(request: Request, call_next: Any) -> Any:
            """Default-deny every API route before endpoint body or side effects."""
            try:
                host_headers = request.headers.getlist("host")
            except Exception:
                host_headers = []
            if (
                len(host_headers) != 1
                or not _dashboard_host_header_allowed(
                    host_headers[0],
                    _dashboard_allowed_hosts(server.host),
                )
            ):
                return JSONResponse(
                    {"detail": {"reason_code": "dashboard_host_forbidden"}},
                    status_code=403,
                )
            path = request.url.path
            if not path.startswith("/api/v1/"):
                ui_class = classify_public_ui_route(path)
                if ui_class is not None:
                    if not server._consume_public_rate_limit(
                        bucket=ui_class,
                        client_ip=_client_ip(request),
                        limit=300 if ui_class == "public_static_asset" else _PUBLIC_RATE_LIMIT,
                    ):
                        return JSONResponse(
                            {"detail": {"reason_code": "bootstrap_rate_limited"}},
                            status_code=429,
                        )
                return await call_next(request)
            method = request.method.upper()
            policy = dashboard_api_route_policy(method, path)
            classification = classify_dashboard_api_route(method, path)
            if classification == "unclassified":
                return JSONResponse(
                    {"detail": {"reason_code": "api_route_unclassified"}},
                    status_code=404,
                )
            if classification == "cors_preflight":
                if not server._consume_public_rate_limit(
                    bucket="cors-preflight",
                    client_ip=_client_ip(request),
                    limit=120,
                ):
                    return JSONResponse(
                        {"detail": {"reason_code": "bootstrap_rate_limited"}},
                        status_code=429,
                    )
                return await call_next(request)
            if policy is None:
                return JSONResponse(
                    {"detail": {"reason_code": "api_route_unclassified"}},
                    status_code=404,
                )
            _auth_class, minimum_role, route_template = policy
            mutating = (method, route_template) in DASHBOARD_MUTATION_ROUTE_TEMPLATES
            if classification == "public_bootstrap":
                if not server._consume_public_rate_limit(
                    bucket=f"{method}:{route_template}",
                    client_ip=_client_ip(request),
                ):
                    return JSONResponse(
                        {"detail": {"reason_code": "bootstrap_rate_limited"}},
                        status_code=429,
                    )
                return await call_next(request)
            if classification == "service_credential":
                # Disabled event ingress performs its own redacted audit and
                # deliberately reaches no credential registry or body parser.
                if route_template == "/api/v1/events/emit":
                    if not server._consume_public_rate_limit(
                        bucket="remote-event-disabled",
                        client_ip=_client_ip(request),
                    ):
                        return JSONResponse(
                            {"detail": {"reason_code": "service_rate_limited"}},
                            status_code=429,
                        )
                    return await call_next(request)
                try:
                    agent_identity = server._require_agent_token(
                        request,
                        allow_bootstrap=(route_template == "/api/v1/agents/register"),
                    )
                    request.state.agent_identity = agent_identity
                except HTTPException as exc:
                    if not server._consume_public_rate_limit(
                        bucket="agent-auth-denial",
                        client_ip=_client_ip(request),
                    ):
                        return JSONResponse(
                            {"detail": {"reason_code": "service_rate_limited"}},
                            status_code=429,
                        )
                    server._write_audit_log(
                        operator="",
                        role="service",
                        ip=_client_ip(request),
                        action="agent.api.denied",
                        object_id=route_template,
                        status="denied",
                        detail={
                            "reason_code": (
                                exc.detail.get("reason_code", "agent_auth_required")
                                if isinstance(exc.detail, dict)
                                else "agent_auth_required"
                            ),
                            "method": method,
                        },
                    )
                    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
                if mutating and not server._write_audit_log(
                    operator="agent-service",
                    role="service",
                    ip=_client_ip(request),
                    action="agent.api.authorization",
                    object_id=route_template,
                    status="authorized",
                    detail={"method": method},
                ):
                    return JSONResponse(
                        {"detail": {"reason_code": "mutation_audit_unavailable"}},
                        status_code=503,
                    )
                try:
                    response = await call_next(request)
                except Exception:
                    if mutating:
                        server._write_audit_log(
                            operator="agent-service",
                            role="service",
                            ip=_client_ip(request),
                            action="agent.api.result",
                            object_id=route_template,
                            status="rejected",
                            detail={"method": method, "reason_code": "internal_error"},
                        )
                    raise
                if mutating:
                    server._write_audit_log(
                        operator="agent-service",
                        role="service",
                        ip=_client_ip(request),
                        action="agent.api.result",
                        object_id=route_template,
                        status="accepted" if response.status_code < 400 else "rejected",
                        detail={"method": method, "http_status": response.status_code},
                    )
                return response
            payload = validate_token(_get_token(request) or "")
            if not payload:
                if mutating:
                    if not server._consume_public_rate_limit(
                        bucket="dashboard-auth-denial",
                        client_ip=_client_ip(request),
                    ):
                        return JSONResponse(
                            {"detail": {"reason_code": "bootstrap_rate_limited"}},
                            status_code=429,
                        )
                    server._write_audit_log(
                        operator="",
                        role="",
                        ip=_client_ip(request),
                        action="api.mutation.denied",
                        object_id=route_template,
                        status="denied",
                        detail={
                            "reason_code": "dashboard_auth_required",
                            "method": method,
                            "route": route_template,
                        },
                    )
                return JSONResponse(
                    {"detail": {"reason_code": "dashboard_auth_required"}},
                    status_code=401,
                )
            if not hmac.compare_digest(payload.tenant_id, server.tenant_id):
                if mutating:
                    server._write_audit_log(
                        operator="",
                        role="",
                        ip=_client_ip(request),
                        action="api.mutation.denied",
                        object_id=route_template,
                        status="denied",
                        detail={
                            "reason_code": "dashboard_tenant_forbidden",
                            "method": method,
                            "route": route_template,
                        },
                    )
                return JSONResponse(
                    {"detail": {"reason_code": "dashboard_tenant_forbidden"}},
                    status_code=403,
                )
            if minimum_role is not None and not payload.has_role(minimum_role):
                if mutating:
                    server._write_audit_log(
                        operator=payload.username,
                        role=payload.role.value,
                        ip=_client_ip(request),
                        action="api.mutation.denied",
                        object_id=route_template,
                        status="denied",
                        detail={
                            "reason_code": "dashboard_role_forbidden",
                            "method": method,
                            "route": route_template,
                            "required_role": minimum_role.value,
                        },
                    )
                return JSONResponse(
                    {"detail": {"reason_code": "dashboard_role_forbidden"}},
                    status_code=403,
                )
            if mutating and not server._write_audit_log(
                operator=payload.username,
                role=payload.role.value,
                ip=_client_ip(request),
                action="api.mutation.authorization",
                object_id=route_template,
                status="authorized",
                detail={"method": method, "route": route_template},
            ):
                return JSONResponse(
                    {"detail": {"reason_code": "mutation_audit_unavailable"}},
                    status_code=503,
                )
            request.state.dashboard_identity = payload
            try:
                response = await call_next(request)
            except BaseException:
                if mutating:
                    server._write_audit_log(
                        operator=payload.username,
                        role=payload.role.value,
                        ip=_client_ip(request),
                        action="api.mutation.result",
                        object_id=route_template,
                        status="rejected",
                        detail={
                            "method": method,
                            "route": route_template,
                            "reason_code": "internal_error",
                        },
                    )
                raise
            finally:
                server._wipe_request_credential_bundles(request)
            if mutating:
                server._write_audit_log(
                    operator=payload.username,
                    role=payload.role.value,
                    ip=_client_ip(request),
                    action="api.mutation.result",
                    object_id=route_template,
                    status="accepted" if response.status_code < 400 else "rejected",
                    detail={
                        "method": method,
                        "route": route_template,
                        "http_status": response.status_code,
                    },
                )
            return response

        def _audit(
            request: Request,
            action: str,
            *,
            object_id: str = "",
            status: str = "ok",
            detail: dict[str, Any] | None = None,
            payload: TokenPayload | None = None,
        ) -> None:
            try:
                payload = payload or _require_auth(request)
            except Exception:
                payload = None
            server._write_audit_log(
                operator=payload.username if payload else "",
                role=payload.role.value if payload else "",
                ip=_client_ip(request),
                action=action,
                object_id=object_id,
                status=status,
                detail=detail or {},
            )

        def _require_not_killed() -> None:
            if server._kill_switch_active():
                raise HTTPException(status_code=423, detail="Operator kill switch is active")

        # ── Routes ────────────────────────────────────────────────────

        @app.get("/", response_class=HTMLResponse)
        async def dashboard_page():
            """Serve the main dashboard SPA."""
            index_path = _TEMPLATE_DIR / "index.html"
            if index_path.exists():
                return HTMLResponse(index_path.read_text(encoding="utf-8"))
            return HTMLResponse("<h1>Forge Suite War Room</h1><p>Dashboard UI not found.</p>")

        @app.get("/login", response_class=HTMLResponse)
        async def login_page(request: Request):
            """Serve the login page."""
            if templates and (_TEMPLATE_DIR / "login.html").exists():
                return templates.TemplateResponse(request=request, name="login.html", context={"request": request})
            return HTMLResponse("<h1>Login</h1>")

        @app.get("/scans/{scan_id}", response_class=HTMLResponse)
        async def scan_detail_page(scan_id: str):
            """Serve the React scan detail route on browser refresh/deep link."""
            index_path = _TEMPLATE_DIR / "index.html"
            if index_path.exists():
                return HTMLResponse(index_path.read_text(encoding="utf-8"))
            return HTMLResponse("<h1>Forge Suite War Room</h1><p>Dashboard UI not found.</p>")

        @app.get("/scan-builder", response_class=HTMLResponse)
        @app.get("/red-teaming", response_class=HTMLResponse)
        @app.get("/c2-console", response_class=HTMLResponse)
        @app.get("/mobile", response_class=HTMLResponse)
        @app.get("/discovery", response_class=HTMLResponse)
        @app.get("/targets", response_class=HTMLResponse)
        @app.get("/scans", response_class=HTMLResponse)
        @app.get("/scheduling", response_class=HTMLResponse)
        @app.get("/reports", response_class=HTMLResponse)
        @app.get("/vulnerabilities", response_class=HTMLResponse)
        @app.get("/policies", response_class=HTMLResponse)
        @app.get("/notifications", response_class=HTMLResponse)
        @app.get("/integrations", response_class=HTMLResponse)
        @app.get("/team", response_class=HTMLResponse)
        @app.get("/activity", response_class=HTMLResponse)
        @app.get("/agents", response_class=HTMLResponse)
        @app.get("/credential-analysis", response_class=HTMLResponse)
        async def spa_page():
            """Serve React client-side routes on browser refresh/deep link."""
            index_path = _TEMPLATE_DIR / "index.html"
            if index_path.exists():
                return HTMLResponse(index_path.read_text(encoding="utf-8"))
            return HTMLResponse("<h1>Forge Suite War Room</h1><p>Dashboard UI not found.</p>")

        @app.post("/api/v1/auth/login")
        async def api_login(request: Request):
            """Authenticate and get a bearer token."""
            try:
                body = await request.json()
            except Exception:
                body = {}
            if not isinstance(body, dict):
                body = {}
            raw_username = body.get("username", "")
            raw_password = body.get("password", "")
            username = raw_username.strip() if isinstance(raw_username, str) else ""
            password = raw_password if isinstance(raw_password, str) else ""
            if len(username) > 200 or len(password) > 4096:
                username = ""
                password = ""
            totp_code = str(body.get("totp") or body.get("totp_code") or body.get("mfa_code") or "")
            token = generate_token(username, password, totp_code=totp_code)
            identity_ref = f"identity:{hashlib.sha256(username.encode('utf-8')).hexdigest()[:16]}"
            if not token:
                server._write_audit_log(
                    operator="",
                    role="",
                    ip=_client_ip(request),
                    action="auth.login",
                    object_id=identity_ref,
                    status="denied",
                    detail={"reason": "invalid_credentials_or_mfa"},
                )
                raise HTTPException(status_code=401, detail="Invalid credentials")
            if not server._write_audit_log(
                operator=username,
                role="",
                ip=_client_ip(request),
                action="auth.login",
                object_id=username,
                status="ok",
            ):
                raise HTTPException(
                    status_code=503,
                    detail={"reason_code": "mutation_audit_unavailable"},
                )
            return {"token": token, "username": username}

        @app.get("/api/v1/auth/sso/config")
        async def api_sso_config():
            """Return public SSO configuration for the login UI."""
            cfg = get_sso_config()
            return {
                **cfg.public_dict(),
                "operational": False,
                "reason_code": "sso_transport_disabled",
            }

        @app.get("/api/v1/auth/sso/start")
        async def api_sso_start(request: Request, next: str = "/"):
            """Start OIDC authorization-code login."""
            del request, next
            return JSONResponse(
                {
                    "status": "disabled",
                    "reason_code": "sso_transport_disabled",
                },
                status_code=503,
            )

        @app.get("/api/v1/auth/sso/callback")
        async def api_sso_callback(request: Request, code: str | None = None, state: str | None = None, error: str | None = None):
            """Complete OIDC login, then redirect UI with a one-time exchange code."""
            del request, code, state, error
            return JSONResponse(
                {
                    "status": "disabled",
                    "reason_code": "sso_transport_disabled",
                },
                status_code=503,
            )

        @app.post("/api/v1/auth/sso/exchange")
        async def api_sso_exchange(request: Request):
            """Exchange one-time SSO code for a dashboard bearer token."""
            server._write_audit_log(
                operator="",
                role="",
                ip=_client_ip(request),
                action="auth.sso.exchange",
                object_id="disabled",
                status="disabled",
                detail={"reason_code": "sso_transport_disabled"},
            )
            return JSONResponse(
                {
                    "status": "disabled",
                    "reason_code": "sso_transport_disabled",
                },
                status_code=503,
            )

        @app.post("/api/v1/auth/sso/discover")
        async def api_sso_discover(request: Request):
            """Fetch OIDC discovery metadata for operator configuration."""
            _require_auth(request, Role.ADMIN)
            del request
            return JSONResponse(
                {
                    "status": "disabled",
                    "reason_code": "sso_transport_disabled",
                },
                status_code=503,
            )

        @app.get("/api/v1/health")
        async def api_health(request: Request):
            """Side-effect-free public bootstrap status.

            Host inventory, process state, tenant state, and configured URLs are
            intentionally available only through authenticated endpoints.
            """
            del request
            return {
                "status": "ok",
                "version": VERSION,
                "auth_required": True,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        @app.get("/api/v1/tools")
        async def api_tools(request: Request):
            """Framework/tool connection inventory used by the dashboard."""
            _require_auth(request, Role.OPERATOR)
            tools = server._tool_inventory()
            return {"tools": tools, "ready": all(t["ready"] for t in tools)}

        @app.get("/api/v1/supervisor")
        async def api_supervisor(request: Request):
            """Dashboard child-process supervisor snapshot."""
            _require_auth(request, Role.OPERATOR)
            return server._supervisor_snapshot()

        @app.get("/api/v1/state")
        async def api_state(request: Request):
            """Full state snapshot for dashboard initialization."""
            payload = _require_auth(request)
            return JSONResponse(
                server._public_state_snapshot(
                    payload.role,
                    actor_id=payload.username,
                )
            )

        @app.get("/api/v1/findings")
        async def api_findings(
            request: Request,
            severity: str | None = None,
            module: str | None = None,
            target: str | None = None,
            limit: int = Query(default=100, le=1000),
            offset: int = Query(default=0, ge=0),
        ):
            """Paginated findings with filters."""
            payload = _require_auth(request)
            findings = server._public_findings(
                severity=severity,
                limit=1000,
                actor_id=payload.username,
            )
            # Apply additional filters
            if module:
                findings = [f for f in findings if f.get("module") == module]
            if target:
                findings = [f for f in findings if f.get("target") == target]
            return {
                "findings": findings[offset:offset + limit],
                "total": len(findings),
            }

        @app.post("/api/v1/findings/export")
        async def api_export_findings(request: Request):
            """Export selected findings from verified persisted derivatives."""
            payload = _require_auth(request)
            try:
                body = await request.json()
            except Exception:
                raise HTTPException(
                    status_code=400,
                    detail="Finding export selection is invalid",
                ) from None
            finding_ids = body.get("finding_ids") if isinstance(body, dict) else None
            if (
                not isinstance(finding_ids, list)
                or not finding_ids
                or len(finding_ids) > 200
                or any(not isinstance(item, str) for item in finding_ids)
            ):
                raise HTTPException(
                    status_code=400,
                    detail="Finding export selection is invalid",
                )
            try:
                content = server._canonical_export(
                    finding_ids,
                    actor_id=payload.username,
                )
            except DashboardArtifactError:
                raise HTTPException(
                    status_code=409,
                    detail="Canonical finding export is unavailable",
                ) from None
            return Response(
                content=content,
                media_type="application/json",
                headers={
                    "Content-Disposition": (
                        'attachment; filename="forge_findings.json"'
                    )
                },
            )

        @app.get("/api/v1/targets")
        async def api_targets(request: Request):
            """Target status map."""
            payload = _require_auth(request)
            snap = server._public_state_snapshot(
                payload.role, actor_id=payload.username
            )
            return {"targets": snap.get("targets", {})}

        @app.get("/api/v1/metrics")
        async def api_metrics(request: Request):
            """Current metrics snapshot."""
            _require_auth(request)
            return server.state_store.metrics_snapshot().to_dict()

        @app.get("/api/v1/kill-chain")
        async def api_kill_chain(request: Request):
            """Kill chain state."""
            _require_auth(request)
            return server.state_store.kill_chain.to_dict()

        @app.get("/api/v1/credentials")
        async def api_credentials(request: Request):
            """Discovered credentials (masked)."""
            payload = _require_auth(request, Role.OPERATOR)
            snap = server._public_state_snapshot(
                payload.role, actor_id=payload.username
            )
            return {"credentials": snap.get("credentials", [])}

        @app.post("/api/v1/credentials/analyze")
        async def api_credentials_analyze(request: Request):
            """Analyze uploaded credential material without replaying secrets."""
            _require_auth(request, Role.OPERATOR)
            body = await request.json()
            filename = str(body.get("filename", "upload.txt"))
            content_base64 = str(body.get("content_base64", ""))
            profile = str(body.get("profile", "defensive"))
            if not content_base64:
                raise HTTPException(status_code=400, detail="content_base64 is required")
            try:
                from common.dashboard.credential_analysis import analyze_uploaded_credential_file
                result = analyze_uploaded_credential_file(filename, content_base64, profile=profile)
                server.event_bus.emit_simple(
                    EventType.CREDENTIAL_FOUND,
                    source="credential_analysis",
                    type="EXPOSURE_ANALYSIS",
                    account=f"{result['summary']['exposures_found']} exposure(s)",
                    secret="redacted",
                    target=filename,
                    discovered_by="dashboard_upload",
                )
                return result
            except ValueError:
                raise HTTPException(
                    status_code=400,
                    detail="credential analysis input is invalid",
                ) from None
            except Exception as exc:
                log.warning(
                    "Credential analysis failed (%s)",
                    type(exc).__name__,
                )
                raise HTTPException(
                    status_code=400,
                    detail="credential analysis failed",
                ) from None

        @app.get("/api/v1/sessions")
        async def api_sessions(request: Request):
            """Active shell sessions."""
            payload = _require_auth(request, Role.OPERATOR)
            snap = server._public_state_snapshot(
                payload.role, actor_id=payload.username
            )
            return {"sessions": snap.get("sessions", [])}

        @app.get("/api/v1/timeline")
        async def api_timeline(request: Request, limit: int = Query(default=100, le=500)):
            """Threat timeline events."""
            payload = _require_auth(request)
            snapshot = server._public_state_snapshot(
                payload.role, actor_id=payload.username
            )
            return {"timeline": snapshot.get("timeline", [])[-limit:]}

        @app.get("/api/v1/audit-logs")
        async def api_audit_logs(request: Request, limit: int = Query(default=100, le=500)):
            """Operator audit log entries."""
            _require_auth(request, Role.ADMIN)
            return {"audit_logs": server._load_audit_logs(limit=limit)}

        # ── Distributed scan agents ─────────────────────────────────

        @app.get("/api/v1/agents")
        async def api_agents_list(request: Request):
            """List registered scan agents and queued/running assignments."""
            _require_auth(request)
            return server._agent_state()

        @app.post("/api/v1/agents/register")
        async def api_agents_register(request: Request):
            """Register a credential-bound scan agent."""
            identity = getattr(request.state, "agent_identity", None)
            if not isinstance(identity, dict):
                raise HTTPException(
                    status_code=401,
                    detail={"reason_code": "agent_auth_required"},
                )
            body = await request.json()
            registration = server._register_scan_agent(
                body,
                request,
                identity=identity,
            )
            return {"status": "registered", **registration}

        @app.post("/api/v1/agents/jobs")
        async def api_agents_create_job(request: Request):
            """Create a scoped job for a registered scan agent."""
            payload = _require_auth(request, Role.OPERATOR)
            body = await request.json()
            if not bool(body.get("dry_run", True)):
                _require_not_killed()
            job = server._create_agent_job(body, payload)
            server.event_bus.emit_simple(
                EventType.CONTROL_COMMAND,
                source="dashboard",
                command="agent_job_created",
                job_id=job["id"],
                agent_id=job["agent_id"],
                engine=job["engine"],
                target=safe_target_display(job["target"]),
                dry_run=job["dry_run"],
            )
            _audit(
                request,
                "agent.job.create",
                object_id=job["id"],
                detail={
                    "agent_id": job["agent_id"],
                    "engine": job["engine"],
                    "target": safe_target_display(job["target"]),
                    "dry_run": job["dry_run"],
                    "authorization": job.get("authorization_public"),
                },
                payload=payload,
            )
            return {"status": "queued", "job": job}

        @app.get("/api/v1/agents/{agent_id}/jobs/next")
        async def api_agents_next_job(request: Request, agent_id: str):
            """Return and lease the next queued job for the authenticated agent."""
            identity = server._require_agent_token(request, allow_bootstrap=False)
            job = server._lease_agent_job(agent_id, identity)
            return {"job": job}

        @app.post("/api/v1/agents/{agent_id}/jobs/{job_id}/lease/renew")
        async def api_agents_renew_lease(request: Request, agent_id: str, job_id: str):
            identity = server._require_agent_token(request, allow_bootstrap=False)
            body = await request.json()
            lease = server._renew_agent_lease(agent_id, job_id, body, identity)
            return {"status": "renewed", "job": lease}

        @app.post("/api/v1/agents/{agent_id}/revoke")
        async def api_agents_revoke(request: Request, agent_id: str):
            identity = server._require_agent_token(request, allow_bootstrap=False)
            agent = server._revoke_agent(agent_id, identity)
            return {"status": "revoked", "agent": agent}

        @app.post("/api/v1/agents/{agent_id}/jobs/{job_id}/result")
        async def api_agents_submit_result(request: Request, agent_id: str, job_id: str):
            """Accept a result only for the authenticated current lease owner."""
            identity = server._require_agent_token(request, allow_bootstrap=False)
            body = await request.json()
            job, duplicate = server._complete_agent_job(agent_id, job_id, body, identity)
            if not duplicate:
                server.event_bus.emit_simple(
                    EventType.CONTROL_COMMAND,
                    source="dashboard",
                    command="agent_job_completed",
                    job_id=job_id,
                    agent_id=agent_id,
                    status=job["status"],
                )
            return {"status": "duplicate" if duplicate else "accepted", "job": job}

        # ── Scan Control ──────────────────────────────────────────────

        @app.post("/api/v1/events/emit")
        async def api_events_emit(request: Request):
            """Keep remote mutation inert until Task-003 transport is usable.

            The short-lived binding/replay contract is implemented and tested
            locally, but RemoteEventBus has no authorized control-plane egress
            context. Consequently HTTP ingress is disabled before body parsing,
            Event deserialization, EventBus publication, or state mutation.
            """
            server._audit_remote_event(
                request=request,
                status="disabled",
                reason_code="remote_event_transport_disabled",
            )
            return JSONResponse(
                {
                    "status": "disabled",
                    "reason_code": "remote_event_transport_disabled",
                },
                status_code=503,
            )

        # ── Credential preflight test ─────────────────────────────────

        def _validate_preflight_url(url: str) -> str | None:
            """Return an error string if the URL is unsafe, else None."""
            import ipaddress as _ip
            import urllib.parse as _up
            try:
                p = _up.urlparse(url)
            except Exception:
                return "Malformed URL"
            if p.scheme not in ("http", "https"):
                return f"Scheme '{p.scheme}' not allowed; use http or https"
            host = (p.hostname or "").lower()
            if not host:
                return "Missing host"
            if host in ("localhost",):
                return f"Host '{host}' is not a routable address"
            try:
                addr = _ip.ip_address(host)
                if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved or addr.is_multicast:
                    return f"Host '{host}' resolves to a non-routable address"
            except ValueError:
                pass  # hostname — routable check happens at DNS time
            return None

        @app.post("/api/v1/auth/test")
        async def api_auth_test(request: Request):
            """Preflight credential check — validates auth before launching a scan.

            Sends a single HTTP request using the supplied credentials and returns
            whether the server responded with a non-4xx/5xx status.  Secrets are
            accepted in the request body but never logged.
            """
            _require_auth(request, Role.OPERATOR)
            body = await request.json()
            auth_type   = body.get("auth_type", "form")
            username    = body.get("username", "")
            password    = body.get("password", "")    # used, never logged
            token       = body.get("token", "")       # used, never logged
            header_name = body.get("header_name", "Authorization")
            cookie_jar  = body.get("cookie_jar", "")  # used, never logged
            login_url   = body.get("login_url", "").strip()

            import re as _re
            cookie_jar = _re.sub(r"^cookie:\s*", "", cookie_jar, flags=_re.IGNORECASE)

            if not login_url:
                return JSONResponse({"success": False, "message": "login_url is required"})

            url_err = _validate_preflight_url(login_url)
            if url_err:
                return JSONResponse({"success": False, "message": f"Invalid login_url: {url_err}"})

            del auth_type, username, password, token, header_name, cookie_jar
            return JSONResponse(
                {
                    "success": False,
                    "status": "not_authorized",
                    "reason_code": "outbound_policy_unsupported",
                    "message": (
                        "Credential preflight is disabled until an exact, "
                        "module-bound outbound authorization is supplied"
                    ),
                }
            )

        @app.post("/api/v1/scans/{scan_id}/pause")
        async def api_scan_pause(request: Request, scan_id: str):
            payload = _require_auth(request, Role.OPERATOR)
            try:
                job = server._durable_job_state().pause_job(
                    scan_id,
                    tenant_id=server.tenant_id,
                    actor=TransitionActor(
                        tenant_id=server.tenant_id,
                        actor_id=payload.username,
                        role=payload.role.value,
                    ),
                    reason="operator pause",
                )
            except (InvalidTransition, KeyError) as exc:
                raise HTTPException(
                    status_code=409,
                    detail={"reason_code": "job_pause_rejected"},
                ) from exc
            server._write_scan_control_files(
                scan_id, {"paused": True, "aborted": False}
            )
            try:
                server._signal_scan_processes(scan_id, "pause")
            except DashboardArtifactError as exc:
                server._durable_job_state().cancel_job(
                    scan_id,
                    tenant_id=server.tenant_id,
                    actor=TransitionActor(
                        tenant_id=server.tenant_id,
                        actor_id="pause-enforcement-failure",
                        role="system",
                    ),
                    reason="process pause could not be enforced",
                    supervisor=server._job_process_supervisor,
                    sla_seconds=5.0,
                )
                server._write_scan_control_files(
                    scan_id,
                    {"paused": False, "aborted": True},
                )
                raise HTTPException(
                    status_code=409,
                    detail={"reason_code": "job_pause_enforcement_failed"},
                ) from exc
            return {"status": job["state"], "job": job}

        @app.post("/api/v1/scans/{scan_id}/resume")
        async def api_scan_resume(request: Request, scan_id: str):
            payload = _require_auth(request, Role.OPERATOR)
            _require_not_killed()
            try:
                job = server._durable_job_state().resume_job(
                    scan_id,
                    tenant_id=server.tenant_id,
                    actor=TransitionActor(
                        tenant_id=server.tenant_id,
                        actor_id=payload.username,
                        role=payload.role.value,
                    ),
                    reason="operator resume",
                )
            except (InvalidTransition, LeaseError, KeyError) as exc:
                raise HTTPException(
                    status_code=409,
                    detail={"reason_code": "job_resume_rejected"},
                ) from exc
            server._write_scan_control_files(
                scan_id, {"paused": False, "aborted": False}
            )
            try:
                server._signal_scan_processes(scan_id, "resume")
            except DashboardArtifactError as exc:
                server._durable_job_state().cancel_job(
                    scan_id,
                    tenant_id=server.tenant_id,
                    actor=TransitionActor(
                        tenant_id=server.tenant_id,
                        actor_id="resume-enforcement-failure",
                        role="system",
                    ),
                    reason="process resume could not be enforced",
                    supervisor=server._job_process_supervisor,
                    sla_seconds=5.0,
                )
                server._write_scan_control_files(
                    scan_id,
                    {"paused": False, "aborted": True},
                )
                raise HTTPException(
                    status_code=409,
                    detail={"reason_code": "job_resume_enforcement_failed"},
                ) from exc
            return {"status": job["state"], "job": job}

        @app.post("/api/v1/scans/{scan_id}/cancel")
        async def api_scan_cancel(request: Request, scan_id: str):
            payload = _require_auth(request, Role.OPERATOR)
            try:
                job = server._durable_job_state().cancel_job(
                    scan_id,
                    tenant_id=server.tenant_id,
                    actor=TransitionActor(
                        tenant_id=server.tenant_id,
                        actor_id=payload.username,
                        role=payload.role.value,
                    ),
                    reason="operator cancellation",
                    supervisor=server._job_process_supervisor,
                    sla_seconds=5.0,
                )
            except (InvalidTransition, LeaseError, KeyError) as exc:
                raise HTTPException(
                    status_code=409,
                    detail={"reason_code": "job_cancel_rejected"},
                ) from exc
            server._write_scan_control_files(
                scan_id, {"paused": False, "aborted": True}
            )
            return {"status": job["state"], "job": job}

        @app.post("/api/v1/scans/{scan_id}/retry")
        async def api_scan_retry(request: Request, scan_id: str):
            payload = _require_auth(request, Role.OPERATOR)
            _require_not_killed()
            try:
                job = server._durable_job_state().retry_job(
                    scan_id,
                    tenant_id=server.tenant_id,
                    actor=TransitionActor(
                        tenant_id=server.tenant_id,
                        actor_id=payload.username,
                        role=payload.role.value,
                    ),
                    reason="operator retry",
                )
            except (InvalidTransition, KeyError) as exc:
                raise HTTPException(
                    status_code=409,
                    detail={"reason_code": "job_retry_rejected"},
                ) from exc
            return {"status": job["state"], "job": job}

        @app.post("/api/v1/control/pause")
        async def api_pause(request: Request):
            """Compatibility control that pauses each durable active job."""
            payload = _require_auth(request, Role.OPERATOR)
            paused = []
            for row in server._durable_job_state().list_jobs(
                tenant_id=server.tenant_id,
                states=(
                    JobState.PLANNED,
                    JobState.PENDING_APPROVAL,
                    JobState.QUEUED,
                    JobState.LEASED,
                    JobState.RUNNING,
                ),
                limit=1000,
            ):
                try:
                    server._durable_job_state().pause_job(
                        str(row["id"]),
                        tenant_id=server.tenant_id,
                        actor=TransitionActor(
                            tenant_id=server.tenant_id,
                            actor_id=payload.username,
                            role=payload.role.value,
                        ),
                    )
                    paused.append(str(row["id"]))
                except InvalidTransition:
                    continue
            server._write_all_control_files({"paused": True, "aborted": False})
            for scan_id in list(paused):
                try:
                    server._signal_scan_processes(scan_id, "pause")
                except DashboardArtifactError:
                    server._durable_job_state().cancel_job(
                        scan_id,
                        tenant_id=server.tenant_id,
                        actor=TransitionActor(
                            tenant_id=server.tenant_id,
                            actor_id="pause-enforcement-failure",
                            role="system",
                        ),
                        reason="process pause could not be enforced",
                        supervisor=server._job_process_supervisor,
                        sla_seconds=5.0,
                    )
                    server._write_scan_control_files(
                        scan_id,
                        {"paused": False, "aborted": True},
                    )
                    paused.remove(scan_id)
            server.event_bus.emit_simple(
                EventType.SCAN_PAUSED, source="dashboard",
            )
            _audit(request, "control.pause", payload=payload)
            return {"status": "paused", "jobs": paused}

        @app.post("/api/v1/control/resume")
        async def api_resume(request: Request):
            """Resume a paused scan."""
            payload = _require_auth(request, Role.OPERATOR)
            _require_not_killed()
            resumed = []
            for row in server._durable_job_state().list_jobs(
                tenant_id=server.tenant_id,
                states=(JobState.PAUSED,),
                limit=1000,
            ):
                try:
                    server._durable_job_state().resume_job(
                        str(row["id"]),
                        tenant_id=server.tenant_id,
                        actor=TransitionActor(
                            tenant_id=server.tenant_id,
                            actor_id=payload.username,
                            role=payload.role.value,
                        ),
                    )
                    resumed.append(str(row["id"]))
                except (InvalidTransition, LeaseError):
                    continue
            server._write_all_control_files({"paused": False, "aborted": False})
            for scan_id in list(resumed):
                try:
                    server._signal_scan_processes(scan_id, "resume")
                except DashboardArtifactError:
                    server._durable_job_state().cancel_job(
                        scan_id,
                        tenant_id=server.tenant_id,
                        actor=TransitionActor(
                            tenant_id=server.tenant_id,
                            actor_id="resume-enforcement-failure",
                            role="system",
                        ),
                        reason="process resume could not be enforced",
                        supervisor=server._job_process_supervisor,
                        sla_seconds=5.0,
                    )
                    server._write_scan_control_files(
                        scan_id,
                        {"paused": False, "aborted": True},
                    )
                    resumed.remove(scan_id)
            server.event_bus.emit_simple(
                EventType.SCAN_RESUMED, source="dashboard",
            )
            _audit(request, "control.resume", payload=payload)
            return {"status": "resumed", "jobs": resumed}

        @app.post("/api/v1/control/abort")
        async def api_abort(request: Request):
            """Abort the current scan."""
            payload = _require_auth(request, Role.ADMIN)
            server._write_all_control_files({"paused": False, "aborted": True})
            killed = server._terminate_active_scans(status="aborted")
            server.event_bus.emit_simple(
                EventType.SCAN_ABORTED, source="dashboard", killed=killed,
            )
            _audit(
                request,
                "control.abort",
                status="ok",
                detail={"killed": killed},
                payload=payload,
            )
            return {"status": "aborted", "killed": killed}

        @app.post("/api/v1/control/kill-switch")
        async def api_kill_switch(request: Request):
            """Toggle the operator kill switch for active execution paths."""
            payload = _require_auth(request, Role.ADMIN)
            body = await request.json()
            enabled = bool(body.get("enabled", True))
            reason = str(body.get("reason", "")).strip()[:500]
            if enabled:
                server._write_all_control_files({"paused": False, "aborted": True})
                killed = server._terminate_active_scans(status="aborted")
            else:
                killed = []
            state = server._set_kill_switch(enabled, reason=reason, operator=payload.username)
            server.event_bus.emit_simple(
                EventType.CONTROL_COMMAND,
                source="dashboard",
                command="kill_switch",
                enabled=enabled,
                killed=killed,
                reason=state["reason"],
            )
            _audit(
                request,
                "control.kill_switch",
                status="enabled" if enabled else "disabled",
                detail={"enabled": enabled, "reason": state["reason"], "killed": killed},
                payload=payload,
            )
            return {"status": "enabled" if enabled else "disabled", "state": state, "killed": killed}

        @app.post("/api/v1/control/skip-module")
        async def api_skip_module(request: Request):
            """Skip the currently running module."""
            _require_auth(request, Role.OPERATOR)
            body = await request.json()
            module_name = body.get("module", "")
            server.event_bus.emit_simple(
                EventType.CONTROL_COMMAND, source="dashboard",
                command="skip_module", module=module_name,
            )
            return {"status": "skip_requested", "module": module_name}

        # ── Scan launch ───────────────────────────────────────────────

        @app.post("/api/v1/action-confirmations")
        async def api_action_confirmations(request: Request):
            """Prepare exact, short-lived confirmations without launching work."""
            payload = _require_auth(request, Role.OPERATOR)
            _require_not_killed()
            try:
                body = await request.json()
            except Exception:
                body = {}
            if not isinstance(body, dict):
                body = {}
            try:
                result = server._prepare_dashboard_confirmation_bundle(body)
            except HTTPException as exc:
                detail: dict[str, Any] = (
                    exc.detail if isinstance(exc.detail, dict) else {}
                )
                _audit(
                    request,
                    "action.confirmation.prepare",
                    status="denied",
                    detail={
                        "reason_code": detail.get(
                            "reason_code",
                            ScopeReason.INVALID_CONFIRMATION.value,
                        )
                    },
                    payload=payload,
                )
                raise
            _audit(
                request,
                "action.confirmation.prepare",
                object_id=str(result["job_id"]),
                status="prepared",
                detail={
                    "intent": str(body.get("intent") or ""),
                    "actions": [
                        {
                            "engine": item["engine"],
                            "action": item["action"],
                        }
                        for item in result["actions"]
                    ],
                    "authorized": False,
                },
                payload=payload,
            )
            return result

        @app.post("/api/v1/scans/start")
        async def api_scan_start(request: Request):
            """Launch explicitly scoped and confirmed scanner subprocesses."""
            payload = _require_auth(request, Role.OPERATOR)
            _require_not_killed()
            body = await request.json()
            job_id = server._server_job_id()

            def _deny_preflight(
                decision: ScopeDecision,
                *,
                engine: str | None = None,
                original_error: HTTPException | None = None,
            ) -> NoReturn:
                requested_type = str(body.get("scan_type", "web")).strip().lower()
                selected_engine = engine or (
                    "netforge" if requested_type == "net" else "webforge"
                )
                server._audit_preflight_denial(
                    decision,
                    action_kind="scan",
                    engine=selected_engine,
                    target=body.get("target"),
                    allowed_scope=body.get("scope", []),
                    excluded_scope=(
                        body.get("exclude")
                        if body.get("exclude") is not None
                        else body.get("excluded_scope", [])
                    ),
                    job_id=job_id,
                    operator_id=payload.username if payload else "operator",
                    operator_role=(
                        payload.role.value if payload else Role.ADMIN.value
                    ),
                )
                if original_error is not None:
                    raise original_error
                server._raise_scope_denial(decision)

            submitted_target = body.get("target")
            if not isinstance(submitted_target, str):
                _deny_preflight(decision_for_reason(ScopeReason.MALFORMED_TARGET))
            raw_target = submitted_target.strip()
            if not raw_target:
                _deny_preflight(decision_for_reason(ScopeReason.MALFORMED_TARGET))
            scan_type = str(body.get("scan_type", "web")).strip().lower()
            mode = str(body.get("mode", "blackbox")).strip().lower()
            try:
                dry_run = server._request_bool(body, "dry_run", default=False)
            except HTTPException:
                _deny_preflight(
                    decision_for_reason(ScopeReason.INVALID_CONFIRMATION)
                )

            _VALID_MODES = {"blackbox", "greybox", "whitebox"}
            if mode not in _VALID_MODES:
                _deny_preflight(
                    decision_for_reason(ScopeReason.INVALID_CONFIRMATION),
                    original_error=HTTPException(
                        status_code=400,
                        detail=(
                            f"Invalid mode '{mode}'. Must be one of: "
                            f"{', '.join(sorted(_VALID_MODES))}"
                        ),
                    ),
                )
            _VALID_SCAN_TYPES = {"web", "net", "vapt"}
            if scan_type not in _VALID_SCAN_TYPES:
                _deny_preflight(
                    decision_for_reason(ScopeReason.INVALID_CONFIRMATION),
                    original_error=HTTPException(
                        status_code=400,
                        detail=(
                            f"Invalid scan_type '{scan_type}'. Must be one of: "
                            f"{', '.join(sorted(_VALID_SCAN_TYPES))}"
                        ),
                    ),
                )

            source_root = ""
            if mode == "whitebox" and scan_type in {"web", "vapt"}:
                try:
                    source_root = server._validated_whitebox_source_root(body)
                except ValueError as exc:
                    _deny_preflight(
                        decision_for_reason(ScopeReason.INVALID_CONFIRMATION),
                        original_error=HTTPException(status_code=400, detail=str(exc)),
                    )

            # Extract credential inputs before authorization so the decision is
            # bound to the exact secret material the child will receive.  Only
            # the opaque reference is persisted in the envelope.
            auth_profile = body.get("auth_profile") or {}
            if not isinstance(auth_profile, dict):
                _deny_preflight(
                    decision_for_reason(ScopeReason.INVALID_CONFIRMATION)
                )

            def _profile_text(field: str, default: str = "") -> str:
                value = auth_profile.get(field, body.get(field, default))
                if not isinstance(value, str):
                    _deny_preflight(
                        decision_for_reason(ScopeReason.INVALID_CONFIRMATION)
                    )
                return value.strip()

            auth_type = _profile_text("auth_type", "form")
            username = _profile_text("username")
            login_url_ = _profile_text("login_url")
            header_name = _profile_text("header_name", "Authorization")
            password = _profile_text("password")
            token = _profile_text("token")
            cookie_jar = _profile_text("cookie_jar")
            cookie_jar = re.sub(
                r"^cookie:\s*", "", cookie_jar, flags=re.IGNORECASE
            )
            web_credential_reference = ""
            web_credential_bundle: ProtectedCredentialBundle | None = None
            if mode != "blackbox" and any(
                (username, password, token, cookie_jar)
            ):
                credential_values = {
                    key: value
                    for key, value in {
                        "password": password,
                        "token": token,
                        "cookie": cookie_jar,
                    }.items()
                    if value
                }
                if dry_run:
                    web_credential_reference = protected_credential_reference(
                        credential_values
                    )
                else:
                    web_credential_bundle = server._request_credential_bundle(
                        request,
                        credential_values,
                        ttl_seconds=60,
                    )
                    web_credential_reference = web_credential_bundle.reference.value
                wipe_mapping(credential_values)
                password = token = cookie_jar = ""
            raw_engagement = body.get("engagement", "Forge-VAPT-Demo")
            raw_tester = body.get("tester", PRODUCT_LABEL)
            if not isinstance(raw_engagement, str) or not isinstance(raw_tester, str):
                _deny_preflight(
                    decision_for_reason(ScopeReason.INVALID_CONFIRMATION)
                )
            engagement = raw_engagement.strip() or "default"
            tester = raw_tester.strip() or PRODUCT_LABEL

            try:
                client_job_id = server._client_job_id(body)
            except HTTPException:
                _deny_preflight(
                    decision_for_reason(ScopeReason.INVALID_CONFIRMATION)
                )
            run_id = f"run-{uuid.uuid4().hex}"
            engagement_name = engagement
            engagement_id = f"engagement-{uuid.uuid5(uuid.NAMESPACE_URL, engagement_name).hex}"
            operator_id = payload.username if payload else "operator"
            operator_role = payload.role.value if payload else Role.ADMIN.value
            allowed_scope, excluded_scope = server._launch_scope_inputs(body)
            target = raw_target
            if scan_type in {"web", "vapt"} and not target.startswith(("http://", "https://")):
                target = "https://" + target

            network_target: str | None = None
            web_allowed_scope = allowed_scope
            net_allowed_scope = allowed_scope
            if scan_type == "net":
                # Ordinary NetForge launches retain its documented hostname and
                # CIDR target contract. Exact-IP binding is specific to the
                # separately approved WebForge-to-NetForge escalation below.
                network_target = raw_target
                target = raw_target
            elif scan_type == "vapt":
                network_target = server._exact_ip(body.get("network_target"))
                if network_target is None:
                    _deny_preflight(
                        decision_for_reason(ScopeReason.MALFORMED_TARGET),
                        engine="netforge",
                    )
                web_allowed_scope = server._scope_entries(body.get("web_scope"))
                if not web_allowed_scope:
                    _deny_preflight(
                        decision_for_reason(ScopeReason.MISSING_SCOPE),
                        engine="webforge",
                    )
                net_allowed_scope, net_scope_decision = (
                    server._exact_network_scope_inputs(
                        network_target,
                        body.get("network_scope"),
                        excluded_scope,
                    )
                )
                if not net_scope_decision.allowed:
                    _deny_preflight(net_scope_decision, engine="netforge")

            action_decisions: list[dict[str, Any]] = []
            web_confirmation: ActionConfirmation | None = None
            net_confirmation: ActionConfirmation | None = None
            web_context: AuthorizationContext | None = None
            net_context: AuthorizationContext | None = None
            web_authorization: ActionAuthorizationEnvelope | None = None
            net_authorization: ActionAuthorizationEnvelope | None = None
            if scan_type in {"web", "vapt"}:
                web_confirmation, submitted_web_decision = server._server_confirmation(
                    body,
                    client_job_id=client_job_id,
                    server_job_id=job_id,
                    target=target,
                    allowed_scope=web_allowed_scope,
                    excluded_scope=excluded_scope,
                    engine="webforge",
                    action="scan",
                    dry_run=dry_run,
                    specific_field="web_confirmation" if scan_type == "vapt" else "",
                )
                web_decision, web_confirmation, web_context = server._prepare_launch_action(
                    target=target,
                    allowed_scope=web_allowed_scope,
                    excluded_scope=excluded_scope,
                    confirmation=web_confirmation,
                    job_id=job_id,
                    engine="webforge",
                    action="scan",
                    dry_run=dry_run,
                    tenant_id=server.tenant_id,
                    engagement_id=engagement_id,
                    run_id=run_id,
                    operator_id=operator_id,
                    operator_role=operator_role,
                    safety_mode=SafetyMode.ACTIVE.value,
                    credential_reference=web_credential_reference,
                    prior_decision=submitted_web_decision,
                )
                action_decisions.append({
                    "engine": "webforge",
                    "action": "scan",
                    "decision": web_decision.to_dict(),
                    "authorization": None,
                })

            if scan_type in {"net", "vapt"}:
                net_action = "web_to_network" if scan_type == "vapt" else "scan"
                net_confirmation, submitted_net_decision = server._server_confirmation(
                    body,
                    client_job_id=client_job_id,
                    server_job_id=job_id,
                    target=network_target or target,
                    allowed_scope=net_allowed_scope,
                    excluded_scope=excluded_scope,
                    engine="netforge",
                    action=net_action,
                    dry_run=dry_run,
                    specific_field="network_confirmation" if scan_type == "vapt" else "",
                )
                net_decision, net_confirmation, net_context = server._prepare_launch_action(
                    target=network_target or target,
                    allowed_scope=net_allowed_scope,
                    excluded_scope=excluded_scope,
                    confirmation=net_confirmation,
                    job_id=job_id,
                    engine="netforge",
                    action=net_action,
                    dry_run=dry_run,
                    tenant_id=server.tenant_id,
                    engagement_id=engagement_id,
                    run_id=run_id,
                    operator_id=operator_id,
                    operator_role=operator_role,
                    safety_mode=SafetyMode.ACTIVE.value,
                    prior_decision=submitted_net_decision,
                )
                action_decisions.append({
                    "engine": "netforge",
                    "action": net_action,
                    "decision": net_decision.to_dict(),
                    "authorization": None,
                })

            if dry_run:
                return {
                    "status": "planned",
                    "job_id": job_id,
                    "client_job_id": client_job_id,
                    "scan_id": job_id,
                    "target": target,
                    "scan_type": scan_type,
                    "dry_run": True,
                    "authorized": False,
                    "actions": action_decisions,
                }

            try:
                results_root = server._allocate_scan_results_dir(job_id)
            except DashboardArtifactError:
                raise HTTPException(
                    status_code=500,
                    detail="Scan result boundary is unavailable",
                ) from None

            # Escalation is separately approved before DNS; the current answer must
            # then include the exact approved network target before any process exists.
            if scan_type == "vapt":
                try:
                    hostname = urlsplit(target).hostname or ""
                except Exception:
                    hostname = ""
                if not server._hostname_resolves_to_exact_ip(
                    hostname,
                    network_target,
                ):
                    server._record_launch_context_denial(
                        net_context,
                        reason=AuthorizationReason.RESOLVED_TARGET_MISMATCH,
                    )
                    server._raise_scope_denial(decision_for_reason(ScopeReason.TARGET_MISMATCH))

            prepared_actions = [
                (context, confirmation)
                for context, confirmation in (
                    (web_context, web_confirmation),
                    (net_context, net_confirmation),
                )
                if context is not None and confirmation is not None
            ]
            committed = server._commit_launch_authorizations(
                prepared_actions,
                job_record={
                    "status": "pending",
                    "target": target,
                    "frameworks": [
                        framework
                        for framework, enabled in (
                            ("web", scan_type in {"web", "vapt"}),
                            ("net", scan_type in {"net", "vapt"}),
                        )
                        if enabled
                    ],
                    "modules": [],
                    "logs": {},
                    "results_dir": str(results_root),
                    "created_at": datetime.now(timezone.utc),
                },
            )
            committed_iter = iter(committed)
            if web_context is not None:
                web_authorization = next(committed_iter)
            if net_context is not None:
                net_authorization = next(committed_iter)
            for item, authorization in zip(action_decisions, committed):
                item["authorization"] = authorization.to_event_payload()

            # Build subprocess env. Secret values use an inherited one-shot pipe;
            # argv and environment contain only the opaque reference and FD id.
            import os as _os
            scan_env = minimal_child_environment(
                _os.environ,
                allowlist={"FORGE_TENANT_ID"},
            )
            if mode != "blackbox":
                scan_env["FORGE_AUTH_TYPE"] = auth_type

            log.info(
                "Scan requested: target=%s type=%s mode=%s auth=%s username=%s password=<redacted>",
                safe_target_display(target), scan_type, mode, auth_type, username or "—",
            )

            # Determine dashboard URL for event relay
            dash_url = server._dashboard_public_url(request)

            forge_root = Path(__file__).parent.parent.parent  # forge-suite/
            scan_id = job_id
            control_file = server._init_control_file(scan_id)

            # Clean env for netforge — it doesn't consume FORGE_* credential vars
            net_scan_env = {k: v for k, v in scan_env.items() if not k.startswith("FORGE_")}

            def _build_cmd(framework: str, net_target: str | None = None) -> list[str]:
                script = str(forge_root / framework / f"{framework}.py")
                effective_target = net_target if (framework == "netforge" and net_target) else target
                if framework == "netforge":
                    cmd = [
                        sys.executable, script,
                        "--target", effective_target,
                        "--mode", "external",
                        "--engagement", engagement,
                        "--dashboard-url", dash_url,
                        "--control-file", str(control_file),
                        "--output", str(results_root / "netforge"),
                    ]
                    server._append_scope_args(
                        cmd,
                        net_allowed_scope,
                        excluded_scope,
                    )
                    return cmd
                cmd = [
                    sys.executable, script,
                    "--target", effective_target,
                    "--mode", mode,
                    "--engagement", engagement,
                    "--tester", tester,
                    "--dashboard-url", dash_url,
                    "--control-file", str(control_file),
                    "--report-format", "html,json",
                    "--output", str(results_root / "webforge"),
                ]
                # Non-secret auth args — username, login_url, header_name are safe in argv
                if mode != "blackbox":
                    cmd += ["--auth-type", auth_type]
                    if username:    cmd += ["--username", username]
                    if login_url_:  cmd += ["--login-url", login_url_]
                    if header_name and auth_type == "bearer":
                        cmd += ["--header-name", header_name]
                if source_root:
                    cmd += ["--source-root", source_root]
                # NEVER: cmd += ["--password", password] or ["--token", token]
                server._append_scope_args(
                    cmd,
                    web_allowed_scope,
                    excluded_scope,
                )
                return cmd

            launch_specs: list[tuple[str, str, list[str], dict[str, str]]] = []
            if scan_type in {"web", "vapt"}:
                assert web_confirmation is not None
                assert web_authorization is not None
                launch_specs.append((
                    scan_id + "_web",
                    "web",
                    _build_cmd("webforge"),
                    server._launch_env(
                        scan_env,
                        web_confirmation,
                        web_authorization,
                        job_id,
                        "scan",
                    ),
                ))
            if scan_type in {"net", "vapt"}:
                assert net_confirmation is not None
                assert net_authorization is not None
                launch_specs.append((
                    scan_id + "_net",
                    "net",
                    _build_cmd("netforge", net_target=network_target or target),
                    server._launch_env(
                        net_scan_env,
                        net_confirmation,
                        net_authorization,
                        job_id,
                        net_action,
                    ),
                ))

            authorization_map: dict[str, ActionAuthorizationEnvelope] = {}
            if web_authorization is not None:
                authorization_map["webforge"] = web_authorization
            if net_authorization is not None:
                authorization_map["netforge"] = net_authorization
            prepared = server._prepare_durable_scan_job(
                scan_id=scan_id,
                target=target,
                process_specs=[
                    (key, framework_name)
                    for key, framework_name, _cmd, _env in launch_specs
                ],
                authorizations=authorization_map,
                modules=[],
                results_dir=str(results_root),
                control_file=control_file,
                actor_id=operator_id,
                actor_role=operator_role,
            )
            spawned: list[tuple[str, str, list[str], subprocess.Popen[str]]] = []
            try:
                for key, framework_name, cmd, child_env in launch_specs:
                    intent = cast(Mapping[str, Any], prepared["intents"])[key]
                    child_env = {
                        **child_env,
                        JOB_ATTEMPT_ID_ENV: str(
                            cast(Mapping[str, Any], prepared["attempt"])["id"]
                        ),
                        f"{JOB_ATTEMPT_ID_ENV}_LAUNCH_NONCE": str(
                            intent["launch_nonce"]
                        ),
                    }
                    if framework_name == "web" and web_credential_bundle is not None:
                        with web_credential_bundle.open_pipe() as handoff:
                            protected_env = {**child_env, **handoff.env}
                            proc = subprocess.Popen(
                                cmd,
                                cwd=str(forge_root),
                                env=protected_env,
                                pass_fds=handoff.pass_fds,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT,
                                text=True,
                            )
                    else:
                        proc = subprocess.Popen(
                            cmd,
                            cwd=str(forge_root),
                            env=child_env,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT,
                            text=True,
                        )
                    spawned.append((key, framework_name, cmd, proc))
            except Exception as exc:
                server._abort_durable_scan_launch(
                    scan_id=scan_id,
                    prepared=prepared,
                    processes={key: child for key, _framework, _cmd, child in spawned},
                    control_file=control_file,
                    reason="dashboard process launch failed",
                )
                log.error("Failed to launch scan reason=%s", type(exc).__name__)
                raise HTTPException(
                    status_code=500,
                    detail="Failed to launch scan; execution denied",
                ) from exc
            finally:
                if web_credential_bundle is not None:
                    web_credential_bundle.wipe()

            launched: list[str] = []
            for key, framework_name, cmd, proc in spawned:
                process_target = target if framework_name == "web" else (network_target or target)
                server._active_scans[key] = {
                    "proc": proc,
                    "type": framework_name,
                    "target": process_target,
                    "started_at": time.time(),
                    "engagement": engagement,
                    "mode": mode if framework_name == "web" else "external",
                    "status": "leased",
                    "started_dt": datetime.now(timezone.utc).isoformat(),
                    "control_file": str(control_file),
                    "command": server._sanitize_cmd(cmd),
                    "dashboard_url": dash_url,
                    "results_dir": str(results_root),
                }
                launched.append(framework_name)

            try:
                server._activate_durable_scan_processes(
                    scan_id=scan_id,
                    prepared=prepared,
                    control_file=control_file,
                    actor_id=operator_id,
                    actor_role=operator_role,
                )
            except Exception as exc:
                server._abort_durable_scan_launch(
                    scan_id=scan_id,
                    prepared=prepared,
                    processes={key: child for key, _framework, _cmd, child in spawned},
                    control_file=control_file,
                    reason="dashboard process identity activation failed",
                )
                raise HTTPException(
                    status_code=500,
                    detail="Failed to bind scan process identity; execution denied",
                ) from exc
            for key, _framework_name, _cmd, _proc in spawned:
                server._active_scans[key]["status"] = "running"
                server._track_scan_process(key, server._active_scans[key])

            # Persist scan record to history DB
            server._write_scan_history(
                scan_id=scan_id, target=target, scan_type=scan_type,
                mode=mode, engagement=engagement, frameworks=launched,
            )
            server._write_scan_job(
                scan_id=scan_id,
                target=target,
                frameworks=launched,
                modules=[],
                results_dir=str(results_root),
                authorization=web_authorization or net_authorization,
            )

            event_authorization = web_authorization or net_authorization
            server.event_bus.emit_simple(
                EventType.SCAN_START, source="dashboard",
                target=safe_target_display(target), scan_type=scan_type, mode=mode,
                engagement=engagement, scan_id=scan_id,
                resolved_ip=network_target or "",
                authorization=(
                    event_authorization.to_event_payload()
                    if event_authorization is not None
                    else None
                ),
            )
            _audit(
                request,
                "scan.start",
                object_id=scan_id,
                detail={
                    "target": safe_target_display(target),
                    "scan_type": scan_type,
                    "mode": mode,
                    "frameworks": launched,
                    "scope_decisions": action_decisions,
                },
                payload=payload,
            )

            return {
                "status": "launched",
                "scan_id": scan_id,
                "client_job_id": client_job_id,
                "target": target,
                "scan_type": scan_type,
                "mode": mode,
                "frameworks": launched,
                "resolved_ip": network_target,
                "dashboard_url": dash_url,
            }

        @app.get("/api/v1/scans/status")
        async def api_scan_status(request: Request):
            """Return status of all tracked scan subprocesses."""
            _require_auth(request)
            running = []
            completed = []
            durable_rows = server._durable_jobs_for_read_projection(limit=1000)
            durable_by_id = {
                str(row.get("scan_id") or ""): row for row in durable_rows
            }
            seen_job_ids: set[str] = set()
            for key, info in list(server._active_scans.items()):
                proc = info["proc"]
                rc = info.get("returncode")
                root_scan_id = server._base_scan_id(key)
                durable = durable_by_id.get(root_scan_id)
                authoritative_status = (
                    str(durable.get("status"))
                    if durable is not None
                    else "orphaned"
                )
                if durable is not None:
                    seen_job_ids.add(root_scan_id)
                entry = {
                    "scan_id": key,
                    "root_scan_id": root_scan_id,
                    "pid": getattr(proc, "pid", None),
                    "type": info["type"],
                    "target": info["target"],
                    "engagement": info.get("engagement", ""),
                    "started_at": info["started_at"],
                    "started_at_iso": info.get("started_dt"),
                    "returncode": rc,
                    "status": authoritative_status,
                    "lifecycle_authority": (
                        "task103" if durable is not None else "unverified_legacy"
                    ),
                    "control_file": info.get("control_file", ""),
                    "dashboard_url": info.get("dashboard_url", ""),
                    "requested_modules": info.get("requested_modules", []),
                    "actual_modules": info.get("actual_modules", []),
                    "scan_options": info.get("scan_options", {}),
                    "control": info.get("control", {}),
                    "log_path": str(server._scan_logs_dir / f"{key}.log"),
                }
                if authoritative_status not in {
                    JobState.CANCELED.value,
                    JobState.PARTIAL.value,
                    JobState.FAILED.value,
                    JobState.COMPLETED.value,
                    JobState.EXPIRED.value,
                    JobState.ORPHANED.value,
                }:
                    running.append(entry)
                else:
                    completed.append(entry)
            for scan_id, durable in durable_by_id.items():
                if not scan_id or scan_id in seen_job_ids:
                    continue
                entry = {
                    "scan_id": scan_id,
                    "root_scan_id": scan_id,
                    "pid": None,
                    "type": durable.get("scan_type", "scan"),
                    "target": durable.get("target", ""),
                    "engagement": durable.get("engagement", ""),
                    "started_at": durable.get("started_at"),
                    "started_at_iso": durable.get("started_at"),
                    "returncode": None,
                    "status": durable.get("status", "unknown"),
                    "lifecycle_authority": "task103",
                    "control_file": "",
                    "dashboard_url": "",
                    "requested_modules": durable.get("requested_modules", []),
                    "actual_modules": durable.get("actual_modules", []),
                    "scan_options": {},
                    "control": {},
                    "log_path": "",
                }
                if str(entry["status"]) in {
                    JobState.CANCELED.value,
                    JobState.PARTIAL.value,
                    JobState.FAILED.value,
                    JobState.COMPLETED.value,
                    JobState.EXPIRED.value,
                    JobState.ORPHANED.value,
                }:
                    completed.append(entry)
                else:
                    running.append(entry)
            return {"running": running, "completed": completed}

        @app.post("/api/v1/scans/stop")
        async def api_scan_stop(request: Request):
            """Kill all running scan subprocesses."""
            payload = _require_auth(request, Role.OPERATOR)
            server._write_all_control_files({"paused": False, "aborted": True})
            killed = server._terminate_active_scans(status="stopped")
            server.event_bus.emit_simple(
                EventType.SCAN_ABORTED, source="dashboard", reason="operator_stop",
            )
            _audit(
                request,
                "scan.stop",
                status="ok",
                detail={"killed": killed},
                payload=payload,
            )
            return {"status": "stopped", "killed": killed}

        @app.get("/api/v1/scans/history")
        async def api_scan_history(request: Request, limit: int = Query(default=50, le=200)):
            """Return scan history across all past and current engagements.

            Combines in-memory active scans with persisted records from the
            scan history JSON store. Sorted newest-first.
            """
            _require_auth(request)
            history = server._load_scan_history(limit=limit)
            return {"history": history, "total": len(history)}

        @app.post("/api/v1/scans/fingerprints/plan")
        async def api_scan_fingerprint_plan(request: Request):
            """Plan incremental scanning from passive host/service facts."""
            _require_auth(request, Role.OPERATOR)
            body = await request.json()
            fingerprints = server._scan_fingerprints_from_payload(body)
            plan = server._scan_fingerprint_store().plan_rescan(fingerprints)
            return plan.to_dict()

        @app.post("/api/v1/scans/fingerprints/record")
        async def api_scan_fingerprint_record(request: Request):
            """Persist last-scan fingerprints after a completed scan."""
            _require_auth(request, Role.OPERATOR)
            body = await request.json()
            fingerprints = server._scan_fingerprints_from_payload(body)
            store = server._scan_fingerprint_store()
            records = [
                store.record_scan(
                    fingerprint,
                    scanned_at=body.get("scanned_at"),
                    metadata=body.get("metadata") or {},
                )
                for fingerprint in fingerprints
            ]
            store.save()
            return {"recorded": len(records), "records": records}

        @app.post("/api/v1/scans/rate-adapt")
        async def api_scan_rate_adapt(request: Request):
            """Adapt per-service request rate from passive failure/success signals."""
            _require_auth(request, Role.OPERATOR)
            body = await request.json()
            if not isinstance(body, dict):
                raise HTTPException(
                    status_code=400,
                    detail={"reason_code": _SCAN_FINGERPRINT_INPUT_INVALID},
                )
            try:
                fingerprint = server._scan_fingerprint_from_payload(body)
            except (TypeError, ValueError):
                raise HTTPException(
                    status_code=400,
                    detail={"reason_code": _SCAN_FINGERPRINT_INPUT_INVALID},
                ) from None
            store = server._scan_fingerprint_store()
            policy_args = body.get("policy") if isinstance(body.get("policy"), dict) else {}
            from common.scan_fingerprint import RatePolicy

            try:
                policy = RatePolicy(**policy_args) if policy_args else None
                adaptation = store.adapt_rate(
                    fingerprint,
                    body.get("signal", ""),
                    policy=policy,
                    updated_at=body.get("updated_at"),
                )
            except (TypeError, ValueError):
                return JSONResponse(
                    {
                        "error": "Unsupported rate signal",
                        "reason_code": _SCAN_RATE_INPUT_INVALID,
                    },
                    status_code=400,
                )
            store.save()
            return adaptation.to_dict()

        @app.get("/api/v1/scans/{scan_id}")
        async def api_scan_detail(request: Request, scan_id: str):
            """Return a single scan's status, subprocesses, logs, reports, and findings."""
            _require_auth(request)
            detail = server._get_scan_detail(scan_id)
            if not detail:
                raise HTTPException(status_code=404, detail="Scan not found")
            return detail

        @app.get("/api/v1/scans/{scan_id}/logs")
        async def api_scan_logs(
            request: Request,
            scan_id: str,
            tail: int = Query(default=400, ge=1, le=5000),
        ):
            """Return persisted subprocess logs for a dashboard-launched scan."""
            _require_auth(request)
            detail = server._get_scan_detail(scan_id)
            if not detail:
                raise HTTPException(status_code=404, detail="Scan not found")
            log_entries = server._logs_for_scan(scan_id, max_lines=tail)
            return {"scan_id": scan_id, "logs": log_entries}

        @app.delete("/api/v1/scans/{scan_id}")
        async def api_scan_delete(
            request: Request,
            scan_id: str,
            purge_artifacts: bool = False,
        ):
            """Delete a scan from dashboard history; optionally purge result artifacts."""
            payload = _require_auth(request, Role.OPERATOR)
            try:
                deleted = server._delete_scan_record(
                    scan_id,
                    purge_artifacts=purge_artifacts,
                )
            except DashboardArtifactError:
                raise HTTPException(
                    status_code=409,
                    detail="Scan deletion would break canonical evidence lineage",
                ) from None
            if not deleted.get("found"):
                raise HTTPException(status_code=404, detail="Scan not found")
            server.event_bus.emit_simple(
                EventType.CONTROL_COMMAND,
                source="dashboard",
                command="delete_scan",
                scan_id=scan_id,
                purge_artifacts=purge_artifacts,
            )
            _audit(
                request,
                "scan.delete",
                object_id=scan_id,
                detail={"purge_artifacts": purge_artifacts, "found": deleted.get("found")},
                payload=payload,
            )
            return deleted

        # ── Scan Templates ─────────────────────────────────────────────

        @app.get("/api/v1/scan/templates")
        async def api_scan_templates(request: Request):
            """List saved scan templates."""
            _require_auth(request)
            templates_list = server._load_scan_templates()
            return {"templates": templates_list}

        @app.post("/api/v1/scan/templates")
        async def api_save_scan_template(request: Request):
            """Save a scan configuration as a reusable template."""
            _require_auth(request, Role.OPERATOR)
            body = await request.json()
            name = body.get("name", "").strip()
            if not name:
                raise HTTPException(status_code=400, detail="Template name is required")
            template = {
                "id": str(uuid.uuid4())[:8],
                "name": name,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "config": {
                    "target": body.get("target", ""),
                    "profile": body.get("profile", ""),
                    "modules": body.get("modules", []),
                    "mode": body.get("mode", "blackbox"),
                    "intensity": body.get("intensity", 2),
                    "maxThreads": body.get("maxThreads", 20),
                    "timeout": body.get("timeout", 30),
                    "rateLimit": body.get("rateLimit", 1000),
                    "maxDepth": body.get("maxDepth", 5),
                    "followRedirects": body.get("followRedirects", True),
                    "schedule": body.get("schedule", "now"),
                },
            }
            server._save_scan_template(template)
            return {"status": "saved", "template": template}

        @app.delete("/api/v1/scan/templates/{template_id}")
        async def api_delete_scan_template(request: Request, template_id: str):
            """Delete a scan template."""
            _require_auth(request, Role.OPERATOR)
            templates_list = server._load_scan_templates()
            templates_list = [t for t in templates_list if t.get("id") != template_id]
            server._write_scan_templates(templates_list)
            return {"status": "deleted"}

        # ── Findings Management ────────────────────────────────────────

        @app.patch("/api/v1/findings/{finding_id}/status")
        async def api_update_finding_status(request: Request, finding_id: str):
            """Update the status of a finding."""
            payload = _require_auth(request, Role.OPERATOR)
            body = await request.json()
            new_status = body.get("status", "").strip()
            valid = {
                "Open",
                "In Progress",
                "Fixed",
                "Accepted",
                "False Positive",
            }
            if new_status not in valid:
                raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: {', '.join(valid)}")
            persisted = server._persist_finding_status(finding_id, new_status)
            if not persisted:
                raise HTTPException(status_code=404, detail="Finding not found")
            # The event cache is a projection only. Update it after canonical
            # persistence succeeds so it can never become authoritative.
            for finding_entry in server.state_store.findings:
                if getattr(finding_entry, "id", "") == finding_id:
                    finding_entry.status = new_status
                    break
            server.event_bus.emit_simple(
                EventType.FINDING_UPDATED, source="dashboard",
                finding_id=finding_id, status=new_status,
            )
            _audit(
                request,
                "finding.status",
                object_id=finding_id,
                detail={"status": new_status, "canonical_status": server._canonical_finding_status(new_status)},
                payload=payload,
            )
            return {
                "status": "updated",
                "finding_id": finding_id,
                "new_status": new_status,
                "canonical_status": server._canonical_finding_status(new_status),
                "persisted": persisted,
            }

        @app.post("/api/v1/findings/{finding_id}/retest")
        async def api_retest_finding(request: Request, finding_id: str):
            """Run the exact canonical verifier for one persisted finding."""
            payload = _require_auth(request, Role.OPERATOR)
            _require_not_killed()
            try:
                body = await request.json()
            except Exception:
                body = {}
            job_id = server._server_job_id()
            try:
                dry_run = server._request_bool(body, "dry_run", default=True)
            except HTTPException:
                decision = decision_for_reason(ScopeReason.INVALID_CONFIRMATION)
                server._audit_preflight_denial(
                    decision,
                    action_kind="retest",
                    engine="forge",
                    target=finding_id,
                    allowed_scope=body.get("scope", []),
                    excluded_scope=body.get("exclude", []),
                    job_id=job_id,
                    operator_id=payload.username if payload else "operator",
                    operator_role=(
                        payload.role.value if payload else Role.ADMIN.value
                    ),
                )
                server._raise_scope_denial(decision)
            finding = server._find_finding_metadata(
                finding_id,
                actor_id=payload.username,
            )
            if not finding:
                raise HTTPException(status_code=404, detail="Finding not found")

            module = str(finding.get("module", "")).strip()
            target = str(finding.get("target") or finding.get("url") or "").strip()
            if not module or not target:
                decision = decision_for_reason(ScopeReason.MALFORMED_TARGET)
                server._audit_preflight_denial(
                    decision,
                    action_kind="retest",
                    engine="forge",
                    target=target or finding_id,
                    allowed_scope=body.get("scope", []),
                    excluded_scope=body.get("exclude", []),
                    job_id=job_id,
                    operator_id=payload.username if payload else "operator",
                    operator_role=(
                        payload.role.value if payload else Role.ADMIN.value
                    ),
                )
                server._raise_scope_denial(decision)

            framework = server._retest_framework(module)
            credential_reference = server._retest_session_reference(finding_id)
            try:
                client_job_id = server._client_job_id(body)
            except HTTPException:
                decision = decision_for_reason(ScopeReason.INVALID_CONFIRMATION)
                server._audit_preflight_denial(
                    decision,
                    action_kind="retest",
                    engine=framework,
                    target=target,
                    allowed_scope=body.get("scope", []),
                    excluded_scope=body.get("exclude", []),
                    job_id=job_id,
                    operator_id=payload.username if payload else "operator",
                    operator_role=(
                        payload.role.value if payload else Role.ADMIN.value
                    ),
                    module_id=module,
                )
                server._raise_scope_denial(decision)
            run_id = f"run-{uuid.uuid4().hex}"
            engagement_id = f"engagement-{uuid.uuid5(uuid.NAMESPACE_URL, job_id).hex}"
            operator_id = payload.username if payload else "operator"
            operator_role = payload.role.value if payload else Role.ADMIN.value
            allowed_scope, excluded_scope = server._launch_scope_inputs(body)
            confirmation, submitted_decision = server._server_confirmation(
                body,
                client_job_id=client_job_id,
                server_job_id=job_id,
                target=target,
                allowed_scope=allowed_scope,
                excluded_scope=excluded_scope,
                engine=framework,
                action="retest",
                dry_run=dry_run,
            )
            scope_decision, confirmation, context = server._prepare_launch_action(
                target=target,
                allowed_scope=allowed_scope,
                excluded_scope=excluded_scope,
                confirmation=confirmation,
                job_id=job_id,
                engine=framework,
                action="retest",
                dry_run=dry_run,
                tenant_id=server.tenant_id,
                engagement_id=engagement_id,
                run_id=run_id,
                operator_id=operator_id,
                operator_role=operator_role,
                safety_mode=SafetyMode.ACTIVE.value,
                module_id=module_set_binding([module]),
                credential_reference=credential_reference,
                prior_decision=submitted_decision,
            )
            authorization: ActionAuthorizationEnvelope | None = None
            if not dry_run:
                if context is None or confirmation is None:
                    server._raise_scope_denial(
                        decision_for_reason(ScopeReason.INVALID_CONFIRMATION)
                    )
                authorization = server._commit_retest_authorization(
                    context,
                    confirmation,
                )

            if dry_run:
                result = {
                    "schema_version": "forge-real-retest-v1",
                    "state": "planned",
                    "retest_verdict": None,
                    "reason_code": "dry_run_planned",
                    "finding_id": finding_id,
                    "retest_id": None,
                    "retest_attempt_id": None,
                    "job_id": job_id,
                    "durable_attempt_id": None,
                    "observation_id": None,
                    "artifact_id": None,
                    "duplicate": False,
                    "verdict_authority": "none",
                }
            else:
                assert authorization is not None
                database_path = server._canonical_finding_database(finding_id)
                service = JobStateService(
                    database_path,
                    clock=lambda: server._agent_now().timestamp(),
                    authorization_checker=server._retest_authorization_allowed,
                )
                canonical_session = create_db(database_path)
                try:
                    retest_service = RetestService(
                        canonical_session,
                        database_path.parent / "evidence-custody",
                        service,
                        authorization_session_factory=(
                            lambda: create_db(server._scan_jobs_db_path)
                        ),
                        session_resolver=server._retest_session_resolver,
                    )
                    execution = await retest_service.execute(
                        finding_id=finding_id,
                        tenant_id=server.tenant_id,
                        authorization=authorization,
                        allowed_scope=tuple(allowed_scope),
                        excluded_scope=tuple(excluded_scope),
                        idempotency_key=f"dashboard:{authorization.job_id}",
                    )
                    result = execution.to_dict()
                finally:
                    canonical_session.close()
                    service.close()
            server.event_bus.emit_simple(
                EventType.FINDING_UPDATED, source="dashboard",
                finding_id=finding_id,
                action="retest",
                retest_state=result["state"],
                retest_verdict=result["retest_verdict"],
                retest_status=result["retest_verdict"] or result["state"],
                retest_reason_code=result["reason_code"],
                retest_id=result["retest_id"],
                job_id=result["job_id"],
                dry_run=dry_run,
            )
            _audit(
                request,
                "finding.retest",
                object_id=finding_id,
                detail={
                    "retest_id": result["retest_id"],
                    "job_id": result["job_id"],
                    "dry_run": dry_run,
                    "state": result["state"],
                    "retest_verdict": result["retest_verdict"],
                    "reason_code": result["reason_code"],
                    "scope_decision": scope_decision.to_dict(),
                },
                payload=payload,
            )
            return {
                **result,
                "status": result["state"],
                "retest_status": result["retest_verdict"] or result["state"],
                "client_job_id": client_job_id,
                "module": module,
                "target": target,
                "dry_run": dry_run,
            }

        # ── Scan Launch (extended for ScanBuilder) ─────────────────────

        @app.post("/api/v1/scans/launch")
        async def api_scan_launch(request: Request):
            """Launch a scan from the ScanBuilder with full configuration.

            Accepts the rich ScanBuilder config with modules, intensity,
            threads, etc. Maps to the simpler scans/start internally.
            """
            payload = _require_auth(request, Role.OPERATOR)
            _require_not_killed()
            body = await request.json()
            job_id = server._server_job_id()

            def _deny_preflight(
                decision: ScopeDecision,
                *,
                engine: str = "webforge",
                original_error: HTTPException | None = None,
            ) -> NoReturn:
                server._audit_preflight_denial(
                    decision,
                    action_kind="scan",
                    engine=engine,
                    target=body.get("target"),
                    allowed_scope=body.get("scope", []),
                    excluded_scope=(
                        body.get("exclude")
                        if body.get("exclude") is not None
                        else body.get("excluded_scope", [])
                    ),
                    job_id=job_id,
                    operator_id=payload.username if payload else "operator",
                    operator_role=(
                        payload.role.value if payload else Role.ADMIN.value
                    ),
                )
                if original_error is not None:
                    raise original_error
                server._raise_scope_denial(decision)

            submitted_target = body.get("target")
            if not isinstance(submitted_target, str):
                _deny_preflight(decision_for_reason(ScopeReason.MALFORMED_TARGET))
            raw_target = submitted_target.strip()
            if not raw_target:
                _deny_preflight(decision_for_reason(ScopeReason.MALFORMED_TARGET))
            target = raw_target
            try:
                dry_run = server._request_bool(body, "dry_run", default=False)
            except HTTPException:
                _deny_preflight(
                    decision_for_reason(ScopeReason.INVALID_CONFIRMATION)
                )

            schedule = str(body.get("schedule", "now") or "now").strip().lower()
            if schedule not in {"now", "once", "recurring"}:
                _deny_preflight(
                    decision_for_reason(ScopeReason.INVALID_CONFIRMATION),
                    original_error=HTTPException(
                        status_code=400,
                        detail=(
                            f"Invalid schedule '{schedule}'. Must be one of: "
                            "now, once, recurring"
                        ),
                    ),
                )
            if schedule != "now":
                _deny_preflight(
                    decision_for_reason(ScopeReason.INVALID_CONFIRMATION),
                    original_error=HTTPException(
                        status_code=400,
                        detail=(
                            "ScanBuilder scheduling is not implemented yet. "
                            "Choose Run Now to launch immediately; no scan was started."
                        ),
                    ),
                )

            raw_mode = body.get("mode", "blackbox")
            if not isinstance(raw_mode, str):
                _deny_preflight(
                    decision_for_reason(ScopeReason.INVALID_CONFIRMATION)
                )
            mode = raw_mode.lower()
            _VALID_MODES = {"blackbox", "greybox", "whitebox"}
            if mode not in _VALID_MODES:
                _deny_preflight(
                    decision_for_reason(ScopeReason.INVALID_CONFIRMATION),
                    original_error=HTTPException(
                        status_code=400,
                        detail=(
                            f"Invalid mode '{mode}'. Must be one of: "
                            f"{', '.join(sorted(_VALID_MODES))}"
                        ),
                    ),
                )

            source_root = ""
            if mode == "whitebox":
                try:
                    source_root = server._validated_whitebox_source_root(body)
                except ValueError as exc:
                    _deny_preflight(
                        decision_for_reason(ScopeReason.INVALID_CONFIRMATION),
                        original_error=HTTPException(status_code=400, detail=str(exc)),
                    )

            raw_max_threads = body.get("maxThreads", 20)
            raw_rate_limit = body.get("rateLimit", 1000)
            raw_timeout = body.get("timeout", 30)
            raw_max_depth = body.get("maxDepth", 5)
            max_threads = _clamp_scanbuilder_int(raw_max_threads, 20, 1, 100)
            rate_limit = _clamp_scanbuilder_float(raw_rate_limit, 1000.0, 1.0, 1000.0)
            timeout_seconds = _clamp_scanbuilder_int(raw_timeout, 30, 5, 300)
            max_depth = _clamp_scanbuilder_int(raw_max_depth, 5, 1, 20)
            raw_follow_redirects = body.get("followRedirects", True)
            if type(raw_follow_redirects) is not bool:
                _deny_preflight(
                    decision_for_reason(ScopeReason.INVALID_CONFIRMATION)
                )
            follow_redirects = raw_follow_redirects
            scan_options = {
                "maxThreads": max_threads,
                "rateLimit": rate_limit,
                "timeout": timeout_seconds,
                "maxDepth": max_depth,
                "followRedirects": follow_redirects,
                "schedule": schedule,
                "clamped": {
                    "maxThreads": max_threads != _clamp_scanbuilder_int(raw_max_threads, 20, -2**31, 2**31),
                    "rateLimit": rate_limit != _clamp_scanbuilder_float(raw_rate_limit, 1000.0, 0.0, 1_000_000.0),
                    "timeout": timeout_seconds != _clamp_scanbuilder_int(raw_timeout, 30, -2**31, 2**31),
                    "maxDepth": max_depth != _clamp_scanbuilder_int(raw_max_depth, 5, -2**31, 2**31),
                },
            }

            # Extract auth_profile — supports both nested auth_profile and legacy flat fields
            auth_profile = body.get("auth_profile") or {}
            if not isinstance(auth_profile, dict):
                _deny_preflight(
                    decision_for_reason(ScopeReason.INVALID_CONFIRMATION)
                )

            def _profile_text(field: str, default: str = "") -> str:
                value = auth_profile.get(field, body.get(field, default))
                if not isinstance(value, str):
                    _deny_preflight(
                        decision_for_reason(ScopeReason.INVALID_CONFIRMATION)
                    )
                return value.strip()

            auth_type = _profile_text("auth_type", "form")
            username = _profile_text("username")
            login_url_ = _profile_text("login_url")
            header_name = _profile_text("header_name", "Authorization")
            password = _profile_text("password")
            token = _profile_text("token")
            cookie_jar = _profile_text("cookie_jar")

            import re as _re2
            cookie_jar = _re2.sub(r"^cookie:\s*", "", cookie_jar, flags=_re2.IGNORECASE)
            web_credential_reference = ""
            web_credential_bundle: ProtectedCredentialBundle | None = None
            if mode != "blackbox" and any(
                (username, password, token, cookie_jar)
            ):
                credential_values = {
                    key: value
                    for key, value in {
                        "password": password,
                        "token": token,
                        "cookie": cookie_jar,
                    }.items()
                    if value
                }
                if dry_run:
                    web_credential_reference = protected_credential_reference(
                        credential_values
                    )
                else:
                    web_credential_bundle = server._request_credential_bundle(
                        request,
                        credential_values,
                        ttl_seconds=60,
                    )
                    web_credential_reference = web_credential_bundle.reference.value
                wipe_mapping(credential_values)
                password = token = cookie_jar = ""

            # Build subprocess env without secret values.
            import os as _os2
            scan_env = minimal_child_environment(
                _os2.environ,
                allowlist={"FORGE_TENANT_ID"},
            )
            if mode != "blackbox":
                scan_env["FORGE_AUTH_TYPE"] = auth_type

            # Resolve UI module IDs → real scanner module names
            modules = server._string_list(body.get("modules", []))
            if not modules:
                _deny_preflight(
                    decision_for_reason(ScopeReason.INVALID_CONFIRMATION),
                    original_error=HTTPException(
                        status_code=400,
                        detail="Select at least one implemented module before launch.",
                    ),
                )
            web_modules, net_modules, unsupported = _resolve_modules(modules)

            # Unknown or not-yet-implemented modules must not be silently
            # dropped; otherwise the operator cannot tell what actually ran.
            if unsupported:
                log.warning(
                    "Rejected ScanBuilder launch with unsupported module IDs: %s",
                    ", ".join(unsupported),
                )
                _deny_preflight(
                    decision_for_reason(ScopeReason.INVALID_CONFIRMATION),
                    original_error=HTTPException(
                        status_code=400,
                        detail=(
                            "Unsupported ScanBuilder module ID(s): "
                            f"{', '.join(unsupported)}. No scan was launched."
                        ),
                    ),
                )

            # Determine scan type from resolved modules
            if web_modules and net_modules:
                scan_type = "vapt"
            elif net_modules and not web_modules:
                scan_type = "net"
            else:
                scan_type = "web"

            raw_tester = body.get("tester", PRODUCT_LABEL)
            raw_intensity = body.get("intensity", 2)
            if not isinstance(raw_tester, str) or type(raw_intensity) is not int:
                _deny_preflight(
                    decision_for_reason(ScopeReason.INVALID_CONFIRMATION)
                )
            tester_ = raw_tester.strip() or PRODUCT_LABEL
            intensity_map = {
                0: "passive",
                1: "low",
                2: "standard",
                3: "aggressive",
                4: "maximum",
            }
            if raw_intensity not in intensity_map:
                _deny_preflight(
                    decision_for_reason(ScopeReason.INVALID_CONFIRMATION)
                )
            intensity_label = intensity_map[raw_intensity]

            try:
                client_job_id = server._client_job_id(body)
            except HTTPException:
                _deny_preflight(
                    decision_for_reason(ScopeReason.INVALID_CONFIRMATION)
                )
            run_id = f"run-{uuid.uuid4().hex}"
            engagement_id = f"engagement-{uuid.uuid5(uuid.NAMESPACE_URL, job_id).hex}"
            operator_id = payload.username if payload else "operator"
            operator_role = payload.role.value if payload else Role.ADMIN.value
            allowed_scope, excluded_scope = server._launch_scope_inputs(body)
            if scan_type in {"web", "vapt"} and not target.startswith(("http://", "https://")):
                target = "https://" + target

            network_target: str | None = None
            web_allowed_scope = allowed_scope
            net_allowed_scope = allowed_scope
            if scan_type == "net":
                # Direct NetForge supports a hostname, address, or CIDR. Do not
                # apply the exact escalation-address rule to this launch type.
                network_target = raw_target
                target = raw_target
            elif scan_type == "vapt":
                network_target = server._exact_ip(body.get("network_target"))
                if network_target is None:
                    _deny_preflight(
                        decision_for_reason(ScopeReason.MALFORMED_TARGET),
                        engine="netforge",
                    )
                web_allowed_scope = server._scope_entries(body.get("web_scope"))
                if not web_allowed_scope:
                    _deny_preflight(
                        decision_for_reason(ScopeReason.MISSING_SCOPE),
                        engine="webforge",
                    )
                net_allowed_scope, net_scope_decision = (
                    server._exact_network_scope_inputs(
                        network_target,
                        body.get("network_scope"),
                        excluded_scope,
                    )
                )
                if not net_scope_decision.allowed:
                    _deny_preflight(net_scope_decision, engine="netforge")

            action_decisions: list[dict[str, Any]] = []
            web_confirmation: ActionConfirmation | None = None
            net_confirmation: ActionConfirmation | None = None
            web_context: AuthorizationContext | None = None
            net_context: AuthorizationContext | None = None
            web_authorization: ActionAuthorizationEnvelope | None = None
            net_authorization: ActionAuthorizationEnvelope | None = None
            if scan_type in {"web", "vapt"}:
                web_confirmation, submitted_web_decision = server._server_confirmation(
                    body,
                    client_job_id=client_job_id,
                    server_job_id=job_id,
                    target=target,
                    allowed_scope=web_allowed_scope,
                    excluded_scope=excluded_scope,
                    engine="webforge",
                    action="scan",
                    dry_run=dry_run,
                    specific_field="web_confirmation" if scan_type == "vapt" else "",
                )
                web_decision, web_confirmation, web_context = server._prepare_launch_action(
                    target=target,
                    allowed_scope=web_allowed_scope,
                    excluded_scope=excluded_scope,
                    confirmation=web_confirmation,
                    job_id=job_id,
                    engine="webforge",
                    action="scan",
                    dry_run=dry_run,
                    tenant_id=server.tenant_id,
                    engagement_id=engagement_id,
                    run_id=run_id,
                    operator_id=operator_id,
                    operator_role=operator_role,
                    safety_mode=SafetyMode.ACTIVE.value,
                    module_id=module_set_binding(web_modules),
                    credential_reference=web_credential_reference,
                    prior_decision=submitted_web_decision,
                )
                action_decisions.append({
                    "engine": "webforge",
                    "action": "scan",
                    "decision": web_decision.to_dict(),
                    "authorization": None,
                })
            if scan_type in {"net", "vapt"}:
                net_action = "web_to_network" if scan_type == "vapt" else "scan"
                net_confirmation, submitted_net_decision = server._server_confirmation(
                    body,
                    client_job_id=client_job_id,
                    server_job_id=job_id,
                    target=network_target or target,
                    allowed_scope=net_allowed_scope,
                    excluded_scope=excluded_scope,
                    engine="netforge",
                    action=net_action,
                    dry_run=dry_run,
                    specific_field="network_confirmation" if scan_type == "vapt" else "",
                )
                net_decision, net_confirmation, net_context = server._prepare_launch_action(
                    target=network_target or target,
                    allowed_scope=net_allowed_scope,
                    excluded_scope=excluded_scope,
                    confirmation=net_confirmation,
                    job_id=job_id,
                    engine="netforge",
                    action=net_action,
                    dry_run=dry_run,
                    tenant_id=server.tenant_id,
                    engagement_id=engagement_id,
                    run_id=run_id,
                    operator_id=operator_id,
                    operator_role=operator_role,
                    safety_mode=SafetyMode.ACTIVE.value,
                    module_id=module_set_binding(net_modules),
                    prior_decision=submitted_net_decision,
                )
                action_decisions.append({
                    "engine": "netforge",
                    "action": net_action,
                    "decision": net_decision.to_dict(),
                    "authorization": None,
                })

            log.info(
                "ScanBuilder launch: target=%s mode=%s auth=%s credentialed=%s",
                safe_target_display(target), mode, auth_type, mode != "blackbox",
            )

            if dry_run:
                return {
                    "status": "planned",
                    "job_id": job_id,
                    "client_job_id": client_job_id,
                    "scan_id": job_id,
                    "target": target,
                    "scan_type": scan_type,
                    "dry_run": True,
                    "authorized": False,
                    "requested_modules": modules,
                    "actual_modules": web_modules + net_modules,
                    "actions": action_decisions,
                }

            try:
                results_root = server._allocate_scan_results_dir(job_id)
            except DashboardArtifactError:
                raise HTTPException(
                    status_code=500,
                    detail="Scan result boundary is unavailable",
                ) from None

            if scan_type == "vapt":
                try:
                    hostname = urlsplit(target).hostname or ""
                except Exception:
                    hostname = ""
                if not server._hostname_resolves_to_exact_ip(
                    hostname,
                    network_target,
                ):
                    server._record_launch_context_denial(
                        net_context,
                        reason=AuthorizationReason.RESOLVED_TARGET_MISMATCH,
                    )
                    server._raise_scope_denial(decision_for_reason(ScopeReason.TARGET_MISMATCH))

            prepared_actions = [
                (context, confirmation)
                for context, confirmation in (
                    (web_context, web_confirmation),
                    (net_context, net_confirmation),
                )
                if context is not None and confirmation is not None
            ]
            committed = server._commit_launch_authorizations(
                prepared_actions,
                job_record={
                    "status": "pending",
                    "target": target,
                    "frameworks": [
                        framework
                        for framework, enabled in (
                            ("web", scan_type in {"web", "vapt"}),
                            ("net", scan_type in {"net", "vapt"}),
                        )
                        if enabled
                    ],
                    "modules": web_modules + net_modules,
                    "logs": {},
                    "results_dir": str(results_root),
                    "created_at": datetime.now(timezone.utc),
                },
            )
            committed_iter = iter(committed)
            if web_context is not None:
                web_authorization = next(committed_iter)
            if net_context is not None:
                net_authorization = next(committed_iter)
            for item, authorization in zip(action_decisions, committed):
                item["authorization"] = authorization.to_event_payload()

            engagement    = f"ScanBuilder-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M')}"
            scan_id       = job_id
            forge_root    = Path(__file__).parent.parent.parent
            control_file  = server._init_control_file(scan_id)
            dash_url      = server._dashboard_public_url(request)
            launched: list[str] = []
            process_metadata: list[dict[str, Any]] = []
            rate_arg = _format_rate_arg(rate_limit)
            control_metadata = {
                "control_file": str(control_file),
                "dashboard_url": dash_url,
                "status_url": f"/api/v1/scans/{scan_id}",
                "logs_url": f"/api/v1/scans/{scan_id}/logs",
                "stop_url": "/api/v1/scans/stop",
                "pause_url": "/api/v1/control/pause",
                "resume_url": "/api/v1/control/resume",
                "abort_url": "/api/v1/control/abort",
            }

            # Clean env for netforge — it doesn't read FORGE_* credential vars
            net_scan_env_ = {k: v for k, v in scan_env.items() if not k.startswith("FORGE_")}

            def _web_cmd() -> list[str]:
                cmd = [
                    sys.executable, str(forge_root / 'webforge' / 'webforge.py'),
                    '--target', target,
                    '--mode', mode,
                    '--engagement', engagement,
                    '--tester', tester_,
                    '--dashboard-url', dash_url,
                    '--control-file', str(control_file),
                    '--report-format', 'html,json',
                    '--rate', rate_arg,
                    '--workers', str(max_threads),
                    '--output', str(results_root / 'webforge'),
                ]
                if mode != "blackbox":
                    cmd += ['--auth-type', auth_type]
                    if username:   cmd += ['--username', username]
                    if login_url_: cmd += ['--login-url', login_url_]
                    if header_name and auth_type == 'bearer':
                        cmd += ['--header-name', header_name]
                if source_root:
                    cmd += ['--source-root', source_root]
                if web_modules:
                    cmd += ['--modules', ','.join(web_modules)]
                server._append_scope_args(
                    cmd,
                    web_allowed_scope,
                    excluded_scope,
                )
                return cmd

            def _net_cmd(net_target: str) -> list[str]:
                cmd = [
                    sys.executable, str(forge_root / 'netforge' / 'netforge.py'),
                    '--target', net_target,
                    '--mode', 'external',
                    '--engagement', engagement,
                    '--dashboard-url', dash_url,
                    '--control-file', str(control_file),
                    '--rate', rate_arg,
                    '--workers', str(max_threads),
                    '--bf-timeout', str(timeout_seconds),
                    '--output', str(results_root / 'netforge'),
                ]
                if net_modules:
                    cmd += ['--modules', ','.join(net_modules)]
                server._append_scope_args(
                    cmd,
                    net_allowed_scope,
                    excluded_scope,
                )
                return cmd

            launch_specs: list[
                tuple[str, str, list[str], dict[str, str], list[str]]
            ] = []
            if scan_type in {'web', 'vapt'}:
                assert web_confirmation is not None
                assert web_authorization is not None
                launch_specs.append((
                    scan_id + '_web',
                    'web',
                    _web_cmd(),
                    server._launch_env(
                        scan_env,
                        web_confirmation,
                        web_authorization,
                        job_id,
                        "scan",
                    ),
                    web_modules,
                ))
            if scan_type in {'net', 'vapt'}:
                assert net_confirmation is not None
                assert net_authorization is not None
                launch_specs.append((
                    scan_id + '_net',
                    'net',
                    _net_cmd(network_target or target),
                    server._launch_env(
                        net_scan_env_,
                        net_confirmation,
                        net_authorization,
                        job_id,
                        net_action,
                    ),
                    net_modules,
                ))

            authorization_map: dict[str, ActionAuthorizationEnvelope] = {}
            if web_authorization is not None:
                authorization_map["webforge"] = web_authorization
            if net_authorization is not None:
                authorization_map["netforge"] = net_authorization
            prepared = server._prepare_durable_scan_job(
                scan_id=scan_id,
                target=target,
                process_specs=[
                    (key, framework_name)
                    for key, framework_name, _cmd, _env, _modules in launch_specs
                ],
                authorizations=authorization_map,
                modules=(web_modules + net_modules),
                results_dir=str(results_root),
                control_file=control_file,
                actor_id=operator_id,
                actor_role=operator_role,
            )
            spawned: list[
                tuple[str, str, list[str], list[str], subprocess.Popen[str]]
            ] = []
            try:
                for key, framework_name, cmd, child_env, actual_modules in launch_specs:
                    intent = cast(Mapping[str, Any], prepared["intents"])[key]
                    child_env = {
                        **child_env,
                        JOB_ATTEMPT_ID_ENV: str(
                            cast(Mapping[str, Any], prepared["attempt"])["id"]
                        ),
                        f"{JOB_ATTEMPT_ID_ENV}_LAUNCH_NONCE": str(
                            intent["launch_nonce"]
                        ),
                    }
                    if framework_name == "web" and web_credential_bundle is not None:
                        with web_credential_bundle.open_pipe() as handoff:
                            protected_env = {**child_env, **handoff.env}
                            proc = subprocess.Popen(
                                cmd,
                                cwd=str(forge_root),
                                env=protected_env,
                                pass_fds=handoff.pass_fds,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT,
                                text=True,
                            )
                    else:
                        proc = subprocess.Popen(
                            cmd,
                            cwd=str(forge_root),
                            env=child_env,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT,
                            text=True,
                        )
                    spawned.append((key, framework_name, cmd, actual_modules, proc))
            except Exception as exc:
                server._abort_durable_scan_launch(
                    scan_id=scan_id,
                    prepared=prepared,
                    processes={
                        key: child
                        for key, _framework, _cmd, _modules, child in spawned
                    },
                    control_file=control_file,
                    reason="dashboard process launch failed",
                )
                raise HTTPException(
                    status_code=500,
                    detail="Failed to launch scan; execution denied",
                ) from exc
            finally:
                if web_credential_bundle is not None:
                    web_credential_bundle.wipe()

            for key, framework_name, cmd, actual_modules, proc in spawned:
                process_target = target if framework_name == 'web' else (network_target or target)
                server._active_scans[key] = {
                    'proc': proc,
                    'type': framework_name,
                    'target': process_target,
                    'started_at': time.time(),
                    'engagement': engagement,
                    'mode': mode if framework_name == 'web' else 'external',
                    'status': 'leased',
                    'started_dt': datetime.now(timezone.utc).isoformat(),
                    'control_file': str(control_file),
                    'command': server._sanitize_cmd(cmd),
                    'dashboard_url': dash_url,
                    'requested_modules': modules,
                    'actual_modules': actual_modules,
                    'scan_options': scan_options,
                    'control': control_metadata,
                    'results_dir': str(results_root),
                }
                launched.append(framework_name)
                process_metadata.append({
                    'process_id': key,
                    'framework': framework_name,
                    'pid': getattr(proc, 'pid', None),
                    'status': 'running',
                    'control_file': str(control_file),
                    'log_path': str(server._scan_logs_dir / f"{key}.log"),
                })

            try:
                server._activate_durable_scan_processes(
                    scan_id=scan_id,
                    prepared=prepared,
                    control_file=control_file,
                    actor_id=operator_id,
                    actor_role=operator_role,
                )
            except Exception as exc:
                server._abort_durable_scan_launch(
                    scan_id=scan_id,
                    prepared=prepared,
                    processes={
                        key: child
                        for key, _framework, _cmd, _modules, child in spawned
                    },
                    control_file=control_file,
                    reason="dashboard process identity activation failed",
                )
                raise HTTPException(
                    status_code=500,
                    detail="Failed to bind scan process identity; execution denied",
                ) from exc
            for key, _framework, _cmd, _modules, _proc in spawned:
                server._active_scans[key]["status"] = "running"
                server._track_scan_process(key, server._active_scans[key])

            server._write_scan_history(
                scan_id=scan_id, target=target, scan_type=scan_type,
                mode=mode, engagement=engagement, frameworks=launched,
                requested_modules=modules,
                actual_modules=(web_modules + net_modules),
                scan_options=scan_options,
                control=control_metadata,
                process_ids=[item["process_id"] for item in process_metadata],
            )
            server._write_scan_job(
                scan_id=scan_id,
                target=target,
                frameworks=launched,
                modules=(web_modules + net_modules),
                results_dir=str(results_root),
                authorization=web_authorization or net_authorization,
            )

            event_authorization = web_authorization or net_authorization
            server.event_bus.emit_simple(
                EventType.SCAN_START, source='scan_builder',
                target=safe_target_display(target), scan_type=scan_type, scan_id=scan_id,
                modules=modules, actual_modules=(web_modules + net_modules),
                authorization=(
                    event_authorization.to_event_payload()
                    if event_authorization is not None
                    else None
                ),
                intensity=intensity_label,
                threads=max_threads,
                rate_limit=rate_limit,
                timeout=timeout_seconds,
                control=control_metadata,
                process_ids=[item["process_id"] for item in process_metadata],
                unsupported=unsupported,
            )

            response_data = {
                'status': 'launched',
                'scan_id': scan_id,
                'client_job_id': client_job_id,
                'target': target,
                'scan_type': scan_type,
                'frameworks': launched,
                'modules_count': len(web_modules) + len(net_modules),
                'requested_modules': modules,
                'actual_modules': web_modules + net_modules,
                'intensity': intensity_label,
                'scan_options': scan_options,
                'control': control_metadata,
                'processes': process_metadata,
                'dashboard_url': dash_url,
                'network_target': network_target,
            }
            if unsupported:
                response_data['unsupported_modules'] = unsupported
                response_data['warning'] = f"{len(unsupported)} module(s) not yet implemented: {', '.join(unsupported)}"
            _audit(
                request,
                "scan.launch",
                object_id=scan_id,
                detail={
                    "target": safe_target_display(target),
                    "scan_type": scan_type,
                    "requested_modules": modules,
                    "actual_modules": web_modules + net_modules,
                    "scan_options": scan_options,
                    "process_ids": [item["process_id"] for item in process_metadata],
                    "scope_decisions": action_decisions,
                },
                payload=payload,
            )
            return response_data

        # ── Report download ───────────────────────────────────────────

        @app.get("/api/v1/reports/latest")
        async def api_report_latest(request: Request, fmt: str = "html"):
            """Return the path of the most recently generated report.

            Query params:
              fmt: "html" | "pdf" | "json"
            """
            _require_auth(request)
            if fmt not in {"html", "pdf", "json"}:
                raise HTTPException(status_code=400, detail="Unsupported report format")
            return JSONResponse(
                {
                    "status": "disabled",
                    "reason_code": "report_artifact_tenant_binding_unavailable",
                },
                status_code=503,
            )

        @app.get("/api/v1/reports/download")
        async def api_report_download(request: Request, fmt: str = "html"):
            """Download the most recently generated report.

            Query params:
              fmt: "html" | "pdf" | "json"
            """
            _require_auth(request)
            if fmt not in {"html", "pdf", "json"}:
                raise HTTPException(status_code=400, detail="Unsupported report format")
            return JSONResponse(
                {
                    "status": "disabled",
                    "reason_code": "report_artifact_tenant_binding_unavailable",
                },
                status_code=503,
            )

        # ── Plugin inventory ──────────────────────────────────────────

        @app.get("/api/v1/plugins")
        async def api_plugins(request: Request):
            """Inventory of available scanner modules from all frameworks."""
            _require_auth(request, Role.OPERATOR)
            plugins = server._discover_plugins()
            return {
                "plugins": plugins,
                "total": len(plugins),
                "frameworks": sorted({p["framework"] for p in plugins}),
            }

        # ── BOF (Beacon Object File) API ───────────────────────────────

        @app.get("/api/v1/c2/bofs")
        async def api_bofs_list(request: Request):
            """Report the ordinary dashboard-host BOF surface as disabled."""
            _require_auth(request)
            return {
                "status": "disabled",
                "enabled": False,
                "reason_code": "local_bof_execution_disabled",
                "message": "Dashboard-host BOF execution is disabled",
                "bofs": [],
                "total": 0,
            }

        @app.post("/api/v1/c2/bofs/{name}/execute")
        async def api_bof_execute(request: Request, name: str):
            """Fail closed before body parsing, imports, or local host access."""
            payload = _require_auth(request)
            if not payload.has_role(Role.ADMIN):
                _audit(
                    request,
                    "bof.execute",
                    object_id="disabled",
                    status="denied",
                    detail={"reason_code": "dashboard_role_forbidden"},
                    payload=payload,
                )
                return JSONResponse(
                    {
                        "status": "forbidden",
                        "reason_code": "dashboard_role_forbidden",
                    },
                    status_code=403,
                )
            _audit(
                request,
                "bof.execute",
                object_id="disabled",
                status="disabled",
                detail={"reason_code": "local_bof_execution_disabled"},
                payload=payload,
            )
            del name
            return JSONResponse(
                {
                    "status": "disabled",
                    "enabled": False,
                    "reason_code": "local_bof_execution_disabled",
                    "message": "Dashboard-host BOF execution is disabled",
                },
                status_code=403,
            )

        # ── Malleable C2 Profiles API ──────────────────────────────────

        @app.get("/api/v1/c2/profiles")
        async def api_profiles_list(request: Request):
            """List static built-in malleable C2 profile metadata."""
            _require_auth(request)
            try:
                from forge_c2.profiles.profile_parser import BUILTIN_PROFILES

                profiles = [
                    {
                        "name": name,
                        "description": data.get("description", ""),
                        "author": data.get("author", ""),
                        "source": "built-in",
                    }
                    for name, data in BUILTIN_PROFILES.items()
                ]
            except ImportError:
                profiles = []
            return {"profiles": profiles, "total": len(profiles)}

        @app.get("/api/v1/c2/profiles/{name}")
        async def api_profile_detail(request: Request, name: str):
            """Get detailed info for a specific malleable C2 profile."""
            _require_auth(request)
            try:
                from forge_c2.profiles.profile_parser import get_builtin_profile
                profile = get_builtin_profile(name)
                return {"profile": profile.to_dict()}
            except ValueError:
                return JSONResponse(
                    {
                        "error": "Profile not found",
                        "reason_code": "c2_profile_not_found",
                    },
                    status_code=404,
                )
            except ImportError:
                return JSONResponse({"error": "Profiles module not available"}, status_code=500)

        # ── Lab-safe C2 emulation API ─────────────────────────────────

        @app.get("/api/v1/c2/emulation/process-injection")
        async def api_c2_injection_emulations(request: Request):
            """List non-executing process-injection validation techniques."""
            _require_auth(request)
            from forge_c2.emulation import list_process_injection_techniques

            techniques = list_process_injection_techniques()
            return {
                "mode": "dry_run_emulation",
                "techniques": techniques,
                "total": len(techniques),
                "safety": "metadata_only_no_injection",
            }

        @app.post("/api/v1/c2/emulation/process-injection/plan")
        async def api_c2_injection_plan(request: Request):
            """Build an inert process-injection validation plan."""
            payload = _require_auth(request)
            from forge_c2.emulation import build_process_injection_emulation_plan

            body = await request.json()
            if not isinstance(body, dict):
                return JSONResponse(
                    {"error": "JSON body must be an object"},
                    status_code=400,
                )
            try:
                plan = build_process_injection_emulation_plan(
                    str(body.get("technique_id", "")),
                    beacon_id=str(body.get("beacon_id", "")),
                    target_process=str(body.get("target_process", "")),
                    operator=payload.username,
                    dry_run=bool(body.get("dry_run", True)),
                )
                return {"plan": plan}
            except ValueError:
                return JSONResponse(
                    {
                        "error": "Process-injection emulation plan rejected",
                        "reason_code": "c2_emulation_plan_rejected",
                    },
                    status_code=400,
                )

        @app.get("/api/v1/c2/emulation/p2p")
        async def api_c2_p2p_emulation(request: Request):
            """Describe supported P2P mesh emulation labels."""
            _require_auth(request)
            from forge_c2.emulation import P2P_TRANSPORTS

            return {
                "mode": "emulation",
                "transports": dict(P2P_TRANSPORTS),
                "safety": "control_plane_only_no_peer_transport",
            }

        # ── Report listing ────────────────────────────────────────────

        @app.get("/api/v1/reports")
        async def api_reports_list(
            request: Request,
            fmt: str | None = None,
            framework: str | None = None,
            limit: int = Query(default=50, le=200),
        ):
            """List all generated reports across all engagements.

            Query params:
              fmt:       filter by format — html | pdf | json
              framework: filter by framework — webforge | netforge
              limit:     max results (default 50, max 200)
            """
            _require_auth(request)
            if framework is not None and framework not in {"webforge", "netforge"}:
                raise HTTPException(status_code=400, detail="Unsupported report framework")
            if fmt is not None and fmt not in {"html", "pdf", "json"}:
                raise HTTPException(status_code=400, detail="Unsupported report format")
            del limit
            return JSONResponse(
                {
                    "status": "disabled",
                    "reason_code": "report_artifact_tenant_binding_unavailable",
                },
                status_code=503,
            )

        # ── Verification queue ────────────────────────────────────────

        @app.get("/api/v1/findings/verification-queue")
        async def api_verification_queue(
            request: Request,
            limit: int = Query(default=100, le=500),
        ):
            """Findings pending operator verification, sorted by risk (VPR then CVSS).

            Returns findings where confidence is UNVERIFIED or status is open.
            """
            _require_auth(request, Role.OPERATOR)
            queue = [
                f for f in server.state_store.findings
                if f.confidence == "UNVERIFIED" or f.status == "open"
            ]
            queue.sort(
                key=lambda f: (f.vpr_score or 0.0, f.cvss_score or 0.0),
                reverse=True,
            )
            return {
                "queue": [f.to_dict() for f in queue[:limit]],
                "total": len(queue),
            }

        # ── WebSocket ─────────────────────────────────────────────────

        @app.websocket("/ws/dashboard")
        async def ws_dashboard(websocket: WebSocket):
            """Real-time dashboard event stream."""
            client_ip = websocket.client.host if websocket.client else ""
            if not server._websocket_origin_allowed(websocket):
                invalid_allowed = server._consume_public_rate_limit(
                    bucket="websocket-invalid-host-origin",
                    client_ip=client_ip,
                    limit=_PUBLIC_RATE_LIMIT,
                )
                await websocket.close(code=4403 if invalid_allowed else 4429)
                return
            if not server._consume_public_rate_limit(
                bucket="websocket-handshake",
                client_ip=client_ip,
                limit=_PUBLIC_RATE_LIMIT,
            ):
                await websocket.close(code=4429)
                return
            if not server._reserve_websocket(websocket):
                await websocket.close(code=4429)
                return

            # Reject public handshake abuse before accepting the connection.
            # ASGI only permits an accept or close while the application is in
            # the CONNECTING state, so pre-accept denials are deliberately
            # close-only and cannot expose dashboard state in a JSON frame.
            try:
                await websocket.accept()

                # WebSocket identity is mandatory even when a legacy caller
                # asked for no-auth mode. No tenant state is sent before
                # validation, and every reserved path releases in the outer
                # finally block.
                try:
                    auth_msg = await asyncio.wait_for(
                        websocket.receive_json(), timeout=10.0,
                    )
                    token = (
                        auth_msg.get("token", "")
                        if isinstance(auth_msg, dict)
                        else ""
                    )
                    payload = validate_token(token)
                    if not payload:
                        await websocket.send_json({
                            "error": "unauthorized",
                            "reason_code": "dashboard_auth_required",
                        })
                        await websocket.close(code=4001)
                        return
                    if not hmac.compare_digest(payload.tenant_id, server.tenant_id):
                        await websocket.send_json({
                            "error": "forbidden",
                            "reason_code": "dashboard_tenant_forbidden",
                        })
                        await websocket.close(code=4403)
                        return
                except (
                    asyncio.TimeoutError,
                    WebSocketDisconnect,
                    ValueError,
                    TypeError,
                ):
                    await websocket.close(code=4002)
                    return

                if payload.is_expired():
                    await websocket.close(code=4001)
                    return
                server._ws_clients[websocket] = payload
                log.info(
                    "WebSocket client connected (%d total)",
                    len(server._ws_clients),
                )

                # Authentication acknowledgement precedes all tenant state.
                try:
                    if payload.is_expired():
                        await server._expire_websocket_session(websocket)
                        return
                    await websocket.send_json({
                        "type": "auth_ack",
                        "role": payload.role.value,
                        "tenant_id": payload.tenant_id,
                    })
                    if payload.is_expired():
                        await server._expire_websocket_session(websocket)
                        return
                    snapshot = server._public_state_snapshot(
                        payload.role, actor_id=payload.username
                    )
                    if payload.is_expired():
                        await server._expire_websocket_session(websocket)
                        return
                    await websocket.send_json({
                        "type": "state_snapshot",
                        "data": snapshot,
                    })
                except Exception:
                    pass

                # Event relay loop
                try:
                    while True:
                        # Keep connection alive + receive client commands
                        remaining = payload.expires_at - time.time()
                        if remaining <= 0:
                            await server._expire_websocket_session(websocket)
                            return
                        try:
                            msg = await asyncio.wait_for(
                                websocket.receive_text(),
                                timeout=remaining,
                            )
                        except asyncio.TimeoutError:
                            await server._expire_websocket_session(websocket)
                            return
                        if payload.is_expired():
                            await server._expire_websocket_session(websocket)
                            return
                        if len(msg.encode("utf-8")) > 8192:
                            await websocket.send_json({
                                "type": "error",
                                "reason_code": "websocket_command_too_large",
                            })
                            continue
                        try:
                            cmd = json.loads(msg)
                            if isinstance(cmd, dict):
                                await server._handle_ws_command(cmd, websocket)
                                if websocket not in server._ws_clients:
                                    return
                            else:
                                await websocket.send_json({
                                    "type": "error",
                                    "reason_code": "websocket_command_malformed",
                                })
                        except json.JSONDecodeError:
                            await websocket.send_json({
                                "type": "error",
                                "reason_code": "websocket_command_malformed",
                            })
                except WebSocketDisconnect:
                    pass
            finally:
                was_connected = server._ws_clients.pop(websocket, None) is not None
                server._release_websocket(websocket)
                if was_connected:
                    log.info(
                        "WebSocket client disconnected (%d remaining)",
                        len(server._ws_clients),
                    )

        self._app = app
        return app

    async def _handle_ws_command(
        self, cmd: dict[str, Any], ws: WebSocket,
    ) -> None:
        """Handle commands from WebSocket clients."""
        payload = self._ws_clients.get(ws)
        if payload is None or not hmac.compare_digest(payload.tenant_id, self.tenant_id):
            await ws.send_json({
                "type": "error",
                "reason_code": "dashboard_auth_required",
            })
            return
        if payload.is_expired():
            await self._expire_websocket_session(ws)
            return
        action = cmd.get("action")
        if action == "ping":
            await ws.send_json({"type": "pong", "ts": time.time()})
        elif action == "get_state":
            snapshot = self._public_state_snapshot(
                payload.role, actor_id=payload.username
            )
            if payload.is_expired():
                await self._expire_websocket_session(ws)
                return
            await ws.send_json({
                "type": "state_snapshot",
                "data": snapshot,
            })
        elif action == "get_findings":
            severity = cmd.get("severity")
            if severity is not None and severity not in {
                "Critical",
                "High",
                "Medium",
                "Low",
                "Informational",
            }:
                await ws.send_json({
                    "type": "error",
                    "reason_code": "websocket_filter_invalid",
                })
                return
            raw_limit = cmd.get("limit", 100)
            if type(raw_limit) is not int or not (1 <= raw_limit <= 200):
                await ws.send_json({
                    "type": "error",
                    "reason_code": "websocket_limit_invalid",
                })
                return
            findings = self._public_findings(
                severity=severity,
                limit=raw_limit,
                actor_id=payload.username,
            )
            if payload.is_expired():
                await self._expire_websocket_session(ws)
                return
            await ws.send_json({"type": "findings", "data": findings})
        else:
            await ws.send_json({
                "type": "error",
                "reason_code": "websocket_command_unsupported",
            })

    async def _broadcast_event(self, event: Event) -> None:
        """Broadcast an event to all connected WebSocket clients."""
        if not self._ws_clients:
            return
        event_tenant = event.data.get("tenant_id")
        if event_tenant is not None and (
            not isinstance(event_tenant, str)
            or not hmac.compare_digest(event_tenant, self.tenant_id)
        ):
            return
        msg = json.dumps(self._public_event(event), default=str)

        disconnected: list[WebSocket] = []
        for ws, payload in list(self._ws_clients.items()):
            if payload.is_expired():
                await self._expire_websocket_session(ws)
                continue
            if not hmac.compare_digest(payload.tenant_id, self.tenant_id):
                disconnected.append(ws)
                continue
            if event.event_type is EventType.CREDENTIAL_FOUND and payload.role is Role.VIEWER:
                continue
            try:
                await ws.send_text(msg)
            except Exception:
                disconnected.append(ws)
        for ws in disconnected:
            if ws in self._ws_clients:
                self._ws_clients.pop(ws, None)
            self._release_websocket(ws)

    async def start(self) -> None:
        """Start the dashboard server with uvicorn."""
        if not _get_users():
            raise RuntimeError(
                "dashboard credentials are required; set "
                "FORGE_DASHBOARD_PASSWORD_HASH or FORGE_DASHBOARD_PASSWORD"
            )
        try:
            import uvicorn
        except ImportError:
            raise ImportError("uvicorn not installed. Run: pip install uvicorn[standard]")

        app = self.create_app()

        # Wire async event broadcasting
        loop = asyncio.get_event_loop()
        self.event_bus.async_subscribe(None, self._broadcast_event)
        if not self.event_bus._running:
            self.event_bus.start(loop=loop)

        # Always attempt TLS (self-signed cert). Browsers must use https://.
        # If cryptography is not installed, falls back to plain HTTP.
        ssl_ctx = self._create_ssl_context()
        try:
            bind_ip = ipaddress.ip_address(self.host)
            loopback_bind = bind_ip.is_loopback
        except ValueError:
            loopback_bind = self.host.strip().lower() == "localhost"
        if ssl_ctx is None and not loopback_bind:
            raise RuntimeError(
                "dashboard TLS is required for a non-loopback bind"
            )
        proto = "https" if ssl_ctx else "http"

        config = uvicorn.Config(
            app=app,
            host=self.host,
            port=self.port,
            ssl_certfile=ssl_ctx.get("certfile") if ssl_ctx else None,
            ssl_keyfile=ssl_ctx.get("keyfile") if ssl_ctx else None,
            log_level="warning",
            access_log=False,
        )
        server = uvicorn.Server(config)
        log.info("War Room dashboard starting at %s://%s:%d", proto, self.host, self.port)
        await server.serve()

    def _create_ssl_context(self) -> dict[str, str] | None:
        """Generate self-signed TLS cert for local HTTPS."""
        cert_dir = _DASHBOARD_DIR / ".tls"
        configured_cert = os.environ.get("FORGE_DASHBOARD_TLS_CERT", "").strip()
        configured_key = os.environ.get("FORGE_DASHBOARD_TLS_KEY", "").strip()
        if bool(configured_cert) != bool(configured_key):
            raise RuntimeError("dashboard TLS certificate and key must be configured together")

        try:
            bind_ip = ipaddress.ip_address(self.host)
            loopback_bind = bind_ip.is_loopback
        except ValueError:
            loopback_bind = self.host.strip().lower() == "localhost"

        if configured_cert:
            cert_file = Path(configured_cert).expanduser()
            key_file = Path(configured_key).expanduser()
        else:
            if not loopback_bind:
                # The generated certificate covers only localhost/127.0.0.1.
                return None
            cert_file = cert_dir / "forge_cert.pem"
            key_file = cert_dir / "forge_key.pem"

        def _secure_existing() -> dict[str, str] | None:
            cert_metadata = _artifact_lstat(cert_file)
            key_metadata = _artifact_lstat(key_file)
            if cert_metadata is None and key_metadata is None:
                return None
            if cert_metadata is None or key_metadata is None:
                raise RuntimeError("dashboard TLS certificate/key state is incomplete")
            for path, metadata, private in (
                (cert_file, cert_metadata, False),
                (key_file, key_metadata, True),
            ):
                if not stat.S_ISREG(metadata.st_mode):
                    raise RuntimeError("dashboard TLS paths must be regular files")
                if metadata.st_nlink != 1:
                    raise RuntimeError("dashboard TLS paths must not be hard-linked")
                if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
                    raise RuntimeError("dashboard TLS paths must be owned by the service user")
                if configured_cert:
                    # Caller-supplied material is validated but never chmodded.
                    # Its directory and file modes remain under caller control.
                    if private and metadata.st_mode & 0o077:
                        raise RuntimeError("dashboard TLS private key must be owner-only")
                else:
                    _set_regular_artifact_mode(path, 0o600 if private else 0o644)
            if configured_cert:
                advertised_host = os.environ.get(
                    "FORGE_DASHBOARD_PUBLIC_HOST",
                    self.host,
                ).strip().strip("[]")
                if advertised_host in {"", "0.0.0.0", "::"}:
                    raise RuntimeError(
                        "an exact dashboard public host is required for a wildcard bind"
                    )
                try:
                    from cryptography import x509
                    from cryptography.hazmat.primitives import serialization

                    certificate = x509.load_pem_x509_certificate(
                        _read_artifact_bytes(cert_file, max_bytes=1024 * 1024)
                    )
                    private_key = serialization.load_pem_private_key(
                        _read_artifact_bytes(key_file, max_bytes=1024 * 1024),
                        password=None,
                    )
                    certificate_key = certificate.public_key().public_bytes(
                        serialization.Encoding.DER,
                        serialization.PublicFormat.SubjectPublicKeyInfo,
                    )
                    private_public_key = private_key.public_key().public_bytes(
                        serialization.Encoding.DER,
                        serialization.PublicFormat.SubjectPublicKeyInfo,
                    )
                    if not hmac.compare_digest(certificate_key, private_public_key):
                        raise RuntimeError("dashboard TLS certificate/key mismatch")
                    now = datetime.now(timezone.utc)
                    not_before = certificate.not_valid_before_utc
                    not_after = certificate.not_valid_after_utc
                    if now < not_before or now > not_after:
                        raise RuntimeError("dashboard TLS certificate is not currently valid")
                    san = certificate.extensions.get_extension_for_class(
                        x509.SubjectAlternativeName
                    ).value
                    try:
                        advertised_ip = ipaddress.ip_address(advertised_host)
                    except ValueError:
                        advertised_ip = None
                    if advertised_ip is not None:
                        covered = any(
                            value == advertised_ip
                            for value in san.get_values_for_type(x509.IPAddress)
                        )
                    else:
                        normalized_host = advertised_host.lower().rstrip(".")

                        def _dns_matches(pattern: str) -> bool:
                            normalized_pattern = pattern.lower().rstrip(".")
                            if normalized_pattern.startswith("*."):
                                suffix = normalized_pattern[1:]
                                return (
                                    normalized_host.endswith(suffix)
                                    and normalized_host.count(".")
                                    == normalized_pattern.count(".")
                                )
                            return hmac.compare_digest(
                                normalized_pattern,
                                normalized_host,
                            )

                        covered = any(
                            _dns_matches(value)
                            for value in san.get_values_for_type(x509.DNSName)
                        )
                    if not covered:
                        raise RuntimeError(
                            "dashboard TLS certificate SAN does not cover the configured host"
                        )
                except RuntimeError:
                    raise
                except Exception:
                    raise RuntimeError(
                        "dashboard TLS material does not cover the configured host"
                    ) from None
            return {"certfile": str(cert_file), "keyfile": str(key_file)}

        existing = _secure_existing()
        if existing is not None:
            return existing

        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa

            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, "Forge Suite War Room"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Forge Suite"),
            ])
            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.now(timezone.utc))
                .not_valid_after(
                    datetime.now(timezone.utc) + timedelta(days=365)
                )
                .add_extension(
                    x509.SubjectAlternativeName([
                        x509.DNSName("localhost"),
                        x509.IPAddress(
                            __import__("ipaddress").IPv4Address("127.0.0.1")
                        ),
                    ]),
                    critical=False,
                )
                .sign(key, hashes.SHA256())
            )

            key_payload = key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
            cert_payload = cert.public_bytes(serialization.Encoding.PEM)
            created_tls_directories: list[Path] = []
            try:
                _atomic_write_artifact(
                    key_file,
                    key_payload,
                    mode=0o600,
                    created_directories=created_tls_directories,
                )
                _atomic_write_artifact(cert_file, cert_payload, mode=0o644)
            except Exception:
                for generated_path in (cert_file, key_file):
                    try:
                        _unlink_artifact(generated_path)
                    except DashboardArtifactError:
                        pass
                _cleanup_created_artifact_directories(created_tls_directories)
                raise

            log.info("Generated self-signed TLS cert at %s", cert_file)
            return {"certfile": str(cert_file), "keyfile": str(key_file)}

        except ImportError:
            log.warning("cryptography not available; local dashboard TLS was not generated")
            return None
        except DashboardArtifactError:
            raise
        except Exception:
            raise RuntimeError("dashboard TLS generation failed") from None

    def _dashboard_public_url(self, request: Request | None = None) -> str:
        """Return the configured/direct dashboard URL without proxy headers."""
        configured = os.environ.get("FORGE_DASHBOARD_URL", "").strip()
        if configured:
            return configured.rstrip("/")

        scheme = "https"
        if request and request.url.scheme in {"http", "https"}:
            scheme = request.url.scheme

        host = "127.0.0.1" if self.host in {"0.0.0.0", "::", ""} else self.host
        return f"{scheme}://{host}:{self.port}"

    def _tool_inventory(self) -> list[dict[str, Any]]:
        """Return the framework scripts the dashboard can launch/control."""
        forge_root = Path(__file__).parent.parent.parent
        specs = [
            ("web", "WebForge", forge_root / "webforge" / "webforge.py", True),
            ("net", "NetForge", forge_root / "netforge" / "netforge.py", True),
            ("ad", "ADForge", forge_root / "adforge" / "adforge.py", False),
            ("ai", "AIForge", forge_root / "aiforge" / "aiforge.py", False),
            ("c2", "Forge C2", forge_root / "forge_c2" / "server.py", False),
            ("payload", "Payload Factory", forge_root / "forge_payload" / "payload_factory.py", False),
        ]
        return [
            {
                "id": tool_id,
                "name": name,
                "path": str(path.relative_to(forge_root)),
                "ready": path.exists(),
                "dashboard_launch": launchable,
            }
            for tool_id, name, path, launchable in specs
        ]

    def _phase_lookup(self, phases: list[tuple[int, str, list[str]]]) -> tuple[dict[str, int], dict[str, str]]:
        """Build module → phase metadata maps."""
        by_num = {
            name: num
            for num, _phase_name, names in phases
            for name in names
        }
        by_name = {
            name: _phase_name
            for num, _phase_name, names in phases
            for name in names
        }
        return by_num, by_name

    def _discover_plugins(self) -> list[dict[str, Any]]:
        """Auto-discover scanner module registry entries from each framework."""
        import importlib

        specs = [
            ("webforge", "webforge.webforge", "webforge.core.mode_engine"),
            ("netforge", "netforge.netforge", None),
            ("adforge", "adforge.adforge", None),
        ]
        plugins: list[dict[str, Any]] = []
        for framework, registry_module, phases_module in specs:
            try:
                registry = importlib.import_module(registry_module)
                module_map = getattr(registry, "MODULE_MAP", {})
                class_map = getattr(registry, "CLASS_NAME_MAP", {})
                phases = getattr(registry, "PHASES", [])
                if phases_module:
                    try:
                        phases = getattr(importlib.import_module(phases_module), "PHASES", phases)
                    except Exception:
                        pass
                phase_by_module, phase_name_by_module = self._phase_lookup(phases)
            except Exception as exc:
                log.debug(
                    "Plugin discovery failed for %s (%s)",
                    framework,
                    type(exc).__name__,
                )
                continue

            for name, import_path in sorted(module_map.items()):
                class_name = class_map.get(name, "")
                loadable = False
                error = ""
                try:
                    mod = importlib.import_module(import_path)
                    loadable = bool(class_name and hasattr(mod, class_name))
                except Exception as exc:
                    error = type(exc).__name__
                plugins.append({
                    "id": f"{framework}:{name}",
                    "framework": framework,
                    "name": name,
                    "import_path": import_path,
                    "class_name": class_name,
                    "phase": phase_by_module.get(name),
                    "phase_name": phase_name_by_module.get(name),
                    "loadable": loadable,
                    "error": error,
                })
        return plugins

    def _supervisor_snapshot(self) -> dict[str, Any]:
        """Return process-manager metadata for dashboard-launched child processes."""
        processes = []
        durable_by_id = {
            str(row.get("scan_id") or ""): row
            for row in self._durable_jobs_for_read_projection(limit=1000)
        }
        for key, info in sorted(self._active_scans.items()):
            proc = info.get("proc")
            rc = info.get("returncode")
            if rc is None and proc is not None:
                rc = proc.poll()
            root_scan_id = self._base_scan_id(key)
            durable = durable_by_id.get(root_scan_id)
            status = (
                str(durable.get("status"))
                if durable is not None
                else "orphaned"
            )
            processes.append({
                "process_id": key,
                "root_scan_id": root_scan_id,
                "pid": getattr(proc, "pid", None),
                "type": info.get("type", ""),
                "target": info.get("target", ""),
                "status": status,
                "lifecycle_authority": (
                    "task103" if durable is not None else "unverified_legacy"
                ),
                "return_code": rc,
                "started_at": info.get("started_dt"),
                "control_file": info.get("control_file", ""),
                "log_path": str(self._scan_logs_dir / f"{key}.log"),
                "command": info.get("command", []),
                "engagement": info.get("engagement", ""),
                "dashboard_url": info.get("dashboard_url", ""),
                "requested_modules": info.get("requested_modules", []),
                "actual_modules": info.get("actual_modules", []),
                "scan_options": info.get("scan_options", {}),
                "control": info.get("control", {}),
            })
        return {
            "processes": processes,
            "counts": {
                "total": len(processes),
                "running": sum(
                    1
                    for item in processes
                    if item["status"]
                    not in {
                        JobState.CANCELED.value,
                        JobState.PARTIAL.value,
                        JobState.FAILED.value,
                        JobState.COMPLETED.value,
                        JobState.EXPIRED.value,
                        JobState.ORPHANED.value,
                    }
                ),
                "terminal": sum(
                    1
                    for item in processes
                    if item["status"]
                    in {
                        JobState.CANCELED.value,
                        JobState.PARTIAL.value,
                        JobState.FAILED.value,
                        JobState.COMPLETED.value,
                        JobState.EXPIRED.value,
                        JobState.ORPHANED.value,
                    }
                ),
            },
            "kill_switch_active": self._kill_switch_active(),
        }

    def _sanitize_cmd(self, cmd: list[str]) -> list[str]:
        """Redact any sensitive argv values before storing command metadata."""
        sensitive_flags = {
            "--password",
            "--token",
            "--cookie",
            "--cookie-jar",
            "--secret",
            "--proxy",
            "--http-proxy",
            "--https-proxy",
        }
        sanitized: list[str] = []
        skip_next = False
        for part in cmd:
            if skip_next:
                sanitized.append("<redacted>")
                skip_next = False
                continue
            flag, separator, _value = part.partition("=")
            if separator and flag in sensitive_flags:
                sanitized.append(f"{flag}=<redacted>")
                continue
            sanitized.append(part)
            if flag in sensitive_flags:
                skip_next = True
        return sanitized

    def _json_artifact_payload(self, value: Any, *, redact: bool = True) -> bytes:
        """Serialize a dashboard artifact only after purpose-bound redaction."""
        try:
            prepared = redact_authorization_value(value) if redact else value
            return json.dumps(
                prepared,
                indent=2,
                sort_keys=True,
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
        except Exception:
            raise DashboardArtifactError("dashboard artifact serialization failed") from None

    def _write_json_artifact(
        self,
        path: Path,
        value: Any,
        *,
        redact: bool = True,
    ) -> None:
        """Redact, serialize, and atomically persist an owner-only JSON artifact."""
        payload = self._json_artifact_payload(value, redact=redact)
        _atomic_write_artifact(path, payload, mode=0o600)

    @staticmethod
    def _load_json_artifact(
        path: Path,
        *,
        linked_entry_as_absent: bool = False,
    ) -> Any | None:
        """Load JSON without consulting a symlink or multi-link alias target.

        Replaceable history/template stores may treat an unsafe linked entry as
        absent, then atomically replace that directory entry. Authentication and
        kill-switch state instead fail closed on the same condition.
        """
        metadata = _artifact_lstat(path)
        if metadata is None:
            return None
        if linked_entry_as_absent and (
            stat.S_ISLNK(metadata.st_mode)
            or (stat.S_ISREG(metadata.st_mode) and metadata.st_nlink != 1)
        ):
            return None
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise DashboardArtifactError("dashboard JSON artifact is not a single-link regular file")
        try:
            return json.loads(_read_artifact_text(path, required_mode=0o600))
        except DashboardArtifactError:
            raise
        except Exception:
            raise DashboardArtifactError("dashboard JSON artifact is invalid") from None

    @property
    def is_paused(self) -> bool:
        return bool(
            self._durable_job_state().list_jobs(
                tenant_id=self.tenant_id,
                states=(JobState.PAUSED,),
                limit=1,
            )
        )

    @property
    def is_aborted(self) -> bool:
        return bool(
            self._durable_job_state().list_jobs(
                tenant_id=self.tenant_id,
                states=(JobState.CANCELING, JobState.CANCELED),
                limit=1,
            )
        )

    # ── Subprocess Control ────────────────────────────────────────────

    def _init_control_file(self, scan_id: str) -> Path:
        """Create a shared control file for all subprocesses in one scan."""
        scan_id = _artifact_identifier(scan_id)
        path = self._control_dir / f"{scan_id}.json"
        self._write_control_file(path, paused=False, aborted=False)
        return path

    def _write_control_file(self, path: Path, paused: bool, aborted: bool) -> None:
        payload = {
            "paused": paused,
            "aborted": aborted,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        try:
            self._write_json_artifact(path, payload)
        except Exception as exc:
            log.warning(
                "Could not write dashboard control state reason=%s",
                type(exc).__name__,
            )
            raise DashboardArtifactError("dashboard control state persistence failed") from None

    def _durable_control_file_path(
        self,
        job: Mapping[str, Any],
    ) -> Path | None:
        """Resolve only the adapter path bound in a durable job payload."""

        payload = job.get("payload")
        path_str = (
            str(payload.get("control_file") or "")
            if isinstance(payload, Mapping)
            else ""
        )
        if not path_str:
            return None
        scan_id = _artifact_identifier(str(job.get("id") or ""))
        supplied_path = Path(path_str)
        expected_path = self._control_dir / f"{scan_id}.json"
        if supplied_path != expected_path:
            raise DashboardArtifactError(
                "durable control-file binding is outside the scan adapter"
            )
        return supplied_path

    def _write_all_control_files(self, state: dict[str, bool]) -> None:
        seen: set[str] = set()
        for job in self._durable_job_state().list_jobs(
            tenant_id=self.tenant_id,
            limit=10_000,
        ):
            self._write_scan_control_files(str(job["id"]), state)
            payload = job.get("payload")
            if isinstance(payload, Mapping) and payload.get("control_file"):
                seen.add(str(payload["control_file"]))
        for info in self._active_scans.values():
            path_str = info.get("control_file")
            if not path_str or path_str in seen:
                continue
            seen.add(path_str)
            self._write_control_file(
                Path(path_str),
                paused=bool(state.get("paused", False)),
                aborted=bool(state.get("aborted", False)),
            )

    def _write_scan_control_files(
        self,
        scan_id: str,
        state: Mapping[str, bool],
    ) -> None:
        """Project one persisted job control state to its child adapters."""

        seen: set[str] = set()
        durable = self._durable_job_state().get_job(
            scan_id,
            tenant_id=self.tenant_id,
        )
        if durable is not None:
            supplied_path = self._durable_control_file_path(durable)
            if supplied_path is not None:
                seen.add(str(supplied_path))
                self._write_control_file(
                    supplied_path,
                    paused=bool(state.get("paused", False)),
                    aborted=bool(state.get("aborted", False)),
                )
        for key, info in self._active_scans.items():
            if self._base_scan_id(key) != scan_id:
                continue
            path_str = str(info.get("control_file") or "")
            if not path_str or path_str in seen:
                continue
            seen.add(path_str)
            self._write_control_file(
                Path(path_str),
                paused=bool(state.get("paused", False)),
                aborted=bool(state.get("aborted", False)),
            )

    def _signal_scan_processes(self, scan_id: str, operation: str) -> None:
        """Apply pause/resume through each persisted full process identity."""

        if operation not in {"pause", "resume"}:
            raise ValueError("unsupported durable process control operation")
        service = self._durable_job_state()
        controller = getattr(self._job_process_supervisor, operation)
        for row in service.list_processes(
            scan_id,
            tenant_id=self.tenant_id,
        ):
            if str(row.get("state") or "") in {"stopped", "orphaned"}:
                continue
            try:
                identity = ProcessIdentity(
                    pid=int(row["pid"]),
                    start_token=str(row["start_token"]),
                    boot_id=str(row["boot_id"]),
                    command_digest=str(row["command_digest"]),
                    launch_nonce=str(row["launch_nonce"]),
                )
                controller(identity)
            except Exception as exc:
                service.append_log(
                    scan_id,
                    f"process {operation} could not be enforced",
                    tenant_id=self.tenant_id,
                    level="error",
                    attempt_id=str(row["attempt_id"]),
                    data={
                        "identity_key": row["identity_key"],
                        "error_type": type(exc).__name__,
                    },
                    actor="dashboard-control",
                )
                raise DashboardArtifactError(
                    f"durable process {operation} could not be enforced"
                ) from None
            service.append_log(
                scan_id,
                f"process {operation} enforced",
                tenant_id=self.tenant_id,
                attempt_id=str(row["attempt_id"]),
                data={"identity_key": row["identity_key"]},
                actor="dashboard-control",
            )

    def _terminate_active_scans(self, status: str = "stopped") -> list[str]:
        """Cancel durable jobs through full persisted child identity only."""

        service = self._durable_job_state()
        canceled: list[str] = []
        scan_ids = sorted(
            {
                self._base_scan_id(key)
                for key in self._active_scans
            }
        )
        for scan_id in scan_ids:
            if service.get_job(scan_id, tenant_id=self.tenant_id) is None:
                log.warning(
                    "Refusing PID-only cancellation for legacy scan %s",
                    str(redact_authorization_value(scan_id))[:100],
                )
                continue
            try:
                job = service.cancel_job(
                    scan_id,
                    tenant_id=self.tenant_id,
                    actor=TransitionActor(
                        tenant_id=self.tenant_id,
                        actor_id="dashboard-global-control",
                        role="system",
                    ),
                    reason=f"operator {status}",
                    supervisor=self._job_process_supervisor,
                    sla_seconds=5.0,
                )
            except (InvalidTransition, LeaseError, KeyError) as exc:
                log.warning(
                    "Could not cancel durable dashboard scan %s reason=%s",
                    str(redact_authorization_value(scan_id))[:100],
                    type(exc).__name__,
                )
                continue
            for key, info in self._active_scans.items():
                if self._base_scan_id(key) == scan_id:
                    info["status"] = job["state"]
                    canceled.append(key)
            self._sync_scan_job_from_active(scan_id)
        return canceled

    # ── Scan History (lightweight JSON store) ─────────────────────────

    @staticmethod
    def _base_scan_id(scan_key: str) -> str:
        """Return the user-facing scan id from a framework-specific process key."""
        for suffix in ("_net_auto", "_web", "_net"):
            if scan_key.endswith(suffix):
                return scan_key[: -len(suffix)]
        return scan_key

    def _tenant_data_path(self, filename: str, *, legacy_default: Path) -> Path:
        """Return a traversal-safe per-tenant control-plane data path."""
        state_root = getattr(self, "_dashboard_state_root", None)
        if self.tenant_id == "default":
            return state_root / filename if state_root is not None else legacy_default
        tenant_ref = hashlib.sha256(self.tenant_id.encode("utf-8")).hexdigest()[:24]
        tenant_root = state_root or Path(__file__).parent.parent.parent / "tmp"
        return tenant_root / "dashboard_tenants" / tenant_ref / filename

    @property
    def _history_path(self) -> Path:
        """Path to the scan history JSON file (next to engagement.db)."""
        forge_root = Path(__file__).parent.parent.parent
        return self._tenant_data_path(
            "scan_history.json",
            legacy_default=forge_root / "scan_history.json",
        )

    @property
    def _scan_fingerprint_path(self) -> Path:
        """Path to incremental scan fingerprint/rate state."""
        forge_root = Path(__file__).parent.parent.parent
        return self._tenant_data_path(
            "scan_fingerprints.json",
            legacy_default=forge_root / "tmp" / "scan_fingerprints.json",
        )

    def _scan_fingerprint_store(self):
        """Load the passive incremental scan state store."""
        from common.scan_fingerprint import ScanFingerprintStore

        return ScanFingerprintStore(self._scan_fingerprint_path)

    def _scan_fingerprint_from_payload(self, payload: dict[str, Any]):
        """Build one scan fingerprint from API payload fields."""
        from common.scan_fingerprint import build_scan_fingerprint

        return build_scan_fingerprint(
            str(payload.get("host") or payload.get("target") or ""),
            payload.get("service"),
            port=payload.get("port"),
            protocol=payload.get("protocol") or "tcp",
            attributes=payload.get("attributes") or {},
        )

    def _scan_fingerprints_from_payload(self, payload: object):
        """Build multiple scan fingerprints from a dashboard API payload."""
        if not isinstance(payload, dict):
            raise HTTPException(
                status_code=400,
                detail={"reason_code": _SCAN_FINGERPRINT_INPUT_INVALID},
            )
        raw_targets = payload.get("targets")
        if raw_targets is None:
            raw_targets = [payload]
        if not isinstance(raw_targets, list):
            raise HTTPException(
                status_code=400,
                detail={"reason_code": _SCAN_FINGERPRINT_INPUT_INVALID},
            )
        if not all(isinstance(item, dict) for item in raw_targets):
            raise HTTPException(
                status_code=400,
                detail={"reason_code": _SCAN_FINGERPRINT_INPUT_INVALID},
            )
        try:
            return [self._scan_fingerprint_from_payload(item) for item in raw_targets]
        except (TypeError, ValueError):
            raise HTTPException(
                status_code=400,
                detail={"reason_code": _SCAN_FINGERPRINT_INPUT_INVALID},
            ) from None

    @property
    def _scan_jobs_db_path(self) -> Path:
        """Path to durable dashboard scan job state."""
        forge_root = Path(__file__).parent.parent.parent
        default_history_path = forge_root / "scan_history.json"
        if self._history_path == default_history_path:
            return forge_root / "scan_jobs.db"
        return self._history_path.with_suffix(".db")

    def _with_scan_jobs_session(self, callback: Any) -> Any:
        """Run a short-lived scan job DB operation."""
        session = create_db(self._scan_jobs_db_path)
        try:
            return callback(session)
        finally:
            session.close()

    @property
    def _agents_path(self) -> Path:
        """Legacy JSON import/projection path; never lifecycle authority."""
        forge_root = Path(__file__).parent.parent.parent
        return self._tenant_data_path(
            "scan_agents.json",
            legacy_default=forge_root / "tmp" / "scan_agents.json",
        )

    @property
    def _kill_switch_path(self) -> Path:
        """JSON state for the operator kill switch."""
        forge_root = Path(__file__).parent.parent.parent
        return self._tenant_data_path(
            "operator_kill_switch.json",
            legacy_default=forge_root / "tmp" / "operator_kill_switch.json",
        )

    def _kill_switch_active(self) -> bool:
        """Return True when active execution should be refused."""
        if os.environ.get("FORGE_KILL_SWITCH", "").strip().lower() in {"1", "true", "yes", "on"}:
            return True
        try:
            data = self._load_json_artifact(self._kill_switch_path)
            if data is None:
                return False
            if not isinstance(data, dict) or type(data.get("enabled")) is not bool:
                raise DashboardArtifactError("dashboard kill-switch state is invalid")
            return data["enabled"]
        except Exception as exc:
            log.warning(
                "Could not load dashboard kill-switch state reason=%s",
                type(exc).__name__,
            )
            # Corrupt, linked, or unreadable control state is not evidence that
            # active execution was re-enabled.
            return True

    def _set_kill_switch(self, enabled: bool, reason: str = "", operator: str = "") -> dict[str, Any]:
        """Persist operator kill-switch state."""
        payload = self._redact_agent_payload({
            "enabled": bool(enabled),
            "reason": reason,
            "operator": operator,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        })
        if not isinstance(payload, dict):
            raise DashboardArtifactError("dashboard kill-switch state is invalid")
        try:
            with self._artifact_state_lock:
                self._write_json_artifact(self._kill_switch_path, payload)
        except Exception as exc:
            log.warning(
                "Could not persist dashboard kill-switch state reason=%s",
                type(exc).__name__,
            )
            raise DashboardArtifactError("dashboard kill-switch persistence failed") from None
        return payload

    def _write_audit_log(
        self,
        *,
        operator: str,
        role: str,
        ip: str,
        action: str,
        object_id: str = "",
        status: str = "ok",
        detail: dict[str, Any] | None = None,
    ) -> bool:
        """Persist a bounded operator audit event."""
        def _text(value: Any, limit: int) -> str:
            rendered = str(redact_authorization_value(str(value or "")))
            rendered = re.sub(r"[\x00-\x1f\x7f]", "?", rendered)
            return rendered[:limit]

        safe_detail = self._redact_agent_payload(detail or {})
        try:
            encoded_detail = json.dumps(
                safe_detail,
                sort_keys=True,
                separators=(",", ":"),
                default=str,
            )
        except Exception:
            encoded_detail = "{}"
            safe_detail = {}
        if len(encoded_detail.encode("utf-8")) > 8192:
            safe_reason = ""
            if isinstance(safe_detail, dict):
                safe_reason = _text(safe_detail.get("reason_code", ""), 100)
            safe_detail = {
                "reason_code": safe_reason,
                "detail_truncated": True,
                "detail_sha256": hashlib.sha256(encoded_detail.encode("utf-8")).hexdigest(),
            }

        def _save(session: Any) -> None:
            save_audit_log(
                session,
                {
                    "tenant_id": self.tenant_id,
                    "operator": _text(operator, 200),
                    "role": _text(role, 50),
                    "ip": _text(ip, 100),
                    "action": _text(action, 200),
                    "object_id": _text(object_id, 500),
                    "status": _text(status, 50),
                    "detail": safe_detail,
                },
            )

        try:
            self._with_scan_jobs_session(_save)
            return True
        except Exception as exc:
            log.debug(
                "Could not write dashboard audit log action=%s reason=%s",
                _text(action, 100),
                type(exc).__name__,
            )
            return False

    def _load_audit_logs(self, limit: int = 100) -> list[dict[str, Any]]:
        """Load recent operator audit events newest-first."""
        def _load(session: Any) -> list[dict[str, Any]]:
            rows = (
                session.query(AuditLogModel)
                .filter_by(tenant_id=self.tenant_id)
                .order_by(AuditLogModel.timestamp.desc(), AuditLogModel.id.desc())
                .limit(limit)
                .all()
            )
            return [audit_log_to_dict(row) for row in rows]

        try:
            return self._with_scan_jobs_session(_load)
        except Exception as exc:
            log.warning(
                "Could not load dashboard audit logs reason=%s",
                type(exc).__name__,
            )
            return []

    def _agent_state(self) -> dict[str, Any]:
        """Return a redacted projection rebuilt only from durable SQLite."""
        durable = self._durable_job_state()
        agents = [
            self._sanitize_agent(
                {
                    **agent,
                    "name": agent.get("display_name", ""),
                    "host": agent.get("host_label", ""),
                    "platform": agent.get("platform_label", ""),
                    "status": agent.get("state", "idle"),
                }
            )
            for agent in durable.list_agents(tenant_id=self.tenant_id)
        ]
        jobs: list[dict[str, Any]] = []
        for durable_job in durable.list_jobs(
            tenant_id=self.tenant_id,
            limit=1000,
        ):
            if not durable_job.get("assigned_agent_id"):
                continue
            payload = durable_job.get("payload")
            projection = dict(payload) if isinstance(payload, Mapping) else {}
            projection.update(
                {
                    "id": durable_job.get("id"),
                    "tenant_id": durable_job.get("tenant_id"),
                    "agent_id": durable_job.get("assigned_agent_id"),
                    "status": durable_job.get("state"),
                    "run_id": durable_job.get("run_id"),
                    "updated_at": durable_job.get("updated_at"),
                    "completed_at": durable_job.get("terminal_at"),
                    "error": durable_job.get("error_reason"),
                    "result": None,
                }
            )
            attempts = durable.list_attempts(
                str(durable_job["id"]),
                tenant_id=self.tenant_id,
            )
            if attempts:
                projection["attempt_id"] = attempts[-1].get("id")
                projection["lease_generation"] = attempts[-1].get(
                    "lease_generation"
                )
                projection["lease_expires_at"] = attempts[-1].get(
                    "lease_expires_at"
                )
            jobs.append(self._sanitize_agent_job(projection))
        counts = {
            "total_agents": len(agents),
            "online": sum(1 for a in agents if a.get("status") in {"online", "idle", "running"}),
            "queued_jobs": sum(1 for j in jobs if j.get("status") == "queued"),
            "running_jobs": sum(1 for j in jobs if j.get("status") == "running"),
            "completed_jobs": sum(1 for j in jobs if j.get("status") == "completed"),
        }
        return {"agents": agents, "jobs": jobs, "counts": counts}

    def _sanitize_agent(self, agent: dict[str, Any]) -> dict[str, Any]:
        """Return agent metadata safe for frontend display."""
        hidden = {
            "registration_token", "token", "secret", "client_key",
            "credential_digest", "lease_digest", "accepted_lease_digest", "result_digest",
            "enrollment_hint_digest", "mtls_subject_digest",
        }
        return {k: v for k, v in agent.items() if k not in hidden}

    def _sanitize_agent_job(self, job: dict[str, Any]) -> dict[str, Any]:
        """Return agent job metadata safe for frontend/agent display."""
        hidden = {"lease_digest", "accepted_lease_digest", "result_digest"}
        result = self._redact_agent_payload(job.get("result"))
        error = self._redact_agent_payload(job.get("error"))
        return {**{k: v for k, v in job.items() if k not in hidden}, "result": result, "error": error}

    def _redact_agent_payload(self, value: Any) -> Any:
        """Best-effort recursive redaction for agent-supplied result payloads."""
        secret_words = ("password", "secret", "token", "cookie", "credential", "authorization")
        if isinstance(value, dict):
            redacted: dict[str, Any] = {}
            for index, (key, item) in enumerate(value.items()):
                key_s = str(self._redact_agent_payload(str(key)))[:200]
                if key_s in redacted:
                    key_s = f"{key_s}#{index}"
                if any(word in key_s.lower() for word in secret_words):
                    redacted[key_s] = "<redacted>"
                else:
                    redacted[key_s] = self._redact_agent_payload(item)
            return redacted
        if isinstance(value, list):
            return [self._redact_agent_payload(item) for item in value]
        return redact_authorization_value(value)

    def _sanitize_agent_result(self, value: Any) -> dict[str, Any]:
        """Retain bounded observation content while removing server-owned truth."""
        if not isinstance(value, dict):
            return {}

        remaining_nodes = [10_000]

        def _sanitize(item: Any, *, depth: int = 0) -> Any:
            remaining_nodes[0] -= 1
            if depth > 8 or remaining_nodes[0] < 0:
                return None
            if isinstance(item, dict):
                sanitized: dict[str, Any] = {}
                for raw_key, nested in list(item.items())[:500]:
                    key = str(raw_key)[:200]
                    if key.strip().lower() in _AGENT_RESULT_SERVER_FIELDS:
                        continue
                    sanitized[key] = _sanitize(nested, depth=depth + 1)
                return sanitized
            if isinstance(item, list):
                return [_sanitize(nested, depth=depth + 1) for nested in item[:1000]]
            if isinstance(item, str):
                return item[:16_384]
            if item is None or isinstance(item, (bool, int, float)):
                return item
            # HTTP JSON input should contain only the types above.  Keep direct
            # helper calls deterministic without serializing arbitrary objects.
            return str(item)[:16_384]

        sanitized = _sanitize(value)
        return cast(dict[str, Any], self._redact_agent_payload(sanitized))

    @staticmethod
    def _agent_digest(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    @classmethod
    def _agent_subject_digest(cls, value: str) -> str:
        """Bind an mTLS subject without persisting its potentially sensitive text."""
        return cls._agent_digest(f"forge-agent-mtls\0{value}") if value else ""

    def _agent_now(self) -> datetime:
        """Clock seam used by deterministic lease-expiry tests."""
        return datetime.now(timezone.utc)

    @staticmethod
    def _agent_timestamp(value: Any) -> datetime | None:
        """Parse only timezone-aware persisted lease timestamps."""
        try:
            parsed = datetime.fromisoformat(str(value or ""))
        except (TypeError, ValueError):
            return None
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            return None
        return parsed

    def _agent_lease_seconds(self) -> int:
        try:
            return max(15, min(900, int(os.environ.get("FORGE_AGENT_LEASE_SECONDS", "120"))))
        except ValueError:
            return 120

    def _agent_lease_max_seconds(self) -> int:
        """Bound total ownership time independently of heartbeat frequency."""
        minimum = self._agent_lease_seconds()
        try:
            configured = int(os.environ.get("FORGE_AGENT_LEASE_MAX_SECONDS", "3600"))
        except ValueError:
            configured = 3600
        return max(minimum, min(86400, configured))

    @staticmethod
    def _agent_header_value(request: Any, name: str) -> str:
        try:
            return str(request.headers.get(name, "")).strip()
        except Exception:
            return ""

    def _require_agent_token(
        self,
        request: Any,
        body: dict[str, Any] | None = None,
        *,
        allow_bootstrap: bool = True,
    ) -> dict[str, Any]:
        """Authenticate bootstrap or issued agent credentials before body parsing."""
        del body
        supplied = self._agent_header_value(request, "X-Forge-Agent-Credential")
        bootstrap = self._agent_header_value(request, "X-Forge-Agent-Token")
        peer_subject = self._mtls_subject_from_request(request, {})
        expected = os.environ.get("FORGE_AGENT_REGISTRATION_TOKEN", "").strip()
        if allow_bootstrap and not expected and not peer_subject:
            raise HTTPException(status_code=503, detail={"reason_code": "agent_auth_not_configured"})
        if allow_bootstrap and bootstrap and expected and hmac.compare_digest(bootstrap, expected):
            return {
                "kind": "bootstrap",
                "peer_subject": peer_subject,
                "key_id": f"bootstrap-{self._agent_digest(expected)[:16]}",
            }
        supplied_digest = self._agent_digest(supplied) if supplied else ""
        if supplied_digest:
            durable = self._job_state_service
            if (
                durable is None
                or self._job_state_service_path != str(self._scan_jobs_db_path)
                or getattr(durable, "_closed", False)
            ):
                raise HTTPException(
                    status_code=503,
                    detail={"reason_code": "agent_control_plane_unavailable"},
                )
            agent = durable.authenticate_agent(
                supplied_digest,
                tenant_id=self.tenant_id,
                mtls_subject_digest=self._agent_subject_digest(peer_subject),
            )
            if agent is not None:
                return {
                    "kind": "agent",
                    "agent_id": str(agent.get("id") or ""),
                    "tenant_id": str(agent.get("tenant_id") or ""),
                    "key_id": str(agent.get("key_id") or ""),
                    "peer_subject": peer_subject,
                }
        if allow_bootstrap and peer_subject:
            return {"kind": "mtls", "peer_subject": peer_subject}
        if not supplied and not (allow_bootstrap and bootstrap) and not peer_subject:
            raise HTTPException(status_code=401, detail={"reason_code": "agent_auth_required"})
        raise HTTPException(status_code=401, detail={"reason_code": "agent_credential_invalid"})

    def _mtls_subject_from_request(self, request: Any, body: dict[str, Any]) -> str:
        """Derive identity only from an ASGI-verified TLS peer certificate."""
        del body
        try:
            ssl_object = request.scope.get("ssl_object")
            certificate = ssl_object.getpeercert() if ssl_object is not None else None
        except Exception:
            certificate = None
        if not isinstance(certificate, dict):
            return ""
        subject_parts: list[str] = []
        for group in certificate.get("subject", ()):
            for key, value in group:
                rendered_key = str(key).strip()
                rendered_value = str(value).strip()
                if rendered_key and rendered_value:
                    subject_parts.append(f"{rendered_key}={rendered_value}")
        return ",".join(subject_parts)[:500]

    def _register_scan_agent(
        self,
        body: dict[str, Any],
        request: Any,
        *,
        identity: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Register an agent and issue a per-agent credential exactly once per call."""
        if not isinstance(body, dict):
            raise HTTPException(status_code=400, detail="JSON body is required")
        identity = (
            identity
            if isinstance(identity, dict)
            else self._require_agent_token(request, allow_bootstrap=True)
        )
        if identity.get("kind") == "agent" and not hmac.compare_digest(
            str(identity.get("tenant_id") or ""),
            self.tenant_id,
        ):
            raise HTTPException(
                status_code=403,
                detail={"reason_code": "agent_tenant_mismatch"},
            )
        audit_job_id = self._server_job_id()
        peer_subject = str(identity.get("peer_subject") or "")
        requested_id = str(body.get("agent_id") or body.get("id") or "").strip()[:80]
        enrollment_hint_digest = ""
        if identity.get("kind") == "agent":
            agent_id = str(identity["agent_id"])
            if requested_id and not hmac.compare_digest(requested_id, agent_id):
                raise HTTPException(status_code=403, detail={"reason_code": "agent_identity_mismatch"})
        elif peer_subject:
            # Stable identifier derived from the authenticated transport identity.
            agent_id = f"agent-{self._agent_digest(peer_subject)[:24]}"
        elif identity.get("kind") == "bootstrap":
            # A shared enrollment secret authenticates only the bootstrap action;
            # it never makes request JSON an identity credential.
            if not requested_id or not _JOB_ID_RE.fullmatch(requested_id):
                raise HTTPException(
                    status_code=400,
                    detail={"reason_code": "agent_enrollment_hint_required"},
                )
            bootstrap_secret = os.environ.get(
                "FORGE_AGENT_REGISTRATION_TOKEN",
                "",
            ).strip()
            if not bootstrap_secret:
                raise HTTPException(
                    status_code=503,
                    detail={"reason_code": "agent_auth_not_configured"},
                )
            enrollment_hint_digest = hmac.new(
                bootstrap_secret.encode("utf-8"),
                requested_id.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            agent_id = f"agent-{uuid.uuid4().hex}"
        else:
            raise HTTPException(
                status_code=401,
                detail={"reason_code": "agent_credential_required"},
            )
        if not _JOB_ID_RE.fullmatch(agent_id):
            raise HTTPException(status_code=400, detail="valid agent identity is required")

        engines = self._string_list(body.get("engines") or body.get("supported_engines") or ["webforge", "netforge"])
        allowed_engines = {"webforge", "netforge", "adforge", "aiforge"}
        if not engines or any(engine not in allowed_engines for engine in engines):
            raise HTTPException(status_code=400, detail={"reason_code": "agent_capability_invalid"})
        capabilities = self._string_list(body.get("capabilities") or ["dry_run"])
        allowed_capabilities = {"dry_run", "active_scan", "result_streaming", "scoped_jobs"}
        if not capabilities or any(item not in allowed_capabilities for item in capabilities):
            raise HTTPException(status_code=400, detail={"reason_code": "agent_capability_invalid"})
        scope = self._scope_entries(body.get("scope"))
        excluded_value = body.get("exclude") if body.get("exclude") is not None else body.get("excluded_scope")
        excluded_scope = self._scope_entries(excluded_value)

        def _deny_registration(decision: ScopeDecision) -> NoReturn:
            self._audit_preflight_denial(
                decision, action_kind="agent.register", engine="forge-agent",
                target=body.get("host", "local-agent"), allowed_scope=scope,
                excluded_scope=excluded_scope, job_id=audit_job_id,
                operator_id=agent_id, operator_role=OperatorRole.AGENT,
                safety_mode=SafetyMode.PASSIVE,
            )
            self._raise_scope_denial(decision)

        scope_syntax = self._scope_syntax_decision(scope, excluded_scope)
        if not scope_syntax.allowed:
            _deny_registration(scope_syntax)
        try:
            active_scan_enabled = self._request_bool(body, "active_scan_enabled", default=False)
        except HTTPException:
            _deny_registration(decision_for_reason(ScopeReason.INVALID_CONFIRMATION))
        if active_scan_enabled and "active_scan" not in capabilities:
            capabilities.append("active_scan")

        registration_kind = str(identity.get("kind") or "")
        durable = self._durable_job_state()
        agents = durable.list_agents(tenant_id=self.tenant_id)
        if registration_kind == "bootstrap":
            duplicate = next(
                (
                    candidate
                    for candidate in agents
                    if hmac.compare_digest(
                        str(candidate.get("enrollment_hint_digest") or ""),
                        enrollment_hint_digest,
                    )
                ),
                None,
            )
            if duplicate is not None:
                raise HTTPException(
                    status_code=409,
                    detail={"reason_code": "agent_already_registered"},
                )
        previous = durable.get_agent(agent_id, tenant_id=self.tenant_id)
        if previous is not None:
            if previous.get("revoked"):
                raise HTTPException(
                    status_code=401,
                    detail={"reason_code": "agent_revoked"},
                )
            if registration_kind == "mtls":
                raise HTTPException(
                    status_code=409,
                    detail={"reason_code": "agent_already_registered"},
                )
            if registration_kind == "agent" and not hmac.compare_digest(
                str(previous.get("key_id") or ""),
                str(identity.get("key_id") or ""),
            ):
                raise HTTPException(
                    status_code=409,
                    detail={"reason_code": "agent_credential_stale"},
                )
            bound_subject_digest = str(
                previous.get("mtls_subject_digest") or ""
            )
            if bound_subject_digest and not hmac.compare_digest(
                bound_subject_digest,
                self._agent_subject_digest(peer_subject),
            ):
                raise HTTPException(
                    status_code=403,
                    detail={"reason_code": "agent_identity_mismatch"},
                )
        credential = secrets.token_urlsafe(32)
        key_id = f"key-{uuid.uuid4().hex}"
        try:
            agent = durable.register_agent(
                agent_id,
                tenant_id=self.tenant_id,
                key_id=key_id,
                credential_digest=self._agent_digest(credential),
                enrollment_hint_digest=(
                    str(previous.get("enrollment_hint_digest") or "")
                    if previous is not None
                    else enrollment_hint_digest or None
                ),
                mtls_subject_digest=(
                    self._agent_subject_digest(peer_subject) or None
                ),
                display_name=str(
                    body.get("name")
                    or (previous or {}).get("display_name")
                    or agent_id
                ),
                host_label=str(
                    body.get("host")
                    or (previous or {}).get("host_label")
                    or ""
                ),
                platform_label=str(
                    body.get("platform")
                    or (previous or {}).get("platform_label")
                    or ""
                ),
                version_label=str(
                    body.get("version")
                    or (previous or {}).get("version_label")
                    or "0.1.0"
                ),
                engines=engines,
                capabilities=capabilities,
                scope=scope,
                excluded_scope=excluded_scope,
                active_scan_enabled=active_scan_enabled,
                expected_version=(
                    int(previous["version"]) if previous is not None else None
                ),
            )
        except (InvalidTransition, ValueError) as exc:
            raise HTTPException(
                status_code=409,
                detail={"reason_code": "agent_registration_conflict"},
            ) from exc
        projected = {
            **agent,
            "name": agent.get("display_name", ""),
            "host": agent.get("host_label", ""),
            "platform": agent.get("platform_label", ""),
            "status": agent.get("state", "idle"),
        }
        return {
            "agent": self._sanitize_agent(projected),
            "credential": credential,
        }

    def _create_agent_job(
        self,
        body: dict[str, Any],
        identity: TokenPayload | None,
    ) -> dict[str, Any]:
        """Create one authorized, durable assignment for a registered agent."""

        if not isinstance(body, dict):
            raise HTTPException(status_code=400, detail="JSON body is required")
        operator_id = identity.username if identity else "operator"
        operator_role = identity.role.value if identity else Role.ADMIN.value
        audit_job_id = self._server_job_id()

        def _deny(
            decision: ScopeDecision,
            *,
            target_value: Any = "agent-job",
            allowed_scope: Any = (),
            excluded_scope: Any = (),
        ) -> NoReturn:
            self._audit_preflight_denial(
                decision,
                action_kind="agent.job.create",
                engine=body.get("engine", "forge-agent"),
                target=target_value,
                allowed_scope=allowed_scope,
                excluded_scope=excluded_scope,
                job_id=audit_job_id,
                operator_id=operator_id,
                operator_role=operator_role,
                safety_mode=SafetyMode.PASSIVE,
            )
            self._raise_scope_denial(decision)

        try:
            self._reject_secret_fields(body)
        except HTTPException:
            self._audit_preflight_denial(
                decision_for_reason(ScopeReason.INVALID_CONFIRMATION),
                action_kind="agent.job.create",
                engine=body.get("engine", "forge-agent"),
                target=body.get("target", "agent-job"),
                allowed_scope=body.get("scope", ()),
                excluded_scope=(
                    body.get("exclude")
                    if body.get("exclude") is not None
                    else body.get("excluded_scope", ())
                ),
                job_id=audit_job_id,
                operator_id=operator_id,
                operator_role=operator_role,
                safety_mode=SafetyMode.PASSIVE,
            )
            raise

        agent_id = str(body.get("agent_id") or "").strip()
        durable = self._durable_job_state()
        agent = durable.get_agent(agent_id, tenant_id=self.tenant_id)
        if agent is None or agent.get("revoked"):
            raise HTTPException(
                status_code=404,
                detail={"reason_code": "agent_not_found"},
            )
        engine = str(body.get("engine") or "").strip().lower()
        if (
            engine not in {"webforge", "netforge", "adforge", "aiforge"}
            or engine not in set(agent.get("engines") or [])
        ):
            raise HTTPException(
                status_code=403,
                detail={"reason_code": "agent_capability_mismatch"},
            )
        raw_target = body.get("target")
        if not isinstance(raw_target, str) or not raw_target.strip():
            _deny(
                decision_for_reason(ScopeReason.MALFORMED_TARGET)
            )
        target = raw_target.strip()
        client_job_id = self._client_job_id(body)
        job_material = (
            f"{self.tenant_id}\x00{agent_id}\x00{client_job_id}"
        ).encode()
        job_id = f"job-{hashlib.sha256(job_material).hexdigest()[:48]}"

        agent_scope = self._scope_entries(agent.get("scope"))
        agent_excluded = self._scope_entries(agent.get("excluded_scope"))
        requested_scope = self._scope_entries(body.get("scope"))
        requested_excluded = self._scope_entries(
            body.get("exclude")
            if body.get("exclude") is not None
            else body.get("excluded_scope")
        )
        syntax = self._scope_syntax_decision(
            requested_scope,
            requested_excluded,
        )
        if not syntax.allowed:
            _deny(
                syntax,
                target_value=target,
                allowed_scope=requested_scope,
                excluded_scope=requested_excluded,
            )
        for entry in requested_scope:
            within = decide_scope(entry, agent_scope, agent_excluded)
            if not within.allowed:
                _deny(
                    within,
                    target_value=target,
                    allowed_scope=requested_scope,
                    excluded_scope=requested_excluded,
                )
        effective_scope = requested_scope
        effective_excluded = list(
            dict.fromkeys([*agent_excluded, *requested_excluded])
        )
        try:
            dry_run = self._request_bool(body, "dry_run", default=True)
        except HTTPException:
            _deny(
                decision_for_reason(ScopeReason.INVALID_CONFIRMATION),
                target_value=target,
                allowed_scope=effective_scope,
                excluded_scope=effective_excluded,
            )
        safety_mode = (
            SafetyMode.PASSIVE
            if dry_run
            else SafetyMode.HIGH_RISK
            if engine == "aiforge"
            else SafetyMode.ACTIVE
        )
        if engine == "adforge" and not dry_run:
            _deny(
                decision_for_reason(ScopeReason.INVALID_CONFIRMATION)
            )
        if not dry_run and not bool(agent.get("active_scan_enabled")):
            _deny(
                decision_for_reason(ScopeReason.MISSING_CONFIRMATION)
            )
        submitted = decide_action(
            target=target,
            allowed_scope=effective_scope,
            excluded_scope=effective_excluded,
            confirmation=body.get("confirmation"),
            job_id=client_job_id,
            engine=engine,
            action="scan",
            require_confirmation=not dry_run,
        )
        if not submitted.allowed:
            _deny(
                submitted,
                target_value=target,
                allowed_scope=effective_scope,
                excluded_scope=effective_excluded,
            )

        modules = self._string_list(body.get("modules") or [])
        capability = "dry_run" if dry_run else "active_scan"
        if capability not in set(agent.get("capabilities") or []):
            raise HTTPException(
                status_code=403,
                detail={"reason_code": "agent_capability_mismatch"},
            )
        client_request_identity = "sha256:" + hashlib.sha256(
            json.dumps(
                {
                    "agent_id": agent_id,
                    "client_job_id": client_job_id,
                    "engine": engine,
                    "target": target,
                    "scope": effective_scope,
                    "excluded_scope": effective_excluded,
                    "modules": modules,
                    "policy_id": str(body.get("policy_id") or "")[:120],
                    "dry_run": dry_run,
                    "safety_mode": safety_mode.value,
                },
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode()
        ).hexdigest()
        existing = durable.get_job(job_id, tenant_id=self.tenant_id)
        if existing is not None:
            payload = existing.get("payload")
            if (
                not isinstance(payload, Mapping)
                or not hmac.compare_digest(
                    str(payload.get("client_request_identity") or ""),
                    client_request_identity,
                )
            ):
                raise HTTPException(
                    status_code=409,
                    detail={"reason_code": "agent_job_idempotency_conflict"},
                )
            projection = dict(payload)
            projection.update(
                {
                    "id": existing["id"],
                    "status": existing["state"],
                    "tenant_id": existing["tenant_id"],
                    "run_id": existing["run_id"],
                    "agent_id": existing["assigned_agent_id"],
                }
            )
            return self._sanitize_agent_job(projection)

        try:
            confirmation_record = ActionConfirmation.create(
                job_id=job_id,
                target=target,
                engine=engine,
                action="scan",
            )
        except (TypeError, ValueError):
            _deny(
                decision_for_reason(ScopeReason.MALFORMED_TARGET)
            )
        scope_decision = decide_action(
            target=target,
            allowed_scope=effective_scope,
            excluded_scope=effective_excluded,
            confirmation=confirmation_record,
            job_id=job_id,
            engine=engine,
            action="scan",
            require_confirmation=True,
        )
        if not scope_decision.allowed:
            _deny(
                scope_decision,
                target_value=target,
                allowed_scope=effective_scope,
                excluded_scope=effective_excluded,
            )
        context = AuthorizationContext(
            tenant_id=self.tenant_id,
            engagement_id=f"engagement-{uuid.uuid5(uuid.NAMESPACE_URL, job_id).hex}",
            run_id=f"run-{uuid.uuid4().hex}",
            job_id=job_id,
            operator_id=operator_id,
            operator_role=OperatorRole(operator_role),
            action_kind="scan",
            engine=engine,
            module_id=module_set_binding(modules),
            requested_target=target,
            resolved_target=target,
            allowed_scope=effective_scope,
            excluded_scope=effective_excluded,
            safety_mode=safety_mode,
            high_risk_approval_required=(engine == "aiforge"),
            confirmation_method=ConfirmationMethod.AGENT_JOB,
            confirmed_by=operator_id,
        )

        def _issue(session: Any) -> Any:
            return issue_authorization(
                session=session,
                context=context,
                confirmation=confirmation_record,
            )

        issued = self._with_scan_jobs_session(_issue)
        if not issued.allowed:
            _deny(
                scope_decision,
                target_value=target,
                allowed_scope=effective_scope,
                excluded_scope=effective_excluded,
            )
        envelope = issued.envelope
        runtime = load_authorization_runtime_facts(
            authorization_runtime_environment(envelope)
        )
        max_attempts_raw = body.get("max_attempts", 1)
        if type(max_attempts_raw) is not int or not 1 <= max_attempts_raw <= 5:
            raise HTTPException(
                status_code=400,
                detail={"reason_code": "agent_max_attempts_invalid"},
            )
        work_plan = modules or ["agent-result"]
        payload = {
            "client_job_id": client_job_id,
            "client_request_identity": client_request_identity,
            "agent_id": agent_id,
            "tenant_id": self.tenant_id,
            "capability": capability,
            "authorization_id": envelope.decision_id,
            "engine": engine,
            "target": target,
            "scope": effective_scope,
            "excluded_scope": effective_excluded,
            "modules": modules,
            "policy_id": str(body.get("policy_id") or "")[:120],
            "safety_mode": safety_mode.value,
            "dry_run": dry_run,
            "action": "scan",
            "confirmation": confirmation_record.to_dict(),
            "authorization_envelope": envelope.to_dict(),
            "authorization_public": envelope.to_event_payload(),
            "runtime_context": runtime,
            "scope_decision": scope_decision.to_dict(),
            "authorized": True,
        }
        try:
            created = durable.create_job(
                payload,
                tenant_id=self.tenant_id,
                job_id=job_id,
                engagement_id=context.engagement_id,
                run_id=context.run_id,
                job_kind=engine,
                target=target,
                authorization_decision_id=envelope.decision_id,
                authorization_action_id=envelope.action_id,
                assigned_agent_id=agent_id,
                idempotency_key=(
                    "agent-job:"
                    + hashlib.sha256(job_material).hexdigest()
                ),
                max_attempts=max_attempts_raw,
                state=JobState.QUEUED,
                work_items=work_plan,
                actor=TransitionActor(
                    tenant_id=self.tenant_id,
                    actor_id=operator_id,
                    role=operator_role,
                    authorization_decision_id=envelope.decision_id,
                ),
                reason="authorized agent job queued",
            )
        except (IdempotencyConflict, InvalidTransition, ValueError) as exc:
            raise HTTPException(
                status_code=409,
                detail={"reason_code": "agent_job_state_conflict"},
            ) from exc
        projection = dict(payload)
        projection.update(
            {
                "id": created["id"],
                "status": created["state"],
                "tenant_id": created["tenant_id"],
                "run_id": created["run_id"],
                "attempt_id": None,
                "lease_generation": 0,
                "lease_expires_at": None,
                "completed_at": None,
                "result": None,
                "error": None,
            }
        )
        return self._sanitize_agent_job(projection)

    def _agent_job_decision(
        self,
        agent: dict[str, Any],
        job: dict[str, Any],
    ) -> ScopeDecision:
        """Revalidate a mutable queued job against the current agent boundary."""
        raw_job_id = job.get("id")
        raw_engine = job.get("engine")
        raw_action = job.get("action", "scan")
        raw_target = job.get("target")
        raw_dry_run = job.get("dry_run", True)
        active_scan_enabled = agent.get("active_scan_enabled", False)
        if not isinstance(raw_job_id, str) or not isinstance(raw_engine, str):
            return decision_for_reason(ScopeReason.INVALID_CONFIRMATION)
        if not isinstance(raw_action, str) or type(raw_dry_run) is not bool:
            return decision_for_reason(ScopeReason.INVALID_CONFIRMATION)
        if not isinstance(raw_target, str):
            return decision_for_reason(ScopeReason.MALFORMED_TARGET)
        if type(active_scan_enabled) is not bool:
            return decision_for_reason(ScopeReason.INVALID_CONFIRMATION)

        job_id = raw_job_id.strip()
        if not _JOB_ID_RE.fullmatch(job_id):
            return decision_for_reason(ScopeReason.INVALID_CONFIRMATION)
        engine = raw_engine.strip().lower()
        if engine not in set(self._string_list(agent.get("engines") or [])):
            return decision_for_reason(ScopeReason.ENGINE_MISMATCH)
        if raw_action.strip().lower() != "scan":
            return decision_for_reason(ScopeReason.ACTION_MISMATCH)

        agent_scope = self._scope_entries(agent.get("scope"))
        agent_excluded = self._scope_entries(agent.get("excluded_scope"))
        job_scope = self._scope_entries(job.get("scope"))
        job_excluded = self._scope_entries(job.get("excluded_scope"))
        syntax = self._scope_syntax_decision(job_scope, job_excluded)
        if not syntax.allowed:
            return syntax
        for entry in job_scope:
            within_agent_scope = decide_scope(entry, agent_scope, agent_excluded)
            if not within_agent_scope.allowed:
                return within_agent_scope

        dry_run = raw_dry_run
        if not dry_run and not active_scan_enabled:
            return decision_for_reason(ScopeReason.MISSING_CONFIRMATION)
        return decide_action(
            target=raw_target,
            allowed_scope=job_scope,
            excluded_scope=job_excluded,
            confirmation=job.get("confirmation"),
            job_id=job_id,
            engine=engine,
            action="scan",
            require_confirmation=not dry_run,
        )

    def _lease_agent_job(
        self,
        agent_id: str,
        identity: dict[str, Any],
    ) -> dict[str, Any] | None:
        """Lease and start one durable assignment for the authenticated agent."""

        if (
            identity.get("kind") != "agent"
            or not hmac.compare_digest(str(identity.get("agent_id") or ""), agent_id)
            or not hmac.compare_digest(
                str(identity.get("tenant_id") or ""), self.tenant_id
            )
        ):
            raise HTTPException(
                status_code=403,
                detail={"reason_code": "agent_identity_mismatch"},
            )
        durable = self._durable_job_state()
        agent = durable.get_agent(agent_id, tenant_id=self.tenant_id)
        if agent is None or agent.get("revoked"):
            raise HTTPException(
                status_code=401,
                detail={"reason_code": "agent_revoked"},
            )
        queued = sorted(
            (
                row
                for row in durable.list_jobs(
                    tenant_id=self.tenant_id,
                    states=(JobState.QUEUED,),
                    limit=1000,
                )
                if hmac.compare_digest(
                    str(row.get("assigned_agent_id") or ""), agent_id
                )
            ),
            key=lambda row: float(row.get("created_at") or 0.0),
        )
        if not queued:
            durable.set_agent_state(agent_id, "idle", tenant_id=self.tenant_id)
            return None
        row = queued[0]
        payload = row.get("payload")
        job = dict(payload) if isinstance(payload, Mapping) else {}
        job.update(
            {
                "id": row["id"],
                "tenant_id": row["tenant_id"],
                "agent_id": row["assigned_agent_id"],
                "status": row["state"],
                "run_id": row["run_id"],
            }
        )
        decision = self._agent_job_decision(agent, job)
        if not decision.allowed:
            durable.cancel_job(
                str(row["id"]),
                tenant_id=self.tenant_id,
                actor=TransitionActor(
                    tenant_id=self.tenant_id,
                    actor_id="agent-lease-policy",
                    role="system",
                ),
                reason=decision.reason_code,
                sla_seconds=0,
            )
            self._raise_scope_denial(decision)
        raw_root_envelope = job.get("authorization_envelope")
        if not isinstance(raw_root_envelope, Mapping):
            raise HTTPException(
                status_code=409,
                detail={"reason_code": "agent_authorization_invalid"},
            )
        try:
            root_envelope = ActionAuthorizationEnvelope.from_value(
                raw_root_envelope
            )
        except Exception as exc:
            raise HTTPException(
                status_code=409,
                detail={"reason_code": "agent_authorization_invalid"},
            ) from exc
        raw_runtime = job.get("runtime_context")
        runtime: Mapping[str, Any] = (
            raw_runtime if isinstance(raw_runtime, Mapping) else {}
        )
        modules = self._string_list(job.get("modules") or [])
        module_binding = module_set_binding(modules)
        expected = AuthorizationContext(
            tenant_id=self.tenant_id,
            engagement_id=str(
                runtime.get("engagement_id") or root_envelope.engagement_id
            ),
            run_id=str(runtime.get("run_id") or root_envelope.run_id),
            job_id=str(row["id"]),
            operator_id=str(
                runtime.get("operator_id") or root_envelope.operator_id
            ),
            operator_role=str(
                runtime.get("operator_role") or root_envelope.operator_role
            ),
            action_kind="scan",
            engine=str(job.get("engine") or root_envelope.engine),
            module_id=module_binding,
            requested_target=str(job.get("target") or ""),
            resolved_target=str(job.get("target") or ""),
            allowed_scope=self._scope_entries(job.get("scope")),
            excluded_scope=self._scope_entries(job.get("excluded_scope")),
            scope_policy_version=str(
                runtime.get("scope_policy_version")
                or root_envelope.scope_policy_version
            ),
            safety_mode=SafetyMode(
                str(job.get("safety_mode") or SafetyMode.PASSIVE.value)
            ),
            high_risk_approval_required=(
                str(job.get("engine") or "") == "aiforge"
            ),
            confirmation_method=ConfirmationMethod.AGENT_JOB,
            confirmed_by=str(
                runtime.get("operator_id") or root_envelope.operator_id
            ),
        )

        prior_attempts = durable.list_attempts(
            str(row["id"]),
            tenant_id=self.tenant_id,
        )
        child_envelope: ActionAuthorizationEnvelope
        if prior_attempts and bool(job.get("dry_run", True)):
            prior_decision_id = str(
                prior_attempts[-1].get("authorization_decision_id") or ""
            )

            def _load_dry_retry_child(
                session: Any,
            ) -> ActionAuthorizationEnvelope | None:
                record = get_authorization_decision(
                    session,
                    prior_decision_id,
                )
                if record is None:
                    return None
                try:
                    envelope = ActionAuthorizationEnvelope.from_value(
                        json.loads(str(record.envelope_json))
                    )
                except Exception:
                    return None
                expected_module = module_set_binding(modules)
                if (
                    envelope.decision_outcome != "allow"
                    or envelope.parent_decision_id != root_envelope.decision_id
                    or envelope.action_kind != "agent.execute"
                    or envelope.tenant_id != self.tenant_id
                    or envelope.job_id != str(row["id"])
                    or envelope.engine != str(job.get("engine") or "")
                    or envelope.module_id != expected_module
                    or not hmac.compare_digest(
                        str(record.binding_digest),
                        envelope.binding_digest,
                    )
                ):
                    return None
                return envelope

            reused = self._with_scan_jobs_session(_load_dry_retry_child)
            if reused is None:
                raise HTTPException(
                    status_code=409,
                    detail={
                        "reason_code": "agent_retry_authorization_invalid"
                    },
                )
            child_envelope = reused
        else:
            def _consume_and_derive(session: Any) -> tuple[Any, Any]:
                consumed = consume_authorization(
                    session=session,
                    envelope=root_envelope,
                    expected=expected,
                    boundary="dashboard.agent_lease",
                )
                if not consumed.allowed:
                    return consumed, None
                child = derive_authorization(
                    session=session,
                    parent_envelope=root_envelope,
                    context=AuthorizationContext(
                        **{
                            **expected.__dict__,
                            "action_kind": "agent.execute",
                            "parent_decision_id": root_envelope.decision_id,
                            "confirmation_method": ConfirmationMethod.INHERITED,
                        }
                    ),
                    parent_boundary="dashboard.agent_lease",
                )
                return consumed, child

            consumed, child = self._with_scan_jobs_session(
                _consume_and_derive
            )
            if not consumed.allowed or child is None or not child.allowed:
                raise HTTPException(
                    status_code=409,
                    detail={
                        "reason_code": "agent_authorization_consumption_failed"
                    },
                )
            child_envelope = child.envelope
        process_capable = job.get("dry_run") is False
        control_boot_id = _DashboardProcessSupervisor._boot_id()
        if process_capable and not control_boot_id:
            raise HTTPException(
                status_code=409,
                detail={"reason_code": "agent_active_worker_not_local"},
            )
        lease_actor = TransitionActor(
            tenant_id=self.tenant_id,
            actor_id=agent_id,
            role="agent",
            authorization_decision_id=child_envelope.decision_id,
        )
        try:
            attempt_number = len(prior_attempts) + 1
            lease = durable.acquire_lease(
                str(row["id"]),
                agent_id,
                tenant_id=self.tenant_id,
                lease_seconds=self._agent_lease_seconds(),
                max_lease_seconds=self._agent_lease_max_seconds(),
                idempotency_key=(
                    f"agent-attempt:{row['id']}:{attempt_number}"
                ),
                attempt_authorization_decision_id=child_envelope.decision_id,
                control_boot_id=(control_boot_id if process_capable else None),
                actor=lease_actor,
            )
            started = durable.start_attempt(
                str(lease["id"]),
                str(lease["lease_token"]),
                tenant_id=self.tenant_id,
                actor=lease_actor,
                worker_id=agent_id,
            )
            durable.set_agent_state(
                agent_id, "running", tenant_id=self.tenant_id
            )
        except (InvalidTransition, LeaseError, LeaseUnavailable) as exc:
            raise HTTPException(
                status_code=409,
                detail={"reason_code": "durable_lease_unavailable"},
            ) from exc
        process_intent: dict[str, Any] | None = None
        if process_capable:
            try:
                process_intent = durable.reserve_process(
                    str(row["id"]),
                    str(started["id"]),
                    "agent-main",
                    lease_token=str(lease["lease_token"]),
                    worker_id=agent_id,
                    control_boot_id=control_boot_id,
                    tenant_id=self.tenant_id,
                    actor=lease_actor,
                )
            except (LeaseError, ProcessIdentityError, KeyError) as exc:
                durable.cancel_job(
                    str(row["id"]),
                    tenant_id=self.tenant_id,
                    actor=TransitionActor(
                        tenant_id=self.tenant_id,
                        actor_id="agent-launch-reservation-failure",
                        role="system",
                    ),
                    reason="agent child launch could not be reserved",
                    supervisor=self._job_process_supervisor,
                    sla_seconds=0,
                )
                raise HTTPException(
                    status_code=409,
                    detail={"reason_code": "agent_process_reservation_failed"},
                ) from exc
        job.update(
            {
                "status": JobState.RUNNING.value,
                "attempt_id": started["id"],
                "attempt_number": started["number"],
                "attempt_run_id": started["run_id"],
                "delivery_idempotency_key": started[
                    "delivery_idempotency_key"
                ],
                "launch_nonce": started["launch_nonce"],
                "lease_token": lease["lease_token"],
                "lease_generation": lease["lease_generation"],
                "lease_expires_at": lease["lease_expires_at"],
                "authorization_id": child_envelope.decision_id,
                "authorization_envelope": child_envelope.to_dict(),
                "authorization_public": child_envelope.to_event_payload(),
                "authorization_db": str(self._scan_jobs_db_path),
            }
        )
        if process_intent is not None:
            job.update(
                {
                    "process_identity_key": str(
                        process_intent["identity_key"]
                    ),
                    "process_launch_nonce": str(
                        process_intent["launch_nonce"]
                    ),
                    "process_control_boot_id": control_boot_id,
                }
            )
        return self._sanitize_agent_job(job)

    def _renew_agent_lease(
        self,
        agent_id: str,
        job_id: str,
        body: dict[str, Any],
        identity: dict[str, Any],
    ) -> dict[str, Any]:
        if not isinstance(body, dict):
            raise HTTPException(status_code=400, detail="JSON body is required")
        if (
            identity.get("kind") != "agent"
            or not hmac.compare_digest(str(identity.get("agent_id") or ""), agent_id)
            or not hmac.compare_digest(
                str(identity.get("tenant_id") or ""), self.tenant_id
            )
        ):
            raise HTTPException(
                status_code=403,
                detail={"reason_code": "agent_identity_mismatch"},
            )
        durable = self._durable_job_state()
        job = durable.get_job(job_id, tenant_id=self.tenant_id)
        if job is None or not hmac.compare_digest(
            str(job.get("assigned_agent_id") or ""), agent_id
        ):
            raise HTTPException(
                status_code=404,
                detail={"reason_code": "agent_job_not_found"},
            )
        attempts = durable.list_attempts(job_id, tenant_id=self.tenant_id)
        if not attempts:
            raise HTTPException(
                status_code=409,
                detail={"reason_code": "lease_not_active"},
            )
        attempt = attempts[-1]
        requested_attempt = str(body.get("attempt_id") or attempt["id"])
        if not hmac.compare_digest(requested_attempt, str(attempt["id"])):
            raise HTTPException(
                status_code=409,
                detail={"reason_code": "lease_assignment_mismatch"},
            )
        try:
            renewed = durable.renew_lease(
                str(attempt["id"]),
                str(body.get("lease_token") or ""),
                lease_seconds=self._agent_lease_seconds(),
                tenant_id=self.tenant_id,
                worker_id=agent_id,
                actor=TransitionActor(
                    tenant_id=self.tenant_id,
                    actor_id=agent_id,
                    role="agent",
                    authorization_decision_id=(
                        str(attempt.get("authorization_decision_id") or "")
                        or None
                    ),
                ),
            )
            durable.set_agent_state(
                agent_id, "running", tenant_id=self.tenant_id
            )
        except LeaseError as exc:
            raise HTTPException(
                status_code=409,
                detail={"reason_code": "durable_lease_renewal_failed"},
            ) from exc
        except (InvalidTransition, KeyError) as exc:
            raise HTTPException(
                status_code=409,
                detail={"reason_code": "durable_lease_renewal_failed"},
            ) from exc
        return {
            **self._sanitize_agent_job(
                {
                    **(job.get("payload") or {}),
                    "id": job["id"],
                    "status": job["state"],
                    "attempt_id": renewed["id"],
                    "lease_generation": renewed["lease_generation"],
                    "lease_expires_at": renewed["lease_expires_at"],
                }
            ),
            "lease_token": renewed["lease_token"],
        }

    def _revoke_agent(
        self, agent_id: str, identity: dict[str, Any]
    ) -> dict[str, Any]:
        if (
            identity.get("kind") != "agent"
            or not hmac.compare_digest(str(identity.get("agent_id") or ""), agent_id)
            or not hmac.compare_digest(
                str(identity.get("tenant_id") or ""), self.tenant_id
            )
        ):
            raise HTTPException(
                status_code=403,
                detail={"reason_code": "agent_identity_mismatch"},
            )
        durable = self._durable_job_state()
        try:
            agent, job_ids = durable.revoke_agent(
                agent_id, tenant_id=self.tenant_id
            )
        except KeyError as exc:
            raise HTTPException(
                status_code=404,
                detail={"reason_code": "agent_not_found"},
            ) from exc
        for job_id_value in job_ids:
            try:
                durable.cancel_job(
                    job_id_value,
                    tenant_id=self.tenant_id,
                    actor=TransitionActor(
                        tenant_id=self.tenant_id,
                        actor_id=f"agent-revocation:{agent_id}",
                        role="system",
                    ),
                    reason="agent credential revoked",
                    supervisor=self._job_process_supervisor,
                    sla_seconds=0,
                )
            except (InvalidTransition, LeaseError, KeyError):
                continue
        return self._sanitize_agent(
            {**agent, "status": agent.get("state", "revoked")}
        )

    def _persist_custodied_job_result(
        self,
        *,
        durable: JobStateService,
        job_id: str,
        attempt: Mapping[str, Any],
        lease_token: str,
        envelope: ActionAuthorizationEnvelope,
        raw_payload: Mapping[str, Any],
        source_target: str,
        outcome: str,
        work: list[dict[str, Any]],
        run_truths: list[RunTruthReceipt],
        worker_id: str,
        actor: TransitionActor,
    ) -> tuple[ObservationReceipt, dict[str, Any]]:
        """Atomically bind Task 102 custody and Task 103 acceptance material."""

        def _reserve_delivery(
            session: Any,
            receipt_data: Mapping[str, Any],
        ) -> None:
            durable.reserve_custodied_result(
                session,
                str(attempt["id"]),
                lease_token,
                delivery_key=str(attempt["delivery_idempotency_key"]),
                tenant_id=self.tenant_id,
                receipt=ObservationReceipt(
                    tenant_id=str(receipt_data["tenant_id"]),
                    job_id=str(receipt_data["job_id"]),
                    attempt_id=str(receipt_data["attempt_id"]),
                    observation_id=str(receipt_data["observation_id"]),
                    artifact_id=str(receipt_data["artifact_id"]),
                    result_ref=str(receipt_data["result_ref"]),
                    manifest_digest=str(receipt_data["manifest_digest"]),
                ),
                outcome=outcome,
                work=work,
                run_truths=run_truths,
                worker_id=worker_id,
                actor=actor,
            )

        custody_root = self._scan_results_dir / _artifact_identifier(job_id)
        _ensure_private_artifact_directory(custody_root)
        session = create_db(self._scan_jobs_db_path)
        try:
            evidence = CanonicalEvidenceService.from_authorization(
                session,
                custody_root / "evidence-custody",
                envelope,
                attempt_id=str(attempt["id"]),
            )
            receipt_data = evidence.persist_job_observation(
                attempt_id=str(attempt["id"]),
                delivery_key=str(attempt["delivery_idempotency_key"]),
                payload=raw_payload,
                source_target=source_target,
                outcome=outcome,
                transaction_guard=_reserve_delivery,
            )
        finally:
            session.close()
        receipt = ObservationReceipt(
            tenant_id=str(receipt_data["tenant_id"]),
            job_id=str(receipt_data["job_id"]),
            attempt_id=str(receipt_data["attempt_id"]),
            observation_id=str(receipt_data["observation_id"]),
            artifact_id=str(receipt_data["artifact_id"]),
            result_ref=str(receipt_data["result_ref"]),
            manifest_digest=str(receipt_data["manifest_digest"]),
        )
        delivery = durable.record_result(
            str(attempt["id"]),
            lease_token,
            delivery_key=str(attempt["delivery_idempotency_key"]),
            tenant_id=self.tenant_id,
            receipt=receipt,
            outcome=outcome,
            work=work,
            run_truths=run_truths,
            worker_id=worker_id,
            actor=actor,
        )
        return receipt, delivery

    def _complete_agent_job(
        self,
        agent_id: str,
        job_id: str,
        body: dict[str, Any],
        identity: dict[str, Any],
    ) -> tuple[dict[str, Any], bool]:
        """Persist one result through Task 102, then finalize its attempt."""

        if not isinstance(body, dict):
            raise HTTPException(status_code=400, detail="JSON body is required")
        if (
            identity.get("kind") != "agent"
            or not hmac.compare_digest(str(identity.get("agent_id") or ""), agent_id)
            or not hmac.compare_digest(
                str(identity.get("tenant_id") or ""), self.tenant_id
            )
        ):
            raise HTTPException(
                status_code=403,
                detail={"reason_code": "agent_identity_mismatch"},
            )
        durable = self._durable_job_state()
        job = durable.get_job(job_id, tenant_id=self.tenant_id)
        if job is None or not hmac.compare_digest(
            str(job.get("assigned_agent_id") or ""), agent_id
        ):
            raise HTTPException(
                status_code=404,
                detail={"reason_code": "agent_job_not_found"},
            )
        attempts = durable.list_attempts(job_id, tenant_id=self.tenant_id)
        if not attempts:
            raise HTTPException(
                status_code=409,
                detail={"reason_code": "lease_not_active"},
            )
        attempt = attempts[-1]
        payload = job.get("payload")
        assignment = dict(payload) if isinstance(payload, Mapping) else {}
        expected_fields = {
            "tenant_id": self.tenant_id,
            "job_id": job_id,
            "agent_id": agent_id,
            "attempt_id": str(attempt["id"]),
            "run_id": str(job["run_id"]),
            "engine": str(assignment.get("engine") or ""),
            "capability": str(assignment.get("capability") or ""),
            "target": str(assignment.get("target") or ""),
            "authorization_id": str(
                attempt.get("authorization_decision_id") or ""
            ),
        }
        for field, expected in expected_fields.items():
            if not hmac.compare_digest(str(body.get(field) or ""), expected):
                raise HTTPException(
                    status_code=409,
                    detail={"reason_code": "result_assignment_mismatch"},
                )
        expected_module_binding = module_set_binding(
            self._string_list(assignment.get("modules") or [])
        )
        if not hmac.compare_digest(
            str(body.get("module_binding") or ""),
            expected_module_binding,
        ):
            raise HTTPException(
                status_code=409,
                detail={"reason_code": "result_assignment_mismatch"},
            )
        if not hmac.compare_digest(
            str(body.get("delivery_idempotency_key") or ""),
            str(attempt["delivery_idempotency_key"]),
        ):
            raise HTTPException(
                status_code=409,
                detail={"reason_code": "result_delivery_identity_mismatch"},
            )
        requested_outcome = str(body.get("outcome") or "").strip().lower()
        if requested_outcome not in {"success", "failure", "canceled", "partial"}:
            raise HTTPException(
                status_code=400,
                detail={"reason_code": "result_outcome_invalid"},
            )
        run_truth_id = str(body.get("run_truth_id") or "").strip()
        active_execution = not bool(assignment.get("dry_run", True))
        decision_id = str(attempt.get("authorization_decision_id") or "")

        def _load_envelope(session: Any) -> ActionAuthorizationEnvelope:
            record = get_authorization_decision(session, decision_id)
            if record is None:
                raise ValueError("attempt authorization is unavailable")
            return ActionAuthorizationEnvelope.from_value(
                json.loads(str(record.envelope_json))
            )

        try:
            envelope = self._with_scan_jobs_session(_load_envelope)
        except Exception as exc:
            raise HTTPException(
                status_code=409,
                detail={"reason_code": "result_authorization_invalid"},
            ) from exc
        result_actor = TransitionActor(
            tenant_id=self.tenant_id,
            actor_id=agent_id,
            role="agent",
            authorization_decision_id=decision_id,
        )
        plan = durable.coverage_snapshot(
            job_id, tenant_id=self.tenant_id
        )["items"]
        run_truths: list[RunTruthReceipt] = []
        work: list[dict[str, Any]] = []
        outcome = requested_outcome
        if active_execution and run_truth_id:
            try:
                inspected_truth = durable.inspect_run_truth(
                    str(attempt["id"]),
                    str(body.get("lease_token") or ""),
                    run_truth_id,
                    tenant_id=self.tenant_id,
                    worker_id=agent_id,
                )
                truth_receipt = cast(
                    RunTruthReceipt,
                    inspected_truth["receipt"],
                )
                run_truths = [truth_receipt]
                outcome = str(inspected_truth["outcome"])
                work = [dict(item) for item in inspected_truth["work"]]
            except (InvalidTransition, LeaseError, KeyError) as exc:
                raise HTTPException(
                    status_code=409,
                    detail={"reason_code": "signed_run_truth_invalid"},
                ) from exc
        elif active_execution and requested_outcome == "success":
            # A worker or process-exit claim is an observation, not completion
            # truth. Preserve it as partial until signed run truth exists.
            outcome = "partial"
        reason = str(
            self._redact_agent_payload(
                body.get("error")
                or (
                    "signed_run_truth_missing"
                    if active_execution and not run_truth_id
                    else "signed_run_truth_outcome_authoritative"
                    if run_truths and outcome != requested_outcome
                    else outcome
                )
            )
        )[:2000]
        if not work:
            for item in plan:
                entry = {
                    "work_key": item["work_key"],
                    "required": bool(item.get("required", True)),
                    "state": (
                        WorkState.COMPLETED.value
                        if outcome == "success"
                        else WorkState.FAILED.value
                        if outcome == "failure"
                        else WorkState.UNCOLLECTED.value
                        if outcome == "canceled"
                        else WorkState.TRUNCATED.value
                    ),
                }
                if entry["state"] != WorkState.COMPLETED.value:
                    entry["reason"] = reason
                work.append(entry)
        raw_payload = {
            "outcome": outcome,
            "requested_outcome": requested_outcome,
            "result": body.get("result"),
            "error": body.get("error"),
            "run_truths": [item.to_dict() for item in run_truths],
        }
        try:
            encoded = json.dumps(
                raw_payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode()
        except (TypeError, ValueError) as exc:
            raise HTTPException(
                status_code=400,
                detail={"reason_code": "result_payload_invalid"},
            ) from exc
        if len(encoded) > 1_048_576:
            raise HTTPException(
                status_code=413,
                detail={"reason_code": "result_payload_too_large"},
            )

        try:
            _receipt, delivery = self._persist_custodied_job_result(
                durable=durable,
                job_id=job_id,
                attempt=attempt,
                lease_token=str(body.get("lease_token") or ""),
                envelope=envelope,
                raw_payload=raw_payload,
                source_target=str(assignment.get("target") or "unknown"),
                outcome=outcome,
                work=work,
                run_truths=run_truths,
                worker_id=agent_id,
                actor=result_actor,
            )
        except CanonicalEvidenceError as exc:
            raise HTTPException(
                status_code=409,
                detail={"reason_code": "result_delivery_conflict"},
            ) from exc
        except LeaseError as exc:
            raise HTTPException(
                status_code=409,
                detail={"reason_code": "durable_result_rejected"},
            ) from exc
        except (IdempotencyConflict, InvalidTransition, KeyError) as exc:
            raise HTTPException(
                status_code=409,
                detail={"reason_code": "durable_result_rejected"},
            ) from exc
        except (CustodyError, OSError) as exc:
            raise HTTPException(
                status_code=503,
                detail={"reason_code": "result_custody_unavailable"},
            ) from exc
        current: dict[str, Any] | None = None
        try:
            current = durable.get_job(job_id, tenant_id=self.tenant_id) or job
            latest_attempts = durable.list_attempts(
                job_id,
                tenant_id=self.tenant_id,
            )
            if str(current.get("state") or "") in {
                JobState.CANCELED.value,
                JobState.PARTIAL.value,
                JobState.FAILED.value,
                JobState.COMPLETED.value,
            }:
                finished = latest_attempts[-1] if latest_attempts else attempt
            else:
                finished = durable.finish_attempt(
                    str(attempt["id"]),
                    tenant_id=self.tenant_id,
                    lease_token=str(body.get("lease_token") or ""),
                    error_reason=(reason if outcome != "success" else None),
                    terminal_reason=(
                        reason
                        if outcome != "success"
                        else "verified agent result completed"
                    ),
                    worker_id=agent_id,
                    actor=result_actor,
                )
                current = durable.get_job(
                    job_id,
                    tenant_id=self.tenant_id,
                ) or current
            durable.set_agent_state(agent_id, "idle", tenant_id=self.tenant_id)
        except (IdempotencyConflict, InvalidTransition, LeaseError, KeyError) as exc:
            race_job = durable.get_job(job_id, tenant_id=self.tenant_id)
            race_attempts = durable.list_attempts(
                job_id,
                tenant_id=self.tenant_id,
            )
            if (
                delivery.get("accepted") is True
                and race_job is not None
                and str(race_job.get("state") or "")
                in {
                    JobState.CANCELED.value,
                    JobState.PARTIAL.value,
                    JobState.FAILED.value,
                    JobState.COMPLETED.value,
                }
            ):
                current = race_job
                finished = race_attempts[-1] if race_attempts else attempt
                durable.set_agent_state(
                    agent_id,
                    "idle",
                    tenant_id=self.tenant_id,
                )
            else:
                raise HTTPException(
                    status_code=409,
                    detail={"reason_code": "durable_result_rejected"},
                ) from exc
        current = current or durable.get_job(
            job_id,
            tenant_id=self.tenant_id,
        ) or job
        if (
            active_execution
            and str(current.get("state") or "") == JobState.QUEUED.value
        ):
            current = durable.require_approval(
                job_id,
                tenant_id=self.tenant_id,
                actor=TransitionActor(
                    tenant_id=self.tenant_id,
                    actor_id="agent-retry-policy",
                    role="system",
                ),
                reason="active retry requires fresh authorization",
            )
        projection = dict(assignment)
        projection.update(
            {
                "id": job_id,
                "tenant_id": self.tenant_id,
                "agent_id": agent_id,
                "attempt_id": attempt["id"],
                "status": current["state"],
                "result": self._sanitize_agent_result(body.get("result")),
                "error": None if outcome == "success" else reason,
                "completed_at": current.get("terminal_at"),
                "result_identity": delivery["result_identity"],
                "attempt_state": finished["state"],
            }
        )
        return self._sanitize_agent_job(projection), bool(
            delivery.get("duplicate")
        )

    def _string_list(self, value: Any) -> list[str]:
        """Normalize a request field to a list of non-empty strings."""
        if value is None:
            return []
        if isinstance(value, str):
            raw = [item.strip() for item in value.split(",")]
        elif isinstance(value, list):
            raw = [str(item).strip() for item in value]
        else:
            return []
        return [item for item in raw if item]

    @staticmethod
    def _scope_entries(value: Any) -> list[str]:
        """Preserve blank/malformed entries so the common parser can deny them."""
        if value is None:
            return []
        if isinstance(value, str):
            return [item.strip() for item in value.split(",")]
        if isinstance(value, list):
            if not all(isinstance(item, str) for item in value):
                return ["*"]
            return [item.strip() for item in value]
        return ["*"]

    def _launch_scope_inputs(self, body: dict[str, Any]) -> tuple[list[str], list[str]]:
        """Return explicit allow and exclude entries from a launch request."""
        allowed = self._scope_entries(body.get("scope"))
        excluded_value = body.get("exclude")
        if excluded_value is None:
            excluded_value = body.get("excluded_scope")
        return allowed, self._scope_entries(excluded_value)

    def _exact_network_scope_inputs(
        self,
        target: str | None,
        value: Any,
        excluded_scope: list[str],
    ) -> tuple[list[str], ScopeDecision]:
        """Validate one separately supplied host-prefix network scope."""
        exact_target = self._exact_ip(target)
        if exact_target is None:
            return [], decision_for_reason(ScopeReason.MALFORMED_TARGET)
        entries = self._scope_entries(value)
        if not entries:
            return [], decision_for_reason(ScopeReason.MISSING_SCOPE)
        if len(entries) != 1:
            return [], decision_for_reason(ScopeReason.MALFORMED_SCOPE)
        try:
            address = ipaddress.ip_address(exact_target)
            scope_entry = entries[0]
            bracketed = re.fullmatch(r"\[([^\[\]]+)\](?:/([0-9]+))?", scope_entry)
            if bracketed:
                scope_entry = bracketed.group(1)
                if bracketed.group(2):
                    scope_entry += f"/{bracketed.group(2)}"
            submitted = ipaddress.ip_network(scope_entry, strict=False)
            expected = ipaddress.ip_network(
                f"{address}/{address.max_prefixlen}",
                strict=False,
            )
        except (TypeError, ValueError):
            return [], decision_for_reason(ScopeReason.MALFORMED_SCOPE)
        if submitted != expected:
            return [], decision_for_reason(ScopeReason.TARGET_MISMATCH)
        canonical = [str(expected)]
        return canonical, decide_scope(exact_target, canonical, excluded_scope)

    def _prepare_dashboard_confirmation_bundle(
        self,
        body: dict[str, Any],
    ) -> dict[str, Any]:
        """Mint short-lived confirmations for one explicit dashboard intent.

        The operator UI calls this boundary only after its confirmation dialog.
        This method performs no execution or authorization persistence: it
        validates the submitted effective scope, derives the exact engine/action
        set on the server, and returns the existing ``ActionConfirmation``
        records consumed by the launch endpoints.
        """
        if not isinstance(body, dict):
            self._raise_scope_denial(
                decision_for_reason(ScopeReason.INVALID_CONFIRMATION)
            )
        raw_intent = body.get("intent")
        if not isinstance(raw_intent, str):
            self._raise_scope_denial(
                decision_for_reason(ScopeReason.INVALID_CONFIRMATION)
            )
        intent = raw_intent.strip().lower()
        if intent not in {"scan.start", "scan.launch", "finding.retest"}:
            self._raise_scope_denial(
                decision_for_reason(ScopeReason.INVALID_CONFIRMATION)
            )

        allowed_scope, excluded_scope = self._launch_scope_inputs(body)
        client_job_id = self._server_job_id()
        primary_scope = list(allowed_scope)
        actions: list[tuple[str, str, str, list[str]]] = []
        network_target = ""
        network_scope: list[str] = []

        def _required_target(value: Any) -> str:
            if not isinstance(value, str) or not value.strip():
                self._raise_scope_denial(
                    decision_for_reason(ScopeReason.MALFORMED_TARGET)
                )
            return value.strip()

        def _web_target(value: str) -> str:
            return (
                value
                if value.startswith(("http://", "https://"))
                else "https://" + value
            )

        def _add_vapt_actions(target: str) -> None:
            nonlocal network_target, network_scope, allowed_scope
            network_target = self._exact_ip(body.get("network_target")) or ""
            if not network_target:
                self._raise_scope_denial(
                    decision_for_reason(ScopeReason.MALFORMED_TARGET)
                )
            network_scope, network_scope_decision = self._exact_network_scope_inputs(
                network_target,
                body.get("network_scope"),
                excluded_scope,
            )
            if not network_scope_decision.allowed:
                self._raise_scope_denial(network_scope_decision)
            allowed_scope = list(dict.fromkeys([*allowed_scope, *network_scope]))
            actions.extend(
                [
                    (_web_target(target), "webforge", "scan", primary_scope),
                    (
                        network_target,
                        "netforge",
                        "web_to_network",
                        network_scope,
                    ),
                ]
            )

        if intent == "scan.start":
            target = _required_target(body.get("target"))
            raw_scan_type = body.get("scan_type", "web")
            if not isinstance(raw_scan_type, str):
                self._raise_scope_denial(
                    decision_for_reason(ScopeReason.INVALID_CONFIRMATION)
                )
            scan_type = raw_scan_type.strip().lower()
            raw_mode = body.get("mode", "blackbox")
            if not isinstance(raw_mode, str) or raw_mode.strip().lower() not in {
                "blackbox",
                "greybox",
                "whitebox",
            }:
                self._raise_scope_denial(
                    decision_for_reason(ScopeReason.INVALID_CONFIRMATION)
                )
            if (
                scan_type in {"web", "vapt"}
                and raw_mode.strip().lower() == "whitebox"
            ):
                try:
                    self._validated_whitebox_source_root(body)
                except ValueError as exc:
                    raise HTTPException(status_code=400, detail=str(exc)) from exc
            if scan_type == "web":
                actions.append(
                    (_web_target(target), "webforge", "scan", primary_scope)
                )
            elif scan_type == "net":
                actions.append((target, "netforge", "scan", primary_scope))
            elif scan_type == "vapt":
                _add_vapt_actions(target)
            else:
                self._raise_scope_denial(
                    decision_for_reason(ScopeReason.INVALID_CONFIRMATION)
                )
        elif intent == "scan.launch":
            target = _required_target(body.get("target"))
            modules = self._string_list(body.get("modules", []))
            if not modules:
                self._raise_scope_denial(
                    decision_for_reason(ScopeReason.INVALID_CONFIRMATION)
                )
            web_modules, net_modules, unsupported = _resolve_modules(modules)
            if unsupported:
                self._raise_scope_denial(
                    decision_for_reason(ScopeReason.INVALID_CONFIRMATION)
                )
            raw_mode = body.get("mode", "blackbox")
            if not isinstance(raw_mode, str) or raw_mode.strip().lower() not in {
                "blackbox",
                "greybox",
                "whitebox",
            }:
                self._raise_scope_denial(
                    decision_for_reason(ScopeReason.INVALID_CONFIRMATION)
                )
            if web_modules and raw_mode.strip().lower() == "whitebox":
                try:
                    self._validated_whitebox_source_root(body)
                except ValueError as exc:
                    raise HTTPException(status_code=400, detail=str(exc)) from exc
            if web_modules and net_modules:
                _add_vapt_actions(target)
            elif net_modules and not web_modules:
                actions.append((target, "netforge", "scan", primary_scope))
            else:
                actions.append(
                    (_web_target(target), "webforge", "scan", primary_scope)
                )
        else:
            raw_finding_id = body.get("finding_id")
            if not isinstance(raw_finding_id, str) or not raw_finding_id.strip():
                self._raise_scope_denial(
                    decision_for_reason(ScopeReason.INVALID_CONFIRMATION)
                )
            finding = self._find_finding_metadata(raw_finding_id.strip())
            if not finding:
                raise HTTPException(status_code=404, detail="Finding not found")
            module = str(finding.get("module", "")).strip()
            target = _required_target(
                finding.get("target") or finding.get("url") or ""
            )
            if not module:
                self._raise_scope_denial(
                    decision_for_reason(ScopeReason.INVALID_CONFIRMATION)
                )
            engine = self._retest_framework(module)
            actions.append((target, engine, "retest", primary_scope))

        decisions: list[ScopeDecision] = []
        confirmations: list[ActionConfirmation] = []
        for target, engine, action, action_scope in actions:
            decision = decide_action(
                target=target,
                allowed_scope=action_scope,
                excluded_scope=excluded_scope,
                confirmation=None,
                job_id=client_job_id,
                engine=engine,
                action=action,
                require_confirmation=False,
            )
            if not decision.allowed:
                self._raise_scope_denial(decision)
            decisions.append(decision)
            confirmations.append(
                ActionConfirmation.create(
                    job_id=client_job_id,
                    target=target,
                    engine=engine,
                    action=action,
                )
            )

        result: dict[str, Any] = {
            "job_id": client_job_id,
            "scope": allowed_scope,
            "exclude": excluded_scope,
            "confirmations": [item.to_dict() for item in confirmations],
            "actions": [
                {
                    "engine": engine,
                    "action": action,
                    "scope": action_scope,
                    "scope_decision": decision.to_dict(),
                }
                for (_, engine, action, action_scope), decision in zip(
                    actions,
                    decisions,
                )
            ],
            "authorized": False,
        }
        if len(confirmations) == 1:
            result["confirmation"] = confirmations[0].to_dict()
        if network_target:
            result["network_target"] = network_target
            result["web_scope"] = primary_scope
            result["network_scope"] = network_scope
        return result

    @staticmethod
    def _validated_whitebox_source_root(body: dict[str, Any]) -> str:
        """Accept only the canonical source_root request key for whitebox scans."""
        if any(key in body for key in ("source", "source_dir", "source_path")):
            raise ValueError("source_root is the only accepted whitebox source key")
        from webforge.core.source_root import canonical_source_root

        return str(canonical_source_root(body.get("source_root")))

    def _request_bool(self, body: dict[str, Any], field: str, *, default: bool) -> bool:
        """Read a JSON boolean without truthiness coercion."""
        value = body.get(field, default)
        if type(value) is not bool:
            self._raise_scope_denial(decision_for_reason(ScopeReason.INVALID_CONFIRMATION))
        return value

    def _audit_preflight_denial(
        self,
        decision: ScopeDecision,
        *,
        action_kind: Any,
        engine: Any,
        target: Any,
        allowed_scope: Any,
        excluded_scope: Any = (),
        engagement_id: Any = "dashboard-preflight",
        run_id: Any = "dashboard-preflight-run",
        job_id: Any = "dashboard-preflight-job",
        operator_id: Any = "dashboard-operator",
        operator_role: OperatorRole | str = OperatorRole.SYSTEM,
        module_id: Any = "",
        safety_mode: SafetyMode | str = SafetyMode.ACTIVE,
    ) -> None:
        """Persist one dashboard denial before returning an HTTP error."""
        def _record(session: Any) -> None:
            record_boundary_denial(
                session=session,
                reason_code=decision.reason_code,
                action_kind=action_kind,
                engine=engine,
                target=target,
                allowed_scope=allowed_scope,
                excluded_scope=excluded_scope,
                tenant_id=self.tenant_id,
                engagement_id=engagement_id,
                run_id=run_id,
                job_id=job_id,
                operator_id=operator_id,
                operator_role=operator_role,
                module_id=module_id,
                safety_mode=safety_mode,
            )

        self._with_scan_jobs_session(_record)

    @staticmethod
    def _raise_scope_denial(decision: ScopeDecision) -> NoReturn:
        malformed = {
            ScopeReason.MALFORMED_SCOPE.value,
            ScopeReason.MALFORMED_TARGET.value,
            ScopeReason.INVALID_CONFIRMATION.value,
        }
        status_code = 400 if decision.reason_code in malformed else 403
        raise HTTPException(status_code=status_code, detail=decision.to_dict())

    def _client_job_id(self, body: dict[str, Any]) -> str:
        """Validate a bounded client correlation id.

        This value is never used as the authorization/job identifier; the
        launch handlers mint a server id after validating the submitted
        confirmation against this correlation value.
        """
        raw_job_id = body.get("job_id") if "job_id" in body else body.get("id")
        if not isinstance(raw_job_id, str):
            self._raise_scope_denial(decision_for_reason(ScopeReason.INVALID_CONFIRMATION))
        job_id = raw_job_id.strip()
        if not _JOB_ID_RE.fullmatch(job_id):
            self._raise_scope_denial(decision_for_reason(ScopeReason.INVALID_CONFIRMATION))
        return job_id

    @staticmethod
    def _server_job_id() -> str:
        return f"job-{uuid.uuid4().hex}"

    @staticmethod
    def _confirmation_from_body(
        body: dict[str, Any],
        *,
        engine: str,
        action: str,
        specific_field: str = "",
    ) -> Any:
        """Select one submitted confirmation without repairing mismatched fields."""
        if specific_field and specific_field in body:
            return body.get(specific_field)
        if "confirmation" in body:
            return body.get("confirmation")
        values = body.get("confirmations")
        if not isinstance(values, list):
            return None
        matches = [
            value
            for value in values
            if isinstance(value, dict)
            and str(value.get("engine", "")).strip().lower() == engine
            and str(value.get("action", "")).strip().lower() == action
        ]
        if len(matches) == 1:
            return matches[0]
        if len(values) == 1:
            return values[0]
        return {} if matches else None

    def _server_confirmation(
        self,
        body: dict[str, Any],
        *,
        client_job_id: str,
        server_job_id: str,
        target: str,
        allowed_scope: list[str],
        excluded_scope: list[str],
        engine: str,
        action: str,
        dry_run: bool,
        specific_field: str = "",
    ) -> tuple[ActionConfirmation | None, ScopeDecision]:
        """Validate explicit client approval, then mint a server-bound record."""
        submitted = self._confirmation_from_body(
            body,
            engine=engine,
            action=action,
            specific_field=specific_field,
        )
        submitted_decision = decide_action(
            target=target,
            allowed_scope=allowed_scope,
            excluded_scope=excluded_scope,
            confirmation=submitted,
            job_id=client_job_id,
            engine=engine,
            action=action,
            require_confirmation=not dry_run,
        )
        if not submitted_decision.allowed:
            return None, submitted_decision
        if dry_run:
            return None, submitted_decision
        try:
            return (
                ActionConfirmation.create(
                    job_id=server_job_id,
                    target=target,
                    engine=engine,
                    action=action,
                ),
                submitted_decision,
            )
        except (TypeError, ValueError):
            return None, decision_for_reason(ScopeReason.MALFORMED_TARGET)

    def _prepare_launch_action(
        self,
        *,
        target: str,
        allowed_scope: list[str],
        excluded_scope: list[str],
        confirmation: Any,
        job_id: str,
        engine: str,
        action: str,
        dry_run: bool,
        tenant_id: str,
        engagement_id: str,
        run_id: str,
        operator_id: str,
        operator_role: str,
        safety_mode: str,
        module_id: str = "",
        credential_reference: str = "",
        prior_decision: ScopeDecision | None = None,
    ) -> tuple[
        ScopeDecision,
        ActionConfirmation | None,
        AuthorizationContext | None,
    ]:
        """Validate one requested action without committing an allow decision."""
        decision = (
            prior_decision
            if prior_decision is not None and not prior_decision.allowed
            else decide_action(
                target=target,
                allowed_scope=allowed_scope,
                excluded_scope=excluded_scope,
                confirmation=confirmation,
                job_id=job_id,
                engine=engine,
                action=action,
                require_confirmation=not dry_run,
            )
        )
        if dry_run:
            if not decision.allowed:
                self._raise_scope_denial(decision)
            return decision, None, None

        context = AuthorizationContext(
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            run_id=run_id,
            job_id=job_id,
            operator_id=operator_id,
            operator_role=OperatorRole(operator_role),
            action_kind=action,
            engine=engine,
            module_id=module_id,
            requested_target=target,
            resolved_target=target,
            allowed_scope=allowed_scope,
            excluded_scope=excluded_scope,
            safety_mode=SafetyMode(safety_mode),
            credential_approval_required=bool(credential_reference),
            network_escalation_approval_required=(action == "web_to_network"),
            credential_reference=credential_reference,
            confirmation_method=ConfirmationMethod.DASHBOARD,
            confirmed_by=operator_id,
        )

        if not decision.allowed:
            def _record_submitted_denial(session: Any) -> None:
                record_authorization_denial(
                    session=session,
                    context=context,
                    reason_code=decision.reason_code,
                )

            self._with_scan_jobs_session(_record_submitted_denial)
            self._raise_scope_denial(decision)

        record = ActionConfirmation.from_value(confirmation)
        return decision, record, context

    def _commit_launch_authorizations(
        self,
        actions: list[tuple[AuthorizationContext, ActionConfirmation]],
        *,
        job_record: dict[str, Any],
    ) -> list[ActionAuthorizationEnvelope]:
        """Atomically issue a launch batch and link its pending scan job."""
        if not actions:
            raise ValueError("at least one launch action is required")

        def _persist(session: Any) -> list[ActionAuthorizationEnvelope]:
            children: list[ActionAuthorizationEnvelope] = []
            failure: tuple[AuthorizationContext, str] | None = None
            try:
                for context, confirmation in actions:
                    issued = issue_authorization(
                        session=session,
                        context=context,
                        confirmation=confirmation,
                        commit=False,
                    )
                    if not issued.allowed:
                        failure = (context, issued.reason_code)
                        break
                    consumed = consume_authorization(
                        session=session,
                        envelope=issued.envelope,
                        expected=context,
                        boundary="dashboard.launch",
                        commit=False,
                    )
                    if not consumed.allowed:
                        failure = (context, consumed.reason_code)
                        break
                    child_context = AuthorizationContext(
                        **{
                            **context.__dict__,
                            "action_kind": "engine.execute",
                            "parent_decision_id": issued.envelope.decision_id,
                            "confirmation_method": ConfirmationMethod.INHERITED,
                        }
                    )
                    derived = derive_authorization(
                        session=session,
                        parent_envelope=issued.envelope,
                        context=child_context,
                        parent_boundary="dashboard.launch",
                        commit=False,
                    )
                    if not derived.allowed:
                        failure = (context, derived.reason_code)
                        break
                    children.append(derived.envelope)

                if failure is not None:
                    failed_context, reason_code = failure
                    session.rollback()
                    record_authorization_denial(
                        session=session,
                        context=failed_context,
                        reason_code=reason_code,
                    )
                    self._raise_scope_denial(
                        decision_for_reason(ScopeReason.INVALID_CONFIRMATION)
                    )

                primary = children[0]
                persisted_job = {
                    **job_record,
                    "id": primary.job_id,
                    "tenant_id": primary.tenant_id,
                    "authorization_state": "allow",
                    "authorization_decision_id": primary.decision_id,
                    "authorization_action_id": primary.action_id,
                }
                # The dashboard handoff still owns a Gate-0 compatibility job
                # row; it has no module-version/asset graph yet.  Keep that
                # exception explicit and fail closed on canonical adapters.
                save_scan_job(
                    session,
                    persisted_job,
                    commit=False,
                    # The handoff has no complete canonical engagement /
                    # module-version / asset graph.  Fail typed before
                    # persisting an orphan job; Task 103 owns the durable
                    # state-machine adapter.
                    allow_legacy_compat=False,
                )
                session.commit()
                return children
            except HTTPException:
                raise
            except Exception as exc:
                session.rollback()
                record_authorization_denial(
                    session=session,
                    context=actions[0][0],
                    reason_code=AuthorizationReason.HANDOFF_PERSISTENCE_FAILED,
                )
                log.error(
                    "Authorized scan handoff persistence failed reason=%s",
                    type(exc).__name__,
                )
                raise HTTPException(
                    status_code=500,
                    detail=(
                        "Authorization handoff persistence failed; execution denied"
                    ),
                ) from exc

        return self._with_scan_jobs_session(_persist)

    def _record_launch_context_denial(
        self,
        context: AuthorizationContext | None,
        *,
        reason: AuthorizationReason,
    ) -> None:
        """Append a denial discovered after batch validation but before commit."""
        if context is None:
            return

        def _record(session: Any) -> None:
            record_authorization_denial(
                session=session,
                context=context,
                reason_code=reason,
            )

        self._with_scan_jobs_session(_record)

    @staticmethod
    def _exact_ip(value: Any) -> str | None:
        if not isinstance(value, str):
            return None
        raw = value.strip()
        if "[" in raw or "]" in raw:
            if (
                raw.count("[") != 1
                or raw.count("]") != 1
                or not raw.startswith("[")
                or not raw.endswith("]")
            ):
                return None
            raw = raw[1:-1]
        if not raw or "/" in raw or "://" in raw:
            return None
        try:
            return str(ipaddress.ip_address(raw))
        except ValueError:
            return None

    @classmethod
    def _hostname_resolves_to_exact_ip(
        cls,
        hostname: str,
        approved_ip: str | None,
    ) -> bool:
        """Match the current DNS answer to an exact approved IPv4 or IPv6.

        IPv4 retains the single-address resolution contract used by the
        existing escalation path. IPv6 uses ``getaddrinfo`` because
        ``gethostbyname`` is IPv4-only.
        """
        expected = cls._exact_ip(approved_ip)
        if not hostname or expected is None:
            return False
        try:
            address = ipaddress.ip_address(expected)
            if address.version == 4:
                return cls._exact_ip(socket.gethostbyname(hostname)) == expected
            answers = socket.getaddrinfo(
                hostname,
                None,
                socket.AF_INET6,
                socket.SOCK_STREAM,
            )
        except (OSError, TypeError, ValueError):
            return False
        return any(
            cls._exact_ip(sockaddr[0]) == expected
            for *_, sockaddr in answers
            if isinstance(sockaddr, tuple) and sockaddr
        )

    @staticmethod
    def _append_scope_args(
        cmd: list[str],
        allowed_scope: list[str],
        excluded_scope: list[str],
    ) -> None:
        for entry in allowed_scope:
            cmd.extend(["--scope", entry])
        for entry in excluded_scope:
            cmd.extend(["--exclude", entry])

    def _launch_env(
        self,
        base_env: dict[str, str],
        confirmation: ActionConfirmation,
        authorization: ActionAuthorizationEnvelope,
        job_id: str,
        action: str,
    ) -> dict[str, str]:
        # Do not inherit the caller's ambient environment.  The only Forge
        # values a scan child receives are the exact authorization/runtime
        # handoff values assembled below (plus the explicitly non-secret
        # tenant/auth-type context used by the engine).
        env = minimal_child_environment(
            base_env,
            allowlist={
                "FORGE_TENANT_ID",
                "FORGE_AUTH_TYPE",
                "FORGE_RUN_TRUTH_POLICY_ID",
                "FORGE_RUN_TRUTH_POLICY_VERSION",
                "FORGE_RUN_TRUTH_ISSUER_ID",
                "FORGE_RUN_TRUTH_PUBLIC_KEY",
                "FORGE_RUN_TRUTH_PRIVATE_KEY_FILE",
                "FORGE_RUN_TRUTH_AUTHORITY_ID",
            },
        )
        env["FORGE_TENANT_ID"] = self.tenant_id
        env[LAUNCH_CONFIRMATIONS_ENV] = encode_launch_confirmations([confirmation])
        env[LAUNCH_JOB_ID_ENV] = job_id
        env[LAUNCH_ACTION_ENV] = action
        env[AUTHORIZATION_ENVELOPES_ENV] = encode_authorization_envelopes(
            [authorization]
        )
        env[AUTHORIZATION_DB_ENV] = str(self._scan_jobs_db_path)
        env.update(authorization_runtime_environment(authorization))
        return env

    @staticmethod
    def _scope_syntax_decision(
        allowed_scope: list[str],
        excluded_scope: list[str],
    ) -> ScopeDecision:
        if not allowed_scope:
            return decide_scope("", allowed_scope, excluded_scope)
        probe = decide_scope(allowed_scope[0], allowed_scope, excluded_scope)
        if probe.reason_code in {
            ScopeReason.MISSING_SCOPE.value,
            ScopeReason.MALFORMED_SCOPE.value,
            ScopeReason.MALFORMED_TARGET.value,
        }:
            return probe
        return decision_for_reason(ScopeReason.ALLOWED)

    def _reject_secret_fields(self, payload: Any, path: str = "") -> None:
        """Reject queued agent jobs containing credential material."""
        secret_words = ("password", "secret", "token", "cookie", "credential", "authorization")
        if isinstance(payload, dict):
            for key, value in payload.items():
                key_s = str(key)
                if any(word in key_s.lower() for word in secret_words):
                    raise HTTPException(status_code=400, detail=f"agent job field '{path + key_s}' may not contain secrets")
                self._reject_secret_fields(value, path=f"{path}{key_s}.")
        elif isinstance(payload, list):
            for idx, item in enumerate(payload):
                self._reject_secret_fields(item, path=f"{path}{idx}.")

    def _canonical_finding_status(self, status: str) -> str:
        """Map dashboard labels to persisted finding statuses."""
        mapping = {
            "Open": "open",
            "Fixed": "remediated",
            "Accepted": "accepted_risk",
            "False Positive": "false_positive",
        }
        return mapping.get(status, status.strip().lower().replace(" ", "_"))

    def _persist_finding_status(self, finding_id: str, status: str) -> bool:
        """Persist finding status changes in the canonical findings table."""
        try:
            canonical = CanonicalFindingStatus(
                self._canonical_finding_status(status)
            ).value
            matches: list[Path] = []
            for root in self._canonical_result_roots():
                for database_path in self._canonical_database_paths(root):
                    session = create_db(database_path)
                    try:
                        count = int(
                            session.execute(
                                sql_text(
                                    "SELECT COUNT(*) FROM canonical_findings "
                                    "WHERE tenant_id=:tenant_id AND id=:finding_id"
                                ),
                                {
                                    "tenant_id": self.tenant_id,
                                    "finding_id": finding_id,
                                },
                            ).scalar_one()
                        )
                        session.rollback()
                    finally:
                        session.close()
                    if count:
                        matches.append(database_path)
            if not matches:
                return False
            if len(matches) != 1:
                raise DashboardArtifactError(
                    "canonical finding identity conflicts across stores"
                )
            session = create_db(matches[0])
            try:
                if session.in_transaction():
                    session.rollback()
                with session.begin():
                    result = session.execute(
                        sql_text(
                            "UPDATE canonical_findings SET status=:status "
                            "WHERE tenant_id=:tenant_id AND id=:finding_id"
                        ),
                        {
                            "status": canonical,
                            "tenant_id": self.tenant_id,
                            "finding_id": finding_id,
                        },
                    )
                    if getattr(result, "rowcount", None) != 1:
                        raise DashboardArtifactError(
                            "canonical finding status update failed"
                        )
            finally:
                session.close()
            return True
        except Exception as exc:
            log.warning(
                "Could not persist dashboard finding status reason=%s",
                type(exc).__name__,
            )
            return False

    @staticmethod
    def _durable_framework(value: str) -> str:
        return {
            "web": "webforge",
            "net": "netforge",
            "webforge": "webforge",
            "netforge": "netforge",
        }.get(str(value).strip().lower(), str(value).strip().lower())

    def _prepare_durable_scan_job(
        self,
        *,
        scan_id: str,
        target: str,
        process_specs: list[tuple[str, str]],
        authorizations: Mapping[str, ActionAuthorizationEnvelope],
        modules: list[str],
        results_dir: str,
        control_file: Path,
        actor_id: str,
        actor_role: str,
    ) -> dict[str, Any]:
        """Persist job, lease, and per-child launch intent before Popen."""

        if not process_specs or not authorizations:
            raise InvalidTransition("durable scan requires process and authorization")
        service = self._durable_job_state()
        control_boot_id = _DashboardProcessSupervisor._boot_id()
        if not control_boot_id:
            raise ProcessIdentityError(
                "durable child control requires a local boot identity"
            )
        framework_order = [
            self._durable_framework(framework)
            for _key, framework in process_specs
        ]
        primary_framework = framework_order[0]
        primary = authorizations[primary_framework]
        bindings = [
            {
                "authorization_decision_id": authorizations[framework].decision_id,
                "authorization_action_id": authorizations[framework].action_id,
                "framework": framework,
            }
            for framework in framework_order
        ]
        payload = {
            "target": target,
            "frameworks": framework_order,
            "modules": list(modules),
            "results_dir": results_dir,
            "control_file": str(control_file),
            "authorization_envelopes": {
                framework: authorizations[framework].to_dict()
                for framework in framework_order
            },
            "source": "dashboard",
        }
        job = service.create_job(
            payload,
            tenant_id=self.tenant_id,
            job_id=scan_id,
            engagement_id=primary.engagement_id,
            run_id=primary.run_id,
            job_kind="dashboard_scan",
            target=target,
            authorization_decision_id=primary.decision_id,
            authorization_action_id=primary.action_id,
            authorization_bindings=bindings,
            idempotency_key=f"dashboard:{scan_id}",
            max_attempts=1,
            state=JobState.QUEUED,
            work_items=framework_order,
            actor=TransitionActor(
                tenant_id=self.tenant_id,
                actor_id=actor_id,
                role=actor_role,
                authorization_decision_id=primary.decision_id,
            ),
            reason="authorized dashboard scan queued",
        )
        attempt = service.acquire_lease(
            scan_id,
            "dashboard",
            tenant_id=self.tenant_id,
            lease_seconds=24 * 60 * 60,
            idempotency_key=f"dashboard-attempt:{scan_id}:1",
            attempt_authorization_decision_id=primary.decision_id,
            control_boot_id=control_boot_id,
            actor=TransitionActor(
                tenant_id=self.tenant_id,
                actor_id=actor_id,
                role=actor_role,
                authorization_decision_id=primary.decision_id,
            ),
        )
        intents = {
            key: service.reserve_process(
                scan_id,
                str(attempt["id"]),
                key,
                lease_token=str(attempt["lease_token"]),
                worker_id="dashboard",
                control_boot_id=control_boot_id,
                tenant_id=self.tenant_id,
                actor=TransitionActor(
                    tenant_id=self.tenant_id,
                    actor_id=actor_id,
                    role=actor_role,
                    authorization_decision_id=primary.decision_id,
                ),
            )
            for key, _framework in process_specs
        }
        # The existing engine control boundary is a delivery gate. A spawned
        # child remains paused until complete identity is durable.
        self._write_control_file(control_file, paused=True, aborted=False)
        return {
            "job": job,
            "attempt": attempt,
            "intents": intents,
            "lease_token": attempt["lease_token"],
        }

    def _activate_durable_scan_processes(
        self,
        *,
        scan_id: str,
        prepared: Mapping[str, Any],
        control_file: Path,
        actor_id: str,
        actor_role: str,
    ) -> None:
        """Persist every full child identity, then release the start gate."""

        service = self._durable_job_state()
        attempt = cast(Mapping[str, Any], prepared["attempt"])
        intents = cast(Mapping[str, Mapping[str, Any]], prepared["intents"])
        for key, info in self._active_scans.items():
            if self._base_scan_id(key) != scan_id:
                continue
            intent = intents.get(key)
            proc = info.get("proc")
            if intent is None or proc is None:
                raise ProcessIdentityError("dashboard child launch intent is missing")
            identity = self._job_process_supervisor.capture(
                proc,
                launch_nonce=str(intent["launch_nonce"]),
            )
            if identity is None:
                raise ProcessIdentityError(
                    "dashboard child process identity could not be captured"
                )
            service.register_process(
                scan_id,
                str(attempt["id"]),
                identity,
                lease_token=str(prepared["lease_token"]),
                worker_id="dashboard",
                control_boot_id=str(attempt["control_boot_id"]),
                tenant_id=self.tenant_id,
                identity_key=key,
                actor=TransitionActor(
                    tenant_id=self.tenant_id,
                    actor_id=actor_id,
                    role=actor_role,
                    authorization_decision_id=str(
                        attempt.get("authorization_decision_id") or ""
                    )
                    or None,
                ),
            )
            info["durable_attempt_id"] = str(attempt["id"])
            info["durable_lease_token"] = str(prepared["lease_token"])
            info["durable_process_identity"] = identity.to_dict()
            info["durable_worker_id"] = "dashboard"
            info["durable_control_boot_id"] = str(
                attempt["control_boot_id"]
            )
        service.start_attempt(
            str(attempt["id"]),
            str(prepared["lease_token"]),
            tenant_id=self.tenant_id,
            actor=TransitionActor(
                tenant_id=self.tenant_id,
                actor_id=actor_id,
                role=actor_role,
                authorization_decision_id=str(
                    attempt.get("authorization_decision_id") or ""
                )
                or None,
            ),
            worker_id="dashboard",
        )
        self._write_control_file(control_file, paused=False, aborted=False)

    def _abort_durable_scan_launch(
        self,
        *,
        scan_id: str,
        prepared: Mapping[str, Any],
        processes: Mapping[str, subprocess.Popen[str]],
        control_file: Path,
        reason: str,
    ) -> None:
        """Fail closed after Popen without losing an unverifiable child."""

        service = self._durable_job_state()
        attempt = cast(Mapping[str, Any], prepared["attempt"])
        intents = cast(Mapping[str, Mapping[str, Any]], prepared["intents"])
        actor = TransitionActor(
            tenant_id=self.tenant_id,
            actor_id="dashboard-launch-failure",
            role="system",
        )
        self._write_control_file(control_file, paused=False, aborted=True)
        live_identity_uncertain = False
        for key, process in processes.items():
            intent = intents.get(key)
            if intent is None:
                if process.poll() is None:
                    live_identity_uncertain = True
                continue
            identity = self._job_process_supervisor.capture(
                process,
                launch_nonce=str(intent["launch_nonce"]),
            )
            if identity is None:
                if process.poll() is None:
                    live_identity_uncertain = True
                continue
            service.register_process(
                scan_id,
                str(attempt["id"]),
                identity,
                lease_token=str(prepared["lease_token"]),
                worker_id="dashboard",
                control_boot_id=str(attempt["control_boot_id"]),
                tenant_id=self.tenant_id,
                identity_key=key,
                actor=actor,
            )
        if live_identity_uncertain:
            service.revoke_lease(
                str(attempt["id"]),
                tenant_id=self.tenant_id,
                actor="dashboard-launch-failure",
                reason=(
                    f"{reason}; a live child identity could not be verified"
                ),
            )
            return
        service.cancel_job(
            scan_id,
            tenant_id=self.tenant_id,
            actor=actor,
            reason=reason,
            supervisor=self._job_process_supervisor,
            sla_seconds=5.0,
        )

    def _finalize_durable_scan_after_exit(self, scan_id: str) -> None:
        """Finalize only after every child stopped and signed truth verifies."""

        service = self._durable_job_state()
        job = service.get_job(scan_id, tenant_id=self.tenant_id)
        if job is None or str(job["state"]) in {
            JobState.CANCELED.value,
            JobState.PARTIAL.value,
            JobState.FAILED.value,
            JobState.COMPLETED.value,
        }:
            return
        attempts = service.list_attempts(scan_id, tenant_id=self.tenant_id)
        if not attempts:
            return
        attempt = attempts[-1]
        active = [
            info
            for key, info in self._active_scans.items()
            if self._base_scan_id(key) == scan_id
            and info.get("returncode") is None
        ]
        if active:
            return
        lease_token = next(
            (
                str(info.get("durable_lease_token") or "")
                for key, info in self._active_scans.items()
                if self._base_scan_id(key) == scan_id
                and info.get("durable_lease_token")
            ),
            "",
        )
        if not lease_token:
            return
        snapshot = service.coverage_snapshot(scan_id, tenant_id=self.tenant_id)
        truth_receipts: list[RunTruthReceipt] = []
        work: list[dict[str, Any]] = []
        missing_truth: list[str] = []
        for item in snapshot["items"]:
            framework = str(item["work_key"])
            run_truth_id = f"{job['run_id']}:{framework}"
            try:
                inspected = service.inspect_run_truth(
                    str(attempt["id"]),
                    lease_token,
                    run_truth_id,
                    tenant_id=self.tenant_id,
                    worker_id="dashboard",
                )
                truth_receipts.append(
                    cast(RunTruthReceipt, inspected["receipt"])
                )
                work.extend(dict(entry) for entry in inspected["work"])
            except (InvalidTransition, LeaseError, KeyError):
                missing_truth.append(framework)
        if missing_truth:
            service.revoke_lease(
                str(attempt["id"]),
                tenant_id=self.tenant_id,
                actor="dashboard-monitor",
                reason=(
                    "signed run truth missing after process exit: "
                    + ",".join(sorted(missing_truth))
                ),
            )
            return
        outcomes = {item.outcome for item in truth_receipts}
        outcome = (
            "success"
            if outcomes == {"success"}
            else "failure"
            if "failure" in outcomes
            else "canceled"
            if outcomes == {"canceled"}
            else "partial"
        )
        payload = job.get("payload")
        assignment = dict(payload) if isinstance(payload, Mapping) else {}
        authorization_values = assignment.get("authorization_envelopes")
        if not isinstance(authorization_values, Mapping) or not snapshot["items"]:
            service.revoke_lease(
                str(attempt["id"]),
                tenant_id=self.tenant_id,
                actor="dashboard-monitor",
                reason="canonical result authorization is unavailable",
            )
            return
        primary_framework = str(snapshot["items"][0]["work_key"])
        try:
            envelope = ActionAuthorizationEnvelope.from_value(
                authorization_values[primary_framework]
            )
        except (KeyError, TypeError, ValueError):
            service.revoke_lease(
                str(attempt["id"]),
                tenant_id=self.tenant_id,
                actor="dashboard-monitor",
                reason="canonical result authorization is invalid",
            )
            return
        actor = TransitionActor(
            tenant_id=self.tenant_id,
            actor_id="dashboard-monitor",
            role="system",
            authorization_decision_id=str(
                attempt.get("authorization_decision_id") or ""
            )
            or None,
        )
        result_payload = {
            "outcome": outcome,
            "requested_outcome": "process_exit_observed",
            "result": {
                "run_truths": [item.to_dict() for item in truth_receipts],
            },
            "error": None if outcome == "success" else "signed run truth incomplete",
            "run_truths": [item.to_dict() for item in truth_receipts],
        }
        try:
            _receipt, _delivery = self._persist_custodied_job_result(
                durable=service,
                job_id=scan_id,
                attempt=attempt,
                lease_token=lease_token,
                envelope=envelope,
                raw_payload=result_payload,
                source_target=str(assignment.get("target") or job.get("target") or "unknown"),
                outcome=outcome,
                work=work,
                run_truths=truth_receipts,
                worker_id="dashboard",
                actor=actor,
            )
            current = service.get_job(scan_id, tenant_id=self.tenant_id) or job
            if str(current.get("state") or "") in {
                JobState.CANCELED.value,
                JobState.PARTIAL.value,
                JobState.FAILED.value,
                JobState.COMPLETED.value,
            }:
                return
            service.finish_attempt(
                str(attempt["id"]),
                tenant_id=self.tenant_id,
                lease_token=lease_token,
                terminal_reason="canonical result and signed run truth accepted",
                worker_id="dashboard",
                actor=actor,
            )
        except (
            CanonicalEvidenceError,
            CustodyError,
            IdempotencyConflict,
            InvalidTransition,
            LeaseError,
            KeyError,
            OSError,
        ):
            race_job = service.get_job(scan_id, tenant_id=self.tenant_id)
            if race_job is not None and str(race_job.get("state") or "") not in {
                JobState.CANCELED.value,
                JobState.PARTIAL.value,
                JobState.FAILED.value,
                JobState.COMPLETED.value,
            }:
                service.revoke_lease(
                    str(attempt["id"]),
                    tenant_id=self.tenant_id,
                    actor="dashboard-monitor",
                    reason="canonical result custody failed after process exit",
                )

    def _write_scan_job(
        self,
        scan_id: str,
        target: str,
        frameworks: list[str],
        modules: list[str] | None = None,
        results_dir: str | None = None,
        authorization: ActionAuthorizationEnvelope | None = None,
    ) -> None:
        """Persist the dashboard scan job row used by status/log APIs."""
        logs = {
            key: str(self._scan_logs_dir / f"{key}.log")
            for key in self._active_scans
            if self._base_scan_id(key) == scan_id
        }
        pids = [
            info["proc"].pid
            for key, info in self._active_scans.items()
            if self._base_scan_id(key) == scan_id and info.get("proc") is not None
        ]
        started_at = datetime.now(timezone.utc)
        for key, info in self._active_scans.items():
            if self._base_scan_id(key) != scan_id:
                continue
            raw_started = info.get("started_dt")
            if raw_started:
                try:
                    started_at = datetime.fromisoformat(raw_started)
                except ValueError:
                    pass
            break

        def _save(session: Any) -> None:
            durable = self._durable_job_state().get_job(
                scan_id,
                tenant_id=self.tenant_id,
            )
            save_scan_job(
                session,
                {
                    "id": scan_id,
                    "tenant_id": self.tenant_id,
                    "status": (
                        durable["state"] if durable is not None else "planned"
                    ),
                    "target": target,
                    "frameworks": frameworks,
                    "modules": modules or [],
                    "pid": pids[0] if len(pids) == 1 else None,
                    "results_dir": results_dir,
                    "logs": logs,
                    "started_at": started_at,
                    "authorization_state": (
                        "allow" if authorization is not None else "unknown_not_authorized"
                    ),
                    "authorization_decision_id": (
                        authorization.decision_id if authorization is not None else None
                    ),
                    "authorization_action_id": (
                        authorization.action_id if authorization is not None else None
                    ),
                },
                # This row is a rebuildable compatibility projection. The
                # canonical Task 103 row already owns lifecycle and lineage.
                allow_legacy_compat=True,
            )

        try:
            self._with_scan_jobs_session(_save)
        except Exception as exc:
            log.warning(
                "Could not write dashboard scan job reason=%s",
                type(exc).__name__,
            )

    def _sync_scan_job_from_active(
        self,
        scan_id: str,
        fallback: str = "running",
    ) -> None:
        """Rebuild the legacy scan row from canonical Task 103 state."""

        del fallback
        active_items = {
            key: info
            for key, info in self._active_scans.items()
            if self._base_scan_id(key) == scan_id
        }
        durable = self._durable_job_state().get_job(
            scan_id,
            tenant_id=self.tenant_id,
        )
        if durable is None:
            return
        return_codes = [
            info.get("returncode")
            for info in active_items.values()
            if info.get("returncode") is not None
        ]
        return_code = (
            0
            if return_codes
            and len(return_codes) == len(active_items)
            and all(code == 0 for code in return_codes)
            else next((code for code in return_codes if code != 0), None)
        )
        logs = {
            key: str(self._scan_logs_dir / f"{key}.log")
            for key in active_items
        }
        state = str(durable["state"])
        terminal = state in {
            JobState.CANCELED.value,
            JobState.PARTIAL.value,
            JobState.FAILED.value,
            JobState.COMPLETED.value,
        }

        def _update(session: Any) -> None:
            update_scan_job(
                session,
                scan_id,
                tenant_id=self.tenant_id,
                status=state,
                return_code=return_code,
                logs=logs,
                error=durable.get("error_reason"),
                completed_at=(
                    datetime.fromtimestamp(
                        float(durable["terminal_at"]),
                        tz=timezone.utc,
                    )
                    if terminal and durable.get("terminal_at") is not None
                    else None
                ),
            )

        try:
            self._with_scan_jobs_session(_update)
        except Exception as exc:
            log.warning(
                "Could not rebuild dashboard scan projection reason=%s",
                type(exc).__name__,
            )

    def _load_scan_job(self, scan_id: str) -> dict[str, Any] | None:
        """Load a durable scan job row as a JSON-friendly dict."""
        durable = self._durable_job_state().get_job(
            scan_id,
            tenant_id=self.tenant_id,
        )
        if durable is not None:
            payload = durable.get("payload")
            projection = dict(payload) if isinstance(payload, Mapping) else {}
            attempts = self._durable_job_state().list_attempts(
                scan_id,
                tenant_id=self.tenant_id,
            )
            coverage = self._durable_job_state().coverage_snapshot(
                scan_id,
                tenant_id=self.tenant_id,
            )
            projection.update(
                {
                    "scan_id": durable["id"],
                    "status": durable["state"],
                    "target": durable["target"],
                    "frameworks": projection.get("frameworks", []),
                    "actual_modules": projection.get("modules", []),
                    "pid": None,
                    "return_code": None,
                    "results_dir": projection.get("results_dir"),
                    "logs": {
                        key: str(self._scan_logs_dir / f"{key}.log")
                        for key in self._active_scans
                        if self._base_scan_id(key) == scan_id
                    },
                    "error": durable.get("error_reason"),
                    "created_at": durable.get("created_at"),
                    "updated_at": durable.get("updated_at"),
                    "started_at": durable.get("started_at"),
                    "completed_at": durable.get("terminal_at"),
                    "authorization_state": "allow",
                    "authorization_decision_id": durable.get(
                        "authorization_decision_id"
                    ),
                    "authorization_action_id": durable.get(
                        "authorization_action_id"
                    ),
                    "attempts": attempts,
                    "coverage": coverage,
                }
            )
            return projection

        def _load(session: Any) -> dict[str, Any] | None:
            job = get_scan_job(session, scan_id, tenant_id=self.tenant_id)
            if job is None:
                return None
            return {
                "scan_id": job.id,
                "status": job.status,
                "target": job.target,
                "frameworks": json.loads(str(job.frameworks or "[]")),
                "actual_modules": json.loads(str(job.modules or "[]")),
                "pid": job.pid,
                "return_code": job.return_code,
                "results_dir": job.results_dir,
                "logs": json.loads(str(job.logs or "{}")),
                "error": job.error,
                "created_at": job.created_at.isoformat() if job.created_at else None,
                "updated_at": job.updated_at.isoformat() if job.updated_at else None,
                "started_at": job.started_at.isoformat() if job.started_at else None,
                "completed_at": job.completed_at.isoformat() if job.completed_at else None,
                "authorization_state": job.authorization_state or "unknown_not_authorized",
                "authorization_decision_id": job.authorization_decision_id,
                "authorization_action_id": job.authorization_action_id,
            }

        try:
            return self._with_scan_jobs_session(_load)
        except Exception as exc:
            log.warning(
                "Could not load dashboard scan job reason=%s",
                type(exc).__name__,
            )
            return None

    @staticmethod
    def _scan_job_mapping(
        row: Mapping[str, Any] | sqlite3.Row,
    ) -> dict[str, Any]:
        """Convert an ORM/SQLite scan-job row to the dashboard projection."""
        def _json(field: str, default: Any) -> Any:
            try:
                return json.loads(str(row[field] or json.dumps(default)))
            except (KeyError, TypeError, json.JSONDecodeError):
                return default

        def _value(field: str, default: Any = None) -> Any:
            try:
                value = row[field]
            except (KeyError, IndexError):
                return default
            return default if value is None else value

        frameworks = _json("frameworks", [])
        modules = _json("modules", [])
        return {
            "scan_id": _value("id", ""),
            "status": _value("status", "unknown"),
            "target": _value("target", ""),
            "scan_type": ",".join(frameworks) or "scan",
            "mode": "",
            "engagement": "",
            "frameworks": frameworks,
            "requested_modules": [],
            "actual_modules": modules,
            "pid": _value("pid"),
            "return_code": _value("return_code"),
            "results_dir": _value("results_dir"),
            "logs": _json("logs", {}),
            "error": _value("error"),
            "created_at": _value("created_at"),
            "updated_at": _value("updated_at"),
            "started_at": _value("started_at"),
            "completed_at": _value("completed_at"),
            "authorization_state": _value(
                "authorization_state",
                "unknown_not_authorized",
            ),
            "authorization_decision_id": _value("authorization_decision_id"),
            "authorization_action_id": _value("authorization_action_id"),
            "findings_count": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "total": 0,
            },
        }

    @staticmethod
    def _durable_scan_job_mapping(
        row: Mapping[str, Any] | sqlite3.Row,
    ) -> dict[str, Any]:
        """Project a Task 103 row without opening a mutable state service."""

        def _value(field: str, default: Any = None) -> Any:
            try:
                value = row[field]
            except (KeyError, IndexError):
                return default
            return default if value is None else value

        try:
            payload = json.loads(str(_value("payload_json", "{}")))
        except (TypeError, json.JSONDecodeError):
            payload = {}
        if not isinstance(payload, Mapping):
            payload = {}
        frameworks = payload.get("frameworks", [])
        modules = payload.get("modules", [])
        if not isinstance(frameworks, list):
            frameworks = []
        if not isinstance(modules, list):
            modules = []
        return {
            "scan_id": _value("id", ""),
            "status": _value("state", "unknown"),
            "target": _value("target", ""),
            "scan_type": ",".join(str(item) for item in frameworks) or "scan",
            "mode": str(payload.get("mode") or ""),
            "engagement": _value("engagement_id", ""),
            "frameworks": frameworks,
            "requested_modules": modules,
            "actual_modules": modules,
            "pid": None,
            "return_code": None,
            "results_dir": payload.get("results_dir"),
            "logs": {},
            "error": _value("error_reason"),
            "created_at": _value("created_at"),
            "updated_at": _value("updated_at"),
            "started_at": _value("started_at"),
            "completed_at": _value("terminal_at"),
            "authorization_state": "allow",
            "authorization_decision_id": _value(
                "authorization_decision_id"
            ),
            "authorization_action_id": _value("authorization_action_id"),
            "run_id": _value("run_id"),
            "version": _value("version", 0),
            "required_work": _value("required_work", 0),
            "completed_work": _value("completed_work", 0),
            "skipped_work": _value("skipped_work", 0),
            "failed_work": _value("failed_work", 0),
            "truncated_work": _value("truncated_work", 0),
            "uncollected_work": _value("uncollected_work", 0),
            "lifecycle_authority": "task103",
            "findings_count": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "total": 0,
            },
        }

    def _load_scan_jobs_read_only_once(
        self,
        *,
        scan_id: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        """Read durable jobs without creating/migrating or writing the DB.

        Viewer GET routes use a read-only URI rooted at the already-open parent
        directory descriptor.  Unlike SQLite's ``immutable=1`` mode, this keeps
        committed WAL rows visible while the pinned main-file and parent
        identities remain the authority for accepting the result.
        """
        parent_descriptor = -1
        comparison_parent_descriptor = -1
        database_descriptor = -1
        sidecar_descriptors: dict[str, int] = {}
        sidecar_initial_metadata: dict[str, os.stat_result] = {}
        sidecar_suffixes = ("-wal", "-shm", "-journal")
        connection: sqlite3.Connection | None = None
        result: list[dict[str, Any]] = []

        def _is_safe_database(metadata: os.stat_result) -> bool:
            return (
                stat.S_ISREG(metadata.st_mode)
                and metadata.st_nlink == 1
                and (
                    not hasattr(os, "getuid")
                    or metadata.st_uid == os.getuid()
                )
            )

        try:
            path = _artifact_path(self._scan_jobs_db_path)
            parent_descriptor = _open_artifact_directory(
                path.parent,
                create=False,
            )
            flags = os.O_RDONLY
            flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
            database_descriptor = os.open(
                path.name,
                flags,
                dir_fd=parent_descriptor,
            )
            initial_metadata = os.fstat(database_descriptor)
            if not _is_safe_database(initial_metadata):
                return []

            for suffix in sidecar_suffixes:
                sidecar_name = f"{path.name}{suffix}"
                try:
                    sidecar_descriptor = os.open(
                        sidecar_name,
                        flags,
                        dir_fd=parent_descriptor,
                    )
                except FileNotFoundError:
                    continue
                sidecar_metadata = os.fstat(sidecar_descriptor)
                if not _is_safe_database(sidecar_metadata):
                    os.close(sidecar_descriptor)
                    return []
                sidecar_descriptors[suffix] = sidecar_descriptor
                sidecar_initial_metadata[suffix] = sidecar_metadata

            descriptor_directory: str | None = None
            for descriptor_root in ("/proc/self/fd", "/dev/fd"):
                try:
                    root_metadata = os.stat(descriptor_root)
                except OSError:
                    continue
                if stat.S_ISDIR(root_metadata.st_mode):
                    descriptor_directory = f"{descriptor_root}/{parent_descriptor}"
                    break
            if descriptor_directory is None:
                return []

            encoded_name = quote(path.name, safe="")
            uri = f"file:{descriptor_directory}/{encoded_name}?mode=ro"
            connection = sqlite3.connect(uri, uri=True, timeout=1.0)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA query_only=ON").close()
            available_tables = {
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' "
                    "AND name IN ('durable_job_state_jobs','scan_jobs')"
                ).fetchall()
            }
            bounded_limit = max(1, min(int(limit), 1000))
            durable_rows: list[sqlite3.Row] = []
            legacy_rows: list[sqlite3.Row] = []
            if "durable_job_state_jobs" in available_tables:
                if scan_id is None:
                    durable_rows = connection.execute(
                        "SELECT * FROM durable_job_state_jobs "
                        "WHERE tenant_id=? ORDER BY created_at DESC LIMIT ?",
                        (self.tenant_id, bounded_limit),
                    ).fetchall()
                else:
                    durable_rows = connection.execute(
                        "SELECT * FROM durable_job_state_jobs "
                        "WHERE id=? AND tenant_id=? LIMIT 1",
                        (scan_id, self.tenant_id),
                    ).fetchall()
            durable_ids = {str(row["id"]) for row in durable_rows}
            if "scan_jobs" in available_tables:
                if scan_id is None:
                    legacy_rows = connection.execute(
                        "SELECT * FROM scan_jobs WHERE tenant_id=? "
                        "ORDER BY created_at DESC LIMIT ?",
                        (self.tenant_id, bounded_limit),
                    ).fetchall()
                elif scan_id not in durable_ids:
                    legacy_rows = connection.execute(
                        "SELECT * FROM scan_jobs "
                        "WHERE id=? AND tenant_id=? LIMIT 1",
                        (scan_id, self.tenant_id),
                    ).fetchall()

            mapped_rows = [
                self._durable_scan_job_mapping(row) for row in durable_rows
            ]
            mapped_rows.extend(
                self._scan_job_mapping(row)
                for row in legacy_rows
                if str(row["id"]) not in durable_ids
            )
            mapped_rows = sorted(
                mapped_rows,
                key=lambda item: str(item.get("created_at") or ""),
                reverse=True,
            )[:bounded_limit]
            connection.close()
            connection = None
            comparison_parent_descriptor = _open_artifact_directory(
                path.parent,
                create=False,
            )
            pinned_parent_metadata = os.fstat(parent_descriptor)
            current_parent_metadata = os.fstat(comparison_parent_descriptor)
            entry_metadata = os.stat(
                path.name,
                dir_fd=comparison_parent_descriptor,
                follow_symlinks=False,
            )
            final_metadata = os.fstat(database_descriptor)
            initial_identity = (initial_metadata.st_dev, initial_metadata.st_ino)
            sidecars_stable = True
            for suffix in sidecar_suffixes:
                sidecar_name = f"{path.name}{suffix}"
                descriptor = sidecar_descriptors.get(suffix)
                try:
                    sidecar_entry = os.stat(
                        sidecar_name,
                        dir_fd=parent_descriptor,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    sidecar_entry = None
                if descriptor is None:
                    if sidecar_entry is not None:
                        sidecars_stable = False
                    continue
                if sidecar_entry is None:
                    sidecars_stable = False
                    continue
                initial_sidecar = sidecar_initial_metadata[suffix]
                final_sidecar = os.fstat(descriptor)
                safe_sidecar = (
                    sidecar_entry is not None
                    and _is_safe_database(final_sidecar)
                    and _is_safe_database(sidecar_entry)
                )
                if suffix == "-shm":
                    # SQLite readers legitimately update the shared-memory
                    # coordination file. Pin its owner-controlled inode, but
                    # do not mistake our own lock bookkeeping for data drift.
                    safe_sidecar = safe_sidecar and all(
                        (metadata.st_dev, metadata.st_ino)
                        == (initial_sidecar.st_dev, initial_sidecar.st_ino)
                        for metadata in (final_sidecar, sidecar_entry)
                    )
                else:
                    safe_sidecar = safe_sidecar and _artifact_read_snapshot_is_stable(
                        initial_sidecar,
                        final_sidecar,
                        sidecar_entry,
                        require_owner=True,
                    )
                if not safe_sidecar:
                    sidecars_stable = False
            if (
                not _is_safe_database(final_metadata)
                or not _is_safe_database(entry_metadata)
                or not _artifact_read_snapshot_is_stable(
                    initial_metadata,
                    final_metadata,
                    entry_metadata,
                    require_owner=True,
                )
                or (final_metadata.st_dev, final_metadata.st_ino) != initial_identity
                or (entry_metadata.st_dev, entry_metadata.st_ino) != initial_identity
                or not stat.S_ISDIR(pinned_parent_metadata.st_mode)
                or not stat.S_ISDIR(current_parent_metadata.st_mode)
                or (
                    pinned_parent_metadata.st_dev,
                    pinned_parent_metadata.st_ino,
                )
                != (
                    current_parent_metadata.st_dev,
                    current_parent_metadata.st_ino,
                )
                or not sidecars_stable
            ):
                return []
            result = mapped_rows
        except (
            DashboardArtifactError,
            FileNotFoundError,
            OSError,
            sqlite3.Error,
            TypeError,
            ValueError,
        ):
            result = []
        finally:
            if connection is not None:
                try:
                    connection.close()
                except sqlite3.Error:
                    result = []
            if database_descriptor >= 0:
                _close_artifact_descriptor(database_descriptor)
            if comparison_parent_descriptor >= 0:
                _close_artifact_descriptor(comparison_parent_descriptor)
            for descriptor in sidecar_descriptors.values():
                _close_artifact_descriptor(descriptor)
            if parent_descriptor >= 0:
                _close_artifact_descriptor(parent_descriptor)
        return result

    def _load_scan_jobs_read_only(
        self,
        *,
        scan_id: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        """Return one fully stable snapshot, tolerating bounded local WAL churn."""
        def _path_identity() -> tuple[int, int, int, int] | None:
            parent_descriptor = -1
            try:
                path = _artifact_path(self._scan_jobs_db_path)
                entry = _artifact_lstat(path)
                if entry is None:
                    return None
                parent_descriptor = _open_artifact_directory(
                    path.parent,
                    create=False,
                )
                parent = os.fstat(parent_descriptor)
            except (DashboardArtifactError, FileNotFoundError, OSError):
                return None
            finally:
                if parent_descriptor >= 0:
                    _close_artifact_descriptor(parent_descriptor)
            return (
                parent.st_dev,
                parent.st_ino,
                entry.st_dev,
                entry.st_ino,
            )

        pinned_identity = _path_identity()
        if pinned_identity is None:
            return []
        for attempt in range(4):
            rows = self._load_scan_jobs_read_only_once(
                scan_id=scan_id,
                limit=limit,
            )
            if rows:
                return rows
            # Retry only while the same main database and parent directory
            # remain pinned. Entry or ancestor replacement is a hard boundary
            # failure, not SQLite coordination churn.
            if _path_identity() != pinned_identity:
                return []
            if attempt < 3:
                # Each attempt repeats every inode/content stability check. A
                # short retry permits the dashboard's own completed audit
                # transaction to settle without accepting a changing snapshot.
                time.sleep(0.025)
        return []

    def _durable_jobs_for_read_projection(
        self,
        *,
        scan_id: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        """Return only Task 103 rows through the descriptor-pinned reader."""

        return [
            row
            for row in self._load_scan_jobs_read_only(
                scan_id=scan_id,
                limit=limit,
            )
            if row.get("lifecycle_authority") == "task103"
        ]

    def _load_scan_jobs(self, limit: int = 200) -> list[dict[str, Any]]:
        """Load canonical Task 103 jobs, then conservative legacy history."""

        durable_rows = self._durable_job_state().list_jobs(
            tenant_id=self.tenant_id,
            limit=limit,
        )
        rows = [
            projection
            for item in durable_rows
            if (
                projection := self._load_scan_job(str(item["id"]))
            )
            is not None
        ]
        known = {str(item.get("scan_id") or "") for item in rows}
        for legacy in self._load_scan_jobs_read_only(limit=limit):
            scan_id = str(legacy.get("scan_id") or "")
            if not scan_id or scan_id in known:
                continue
            legacy = dict(legacy)
            if legacy.get("status") in {"running", "pending"}:
                legacy["status"] = "orphaned"
                legacy["status_note"] = (
                    "Legacy row has no Task 103 lifecycle authority."
                )
            rows.append(legacy)
        return sorted(
            rows,
            key=lambda item: str(
                item.get("created_at")
                or item.get("started_at")
                or ""
            ),
            reverse=True,
        )[:limit]

    def _delete_scan_job(self, scan_id: str) -> None:
        """Delete only an unbound legacy projection, never Task 103 history."""
        if self._durable_job_state().get_job(
            scan_id,
            tenant_id=self.tenant_id,
        ) is not None:
            raise DashboardArtifactError(
                "durable job history cannot be deleted"
            )
        def _delete(session: Any) -> None:
            job = get_scan_job(session, scan_id, tenant_id=self.tenant_id)
            if job is not None:
                session.delete(job)
                session.commit()

        try:
            self._with_scan_jobs_session(_delete)
        except Exception as exc:
            log.warning(
                "Could not delete dashboard scan job reason=%s",
                type(exc).__name__,
            )

    def _find_finding_metadata(
        self,
        finding_id: str,
        *,
        actor_id: str | None = None,
    ) -> dict[str, Any] | None:
        """Find one tenant-bound persisted canonical finding."""
        for finding in self._canonical_projection_rows(actor_id=actor_id):
            if finding.get("id") == finding_id:
                return self._public_finding(finding)
        return None

    def _retest_framework(self, module: str) -> str:
        """Classify an existing module without a generic execution fallback."""

        if module in self._netforge_module_names():
            return "netforge"
        try:
            from webforge.webforge import MODULE_MAP as WEBFORGE_MODULE_MAP

            if module in WEBFORGE_MODULE_MAP:
                return "webforge"
        except Exception:
            pass
        return "forge"

    def _canonical_finding_database(self, finding_id: str) -> Path:
        """Resolve the one verified canonical database that owns a finding."""

        matches: list[Path] = []
        for root in self._canonical_result_roots():
            for database_path in self._canonical_database_paths(root):
                session = create_db(database_path)
                try:
                    count = int(
                        session.execute(
                            sql_text(
                                "SELECT COUNT(*) FROM canonical_findings "
                                "WHERE tenant_id=:tenant_id AND id=:finding_id"
                            ),
                            {
                                "tenant_id": self.tenant_id,
                                "finding_id": finding_id,
                            },
                        ).scalar_one()
                    )
                    session.rollback()
                finally:
                    session.close()
                if count:
                    matches.append(database_path)
        if len(matches) != 1:
            raise DashboardArtifactError(
                "canonical finding source is unavailable or ambiguous"
            )
        return matches[0]

    def _retest_session_reference(self, finding_id: str) -> str:
        """Load only the original opaque credential reference for authorization.

        The canonical database supplies the exact source action identity; the
        protected authorization database supplies its signed envelope.  Secret
        values are never read here and a client-supplied replacement is never
        accepted.
        """

        database_path = self._canonical_finding_database(finding_id)
        canonical_session = create_db(database_path)
        try:
            row = canonical_session.execute(
                sql_text(
                    "SELECT f.tenant_id,o.engagement_id,o.job_id,o.action_id,"
                    "mv.module_id,asset.canonical_uri,"
                    "action.authorization_decision_id "
                    "FROM canonical_findings f "
                    "JOIN canonical_observations o "
                    "ON o.tenant_id=f.tenant_id AND o.id=f.observation_id "
                    "JOIN canonical_module_versions mv "
                    "ON mv.tenant_id=o.tenant_id AND mv.id=o.module_version_id "
                    "JOIN canonical_assets asset "
                    "ON asset.tenant_id=o.tenant_id AND asset.id=o.asset_id "
                    "JOIN canonical_actions action "
                    "ON action.tenant_id=o.tenant_id AND action.id=o.action_id "
                    "WHERE f.tenant_id=:tenant_id AND f.id=:finding_id"
                ),
                {"tenant_id": self.tenant_id, "finding_id": finding_id},
            ).mappings().first()
            canonical_session.rollback()
        finally:
            canonical_session.close()
        if row is None:
            raise DashboardArtifactError("canonical finding source is unavailable")

        def _load(session: Any) -> str:
            record = get_authorization_decision(
                session,
                str(row["authorization_decision_id"]),
            )
            if record is None:
                return ""
            try:
                envelope = ActionAuthorizationEnvelope.from_value(
                    json.loads(str(record.envelope_json))
                )
            except Exception:
                return ""
            expected_target = canonical_target(str(row["canonical_uri"]))
            if not all(
                (
                    envelope.decision_outcome == "allow",
                    envelope.tenant_id == str(row["tenant_id"]),
                    envelope.engagement_id == str(row["engagement_id"]),
                    envelope.job_id == str(row["job_id"]),
                    envelope.action_id == str(row["action_id"]),
                    envelope.decision_id
                    == str(row["authorization_decision_id"]),
                    envelope.module_id
                    in {
                        str(row["module_id"]),
                        module_set_binding([str(row["module_id"])]),
                    },
                    envelope.resolved_target == expected_target,
                )
            ):
                return ""
            return str(envelope.credential_reference or "")

        return str(self._with_scan_jobs_session(_load))

    def _commit_retest_authorization(
        self,
        context: AuthorizationContext,
        confirmation: ActionConfirmation,
    ) -> ActionAuthorizationEnvelope:
        """Issue and consume the exact parent/child retest authority only."""

        def _persist(session: Any) -> ActionAuthorizationEnvelope:
            try:
                issued = issue_authorization(
                    session=session,
                    context=context,
                    confirmation=confirmation,
                    commit=False,
                )
                if not issued.allowed:
                    raise ValueError("retest authorization was denied")
                consumed_parent = consume_authorization(
                    session=session,
                    envelope=issued.envelope,
                    expected=context,
                    boundary="dashboard.launch",
                    commit=False,
                )
                if not consumed_parent.allowed:
                    raise ValueError("retest parent authorization was not consumed")
                child_context = AuthorizationContext(
                    **{
                        **context.__dict__,
                        "action_kind": "engine.execute",
                        "parent_decision_id": issued.envelope.decision_id,
                        "confirmation_method": ConfirmationMethod.INHERITED,
                    }
                )
                derived = derive_authorization(
                    session=session,
                    parent_envelope=issued.envelope,
                    context=child_context,
                    parent_boundary="dashboard.launch",
                    commit=False,
                )
                if not derived.allowed:
                    raise ValueError("retest execution authorization was denied")
                consumed_child = consume_authorization(
                    session=session,
                    envelope=derived.envelope,
                    expected=child_context,
                    boundary="retest.verifier",
                    commit=False,
                )
                if not consumed_child.allowed:
                    raise ValueError("retest verifier authorization was not consumed")
                session.commit()
                return consumed_child.envelope
            except Exception as exc:
                session.rollback()
                record_authorization_denial(
                    session=session,
                    context=context,
                    reason_code=AuthorizationReason.HANDOFF_PERSISTENCE_FAILED,
                )
                raise HTTPException(
                    status_code=500,
                    detail="Retest authorization handoff failed; execution denied",
                ) from exc

        return self._with_scan_jobs_session(_persist)

    def _retest_authorization_allowed(
        self,
        tenant_id: str,
        job_id: str,
        decision_id: str,
        action_id: str,
    ) -> bool:
        """Validate one immutable child envelope from the authorization DB."""

        def _load(session: Any) -> bool:
            record = get_authorization_decision(session, decision_id)
            if record is None:
                return False
            try:
                envelope = ActionAuthorizationEnvelope.from_value(
                    json.loads(str(record.envelope_json))
                )
                expires = datetime.fromisoformat(
                    envelope.expires_at.replace("Z", "+00:00")
                )
            except Exception:
                return False
            return (
                envelope.decision_outcome == "allow"
                and envelope.tenant_id == tenant_id
                and envelope.job_id == job_id
                and envelope.decision_id == decision_id
                and envelope.action_id == action_id
                and envelope.action_kind == "engine.execute"
                and datetime.now(timezone.utc) < expires.astimezone(timezone.utc)
            )

        try:
            return bool(self._with_scan_jobs_session(_load))
        except Exception:
            return False

    def _netforge_module_names(self) -> set[str]:
        """Return known netforge module names."""
        names = {
            module
            for entry in UI_MODULE_MAP.values()
            if entry and entry[0] == "net"
            for module in [entry[1]]
        }
        try:
            from netforge.netforge import MODULE_MAP as NETFORGE_MODULE_MAP
            names.update(NETFORGE_MODULE_MAP.keys())
        except Exception:
            pass
        return names

    def _write_scan_history(
        self,
        scan_id: str,
        target: str,
        scan_type: str,
        mode: str,
        engagement: str,
        frameworks: list[str],
        requested_modules: list[str] | None = None,
        actual_modules: list[str] | None = None,
        scan_options: dict[str, Any] | None = None,
        control: dict[str, Any] | None = None,
        process_ids: list[str] | None = None,
    ) -> None:
        """Append a new scan record to the persistent history store."""
        record = {
            "scan_id": scan_id,
            "tenant_id": self.tenant_id,
            "target": target,
            "scan_type": scan_type,
            "mode": mode,
            "engagement": engagement,
            "frameworks": frameworks,
            "requested_modules": requested_modules or [],
            "actual_modules": actual_modules or [],
            "scan_options": scan_options or {},
            "control": control or {},
            "process_ids": process_ids or [],
            "return_code": None,
            "logs": {
                process_id: str(self._scan_logs_dir / f"{process_id}.log")
                for process_id in (process_ids or [])
            },
            "started_at": datetime.now(timezone.utc).isoformat(),
            "status": "running",
            "findings_count": {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0},
        }
        try:
            with self._artifact_state_lock:
                loaded = self._load_json_artifact(
                    self._history_path,
                    linked_entry_as_absent=True,
                )
                if loaded is None:
                    history: list[dict[str, Any]] = []
                elif isinstance(loaded, list) and all(
                    isinstance(item, dict) for item in loaded
                ):
                    history = loaded
                else:
                    raise DashboardArtifactError("dashboard scan history is invalid")
                history.insert(0, record)
                self._write_json_artifact(self._history_path, history)
        except Exception as exc:
            log.warning(
                "Could not write dashboard scan history reason=%s",
                type(exc).__name__,
            )

    def _update_scan_history_status(self, scan_id: str, status: str) -> None:
        """Persist terminal status for a scan record when a child process exits."""
        del status
        try:
            with self._artifact_state_lock:
                loaded = self._load_json_artifact(
                    self._history_path,
                    linked_entry_as_absent=True,
                )
                if loaded is None:
                    return
                if not isinstance(loaded, list) or not all(
                    isinstance(item, dict) for item in loaded
                ):
                    raise DashboardArtifactError("dashboard scan history is invalid")
                changed = False
                durable = self._durable_job_state().get_job(
                    scan_id,
                    tenant_id=self.tenant_id,
                )
                for record in loaded:
                    record_tenant = str(record.get("tenant_id") or "default")
                    if record.get("scan_id") == scan_id and record_tenant == self.tenant_id:
                        record["status"] = (
                            durable["state"]
                            if durable is not None
                            else "orphaned"
                        )
                        record["updated_at"] = datetime.now(timezone.utc).isoformat()
                        changed = True
                        break
                if changed:
                    self._write_json_artifact(self._history_path, loaded)
        except Exception as exc:
            log.warning(
                "Could not update dashboard scan history status reason=%s",
                type(exc).__name__,
            )

    def _load_scan_history(self, limit: int = 50) -> list[dict]:
        """Load scan history records, enriched with live status from active scans."""
        history: list[dict] = []
        try:
            loaded = self._load_json_artifact(
                self._history_path,
                linked_entry_as_absent=True,
            )
            if isinstance(loaded, list):
                history = [item for item in loaded if isinstance(item, dict)]
        except Exception as exc:
            log.warning(
                "Could not load dashboard scan history reason=%s",
                type(exc).__name__,
            )
        history = [
            record
            for record in history
            if isinstance(record, dict)
            and str(record.get("tenant_id") or "default") == self.tenant_id
        ]

        jobs = {
            job.get("scan_id", ""): job
            for job in self._load_scan_jobs_read_only(limit=max(limit, 200))
        }
        seen_ids = {record.get("scan_id", "") for record in history}
        for record in history:
            job = jobs.get(record.get("scan_id", ""))
            if not job:
                continue
            record.update({
                "status": job.get("status", record.get("status")),
                "return_code": job.get("return_code"),
                "results_dir": job.get("results_dir"),
                "logs": job.get("logs", {}),
                "error": job.get("error"),
                "completed_at": job.get("completed_at"),
                "updated_at": job.get("updated_at") or record.get("updated_at"),
            })
            if not record.get("frameworks"):
                record["frameworks"] = job.get("frameworks", [])
            if not record.get("actual_modules"):
                record["actual_modules"] = job.get("actual_modules", [])

        for job in jobs.values():
            if job.get("scan_id") not in seen_ids:
                history.append(job)

        # Enrich the response projection only.  A viewer GET must never
        # reconcile jobs or persist orphan status.
        for record in history:
            sid = record.get("scan_id", "")
            authoritative = jobs.get(str(sid))
            if (
                authoritative is not None
                and authoritative.get("lifecycle_authority") == "task103"
            ):
                record["status"] = authoritative.get("status", "orphaned")
            elif record.get("status") in {
                "leased",
                "running",
                "paused",
                "canceling",
            }:
                record["status"] = "orphaned"
                record["status_note"] = (
                    "No Task 103 lifecycle authority exists for this legacy row."
                )

        # Collect finding counts from results directories for completed scans
        forge_root = Path(__file__).parent.parent.parent
        for record in history:
            if record.get("status") == "completed":
                record["findings_count"] = self._count_findings_for_scan(
                    forge_root, record,
                )
        return sorted(
            history,
            key=lambda r: r.get("started_at") or r.get("created_at") or "",
            reverse=True,
        )[:limit]

    def _write_scan_history_records(self, history: list[dict]) -> None:
        try:
            with self._artifact_state_lock:
                self._write_json_artifact(self._history_path, history)
        except Exception as exc:
            log.warning(
                "Could not write dashboard scan history reason=%s",
                type(exc).__name__,
            )

    def _delete_scan_record(self, scan_id: str, purge_artifacts: bool = False) -> dict:
        """Remove scan history/log/control state and optionally matching result artifacts."""
        scan_id = _artifact_identifier(scan_id)
        history: list[dict] = []
        try:
            loaded = self._load_json_artifact(
                self._history_path,
                linked_entry_as_absent=True,
            )
            if isinstance(loaded, list):
                history = [item for item in loaded if isinstance(item, dict)]
        except Exception as exc:
            log.warning(
                "Could not load dashboard scan history for deletion reason=%s",
                type(exc).__name__,
            )

        record = next(
            (
                r
                for r in history
                if isinstance(r, dict)
                and r.get("scan_id") == scan_id
                and str(r.get("tenant_id") or "default") == self.tenant_id
            ),
            None,
        )
        # This is an authenticated mutation path. Its mandatory pre-dispatch
        # audit write can legitimately change the SQLite WAL, so use the
        # descriptor-bound transactional loader rather than the viewer-only
        # stable-snapshot reader.
        job = self._load_scan_job(scan_id)
        found = (
            record is not None
            or job is not None
            or any(self._base_scan_id(k) == scan_id for k in self._active_scans)
        )
        if not found:
            return {"found": False, "scan_id": scan_id}

        durable_job = self._durable_job_state().get_job(
            scan_id,
            tenant_id=self.tenant_id,
        )
        if durable_job is not None:
            raise DashboardArtifactError(
                "durable job history cannot be deleted; cancel active work "
                "through the versioned job-state service"
            )

        if job is not None and self._scan_job_has_canonical_lineage(job):
            raise DashboardArtifactError(
                "scan deletion would break canonical evidence lineage"
            )

        removed_processes: list[str] = []
        for key, info in list(self._active_scans.items()):
            if self._base_scan_id(key) != scan_id:
                continue
            proc = info.get("proc")
            if proc and proc.poll() is None:
                raise DashboardArtifactError(
                    "legacy live process has no persisted Task 103 child "
                    "identity; refuse PID-only deletion control"
                )
            removed_processes.append(key)
            self._active_scans.pop(key, None)

        removed_files: list[str] = []
        for path in (
            self._control_dir / f"{scan_id}.json",
            self._scan_logs_dir / f"{scan_id}.log",
        ):
            try:
                if _unlink_artifact(path):
                    removed_files.append(str(path))
            except Exception as exc:
                log.warning(
                    "Could not remove dashboard scan artifact reason=%s",
                    type(exc).__name__,
                )
        try:
            removed_files.extend(
                str(path)
                for path in _unlink_matching_artifacts(
                    self._scan_logs_dir,
                    prefix=f"{scan_id}_",
                    suffix=".log",
                )
            )
        except Exception as exc:
            log.warning(
                "Could not remove dashboard scan logs reason=%s",
                type(exc).__name__,
            )

        removed_artifacts: list[str] = []
        if purge_artifacts and record:
            removed_artifacts = self._purge_scan_artifacts(record)

        if record:
            history = [
                r
                for r in history
                if not (
                    isinstance(r, dict)
                    and r.get("scan_id") == scan_id
                    and str(r.get("tenant_id") or "default") == self.tenant_id
                )
            ]
            self._write_scan_history_records(history)
        self._delete_scan_job(scan_id)

        return {
            "found": True,
            "scan_id": scan_id,
            "history_deleted": bool(record),
            "processes_removed": removed_processes,
            "files_deleted": removed_files,
            "artifacts_deleted": removed_artifacts,
        }

    def _scan_job_has_canonical_lineage(
        self,
        record: Mapping[str, Any],
    ) -> bool:
        """Return whether a durable job owns observations that must be retained."""
        if record.get("authorization_state") != "allow":
            return False
        root = self._job_bound_canonical_result_root(record)
        for database_path in self._canonical_database_paths(root):
            try:
                session = create_db(database_path)
                try:
                    count = int(
                        session.execute(
                            sql_text(
                                "SELECT COUNT(*) FROM canonical_observations "
                                "WHERE tenant_id=:tenant_id"
                            ),
                            {"tenant_id": self.tenant_id},
                        ).scalar_one()
                    )
                    session.rollback()
                finally:
                    session.close()
            except Exception:
                raise DashboardArtifactError(
                    "canonical lineage could not be verified for deletion"
                ) from None
            if count:
                return True
        return False

    def _purge_scan_artifacts(self, record: dict) -> list[str]:
        """Keep unbound legacy result artifacts outside dashboard deletion."""
        del record
        return []

    def _get_scan_detail(self, scan_id: str) -> dict | None:
        """Build the Nessus-style drilldown payload for one scan."""
        scan_id = _artifact_identifier(scan_id)
        records = self._load_scan_history(limit=500)
        record = next((r for r in records if r.get("scan_id") == scan_id), None)
        read_only_jobs = self._load_scan_jobs_read_only(
            scan_id=scan_id,
            limit=1,
        )
        job = read_only_jobs[0] if read_only_jobs else None
        authoritative_status = (
            str(job.get("status"))
            if job is not None
            and job.get("lifecycle_authority") == "task103"
            else "orphaned"
        )

        process_entries = []
        for key, info in self._active_scans.items():
            if self._base_scan_id(key) != scan_id:
                continue
            proc = info.get("proc")
            rc = info.get("returncode")
            log_path = self._scan_logs_dir / f"{key}.log"
            try:
                log_metadata = _artifact_lstat(log_path)
            except DashboardArtifactError:
                log_metadata = None
            log_available = bool(
                log_metadata is not None
                and stat.S_ISREG(log_metadata.st_mode)
                and log_metadata.st_nlink == 1
            )
            process_entries.append({
                "process_id": key,
                "framework": info.get("type", ""),
                "target": info.get("target", ""),
                "mode": info.get("mode", ""),
                "status": authoritative_status,
                "lifecycle_authority": (
                    "task103"
                    if job is not None
                    and job.get("lifecycle_authority") == "task103"
                    else "unverified_legacy"
                ),
                "returncode": rc,
                "started_at": info.get("started_dt"),
                "log_path": str(log_path) if log_available else "",
                "log_tail": self._tail_text(log_path),
                "command": info.get("command", []),
                "control_file": info.get("control_file", ""),
                "dashboard_url": info.get("dashboard_url", ""),
                "requested_modules": info.get("requested_modules", []),
                "actual_modules": info.get("actual_modules", []),
                "scan_options": info.get("scan_options", {}),
                "control": info.get("control", {}),
            })

        if not record and not process_entries:
            return None

        if not record:
            first = process_entries[0]
            record = {
                "scan_id": scan_id,
                "target": first.get("target", ""),
                "scan_type": first.get("framework", ""),
                "mode": first.get("mode", ""),
                "engagement": "",
                "frameworks": [p["framework"] for p in process_entries],
                "started_at": first.get("started_at"),
                "status": first.get("status", "running"),
                "requested_modules": [],
                "actual_modules": [],
            }

        forge_root = Path(__file__).parent.parent.parent
        findings = self._findings_for_scan(forge_root, record)
        if job:
            record = {
                **record,
                **job,
                "logs": job.get("logs", {}),
                "return_code": job.get("return_code"),
                "error": job.get("error"),
                "completed_at": job.get("completed_at"),
            }
        return {
            **record,
            "findings_count": self._count_findings(findings),
            "processes": process_entries,
            "reports": self._reports_for_scan(forge_root, record),
            "findings": findings[:200],
        }

    def _logs_for_scan(self, scan_id: str, max_lines: int = 400) -> list[dict[str, Any]]:
        """Return bounded log tails for known subprocess logs for one scan."""
        scan_id = _artifact_identifier(scan_id)
        log_paths: dict[str, Path] = {}
        for suffix in ("_web", "_net", "_net_auto"):
            process_id = f"{scan_id}{suffix}"
            log_paths[process_id] = self._scan_logs_dir / f"{process_id}.log"

        read_only_jobs = self._load_scan_jobs_read_only(scan_id=scan_id, limit=1)
        job = read_only_jobs[0] if read_only_jobs else None
        for process_id, raw_path in (job or {}).get("logs", {}).items():
            path = Path(str(raw_path))
            try:
                if path.resolve().is_relative_to(self._scan_logs_dir.resolve()):
                    log_paths[str(process_id)] = path
            except Exception:
                continue

        entries: list[dict[str, Any]] = []
        for process_id, path in sorted(log_paths.items()):
            try:
                metadata = _artifact_lstat(path)
            except DashboardArtifactError:
                continue
            if (
                metadata is None
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
            ):
                continue
            entries.append({
                "process_id": process_id,
                "path": str(path),
                "size": metadata.st_size,
                "modified_at": datetime.fromtimestamp(metadata.st_mtime, tz=timezone.utc).isoformat(),
                "tail": self._tail_text(path, max_lines=max_lines),
            })
        return entries

    def _tail_text(self, path: Path, max_lines: int = 120) -> str:
        """Return the last lines of a subprocess log without loading huge files into memory."""
        try:
            redacted = self._redact_subprocess_output(
                _read_artifact_tail(path)
            )
            lines = redacted.splitlines()
            return "\n".join(lines[-max_lines:])
        except (FileNotFoundError, DashboardArtifactError):
            return ""

    @staticmethod
    def _redact_subprocess_output(value: str) -> str:
        """Redact scalar canaries and complete multiline private-key blocks."""
        rendered: list[str] = []
        private_key_open = False
        for line in str(value).splitlines(keepends=True):
            if private_key_open:
                if _PRIVATE_KEY_END_RE.search(line):
                    private_key_open = False
                continue
            if _PRIVATE_KEY_BEGIN_RE.search(line):
                rendered.append("<redacted>\n" if line.endswith(("\n", "\r")) else "<redacted>")
                private_key_open = not bool(_PRIVATE_KEY_END_RE.search(line))
                continue
            rendered.append(str(redact_authorization_value(line)))
        return "".join(rendered)

    def _reports_for_scan(self, forge_root: Path, record: dict) -> list[dict]:
        """Return no unbound legacy report artifacts."""
        del forge_root, record
        return []

    def _findings_for_scan(self, forge_root: Path, record: dict) -> list[dict]:
        """Return verified canonical findings for one tenant-bound scan job."""
        del forge_root
        if record.get("authorization_state") != "allow":
            return []
        root = self._job_bound_canonical_result_root(record)
        return [
            self._public_finding(row)
            for row in self._canonical_projection_rows(
                actor_id="dashboard-scan-history",
                roots=[root],
            )
        ]

    def _count_findings(self, findings: list[dict]) -> dict:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}
        for finding in findings:
            sev = (finding.get("severity") or "info").lower()
            if sev == "informational":
                sev = "info"
            if sev in counts:
                counts[sev] += 1
            counts["total"] += 1
        return counts

    def _count_findings_for_scan(self, forge_root: Path, record: dict) -> dict:
        """Count findings from result JSON files for a completed scan."""
        counts = self._count_findings(self._findings_for_scan(forge_root, record))
        return {k: counts[k] for k in ("critical", "high", "medium", "low", "total")}

    # ── Scan Templates store ────────────────────────────────────────

    @property
    def _templates_path(self) -> Path:
        forge_root = Path(__file__).parent.parent.parent
        return self._tenant_data_path(
            "scan_templates.json",
            legacy_default=forge_root / "scan_templates.json",
        )

    def _load_scan_templates(self) -> list[dict]:
        try:
            loaded = self._load_json_artifact(
                self._templates_path,
                linked_entry_as_absent=True,
            )
            if isinstance(loaded, list):
                return [item for item in loaded if isinstance(item, dict)]
        except Exception as exc:
            log.warning(
                "Could not load dashboard scan templates reason=%s",
                type(exc).__name__,
            )
        return []

    def _save_scan_template(self, template: dict) -> None:
        try:
            with self._artifact_state_lock:
                templates = self._load_scan_templates()
                templates.insert(0, template)
                self._write_scan_templates(templates)
        except Exception as exc:
            log.warning(
                "Could not save dashboard scan template reason=%s",
                type(exc).__name__,
            )
            raise DashboardArtifactError("dashboard scan-template persistence failed") from None

    def _write_scan_templates(self, templates: list[dict]) -> None:
        try:
            with self._artifact_state_lock:
                self._write_json_artifact(self._templates_path, templates)
        except Exception as exc:
            log.warning(
                "Could not write dashboard scan templates reason=%s",
                type(exc).__name__,
            )
            raise DashboardArtifactError("dashboard scan-template persistence failed") from None


def create_app(
    event_bus: EventBus | None = None,
    state_store: StateStore | None = None,
) -> Any:
    """Factory function for creating the dashboard app.

    Useful for testing and when running with external ASGI servers.
    """
    server = DashboardServer(
        event_bus=event_bus,
        state_store=state_store,
        auth=True,
    )
    return server.create_app()
