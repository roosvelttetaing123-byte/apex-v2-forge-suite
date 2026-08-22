#!/usr/bin/env python3
"""
ADForge — Active Directory Penetration Testing Framework
=========================================================
Master entry point. Runs ALL modules in PHASE ORDER (phases 1-14).
v5 APEX: EventBus integration, multi-target, pause/resume/abort.

FOR AUTHORIZED PENETRATION TESTING ONLY.

Usage:
  python adforge.py --dc 10.0.0.1 --domain corp.local --mode auth --username jsmith --password Pass123
  python adforge.py --dc 10.0.0.1 --domain corp.local --mode unauth
  python adforge.py --dc 10.0.0.1 --domain corp.local --mode admin --username da --password DaPass! --dcsync --bloodhound
  python adforge.py --dc 10.0.0.1 --domain corp.local --mode auth --username admin --hash NTHASH
  python adforge.py --dc 10.0.0.1 --domain corp.local --dry-run
"""
from __future__ import annotations

import argparse
import asyncio
import getpass
import importlib
import os
import sys
import time
import uuid
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

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
    redact_authorization_value,
    record_boundary_denial,
    record_authorization_denial,
    select_authorization_envelope,
    validate_consumed_authorization,
)
from common.config import BaseForgeConfig, load_config
from common.confirm_gate import (
    LAUNCH_CONFIRMATIONS_ENV,
    ActionConfirmation,
    decide_action,
    load_launch_confirmations,
    load_launch_expectation,
    set_auto_confirm,
)
from common.db import create_db, ScanRunModel, Session as DbSession
from common.logger import get_logger, phase_banner, console
from common.reporter import BaseReporter
from common.scope import Scope, ScopeDecision, ScopeReason, canonical_target, decision_for_reason, safe_target_display

log = get_logger("adforge")
from common.version import VERSION
ENGINE_NAME = "adforge"
DEFAULT_LAUNCH_ACTION = "scan"

PHASES: list[tuple[int, str, list[str], list[str]]] = [
    # (num, name, modules, required_modes)
    (1,  "Unauthenticated Recon",  ["null_session","ldap_anon","kerb_user_enum","rid_cycle","dns_enum"],
         ["unauth","auth","admin"]),
    (2,  "Domain Enumeration",     ["domain_enum","user_enum","group_enum","computer_enum","ou_enum",
                                    "gpo_enum","trust_enum","schema_enum","fine_grained_psp",
                                    "admin_count","inactive_account","service_account_audit","gpp_password"],
         ["auth","admin"]),
    (3,  "Attack Surface",         ["acl_enum","spn_enum","asrep_enum","laps_enum","gmsa_enum",
                                    "adcs_enum","rc4_check","entra_hybrid"],
         ["auth","admin"]),
    (4,  "Vulnerability Checks",   ["zerologon","petitpotam","nopac","printspooler","ms14_068",
                                    "dfscoerce","dcshadow","shadowcoerce","certifried",
                                    "pre2000_computers"],
         ["auth","admin"]),
    (5,  "Kerberos Attacks",       ["kerberoast","asrep_roast"],
         ["auth","admin"]),
    (6,  "Password Attacks",       ["password_spray"],
         ["auth","admin"]),
    (7,  "Credential Attacks",     ["ntlm_relay","pass_hash","pass_ticket"],
         ["auth","admin"]),
    (8,  "Ticket Attacks",         ["golden_ticket","silver_ticket"],
         ["admin"]),
    (9,  "ACL Abuse Analysis",     ["acl_scanner","dacl_abuse","forcechangepw","add_member","shadow_creds"],
         ["auth","admin"]),
    (10, "GPO + Delegation",       ["gpo_scanner","gpo_path_check","linked_gpo_check",
                                    "uncons_deleg","cons_deleg","rbcd_attack"],
         ["auth","admin"]),
    (11, "AD CS Audit",            ["esc1_check","esc2_check","esc3_check","esc4_check",
                                    "esc6_check","esc7_check","esc8_check",
                                    "esc9_check","esc10_check","esc11_check",
                                    "esc13_check","esc14_check"],
         ["auth","admin"]),
    (12, "Lateral Movement",       ["smb_exec","wmi_exec","rdp_check"],
         ["auth","admin"]),
    (13, "Post-Exploitation",      ["da_check","dcsync","secretsdump","loot_collector","bitlocker_check",
                                    "recycle_bin","ad_backup_check","persist_check",
                                    "privileged_group_mon","adminsdholder"],
         ["admin"]),
    (14, "Reporting",              ["html_report","pdf_report","json_export","csv_export",
                                    "bloodhound_export","attack_path_svg"],
         ["unauth","auth","admin"]),
]

def _mod_pkg(subpkg: str, name: str) -> str:
    return f"adforge.modules.{subpkg}.{name}"

MODULE_MAP: dict[str, str] = {
    "null_session":     _mod_pkg("unauth","null_session"),
    "ldap_anon":        _mod_pkg("unauth","ldap_anon"),
    "kerb_user_enum":   _mod_pkg("unauth","kerb_user_enum"),
    "rid_cycle":        _mod_pkg("unauth","rid_cycle"),
    "dns_enum":         _mod_pkg("unauth","dns_enum"),
    "domain_enum":      _mod_pkg("enum","domain_enum"),
    "user_enum":        _mod_pkg("enum","user_enum"),
    "group_enum":       _mod_pkg("enum","group_enum"),
    "computer_enum":    _mod_pkg("enum","computer_enum"),
    "ou_enum":          _mod_pkg("enum","ou_enum"),
    "gpo_enum":         _mod_pkg("enum","gpo_enum"),
    "trust_enum":       _mod_pkg("enum","trust_enum"),
    "schema_enum":      _mod_pkg("enum","schema_enum"),
    "fine_grained_psp": _mod_pkg("enum","fine_grained_psp"),
    "admin_count":      _mod_pkg("enum","admin_count"),
    "inactive_account": _mod_pkg("enum","inactive_account"),
    "service_account_audit": _mod_pkg("enum","service_account_audit"),
    "gpp_password":     _mod_pkg("enum","gpp_password"),
    "acl_enum":         _mod_pkg("enum","acl_enum"),
    "spn_enum":         _mod_pkg("enum","spn_enum"),
    "asrep_enum":       _mod_pkg("enum","asrep_enum"),
    "laps_enum":        _mod_pkg("enum","laps_enum"),
    "gmsa_enum":        _mod_pkg("enum","gmsa_enum"),
    "adcs_enum":        _mod_pkg("enum","adcs_enum"),
    "zerologon":        _mod_pkg("attacks","zerologon"),
    "petitpotam":       _mod_pkg("attacks","petitpotam"),
    "nopac":            _mod_pkg("attacks","nopac"),
    "printspooler":     _mod_pkg("attacks","printspooler"),
    "ms14_068":         _mod_pkg("attacks","ms14_068"),
    "dfscoerce":        _mod_pkg("attacks","dfscoerce"),
    "dcshadow":         _mod_pkg("attacks","dcshadow"),
    "kerberoast":       _mod_pkg("attacks","kerberoast"),
    "asrep_roast":      _mod_pkg("attacks","asrep_roast"),
    "password_spray":   _mod_pkg("attacks","password_spray"),
    "ntlm_relay":       _mod_pkg("attacks","ntlm_relay"),
    "pass_hash":        _mod_pkg("attacks","pass_hash"),
    "pass_ticket":      _mod_pkg("attacks","pass_ticket"),
    "golden_ticket":    _mod_pkg("attacks","golden_ticket"),
    "silver_ticket":    _mod_pkg("attacks","silver_ticket"),
    "dcsync":           _mod_pkg("attacks","dcsync"),
    "acl_scanner":      _mod_pkg("acl_abuse","acl_scanner"),
    "dacl_abuse":       _mod_pkg("acl_abuse","dacl_abuse"),
    "forcechangepw":    _mod_pkg("acl_abuse","forcechangepw"),
    "add_member":       _mod_pkg("acl_abuse","add_member"),
    "shadow_creds":     _mod_pkg("acl_abuse","shadow_creds"),
    "gpo_scanner":      _mod_pkg("gpo_abuse","gpo_scanner"),
    "gpo_path_check":   _mod_pkg("gpo_abuse","gpo_path_check"),
    "linked_gpo_check": _mod_pkg("gpo_abuse","linked_gpo_check"),
    "uncons_deleg":     _mod_pkg("delegation","uncons_deleg"),
    "cons_deleg":       _mod_pkg("delegation","cons_deleg"),
    "rbcd_attack":      _mod_pkg("delegation","rbcd_attack"),
    "esc1_check":       _mod_pkg("adcs","esc1_check"),
    "esc2_check":       _mod_pkg("adcs","esc2_check"),
    "esc3_check":       _mod_pkg("adcs","esc3_check"),
    "esc4_check":       _mod_pkg("adcs","esc4_check"),
    "esc6_check":       _mod_pkg("adcs","esc6_check"),
    "esc7_check":       _mod_pkg("adcs","esc7_check"),
    "esc8_check":       _mod_pkg("adcs","esc8_check"),
    "esc9_check":       _mod_pkg("adcs","esc9_check"),
    "esc10_check":      _mod_pkg("adcs","esc10_check"),
    "esc11_check":      _mod_pkg("adcs","esc11_check"),
    "esc13_check":      _mod_pkg("adcs","esc13_check"),
    "esc14_check":      _mod_pkg("adcs","esc14_check"),
    "certifried":       _mod_pkg("attacks","certifried"),
    "shadowcoerce":     _mod_pkg("attacks","shadowcoerce"),
    "pre2000_computers":_mod_pkg("attacks","pre2000_computers"),
    "entra_hybrid":     _mod_pkg("enum","entra_hybrid"),
    "rc4_check":        _mod_pkg("enum","rc4_check"),
    "smb_exec":         _mod_pkg("lateral","smb_exec"),
    "wmi_exec":         _mod_pkg("lateral","wmi_exec"),
    "rdp_check":        _mod_pkg("lateral","rdp_check"),
    "da_check":         _mod_pkg("post","da_check"),
    "secretsdump":      _mod_pkg("post","secretsdump"),
    "loot_collector":   _mod_pkg("post","loot_collector"),
    "bitlocker_check":  _mod_pkg("post","bitlocker_check"),
    "recycle_bin":       _mod_pkg("post","recycle_bin"),
    "ad_backup_check":  _mod_pkg("post","ad_backup_check"),
    "persist_check":    _mod_pkg("post","persist_check"),
    "privileged_group_mon": _mod_pkg("post","privileged_group_mon"),
    "adminsdholder":    _mod_pkg("post","adminsdholder"),
    "html_report":      _mod_pkg("reporting","html_report"),
    "pdf_report":       _mod_pkg("reporting","pdf_report"),
    "json_export":      _mod_pkg("reporting","json_export"),
    "csv_export":       _mod_pkg("reporting","csv_export"),
    "bloodhound_export":_mod_pkg("reporting","bloodhound_export"),
    "attack_path_svg":  _mod_pkg("reporting","attack_path_svg"),
}

CLASS_NAME_MAP: dict[str, str] = {
    k: "".join(p.capitalize() for p in k.split("_"))
    for k in MODULE_MAP
}
CLASS_NAME_MAP.update({
    "esc1_check":  "Esc1Check",  "esc2_check":  "Esc2Check",  "esc3_check":  "Esc3Check",
    "esc4_check":  "Esc4Check",  "esc6_check":  "Esc6Check",  "esc7_check":  "Esc7Check",
    "esc8_check":  "Esc8Check",  "esc9_check":  "Esc9Check",  "esc10_check": "Esc10Check",
    "esc11_check": "Esc11Check", "esc13_check": "Esc13Check", "esc14_check": "Esc14Check",
    "certifried":  "Certifried", "shadowcoerce": "ShadowCoerce",
    "pre2000_computers": "Pre2000Computers",
    "entra_hybrid": "EntraHybrid", "rc4_check": "Rc4Check",
    "ms14_068": "Ms14068", "dcshadow": "Dcshadow",
    "gpp_password": "GppPassword", "adminsdholder": "AdminSdHolder",
    "ntlm_relay": "NtlmRelay", "pass_hash": "PassHash", "pass_ticket": "PassTicket",
    "asrep_roast": "AsrepRoast", "kerberoast": "Kerberoast",
    "bloodhound_export": "BloodhoundExport", "attack_path_svg": "AttackPathSvg",
    "ldap_anon": "LdapAnon", "rid_cycle": "RidCycle", "dns_enum": "DnsEnum",
    "null_session": "NullSession", "kerb_user_enum": "KerbUserEnum",
    "acl_enum": "AclEnum", "spn_enum": "SpnEnum", "asrep_enum": "AsrepEnum",
    "laps_enum": "LapsEnum", "gmsa_enum": "GmsaEnum", "adcs_enum": "AdcsEnum",
    "ou_enum": "OuEnum", "gpo_enum": "GpoEnum", "acl_scanner": "AclScanner",
    "dacl_abuse": "DaclAbuse", "forcechangepw": "ForceChangePw",
    "add_member": "AddMember", "shadow_creds": "ShadowCreds",
    "gpo_scanner": "GpoScanner", "gpo_path_check": "GpoPathCheck",
    "linked_gpo_check": "LinkedGpoCheck", "uncons_deleg": "UnconsDeleg",
    "cons_deleg": "ConsDeleg", "rbcd_attack": "RbcdAttack",
    "smb_exec": "SmbExec", "wmi_exec": "WmiExec", "rdp_check": "RdpCheck",
    "da_check": "DaCheck", "secretsdump": "Secretsdump",
    "loot_collector": "LootCollector", "bitlocker_check": "BitlockerCheck",
    "recycle_bin": "RecycleBin", "ad_backup_check": "AdBackupCheck",
    "persist_check": "PersistCheck", "privileged_group_mon": "PrivilegedGroupMon",
})


# ── EventBus helpers ──────────────────────────────────────────────────

def _get_event_bus(event_bus: Any = None):
    if event_bus is None:
        return None, None, None
    try:
        from common.dashboard.event_bus import Event, EventType
        return event_bus, Event, EventType
    except ImportError:
        return None, None, None

def _get_eng_bus():
    try:
        from common.brain.engagement_bus import EngagementBus
        return EngagementBus.get_instance()
    except ImportError:
        return None


def _emit(bus: Any, Event: Any, EventType: Any, etype: str, source: str = "adforge", **data: Any) -> None:
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
    except Exception:
        pass


# ── Pause / Resume / Abort control ───────────────────────────────────

class ScanControl:
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
    p = argparse.ArgumentParser(
        description="ADForge — Active Directory Penetration Testing Framework",
        allow_abbrev=False,
    )
    p.add_argument("--dc",           required=True,                         help="Domain controller IP")
    p.add_argument("--domain",       required=True,                         help="Domain name (e.g. corp.local)")
    p.add_argument("--mode",         default="unauth",
                   choices=["unauth","auth","admin"],                        help="Scan mode")
    p.add_argument("--username",     default=None,                          help="Domain username")
    p.add_argument("--password",     default=None,                          help="Domain password")
    p.add_argument("--hash",         default=None,                          help="NTLM hash for pass-the-hash")
    p.add_argument("--ticket",       default=None,                          help="Kerberos ccache file path")
    p.add_argument("--engagement",   default="engagement",                   help="Engagement name")
    p.add_argument("--tester",       default="anonymous",                    help="Tester name")
    p.add_argument("--modules",      default=None,                          help="Comma-separated modules to run")
    p.add_argument("--skip-modules", default=None,                          help="Comma-separated modules to skip")
    p.add_argument("--scope",        action="append", default=[],          help="Explicitly authorized host/domain/CIDR (repeatable)")
    p.add_argument("--exclude",      action="append", default=[],          help="Explicitly excluded host/domain/CIDR (repeatable)")
    p.add_argument("--dcsync",       action="store_true",                    help="Enable DCSync in post phase (admin only)")
    p.add_argument("--bloodhound",   action="store_true",                    help="Export BloodHound JSON")
    p.add_argument("--spray-delay",  type=float, default=60.0,               help="Password spray round delay (s)")
    p.add_argument("--spray-max-rounds", type=int, default=1,               help="Max spray rounds")
    p.add_argument("--output",       default=None,                          help="Results output directory")
    p.add_argument("--report-format",default="html,pdf",                    help="Report formats")
    p.add_argument("--dry-run",      action="store_true",                    help="No connections made")
    p.add_argument("--resume",       default=None,                          help="Resume from results dir")
    p.add_argument("--auto-confirm", action="store_true",                    help="Skip confirmation gates (same as --autopilot)")
    p.add_argument("--autopilot",    action="store_true",                    help="Run all modules without confirmation (alias for --auto-confirm)")
    p.add_argument("--verbose",      action="store_true",                    help="Verbose output")
    p.add_argument("--version",      action="version", version=f"ADForge {VERSION}")
    p.add_argument("--dashboard-url", default=None,
                   help="Live dashboard URL (e.g. http://localhost:1337) — streams events in real time")
    return p.parse_args()


def _denied_summary(
    decision: ScopeDecision,
    *,
    dry_run: bool = False,
) -> dict[str, Any]:
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
        f"[bold red]Launch denied:[/bold red] reason_code={decision.reason_code}; "
        f"{decision.reason}"
    )


def _confirmation_for_target(
    confirmations: list[ActionConfirmation],
    target: str,
) -> ActionConfirmation | None:
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
        network_escalation_approval_required=False,
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
    """Return credential inputs actually available to this ADForge process."""
    names = ("username", "password", "hash", "ticket")
    return {
        name: str(getattr(args, name, "") or "")
        for name in names
        if getattr(args, name, "")
    }


def _credential_reference(args: argparse.Namespace) -> str:
    return protected_credential_reference(_credential_values(args))


_DIRECT_SECRET_ARGUMENTS = ("password", "hash", "ticket")


def _has_direct_secret_args(
    args: argparse.Namespace,
    cfg: BaseForgeConfig | None = None,
) -> bool:
    return any(
        getattr(args, field, None)
        or (cfg is not None and cfg.extra.get(field))
        for field in _DIRECT_SECRET_ARGUMENTS
    )


def _clear_direct_secret_args(
    args: argparse.Namespace,
    cfg: BaseForgeConfig | None = None,
) -> None:
    for field in _DIRECT_SECRET_ARGUMENTS:
        setattr(args, field, None)
        if cfg is not None:
            cfg.extra.pop(field, None)


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
            target=target if target is not None else getattr(args, "dc", None),
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
            run_id=runtime.get("run_id", "adforge-preflight-run"),
            job_id=getattr(args, "_launch_job_id", "adforge-preflight-job"),
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


def _prepare_cli_confirmation(
    args: argparse.Namespace,
) -> tuple[ScopeDecision, list[ActionConfirmation]]:
    inherited = load_launch_confirmations()
    if not args.dry_run and os.environ.get(LAUNCH_CONFIRMATIONS_ENV) and not inherited:
        return decision_for_reason(ScopeReason.INVALID_CONFIRMATION), []
    inherited_expectation = load_launch_expectation() if inherited else None
    if inherited and inherited_expectation is None:
        return decision_for_reason(ScopeReason.INVALID_CONFIRMATION), []
    job_id, expected_action = inherited_expectation or (
        f"adforge-cli-{uuid.uuid4().hex}",
        DEFAULT_LAUNCH_ACTION,
    )
    if expected_action != DEFAULT_LAUNCH_ACTION:
        return decision_for_reason(ScopeReason.ACTION_MISMATCH), []
    args._launch_job_id = job_id
    args._launch_action = expected_action
    decision = decide_action(
        target=args.dc,
        allowed_scope=args.scope,
        excluded_scope=args.exclude,
        confirmation=None,
        job_id=job_id,
        engine=ENGINE_NAME,
        action=expected_action,
        require_confirmation=False,
    )
    if not decision.allowed or args.dry_run:
        return decision, []

    confirmation = _confirmation_for_target(inherited, args.dc)
    if confirmation is None and inherited:
        return decision_for_reason(ScopeReason.MISSING_CONFIRMATION), []
    if confirmation is None:
        if not (args.auto_confirm or args.autopilot):
            try:
                require_authorization(args.dc, "ADForge")
            except SystemExit:
                _audit_scope_denial(
                    args,
                    decision_for_reason(ScopeReason.MISSING_CONFIRMATION),
                    target=args.dc,
                )
                raise
        confirmation = ActionConfirmation.create(
            job_id=job_id,
            target=args.dc,
            engine=ENGINE_NAME,
            action=expected_action,
        )
    decision = decide_action(
        target=args.dc,
        allowed_scope=args.scope,
        excluded_scope=args.exclude,
        confirmation=confirmation,
        job_id=job_id,
        engine=ENGINE_NAME,
        action=expected_action,
    )
    return decision, [confirmation] if decision.allowed else []


def _prepare_engine_authorization(
    args: argparse.Namespace,
    confirmations: list[ActionConfirmation],
) -> tuple[ScopeDecision, ActionAuthorizationEnvelope | None]:
    inherited = load_authorization_envelopes()
    if os.environ.get(AUTHORIZATION_ENVELOPES_ENV) and not inherited:
        denied = decision_for_reason(ScopeReason.INVALID_CONFIRMATION)
        _audit_scope_denial(args, denied, target=args.dc)
        return denied, None
    job_id = str(getattr(args, "_launch_job_id", ""))
    module_binding = module_set_binding(_requested_modules(args))
    if inherited:
        selected = select_authorization_envelope(
            inherited,
            job_id=job_id,
            engine=ENGINE_NAME,
            action_kind="engine.execute",
            requested_target=args.dc,
            resolved_target=args.dc,
            module_id=module_binding,
        )
        if selected is None:
            denied = decision_for_reason(ScopeReason.INVALID_CONFIRMATION)
            _audit_scope_denial(args, denied, target=args.dc)
            return denied, None
        return decision_for_reason(ScopeReason.ALLOWED), selected

    confirmation = _confirmation_for_target(confirmations, args.dc)
    if confirmation is None:
        return decision_for_reason(ScopeReason.MISSING_CONFIRMATION), None
    operator_id = getpass.getuser().strip() or "operator"
    credential_reference = _credential_reference(args)
    base_context = AuthorizationContext(
        tenant_id=os.environ.get("FORGE_TENANT_ID", "default").strip() or "default",
        engagement_id=str(args.engagement or "default"),
        run_id=f"run-{uuid.uuid4().hex}",
        job_id=job_id,
        operator_id=operator_id,
        operator_role=OperatorRole.OPERATOR,
        action_kind=str(getattr(args, "_launch_action", DEFAULT_LAUNCH_ACTION)),
        engine=ENGINE_NAME,
        module_id=module_binding,
        requested_target=args.dc,
        resolved_target=args.dc,
        allowed_scope=args.scope,
        excluded_scope=args.exclude,
        safety_mode=SafetyMode.ACTIVE,
        credential_approval_required=bool(credential_reference),
        credential_reference=credential_reference,
        confirmation_method=(
            ConfirmationMethod.CLI_FLAG
            if args.auto_confirm or args.autopilot
            else ConfirmationMethod.CLI_PROMPT
        ),
        confirmed_by=operator_id,
    )
    session = open_authorization_session()
    try:
        issued = issue_authorization(
            session=session,
            context=base_context,
            confirmation=confirmation,
        )
        if not issued.allowed:
            return decision_for_reason(ScopeReason.INVALID_CONFIRMATION), None
        consumed = consume_authorization(
            session=session,
            envelope=issued.envelope,
            expected=base_context,
            boundary="adforge.cli",
        )
        if not consumed.allowed:
            return decision_for_reason(ScopeReason.INVALID_CONFIRMATION), None
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
            parent_boundary="adforge.cli",
        )
        if not derived.allowed:
            return decision_for_reason(ScopeReason.INVALID_CONFIRMATION), None
        args._authorization_runtime = load_authorization_runtime_facts(
            authorization_runtime_environment(derived.envelope)
        )
        return decision_for_reason(ScopeReason.ALLOWED), derived.envelope
    finally:
        session.close()


def _apply_launch_context(
    cfg: BaseForgeConfig,
    args: argparse.Namespace,
    confirmations: list[ActionConfirmation],
    authorization: ActionAuthorizationEnvelope | None,
) -> None:
    cfg.extra["allowed_scope"] = list(args.scope or [])
    cfg.extra["excluded_scope"] = list(args.exclude or [])
    requested_modules = _requested_modules(args)
    cfg.extra["authorized_requested_modules"] = requested_modules
    cfg.extra["authorization_module_binding"] = module_set_binding(requested_modules)
    runtime = getattr(args, "_authorization_runtime", None)
    if not isinstance(runtime, Mapping):
        runtime = load_authorization_runtime_facts()
    cfg.extra["authorization_runtime"] = dict(runtime)
    cfg.extra["runtime_credential_reference"] = _credential_reference(args)
    confirmation = _confirmation_for_target(confirmations, args.dc)
    if confirmation is not None:
        cfg.extra["job_id"] = getattr(args, "_launch_job_id", "")
        cfg.extra["launch_action"] = getattr(args, "_launch_action", "")
        cfg.extra["launch_confirmation"] = confirmation
    if authorization is not None:
        cfg.extra["authorization_envelope"] = authorization


def _launch_decision(cfg: BaseForgeConfig, args: argparse.Namespace) -> ScopeDecision:
    action = str(cfg.extra.get("launch_action") or DEFAULT_LAUNCH_ACTION)
    if action != DEFAULT_LAUNCH_ACTION:
        return decision_for_reason(ScopeReason.ACTION_MISMATCH)
    return decide_action(
        target=cfg.target,
        allowed_scope=cfg.extra.get("allowed_scope", getattr(args, "scope", None)),
        excluded_scope=cfg.extra.get("excluded_scope", getattr(args, "exclude", None)),
        confirmation=cfg.extra.get("launch_confirmation"),
        job_id=str(cfg.extra.get("job_id") or ""),
        engine=ENGINE_NAME,
        action=action,
        require_confirmation=not bool(args.dry_run),
    )


def _consume_engine_authorization(cfg: BaseForgeConfig) -> AuthorizationDecision:
    envelope = cfg.extra.get("authorization_envelope")
    if isinstance(envelope, dict):
        try:
            envelope = ActionAuthorizationEnvelope.from_value(envelope)
        except (TypeError, ValueError):
            pass
    if isinstance(envelope, ActionAuthorizationEnvelope):
        expected = _authorization_context_from_envelope(
            envelope,
            cfg,
            action_kind="engine.execute",
            module_id=str(cfg.extra.get("authorization_module_binding", "")),
        )
    else:
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
                boundary="adforge.engine",
            )
        decision = consume_authorization(
            session=session,
            envelope=envelope,
            expected=expected,
            boundary="adforge.engine",
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
            parent_boundary="adforge.engine",
        )
        if not derived.allowed:
            return derived
        consumed = consume_authorization(
            session=session,
            envelope=derived.envelope,
            expected=context,
            boundary="adforge.module",
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


def setup_results(engagement: str, domain: str, resume: str | None) -> Path:
    if resume:
        return Path(resume)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    path = Path(__file__).parent / "results" / f"{engagement}_{domain}_{ts}"
    for subdir in ["hashes", "bloodhound", "loot"]:
        (path / subdir).mkdir(parents=True, exist_ok=True)
    return path


def load_module(name: str):
    mod_path = MODULE_MAP.get(name)
    cls_name = CLASS_NAME_MAP.get(name)
    if not mod_path or not cls_name:
        return None
    try:
        mod = importlib.import_module(mod_path)
        return getattr(mod, cls_name, None)
    except ImportError:
        return None


class _ADForgeResourceLifecycle:
    """Own scan resources and release them without masking primary failures."""

    def __init__(self) -> None:
        self.db_session: Any = None
        self._cleaned = False

    def cleanup(self) -> None:
        if self._cleaned:
            return
        self._cleaned = True
        if self.db_session is not None:
            try:
                self.db_session.close()
            except BaseException as exc:
                log.debug("Database cleanup error: %s", type(exc).__name__)


async def run_scan(
    cfg: BaseForgeConfig,
    args: argparse.Namespace,
    results_dir: Path,
    event_bus: Any = None,
    scan_control: ScanControl | None = None,
) -> dict[str, Any]:
    """Run one scan with deterministic exceptional-path resource cleanup."""
    lifecycle = _ADForgeResourceLifecycle()
    try:
        return await _run_scan_impl(
            cfg,
            args,
            results_dir,
            event_bus,
            scan_control,
            lifecycle,
        )
    finally:
        lifecycle.cleanup()


async def _run_scan_impl(
    cfg: BaseForgeConfig,
    args: argparse.Namespace,
    results_dir: Path,
    event_bus: Any = None,
    scan_control: ScanControl | None = None,
    lifecycle: _ADForgeResourceLifecycle | None = None,
) -> dict[str, Any]:
    """Core scan loop — EventBus wired, pause/resume/abort ready."""
    if _has_direct_secret_args(args, cfg):
        _clear_direct_secret_args(args, cfg)
        return {
            "status": "failed",
            "findings": 0,
            "errors": ["credential_reference_required"],
            "duration": 0.0,
        }
    launch_decision = _launch_decision(cfg, args)
    if not launch_decision.allowed:
        _audit_scope_denial(args, launch_decision, target=cfg.target)
        _print_launch_denial(launch_decision)
        return _denied_summary(launch_decision, dry_run=bool(args.dry_run))
    if args.dry_run:
        return {
            "status": "completed",
            "findings": 0,
            "errors": [],
            "duration": 0.0,
            "dry_run": True,
            "authorized": False,
            "plan": {
                "target": cfg.target,
                "engine": ENGINE_NAME,
                "authorized": False,
            },
        }

    authorization_decision = _consume_engine_authorization(cfg)
    if not authorization_decision.allowed:
        log.warning(
            "Engine authorization denied reason_code=%s",
            authorization_decision.reason_code,
        )
        return _authorization_denied_summary(authorization_decision)
    engine_authorization = authorization_decision.envelope

    bus, Event, EventType = _get_event_bus(event_bus)
    ctrl = scan_control or ScanControl()
    cfg.extra["outbound_cancellation_check"] = lambda: ctrl.is_aborted
    eng_bus = _get_eng_bus()

    target_str = f"{args.domain} (DC: {args.dc})"

    db_session  = create_db(results_dir / "adforge.db")
    if lifecycle is not None:
        lifecycle.db_session = db_session
    scope       = Scope(
        cfg.extra.get("allowed_scope", args.scope),
        excluded=cfg.extra.get("excluded_scope", args.exclude),
    )
    run_id      = engine_authorization.run_id
    all_findings = []
    errors: list[str] = []
    aborted = False

    scan_run = ScanRunModel(
        id=run_id, framework="adforge",
        target=target_str, mode=args.mode,
        engagement=cfg.engagement, tester=cfg.tester,
    )
    db_session.add(scan_run)
    db_session.commit()

    include = [m.strip() for m in args.modules.split(",")] if args.modules else None
    skip    = [m.strip() for m in args.skip_modules.split(",")] if args.skip_modules else None

    # Collect all modules for SCAN_START
    all_module_names = []
    for _, _, phase_mods, req_modes in PHASES:
        if args.mode in req_modes:
            all_module_names.extend(phase_mods)

    # ── Emit: scan_start ──────────────────────────────────────────────
    _emit(bus, Event, EventType, "scan_start", source="adforge",
          target=target_str, mode=args.mode, engagement=cfg.engagement,
          tester=cfg.tester, framework="ADForge", modules=all_module_names)

    console.print(f"\n[bold cyan]ADForge v{VERSION}[/bold cyan]")
    console.print(f"DC: [cyan]{args.dc}[/cyan] | Domain: [cyan]{args.domain}[/cyan]")
    console.print(f"Mode: [yellow]{args.mode}[/yellow]")
    if args.dry_run:
        console.print("[bold yellow]DRY RUN — no connections made[/bold yellow]")

    start_time = time.monotonic()

    for phase_num, phase_name, phase_mods, required_modes in PHASES:
        # ── Abort check ───────────────────────────────────────────────
        if ctrl.is_aborted:
            aborted = True
            break

        # ── Pause gate ────────────────────────────────────────────────
        if ctrl.is_paused:
            _emit(bus, Event, EventType, "scan_paused", source="adforge")
            await ctrl.wait_if_paused()
            if ctrl.is_aborted:
                aborted = True
                break
            _emit(bus, Event, EventType, "scan_resumed", source="adforge")

        if args.mode not in required_modes:
            continue

        filtered = [m for m in phase_mods
                    if (not include or m in include) and (not skip or m not in skip)]
        if not filtered:
            continue

        # Special flag checks
        if "dcsync" in filtered and not args.dcsync:
            filtered.remove("dcsync")
        if "bloodhound_export" in filtered and not args.bloodhound:
            filtered = [m for m in filtered if m != "bloodhound_export"]

        phase_banner(phase_num, 14, phase_name)

        # ── Emit: phase_start ─────────────────────────────────────────
        _emit(bus, Event, EventType, "phase_start", source="adforge",
              number=phase_num, name=phase_name, modules=filtered)

        phase_start = time.monotonic()

        for module_name in filtered:
            # ── Abort / pause mid-phase ───────────────────────────────
            if ctrl.is_aborted:
                aborted = True
                break
            if ctrl.is_paused:
                _emit(bus, Event, EventType, "scan_paused", source="adforge")
                await ctrl.wait_if_paused()
                if ctrl.is_aborted:
                    aborted = True
                    break
                _emit(bus, Event, EventType, "scan_resumed", source="adforge")

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
                    continue

            cls = load_module(module_name)
            if cls is None:
                log.debug("Module not yet built: %s", module_name)
                _emit(bus, Event, EventType, "module_skip", source=module_name,
                      name=module_name, reason="not built")
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
                continue

            # ── Emit: module_start ────────────────────────────────────
            _emit(bus, Event, EventType, "module_start", source=module_name,
                  name=module_name, phase=phase_num)

            try:
                module_config = cfg.model_copy(deep=False)
                module_config.extra = dict(cfg.extra)
                mod = cls(config=module_config, scope=scope, db_session=db_session,
                          results_dir=results_dir, run_id=run_id)
                result = await mod.run()
                if ctrl.is_aborted:
                    aborted = True
                    _emit(
                        bus, Event, EventType, "module_skip",
                        source=module_name, name=module_name,
                        reason="cancelled", outcome="canceled",
                    )
                    break
                module_policy = getattr(mod, "outbound_policy", None)
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
                if getattr(result, "skipped", False):
                    reason = str(
                        redact_authorization_value(
                            str(getattr(result, "skip_reason", "") or "not_tested")
                        )
                    )
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
                    continue
                merge_module_output_extra(cfg.extra, module_config.extra)
                all_findings.extend(result.findings)

                # ── Emit: module_complete + findings ──────────────────
                _emit(bus, Event, EventType, "module_complete", source=module_name,
                      name=module_name, findings_count=len(result.findings))

                for finding in result.findings:
                    fd = finding.to_dict()
                    _emit(bus, Event, EventType, "finding_new", source=module_name,
                          **fd)
                    if eng_bus:
                        eng_bus.publish(finding)

            except Exception as exc:
                if ctrl.is_aborted or getattr(exc, "reason_code", "") == "cancelled":
                    aborted = True
                    _emit(
                        bus, Event, EventType, "module_skip",
                        source=module_name, name=module_name,
                        reason="cancelled", outcome="canceled",
                    )
                    break
                safe_error = str(redact_authorization_value(str(exc)))
                log.error("Module %s failed: %s", module_name, safe_error)
                errors.append(f"{module_name}: {safe_error}")
                _emit(bus, Event, EventType, "module_fail", source=module_name,
                      name=module_name, error=safe_error)

        # ── Emit: phase_complete ──────────────────────────────────────
        phase_duration = time.monotonic() - phase_start
        _emit(bus, Event, EventType, "phase_complete", source="adforge",
              number=phase_num, name=phase_name, duration=round(phase_duration, 1))

    elapsed = time.monotonic() - start_time
    status = "aborted" if aborted else ("failed" if errors else "completed")

    scan_run.ended_at = datetime.now(timezone.utc)
    scan_run.status = status
    db_session.commit()

    if aborted:
        _emit(bus, Event, EventType, "scan_aborted", source="adforge",
              reason="operator", target=target_str,
              findings=len(all_findings), duration=round(elapsed, 1))
    elif errors:
        _emit(bus, Event, EventType, "scan_interrupted", source="adforge",
              target=target_str, findings=len(all_findings),
              duration=round(elapsed, 1), errors=errors)
    else:
        _emit(bus, Event, EventType, "scan_complete", source="adforge",
              target=target_str, findings=len(all_findings),
              duration=round(elapsed, 1))

    formats = [f.strip() for f in args.report_format.split(",")]
    reporter = BaseReporter(
        findings=[f.to_dict() for f in all_findings],
        results_dir=results_dir,
        engagement=cfg.engagement,
        target=target_str,
        tester=cfg.tester,
        framework="ADForge",
        formats=formats,
    )
    reporter.generate_all()

    label = "SCAN ABORTED" if aborted else ("SCAN FAILED" if errors else "SCAN COMPLETE")
    color = "yellow" if aborted else ("red" if errors else "green")
    console.print(f"\n[bold {color}]═══ {label} ═══[/bold {color}]")
    console.print(f"  Duration: {elapsed:.1f}s | Findings: {len(all_findings)}")
    console.print(f"  Results:  {results_dir}")
    console.print(f"  Hashes:   {results_dir}/hashes/")
    if args.bloodhound:
        console.print(f"  BloodHound: {results_dir}/bloodhound/")

    return {
        "status": status,
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
    """Entry point for TargetManager multi-target orchestration."""
    import copy
    args = copy.deepcopy(base_args)
    if _has_direct_secret_args(args):
        if not args.dry_run:
            _clear_direct_secret_args(args)
            return {
                "status": "failed",
                "findings": 0,
                "errors": ["credential_reference_required"],
                "duration": 0.0,
            }
        _clear_direct_secret_args(args)

    # ADForge target is dc+domain, extract from target_entry
    target = target_entry.target
    if hasattr(args, "dc"):
        args.dc = target
    args.target = target

    for key in ("spray_delay", "spray_max_rounds"):
        if key in target_entry.options and hasattr(args, key):
            setattr(args, key, target_entry.options[key])

    confirmations = list(
        getattr(args, "_launch_confirmations", None) or load_launch_confirmations()
    )
    confirmation = _confirmation_for_target(confirmations, args.dc)
    preflight = decide_action(
        target=args.dc,
        allowed_scope=args.scope,
        excluded_scope=args.exclude,
        confirmation=confirmation,
        job_id=str(getattr(args, "_launch_job_id", "")),
        engine=ENGINE_NAME,
        action=str(getattr(args, "_launch_action", DEFAULT_LAUNCH_ACTION)),
        require_confirmation=not bool(args.dry_run),
    )
    if not preflight.allowed:
        _audit_scope_denial(args, preflight, target=args.dc)
        _print_launch_denial(preflight)
        return _denied_summary(preflight, dry_run=bool(args.dry_run))

    cfg = load_config(Path(__file__).parent / "adforge.yaml")
    cfg.target     = args.dc
    cfg.engagement = args.engagement
    cfg.tester     = args.tester
    cfg.mode       = args.mode
    cfg.dry_run    = args.dry_run
    cfg.brute_force.spray_delay_seconds = args.spray_delay
    cfg.brute_force.spray_max_rounds    = args.spray_max_rounds
    cfg.extra.update({
        "dc":         args.dc,
        "domain":     args.domain,
        "username":   args.username,
        "password":   args.password,
        "hash":       args.hash,
        "ticket":     args.ticket,
        "dcsync":     args.dcsync,
        "bloodhound": args.bloodhound,
    })
    authorization = getattr(args, "_authorization_envelope", None)
    if authorization is None and not args.dry_run:
        authorization = select_authorization_envelope(
            load_authorization_envelopes(),
            job_id=str(getattr(args, "_launch_job_id", "")),
            engine=ENGINE_NAME,
            action_kind="engine.execute",
            requested_target=args.dc,
            resolved_target=args.dc,
            module_id=module_set_binding(_requested_modules(args)),
        )
    _apply_launch_context(cfg, args, confirmations, authorization)

    if not args.dry_run:
        authorization_decision = _consume_engine_authorization(cfg)
        if not authorization_decision.allowed:
            return _authorization_denied_summary(authorization_decision)

    results_dir = setup_results(args.engagement, args.domain, args.resume)
    cfg.extra["results_dir"] = str(results_dir)

    return await run_scan(cfg, args, results_dir, event_bus, scan_control)


def _summary_exit_code(summary: Mapping[str, Any] | None) -> int:
    return 0 if summary and summary.get("status") == "completed" else 1


async def main() -> int:
    args = parse_args()
    if _has_direct_secret_args(args):
        if not args.dry_run:
            _clear_direct_secret_args(args)
            log.error("Direct secret-bearing AD credential options are disabled")
            return 1
        _clear_direct_secret_args(args)
    launch_decision, confirmations = _prepare_cli_confirmation(args)
    if not launch_decision.allowed:
        _audit_scope_denial(args, launch_decision, target=args.dc)
        _print_launch_denial(launch_decision)
        sys.exit(1)
    args._launch_confirmations = confirmations
    if args.dry_run:
        authorization = None
    else:
        auth_decision, authorization = _prepare_engine_authorization(
            args,
            confirmations,
        )
        if not auth_decision.allowed or authorization is None:
            _print_launch_denial(auth_decision)
            sys.exit(1)
    args._authorization_envelope = authorization
    set_auto_confirm(args.auto_confirm or args.autopilot)

    cfg = load_config(Path(__file__).parent / "adforge.yaml")
    cfg.target     = args.dc
    cfg.engagement = args.engagement
    cfg.tester     = args.tester
    cfg.mode       = args.mode
    cfg.dry_run    = args.dry_run
    cfg.brute_force.spray_delay_seconds = args.spray_delay
    cfg.brute_force.spray_max_rounds    = args.spray_max_rounds
    cfg.extra.update({
        "dc":         args.dc,
        "domain":     args.domain,
        "username":   args.username,
        "password":   args.password,
        "hash":       args.hash,
        "ticket":     args.ticket,
        "dcsync":     args.dcsync,
        "bloodhound": args.bloodhound,
    })
    _apply_launch_context(cfg, args, confirmations, authorization)

    if not args.dry_run:
        authorization_decision = _consume_engine_authorization(cfg)
        if not authorization_decision.allowed:
            log.warning(
                "Engine authorization denied reason_code=%s",
                authorization_decision.reason_code,
            )
            sys.exit(1)

    results_dir = setup_results(args.engagement, args.domain, args.resume)
    cfg.extra["results_dir"] = str(results_dir)

    if args.dry_run:
        return _summary_exit_code(await run_scan(cfg, args, results_dir))

    # Wire EventBus — remote when dashboard URL given, local otherwise
    event_bus = None
    if args.dashboard_url:
        try:
            from common.dashboard.event_bus import RemoteEventBus
            event_bus = RemoteEventBus(args.dashboard_url, run_id="adforge")
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
            event_bus = EventBus(run_id="adforge")
            event_bus.start()
        except ImportError:
            pass

    try:
        summary = await run_scan(cfg, args, results_dir, event_bus=event_bus)
        return _summary_exit_code(summary)
    finally:
        if event_bus and hasattr(event_bus, "stop"):
            try:
                event_bus.stop()
            except BaseException as exc:
                log.debug("EventBus cleanup error: %s", type(exc).__name__)


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
