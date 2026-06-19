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
import importlib
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent))

from common.auth_prompt import require_authorization
from common.config import BaseForgeConfig, load_config
from common.confirm_gate import set_auto_confirm
from common.db import create_db, ScanRunModel, Session as DbSession
from common.logger import get_logger, phase_banner, console
from common.reporter import BaseReporter
from common.scope import Scope

log = get_logger("adforge")
VERSION = "5.0.0"

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
        bus.emit(Event(event_type=EventType(etype), data=data, source=source))
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
    p = argparse.ArgumentParser(description="ADForge — Active Directory Penetration Testing Framework")
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


async def run_scan(
    cfg: BaseForgeConfig,
    args: argparse.Namespace,
    results_dir: Path,
    event_bus: Any = None,
    scan_control: ScanControl | None = None,
) -> dict[str, Any]:
    """Core scan loop — EventBus wired, pause/resume/abort ready."""
    bus, Event, EventType = _get_event_bus(event_bus)
    ctrl = scan_control or ScanControl()
    eng_bus = _get_eng_bus()

    target_str = f"{args.domain} (DC: {args.dc})"

    db_session  = create_db(results_dir / "adforge.db")
    scope       = Scope([args.dc, args.domain])
    run_id      = str(uuid.uuid4())
    all_findings = []
    errors: list[str] = []

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
            _emit(bus, Event, EventType, "scan_aborted", source="adforge",
                  reason="operator", target=target_str)
            break

        # ── Pause gate ────────────────────────────────────────────────
        if ctrl.is_paused:
            _emit(bus, Event, EventType, "scan_paused", source="adforge")
            await ctrl.wait_if_paused()
            if ctrl.is_aborted:
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
                break
            if ctrl.is_paused:
                _emit(bus, Event, EventType, "scan_paused", source="adforge")
                await ctrl.wait_if_paused()
                if ctrl.is_aborted:
                    break
                _emit(bus, Event, EventType, "scan_resumed", source="adforge")

            cls = load_module(module_name)
            if cls is None:
                log.debug("Module not yet built: %s", module_name)
                _emit(bus, Event, EventType, "module_skip", source=module_name,
                      name=module_name, reason="not built")
                continue

            # ── Emit: module_start ────────────────────────────────────
            _emit(bus, Event, EventType, "module_start", source=module_name,
                  name=module_name, phase=phase_num)

            try:
                mod = cls(config=cfg, scope=scope, db_session=db_session,
                          results_dir=results_dir, run_id=run_id)
                if args.dry_run:
                    log.info("[DRY RUN] Would run: %s", module_name)
                    _emit(bus, Event, EventType, "module_skip", source=module_name,
                          name=module_name, reason="dry run")
                    continue

                result = await mod.run()
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
                log.error("Module %s failed: %s", module_name, exc)
                errors.append(f"{module_name}: {exc}")
                _emit(bus, Event, EventType, "module_fail", source=module_name,
                      name=module_name, error=str(exc))

        # ── Emit: phase_complete ──────────────────────────────────────
        phase_duration = time.monotonic() - phase_start
        _emit(bus, Event, EventType, "phase_complete", source="adforge",
              number=phase_num, name=phase_name, duration=round(phase_duration, 1))

    elapsed = time.monotonic() - start_time

    scan_run.ended_at = datetime.now(timezone.utc)
    scan_run.status = "completed"
    db_session.commit()

    # ── Emit: scan_complete ───────────────────────────────────────────
    _emit(bus, Event, EventType, "scan_complete", source="adforge",
          target=target_str, findings=len(all_findings), duration=round(elapsed, 1))

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

    console.print(f"\n[bold green]═══ SCAN COMPLETE ═══[/bold green]")
    console.print(f"  Duration: {elapsed:.1f}s | Findings: {len(all_findings)}")
    console.print(f"  Results:  {results_dir}")
    console.print(f"  Hashes:   {results_dir}/hashes/")
    if args.bloodhound:
        console.print(f"  BloodHound: {results_dir}/bloodhound/")
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
    """Entry point for TargetManager multi-target orchestration."""
    import copy
    args = copy.deepcopy(base_args)

    # ADForge target is dc+domain, extract from target_entry
    target = target_entry.target
    if hasattr(args, "dc"):
        args.dc = target
    args.target = target

    for key, val in target_entry.options.items():
        if hasattr(args, key):
            setattr(args, key, val)

    results_dir = setup_results(args.engagement, args.domain, args.resume)
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
        "results_dir": str(results_dir),
    })

    return await run_scan(cfg, args, results_dir, event_bus, scan_control)


async def main() -> None:
    args = parse_args()
    target_str = f"{args.domain} (DC: {args.dc})"
    require_authorization(target_str, "ADForge")
    set_auto_confirm(args.auto_confirm or args.autopilot)

    results_dir = setup_results(args.engagement, args.domain, args.resume)
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
        "results_dir": str(results_dir),
    })

    # Wire EventBus — remote when dashboard URL given, local otherwise
    event_bus = None
    if args.dashboard_url:
        try:
            from common.dashboard.event_bus import RemoteEventBus
            event_bus = RemoteEventBus(args.dashboard_url, run_id="adforge")
            event_bus.start()
            log.info("Dashboard relay: %s", args.dashboard_url)
        except Exception as exc:
            log.warning("RemoteEventBus init failed: %s — events won't reach dashboard", exc)
    else:
        try:
            from common.dashboard.event_bus import EventBus
            event_bus = EventBus(run_id="adforge")
            event_bus.start()
        except ImportError:
            pass

    await run_scan(cfg, args, results_dir, event_bus=event_bus)

    if event_bus and hasattr(event_bus, "stop"):
        event_bus.stop()


if __name__ == "__main__":
    asyncio.run(main())
