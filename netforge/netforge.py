#!/usr/bin/env python3
"""
NetForge — Network Penetration & Red Team Framework
====================================================
Master entry point. Runs ALL modules in PHASE ORDER (phases 1-9).
v5 APEX: EventBus integration, multi-target, pause/resume/abort.

FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY.

Usage:
  python netforge.py --target 10.0.0.0/24 --mode internal
  python netforge.py --target 203.0.113.0/24 --mode external --engagement "Client_Ext"
  python netforge.py --target 10.0.0.0/24 --mode internal --capture --bf-delay 5
  python netforge.py --target 10.0.0.0/24 --dry-run
  python netforge.py --target 10.0.0.0/24 --opsec stealth --mode internal
  python netforge.py --target 10.0.0.0/24 --red-team --opsec stealth
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
from common.db import create_db, ScanRunModel
from common.logger import get_logger, phase_banner, console
from common.netcheck import ask_internet_permission
from common.reporter import BaseReporter
from common.scope import Scope

from netforge.core.opsec import get_opsec, OpSecProfile
from netforge.core.stealth_log import install_stealth_logging, dump_stealth_log
from netforge.core.session import close_session
from netforge.core.cred_engine import CredEngine
from netforge.core.attack_chain import AttackChain

log = get_logger("netforge")
VERSION = "4.0.0"

PHASES: list[tuple[int, str, list[str]]] = [
    (1, "Host Discovery",    ["host_discover","port_scanner","os_detect","service_id","topology_map"]),
    (2, "External Recon",    ["dns_recon","ssl_audit","smtp_check","firewall_detect","exposure_check","firewall_rule_check"]),
    (3, "Internal Analysis", ["arp_monitor","dhcp_audit","vlan_check","cdp_ldp","ipv6_audit","llmnr_detect"]),
    (4, "Service Auditing",  ["smb_audit","ftp_audit","ssh_audit","telnet_audit","rdp_audit","snmp_audit",
                               "nfs_audit","mssql_audit","mysql_audit","redis_audit","mongo_audit",
                               "elastic_audit","vnc_audit","tftp_audit","printer_audit","voip_audit",
                               "ipmi_audit","kubernetes_audit","docker_audit","cloud_metadata","ics_audit","upnp_audit"]),
    (5, "Vuln Matching",     ["cve_matcher","nmap_vulns","nuclei_runner","exploit_suggest"]),
    (6, "Brute Force",       ["native_brute","smart_brute","cred_spray","hydra_wrap"]),
    (7, "Exploitation",      ["heartbleed","redis_rce","ntlm_relay","eternalblue","bluekeep","zerologon"]),
    (8, "Post-Exploitation", ["pivot_finder","loot_parse","tunnel_suggest"]),
    (9, "Reporting",         ["html_report","pdf_report","json_export","csv_export","network_diagram"]),
]

MODULE_MAP: dict[str, str] = {
    "host_discover":    "netforge.modules.discovery.host_discover",
    "port_scanner":     "netforge.modules.discovery.port_scanner",
    "os_detect":        "netforge.modules.discovery.os_detect",
    "service_id":       "netforge.modules.discovery.service_id",
    "topology_map":     "netforge.modules.discovery.topology_map",
    "dns_recon":        "netforge.modules.external.dns_recon",
    "ssl_audit":        "netforge.modules.external.ssl_audit",
    "smtp_check":       "netforge.modules.external.smtp_check",
    "firewall_detect":  "netforge.modules.external.firewall_detect",
    "exposure_check":   "netforge.modules.external.exposure_check",
    "firewall_rule_check": "netforge.modules.external.firewall_rule_check",
    "arp_monitor":      "netforge.modules.internal.arp_monitor",
    "dhcp_audit":       "netforge.modules.internal.dhcp_audit",
    "vlan_check":       "netforge.modules.internal.vlan_check",
    "cdp_ldp":          "netforge.modules.internal.cdp_ldp",
    "ipv6_audit":       "netforge.modules.internal.ipv6_audit",
    "llmnr_detect":     "netforge.modules.internal.llmnr_detect",
    "smb_audit":        "netforge.modules.services.smb_audit",
    "ftp_audit":        "netforge.modules.services.ftp_audit",
    "ssh_audit":        "netforge.modules.services.ssh_audit",
    "telnet_audit":     "netforge.modules.services.telnet_audit",
    "rdp_audit":        "netforge.modules.services.rdp_audit",
    "snmp_audit":       "netforge.modules.services.snmp_audit",
    "nfs_audit":        "netforge.modules.services.nfs_audit",
    "mssql_audit":      "netforge.modules.services.mssql_audit",
    "mysql_audit":      "netforge.modules.services.mysql_audit",
    "redis_audit":      "netforge.modules.services.redis_audit",
    "mongo_audit":      "netforge.modules.services.mongo_audit",
    "elastic_audit":    "netforge.modules.services.elastic_audit",
    "vnc_audit":        "netforge.modules.services.vnc_audit",
    "tftp_audit":       "netforge.modules.services.tftp_audit",
    "printer_audit":    "netforge.modules.services.printer_audit",
    "voip_audit":       "netforge.modules.services.voip_audit",
    "ipmi_audit":       "netforge.modules.services.ipmi_audit",
    "kubernetes_audit": "netforge.modules.services.kubernetes_audit",
    "docker_audit":     "netforge.modules.services.docker_audit",
    "cloud_metadata":   "netforge.modules.services.cloud_metadata",
    "ics_audit":        "netforge.modules.services.ics_audit",
    "upnp_audit":       "netforge.modules.services.upnp_audit",
    "cve_matcher":      "netforge.modules.vuln.cve_matcher",
    "nmap_vulns":       "netforge.modules.vuln.nmap_vulns",
    "nuclei_runner":    "netforge.modules.vuln.nuclei_runner",
    "exploit_suggest":  "netforge.modules.vuln.exploit_suggest",
    "native_brute":     "netforge.modules.bruteforce.native_brute",
    "smart_brute":      "netforge.modules.bruteforce.smart_brute",
    "hydra_wrap":       "netforge.modules.bruteforce.hydra_wrap",
    "cred_spray":       "netforge.modules.bruteforce.cred_spray",
    # ── Exploitation (Red Team only) ──────────────────────────────
    "heartbleed":       "netforge.modules.exploit.heartbleed",
    "redis_rce":        "netforge.modules.exploit.redis_rce",
    "ntlm_relay":       "netforge.modules.exploit.ntlm_relay",
    "eternalblue":      "netforge.modules.exploit.eternalblue",
    "bluekeep":         "netforge.modules.exploit.bluekeep",
    "zerologon":        "netforge.modules.exploit.zerologon",
    # ── Post-Exploitation ─────────────────────────────────────────
    "pivot_finder":     "netforge.modules.post_exploit.pivot_finder",
    "loot_parse":       "netforge.modules.post_exploit.loot_parse",
    "tunnel_suggest":   "netforge.modules.post_exploit.tunnel_suggest",
    "html_report":      "netforge.modules.reporting.html_report",
    "pdf_report":       "netforge.modules.reporting.pdf_report",
    "json_export":      "netforge.modules.reporting.json_export",
    "csv_export":       "netforge.modules.reporting.csv_export",
    "network_diagram":  "netforge.modules.reporting.network_diagram",
}

CLASS_NAME_MAP: dict[str, str] = {k: "".join(p.capitalize() for p in k.split("_")) for k in MODULE_MAP}
CLASS_NAME_MAP.update({"llmnr_detect": "LlmnrDetect", "cdp_ldp": "CdpLdp",
                        "ics_audit": "IcsAudit", "upnp_audit": "UpnpAudit",
                        "ipmi_audit": "IpmiAudit",
                        "redis_rce": "RedisRce", "ntlm_relay": "NtlmRelay",
                        "native_brute": "NativeBrute"})

# Exploitation modules — ONLY loaded when --red-team is active
RED_TEAM_MODULES = {"heartbleed", "redis_rce", "ntlm_relay", "eternalblue", "bluekeep", "zerologon"}


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


def _emit(bus: Any, Event: Any, EventType: Any, etype: str, source: str = "netforge", **data: Any) -> None:
    """Fire-and-forget event emission — never crashes the scan."""
    if bus is None:
        return
    try:
        bus.emit(Event(event_type=EventType(etype), data=data, source=source))
    except Exception:
        pass


# ── Pause / Resume / Abort control ───────────────────────────────────

class ScanControl:
    """Async-safe scan control flags shared across the orchestrator.

    Attributes:
        paused:  asyncio.Event — cleared = paused, set = running.
        aborted: bool flag checked in the scan loop.
    """

    def __init__(self) -> None:
        self._paused = asyncio.Event()
        self._paused.set()            # starts in running state
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
        self._paused.set()            # unblock if paused so loop can exit
        log.info("Scan ABORTED by operator")

    async def wait_if_paused(self) -> None:
        """Block until un-paused. Returns immediately if not paused."""
        await self._paused.wait()


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="NetForge — Network Penetration Testing Framework")
    p.add_argument("--target",       required=True,                            help="Target IP/CIDR/host")
    p.add_argument("--mode",         default="internal",
                   choices=["external","internal","full"],                      help="Scan mode")
    p.add_argument("--engagement",   default="engagement",                      help="Engagement name")
    p.add_argument("--tester",       default="anonymous",                       help="Tester name")
    p.add_argument("--interface",    default=None,                              help="Network interface (internal mode)")
    p.add_argument("--rate",         type=float, default=10.0,                  help="Rate limit (req/s)")
    p.add_argument("--workers",      type=int,   default=10,                    help="Concurrent workers")
    p.add_argument("--capture",      action="store_true",                        help="Enable passive PCAP capture")
    p.add_argument("--stealth",      action="store_true",                        help="Stealth/slow scan mode (alias for --opsec stealth)")
    p.add_argument("--opsec",        default="normal",
                   choices=["stealth","normal","aggressive"],                   help="OpSec profile: stealth|normal|aggressive")
    p.add_argument("--modules",      default=None,                              help="Comma-separated modules to run")
    p.add_argument("--skip-modules", default=None,                              help="Comma-separated modules to skip")
    p.add_argument("--bf-delay",     type=float, default=3.0,                   help="Brute force delay seconds")
    p.add_argument("--bf-max",       type=int,   default=3,                     help="Max brute force attempts per account")
    p.add_argument("--bf-timeout",   type=int,   default=30,                    help="Brute force timeout seconds")
    p.add_argument("--output",       default=None,                              help="Results output directory")
    p.add_argument("--report-format",default="html,pdf",                        help="Report formats")
    p.add_argument("--dry-run",      action="store_true",                        help="No packets sent")
    p.add_argument("--resume",       default=None,                              help="Resume from results dir")
    p.add_argument("--red-team",     action="store_true",                        help="Enable exploitation modules (Red Team mode)")
    p.add_argument("--attacker-ip",  default=None,                              help="Attacker IP for reverse shells/callbacks")
    p.add_argument("--auto-confirm", action="store_true",                        help="Skip confirmation gates")
    p.add_argument("--verbose",      action="store_true",                        help="Verbose output")
    p.add_argument("--version",      action="version", version=f"NetForge {VERSION}")
    return p.parse_args()


def setup_results(engagement: str, target: str, resume: str | None) -> Path:
    if resume:
        return Path(resume)
    safe_target = target.replace("/","_").replace(":","_")
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    path = Path(__file__).parent / "results" / f"{engagement}_{safe_target}_{ts}"
    path.mkdir(parents=True, exist_ok=True)
    (path / "pcaps").mkdir(exist_ok=True)
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
    """Core scan loop — separated from main() so TargetManager can call it.

    Args:
        cfg:          Fully configured BaseForgeConfig.
        args:         Parsed CLI args (mode, modules, red-team, etc.).
        results_dir:  Where results/reports go.
        event_bus:    Optional EventBus for dashboard events.
        scan_control: Optional ScanControl for pause/resume/abort.

    Returns:
        Summary dict with 'findings', 'errors', 'duration'.
    """
    bus, Event, EventType = _get_event_bus(event_bus)
    ctrl = scan_control or ScanControl()

    # ── OpSec Profile ─────────────────────────────────────────────────
    opsec_level = "stealth" if args.stealth else args.opsec
    opsec = get_opsec(opsec_level)
    cfg.extra["opsec_level"] = opsec.level.value
    cfg.extra["opsec_stats"] = opsec.stats

    if opsec.max_threads < cfg.workers:
        cfg.workers = opsec.max_threads
        log.info("Workers capped to %d by OpSec profile '%s'", cfg.workers, opsec.level.value)

    # ── Stealth Logging ───────────────────────────────────────────────
    stealth_session_key = None
    if opsec.suppress_console:
        console.print(f"[bold yellow]STEALTH MODE — console output suppressed after this line[/bold yellow]")
        console.print(f"[yellow]All logs encrypted → {results_dir / 'stealth.db'}[/yellow]")
        stealth_session_key = install_stealth_logging(results_dir)

    # ── Credential Engine ─────────────────────────────────────────────
    cred_engine = CredEngine()
    cfg.extra["cred_engine"] = cred_engine

    # ── Attack Chain Engine (Red Team) ────────────────────────────────
    attack_chain = AttackChain(cred_engine=cred_engine) if args.red_team else None
    cfg.extra["attack_chain"] = attack_chain

    db_session = create_db(results_dir / "netforge.db")
    scope = Scope([cfg.target])
    run_id = str(uuid.uuid4())

    scan_run = ScanRunModel(
        id=run_id, framework="netforge",
        target=cfg.target, mode=args.mode,
        engagement=cfg.engagement, tester=cfg.tester,
    )
    db_session.add(scan_run)
    db_session.commit()

    include = [m.strip() for m in args.modules.split(",")] if args.modules else None
    skip    = [m.strip() for m in args.skip_modules.split(",")] if args.skip_modules else None

    # Collect all module names for the SCAN_START event
    all_module_names = []
    for _, _, phase_mods in PHASES:
        all_module_names.extend(phase_mods)

    # ── Emit: scan_start ──────────────────────────────────────────────
    _emit(bus, Event, EventType, "scan_start", source="netforge",
          target=cfg.target, mode=args.mode, engagement=cfg.engagement,
          tester=cfg.tester, framework="NetForge", modules=all_module_names)

    console.print(f"\n[bold cyan]NetForge v{VERSION}[/bold cyan] — Target: [cyan]{cfg.target}[/cyan]")
    mode_label = f"{args.mode}"
    if args.red_team:
        mode_label += " [bold red][RED TEAM][/bold red]"
    console.print(f"Mode: [yellow]{mode_label}[/yellow] | OpSec: [yellow]{opsec.level.value}[/yellow]")
    if args.red_team:
        console.print("[bold red]RED TEAM MODE — exploitation modules ACTIVE[/bold red]")
        console.print(f"[red]Attacker IP: {args.attacker_ip or 'NOT SET (use --attacker-ip)'}[/red]")
    if args.dry_run:
        console.print("[bold yellow]DRY RUN — no packets sent[/bold yellow]")

    all_findings = []
    errors = []
    start_time = time.monotonic()

    for phase_num, phase_name, phase_mods in PHASES:
        # ── Abort check ───────────────────────────────────────────────
        if ctrl.is_aborted:
            _emit(bus, Event, EventType, "scan_aborted", source="netforge",
                  reason="operator", target=cfg.target)
            break

        # ── Pause gate ────────────────────────────────────────────────
        if ctrl.is_paused:
            _emit(bus, Event, EventType, "scan_paused", source="netforge")
            await ctrl.wait_if_paused()
            if ctrl.is_aborted:
                break
            _emit(bus, Event, EventType, "scan_resumed", source="netforge")

        # Filter by mode
        if args.mode == "external" and phase_name == "Internal Analysis":
            continue
        if args.mode == "internal" and phase_name == "External Recon":
            continue

        filtered = [m for m in phase_mods
                    if (not include or m in include) and (not skip or m not in skip)]

        # Red Team gate
        if not args.red_team:
            filtered = [m for m in filtered if m not in RED_TEAM_MODULES]

        if not filtered:
            continue

        # OpSec: randomize module order within this phase
        filtered = opsec.shuffle_modules(filtered)

        phase_banner(phase_num, 9, phase_name)

        # ── Emit: phase_start ─────────────────────────────────────────
        _emit(bus, Event, EventType, "phase_start", source="netforge",
              number=phase_num, name=phase_name, modules=filtered)

        phase_start = time.monotonic()

        for module_name in filtered:
            # ── Abort / pause mid-phase ───────────────────────────────
            if ctrl.is_aborted:
                break
            if ctrl.is_paused:
                _emit(bus, Event, EventType, "scan_paused", source="netforge")
                await ctrl.wait_if_paused()
                if ctrl.is_aborted:
                    break
                _emit(bus, Event, EventType, "scan_resumed", source="netforge")

            cls = load_module(module_name)
            if cls is None:
                log.debug("Module not yet built: %s", module_name)
                _emit(bus, Event, EventType, "module_skip", source=module_name,
                      name=module_name, reason="not built")
                continue
            try:
                # OpSec: inject decoy traffic between modules
                await opsec.maybe_inject_decoy()

                mod = cls(config=cfg, scope=scope, db_session=db_session,
                          results_dir=results_dir, run_id=run_id)
                if args.dry_run:
                    log.info("[DRY RUN] Would run: %s", module_name)
                    _emit(bus, Event, EventType, "module_skip", source=module_name,
                          name=module_name, reason="dry run")
                    continue

                # ── Emit: module_start ────────────────────────────────
                _emit(bus, Event, EventType, "module_start", source=module_name,
                      name=module_name, phase=phase_num)

                # OpSec: inter-module jitter
                await opsec.jitter()

                result = await mod.run()
                all_findings.extend(result.findings)

                # ── Emit: module_complete + each finding ──────────────
                _emit(bus, Event, EventType, "module_complete", source=module_name,
                      name=module_name, findings_count=len(result.findings))

                for finding in result.findings:
                    fd = finding.to_dict()
                    _emit(bus, Event, EventType, "finding_new", source=module_name,
                          **fd)

                # Attack chain: feed findings into the chain engine
                if attack_chain:
                    for finding in result.findings:
                        attack_chain.ingest_finding(finding.to_dict())

            except Exception as exc:
                log.error("Module %s failed: %s", module_name, exc)
                errors.append(f"{module_name}: {exc}")
                _emit(bus, Event, EventType, "module_fail", source=module_name,
                      name=module_name, error=str(exc))

        # ── Emit: phase_complete ──────────────────────────────────────
        phase_duration = time.monotonic() - phase_start
        _emit(bus, Event, EventType, "phase_complete", source="netforge",
              number=phase_num, name=phase_name, duration=round(phase_duration, 1))

        # After each phase: check attack chain for recommended actions
        if attack_chain and phase_num in (5, 6, 7):
            actions = attack_chain.recommend_next()
            if actions:
                log.info("[CHAIN] %d recommended actions after phase %d",
                         len(actions), phase_num)
                for a in actions[:5]:
                    log.info("  [%s] %s → %s", a.phase.value, a.module, a.description)

    elapsed = time.monotonic() - start_time

    scan_run.ended_at = datetime.now(timezone.utc)
    scan_run.status = "completed"
    db_session.commit()

    # ── Emit: scan_complete ───────────────────────────────────────────
    _emit(bus, Event, EventType, "scan_complete", source="netforge",
          target=cfg.target, findings=len(all_findings), duration=round(elapsed, 1))

    formats = [f.strip() for f in args.report_format.split(",")]
    reporter = BaseReporter(
        findings=[f.to_dict() for f in all_findings],
        results_dir=results_dir,
        engagement=cfg.engagement,
        target=cfg.target,
        tester=cfg.tester,
        framework="NetForge",
        formats=formats,
    )
    reporter.generate_all()

    # ── Cleanup ───────────────────────────────────────────────────────
    await close_session()

    if len(cred_engine) > 0:
        cred_engine.export_json(results_dir / "credentials_encrypted.json")
        log.info("Exported %d encrypted credentials", len(cred_engine))
        # Emit each cred to the dashboard
        for cred in cred_engine.all():
            _emit(bus, Event, EventType, "credential_found", source="cred_engine",
                  type=cred.get("type", ""), account=cred.get("account", ""),
                  secret=cred.get("secret", ""), target=cred.get("target", ""))
    cred_engine.wipe_all()

    if stealth_session_key:
        log_records = dump_stealth_log(
            results_dir / "stealth.db", stealth_session_key,
            output_path=results_dir / "stealth_log_decrypted.json",
        )
        from common.logger import console as _console
        _console.print(f"\n[bold green]═══ SCAN COMPLETE (STEALTH) ═══[/bold green]")
        _console.print(f"  Duration: {elapsed:.1f}s | Findings: {len(all_findings)}")
        _console.print(f"  OpSec:    {opsec.level.value} | Requests: {opsec.stats['requests']} | Decoys: {opsec.stats['decoys_injected']}")
        _console.print(f"  Results:  {results_dir}")
        _console.print(f"  Stealth log: {len(log_records)} records decrypted")
    else:
        label = "SCAN COMPLETE" if not args.red_team else "RED TEAM ENGAGEMENT COMPLETE"
        color = "green" if not args.red_team else "red"
        console.print(f"\n[bold {color}]═══ {label} ═══[/bold {color}]")
        console.print(f"  Duration: {elapsed:.1f}s | Findings: {len(all_findings)}")
        console.print(f"  OpSec:    {opsec.level.value} | Requests: {opsec.stats['requests']} | Decoys: {opsec.stats['decoys_injected']}")
        if attack_chain:
            console.print(f"  Chain:    {attack_chain.stats['compromised_hosts']} hosts compromised | {attack_chain.stats['valid_creds']} creds")
        console.print(f"  Results:  {results_dir}")

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

    Creates a per-target config + results dir and runs the full scan.

    Args:
        target_entry:  TargetEntry from TargetManager (has .target, .options).
        base_args:     Parsed CLI args as template.
        event_bus:     Optional EventBus.
        scan_control:  Optional ScanControl.

    Returns:
        Summary dict with findings/errors/duration.
    """
    import copy
    args = copy.deepcopy(base_args)
    args.target = target_entry.target

    # Merge per-target inline options
    for key, val in target_entry.options.items():
        if hasattr(args, key):
            setattr(args, key, val)

    results_dir = setup_results(args.engagement, args.target, args.resume)
    cfg = load_config(Path(__file__).parent / "netforge.yaml")
    cfg.target     = args.target
    cfg.engagement = args.engagement
    cfg.tester     = args.tester
    cfg.mode       = args.mode
    cfg.rate.requests_per_second = args.rate
    cfg.workers    = args.workers
    cfg.dry_run    = args.dry_run
    cfg.brute_force.delay_seconds = args.bf_delay
    cfg.brute_force.max_attempts  = args.bf_max
    cfg.brute_force.timeout_seconds = args.bf_timeout
    cfg.extra["interface"]   = args.interface
    cfg.extra["stealth"]     = args.stealth
    cfg.extra["capture"]     = args.capture
    cfg.extra["red_team"]    = args.red_team
    cfg.extra["attacker_ip"] = args.attacker_ip or "ATTACKER_IP"

    return await run_scan(cfg, args, results_dir, event_bus, scan_control)


async def main() -> None:
    args = parse_args()
    set_auto_confirm(args.auto_confirm)
    if not args.auto_confirm:
        require_authorization(args.target, "NetForge")
    ask_internet_permission("CVE database updates, nuclei templates")

    results_dir = setup_results(args.engagement, args.target, args.resume)
    cfg = load_config(Path(__file__).parent / "netforge.yaml")
    cfg.target     = args.target
    cfg.engagement = args.engagement
    cfg.tester     = args.tester
    cfg.mode       = args.mode
    cfg.rate.requests_per_second = args.rate
    cfg.workers    = args.workers
    cfg.dry_run    = args.dry_run
    cfg.brute_force.delay_seconds = args.bf_delay
    cfg.brute_force.max_attempts  = args.bf_max
    cfg.brute_force.timeout_seconds = args.bf_timeout
    cfg.extra["interface"]   = args.interface
    cfg.extra["stealth"]     = args.stealth
    cfg.extra["capture"]     = args.capture
    cfg.extra["red_team"]    = args.red_team
    cfg.extra["attacker_ip"] = args.attacker_ip or "ATTACKER_IP"

    await run_scan(cfg, args, results_dir)


if __name__ == "__main__":
    asyncio.run(main())