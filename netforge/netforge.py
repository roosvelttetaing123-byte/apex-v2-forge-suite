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
import getpass
import importlib
import json
import os
import re
import stat
import sys
import time
import uuid
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent))

from common.auth_prompt import require_authorization
from common.artifact_io import (
    ArtifactBoundaryError,
    absolute_lexical_path,
    open_private_directory,
    prepare_owner_controlled_directory,
)
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
from common.credential_boundary import (
    CREDENTIAL_REF_ENV,
    CredentialReference,
    resolved_process_credentials,
)
from common.db import create_db, ScanRunModel
from common.logger import get_logger, phase_banner, console
from common.netcheck import ask_internet_permission
from common.reporter import BaseReporter
from common.redaction import redact_text
from common.scope import Scope, ScopeDecision, ScopeReason, canonical_target, decision_for_reason, safe_target_display

# Lazy imports — these are optional features that must NOT crash the scan
def _import_opsec():
    try:
        from netforge.core.opsec import get_opsec
        return get_opsec
    except ImportError:
        log.debug("opsec module not available — using defaults")
        return None

def _import_stealth():
    try:
        from netforge.core.stealth_log import install_stealth_logging, dump_stealth_log
        return install_stealth_logging, dump_stealth_log
    except ImportError:
        log.debug("stealth_log module not available")
        return None, None

def _import_session_cleanup():
    try:
        from netforge.core.session import close_session
        return close_session
    except ImportError:
        return None

def _import_cred_engine():
    try:
        from netforge.core.cred_engine import CredEngine
        return CredEngine
    except ImportError:
        log.debug("cred_engine module not available — credentials won't be tracked")
        return None

def _import_attack_chain():
    try:
        from netforge.core.attack_chain import AttackChain
        return AttackChain
    except ImportError:
        log.debug("attack_chain module not available")
        return None

def _import_transport_manager():
    try:
        from netforge.core.cred_transport import TransportManager
        return TransportManager
    except ImportError:
        log.debug("cred_transport module not available — credentialed scanning disabled")
        return None

log = get_logger("netforge")
from common.version import VERSION
ENGINE_NAME = "netforge"
DEFAULT_LAUNCH_ACTION = "scan"
ALLOWED_LAUNCH_ACTIONS = {"scan", "retest", "web_to_network"}

PHASES: list[tuple[int, str, list[str]]] = [
    (1,  "Host Discovery",         ["host_discover","port_scanner","os_detect","service_id","topology_map"]),
    (2,  "External Recon",         ["dns_recon","ssl_audit","smtp_check","firewall_detect","exposure_check","firewall_rule_check"]),
    (3,  "Internal Analysis",      ["arp_monitor","dhcp_audit","vlan_check","cdp_ldp","ipv6_audit","llmnr_detect"]),
    (4,  "Service Auditing",       ["smb_audit","ftp_audit","ssh_audit","telnet_audit","rdp_audit","snmp_audit",
                                     "nfs_audit","mssql_audit","mysql_audit","redis_audit","mongo_audit",
                                     "elastic_audit","vnc_audit","tftp_audit","printer_audit","voip_audit",
                                     "ipmi_audit","kubernetes_audit","docker_audit","cloud_metadata","ics_audit","upnp_audit",
                                     # ── Infra service auditors (v5.1) ────────
                                     "jenkins_audit","gitlab_audit","consul_audit","vault_audit",
                                     "kafka_audit","etcd_audit"]),
    (5,  "Credentialed Checks",    [# ── Linux SSH credentialed ────────────────
                                     "cis_benchmark",
                                     "linux_patch_audit","linux_user_audit","linux_suid_audit",
                                     "linux_service_audit","linux_firewall_audit","linux_kernel_audit",
                                     "linux_cron_audit","linux_ssh_config","linux_sudo_audit",
                                     "linux_crypto_audit","linux_logging_audit","linux_docker_audit",
                                     # ── Linux compliance (v5.3) ──────────────
                                     "linux_cis_audit","linux_pci_audit",
                                     # ── SNMPv3 credentialed ──────────────────
                                     "snmp_system_info","snmp_interface_audit","snmp_process_audit",
                                     "snmp_software_audit","snmp_config_audit",
                                     # ── Windows WinRM credentialed ───────────
                                     "win_patch_audit","win_user_audit","win_service_audit",
                                     "win_firewall_audit","win_registry_audit","win_defender_audit",
                                     "win_share_audit","win_scheduled_task",
                                     # ── Windows AD / ADCS / Kerberos (v5.3) ──
                                     "win_adcs_audit","win_kerberos_audit","win_ad_enum",
                                     # ── Windows compliance (v5.3) ────────────
                                     "win_cis_audit",
                                     # ── Windows application depth (v5.3) ─────
                                     "win_iis_audit","win_exchange_audit","win_mssql_deep",
                                     # ── macOS SSH credentialed (v5.3) ────────
                                     "macos_patch_audit","macos_user_audit"]),
    (6,  "Vuln Matching",          ["cve_matcher","nmap_vulns","nuclei_runner","exploit_suggest",
                                     # ── Modern CVE detectors (v5.1) ──────────
                                     "log4shell","spring4shell","proxyshell",
                                     "moveit_sqli","citrix_bleed","fortigate_rce","connectwise_rce",
                                     # ── CVE Coverage Engine (v5.2) ─────────
                                     "cpe_vuln_engine","yaml_check_engine"]),
    (7,  "Brute Force",            ["native_brute","smart_brute","cred_spray","hydra_wrap"]),
    (8,  "Exploitation",           ["heartbleed","redis_rce","ntlm_relay","eternalblue","bluekeep","zerologon"]),
    (9,  "Credential Harvesting",  ["mimikatz_exec","sam_dump","ntds_dump","token_steal"]),
    (10, "Lateral Movement",       ["lateral_psexec","lateral_smb","lateral_ssh","lateral_winrm","lateral_wmi"]),
    (11, "Evasion",                ["amsi_bypass","etw_blind","process_hollow"]),
    (12, "Persistence",            ["persist_cron","persist_registry","persist_schtask","persist_service",
                                     "kernel_rootkit","userland_rootkit"]),
    (13, "Post-Exploit Intel",     ["pivot_finder","loot_parse","tunnel_suggest"]),
    (14, "Reporting",              ["html_report","pdf_report","json_export","csv_export","network_diagram"]),
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
    # ── Modern CVE detectors (v5.1) ──────────────────────────────
    "log4shell":        "netforge.modules.vuln.log4shell",
    "spring4shell":     "netforge.modules.vuln.spring4shell",
    "proxyshell":       "netforge.modules.vuln.proxyshell",
    "moveit_sqli":      "netforge.modules.vuln.moveit_sqli",
    "citrix_bleed":     "netforge.modules.vuln.citrix_bleed",
    "fortigate_rce":    "netforge.modules.vuln.fortigate_rce",
    "connectwise_rce":  "netforge.modules.vuln.connectwise_rce",
    # ── CVE Coverage Engine (v5.2) ──────────────────────────────
    "cpe_vuln_engine":  "netforge.modules.vuln.cpe_vuln_engine",
    "yaml_check_engine":"netforge.modules.vuln.yaml_check_engine",
    # ── Infra service auditors (v5.1) ────────────────────────────
    "jenkins_audit":    "netforge.modules.services.jenkins_audit",
    "gitlab_audit":     "netforge.modules.services.gitlab_audit",
    "consul_audit":     "netforge.modules.services.consul_audit",
    "vault_audit":      "netforge.modules.services.vault_audit",
    "kafka_audit":      "netforge.modules.services.kafka_audit",
    "etcd_audit":       "netforge.modules.services.etcd_audit",
    # ── Credentialed checks — Linux SSH (v5.1) ───────────────────
    "linux_patch_audit":   "netforge.modules.credentialed.linux_patch_audit",
    "linux_user_audit":    "netforge.modules.credentialed.linux_user_audit",
    "linux_suid_audit":    "netforge.modules.credentialed.linux_suid_audit",
    "linux_service_audit": "netforge.modules.credentialed.linux_service_audit",
    "linux_firewall_audit":"netforge.modules.credentialed.linux_firewall_audit",
    "linux_kernel_audit":  "netforge.modules.credentialed.linux_kernel_audit",
    "linux_cron_audit":    "netforge.modules.credentialed.linux_cron_audit",
    "linux_ssh_config":    "netforge.modules.credentialed.linux_ssh_config",
    "linux_sudo_audit":    "netforge.modules.credentialed.linux_sudo_audit",
    "linux_crypto_audit":  "netforge.modules.credentialed.linux_crypto_audit",
    "linux_logging_audit": "netforge.modules.credentialed.linux_logging_audit",
    "linux_docker_audit":  "netforge.modules.credentialed.linux_docker_audit",
    # ── Credentialed checks — SNMPv3 (v5.1) ──────────────────────
    "snmp_system_info":    "netforge.modules.credentialed.snmp_system_info",
    "snmp_interface_audit":"netforge.modules.credentialed.snmp_interface_audit",
    "snmp_process_audit":  "netforge.modules.credentialed.snmp_process_audit",
    "snmp_software_audit": "netforge.modules.credentialed.snmp_software_audit",
    "snmp_config_audit":   "netforge.modules.credentialed.snmp_config_audit",
    # ── Credentialed checks — Windows WinRM (v5.1) ───────────────
    "win_patch_audit":     "netforge.modules.credentialed.win_patch_audit",
    "win_user_audit":      "netforge.modules.credentialed.win_user_audit",
    "win_service_audit":   "netforge.modules.credentialed.win_service_audit",
    "win_firewall_audit":  "netforge.modules.credentialed.win_firewall_audit",
    "win_registry_audit":  "netforge.modules.credentialed.win_registry_audit",
    "win_defender_audit":  "netforge.modules.credentialed.win_defender_audit",
    "win_share_audit":     "netforge.modules.credentialed.win_share_audit",
    "win_scheduled_task":  "netforge.modules.credentialed.win_scheduled_task",
    # ── Credentialed checks — AD / ADCS / Kerberos (v5.3) ────────
    "win_adcs_audit":      "netforge.modules.credentialed.win_adcs_audit",
    "win_kerberos_audit":  "netforge.modules.credentialed.win_kerberos_audit",
    "win_ad_enum":         "netforge.modules.credentialed.win_ad_enum",
    # ── Credentialed checks — Compliance (v5.3) ──────────────────
    "cis_benchmark":      "netforge.modules.compliance.cis_benchmark",
    "linux_cis_audit":     "netforge.modules.credentialed.linux_cis_audit",
    "win_cis_audit":       "netforge.modules.credentialed.win_cis_audit",
    "linux_pci_audit":     "netforge.modules.credentialed.linux_pci_audit",
    # ── Credentialed checks — Windows Application Depth (v5.3) ──
    "win_iis_audit":       "netforge.modules.credentialed.win_iis_audit",
    "win_exchange_audit":  "netforge.modules.credentialed.win_exchange_audit",
    "win_mssql_deep":      "netforge.modules.credentialed.win_mssql_deep",
    # ── Credentialed checks — macOS SSH (v5.3) ───────────────────
    "macos_patch_audit":   "netforge.modules.credentialed.macos_patch_audit",
    "macos_user_audit":    "netforge.modules.credentialed.macos_user_audit",
    # ── Brute force ──────────────────────────────────────────────
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
    # ── Credential Harvesting (Red Team only) ─────────────────────
    "mimikatz_exec":    "netforge.modules.post_exploit.mimikatz_exec",
    "sam_dump":         "netforge.modules.post_exploit.sam_dump",
    "ntds_dump":        "netforge.modules.post_exploit.ntds_dump",
    "token_steal":      "netforge.modules.post_exploit.token_steal",
    # ── Lateral Movement (Red Team only) ──────────────────────────
    "lateral_psexec":   "netforge.modules.post_exploit.lateral_psexec",
    "lateral_smb":      "netforge.modules.post_exploit.lateral_smb",
    "lateral_ssh":      "netforge.modules.post_exploit.lateral_ssh",
    "lateral_winrm":    "netforge.modules.post_exploit.lateral_winrm",
    "lateral_wmi":      "netforge.modules.post_exploit.lateral_wmi",
    # ── Evasion (Red Team only) ───────────────────────────────────
    "amsi_bypass":      "netforge.modules.rootkit.amsi_bypass",
    "etw_blind":        "netforge.modules.rootkit.etw_blind",
    "process_hollow":   "netforge.modules.rootkit.process_hollow",
    # ── Persistence / Rootkit (Red Team only) ─────────────────────
    "persist_cron":     "netforge.modules.post_exploit.persist_cron",
    "persist_registry":  "netforge.modules.post_exploit.persist_registry",
    "persist_schtask":  "netforge.modules.post_exploit.persist_schtask",
    "persist_service":  "netforge.modules.post_exploit.persist_service",
    "kernel_rootkit":   "netforge.modules.rootkit.kernel_rootkit",
    "userland_rootkit":  "netforge.modules.rootkit.userland_rootkit",
    # ── Post-Exploit Intel ────────────────────────────────────────
    "pivot_finder":     "netforge.modules.post_exploit.pivot_finder",
    "loot_parse":       "netforge.modules.post_exploit.loot_parse",
    "tunnel_suggest":   "netforge.modules.post_exploit.tunnel_suggest",
    # ── Reporting ─────────────────────────────────────────────────
    "html_report":      "netforge.modules.reporting.html_report",
    "pdf_report":       "netforge.modules.reporting.pdf_report",
    "json_export":      "netforge.modules.reporting.json_export",
    "csv_export":       "netforge.modules.reporting.csv_export",
    "network_diagram":  "netforge.modules.reporting.network_diagram",
}

CLASS_NAME_MAP: dict[str, str] = {k: "".join(p.capitalize() for p in k.split("_")) for k in MODULE_MAP}
CLASS_NAME_MAP.update({
    "llmnr_detect": "LlmnrDetect", "cdp_ldp": "CdpLdp",
    "ics_audit": "IcsAudit", "upnp_audit": "UpnpAudit",
    "ipmi_audit": "IpmiAudit",
    "redis_rce": "RedisRce", "ntlm_relay": "NtlmRelay",
    "native_brute": "NativeBrute",
    # ── Credential Harvesting class name overrides ────────────────
    "sam_dump": "SAMDump", "ntds_dump": "NTDSDump",
    # ── Lateral Movement class name overrides ─────────────────────
    "lateral_psexec": "LateralPsExec", "lateral_smb": "LateralSMB",
    "lateral_ssh": "LateralSSH", "lateral_winrm": "LateralWinRM",
    "lateral_wmi": "LateralWMI",
    # ── Evasion class name overrides ──────────────────────────────
    "amsi_bypass": "AMSIBypass", "etw_blind": "ETWBlind",
    # ── Persistence class name overrides ──────────────────────────
    "persist_schtask": "PersistScheduledTask",
    # ── v5.1 CVE detector class overrides ─────────────────────────
    "log4shell": "Log4Shell", "spring4shell": "Spring4Shell",
    "proxyshell": "ProxyShell", "moveit_sqli": "MoveitSqli",
    "citrix_bleed": "CitrixBleed", "fortigate_rce": "FortigateRce",
    "connectwise_rce": "ConnectwiseRce",
    "eternalblue": "EternalBlue", "bluekeep": "BlueKeep",
    # ── v5.1 Credentialed Linux class overrides ───────────────────
    "linux_ssh_config": "LinuxSshConfig",
    # ── v5.1 Credentialed Windows class overrides ─────────────────
    "win_scheduled_task": "WinScheduledTask",
})

# Exploitation modules — ONLY loaded when --red-team is active
RED_TEAM_MODULES = {
    # Exploitation
    "heartbleed", "redis_rce", "ntlm_relay", "eternalblue", "bluekeep", "zerologon",
    # Credential Harvesting
    "mimikatz_exec", "sam_dump", "ntds_dump", "token_steal",
    # Lateral Movement
    "lateral_psexec", "lateral_smb", "lateral_ssh", "lateral_winrm", "lateral_wmi",
    # Evasion
    "amsi_bypass", "etw_blind", "process_hollow",
    # Persistence / Rootkit
    "persist_cron", "persist_registry", "persist_schtask", "persist_service",
    "kernel_rootkit", "userland_rootkit",
}

# Phases that must run sequentially — active exploitation is never parallelised.
# Updated for v5.1 phase renumbering (exploitation=8, cred_harvest=9, lateral=10, evasion=11, persist=12)
SEQUENTIAL_PHASES = {8, 9, 10, 11, 12}


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


def _emit(bus: Any, Event: Any, EventType: Any, etype: str, source: str = "netforge", **data: Any) -> None:
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


def _finalize_credential_engine(
    cred_engine: Any,
    results_dir: Path,
    bus: Any,
    Event: Any,
    EventType: Any,
) -> None:
    """Export references, tolerate event/report failures, and always wipe values."""
    if cred_engine is None:
        return
    try:
        if len(cred_engine) <= 0:
            return
        export_path = results_dir / "credential_references.json"
        cred_engine.export_json(export_path)
        log.info("Exported %d protected credential references", len(cred_engine))
        for cred in cred_engine.all():
            safe_record = cred.to_dict()
            _emit(
                bus,
                Event,
                EventType,
                "credential_found",
                source="cred_engine",
                service=safe_record.get("service", ""),
                account=safe_record.get("username", ""),
                target=safe_record.get("host", ""),
                credential_reference=protected_credential_reference(
                    {"credential_key": cred.key(), "source": cred.source}
                ),
            )
    except Exception as exc:
        log.debug("Credential reference export failed: %s", type(exc).__name__)
    finally:
        cred_engine.wipe_all()


# ── Pause / Resume / Abort control ───────────────────────────────────

class ScanControl:
    """Async-safe scan control flags shared across the orchestrator.

    Attributes:
        paused:  asyncio.Event — cleared = paused, set = running.
        aborted: bool flag checked in the scan loop.
    """

    def __init__(self, control_file: str | None = None) -> None:
        self._paused = asyncio.Event()
        self._paused.set()            # starts in running state
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
        self._paused.set()            # unblock if paused so loop can exit
        log.info("Scan ABORTED by operator")

    async def wait_if_paused(self) -> None:
        """Block until un-paused. Returns immediately if not paused."""
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


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="NetForge — Network Penetration Testing Framework",
        allow_abbrev=False,
    )
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
    p.add_argument("--scope",        action="append", default=[], metavar="ENTRY",
                   help="Explicitly authorized host, URL, IP, or CIDR (repeatable)")
    p.add_argument("--exclude",      action="append", default=[], metavar="ENTRY",
                   help="Explicitly excluded host, URL, IP, or CIDR (repeatable)")
    p.add_argument("--verbose",      action="store_true",                        help="Verbose output")
    p.add_argument("--collab-domain", default=None,
                   help="ForgeCollab OOB domain (e.g. collab.example.com) for blind vuln confirmation")
    p.add_argument("--version",      action="version", version=f"NetForge {VERSION}")
    p.add_argument("--dashboard-url", default=None,
                   help="Live dashboard URL (e.g. http://localhost:1337) — streams events in real time")
    p.add_argument("--control-file",  default=None,
                   help="JSON control file used by dashboard pause/resume/abort")
    # ── Credentialed scanning (v5.1) ─────────────────────────────────
    cred_group = p.add_argument_group("Credentialed Scanning", "SSH/SNMP/WinRM credentials for local checks")
    cred_group.add_argument("--ssh-user",      default=None,       help="SSH username for credentialed checks")
    cred_group.add_argument("--ssh-pass",      default=None,       help="SSH password (or use --ssh-key)")
    cred_group.add_argument("--ssh-key",       default=None,       help="SSH private key file path")
    cred_group.add_argument("--ssh-port",      type=int, default=22, help="SSH port (default: 22)")
    cred_group.add_argument("--snmp-user",     default=None,       help="SNMPv3 username")
    cred_group.add_argument("--snmp-auth-pass",default=None,       help="SNMPv3 auth passphrase")
    cred_group.add_argument("--snmp-priv-pass",default=None,       help="SNMPv3 privacy passphrase")
    cred_group.add_argument("--snmp-auth-proto",default="SHA",     help="SNMPv3 auth protocol (MD5/SHA)")
    cred_group.add_argument("--snmp-priv-proto",default="AES",     help="SNMPv3 priv protocol (DES/AES)")
    cred_group.add_argument("--winrm-user",    default=None,       help="WinRM username (domain\\user)")
    cred_group.add_argument("--winrm-pass",    default=None,       help="WinRM password")
    cred_group.add_argument("--winrm-port",    type=int, default=5986, help="WinRM HTTPS port (required default: 5986)")
    cred_group.add_argument("--winrm-ssl",     action="store_true", default=True, help="Require HTTPS and certificate validation for WinRM")
    return p.parse_args()


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


def _print_launch_denial(decision: ScopeDecision) -> None:
    console.print(
        f"[bold red]Launch denied:[/bold red] reason_code={decision.reason_code}; {decision.reason}"
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
    """Return credential inputs actually available to this NetForge process."""
    names = (
        "ssh_user",
        "ssh_pass",
        "ssh_key",
        "snmp_user",
        "snmp_auth_pass",
        "snmp_priv_pass",
        "winrm_user",
        "winrm_pass",
    )
    return {
        name: str(getattr(args, name, "") or "")
        for name in names
        if getattr(args, name, "")
    }


def _credential_reference(args: argparse.Namespace) -> str:
    inherited = os.environ.get(CREDENTIAL_REF_ENV, "")
    if inherited:
        return CredentialReference.parse(inherited).value
    return protected_credential_reference(_credential_values(args))


_DIRECT_SECRET_ARGUMENTS = (
    "ssh_pass",
    "snmp_auth_pass",
    "snmp_priv_pass",
    "winrm_pass",
)


def _has_direct_secret_args(args: argparse.Namespace) -> bool:
    return any(getattr(args, field, None) for field in _DIRECT_SECRET_ARGUMENTS)


def _apply_resolved_credentials(
    args: argparse.Namespace,
    values: Mapping[str, str],
) -> None:
    """Apply only allowlisted values from the authorized inherited handoff."""
    unknown = set(values) - set(_DIRECT_SECRET_ARGUMENTS)
    if unknown:
        raise ValueError("credential process handoff contains unsupported fields")
    for field in _DIRECT_SECRET_ARGUMENTS:
        setattr(args, field, values.get(field) or None)
    setattr(args, "_credentials_from_protected_handoff", bool(values))


def _clear_resolved_credentials(args: argparse.Namespace) -> None:
    for field in _DIRECT_SECRET_ARGUMENTS:
        setattr(args, field, None)
    setattr(args, "_credentials_from_protected_handoff", False)


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
    action = str(getattr(args, "_launch_action", DEFAULT_LAUNCH_ACTION))
    session = open_authorization_session()
    try:
        record_boundary_denial(
            session=session,
            reason_code=decision.reason_code,
            action_kind=action,
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
            run_id=runtime.get("run_id", "netforge-preflight-run"),
            job_id=getattr(args, "_launch_job_id", "netforge-preflight-job"),
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
            network_escalation_approval_required=(action == "web_to_network"),
        )
    finally:
        session.close()


def _prepare_engine_authorization(
    args: argparse.Namespace,
    confirmations: list[ActionConfirmation],
) -> tuple[ScopeDecision, ActionAuthorizationEnvelope | None]:
    inherited = load_authorization_envelopes()
    if os.environ.get(AUTHORIZATION_ENVELOPES_ENV) and not inherited:
        denied = decision_for_reason(ScopeReason.INVALID_CONFIRMATION)
        _audit_scope_denial(args, denied, target=args.target)
        return denied, None
    job_id = str(getattr(args, "_launch_job_id", ""))
    module_binding = module_set_binding(_requested_modules(args))
    if inherited:
        envelope = select_authorization_envelope(
            inherited,
            job_id=job_id,
            engine=ENGINE_NAME,
            action_kind="engine.execute",
            requested_target=args.target,
            resolved_target=args.target,
            module_id=module_binding,
        )
        if envelope is None:
            denied = decision_for_reason(ScopeReason.INVALID_CONFIRMATION)
            _audit_scope_denial(args, denied, target=args.target)
            return denied, None
        return decision_for_reason(ScopeReason.ALLOWED), envelope

    confirmation = _confirmation_for_target(confirmations, args.target)
    if confirmation is None:
        return decision_for_reason(ScopeReason.MISSING_CONFIRMATION), None
    tenant_id = os.environ.get("FORGE_TENANT_ID", "default").strip() or "default"
    operator_id = getpass.getuser().strip() or "operator"
    credential_reference = _credential_reference(args)
    session = open_authorization_session()
    try:
        base_context = AuthorizationContext(
            tenant_id=tenant_id,
            engagement_id=str(args.engagement or "default"),
            run_id=f"run-{uuid.uuid4().hex}",
            job_id=job_id,
            operator_id=operator_id,
            operator_role=OperatorRole.OPERATOR,
            action_kind=str(getattr(args, "_launch_action", DEFAULT_LAUNCH_ACTION)),
            engine=ENGINE_NAME,
            module_id=module_binding,
            requested_target=args.target,
            resolved_target=args.target,
            allowed_scope=args.scope,
            excluded_scope=args.exclude,
            safety_mode=SafetyMode.ACTIVE,
            credential_approval_required=bool(credential_reference),
            network_escalation_approval_required=(
                str(getattr(args, "_launch_action", "")) == "web_to_network"
            ),
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
            boundary="netforge.cli",
        )
        if not issued.allowed or not consumed.allowed:
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
            parent_boundary="netforge.cli",
        )
        if not derived.allowed:
            return decision_for_reason(ScopeReason.INVALID_CONFIRMATION), None
        args._authorization_runtime = load_authorization_runtime_facts(
            authorization_runtime_environment(derived.envelope)
        )
        return decision_for_reason(ScopeReason.ALLOWED), derived.envelope
    finally:
        session.close()


def _launch_decision(
    cfg: BaseForgeConfig,
    args: argparse.Namespace,
    *,
    target: str | None = None,
) -> ScopeDecision:
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
    authorization: ActionAuthorizationEnvelope | None = None,
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
    if authorization is not None:
        cfg.extra["authorization_envelope"] = authorization


def _consume_engine_authorization(cfg: BaseForgeConfig) -> AuthorizationDecision:
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
                boundary="netforge.engine",
            )
        decision = consume_authorization(
            session=session,
            envelope=envelope,
            expected=expected,
            boundary="netforge.engine",
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
            parent_boundary="netforge.engine",
        )
        if not derived.allowed:
            return derived
        consumed = consume_authorization(
            session=session,
            envelope=derived.envelope,
            expected=context,
            boundary="netforge.module",
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
        f"netforge-cli-{uuid.uuid4().hex}",
        DEFAULT_LAUNCH_ACTION,
    )
    if expected_action not in ALLOWED_LAUNCH_ACTIONS:
        return decision_for_reason(ScopeReason.ACTION_MISMATCH), []
    args._launch_job_id = job_id
    args._launch_action = expected_action
    decision = decide_action(
        target=args.target,
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

    confirmation = _confirmation_for_target(inherited, args.target)
    if confirmation is None and inherited:
        return decision_for_reason(ScopeReason.MISSING_CONFIRMATION), []
    if confirmation is None:
        if not args.auto_confirm:
            try:
                require_authorization(args.target, "NetForge")
            except SystemExit:
                _audit_scope_denial(
                    args,
                    decision_for_reason(ScopeReason.MISSING_CONFIRMATION),
                    target=args.target,
                )
                raise
        confirmation = ActionConfirmation.create(
            job_id=job_id,
            target=args.target,
            engine=ENGINE_NAME,
            action=expected_action,
        )

    decision = decide_action(
        target=args.target,
        allowed_scope=args.scope,
        excluded_scope=args.exclude,
        confirmation=confirmation,
        job_id=job_id,
        engine=ENGINE_NAME,
        action=expected_action,
    )
    return decision, [confirmation] if decision.allowed else []


def _planned_phases(args: argparse.Namespace) -> list[dict[str, Any]]:
    include = {item.strip() for item in args.modules.split(",")} if args.modules else None
    skip = {item.strip() for item in args.skip_modules.split(",")} if args.skip_modules else set()
    planned: list[dict[str, Any]] = []
    for number, name, modules in PHASES:
        if args.mode == "external" and name == "Internal Analysis":
            continue
        if args.mode == "internal" and name == "External Recon":
            continue
        selected = [
            module
            for module in modules
            if (include is None or module in include)
            and module not in skip
            and (args.red_team or module not in RED_TEAM_MODULES)
        ]
        if selected:
            planned.append({"number": number, "name": name, "modules": selected})
    return planned


async def dry_run_plan(cfg: BaseForgeConfig, args: argparse.Namespace) -> dict[str, Any]:
    phases = _planned_phases(args)
    module_count = sum(len(phase["modules"]) for phase in phases)
    console.print(
        f"[bold yellow]DRY RUN[/bold yellow] — {module_count} modules planned; "
        "no modules, events, reports, sockets, or subprocesses created"
    )
    return {
        "status": "completed",
        "findings": 0,
        "errors": [],
        "duration": 0.0,
        "dry_run": True,
        "authorized": False,
        "plan": {
            "status": "planned",
            "dry_run": True,
            "authorized": False,
            "target": safe_target_display(cfg.target),
            "module_count": module_count,
            "phases": phases,
        },
    }


def _prepare_owner_only_directory(path: Path) -> None:
    """Create/validate one results leaf and force it to owner-only mode."""
    descriptor = -1
    try:
        descriptor = open_private_directory(path, create=True)
        os.fchmod(descriptor, 0o700)
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except Exception:
                pass


def _safe_result_component(value: object, fallback: str) -> str:
    """Return one redacted bounded filename component without path syntax."""
    rendered = redact_text(str(value or ""))
    rendered = re.sub(r"[^A-Za-z0-9._-]+", "_", rendered).strip("._-")
    if not rendered or rendered in {".", ".."}:
        rendered = fallback
    return rendered[:80]


def _unique_results_dir(base: Path, dirname: str) -> Path:
    """Exclusively allocate one owner-only result directory below a pinned base."""
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


def setup_results(
    engagement: str,
    target: str,
    resume: str | None,
    output_dir: str | None = None,
) -> Path:
    if resume:
        path = absolute_lexical_path(Path(resume).expanduser())
        _prepare_owner_only_directory(path)
    else:
        safe_target = _safe_result_component(safe_target_display(target), "target")
        safe_engagement = _safe_result_component(engagement, "engagement")
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        base = (
            absolute_lexical_path(Path(output_dir).expanduser())
            if output_dir
            else Path(__file__).parent / "results"
        )
        path = _unique_results_dir(
            base,
            f"{safe_engagement}_{safe_target}_{ts}",
        )
    _prepare_owner_only_directory(path / "pcaps")
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


class _NetForgeResourceLifecycle:
    """Own scan resources and release them without masking primary failures."""

    def __init__(self, results_dir: Path) -> None:
        self.results_dir = results_dir
        self.session_cleanup = False
        self.transport_manager: Any = None
        self.credential_engine: Any = None
        self.db_session: Any = None
        self.bus: Any = None
        self.Event: Any = None
        self.EventType: Any = None
        self.stealth_db_path: Path | None = None
        self.stealth_session_key: bytearray | None = None
        self._cleaned = False

    async def cleanup(self) -> None:
        if self._cleaned:
            return
        self._cleaned = True
        try:
            await self._cleanup_resources()
        finally:
            self._finalize_stealth_session()

    async def _cleanup_resources(self) -> None:
        if self.transport_manager is not None:
            try:
                await self.transport_manager.close_all()
                log.info("Transport sessions closed")
            except BaseException as exc:
                log.debug("Transport cleanup error: %s", type(exc).__name__)

        if self.session_cleanup:
            close_session = _import_session_cleanup()
            if close_session is not None:
                try:
                    await close_session()
                except BaseException as exc:
                    log.debug("Session cleanup error: %s", type(exc).__name__)

        if self.credential_engine is not None:
            try:
                _finalize_credential_engine(
                    self.credential_engine,
                    self.results_dir,
                    self.bus,
                    self.Event,
                    self.EventType,
                )
            except BaseException as exc:
                log.debug("Credential cleanup error: %s", type(exc).__name__)
            finally:
                try:
                    self.credential_engine.wipe_all()
                except BaseException as exc:
                    log.debug("Credential wipe error: %s", type(exc).__name__)

        if self.db_session is not None:
            try:
                self.db_session.close()
            except BaseException as exc:
                log.debug("Database cleanup error: %s", type(exc).__name__)

    def _finalize_stealth_session(self) -> None:
        """Finalize last and wipe the caller alias even if other cleanup fails."""
        key = self.stealth_session_key
        try:
            if self.stealth_db_path is None:
                return
            try:
                from netforge.core.stealth_log import finalize_stealth_logging

                finalize_stealth_logging(self.stealth_db_path)
            except BaseException as exc:
                log.debug("Private log cleanup error: %s", type(exc).__name__)
        finally:
            if isinstance(key, bytearray):
                key[:] = b"\x00" * len(key)
                key.clear()
            self.stealth_session_key = None
            self.stealth_db_path = None


async def run_scan(
    cfg: BaseForgeConfig,
    args: argparse.Namespace,
    results_dir: Path,
    event_bus: Any = None,
    scan_control: ScanControl | None = None,
) -> dict[str, Any]:
    """Run one scan with deterministic exceptional-path resource cleanup."""
    lifecycle = _NetForgeResourceLifecycle(results_dir)
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
        await lifecycle.cleanup()


async def _run_scan_impl(
    cfg: BaseForgeConfig,
    args: argparse.Namespace,
    results_dir: Path,
    event_bus: Any = None,
    scan_control: ScanControl | None = None,
    lifecycle: _NetForgeResourceLifecycle | None = None,
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
    if _has_direct_secret_args(args) and not bool(
        getattr(args, "_credentials_from_protected_handoff", False)
    ):
        _clear_resolved_credentials(args)
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
        return await dry_run_plan(cfg, args)

    authorization_decision = _consume_engine_authorization(cfg)
    if not authorization_decision.allowed:
        log.warning(
            "Engine authorization denied reason_code=%s",
            authorization_decision.reason_code,
        )
        return {
            "status": "not_authorized",
            "findings": 0,
            "errors": [authorization_decision.reason],
            "duration": 0.0,
            "dry_run": False,
            "authorized": False,
            "reason_code": authorization_decision.reason_code,
            "reason": authorization_decision.reason,
        }
    engine_authorization = authorization_decision.envelope

    bus, Event, EventType = _get_event_bus(event_bus)
    if lifecycle is not None:
        lifecycle.bus = bus
        lifecycle.Event = Event
        lifecycle.EventType = EventType
        lifecycle.session_cleanup = True
    ctrl = scan_control or ScanControl(getattr(args, "control_file", None))
    cfg.extra["outbound_cancellation_check"] = lambda: ctrl.is_aborted
    eng_bus = _get_eng_bus()

    # ── OpSec Profile (graceful if unavailable) ───────────────────────
    _get_opsec = _import_opsec()
    opsec_level = "stealth" if args.stealth else args.opsec
    opsec = _get_opsec(opsec_level) if _get_opsec else None

    if opsec:
        cfg.extra["opsec_level"] = opsec.level.value
        cfg.extra["opsec_stats"] = opsec.stats
        if opsec.max_threads < cfg.workers:
            cfg.workers = opsec.max_threads
            log.info("Workers capped to %d by OpSec profile '%s'", cfg.workers, opsec.level.value)
    else:
        cfg.extra["opsec_level"] = opsec_level
        cfg.extra["opsec_stats"] = {"requests": 0, "decoys_injected": 0}

    # ── Stealth Logging (graceful if unavailable) ─────────────────────
    install_stealth_logging, dump_stealth_log = _import_stealth()
    stealth_session_key = None
    if opsec and hasattr(opsec, 'suppress_console') and opsec.suppress_console and install_stealth_logging:
        console.print(f"[bold yellow]STEALTH MODE — console output suppressed after this line[/bold yellow]")
        console.print(f"[yellow]All logs encrypted → {results_dir / 'stealth.db'}[/yellow]")
        stealth_session_key = install_stealth_logging(results_dir)
        if lifecycle is not None:
            lifecycle.stealth_db_path = results_dir / "stealth.db"
            lifecycle.stealth_session_key = stealth_session_key

    # ── Credential Engine (graceful if unavailable) ───────────────────
    CredEngine = _import_cred_engine()
    cred_engine = CredEngine() if CredEngine else None
    if lifecycle is not None:
        lifecycle.credential_engine = cred_engine
    cfg.extra["cred_engine"] = cred_engine

    # ── Attack Chain Engine (Red Team, graceful if unavailable) ───────
    AttackChain = _import_attack_chain()
    attack_chain = AttackChain(cred_engine=cred_engine) if (args.red_team and AttackChain and cred_engine) else None
    cfg.extra["attack_chain"] = attack_chain

    # ── Transport Manager for credentialed scanning (v5.1) ───────────
    TransportManager = _import_transport_manager()
    transport_mgr = None
    has_creds = any([
        getattr(args, 'ssh_user', None),
        getattr(args, 'snmp_user', None),
        getattr(args, 'winrm_user', None),
    ])
    if TransportManager and has_creds:
        transport_mgr = TransportManager()
        if lifecycle is not None:
            lifecycle.transport_manager = transport_mgr
        # Register SSH credentials
        if getattr(args, 'ssh_user', None):
            transport_mgr.add_ssh_creds(
                username=args.ssh_user,
                password=getattr(args, 'ssh_pass', None),
                key_file=getattr(args, 'ssh_key', None),
                port=getattr(args, 'ssh_port', 22),
                host_pattern=cfg.target,
            )
            console.print(f"[green]SSH credentials loaded for user: {args.ssh_user}[/green]")
        # Register SNMPv3 credentials
        if getattr(args, 'snmp_user', None):
            transport_mgr.add_snmpv3_creds(
                username=args.snmp_user,
                auth_passphrase=getattr(args, 'snmp_auth_pass', None),
                priv_passphrase=getattr(args, 'snmp_priv_pass', None),
                auth_protocol=getattr(args, 'snmp_auth_proto', 'SHA'),
                priv_protocol=getattr(args, 'snmp_priv_proto', 'AES'),
                host_pattern=cfg.target,
            )
            console.print(f"[green]SNMPv3 credentials loaded for user: {args.snmp_user}[/green]")
        # Register WinRM credentials
        if getattr(args, 'winrm_user', None):
            transport_mgr.add_winrm_creds(
                username=args.winrm_user,
                password=getattr(args, 'winrm_pass', None),
                port=getattr(args, 'winrm_port', 5986),
                use_ssl=getattr(args, 'winrm_ssl', True),
                host_pattern=cfg.target,
            )
            console.print(f"[green]WinRM credentials loaded for user: {args.winrm_user}[/green]")
        log.info("TransportManager initialized with %d credential type(s)",
                 sum([bool(getattr(args, 'ssh_user', None)),
                      bool(getattr(args, 'snmp_user', None)),
                      bool(getattr(args, 'winrm_user', None))]))
    elif not has_creds:
        log.info("No credentials provided — credentialed checks will be skipped")
    cfg.extra["transport_manager"] = transport_mgr

    db_session = create_db(results_dir / "netforge.db")
    if lifecycle is not None:
        lifecycle.db_session = db_session
    scope = Scope(
        cfg.extra.get("allowed_scope", getattr(args, "scope", None)),
        excluded=cfg.extra.get("excluded_scope", getattr(args, "exclude", None)),
    )
    run_id = engine_authorization.run_id
    run = ScanRunModel(
        id=run_id,
        tenant_id=engine_authorization.tenant_id,
        framework=ENGINE_NAME,
        target=cfg.target,
        mode=cfg.mode,
        engagement=cfg.engagement,
        tester=cfg.tester,
    )
    db_session.add(run)
    db_session.commit()

    include = [m.strip() for m in args.modules.split(",")] if args.modules else None
    skip    = [m.strip() for m in args.skip_modules.split(",")] if args.skip_modules else None

    # Collect all module names for the SCAN_START event
    all_module_names = []
    for _, _, phase_mods in PHASES:
        all_module_names.extend(phase_mods)
    planned_capabilities = tuple(
        module
        for phase in _planned_phases(args)
        for module in phase["modules"]
    )

    # ── Emit: scan_start ──────────────────────────────────────────────
    _emit(bus, Event, EventType, "scan_start", source="netforge",
          target=safe_target_display(cfg.target), mode=args.mode, engagement=cfg.engagement,
          tester=cfg.tester, framework="NetForge", modules=all_module_names)

    console.print(
        f"\n[bold cyan]NetForge v{VERSION}[/bold cyan] — Target: "
        f"[cyan]{safe_target_display(cfg.target)}[/cyan]"
    )
    mode_label = f"{args.mode}"
    if args.red_team:
        mode_label += " [bold red][RED TEAM][/bold red]"
    total_phases = len([p for p in PHASES if True])  # dynamic count
    console.print(f"Mode: [yellow]{mode_label}[/yellow] | Phases: {total_phases} | OpSec: [yellow]{opsec.level.value}[/yellow]")
    if args.red_team:
        console.print("[bold red]RED TEAM MODE — exploitation modules ACTIVE[/bold red]")
        console.print(f"[red]Attacker IP: {args.attacker_ip or 'NOT SET (use --attacker-ip)'}[/red]")
    if args.dry_run:
        console.print("[bold yellow]DRY RUN — no packets sent[/bold yellow]")

    all_findings = []
    errors = []
    aborted = False
    start_time = time.monotonic()

    # Count total modules for progress calculation
    total_modules = 0
    coverage_completed: set[str] = set()
    for _, pname, pmods in PHASES:
        if args.mode == "external" and pname == "Internal Analysis":
            continue
        if args.mode == "internal" and pname == "External Recon":
            continue
        filt = [m for m in pmods
                if (not include or m in include) and (not skip or m not in skip)]
        if not args.red_team:
            filt = [m for m in filt if m not in RED_TEAM_MODULES]
        total_modules += len(filt)
    modules_completed = 0
    _progress_lock = asyncio.Lock()

    for phase_num, phase_name, phase_mods in PHASES:
        # ── Abort check ───────────────────────────────────────────────
        if ctrl.is_aborted:
            aborted = True
            break

        # ── Pause gate ────────────────────────────────────────────────
        if ctrl.is_paused:
            _emit(bus, Event, EventType, "scan_paused", source="netforge")
            await ctrl.wait_if_paused()
            if ctrl.is_aborted:
                aborted = True
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
        if opsec and hasattr(opsec, 'shuffle_modules'):
            filtered = opsec.shuffle_modules(filtered)

        phase_banner(phase_num, len(PHASES), phase_name)

        # ── Emit: phase_start ─────────────────────────────────────────
        _emit(bus, Event, EventType, "phase_start", source="netforge",
              number=phase_num, name=phase_name, modules=filtered)

        phase_start = time.monotonic()

        # Exploitation phases run sequentially; all others respect cfg.workers.
        phase_concurrency = 1 if phase_num in SEQUENTIAL_PHASES else cfg.workers
        phase_sem = asyncio.Semaphore(phase_concurrency)

        async def _exec(mname: str) -> tuple[list, list]:
            """Run one module within the phase semaphore."""
            nonlocal modules_completed, aborted
            async with phase_sem:
                if ctrl.is_aborted:
                    aborted = True
                    return [], []
                if mname in MODULE_MAP:
                    from common.outbound_policy import evaluate_module_outbound_support
                    support = evaluate_module_outbound_support(
                        engine=ENGINE_NAME,
                        module_id=mname,
                    )
                    if not support.supported:
                        _emit(
                            bus, Event, EventType, "module_skip",
                            source=mname, name=mname,
                            reason=support.reason_code, outcome=support.outcome,
                        )
                        async with _progress_lock:
                            modules_completed += 1
                        return [], [f"{mname}: {support.reason_code}"]
                cls = load_module(mname)
                if cls is None:
                    log.debug("Module not yet built: %s", mname)
                    _emit(bus, Event, EventType, "module_skip", source=mname,
                          name=mname, reason="not built")
                    async with _progress_lock:
                        modules_completed += 1
                        pct = round(modules_completed / total_modules * 100) if total_modules else 0
                    _emit(bus, Event, EventType, "module_progress", source=mname,
                          name=mname, progress=pct)
                    return [], []
                module_authorization = _authorize_module_execution(
                    cfg,
                    engine_authorization,
                    mname,
                )
                if not module_authorization.allowed:
                    reason = module_authorization.reason_code
                    _emit(
                        bus,
                        Event,
                        EventType,
                        "module_skip",
                        source=mname,
                        name=mname,
                        reason=reason,
                    )
                    async with _progress_lock:
                        modules_completed += 1
                        pct = round(modules_completed / total_modules * 100) if total_modules else 0
                    _emit(
                        bus,
                        Event,
                        EventType,
                        "module_progress",
                        source=mname,
                        name=mname,
                        progress=pct,
                    )
                    return [], [f"{mname}: not authorized ({reason})"]
                try:
                    if opsec and hasattr(opsec, 'maybe_inject_decoy'):
                        await opsec.maybe_inject_decoy()
                    module_config = cfg.model_copy(deep=False)
                    module_config.extra = dict(cfg.extra)
                    mod = cls(config=module_config, scope=scope, db_session=db_session,
                              results_dir=results_dir, run_id=run_id,
                              event_bus=event_bus)
                    if args.dry_run:
                        log.info("[DRY RUN] Would run: %s", mname)
                        _emit(bus, Event, EventType, "module_skip", source=mname,
                              name=mname, reason="dry run")
                        async with _progress_lock:
                            modules_completed += 1
                            pct = round(modules_completed / total_modules * 100) if total_modules else 0
                        _emit(bus, Event, EventType, "module_progress", source=mname,
                              name=mname, progress=pct)
                        return [], []
                    _emit(bus, Event, EventType, "module_start", source=mname,
                          name=mname, phase=phase_num)
                    # Emit current progress at module start
                    async with _progress_lock:
                        pct = round(modules_completed / total_modules * 100) if total_modules else 0
                    _emit(bus, Event, EventType, "module_progress", source=mname,
                          name=mname, progress=pct)
                    if opsec and hasattr(opsec, 'jitter'):
                        await opsec.jitter()
                    result = await mod.run()
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
                        async with _progress_lock:
                            modules_completed += 1
                            pct = (
                                round(modules_completed / total_modules * 100)
                                if total_modules
                                else 0
                            )
                        _emit(
                            bus,
                            Event,
                            EventType,
                            "module_skip",
                            source=mname,
                            name=mname,
                            reason=reason,
                            outcome="not_tested",
                        )
                        _emit(
                            bus,
                            Event,
                            EventType,
                            "module_progress",
                            source=mname,
                            name=mname,
                            progress=pct,
                        )
                        return [], []
                    merge_module_output_extra(cfg.extra, module_config.extra)
                    async with _progress_lock:
                        modules_completed += 1
                        coverage_completed.add(mname)
                        pct = round(modules_completed / total_modules * 100) if total_modules else 0
                    _emit(bus, Event, EventType, "module_complete", source=mname,
                          name=mname, findings_count=len(result.findings))
                    _emit(bus, Event, EventType, "module_progress", source=mname,
                          name=mname, progress=pct)
                    for finding in result.findings:
                        _emit(bus, Event, EventType, "finding_new", source=mname,
                              **finding.to_dict())
                        if eng_bus:
                            eng_bus.publish(finding)
                    if attack_chain:
                        for finding in result.findings:
                            attack_chain.ingest_finding(finding.to_dict())
                    return result.findings, []
                except Exception as exc:
                    if ctrl.is_aborted or getattr(exc, "reason_code", "") == "cancelled":
                        aborted = True
                        async with _progress_lock:
                            modules_completed += 1
                        _emit(
                            bus, Event, EventType, "module_skip",
                            source=mname, name=mname,
                            reason="cancelled", outcome="canceled",
                        )
                        return [], []
                    safe_error = str(redact_authorization_value(str(exc)))
                    log.error("Module %s failed: %s", mname, safe_error)
                    async with _progress_lock:
                        modules_completed += 1
                        pct = round(modules_completed / total_modules * 100) if total_modules else 0
                    _emit(bus, Event, EventType, "module_fail", source=mname,
                          name=mname, error=safe_error)
                    _emit(bus, Event, EventType, "module_progress", source=mname,
                          name=mname, progress=pct)
                    return [], [f"{mname}: {safe_error}"]

        # Check pause before dispatching the phase
        if ctrl.is_paused:
            _emit(bus, Event, EventType, "scan_paused", source="netforge")
            await ctrl.wait_if_paused()
            if ctrl.is_aborted:
                aborted = True
                break
            _emit(bus, Event, EventType, "scan_resumed", source="netforge")

        phase_results = await asyncio.gather(*[_exec(m) for m in filtered])
        for findings, errs in phase_results:
            all_findings.extend(findings)
            errors.extend(errs)
        if ctrl.is_aborted:
            aborted = True

        # ── Emit: phase_complete ──────────────────────────────────────
        phase_duration = time.monotonic() - phase_start
        _emit(bus, Event, EventType, "phase_complete", source="netforge",
              number=phase_num, name=phase_name, duration=round(phase_duration, 1))

        # After each phase: check attack chain for recommended actions
        if attack_chain and phase_num in (6, 7, 8, 9, 10, 11, 12):
            actions = attack_chain.recommend_next()
            if actions:
                log.info("[CHAIN] %d recommended actions after phase %d",
                         len(actions), phase_num)
                for a in actions[:5]:
                    log.info("  [%s] %s → %s", a.phase.value, a.module, a.description)

    elapsed = time.monotonic() - start_time
    status = "aborted" if aborted else ("failed" if errors else "completed")
    run.ended_at = datetime.now(timezone.utc)
    run.status = status
    db_session.commit()

    if aborted:
        _emit(bus, Event, EventType, "scan_aborted", source="netforge",
              reason="operator", target=safe_target_display(cfg.target),
              findings=len(all_findings), duration=round(elapsed, 1))
    elif errors:
        _emit(bus, Event, EventType, "scan_interrupted", source="netforge",
              target=safe_target_display(cfg.target), findings=len(all_findings),
              duration=round(elapsed, 1), errors=errors)
    else:
        _emit(bus, Event, EventType, "scan_complete", source="netforge",
              target=safe_target_display(cfg.target), findings=len(all_findings),
              duration=round(elapsed, 1))

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

    if stealth_session_key and dump_stealth_log:
        log_records = dump_stealth_log(
            results_dir / "stealth.db", stealth_session_key,
            output_path=results_dir / "stealth_log_decrypted.json",
        )
        from common.logger import console as _console
        stealth_label = (
            "SCAN ABORTED (STEALTH)"
            if aborted
            else ("SCAN FAILED (STEALTH)" if errors else "SCAN COMPLETE (STEALTH)")
        )
        stealth_color = "yellow" if aborted else ("red" if errors else "green")
        _console.print(f"\n[bold {stealth_color}]═══ {stealth_label} ═══[/bold {stealth_color}]")
        _console.print(f"  Duration: {elapsed:.1f}s | Findings: {len(all_findings)}")
        opsec_stats = cfg.extra.get('opsec_stats', {})
        _console.print(f"  OpSec:    {cfg.extra.get('opsec_level', 'normal')} | Requests: {opsec_stats.get('requests', 0)} | Decoys: {opsec_stats.get('decoys_injected', 0)}")
        _console.print(f"  Results:  {results_dir}")
        _console.print(f"  Stealth log: {len(log_records)} records decrypted")
    else:
        label = (
            "SCAN ABORTED"
            if aborted
            else "SCAN FAILED"
            if errors
            else ("SCAN COMPLETE" if not args.red_team else "RED TEAM ENGAGEMENT COMPLETE")
        )
        color = "yellow" if aborted else ("red" if errors or args.red_team else "green")
        console.print(f"\n[bold {color}]═══ {label} ═══[/bold {color}]")
        console.print(f"  Duration: {elapsed:.1f}s | Findings: {len(all_findings)}")
        opsec_stats = cfg.extra.get('opsec_stats', {})
        console.print(f"  OpSec:    {cfg.extra.get('opsec_level', 'normal')} | Requests: {opsec_stats.get('requests', 0)} | Decoys: {opsec_stats.get('decoys_injected', 0)}")
        if attack_chain:
            console.print(f"  Chain:    {attack_chain.stats['compromised_hosts']} hosts compromised | {attack_chain.stats['valid_creds']} creds")
        console.print(f"  Results:  {results_dir}")

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
            framework=ENGINE_NAME,
            target=cfg.target,
            manifest=RunCompletionManifest(
                planned_capabilities=planned_capabilities,
                completed_capabilities=tuple(coverage_completed),
                status=status,
                completed_at=run.ended_at,
                engine_version=VERSION,
            ),
        )
        run_truth = {
            "state": "persisted",
            "run_id": finalized.truth.run_id,
            "collection_status": finalized.truth.collection_status.value,
            "coverage_complete": finalized.truth.coverage_complete,
            "delta_state": finalized.delta.get(
                "comparison_state",
                "inconclusive",
            ),
        }
    except RunFinalizationError as exc:
        run_truth = {
            "state": "unavailable",
            "reason_code": exc.reason_code,
        }

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
    authorization = getattr(args, "_authorization_envelope", None)
    _apply_launch_context(cfg, args, args.target, confirmations, authorization)

    if not args.dry_run:
        authorization_decision = _consume_engine_authorization(cfg)
        if not authorization_decision.allowed:
            log.warning(
                "Engine authorization denied reason_code=%s",
                authorization_decision.reason_code,
            )
            return {
                "status": "not_authorized",
                "findings": 0,
                "errors": [authorization_decision.reason],
                "duration": 0.0,
                "dry_run": False,
                "authorized": False,
                "reason_code": authorization_decision.reason_code,
                "reason": authorization_decision.reason,
            }

    if args.dry_run:
        results_dir = Path(args.output).expanduser() if args.output else Path.cwd()
    else:
        results_dir = setup_results(
            args.engagement,
            args.target,
            args.resume,
            args.output,
        )

    return await run_scan(cfg, args, results_dir, event_bus, scan_control)


def _summary_exit_code(summary: Mapping[str, Any] | None) -> int:
    return 0 if summary and summary.get("status") == "completed" else 1


async def main() -> int:
    args = parse_args()
    if _has_direct_secret_args(args):
        log.error("Direct secret-bearing credential options are disabled")
        return 1
    launch_decision, confirmations = _prepare_cli_confirmation(args)
    if not launch_decision.allowed:
        _audit_scope_denial(args, launch_decision, target=args.target)
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
    set_auto_confirm(args.auto_confirm)

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
    _apply_launch_context(cfg, args, args.target, confirmations, authorization)

    if not args.dry_run:
        authorization_decision = _consume_engine_authorization(cfg)
        if not authorization_decision.allowed:
            log.warning(
                "Engine authorization denied reason_code=%s",
                authorization_decision.reason_code,
            )
            sys.exit(1)

    if args.dry_run:
        results_dir = Path(args.output).expanduser() if args.output else Path.cwd()
    else:
        results_dir = setup_results(
            args.engagement,
            args.target,
            args.resume,
            args.output,
        )

    if not args.dry_run:
        ask_internet_permission("CVE database updates, nuclei templates")

    if args.dry_run:
        return _summary_exit_code(await run_scan(cfg, args, results_dir))

    # OOB callbacks require their own delegated destination authorization.
    _collab_domain = getattr(args, 'collab_domain', None) or os.environ.get('FORGE_COLLAB_DOMAIN', '')
    if _collab_domain:
        cfg.extra["collab_outbound_state"] = "outbound_policy_unsupported"
        log.warning(
            "ForgeCollab OOB not tested: outbound_policy_unsupported"
        )

    # Wire EventBus — remote when dashboard URL given, local otherwise
    event_bus = None
    if args.dashboard_url:
        try:
            from common.dashboard.event_bus import RemoteEventBus
            event_bus = RemoteEventBus(args.dashboard_url, run_id="netforge")
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
            event_bus = EventBus(run_id="netforge")
            event_bus.start()
        except ImportError:
            pass

    try:
        with resolved_process_credentials() as credentials:
            _apply_resolved_credentials(args, credentials)
            summary = await run_scan(cfg, args, results_dir, event_bus=event_bus)
    except ValueError as exc:
        log.error("Protected credential handoff rejected: %s", redact_authorization_value(exc))
        return 1
    finally:
        _clear_resolved_credentials(args)
        if event_bus and hasattr(event_bus, "stop"):
            event_bus.stop()
    return _summary_exit_code(summary)


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
