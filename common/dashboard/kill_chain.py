"""Kill chain phase mapping and progression calculator.

Maps forge-suite modules to Lockheed Martin Cyber Kill Chain phases
and MITRE ATT&CK tactics for real-time kill chain visualization
in the dashboard.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Mapping

log = logging.getLogger("forge.dashboard.killchain")


class KillChainPhase(IntEnum):
    """Lockheed Martin Cyber Kill Chain phases."""
    RECONNAISSANCE       = 1
    WEAPONIZATION        = 2
    DELIVERY             = 3
    EXPLOITATION         = 4
    INSTALLATION         = 5
    COMMAND_AND_CONTROL  = 6
    ACTIONS_ON_OBJECTIVE = 7


PHASE_LABELS: dict[KillChainPhase, str] = {
    KillChainPhase.RECONNAISSANCE:       "Recon",
    KillChainPhase.WEAPONIZATION:        "Weaponize",
    KillChainPhase.DELIVERY:             "Deliver",
    KillChainPhase.EXPLOITATION:         "Exploit",
    KillChainPhase.INSTALLATION:         "Install",
    KillChainPhase.COMMAND_AND_CONTROL:  "C2",
    KillChainPhase.ACTIONS_ON_OBJECTIVE: "Actions",
}

PHASE_ICONS: dict[KillChainPhase, str] = {
    KillChainPhase.RECONNAISSANCE:       "🔍",
    KillChainPhase.WEAPONIZATION:        "⚔️",
    KillChainPhase.DELIVERY:             "📨",
    KillChainPhase.EXPLOITATION:         "💥",
    KillChainPhase.INSTALLATION:         "📥",
    KillChainPhase.COMMAND_AND_CONTROL:  "🎯",
    KillChainPhase.ACTIONS_ON_OBJECTIVE: "🏴",
}

PHASE_COLORS: dict[KillChainPhase, str] = {
    KillChainPhase.RECONNAISSANCE:       "#85c1e9",
    KillChainPhase.WEAPONIZATION:        "#82e0aa",
    KillChainPhase.DELIVERY:             "#f7dc6f",
    KillChainPhase.EXPLOITATION:         "#f5a623",
    KillChainPhase.INSTALLATION:         "#e94560",
    KillChainPhase.COMMAND_AND_CONTROL:  "#c39bd3",
    KillChainPhase.ACTIONS_ON_OBJECTIVE: "#ff6b6b",
}

# ── Module → Kill Chain Phase mapping ─────────────────────────────────

# WebForge modules
WEBFORGE_KILL_CHAIN: dict[str, KillChainPhase] = {
    # Recon
    "tech_detect":        KillChainPhase.RECONNAISSANCE,
    "cms_detect":         KillChainPhase.RECONNAISSANCE,
    "dir_fuzzer":         KillChainPhase.RECONNAISSANCE,
    "vhost_enum":         KillChainPhase.RECONNAISSANCE,
    "js_analyzer":        KillChainPhase.RECONNAISSANCE,
    "link_crawler":       KillChainPhase.RECONNAISSANCE,
    "robots_sitemap":     KillChainPhase.RECONNAISSANCE,
    "api_discover":       KillChainPhase.RECONNAISSANCE,
    "param_discover":     KillChainPhase.RECONNAISSANCE,
    "subdomain_takeover": KillChainPhase.RECONNAISSANCE,
    "ssl_audit":          KillChainPhase.RECONNAISSANCE,
    "cert_inspect":       KillChainPhase.RECONNAISSANCE,
    "hsts_check":         KillChainPhase.RECONNAISSANCE,
    "header_audit":       KillChainPhase.RECONNAISSANCE,
    "cors_check":         KillChainPhase.RECONNAISSANCE,
    "csp_audit":          KillChainPhase.RECONNAISSANCE,
    "cookie_audit":       KillChainPhase.RECONNAISSANCE,
    "sri_check":          KillChainPhase.RECONNAISSANCE,
    "clickjacking":       KillChainPhase.RECONNAISSANCE,
    # Exploitation
    "sqli_scanner":       KillChainPhase.EXPLOITATION,
    "xss_scanner":        KillChainPhase.EXPLOITATION,
    "xxe_scanner":        KillChainPhase.EXPLOITATION,
    "ssti_scanner":       KillChainPhase.EXPLOITATION,
    "cmd_inject":         KillChainPhase.EXPLOITATION,
    "ldap_inject":        KillChainPhase.EXPLOITATION,
    "nosql_inject":       KillChainPhase.EXPLOITATION,
    "jsonp_inject":       KillChainPhase.EXPLOITATION,
    "host_header_inject": KillChainPhase.EXPLOITATION,
    "crlf_inject":        KillChainPhase.EXPLOITATION,
    "parameter_pollution": KillChainPhase.EXPLOITATION,
    "http_smuggling":     KillChainPhase.EXPLOITATION,
    "deserialization":    KillChainPhase.EXPLOITATION,
    # Delivery (auth/access attacks = delivery vector)
    "session_audit":      KillChainPhase.DELIVERY,
    "password_policy":    KillChainPhase.DELIVERY,
    "jwt_audit":          KillChainPhase.DELIVERY,
    "oauth_check":        KillChainPhase.DELIVERY,
    "login_brute":        KillChainPhase.DELIVERY,
    "mfa_bypass":         KillChainPhase.DELIVERY,
    "totp_bypass":        KillChainPhase.DELIVERY,
    "idor_scanner":       KillChainPhase.EXPLOITATION,
    "priv_esc":           KillChainPhase.EXPLOITATION,
    "path_traversal":     KillChainPhase.EXPLOITATION,
    "forced_browse":      KillChainPhase.DELIVERY,
    "403_bypass":         KillChainPhase.DELIVERY,
    "mass_assignment":    KillChainPhase.EXPLOITATION,
    # API (weaponization — building attack payloads)
    "rest_audit":         KillChainPhase.WEAPONIZATION,
    "graphql_audit":      KillChainPhase.WEAPONIZATION,
    "soap_audit":         KillChainPhase.WEAPONIZATION,
    "api_rate_check":     KillChainPhase.WEAPONIZATION,
    # File attacks (installation)
    "ssrf_scanner":       KillChainPhase.EXPLOITATION,
    "lfi_rfi":            KillChainPhase.EXPLOITATION,
    "upload_bypass":      KillChainPhase.INSTALLATION,
    # Business logic
    "open_redirect":      KillChainPhase.DELIVERY,
    "price_tamper":       KillChainPhase.ACTIONS_ON_OBJECTIVE,
    "workflow_bypass":    KillChainPhase.ACTIONS_ON_OBJECTIVE,
    "race_condition":     KillChainPhase.EXPLOITATION,
    # Advanced
    "websocket_audit":    KillChainPhase.WEAPONIZATION,
    "http2_audit":        KillChainPhase.WEAPONIZATION,
    "cache_poison":       KillChainPhase.INSTALLATION,
    "cache_deception":    KillChainPhase.EXPLOITATION,
    "prototype_poll":     KillChainPhase.EXPLOITATION,
    "email_security":     KillChainPhase.DELIVERY,
    "account_takeover":   KillChainPhase.ACTIONS_ON_OBJECTIVE,
    "zip_slip":           KillChainPhase.INSTALLATION,
    # Whitebox
    "source_audit":       KillChainPhase.RECONNAISSANCE,
    "secret_scan":        KillChainPhase.RECONNAISSANCE,
    "dep_audit":          KillChainPhase.RECONNAISSANCE,
    "config_audit":       KillChainPhase.RECONNAISSANCE,
    "code_flow":          KillChainPhase.RECONNAISSANCE,
}

# NetForge modules
NETFORGE_KILL_CHAIN: dict[str, KillChainPhase] = {
    # Discovery = recon
    "host_discover":     KillChainPhase.RECONNAISSANCE,
    "port_scanner":      KillChainPhase.RECONNAISSANCE,
    "service_id":        KillChainPhase.RECONNAISSANCE,
    "os_detect":         KillChainPhase.RECONNAISSANCE,
    "topology_map":      KillChainPhase.RECONNAISSANCE,
    # External
    "dns_recon":         KillChainPhase.RECONNAISSANCE,
    "ssl_audit":         KillChainPhase.RECONNAISSANCE,
    "smtp_check":        KillChainPhase.RECONNAISSANCE,
    "firewall_detect":   KillChainPhase.RECONNAISSANCE,
    "exposure_check":    KillChainPhase.RECONNAISSANCE,
    "firewall_rule_check": KillChainPhase.RECONNAISSANCE,
    # Internal
    "arp_monitor":       KillChainPhase.RECONNAISSANCE,
    "dhcp_audit":        KillChainPhase.RECONNAISSANCE,
    "vlan_check":        KillChainPhase.RECONNAISSANCE,
    "cdp_ldp":           KillChainPhase.RECONNAISSANCE,
    "ipv6_audit":        KillChainPhase.RECONNAISSANCE,
    "llmnr_detect":      KillChainPhase.RECONNAISSANCE,
    "upnp_audit":        KillChainPhase.RECONNAISSANCE,
    # Services
    "smb_audit":         KillChainPhase.WEAPONIZATION,
    "ftp_audit":         KillChainPhase.WEAPONIZATION,
    "ssh_audit":         KillChainPhase.WEAPONIZATION,
    "telnet_audit":      KillChainPhase.WEAPONIZATION,
    "rdp_audit":         KillChainPhase.WEAPONIZATION,
    "snmp_audit":        KillChainPhase.WEAPONIZATION,
    "ldap_audit":        KillChainPhase.WEAPONIZATION,
    "nfs_audit":         KillChainPhase.WEAPONIZATION,
    "mssql_audit":       KillChainPhase.WEAPONIZATION,
    "mysql_audit":       KillChainPhase.WEAPONIZATION,
    "redis_audit":       KillChainPhase.WEAPONIZATION,
    "mongo_audit":       KillChainPhase.WEAPONIZATION,
    "elastic_audit":     KillChainPhase.WEAPONIZATION,
    "vnc_audit":         KillChainPhase.WEAPONIZATION,
    "tftp_audit":        KillChainPhase.WEAPONIZATION,
    "printer_audit":     KillChainPhase.WEAPONIZATION,
    "voip_audit":        KillChainPhase.WEAPONIZATION,
    "ipmi_audit":        KillChainPhase.WEAPONIZATION,
    "kubernetes_audit":  KillChainPhase.WEAPONIZATION,
    "docker_audit":      KillChainPhase.WEAPONIZATION,
    "cloud_metadata":    KillChainPhase.EXPLOITATION,
    "ics_audit":         KillChainPhase.WEAPONIZATION,
    # Vuln
    "cve_matcher":       KillChainPhase.WEAPONIZATION,
    "nmap_vulns":        KillChainPhase.WEAPONIZATION,
    "nuclei_runner":     KillChainPhase.EXPLOITATION,
    "exploit_suggest":   KillChainPhase.WEAPONIZATION,
    # Bruteforce
    "smart_brute":       KillChainPhase.DELIVERY,
    "hydra_wrap":        KillChainPhase.DELIVERY,
    "wordlist_mgr":      KillChainPhase.DELIVERY,
    "cred_spray":        KillChainPhase.DELIVERY,
    # Post-exploit
    "pivot_finder":      KillChainPhase.COMMAND_AND_CONTROL,
    "tunnel_suggest":    KillChainPhase.COMMAND_AND_CONTROL,
    "loot_parse":        KillChainPhase.ACTIONS_ON_OBJECTIVE,
}

# ADForge modules
ADFORGE_KILL_CHAIN: dict[str, KillChainPhase] = {
    # Unauth recon
    "null_session":      KillChainPhase.RECONNAISSANCE,
    "ldap_anon":         KillChainPhase.RECONNAISSANCE,
    "rid_cycle":         KillChainPhase.RECONNAISSANCE,
    "kerb_user_enum":    KillChainPhase.RECONNAISSANCE,
    "dns_enum":          KillChainPhase.RECONNAISSANCE,
    # Domain enum
    "domain_enum":       KillChainPhase.RECONNAISSANCE,
    "user_enum":         KillChainPhase.RECONNAISSANCE,
    "group_enum":        KillChainPhase.RECONNAISSANCE,
    "computer_enum":     KillChainPhase.RECONNAISSANCE,
    "gpo_enum":          KillChainPhase.RECONNAISSANCE,
    "ou_enum":           KillChainPhase.RECONNAISSANCE,
    "trust_enum":        KillChainPhase.RECONNAISSANCE,
    "schema_enum":       KillChainPhase.RECONNAISSANCE,
    "spn_enum":          KillChainPhase.RECONNAISSANCE,
    "asrep_enum":        KillChainPhase.RECONNAISSANCE,
    "laps_enum":         KillChainPhase.RECONNAISSANCE,
    "gmsa_enum":         KillChainPhase.RECONNAISSANCE,
    "adcs_enum":         KillChainPhase.RECONNAISSANCE,
    "acl_enum":          KillChainPhase.RECONNAISSANCE,
    "fine_grained_psp":  KillChainPhase.RECONNAISSANCE,
    "admin_count":       KillChainPhase.RECONNAISSANCE,
    "inactive_account":  KillChainPhase.RECONNAISSANCE,
    "service_account_audit": KillChainPhase.RECONNAISSANCE,
    "rc4_check":         KillChainPhase.RECONNAISSANCE,
    "entra_hybrid":      KillChainPhase.RECONNAISSANCE,
    # Attacks
    "kerberoast":        KillChainPhase.EXPLOITATION,
    "asrep_roast":       KillChainPhase.EXPLOITATION,
    "password_spray":    KillChainPhase.DELIVERY,
    "ntlm_relay":        KillChainPhase.EXPLOITATION,
    "pass_hash":         KillChainPhase.EXPLOITATION,
    "pass_ticket":       KillChainPhase.EXPLOITATION,
    "golden_ticket":     KillChainPhase.INSTALLATION,
    "silver_ticket":     KillChainPhase.INSTALLATION,
    "dcsync":            KillChainPhase.ACTIONS_ON_OBJECTIVE,
    "zerologon":         KillChainPhase.EXPLOITATION,
    "petitpotam":        KillChainPhase.EXPLOITATION,
    "nopac":             KillChainPhase.EXPLOITATION,
    "printspooler":      KillChainPhase.EXPLOITATION,
    "ms14_068":          KillChainPhase.EXPLOITATION,
    "dfscoerce":         KillChainPhase.EXPLOITATION,
    "shadowcoerce":      KillChainPhase.EXPLOITATION,
    "certifried":        KillChainPhase.EXPLOITATION,
    "pre2000_computers": KillChainPhase.EXPLOITATION,
    # ACL abuse
    "acl_scanner":       KillChainPhase.WEAPONIZATION,
    "dacl_abuse":        KillChainPhase.EXPLOITATION,
    "forcechangepw":     KillChainPhase.EXPLOITATION,
    "add_member":        KillChainPhase.EXPLOITATION,
    "shadow_creds":      KillChainPhase.EXPLOITATION,
    # GPO / delegation
    "gpo_scanner":       KillChainPhase.WEAPONIZATION,
    "gpo_path_check":    KillChainPhase.WEAPONIZATION,
    "linked_gpo_check":  KillChainPhase.WEAPONIZATION,
    "uncons_deleg":      KillChainPhase.EXPLOITATION,
    "cons_deleg":        KillChainPhase.EXPLOITATION,
    "rbcd_attack":       KillChainPhase.EXPLOITATION,
    # ADCS
    "esc1_check":        KillChainPhase.EXPLOITATION,
    "esc2_check":        KillChainPhase.EXPLOITATION,
    "esc3_check":        KillChainPhase.EXPLOITATION,
    "esc4_check":        KillChainPhase.EXPLOITATION,
    "esc6_check":        KillChainPhase.EXPLOITATION,
    "esc7_check":        KillChainPhase.EXPLOITATION,
    "esc8_check":        KillChainPhase.EXPLOITATION,
    "esc9_check":        KillChainPhase.EXPLOITATION,
    "esc10_check":       KillChainPhase.EXPLOITATION,
    "esc11_check":       KillChainPhase.EXPLOITATION,
    "esc13_check":       KillChainPhase.EXPLOITATION,
    "esc14_check":       KillChainPhase.EXPLOITATION,
    # Lateral
    "smb_exec":          KillChainPhase.COMMAND_AND_CONTROL,
    "wmi_exec":          KillChainPhase.COMMAND_AND_CONTROL,
    "winrm_exec":        KillChainPhase.COMMAND_AND_CONTROL,
    "psexec_exec":       KillChainPhase.COMMAND_AND_CONTROL,
    "rdp_check":         KillChainPhase.COMMAND_AND_CONTROL,
    # Post
    "secretsdump":       KillChainPhase.ACTIONS_ON_OBJECTIVE,
    "loot_collector":    KillChainPhase.ACTIONS_ON_OBJECTIVE,
    "da_check":          KillChainPhase.ACTIONS_ON_OBJECTIVE,
    "persist_check":     KillChainPhase.INSTALLATION,
    "attack_path":       KillChainPhase.WEAPONIZATION,
    "bitlocker_check":   KillChainPhase.ACTIONS_ON_OBJECTIVE,
    "recycle_bin":       KillChainPhase.ACTIONS_ON_OBJECTIVE,
    "ad_backup_check":   KillChainPhase.ACTIONS_ON_OBJECTIVE,
    "privileged_group_mon": KillChainPhase.ACTIONS_ON_OBJECTIVE,
    "gpp_password":      KillChainPhase.ACTIONS_ON_OBJECTIVE,
    "adminsdholder":     KillChainPhase.INSTALLATION,
}

# AIForge modules (new — LLM/AI red teaming)
AIFORGE_KILL_CHAIN: dict[str, KillChainPhase] = {
    "llm_fingerprint":    KillChainPhase.RECONNAISSANCE,
    "system_prompt_extract": KillChainPhase.RECONNAISSANCE,
    "guardrail_probe":    KillChainPhase.RECONNAISSANCE,
    "prompt_inject":      KillChainPhase.EXPLOITATION,
    "indirect_inject":    KillChainPhase.EXPLOITATION,
    "jailbreak_test":     KillChainPhase.EXPLOITATION,
    "rag_poison":         KillChainPhase.INSTALLATION,
    "tool_abuse":         KillChainPhase.EXPLOITATION,
    "data_exfil":         KillChainPhase.ACTIONS_ON_OBJECTIVE,
    "training_extract":   KillChainPhase.ACTIONS_ON_OBJECTIVE,
    "output_manipulation": KillChainPhase.EXPLOITATION,
    "context_overflow":   KillChainPhase.DELIVERY,
    "encoding_bypass":    KillChainPhase.DELIVERY,
    "multi_turn_attack":  KillChainPhase.EXPLOITATION,
    "agent_hijack":       KillChainPhase.COMMAND_AND_CONTROL,
    "pii_leak_test":      KillChainPhase.ACTIONS_ON_OBJECTIVE,
}

# Combined mapping for all frameworks
ALL_KILL_CHAIN: dict[str, KillChainPhase] = {
    **WEBFORGE_KILL_CHAIN,
    **NETFORGE_KILL_CHAIN,
    **ADFORGE_KILL_CHAIN,
    **AIFORGE_KILL_CHAIN,
}


@dataclass
class KillChainState:
    """Live state of kill chain progression for dashboard rendering."""

    phase_findings: dict[KillChainPhase, int] = field(
        default_factory=lambda: {p: 0 for p in KillChainPhase}
    )
    phase_modules_run: dict[KillChainPhase, int] = field(
        default_factory=lambda: {p: 0 for p in KillChainPhase}
    )
    phase_modules_total: dict[KillChainPhase, int] = field(
        default_factory=lambda: {p: 0 for p in KillChainPhase}
    )
    active_phase: KillChainPhase | None = None
    highest_phase_reached: KillChainPhase = KillChainPhase.RECONNAISSANCE
    compromise_achieved: bool = False
    _finding_identities: set[str] = field(default_factory=set, repr=False)
    _completion_identities: set[str] = field(default_factory=set, repr=False)

    def record_finding(
        self,
        module_name: str,
        *,
        verification_state: str = "unknown",
        observation_id: str = "",
        evidence_refs: list[str] | tuple[str, ...] = (),
    ) -> bool:
        """Record only a canonical verified finding with evidence lineage."""
        if (
            str(verification_state).lower() != "verified"
            or not str(observation_id)
            or not tuple(evidence_refs)
        ):
            return False
        identity = "\x1f".join(
            (str(observation_id), module_name, *sorted(str(ref) for ref in evidence_refs))
        )
        if identity in self._finding_identities:
            return False
        self._finding_identities.add(identity)
        phase = ALL_KILL_CHAIN.get(module_name, KillChainPhase.RECONNAISSANCE)
        self.phase_findings[phase] = self.phase_findings.get(phase, 0) + 1
        if phase.value > self.highest_phase_reached.value:
            self.highest_phase_reached = phase
        if phase == KillChainPhase.ACTIONS_ON_OBJECTIVE:
            self.compromise_achieved = True
        return True

    def record_module_start(self, module_name: str) -> None:
        """Track which kill chain phase is currently active."""
        phase = ALL_KILL_CHAIN.get(module_name, KillChainPhase.RECONNAISSANCE)
        self.active_phase = phase

    def record_module_complete(
        self,
        module_name: str,
        *,
        canonical_job_id: str = "",
        outcome: str = "",
        evidence_refs: list[str] | tuple[str, ...] = (),
    ) -> bool:
        """Track only signed/evidenced canonical success, never an event claim."""
        if (
            not str(canonical_job_id)
            or str(outcome).lower() != "success"
            or not tuple(evidence_refs)
        ):
            return False
        identity = "\x1f".join(
            (
                str(canonical_job_id),
                module_name,
                *sorted(str(ref) for ref in evidence_refs),
            )
        )
        if identity in self._completion_identities:
            return False
        self._completion_identities.add(identity)
        phase = ALL_KILL_CHAIN.get(module_name, KillChainPhase.RECONNAISSANCE)
        self.phase_modules_run[phase] = self.phase_modules_run.get(phase, 0) + 1
        return True

    def set_module_totals(self, module_names: list[str]) -> None:
        """Calculate total modules per kill chain phase."""
        for name in module_names:
            phase = ALL_KILL_CHAIN.get(name, KillChainPhase.RECONNAISSANCE)
            self.phase_modules_total[phase] = self.phase_modules_total.get(phase, 0) + 1

    def completion_pct(self) -> float:
        """Overall kill chain completion percentage."""
        total = sum(self.phase_modules_total.values())
        done = sum(self.phase_modules_run.values())
        return (done / total * 100) if total > 0 else 0.0

    def phase_completion_pct(self, phase: KillChainPhase) -> float:
        """Completion percentage for a single phase."""
        total = self.phase_modules_total.get(phase, 0)
        done = self.phase_modules_run.get(phase, 0)
        return (done / total * 100) if total > 0 else 0.0

    def to_dict(self) -> dict[str, Any]:
        """Serialize for JSON/WebSocket transmission."""
        phases = []
        for p in KillChainPhase:
            phases.append({
                "phase": p.value,
                "name": PHASE_LABELS[p],
                "icon": PHASE_ICONS[p],
                "color": PHASE_COLORS[p],
                "findings": self.phase_findings.get(p, 0),
                "modules_run": self.phase_modules_run.get(p, 0),
                "modules_total": self.phase_modules_total.get(p, 0),
                "completion_pct": round(self.phase_completion_pct(p), 1),
                "is_active": self.active_phase == p,
                "is_reached": p.value <= self.highest_phase_reached.value,
            })
        return {
            "phases": phases,
            "active_phase": self.active_phase.value if self.active_phase else None,
            "highest_reached": self.highest_phase_reached.value,
            "overall_completion": round(self.completion_pct(), 1),
            "compromise_achieved": self.compromise_achieved,
            "truth_source": "canonical_job_outcome_and_evidence",
        }

    def render_ascii(self, width: int = 70) -> str:
        """Render an ASCII kill chain for terminal display.

        Returns a multi-line string showing the kill chain pipeline
        with highlighted active phase and finding counts.
        """
        lines: list[str] = []
        bar_parts: list[str] = []

        for p in KillChainPhase:
            findings = self.phase_findings.get(p, 0)
            is_active = self.active_phase == p
            is_reached = p.value <= self.highest_phase_reached.value

            label = PHASE_LABELS[p]
            if is_active:
                cell = f"[>>>{label}<<<]"
            elif is_reached and findings > 0:
                cell = f"[{label}:{findings}]"
            elif is_reached:
                cell = f"[{label}:✓]"
            else:
                cell = f"[{label}:·]"
            bar_parts.append(cell)

        chain = "→".join(bar_parts)
        lines.append(chain)

        status = "🏴 COMPROMISED" if self.compromise_achieved else "⏳ IN PROGRESS"
        lines.append(f"  Status: {status} | Progress: {self.completion_pct():.0f}%")

        return "\n".join(lines)


# ── OWASP / MITRE coverage tracking ──────────────────────────────────

OWASP_TOP_10_2021 = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable Components",
    "A07": "Auth Failures",
    "A08": "Software Integrity",
    "A09": "Logging Failures",
    "A10": "SSRF",
}

# Module → OWASP category mapping
MODULE_OWASP: dict[str, list[str]] = {
    "sqli_scanner":      ["A03"],
    "xss_scanner":       ["A03"],
    "ssti_scanner":      ["A03"],
    "cmd_inject":        ["A03"],
    "ldap_inject":       ["A03"],
    "nosql_inject":      ["A03"],
    "xxe_scanner":       ["A03"],
    "idor_scanner":      ["A01"],
    "priv_esc":          ["A01"],
    "path_traversal":    ["A01"],
    "forced_browse":     ["A01"],
    "403_bypass":        ["A01"],
    "mass_assignment":   ["A01"],
    "cors_check":        ["A01"],
    "jwt_audit":         ["A02", "A07"],
    "ssl_audit":         ["A02"],
    "cert_inspect":      ["A02"],
    "session_audit":     ["A07"],
    "login_brute":       ["A07"],
    "mfa_bypass":        ["A07"],
    "oauth_check":       ["A07"],
    "password_policy":   ["A07"],
    "dep_audit":         ["A06"],
    "config_audit":      ["A05"],
    "header_audit":      ["A05"],
    "csp_audit":         ["A05"],
    "ssrf_scanner":      ["A10"],
    "deserialization":   ["A08"],
    "secret_scan":       ["A02"],
    "upload_bypass":     ["A04"],
    "race_condition":    ["A04"],
    "cache_poison":      ["A05"],
}

OWASP_LLM_TOP_10_2025 = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain Vulnerabilities",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}


def calculate_owasp_coverage(
    canonical_outcomes: list[Mapping[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Calculate OWASP coverage only from evidenced canonical success rows.

    Returns dict mapping OWASP ID → {name, covered, modules}.
    """
    completed_modules = [
        str(item.get("module") or "")
        for item in canonical_outcomes
        if str(item.get("outcome") or "").lower() == "success"
        and bool(item.get("canonical_job_id"))
        and bool(item.get("evidence_refs"))
    ]
    coverage: dict[str, dict[str, Any]] = {}
    for owasp_id, name in OWASP_TOP_10_2021.items():
        matching = [
            m for m in completed_modules
            if owasp_id in MODULE_OWASP.get(m, [])
        ]
        coverage[owasp_id] = {
            "name": name,
            "covered": len(matching) > 0,
            "modules": matching,
            "depth": len(matching),
        }
    return coverage


class TestKillChain:
    """Unit tests for kill_chain module."""

    def test_phase_labels_complete(self) -> None:
        for phase in KillChainPhase:
            assert phase in PHASE_LABELS

    def test_kill_chain_state_finding(self) -> None:
        state = KillChainState()
        state.record_finding(
            "sqli_scanner",
            verification_state="verified",
            observation_id="observation-fixture",
            evidence_refs=("artifact:fixture",),
        )
        assert state.phase_findings[KillChainPhase.EXPLOITATION] == 1
        assert state.highest_phase_reached == KillChainPhase.EXPLOITATION

    def test_kill_chain_compromise(self) -> None:
        state = KillChainState()
        state.record_finding(
            "dcsync",
            verification_state="verified",
            observation_id="observation-fixture",
            evidence_refs=("artifact:fixture",),
        )
        assert state.compromise_achieved is True

    def test_completion_pct(self) -> None:
        state = KillChainState()
        state.set_module_totals(["sqli_scanner", "xss_scanner"])
        state.record_module_complete(
            "sqli_scanner",
            canonical_job_id="job-fixture",
            outcome="success",
            evidence_refs=("artifact:fixture",),
        )
        assert state.completion_pct() == 50.0

    def test_ascii_render(self) -> None:
        state = KillChainState()
        state.set_module_totals(["sqli_scanner"])
        state.record_module_start("sqli_scanner")
        output = state.render_ascii()
        assert "Exploit" in output

    def test_owasp_coverage(self) -> None:
        coverage = calculate_owasp_coverage([
            {
                "module": "sqli_scanner",
                "outcome": "success",
                "canonical_job_id": "job-sqli",
                "evidence_refs": ["artifact:sqli"],
            },
            {
                "module": "xss_scanner",
                "outcome": "success",
                "canonical_job_id": "job-xss",
                "evidence_refs": ["artifact:xss"],
            },
        ])
        assert coverage["A03"]["covered"] is True
        assert coverage["A03"]["depth"] == 2
        assert coverage["A01"]["covered"] is False

    def test_serialization(self) -> None:
        state = KillChainState()
        state.record_finding(
            "sqli_scanner",
            verification_state="verified",
            observation_id="observation-fixture",
            evidence_refs=("artifact:fixture",),
        )
        d = state.to_dict()
        assert "phases" in d
        assert len(d["phases"]) == 7
        assert d["compromise_achieved"] is False
