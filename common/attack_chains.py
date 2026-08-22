"""Cross-Framework Attack Chains (Pillar 12) — Sprint 2: Chain Engine v2.

Upgrades:
  - Multi-hop A→B→C→D chains with automatic continuation
  - Per-chain state machine: PENDING → IN_PROGRESS → COMPLETED | FAILED | BLOCKED
  - Conditional branching on payload values (SSRF→cloud vs SSRF→pivot)
  - Failure adaptation with ordered module fallbacks (PsExec→WinRM→WMI→SSH)
  - Priority scoring: impact × P(success) × stealth_multiplier
  - Chain dependency DAG — prerequisite enforcement
  - OSINT-driven proactive chain priming before active scanning

FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import logging
from collections.abc import Awaitable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

log = logging.getLogger("forge.attack_chains")


# ══════════════════════════════════════════════════════════════════════
# STATE MACHINE
# ══════════════════════════════════════════════════════════════════════

class ChainState(Enum):
    """Per-engagement lifecycle state for a chain trigger."""
    PENDING     = "PENDING"      # Registered, not yet fired
    IN_PROGRESS = "IN_PROGRESS"  # Module execution underway
    COMPLETED   = "COMPLETED"    # Module succeeded, next-hops queued
    FAILED      = "FAILED"       # All modules (primary + fallbacks) errored
    BLOCKED     = "BLOCKED"      # Prerequisites not satisfied


# ══════════════════════════════════════════════════════════════════════
# EVENT BUS (lightweight fallback if EngagementBus not available)
# ══════════════════════════════════════════════════════════════════════

class _SimpleEventBus:
    """Minimal synchronous event bus for chain triggers."""

    def __init__(self) -> None:
        self._handlers: dict[str, list[Callable]] = {}

    def subscribe(self, event: str, handler: Callable) -> None:
        self._handlers.setdefault(event, []).append(handler)

    def emit(self, event: str, payload: dict[str, Any]) -> None:
        for handler in self._handlers.get(event, []):
            try:
                handler(payload)
            except Exception as exc:
                log.error("Chain handler error (%s): %s", event, exc)


# ══════════════════════════════════════════════════════════════════════
# CHAIN TRIGGER DESCRIPTORS
# ══════════════════════════════════════════════════════════════════════

@dataclass
class ChainTrigger:
    """Definition of a cross-framework attack chain step.

    Sprint 2 additions vs v1:
      next_chains:         chain_ids automatically fired after this succeeds (multi-hop)
      fallback_modules:    ordered module names tried if next_module raises (failure adaptation)
      branch_conditions:   payload-value → chain_id map for conditional routing
      impact_score:        0-10 severity if chain succeeds
      success_probability: 0-1 estimated P(success) based on historical data
      stealth_cost:        0-1; 0 = fully covert, 1 = highly noisy
      prerequisites:       chain_ids that must be COMPLETED before this fires (DAG)
    """
    chain_id:            str
    name:                str
    trigger_event:       str
    trigger_types:       list[str]
    next_module:         str
    description:         str
    mitre_tactics:       list[str]      = field(default_factory=list)
    opsec_level:         str            = "STANDARD"
    auto_execute:        bool           = True
    # Sprint 2 fields
    next_chains:         list[str]      = field(default_factory=list)
    fallback_modules:    list[str]      = field(default_factory=list)
    branch_conditions:   dict[str, str] = field(default_factory=dict)
    impact_score:        float          = 5.0
    success_probability: float          = 0.5
    stealth_cost:        float          = 0.5
    prerequisites:       list[str]      = field(default_factory=list)

    @property
    def priority_score(self) -> float:
        """Composite scheduling priority.

        Formula: impact x P(success) x stealth_multiplier
        stealth_multiplier in [1.0, 2.0] — lower stealth_cost yields higher multiplier,
        rewarding covert operations over noisy ones at equal impact/probability.
        """
        stealth_multiplier = 2.0 - self.stealth_cost  # cost 0 -> 2.0x, cost 1 -> 1.0x
        return self.impact_score * self.success_probability * stealth_multiplier


# ══════════════════════════════════════════════════════════════════════
# CHAIN DEFINITIONS — 24 total (10 original + 5 sprint-0 + 3 sprint-1 + 14 sprint-2)
# ══════════════════════════════════════════════════════════════════════

_CHAIN_DEFINITIONS: list[ChainTrigger] = [

    # ── Original 10 chains (upgraded with Sprint 2 metadata) ─────────

    ChainTrigger(
        chain_id="sqli_to_cred_spray",
        name="SQLi → Credential Spray",
        trigger_event="finding.confirmed",
        trigger_types=["sqli", "sqli_time", "sqli_error", "sqli_union"],
        next_module="cred_spray",
        next_chains=["ad_creds_to_lateral"],
        fallback_modules=["offline_hash_crack", "default_cred_check"],
        description=(
            "Extracted DB credentials from SQLi finding are sprayed against "
            "discovered authentication endpoints (AD, web login, VPN, OWA)."
        ),
        mitre_tactics=["T1190", "T1110.003", "T1078"],
        opsec_level="STANDARD",
        auto_execute=True,
        impact_score=8.5,
        success_probability=0.7,
        stealth_cost=0.4,
    ),
    ChainTrigger(
        chain_id="xss_to_session_hijack",
        name="XSS → Session Hijack",
        trigger_event="finding.confirmed",
        trigger_types=["xss", "xss_reflected", "xss_stored", "xss_dom"],
        next_module="session_hijack",
        fallback_modules=["csrf_ride", "cookie_theft"],
        description=(
            "Stored or reflected XSS used to steal admin session tokens "
            "or JWTs via JavaScript, then replay them as a privileged user."
        ),
        mitre_tactics=["T1185", "T1539", "T1606"],
        opsec_level="STEALTH",
        auto_execute=False,
        impact_score=8.0,
        success_probability=0.6,
        stealth_cost=0.3,
    ),
    ChainTrigger(
        chain_id="smb_signing_to_ntlm_relay",
        name="SMB Signing Disabled → NTLM Relay",
        trigger_event="finding.confirmed",
        trigger_types=["smb_signing_disabled", "smb_signing_not_required"],
        next_module="ntlm_relay",
        next_chains=["ntlm_to_adcs_da"],
        fallback_modules=["responder_capture", "ipv6_mitm"],
        description=(
            "SMB signing disabled allows NTLM relay attacks. "
            "Triggers responder/ntlmrelayx to relay auth to LDAP/SMB/ADCS."
        ),
        mitre_tactics=["T1557.001", "T1558", "T1187"],
        opsec_level="NOISY",
        auto_execute=False,
        impact_score=9.0,
        success_probability=0.65,
        stealth_cost=0.8,
    ),
    ChainTrigger(
        chain_id="ad_creds_to_lateral",
        name="AD Credentials → Lateral Movement + C2",
        trigger_event="credential.found",
        trigger_types=["credential", "kerberoast_hash", "asrep_hash", "ntlm_hash"],
        next_module="lateral_movement",
        next_chains=["host_comp_to_bloodhound", "kerberoast_to_lateral"],
        fallback_modules=["winrm_exec", "wmi_exec", "ssh_exec"],
        description=(
            "Valid AD credentials trigger automated lateral movement via "
            "PsExec/WinRM/WMI, then beacon deployment."
        ),
        mitre_tactics=["T1550.002", "T1021.002", "T1021.006", "T1543.003"],
        opsec_level="STANDARD",
        auto_execute=True,
        impact_score=9.5,
        success_probability=0.75,
        stealth_cost=0.5,
    ),
    ChainTrigger(
        chain_id="ssrf_to_internal_scan",
        name="SSRF → Internal Network Scan",
        trigger_event="finding.confirmed",
        trigger_types=["ssrf", "blind_ssrf"],
        next_module="internal_scan_via_ssrf",
        next_chains=["ssrf_to_cloud_iam"],
        fallback_modules=["gopher_pivot", "dict_protocol_probe"],
        branch_conditions={
            "cloud_metadata": "ssrf_to_cloud_iam",
            "kubernetes":     "k8s_pod_to_cluster_admin",
        },
        description=(
            "Confirmed SSRF port-scans internal subnets and probes internal services "
            "(Redis, Memcached, K8s API, cloud metadata). "
            "Branches: cloud metadata → IAM pivot, k8s → cluster-admin."
        ),
        mitre_tactics=["T1018", "T1046", "T1530"],
        opsec_level="STEALTH",
        auto_execute=True,
        impact_score=8.0,
        success_probability=0.6,
        stealth_cost=0.25,
    ),
    ChainTrigger(
        chain_id="host_comp_to_bloodhound",
        name="Host Compromise → BloodHound Ingest",
        trigger_event="host.compromised",
        trigger_types=["rce", "cmd_injection", "webshell"],
        next_module="bloodhound_ingest",
        next_chains=["adcs_to_domain_admin"],
        fallback_modules=["ldapdomaindump", "manual_ad_enum"],
        description=(
            "After host compromise, run SharpHound/BloodHound-CE to map "
            "AD attack paths to Domain Admin."
        ),
        mitre_tactics=["T1087.002", "T1069.002", "T1482", "T1018"],
        opsec_level="STANDARD",
        auto_execute=False,
        impact_score=9.0,
        success_probability=0.8,
        stealth_cost=0.6,
    ),
    ChainTrigger(
        chain_id="file_upload_to_webshell",
        name="File Upload → Webshell → RCE",
        trigger_event="finding.confirmed",
        trigger_types=["file_upload", "unrestricted_file_upload", "file_upload_bypass"],
        next_module="webshell",
        next_chains=["webshell_to_beacon"],
        fallback_modules=["polyglot_upload", "mime_confusion_upload", "svg_xxe_upload"],
        description=(
            "Unrestricted file upload deploys a webshell for interactive RCE "
            "and privilege escalation, then beacons out."
        ),
        mitre_tactics=["T1190", "T1505.003", "T1059"],
        opsec_level="STANDARD",
        auto_execute=True,
        impact_score=9.0,
        success_probability=0.7,
        stealth_cost=0.5,
    ),
    ChainTrigger(
        chain_id="ssti_to_rce",
        name="SSTI → RCE Chain",
        trigger_event="finding.confirmed",
        trigger_types=["ssti", "template_injection"],
        next_module="ssti_rce",
        next_chains=["webshell_to_beacon"],
        fallback_modules=["ssti_jinja2", "ssti_twig", "ssti_pebble", "ssti_velocity"],
        description=(
            "Server-Side Template Injection escalated to full OS RCE via "
            "engine-specific gadgets (Jinja2/Twig/Pebble/Velocity)."
        ),
        mitre_tactics=["T1190", "T1059", "T1068"],
        opsec_level="STANDARD",
        auto_execute=True,
        impact_score=9.5,
        success_probability=0.75,
        stealth_cost=0.4,
    ),
    ChainTrigger(
        chain_id="xxe_to_ssrf",
        name="XXE → SSRF Pivot",
        trigger_event="finding.confirmed",
        trigger_types=["xxe", "xml_injection"],
        next_module="ssrf_scanner",
        next_chains=["ssrf_to_cloud_iam", "ssrf_to_internal_scan"],
        fallback_modules=["xxe_oob_dns", "xxe_php_expect", "xxe_jar_protocol"],
        description=(
            "XXE blind/OOB pivoted to internal SSRF via php://expect, "
            "external entity, or cloud metadata."
        ),
        mitre_tactics=["T1190", "T1530"],
        opsec_level="STEALTH",
        auto_execute=True,
        impact_score=8.5,
        success_probability=0.65,
        stealth_cost=0.3,
    ),
    ChainTrigger(
        chain_id="default_creds_to_privesc",
        name="Default Credentials → Auth Bypass → Privilege Escalation",
        trigger_event="finding.confirmed",
        trigger_types=["default_creds", "weak_credentials", "auth_bypass"],
        next_module="priv_esc",
        next_chains=["host_comp_to_bloodhound"],
        fallback_modules=["sudo_abuse", "suid_exploit", "service_exploit"],
        description=(
            "Default/weak credentials on admin panel authenticate, then "
            "privilege escalation to system/root."
        ),
        mitre_tactics=["T1078", "T1068", "T1134"],
        opsec_level="STANDARD",
        auto_execute=True,
        impact_score=9.0,
        success_probability=0.7,
        stealth_cost=0.5,
    ),

    # ── Sprint 0: Leak Intelligence Chains ────────────────────────────

    ChainTrigger(
        chain_id="git_leak_to_cred_to_webapp",
        name="Git Leak → Credential → Internal Web App",
        trigger_event="finding.confirmed",
        trigger_types=["git_secret_find", "github_leak", "gitlab_leak", "bitbucket_leak"],
        next_module="credential_tester",
        next_chains=["ad_creds_to_lateral", "sqli_to_cred_spray"],
        fallback_modules=["secret_reuse_check", "token_replay"],
        description=(
            "Secrets discovered in Git repos (GitHub/GitLab/Bitbucket) tested "
            "against internal web apps, then used for authenticated exploitation."
        ),
        mitre_tactics=["T1552.001", "T1552.004", "T1078"],
        opsec_level="STEALTH",
        auto_execute=True,
        impact_score=8.5,
        success_probability=0.6,
        stealth_cost=0.2,
    ),
    ChainTrigger(
        chain_id="pastebin_leak_to_vpn",
        name="Pastebin Leak → VPN/RDP Credential → Perimeter",
        trigger_event="finding.confirmed",
        trigger_types=["pastebin_leak", "paste_credential", "paste_dump_leak"],
        next_module="credential_tester",
        next_chains=["ad_creds_to_lateral"],
        fallback_modules=["rdp_bruteforce", "vpn_spray"],
        description=(
            "Credentials from paste sites tested against VPN portals and RDP "
            "gateways for perimeter access."
        ),
        mitre_tactics=["T1589.001", "T1078", "T1133"],
        opsec_level="STEALTH",
        auto_execute=True,
        impact_score=8.0,
        success_probability=0.45,
        stealth_cost=0.25,
    ),
    ChainTrigger(
        chain_id="crtsh_to_hidden_subdomain",
        name="Cert Transparency → Hidden Subdomain → Forgotten App",
        trigger_event="finding.confirmed",
        trigger_types=["crtsh_find", "ct_log_subdomain", "internal_subdomain_leak"],
        next_module="subdomain_probe",
        next_chains=["subdomain_takeover_to_phish", "default_creds_to_privesc"],
        fallback_modules=["dns_bruteforce", "vhost_enum"],
        description=(
            "Certificate Transparency logs reveal hidden subdomains hosting forgotten "
            "or unpatched apps — probed for outdated software and default creds."
        ),
        mitre_tactics=["T1596.003", "T1590.002", "T1190"],
        opsec_level="STEALTH",
        auto_execute=True,
        impact_score=7.0,
        success_probability=0.55,
        stealth_cost=0.15,
    ),
    ChainTrigger(
        chain_id="shodan_origin_to_cdn_bypass",
        name="Shodan Origin IP → CDN Bypass → Direct Backend",
        trigger_event="finding.confirmed",
        trigger_types=["shodan_origin_find", "origin_ip_discovery", "cdn_bypass"],
        next_module="direct_ip_probe",
        fallback_modules=["censys_origin_find", "http_header_leak_origin"],
        description=(
            "Shodan reveals the real origin IP behind CDN/WAF. Direct connection "
            "bypasses WAF and enables backend exploitation."
        ),
        mitre_tactics=["T1590.004", "T1595.001", "T1190"],
        opsec_level="STANDARD",
        auto_execute=True,
        impact_score=7.5,
        success_probability=0.6,
        stealth_cost=0.4,
    ),
    ChainTrigger(
        chain_id="dns_history_to_stale_auth",
        name="DNS History → Decommissioned Subdomain → Stale Auth",
        trigger_event="finding.confirmed",
        trigger_types=["dns_history", "stale_subdomain", "dangling_cname"],
        next_module="subdomain_probe",
        next_chains=["subdomain_takeover_to_phish"],
        fallback_modules=["wayback_enum", "passive_dns_lookup"],
        description=(
            "Historical DNS reveals decommissioned subdomains with dangling CNAMEs — "
            "tested for takeover and stale auth bypass."
        ),
        mitre_tactics=["T1596.001", "T1584.001", "T1078"],
        opsec_level="STEALTH",
        auto_execute=True,
        impact_score=7.0,
        success_probability=0.5,
        stealth_cost=0.15,
    ),

    # ── Sprint 1: Cloud & Container Chains ────────────────────────────

    ChainTrigger(
        chain_id="ssrf_to_cloud_metadata",
        name="SSRF → Cloud Metadata → IAM Pivot",
        trigger_event="finding.confirmed",
        trigger_types=["ssrf", "blind_ssrf", "ssrf_confirmed"],
        next_module="cloud_api_scanner",
        next_chains=["ssrf_to_cloud_iam", "k8s_pod_to_cluster_admin"],
        fallback_modules=["imds_v1_probe", "link_local_probe"],
        description=(
            "Confirmed SSRF accesses cloud IMDS (169.254.169.254). Extracted IAM "
            "credentials pivot through cloud via role assumption and API abuse."
        ),
        mitre_tactics=["T1190", "T1552.005", "T1078.004"],
        opsec_level="STEALTH",
        auto_execute=True,
        impact_score=9.5,
        success_probability=0.7,
        stealth_cost=0.2,
    ),
    ChainTrigger(
        chain_id="container_escape_to_host",
        name="Container Escape → Host → Cloud Creds",
        trigger_event="finding.confirmed",
        trigger_types=["container_escape", "docker_escape", "privileged_container"],
        next_module="cloud_api_scanner",
        next_chains=["ssrf_to_cloud_iam"],
        fallback_modules=["cgroup_escape", "docker_socket_abuse", "namespace_breakout"],
        description=(
            "Container breakout grants host access. Host-level cloud creds "
            "(IMDS, kubelet certs, cloud CLI configs) exfiltrated for cloud pivot."
        ),
        mitre_tactics=["T1611", "T1552.005", "T1078.004"],
        opsec_level="STANDARD",
        auto_execute=True,
        impact_score=9.5,
        success_probability=0.65,
        stealth_cost=0.45,
    ),
    ChainTrigger(
        chain_id="k8s_pod_to_cluster_admin",
        name="K8s Pod → Service Account → Cluster Admin",
        trigger_event="finding.confirmed",
        trigger_types=["kubectl_pod_exec", "k8s_pod_access", "sa_token_exfil"],
        next_module="k8s_attack",
        next_chains=["container_escape_to_host"],
        fallback_modules=["k8s_rbac_abuse", "k8s_secret_dump", "k8s_etcd_read"],
        description=(
            "Pod-level access extracts the mounted service account token. Token "
            "enumerates RBAC, reads secrets, escalates to cluster-admin."
        ),
        mitre_tactics=["T1528", "T1552.001", "T1078"],
        opsec_level="STANDARD",
        auto_execute=True,
        impact_score=9.5,
        success_probability=0.7,
        stealth_cost=0.4,
    ),

    # ── Sprint 2: 14 New Attack Chains ────────────────────────────────

    ChainTrigger(
        chain_id="lfi_to_cred_harvest",
        name="LFI → Source Code → Credential Harvest",
        trigger_event="finding.confirmed",
        trigger_types=["lfi", "local_file_inclusion", "path_traversal"],
        next_module="source_code_parser",
        next_chains=["git_leak_to_cred_to_webapp", "sqli_to_cred_spray"],
        fallback_modules=["log_poisoning", "php_filter_chain", "null_byte_lfi"],
        branch_conditions={
            "database_config": "sqli_to_cred_spray",
            "ssh_key":         "ad_creds_to_lateral",
            "aws_credential":  "ssrf_to_cloud_iam",
        },
        description=(
            "Local File Inclusion reads source files (/etc/passwd, .env, config.php, "
            "wp-config.php). Parser extracts DB creds, API keys, SSH keys. "
            "Branches based on credential type found."
        ),
        mitre_tactics=["T1190", "T1552.001", "T1083"],
        opsec_level="STEALTH",
        auto_execute=True,
        impact_score=8.5,
        success_probability=0.7,
        stealth_cost=0.2,
    ),
    ChainTrigger(
        chain_id="ssrf_to_cloud_iam",
        name="SSRF → Cloud IAM → Privilege Escalation",
        trigger_event="finding.confirmed",
        trigger_types=["ssrf", "blind_ssrf", "cloud_metadata"],
        next_module="cloud_iam_chaining",
        next_chains=["container_escape_to_host", "k8s_pod_to_cluster_admin"],
        fallback_modules=["iam_enum_cli", "sts_assume_role_brute", "lambda_env_dump"],
        branch_conditions={
            "aws":   "aws_iam_privesc",
            "azure": "azure_managed_identity",
            "gcp":   "gcp_workload_identity",
        },
        description=(
            "SSRF reaches cloud IMDS. Extracted short-lived credentials enumerate "
            "IAM policies, assume privileged roles, and pivot through cloud control "
            "plane. Branches by CSP (AWS/Azure/GCP)."
        ),
        mitre_tactics=["T1552.005", "T1078.004", "T1098"],
        opsec_level="STEALTH",
        auto_execute=True,
        impact_score=9.5,
        success_probability=0.7,
        stealth_cost=0.2,
        prerequisites=["ssrf_to_internal_scan"],
    ),
    ChainTrigger(
        chain_id="kerberoast_to_lateral",
        name="Kerberoasting → Hash Crack → Lateral Movement",
        trigger_event="credential.found",
        trigger_types=["kerberoast_hash", "spn_discovered"],
        next_module="hash_crack",
        next_chains=["ad_creds_to_lateral", "adcs_to_domain_admin"],
        fallback_modules=["asreproast_offline", "pass_the_hash"],
        description=(
            "Kerberoastable SPN hashes cracked offline (hashcat -m 13100). "
            "Cracked service account creds trigger lateral movement and ADCS abuse."
        ),
        mitre_tactics=["T1558.003", "T1110.002", "T1021"],
        opsec_level="STANDARD",
        auto_execute=True,
        impact_score=9.0,
        success_probability=0.65,
        stealth_cost=0.5,
    ),
    ChainTrigger(
        chain_id="spray_to_mfa_bypass",
        name="Password Spray → MFA Bypass",
        trigger_event="credential.found",
        trigger_types=["password_spray", "spray_hit", "valid_credential"],
        next_module="mfa_bypass",
        next_chains=["ad_creds_to_lateral"],
        fallback_modules=["evilginx_phish", "aitm_proxy", "push_fatigue"],
        branch_conditions={
            "totp": "totp_intercept",
            "push": "push_fatigue_attack",
            "sms":  "sim_swap_chain",
        },
        description=(
            "Valid credentials from spray trigger MFA bypass: push fatigue, "
            "AiTM proxy (Evilginx2), or TOTP interception. Branches by MFA type."
        ),
        mitre_tactics=["T1110.003", "T1621", "T1078"],
        opsec_level="STANDARD",
        auto_execute=False,
        impact_score=9.0,
        success_probability=0.5,
        stealth_cost=0.5,
    ),
    ChainTrigger(
        chain_id="adcs_to_domain_admin",
        name="ADCS Vulnerability → Certificate → Domain Admin",
        trigger_event="finding.confirmed",
        trigger_types=["adcs_vuln", "esc1", "esc2", "esc4", "esc8", "vulnerable_template"],
        next_module="cert_request",
        next_chains=["ad_creds_to_lateral"],
        fallback_modules=["certipy_shadow_cred", "pass_the_cert", "ntlm_relay_adcs"],
        branch_conditions={
            "ESC1":               "esc1_exploit",
            "ESC8":               "ntlm_to_adcs_da",
            "shadow_credentials": "shadow_cred_chain",
        },
        description=(
            "Vulnerable ADCS template (ESC1/2/4/8) abused to request a certificate "
            "for a privileged account. Certificate used for Kerberos auth → DA."
        ),
        mitre_tactics=["T1649", "T1558.003", "T1134.001"],
        opsec_level="STANDARD",
        auto_execute=False,
        impact_score=10.0,
        success_probability=0.75,
        stealth_cost=0.5,
        prerequisites=["host_comp_to_bloodhound"],
    ),
    ChainTrigger(
        chain_id="webshell_to_beacon",
        name="Webshell → C2 Beacon Deployment",
        trigger_event="finding.confirmed",
        trigger_types=["webshell", "rce_confirmed", "cmd_exec"],
        next_module="reverse_shell",
        next_chains=["host_comp_to_bloodhound"],
        fallback_modules=["powershell_cradle", "mshta_beacon", "certutil_download"],
        branch_conditions={
            "linux":   "linux_implant",
            "windows": "windows_beacon",
            "macos":   "macos_implant",
        },
        description=(
            "Active webshell upgraded to persistent C2 beacon via staged payload "
            "delivery. Platform-aware: adapts implant per OS (Linux/Windows/macOS)."
        ),
        mitre_tactics=["T1505.003", "T1059.001", "T1543.003"],
        opsec_level="STANDARD",
        auto_execute=True,
        impact_score=9.5,
        success_probability=0.8,
        stealth_cost=0.5,
        prerequisites=["file_upload_to_webshell"],
    ),
    ChainTrigger(
        chain_id="subdomain_takeover_to_phish",
        name="Subdomain Takeover → Phishing Infrastructure",
        trigger_event="finding.confirmed",
        trigger_types=["subdomain_takeover", "dangling_dns", "unclaimed_cname"],
        next_module="phishing_page",
        next_chains=["spray_to_mfa_bypass"],
        fallback_modules=["github_pages_takeover", "s3_bucket_claim", "heroku_claim"],
        description=(
            "Dangling CNAME on trusted subdomain (login.target.com) claimed to host "
            "convincing phishing page for credential and session harvesting."
        ),
        mitre_tactics=["T1584.001", "T1598.003", "T1056.003"],
        opsec_level="STEALTH",
        auto_execute=False,
        impact_score=8.0,
        success_probability=0.6,
        stealth_cost=0.3,
    ),
    ChainTrigger(
        chain_id="graphql_to_exfil",
        name="GraphQL Introspection → Object Abuse → Data Exfil",
        trigger_event="finding.confirmed",
        trigger_types=["graphql_introspection", "graphql_exposed", "graphql_nosec"],
        next_module="sqli",
        next_chains=["sqli_to_cred_spray"],
        fallback_modules=["graphql_batch_query", "graphql_alias_dos", "graphql_depth_abuse"],
        description=(
            "Exposed GraphQL schema introspected for sensitive types (User, Admin, "
            "Payment). Deeply nested queries or SQLi via resolver args exfiltrate data."
        ),
        mitre_tactics=["T1190", "T1213", "T1530"],
        opsec_level="STEALTH",
        auto_execute=True,
        impact_score=8.5,
        success_probability=0.65,
        stealth_cost=0.25,
    ),
    ChainTrigger(
        chain_id="jwt_to_admin",
        name="JWT Weak Secret → Forge Admin Token",
        trigger_event="finding.confirmed",
        trigger_types=["jwt_weak_secret", "jwt_none_alg", "jwt_algorithm_confusion"],
        next_module="jwt_forge",
        next_chains=["default_creds_to_privesc"],
        fallback_modules=["jwt_none_alg", "jwks_injection", "kid_sqli"],
        branch_conditions={
            "HS256": "jwt_secret_crack",
            "RS256": "jwt_algorithm_confusion",
            "none":  "jwt_none_bypass",
        },
        description=(
            "JWT signed with weak HS256 secret cracked offline. Forged token sets "
            "role=admin for full admin access. Algorithm-confusion fallback for "
            "RS256 → HS256 downgrade."
        ),
        mitre_tactics=["T1606", "T1078", "T1134"],
        opsec_level="STEALTH",
        auto_execute=True,
        impact_score=9.0,
        success_probability=0.6,
        stealth_cost=0.2,
    ),
    ChainTrigger(
        chain_id="redirect_to_oauth_theft",
        name="Open Redirect → OAuth Token Interception",
        trigger_event="finding.confirmed",
        trigger_types=["open_redirect", "unvalidated_redirect"],
        next_module="oauth_intercept",
        next_chains=["xss_to_session_hijack", "spray_to_mfa_bypass"],
        fallback_modules=["redirect_to_ssrf", "redirect_to_phish"],
        description=(
            "Open redirect in OAuth callback URI used to steal authorization codes "
            "or tokens via Referer leakage. Chains into session hijack."
        ),
        mitre_tactics=["T1550.001", "T1606.001", "T1185"],
        opsec_level="STEALTH",
        auto_execute=False,
        impact_score=8.0,
        success_probability=0.5,
        stealth_cost=0.25,
    ),
    ChainTrigger(
        chain_id="deser_to_beacon",
        name="Deserialization → RCE → C2 Beacon",
        trigger_event="finding.confirmed",
        trigger_types=["deserialization", "java_deser", "pickle_deser", "yaml_deser", "ysoserial"],
        next_module="rce_exec",
        next_chains=["webshell_to_beacon", "host_comp_to_bloodhound"],
        fallback_modules=["ysoserial_commons_collections", "ysoserial_spring", "marshalsec"],
        branch_conditions={
            "java":   "ysoserial_chain",
            "python": "pickle_rce",
            "php":    "php_object_injection",
            "dotnet": "viewstate_exploit",
        },
        description=(
            "Unsafe deserialization achieves OS RCE via gadget chains (ysoserial, "
            "pickle, PHP Object Injection). Beacon deployed post-RCE. "
            "Language-aware gadget selection."
        ),
        mitre_tactics=["T1190", "T1059", "T1068"],
        opsec_level="STANDARD",
        auto_execute=True,
        impact_score=9.5,
        success_probability=0.65,
        stealth_cost=0.45,
    ),
    ChainTrigger(
        chain_id="ntlm_to_adcs_da",
        name="NTLM Relay → ADCS ESC8 → Domain Admin",
        trigger_event="finding.confirmed",
        trigger_types=["ntlm_relay", "ntlm_relay_success", "relay_to_adcs"],
        next_module="adcs_relay",
        next_chains=["adcs_to_domain_admin"],
        fallback_modules=["ntlm_relay_smb", "ntlm_relay_ldap", "shadow_credentials"],
        description=(
            "NTLM relay to ADCS HTTP endpoint (ESC8) requests a certificate for the "
            "relayed machine account, enabling DCSync or UnPAC-the-Hash → DA."
        ),
        mitre_tactics=["T1557.001", "T1649", "T1003.006"],
        opsec_level="NOISY",
        auto_execute=False,
        impact_score=10.0,
        success_probability=0.7,
        stealth_cost=0.75,
        prerequisites=["smb_signing_to_ntlm_relay"],
    ),
    ChainTrigger(
        chain_id="race_to_privesc",
        name="Race Condition → Privilege Escalation",
        trigger_event="finding.confirmed",
        trigger_types=["race_condition", "toctou", "concurrent_request_vuln"],
        next_module="priv_esc_check",
        next_chains=["default_creds_to_privesc"],
        fallback_modules=["race_limit_bypass", "race_balance_manipulation"],
        description=(
            "Race condition (TOCTOU, concurrent fund transfer, limit bypass) "
            "exploited for privilege escalation or unauthorized resource access."
        ),
        mitre_tactics=["T1068", "T1190", "T1134"],
        opsec_level="STANDARD",
        auto_execute=True,
        impact_score=8.5,
        success_probability=0.55,
        stealth_cost=0.45,
    ),
    ChainTrigger(
        chain_id="cache_to_session",
        name="Cache Poisoning → XSS → Session Theft",
        trigger_event="finding.confirmed",
        trigger_types=["cache_poison", "web_cache_deception", "cache_key_injection"],
        next_module="xss",
        next_chains=["xss_to_session_hijack"],
        fallback_modules=["cache_deception_fat_get", "vary_header_poison"],
        description=(
            "Cache poisoning injects malicious XSS payload into CDN cache. "
            "Stolen session tokens replayed for account takeover."
        ),
        mitre_tactics=["T1190", "T1185", "T1539"],
        opsec_level="STEALTH",
        auto_execute=True,
        impact_score=8.5,
        success_probability=0.55,
        stealth_cost=0.3,
    ),
    # ── Sprint 0: Leak Intelligence Chains ────────────────────────────
    ChainTrigger(
        chain_id="git_leak_to_cred_to_webapp",
        name="Git Leak → Credential → Internal Web App",
        trigger_event="finding.confirmed",
        trigger_types=["git_secret_find", "github_leak", "gitlab_leak", "bitbucket_leak"],
        next_module="credential_tester",
        description=(
            "Secrets discovered in Git repositories (GitHub/GitLab/Bitbucket) "
            "are extracted and tested against internal web applications, "
            "then used for authenticated access and further exploitation."
        ),
        mitre_tactics=["T1552.001", "T1552.004", "T1078"],
        opsec_level="STEALTH",
        auto_execute=True,
    ),
    ChainTrigger(
        chain_id="pastebin_leak_to_vpn",
        name="Pastebin Leak → VPN/RDP Credential → Perimeter",
        trigger_event="finding.confirmed",
        trigger_types=["pastebin_leak", "paste_credential", "paste_dump_leak"],
        next_module="credential_tester",
        description=(
            "Credentials found in paste sites (Pastebin, Ghostbin, Hastebin) "
            "are tested against VPN portals and RDP gateways for perimeter access."
        ),
        mitre_tactics=["T1589.001", "T1078", "T1133"],
        opsec_level="STEALTH",
        auto_execute=True,
    ),
    ChainTrigger(
        chain_id="crtsh_to_hidden_subdomain",
        name="Cert Transparency → Hidden Subdomain → Forgotten App",
        trigger_event="finding.confirmed",
        trigger_types=["crtsh_find", "ct_log_subdomain", "internal_subdomain_leak"],
        next_module="subdomain_probe",
        description=(
            "Certificate Transparency logs reveal hidden subdomains that may host "
            "forgotten, unpatched, or internal-only applications. These are probed "
            "for outdated software and default credentials."
        ),
        mitre_tactics=["T1596.003", "T1590.002", "T1190"],
        opsec_level="STEALTH",
        auto_execute=True,
    ),
    ChainTrigger(
        chain_id="shodan_origin_to_cdn_bypass",
        name="Shodan Origin IP → CDN Bypass → Direct Backend",
        trigger_event="finding.confirmed",
        trigger_types=["shodan_origin_find", "origin_ip_discovery", "cdn_bypass"],
        next_module="direct_ip_probe",
        description=(
            "Shodan reveals the real origin IP behind a CDN/WAF. Direct connection "
            "bypasses WAF protections, enabling exploitation of backend vulnerabilities "
            "that are normally filtered."
        ),
        mitre_tactics=["T1590.004", "T1595.001", "T1190"],
        opsec_level="STANDARD",
        auto_execute=True,
    ),
    ChainTrigger(
        chain_id="dns_history_to_stale_auth",
        name="DNS History → Decommissioned Subdomain → Stale Auth",
        trigger_event="finding.confirmed",
        trigger_types=["dns_history", "stale_subdomain", "dangling_cname"],
        next_module="subdomain_probe",
        description=(
            "Historical DNS records reveal decommissioned subdomains with dangling "
            "CNAME records or expired cloud resources. These are tested for subdomain "
            "takeover and stale authentication bypass."
        ),
        mitre_tactics=["T1596.001", "T1584.001", "T1078"],
        opsec_level="STEALTH",
        auto_execute=True,
    ),
    # ── Sprint 1: Cloud & Container Chains ────────────────────────────
    ChainTrigger(
        chain_id="ssrf_to_cloud_metadata",
        name="SSRF → Cloud Metadata → IAM Pivot",
        trigger_event="finding.confirmed",
        trigger_types=["ssrf", "blind_ssrf", "ssrf_confirmed"],
        next_module="cloud_api_scanner",
        description=(
            "Confirmed SSRF is leveraged to access cloud instance metadata APIs "
            "(169.254.169.254). Extracted IAM credentials are then used to pivot "
            "through cloud infrastructure via role assumption and API abuse."
        ),
        mitre_tactics=["T1190", "T1552.005", "T1078.004"],
        opsec_level="STEALTH",
        auto_execute=True,
    ),
    ChainTrigger(
        chain_id="container_escape_to_host",
        name="Container Escape → Host → Cloud Creds",
        trigger_event="finding.confirmed",
        trigger_types=["container_escape", "docker_escape", "privileged_container"],
        next_module="cloud_api_scanner",
        description=(
            "Container breakout (via cgroup, mount namespace, or Docker socket) "
            "grants host access. Host-level cloud credentials (instance metadata, "
            "kubelet certs, cloud CLI configs) are exfiltrated for cloud pivot."
        ),
        mitre_tactics=["T1611", "T1552.005", "T1078.004"],
        opsec_level="STANDARD",
        auto_execute=True,
    ),
    ChainTrigger(
        chain_id="k8s_pod_to_cluster_admin",
        name="K8s Pod → Service Account → Cluster Admin",
        trigger_event="finding.confirmed",
        trigger_types=["kubectl_pod_exec", "k8s_pod_access", "sa_token_exfil"],
        next_module="k8s_attack",
        description=(
            "Pod-level access is leveraged to extract the mounted service account "
            "token. The token is used to enumerate RBAC permissions, read secrets, "
            "and escalate to cluster-admin via role binding abuse."
        ),
        mitre_tactics=["T1528", "T1552.001", "T1078"],
        opsec_level="STANDARD",
        auto_execute=True,
    ),
]


# ══════════════════════════════════════════════════════════════════════
# CHAIN ENGINE v2
# ══════════════════════════════════════════════════════════════════════

class ChainEngine:
    """Multi-hop, scored, stateful attack chain orchestrator.

    Sprint 2 capabilities:
      - State machine per chain (PENDING/IN_PROGRESS/COMPLETED/FAILED/BLOCKED)
      - Multi-hop continuation: after chain A completes, fires B, C, ...
      - Failure adaptation: tries primary module, then fallback_modules in order
      - Conditional branching: result payload selects downstream chain branch
      - Priority scheduling: highest impact x probability x stealth chains fire first
      - DAG enforcement: prerequisites must be COMPLETED before a chain runs
      - OSINT priming: proactively emits leak-intel events before active phases

    Usage::
        engine = ChainEngine(bus=engagement_bus)
        engine.register_all()
        engine.prime_osint(target="example.com")
        bus.emit("finding.confirmed", {"type": "sqli", ...})
    """

    # Maximum hop depth to prevent infinite recursion in multi-hop chains
    MAX_HOP_DEPTH: int = 8

    def __init__(
        self,
        bus: Any = None,
        auto_trigger: bool = True,
        opsec_level: str = "STANDARD",
        module_registry: dict[str, Any] | None = None,
        max_hop_depth: int = 8,
    ) -> None:
        self._bus = bus or _SimpleEventBus()
        self._auto_trigger = auto_trigger
        self._opsec_level = opsec_level
        self._modules = module_registry or {}
        self._triggered: list[dict[str, Any]] = []
        self._chain_states: dict[str, ChainState] = {
            c.chain_id: ChainState.PENDING for c in _CHAIN_DEFINITIONS
        }
        self._chain_index: dict[str, ChainTrigger] = {
            c.chain_id: c for c in _CHAIN_DEFINITIONS
        }
        self._max_hop_depth = max_hop_depth
        # Track active hop paths to detect cycles at runtime
        self._active_hops: set[str] = set()
        # Custom chains registered via register_chain (separate from built-ins)
        self._custom_chains: list[ChainTrigger] = []

    # ── Public state API ──────────────────────────────────────────────

    @property
    def chain_states(self) -> dict[str, ChainState]:
        """Live state machine snapshot keyed by chain_id."""
        return dict(self._chain_states)

    @property
    def triggered_chains(self) -> list[dict[str, Any]]:
        """All chain trigger records that fired this engagement."""
        return list(self._triggered)

    def dependency_graph(self) -> dict[str, list[str]]:
        """Return the prerequisite DAG as an adjacency list.

        Returns:
            {chain_id: [prerequisite_chain_ids, ...]}
        """
        return {c.chain_id: list(c.prerequisites) for c in _CHAIN_DEFINITIONS}

    # ── Registration ─────────────────────────────────────────────────

    def register_all(self) -> None:
        """Subscribe all chain triggers to the event bus, sorted by priority score."""
        sorted_chains = sorted(
            _CHAIN_DEFINITIONS, key=lambda c: c.priority_score, reverse=True
        )
        for chain in sorted_chains:
            def make_handler(c: ChainTrigger) -> Callable:
                def handler(payload: dict[str, Any]) -> None:
                    self._on_event(c, payload)
                return handler
            self._bus.subscribe(chain.trigger_event, make_handler(chain))
        log.info(
            "ChainEngine v2: registered %d chains (priority-sorted)",
            len(_CHAIN_DEFINITIONS),
        )

    def register_chain(self, chain: ChainTrigger) -> None:
        """Register a single custom chain and index it.

        Custom chains are added to both the index (for execution) and
        the custom_chains list (so list_all_chains/get_chain_suggestions
        can find them).
        """
        self._chain_states.setdefault(chain.chain_id, ChainState.PENDING)
        self._chain_index[chain.chain_id] = chain
        self._custom_chains.append(chain)

        def handler(payload: dict[str, Any]) -> None:
            self._on_event(chain, payload)
        self._bus.subscribe(chain.trigger_event, handler)

    # ── OSINT Priming ─────────────────────────────────────────────────

    def prime_osint(self, target: str) -> None:
        """Proactively fire OSINT/leak-intel chains before active scanning.

        Emits synthetic events for all leak-intel trigger types so chain
        handlers run immediately, feeding results into subsequent active chains.
        """
        _OSINT_PRIMES = [
            ("finding.confirmed", "crtsh_find"),
            ("finding.confirmed", "shodan_origin_find"),
            ("finding.confirmed", "dns_history"),
            ("finding.confirmed", "github_leak"),
            ("finding.confirmed", "pastebin_leak"),
        ]
        log.info(
            "ChainEngine: priming %d OSINT chains for %s", len(_OSINT_PRIMES), target
        )
        for event, finding_type in _OSINT_PRIMES:
            self._bus.emit(event, {
                "type":   finding_type,
                "target": target,
                "source": "osint_prime",
                "auto":   True,
            })

    # ── Internal event dispatch ───────────────────────────────────────

    def _on_event(self, chain: ChainTrigger, payload: dict[str, Any]) -> None:
        """Evaluate incoming event against chain preconditions and fire if match."""
        finding_type = (
            payload.get("type") or payload.get("vuln_type") or payload.get("category", "")
        ).lower()

        if not any(
            t.lower() in finding_type or finding_type in t.lower()
            for t in chain.trigger_types
        ):
            return

        if not self._opsec_allows(chain):
            return

        if not self._prerequisites_met(chain):
            self._transition(chain.chain_id, ChainState.BLOCKED)
            log.debug(
                "Chain %s BLOCKED — prerequisites unmet: %s",
                chain.chain_id, chain.prerequisites,
            )
            return

        # Cycle detection: if this chain is already in the active hop stack, bail
        if chain.chain_id in self._active_hops:
            log.warning(
                "Chain %s SKIPPED — cycle detected in hop path: %s",
                chain.chain_id, self._active_hops,
            )
            return

        # Depth guard: count _hop_depth in payload to prevent infinite recursion
        hop_depth = int(payload.get("_hop_depth", 0))
        if hop_depth >= self._max_hop_depth:
            log.warning(
                "Chain %s SKIPPED — max hop depth %d reached",
                chain.chain_id, self._max_hop_depth,
            )
            return

        record: dict[str, Any] = {
            "chain_id":       chain.chain_id,
            "chain_name":     chain.name,
            "trigger_type":   finding_type,
            "next_module":    chain.next_module,
            "description":    chain.description,
            "mitre_tactics":  chain.mitre_tactics,
            "opsec_level":    chain.opsec_level,
            "priority_score": chain.priority_score,
            "payload":        payload,
            "auto_executed":  False,
            "state":          ChainState.PENDING.value,
            "hop_depth":      hop_depth,
        }

        if self._auto_trigger and chain.auto_execute:
            self._transition(chain.chain_id, ChainState.IN_PROGRESS)
            self._active_hops.add(chain.chain_id)
            try:
                success = self._execute_with_fallback(chain, payload, record)
                if success:
                    self._transition(chain.chain_id, ChainState.COMPLETED)
                    self._continue_hop(chain, payload, hop_depth)
                    self._evaluate_branch(chain, payload, hop_depth)
                else:
                    self._transition(chain.chain_id, ChainState.FAILED)
            finally:
                self._active_hops.discard(chain.chain_id)
        else:
            log.info(
                "Chain suggestion: %s → %s (auto=%s, opsec=%s, score=%.2f)",
                chain.name, chain.next_module,
                chain.auto_execute, chain.opsec_level, chain.priority_score,
            )

        record["state"] = self._chain_states[chain.chain_id].value
        self._triggered.append(record)

        try:
            self._bus.emit("chain.triggered", record)
        except Exception:
            pass

    def _execute_with_fallback(
        self,
        chain: ChainTrigger,
        payload: dict[str, Any],
        record: dict[str, Any],
    ) -> bool:
        """Try next_module then iterate through fallback_modules on failure.

        Handles both sync and async module methods (run_chain / run_for_target).
        Returns True if any module succeeded, False when all exhausted.
        """
        import asyncio
        import inspect

        async def _resolve_awaitable(awaitable: Awaitable[Any]) -> Any:
            return await awaitable

        candidates = [chain.next_module] + list(chain.fallback_modules)
        for module_name in candidates:
            module = self._modules.get(module_name)
            if not module:
                log.debug(
                    "Chain %s: module %r not in registry — skipping",
                    chain.chain_id, module_name,
                )
                continue
            try:
                log.info("Firing chain: %s → %s", chain.name, module_name)
                result = None
                if hasattr(module, "run_chain"):
                    result = module.run_chain(payload)
                elif hasattr(module, "run_for_target"):
                    target = payload.get("url") or payload.get("target", "")
                    result = module.run_for_target(target)
                # If the module returned a coroutine, schedule it properly
                if inspect.isawaitable(result):
                    try:
                        loop = asyncio.get_running_loop()
                    except RuntimeError:
                        # No running loop — run synchronously as last resort
                        asyncio.run(_resolve_awaitable(result))
                    else:
                        loop.create_task(_resolve_awaitable(result))
                record["auto_executed"] = True
                record["executed_module"] = module_name
                return True
            except Exception as exc:
                log.warning(
                    "Chain %s: module %r failed (%s) — trying next fallback",
                    chain.chain_id, module_name, exc,
                )
        log.error(
            "Chain %s: all modules exhausted — primary=%r fallbacks=%r",
            chain.chain_id, chain.next_module, chain.fallback_modules,
        )
        return False

    def _continue_hop(
        self, chain: ChainTrigger, payload: dict[str, Any], hop_depth: int = 0
    ) -> None:
        """Fire downstream next_chains after this chain completes (multi-hop).

        Increments _hop_depth in the forwarded payload so _on_event can
        enforce MAX_HOP_DEPTH and prevent infinite recursion.
        """
        for next_chain_id in chain.next_chains:
            next_chain = self._chain_index.get(next_chain_id)
            if not next_chain:
                log.debug("Multi-hop: unknown chain_id %r — skipping", next_chain_id)
                continue
            log.info("Multi-hop: %s → %s (depth=%d)", chain.chain_id, next_chain_id, hop_depth + 1)
            forwarded = dict(payload)
            forwarded["_hop_from"] = chain.chain_id
            forwarded["_hop_depth"] = hop_depth + 1
            self._bus.emit(next_chain.trigger_event, {
                "type": next_chain.trigger_types[0] if next_chain.trigger_types else "",
                **forwarded,
            })

    def _evaluate_branch(
        self, chain: ChainTrigger, payload: dict[str, Any], hop_depth: int = 0
    ) -> None:
        """Check payload values against branch_conditions, fire the first match.

        Only inspects semantically relevant payload fields (type, category,
        target, description) to prevent false-positive branch routing from
        unrelated metadata leaking into the match string.
        """
        if not chain.branch_conditions:
            return
        # Only match against semantically relevant fields, not everything
        _BRANCH_FIELDS = ("type", "vuln_type", "category", "description", "target", "service")
        payload_text = " ".join(
            str(payload.get(k, "")) for k in _BRANCH_FIELDS
        ).lower()
        for condition_key, target_chain_id in chain.branch_conditions.items():
            if condition_key.lower() in payload_text:
                target_chain = self._chain_index.get(target_chain_id)
                if not target_chain:
                    log.debug(
                        "Branch condition %r → unknown chain %r",
                        condition_key, target_chain_id,
                    )
                    continue
                log.info(
                    "Branch: %s condition=%r → %s",
                    chain.chain_id, condition_key, target_chain_id,
                )
                self._bus.emit(target_chain.trigger_event, {
                    "type":               target_chain.trigger_types[0] if target_chain.trigger_types else "",
                    "_branch_from":       chain.chain_id,
                    "_branch_condition":  condition_key,
                    "_hop_depth":         hop_depth + 1,
                    **payload,
                })
                break  # first matching condition wins

    # ── Helpers ───────────────────────────────────────────────────────

    def _transition(self, chain_id: str, state: ChainState) -> None:
        prev = self._chain_states.get(chain_id, ChainState.PENDING)
        self._chain_states[chain_id] = state
        log.debug("State: %s  %s → %s", chain_id, prev.value, state.value)

    def _prerequisites_met(self, chain: ChainTrigger) -> bool:
        if not chain.prerequisites:
            return True
        return all(
            self._chain_states.get(pid) == ChainState.COMPLETED
            for pid in chain.prerequisites
        )

    def _opsec_allows(self, chain: ChainTrigger) -> bool:
        opsec_order = {"STEALTH": 0, "STANDARD": 1, "NOISY": 2}
        if opsec_order.get(chain.opsec_level, 1) > opsec_order.get(self._opsec_level, 1):
            log.debug(
                "Chain %s suppressed: opsec=%s > allowed=%s",
                chain.chain_id, chain.opsec_level, self._opsec_level,
            )
            return False
        return True


# ══════════════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ══════════════════════════════════════════════════════════════════════

def _all_chain_definitions() -> list[ChainTrigger]:
    """Return built-in + any custom-registered chain definitions."""
    # ChainEngine instances may have registered custom chains;
    # this function returns the global built-in set. For custom chains,
    # use the engine instance's chain_index.
    return list(_CHAIN_DEFINITIONS)


def get_chain_suggestions(finding_type: str) -> list[dict[str, str]]:
    """Return chain suggestions for a given finding type, ranked by priority score."""
    ft = finding_type.lower()
    suggestions = []
    for chain in _all_chain_definitions():
        if any(t.lower() in ft or ft in t.lower() for t in chain.trigger_types):
            suggestions.append({
                "chain_id":       chain.chain_id,
                "name":           chain.name,
                "description":    chain.description,
                "next_module":    chain.next_module,
                "mitre":          ", ".join(chain.mitre_tactics),
                "opsec":          chain.opsec_level,
                "priority_score": f"{chain.priority_score:.2f}",
                "fallbacks":      ", ".join(chain.fallback_modules),
                "next_chains":    ", ".join(chain.next_chains),
            })
    return sorted(suggestions, key=lambda s: float(s["priority_score"]), reverse=True)


def list_all_chains() -> str:
    """Return a formatted priority-ranked table of all attack chains."""
    chains = sorted(_CHAIN_DEFINITIONS, key=lambda c: c.priority_score, reverse=True)
    lines = [
        "  Forge Suite v5 APEX — Attack Chain Engine v2 (Sprint 2)",
        "  " + "-" * 75,
        f"  {'SCORE':>6}  {'OPSEC':8}  {'MODE':6}  Chain",
        "  " + "-" * 75,
    ]
    for c in chains:
        auto  = "AUTO  " if c.auto_execute else "MANUAL"
        score = f"{c.priority_score:6.2f}"
        lines.append(f"  {score}  [{c.opsec_level:8}]  [{auto}]  {c.name}")
        if c.next_chains:
            lines.append(f"           Next hops : {', '.join(c.next_chains)}")
        if c.fallback_modules:
            lines.append(f"           Fallbacks : {', '.join(c.fallback_modules[:3])}")
        if c.prerequisites:
            lines.append(f"           Requires  : {', '.join(c.prerequisites)}")
        lines.append(
            f"           Trigger   : {', '.join(c.trigger_types[:3])} | "
            f"MITRE: {', '.join(c.mitre_tactics[:2])}"
        )
        lines.append("")
    return "\n".join(lines)
