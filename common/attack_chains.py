"""Cross-Framework Attack Chains (Pillar 12).

When one module confirms a finding, it fires an EngagementBus event
that triggers downstream modules to exploit the chain automatically.

Chains implemented:
    1.  SQLi        → Credential Spray (extract creds → spray AD/web logins)
    2.  XSS         → Session Hijack (steal JWT/cookie → replay as victim)
    3.  SMB Signing → NTLM Relay (signing disabled → relay to LDAP/SMB)
    4.  AD Creds    → Lateral Movement + C2 (valid creds → PsExec/WinRM → beacon)
    5.  SSRF        → Internal Scan (SSRF reaches internal services)
    6.  Host Comp   → BloodHound Ingest (compromised host → run SharpHound)
    7.  File Upload → Webshell (bypass → drop shell → RCE)
    8.  SSTI        → RCE Chain (template injection → server-side code exec)
    9.  XXE         → SSRF Pivot (XXE → internal service access)
    10. Default Creds → Auth Bypass → Privilege Escalation

Usage::
    from common.attack_chains import ChainEngine
    from common.brain.autonomous import EngagementBus

    bus = EngagementBus()
    engine = ChainEngine(bus=bus, auto_trigger=True)
    engine.register_all()

    # When SQLi is confirmed:
    bus.emit("finding.confirmed", {
        "type": "sqli",
        "url": "...",
        "param": "username",
        "evidence": "...",
        "extracted_data": {"creds": [("admin", "password123")]},
    })
    # → ChainEngine auto-triggers sqli_to_cred_spray

FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable

log = logging.getLogger("forge.attack_chains")


# ══════════════════════════════════════════════════════════════════════
# EVENT BUS (lightweight fallback if EngagementBus not available)
# ══════════════════════════════════════════════════════════════════════

class _SimpleEventBus:
    """Minimal sync event bus for chain triggers."""

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
    """Definition of a cross-framework chain trigger."""
    chain_id:         str
    name:             str
    trigger_event:    str                 # EngagementBus event that fires this
    trigger_types:    list[str]           # Finding types that match
    next_module:      str                 # Module to invoke next
    description:      str
    mitre_tactics:    list[str]           = field(default_factory=list)
    opsec_level:      str                 = "STANDARD"   # STEALTH/STANDARD/NOISY
    auto_execute:     bool                = True         # Run without human confirm


_CHAIN_DEFINITIONS: list[ChainTrigger] = [
    ChainTrigger(
        chain_id="sqli_to_cred_spray",
        name="SQLi → Credential Spray",
        trigger_event="finding.confirmed",
        trigger_types=["sqli", "sqli_time", "sqli_error", "sqli_union"],
        next_module="cred_spray",
        description=(
            "Extracted DB credentials from SQLi finding are sprayed against "
            "discovered authentication endpoints (AD, web login, VPN, OWA)."
        ),
        mitre_tactics=["T1190", "T1110.003", "T1078"],
        opsec_level="STANDARD",
        auto_execute=True,
    ),
    ChainTrigger(
        chain_id="xss_to_session_hijack",
        name="XSS → Session Hijack",
        trigger_event="finding.confirmed",
        trigger_types=["xss", "xss_reflected", "xss_stored", "xss_dom"],
        next_module="session_hijack",
        description=(
            "Stored or reflected XSS is used to steal admin session tokens "
            "or JWTs via JavaScript, then replay them as a privileged user."
        ),
        mitre_tactics=["T1185", "T1539", "T1606"],
        opsec_level="STEALTH",
        auto_execute=False,  # Requires human to set up XSS payload delivery
    ),
    ChainTrigger(
        chain_id="smb_signing_to_ntlm_relay",
        name="SMB Signing Disabled → NTLM Relay",
        trigger_event="finding.confirmed",
        trigger_types=["smb_signing_disabled", "smb_signing_not_required"],
        next_module="ntlm_relay",
        description=(
            "SMB signing disabled on target allows NTLM relay attacks. "
            "Triggers responder/ntlmrelayx setup to relay auth to LDAP/SMB."
        ),
        mitre_tactics=["T1557.001", "T1558", "T1187"],
        opsec_level="NOISY",
        auto_execute=False,  # Requires MitM positioning
    ),
    ChainTrigger(
        chain_id="ad_creds_to_lateral",
        name="AD Credentials → Lateral Movement + C2",
        trigger_event="credential.found",
        trigger_types=["credential", "kerberoast_hash", "asrep_hash", "ntlm_hash"],
        next_module="lateral_movement",
        description=(
            "Valid AD credentials trigger automated lateral movement: "
            "PsExec/WinRM to domain hosts, then beacon deployment."
        ),
        mitre_tactics=["T1550.002", "T1021.002", "T1021.006", "T1543.003"],
        opsec_level="STANDARD",
        auto_execute=True,
    ),
    ChainTrigger(
        chain_id="ssrf_to_internal_scan",
        name="SSRF → Internal Network Scan",
        trigger_event="finding.confirmed",
        trigger_types=["ssrf", "blind_ssrf"],
        next_module="internal_scan_via_ssrf",
        description=(
            "Confirmed SSRF is used to port-scan internal subnets and probe "
            "internal services (Redis, Memcached, Kubernetes API, cloud metadata)."
        ),
        mitre_tactics=["T1018", "T1046", "T1530"],
        opsec_level="STEALTH",
        auto_execute=True,
    ),
    ChainTrigger(
        chain_id="host_comp_to_bloodhound",
        name="Host Compromise → BloodHound Ingest",
        trigger_event="host.compromised",
        trigger_types=["rce", "cmd_injection", "webshell"],
        next_module="bloodhound_ingest",
        description=(
            "After host compromise, run SharpHound/BloodHound-CE collector "
            "to map AD attack paths to Domain Admin."
        ),
        mitre_tactics=["T1087.002", "T1069.002", "T1482", "T1018"],
        opsec_level="STANDARD",
        auto_execute=False,  # BloodHound generates significant AD noise
    ),
    ChainTrigger(
        chain_id="file_upload_to_webshell",
        name="File Upload → Webshell → RCE",
        trigger_event="finding.confirmed",
        trigger_types=["file_upload", "unrestricted_file_upload", "file_upload_bypass"],
        next_module="webshell",
        description=(
            "Unrestricted file upload is exploited to deploy a webshell, "
            "followed by interactive RCE and privilege escalation."
        ),
        mitre_tactics=["T1190", "T1505.003", "T1059"],
        opsec_level="STANDARD",
        auto_execute=True,
    ),
    ChainTrigger(
        chain_id="ssti_to_rce",
        name="SSTI → RCE Chain",
        trigger_event="finding.confirmed",
        trigger_types=["ssti", "template_injection"],
        next_module="ssti_rce",
        description=(
            "Server-Side Template Injection escalated to full OS command execution "
            "via engine-specific RCE gadgets (Jinja2/Twig/Pebble/Velocity)."
        ),
        mitre_tactics=["T1190", "T1059", "T1068"],
        opsec_level="STANDARD",
        auto_execute=True,
    ),
    ChainTrigger(
        chain_id="xxe_to_ssrf",
        name="XXE → SSRF Pivot",
        trigger_event="finding.confirmed",
        trigger_types=["xxe", "xml_injection"],
        next_module="ssrf_scanner",
        description=(
            "XXE blind/OOB finding pivoted to internal SSRF: "
            "php://expect, SSRF via external entity, cloud metadata access."
        ),
        mitre_tactics=["T1190", "T1530"],
        opsec_level="STEALTH",
        auto_execute=True,
    ),
    ChainTrigger(
        chain_id="default_creds_to_privesc",
        name="Default Credentials → Auth Bypass → Privilege Escalation",
        trigger_event="finding.confirmed",
        trigger_types=["default_creds", "weak_credentials", "auth_bypass"],
        next_module="priv_esc",
        description=(
            "Default/weak credentials on admin panel used to authenticate, "
            "then privilege escalation path is pursued to system/root."
        ),
        mitre_tactics=["T1078", "T1068", "T1134"],
        opsec_level="STANDARD",
        auto_execute=True,
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
# CHAIN ENGINE
# ══════════════════════════════════════════════════════════════════════

class ChainEngine:
    """Orchestrates cross-framework attack chain triggers.

    Subscribes to EngagementBus events and fires next-stage modules
    when preconditions are met.

    Usage::
        from common.attack_chains import ChainEngine
        engine = ChainEngine(bus=engagement_bus)
        engine.register_all()
    """

    def __init__(
        self,
        bus: Any = None,
        auto_trigger: bool = True,
        opsec_level: str = "STANDARD",
        module_registry: dict[str, Any] | None = None,
    ) -> None:
        """
        Args:
            bus:             EngagementBus instance. Falls back to SimpleEventBus.
            auto_trigger:    If False, chains only log suggestions; don't fire.
            opsec_level:     Only fire chains at or below this opsec level.
            module_registry: Map of module_name → module instance.
        """
        self._bus = bus or _SimpleEventBus()
        self._auto_trigger = auto_trigger
        self._opsec_level = opsec_level
        self._modules = module_registry or {}
        self._triggered: list[dict[str, Any]] = []

    @property
    def triggered_chains(self) -> list[dict[str, Any]]:
        """List of chain trigger events that have fired this engagement."""
        return list(self._triggered)

    def register_all(self) -> None:
        """Subscribe all defined chain triggers to the event bus."""
        for chain in _CHAIN_DEFINITIONS:
            event = chain.trigger_event
            # Capture chain in closure
            def make_handler(c: ChainTrigger) -> Callable:
                def handler(payload: dict[str, Any]) -> None:
                    self._on_event(c, payload)
                return handler
            self._bus.subscribe(event, make_handler(chain))
        log.info("ChainEngine: registered %d attack chains", len(_CHAIN_DEFINITIONS))

    def register_chain(self, chain: ChainTrigger) -> None:
        """Register a single chain trigger."""
        def handler(payload: dict[str, Any]) -> None:
            self._on_event(chain, payload)
        self._bus.subscribe(chain.trigger_event, handler)

    def _on_event(self, chain: ChainTrigger, payload: dict[str, Any]) -> None:
        """Handle an incoming event and fire the chain if conditions match."""
        # Check if finding type matches
        finding_type = (
            payload.get("type") or payload.get("vuln_type") or payload.get("category", "")
        ).lower()

        matches = any(t.lower() in finding_type or finding_type in t.lower()
                      for t in chain.trigger_types)
        if not matches:
            return

        # Check opsec level
        opsec_order = {"STEALTH": 0, "STANDARD": 1, "NOISY": 2}
        chain_order = opsec_order.get(chain.opsec_level, 1)
        allowed_order = opsec_order.get(self._opsec_level, 1)
        if chain_order > allowed_order:
            log.debug("Chain %s suppressed: opsec=%s > allowed=%s",
                      chain.chain_id, chain.opsec_level, self._opsec_level)
            return

        trigger_record = {
            "chain_id": chain.chain_id,
            "chain_name": chain.name,
            "trigger_type": finding_type,
            "next_module": chain.next_module,
            "description": chain.description,
            "mitre_tactics": chain.mitre_tactics,
            "payload": payload,
            "auto_executed": False,
        }

        if self._auto_trigger and chain.auto_execute:
            self._fire_chain(chain, payload, trigger_record)
        else:
            log.info(
                "Chain suggestion: %s → %s (auto_execute=%s, opsec=%s)",
                chain.name, chain.next_module, chain.auto_execute, chain.opsec_level,
            )

        self._triggered.append(trigger_record)

        # Emit chain event on bus for dashboard visibility
        try:
            self._bus.emit("chain.triggered", trigger_record)
        except Exception:
            pass

    def _fire_chain(
        self, chain: ChainTrigger, payload: dict[str, Any], record: dict[str, Any]
    ) -> None:
        """Actually invoke the next module in the chain."""
        next_module = self._modules.get(chain.next_module)
        if not next_module:
            log.debug("Chain %s: next_module %r not in registry — logging only",
                      chain.chain_id, chain.next_module)
            return

        log.info("Firing chain: %s → %s", chain.name, chain.next_module)
        try:
            # Each module is expected to have a run_for_target() or run_chain() method
            if hasattr(next_module, "run_chain"):
                next_module.run_chain(payload)
            elif hasattr(next_module, "run_for_target"):
                target = payload.get("url") or payload.get("target", "")
                next_module.run_for_target(target)
            record["auto_executed"] = True
        except Exception as exc:
            log.error("Chain execution error (%s): %s", chain.chain_id, exc)


# ══════════════════════════════════════════════════════════════════════
# CHAIN SUGGESTIONS (for AI planner output)
# ══════════════════════════════════════════════════════════════════════

def get_chain_suggestions(finding_type: str) -> list[dict[str, str]]:
    """Return chain suggestions for a given finding type.

    Args:
        finding_type: Vulnerability type string.

    Returns:
        List of {chain_id, name, description, next_module, mitre} dicts.
    """
    ft = finding_type.lower()
    suggestions = []
    for chain in _CHAIN_DEFINITIONS:
        if any(t.lower() in ft or ft in t.lower() for t in chain.trigger_types):
            suggestions.append({
                "chain_id": chain.chain_id,
                "name": chain.name,
                "description": chain.description,
                "next_module": chain.next_module,
                "mitre": ", ".join(chain.mitre_tactics),
                "opsec": chain.opsec_level,
            })
    return suggestions


def list_all_chains() -> str:
    """Return a formatted table of all defined attack chains."""
    lines = [
        "  Forge Suite v5 APEX — Cross-Framework Attack Chains (Pillar 12)",
        "  " + "─" * 70,
    ]
    for c in _CHAIN_DEFINITIONS:
        auto = "AUTO" if c.auto_execute else "MANUAL"
        lines.append(f"  [{c.opsec_level:8}] [{auto:6}] {c.name}")
        lines.append(f"             Trigger: {', '.join(c.trigger_types[:3])}")
        lines.append(f"             Next: {c.next_module} | MITRE: {', '.join(c.mitre_tactics[:2])}")
        lines.append("")
    return "\n".join(lines)
