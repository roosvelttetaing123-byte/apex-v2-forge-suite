"""AttackPlanner — AI-powered attack path planning and kill chain progression.

Wraps ForgeBrain to provide tactical attack planning:
    - plan_next()           → next attack steps based on current intel
    - adapt_to_failure()    → pivot strategy after a failed action
    - adapt_to_discovery()  → react to new findings with follow-up actions
    - autonomous_gate()     → decide if an action can auto-execute

Kill Chain Progression:
    RECON → INITIAL_ACCESS → EXECUTION → PERSISTENCE → PRIV_ESC →
    LATERAL → COLLECTION → EXFIL

Graceful degradation: if brain is unavailable, wraps existing
AttackChain with rule-based planning heuristics.

FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from common.brain.brain import (
    ForgeBrain,
    PlannedAction,
    Confidence,
    RiskLevel,
)

log = logging.getLogger("forge.brain.planner")


# ══════════════════════════════════════════════════════════════════════
# KILL CHAIN PHASES
# ══════════════════════════════════════════════════════════════════════

class KillChainPhase(str, Enum):
    """MITRE ATT&CK-aligned kill chain phases."""
    RECON           = "RECON"
    INITIAL_ACCESS  = "INITIAL_ACCESS"
    EXECUTION       = "EXECUTION"
    PERSISTENCE     = "PERSISTENCE"
    PRIV_ESC        = "PRIV_ESC"
    DEFENSE_EVASION = "DEFENSE_EVASION"
    LATERAL         = "LATERAL"
    COLLECTION      = "COLLECTION"
    EXFIL           = "EXFIL"
    IMPACT          = "IMPACT"


# Phase ordering for progression detection
_PHASE_ORDER = {phase: i for i, phase in enumerate(KillChainPhase)}


# ══════════════════════════════════════════════════════════════════════
# ATTACK PLAN
# ══════════════════════════════════════════════════════════════════════

@dataclass
class PhaseAssessment:
    """Assessment of the current kill chain phase."""
    current_phase:    KillChainPhase
    phase_complete:   bool
    next_phase:       KillChainPhase
    completion_pct:   float  # 0.0 - 1.0
    blockers:         list[str] = field(default_factory=list)


@dataclass
class AttackPlan:
    """Full attack plan with phase assessment and ordered actions."""
    phase:            PhaseAssessment
    actions:          list[PlannedAction]
    total_actions:    int = 0
    auto_executable:  int = 0
    requires_confirm: int = 0

    def __post_init__(self) -> None:
        self.total_actions = len(self.actions)
        self.auto_executable = sum(1 for a in self.actions if a.auto_execute)
        self.requires_confirm = sum(1 for a in self.actions if a.requires_confirm)


# ══════════════════════════════════════════════════════════════════════
# AUTO-EXECUTE SAFETY GATES
# ══════════════════════════════════════════════════════════════════════

# Modules that are SAFE to auto-execute (passive, non-destructive)
_SAFE_MODULES = frozenset({
    # Recon / passive
    "port_scanner", "service_scanner", "os_fingerprint", "dns_enum",
    "subdomain_enum", "whois_lookup", "cert_check", "header_check",
    "ssl_scanner", "cors_scanner", "csp_scanner", "cookie_audit",
    "security_headers", "robots_check", "sitemap_check",
    "technology_detect", "waf_detect", "cms_detect", "version_detect",
    # Info gathering (passive)
    "crawler", "spider", "directory_bruteforce", "vhost_enum",
    "email_enum", "user_enum", "api_discovery",
    # ADForge passive
    "ad_enum", "bloodhound_collect", "ldap_enum", "dns_zone",
    "trust_enum", "gpo_enum", "acl_enum",
})

# Modules that ALWAYS require operator confirmation
_DANGEROUS_MODULES = frozenset({
    # Active exploitation
    "sqli_exploit", "rce_exploit", "file_upload_exploit",
    "credential_spray", "brute_force", "password_spray",
    # Post-exploit
    "sam_dump", "ntds_dump", "mimikatz", "token_steal",
    "lateral_smb", "lateral_wmi", "lateral_winrm", "lateral_psexec",
    "lateral_ssh", "pivot", "persistence_schtask", "persistence_registry",
    "persistence_service", "persistence_cron",
    # Rootkit / evasion
    "rootkit_deploy", "process_hollow", "amsi_bypass", "etw_blind",
    "dll_inject", "dkom_hide",
    # C2
    "beacon_deploy", "stager_deploy",
    # Destructive
    "dos_test", "data_exfil", "wipe_logs",
})

# Actions safe for auto-execute by phase
_SAFE_PHASES = frozenset({
    KillChainPhase.RECON,
})


# ══════════════════════════════════════════════════════════════════════
# ATTACK PLANNER
# ══════════════════════════════════════════════════════════════════════

class AttackPlanner:
    """AI-powered attack path planner.

    Uses ForgeBrain for intelligent attack planning with rule-based
    fallback. Manages kill chain progression, action safety gates,
    and adaptation to new findings or failures.

    Usage::

        brain = ForgeBrain()
        planner = AttackPlanner(brain)

        # Get next attack steps
        plan = await planner.plan_next(intel, target_context, opsec_level="standard")
        for action in plan.actions:
            if action.auto_execute or operator_approves(action):
                execute(action)

        # React to failure
        alternatives = await planner.adapt_to_failure(
            failed_action, error_msg, current_intel
        )

        # React to new finding
        follow_ups = await planner.adapt_to_discovery(
            new_finding, existing_intel
        )
    """

    def __init__(self, brain: ForgeBrain | None = None) -> None:
        """Initialize the planner.

        Args:
            brain: ForgeBrain instance. If None, a new one is created.
        """
        self._brain = brain or ForgeBrain()

    @property
    def brain(self) -> ForgeBrain:
        return self._brain

    async def plan_next(
        self,
        intel: dict[str, Any],
        target_context: dict[str, Any],
        opsec_level: str = "standard",
    ) -> AttackPlan:
        """Plan the next attack steps based on current intelligence.

        Args:
            intel:          All gathered intelligence (findings, creds, hosts).
            target_context: Target info (tech stack, OS, network topology).
            opsec_level:    "stealth", "standard", or "noisy".

        Returns:
            AttackPlan with ordered actions and phase assessment.
        """
        # Assess current kill chain phase
        phase = self._assess_phase(intel)

        # Get planned actions from brain
        actions = await self._brain.plan_next_attack(intel, target_context, opsec_level)

        # Apply safety gates to each action
        for action in actions:
            action.auto_execute = self.autonomous_gate(action)
            if not action.auto_execute:
                action.requires_confirm = True

        # Sort by priority
        actions.sort(key=lambda a: a.priority)

        return AttackPlan(phase=phase, actions=actions)

    async def adapt_to_failure(
        self,
        failed_action: PlannedAction,
        error: str,
        intel: dict[str, Any],
    ) -> list[PlannedAction]:
        """Generate alternative actions after a failure.

        Args:
            failed_action: The action that failed.
            error:         Error message from the failure.
            intel:         Current intelligence state.

        Returns:
            List of alternative PlannedActions to try.
        """
        if self._brain.available:
            try:
                prompt_data = {
                    "task": "adapt_to_failure",
                    "failed_action": {
                        "module": failed_action.module,
                        "framework": failed_action.framework,
                        "target": failed_action.target,
                        "phase": failed_action.phase,
                    },
                    "error": error[:500],
                    "intel_summary": self._summarize_intel(intel),
                }
                import json
                raw = await self._brain._call(
                    json.dumps(prompt_data, indent=2, default=str),
                    model=self._brain._fast_model,
                    max_tokens=1500,
                )
                items = self._brain._parse_json_array(raw)
                return [
                    PlannedAction(
                        priority=item.get("priority", 5),
                        phase=item.get("phase", failed_action.phase),
                        mitre=item.get("mitre", ""),
                        framework=item.get("framework", failed_action.framework),
                        module=item.get("module", ""),
                        target=item.get("target", failed_action.target),
                        rationale=item.get("rationale", ""),
                        auto_execute=False,
                        requires_confirm=True,
                    )
                    for item in items
                ]
            except Exception as exc:
                log.warning("Brain adapt_to_failure failed: %s", exc)

        # Rule-based fallback: suggest alternatives based on failure type
        return self._rule_based_adapt_failure(failed_action, error)

    async def adapt_to_discovery(
        self,
        new_finding: dict[str, Any],
        existing_intel: dict[str, Any],
    ) -> list[PlannedAction]:
        """React to a new finding with follow-up attack actions.

        This is the engine behind cross-framework attack chains:
        e.g., WebForge SQLi → NetForge credential spray.

        Args:
            new_finding:    The newly discovered finding (as dict).
            existing_intel: Current intelligence state.

        Returns:
            List of follow-up PlannedActions triggered by the finding.
        """
        if self._brain.available:
            try:
                import json
                prompt_data = {
                    "task": "adapt_to_discovery",
                    "new_finding": {
                        "title": new_finding.get("title", ""),
                        "severity": new_finding.get("severity", ""),
                        "module": new_finding.get("module", ""),
                        "target": new_finding.get("target", ""),
                        "description": new_finding.get("description", "")[:300],
                    },
                    "intel_summary": self._summarize_intel(existing_intel),
                    "instructions": (
                        "Based on this new finding, what follow-up attack actions should we take? "
                        "Consider cross-framework chains: "
                        "SQLi creds → credential spray, SSRF → internal scan, "
                        "host compromise → lateral movement, etc."
                    ),
                }
                raw = await self._brain._call(
                    json.dumps(prompt_data, indent=2, default=str),
                    model=self._brain._fast_model,
                    max_tokens=1500,
                )
                items = self._brain._parse_json_array(raw)
                return [
                    PlannedAction(
                        priority=item.get("priority", 5),
                        phase=item.get("phase", ""),
                        mitre=item.get("mitre", ""),
                        framework=item.get("framework", ""),
                        module=item.get("module", ""),
                        target=item.get("target", ""),
                        rationale=item.get("rationale", ""),
                        auto_execute=False,
                        requires_confirm=True,
                    )
                    for item in items
                ]
            except Exception as exc:
                log.warning("Brain adapt_to_discovery failed: %s", exc)

        # Rule-based fallback
        return self._rule_based_adapt_discovery(new_finding)

    def autonomous_gate(self, action: PlannedAction) -> bool:
        """Determine if an action should auto-execute without human approval.

        Safety rules:
        - Safe modules (recon/passive) → auto-execute
        - Dangerous modules (exploit/lateral) → always require confirm
        - RECON phase → auto-execute
        - Everything else → require confirm

        Args:
            action: The PlannedAction to evaluate.

        Returns:
            True if safe to auto-execute.
        """
        module = action.module.lower()
        phase = action.phase.upper()

        # Always block dangerous modules
        if module in _DANGEROUS_MODULES:
            return False

        # Always allow safe modules
        if module in _SAFE_MODULES:
            return True

        # Allow auto-execute in safe phases
        try:
            if KillChainPhase(phase) in _SAFE_PHASES:
                return True
        except ValueError:
            pass

        # Default: require confirmation
        return False

    # ── Phase Assessment ──────────────────────────────────────────────

    def _assess_phase(self, intel: dict[str, Any]) -> PhaseAssessment:
        """Assess the current kill chain phase based on gathered intel.

        Analyzes findings, credentials, and access levels to determine
        where we are in the kill chain.
        """
        findings = intel.get("findings", [])
        creds = intel.get("credentials", [])
        shells = intel.get("shells", [])
        persisted = intel.get("persistence", [])
        lateral_moves = intel.get("lateral_moves", [])

        # Determine current phase based on evidence
        has_findings = len(findings) > 0
        has_creds = len(creds) > 0
        has_shells = len(shells) > 0
        has_persistence = len(persisted) > 0
        has_lateral = len(lateral_moves) > 0

        # Work backwards from most advanced phase.
        # phase_complete: True when the next phase's entry condition is already met,
        # meaning we can (or should) advance the kill chain.
        if has_lateral:
            current = KillChainPhase.LATERAL
            next_phase = KillChainPhase.COLLECTION
            completion = 0.7
            phase_complete = len(intel.get("collection", [])) > 0
        elif has_persistence:
            current = KillChainPhase.PERSISTENCE
            next_phase = KillChainPhase.PRIV_ESC
            completion = 0.5
            phase_complete = has_lateral
        elif has_shells:
            current = KillChainPhase.EXECUTION
            next_phase = KillChainPhase.PERSISTENCE
            completion = 0.35
            phase_complete = has_persistence
        elif has_creds:
            current = KillChainPhase.INITIAL_ACCESS
            next_phase = KillChainPhase.EXECUTION
            completion = 0.2
            phase_complete = has_shells
        elif has_findings:
            current = KillChainPhase.RECON
            next_phase = KillChainPhase.INITIAL_ACCESS
            completion = 0.1
            phase_complete = has_creds
        else:
            current = KillChainPhase.RECON
            next_phase = KillChainPhase.RECON
            completion = 0.0
            phase_complete = False

        # Identify blockers
        blockers: list[str] = []
        if not has_findings:
            blockers.append("No vulnerabilities discovered yet")
        if current == KillChainPhase.RECON and not has_creds:
            blockers.append("No credentials obtained — need initial access vector")
        if current == KillChainPhase.EXECUTION and not has_persistence:
            blockers.append("Shell access but no persistence — may lose access")

        return PhaseAssessment(
            current_phase=current,
            phase_complete=phase_complete,
            next_phase=next_phase,
            completion_pct=completion,
            blockers=blockers,
        )

    # ── Rule-Based Fallbacks ──────────────────────────────────────────

    def _rule_based_adapt_failure(
        self,
        failed_action: PlannedAction,
        error: str,
    ) -> list[PlannedAction]:
        """Generate alternatives after failure using rules."""
        alternatives: list[PlannedAction] = []
        error_lower = error.lower()
        module = failed_action.module.lower()

        # WAF/firewall blocked → suggest evasion
        if any(kw in error_lower for kw in ["blocked", "forbidden", "waf", "firewall"]):
            alternatives.append(PlannedAction(
                priority=1,
                phase=failed_action.phase,
                mitre=failed_action.mitre,
                framework=failed_action.framework,
                module=f"{module}_evasion",
                target=failed_action.target,
                rationale="WAF/firewall detected — retry with evasion techniques",
                auto_execute=False,
                requires_confirm=True,
                expected_outcome="Bypass WAF filtering",
            ))

        # Timeout → suggest slower approach
        if "timeout" in error_lower or "timed out" in error_lower:
            alternatives.append(PlannedAction(
                priority=2,
                phase=failed_action.phase,
                mitre=failed_action.mitre,
                framework=failed_action.framework,
                module=module,
                target=failed_action.target,
                rationale="Request timed out — retry with slower rate and longer timeouts",
                auto_execute=False,
                requires_confirm=True,
                expected_outcome="Successful scan with adjusted timing",
            ))

        # Auth required → suggest auth bypass or credential attack
        if any(kw in error_lower for kw in ["401", "403", "unauthorized", "authentication"]):
            alternatives.append(PlannedAction(
                priority=1,
                phase="INITIAL_ACCESS",
                mitre="TA0001/T1078",
                framework=failed_action.framework,
                module="auth_bypass",
                target=failed_action.target,
                rationale="Authentication required — attempt auth bypass or credential attack",
                auto_execute=False,
                requires_confirm=True,
                expected_outcome="Authenticated access obtained",
            ))

        # Connection refused → try different port/service
        if "connection refused" in error_lower or "unreachable" in error_lower:
            alternatives.append(PlannedAction(
                priority=3,
                phase="RECON",
                mitre="TA0043/T1595",
                framework="netforge",
                module="port_scanner",
                target=failed_action.target,
                rationale="Service unreachable — rescan for alternative ports/services",
                auto_execute=True,
                requires_confirm=False,
                expected_outcome="Discover alternative attack surface",
            ))

        # Generic fallback: skip and move to next module
        if not alternatives:
            alternatives.append(PlannedAction(
                priority=5,
                phase=failed_action.phase,
                mitre=failed_action.mitre,
                framework=failed_action.framework,
                module="skip",
                target=failed_action.target,
                rationale=f"Module {module} failed — skipping, trying next module in phase",
                auto_execute=True,
                requires_confirm=False,
                expected_outcome="Continue with remaining modules",
            ))

        return alternatives

    def _rule_based_adapt_discovery(
        self,
        new_finding: dict[str, Any],
    ) -> list[PlannedAction]:
        """React to new finding with rule-based follow-up actions."""
        follow_ups: list[PlannedAction] = []
        title = new_finding.get("title", "").lower()
        module = new_finding.get("module", "").lower()
        target = new_finding.get("target", "")

        # SQLi found → try credential extraction + spray
        if "sqli" in title or "sql injection" in title:
            follow_ups.append(PlannedAction(
                priority=1,
                phase="INITIAL_ACCESS",
                mitre="TA0006/T1003",
                framework="webforge",
                module="sqli_exploit",
                target=target,
                rationale="SQLi confirmed — attempt database credential extraction",
                auto_execute=False,
                requires_confirm=True,
                expected_outcome="Database credentials extracted",
            ))
            follow_ups.append(PlannedAction(
                priority=2,
                phase="INITIAL_ACCESS",
                mitre="TA0001/T1078",
                framework="netforge",
                module="credential_spray",
                target=target,
                rationale="Extracted DB creds → try credential reuse on SMB/SSH/RDP",
                auto_execute=False,
                requires_confirm=True,
                expected_outcome="Credential reuse across services",
            ))

        # XSS found → try stored XSS for session hijack
        if "xss" in title and "stored" not in title:
            follow_ups.append(PlannedAction(
                priority=3,
                phase="INITIAL_ACCESS",
                mitre="TA0004/T1059.007",
                framework="webforge",
                module="xss_stored_test",
                target=target,
                rationale="Reflected XSS found — check for stored XSS for session hijacking",
                auto_execute=False,
                requires_confirm=True,
                expected_outcome="Stored XSS for persistent access",
            ))

        # SSRF found → internal network scan
        if "ssrf" in title:
            follow_ups.append(PlannedAction(
                priority=1,
                phase="RECON",
                mitre="TA0043/T1595",
                framework="netforge",
                module="port_scanner",
                target="internal_via_ssrf",
                rationale="SSRF confirmed — scan internal network through SSRF pivot",
                auto_execute=False,
                requires_confirm=True,
                expected_outcome="Internal network topology discovered",
            ))

        # SMB signing disabled → NTLM relay
        if "smb signing" in title and "disabled" in title:
            follow_ups.append(PlannedAction(
                priority=1,
                phase="INITIAL_ACCESS",
                mitre="TA0001/T1557",
                framework="adforge",
                module="ntlm_relay",
                target=target,
                rationale="SMB signing disabled — NTLM relay to capture credentials",
                auto_execute=False,
                requires_confirm=True,
                expected_outcome="Domain user credentials via NTLM relay",
            ))

        # Host compromise → deploy C2 + run BloodHound
        if any(kw in title for kw in ["shell", "rce", "remote code execution", "command injection"]):
            follow_ups.append(PlannedAction(
                priority=1,
                phase="EXECUTION",
                mitre="TA0011/T1071",
                framework="forge_c2",
                module="beacon_deploy",
                target=target,
                rationale="RCE confirmed — deploy C2 beacon for persistent access",
                auto_execute=False,
                requires_confirm=True,
                expected_outcome="C2 beacon established",
            ))
            follow_ups.append(PlannedAction(
                priority=2,
                phase="RECON",
                mitre="TA0007/T1069",
                framework="adforge",
                module="bloodhound_collect",
                target=target,
                rationale="Host compromised — collect AD topology with BloodHound",
                auto_execute=True,
                requires_confirm=False,
                expected_outcome="AD attack paths identified",
            ))

        # File upload → web shell → C2
        if "file upload" in title or "upload bypass" in title:
            follow_ups.append(PlannedAction(
                priority=1,
                phase="EXECUTION",
                mitre="TA0002/T1505.003",
                framework="webforge",
                module="webshell_deploy",
                target=target,
                rationale="File upload vulnerability — deploy web shell for code execution",
                auto_execute=False,
                requires_confirm=True,
                expected_outcome="Web shell deployed, RCE achieved",
            ))

        # Domain creds → lateral movement
        if "credential" in title or "password" in title or "ntlm" in title:
            follow_ups.append(PlannedAction(
                priority=2,
                phase="LATERAL",
                mitre="TA0008/T1021",
                framework="netforge",
                module="lateral_smb",
                target=target,
                rationale="Domain credentials obtained — attempt lateral movement",
                auto_execute=False,
                requires_confirm=True,
                expected_outcome="Lateral access to additional hosts",
            ))

        return follow_ups

    def _summarize_intel(self, intel: dict[str, Any]) -> dict[str, Any]:
        """Create a compact summary of intel for brain prompts."""
        findings = intel.get("findings", [])
        return {
            "total_findings": len(findings),
            "severity_counts": _count_severities(findings),
            "has_credentials": len(intel.get("credentials", [])) > 0,
            "has_shells": len(intel.get("shells", [])) > 0,
            "has_persistence": len(intel.get("persistence", [])) > 0,
            "modules_active": list(set(
                f.get("module", "") for f in findings if f.get("module")
            )),
        }


def _count_severities(findings: list[dict[str, Any]]) -> dict[str, int]:
    """Count findings by severity."""
    counts: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "Informational")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


# ══════════════════════════════════════════════════════════════════════
# TESTS
# ══════════════════════════════════════════════════════════════════════

class TestAttackPlanner:
    """Unit tests for AttackPlanner."""

    def test_init_without_brain(self) -> None:
        planner = AttackPlanner()
        assert planner.brain is not None

    def test_autonomous_gate_safe_module(self) -> None:
        planner = AttackPlanner()
        action = PlannedAction(
            priority=1, phase="RECON", mitre="TA0043/T1595",
            framework="netforge", module="port_scanner",
            target="10.0.0.1", rationale="Recon scan",
        )
        assert planner.autonomous_gate(action) is True

    def test_autonomous_gate_dangerous_module(self) -> None:
        planner = AttackPlanner()
        action = PlannedAction(
            priority=1, phase="EXECUTION", mitre="TA0002/T1059",
            framework="netforge", module="mimikatz",
            target="10.0.0.1", rationale="Credential dump",
        )
        assert planner.autonomous_gate(action) is False

    def test_autonomous_gate_unknown_module_requires_confirm(self) -> None:
        planner = AttackPlanner()
        action = PlannedAction(
            priority=1, phase="EXECUTION", mitre="",
            framework="webforge", module="custom_exploit",
            target="10.0.0.1", rationale="Custom",
        )
        assert planner.autonomous_gate(action) is False

    def test_phase_assessment_empty_intel(self) -> None:
        planner = AttackPlanner()
        phase = planner._assess_phase({})
        assert phase.current_phase == KillChainPhase.RECON
        assert phase.completion_pct == 0.0
        assert len(phase.blockers) > 0

    def test_phase_assessment_with_findings(self) -> None:
        planner = AttackPlanner()
        intel = {
            "findings": [{"title": "SQLi", "severity": "Critical"}],
            "credentials": [],
            "shells": [],
        }
        phase = planner._assess_phase(intel)
        assert phase.current_phase == KillChainPhase.RECON

    def test_phase_assessment_with_creds(self) -> None:
        planner = AttackPlanner()
        intel = {
            "findings": [{"title": "SQLi"}],
            "credentials": [{"user": "admin", "hash": "abc"}],
            "shells": [],
        }
        phase = planner._assess_phase(intel)
        assert phase.current_phase == KillChainPhase.INITIAL_ACCESS

    def test_phase_assessment_with_shells(self) -> None:
        planner = AttackPlanner()
        intel = {
            "findings": [{"title": "RCE"}],
            "credentials": [{"user": "admin"}],
            "shells": [{"host": "10.0.0.1"}],
            "persistence": [],
        }
        phase = planner._assess_phase(intel)
        assert phase.current_phase == KillChainPhase.EXECUTION

    def test_adapt_failure_waf(self) -> None:
        planner = AttackPlanner()
        action = PlannedAction(
            priority=1, phase="EXECUTION", mitre="TA0002",
            framework="webforge", module="sqli_scanner",
            target="https://example.com", rationale="Test",
        )
        alternatives = planner._rule_based_adapt_failure(action, "403 Forbidden - WAF blocked")
        assert len(alternatives) >= 1
        assert "evasion" in alternatives[0].module.lower() or "evasion" in alternatives[0].rationale.lower()

    def test_adapt_failure_timeout(self) -> None:
        planner = AttackPlanner()
        action = PlannedAction(
            priority=1, phase="RECON", mitre="TA0043",
            framework="netforge", module="port_scanner",
            target="10.0.0.1", rationale="Scan",
        )
        alternatives = planner._rule_based_adapt_failure(action, "Connection timed out")
        assert len(alternatives) >= 1
        assert "timeout" in alternatives[0].rationale.lower() or "timing" in alternatives[0].rationale.lower()

    def test_adapt_discovery_sqli(self) -> None:
        planner = AttackPlanner()
        finding = {
            "title": "SQL Injection — id param",
            "severity": "Critical",
            "module": "sqli_scanner",
            "target": "https://example.com",
        }
        follow_ups = planner._rule_based_adapt_discovery(finding)
        assert len(follow_ups) >= 1
        # Should suggest credential extraction
        modules = [a.module for a in follow_ups]
        assert "sqli_exploit" in modules or "credential_spray" in modules

    def test_adapt_discovery_ssrf(self) -> None:
        planner = AttackPlanner()
        finding = {
            "title": "SSRF — AWS metadata",
            "severity": "Critical",
            "module": "ssrf_scanner",
            "target": "https://example.com",
        }
        follow_ups = planner._rule_based_adapt_discovery(finding)
        assert len(follow_ups) >= 1

    def test_adapt_discovery_rce(self) -> None:
        planner = AttackPlanner()
        finding = {
            "title": "Remote Code Execution via cmd injection",
            "severity": "Critical",
            "module": "cmd_inject",
            "target": "https://example.com",
        }
        follow_ups = planner._rule_based_adapt_discovery(finding)
        # Should suggest C2 beacon deploy + BloodHound
        modules = [a.module for a in follow_ups]
        assert "beacon_deploy" in modules

    def test_attack_plan_counts(self) -> None:
        plan = AttackPlan(
            phase=PhaseAssessment(
                current_phase=KillChainPhase.RECON,
                phase_complete=False,
                next_phase=KillChainPhase.INITIAL_ACCESS,
                completion_pct=0.1,
            ),
            actions=[
                PlannedAction(
                    priority=1, phase="RECON", mitre="", framework="netforge",
                    module="port_scanner", target="10.0.0.1", rationale="Scan",
                    auto_execute=True, requires_confirm=False,
                ),
                PlannedAction(
                    priority=2, phase="EXECUTION", mitre="", framework="webforge",
                    module="sqli_exploit", target="10.0.0.1", rationale="Exploit",
                    auto_execute=False, requires_confirm=True,
                ),
            ],
        )
        assert plan.total_actions == 2
        assert plan.auto_executable == 1
        assert plan.requires_confirm == 1

    def test_phase_complete_recon_no_creds(self) -> None:
        """RECON phase_complete is False when no credentials obtained yet."""
        planner = AttackPlanner()
        intel = {"findings": [{"title": "SQLi"}], "credentials": [], "shells": []}
        phase = planner._assess_phase(intel)
        assert phase.current_phase == KillChainPhase.RECON
        assert phase.phase_complete is False

    def test_phase_complete_lateral_with_collection(self) -> None:
        """LATERAL phase_complete is True when collection data is present."""
        planner = AttackPlanner()
        intel = {
            "findings": [{"title": "RCE"}],
            "credentials": [{"user": "admin"}],
            "shells": [{"host": "10.0.0.1"}],
            "persistence": [{"method": "cron"}],
            "lateral_moves": [{"host": "10.0.0.2"}],
            "collection": [{"data": "secrets.txt"}],
        }
        phase = planner._assess_phase(intel)
        assert phase.current_phase == KillChainPhase.LATERAL
        assert phase.phase_complete is True

    def test_summarize_intel_uses_module_names(self) -> None:
        """_summarize_intel should collect full module names, not split prefixes."""
        planner = AttackPlanner()
        intel = {
            "findings": [
                {"title": "SQLi", "module": "sqli_scanner", "severity": "Critical"},
                {"title": "XSS", "module": "xss_scanner", "severity": "High"},
            ],
            "credentials": [],
        }
        summary = planner._summarize_intel(intel)
        assert "sqli_scanner" in summary["modules_active"]
        assert "xss_scanner" in summary["modules_active"]

    def test_ssrf_follow_up_requires_confirm(self) -> None:
        """SSRF → internal scan follow-up must require operator confirmation."""
        planner = AttackPlanner()
        finding = {
            "title": "SSRF — AWS metadata",
            "severity": "Critical",
            "module": "ssrf_scanner",
            "target": "https://example.com",
        }
        follow_ups = planner._rule_based_adapt_discovery(finding)
        assert len(follow_ups) >= 1
        ssrf_action = follow_ups[0]
        assert ssrf_action.auto_execute is False
        assert ssrf_action.requires_confirm is True

    def test_kill_chain_phase_order(self) -> None:
        """Verify phase ordering is sequential."""
        assert _PHASE_ORDER[KillChainPhase.RECON] < _PHASE_ORDER[KillChainPhase.INITIAL_ACCESS]
        assert _PHASE_ORDER[KillChainPhase.LATERAL] < _PHASE_ORDER[KillChainPhase.EXFIL]

    def test_plan_next_sync(self) -> None:
        """Test plan_next() runs with rule-based fallback."""
        import asyncio
        planner = AttackPlanner()
        intel = {"findings": [], "credentials": []}
        context = {"target": "https://example.com"}
        plan = asyncio.run(planner.plan_next(intel, context))
        assert isinstance(plan, AttackPlan)
        assert plan.phase.current_phase == KillChainPhase.RECON
