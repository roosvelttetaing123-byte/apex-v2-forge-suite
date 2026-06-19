"""AutonomousEngine — Fully autonomous VAPT mode for Forge Suite.

Runs complete security assessments without human interaction:
    - run_engagement()         → full VAPT engagement from RECON to REPORT
    - Autonomous phase progression (RECON → SCAN → EXPLOIT → POST → REPORT)
    - auto_confirm gates: safe actions auto-execute, risky ones queue
    - Stop conditions: domain compromise, time limit, finding count
    - Brain-driven module selection: smart module ordering
    - FN sweep after each phase
    - Engagement report at completion

Graceful degradation: works without brain (sequential module execution).

FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

log = logging.getLogger("forge.brain.autonomous")


# ══════════════════════════════════════════════════════════════════════
# DATA MODELS
# ══════════════════════════════════════════════════════════════════════

class EngagementPhase(str, Enum):
    """Autonomous engagement phases."""
    INIT     = "INIT"
    RECON    = "RECON"
    SCAN     = "SCAN"
    EXPLOIT  = "EXPLOIT"
    POST     = "POST"
    REPORT   = "REPORT"
    COMPLETE = "COMPLETE"
    ABORTED  = "ABORTED"


class OpsecLevel(str, Enum):
    """Operational security levels."""
    STEALTH  = "stealth"   # Slow, minimal footprint, max evasion
    STANDARD = "standard"  # Balanced speed vs noise
    NOISY    = "noisy"     # Full speed, don't care about detection


class StopReason(str, Enum):
    """Reasons the engagement stopped."""
    COMPLETED        = "completed"
    DOMAIN_COMPROMISED = "domain_compromised"
    CRITICAL_FOUND   = "critical_found"
    TIME_LIMIT       = "time_limit"
    FINDING_LIMIT    = "finding_limit"
    OPERATOR_ABORT   = "operator_abort"
    ERROR            = "error"


@dataclass
class EngagementProgress:
    """Real-time progress tracker for autonomous mode."""
    phase:              EngagementPhase = EngagementPhase.INIT
    percent_complete:   float           = 0.0
    findings_count:     int             = 0
    credentials_count:  int             = 0
    modules_run:        int             = 0
    modules_total:      int             = 0
    current_module:     str             = ""
    current_target:     str             = ""
    elapsed_seconds:    float           = 0.0
    chains_triggered:   int             = 0
    fn_sweeps_done:     int             = 0
    errors:             int             = 0
    phase_history:      list[str]       = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class EngagementConfig:
    """Configuration for an autonomous engagement."""
    target:             str
    frameworks:         list[str]       = field(default_factory=lambda: ["netforge", "webforge"])
    opsec_level:        OpsecLevel      = OpsecLevel.STANDARD
    stop_on_critical:   bool            = True
    max_findings:       int             = 100
    max_time_seconds:   float           = 3600.0  # 1 hour default
    max_chains:         int             = 20
    auto_confirm_safe:  bool            = True
    fn_sweep_enabled:   bool            = True
    report_at_end:      bool            = True

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["opsec_level"] = self.opsec_level.value
        return d


@dataclass
class EngagementReport:
    """Final report from an autonomous engagement."""
    engagement_id:      str
    target:             str
    started_at:         str
    ended_at:           str
    duration_seconds:   float
    stop_reason:        StopReason
    phase_reached:      EngagementPhase
    config:             dict[str, Any]
    progress:           dict[str, Any]
    findings_summary:   dict[str, Any]
    executive_summary:  str             = ""
    attack_narrative:   str             = ""
    remediation_roadmap: str            = ""
    risk_scenario:      str             = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["stop_reason"] = self.stop_reason.value
        d["phase_reached"] = self.phase_reached.value
        return d


# ══════════════════════════════════════════════════════════════════════
# MODULE SETS PER FRAMEWORK / PHASE
# ══════════════════════════════════════════════════════════════════════

# Modules safe for auto-execution (passive/recon)
_SAFE_MODULES = frozenset({
    "port_scanner", "service_scanner", "os_fingerprint", "dns_enum",
    "subdomain_enum", "whois_lookup", "cert_check", "header_check",
    "ssl_scanner", "cors_scanner", "csp_scanner", "cookie_audit",
    "security_headers", "robots_check", "sitemap_check",
    "technology_detect", "waf_detect", "cms_detect", "version_detect",
    "crawler", "spider", "directory_bruteforce", "vhost_enum",
    "email_enum", "user_enum", "api_discovery",
    "ad_enum", "bloodhound_collect", "ldap_enum", "dns_zone",
    "trust_enum", "gpo_enum", "acl_enum",
})

# Modules that ALWAYS need human approval even in autonomous mode
_ALWAYS_CONFIRM = frozenset({
    "rootkit_deploy", "process_hollow", "dkom_hide",
    "data_exfil", "wipe_logs", "dos_test",
    "persistence_schtask", "persistence_registry",
    "persistence_service", "persistence_cron",
})

# Default module execution order per framework/phase
_PHASE_MODULES: dict[str, dict[str, list[str]]] = {
    "netforge": {
        "RECON": [
            "port_scanner", "service_scanner", "os_fingerprint",
            "dns_enum", "subdomain_enum",
        ],
        "SCAN": [
            "vuln_scanner", "ssl_scanner", "smb_scanner",
            "ssh_scanner", "rdp_scanner", "ftp_scanner",
        ],
        "EXPLOIT": [
            "credential_spray", "brute_force",
            "smb_exploit", "ssh_exploit",
        ],
        "POST": [
            "sam_dump", "mimikatz", "token_steal",
            "lateral_smb", "lateral_ssh",
        ],
    },
    "webforge": {
        "RECON": [
            "crawler", "technology_detect", "waf_detect",
            "header_check", "security_headers", "ssl_scanner",
            "robots_check", "sitemap_check",
        ],
        "SCAN": [
            "sqli_scanner", "xss_scanner", "ssti_scanner",
            "ssrf_scanner", "cmd_inject", "lfi_rfi",
            "xxe_scanner", "idor_scanner", "cors_scanner",
            "cookie_audit", "jwt_scanner",
        ],
        "EXPLOIT": [
            "sqli_exploit", "file_upload_exploit",
            "auth_bypass", "session_hijack",
        ],
        "POST": [
            "webshell_deploy",
        ],
    },
    "adforge": {
        "RECON": [
            "ad_enum", "ldap_enum", "dns_zone",
            "trust_enum", "gpo_enum", "acl_enum",
            "bloodhound_collect",
        ],
        "SCAN": [
            "kerberoast", "asrep_roast", "delegation_check",
            "adcs_check", "zerologon_check",
            "esc1_check", "esc2_check", "esc3_check", "esc4_check",
            "esc6_check", "esc7_check", "esc8_check", "esc9_check",
            "esc10_check", "esc11_check", "esc13_check", "esc14_check",
        ],
        "EXPLOIT": [
            "kerberoast_crack", "ntlm_relay",
            "dcsync", "golden_ticket",
            "shadow_creds", "acl_abuse", "certifried",
        ],
        "POST": [
            "lateral_smb", "lateral_wmi", "lateral_winrm",
        ],
    },
    "aiforge": {
        "RECON": [
            "model_enum", "api_discover", "prompt_probe",
        ],
        "SCAN": [
            "prompt_injection", "jailbreak_test",
            "data_extraction", "model_inversion",
        ],
        "EXPLOIT": [
            "jailbreak_exploit", "indirect_prompt_inject_chain", "model_data_exfil",
        ],
        "POST": [
            "conversation_persist", "model_backdoor_test",
        ],
    },
}


# ══════════════════════════════════════════════════════════════════════
# AUTONOMOUS ENGINE
# ══════════════════════════════════════════════════════════════════════

class AutonomousEngine:
    """Fully autonomous VAPT engine.

    Runs complete security assessments without human prompts. Uses
    ForgeBrain for intelligent module selection and AttackPlanner for
    kill chain progression. Falls back to sequential execution when
    brain is unavailable.

    Usage::

        from common.brain.brain import ForgeBrain
        from common.brain.planner import AttackPlanner
        from common.brain.engagement_bus import EngagementBus

        brain = ForgeBrain()
        planner = AttackPlanner(brain)
        eng_bus = EngagementBus.get_instance(brain=brain, planner=planner)

        engine = AutonomousEngine(
            brain=brain, planner=planner, engagement_bus=eng_bus
        )

        config = EngagementConfig(
            target="https://target.com",
            frameworks=["webforge", "netforge"],
            opsec_level=OpsecLevel.STANDARD,
            stop_on_critical=True,
        )

        report = await engine.run_engagement(config)
        print(report.executive_summary)
    """

    def __init__(
        self,
        brain: Any | None = None,
        planner: Any | None = None,
        engagement_bus: Any | None = None,
        narrator: Any | None = None,
        analyst: Any | None = None,
        event_bus: Any | None = None,
    ) -> None:
        """Initialize the autonomous engine.

        Args:
            brain:          ForgeBrain instance for AI decisions.
            planner:        AttackPlanner for phase progression.
            engagement_bus: EngagementBus for cross-framework exchange.
            narrator:       ReportNarrator for report generation.
            analyst:        FindingAnalyst for FP/FN analysis.
            event_bus:      Dashboard EventBus for real-time updates.
        """
        self._brain = brain
        self._planner = planner
        self._eng_bus = engagement_bus
        self._narrator = narrator
        self._analyst = analyst
        self._event_bus = event_bus

        # State
        self._progress = EngagementProgress()
        self._chain_log: list[dict[str, Any]] = []
        self._review_queue: list[dict[str, Any]] = []
        self._running = False
        self._aborted = False
        self._start_time = 0.0

        # Subscribe to bus so findings_count stays current
        if engagement_bus:
            engagement_bus.subscribe(self._on_finding_published)

    @property
    def progress(self) -> EngagementProgress:
        """Current engagement progress."""
        return self._progress

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def review_queue(self) -> list[dict[str, Any]]:
        """Actions queued for optional human review."""
        return list(self._review_queue)

    def abort(self) -> None:
        """Signal the engine to abort the engagement."""
        self._aborted = True
        log.warning("Autonomous engagement abort requested")

    def _on_finding_published(self, framework: str, finding: dict[str, Any]) -> None:
        """Increment findings_count when the bus receives a new finding."""
        self._progress.findings_count += 1

    async def run_engagement(
        self, config: EngagementConfig
    ) -> EngagementReport:
        """Run a full autonomous VAPT engagement.

        Progresses through RECON → SCAN → EXPLOIT → POST → REPORT
        phases, using brain-driven module selection when available.

        Args:
            config: Engagement configuration.

        Returns:
            EngagementReport with findings, narrative, and recommendations.
        """
        import uuid as _uuid
        engagement_id = str(_uuid.uuid4())[:12]
        started_at = datetime.now(timezone.utc).isoformat()
        self._start_time = time.monotonic()
        self._running = True
        self._aborted = False
        self._progress = EngagementProgress()
        self._chain_log = []
        self._review_queue = []

        stop_reason = StopReason.COMPLETED

        log.info(
            "Autonomous engagement started: %s → %s (frameworks=%s, opsec=%s)",
            engagement_id, config.target,
            ",".join(config.frameworks), config.opsec_level.value,
        )

        self._emit_progress("engagement_start", {
            "engagement_id": engagement_id,
            "target": config.target,
            "frameworks": config.frameworks,
        })

        try:
            # Execute each phase
            phases = [
                EngagementPhase.RECON,
                EngagementPhase.SCAN,
                EngagementPhase.EXPLOIT,
                EngagementPhase.POST,
            ]
            total_phases = len(phases)

            for phase_idx, phase in enumerate(phases):
                if self._aborted:
                    stop_reason = StopReason.OPERATOR_ABORT
                    break

                # Check stop conditions
                stop = self._check_stop_conditions(config)
                if stop:
                    stop_reason = stop
                    break

                # Advance phase
                self._progress.phase = phase
                self._progress.phase_history.append(phase.value)
                self._progress.percent_complete = (phase_idx / total_phases) * 100

                log.info("Phase %s started", phase.value)
                self._emit_progress("phase_start", {"phase": phase.value})

                # Get modules for this phase
                modules = self._get_modules_for_phase(
                    config.frameworks, phase.value, config
                )
                self._progress.modules_total += len(modules)

                # Execute modules
                for module_info in modules:
                    if self._aborted:
                        break

                    stop = self._check_stop_conditions(config)
                    if stop:
                        stop_reason = stop
                        break

                    fw = module_info["framework"]
                    mod = module_info["module"]
                    self._progress.current_module = f"{fw}/{mod}"
                    self._progress.current_target = config.target

                    # Auto-confirm gate
                    if not self._should_auto_execute(mod, phase.value, config):
                        self._review_queue.append({
                            "framework": fw,
                            "module": mod,
                            "phase": phase.value,
                            "target": config.target,
                            "reason": "Requires operator confirmation",
                        })
                        log.info(
                            "Queued for review: %s/%s (phase=%s)",
                            fw, mod, phase.value,
                        )
                        continue

                    # Execute module (simulated — actual execution hooks
                    # into framework orchestrators)
                    await self._execute_module(fw, mod, config)
                    self._progress.modules_run += 1

                # FN sweep after each phase
                if config.fn_sweep_enabled and not self._aborted:
                    await self._fn_sweep(config, phase.value)

                self._emit_progress("phase_complete", {"phase": phase.value})

            # Report phase
            if not self._aborted:
                self._progress.phase = EngagementPhase.REPORT
                self._progress.percent_complete = 90.0
                report_content = await self._generate_report(config)
            else:
                report_content = {
                    "executive_summary": "",
                    "attack_narrative": "",
                    "remediation_roadmap": "",
                    "risk_scenario": "",
                }

        except Exception as exc:
            log.error("Autonomous engagement error: %s", exc)
            stop_reason = StopReason.ERROR
            report_content = {
                "executive_summary": f"Engagement aborted due to error: {exc}",
                "attack_narrative": "",
                "remediation_roadmap": "",
                "risk_scenario": "",
            }

        # Final state
        ended_at = datetime.now(timezone.utc).isoformat()
        elapsed = time.monotonic() - self._start_time
        self._progress.elapsed_seconds = elapsed
        self._progress.percent_complete = 100.0
        self._progress.phase = (
            EngagementPhase.ABORTED if self._aborted else EngagementPhase.COMPLETE
        )
        self._running = False

        # Build findings summary
        findings_summary = self._build_findings_summary()

        log.info(
            "Autonomous engagement complete: %s (reason=%s, findings=%d, elapsed=%.0fs)",
            engagement_id, stop_reason.value,
            self._progress.findings_count, elapsed,
        )

        self._emit_progress("engagement_complete", {
            "engagement_id": engagement_id,
            "stop_reason": stop_reason.value,
            "findings_count": self._progress.findings_count,
            "elapsed_seconds": elapsed,
        })

        return EngagementReport(
            engagement_id=engagement_id,
            target=config.target,
            started_at=started_at,
            ended_at=ended_at,
            duration_seconds=elapsed,
            stop_reason=stop_reason,
            phase_reached=self._progress.phase,
            config=config.to_dict(),
            progress=self._progress.to_dict(),
            findings_summary=findings_summary,
            **report_content,
        )

    # ══════════════════════════════════════════════════════════════════
    # INTERNAL METHODS
    # ══════════════════════════════════════════════════════════════════

    def _check_stop_conditions(self, config: EngagementConfig) -> StopReason | None:
        """Check if any stop condition has been met."""
        elapsed = time.monotonic() - self._start_time

        if elapsed >= config.max_time_seconds:
            log.info("Time limit reached (%.0fs)", elapsed)
            return StopReason.TIME_LIMIT

        if self._progress.findings_count >= config.max_findings:
            log.info("Finding limit reached (%d)", self._progress.findings_count)
            return StopReason.FINDING_LIMIT

        # Check for domain compromise and critical findings (single intel fetch)
        if self._eng_bus:
            intel = self._eng_bus.get_intel()
            has_domain_admin = any(
                "domain admin" in (f.get("title") or "").lower()
                or "dcsync" in (f.get("title") or "").lower()
                or "golden ticket" in (f.get("title") or "").lower()
                for f in intel.findings
            )
            if has_domain_admin:
                log.info("Domain compromise detected — engagement objective achieved")
                return StopReason.DOMAIN_COMPROMISED

            if config.stop_on_critical:
                crits = intel.severity_counts.get("Critical", 0)
                if crits > 0 and self._progress.phase in (
                    EngagementPhase.EXPLOIT, EngagementPhase.POST
                ):
                    log.info("Critical finding detected in exploit phase — stopping")
                    return StopReason.CRITICAL_FOUND

        return None

    def _get_modules_for_phase(
        self,
        frameworks: list[str],
        phase: str,
        config: EngagementConfig,
    ) -> list[dict[str, str]]:
        """Get ordered module list for a phase across frameworks.

        If brain is available, uses brain-driven module selection.
        Otherwise, uses the default sequential order.
        """
        modules: list[dict[str, str]] = []

        for fw in frameworks:
            fw_modules = _PHASE_MODULES.get(fw, {}).get(phase, [])
            for mod in fw_modules:
                modules.append({"framework": fw, "module": mod})

        # If brain available, let it reorder/filter based on intel
        if self._brain and getattr(self._brain, "available", False) and self._eng_bus:
            modules = self._brain_driven_selection(modules, phase, config)

        return modules

    def _brain_driven_selection(
        self,
        modules: list[dict[str, str]],
        phase: str,
        config: EngagementConfig,
    ) -> list[dict[str, str]]:
        """Use brain to intelligently reorder/filter modules.

        Based on current intel, the brain can:
        - Skip irrelevant modules (e.g., AD modules if no AD found)
        - Prioritize modules likely to succeed
        - Add modules not in default list
        """
        if not self._eng_bus:
            return modules

        intel = self._eng_bus.get_intel()
        findings = intel.findings

        # Simple heuristic: if we have creds, prioritize credential-using modules
        has_creds = len(intel.credentials) > 0
        has_web_vuln = any(
            f.get("framework") == "webforge" for f in findings
        )
        has_ad_info = any(
            f.get("framework") == "adforge" for f in findings
        )

        # Reorder: push relevant modules up
        scored: list[tuple[int, dict[str, str]]] = []
        for mod_info in modules:
            fw = mod_info["framework"]
            mod = mod_info["module"]
            score = 50  # default

            # Boost credential-using modules if we have creds
            if has_creds and mod in ("credential_spray", "brute_force",
                                      "lateral_smb", "lateral_ssh"):
                score = 10

            # Boost AD modules if we found AD info
            if has_ad_info and fw == "adforge":
                score = 20

            # Boost web exploit modules if we have web vulns
            if has_web_vuln and fw == "webforge" and phase == "EXPLOIT":
                score = 15

            # Deprioritize AD modules if no AD found in recon
            if not has_ad_info and fw == "adforge" and phase != "RECON":
                score = 90

            scored.append((score, mod_info))

        scored.sort(key=lambda x: x[0])
        return [m for _, m in scored]

    def _should_auto_execute(
        self, module: str, phase: str, config: EngagementConfig
    ) -> bool:
        """Determine if a module should auto-execute.

        Args:
            module: Module name.
            phase:  Current phase.
            config: Engagement config.

        Returns:
            True if the module can execute without human approval.
        """
        if not config.auto_confirm_safe:
            return False

        if module in _ALWAYS_CONFIRM:
            return False

        if module in _SAFE_MODULES:
            return True

        if phase == "RECON":
            return True

        # In standard opsec, allow scanning modules
        if config.opsec_level in (OpsecLevel.STANDARD, OpsecLevel.NOISY):
            if phase == "SCAN":
                return True

        # In noisy mode, allow exploitation too
        if config.opsec_level == OpsecLevel.NOISY:
            if phase == "EXPLOIT" and module not in _ALWAYS_CONFIRM:
                return True

        return False

    async def _execute_module(
        self,
        framework: str,
        module: str,
        config: EngagementConfig,
    ) -> None:
        """Execute a single module.

        This is the integration point where the autonomous engine
        hooks into the actual framework orchestrators. Currently
        logs the execution — actual wiring happens in 9G.
        """
        log.info("Executing: %s/%s → %s", framework, module, config.target)

        self._chain_log.append({
            "action": f"Execute {module}",
            "framework": framework,
            "module": module,
            "target": config.target,
            "phase": self._progress.phase.value,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "result": "executed",
        })

        self._emit_progress("module_execute", {
            "framework": framework,
            "module": module,
            "target": config.target,
            "phase": self._progress.phase.value,
        })

        # Apply opsec jitter
        if config.opsec_level == OpsecLevel.STEALTH:
            import random
            jitter = random.uniform(1.0, 5.0)
            await asyncio.sleep(jitter)
        elif config.opsec_level == OpsecLevel.STANDARD:
            import random
            jitter = random.uniform(0.2, 1.0)
            await asyncio.sleep(jitter)
        # NOISY: no jitter

    async def _fn_sweep(self, config: EngagementConfig, phase: str) -> None:
        """Run false negative sweep after a phase.

        Uses FindingAnalyst.detect_false_negatives() to identify
        likely missed vulnerabilities and queue follow-up modules.
        """
        if not self._analyst:
            return

        log.info("FN sweep for phase %s", phase)
        self._progress.fn_sweeps_done += 1

        try:
            findings = []
            modules_run = []
            if self._eng_bus:
                findings = self._eng_bus.get_all_findings()
                modules_run = list(set(
                    f.get("module", "") for f in findings if f.get("module")
                ))

            hints = await self._analyst.detect_false_negatives(
                findings, modules_run, {"target": config.target}
            )

            for hint in hints:
                log.info(
                    "FN hint: %s → suggest %s (priority=%d)",
                    hint.likely_vuln, hint.suggested_module, hint.priority,
                )
                if (
                    config.auto_confirm_safe
                    and self._should_auto_execute(hint.suggested_module, phase, config)
                ):
                    await self._execute_module("auto", hint.suggested_module, config)
                    self._progress.modules_run += 1
                else:
                    self._review_queue.append({
                        "framework": "auto",
                        "module": hint.suggested_module,
                        "phase": phase,
                        "target": config.target,
                        "reason": f"FN sweep: {hint.likely_vuln} — {hint.reason}",
                        "fn_hint": True,
                    })

        except Exception as exc:
            log.warning("FN sweep failed for phase %s: %s", phase, exc)

    async def _generate_report(
        self, config: EngagementConfig
    ) -> dict[str, str]:
        """Generate engagement report using the narrator."""
        findings = []
        if self._eng_bus:
            findings = self._eng_bus.get_all_findings()

        result: dict[str, str] = {
            "executive_summary": "",
            "attack_narrative": "",
            "remediation_roadmap": "",
            "risk_scenario": "",
        }

        if self._narrator:
            try:
                result["executive_summary"] = await self._narrator.executive_summary(
                    findings, config.target,
                    engagement=f"Autonomous Assessment — {config.target}",
                )
            except Exception as exc:
                log.warning("Report executive_summary failed: %s", exc)

            try:
                result["attack_narrative"] = await self._narrator.attack_narrative(
                    self._chain_log,
                )
            except Exception as exc:
                log.warning("Report attack_narrative failed: %s", exc)

            try:
                result["remediation_roadmap"] = await self._narrator.remediation_roadmap(
                    findings,
                )
            except Exception as exc:
                log.warning("Report remediation_roadmap failed: %s", exc)

            try:
                result["risk_scenario"] = await self._narrator.risk_scenario(
                    findings,
                )
            except Exception as exc:
                log.warning("Report risk_scenario failed: %s", exc)
        else:
            # Basic fallback report
            result["executive_summary"] = (
                f"# Autonomous Assessment — {config.target}\n\n"
                f"**Findings:** {len(findings)}\n"
                f"**Duration:** {self._progress.elapsed_seconds:.0f}s\n"
                f"**Frameworks:** {', '.join(config.frameworks)}\n"
            )

        return result

    def _build_findings_summary(self) -> dict[str, Any]:
        """Build a findings summary dict."""
        if not self._eng_bus:
            return {
                "total": self._progress.findings_count,
                "by_severity": {},
                "by_framework": {},
            }

        intel = self._eng_bus.get_intel()
        findings = intel.findings

        by_framework: dict[str, int] = {}
        for f in findings:
            fw = f.get("framework", "unknown")
            by_framework[fw] = by_framework.get(fw, 0) + 1

        return {
            "total": len(findings),
            "by_severity": intel.severity_counts,
            "by_framework": by_framework,
            "credentials_found": len(intel.credentials),
            "chains_triggered": self._progress.chains_triggered,
            "review_queue_size": len(self._review_queue),
        }

    def _emit_progress(self, event_type: str, data: dict[str, Any]) -> None:
        """Emit a progress event to the dashboard."""
        if not self._event_bus:
            return
        try:
            from common.dashboard.event_bus import Event, EventType
            self._event_bus.emit(Event(
                event_type=EventType.STATE_SNAPSHOT,
                data={"sub_type": f"autonomous_{event_type}", **data},
                source="autonomous_engine",
            ))
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════
# TESTS
# ══════════════════════════════════════════════════════════════════════

class TestAutonomousEngine:
    """Unit tests for AutonomousEngine."""

    def test_init(self) -> None:
        engine = AutonomousEngine()
        assert not engine.is_running
        assert engine.progress.phase == EngagementPhase.INIT

    def test_engagement_config_defaults(self) -> None:
        config = EngagementConfig(target="https://example.com")
        assert config.target == "https://example.com"
        assert config.opsec_level == OpsecLevel.STANDARD
        assert config.stop_on_critical is True
        assert config.max_time_seconds == 3600.0

    def test_config_to_dict(self) -> None:
        config = EngagementConfig(
            target="10.0.0.0/24",
            frameworks=["netforge", "adforge"],
            opsec_level=OpsecLevel.STEALTH,
        )
        d = config.to_dict()
        assert d["opsec_level"] == "stealth"
        assert "netforge" in d["frameworks"]

    def test_progress_to_dict(self) -> None:
        progress = EngagementProgress(
            phase=EngagementPhase.SCAN,
            percent_complete=45.0,
            findings_count=12,
        )
        d = progress.to_dict()
        assert d["findings_count"] == 12

    def test_should_auto_execute_safe(self) -> None:
        engine = AutonomousEngine()
        config = EngagementConfig(target="test")
        assert engine._should_auto_execute("port_scanner", "RECON", config) is True

    def test_should_auto_execute_dangerous(self) -> None:
        engine = AutonomousEngine()
        config = EngagementConfig(target="test")
        assert engine._should_auto_execute("rootkit_deploy", "EXPLOIT", config) is False

    def test_should_auto_execute_scan_standard(self) -> None:
        engine = AutonomousEngine()
        config = EngagementConfig(
            target="test", opsec_level=OpsecLevel.STANDARD
        )
        assert engine._should_auto_execute("sqli_scanner", "SCAN", config) is True

    def test_should_auto_execute_exploit_noisy(self) -> None:
        engine = AutonomousEngine()
        config = EngagementConfig(
            target="test", opsec_level=OpsecLevel.NOISY
        )
        assert engine._should_auto_execute("credential_spray", "EXPLOIT", config) is True

    def test_should_auto_execute_exploit_stealth(self) -> None:
        engine = AutonomousEngine()
        config = EngagementConfig(
            target="test", opsec_level=OpsecLevel.STEALTH
        )
        # Exploit phase in stealth mode should not auto-execute
        assert engine._should_auto_execute("credential_spray", "EXPLOIT", config) is False

    def test_should_auto_execute_disabled(self) -> None:
        engine = AutonomousEngine()
        config = EngagementConfig(target="test", auto_confirm_safe=False)
        assert engine._should_auto_execute("port_scanner", "RECON", config) is False

    def test_get_modules_for_phase(self) -> None:
        engine = AutonomousEngine()
        config = EngagementConfig(target="test")
        modules = engine._get_modules_for_phase(["webforge"], "RECON", config)
        assert len(modules) > 0
        assert all(m["framework"] == "webforge" for m in modules)

    def test_get_modules_multi_framework(self) -> None:
        engine = AutonomousEngine()
        config = EngagementConfig(target="test")
        modules = engine._get_modules_for_phase(
            ["netforge", "webforge"], "RECON", config
        )
        frameworks = set(m["framework"] for m in modules)
        assert "netforge" in frameworks
        assert "webforge" in frameworks

    def test_abort(self) -> None:
        engine = AutonomousEngine()
        engine.abort()
        assert engine._aborted is True

    def test_engagement_report_to_dict(self) -> None:
        report = EngagementReport(
            engagement_id="test-123",
            target="https://example.com",
            started_at="2026-01-01T00:00:00Z",
            ended_at="2026-01-01T01:00:00Z",
            duration_seconds=3600.0,
            stop_reason=StopReason.COMPLETED,
            phase_reached=EngagementPhase.COMPLETE,
            config={},
            progress={},
            findings_summary={"total": 5},
        )
        d = report.to_dict()
        assert d["stop_reason"] == "completed"
        assert d["phase_reached"] == "COMPLETE"
        assert d["findings_summary"]["total"] == 5

    def test_run_engagement_basic(self) -> None:
        """Test run_engagement completes without errors in headless mode."""
        import asyncio
        engine = AutonomousEngine()
        config = EngagementConfig(
            target="https://example.com",
            frameworks=["webforge"],
            max_time_seconds=5.0,  # Short timeout
        )
        report = asyncio.run(engine.run_engagement(config))
        assert report.engagement_id
        assert report.stop_reason in (StopReason.COMPLETED, StopReason.TIME_LIMIT)
        assert report.duration_seconds > 0

    def test_stop_conditions_time_limit(self) -> None:
        engine = AutonomousEngine()
        engine._start_time = time.monotonic() - 10000  # Way past
        config = EngagementConfig(target="test", max_time_seconds=1.0)
        reason = engine._check_stop_conditions(config)
        assert reason == StopReason.TIME_LIMIT

    def test_stop_conditions_finding_limit(self) -> None:
        engine = AutonomousEngine()
        engine._start_time = time.monotonic()
        engine._progress.findings_count = 200
        config = EngagementConfig(target="test", max_findings=100)
        reason = engine._check_stop_conditions(config)
        assert reason == StopReason.FINDING_LIMIT

    def test_brain_driven_selection_no_brain(self) -> None:
        """Without brain, module order should be unchanged."""
        engine = AutonomousEngine()
        config = EngagementConfig(target="test")
        modules = engine._get_modules_for_phase(["netforge"], "RECON", config)
        # Should return default order without brain
        assert modules[0]["module"] == "port_scanner"

    def test_on_finding_published_increments_count(self) -> None:
        engine = AutonomousEngine()
        assert engine._progress.findings_count == 0
        engine._on_finding_published("webforge", {"title": "test"})
        assert engine._progress.findings_count == 1
        engine._on_finding_published("netforge", {"title": "test2"})
        assert engine._progress.findings_count == 2

    def test_adcs_esc_modules_in_phase(self) -> None:
        engine = AutonomousEngine()
        config = EngagementConfig(target="test")
        modules = engine._get_modules_for_phase(["adforge"], "SCAN", config)
        module_names = [m["module"] for m in modules]
        assert "esc1_check" in module_names
        assert "esc8_check" in module_names
        assert "esc14_check" in module_names

    def test_adforge_exploit_has_new_modules(self) -> None:
        engine = AutonomousEngine()
        config = EngagementConfig(target="test")
        modules = engine._get_modules_for_phase(["adforge"], "EXPLOIT", config)
        module_names = [m["module"] for m in modules]
        assert "shadow_creds" in module_names
        assert "acl_abuse" in module_names
        assert "certifried" in module_names

    def test_aiforge_exploit_modules(self) -> None:
        engine = AutonomousEngine()
        config = EngagementConfig(target="test")
        modules = engine._get_modules_for_phase(["aiforge"], "EXPLOIT", config)
        assert len(modules) > 0
        module_names = [m["module"] for m in modules]
        assert "jailbreak_exploit" in module_names

    def test_check_stop_conditions_single_intel_fetch(self) -> None:
        """Domain compromise and critical check reuse the same intel object."""
        from unittest.mock import MagicMock
        engine = AutonomousEngine()
        engine._start_time = time.monotonic()
        mock_bus = MagicMock()
        mock_bus.get_intel.return_value = MagicMock(
            findings=[{"title": "DCSync Attack Successful"}],
            severity_counts={"Critical": 1},
        )
        engine._eng_bus = mock_bus
        config = EngagementConfig(target="test")
        reason = engine._check_stop_conditions(config)
        assert reason == StopReason.DOMAIN_COMPROMISED
        # Should only have been called once despite two checks
        assert mock_bus.get_intel.call_count == 1
