"""ForgeBrain — Core AI Reasoning Engine.

Wraps the Anthropic AsyncAnthropic client to provide AI-powered
security analysis across all 4 frameworks: NetForge, WebForge, ADForge, AIForge.

Advisory features:
    - analyze_finding()      → canonical-review-required advisory result
    - detect_false_negatives()→ disabled until canonical plan persistence
    - plan_next_attack()     → disabled until canonical plan persistence
    - advise_evasion()       → disabled until canonical plan persistence
    - interpret_error()      → evidence-lineage-required advisory result
    - write_executive_summary()→ bounded non-authoritative notice
    - write_attack_narrative()→ bounded non-authoritative notice
    - autonomous_decision()  → fail-closed no-action decision

Engagement Memory:
    Rolling buffer of last N events across all frameworks fed to each call.
    SHA-256 cache deduplicates identical findings.

Graceful Degradation:
    Missing model access never relaxes the canonical truth boundary.

FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import time
from collections.abc import Mapping
from collections import deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from common.brain.truth_boundary import (
    advisory_narrative_projection,
    advisory_report_projection,
    project_model_input,
)
from common.evidence import ordinary_finding_projection
from common.redaction import redact_text, redact_value
from common.version import PRODUCT_LABEL

log = logging.getLogger("forge.brain")

_NARRATIVE_DETAIL_WITHHELD = (
    "Observation detail withheld; use verified canonical evidence derivatives."
)
_NARRATIVE_LABEL_FIELDS = (
    "action",
    "target",
    "framework",
    "timestamp",
    "mitre",
    "module",
    "phase",
)


def _ordinary_label(value: Any, *, limit: int = 512) -> str:
    """Return one bounded, redacted narrative label without object traversal."""
    if value is None:
        return ""
    if not isinstance(value, (str, int, float, bool)):
        return "<withheld>"
    return " ".join(redact_text(str(value)).split())[:limit]


def _ordinary_chain_log(value: Any) -> list[dict[str, str]]:
    """Allowlist attack-chain metadata and withhold mutable inline results."""
    if not isinstance(value, list) or len(value) > 10_000:
        raise ValueError("attack narrative chain log is invalid")
    rendered: list[dict[str, str]] = []
    for raw_step in value:
        if not isinstance(raw_step, Mapping):
            raise ValueError("attack narrative chain step is invalid")
        step = {
            field: _ordinary_label(raw_step.get(field))
            for field in _NARRATIVE_LABEL_FIELDS
            if raw_step.get(field) is not None
        }
        step["verification_state"] = _ordinary_label(
            raw_step.get("verification_state") or "unknown",
            limit=100,
        )
        step["proof_type"] = _ordinary_label(
            raw_step.get("proof_type") or "unknown",
            limit=100,
        )
        step["maturity"] = _ordinary_label(
            raw_step.get("maturity") or "experimental",
            limit=100,
        )
        raw_result = raw_step.get("result")
        if raw_result is not None and raw_result != "":
            step["result"] = _NARRATIVE_DETAIL_WITHHELD
        rendered.append(step)
    return rendered


def _ordinary_memory_metadata(value: Any) -> list[dict[str, str]]:
    """Keep only content-free memory metadata in an external-model prompt."""
    if not isinstance(value, list):
        return []
    rendered: list[dict[str, str]] = []
    for raw_entry in value[:100]:
        if not isinstance(raw_entry, Mapping):
            continue
        rendered.append(
            {
                field: _ordinary_label(raw_entry.get(field), limit=200)
                for field in ("timestamp", "event_type", "framework")
            }
        )
    return rendered


# ══════════════════════════════════════════════════════════════════════
# DATA MODELS
# ══════════════════════════════════════════════════════════════════════

class Verdict(str, Enum):
    """FP analysis verdict."""
    TRUE_POSITIVE      = "TRUE_POSITIVE"
    FALSE_POSITIVE     = "FALSE_POSITIVE"
    NEEDS_VERIFICATION = "NEEDS_VERIFICATION"


class Confidence(str, Enum):
    """Confidence level for brain outputs."""
    HIGH   = "HIGH"
    MEDIUM = "MEDIUM"
    LOW    = "LOW"


class RiskLevel(str, Enum):
    """Risk level for autonomous decisions."""
    NONE     = "NONE"
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class AnalysisResult:
    """Result from analyze_finding()."""
    finding_id:          str
    verdict:             Verdict
    confidence:          Confidence
    reasoning:           str
    action:              str           = ""
    severity_adjustment: str           = ""  # "upgrade", "downgrade", "unchanged"
    fn_risk:             str           = ""  # risk of this being a FN if dismissed


@dataclass
class FalseNegativeHint:
    """A likely missed vulnerability from detect_false_negatives()."""
    likely_vuln:      str
    reason:           str
    suggested_module: str
    suggested_payload: str = ""
    priority:         int  = 5
    mitre:            str  = ""


@dataclass
class PlannedAction:
    """A single step in an attack plan."""
    priority:         int
    phase:            str
    mitre:            str
    framework:        str
    module:           str
    target:           str
    rationale:        str
    auto_execute:     bool = False
    requires_confirm: bool = True
    expected_outcome: str  = ""

    def __post_init__(self) -> None:
        # Model and rule-based planner output is advisory metadata only.
        self.auto_execute = False
        self.requires_confirm = True


@dataclass
class EvasionAdvice:
    """WAF/filter bypass payload suggestion."""
    payload:    str
    technique:  str
    confidence: Confidence
    notes:      str = ""


@dataclass
class ErrorInterpretation:
    """Interpretation of an error response."""
    interpretation:  str
    technology:      str
    is_injectable:   bool = False
    filter_detected: bool = False
    next_payload:    str  = ""
    confidence:      Confidence = Confidence.MEDIUM


@dataclass
class AutonomousDecision:
    """Decision from autonomous mode."""
    decision:   str
    reasoning:  str
    confidence: Confidence
    risk_level: RiskLevel
    abort:      bool = False


@dataclass
class EngagementMemoryEntry:
    """Single entry in the engagement memory."""
    timestamp:  str
    event_type: str
    framework:  str
    data:       dict[str, Any]


@dataclass
class BrainStats:
    """Runtime statistics for the brain engine."""
    model:             str
    fast_model:        str
    memory_entries:    int
    cache_size:        int
    cache_hits:        int
    total_calls:       int
    calls_last_minute: int
    api_available:     bool


# ══════════════════════════════════════════════════════════════════════
# TOKEN BUCKET RATE LIMITER
# ══════════════════════════════════════════════════════════════════════

class _TokenBucket:
    """Token-bucket rate limiter for API calls."""

    def __init__(self, rate_per_minute: int = 20) -> None:
        self._rate = rate_per_minute
        self._tokens = float(rate_per_minute)
        self._max_tokens = float(rate_per_minute)
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()
        self._call_timestamps: deque[float] = deque(maxlen=rate_per_minute * 2)

    async def acquire(self) -> None:
        """Wait until a token is available, then consume one."""
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            self._tokens = min(
                self._max_tokens,
                self._tokens + elapsed * (self._rate / 60.0),
            )
            self._last_refill = now

            if self._tokens < 1.0:
                wait_time = (1.0 - self._tokens) / (self._rate / 60.0)
                await asyncio.sleep(wait_time)
                self._tokens = 0.0
            else:
                self._tokens -= 1.0

            self._call_timestamps.append(time.monotonic())

    @property
    def calls_last_minute(self) -> int:
        cutoff = time.monotonic() - 60.0
        return sum(1 for t in self._call_timestamps if t > cutoff)


# ══════════════════════════════════════════════════════════════════════
# ENGAGEMENT MEMORY
# ══════════════════════════════════════════════════════════════════════

class EngagementMemory:
    """Rolling engagement context buffer.

    Stores the last N events across all frameworks and provides
    context windows for brain API calls.
    """

    def __init__(
        self,
        max_entries: int = 100,
        *,
        tenant_id: str = "default",
        engagement_id: str = "default-engagement",
    ) -> None:
        self._entries: deque[EngagementMemoryEntry] = deque(maxlen=max_entries)
        self._max = max_entries
        self._tenant_id = str(tenant_id)
        self._engagement_id = str(engagement_id)

    def add(self, event_type: str, framework: str, data: dict[str, Any]) -> None:
        """Record only a bounded allowlisted tenant-scoped projection."""
        projected = project_model_input(
            {"event_type": event_type, **dict(data)},
            tenant_id=self._tenant_id,
            engagement_id=self._engagement_id,
        )
        self._entries.append(EngagementMemoryEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type=event_type,
            framework=framework,
            data=projected,
        ))

    def get_context(self, last_n: int = 15) -> list[dict[str, Any]]:
        """Get the most recent N entries as dicts for prompt injection."""
        entries = list(self._entries)[-last_n:]
        return [
            {
                "timestamp": e.timestamp,
                "event_type": e.event_type,
                "framework": e.framework,
                "data": e.data,
            }
            for e in entries
        ]

    def get_findings_context(self, last_n: int = 30) -> list[dict[str, Any]]:
        """Get only finding-type events for heavier analysis."""
        finding_events = [
            e for e in self._entries
            if e.event_type in ("finding", "credential", "vuln_confirmed")
        ]
        return [
            {"framework": e.framework, **e.data}
            for e in finding_events[-last_n:]
        ]

    @property
    def size(self) -> int:
        return len(self._entries)

    def clear(self) -> None:
        self._entries.clear()


# ══════════════════════════════════════════════════════════════════════
# RESPONSE CACHE
# ══════════════════════════════════════════════════════════════════════

class _ResponseCache:
    """Bounded cache keyed only by a redacted tenant-scoped digest."""

    def __init__(self, max_size: int = 500) -> None:
        self._cache: dict[str, Any] = {}
        self._max = max_size
        self._hits = 0

    def get(self, key: str) -> Any | None:
        result = self._cache.get(str(key))
        if result is not None:
            self._hits += 1
        return result

    def put(self, key: str, result: Any) -> None:
        if len(self._cache) >= self._max:
            # Evict oldest 10%
            keys = list(self._cache.keys())
            for k in keys[: len(keys) // 10]:
                del self._cache[k]
        self._cache[str(key)] = redact_value(result)

    @property
    def hits(self) -> int:
        return self._hits

    @property
    def size(self) -> int:
        return len(self._cache)


# ══════════════════════════════════════════════════════════════════════
# CORE BRAIN ENGINE
# ══════════════════════════════════════════════════════════════════════

class ForgeBrain:
    """AI reasoning engine wrapping Anthropic Claude API.

    Graceful degradation: if ANTHROPIC_API_KEY is missing or the API
    is unreachable, all methods fall back to rule-based heuristics.
    The rest of the suite works identically — brain just adds intelligence.

    Usage::

        brain = ForgeBrain()
        if brain.available:
            result = await brain.analyze_finding(finding_dict)
        else:
            # Rule-based fallback already handled internally
            result = await brain.analyze_finding(finding_dict)
    """

    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        fast_model: str | None = None,
        rate_per_minute: int | None = None,
        max_memory: int | None = None,
        api_timeout: float | None = None,
        tenant_id: str = "default",
        engagement_id: str = "default-engagement",
    ) -> None:
        """Initialize ForgeBrain.

        Args:
            api_key:         Retained compatibility argument; model access is disabled.
            model:           Heavy reasoning model. Default: claude-opus-4-8.
            fast_model:      Fast model for FP analysis. Default: claude-haiku-4-5-20251001.
            rate_per_minute: API call rate limit. Default: 20.
            max_memory:      Max engagement memory entries. Default: 100.
            api_timeout:     Seconds before an API call times out. Default: 60.
                             Override via FORGE_BRAIN_TIMEOUT env var.
        """
        del api_key
        self._model: str = model or os.environ.get(
            "FORGE_BRAIN_MODEL", "claude-opus-4-8"
        ) or "claude-opus-4-8"
        self._fast_model: str = fast_model or os.environ.get(
            "FORGE_BRAIN_FAST_MODEL", "claude-haiku-4-5-20251001"
        ) or "claude-haiku-4-5-20251001"
        self._rpm = rate_per_minute or int(os.environ.get("FORGE_BRAIN_RPM", "20"))
        self._max_memory = max_memory or int(os.environ.get("FORGE_BRAIN_MAX_MEMORY", "100"))
        self._timeout = api_timeout or float(os.environ.get("FORGE_BRAIN_TIMEOUT", "60"))
        self._tenant_id = str(tenant_id or "").strip()
        self._engagement_id = str(engagement_id or "").strip()
        if not self._tenant_id or not self._engagement_id:
            raise ValueError("ForgeBrain tenant and engagement context are required")

        self._client: Any = None
        self._rate_limiter = _TokenBucket(self._rpm)
        self._cache = _ResponseCache()
        self.memory = EngagementMemory(
            self._max_memory,
            tenant_id=self._tenant_id,
            engagement_id=self._engagement_id,
        )
        self._total_calls = 0
        self._seed_built_in_knowledge()

        log.info(
            "ForgeBrain model adapter disabled pending canonical projection custody"
        )

    def _seed_built_in_knowledge(self) -> None:
        """Pre-seed engagement memory with anonymized built-in TTP knowledge."""
        try:
            from common.brain.built_in_knowledge import (
                LESSONS, ATTACK_CHAINS, FALSE_NEGATIVES,
                EVASION_TECHNIQUES, ERROR_SIGNATURES,
            )
        except ImportError:
            return
        for item in LESSONS:
            self.memory.add("lesson", item.get("framework", "manual"), item)
        for item in ATTACK_CHAINS:
            self.memory.add("attack_chain", item.get("framework", "manual"), item)
        for item in FALSE_NEGATIVES:
            self.memory.add("fn_hint", "import", item)
        for item in EVASION_TECHNIQUES:
            self.memory.add("evasion", "import", item)
        for item in ERROR_SIGNATURES:
            self.memory.add("error_sig", "import", item)

    @property
    def available(self) -> bool:
        """Return false while the raw model adapter is disabled."""
        return False

    def model_projection(self, value: Mapping[str, Any]) -> dict[str, Any]:
        """Return the one allowlisted tenant-scoped model input view."""
        return project_model_input(
            value,
            tenant_id=self._tenant_id,
            engagement_id=self._engagement_id,
        )

    @property
    def stats(self) -> BrainStats:
        """Runtime statistics."""
        return BrainStats(
            model=self._model,
            fast_model=self._fast_model,
            memory_entries=self.memory.size,
            cache_size=self._cache.size,
            cache_hits=self._cache.hits,
            total_calls=self._total_calls,
            calls_last_minute=self._rate_limiter.calls_last_minute,
            api_available=self.available,
        )

    # ── Internal API Call ─────────────────────────────────────────────

    async def _call(
        self,
        prompt: str,
        system: str = "",
        model: str | None = None,
        max_tokens: int = 2048,
        temperature: float = 0.3,
        timeout_s: float | None = None,
    ) -> str:
        """Reject the legacy raw-string model adapter.

        Task 106 has no typed, canonical report projection that can safely
        consume arbitrary model prose. Model-backed compatibility paths remain
        disabled until such a contract exists.
        """

        del prompt, system, model, max_tokens, temperature, timeout_s
        raise RuntimeError("raw_model_adapter_disabled")

    def _default_system(self) -> str:
        """Default system prompt for the brain."""
        return (
            f"You are ForgeBrain, the AI reasoning engine for {PRODUCT_LABEL} — "
            "an authorized security platform. You analyze redacted finding projections, "
            "suggest advisory plans, detect possible false positives/negatives, "
            "and write evidence-bounded summaries. You never approve or execute work, "
            "and never claim that a suggestion, simulation, event, or narrative is an "
            "observed outcome. "
            "Always respond in valid JSON unless explicitly told otherwise."
        )

    # ── Public Brain Methods ──────────────────────────────────────────

    async def analyze_finding(self, finding: dict[str, Any]) -> AnalysisResult:
        """Analyze a finding for false positive likelihood.

        Args:
            finding: Finding dict (from Finding.to_dict()).

        Returns:
            AnalysisResult with verdict, confidence, reasoning, action.
        """
        ordinary_finding = ordinary_finding_projection(finding)
        finding_id = str(ordinary_finding.get("id") or "unknown")
        return AnalysisResult(
            finding_id=finding_id,
            verdict=Verdict.NEEDS_VERIFICATION,
            confidence=Confidence.LOW,
            reasoning=(
                "Advisory analysis only; resolve canonical observation, finding, "
                "proof, and evidence lineage before assigning a verdict."
            ),
            action="canonical_review_required",
            severity_adjustment="unchanged",
            fn_risk="unknown",
        )

    async def detect_false_negatives(
        self,
        findings: list[dict[str, Any]],
        modules_run: list[str],
        target_context: dict[str, Any],
    ) -> list[FalseNegativeHint]:
        """Detect likely missed vulnerabilities (false negatives).

        Args:
            findings:       All findings so far.
            modules_run:    List of module names that have run.
            target_context: Target info (tech stack, OS, headers, etc.).

        Returns:
            List of FalseNegativeHint with suggested follow-up actions.
        """
        del findings, modules_run, target_context
        return []

    async def plan_next_attack(
        self,
        intel: dict[str, Any],
        target_context: dict[str, Any],
        opsec_level: str = "standard",
    ) -> list[PlannedAction]:
        """Plan the next attack steps based on current intel.

        Args:
            intel:          All gathered intelligence (findings, creds, hosts).
            target_context: Target info (tech stack, OS, network topology).
            opsec_level:    "stealth", "standard", or "noisy".

        Returns:
            Prioritized list of PlannedAction steps.
        """
        del intel, target_context, opsec_level
        return []

    async def advise_evasion(
        self,
        blocked_payload: str,
        waf_name: str,
        vuln_type: str,
        target: str,
    ) -> list[EvasionAdvice]:
        """Advise on WAF/filter bypass payloads.

        Args:
            blocked_payload: The payload that was blocked.
            waf_name:        Detected WAF name (e.g., "Cloudflare", "ModSecurity").
            vuln_type:       Vulnerability type (sqli, xss, cmdi, etc.).
            target:          Target URL.

        Returns:
            List of EvasionAdvice with alternative payloads.
        """
        del blocked_payload, waf_name, vuln_type, target
        return []

    async def interpret_error(
        self,
        error_response: str,
        payload: str,
        vuln_type: str,
    ) -> ErrorInterpretation:
        """Interpret an error response for technology identification.

        Args:
            error_response: The error response body (truncated).
            payload:        The payload that caused the error.
            vuln_type:      Vulnerability type being tested.

        Returns:
            ErrorInterpretation with technology, injectability assessment.
        """
        del error_response, payload, vuln_type
        return ErrorInterpretation(
            interpretation=(
                "Advisory interpretation withheld pending canonical observation "
                "and evidence lineage."
            ),
            technology="unknown",
            is_injectable=False,
            filter_detected=False,
            confidence=Confidence.LOW,
        )

    async def write_executive_summary(
        self,
        findings: list[dict[str, Any]],
        target: str,
        engagement_name: str = "Security Assessment",
    ) -> str:
        """Generate an executive summary for C-suite audiences.

        Args:
            findings:        All findings (as dicts).
            target:          Primary target.
            engagement_name: Name of the engagement.

        Returns:
            Executive summary as a formatted string.
        """
        findings = [ordinary_finding_projection(item) for item in findings]
        target = _ordinary_label(target, limit=2_000)
        engagement_name = _ordinary_label(engagement_name, limit=500)
        del target, engagement_name
        return advisory_report_projection(
            projection_kind="executive_summary",
            entry_count=len(findings),
        )

    async def write_attack_narrative(self, chain_log: list[dict[str, Any]]) -> str:
        """Generate a step-by-step attack narrative from chain log.

        Args:
            chain_log: Ordered list of attack steps with findings.

        Returns:
            Attack narrative as a formatted string.
        """
        chain_log = _ordinary_chain_log(chain_log)
        return advisory_narrative_projection(chain_log)

    async def autonomous_decision(
        self,
        situation: str,
        options: list[str],
        opsec_level: str = "standard",
    ) -> AutonomousDecision:
        """Make an autonomous decision during unsupervised mode.

        Args:
            situation: Description of the current situation.
            options:   List of possible actions.
            opsec_level: "stealth", "standard", or "noisy".

        Returns:
            AutonomousDecision with chosen action and reasoning.
        """
        del situation, options, opsec_level
        return AutonomousDecision(
            decision="no_action",
            reasoning=(
                "Legacy autonomous decision path is disabled pending canonical "
                "advisory plan persistence."
            ),
            confidence=Confidence.LOW,
            risk_level=RiskLevel.HIGH,
            abort=True,
        )

    # ── JSON Parsing Helpers ──────────────────────────────────────────

    def _parse_json(self, raw: str) -> dict[str, Any]:
        """Extract JSON object from Claude's response (may have markdown fences)."""
        text = raw.strip()
        # Strip markdown code fences
        if text.startswith("```"):
            lines = text.split("\n")
            text = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
        # Find JSON object
        start = text.find("{")
        end = text.rfind("}") + 1
        if start >= 0 and end > start:
            return json.loads(text[start:end])
        return json.loads(text)

    def _parse_json_array(self, raw: str) -> list[dict[str, Any]]:
        """Extract JSON array from Claude's response."""
        text = raw.strip()
        if text.startswith("```"):
            lines = text.split("\n")
            text = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
        start = text.find("[")
        end = text.rfind("]") + 1
        if start >= 0 and end > start:
            return json.loads(text[start:end])
        # Maybe it's a single object — wrap it
        obj = self._parse_json(text)
        return [obj] if isinstance(obj, dict) else []

    # ══════════════════════════════════════════════════════════════════
    # RULE-BASED FALLBACKS
    # ══════════════════════════════════════════════════════════════════

    def _rule_based_analyze(self, finding: dict[str, Any]) -> AnalysisResult:
        """Rule-based FP analysis when brain is unavailable."""
        finding_id = finding.get("id", "unknown")
        return AnalysisResult(
            finding_id=str(finding_id),
            verdict=Verdict.NEEDS_VERIFICATION,
            confidence=Confidence.LOW,
            reasoning=(
                "Advisory analysis only; canonical verification is required."
            ),
            action="canonical_review_required",
            severity_adjustment="unchanged",
            fn_risk="unknown",
        )

    def _rule_based_fn_detect(
        self,
        findings: list[dict[str, Any]],
        modules_run: list[str],
    ) -> list[FalseNegativeHint]:
        """Rule-based FN detection when brain is unavailable."""
        hints: list[FalseNegativeHint] = []
        finding_titles = " ".join(f.get("title", "").lower() for f in findings)
        modules_lower = [m.lower() for m in modules_run]

        # SQLi found → check for second-order, stored
        if "sqli" in finding_titles or "sql injection" in finding_titles:
            if "second_order_sqli" not in modules_lower:
                hints.append(FalseNegativeHint(
                    likely_vuln="Second-Order SQL Injection",
                    reason="Direct SQLi found — stored/second-order SQLi likely exists",
                    suggested_module="second_order_sqli",
                    priority=2,
                    mitre="TA0006/T1190",
                ))

        # File upload found → check polyglot/double extension
        if "upload" in finding_titles or "file upload" in finding_titles:
            hints.append(FalseNegativeHint(
                likely_vuln="Upload Bypass (polyglot/double extension)",
                reason="File upload vulnerability found — advanced bypasses likely work",
                suggested_module="upload_bypass",
                suggested_payload=".php.jpg, .phtml, polyglot GIF89a",
                priority=2,
                mitre="TA0002/T1059",
            ))

        # SSRF found → check blind SSRF, cloud metadata
        if "ssrf" in finding_titles:
            hints.append(FalseNegativeHint(
                likely_vuln="Blind SSRF / Cloud Metadata Access",
                reason="SSRF found — blind SSRF via OOB callback likely exploitable",
                suggested_module="ssrf_scanner",
                suggested_payload="OOB DNS/HTTP callback via ForgeCollab",
                priority=1,
                mitre="TA0001/T1190",
            ))

        # XSS found → check stored XSS
        if "xss" in finding_titles and "stored" not in finding_titles:
            hints.append(FalseNegativeHint(
                likely_vuln="Stored XSS",
                reason="Reflected XSS found — stored XSS in forms/comments likely exists",
                suggested_module="xss_scanner",
                priority=3,
                mitre="TA0004/T1059.007",
            ))

        return hints

    def _rule_based_plan(
        self,
        intel: dict[str, Any],
        target_context: dict[str, Any],
    ) -> list[PlannedAction]:
        """Rule-based attack planning when brain is unavailable."""
        actions: list[PlannedAction] = []

        # Basic kill chain progression
        findings = intel.get("findings", [])
        creds = intel.get("credentials", [])
        has_web_vuln = any("web" in f.get("module", "").lower() for f in findings)
        has_creds = len(creds) > 0
        has_host_access = any("shell" in f.get("title", "").lower() for f in findings)

        if not findings:
            # Start with recon
            actions.append(PlannedAction(
                priority=1, phase="RECON", mitre="TA0043/T1595",
                framework="netforge", module="port_scanner",
                target=target_context.get("target", ""),
                rationale="No findings yet — start with network reconnaissance",
                auto_execute=True, requires_confirm=False,
                expected_outcome="Open ports and services discovered",
            ))
        elif has_creds and not has_host_access:
            # Try credential reuse
            actions.append(PlannedAction(
                priority=1, phase="INITIAL_ACCESS", mitre="TA0001/T1078",
                framework="netforge", module="credential_spray",
                target=target_context.get("target", ""),
                rationale="Credentials found — attempt credential reuse across services",
                auto_execute=False, requires_confirm=True,
                expected_outcome="Authenticated access via credential reuse",
            ))
        elif has_host_access:
            # Post-exploit
            actions.append(PlannedAction(
                priority=1, phase="PRIV_ESC", mitre="TA0004/T1068",
                framework="netforge", module="priv_esc",
                target=target_context.get("target", ""),
                rationale="Shell access obtained — attempt privilege escalation",
                auto_execute=False, requires_confirm=True,
                expected_outcome="Elevated privileges on compromised host",
            ))

        return actions

    def _rule_based_evasion(
        self,
        blocked_payload: str,
        waf_name: str,
        vuln_type: str,
    ) -> list[EvasionAdvice]:
        """Rule-based evasion advice when brain is unavailable."""
        advice: list[EvasionAdvice] = []

        if vuln_type.lower() in ("sqli", "sql injection"):
            advice.extend([
                EvasionAdvice(
                    payload="1' /*!50000OR*/ '1'='1",
                    technique="MySQL version comment bypass",
                    confidence=Confidence.MEDIUM,
                    notes="MySQL-specific — uses versioned comments to hide keywords",
                ),
                EvasionAdvice(
                    payload="1'%0aOR%0a'1'='1",
                    technique="Newline/whitespace bypass",
                    confidence=Confidence.MEDIUM,
                    notes="Uses URL-encoded newlines instead of spaces",
                ),
                EvasionAdvice(
                    payload="1' || '1'='1",
                    technique="Double-pipe OR syntax",
                    confidence=Confidence.LOW,
                    notes="Alternative OR syntax — may bypass keyword filters",
                ),
            ])
        elif vuln_type.lower() in ("xss", "cross-site scripting"):
            advice.extend([
                EvasionAdvice(
                    payload="<svg/onload=alert(1)>",
                    technique="SVG event handler (shorter)",
                    confidence=Confidence.MEDIUM,
                ),
                EvasionAdvice(
                    payload="<img src=x onerror=alert`1`>",
                    technique="Template literal backticks",
                    confidence=Confidence.MEDIUM,
                ),
                EvasionAdvice(
                    payload="<details open ontoggle=alert(1)>",
                    technique="HTML5 details/ontoggle event",
                    confidence=Confidence.MEDIUM,
                    notes="Often not filtered — HTML5 element with auto-trigger event",
                ),
            ])
        elif vuln_type.lower() in ("cmdi", "command injection"):
            advice.extend([
                EvasionAdvice(
                    payload="${IFS}",
                    technique="IFS variable as space substitute",
                    confidence=Confidence.MEDIUM,
                    notes="Replaces spaces which are commonly filtered",
                ),
                EvasionAdvice(
                    payload="; $'\\x73\\x6c\\x65\\x65\\x70' 5",
                    technique="$'' ANSI-C quoting",
                    confidence=Confidence.LOW,
                    notes="Hex-encodes the command name",
                ),
            ])

        return advice

    def _rule_based_interpret(
        self,
        error_response: str,
        payload: str,
        vuln_type: str,
    ) -> ErrorInterpretation:
        """Rule-based error interpretation when brain is unavailable."""
        resp = error_response.lower()
        tech = "unknown"

        # Technology detection
        if "apache" in resp:
            tech = "Apache"
        elif "nginx" in resp:
            tech = "nginx"
        elif "iis" in resp or "asp.net" in resp:
            tech = "IIS/ASP.NET"
        elif "express" in resp or "node" in resp:
            tech = "Node.js/Express"
        elif "django" in resp or "wsgi" in resp:
            tech = "Python/Django"
        elif "laravel" in resp or "symfony" in resp:
            tech = "PHP/Laravel"
        elif "spring" in resp or "java" in resp:
            tech = "Java/Spring"

        # Filter/WAF detection
        filter_detected = any(kw in resp for kw in [
            "forbidden", "blocked", "waf", "firewall",
            "not acceptable", "security", "mod_security",
        ])

        # Injectability heuristic
        is_injectable = any(kw in resp for kw in [
            "syntax", "error", "warning", "exception",
            "unexpected", "unterminated", "invalid",
        ]) and not filter_detected

        return ErrorInterpretation(
            interpretation=f"Error response from {tech} server",
            technology=tech,
            is_injectable=is_injectable,
            filter_detected=filter_detected,
            confidence=Confidence.LOW,
        )

    def _rule_based_exec_summary(
        self,
        findings: list[dict[str, Any]],
        target: str,
        engagement_name: str,
    ) -> str:
        """Rule-based executive summary when brain is unavailable."""
        del target, engagement_name
        return advisory_report_projection(
            projection_kind="executive_summary",
            entry_count=len(findings),
        )

    def _rule_based_narrative(self, chain_log: list[dict[str, Any]]) -> str:
        """Rule-based attack narrative when brain is unavailable."""
        return advisory_narrative_projection(chain_log)

    def _rule_based_autonomous(
        self,
        situation: str,
        options: list[str],
        opsec_level: str,
    ) -> AutonomousDecision:
        """Rule-based autonomous decision when brain is unavailable."""
        del situation, options, opsec_level
        return AutonomousDecision(
            decision="no_action",
            reasoning=(
                "Legacy autonomous decision path is disabled pending canonical "
                "advisory plan persistence."
            ),
            confidence=Confidence.LOW,
            risk_level=RiskLevel.HIGH,
            abort=True,
        )


# ══════════════════════════════════════════════════════════════════════
# TESTS
# ══════════════════════════════════════════════════════════════════════

class TestForgeBrain:
    """Unit tests for the ForgeBrain engine."""

    def test_init_without_api_key(self) -> None:
        """Brain initializes gracefully without API key."""
        brain = ForgeBrain(api_key="")
        assert not brain.available
        assert brain.stats.api_available is False

    def test_init_custom_timeout(self) -> None:
        brain = ForgeBrain(api_key="", api_timeout=30.0)
        assert brain._timeout == 30.0

    def test_init_default_timeout(self) -> None:
        brain = ForgeBrain(api_key="")
        assert brain._timeout == 60.0

    def test_engagement_memory(self) -> None:
        brain = ForgeBrain(api_key="")
        seeded_entries = brain.memory.size
        brain.memory.add("finding", "webforge", {"title": "SQLi"})
        brain.memory.add("finding", "netforge", {"title": "Open SSH"})
        assert brain.memory.size == seeded_entries + 2
        ctx = brain.memory.get_context(last_n=2)
        assert len(ctx) == 2
        assert ctx[0]["framework"] == "webforge"
        assert ctx[1]["framework"] == "netforge"

    def test_cache_dedup(self) -> None:
        cache = _ResponseCache(max_size=10)
        cache.put("test_content", {"result": "cached"})
        assert cache.get("test_content") == {"result": "cached"}
        assert cache.hits == 1
        assert cache.get("other_content") is None

    def test_rule_based_analyze_is_advisory_only(self) -> None:
        brain = ForgeBrain(api_key="")
        finding = {
            "id": "test-123",
            "title": "SQL Injection (time-based) — id",
            "severity": "Critical",
            "module": "sqli_scanner",
            "evidence": {"request_raw": "GET /page?id=1' AND SLEEP(5)--"},
        }
        result = brain._rule_based_analyze(finding)
        assert result.verdict == Verdict.NEEDS_VERIFICATION
        assert result.confidence == Confidence.LOW
        assert result.action == "canonical_review_required"
        assert result.severity_adjustment == "unchanged"
        assert "Advisory analysis only" in result.reasoning
        assert "SLEEP(5)" not in result.reasoning

    def test_rule_based_fn_detect(self) -> None:
        brain = ForgeBrain(api_key="")
        findings = [{"title": "SQL Injection in id param", "module": "sqli_scanner"}]
        hints = brain._rule_based_fn_detect(findings, ["sqli_scanner"])
        assert len(hints) >= 1
        assert "second-order" in hints[0].likely_vuln.lower()

    def test_rule_based_evasion_sqli(self) -> None:
        brain = ForgeBrain(api_key="")
        advice = brain._rule_based_evasion("' OR 1=1--", "ModSecurity", "sqli")
        assert len(advice) >= 2

    def test_rule_based_interpret(self) -> None:
        brain = ForgeBrain(api_key="")
        result = brain._rule_based_interpret(
            "Warning: mysql_fetch_array() expects parameter 1",
            "'", "sqli"
        )
        assert result.is_injectable is True

    def test_rule_based_exec_summary(self) -> None:
        brain = ForgeBrain(api_key="")
        findings = [
            {"title": "SQLi", "severity": "Critical", "description": "test"},
            {"title": "XSS", "severity": "High", "description": "test"},
        ]
        summary = brain._rule_based_exec_summary(findings, "https://example.com", "Test")
        assert "Advisory projection only" in summary
        assert "not published as execution" in summary
        assert "Submitted advisory records: **2**" in summary
        assert "CRITICAL" not in summary
        assert "SQLi" not in summary
        unsupported_claim = (
            "COMPLETE: executed network action; finding verified; evidence created."
        )
        narrative = brain._rule_based_narrative(
            [
                {
                    "action": unsupported_claim,
                    "result": unsupported_claim,
                    "verification_state": "verified",
                }
            ]
        )
        assert "Advisory projection only" in narrative
        assert "does not assert" in narrative
        assert "Recorded advisory entries: **1**" in narrative
        assert unsupported_claim not in narrative
        assert "verification_state=verified" not in narrative

    def test_stats_property(self) -> None:
        brain = ForgeBrain(api_key="")
        stats = brain.stats
        assert stats.total_calls == 0
        assert stats.model == "claude-opus-4-8"

    def test_token_bucket(self) -> None:
        bucket = _TokenBucket(rate_per_minute=60)
        assert bucket.calls_last_minute == 0

    def test_parse_json(self) -> None:
        brain = ForgeBrain(api_key="")
        # Test with markdown fences
        raw = '```json\n{"key": "value"}\n```'
        assert brain._parse_json(raw) == {"key": "value"}
        # Test raw JSON
        raw2 = '{"key": "value"}'
        assert brain._parse_json(raw2) == {"key": "value"}

    def test_parse_json_array(self) -> None:
        brain = ForgeBrain(api_key="")
        raw = '```json\n[{"a": 1}, {"a": 2}]\n```'
        result = brain._parse_json_array(raw)
        assert len(result) == 2
