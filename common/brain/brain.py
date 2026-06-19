"""ForgeBrain — Core AI Reasoning Engine.

Wraps the Anthropic AsyncAnthropic client to provide AI-powered
security analysis across all 4 frameworks: NetForge, WebForge, ADForge, AIForge.

Features:
    - analyze_finding()      → FP verdict with confidence + severity adjustment
    - detect_false_negatives()→ what was probably missed based on context
    - plan_next_attack()     → autonomous attack path planning
    - advise_evasion()       → WAF bypass payload generation
    - interpret_error()      → technology identification from error responses
    - write_executive_summary()→ C-suite narrative
    - write_attack_narrative()→ red team story from chain log
    - autonomous_decision()  → unsupervised mode decision making

Engagement Memory:
    Rolling buffer of last N events across all frameworks fed to each call.
    SHA-256 cache deduplicates identical findings.

Graceful Degradation:
    No ANTHROPIC_API_KEY → rule-based heuristics, tools still work 100%.

FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import time
from collections import deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any

log = logging.getLogger("forge.brain")


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

    def __init__(self, max_entries: int = 100) -> None:
        self._entries: deque[EngagementMemoryEntry] = deque(maxlen=max_entries)
        self._max = max_entries

    def add(self, event_type: str, framework: str, data: dict[str, Any]) -> None:
        """Record a new event."""
        self._entries.append(EngagementMemoryEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type=event_type,
            framework=framework,
            data=data,
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
    """SHA-256 keyed cache to avoid re-analyzing identical findings."""

    def __init__(self, max_size: int = 500) -> None:
        self._cache: dict[str, Any] = {}
        self._max = max_size
        self._hits = 0

    def _key(self, content: str) -> str:
        return hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]

    def get(self, content: str) -> Any | None:
        result = self._cache.get(self._key(content))
        if result is not None:
            self._hits += 1
        return result

    def put(self, content: str, result: Any) -> None:
        if len(self._cache) >= self._max:
            # Evict oldest 10%
            keys = list(self._cache.keys())
            for k in keys[: len(keys) // 10]:
                del self._cache[k]
        self._cache[self._key(content)] = result

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
    ) -> None:
        """Initialize ForgeBrain.

        Args:
            api_key:         Anthropic API key. Falls back to ANTHROPIC_API_KEY env var.
            model:           Heavy reasoning model. Default: claude-opus-4-8.
            fast_model:      Fast model for FP analysis. Default: claude-haiku-4-5-20251001.
            rate_per_minute: API call rate limit. Default: 20.
            max_memory:      Max engagement memory entries. Default: 100.
            api_timeout:     Seconds before an API call times out. Default: 60.
                             Override via FORGE_BRAIN_TIMEOUT env var.
        """
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self._model = model or os.environ.get("FORGE_BRAIN_MODEL", "claude-opus-4-8")
        self._fast_model = fast_model or os.environ.get("FORGE_BRAIN_FAST_MODEL", "claude-haiku-4-5-20251001")
        self._rpm = rate_per_minute or int(os.environ.get("FORGE_BRAIN_RPM", "20"))
        self._max_memory = max_memory or int(os.environ.get("FORGE_BRAIN_MAX_MEMORY", "100"))
        self._timeout = api_timeout or float(os.environ.get("FORGE_BRAIN_TIMEOUT", "60"))

        self._client: Any = None
        self._rate_limiter = _TokenBucket(self._rpm)
        self._cache = _ResponseCache()
        self.memory = EngagementMemory(self._max_memory)
        self._total_calls = 0

        # Initialize API client if key available
        if self._api_key:
            try:
                from anthropic import AsyncAnthropic
                self._client = AsyncAnthropic(api_key=self._api_key)
                log.info(
                    "ForgeBrain initialized — model=%s, fast=%s, rpm=%d",
                    self._model, self._fast_model, self._rpm,
                )
            except ImportError:
                log.warning(
                    "anthropic package not installed — brain running in rule-based mode. "
                    "Install: pip install anthropic>=0.40.0"
                )
        else:
            log.info(
                "No ANTHROPIC_API_KEY set — ForgeBrain running in rule-based fallback mode. "
                "All tools work, but AI-powered analysis is disabled."
            )

    @property
    def available(self) -> bool:
        """Check if the AI brain is available (API key + client loaded)."""
        return self._client is not None

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
        """Make a rate-limited, cached API call to Claude.

        Args:
            prompt:      User message content.
            system:      System message.
            model:       Model override (defaults to self._model).
            max_tokens:  Max response tokens.
            temperature: Sampling temperature.
            timeout_s:   Per-call timeout override (defaults to self._timeout).

        Returns:
            Claude's text response.

        Raises:
            RuntimeError:         If API client not available.
            asyncio.TimeoutError: If the call exceeds the timeout.
        """
        if not self._client:
            raise RuntimeError("ForgeBrain API client not initialized")

        # Check cache
        cache_key = f"{model or self._model}:{system[:100]}:{prompt}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached

        # Rate limit
        await self._rate_limiter.acquire()
        self._total_calls += 1

        try:
            response = await asyncio.wait_for(
                self._client.messages.create(
                    model=model or self._model,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    system=system or self._default_system(),
                    messages=[{"role": "user", "content": prompt}],
                ),
                timeout=timeout_s or self._timeout,
            )
            text = response.content[0].text
            self._cache.put(cache_key, text)
            return text

        except asyncio.TimeoutError:
            log.error("Brain API call timed out after %ss", timeout_s or self._timeout)
            raise
        except Exception as exc:
            log.error("Brain API call failed: %s", exc)
            raise

    def _default_system(self) -> str:
        """Default system prompt for the brain."""
        return (
            "You are ForgeBrain, the AI reasoning engine for Forge Suite v5 APEX — "
            "an enterprise offensive security platform. You analyze vulnerability findings, "
            "plan attack chains, detect false positives/negatives, advise on evasion, "
            "and write executive summaries. You are precise, technical, and think like an "
            "experienced penetration tester and red team operator. "
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
        finding_id = finding.get("id", "unknown")

        if not self.available:
            return self._rule_based_analyze(finding)

        context = self.memory.get_context(last_n=15)
        prompt = json.dumps({
            "task": "analyze_finding",
            "finding": finding,
            "engagement_context": context,
            "instructions": (
                "Analyze this security finding. Determine if it's a TRUE_POSITIVE, "
                "FALSE_POSITIVE, or NEEDS_VERIFICATION. Consider: "
                "1) Is the evidence strong enough? 2) Could this be a server artifact? "
                "3) Does the detection method match the vuln type? "
                "Respond with JSON: {verdict, confidence, reasoning, action, "
                "severity_adjustment, fn_risk}"
            ),
        }, indent=2, default=str)

        try:
            raw = await self._call(prompt, model=self._fast_model, max_tokens=1024)
            data = self._parse_json(raw)
            return AnalysisResult(
                finding_id=finding_id,
                verdict=Verdict(data.get("verdict", "NEEDS_VERIFICATION")),
                confidence=Confidence(data.get("confidence", "MEDIUM")),
                reasoning=data.get("reasoning", ""),
                action=data.get("action", ""),
                severity_adjustment=data.get("severity_adjustment", "unchanged"),
                fn_risk=data.get("fn_risk", ""),
            )
        except Exception as exc:
            log.warning("Brain analyze_finding failed, using rule-based: %s", exc)
            return self._rule_based_analyze(finding)

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
        if not self.available:
            return self._rule_based_fn_detect(findings, modules_run)

        prompt = json.dumps({
            "task": "detect_false_negatives",
            "findings_summary": [
                {"title": f.get("title"), "severity": f.get("severity"),
                 "module": f.get("module"), "target": f.get("target")}
                for f in findings[:30]
            ],
            "modules_run": modules_run,
            "target_context": target_context,
            "engagement_context": self.memory.get_findings_context(last_n=20),
            "instructions": (
                "Based on the findings, modules run, and target context, identify "
                "likely missed vulnerabilities (false negatives). Consider: "
                "1) SQLi found → check second-order, stored SQLi "
                "2) File upload found → polyglot, double extension, null byte "
                "3) SSRF found → blind SSRF, AWS metadata, gopher "
                "4) JWT found → alg:none, weak HMAC, key confusion "
                "Respond with JSON array: [{likely_vuln, reason, suggested_module, "
                "suggested_payload, priority, mitre}]"
            ),
        }, indent=2, default=str)

        try:
            raw = await self._call(prompt, model=self._fast_model, max_tokens=2048)
            items = self._parse_json_array(raw)
            return [
                FalseNegativeHint(
                    likely_vuln=item.get("likely_vuln", ""),
                    reason=item.get("reason", ""),
                    suggested_module=item.get("suggested_module", ""),
                    suggested_payload=item.get("suggested_payload", ""),
                    priority=item.get("priority", 5),
                    mitre=item.get("mitre", ""),
                )
                for item in items
            ]
        except Exception as exc:
            log.warning("Brain detect_false_negatives failed: %s", exc)
            return self._rule_based_fn_detect(findings, modules_run)

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
        if not self.available:
            return self._rule_based_plan(intel, target_context)

        prompt = json.dumps({
            "task": "plan_next_attack",
            "intel": intel,
            "target_context": target_context,
            "opsec_level": opsec_level,
            "engagement_context": self.memory.get_context(last_n=30),
            "instructions": (
                "Plan the next attack steps. Consider MITRE ATT&CK kill chain: "
                "RECON → INITIAL_ACCESS → EXECUTION → PERSISTENCE → PRIV_ESC → "
                "LATERAL → COLLECTION → EXFIL. "
                "For each action specify: framework (netforge/webforge/adforge/aiforge), "
                "module, rationale, auto_execute (true for safe recon), "
                "requires_confirm (true for exploitation). "
                "Respond with JSON array: [{priority, phase, mitre, framework, module, "
                "target, rationale, auto_execute, requires_confirm, expected_outcome}]"
            ),
        }, indent=2, default=str)

        try:
            raw = await self._call(prompt, model=self._model, max_tokens=3000)
            items = self._parse_json_array(raw)
            return [
                PlannedAction(
                    priority=item.get("priority", 5),
                    phase=item.get("phase", ""),
                    mitre=item.get("mitre", ""),
                    framework=item.get("framework", ""),
                    module=item.get("module", ""),
                    target=item.get("target", ""),
                    rationale=item.get("rationale", ""),
                    auto_execute=item.get("auto_execute", False),
                    requires_confirm=item.get("requires_confirm", True),
                    expected_outcome=item.get("expected_outcome", ""),
                )
                for item in items
            ]
        except Exception as exc:
            log.warning("Brain plan_next_attack failed: %s", exc)
            return self._rule_based_plan(intel, target_context)

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
        if not self.available:
            return self._rule_based_evasion(blocked_payload, waf_name, vuln_type)

        prompt = json.dumps({
            "task": "advise_evasion",
            "blocked_payload": blocked_payload,
            "waf_name": waf_name,
            "vuln_type": vuln_type,
            "target": target,
            "instructions": (
                f"The payload was blocked by {waf_name or 'a WAF/filter'}. "
                f"Generate 3-5 alternative {vuln_type} payloads that might bypass this filter. "
                "Consider: encoding, case manipulation, double encoding, comment injection, "
                "concatenation, alternative syntax, and WAF-specific bypasses. "
                "Respond with JSON array: [{payload, technique, confidence, notes}]"
            ),
        }, indent=2, default=str)

        try:
            raw = await self._call(prompt, model=self._fast_model, max_tokens=2048)
            items = self._parse_json_array(raw)
            return [
                EvasionAdvice(
                    payload=item.get("payload", ""),
                    technique=item.get("technique", ""),
                    confidence=Confidence(item.get("confidence", "MEDIUM")),
                    notes=item.get("notes", ""),
                )
                for item in items
            ]
        except Exception as exc:
            log.warning("Brain advise_evasion failed: %s", exc)
            return self._rule_based_evasion(blocked_payload, waf_name, vuln_type)

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
        if not self.available:
            return self._rule_based_interpret(error_response, payload, vuln_type)

        prompt = json.dumps({
            "task": "interpret_error",
            "error_response": error_response[:3000],
            "payload": payload,
            "vuln_type": vuln_type,
            "instructions": (
                "Analyze this error response. Identify: "
                "1) Backend technology (web server, framework, database) "
                "2) Whether the parameter is injectable "
                "3) Whether a WAF/filter was detected "
                "4) Suggest next payload to try "
                "Respond with JSON: {interpretation, technology, is_injectable, "
                "filter_detected, next_payload, confidence}"
            ),
        }, indent=2, default=str)

        try:
            raw = await self._call(prompt, model=self._fast_model, max_tokens=1024)
            data = self._parse_json(raw)
            return ErrorInterpretation(
                interpretation=data.get("interpretation", ""),
                technology=data.get("technology", ""),
                is_injectable=data.get("is_injectable", False),
                filter_detected=data.get("filter_detected", False),
                next_payload=data.get("next_payload", ""),
                confidence=Confidence(data.get("confidence", "MEDIUM")),
            )
        except Exception as exc:
            log.warning("Brain interpret_error failed: %s", exc)
            return self._rule_based_interpret(error_response, payload, vuln_type)

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
        if not self.available:
            return self._rule_based_exec_summary(findings, target, engagement_name)

        severity_counts = {}
        for f in findings:
            sev = f.get("severity", "Informational")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        prompt = json.dumps({
            "task": "write_executive_summary",
            "engagement_name": engagement_name,
            "target": target,
            "total_findings": len(findings),
            "severity_breakdown": severity_counts,
            "top_findings": [
                {"title": f.get("title"), "severity": f.get("severity"),
                 "description": f.get("description", "")[:200]}
                for f in findings[:10]
            ],
            "instructions": (
                "Write a professional executive summary for C-suite leadership. "
                "Use clear, non-technical language. Include: overall risk rating, "
                "key findings, business impact, and remediation priorities. "
                "Format as markdown prose (not JSON). 300-500 words."
            ),
        }, indent=2, default=str)

        try:
            raw = await self._call(
                prompt,
                model=self._model,
                max_tokens=2048,
                system=(
                    "You are a senior security consultant writing an executive summary "
                    "for C-suite leadership. Write clearly, professionally, and focus "
                    "on business impact. Respond in markdown prose, not JSON."
                ),
            )
            return raw
        except Exception as exc:
            log.warning("Brain write_executive_summary failed: %s", exc)
            return self._rule_based_exec_summary(findings, target, engagement_name)

    async def write_attack_narrative(self, chain_log: list[dict[str, Any]]) -> str:
        """Generate a step-by-step attack narrative from chain log.

        Args:
            chain_log: Ordered list of attack steps with findings.

        Returns:
            Attack narrative as a formatted string.
        """
        if not self.available:
            return self._rule_based_narrative(chain_log)

        prompt = json.dumps({
            "task": "write_attack_narrative",
            "chain_log": chain_log[:30],
            "instructions": (
                "Write a compelling attack narrative from this chain log. "
                "Describe what an attacker did step by step, what was discovered, "
                "and what the impact was. Write as a story — 'First we... then we found... "
                "which led us to...' Format as markdown prose, not JSON."
            ),
        }, indent=2, default=str)

        try:
            return await self._call(
                prompt,
                model=self._model,
                max_tokens=3000,
                system=(
                    "You are an expert red team operator writing an attack narrative "
                    "for a penetration test report. Write technically accurate but "
                    "readable prose that tells the story of the engagement. "
                    "Respond in markdown, not JSON."
                ),
            )
        except Exception as exc:
            log.warning("Brain write_attack_narrative failed: %s", exc)
            return self._rule_based_narrative(chain_log)

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
        if not self.available:
            return self._rule_based_autonomous(situation, options, opsec_level)

        prompt = json.dumps({
            "task": "autonomous_decision",
            "situation": situation,
            "options": options,
            "opsec_level": opsec_level,
            "engagement_context": self.memory.get_context(last_n=10),
            "instructions": (
                "Choose the best action for this situation. Consider: "
                "1) OpSec level constraints "
                "2) Risk vs reward "
                "3) Kill chain progression "
                "4) Whether to abort if risk is too high "
                "Respond with JSON: {decision, reasoning, confidence, risk_level, abort}"
            ),
        }, indent=2, default=str)

        try:
            raw = await self._call(prompt, model=self._fast_model, max_tokens=1024)
            data = self._parse_json(raw)
            return AutonomousDecision(
                decision=data.get("decision", options[0] if options else ""),
                reasoning=data.get("reasoning", ""),
                confidence=Confidence(data.get("confidence", "MEDIUM")),
                risk_level=RiskLevel(data.get("risk_level", "MEDIUM")),
                abort=data.get("abort", False),
            )
        except Exception as exc:
            log.warning("Brain autonomous_decision failed: %s", exc)
            return self._rule_based_autonomous(situation, options, opsec_level)

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
        severity = finding.get("severity", "").lower()
        title = finding.get("title", "").lower()
        module = finding.get("module", "")
        evidence = finding.get("evidence", {})

        # High confidence indicators
        has_request = bool(evidence.get("request_raw"))
        has_response = bool(evidence.get("response_raw"))
        has_screenshot = bool(evidence.get("screenshot_path"))

        # Time-based SQLi with delay evidence → HIGH confidence
        if "time-based" in title and "sqli" in module.lower():
            return AnalysisResult(
                finding_id=finding_id,
                verdict=Verdict.TRUE_POSITIVE,
                confidence=Confidence.HIGH if has_request else Confidence.MEDIUM,
                reasoning="Time-based SQL injection with measurable delay — strong evidence",
                action="verify_with_variant",
                severity_adjustment="unchanged",
            )

        # Error-based with DB-specific error → HIGH confidence
        if "error" in title.lower() and any(
            db in title for db in ["mysql", "mssql", "postgresql", "oracle", "sqlite"]
        ):
            return AnalysisResult(
                finding_id=finding_id,
                verdict=Verdict.TRUE_POSITIVE,
                confidence=Confidence.HIGH,
                reasoning="Database-specific error pattern detected — not a generic 500",
                action="exploit_further",
                severity_adjustment="unchanged",
            )

        # XSS with canary reflection → MEDIUM-HIGH
        if "xss" in title.lower() and has_response:
            return AnalysisResult(
                finding_id=finding_id,
                verdict=Verdict.TRUE_POSITIVE,
                confidence=Confidence.MEDIUM,
                reasoning="XSS payload reflected in response — verify not HTML-encoded",
                action="verify_in_browser",
                severity_adjustment="unchanged",
            )

        # Generic — needs verification
        return AnalysisResult(
            finding_id=finding_id,
            verdict=Verdict.NEEDS_VERIFICATION,
            confidence=Confidence.LOW,
            reasoning="Insufficient evidence for automated verdict — manual review recommended",
            action="manual_verify",
            severity_adjustment="unchanged",
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
        severity_counts: dict[str, int] = {}
        for f in findings:
            sev = f.get("severity", "Informational")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        critical = severity_counts.get("Critical", 0)
        high = severity_counts.get("High", 0)
        medium = severity_counts.get("Medium", 0)
        low = severity_counts.get("Low", 0)

        if critical > 0:
            risk = "CRITICAL"
        elif high > 0:
            risk = "HIGH"
        elif medium > 0:
            risk = "MEDIUM"
        else:
            risk = "LOW"

        top_findings = "\n".join(
            f"- **{f.get('title')}** ({f.get('severity')})"
            for f in findings[:5]
        )

        return (
            f"# Executive Summary — {engagement_name}\n\n"
            f"**Target:** {target}\n"
            f"**Overall Risk Rating:** {risk}\n"
            f"**Total Findings:** {len(findings)}\n\n"
            f"## Severity Breakdown\n"
            f"- Critical: {critical}\n"
            f"- High: {high}\n"
            f"- Medium: {medium}\n"
            f"- Low: {low}\n\n"
            f"## Top Findings\n{top_findings}\n\n"
            f"## Recommendation\n"
            f"{'Immediate remediation required for critical vulnerabilities.' if critical > 0 else ''}\n"
            f"{'High-priority findings should be addressed within 7 days.' if high > 0 else ''}\n"
        )

    def _rule_based_narrative(self, chain_log: list[dict[str, Any]]) -> str:
        """Rule-based attack narrative when brain is unavailable."""
        if not chain_log:
            return "No attack chain log available."

        steps = []
        for i, step in enumerate(chain_log, 1):
            action = step.get("action", "Unknown action")
            result = step.get("result", "")
            target = step.get("target", "")
            steps.append(f"{i}. **{action}** against `{target}`\n   Result: {result}")

        return (
            "# Attack Narrative\n\n"
            + "\n\n".join(steps)
            + "\n\n---\n*Generated by ForgeBrain (rule-based mode)*\n"
        )

    def _rule_based_autonomous(
        self,
        situation: str,
        options: list[str],
        opsec_level: str,
    ) -> AutonomousDecision:
        """Rule-based autonomous decision when brain is unavailable."""
        # Conservative: pick the safest option (usually first/recon)
        safe_keywords = ["recon", "scan", "enumerate", "check", "detect", "discover"]
        risky_keywords = ["exploit", "inject", "execute", "lateral", "persist"]

        chosen = options[0] if options else "skip"
        risk = RiskLevel.LOW

        for opt in options:
            opt_lower = opt.lower()
            if any(kw in opt_lower for kw in safe_keywords):
                chosen = opt
                risk = RiskLevel.LOW
                break

        # Abort if opsec is stealth and options are all risky
        abort = (
            opsec_level == "stealth"
            and all(
                any(kw in opt.lower() for kw in risky_keywords)
                for opt in options
            )
        )

        return AutonomousDecision(
            decision=chosen,
            reasoning="Rule-based: selected safest available option",
            confidence=Confidence.LOW,
            risk_level=risk,
            abort=abort,
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
        brain.memory.add("finding", "webforge", {"title": "SQLi"})
        brain.memory.add("finding", "netforge", {"title": "Open SSH"})
        assert brain.memory.size == 2
        ctx = brain.memory.get_context(last_n=5)
        assert len(ctx) == 2
        assert ctx[0]["framework"] == "webforge"

    def test_cache_dedup(self) -> None:
        cache = _ResponseCache(max_size=10)
        cache.put("test_content", {"result": "cached"})
        assert cache.get("test_content") == {"result": "cached"}
        assert cache.hits == 1
        assert cache.get("other_content") is None

    def test_rule_based_analyze(self) -> None:
        brain = ForgeBrain(api_key="")
        finding = {
            "id": "test-123",
            "title": "SQL Injection (time-based) — id",
            "severity": "Critical",
            "module": "sqli_scanner",
            "evidence": {"request_raw": "GET /page?id=1' AND SLEEP(5)--"},
        }
        result = brain._rule_based_analyze(finding)
        assert result.verdict == Verdict.TRUE_POSITIVE
        assert result.confidence == Confidence.HIGH

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
        assert "CRITICAL" in summary
        assert "SQLi" in summary

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
