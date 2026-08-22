"""FindingAnalyst — AI-powered finding analysis and FP/FN reduction.

Wraps ForgeBrain to provide finding-level analysis:
    - analyze()              → AnalysisResult for a single finding
    - bulk_analyze()         → batch analysis (token-efficient)
    - enrich_finding()       → mutate finding with brain verdict
    - filter_false_positives()→ remove FPs based on confidence
    - detect_false_negatives()→ identify likely missed vulns

Graceful degradation: if brain is unavailable, falls back to
rule-based confidence heuristics that already exist in the codebase.

FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from common.finding import Finding

from common.brain.brain import (
    ForgeBrain,
    AnalysisResult,
    FalseNegativeHint,
    Verdict,
    Confidence,
)

log = logging.getLogger("forge.brain.analyst")


# ══════════════════════════════════════════════════════════════════════
# FINDING ANALYST
# ══════════════════════════════════════════════════════════════════════

class FindingAnalyst:
    """AI-powered finding analysis engine.

    Wraps ForgeBrain for per-finding analysis and provides bulk
    operations for efficient token usage. Falls back to rule-based
    heuristics when the brain API is unavailable.

    Usage::

        brain = ForgeBrain()
        analyst = FindingAnalyst(brain)

        # Single finding analysis
        result = await analyst.analyze(finding)

        # Bulk analysis (batches for token efficiency)
        results = await analyst.bulk_analyze(findings)

        # Filter false positives
        real_findings = await analyst.filter_false_positives(findings)

        # Detect false negatives
        missed = await analyst.detect_false_negatives(findings, modules_run, context)
    """

    def __init__(self, brain: ForgeBrain | None = None) -> None:
        """Initialize the analyst.

        Args:
            brain: ForgeBrain instance. If None, a new one is created
                   (which may run in rule-based mode if no API key).
        """
        self._brain = brain or ForgeBrain()

    @property
    def brain(self) -> ForgeBrain:
        """Access the underlying brain engine."""
        return self._brain

    async def analyze(self, finding: dict[str, Any] | Any) -> AnalysisResult:
        """Analyze a single finding.

        Args:
            finding: Finding dict (from Finding.to_dict()) or Finding object.

        Returns:
            AnalysisResult with verdict, confidence, reasoning.
        """
        finding_dict = finding.to_dict() if hasattr(finding, "to_dict") else finding

        # Try brain first, then rule-based
        result = await self._brain.analyze_finding(finding_dict)

        # Augment with vuln-type-specific heuristic confidence
        heuristic = self._heuristic_confidence(finding_dict)
        if heuristic and result.confidence == Confidence.LOW:
            # Upgrade confidence if heuristic evidence is strong
            result.confidence = heuristic

        return result

    async def bulk_analyze(
        self,
        findings: list[dict[str, Any] | Any],
        batch_size: int = 5,
    ) -> list[AnalysisResult]:
        """Analyze multiple findings with batching for token efficiency.

        Args:
            findings:   List of Finding dicts or Finding objects.
            batch_size: Number of findings to analyze concurrently.

        Returns:
            List of AnalysisResult, one per finding (same order).
        """
        results: list[AnalysisResult] = []

        for i in range(0, len(findings), batch_size):
            batch = findings[i : i + batch_size]
            tasks = [self.analyze(f) for f in batch]
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)

            for j, result in enumerate(batch_results):
                if isinstance(result, asyncio.CancelledError):
                    raise result
                if isinstance(result, BaseException):
                    log.warning("Bulk analysis failed for finding %d: %s", i + j, result)
                    finding = batch[j]
                    fid = (
                        finding.get("id", f"unknown-{i+j}")
                        if isinstance(finding, dict)
                        else getattr(finding, "id", f"unknown-{i+j}")
                    )
                    results.append(AnalysisResult(
                        finding_id=fid,
                        verdict=Verdict.NEEDS_VERIFICATION,
                        confidence=Confidence.LOW,
                        reasoning=f"Analysis failed: {result}",
                    ))
                else:
                    results.append(result)

        return results

    def enrich_finding(
        self,
        finding: Any,
        analysis: AnalysisResult,
    ) -> Any:
        """Mutate a Finding object with brain analysis results.

        Adds brain verdict, adjusted severity, and confidence to the
        finding's tags and evidence.extra.

        Args:
            finding:  Finding object (with .tags, .evidence.extra, .severity).
            analysis: AnalysisResult from analyze().

        Returns:
            The mutated Finding (same object).
        """
        # Add brain tags
        finding.tags = getattr(finding, "tags", []) or []
        finding.tags.append(f"brain:verdict:{analysis.verdict.value}")
        finding.tags.append(f"brain:confidence:{analysis.confidence.value}")

        if analysis.verdict == Verdict.FALSE_POSITIVE:
            finding.tags.append("brain:fp")

        # Add to evidence.extra
        if hasattr(finding, "evidence") and hasattr(finding.evidence, "extra"):
            finding.evidence.extra = finding.evidence.extra or {}
            finding.evidence.extra["brain_verdict"] = analysis.verdict.value
            finding.evidence.extra["brain_confidence"] = analysis.confidence.value
            finding.evidence.extra["brain_reasoning"] = analysis.reasoning
            if analysis.action:
                finding.evidence.extra["brain_action"] = analysis.action

        # Severity adjustment
        if analysis.severity_adjustment == "upgrade":
            _upgrade_severity(finding)
        elif analysis.severity_adjustment == "downgrade":
            _downgrade_severity(finding)

        return finding

    async def filter_false_positives(
        self,
        findings: list[Any],
        min_confidence: str = "MEDIUM",
    ) -> list[Any]:
        """Filter out false positive findings based on brain analysis.

        Args:
            findings:       List of Finding objects or dicts.
            min_confidence: Minimum confidence to keep. Findings with
                           brain verdict of FALSE_POSITIVE are removed.

        Returns:
            Filtered list of findings (FPs removed).
        """
        min_conf = Confidence(min_confidence)
        results = await self.bulk_analyze(findings)

        filtered: list[Any] = []
        for finding, analysis in zip(findings, results):
            if analysis.verdict == Verdict.FALSE_POSITIVE:
                fid = (
                    finding.get("id", "?")
                    if isinstance(finding, dict)
                    else getattr(finding, "id", "?")
                )
                log.info(
                    "FP filtered: %s (confidence=%s, reason=%s)",
                    fid, analysis.confidence.value, analysis.reasoning[:80],
                )
                continue

            # Keep if confidence meets minimum
            conf_order = {Confidence.HIGH: 3, Confidence.MEDIUM: 2, Confidence.LOW: 1}
            if conf_order.get(analysis.confidence, 0) >= conf_order.get(min_conf, 0):
                filtered.append(finding)
            else:
                log.info(
                    "Low-confidence finding suppressed: %s (%s < %s)",
                    analysis.finding_id, analysis.confidence.value, min_conf.value,
                )

        return filtered

    async def detect_false_negatives(
        self,
        findings: list[dict[str, Any]],
        modules_run: list[str],
        target_context: dict[str, Any] | None = None,
    ) -> list[FalseNegativeHint]:
        """Detect likely missed vulnerabilities (false negatives).

        Combines brain AI analysis with rule-based heuristics.

        Args:
            findings:       All findings so far (as dicts).
            modules_run:    List of module names that have completed.
            target_context: Target info (tech stack, headers, etc.).

        Returns:
            List of FalseNegativeHint with suggested follow-ups.
        """
        context = target_context or {}
        return await self._brain.detect_false_negatives(findings, modules_run, context)

    # ── Internal Helpers ──────────────────────────────────────────────

    def _heuristic_confidence(self, finding: dict[str, Any]) -> Confidence | None:
        """Compute heuristic confidence based on vuln type and evidence.

        Returns Confidence level or None if no heuristic applies.
        """
        title = finding.get("title", "").lower()
        evidence = finding.get("evidence", {})
        extra = evidence.get("extra", {})

        # Time-based SQLi: check for delay evidence
        if "time-based" in title and ("sqli" in title or "sql" in title):
            elapsed = extra.get("elapsed") or extra.get("delay_s", 0)
            if isinstance(elapsed, (int, float)) and elapsed >= 4.0:
                return Confidence.HIGH
            return Confidence.MEDIUM

        # Error-based SQLi: check for DB-specific error
        if "error" in title and ("sqli" in title or "sql" in title):
            db_type = extra.get("db_type", "")
            if db_type and db_type.lower() not in ("generic", "unknown", ""):
                return Confidence.HIGH
            return Confidence.MEDIUM

        # XSS: check for canary reflection
        if "xss" in title:
            payload = extra.get("payload", "")
            response = evidence.get("response_raw", "")
            if payload and payload in response:
                return Confidence.MEDIUM
            return Confidence.LOW

        # SSRF: OOB callback = HIGH, response change alone = LOW
        if "ssrf" in title:
            if extra.get("oob_callback") or extra.get("callback_received"):
                return Confidence.HIGH
            if extra.get("indicators_hit"):
                return Confidence.MEDIUM
            return Confidence.LOW

        # Command injection
        if "command injection" in title or "cmdi" in title:
            if extra.get("oob_callback"):
                return Confidence.HIGH
            detection = extra.get("detection", "")
            if "time-based" in detection:
                return Confidence.MEDIUM
            if "output-based" in detection:
                return Confidence.MEDIUM
            return Confidence.LOW

        return None


# ══════════════════════════════════════════════════════════════════════
# SEVERITY ADJUSTMENT HELPERS
# ══════════════════════════════════════════════════════════════════════

def _upgrade_severity(finding: Any) -> None:
    """Upgrade finding severity by one level."""
    from common.finding import Severity
    order = [
        Severity.INFORMATIONAL, Severity.LOW, Severity.MEDIUM,
        Severity.HIGH, Severity.CRITICAL,
    ]
    try:
        idx = order.index(finding.severity)
        if idx < len(order) - 1:
            finding.severity = order[idx + 1]
    except (ValueError, AttributeError):
        pass


def _downgrade_severity(finding: Any) -> None:
    """Downgrade finding severity by one level."""
    from common.finding import Severity
    order = [
        Severity.INFORMATIONAL, Severity.LOW, Severity.MEDIUM,
        Severity.HIGH, Severity.CRITICAL,
    ]
    try:
        idx = order.index(finding.severity)
        if idx > 0:
            finding.severity = order[idx - 1]
    except (ValueError, AttributeError):
        pass


# ══════════════════════════════════════════════════════════════════════
# TESTS
# ══════════════════════════════════════════════════════════════════════

class TestFindingAnalyst:
    """Unit tests for FindingAnalyst."""

    def test_init_without_brain(self) -> None:
        analyst = FindingAnalyst()
        assert analyst.brain is not None
        assert not analyst.brain.available  # No API key in test

    def test_heuristic_time_sqli_high(self) -> None:
        analyst = FindingAnalyst()
        finding = {
            "title": "Blind SQL Injection (Time-Based) — id",
            "evidence": {"extra": {"elapsed": 5.2}},
        }
        conf = analyst._heuristic_confidence(finding)
        assert conf == Confidence.HIGH

    def test_heuristic_time_sqli_medium(self) -> None:
        analyst = FindingAnalyst()
        finding = {
            "title": "Blind SQL Injection (Time-Based) — id",
            "evidence": {"extra": {"elapsed": 3.0}},
        }
        conf = analyst._heuristic_confidence(finding)
        assert conf == Confidence.MEDIUM

    def test_heuristic_error_sqli_high(self) -> None:
        analyst = FindingAnalyst()
        finding = {
            "title": "SQL Injection (error) — param (MySQL)",
            "evidence": {"extra": {"db_type": "MySQL"}},
        }
        conf = analyst._heuristic_confidence(finding)
        assert conf == Confidence.HIGH

    def test_heuristic_xss_medium(self) -> None:
        analyst = FindingAnalyst()
        finding = {
            "title": "Reflected XSS — q",
            "evidence": {
                "extra": {"payload": "<script>alert(1)</script>"},
                "response_raw": "blah <script>alert(1)</script> blah",
            },
        }
        conf = analyst._heuristic_confidence(finding)
        assert conf == Confidence.MEDIUM

    def test_heuristic_ssrf_oob_high(self) -> None:
        analyst = FindingAnalyst()
        finding = {
            "title": "SSRF via OOB",
            "evidence": {"extra": {"oob_callback": True}},
        }
        conf = analyst._heuristic_confidence(finding)
        assert conf == Confidence.HIGH

    def test_heuristic_ssrf_response_medium(self) -> None:
        analyst = FindingAnalyst()
        finding = {
            "title": "SSRF — AWS metadata",
            "evidence": {"extra": {"indicators_hit": ["ami-id"]}},
        }
        conf = analyst._heuristic_confidence(finding)
        assert conf == Confidence.MEDIUM

    def test_heuristic_cmdi_oob_high(self) -> None:
        analyst = FindingAnalyst()
        finding = {
            "title": "OS Command Injection — cmd param",
            "evidence": {"extra": {"oob_callback": True}},
        }
        conf = analyst._heuristic_confidence(finding)
        assert conf == Confidence.HIGH

    def test_heuristic_unknown_returns_none(self) -> None:
        analyst = FindingAnalyst()
        finding = {
            "title": "Something Unknown",
            "evidence": {"extra": {}},
        }
        conf = analyst._heuristic_confidence(finding)
        assert conf is None

    def test_analyze_sync(self) -> None:
        """Test that analyze() works with rule-based fallback."""
        import asyncio
        analyst = FindingAnalyst()
        finding = {
            "id": "test-1",
            "title": "Reflected XSS — param q",
            "severity": "High",
            "module": "xss_scanner",
            "evidence": {"request_raw": "GET /search?q=<script>", "response_raw": "<script>"},
        }
        result = asyncio.run(analyst.analyze(finding))
        assert result.finding_id == "test-1"
        assert result.verdict in (Verdict.TRUE_POSITIVE, Verdict.NEEDS_VERIFICATION)

    def test_filter_suppresses_low_confidence(self) -> None:
        """filter_false_positives must suppress findings below min_confidence."""
        import asyncio
        analyst = FindingAnalyst()
        finding = {
            "id": "low-conf-1",
            "title": "Something Unknown",
            "severity": "Low",
            "module": "unknown_module",
            "evidence": {"extra": {}},
        }
        result = asyncio.run(
            analyst.filter_false_positives([finding], min_confidence="MEDIUM")
        )
        assert len(result) == 0

    def test_filter_keeps_high_confidence(self) -> None:
        """filter_false_positives must keep findings at or above min_confidence."""
        import asyncio
        analyst = FindingAnalyst()
        finding = {
            "id": "high-conf-1",
            "title": "SQL Injection (time-based) — id",
            "severity": "Critical",
            "module": "sqli_scanner",
            "evidence": {"request_raw": "GET /?id=1", "extra": {"elapsed": 5.5}},
        }
        result = asyncio.run(
            analyst.filter_false_positives([finding], min_confidence="MEDIUM")
        )
        assert len(result) == 1

    def test_enrich_finding(self) -> None:
        """Test that enrich_finding adds brain metadata."""
        from common.finding import Finding, Severity
        from common.evidence import Evidence

        analyst = FindingAnalyst()
        finding = Finding(
            title="Test",
            severity=Severity.HIGH,
            target="https://example.com",
            module="test",
            description="Test finding",
            reproduction_steps=["Step 1"],
            remediation="Fix it",
            references=["CWE-79"],
        )
        analysis = AnalysisResult(
            finding_id=finding.id,
            verdict=Verdict.TRUE_POSITIVE,
            confidence=Confidence.HIGH,
            reasoning="Strong evidence",
        )
        enriched = analyst.enrich_finding(finding, analysis)
        assert "brain:verdict:TRUE_POSITIVE" in enriched.tags
        assert "brain:confidence:HIGH" in enriched.tags

    def test_severity_upgrade(self) -> None:
        from common.finding import Severity

        class FakeFinding:
            severity = Severity.MEDIUM

        f = FakeFinding()
        _upgrade_severity(f)
        assert f.severity == Severity.HIGH

    def test_severity_downgrade(self) -> None:
        from common.finding import Severity

        class FakeFinding:
            severity = Severity.HIGH

        f = FakeFinding()
        _downgrade_severity(f)
        assert f.severity == Severity.MEDIUM
