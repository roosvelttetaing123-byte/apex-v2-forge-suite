"""FindingAnalyst — AI-powered finding analysis and FP/FN reduction.

Wraps ForgeBrain to provide finding-level analysis:
    - analyze()              → AnalysisResult for a single finding
    - bulk_analyze()         → batch analysis (token-efficient)
    - enrich_finding()       → compatibility no-op; verdict stays advisory
    - filter_false_positives()→ analyze without removing canonical findings
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
from common.redaction import redact_text

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
                    log.warning(
                        "Bulk analysis failed for finding %d: %s",
                        i + j,
                        redact_text(str(result)),
                    )
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
                        reasoning="Advisory analysis failed.",
                    ))
                else:
                    results.append(result)

        return results

    def enrich_finding(
        self,
        finding: Any,
        analysis: AnalysisResult,
    ) -> Any:
        """Return the finding unchanged; analysis is an advisory projection.

        Args:
            finding:  Finding object (with .tags, .evidence.extra, .severity).
            analysis: AnalysisResult from analyze().

        Returns:
            The original finding (same object), with no canonical mutation.
        """
        del analysis
        return finding

    async def filter_false_positives(
        self,
        findings: list[Any],
        min_confidence: str = "MEDIUM",
    ) -> list[Any]:
        """Analyze findings without allowing the model to remove canonical rows.

        Args:
            findings:       List of Finding objects or dicts.
            min_confidence: Minimum confidence to keep. Findings with
                           brain verdict of FALSE_POSITIVE are removed.

        Returns:
            The original list. Advisory verdicts are not finding authority.
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
                    "Advisory FP suggestion retained canonically: %s (confidence=%s, reason=%s)",
                    fid, analysis.confidence.value, analysis.reasoning[:80],
                )
            elif analysis.confidence == Confidence.LOW:
                log.info(
                    "Low-confidence advisory retained canonically: %s (%s < %s)",
                    analysis.finding_id, analysis.confidence.value, min_conf.value,
                )
            filtered.append(finding)

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

    def test_filter_retains_low_confidence_as_canonical_truth(self) -> None:
        """Advisory confidence cannot remove a canonical finding."""
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
        assert result == [finding]

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

    def test_enrich_finding_is_read_only(self) -> None:
        """Model output cannot mutate finding tags, evidence, or severity."""
        from common.finding import Finding, Severity

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
        original_tags = list(finding.tags)
        original_severity = finding.severity
        enriched = analyst.enrich_finding(finding, analysis)
        assert enriched is finding
        assert enriched.tags == original_tags
        assert enriched.severity == original_severity

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
