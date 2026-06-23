"""Abstract BaseModule — all forge modules inherit from this."""
from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from common.dashboard.event_bus import EventBus

from common.config import BaseForgeConfig
from common.confirm_gate import confirm
from common.db import Session, save_finding
from common.evidence import Evidence
from common.finding import Finding, Severity, cvss31_score
from common.scope import Scope, ScopeViolation


@dataclass
class ModuleResult:
    """Container for all findings produced by a module run."""
    module_name: str
    findings:    list[Finding] = field(default_factory=list)
    errors:      list[str]     = field(default_factory=list)
    duration_s:  float         = 0.0
    skipped:     bool          = False
    skip_reason: str           = ""


class BaseModule(ABC):
    """Abstract base class for all forge modules.

    Every module must implement run() and provide NAME, DESCRIPTION, PHASE.
    Subclasses inherit scope checking, rate limiting, logging, finding
    persistence, screenshot capture, and operator confirmation gate.
    """

    NAME:        str = "base_module"
    DESCRIPTION: str = "Base module"
    PHASE:       int = 0
    TAGS:        list[str] = []

    # Shared rate-limit state per target — ensures the configured req/s limit
    # holds globally even when multiple modules run concurrently in a phase.
    _shared_rate_locks: dict[str, asyncio.Lock] = {}
    _shared_rate_last:  dict[str, float]        = {}

    def __init__(
        self,
        config: BaseForgeConfig,
        scope: Scope,
        db_session: Session,
        results_dir: Path,
        run_id: str | None = None,
        event_bus: "EventBus | None" = None,
    ) -> None:
        """Initialize module with shared resources.

        Args:
            config:      Framework configuration.
            scope:       Scope enforcer instance.
            db_session:  Active SQLAlchemy session.
            results_dir: Directory for evidence output.
            run_id:      Scan run UUID for correlation.
            event_bus:   Optional dashboard event bus for real-time UI.
        """
        self.config      = config
        self.scope       = scope
        self.db          = db_session
        self.results_dir = results_dir
        self.run_id      = run_id or str(uuid.uuid4())
        self.findings:   list[Finding] = []
        self.log         = logging.getLogger(f"forge.{self.NAME}")
        self._evidence_dir = results_dir / "evidence"
        self._screenshot_dir = self._evidence_dir / "screenshots"
        self._event_bus: "EventBus | None" = event_bus
        self._request_count: int = 0
        # Deduplication guard — tracks (module, title, url) tuples already emitted.
        # Prevents per-origin / per-payload / per-probe-variant inflation where the
        # same vulnerability fires N times because an inner loop wasn't broken early.
        self._seen_finding_keys: dict[str, int] = {}

    @abstractmethod
    async def run(self) -> ModuleResult:
        """Execute the module. Must be implemented by every module.

        Returns:
            ModuleResult containing all findings and metadata.
        """

    def check_scope(self, target: str) -> bool:
        """Validate target is in scope before any request.

        Returns:
            True if in scope. Logs and returns False if out of scope.
        """
        try:
            return self.scope.check(target)
        except ScopeViolation as exc:
            self.log.warning("Scope violation blocked: %s", exc)
            return False

    async def rate_limit(self, bytes_out: int = 0, bytes_in: int = 0) -> None:
        """Enforce rate limiting between requests, shared across concurrent modules.

        Uses a class-level lock per target so the configured req/s cap holds
        globally regardless of how many modules are running in parallel.
        """
        if self.config.rate.requests_per_second <= 0:
            return
        target = self.config.target
        if target not in BaseModule._shared_rate_locks:
            BaseModule._shared_rate_locks[target] = asyncio.Lock()
            BaseModule._shared_rate_last[target]  = 0.0
        min_interval = 1.0 / self.config.rate.requests_per_second
        async with BaseModule._shared_rate_locks[target]:
            elapsed = time.monotonic() - BaseModule._shared_rate_last[target]
            if elapsed < min_interval:
                await asyncio.sleep(min_interval - elapsed)
            BaseModule._shared_rate_last[target] = time.monotonic()
        self._request_count += 1
        self._emit_event("request_sent", bytes_out=bytes_out, bytes_in=bytes_in)

    def add_finding(self, finding: Finding) -> None:
        """Record a finding, persist to DB, emit to dashboard, and log it.

        Duplicate suppression: if this module has already emitted a finding with
        the same title at the same URL/target, the second call is dropped and a
        warning is logged.  This catches per-payload / per-probe-variant inflation
        (e.g. testing 4 evil origins against the same URL, all returning wildcard
        CORS) without requiring every module to track dedup state manually.
        """
        _url = finding.url or finding.target or ""
        _dedup_key = f"{self.NAME}\x00{finding.title}\x00{_url}"
        if _dedup_key in self._seen_finding_keys:
            self._seen_finding_keys[_dedup_key] += 1
            self.log.warning(
                "[DEDUP] Suppressed duplicate finding (occurrence %d): '%s' at '%s'",
                self._seen_finding_keys[_dedup_key],
                finding.title,
                _url,
            )
            return
        self._seen_finding_keys[_dedup_key] = 1
        self.findings.append(finding)
        try:
            save_finding(self.db, finding.to_dict(), run_id=self.run_id)
        except Exception as exc:
            self.log.error("Failed to save finding to DB: %s", exc)
        self.log.info(
            "[FINDING] %s | %s | %s",
            finding.severity.value,
            finding.title,
            finding.target,
            extra={"forge_module": self.NAME, "target": finding.target},
        )
        # Emit to dashboard event bus
        self._emit_event(
            "finding_new",
            id=finding.id,
            title=finding.title,
            severity=finding.severity.value,
            module=self.NAME,
            target=finding.target,
            cvss_score=finding.cvss_v31_score,
            url=finding.url or "",
            port=finding.port,
            service=finding.service,
            description=finding.description,
            mitre_attack=finding.mitre_attack,
            confidence=finding.confidence,
            status=finding.status,
            vpr_score=finding.vpr_score,
            vpr_priority=finding.vpr_priority or finding.vpr,
            verification=finding.verification or {},
            evidence=finding.evidence.to_dict(),
        )

        # Start auto-analysis in background
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self._async_analyze_finding(finding))
        except RuntimeError:
            pass

    async def _async_analyze_finding(self, finding: Finding) -> None:
        """Background task to run Brain analysis on a new finding."""
        try:
            from common.brain.analyst import FindingAnalyst
            analyst = FindingAnalyst()
            if not analyst.brain.available:
                return
            analysis = await analyst.analyze(finding)
            analyst.enrich_finding(finding, analysis)
            
            # Re-save enriched finding
            try:
                from common.db import save_finding
                save_finding(self.db, finding.to_dict(), run_id=self.run_id)
            except Exception as exc:
                self.log.debug("Failed to update finding after analysis: %s", exc)

            # Emit verdict event
            self._emit_event(
                "brain_verdict",
                finding_id=finding.id,
                verdict=analysis.verdict.value,
                confidence=analysis.confidence.value,
                reasoning=analysis.reasoning,
                severity_adjustment=analysis.severity_adjustment,
            )
        except Exception as exc:
            self.log.debug("Finding auto-analysis failed: %s", exc)

    def new_finding(
        self,
        title: str,
        severity: Severity,
        description: str,
        reproduction_steps: list[str],
        remediation: str,
        references: list[str],
        evidence: Evidence | None = None,
        cvss_v31_vector: str | None = None,
        cvss_v40_vector: str | None = None,
        mitre_attack: list[str] | None = None,
        port: int | None = None,
        service: str | None = None,
        target: str | None = None,
        url: str | None = None,
        confidence: str = "UNVERIFIED",
        verification: "dict[str, Any] | None" = None,
    ) -> Finding:
        """Create a new finding, add it, and return it."""
        evidence = evidence or Evidence()
        verification = verification or self._verification_from_evidence(evidence)
        confidence = self._normalise_confidence(
            confidence,
            verification=verification,
            evidence=evidence,
        )
        cvss_score = cvss31_score(cvss_v31_vector) if cvss_v31_vector else 0.0
        vpr_score, vpr_priority = self._calculate_vpr(cvss_score, title)
        status = "verified" if confidence in {"HIGH", "MEDIUM"} else "open"
        if verification:
            verification.setdefault("confidence", confidence)

        f = Finding(
            title=title,
            severity=severity,
            target=target or self.config.target,
            module=self.NAME,
            description=description,
            reproduction_steps=reproduction_steps,
            remediation=remediation,
            references=references,
            evidence=evidence,
            cvss_v31_vector=cvss_v31_vector,
            cvss_v40_vector=cvss_v40_vector,
            mitre_attack=mitre_attack or [],
            port=port,
            service=service,
            url=url,
            confidence=confidence,
            status=status,
            vpr_score=vpr_score,
            vpr_priority=vpr_priority,
            vpr=vpr_priority,
            verification=verification or None,
        )
        self.add_finding(f)
        return f

    def _normalise_confidence(
        self,
        confidence: str,
        verification: dict[str, Any] | None = None,
        evidence: Evidence | None = None,
    ) -> str:
        """Return canonical finding confidence."""
        raw = confidence
        if raw == "UNVERIFIED" and verification:
            raw = str(verification.get("confidence") or raw)
        if raw == "UNVERIFIED" and evidence:
            raw = str(evidence.extra.get("fp_confidence") or raw)
        raw = raw.upper().replace(" ", "_")
        return raw if raw in {"HIGH", "MEDIUM", "LOW", "UNVERIFIED"} else "UNVERIFIED"

    def _verification_from_evidence(self, evidence: Evidence) -> dict[str, Any]:
        """Promote FPReducer evidence extras into the first-class verification field."""
        extra = evidence.extra or {}
        if not any(k in extra for k in ("fp_confidence", "fp_evidence", "fp_probe_count", "fp_probe_hits")):
            return {}
        return {
            "confidence": extra.get("fp_confidence", "UNVERIFIED"),
            "evidence": extra.get("fp_evidence", []),
            "probe_count": extra.get("fp_probe_count", 0),
            "probe_hits": extra.get("fp_probe_hits", 0),
        }

    def _is_waf_placeholder(
        self,
        body: str,
        status: int | None = None,
        headers: Any | None = None,
    ) -> bool:
        """Return True for generic WAF/firewall block pages, not app content."""
        haystack = body[:2000].lower()
        patterns = (
            "request rejected",
            "the requested url was rejected",
            "please consult with your administrator",
            "your support id is",
            "access denied",
            "blocked by",
            "web application firewall",
            "mod_security",
            "modsecurity",
            "forbidden by rule",
        )
        if any(p in haystack for p in patterns):
            return True
        header_text = " ".join(f"{k}: {v}" for k, v in dict(headers or {}).items()).lower()
        return status in {403, 406, 429} and any(
            p in header_text for p in ("waf", "firewall", "akamai", "cloudflare", "imperva", "f5")
        )

    async def _soft_404_fingerprints(self, target: str, probes: int = 2) -> set[str]:
        """Fingerprint unknown-path responses used by SPAs, CDNs, and firewalls."""
        _cache_key = f"_soft404_fp_cache\x00{target}"
        if _cache_key in self.config.extra:
            return set(self.config.extra[_cache_key] or [])

        import aiohttp
        fps: set[str] = set()
        try:
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False)
            ) as session:
                for _ in range(max(1, probes)):
                    canary = f"{target}/_forge_missing_{uuid.uuid4().hex[:12]}"
                    async with session.get(
                        canary, allow_redirects=True,
                        timeout=aiohttp.ClientTimeout(total=5),
                    ) as resp:
                        body = await resp.text(errors="ignore")
                        if resp.status in {200, 401, 403, 404, 406, 429}:
                            fps.add(self._response_fingerprint(body, resp.status))
        except Exception:
            pass

        self.config.extra[_cache_key] = sorted(fps)
        return fps

    def _response_fingerprint(self, body: str, status: int | None = None) -> str:
        """Stable fingerprint with volatile support/request IDs stripped."""
        normalized = re.sub(
            r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
            "<uuid>",
            body[:4096],
            flags=re.IGNORECASE,
        )
        normalized = re.sub(r"\b[0-9a-f]{16,}\b", "<hex>", normalized, flags=re.IGNORECASE)
        normalized = re.sub(r"\b\d{6,}\b", "<num>", normalized)
        normalized = re.sub(r"\s+", " ", normalized).strip()
        digest = hashlib.md5(normalized.encode(errors="ignore")).hexdigest()
        return f"{status or 0}:{digest}:{len(normalized)}"

    def _is_soft_404_body(self, body: str, status: int, fingerprints: set[str] | None) -> bool:
        """Return True when a response matches unknown-path baseline fingerprints."""
        if not fingerprints:
            return False
        return self._response_fingerprint(body, status) in fingerprints

    def _calculate_vpr(self, cvss_score: float, title: str) -> tuple[float | None, str | None]:
        """Calculate a lightweight VPR score when CVSS is available."""
        try:
            if cvss_score <= 0:
                return None, None
            from common.vpr import calculate_vpr
            score = calculate_vpr(cvss_score, vuln_type=self._infer_vuln_type(title))
            return round(score.vpr, 2), score.priority
        except Exception:
            if cvss_score >= 9.0:
                return cvss_score, "Critical"
            if cvss_score >= 7.0:
                return cvss_score, "High"
            if cvss_score >= 4.0:
                return cvss_score, "Medium"
            if cvss_score > 0:
                return cvss_score, "Low"
            return None, None

    def _infer_vuln_type(self, title: str) -> str:
        """Infer a VPR vuln type from the module name and title."""
        haystack = f"{self.NAME} {title}".lower()
        mappings = {
            "sqli": ("sqli", "sql injection"),
            "xss": ("xss", "cross-site scripting"),
            "ssti": ("ssti", "template injection"),
            "cmdi": ("cmdi", "command injection", "cmd injection"),
            "ssrf": ("ssrf",),
            "lfi": ("lfi", "local file inclusion"),
            "xxe": ("xxe",),
            "idor": ("idor",),
            "auth_bypass": ("auth bypass", "authentication bypass"),
            "rce": ("rce", "remote code execution"),
        }
        for vuln_type, needles in mappings.items():
            if any(needle in haystack for needle in needles):
                return vuln_type
        return ""

    def confirm_action(
        self,
        action: str,
        target: str,
        risk: str,
        on_confirm: Any = None,
        on_skip: Any = None,
    ) -> bool:
        """Require operator confirmation before executing a sensitive action."""
        return confirm(
            module=self.NAME,
            action=action,
            target=target,
            risk=risk,
            on_confirm=on_confirm,
            on_skip=on_skip,
        )

    def capture_screenshot(
        self,
        url: str,
        finding_id: str,
        highlight_js: str | None = None,
        cookies: list[dict] | None = None,
    ) -> str | None:
        """Capture a screenshot for POC evidence.

        Returns path to PNG, or None if screenshot unavailable.
        """
        try:
            from common.screenshot import capture
            return capture(
                url=url,
                output_dir=self._screenshot_dir,
                highlight_js=highlight_js,
                cookies=cookies,
                finding_id=finding_id,
            )
        except Exception as exc:
            self.log.debug("Screenshot unavailable: %s", exc)
            return None

    def _make_result(self, start_time: float, skipped: bool = False, skip_reason: str = "") -> ModuleResult:
        """Build a ModuleResult from accumulated findings."""
        duration = time.monotonic() - start_time
        if skipped:
            self._emit_event("module_skip", name=self.NAME, reason=skip_reason)
        else:
            self._emit_event(
                "module_complete", name=self.NAME,
                findings_count=len(self.findings), duration=duration,
            )
        return ModuleResult(
            module_name=self.NAME,
            findings=self.findings,
            duration_s=duration,
            skipped=skipped,
            skip_reason=skip_reason,
        )

    def _emit_event(self, event_type_str: str, **data: Any) -> None:
        """Emit a dashboard event if event_bus is connected."""
        if not self._event_bus:
            return
        try:
            from common.dashboard.event_bus import Event, EventType
            et = EventType(event_type_str)
            self._event_bus.emit(Event(
                event_type=et, data=data, source=self.NAME, run_id=self.run_id,
            ))
        except (ValueError, ImportError) as exc:
            self.log.debug("Event emission skipped (%s): %s", event_type_str, exc)

    async def _spa_fingerprint(self, target: str) -> str | None:
        """Return MD5 fingerprint if the target uses SPA catch-all routing.

        GETs a random canary URL; if the server returns 200 (SPA rewrites
        all unknown paths to index.html), returns the body MD5 so callers
        can compare against it and skip findings that are just the SPA shell.
        Returns None if the server correctly 404s on unknown paths.

        Result is cached in config.extra so all modules in the same scan
        share it — only one HTTP probe is sent per target per scan run.
        """
        _cache_key = f"_spa_fp_cache\x00{target}"
        if _cache_key in self.config.extra:
            return self.config.extra[_cache_key]

        import aiohttp
        canary = f"{target}/_forge_probe_{uuid.uuid4().hex[:8]}"
        result: str | None = None
        try:
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False)
            ) as session:
                async with session.get(
                    canary, allow_redirects=True,
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as resp:
                    if resp.status == 200:
                        body = await resp.text(errors="ignore")
                        result = hashlib.md5(body.encode()).hexdigest()
        except Exception:
            pass

        self.config.extra[_cache_key] = result  # cache even None to avoid re-probing
        return result

    def _is_spa_body(self, body: str, spa_fp: str | None) -> bool:
        """Return True when body matches the SPA catch-all fingerprint."""
        if spa_fp is None:
            return False
        return hashlib.md5(body.encode()).hexdigest() == spa_fp


class TestBaseModule:
    """Unit tests for base_module."""

    def test_module_requires_run(self) -> None:
        import inspect
        assert inspect.isabstract(BaseModule)

    def test_concrete_module(self, tmp_path: Path) -> None:
        from common.config import BaseForgeConfig
        from common.scope import Scope
        from common.db import create_db

        class DummyModule(BaseModule):
            NAME = "dummy"
            DESCRIPTION = "Test module"
            PHASE = 1

            async def run(self) -> ModuleResult:
                start = time.monotonic()
                return self._make_result(start)

        cfg = BaseForgeConfig(target="10.0.0.1")
        scope = Scope(["10.0.0.0/24"])
        session = create_db(tmp_path / "test.db")
        mod = DummyModule(cfg, scope, session, tmp_path)
        result = asyncio.run(mod.run())
        assert result.module_name == "dummy"
        assert result.findings == []
        session.close()
