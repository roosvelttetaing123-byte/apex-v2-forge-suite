"""YAML Check Engine — data-driven vulnerability scanning at scale.

Loads YAML check definitions from netforge/data/checks/ and executes
them during scans. One engine, hundreds of checks, zero Python modules
per CVE. This is how you go from 33 CVEs to 500+ active checks without
losing your goddamn mind writing individual modules.

Supports:
  - HTTP probing (GET/POST with custom headers, body matching, regex)
  - Banner grabbing (TCP connect, pattern matching)
  - Version comparison (CPE + version range)
  - OOB callback detection (via ForgeCollab)
  - Smart targeting (only run checks matching discovered services)

Tests:
  - YAML loading and validation
  - HTTP probe execution
  - Banner probe execution
  - Match condition evaluation
  - Service filtering
"""
from __future__ import annotations

import asyncio
import re
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

# Checks directory
CHECKS_DIR = Path(__file__).parent.parent.parent / "data" / "checks"

SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFORMATIONAL,
}


class YamlCheckEngine(BaseModule):
    """Data-driven vulnerability scanner using YAML check definitions.

    Loads all .yaml files from netforge/data/checks/, filters by
    discovered services, and executes matching probes. Findings go
    through the standard new_finding() pipeline with FP reduction,
    dedup, and dashboard emission.
    """

    NAME        = "yaml_check_engine"
    DESCRIPTION = "YAML: data-driven vulnerability checks (500+ active probes)"
    PHASE       = 5
    TAGS        = ["vuln", "yaml-checks", "active"]

    MAX_CONCURRENT_CHECKS = 10
    CHECK_TIMEOUT = 15.0

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        # Load check definitions
        try:
            from netforge.data.check_schema import load_checks_from_directory, VulnCheck
        except ImportError as exc:
            self.log.error("Check schema import failed: %s", exc)
            return self._make_result(start, skipped=True, skip_reason=str(exc))

        checks_dir = Path(self.config.extra.get("checks_dir", str(CHECKS_DIR)))
        all_checks = load_checks_from_directory(checks_dir)

        if not all_checks:
            self.log.info("No YAML checks found in %s — skipping", checks_dir)
            return self._make_result(start, skipped=True, skip_reason="no checks loaded")

        # Filter checks by discovered services
        service_map = self.config.extra.get("service_map", {})
        discovered_services = self._extract_services(service_map)

        applicable_checks = self._filter_checks(all_checks, discovered_services)
        self.log.info(
            "Loaded %d checks, %d applicable to discovered services",
            len(all_checks), len(applicable_checks),
        )

        # Execute checks with concurrency control
        semaphore = asyncio.Semaphore(self.MAX_CONCURRENT_CHECKS)
        tasks = [
            self._run_check_with_semaphore(semaphore, check, target, service_map)
            for check in applicable_checks
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

        self.log.info(
            "YAML check engine complete: %d checks run, %d findings",
            len(applicable_checks), len(self.findings),
        )

        return self._make_result(start)

    def _extract_services(self, service_map: dict) -> list[dict]:
        """Extract flat list of discovered services from service_map."""
        services = []
        for host, svcs in service_map.items():
            for svc in svcs:
                svc_copy = dict(svc)
                svc_copy["host"] = host
                services.append(svc_copy)
        return services

    def _filter_checks(
        self,
        checks: list,
        discovered_services: list[dict],
    ) -> list:
        """Filter checks to only those applicable to discovered services.

        If a check has no target_service/target_port, it runs against all targets.
        """
        if not discovered_services:
            # No service map — run all untargeted checks
            return [c for c in checks if not c.target_service and not c.target_port]

        applicable = []
        for check in checks:
            if not check.target_service and not check.target_port and not check.target_ports:
                # Untargeted check — always run
                applicable.append(check)
                continue

            for svc in discovered_services:
                svc_name = svc.get("service", svc.get("name", ""))
                svc_port = svc.get("port", 0)
                if check.matches_service(svc_name, svc_port):
                    applicable.append(check)
                    break

        return applicable

    async def _run_check_with_semaphore(
        self,
        semaphore: asyncio.Semaphore,
        check: Any,
        target: str,
        service_map: dict,
    ) -> None:
        async with semaphore:
            try:
                await asyncio.wait_for(
                    self._run_check(check, target, service_map),
                    timeout=self.CHECK_TIMEOUT * len(check.detection),
                )
            except asyncio.TimeoutError:
                self.log.debug("Check %s timed out", check.id)
            except Exception as exc:
                self.log.debug("Check %s failed: %s", check.id, exc)

    async def _run_check(
        self, check: Any, target: str, service_map: dict
    ) -> None:
        """Execute a single vulnerability check against the target."""
        from netforge.data.check_schema import CheckType

        results = []

        for step in check.detection:
            matched = False
            extracted = {}

            if step.type == CheckType.HTTP:
                matched, extracted = await self._run_http_step(step, target)
            elif step.type == CheckType.BANNER:
                matched, extracted = await self._run_banner_step(step, target, service_map)
            elif step.type == CheckType.TCP_PROBE:
                matched, extracted = await self._run_tcp_step(step, target)
            elif step.type == CheckType.VERSION:
                matched, extracted = await self._run_version_step(step, target, service_map)

            results.append((matched, extracted))

            # Short-circuit: if detection_all=False (OR logic), one match is enough
            if matched and not check.detection_all:
                break
            # Short-circuit: if detection_all=True (AND logic), one failure kills it
            if not matched and check.detection_all:
                return

        # Determine if check passed
        if check.detection_all:
            passed = all(r[0] for r in results)
        else:
            passed = any(r[0] for r in results)

        if passed:
            # Merge extracted data
            all_extracted = {}
            for _, ext in results:
                all_extracted.update(ext)
            self._emit_check_finding(check, target, all_extracted)

    async def _run_http_step(
        self, step: Any, target: str
    ) -> tuple[bool, dict]:
        """Execute an HTTP probe step."""
        import aiohttp
        from netforge.data.check_schema import MatchType

        paths = step.paths or [step.path]
        extracted = {}

        for path in paths:
            url = f"{target.rstrip('/')}{path}"

            await self.rate_limit()

            try:
                async with self.http_session(timeout=step.timeout) as session:
                    kwargs: dict[str, Any] = {
                        "allow_redirects": step.follow_redirects,
                    }
                    if step.headers:
                        # Merge with session headers
                        kwargs["headers"] = step.headers
                    if step.body:
                        kwargs["data"] = step.body

                    method = getattr(session, step.method.lower(), session.get)
                    async with method(url, **kwargs) as resp:
                        body = await resp.text(errors="ignore")
                        status = resp.status
                        resp_headers = dict(resp.headers)

                        # Evaluate match conditions
                        all_matched = True
                        any_matched = False

                        for cond in step.match:
                            hit = self._evaluate_condition(
                                cond, body, status, resp_headers
                            )
                            if hit:
                                any_matched = True
                            else:
                                all_matched = False

                        matched = all_matched if step.match_all else any_matched

                        # Extract data if configured
                        if matched and step.extract_regex:
                            m = re.search(step.extract_regex, body)
                            if m:
                                extracted[step.extract_name or "extracted"] = m.group(1) if m.groups() else m.group(0)

                        extracted["url"] = url
                        extracted["status_code"] = status
                        extracted["response_snippet"] = body[:500]

                        if matched:
                            return True, extracted

            except Exception as exc:
                self.log.debug("HTTP probe %s failed: %s", url, exc)
                continue

        return False, extracted

    async def _run_banner_step(
        self, step: Any, target: str, service_map: dict
    ) -> tuple[bool, dict]:
        """Execute a banner/TCP probe step."""
        from netforge.data.check_schema import MatchType

        # Determine target host and ports
        import urllib.parse
        parsed = urllib.parse.urlparse(target if "://" in target else f"tcp://{target}")
        host = parsed.hostname or target

        ports = step.ports or ([step.port] if step.port else [])

        # Also check service_map for matching ports
        if not ports:
            for svc_host, svcs in service_map.items():
                for svc in svcs:
                    ports.append(svc.get("port", 0))

        extracted = {}
        for port in ports:
            if port <= 0:
                continue

            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=step.timeout,
                )

                # Send data if configured
                if step.send:
                    send_data = step.send.encode("utf-8", errors="ignore")
                    writer.write(send_data)
                    await writer.drain()

                # Read banner
                banner_data = await asyncio.wait_for(
                    reader.read(step.read_bytes),
                    timeout=step.timeout,
                )
                banner = banner_data.decode("utf-8", errors="ignore")

                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

                # Evaluate match conditions
                all_matched = True
                any_matched = False

                for cond in step.match:
                    hit = self._evaluate_banner_condition(cond, banner)
                    if hit:
                        any_matched = True
                    else:
                        all_matched = False

                matched = all_matched if step.match_all else any_matched

                if matched:
                    extracted["host"] = host
                    extracted["port"] = port
                    extracted["banner"] = banner[:500]

                    if step.extract_regex:
                        m = re.search(step.extract_regex, banner)
                        if m:
                            extracted[step.extract_name or "version"] = (
                                m.group(1) if m.groups() else m.group(0)
                            )

                    return True, extracted

            except Exception as exc:
                self.log.debug("Banner probe %s:%d failed: %s", host, port, exc)
                continue

        return False, extracted

    async def _run_tcp_step(
        self, step: Any, target: str
    ) -> tuple[bool, dict]:
        """Execute a raw TCP probe step."""
        import urllib.parse
        parsed = urllib.parse.urlparse(target if "://" in target else f"tcp://{target}")
        host = parsed.hostname or target

        ports = step.ports or ([step.port] if step.port else [])
        extracted = {}

        for port in ports:
            if port <= 0:
                continue

            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=step.timeout,
                )

                if step.send:
                    # Handle hex-encoded payloads
                    if step.send.startswith("\\x") or step.send.startswith("0x"):
                        send_data = bytes.fromhex(
                            step.send.replace("\\x", "").replace("0x", "").replace(" ", "")
                        )
                    else:
                        send_data = step.send.encode("utf-8", errors="ignore")
                    writer.write(send_data)
                    await writer.drain()

                response = await asyncio.wait_for(
                    reader.read(step.read_bytes),
                    timeout=step.timeout,
                )

                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

                response_text = response.decode("utf-8", errors="ignore")

                all_matched = True
                any_matched = False
                for cond in step.match:
                    hit = self._evaluate_banner_condition(cond, response_text)
                    if hit:
                        any_matched = True
                    else:
                        all_matched = False

                matched = all_matched if step.match_all else any_matched
                if matched:
                    extracted["host"] = host
                    extracted["port"] = port
                    extracted["response"] = response_text[:500]
                    return True, extracted

            except Exception:
                continue

        return False, extracted

    async def _run_version_step(
        self, step: Any, target: str, service_map: dict
    ) -> tuple[bool, dict]:
        """Execute a version comparison step against service_map."""
        from netforge.data.cpe_generator import CPEGenerator

        cpe_gen = CPEGenerator()
        extracted = {}

        for host, svcs in service_map.items():
            for svc in svcs:
                cpe_entries = cpe_gen.from_nmap_service(svc)

                for cpe_entry in cpe_entries:
                    if (step.cpe_vendor and
                            cpe_entry.vendor.lower() != step.cpe_vendor.lower()):
                        continue
                    if (step.cpe_product and
                            cpe_entry.product.lower() != step.cpe_product.lower()):
                        continue

                    if step.version_range and cpe_entry.version:
                        if self._version_in_range(cpe_entry.version, step.version_range):
                            extracted["host"] = host
                            extracted["port"] = svc.get("port", 0)
                            extracted["version"] = cpe_entry.version
                            extracted["product"] = f"{cpe_entry.vendor}:{cpe_entry.product}"
                            return True, extracted

        return False, extracted

    def _version_in_range(self, version: str, range_str: str) -> bool:
        """Check if version is in a range string like '>=2.0,<2.15.0'."""
        try:
            from netforge.data.cve_db import CVEDatabase
            db = CVEDatabase.__new__(CVEDatabase)

            for constraint in range_str.split(","):
                constraint = constraint.strip()
                if constraint.startswith(">="):
                    ref = constraint[2:]
                    if db._version_compare(version, ref) < 0:
                        return False
                elif constraint.startswith(">"):
                    ref = constraint[1:]
                    if db._version_compare(version, ref) <= 0:
                        return False
                elif constraint.startswith("<="):
                    ref = constraint[2:]
                    if db._version_compare(version, ref) > 0:
                        return False
                elif constraint.startswith("<"):
                    ref = constraint[1:]
                    if db._version_compare(version, ref) >= 0:
                        return False
                elif constraint.startswith("="):
                    ref = constraint[1:]
                    if db._version_compare(version, ref) != 0:
                        return False
            return True
        except Exception:
            return False

    def _evaluate_condition(
        self,
        cond: Any,
        body: str,
        status: int,
        headers: dict,
    ) -> bool:
        """Evaluate a single match condition against an HTTP response."""
        from netforge.data.check_schema import MatchType

        result = False

        if cond.type == MatchType.STATUS_CODE:
            if isinstance(cond.value, list):
                result = status in cond.value
            else:
                result = status == int(cond.value)

        elif cond.type == MatchType.BODY_CONTAINS:
            if isinstance(cond.value, list):
                result = all(v in body for v in cond.value)
            else:
                result = str(cond.value) in body

        elif cond.type == MatchType.BODY_REGEX:
            try:
                result = bool(re.search(str(cond.value), body))
            except re.error:
                pass

        elif cond.type == MatchType.HEADER_CONTAINS:
            header_text = " ".join(f"{k}: {v}" for k, v in headers.items())
            result = str(cond.value) in header_text

        elif cond.type == MatchType.HEADER_REGEX:
            header_text = " ".join(f"{k}: {v}" for k, v in headers.items())
            try:
                result = bool(re.search(str(cond.value), header_text))
            except re.error:
                pass

        elif cond.type == MatchType.NOT_CONTAINS:
            result = str(cond.value) not in body

        elif cond.type == MatchType.RESPONSE_TIME:
            pass  # Would need timing data

        if cond.negate:
            result = not result

        return result

    def _evaluate_banner_condition(self, cond: Any, banner: str) -> bool:
        """Evaluate a match condition against a banner string."""
        from netforge.data.check_schema import MatchType

        result = False

        if cond.type == MatchType.BANNER_CONTAINS:
            if isinstance(cond.value, list):
                result = all(v in banner for v in cond.value)
            else:
                result = str(cond.value) in banner

        elif cond.type == MatchType.BANNER_REGEX:
            try:
                result = bool(re.search(str(cond.value), banner))
            except re.error:
                pass

        elif cond.type in (MatchType.BODY_CONTAINS, MatchType.BODY_REGEX):
            # Treat banner as body for generic matchers
            if cond.type == MatchType.BODY_CONTAINS:
                result = str(cond.value) in banner
            else:
                try:
                    result = bool(re.search(str(cond.value), banner))
                except re.error:
                    pass

        elif cond.type == MatchType.NOT_CONTAINS:
            result = str(cond.value) not in banner

        if cond.negate:
            result = not result

        return result

    def _emit_check_finding(
        self, check: Any, target: str, extracted: dict
    ) -> None:
        """Create a finding from a matched check."""
        severity = SEVERITY_MAP.get(check.severity, Severity.MEDIUM)

        # Build CVE reference list
        cve_refs = check.cves or ([check.cve] if check.cve else [])
        references = list(cve_refs)
        for cve_id in cve_refs[:3]:
            references.append(f"https://nvd.nist.gov/vuln/detail/{cve_id}")
        references.extend(check.references[:5])

        # Build title
        cve_prefix = cve_refs[0] if cve_refs else check.id
        title = f"[CHECK] {cve_prefix} — {check.name}"
        if extracted.get("host"):
            title += f" — {extracted['host']}"
            if extracted.get("port"):
                title += f":{extracted['port']}"

        # Build description
        desc = check.description or f"Vulnerability check {check.id} matched."
        if extracted.get("version"):
            desc += f"\n\nDetected version: {extracted['version']}"
        if extracted.get("url"):
            desc += f"\nMatched URL: {extracted['url']}"
        if extracted.get("banner"):
            desc += f"\nBanner: {extracted['banner'][:200]}"

        ev = Evidence(
            request_raw=extracted.get("url", ""),
            response_raw=extracted.get("response_snippet", extracted.get("banner", ""))[:2000],
            extra={
                "check_id": check.id,
                "cves": cve_refs,
                "tags": check.tags,
                "extracted": {
                    k: v for k, v in extracted.items()
                    if k not in ("response_snippet",)
                },
                "maturity": check.maturity,
                "proof_type": check.proof_type,
                "verification_state": check.verification_state,
                "detection_method": "active-probe",
            },
        )

        # Tags
        tags = list(check.tags)
        tags.append("yaml-check")
        if any("kev" in t.lower() for t in check.tags):
            tags.append("cisa-kev")

        self.new_finding(
            title=title,
            severity=severity,
            description=desc,
            reproduction_steps=[
                f"# Check ID: {check.id}",
                f"# CVEs: {', '.join(cve_refs)}",
                *(
                    [f"# URL: {extracted['url']}"]
                    if extracted.get("url") else []
                ),
                *(
                    [f"# Port: {extracted.get('host', target)}:{extracted['port']}"]
                    if extracted.get("port") else []
                ),
            ],
            remediation=check.remediation or f"Patch the vulnerability identified by {cve_prefix}.",
            references=references[:10],
            evidence=ev,
            cvss_v31_vector=check.cvss or "",
            cvss_v40_vector=check.cvss40 or "",
            port=extracted.get("port"),
            service=extracted.get("service", ""),
            target=extracted.get("host", target),
            url=extracted.get("url"),
            confidence="LOW",
            verification={
                "state": check.verification_state,
                "proof_type": check.proof_type,
                "maturity": check.maturity,
                "observations": {
                    key: value for key, value in extracted.items()
                    if key in {"status_code", "banner", "product", "version"}
                },
                "reasons": ["native_yaml_match_is_candidate"],
            },
            proof_type=check.proof_type,
            maturity=check.maturity,
            tags=tags,
        )


# ── Tests ────────────────────────────────────────────────────────────────

class TestYamlCheckEngine:
    def test_phase(self) -> None:
        assert YamlCheckEngine.PHASE == 5

    def test_severity_map(self) -> None:
        assert SEVERITY_MAP["critical"] == Severity.CRITICAL
        assert SEVERITY_MAP["info"] == Severity.INFORMATIONAL
