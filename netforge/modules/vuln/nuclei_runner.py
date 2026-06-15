"""Nuclei Runner — run Project Discovery Nuclei templates for vuln scanning.

Wraps nuclei CLI for:
  - Template-based vulnerability scanning
  - Custom severity filtering
  - Rate-limited scanning
  - Result parsing and integration
"""
from __future__ import annotations

import asyncio
import json
import re
import shutil
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFORMATIONAL,
}


class NucleiRunner(BaseModule):
    """Nuclei template-based vulnerability scanner wrapper."""

    NAME        = "nuclei_runner"
    DESCRIPTION = "Nuclei: template-based vuln scanning via Project Discovery"
    PHASE       = 5
    TAGS        = ["vuln", "scanner", "nuclei"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        nuclei = shutil.which("nuclei")
        if not nuclei:
            self.log.info("nuclei not found in PATH — skipping")
            return self._make_result(start, skipped=True, skip_reason="nuclei not installed")

        # Build nuclei command
        severity = self.config.extra.get("nuclei_severity", "critical,high,medium")
        rate_limit = self.config.extra.get("nuclei_rate_limit", 50)
        templates = self.config.extra.get("nuclei_templates", "")
        timeout = self.config.extra.get("nuclei_timeout", 120)

        cmd = [
            nuclei,
            "-target", target,
            "-severity", severity,
            "-rate-limit", str(rate_limit),
            "-jsonl",
            "-silent",
            "-no-color",
        ]

        if templates:
            cmd.extend(["-templates", templates])

        self.log.info("Running nuclei: %s", " ".join(cmd))

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout + 30
            )
            output = stdout.decode(errors="ignore")

            finding_count = 0
            for line in output.strip().split("\n"):
                if not line.strip():
                    continue
                try:
                    result = json.loads(line)
                    self._process_nuclei_result(result, target)
                    finding_count += 1
                except json.JSONDecodeError:
                    # Try parsing non-JSON output
                    self._parse_text_result(line, target)
                    finding_count += 1

            self.log.info("Nuclei found %d results", finding_count)

        except asyncio.TimeoutError:
            self.log.warning("Nuclei scan timed out after %ds", timeout)
        except Exception as exc:
            self.log.error("Nuclei failed: %s", exc)

        return self._make_result(start)

    def _process_nuclei_result(self, result: dict, target: str) -> None:
        template_id = result.get("template-id", result.get("templateID", "unknown"))
        name = result.get("info", {}).get("name", result.get("name", template_id))
        severity_str = result.get("info", {}).get("severity", result.get("severity", "info"))
        matched_at = result.get("matched-at", result.get("matched", target))
        description = result.get("info", {}).get("description", "")
        references = result.get("info", {}).get("reference", [])
        if isinstance(references, str):
            references = [references]
        curl_cmd = result.get("curl-command", "")
        extracted = result.get("extracted-results", [])

        severity = SEVERITY_MAP.get(severity_str.lower(), Severity.MEDIUM)

        ev = Evidence(
            request_raw=curl_cmd[:500] if curl_cmd else "",
            extra={
                "template": template_id,
                "matched_at": matched_at,
                "extracted": extracted[:5] if extracted else [],
            },
        )

        self.new_finding(
            title=f"[Nuclei] {name} — {matched_at}",
            severity=severity,
            description=description or f"Nuclei template {template_id} matched at {matched_at}",
            reproduction_steps=[
                f"nuclei -target {target} -templates {template_id}",
                *(([curl_cmd] if curl_cmd else [])),
            ],
            remediation=result.get("info", {}).get("remediation", "See template details."),
            references=references[:5],
            evidence=ev,
            cvss_v31_vector=self._severity_to_cvss31(severity),
            cvss_v40_vector=self._severity_to_cvss40(severity),
            target=target,
        )

    def _parse_text_result(self, line: str, target: str) -> None:
        """Parse non-JSON nuclei output."""
        # Format: [template-id] [protocol] [severity] matched-url
        m = re.match(r"\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(.*)", line)
        if m:
            template_id, protocol, severity_str, matched = m.groups()
            severity = SEVERITY_MAP.get(severity_str.lower(), Severity.MEDIUM)
            ev = Evidence(extra={"template": template_id, "matched": matched.strip()})
            self.new_finding(
                title=f"[Nuclei] {template_id} — {matched.strip()}",
                severity=severity,
                description=f"Nuclei {template_id} ({protocol}) matched: {matched.strip()}",
                reproduction_steps=[f"nuclei -target {target} -templates {template_id}"],
                remediation="Review nuclei template for details.",
                references=[],
                evidence=ev,
                cvss_v31_vector=self._severity_to_cvss31(severity),
                cvss_v40_vector=self._severity_to_cvss40(severity),
                target=target,
            )

    def _severity_to_cvss31(self, severity: Severity) -> str:
        mapping = {
            Severity.CRITICAL: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            Severity.HIGH: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            Severity.MEDIUM: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
            Severity.LOW: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        }
        return mapping.get(severity, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")

    def _severity_to_cvss40(self, severity: Severity) -> str:
        mapping = {
            Severity.CRITICAL: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            Severity.HIGH: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
            Severity.MEDIUM: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
            Severity.LOW: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
        }
        return mapping.get(severity, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N")


class TestNucleiRunner:
    def test_severity_map(self) -> None:
        assert SEVERITY_MAP["critical"] == Severity.CRITICAL
        assert SEVERITY_MAP["info"] == Severity.INFORMATIONAL

    def test_phase(self) -> None:
        assert NucleiRunner.PHASE == 5
