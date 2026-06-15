"""Static source code audit — bandit + semgrep wrapper for whitebox testing."""
from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_HIGH_SAST  = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
CVSS_MED_SAST   = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
CVSS_LOW_SAST   = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"

SEVERITY_MAP = {
    "HIGH":   (Severity.HIGH,   CVSS_HIGH_SAST),
    "MEDIUM": (Severity.MEDIUM, CVSS_MED_SAST),
    "LOW":    (Severity.LOW,    CVSS_LOW_SAST),
    "ERROR":  (Severity.HIGH,   CVSS_HIGH_SAST),
    "WARNING":(Severity.MEDIUM, CVSS_MED_SAST),
    "INFO":   (Severity.LOW,    CVSS_LOW_SAST),
}


class SourceAudit(BaseModule):
    """Whitebox static analysis via bandit and semgrep."""

    NAME        = "source_audit"
    DESCRIPTION = "Static analysis: run bandit and semgrep on source directory for security issues"
    PHASE       = 11
    TAGS        = ["whitebox", "sast", "bandit", "semgrep", "owasp-a06", "cwe-676"]

    async def run(self) -> ModuleResult:
        """Run SAST tools on the configured source directory."""
        start      = time.monotonic()
        target     = self.config.target.rstrip("/")
        source_dir = self.config.extra.get("source", "")

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        if not source_dir:
            self.log.warning("source_audit requires --source <path>; skipping")
            return self._make_result(start, skipped=True, skip_reason="no source directory")

        src_path = Path(source_dir).expanduser().resolve()
        if not src_path.exists():
            self.log.warning("Source directory not found: %s", src_path)
            return self._make_result(start, skipped=True, skip_reason="source dir not found")

        self.log.info("Running static analysis on %s", src_path)

        await self._run_bandit(src_path, target)
        await self._run_semgrep(src_path, target)

        return self._make_result(start)

    async def _run_bandit(self, src: Path, target: str) -> None:
        """Run bandit and parse JSON output."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "bandit", "-r", str(src), "-f", "json", "-q",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
        except FileNotFoundError:
            self.log.warning("bandit not found — skipping bandit analysis")
            return
        except asyncio.TimeoutError:
            self.log.warning("bandit timed out after 120s")
            return
        except Exception as exc:
            self.log.error("bandit error: %s", exc)
            return

        try:
            data = json.loads(stdout.decode(errors="ignore"))
        except Exception:
            return

        results = data.get("results", [])
        self.log.info("bandit: %d issues found", len(results))

        for issue in results:
            sev_key = issue.get("issue_severity", "LOW").upper()
            severity, cvss = SEVERITY_MAP.get(sev_key, (Severity.LOW, CVSS_LOW_SAST))

            ev = Evidence(
                request_raw=f"bandit -r {src}",
                response_raw=json.dumps(issue, indent=2)[:500],
                extra={
                    "file": issue.get("filename", ""),
                    "line": issue.get("line_number", 0),
                    "test_id": issue.get("test_id", ""),
                },
            )
            self.new_finding(
                title=f"[bandit] {issue.get('test_name', 'Issue')}: {Path(issue.get('filename', '')).name}:{issue.get('line_number')}",
                severity=severity,
                description=(
                    f"{issue.get('issue_text', '')}\n\n"
                    f"File: {issue.get('filename')}:{issue.get('line_number')}\n"
                    f"Test: {issue.get('test_id')} — {issue.get('test_name')}\n"
                    f"More info: {issue.get('more_info', '')}"
                ),
                reproduction_steps=[
                    f"Open {issue.get('filename')}:{issue.get('line_number')}",
                    f"Observe: {issue.get('code', '').strip()[:200]}",
                ],
                remediation=f"Refer to {issue.get('more_info', 'CWE references')} for remediation.",
                references=[issue.get("test_id", "CWE"), "OWASP A06:2021"],
                evidence=ev,
                cvss_v31_vector=cvss,
                target=target,
            )

    async def _run_semgrep(self, src: Path, target: str) -> None:
        """Run semgrep with auto ruleset and parse JSON output."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "semgrep", "--config", "auto", "--json", "--quiet", str(src),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=180)
        except FileNotFoundError:
            self.log.warning("semgrep not found — skipping semgrep analysis")
            return
        except asyncio.TimeoutError:
            self.log.warning("semgrep timed out after 180s")
            return
        except Exception as exc:
            self.log.error("semgrep error: %s", exc)
            return

        try:
            data = json.loads(stdout.decode(errors="ignore"))
        except Exception:
            return

        findings = data.get("results", [])
        self.log.info("semgrep: %d findings", len(findings))

        for finding in findings:
            sev_key = finding.get("extra", {}).get("severity", "WARNING").upper()
            severity, cvss = SEVERITY_MAP.get(sev_key, (Severity.LOW, CVSS_LOW_SAST))
            meta = finding.get("extra", {}).get("metadata", {})
            path = finding.get("path", "")
            start_line = finding.get("start", {}).get("line", 0)

            ev = Evidence(
                request_raw=f"semgrep --config auto {src}",
                response_raw=json.dumps(finding, indent=2)[:500],
                extra={"file": path, "line": start_line, "rule": finding.get("check_id")},
            )
            self.new_finding(
                title=f"[semgrep] {finding.get('check_id', 'finding')}: {Path(path).name}:{start_line}",
                severity=severity,
                description=(
                    f"{finding.get('extra', {}).get('message', '')}\n\n"
                    f"File: {path}:{start_line}\n"
                    f"Rule: {finding.get('check_id', '')}\n"
                    f"References: {meta.get('references', [])}"
                ),
                reproduction_steps=[
                    f"Open {path}:{start_line}",
                    "Review flagged code pattern",
                ],
                remediation=meta.get("fix", "Review semgrep rule documentation for remediation."),
                references=meta.get("cwe", ["OWASP A06:2021"]),
                evidence=ev,
                cvss_v31_vector=cvss,
                target=target,
            )


class TestSourceAudit:
    def test_severity_map_complete(self) -> None:
        for key in ("HIGH", "MEDIUM", "LOW"):
            assert key in SEVERITY_MAP

    def test_cvss_vectors(self) -> None:
        for v in (CVSS_HIGH_SAST, CVSS_MED_SAST, CVSS_LOW_SAST):
            assert v.startswith("CVSS:3.1/")

    def test_phase(self) -> None:
        assert SourceAudit.PHASE == 11
