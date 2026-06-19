"""Dependency auditor — scan for known vulnerable packages."""
from __future__ import annotations

import asyncio
import json
import re
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_VULN_DEP = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
CVSS40_VULN_DEP = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
class DepAudit(BaseModule):
    """Dependency vulnerability auditor."""

    NAME        = "dep_audit"
    DESCRIPTION = "Audit project dependencies for known CVEs using pip-audit, npm audit, etc."
    PHASE       = 11
    TAGS        = ["whitebox", "dependencies", "cve", "supply-chain", "cwe-1395"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        source_dir = Path(self.config.extra.get("source_dir", "."))
        target = self.config.target

        if not source_dir.exists():
            return self._make_result(start, skipped=True, skip_reason="no source directory")

        self.log.info("Auditing dependencies in %s", source_dir)

        await asyncio.gather(
            self._audit_python(source_dir, target),
            self._audit_node(source_dir, target),
            self._audit_ruby(source_dir, target),
        )
        return self._make_result(start)

    async def _audit_python(self, source_dir: Path, target: str) -> None:
        """Run pip-audit or safety on Python requirements."""
        import shutil
        for req_file in ["requirements.txt", "Pipfile.lock", "pyproject.toml"]:
            req_path = source_dir / req_file
            if not req_path.exists():
                continue

            for tool in ["pip-audit", "safety"]:
                cmd_path = shutil.which(tool)
                if not cmd_path:
                    continue

                try:
                    loop = asyncio.get_event_loop()
                    args = (
                        [cmd_path, "-r", str(req_path), "--output", "json"]
                        if tool == "pip-audit"
                        else [cmd_path, "check", "-r", str(req_path), "--json"]
                    )
                    proc = await asyncio.create_subprocess_exec(
                        *args,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                        cwd=str(source_dir),
                    )
                    stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
                    data = json.loads(stdout.decode())

                    vulns = self._parse_pip_audit(data) if tool == "pip-audit" else self._parse_safety(data)
                    await self._report_vulnerabilities(vulns, target, tool)
                except Exception as exc:
                    self.log.debug("%s failed: %s", tool, exc)
            break  # Only process first found req file

    async def _audit_node(self, source_dir: Path, target: str) -> None:
        """Run npm audit on Node.js projects."""
        import shutil
        pkg_json = source_dir / "package-lock.json"
        if not pkg_json.exists():
            pkg_json = source_dir / "yarn.lock"
        if not pkg_json.exists():
            return

        npm = shutil.which("npm")
        if not npm:
            return

        try:
            proc = await asyncio.create_subprocess_exec(
                npm, "audit", "--json",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(source_dir),
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
            data = json.loads(stdout.decode())
            vulns = self._parse_npm_audit(data)
            await self._report_vulnerabilities(vulns, target, "npm audit")
        except Exception as exc:
            self.log.debug("npm audit failed: %s", exc)

    async def _audit_ruby(self, source_dir: Path, target: str) -> None:
        """Run bundler-audit on Ruby projects."""
        import shutil
        gemfile = source_dir / "Gemfile.lock"
        if not gemfile.exists():
            return

        bundler_audit = shutil.which("bundler-audit") or shutil.which("bundle-audit")
        if not bundler_audit:
            return

        try:
            proc = await asyncio.create_subprocess_exec(
                bundler_audit, "check", "--format", "json",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(source_dir),
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
            vulns = self._parse_bundler_audit(stdout.decode())
            await self._report_vulnerabilities(vulns, target, "bundler-audit")
        except Exception:
            pass

    def _parse_pip_audit(self, data) -> list[dict]:
        vulns = []
        if isinstance(data, list):
            for item in data:
                pkg = item.get("name", "")
                version = item.get("version", "")
                for vuln in item.get("vulns", []):
                    vulns.append({
                        "package":    pkg,
                        "version":    version,
                        "cve":        vuln.get("id", ""),
                        "desc":       vuln.get("description", "")[:100],
                        "fix":        vuln.get("fix_versions", []),
                    })
        return vulns

    def _parse_safety(self, data) -> list[dict]:
        vulns = []
        for item in data if isinstance(data, list) else []:
            if len(item) >= 5:
                vulns.append({
                    "package":  item[0],
                    "version":  item[2],
                    "cve":      item[4],
                    "desc":     item[3][:100],
                    "fix":      [item[1]],
                })
        return vulns

    def _parse_npm_audit(self, data) -> list[dict]:
        vulns = []
        advisories = data.get("advisories", {}) if isinstance(data, dict) else {}
        for adv_id, adv in advisories.items():
            vulns.append({
                "package":  adv.get("module_name", ""),
                "version":  str(adv.get("findings", [{}])[0].get("version", "")),
                "cve":      str(adv.get("cves", [""])[0]) if adv.get("cves") else adv.get("url", ""),
                "desc":     adv.get("title", "")[:100],
                "severity": adv.get("severity", "moderate"),
                "fix":      [adv.get("patched_versions", "")],
            })
        return vulns

    def _parse_bundler_audit(self, output: str) -> list[dict]:
        vulns = []
        for m in re.finditer(
            r"Name:\s+(.+)\nVersion:\s+(.+)\nAdvisory:\s+(.+)\nCriticality:\s+(\w+)\nURL:\s+(.+)\nTitle:\s+(.+)",
            output, re.MULTILINE
        ):
            vulns.append({
                "package":  m.group(1).strip(),
                "version":  m.group(2).strip(),
                "cve":      m.group(3).strip(),
                "severity": m.group(4).strip(),
                "desc":     m.group(6).strip()[:100],
                "fix":      ["See advisory URL"],
            })
        return vulns

    async def _report_vulnerabilities(
        self, vulns: list[dict], target: str, tool: str
    ) -> None:
        if not vulns:
            return

        # Group by severity
        critical = [v for v in vulns if "critical" in str(v.get("severity", "")).lower() or
                    any(cve in v.get("cve", "") for cve in ["CVE-2021", "CVE-2022", "CVE-2023"])]

        ev = Evidence(
            extra={
                "tool":          tool,
                "total_vulns":   len(vulns),
                "vulnerabilities": vulns[:10],
            }
        )
        self.new_finding(
            title=f"Vulnerable Dependencies ({len(vulns)} found via {tool})",
            severity=Severity.HIGH if critical else Severity.MEDIUM,
            description=(
                f"{tool} found {len(vulns)} vulnerability(ies) in project dependencies. "
                f"Critical issues: {len(critical)}. "
                f"Packages: {', '.join(set(v.get('package','?') for v in vulns[:5]))}"
            ),
            reproduction_steps=[
                f"Run: {tool}",
                f"Vulnerabilities: {[v.get('cve','?') for v in vulns[:5]]}",
            ],
            remediation=(
                "Update vulnerable packages to patched versions. "
                "Run dependency audits in CI/CD pipeline. "
                "Consider using a software composition analysis (SCA) tool."
            ),
            references=["CWE-1395", "OWASP A06:2021"] + [v.get("cve", "") for v in vulns[:5] if v.get("cve")],
            evidence=ev,
            cvss_v31_vector=CVSS_VULN_DEP,
            cvss_v40_vector=CVSS40_VULN_DEP,
            target=target,
        )


class TestDepAudit:
    def test_parse_pip_audit_empty(self) -> None:
        mod = DepAudit.__new__(DepAudit)
        result = mod._parse_pip_audit([])
        assert result == []

    def test_parse_npm_empty(self) -> None:
        mod = DepAudit.__new__(DepAudit)
        result = mod._parse_npm_audit({})
        assert result == []
