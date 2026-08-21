"""Contained whitebox dependency-manifest inventory for Gate 0."""
from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Any

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
from webforge.core.source_root import (
    SourceRootError,
    open_source_file,
    require_approved_source_root,
)


CVSS_VULN_DEP = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
CVSS40_VULN_DEP = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"

_MANIFEST_LIMITS = (
    ("requirements.txt", 10 * 1024 * 1024),
    ("Pipfile.lock", 10 * 1024 * 1024),
    ("pyproject.toml", 10 * 1024 * 1024),
    ("package-lock.json", 20 * 1024 * 1024),
    ("yarn.lock", 20 * 1024 * 1024),
    ("Gemfile.lock", 10 * 1024 * 1024),
)


def inventory_dependency_manifests(source_root: Path | str) -> int:
    """Count approved manifests through the no-follow source-root boundary."""
    root = require_approved_source_root(source_root)
    manifests = 0
    for name, limit in _MANIFEST_LIMITS:
        try:
            open_source_file(root, root / name, max_bytes=limit)
            manifests += 1
        except SourceRootError as exc:
            # Missing manifests are expected; a changed root authorization is
            # not.  Revalidate so replacement becomes an explicit module skip.
            require_approved_source_root(root)
            if str(exc) == "source entry is unavailable or unsafe":
                continue
            raise
    return manifests


class DepAudit(BaseModule):
    """Inventory only approved in-root manifests without spawning audit tools."""

    NAME = "dep_audit"
    DESCRIPTION = "Inventory dependency manifests inside the approved source root"
    PHASE = 11
    TAGS = ["whitebox", "dependencies", "cve", "supply-chain", "cwe-1395"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        try:
            source_root = require_approved_source_root(
                self.config.extra.get("source_root")
            )
        except SourceRootError as exc:
            return self._make_result(start, skipped=True, skip_reason=str(exc))

        try:
            manifests = inventory_dependency_manifests(source_root)
            # Do not report a complete inventory when the approved root was
            # replaced immediately after the final descriptor-safe read.
            require_approved_source_root(source_root)
        except SourceRootError as exc:
            return self._make_result(
                start,
                skipped=True,
                skip_reason=str(exc),
            )
        self.log.info(
            "Dependency manifest inventory complete: %d in-root file(s); "
            "external analyzers disabled at Gate 0",
            manifests,
        )
        return self._make_result(start)

    async def _audit_python(self, source_root: Path, target: str) -> None:
        del source_root, target

    async def _audit_node(self, source_root: Path, target: str) -> None:
        del source_root, target

    async def _audit_ruby(self, source_root: Path, target: str) -> None:
        del source_root, target

    def _parse_pip_audit(self, data: Any) -> list[dict[str, Any]]:
        vulns: list[dict[str, Any]] = []
        if isinstance(data, list):
            for item in data:
                if not isinstance(item, dict):
                    continue
                for vuln in item.get("vulns", []):
                    if not isinstance(vuln, dict):
                        continue
                    vulns.append({
                        "package": item.get("name", ""),
                        "version": item.get("version", ""),
                        "cve": vuln.get("id", ""),
                        "desc": str(vuln.get("description", ""))[:100],
                        "fix": vuln.get("fix_versions", []),
                    })
        return vulns

    def _parse_safety(self, data: Any) -> list[dict[str, Any]]:
        vulns: list[dict[str, Any]] = []
        for item in data if isinstance(data, list) else []:
            if isinstance(item, (list, tuple)) and len(item) >= 5:
                vulns.append({
                    "package": item[0],
                    "version": item[2],
                    "cve": item[4],
                    "desc": str(item[3])[:100],
                    "fix": [item[1]],
                })
        return vulns

    def _parse_npm_audit(self, data: Any) -> list[dict[str, Any]]:
        vulns: list[dict[str, Any]] = []
        advisories = data.get("advisories", {}) if isinstance(data, dict) else {}
        for advisory in advisories.values():
            if not isinstance(advisory, dict):
                continue
            findings = advisory.get("findings") or [{}]
            first = findings[0] if isinstance(findings, list) and findings else {}
            cves = advisory.get("cves") or []
            vulns.append({
                "package": advisory.get("module_name", ""),
                "version": str(first.get("version", "")) if isinstance(first, dict) else "",
                "cve": str(cves[0]) if cves else advisory.get("url", ""),
                "desc": str(advisory.get("title", ""))[:100],
                "severity": advisory.get("severity", "moderate"),
                "fix": [advisory.get("patched_versions", "")],
            })
        return vulns

    def _parse_bundler_audit(self, output: str) -> list[dict[str, Any]]:
        vulns: list[dict[str, Any]] = []
        for match in re.finditer(
            r"Name:\s+(.+)\nVersion:\s+(.+)\nAdvisory:\s+(.+)\n"
            r"Criticality:\s+(\w+)\nURL:\s+(.+)\nTitle:\s+(.+)",
            output,
            re.MULTILINE,
        ):
            vulns.append({
                "package": match.group(1).strip(),
                "version": match.group(2).strip(),
                "cve": match.group(3).strip(),
                "severity": match.group(4).strip(),
                "desc": match.group(6).strip()[:100],
                "fix": ["See advisory URL"],
            })
        return vulns

    async def _report_vulnerabilities(
        self,
        vulns: list[dict[str, Any]],
        target: str,
        tool: str,
    ) -> None:
        if not vulns:
            return
        critical = [
            vuln
            for vuln in vulns
            if str(vuln.get("severity", "")).lower() in {"critical", "high"}
        ]
        self.new_finding(
            title=f"Vulnerable Dependencies ({len(vulns)} found via {tool})",
            severity=Severity.HIGH if critical else Severity.MEDIUM,
            description=(
                f"{tool} found {len(vulns)} dependency issue(s); "
                "raw external analyzer output is not retained."
            ),
            reproduction_steps=["Review the approved in-root dependency manifest."],
            remediation="Update affected packages to supported patched versions.",
            references=["CWE-1395", "OWASP A06:2021"],
            evidence=Evidence(extra={"tool": tool, "total_vulns": len(vulns)}),
            cvss_v31_vector=CVSS_VULN_DEP,
            cvss_v40_vector=CVSS40_VULN_DEP,
            target=target,
        )


class TestDepAudit:
    def test_parse_pip_audit_empty(self) -> None:
        assert DepAudit.__new__(DepAudit)._parse_pip_audit([]) == []

    def test_parse_npm_empty(self) -> None:
        assert DepAudit.__new__(DepAudit)._parse_npm_audit({}) == []
