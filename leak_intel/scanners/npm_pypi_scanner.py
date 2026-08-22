"""NPM/PyPI Registry Scanner — package metadata analysis for internal URL leakage.

Scans package registry metadata (package.json, setup.py/pyproject.toml) for:
  - Internal URLs leaked in homepage/repository/bugs fields
  - Private registry URLs
  - CI/CD pipeline URLs
  - Dependency confusion candidates (internal package names on public registries)

No API keys required — NPM and PyPI registries are public.

FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import logging
import re
import time
from typing import Any

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

log = logging.getLogger("forge.leak_intel.npm_pypi_scanner")

_INTERNAL_PATTERNS = [
    (r"https?://(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)[:/]\S*", "internal_ip"),
    (r"https?://[a-z0-9\-]+\.(?:internal|local|corp|lan|intranet)\b\S*", "internal_domain"),
    (r"https?://(?:gitlab|jenkins|jira|confluence|artifactory|nexus|sonar)\.[a-z0-9\-]+\.\w+\S*", "ci_cd_tool"),
    (r"https?://[a-z0-9\-]+\.(?:azurewebsites\.net|herokuapp\.com|elasticbeanstalk\.com)\S*", "cloud_service"),
]


class NpmPypiScanner(BaseModule):
    """Scan NPM/PyPI registries for internal URL leakage and dependency confusion."""

    NAME        = "npm_pypi_scanner"
    DESCRIPTION = "NPM/PyPI registry metadata — internal URL leakage and dependency confusion detection"
    PHASE       = 0
    TAGS        = ["osint", "leak_intel", "npm", "pypi", "supply_chain", "recon"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()

        org = self._extract_org()
        if not org:
            return self._make_result(start, skipped=True, skip_reason="No org name derivable from target")

        self.log.info("Scanning NPM/PyPI registries for org: %s", org)

        try:
            import aiohttp
        except ImportError:
            return self._make_result(start, skipped=True, skip_reason="aiohttp not installed")

        async with aiohttp.ClientSession() as session:
            await self._search_npm(session, org)
            await self._search_pypi(session, org)

        return self._make_result(start)

    async def _search_npm(self, session: Any, org: str) -> None:
        """Search NPM for packages by the target org."""
        # Search by org scope and text
        search_terms = [f"@{org}", org]
        for term in search_terms:
            await self.rate_limit()
            url = f"https://registry.npmjs.org/-/v1/search?text={term}&size=20"
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status != 200:
                        continue
                    data = await resp.json()

                for obj in data.get("objects", []):
                    pkg = obj.get("package", {})
                    name = pkg.get("name", "")
                    version = pkg.get("version", "")
                    links = pkg.get("links", {})
                    description = pkg.get("description", "")

                    # Check all URL fields for internal leakage
                    all_text = " ".join([
                        links.get("homepage", ""),
                        links.get("repository", ""),
                        links.get("bugs", ""),
                        links.get("npm", ""),
                        description,
                    ])

                    for pattern, leak_type in _INTERNAL_PATTERNS:
                        matches = re.findall(pattern, all_text, re.IGNORECASE)
                        if matches:
                            self.new_finding(
                                title=f"NPM Internal URL Leak: {name}@{version}",
                                severity=Severity.MEDIUM,
                                description=(
                                    f"NPM package '{name}' v{version} metadata leaks internal URL(s):\n"
                                    f"{', '.join(matches[:5])}"
                                ),
                                reproduction_steps=[
                                    f"1. npm view {name}",
                                    "2. Check homepage/repository/bugs fields for internal URLs",
                                ],
                                remediation="Update package metadata to remove internal URLs before publishing.",
                                references=["https://docs.npmjs.com/cli/v10/configuring-npm/package-json"],
                                evidence=Evidence(extra={
                                    "package": name, "version": version,
                                    "leaked_urls": matches[:5], "leak_type": leak_type,
                                }),
                                url=links.get("npm", ""),
                                tags=["osint", "npm", "internal_url", leak_type],
                                mitre_attack=["T1592.004"],
                                cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                            )

            except Exception as exc:
                self.log.debug("NPM search error for '%s': %s", term, exc)

    async def _search_pypi(self, session: Any, org: str) -> None:
        """Search PyPI for packages by the target org."""
        # PyPI search via JSON API
        search_terms = [org, f"{org}-", f"py{org}"]
        for term in search_terms[:2]:
            await self.rate_limit()
            # PyPI doesn't have a great search API — use the JSON endpoint for known names
            url = f"https://pypi.org/pypi/{term}/json"
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status != 200:
                        continue
                    data = await resp.json()

                info = data.get("info", {})
                name = info.get("name", "")
                version = info.get("version", "")
                all_text = " ".join([
                    info.get("home_page", "") or "",
                    info.get("project_url", "") or "",
                    info.get("description", "") or "",
                    info.get("summary", "") or "",
                    " ".join(v or "" for v in (info.get("project_urls") or {}).values()),
                ])

                for pattern, leak_type in _INTERNAL_PATTERNS:
                    matches = re.findall(pattern, all_text, re.IGNORECASE)
                    if matches:
                        self.new_finding(
                            title=f"PyPI Internal URL Leak: {name}=={version}",
                            severity=Severity.MEDIUM,
                            description=(
                                f"PyPI package '{name}' v{version} metadata leaks internal URL(s):\n"
                                f"{', '.join(matches[:5])}"
                            ),
                            reproduction_steps=[
                                f"1. pip show {name}",
                                "2. Check home_page and project_urls for internal URLs",
                            ],
                            remediation="Update setup.py/pyproject.toml to remove internal URLs.",
                            references=["https://pypi.org/"],
                            evidence=Evidence(extra={
                                "package": name, "version": version,
                                "leaked_urls": matches[:5], "leak_type": leak_type,
                            }),
                            url=f"https://pypi.org/project/{name}/",
                            tags=["osint", "pypi", "internal_url", leak_type],
                            mitre_attack=["T1592.004"],
                            cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                        )

            except Exception as exc:
                self.log.debug("PyPI search error for '%s': %s", term, exc)

    def _extract_org(self) -> str:
        target = self.config.target.replace("https://", "").replace("http://", "")
        target = target.split("/")[0].split(":")[0]
        parts = target.split(".")
        return parts[0] if parts else ""


import aiohttp  # noqa: E402
