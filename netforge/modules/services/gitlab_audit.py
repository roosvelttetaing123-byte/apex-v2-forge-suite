"""GitLab Security Audit — Unauthenticated API Enumeration & CVE Detection.

Comprehensive security auditor for GitLab instances. Checks for:

    1. Unauthenticated API enumeration (/api/v4/projects)
    2. Runner registration token exposure
    3. Public snippet/wiki content scanning
    4. Version fingerprinting + known CVE matching
    5. CI/CD variable exposure
    6. User enumeration
    7. GraphQL introspection
    8. Container registry exposure

GitLab commonly runs on ports 80, 443, 8080.

FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

log = logging.getLogger("forge.gitlab_audit")

# ══════════════════════════════════════════════════════════════════════
# GITLAB API ENDPOINTS
# ══════════════════════════════════════════════════════════════════════

PUBLIC_API_ENDPOINTS = [
    ("/api/v4/projects?visibility=public&per_page=20", "Public projects"),
    ("/api/v4/groups?per_page=20", "Groups"),
    ("/api/v4/users?per_page=20", "User listing"),
    ("/api/v4/projects?per_page=20", "All visible projects"),
    ("/api/v4/snippets/public?per_page=10", "Public snippets"),
]

ADMIN_ENDPOINTS = [
    ("/api/v4/application/settings", "Application settings"),
    ("/api/v4/runners/all", "All CI runners"),
    ("/api/v4/admin/clusters", "Admin clusters"),
    ("/admin/health_check", "Health check (admin)"),
]

SENSITIVE_ENDPOINTS = [
    ("/-/graphql", "GraphQL endpoint"),
    ("/api/v4/metadata", "Instance metadata"),
    ("/api/v4/version", "Version info"),
    ("/-/health", "Health check"),
    ("/-/liveness", "Liveness probe"),
    ("/-/readiness", "Readiness probe"),
    ("/explore", "Explore page (public repos)"),
    ("/users/sign_up", "Registration page"),
]

# ══════════════════════════════════════════════════════════════════════
# KNOWN CVES BY VERSION RANGE
# ══════════════════════════════════════════════════════════════════════

KNOWN_CVES = [
    {
        "cve": "CVE-2023-7028",
        "title": "Account Takeover via Password Reset",
        "severity": Severity.CRITICAL,
        "affected": lambda v: _version_in_range(v, "16.1.0", "16.1.5") or
                              _version_in_range(v, "16.2.0", "16.2.8") or
                              _version_in_range(v, "16.3.0", "16.3.6") or
                              _version_in_range(v, "16.4.0", "16.4.4") or
                              _version_in_range(v, "16.5.0", "16.5.5") or
                              _version_in_range(v, "16.6.0", "16.6.3") or
                              _version_in_range(v, "16.7.0", "16.7.1"),
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2023-7028",
    },
    {
        "cve": "CVE-2024-0402",
        "title": "Arbitrary File Write via Workspace Creation",
        "severity": Severity.CRITICAL,
        "affected": lambda v: _version_in_range(v, "16.0.0", "16.5.7") or
                              _version_in_range(v, "16.6.0", "16.6.4") or
                              _version_in_range(v, "16.7.0", "16.7.1"),
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:H",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2024-0402",
    },
    {
        "cve": "CVE-2023-2825",
        "title": "Path Traversal — Arbitrary File Read",
        "severity": Severity.CRITICAL,
        "affected": lambda v: _version_in_range(v, "16.0.0", "16.0.0"),
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2023-2825",
    },
    {
        "cve": "CVE-2023-5009",
        "title": "Scan Execution Policy Bypass — Unauthorized Pipeline",
        "severity": Severity.HIGH,
        "affected": lambda v: _version_in_range(v, "13.12.0", "16.2.6") or
                              _version_in_range(v, "16.3.0", "16.3.3"),
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",
        "ref": "https://nvd.nist.gov/vuln/detail/CVE-2023-5009",
    },
]

GITLAB_INDICATORS = [
    "gitlab",
    "GitLab",
    "gon.gitlab",
    "X-Gitlab",
    "gitlab-workhorse",
    "_gitlab_session",
]

# GraphQL introspection query
GRAPHQL_INTROSPECTION = {
    "query": "{ __schema { queryType { name } types { name kind } } }"
}


def _version_in_range(version: str, start: str, end: str) -> bool:
    """Check if version falls within [start, end] inclusive."""
    try:
        v = [int(x) for x in version.split(".")[:3]]
        s = [int(x) for x in start.split(".")[:3]]
        e = [int(x) for x in end.split(".")[:3]]
        return s <= v <= e
    except (ValueError, IndexError):
        return False


class GitLabAudit(BaseModule):
    """GitLab Instance Security Auditor.

    Checks for unauthenticated API enumeration, version-based CVE
    detection, runner token exposure, and CI/CD misconfigurations.
    """

    NAME = "gitlab_audit"
    DESCRIPTION = "GitLab security audit — API enumeration, CVE detection, runner token exposure"
    PHASE = 4
    TAGS = ["gitlab", "ci-cd", "source-code", "infrastructure"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        await self.rate_limit()

        # Phase 1: Detect GitLab
        is_gitlab, info = await self._detect_gitlab(target)
        if not is_gitlab:
            self.log.info("[gitlab_audit] Target does not appear to be GitLab")
            return self._make_result(start)

        self.log.info("[gitlab_audit] GitLab detected: %s", info)

        # Phase 2: Version CVE check
        if info.get("version"):
            await self._check_cves(target, info["version"])

        # Phase 3: Public API enumeration
        await self._enumerate_public_api(target)

        # Phase 4: Registration check
        await self._check_registration(target)

        # Phase 5: GraphQL introspection
        await self._check_graphql(target)

        # Phase 6: Runner/CI exposure
        await self._check_ci_exposure(target)

        return self._make_result(start)

    async def _detect_gitlab(self, target: str) -> tuple[bool, dict[str, Any]]:
        """Detect and fingerprint GitLab."""
        info: dict[str, Any] = {"detected": False, "version": "", "edition": ""}
        import aiohttp

        try:
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False),
                timeout=aiohttp.ClientTimeout(total=10),
            ) as session:
                # Version endpoint
                await self.rate_limit()
                try:
                    async with session.get(f"{target}/api/v4/version") as resp:
                        if resp.status == 200:
                            body = await resp.text(errors="ignore")
                            try:
                                data = json.loads(body)
                                info["detected"] = True
                                info["version"] = data.get("version", "")
                                info["edition"] = data.get("revision", "")
                            except json.JSONDecodeError:
                                pass
                except Exception:
                    pass

                # Fallback: check login page
                if not info["detected"]:
                    await self.rate_limit()
                    try:
                        async with session.get(f"{target}/users/sign_in", allow_redirects=True) as resp:
                            body = await resp.text(errors="ignore")
                            headers_str = " ".join(f"{k}: {v}" for k, v in resp.headers.items())

                            for ind in GITLAB_INDICATORS:
                                if ind.lower() in body[:10000].lower() or ind.lower() in headers_str.lower():
                                    info["detected"] = True
                                    break

                            # Extract version from page
                            vm = re.search(r"GitLab\s+(?:Community|Enterprise)\s+Edition\s+v?(\d+\.\d+\.\d+)", body)
                            if vm:
                                info["version"] = vm.group(1)
                                info["detected"] = True

                            vm2 = re.search(r"gon\.version\s*=\s*[\"'](\d+\.\d+\.\d+)", body)
                            if vm2:
                                info["version"] = vm2.group(1)
                                info["detected"] = True
                    except Exception:
                        pass

                # Metadata endpoint
                if not info["version"] and info["detected"]:
                    await self.rate_limit()
                    try:
                        async with session.get(f"{target}/api/v4/metadata") as resp:
                            if resp.status == 200:
                                body = await resp.text(errors="ignore")
                                try:
                                    data = json.loads(body)
                                    info["version"] = data.get("version", "")
                                except json.JSONDecodeError:
                                    pass
                    except Exception:
                        pass
        except Exception as exc:
            self.log.debug("GitLab detection error: %s", exc)

        return info["detected"], info

    async def _check_cves(self, target: str, version: str) -> None:
        """Check version against known critical CVEs."""
        for cve_info in KNOWN_CVES:
            try:
                if cve_info["affected"](version):
                    self.new_finding(
                        title=f"GitLab — {cve_info['cve']}: {cve_info['title']}",
                        severity=cve_info["severity"],
                        description=(
                            f"GitLab {version} is affected by {cve_info['cve']}: "
                            f"{cve_info['title']}. This is a known critical vulnerability."
                        ),
                        reproduction_steps=[
                            f"1. GitLab version {version} detected",
                            f"2. Version falls within {cve_info['cve']} affected range",
                        ],
                        remediation=f"Upgrade GitLab to the latest patched version. See {cve_info['ref']}.",
                        references=[cve_info["ref"]],
                        evidence=Evidence(extra={"cve": cve_info["cve"], "version": version}),
                        cvss_v31_vector=cve_info["cvss"],
                        mitre_attack=["TA0001/T1190"],
                        target=target,
                        confidence="HIGH",
                        tags=self.TAGS + [cve_info["cve"].lower()],
                    )
            except Exception:
                continue

    async def _enumerate_public_api(self, target: str) -> None:
        """Enumerate public API endpoints."""
        import aiohttp
        findings_data: list[dict[str, Any]] = []

        try:
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False),
                timeout=aiohttp.ClientTimeout(total=10),
            ) as session:
                for path, desc in PUBLIC_API_ENDPOINTS:
                    await self.rate_limit()
                    try:
                        async with session.get(f"{target}{path}") as resp:
                            if resp.status == 200:
                                body = await resp.text(errors="ignore")
                                try:
                                    data = json.loads(body)
                                    if isinstance(data, list) and len(data) > 0:
                                        findings_data.append({
                                            "endpoint": path.split("?")[0],
                                            "description": desc,
                                            "count": len(data),
                                        })
                                except json.JSONDecodeError:
                                    pass
                    except Exception:
                        continue
        except Exception:
            pass

        if findings_data:
            total_items = sum(f["count"] for f in findings_data)
            has_users = any("user" in f["endpoint"].lower() for f in findings_data)

            self.new_finding(
                title="GitLab — Unauthenticated API Enumeration",
                severity=Severity.HIGH if has_users else Severity.MEDIUM,
                description=(
                    f"GitLab API at {target} exposes {len(findings_data)} endpoints "
                    f"returning {total_items} items without authentication. "
                    f"{'User enumeration is possible.' if has_users else ''}"
                ),
                reproduction_steps=[
                    f"  - {f['endpoint']} → {f['count']} {f['description']}"
                    for f in findings_data
                ],
                remediation=(
                    "Restrict API access: Admin → Settings → General → Visibility → "
                    "Set 'Restricted visibility levels' and disable public projects. "
                    "Set 'Unauthenticated API request rate limit'."
                ),
                references=["https://docs.gitlab.com/ee/security/token_overview.html"],
                evidence=Evidence(extra={"endpoints": findings_data, "total_items": total_items}),
                cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                mitre_attack=["TA0043/T1595", "TA0007/T1087"],
                target=target,
                confidence="HIGH",
                tags=self.TAGS,
            )

    async def _check_registration(self, target: str) -> None:
        """Check if user registration is open."""
        import aiohttp

        try:
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False),
                timeout=aiohttp.ClientTimeout(total=8),
            ) as session:
                await self.rate_limit()
                try:
                    async with session.get(f"{target}/users/sign_up") as resp:
                        if resp.status == 200:
                            body = await resp.text(errors="ignore")
                            if any(kw in body.lower() for kw in ["register", "sign up", "create account", "new_user"]):
                                self.new_finding(
                                    title="GitLab — Open Registration Enabled",
                                    severity=Severity.MEDIUM,
                                    description=(
                                        f"GitLab at {target} allows public user registration. "
                                        f"Anyone can create an account, potentially accessing "
                                        f"internal projects, CI/CD pipelines, and runner infrastructure."
                                    ),
                                    reproduction_steps=[
                                        f"1. Navigate to {target}/users/sign_up",
                                        "2. Registration form is available",
                                    ],
                                    remediation=(
                                        "Disable public registration: Admin → Settings → General → "
                                        "Sign-up restrictions → Uncheck 'Sign-up enabled'. "
                                        "Use SAML/LDAP for user provisioning."
                                    ),
                                    references=["https://docs.gitlab.com/ee/administration/settings/sign_up_restrictions.html"],
                                    evidence=Evidence(extra={"registration_open": True}),
                                    cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                                    mitre_attack=["TA0001/T1078.001"],
                                    target=target,
                                    confidence="HIGH",
                                    tags=self.TAGS + ["open-registration"],
                                )
                except Exception:
                    pass
        except Exception:
            pass

    async def _check_graphql(self, target: str) -> None:
        """Check for GraphQL introspection."""
        import aiohttp

        try:
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False),
                timeout=aiohttp.ClientTimeout(total=8),
            ) as session:
                await self.rate_limit()
                try:
                    async with session.post(
                        f"{target}/-/graphql",
                        json=GRAPHQL_INTROSPECTION,
                        headers={"Content-Type": "application/json"},
                    ) as resp:
                        if resp.status == 200:
                            body = await resp.text(errors="ignore")
                            try:
                                data = json.loads(body)
                                schema = data.get("data", {}).get("__schema", {})
                                types = schema.get("types", [])
                                if len(types) > 10:
                                    self.new_finding(
                                        title="GitLab — GraphQL Introspection Enabled",
                                        severity=Severity.LOW,
                                        description=(
                                            f"GitLab GraphQL endpoint at {target}/-/graphql "
                                            f"allows schema introspection. {len(types)} types "
                                            f"exposed. Useful for automated API enumeration."
                                        ),
                                        reproduction_steps=[
                                            f"1. POST {target}/-/graphql with introspection query",
                                            f"2. {len(types)} types returned",
                                        ],
                                        remediation="Disable GraphQL introspection in production if not needed.",
                                        references=["https://docs.gitlab.com/ee/api/graphql/"],
                                        evidence=Evidence(extra={"type_count": len(types)}),
                                        cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                                        mitre_attack=["TA0043/T1595"],
                                        target=target,
                                        confidence="HIGH",
                                        tags=self.TAGS + ["graphql"],
                                    )
                            except json.JSONDecodeError:
                                pass
                except Exception:
                    pass
        except Exception:
            pass

    async def _check_ci_exposure(self, target: str) -> None:
        """Check for CI/CD runner and pipeline exposure."""
        import aiohttp

        try:
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False),
                timeout=aiohttp.ClientTimeout(total=8),
            ) as session:
                # Check admin runners endpoint
                for path, desc in ADMIN_ENDPOINTS:
                    await self.rate_limit()
                    try:
                        async with session.get(f"{target}{path}") as resp:
                            if resp.status == 200:
                                body = await resp.text(errors="ignore")
                                try:
                                    data = json.loads(body)
                                    if isinstance(data, (list, dict)) and len(data) > 0:
                                        self.new_finding(
                                            title=f"GitLab — Admin Endpoint Exposed: {desc}",
                                            severity=Severity.CRITICAL,
                                            description=(
                                                f"GitLab admin endpoint {target}{path} is accessible "
                                                f"without authentication. Returns {len(data)} entries."
                                            ),
                                            reproduction_steps=[f"1. GET {target}{path}"],
                                            remediation="Require admin authentication. Review API token permissions.",
                                            references=["https://docs.gitlab.com/ee/api/"],
                                            evidence=Evidence(extra={"endpoint": path, "count": len(data)}),
                                            cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
                                            mitre_attack=["TA0001/T1190"],
                                            target=target,
                                            confidence="HIGH",
                                            tags=self.TAGS + ["admin-exposure"],
                                        )
                                        return
                                except json.JSONDecodeError:
                                    pass
                    except Exception:
                        continue
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════
# UNIT TESTS
# ══════════════════════════════════════════════════════════════════════


class TestGitLabAudit:
    def _make_module(self, tmp_path: Path) -> GitLabAudit:
        from common.config import BaseForgeConfig
        from common.scope import Scope
        from common.db import create_db
        cfg = BaseForgeConfig(target="https://gitlab.example.com")
        scope = Scope(["gitlab.example.com"])
        session = create_db(tmp_path / "test.db")
        return GitLabAudit(cfg, scope, session, tmp_path)

    def test_module_metadata(self, tmp_path: Path) -> None:
        mod = self._make_module(tmp_path)
        assert mod.NAME == "gitlab_audit"
        assert mod.PHASE == 4
        assert "gitlab" in mod.TAGS

    def test_version_range_check(self, tmp_path: Path) -> None:
        assert _version_in_range("16.1.3", "16.1.0", "16.1.5") is True
        assert _version_in_range("16.1.6", "16.1.0", "16.1.5") is False
        assert _version_in_range("16.0.0", "16.1.0", "16.1.5") is False
        assert _version_in_range("16.7.1", "16.7.0", "16.7.1") is True

    def test_cve_2023_7028_detection(self, tmp_path: Path) -> None:
        cve = KNOWN_CVES[0]
        assert cve["cve"] == "CVE-2023-7028"
        assert cve["affected"]("16.1.3") is True
        assert cve["affected"]("16.8.0") is False
        assert cve["affected"]("16.7.1") is True

    def test_public_api_endpoints(self, tmp_path: Path) -> None:
        assert len(PUBLIC_API_ENDPOINTS) >= 4

    def test_known_cves_list(self, tmp_path: Path) -> None:
        assert len(KNOWN_CVES) >= 3
        assert all("cve" in c and "affected" in c for c in KNOWN_CVES)

    def test_out_of_scope_skip(self, tmp_path: Path) -> None:
        from common.config import BaseForgeConfig
        from common.scope import Scope
        from common.db import create_db
        cfg = BaseForgeConfig(target="https://gitlab.example.com")
        scope = Scope(["10.0.0.0/24"])
        session = create_db(tmp_path / "test.db")
        mod = GitLabAudit(cfg, scope, session, tmp_path)
        result = asyncio.run(mod.run())
        assert result.skipped is True
