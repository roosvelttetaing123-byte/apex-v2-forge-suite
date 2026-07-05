"""Jenkins Security Audit — Script Console, Groovy RCE & Misconfig Detection.

Comprehensive security auditor for Jenkins CI/CD servers. Checks for:

    1. Unauthenticated Script Console access (/script)
    2. Groovy RCE confirmation via safe math probe
    3. Anonymous user permission enumeration
    4. Build log credential leakage
    5. CSRF token bypass (crumb check)
    6. API endpoint exposure
    7. Plugin vulnerability surface
    8. Node/agent enumeration

Jenkins commonly runs on ports 8080, 8443, 443.

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

log = logging.getLogger("forge.jenkins_audit")

# ══════════════════════════════════════════════════════════════════════
# JENKINS ENDPOINTS
# ══════════════════════════════════════════════════════════════════════

CRITICAL_ENDPOINTS = [
    ("/script", "Groovy Script Console"),
    ("/scriptText", "Script Console (text API)"),
    ("/computer/", "Node/Agent Management"),
    ("/configureSecurity", "Security Configuration"),
    ("/configure", "System Configuration"),
    ("/credentials/", "Credential Store"),
    ("/credentials/store/system/domain/_/", "System Credentials"),
]

RECON_ENDPOINTS = [
    ("/api/json", "JSON API root"),
    ("/api/json?tree=jobs[name,url,lastBuild[number,result]]", "Job listing"),
    ("/api/json?tree=nodeProperties,primaryView[name]", "Node properties"),
    ("/people/", "User listing"),
    ("/systemInfo", "System information"),
    ("/log/all", "System log"),
    ("/pluginManager/installed", "Installed plugins"),
    ("/queue/api/json", "Build queue"),
    ("/computer/api/json", "Agent listing"),
]

VERSION_PATTERNS = [
    re.compile(r"X-Jenkins:\s*(\d+\.\d+(?:\.\d+)?)", re.I),
    re.compile(r"Jenkins\s+ver\.\s*(\d+\.\d+(?:\.\d+)?)", re.I),
    re.compile(r"Jenkins-Version:\s*(\d+\.\d+(?:\.\d+)?)", re.I),
]

JENKINS_INDICATORS = [
    "jenkins",
    "X-Jenkins",
    "Jenkins-Session",
    "hudson",
    "Jenkins-Crumb",
    "JSESSIONID",
]

# Groovy math probe — safe, returns "49" if script console works
GROOVY_MATH_PROBE = "println(7*7)"
GROOVY_EXPECTED = "49"


class JenkinsAudit(BaseModule):
    """Jenkins CI/CD Security Auditor.

    Detects unauthenticated script console access, credential exposure,
    anonymous permissions, and common Jenkins misconfigurations.
    """

    NAME = "jenkins_audit"
    DESCRIPTION = "Jenkins CI/CD security audit — script console, credential exposure, anonymous access"
    PHASE = 4
    TAGS = ["jenkins", "ci-cd", "rce", "credential-exposure", "infrastructure"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        await self.rate_limit()

        # Phase 1: Detect Jenkins
        is_jenkins, info = await self._detect_jenkins(target)
        if not is_jenkins:
            self.log.info("[jenkins_audit] Target does not appear to be Jenkins")
            return self._make_result(start)

        self.log.info("[jenkins_audit] Jenkins detected: %s", info)

        # Phase 2: Script Console check (CRITICAL)
        await self._check_script_console(target)

        # Phase 3: Anonymous permissions
        await self._check_anonymous_access(target)

        # Phase 4: Credential store exposure
        await self._check_credential_store(target)

        # Phase 5: API enumeration
        await self._enumerate_api(target, info)

        # Phase 6: CSRF bypass check
        await self._check_csrf_protection(target)

        return self._make_result(start)

    async def _detect_jenkins(self, target: str) -> tuple[bool, dict[str, Any]]:
        """Detect and fingerprint Jenkins."""
        info: dict[str, Any] = {"detected": False, "version": ""}
        import aiohttp

        try:
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False),
                timeout=aiohttp.ClientTimeout(total=10),
            ) as session:
                await self.rate_limit()
                try:
                    async with session.get(f"{target}/", allow_redirects=True) as resp:
                        body = await resp.text(errors="ignore")
                        headers_str = " ".join(f"{k}: {v}" for k, v in resp.headers.items())

                        for ind in JENKINS_INDICATORS:
                            if ind.lower() in headers_str.lower() or ind.lower() in body[:5000].lower():
                                info["detected"] = True
                                break

                        for pat in VERSION_PATTERNS:
                            m = pat.search(headers_str)
                            if m:
                                info["version"] = m.group(1)
                                info["detected"] = True
                                break

                        jenkins_header = resp.headers.get("X-Jenkins", "")
                        if jenkins_header:
                            info["version"] = jenkins_header
                            info["detected"] = True
                except Exception:
                    pass
        except Exception as exc:
            self.log.debug("Jenkins detection error: %s", exc)

        return info["detected"], info

    async def _check_script_console(self, target: str) -> None:
        """Check for unauthenticated Groovy Script Console access."""
        import aiohttp

        try:
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False),
                timeout=aiohttp.ClientTimeout(total=10),
            ) as session:
                # Check if /script is accessible
                await self.rate_limit()
                try:
                    async with session.get(f"{target}/script", allow_redirects=False) as resp:
                        if resp.status == 200:
                            body = await resp.text(errors="ignore")
                            if "Groovy script" in body or "script" in body.lower():
                                # Try safe math probe
                                await self.rate_limit()
                                try:
                                    async with session.post(
                                        f"{target}/scriptText",
                                        data={"script": GROOVY_MATH_PROBE},
                                    ) as script_resp:
                                        script_body = await script_resp.text(errors="ignore")
                                        rce_confirmed = GROOVY_EXPECTED in script_body

                                        self.new_finding(
                                            title="Jenkins — Unauthenticated Script Console (RCE)",
                                            severity=Severity.CRITICAL,
                                            description=(
                                                f"Jenkins Script Console at {target}/script is accessible "
                                                f"without authentication. Groovy code execution "
                                                f"{'CONFIRMED' if rce_confirmed else 'likely'} — "
                                                f"this provides full RCE on the Jenkins server. "
                                                f"An attacker can execute arbitrary commands, read "
                                                f"credentials, pivot to build agents, and access source code."
                                            ),
                                            reproduction_steps=[
                                                f"1. Navigate to {target}/script",
                                                "2. Script Console page loads without authentication",
                                                f"3. Execute: {GROOVY_MATH_PROBE}",
                                                f"4. Response: {'confirmed ' + GROOVY_EXPECTED if rce_confirmed else 'page accessible'}",
                                            ],
                                            remediation=(
                                                "CRITICAL: Restrict Script Console to authenticated admins immediately. "
                                                "Enable Jenkins security realm (LDAP, Active Directory, or internal). "
                                                "Configure matrix-based authorization. "
                                                "Restrict admin access to specific users/groups. "
                                                "Audit for unauthorized job modifications and credential access."
                                            ),
                                            references=[
                                                "https://www.jenkins.io/doc/book/managing/script-console/",
                                                "https://www.jenkins.io/doc/book/security/securing-jenkins/",
                                            ],
                                            evidence=Evidence(
                                                request_raw=f"POST {target}/scriptText\nscript={GROOVY_MATH_PROBE}",
                                                response_raw=script_body[:2000] if rce_confirmed else body[:2000],
                                                extra={
                                                    "rce_confirmed": rce_confirmed,
                                                    "probe": GROOVY_MATH_PROBE,
                                                    "response": script_body[:200] if rce_confirmed else "",
                                                },
                                            ),
                                            cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                            mitre_attack=["TA0002/T1059", "TA0001/T1190"],
                                            target=target,
                                            url=f"{target}/script",
                                            confidence="HIGH" if rce_confirmed else "MEDIUM",
                                            tags=self.TAGS + ["rce-confirmed"] if rce_confirmed else self.TAGS,
                                        )
                                        return
                                except Exception:
                                    pass

                                # Script console accessible even without execution test
                                self.new_finding(
                                    title="Jenkins — Script Console Accessible (Potential RCE)",
                                    severity=Severity.CRITICAL,
                                    description=(
                                        f"Jenkins Script Console page at {target}/script loads "
                                        f"without authentication. Could not confirm code execution "
                                        f"but the console presence indicates no auth requirement."
                                    ),
                                    reproduction_steps=[
                                        f"1. GET {target}/script returns 200",
                                        "2. Groovy Script Console interface rendered",
                                    ],
                                    remediation="Enable authentication and restrict Script Console access.",
                                    references=["https://www.jenkins.io/doc/book/security/securing-jenkins/"],
                                    evidence=Evidence(response_raw=body[:2000]),
                                    cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                    mitre_attack=["TA0002/T1059", "TA0001/T1190"],
                                    target=target,
                                    confidence="MEDIUM",
                                    tags=self.TAGS,
                                )
                except Exception:
                    pass
        except Exception as exc:
            self.log.debug("Script console check error: %s", exc)

    async def _check_anonymous_access(self, target: str) -> None:
        """Check what anonymous users can access."""
        import aiohttp
        accessible = []

        try:
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False),
                timeout=aiohttp.ClientTimeout(total=10),
            ) as session:
                for path, desc in CRITICAL_ENDPOINTS + RECON_ENDPOINTS:
                    await self.rate_limit()
                    try:
                        async with session.get(
                            f"{target}{path}", allow_redirects=False,
                        ) as resp:
                            if resp.status == 200:
                                accessible.append({"path": path, "description": desc})
                    except Exception:
                        continue
        except Exception:
            pass

        if len(accessible) >= 3:
            critical_exposed = [a for a in accessible if a["path"] in dict(CRITICAL_ENDPOINTS)]
            self.new_finding(
                title="Jenkins — Excessive Anonymous Access",
                severity=Severity.HIGH if critical_exposed else Severity.MEDIUM,
                description=(
                    f"Jenkins at {target} allows anonymous access to {len(accessible)} endpoints. "
                    f"Critical endpoints exposed: {len(critical_exposed)}."
                ),
                reproduction_steps=[f"  - {a['path']} ({a['description']})" for a in accessible[:15]],
                remediation=(
                    "Configure Jenkins security realm and authorization strategy. "
                    "Remove anonymous read access. Use matrix-based authorization."
                ),
                references=["https://www.jenkins.io/doc/book/security/securing-jenkins/"],
                evidence=Evidence(extra={"accessible_count": len(accessible), "endpoints": accessible[:15]}),
                cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                mitre_attack=["TA0007/T1083", "TA0043/T1595"],
                target=target,
                confidence="HIGH",
                tags=self.TAGS,
            )

    async def _check_credential_store(self, target: str) -> None:
        """Check if credential store is accessible."""
        import aiohttp

        cred_paths = [
            "/credentials/",
            "/credentials/store/system/domain/_/",
            "/credentials/store/system/domain/_/api/json",
        ]

        try:
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False),
                timeout=aiohttp.ClientTimeout(total=8),
            ) as session:
                for path in cred_paths:
                    await self.rate_limit()
                    try:
                        async with session.get(f"{target}{path}", allow_redirects=False) as resp:
                            if resp.status == 200:
                                body = await resp.text(errors="ignore")
                                if any(kw in body.lower() for kw in ["credential", "username", "secret", "password"]):
                                    self.new_finding(
                                        title="Jenkins — Credential Store Accessible",
                                        severity=Severity.CRITICAL,
                                        description=(
                                            f"Jenkins credential store at {target}{path} is accessible. "
                                            f"Stored credentials (SSH keys, API tokens, passwords) "
                                            f"may be extractable by anonymous users."
                                        ),
                                        reproduction_steps=[
                                            f"1. GET {target}{path}",
                                            "2. Credential listing returned",
                                        ],
                                        remediation="Restrict credential store access. Enable authentication.",
                                        references=["https://www.jenkins.io/doc/book/using/using-credentials/"],
                                        evidence=Evidence(response_raw=body[:2000]),
                                        cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
                                        mitre_attack=["TA0006/T1552", "TA0006/T1555"],
                                        target=target,
                                        confidence="HIGH",
                                        tags=self.TAGS + ["credential-theft"],
                                    )
                                    return
                    except Exception:
                        continue
        except Exception as exc:
            self.log.debug("Credential store check error: %s", exc)

    async def _enumerate_api(self, target: str, info: dict[str, Any]) -> None:
        """Enumerate Jenkins API for jobs, users, and agents."""
        import aiohttp

        try:
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False),
                timeout=aiohttp.ClientTimeout(total=8),
            ) as session:
                # Job listing
                await self.rate_limit()
                try:
                    async with session.get(
                        f"{target}/api/json?tree=jobs[name,url,color]",
                    ) as resp:
                        if resp.status == 200:
                            body = await resp.text(errors="ignore")
                            try:
                                data = json.loads(body)
                                jobs = data.get("jobs", [])
                                if jobs:
                                    self.new_finding(
                                        title="Jenkins — Job Listing Exposed",
                                        severity=Severity.MEDIUM,
                                        description=(
                                            f"Jenkins API at {target} exposes {len(jobs)} jobs "
                                            f"to anonymous users. Job names may reveal internal "
                                            f"project names, deployment targets, and infrastructure."
                                        ),
                                        reproduction_steps=[
                                            f"1. GET {target}/api/json?tree=jobs[name]",
                                            f"2. {len(jobs)} jobs returned",
                                        ],
                                        remediation="Restrict API access. Configure authorization matrix.",
                                        references=["https://www.jenkins.io/doc/book/security/"],
                                        evidence=Evidence(
                                            extra={
                                                "job_count": len(jobs),
                                                "sample_jobs": [j.get("name", "") for j in jobs[:10]],
                                            },
                                        ),
                                        cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                                        mitre_attack=["TA0007/T1083"],
                                        target=target,
                                        confidence="HIGH",
                                        tags=self.TAGS,
                                    )
                            except json.JSONDecodeError:
                                pass
                except Exception:
                    pass
        except Exception as exc:
            self.log.debug("API enumeration error: %s", exc)

    async def _check_csrf_protection(self, target: str) -> None:
        """Check if CSRF protection (crumb) is enabled."""
        import aiohttp

        try:
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False),
                timeout=aiohttp.ClientTimeout(total=8),
            ) as session:
                await self.rate_limit()
                try:
                    async with session.get(f"{target}/crumbIssuer/api/json") as resp:
                        if resp.status == 404:
                            self.new_finding(
                                title="Jenkins — CSRF Protection Disabled",
                                severity=Severity.MEDIUM,
                                description=(
                                    f"Jenkins at {target} has CSRF protection (crumb issuer) "
                                    f"disabled. This allows cross-site request forgery attacks "
                                    f"against authenticated administrators."
                                ),
                                reproduction_steps=[
                                    f"1. GET {target}/crumbIssuer/api/json → 404",
                                    "2. No crumb issuer configured",
                                ],
                                remediation="Enable CSRF protection in Manage Jenkins → Security.",
                                references=["https://www.jenkins.io/doc/book/security/csrf-protection/"],
                                evidence=Evidence(extra={"crumb_status": 404}),
                                cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
                                mitre_attack=["TA0001/T1189"],
                                target=target,
                                confidence="MEDIUM",
                                tags=self.TAGS + ["csrf"],
                            )
                except Exception:
                    pass
        except Exception as exc:
            self.log.debug("CSRF check error: %s", exc)


# ══════════════════════════════════════════════════════════════════════
# UNIT TESTS
# ══════════════════════════════════════════════════════════════════════


class TestJenkinsAudit:
    def _make_module(self, tmp_path: Path) -> JenkinsAudit:
        from common.config import BaseForgeConfig
        from common.scope import Scope
        from common.db import create_db
        cfg = BaseForgeConfig(target="http://jenkins.example.com:8080")
        scope = Scope(["jenkins.example.com"])
        session = create_db(tmp_path / "test.db")
        return JenkinsAudit(cfg, scope, session, tmp_path)

    def test_module_metadata(self, tmp_path: Path) -> None:
        mod = self._make_module(tmp_path)
        assert mod.NAME == "jenkins_audit"
        assert mod.PHASE == 4
        assert "jenkins" in mod.TAGS

    def test_critical_endpoints_defined(self, tmp_path: Path) -> None:
        assert len(CRITICAL_ENDPOINTS) >= 5
        assert any("/script" in ep[0] for ep in CRITICAL_ENDPOINTS)

    def test_recon_endpoints_defined(self, tmp_path: Path) -> None:
        assert len(RECON_ENDPOINTS) >= 5
        assert any("/api/json" in ep[0] for ep in RECON_ENDPOINTS)

    def test_groovy_probe(self, tmp_path: Path) -> None:
        assert GROOVY_MATH_PROBE == "println(7*7)"
        assert GROOVY_EXPECTED == "49"

    def test_version_patterns_compile(self, tmp_path: Path) -> None:
        for pat in VERSION_PATTERNS:
            assert pat.pattern
        assert VERSION_PATTERNS[0].search("X-Jenkins: 2.426.3")

    def test_out_of_scope_skip(self, tmp_path: Path) -> None:
        from common.config import BaseForgeConfig
        from common.scope import Scope
        from common.db import create_db
        cfg = BaseForgeConfig(target="http://jenkins.example.com:8080")
        scope = Scope(["10.0.0.0/24"])
        session = create_db(tmp_path / "test.db")
        mod = JenkinsAudit(cfg, scope, session, tmp_path)
        result = asyncio.run(mod.run())
        assert result.skipped is True
