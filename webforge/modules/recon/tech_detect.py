"""Technology detection — Wappalyzer-style offline fingerprinting with version disclosure."""
from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS31_INFO = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
CVSS40_INFO = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"

# Signatures: body patterns, header patterns, cookie patterns, meta patterns
# "version_re" extracts version string from header/body match for disclosure findings
TECH_SIGNATURES: dict[str, dict[str, Any]] = {
    "WordPress": {
        "headers": {},
        "body": [r"wp-content/", r"wp-includes/", r"WordPress"],
        "cookies": ["wordpress_"],
        "version_re": r"/wp-includes/js/[^?\"]*\?ver=([\d.]+)",
    },
    "Joomla": {
        "headers": {},
        "body": [r"/components/com_", r"Joomla!"],
        "cookies": [],
        "version_re": r"Joomla! ([\d.]+)",
    },
    "Drupal": {
        "headers": {"x-generator": r"Drupal ([\d.]+)"},
        "body": [r"Drupal\.settings", r"/sites/default/"],
        "cookies": ["SESS"],
        "version_re": r"Drupal ([\d.]+)",
    },
    "Laravel": {
        "headers": {},
        "body": [],
        "cookies": ["laravel_session"],
        "meta": [r"csrf-token"],
    },
    "Django": {
        "headers": {},
        "body": [],
        "cookies": ["csrftoken", "sessionid"],
        "meta": [],
    },
    "Ruby on Rails": {
        "headers": {"x-powered-by": r"Phusion Passenger ([\d.]+)"},
        "body": [r"rails_ujs"],
        "cookies": ["_session_id"],
        "meta": [],
    },
    "PHP": {
        "headers": {"x-powered-by": r"PHP/([\d.]+)"},
        "body": [],
        "cookies": ["PHPSESSID"],
        "meta": [],
        "version_re_header": "x-powered-by",
        "version_re": r"PHP/([\d.]+)",
    },
    "ASP.NET": {
        "headers": {
            "x-powered-by": r"ASP\.NET",
            "x-aspnet-version": r"([\d.]+)",
        },
        "body": [r"__VIEWSTATE", r"__EVENTVALIDATION", r"__doPostBack"],
        "cookies": [r"ASP\.NET_SessionId"],
        "version_re": r"^([\d.]+)$",
        "version_header": "x-aspnet-version",
    },
    "jQuery": {
        "headers": {},
        "body": [r"jquery[.-]([\d.]+)(?:\.min)?\.js", r"jquery\.min\.js"],
        "cookies": [],
        "version_re": r"jquery[.-]([\d.]+)",
    },
    "React": {
        "headers": {},
        "body": [r"__REACT_DEVTOOLS", r"data-reactroot", r"react\.development\.js", r"react\.production\.min\.js"],
        "cookies": [],
    },
    "Angular": {
        "headers": {},
        "body": [r"ng-version=[\"']([\d.]+)", r"angular\.min\.js", r"\[ng-"],
        "cookies": [],
        "version_re": r"ng-version=[\"']([\d.]+)",
    },
    "Vue.js": {
        "headers": {},
        "body": [r"vue\.min\.js", r"__vue__", r"data-v-"],
        "cookies": [],
    },
    "Next.js": {
        "headers": {"x-powered-by": r"Next\.js"},
        "body": [r"__NEXT_DATA__", r"_next/static/"],
        "cookies": [],
    },
    "Nuxt.js": {
        "headers": {},
        "body": [r"__nuxt", r"_nuxt/"],
        "cookies": [],
    },
    "Bootstrap": {
        "headers": {},
        "body": [r"bootstrap\.([\d.]+)(?:\.min)?\.css", r"bootstrap\.min\.css"],
        "cookies": [],
        "version_re": r"bootstrap\.([\d.]+)\.min\.(css|js)",
    },
    "Nginx": {
        "headers": {"server": r"nginx/([\d.]+)"},
        "body": [],
        "cookies": [],
        "version_re": r"nginx/([\d.]+)",
        "version_header": "server",
    },
    "Apache": {
        "headers": {"server": r"Apache/([\d.]+)"},
        "body": [],
        "cookies": [],
        "version_re": r"Apache/([\d.]+)",
        "version_header": "server",
    },
    "Microsoft IIS": {
        "headers": {"server": r"Microsoft-IIS/([\d.]+)"},
        "body": [],
        "cookies": [],
        "version_re": r"Microsoft-IIS/([\d.]+)",
        "version_header": "server",
    },
    "Cloudflare": {
        "headers": {"server": r"cloudflare", "cf-ray": r".+"},
        "body": [],
        "cookies": ["__cfduid", "cf_clearance"],
    },
    "AWS S3": {
        "headers": {"x-amz-request-id": r".+", "x-amz-id-2": r".+"},
        "body": [],
        "cookies": [],
    },
    "GraphQL": {
        "headers": {},
        "body": [r"graphql", r"__schema", r"IntrospectionQuery"],
        "cookies": [],
    },
    "Swagger/OpenAPI": {
        "headers": {},
        "body": [r"swagger-ui", r"openapi\.json", r"/api-docs"],
        "cookies": [],
    },
    "Spring Boot": {
        "headers": {},
        "body": [],
        "cookies": ["JSESSIONID"],
        "meta": [],
        "actuator_paths": ["/actuator", "/actuator/health"],
    },
    "Node.js/Express": {
        "headers": {"x-powered-by": r"Express"},
        "body": [],
        "cookies": [],
    },
    "Strapi": {
        "headers": {"x-powered-by": r"Strapi"},
        "body": [r"strapi"],
        "cookies": [],
    },
    "Tomcat": {
        "headers": {"server": r"Apache-Coyote|Tomcat"},
        "body": [r"Apache Tomcat/([\d.]+)", r"org\.apache\.catalina"],
        "cookies": ["JSESSIONID"],
        "version_re": r"Apache Tomcat/([\d.]+)",
    },
}

# Headers whose values should be reported as version disclosure
VERSION_DISCLOSURE_HEADERS = [
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "x-runtime",
    "x-drupal-cache",
    "x-drupal-dynamic-cache",
]


class TechDetect(BaseModule):
    """Technology fingerprinting module."""

    NAME        = "tech_detect"
    DESCRIPTION = "Detect server-side and client-side technologies; report version disclosures"
    PHASE       = 1
    TAGS        = ["recon", "fingerprint", "cwe-200", "owasp-a05"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        self.log.info("Detecting technologies on %s", target)

        from webforge.core.session import ForgeSession
        async with ForgeSession(
            rate=self.config.rate.requests_per_second,
            proxy=self.config.extra.get("proxy"),
        ) as session:
            try:
                await self.rate_limit()
                resp = await session.get(target)
                headers = {k.lower(): v for k, v in resp.headers.items()}
                body    = await resp.text()
                cookies = {c.key: c.value for c in resp.cookies.values()}
            except Exception as exc:
                self.log.error("Tech detect failed: %s", exc)
                return self._make_result(start)

        # 1. Technology fingerprinting
        detected: dict[str, list[str]] = {}
        versions: dict[str, str]       = {}

        for tech, sigs in TECH_SIGNATURES.items():
            matches: list[str] = []
            # Header checks
            for hdr_key, pattern in sigs.get("headers", {}).items():
                hdr_val = headers.get(hdr_key, "")
                if hdr_val and re.search(pattern, hdr_val, re.I):
                    matches.append(f"header:{hdr_key}")
                    # Try to extract version
                    ver_hdr = sigs.get("version_header", "")
                    ver_re  = sigs.get("version_re", pattern)
                    if ver_hdr == hdr_key or hdr_key in ("server", "x-powered-by",
                                                          "x-aspnet-version"):
                        m = re.search(ver_re, hdr_val, re.I)
                        if m and m.lastindex:
                            versions[tech] = m.group(1)

            # Body checks
            for pattern in sigs.get("body", []):
                m = re.search(pattern, body, re.I)
                if m:
                    matches.append(f"body:{pattern[:30]}")
                    # Try to extract version from body match
                    if m.lastindex and tech not in versions:
                        ver_re = sigs.get("version_re", "")
                        if ver_re:
                            mv = re.search(ver_re, body, re.I)
                            if mv and mv.lastindex:
                                versions[tech] = mv.group(1)

            # Cookie checks
            for cookie_pattern in sigs.get("cookies", []):
                for cookie_name in cookies:
                    if re.search(cookie_pattern, cookie_name, re.I):
                        matches.append(f"cookie:{cookie_name}")

            # Meta tag checks
            for meta_pattern in sigs.get("meta", []):
                if re.search(meta_pattern, body, re.I):
                    matches.append(f"meta:{meta_pattern[:30]}")

            if matches:
                detected[tech] = matches

        if detected:
            self.log.info("Technologies detected: %s", list(detected.keys()))
            ev = Evidence(
                extra={
                    "detected": detected,
                    "versions": versions,
                    "headers":  dict(list(headers.items())[:20]),
                },
            )
            self.new_finding(
                title=f"Technology Fingerprint: {', '.join(list(detected.keys())[:6])}",
                severity=Severity.INFORMATIONAL,
                description=(
                    f"Detected technologies: {', '.join(detected.keys())}. "
                    + (f"Version information: {versions}. " if versions else "")
                    + "This information helps attackers target known CVEs for detected versions."
                ),
                reproduction_steps=[
                    f"GET {target}",
                    "Analyse headers and body for technology signatures",
                ],
                remediation=(
                    "Remove/suppress version information from Server, X-Powered-By, and similar headers. "
                    "Keep all software updated. "
                    "Set server_tokens off (Nginx) or ServerTokens Prod (Apache)."
                ),
                references=["CWE-200", "OWASP A05:2021"],
                evidence=ev,
                cvss_v31_vector=CVSS31_INFO,
                cvss_v40_vector=CVSS40_INFO,
                mitre_attack=["TA0043/T1595.002"],
                target=target,
            )
            self.config.extra.setdefault("detected_tech", detected)
            if versions:
                self.config.extra.setdefault("tech_versions", versions)

        # 2. Per-header version disclosure findings
        for hdr_name in VERSION_DISCLOSURE_HEADERS:
            val = headers.get(hdr_name)
            if not val:
                continue
            # Check if value includes version number
            version_match = re.search(r"[\d]+\.[\d]+", val)
            if version_match:
                ev = Evidence(
                    extra={"header": hdr_name, "value": val},
                )
                self.new_finding(
                    title=f"Version Disclosure in '{hdr_name}' Header",
                    severity=Severity.LOW,
                    description=(
                        f"The response header '{hdr_name}' discloses a software version: {val!r}. "
                        "Version disclosure allows attackers to look up known CVEs for the exact "
                        "version of the software being used."
                    ),
                    reproduction_steps=[
                        f"curl -I {target} | grep -i {hdr_name}",
                        f"Cross-reference {val!r} against CVE databases",
                    ],
                    remediation=(
                        f"Suppress version number from '{hdr_name}' header:\n"
                        "• Nginx: server_tokens off;\n"
                        "• Apache: ServerTokens Prod\n"
                        "• PHP: expose_php = Off in php.ini\n"
                        "• IIS: Remove X-Powered-By via custom headers config"
                    ),
                    references=["CWE-200", "OWASP A05:2021"],
                    evidence=ev,
                    cvss_v31_vector=CVSS31_INFO,
                    cvss_v40_vector=CVSS40_INFO,
                    target=target,
                )

        return self._make_result(start)


class TestTechDetect:
    def test_signatures_loaded(self) -> None:
        assert "WordPress" in TECH_SIGNATURES
        assert "Nginx" in TECH_SIGNATURES
        assert "PHP" in TECH_SIGNATURES

    def test_signature_structure(self) -> None:
        for tech, sigs in TECH_SIGNATURES.items():
            # Each tech must have at least headers OR body
            assert "headers" in sigs or "body" in sigs, f"Missing headers/body for {tech}"

    def test_version_disclosure_headers_defined(self) -> None:
        assert "server" in VERSION_DISCLOSURE_HEADERS
        assert "x-powered-by" in VERSION_DISCLOSURE_HEADERS
        assert "x-aspnet-version" in VERSION_DISCLOSURE_HEADERS

    def test_body_patterns_compile(self) -> None:
        for tech, sigs in TECH_SIGNATURES.items():
            for pattern in sigs.get("body", []):
                compiled = re.compile(pattern, re.I)
                assert compiled is not None, f"Pattern failed for {tech}: {pattern}"

    def test_header_patterns_compile(self) -> None:
        for tech, sigs in TECH_SIGNATURES.items():
            for hdr, pattern in sigs.get("headers", {}).items():
                compiled = re.compile(pattern, re.I)
                assert compiled is not None, f"Header pattern failed for {tech}/{hdr}"

    def test_version_re_extracts(self) -> None:
        php_sigs = TECH_SIGNATURES["PHP"]
        ver_re = php_sigs.get("version_re", "")
        if ver_re:
            m = re.search(ver_re, "PHP/8.1.12", re.I)
            assert m is not None
            assert m.group(1) == "8.1.12"
