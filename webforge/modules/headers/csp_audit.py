"""CSP (Content Security Policy) auditor — detect unsafe directives and missing requirements."""
from __future__ import annotations

import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
from common.fp_reducer import FPReducer, Confidence

CVSS_NO_CSP      = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
CVSS40_NO_CSP    = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N"
CVSS_UNSAFE_CSP  = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
CVSS40_UNSAFE_CSP = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N"
CVSS_MISSING_DIR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
CVSS40_MISSING_DIR = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N"
class CspAudit(BaseModule):
    """Content Security Policy auditor."""

    NAME        = "csp_audit"
    DESCRIPTION = "Audit Content-Security-Policy header for unsafe directives and missing requirements"
    PHASE       = 3
    TAGS        = ["headers", "csp", "xss", "owasp-a05", "cwe-1021"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        self._fp = FPReducer(
            collab_client=self.config.extra.get("collab_client"),
            headers=self.config.extra.get("session_headers", {}),
        )
        headers = await self._fetch_headers(target)
        if headers is None:
            return self._make_result(start)

        csp   = headers.get("content-security-policy", "")
        cspro = headers.get("content-security-policy-report-only", "")

        if not csp:
            ev = Evidence(
                response_raw=f"Headers:\n" + "\n".join(f"{k}: {v}" for k, v in headers.items()),
                extra={"has_csp": False, "has_report_only": bool(cspro)},
            )
            self.new_finding(
                title="Content-Security-Policy Header Missing",
                severity=Severity.MEDIUM,
                description=(
                    f"No Content-Security-Policy header on {target}. "
                    "CSP is a critical defence layer against XSS attacks. "
                    + ("A Report-Only policy is present but not enforced. "
                       "Move to an enforcing CSP."
                       if cspro else "")
                ),
                reproduction_steps=[f"curl -I {target} | grep -i content-security-policy"],
                remediation=(
                    "Implement a CSP header. Start with: "
                    "Content-Security-Policy: default-src 'self'; "
                    "script-src 'self'; style-src 'self'; img-src 'self' data:; "
                    "object-src 'none'; base-uri 'self'; form-action 'self'"
                ),
                references=["CWE-1021", "OWASP CSP Cheat Sheet"],
                evidence=ev,
                cvss_v31_vector=CVSS_NO_CSP,
                cvss_v40_vector=CVSS40_NO_CSP,
                mitre_attack=["TA0001/T1059.007"],
                target=target,
            )
            return self._make_result(start)

        # Parse and analyze CSP directives
        issues = self._analyze_csp(csp)
        for issue_title, issue_desc, severity in issues:
            ev = Evidence(
                response_raw=f"Content-Security-Policy: {csp}",
                extra={"csp": csp[:400], "issue": issue_title},
            )
            self.new_finding(
                title=f"Weak CSP — {issue_title}",
                severity=severity,
                description=(
                    f"CSP directive issue on {target}: {issue_desc}\n"
                    f"Full CSP: {csp[:300]}"
                ),
                reproduction_steps=[f"curl -I {target} | grep Content-Security-Policy"],
                remediation=(
                    "Remove unsafe directives from CSP. "
                    "Use nonces or hashes instead of 'unsafe-inline'. "
                    "Replace wildcards with specific trusted domains."
                ),
                references=["CWE-1021", "OWASP CSP Cheat Sheet"],
                evidence=ev,
                cvss_v31_vector=CVSS_UNSAFE_CSP,
                cvss_v40_vector=CVSS40_UNSAFE_CSP,
                mitre_attack=["TA0001/T1059.007"],
                target=target,
            )

        return self._make_result(start)

    def _parse_directives(self, csp: str) -> dict[str, list[str]]:
        """Parse CSP string into a dict of directive → list of values."""
        directives: dict[str, list[str]] = {}
        for directive in csp.split(";"):
            directive = directive.strip()
            if not directive:
                continue
            parts = directive.split()
            if parts:
                name = parts[0].lower()
                values = [p.lower() for p in parts[1:]]
                directives[name] = values
        return directives

    def _analyze_csp(self, csp: str) -> list[tuple[str, str, Severity]]:
        issues: list[tuple[str, str, Severity]] = []
        directives = self._parse_directives(csp)

        # ---- Unsafe value checks ----
        # Directives that govern script execution
        script_directives = [
            "script-src", "script-src-elem", "script-src-attr", "default-src"
        ]
        style_directives = [
            "style-src", "style-src-elem", "style-src-attr", "default-src"
        ]

        for dir_name in script_directives:
            if dir_name not in directives:
                continue
            values = directives[dir_name]

            if "'unsafe-inline'" in values:
                issues.append((
                    f"'unsafe-inline' in {dir_name}",
                    f"'unsafe-inline' in {dir_name} allows inline <script> blocks and event handlers. "
                    "This effectively negates XSS protection for scripts. "
                    "Use nonces (nonce-{random}) or hashes instead.",
                    Severity.HIGH,
                ))

            if "'unsafe-eval'" in values:
                issues.append((
                    f"'unsafe-eval' in {dir_name}",
                    f"'unsafe-eval' in {dir_name} allows eval(), Function(), setTimeout/setInterval "
                    "with string arguments, and new Function(). "
                    "This enables XSS via eval injection and amplifies other injection attacks.",
                    Severity.HIGH,
                ))

            if "'unsafe-hashes'" in values:
                issues.append((
                    f"'unsafe-hashes' in {dir_name}",
                    f"'unsafe-hashes' in {dir_name} allows inline event handlers matched by hash. "
                    "This weakens protection if the application has injectable inline event attributes.",
                    Severity.MEDIUM,
                ))

            # Wildcard host sources
            wildcard_values = [v for v in values if v == "*" or re.match(r"^https?://\*", v)]
            if wildcard_values:
                issues.append((
                    f"Wildcard source in {dir_name} ({', '.join(wildcard_values)})",
                    f"{dir_name} contains wildcard source(s) {wildcard_values!r}, "
                    "allowing scripts to be loaded from any origin. "
                    "An attacker who can inject a <script> tag pointing to any server can bypass CSP.",
                    Severity.HIGH,
                ))

            # data: URI in script-src
            if "data:" in values:
                issues.append((
                    f"data: URI in {dir_name}",
                    f"data: URI scheme in {dir_name} allows inline script execution via "
                    "<script src='data:text/javascript,...'>. This is a known CSP bypass technique.",
                    Severity.HIGH,
                ))

            # http: scheme allows any HTTP origin
            if "http:" in values:
                issues.append((
                    f"http: scheme in {dir_name}",
                    f"{dir_name} allows loading scripts from any HTTP (non-HTTPS) URL. "
                    "This allows MITM-injected scripts and undermines TLS protection.",
                    Severity.MEDIUM,
                ))

        # Style unsafe-inline (lower severity than script)
        for dir_name in style_directives:
            if dir_name not in directives:
                continue
            if dir_name in script_directives:
                continue  # Already checked above
            values = directives[dir_name]
            if "'unsafe-inline'" in values:
                issues.append((
                    f"'unsafe-inline' in {dir_name}",
                    f"'unsafe-inline' in {dir_name} allows inline <style> and style= attributes. "
                    "CSS injection can leak data via CSS selectors and lead to UI redressing.",
                    Severity.MEDIUM,
                ))

        # ---- Missing important directives ----

        # No script restriction at all
        if "script-src" not in directives and "default-src" not in directives:
            issues.append((
                "Missing script-src directive",
                "Neither script-src nor default-src is defined — no JavaScript source restriction. "
                "Scripts can be loaded from any origin, providing zero XSS protection.",
                Severity.HIGH,
            ))

        # default-src alone may not cover all directives — note if relied upon
        if "default-src" in directives and "script-src" not in directives:
            default_values = directives["default-src"]
            if "'unsafe-inline'" in default_values or "'unsafe-eval'" in default_values:
                issues.append((
                    "default-src contains unsafe values with no script-src override",
                    "default-src has unsafe values and there is no script-src to override them. "
                    "Add an explicit script-src without unsafe values.",
                    Severity.HIGH,
                ))

        # Missing object-src → allows Flash/Java plugins
        has_object = "object-src" in directives
        default_values = directives.get("default-src", [])
        if not has_object and "object-src" not in directives:
            if not any(v in ("'none'", "none") for v in default_values):
                issues.append((
                    "Missing object-src directive",
                    "No object-src directive restricts plugins (Flash, Silverlight, Java Applets). "
                    "These can bypass CSP entirely. Add: object-src 'none'",
                    Severity.MEDIUM,
                ))

        # Missing base-uri → base tag injection
        if "base-uri" not in directives:
            issues.append((
                "Missing base-uri directive",
                "Without base-uri restriction, attackers who can inject a <base href='https://evil.com'> "
                "can redirect all relative URL loads (scripts, images, forms) to an attacker-controlled server.",
                Severity.MEDIUM,
            ))

        # Missing form-action → open redirect via form submissions
        if "form-action" not in directives:
            issues.append((
                "Missing form-action directive",
                "Without form-action restriction, <form action='https://attacker.com'> injections "
                "can exfiltrate form submissions to arbitrary destinations. "
                "Add: form-action 'self'",
                Severity.LOW,
            ))

        # frame-ancestors missing (clickjacking defence)
        if "frame-ancestors" not in directives:
            issues.append((
                "Missing frame-ancestors directive",
                "Without frame-ancestors, the page can be framed by any origin, enabling clickjacking. "
                "CSP frame-ancestors supersedes X-Frame-Options for modern browsers. "
                "Add: frame-ancestors 'none' or 'self'",
                Severity.LOW,
            ))

        # upgrade-insecure-requests missing (on HTTPS sites)
        if "upgrade-insecure-requests" not in directives and "block-all-mixed-content" not in directives:
            issues.append((
                "Missing upgrade-insecure-requests or block-all-mixed-content",
                "Without upgrade-insecure-requests, HTTP sub-resources may be loaded alongside HTTPS, "
                "creating mixed content vulnerabilities. Add: upgrade-insecure-requests",
                Severity.LOW,
            ))

        return issues

    def _find_directive_context(self, csp: str, term: str) -> str:
        for directive in csp.split(";"):
            if term.lower() in directive.lower():
                return directive.strip()[:60]
        return term

    async def _fetch_headers(self, url: str) -> dict | None:
        await self.rate_limit()
        try:
            import aiohttp
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False),
                headers={"Accept-Encoding": "gzip, deflate"},
            ) as session:
                async with session.get(
                    url, timeout=aiohttp.ClientTimeout(total=8), allow_redirects=True
                ) as resp:
                    # Lowercase all header names for consistent lookup
                    return {k.lower(): v for k, v in resp.headers.items()}
        except Exception:
            return None


class TestCspAudit:
    def test_analyze_unsafe_inline_in_script_src(self) -> None:
        mod = CspAudit.__new__(CspAudit)
        issues = mod._analyze_csp(
            "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'"
        )
        titles = [i[0] for i in issues]
        assert any("unsafe-inline" in t and "script-src" in t for t in titles)

    def test_analyze_unsafe_eval(self) -> None:
        mod = CspAudit.__new__(CspAudit)
        issues = mod._analyze_csp("default-src 'self' 'unsafe-eval'")
        titles = [i[0] for i in issues]
        assert any("unsafe-eval" in t for t in titles)

    def test_analyze_wildcard(self) -> None:
        mod = CspAudit.__new__(CspAudit)
        issues = mod._analyze_csp("script-src *; default-src 'self'")
        titles = [i[0] for i in issues]
        assert any("Wildcard" in t for t in titles)

    def test_analyze_data_uri_in_script(self) -> None:
        mod = CspAudit.__new__(CspAudit)
        issues = mod._analyze_csp("script-src 'self' data:; object-src 'none'; base-uri 'self'")
        titles = [i[0] for i in issues]
        assert any("data:" in t for t in titles)

    def test_analyze_missing_base_uri(self) -> None:
        mod = CspAudit.__new__(CspAudit)
        issues = mod._analyze_csp("default-src 'self'; script-src 'self'; object-src 'none'")
        titles = [i[0] for i in issues]
        assert any("base-uri" in t for t in titles)

    def test_analyze_clean_strict_csp(self) -> None:
        mod = CspAudit.__new__(CspAudit)
        clean = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "object-src 'none'; base-uri 'self'; form-action 'self'; "
            "frame-ancestors 'none'; upgrade-insecure-requests"
        )
        issues = mod._analyze_csp(clean)
        # Should have no HIGH severity issues
        high_issues = [i for i in issues if i[2] == Severity.HIGH]
        assert len(high_issues) == 0

    def test_analyze_missing_directives(self) -> None:
        mod = CspAudit.__new__(CspAudit)
        issues = mod._analyze_csp("img-src *")
        titles = [i[0] for i in issues]
        assert any("script-src" in t for t in titles)

    def test_parse_directives(self) -> None:
        mod = CspAudit.__new__(CspAudit)
        result = mod._parse_directives("default-src 'self'; script-src 'self' 'nonce-abc'; object-src 'none'")
        assert "default-src" in result
        assert "'self'" in result["default-src"]
        assert "object-src" in result
        assert "'none'" in result["object-src"]
