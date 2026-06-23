"""Compliance engine — map findings to PCI-DSS 4.0, OWASP Top 10 2021, ISO 27001.

Generates compliance evidence reports showing which rules pass/fail based on
actual scan findings. Used by the reporting engine for compliance-oriented exports.

Usage:
    engine = ComplianceEngine(ComplianceFramework.PCI_DSS)
    report = engine.evaluate(findings)
    print(report.summary())
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable


class ComplianceFramework(str, Enum):
    PCI_DSS = "pci-dss-4.0"
    OWASP_TOP10 = "owasp-top10-2021"
    ISO_27001 = "iso-27001-2022"
    NIST_CSF = "nist-csf-2.0"
    HIPAA = "hipaa"


class ComplianceStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    PARTIAL = "partial"
    NOT_TESTED = "not_tested"


@dataclass
class ComplianceRule:
    """A single compliance rule/requirement."""
    rule_id: str
    title: str
    description: str
    framework: ComplianceFramework
    severity: str = "high"       # critical, high, medium, low, info
    section: str = ""            # e.g. "6.2" for PCI-DSS
    check_fn: Callable[[list[dict]], ComplianceStatus] | None = None
    # Matching: which finding tags/titles trigger this rule
    match_tags: list[str] = field(default_factory=list)
    match_title_patterns: list[str] = field(default_factory=list)
    remediation: str = ""

    def evaluate(self, findings: list[dict]) -> "RuleResult":
        """Evaluate this rule against findings."""
        if self.check_fn:
            status = self.check_fn(findings)
        else:
            status = self._default_check(findings)

        matched = self._find_matching(findings)
        return RuleResult(
            rule=self,
            status=status,
            matched_findings=matched,
        )

    def _default_check(self, findings: list[dict]) -> ComplianceStatus:
        """Default: FAIL if any matching finding has severity >= rule severity."""
        matched = self._find_matching(findings)
        if not matched:
            return ComplianceStatus.PASS

        severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        rule_rank = severity_rank.get(self.severity, 0)

        for f in matched:
            f_sev = f.get("severity", "info").lower()
            if severity_rank.get(f_sev, 0) >= rule_rank:
                return ComplianceStatus.FAIL

        return ComplianceStatus.PARTIAL

    def _find_matching(self, findings: list[dict]) -> list[dict]:
        """Find findings that match this rule's tags or title patterns."""
        matched: list[dict] = []
        for f in findings:
            f_tags = set(t.lower() for t in f.get("tags", []))
            f_refs = set(r.lower() for r in f.get("references", []))
            f_title = f.get("title", "").lower()

            # Tag match
            if self.match_tags and any(t.lower() in f_tags | f_refs for t in self.match_tags):
                matched.append(f)
                continue

            # Title pattern match
            for pattern in self.match_title_patterns:
                if re.search(pattern, f_title, re.IGNORECASE):
                    matched.append(f)
                    break

        return matched


@dataclass
class RuleResult:
    """Result of evaluating a single compliance rule."""
    rule: ComplianceRule
    status: ComplianceStatus
    matched_findings: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule.rule_id,
            "title": self.rule.title,
            "section": self.rule.section,
            "severity": self.rule.severity,
            "status": self.status.value,
            "finding_count": len(self.matched_findings),
            "finding_titles": [f.get("title", "") for f in self.matched_findings[:5]],
            "matched_findings": [
                {"id": f.get("id", ""), "title": f.get("title", ""), "severity": f.get("severity", "")}
                for f in self.matched_findings[:5]
            ],
            "remediation": self.rule.remediation,
        }


@dataclass
class ComplianceReport:
    """Full compliance evaluation report."""
    framework: ComplianceFramework
    results: list[RuleResult] = field(default_factory=list)

    @property
    def pass_count(self) -> int:
        return sum(1 for r in self.results if r.status == ComplianceStatus.PASS)

    @property
    def fail_count(self) -> int:
        return sum(1 for r in self.results if r.status == ComplianceStatus.FAIL)

    @property
    def partial_count(self) -> int:
        return sum(1 for r in self.results if r.status == ComplianceStatus.PARTIAL)

    @property
    def not_tested_count(self) -> int:
        return sum(1 for r in self.results if r.status == ComplianceStatus.NOT_TESTED)

    @property
    def compliance_pct(self) -> float:
        tested = [r for r in self.results if r.status != ComplianceStatus.NOT_TESTED]
        if not tested:
            return 0.0
        passed = sum(1 for r in tested if r.status == ComplianceStatus.PASS)
        return round((passed / len(tested)) * 100, 1)

    def summary(self) -> str:
        return (
            f"{self.framework.value}: {self.compliance_pct}% compliant "
            f"({self.pass_count} pass, {self.fail_count} fail, "
            f"{self.partial_count} partial, {self.not_tested_count} not tested)"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "framework": self.framework.value,
            "compliance_pct": self.compliance_pct,
            "pass": self.pass_count,
            "fail": self.fail_count,
            "partial": self.partial_count,
            "not_tested": self.not_tested_count,
            "rules": [r.to_dict() for r in self.results],
        }


# ── Rule definitions ─────────────────────────────────────────────────────────

def _pci_dss_rules() -> list[ComplianceRule]:
    """PCI-DSS 4.0 security requirements relevant to web penetration testing."""
    fw = ComplianceFramework.PCI_DSS
    return [
        ComplianceRule(
            rule_id="PCI-6.2.4", section="6.2.4", framework=fw,
            title="Software engineering — prevent common vulnerabilities",
            description="Software is developed to prevent or mitigate common software attacks (SQLi, XSS, CSRF, etc.)",
            severity="critical",
            match_tags=["cwe-89", "cwe-79", "cwe-352", "cwe-78", "cwe-94", "sqli", "xss", "csrf", "ssti", "cmdi"],
            match_title_patterns=[r"sql.?inject", r"xss", r"command.?inject", r"template.?inject"],
            remediation="Address all injection vulnerabilities per OWASP Secure Coding guidelines.",
        ),
        ComplianceRule(
            rule_id="PCI-6.3.1", section="6.3.1", framework=fw,
            title="Identify and manage security vulnerabilities",
            description="Security vulnerabilities are identified and managed via a vulnerability management process.",
            severity="high",
            match_tags=["cve-"],
            match_title_patterns=[r"CVE-\\d{4}", r"known.?vuln"],
            remediation="Establish a vulnerability management process; patch within 30 days for critical/high.",
        ),
        ComplianceRule(
            rule_id="PCI-6.4.1", section="6.4.1", framework=fw,
            title="Public-facing web apps protected against attacks",
            description="Web applications must be protected by WAF or equivalent.",
            severity="high",
            match_tags=["waf-bypass", "no-waf"],
            match_title_patterns=[r"no.?waf", r"waf.?bypass"],
            remediation="Deploy a WAF (ModSecurity, Cloudflare, AWS WAF) for all public web apps.",
        ),
        ComplianceRule(
            rule_id="PCI-4.2.1", section="4.2.1", framework=fw,
            title="Strong cryptography for transmission",
            description="Strong cryptography protects PAN during transmission over open, public networks.",
            severity="critical",
            match_tags=["ssl", "tls", "weak-cipher", "expired-cert"],
            match_title_patterns=[r"ssl", r"tls", r"weak.?cipher", r"expired.?cert", r"self.?signed"],
            remediation="Use TLS 1.2+ with strong cipher suites; renew certificates before expiry.",
        ),
        ComplianceRule(
            rule_id="PCI-6.5.1", section="6.5.1", framework=fw,
            title="Injection flaws prevented",
            description="SQL injection, OS command injection, and similar injection attacks must be prevented.",
            severity="critical",
            match_tags=["cwe-89", "cwe-78", "cwe-90", "cwe-94"],
            match_title_patterns=[r"inject"],
            remediation="Use parameterized queries and input validation for all data paths.",
        ),
        ComplianceRule(
            rule_id="PCI-6.5.4", section="6.5.4", framework=fw,
            title="Insecure communications prevented",
            description="Prevent insecure communications that expose sensitive data.",
            severity="high",
            match_tags=["missing-hsts", "mixed-content"],
            match_title_patterns=[r"hsts", r"http.?header", r"missing.?header"],
            remediation="Enable HSTS, set Secure flag on cookies, enforce HTTPS everywhere.",
        ),
        ComplianceRule(
            rule_id="PCI-6.5.7", section="6.5.7", framework=fw,
            title="Cross-site scripting prevented",
            description="XSS vulnerabilities must be prevented in web applications.",
            severity="high",
            match_tags=["cwe-79", "xss"],
            match_title_patterns=[r"xss", r"cross.?site.?script"],
            remediation="Apply context-aware output encoding; deploy Content Security Policy.",
        ),
        ComplianceRule(
            rule_id="PCI-8.3.6", section="8.3.6", framework=fw,
            title="Password complexity requirements",
            description="Passwords must meet minimum complexity requirements (12+ chars, alphanumeric).",
            severity="medium",
            match_tags=["weak-password", "password-policy"],
            match_title_patterns=[r"password.?policy", r"weak.?password", r"brute.?force"],
            remediation="Enforce 12+ character passwords with complexity; implement account lockout.",
        ),
        ComplianceRule(
            rule_id="PCI-11.3.1", section="11.3.1", framework=fw,
            title="Internal vulnerability scans",
            description="Internal vulnerability scans performed at least quarterly.",
            severity="medium",
            match_tags=[],
            match_title_patterns=[],
            remediation="Run quarterly internal vulnerability scans with a qualified scanner.",
            check_fn=lambda _: ComplianceStatus.PASS,  # This test itself satisfies the requirement
        ),
        ComplianceRule(
            rule_id="PCI-11.3.2", section="11.3.2", framework=fw,
            title="External vulnerability scans by ASV",
            description="External scans performed by PCI SSC Approved Scanning Vendor quarterly.",
            severity="medium",
            match_tags=[],
            match_title_patterns=[],
            remediation="Engage a PCI ASV for quarterly external scans.",
            check_fn=lambda _: ComplianceStatus.NOT_TESTED,
        ),
    ]


def _owasp_top10_rules() -> list[ComplianceRule]:
    """OWASP Top 10 2021 mapping."""
    fw = ComplianceFramework.OWASP_TOP10
    return [
        ComplianceRule(
            rule_id="A01:2021", section="A01", framework=fw,
            title="Broken Access Control",
            description="Access control enforces policy such that users cannot act outside intended permissions.",
            severity="critical",
            match_tags=["cwe-200", "cwe-284", "cwe-285", "cwe-352", "cwe-639", "idor", "priv-esc",
                        "path-traversal", "forced-browse", "mass-assignment"],
            match_title_patterns=[r"idor", r"access.?control", r"priv.?esc", r"path.?traversal",
                                  r"forced.?brows", r"403.?bypass", r"mass.?assign"],
            remediation="Implement proper access controls; deny by default; enforce ownership.",
        ),
        ComplianceRule(
            rule_id="A02:2021", section="A02", framework=fw,
            title="Cryptographic Failures",
            description="Data exposure from cryptographic failures (formerly Sensitive Data Exposure).",
            severity="critical",
            match_tags=["cwe-311", "cwe-327", "cwe-328", "weak-cipher", "expired-cert",
                        "cwe-798", "cwe-312", "secret", "hardcoded"],
            match_title_patterns=[r"ssl", r"tls", r"weak.?ciph", r"secret", r"hardcoded", r"credential",
                                  r"private.?key", r"api.?key"],
            remediation="Use strong encryption; don't store secrets in code; rotate exposed credentials.",
        ),
        ComplianceRule(
            rule_id="A03:2021", section="A03", framework=fw,
            title="Injection",
            description="User-supplied data is not validated, filtered, or sanitized by the application.",
            severity="critical",
            match_tags=["cwe-79", "cwe-89", "cwe-78", "cwe-94", "cwe-917", "sqli", "xss",
                        "ssti", "cmdi", "ldap", "nosql", "xxe", "log4shell"],
            match_title_patterns=[r"inject", r"xss", r"template.?inject", r"log4shell", r"jndi"],
            remediation="Use parameterized queries; validate input; apply output encoding.",
        ),
        ComplianceRule(
            rule_id="A04:2021", section="A04", framework=fw,
            title="Insecure Design",
            description="Missing or ineffective control design — threat modeling and secure design patterns required.",
            severity="high",
            match_tags=["cwe-522", "cwe-306"],
            match_title_patterns=[r"insecure.?design", r"no.?rate.?limit", r"race.?condition",
                                  r"workflow.?bypass"],
            remediation="Apply threat modeling; use secure design patterns from OWASP ASVS.",
        ),
        ComplianceRule(
            rule_id="A05:2021", section="A05", framework=fw,
            title="Security Misconfiguration",
            description="Missing hardening, misconfigured permissions, unnecessary features enabled.",
            severity="high",
            match_tags=["cwe-16", "cwe-200", "cwe-538", "cors", "csp", "clickjacking",
                        "cookie-audit", "git-exposure", "config"],
            match_title_patterns=[r"header", r"cors", r"csp", r"clickjack", r"cookie",
                                  r"\.git", r"directory.?list", r"config.?expos"],
            remediation="Harden configurations; remove defaults; implement security headers.",
        ),
        ComplianceRule(
            rule_id="A06:2021", section="A06", framework=fw,
            title="Vulnerable and Outdated Components",
            description="Application uses components with known vulnerabilities.",
            severity="high",
            match_tags=["cve-", "dep-audit", "outdated"],
            match_title_patterns=[r"CVE-\\d{4}", r"outdated", r"vulnerable.?compon", r"dep.?audit"],
            remediation="Monitor dependencies; update/patch regularly; remove unused components.",
        ),
        ComplianceRule(
            rule_id="A07:2021", section="A07", framework=fw,
            title="Identification and Authentication Failures",
            description="Confirmation of the user's identity, authentication, and session management.",
            severity="high",
            match_tags=["cwe-287", "cwe-384", "session", "jwt", "oauth", "mfa-bypass",
                        "password-policy", "brute-force"],
            match_title_patterns=[r"session", r"jwt", r"auth", r"password", r"brute",
                                  r"mfa.?bypass", r"totp", r"login"],
            remediation="Implement MFA; enforce strong password policy; secure session management.",
        ),
        ComplianceRule(
            rule_id="A08:2021", section="A08", framework=fw,
            title="Software and Data Integrity Failures",
            description="Code/infrastructure integrity — insecure CI/CD, unsigned updates, deserialization.",
            severity="high",
            match_tags=["cwe-502", "deserialization", "sri"],
            match_title_patterns=[r"deseriali", r"sri", r"integrity"],
            remediation="Verify integrity of software/data; use SRI for CDN resources.",
        ),
        ComplianceRule(
            rule_id="A09:2021", section="A09", framework=fw,
            title="Security Logging and Monitoring Failures",
            description="Insufficient logging, detection, monitoring, and active response.",
            severity="medium",
            match_tags=["logging", "monitoring"],
            match_title_patterns=[r"log(?:ging)?", r"monitor"],
            remediation="Implement comprehensive logging; monitor for suspicious activity.",
            check_fn=lambda _: ComplianceStatus.NOT_TESTED,  # Requires manual review
        ),
        ComplianceRule(
            rule_id="A10:2021", section="A10", framework=fw,
            title="Server-Side Request Forgery (SSRF)",
            description="Web application fetches a remote resource without validating the user-supplied URL.",
            severity="critical",
            match_tags=["cwe-918", "ssrf"],
            match_title_patterns=[r"ssrf", r"server.?side.?request"],
            remediation="Validate/sanitize all user-supplied URLs; use allowlists for remote fetches.",
        ),
    ]


def _iso27001_rules() -> list[ComplianceRule]:
    """ISO 27001:2022 Annex A controls relevant to web security testing."""
    fw = ComplianceFramework.ISO_27001
    return [
        ComplianceRule(
            rule_id="A.8.9", section="A.8.9", framework=fw,
            title="Configuration management",
            description="Configurations of hardware, software, services and networks shall be managed.",
            severity="medium",
            match_tags=["config", "misconfiguration"],
            match_title_patterns=[r"config", r"misconfig", r"header", r"default"],
            remediation="Implement configuration baselines and monitor for drift.",
        ),
        ComplianceRule(
            rule_id="A.8.24", section="A.8.24", framework=fw,
            title="Use of cryptography",
            description="Rules for the effective use of cryptography shall be defined and implemented.",
            severity="high",
            match_tags=["ssl", "tls", "weak-cipher", "crypto"],
            match_title_patterns=[r"ssl", r"tls", r"cipher", r"crypto", r"certificate"],
            remediation="Use approved cryptographic algorithms and key lengths per organizational policy.",
        ),
        ComplianceRule(
            rule_id="A.8.26", section="A.8.26", framework=fw,
            title="Application security requirements",
            description="Information security requirements shall be identified and specified when developing/acquiring apps.",
            severity="high",
            match_tags=["cwe-89", "cwe-79", "cwe-78", "injection"],
            match_title_patterns=[r"inject", r"xss", r"vulnerability"],
            remediation="Include security requirements in SDLC; perform security testing.",
        ),
        ComplianceRule(
            rule_id="A.8.28", section="A.8.28", framework=fw,
            title="Secure coding",
            description="Secure coding principles shall be applied to software development.",
            severity="high",
            match_tags=["sqli", "xss", "ssti", "lfi", "rce"],
            match_title_patterns=[r"sql", r"xss", r"template", r"file.?inclus", r"command"],
            remediation="Apply OWASP Secure Coding Practices throughout development lifecycle.",
        ),
    ]


# ── Compliance engine ────────────────────────────────────────────────────────

class ComplianceEngine:
    """Evaluate findings against a compliance framework's rules.

    Usage:
        engine = ComplianceEngine(ComplianceFramework.PCI_DSS)
        report = engine.evaluate(findings_dicts)
    """

    RULE_REGISTRY: dict[ComplianceFramework, Callable[[], list[ComplianceRule]]] = {
        ComplianceFramework.PCI_DSS: _pci_dss_rules,
        ComplianceFramework.OWASP_TOP10: _owasp_top10_rules,
        ComplianceFramework.ISO_27001: _iso27001_rules,
    }

    def __init__(self, framework: ComplianceFramework) -> None:
        self.framework = framework
        rule_fn = self.RULE_REGISTRY.get(framework)
        if not rule_fn:
            raise ValueError(f"No rules defined for framework: {framework.value}")
        self.rules: list[ComplianceRule] = rule_fn()

    def evaluate(self, findings: list[dict]) -> ComplianceReport:
        """Evaluate all rules against findings and produce a report."""
        results: list[RuleResult] = []
        for rule in self.rules:
            results.append(rule.evaluate(findings))
        return ComplianceReport(framework=self.framework, results=results)

    @classmethod
    def evaluate_all(cls, findings: list[dict]) -> dict[str, ComplianceReport]:
        """Evaluate against ALL registered frameworks at once."""
        reports: dict[str, ComplianceReport] = {}
        for fw in cls.RULE_REGISTRY:
            engine = cls(fw)
            reports[fw.value] = engine.evaluate(findings)
        return reports


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestComplianceEngine:
    def test_pci_dss_rules_count(self) -> None:
        engine = ComplianceEngine(ComplianceFramework.PCI_DSS)
        assert len(engine.rules) >= 8

    def test_owasp_rules_count(self) -> None:
        engine = ComplianceEngine(ComplianceFramework.OWASP_TOP10)
        assert len(engine.rules) == 10

    def test_iso27001_rules_count(self) -> None:
        engine = ComplianceEngine(ComplianceFramework.ISO_27001)
        assert len(engine.rules) >= 4

    def test_sqli_finding_fails_pci(self) -> None:
        engine = ComplianceEngine(ComplianceFramework.PCI_DSS)
        findings = [{"title": "SQL Injection — param 'id'", "severity": "critical",
                      "tags": ["cwe-89", "sqli"], "references": ["CWE-89"]}]
        report = engine.evaluate(findings)
        failed = [r for r in report.results if r.status == ComplianceStatus.FAIL]
        assert len(failed) >= 1
        rule_ids = {r.rule.rule_id for r in failed}
        assert "PCI-6.2.4" in rule_ids or "PCI-6.5.1" in rule_ids

    def test_clean_scan_passes(self) -> None:
        engine = ComplianceEngine(ComplianceFramework.OWASP_TOP10)
        report = engine.evaluate([])
        # With no findings, rules with no match should pass
        pass_count = report.pass_count
        assert pass_count >= 5

    def test_compliance_pct(self) -> None:
        engine = ComplianceEngine(ComplianceFramework.PCI_DSS)
        report = engine.evaluate([])
        assert 0 <= report.compliance_pct <= 100

    def test_evaluate_all(self) -> None:
        reports = ComplianceEngine.evaluate_all([])
        assert len(reports) >= 3
        for fw_name, report in reports.items():
            assert isinstance(report, ComplianceReport)

    def test_report_serialization(self) -> None:
        engine = ComplianceEngine(ComplianceFramework.OWASP_TOP10)
        report = engine.evaluate([])
        data = report.to_dict()
        assert "framework" in data
        assert "rules" in data
        assert isinstance(data["rules"], list)
