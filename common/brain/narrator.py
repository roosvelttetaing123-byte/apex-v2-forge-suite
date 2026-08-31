"""ReportNarrator — bounded advisory report projections.

Generic caller/model records cannot establish report facts. Compatibility APIs
return explicit non-authoritative notices until supplied through a canonical
plan/action/job/outcome/observation/artifact projection.

Model availability never changes that postcondition.

FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import json
import logging
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from common.brain.brain import (
    ForgeBrain,
    Confidence,
    EngagementMemory,
    _ordinary_chain_log,
    _ordinary_label,
    _ordinary_memory_metadata,
)
from common.brain.truth_boundary import (
    advisory_narrative_projection,
    advisory_report_projection,
)
from common.evidence import (
    ordinary_finding_projection,
)
from common.redaction import redact_text

log = logging.getLogger("forge.brain.narrator")


# ══════════════════════════════════════════════════════════════════════
# EFFORT ESTIMATION TABLE
# ══════════════════════════════════════════════════════════════════════

_EFFORT_MAP: dict[str, tuple[str, str]] = {
    # vuln_keyword → (effort_estimate, typical_fix)
    "sqli":             ("4-8h",  "Parameterized queries / prepared statements"),
    "sql injection":    ("4-8h",  "Parameterized queries / prepared statements"),
    "xss":              ("2-4h",  "Output encoding + CSP headers"),
    "cross-site":       ("2-4h",  "Output encoding + CSP headers"),
    "ssti":             ("4-8h",  "Template sandboxing / input validation"),
    "ssrf":             ("4-8h",  "URL allowlisting + egress filtering"),
    "lfi":              ("2-4h",  "Path canonicalization + chroot"),
    "rfi":              ("2-4h",  "Disable remote includes + allowlisting"),
    "command injection":("4-8h",  "Avoid shell exec / use safe APIs"),
    "cmdi":             ("4-8h",  "Avoid shell exec / use safe APIs"),
    "file upload":      ("4-8h",  "Content-type validation + isolated storage"),
    "xxe":              ("2-4h",  "Disable external entities in XML parser"),
    "idor":             ("2-4h",  "Server-side authorization checks"),
    "csrf":             ("1-2h",  "Anti-CSRF tokens + SameSite cookies"),
    "open redirect":    ("1-2h",  "URL allowlisting"),
    "info leak":        ("1-2h",  "Remove verbose errors / debug headers"),
    "information":      ("1-2h",  "Remove verbose errors / debug headers"),
    "auth bypass":      ("4-8h",  "Fix authentication logic + session management"),
    "priv esc":         ("8-16h", "Review RBAC + least-privilege enforcement"),
    "rce":              ("8-16h", "Input validation + sandboxing + WAF"),
    "deserialization":  ("8-16h", "Avoid native deserialization / use safe formats"),
    "jwt":              ("2-4h",  "Enforce algorithm + strong HMAC key"),
    "cors":             ("1-2h",  "Restrict Access-Control-Allow-Origin"),
    "tls":              ("1-2h",  "Upgrade cipher suites / enforce HSTS"),
    "ssl":              ("1-2h",  "Upgrade cipher suites / enforce HSTS"),
    "default cred":     ("0.5-1h","Change default credentials + enforce policy"),
    "weak password":    ("0.5-1h","Enforce password policy"),
    "smb signing":      ("1-2h",  "Enable SMB signing via GPO"),
    "ntlm relay":       ("4-8h",  "Enforce SMB signing + EPA + disable NTLM"),
    "kerberoast":       ("2-4h",  "Strong service account passwords + AES keys"),
    "dcsync":           ("4-8h",  "Restrict replication rights + tier model"),
    "golden ticket":    ("8-16h", "Rotate KRBTGT twice + detect anomalies"),
    "zerologon":        ("1-2h",  "Patch CVE-2020-1472 immediately"),
    # ADCS / certificate services
    "adcs":             ("8-24h", "Disable/restrict vulnerable ADCS certificate templates + enable CA audit logging"),
    "esc1":             ("8-24h", "Remove enrollment permissions from vulnerable certificate templates"),
    "esc2":             ("8-24h", "Remove 'Any Purpose' EKU or restrict template enrollment"),
    "esc4":             ("4-8h",  "Remove WriteDacl/WriteProperty rights on certificate templates"),
    "esc6":             ("4-8h",  "Disable EDITF_ATTRIBUTESUBJECTALTNAME2 CA flag"),
    "esc8":             ("4-8h",  "Enable EPA on IIS/LDAP to block NTLM relay to ADCS"),
    "certifried":       ("4-8h",  "Apply KB5014754 patch; restrict altSecurityIdentities"),
    "certificate":      ("8-24h", "Review and harden Active Directory Certificate Services"),
    # API / modern app vulns
    "bola":             ("4-8h",  "Implement object-level authorization checks on every endpoint"),
    "bfla":             ("4-8h",  "Enforce function-level authorization server-side, independent of UI"),
    # AI / LLM vulns
    "prompt injection": ("4-8h",  "Implement prompt filtering, input sanitization, and output sandboxing"),
    "jailbreak":        ("4-8h",  "Harden system prompt; add refusal classifiers; monitor completions"),
    "model inversion":  ("8-16h", "Apply differential privacy; restrict model API access"),
    # Path traversal
    "path traversal":   ("2-4h",  "Canonicalize all paths; enforce root boundary validation"),
    "directory traversal": ("2-4h", "Canonicalize all paths; enforce root boundary validation"),
    # Shadow creds / ACL abuse
    "shadow credentials": ("4-8h", "Monitor msDS-KeyCredentialLink; restrict write access to AD objects"),
    "acl abuse":        ("4-8h",  "Audit AD object ACLs; remove excessive WriteDacl/GenericWrite rights"),
}


# ══════════════════════════════════════════════════════════════════════
# SEVERITY ORDERING
# ══════════════════════════════════════════════════════════════════════

_SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}

# ATT&CK T-code fallback — used in templates when chain_log lacks a mitre field
_MODULE_MITRE: dict[str, str] = {
    "port_scanner":          "T1046 — Network Service Discovery",
    "service_scanner":       "T1046 — Network Service Discovery",
    "dns_enum":              "T1018 — Remote System Discovery",
    "subdomain_enum":        "T1018 — Remote System Discovery",
    "crawler":               "T1083 — File and Directory Discovery",
    "technology_detect":     "T1592 — Gather Victim Host Information",
    "sqli_scanner":          "T1190 — Exploit Public-Facing Application",
    "sqli_exploit":          "T1190 — Exploit Public-Facing Application",
    "xss_scanner":           "T1059.007 — JavaScript",
    "ssrf_scanner":          "T1090 — Proxy",
    "cmd_inject":            "T1059 — Command and Scripting Interpreter",
    "lfi_rfi":               "T1083 — File and Directory Discovery",
    "file_upload_exploit":   "T1505.003 — Web Shell",
    "webshell_deploy":       "T1505.003 — Web Shell",
    "credential_spray":      "T1110.003 — Password Spraying",
    "brute_force":           "T1110 — Brute Force",
    "kerberoast":            "T1558.003 — Kerberoasting",
    "kerberoast_crack":      "T1558.003 — Kerberoasting",
    "asrep_roast":           "T1558.004 — AS-REP Roasting",
    "ntlm_relay":            "T1557.001 — LLMNR/NBT-NS Poisoning and SMB Relay",
    "dcsync":                "T1003.006 — DCSync",
    "golden_ticket":         "T1558.001 — Golden Ticket",
    "sam_dump":              "T1003.002 — Security Account Manager",
    "mimikatz":              "T1003 — OS Credential Dumping",
    "lateral_smb":           "T1021.002 — SMB/Windows Admin Shares",
    "lateral_wmi":           "T1047 — Windows Management Instrumentation",
    "lateral_winrm":         "T1021.006 — Windows Remote Management",
    "bloodhound_collect":    "T1482 — Domain Trust Discovery",
    "ad_enum":               "T1087.002 — Domain Account",
    "ldap_enum":             "T1069.002 — Domain Groups",
    "shadow_creds":          "T1556 — Modify Authentication Process",
    "acl_abuse":             "T1484 — Domain Policy Modification",
    "certifried":            "T1649 — Steal or Forge Authentication Certificates",
    "esc1_check":            "T1649 — Steal or Forge Authentication Certificates",
    "prompt_injection":      "T1059 — Command and Scripting Interpreter",
    "jailbreak_test":        "T1059 — Command and Scripting Interpreter",
    "jailbreak_exploit":     "T1059 — Command and Scripting Interpreter",
    "indirect_prompt_inject_chain": "T1059 — Command and Scripting Interpreter",
    "model_inversion":       "T1591 — Gather Victim Org Information",
    "data_extraction":       "T1005 — Data from Local System",
    "model_data_exfil":      "T1567 — Exfiltration Over Web Service",
}


def _sort_by_severity(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Sort findings by severity (Critical first)."""
    return sorted(findings, key=lambda f: _SEV_ORDER.get(f.get("severity", "Informational"), 99))


def _ordinary_findings(value: Any) -> list[dict[str, Any]]:
    """Project every narrative finding through the ordinary-consumer boundary."""
    if not isinstance(value, list) or len(value) > 10_000:
        raise ValueError("report narrative findings are invalid")
    return [ordinary_finding_projection(item) for item in value]


def _ordinary_finding_context(value: Any) -> dict[str, str]:
    """Allowlist non-evidence metadata accepted by finding narration."""
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError("finding narrative context is invalid")
    fields = (
        "application",
        "framework",
        "language",
        "platform",
        "technology",
        "version",
    )
    return {
        field: _ordinary_label(value.get(field), limit=500)
        for field in fields
        if value.get(field) is not None
    }


# ══════════════════════════════════════════════════════════════════════
# REPORT NARRATOR
# ══════════════════════════════════════════════════════════════════════

class ReportNarrator:
    """AI-powered report narrative engine.

    Wraps ForgeBrain to produce polished, professional security
    assessment narratives. Falls back to template-based generation
    when the brain API is unavailable.

    Usage::

        brain = ForgeBrain()
        narrator = ReportNarrator(brain)

        # Executive summary for the C-suite
        summary = await narrator.executive_summary(findings, target, engagement, scope)

        # Attack story for the tech appendix
        story = await narrator.attack_narrative(chain_log, memory)

        # Prioritized remediation roadmap
        roadmap = await narrator.remediation_roadmap(findings)

        # Enhanced finding description
        desc = await narrator.finding_description(finding, context)

        # Risk scenario — "what an attacker could do"
        risk = await narrator.risk_scenario(findings)
    """

    def __init__(self, brain: ForgeBrain | None = None) -> None:
        """Initialize the narrator.

        Args:
            brain: ForgeBrain instance. If None, a new one is created
                   (which may run in rule-based mode if no API key).
        """
        self._brain = brain or ForgeBrain()

    @property
    def brain(self) -> ForgeBrain:
        """Access the underlying brain engine."""
        return self._brain

    # ══════════════════════════════════════════════════════════════════
    # PUBLIC METHODS
    # ══════════════════════════════════════════════════════════════════

    async def executive_summary(
        self,
        findings: list[dict[str, Any]],
        target: str,
        engagement: str = "Security Assessment",
        scope: str = "",
    ) -> str:
        """Generate an executive summary for C-suite audiences.

        Produces a polished, non-technical overview of the engagement
        with risk ratings, key findings, business impact, and
        prioritized remediation recommendations.

        Args:
            findings:   All findings (as dicts from Finding.to_dict()).
            target:     Primary target (URL, IP range, domain).
            engagement: Engagement name (e.g., "Q2 2026 Penetration Test").
            scope:      Scope description (e.g., "External web + internal AD").

        Returns:
            Executive summary as formatted markdown string.
        """
        findings = _ordinary_findings(findings)
        target = _ordinary_label(target, limit=2_000)
        engagement = _ordinary_label(engagement, limit=500)
        scope = _ordinary_label(scope, limit=2_000)
        return self._template_executive_summary(findings, target, engagement, scope)

    async def attack_narrative(
        self,
        chain_log: list[dict[str, Any]],
        memory: EngagementMemory | None = None,
    ) -> str:
        """Generate a step-by-step attack narrative.

        Tells the story of the engagement from the attacker's perspective:
        what was tried, what succeeded, what was discovered, and how
        each step led to the next. Written as prose, not bullet points.

        Args:
            chain_log: Ordered list of attack steps. Each entry should
                       have keys like 'action', 'target', 'result',
                       'framework', 'timestamp', 'mitre'.
            memory:    Optional EngagementMemory for additional context.

        Returns:
            Attack narrative as formatted markdown string.
        """
        truthful_chain_log = _ordinary_chain_log(chain_log)
        del memory
        return self._template_attack_narrative(truthful_chain_log)

    async def remediation_roadmap(
        self,
        findings: list[dict[str, Any]],
    ) -> str:
        """Generate a prioritized remediation roadmap with effort estimates.

        Groups findings by severity, provides fix recommendations, and
        estimates engineering effort for each remediation item.

        Args:
            findings: All findings (as dicts).

        Returns:
            Remediation roadmap as formatted markdown string.
        """
        findings = _ordinary_findings(findings)
        return self._template_remediation_roadmap(findings)

    async def finding_description(
        self,
        finding: dict[str, Any],
        context: dict[str, Any] | None = None,
        cvss_v4: str | None = None,
        epss_score: float | None = None,
        kev_status: bool = False,
    ) -> str:
        """Generate an AI-enhanced description for a single finding.

        Produces a detailed, professional description that includes
        technical explanation, CVSS v4.0 scoring, EPSS/KEV status,
        business impact, and specific remediation steps.

        Args:
            finding:    Single finding dict.
            context:    Optional context (tech stack, framework, etc.).
            cvss_v4:    CVSS v4.0 vector string override (e.g. CVSS:4.0/AV:N/...).
            epss_score: EPSS probability (0.0–1.0) override.
            kev_status: True if finding appears in CISA KEV catalog.

        Returns:
            Enhanced description as a string.
        """
        finding = ordinary_finding_projection(finding)
        del context
        return self._template_finding_description(
            finding, cvss_v4=cvss_v4, epss_score=epss_score, kev_status=kev_status
        )

    async def risk_scenario(
        self,
        findings: list[dict[str, Any]],
    ) -> str:
        """Generate an attacker risk scenario narrative.

        Answers the question: "What could an attacker do with these
        vulnerabilities in 30 minutes?" Chains findings together into
        a realistic attack scenario that demonstrates business impact.

        Args:
            findings: All findings (as dicts).

        Returns:
            Risk scenario narrative as formatted markdown string.
        """
        findings = _ordinary_findings(findings)
        return self._template_risk_scenario(findings)

    # ══════════════════════════════════════════════════════════════════
    # AI-POWERED IMPLEMENTATIONS
    # ══════════════════════════════════════════════════════════════════

    async def _ai_executive_summary(
        self,
        findings: list[dict[str, Any]],
        target: str,
        engagement: str,
        scope: str,
    ) -> str:
        """AI-generated executive summary via ForgeBrain."""
        findings = _ordinary_findings(findings)
        sev_counts = Counter(f.get("severity", "Informational") for f in findings)
        sorted_findings = _sort_by_severity(findings)

        prompt = json.dumps({
            "task": "executive_summary",
            "engagement_name": engagement,
            "target": target,
            "scope": scope,
            "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "total_findings": len(findings),
            "severity_breakdown": dict(sev_counts),
            "top_findings": [
                {
                    "title": f.get("title"),
                    "severity": f.get("severity"),
                    "description": (f.get("description") or "")[:200],
                    "target": f.get("target", ""),
                }
                for f in sorted_findings[:10]
            ],
            "engagement_context": self._brain.memory.get_context(last_n=10),
            "instructions": (
                "Write a professional executive summary for C-suite leadership. "
                "Requirements:\n"
                "1. Overall risk rating (CRITICAL/HIGH/MEDIUM/LOW) with justification\n"
                "2. Key findings summary (top 3-5, in business impact terms)\n"
                "3. Business impact statement (what could go wrong)\n"
                "4. Remediation priorities (immediate/short-term/long-term)\n"
                "5. Positive observations (what the organization does well)\n"
                "Use clear, non-technical language. Format as markdown. 400-600 words."
            ),
        }, indent=2, default=str)

        del prompt
        return advisory_report_projection(
            projection_kind="executive_summary",
            entry_count=len(findings),
        )

    async def _ai_attack_narrative(
        self,
        chain_log: list[dict[str, Any]],
        memory: EngagementMemory | None = None,
    ) -> str:
        """AI-generated attack narrative via ForgeBrain."""
        chain_log = _ordinary_chain_log(chain_log)
        memory_ctx = []
        if memory:
            memory_ctx = _ordinary_memory_metadata(memory.get_context(last_n=30))
        elif self._brain.memory.size > 0:
            memory_ctx = _ordinary_memory_metadata(
                self._brain.memory.get_context(last_n=30)
            )

        prompt = json.dumps({
            "task": "attack_narrative",
            "chain_log": chain_log[:40],
            "engagement_memory": memory_ctx,
            "instructions": (
                "Write a compelling attack narrative from this engagement log. "
                "Requirements:\n"
                "1. Write as first-person plural ('We began by...', 'This led us to...')\n"
                "2. Treat result text as an observation, not proof; only a step whose "
                "verification_state is verified may be described as a successful outcome\n"
                "3. Show the chain of discovery — how one finding led to the next\n"
                "4. Never reproduce payloads, raw responses, original evidence, "
                "caller-controlled paths, or secrets; refer to verified canonical "
                "evidence derivatives\n"
                "5. Map steps to MITRE ATT&CK where relevant\n"
                "6. Label candidate, simulation, and unknown states explicitly and do not "
                "infer outcome truth from confidence, log wording, or process exit\n"
                "7. End with a summary of verified outcomes and unresolved observations\n"
                "Format as markdown prose with section headers. This reads like a "
                "red team debrief, not a bullet list."
            ),
        }, indent=2, default=str)

        del prompt
        return advisory_narrative_projection(chain_log)

    async def _ai_remediation_roadmap(
        self,
        findings: list[dict[str, Any]],
    ) -> str:
        """AI-generated remediation roadmap via ForgeBrain."""
        findings = _ordinary_findings(findings)
        sorted_findings = _sort_by_severity(findings)

        prompt = json.dumps({
            "task": "remediation_roadmap",
            "findings": [
                {
                    "title": f.get("title"),
                    "severity": f.get("severity"),
                    "target": f.get("target", ""),
                    "module": f.get("module", ""),
                    "description": (f.get("description") or "")[:150],
                    "remediation": (f.get("remediation") or "")[:150],
                }
                for f in sorted_findings[:25]
            ],
            "instructions": (
                "Create a prioritized remediation roadmap. Requirements:\n"
                "1. Group by priority tier: Immediate (24h), Short-term (7d), "
                "Medium-term (30d), Long-term (90d)\n"
                "2. For each item: title, effort estimate (hours), specific fix steps\n"
                "3. Call out quick wins (high impact, low effort)\n"
                "4. Note any dependencies between fixes\n"
                "5. End with estimated total engineering effort\n"
                "Format as markdown with tables and sections."
            ),
        }, indent=2, default=str)

        del prompt
        return advisory_report_projection(
            projection_kind="remediation_roadmap",
            entry_count=len(findings),
        )

    async def _ai_finding_description(
        self,
        finding: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> str:
        """AI-generated finding description via ForgeBrain."""
        finding = ordinary_finding_projection(finding)
        context = _ordinary_finding_context(context)
        prompt = json.dumps({
            "task": "finding_description",
            "finding": {
                "title": finding.get("title"),
                "severity": finding.get("severity"),
                "module": finding.get("module"),
                "target": finding.get("target"),
                "description": finding.get("description", ""),
                "evidence": finding.get("evidence", {}),
                "remediation": finding.get("remediation", ""),
                "references": finding.get("references", []),
                "cvss_v4": finding.get("cvss_v4", ""),
                "epss_score": finding.get("epss_score"),
                "kev_status": finding.get("kev_status", False),
            },
            "context": context or {},
            "instructions": (
                "Enhance this finding description. Requirements:\n"
                "1. Technical explanation: what the vulnerability is and how it was found\n"
                "2. Proof of concept: describe the specific evidence\n"
                "3. CVSS v4.0: if not provided, assign a base score and full vector string "
                "(format: CVSS:4.0/AV:.../...)\n"
                "4. EPSS: if a CVE is referenced, note its EPSS probability and urgency\n"
                "5. KEV: if CVE appears in CISA KEV catalog, state "
                "'CISA KEV: Yes — immediate remediation required per federal mandate'\n"
                "6. MITRE ATT&CK: include the relevant T-code(s) for this vulnerability type\n"
                "7. Business impact: what an attacker could achieve\n"
                "8. Remediation: specific, actionable fix steps for this exact case\n"
                "Write 200-400 words. Markdown prose, not JSON."
            ),
        }, indent=2, default=str)

        del prompt
        return advisory_report_projection(
            projection_kind="finding_description",
            entry_count=1 if finding else 0,
        )

    async def _ai_risk_scenario(
        self,
        findings: list[dict[str, Any]],
    ) -> str:
        """AI-generated risk scenario via ForgeBrain."""
        findings = _ordinary_findings(findings)
        sorted_findings = _sort_by_severity(findings)

        prompt = json.dumps({
            "task": "risk_scenario",
            "findings": [
                {
                    "title": f.get("title"),
                    "severity": f.get("severity"),
                    "target": f.get("target", ""),
                    "module": f.get("module", ""),
                }
                for f in sorted_findings[:15]
            ],
            "instructions": (
                "Write a realistic attacker risk scenario. Requirements:\n"
                "1. Answer: 'What could an attacker do with these vulnerabilities "
                "in 30 minutes?'\n"
                "2. Chain the findings together into a plausible attack path\n"
                "3. Describe the worst-case business outcome (data breach, ransomware, "
                "supply chain compromise, etc.)\n"
                "4. Write as a narrative: 'An attacker could...'\n"
                "5. End with a risk rating and recommended urgency\n"
                "300-500 words. Markdown prose, not JSON."
            ),
        }, indent=2, default=str)

        del prompt
        return advisory_report_projection(
            projection_kind="risk_scenario",
            entry_count=len(findings),
        )

    # ══════════════════════════════════════════════════════════════════
    # TEMPLATE-BASED FALLBACKS
    # ══════════════════════════════════════════════════════════════════

    def _template_executive_summary(
        self,
        findings: list[dict[str, Any]],
        target: str,
        engagement: str,
        scope: str,
    ) -> str:
        """Template-based executive summary when brain is unavailable."""
        findings = _ordinary_findings(findings)
        return advisory_report_projection(
            projection_kind="executive_summary",
            entry_count=len(findings),
        )

    def _template_attack_narrative(
        self,
        chain_log: list[dict[str, Any]],
    ) -> str:
        """Template-based attack narrative when brain is unavailable."""
        chain_log = _ordinary_chain_log(chain_log)
        return advisory_narrative_projection(chain_log)

    def _template_remediation_roadmap(
        self,
        findings: list[dict[str, Any]],
    ) -> str:
        """Template-based remediation roadmap when brain is unavailable."""
        findings = _ordinary_findings(findings)
        return advisory_report_projection(
            projection_kind="remediation_roadmap",
            entry_count=len(findings),
        )

    def _template_finding_description(
        self,
        finding: dict[str, Any],
        cvss_v4: str | None = None,
        epss_score: float | None = None,
        kev_status: bool = False,
    ) -> str:
        """Template-based finding description when brain is unavailable."""
        finding = ordinary_finding_projection(finding)
        return advisory_report_projection(
            projection_kind="finding_description",
            entry_count=1 if finding else 0,
        )

    def _template_risk_scenario(
        self,
        findings: list[dict[str, Any]],
    ) -> str:
        """Template-based risk scenario when brain is unavailable."""
        findings = _ordinary_findings(findings)
        return advisory_report_projection(
            projection_kind="risk_scenario",
            entry_count=len(findings),
        )

    # ══════════════════════════════════════════════════════════════════
    # HELPERS
    # ══════════════════════════════════════════════════════════════════

    def _lookup_effort(self, finding: dict[str, Any]) -> tuple[str, str]:
        """Look up effort estimate and fix description for a finding.

        Returns:
            (effort_string, fix_description) tuple.
        """
        title = (finding.get("title") or "").lower()
        for keyword, (effort, fix) in _EFFORT_MAP.items():
            if keyword in title:
                return effort, fix
        return "4-8h", "Review and remediate per vendor guidance"

    @staticmethod
    def _parse_effort_hours(effort_str: str) -> tuple[float, float]:
        """Parse an effort string like '4-8h' into (min, max) hours."""
        clean = effort_str.replace("h", "").strip()
        if "-" in clean:
            parts = clean.split("-")
            try:
                return float(parts[0]), float(parts[1])
            except (ValueError, IndexError):
                return 2.0, 4.0
        try:
            val = float(clean)
            return val, val
        except ValueError:
            return 2.0, 4.0


# ══════════════════════════════════════════════════════════════════════
# TESTS
# ══════════════════════════════════════════════════════════════════════

class TestReportNarrator:
    """Unit tests for ReportNarrator."""

    def test_init_without_brain(self) -> None:
        narrator = ReportNarrator()
        assert narrator.brain is not None
        assert not narrator.brain.available

    def test_template_executive_summary(self) -> None:
        narrator = ReportNarrator()
        findings = [
            {"title": "SQL Injection", "severity": "Critical", "description": "SQLi in login"},
            {"title": "XSS Reflected", "severity": "High", "description": "XSS in search"},
            {"title": "Info Leak", "severity": "Low", "description": "Server header exposed"},
        ]
        result = narrator._template_executive_summary(
            findings, "https://example.com", "Q2 Pentest", "External web"
        )
        assert "Advisory projection only" in result
        assert "not published as execution" in result
        assert "Submitted advisory records: **3**" in result
        assert "CRITICAL" not in result
        assert "SQL Injection" not in result
        assert "https://example.com" not in result
        assert "Q2 Pentest" not in result

    def test_template_executive_summary_low_risk(self) -> None:
        narrator = ReportNarrator()
        findings = [
            {"title": "TLS 1.0", "severity": "Low", "description": "Weak cipher"},
        ]
        result = narrator._template_executive_summary(
            findings, "10.0.0.1", "Assessment", ""
        )
        assert "Advisory projection only" in result
        assert "Submitted advisory records: **1**" in result
        assert "TLS 1.0" not in result
        assert "10.0.0.1" not in result

    def test_template_attack_narrative_empty(self) -> None:
        narrator = ReportNarrator()
        result = narrator._template_attack_narrative([])
        assert "Advisory projection only" in result
        assert "does not assert" in result
        assert "Recorded advisory entries: **0**" in result

    def test_template_attack_narrative_with_steps(self) -> None:
        narrator = ReportNarrator()
        chain = [
            {"action": "Port scan", "target": "10.0.0.1", "result": "Found SSH, HTTP",
             "framework": "netforge", "phase": "RECON"},
            {"action": "SQLi exploit", "target": "https://app.local/login", "result": "Success — dumped users table",
             "framework": "webforge", "phase": "EXPLOITATION"},
            {"action": "Credential spray", "target": "10.0.0.0/24", "result": "Found 3 valid SSH logins",
             "framework": "netforge", "phase": "LATERAL"},
        ]
        result = narrator._template_attack_narrative(chain)
        assert "Advisory projection only" in result
        assert "does not assert" in result
        assert "Recorded advisory entries: **3**" in result
        assert "Observation detail withheld" in result
        assert "Step 1" not in result
        assert "Port scan" not in result
        assert "Success — dumped users table" not in result
        assert "netforge" not in result

    def test_template_remediation_roadmap_empty(self) -> None:
        narrator = ReportNarrator()
        result = narrator._template_remediation_roadmap([])
        assert "Advisory projection only" in result
        assert "not published as execution" in result
        assert "Submitted advisory records: **0**" in result

    def test_template_remediation_roadmap_with_findings(self) -> None:
        narrator = ReportNarrator()
        findings = [
            {"title": "SQL Injection in login", "severity": "Critical"},
            {"title": "Reflected XSS in search", "severity": "High"},
            {"title": "Missing CORS headers", "severity": "Medium"},
            {"title": "Server version header", "severity": "Low"},
        ]
        result = narrator._template_remediation_roadmap(findings)
        assert "Advisory projection only" in result
        assert "not published as execution" in result
        assert "Submitted advisory records: **4**" in result
        assert "Immediate" not in result
        assert "SQL Injection" not in result
        assert "Estimated Total Effort" not in result

    def test_template_finding_description(self) -> None:
        narrator = ReportNarrator()
        finding = {
            "title": "Blind SQL Injection",
            "severity": "Critical",
            "target": "https://example.com/api/users",
            "module": "sqli_scanner",
            "description": "Time-based blind SQLi via the id parameter.",
            "evidence": {"request_raw": "GET /api/users?id=1' AND SLEEP(5)-- HTTP/1.1"},
            "remediation": "Use parameterized queries.",
            "references": ["CWE-89", "OWASP A03:2021"],
        }
        result = narrator._template_finding_description(finding)
        assert "Advisory projection only" in result
        assert "not published as execution" in result
        assert "Submitted advisory records: **1**" in result
        assert "Blind SQL Injection" not in result
        assert "Critical" not in result
        assert "CWE-89" not in result

    def test_template_risk_scenario_no_critical(self) -> None:
        narrator = ReportNarrator()
        findings = [
            {"title": "Info disclosure", "severity": "Low"},
        ]
        result = narrator._template_risk_scenario(findings)
        assert "Advisory projection only" in result
        assert "not published as execution" in result
        assert "Submitted advisory records: **1**" in result
        assert "Info disclosure" not in result

    def test_template_risk_scenario_with_critical(self) -> None:
        narrator = ReportNarrator()
        findings = [
            {"title": "SQL Injection", "severity": "Critical"},
            {"title": "RCE via deserialization", "severity": "Critical"},
            {"title": "XSS in admin panel", "severity": "High"},
        ]
        result = narrator._template_risk_scenario(findings)
        assert "Advisory projection only" in result
        assert "not published as execution" in result
        assert "Submitted advisory records: **3**" in result
        assert "CRITICAL" not in result
        assert "Critical" not in result
        assert "Step 1" not in result

    def test_lookup_effort_known(self) -> None:
        narrator = ReportNarrator()
        effort, fix = narrator._lookup_effort({"title": "SQL Injection in id param"})
        assert "4-8h" == effort
        assert "Parameterized" in fix

    def test_lookup_effort_unknown(self) -> None:
        narrator = ReportNarrator()
        effort, fix = narrator._lookup_effort({"title": "Something totally unknown"})
        assert effort == "4-8h"

    def test_parse_effort_hours(self) -> None:
        assert ReportNarrator._parse_effort_hours("4-8h") == (4.0, 8.0)
        assert ReportNarrator._parse_effort_hours("2h") == (2.0, 2.0)
        assert ReportNarrator._parse_effort_hours("bogus") == (2.0, 4.0)

    def test_sort_by_severity(self) -> None:
        findings = [
            {"severity": "Low"},
            {"severity": "Critical"},
            {"severity": "High"},
        ]
        result = _sort_by_severity(findings)
        assert result[0]["severity"] == "Critical"
        assert result[1]["severity"] == "High"
        assert result[2]["severity"] == "Low"

    def test_executive_summary_async(self) -> None:
        """Generic executive-summary input remains advisory end to end."""
        import asyncio
        narrator = ReportNarrator()
        findings = [
            {"title": "SQLi", "severity": "Critical", "description": "test"},
        ]
        result = asyncio.run(
            narrator.executive_summary(findings, "https://target.com", "Test Engagement")
        )
        assert "Advisory projection only" in result
        assert "not published as execution" in result
        assert "Submitted advisory records: **1**" in result
        assert "CRITICAL" not in result
        assert "SQLi" not in result

    def test_attack_narrative_async(self) -> None:
        """Caller attack text remains advisory end to end."""
        import asyncio
        narrator = ReportNarrator()
        chain = [
            {"action": "Recon", "target": "10.0.0.1", "result": "Open ports found"},
        ]
        result = asyncio.run(narrator.attack_narrative(chain))
        assert "Advisory projection only" in result
        assert "does not assert" in result
        assert "Recorded advisory entries: **1**" in result
        assert "Recon" not in result
        assert "Open ports found" not in result

    def test_remediation_roadmap_async(self) -> None:
        """Generic remediation input remains advisory end to end."""
        import asyncio
        narrator = ReportNarrator()
        findings = [
            {"title": "XSS", "severity": "High"},
        ]
        result = asyncio.run(narrator.remediation_roadmap(findings))
        assert "Advisory projection only" in result
        assert "not published as execution" in result
        assert "Submitted advisory records: **1**" in result
        assert "XSS" not in result

    def test_finding_description_async(self) -> None:
        """Generic finding input remains advisory end to end."""
        import asyncio
        narrator = ReportNarrator()
        finding = {"title": "SSRF", "severity": "High", "target": "https://app.com"}
        result = asyncio.run(narrator.finding_description(finding))
        assert "Advisory projection only" in result
        assert "not published as execution" in result
        assert "Submitted advisory records: **1**" in result
        assert "SSRF" not in result
        assert "https://app.com" not in result

    def test_risk_scenario_async(self) -> None:
        """Generic risk-scenario input remains advisory end to end."""
        import asyncio
        narrator = ReportNarrator()
        findings = [
            {"title": "SQL Injection", "severity": "Critical"},
            {"title": "Auth bypass", "severity": "High"},
        ]
        result = asyncio.run(narrator.risk_scenario(findings))
        assert "Advisory projection only" in result
        assert "not published as execution" in result
        assert "Submitted advisory records: **2**" in result
        assert "SQL Injection" not in result
        assert "Auth bypass" not in result
