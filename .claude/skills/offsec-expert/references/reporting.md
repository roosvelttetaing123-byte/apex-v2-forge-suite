# Reporting + Risk Scoring Reference

## CVSS v4.0

CVSS v4.0 replaced v3.1 as the standard in November 2023. Always use v4.0 for new reports.

### Score Groups
- **Base (CVSS-B)**: Intrinsic characteristics — AV/AC/AT/PR/UI + VC/VI/VA/SC/SI/SA
- **Threat (CVSS-BT)**: Base + Exploit Maturity (E)
- **Environmental (CVSS-BE/BTE)**: Base+Threat + organizational context modifiers

### Key Metric Changes from v3.1
- **Attack Requirements (AT)**: New metric — prerequisites beyond attacker control (None/Present)
- **Scope removed**: Replaced by separate Vulnerable System (VC/VI/VA) and Subsequent System (SC/SI/SA) impact
- **User Interaction**: Now None / Passive / Active (not just None/Required)
- **Exploit Maturity (E)**: Unreported / POC / Attacked (replaces Exploitability)

### Vector String Format
```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H
```

### Score Ranges
| Score | Severity |
|-------|----------|
| 0.0 | None |
| 0.1–3.9 | Low |
| 4.0–6.9 | Medium |
| 7.0–8.9 | High |
| 9.0–10.0 | Critical |

Calculator: https://www.first.org/cvss/calculator/4.0

---

## EPSS (Exploit Prediction Scoring System)

EPSS = probability (0–1) that a CVE will be exploited in the wild within 30 days.

- Source: FIRST.org, updated daily
- Combined with CVSS: a CVE with CVSS 7.0 + EPSS 0.85 is far more urgent than CVSS 9.8 + EPSS 0.003
- **>0.5 EPSS** = mention in report, flag for immediate prioritization
- **>0.9 EPSS** = P0 regardless of CVSS score

API:
```bash
curl "https://api.first.org/data/v1/epss?cve=CVE-2024-XXXX"
```

---

## KEV (CISA Known Exploited Vulnerabilities)

If a CVE appears in CISA KEV catalog → it is being actively exploited in the wild.

- Any KEV finding = automatic P0/Critical regardless of CVSS
- Check: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- API: `curl https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`

Report language: "This vulnerability (CVE-XXXX-YYYY) appears in the CISA Known Exploited Vulnerabilities catalog, indicating active exploitation in the wild. Federal agencies are required to patch within [CISA deadline]. Immediate remediation is required."

---

## Prioritization Framework

```
P0 — Critical (patch within 24–48h)
  - KEV listed, OR
  - CVSS v4.0 ≥ 9.0 + EPSS > 0.5, OR
  - Unauthenticated RCE / domain compromise path demonstrated

P1 — High (patch within 1–2 weeks)
  - CVSS v4.0 7.0–8.9 + EPSS > 0.3, OR
  - Authenticated RCE, privilege escalation to admin/domain admin

P2 — Medium (patch within 30 days)
  - CVSS v4.0 4.0–6.9, OR
  - Information disclosure of sensitive data, SSRF, XXE

P3 — Low (patch within 90 days)
  - CVSS v4.0 < 4.0, OR
  - Defense-in-depth findings, best practice deviations
```

---

## Finding Template

```markdown
### [FIND-001] <Title — descriptive, not just CVE number>

**Severity**: Critical | High | Medium | Low
**CVSS v4.0**: X.X (CVSS:4.0/AV:.../...)
**EPSS**: X.XX (Xth percentile)
**KEV**: Yes / No
**ATT&CK**: T<code> — <technique name>
**Priority**: P0 / P1 / P2 / P3

#### Description
<2-3 sentences: what is the vulnerability, where was it found, what does it allow>

#### Attack Narrative
<Step-by-step: how an attacker would discover and exploit this in practice. Written as a story, not a bullet list. Reference the specific endpoint/parameter/system observed during testing.>

#### Evidence
- Screenshot / command output demonstrating exploitability
- Request/response pair (redact sensitive data per ROE)
- Proof of impact (data accessed, privilege level achieved)

#### Business Impact
<Quantified where possible: "An attacker exploiting this finding could extract the customer PII database (estimated X records), triggering GDPR breach notification obligations and potential fines of up to 4% of annual global turnover.">

#### Remediation
<Specific, actionable fix — not "update the software." Name the version, the config change, the code pattern to replace.>

**References**: CVE-XXXX-YYYY, vendor advisory URL, NVD link
```

---

## Executive Summary Template

```markdown
## Executive Summary

[CLIENT NAME] engaged [PLATFORM NAME] to conduct a [engagement type] of [scope] between [dates].

### Key Findings

| Severity | Count |
|----------|-------|
| Critical | X |
| High | X |
| Medium | X |
| Low | X |
| Informational | X |

### Crown Jewel Exposure
During testing, the assessment team demonstrated [specific impact — e.g., "unauthorized access to the core banking database containing X customer records"] through a chain of [N] vulnerabilities beginning with [initial access vector].

### Risk Posture
[One paragraph: overall security maturity, most significant risks, comparison to industry baseline if applicable.]

### Immediate Actions Required
1. [P0 finding — action required within 48h]
2. [P1 finding — action required within 2 weeks]
```

---

## Compliance Mapping

Include mapping to relevant frameworks when client has compliance obligations:

| Finding Type | NIST CSF | PCI DSS v4.0 | ISO 27001:2022 | SOC 2 |
|---|---|---|---|---|
| Unpatched critical vuln | RS.MI-3 | Req 6.3 | A.8.8 | CC7.1 |
| Weak authentication | PR.AC-7 | Req 8.3 | A.5.17 | CC6.1 |
| Unencrypted sensitive data | PR.DS-1 | Req 3.5 | A.8.24 | CC6.7 |
| Missing logging | DE.CM-1 | Req 10.2 | A.8.15 | CC7.2 |
| Privilege escalation | PR.AC-4 | Req 7.2 | A.8.2 | CC6.3 |
