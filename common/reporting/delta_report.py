"""Forge Suite v5 APEX — Differential scan report generator.

Compares two scan result dicts and produces a structured delta showing
new, fixed, regressed, changed, and unchanged findings along with SLA
breach detection and risk trend analysis.
"""
from __future__ import annotations

import dataclasses
import datetime
import hashlib
import json
import os
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class FindingDelta:
    """Represents a single finding in the context of a scan delta."""
    status: str            # "NEW", "FIXED", "REGRESSED", "CHANGED", "UNCHANGED"
    finding_id: str
    title: str
    severity: str
    old_severity: str | None
    host: str
    description: str
    cvss_score: float | None
    mitre_ttps: list[str]
    first_seen: str        # ISO timestamp
    last_seen: str         # ISO timestamp


@dataclass
class DeltaReport:
    """Full delta between two scans."""
    scan_id_old: str
    scan_id_new: str
    generated_at: str
    target: str
    new_findings: list[FindingDelta]
    fixed_findings: list[FindingDelta]
    regressed_findings: list[FindingDelta]   # severity increased
    changed_findings: list[FindingDelta]      # same issue, different details
    unchanged_findings: list[FindingDelta]
    risk_trend: str           # "IMPROVING", "WORSENING", "STABLE"
    critical_delta: int       # +N new criticals, -N fixed criticals
    high_delta: int
    sla_breaches: list[dict]  # findings past SLA


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFORMATIONAL": 0}


class DeltaReportGenerator:
    """Generate a differential report between two scan result dicts.

    Each scan dict must have the shape::

        {
            "scan_id": str,
            "target":  str,
            "timestamp": str,           # ISO-8601
            "findings": [
                {
                    "id":          str,
                    "title":       str,
                    "severity":    str,   # CRITICAL / HIGH / MEDIUM / LOW / INFO
                    "host":        str,
                    "vuln_type":   str,
                    "description": str,
                    "cvss_score":  float | None,
                    "mitre_ttps":  list[str],
                    "first_seen":  str,   # ISO-8601
                    "last_seen":   str,   # ISO-8601
                },
                ...
            ]
        }
    """

    _DEFAULT_SLA = {
        "CRITICAL":      7,
        "HIGH":         30,
        "MEDIUM":       90,
        "LOW":         180,
        "INFORMATIONAL": 365,
    }

    def __init__(self, sla_days: dict | None = None) -> None:
        self.sla_days: dict[str, int] = {**self._DEFAULT_SLA, **(sla_days or {})}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(self, old_scan: dict, new_scan: dict) -> DeltaReport:
        """Compare *old_scan* against *new_scan* and return a :class:`DeltaReport`."""
        old_findings: list[dict] = old_scan.get("findings", [])
        new_findings_raw: list[dict] = new_scan.get("findings", [])

        new, fixed, regressed, changed, unchanged = self._classify_findings(
            old_findings, new_findings_raw
        )

        sla_breaches = self._check_sla_breaches(
            new + unchanged, new_scan.get("timestamp", datetime.datetime.now(datetime.timezone.utc).isoformat())
        )

        risk_trend = self._compute_risk_trend(
            old_scan, new_scan, len(new), len(fixed), len(regressed)
        )

        critical_delta = self._severity_delta("CRITICAL", new, fixed)
        high_delta = self._severity_delta("HIGH", new, fixed)

        return DeltaReport(
            scan_id_old=old_scan.get("scan_id", "unknown"),
            scan_id_new=new_scan.get("scan_id", "unknown"),
            generated_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            target=new_scan.get("target", old_scan.get("target", "unknown")),
            new_findings=new,
            fixed_findings=fixed,
            regressed_findings=regressed,
            changed_findings=changed,
            unchanged_findings=unchanged,
            risk_trend=risk_trend,
            critical_delta=critical_delta,
            high_delta=high_delta,
            sla_breaches=sla_breaches,
        )

    def to_json(self, report: DeltaReport) -> str:
        """Serialize *report* to a JSON string."""
        return json.dumps(dataclasses.asdict(report), indent=2, default=str)

    def to_markdown(self, report: DeltaReport) -> str:
        """Render a Markdown summary of *report*."""
        lines: list[str] = []

        lines.append(f"# Delta Report: {report.target}")
        lines.append("")
        lines.append(f"**Generated:** {report.generated_at}")
        lines.append(f"**Baseline scan:** `{report.scan_id_old}`")
        lines.append(f"**Current scan:** `{report.scan_id_new}`")
        lines.append(f"**Risk trend:** {report.risk_trend}")
        lines.append(f"**Critical delta:** {report.critical_delta:+d}  |  **High delta:** {report.high_delta:+d}")
        lines.append("")

        # Summary table
        lines.append("## Summary")
        lines.append("")
        lines.append("| Category | Count |")
        lines.append("|----------|-------|")
        lines.append(f"| New | {len(report.new_findings)} |")
        lines.append(f"| Fixed | {len(report.fixed_findings)} |")
        lines.append(f"| Regressed | {len(report.regressed_findings)} |")
        lines.append(f"| Changed | {len(report.changed_findings)} |")
        lines.append(f"| Unchanged | {len(report.unchanged_findings)} |")
        lines.append("")

        # Top 5 new findings
        if report.new_findings:
            lines.append("## Top New Findings (up to 5)")
            lines.append("")
            lines.append("| Severity | Title | Host | CVSS |")
            lines.append("|----------|-------|------|------|")
            top5 = sorted(
                report.new_findings,
                key=lambda f: _SEVERITY_ORDER.get(f.severity.upper(), 0),
                reverse=True,
            )[:5]
            for f in top5:
                cvss = f"{f.cvss_score:.1f}" if f.cvss_score is not None else "N/A"
                lines.append(f"| {f.severity} | {f.title} | {f.host} | {cvss} |")
            lines.append("")

        # Regressed findings
        if report.regressed_findings:
            lines.append("## Regressed Findings (severity increased)")
            lines.append("")
            lines.append("| Title | Host | Old Severity | New Severity |")
            lines.append("|-------|------|--------------|--------------|")
            for f in report.regressed_findings:
                lines.append(f"| {f.title} | {f.host} | {f.old_severity} | {f.severity} |")
            lines.append("")

        # SLA breaches
        if report.sla_breaches:
            lines.append("## SLA Breaches")
            lines.append("")
            lines.append("| Finding | Severity | SLA (days) | Days Overdue |")
            lines.append("|---------|----------|------------|--------------|")
            for b in report.sla_breaches:
                lines.append(
                    f"| {b['title']} | {b['severity']} | {b['sla_limit']} | {b['days_overdue']} |"
                )
            lines.append("")

        return "\n".join(lines)

    def to_html(self, report: DeltaReport) -> str:
        """Render an HTML page with all delta sections."""
        css = """
        <style>
            body { font-family: Arial, sans-serif; margin: 2em; background: #f8f8f8; }
            h1 { color: #333; }
            h2 { color: #555; margin-top: 1.5em; }
            table { border-collapse: collapse; width: 100%; margin-bottom: 1em; }
            th { background: #444; color: #fff; padding: 6px 10px; text-align: left; }
            td { padding: 5px 10px; border-bottom: 1px solid #ddd; }
            tr.new-row    { background: #ffe6e6; }
            tr.fixed-row  { background: #e6ffe6; }
            tr.regressed-row { background: #fff0d9; }
            tr.changed-row { background: #e6eeff; }
            tr.unchanged-row { color: #888; }
            .trend-worsening { color: #c00; font-weight: bold; }
            .trend-improving { color: #080; font-weight: bold; }
            .trend-stable    { color: #555; font-weight: bold; }
            .sla-breach { background: #ffd6d6; }
            .summary-box { background: #fff; border: 1px solid #ccc;
                           padding: 1em; border-radius: 4px; margin-bottom: 1em; }
        </style>
        """

        trend_class = {
            "WORSENING": "trend-worsening",
            "IMPROVING": "trend-improving",
            "STABLE":    "trend-stable",
        }.get(report.risk_trend, "trend-stable")

        def _finding_rows(findings: list[FindingDelta], row_class: str) -> str:
            rows = []
            for f in findings:
                cvss = f"{f.cvss_score:.1f}" if f.cvss_score is not None else "N/A"
                old_sev = f.old_severity if f.old_severity else "-"
                ttps = ", ".join(f.mitre_ttps) if f.mitre_ttps else "-"
                rows.append(
                    f'<tr class="{row_class}">'
                    f"<td>{f.severity}</td>"
                    f"<td>{old_sev}</td>"
                    f"<td>{f.title}</td>"
                    f"<td>{f.host}</td>"
                    f"<td>{cvss}</td>"
                    f"<td>{ttps}</td>"
                    f"<td>{f.first_seen}</td>"
                    f"</tr>"
                )
            return "\n".join(rows)

        def _section(title: str, findings: list[FindingDelta], row_class: str) -> str:
            if not findings:
                return f"<h2>{title}</h2><p>None.</p>"
            rows = _finding_rows(findings, row_class)
            return (
                f"<h2>{title} ({len(findings)})</h2>"
                "<table>"
                "<tr><th>Severity</th><th>Old Severity</th><th>Title</th>"
                "<th>Host</th><th>CVSS</th><th>MITRE TTPs</th><th>First Seen</th></tr>"
                f"{rows}</table>"
            )

        sla_rows = ""
        for b in report.sla_breaches:
            sla_rows += (
                f'<tr class="sla-breach">'
                f"<td>{b['title']}</td>"
                f"<td>{b['severity']}</td>"
                f"<td>{b['sla_limit']}</td>"
                f"<td>{b['days_overdue']}</td>"
                f"<td>{b.get('finding_id','')}</td>"
                f"</tr>"
            )
        sla_section = (
            "<h2>SLA Breaches</h2>"
            "<table><tr><th>Title</th><th>Severity</th>"
            "<th>SLA (days)</th><th>Days Overdue</th><th>ID</th></tr>"
            f"{sla_rows}</table>"
        ) if report.sla_breaches else "<h2>SLA Breaches</h2><p>None.</p>"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Delta Report — {report.target}</title>{css}</head>
<body>
<h1>Delta Report: {report.target}</h1>
<div class="summary-box">
  <p><strong>Generated:</strong> {report.generated_at}</p>
  <p><strong>Baseline scan:</strong> {report.scan_id_old}</p>
  <p><strong>Current scan:</strong> {report.scan_id_new}</p>
  <p><strong>Risk trend:</strong> <span class="{trend_class}">{report.risk_trend}</span></p>
  <p><strong>Critical delta:</strong> {report.critical_delta:+d}
     &nbsp;|&nbsp;
     <strong>High delta:</strong> {report.high_delta:+d}</p>
  <table>
    <tr><th>Category</th><th>Count</th></tr>
    <tr class="new-row"><td>New</td><td>{len(report.new_findings)}</td></tr>
    <tr class="fixed-row"><td>Fixed</td><td>{len(report.fixed_findings)}</td></tr>
    <tr class="regressed-row"><td>Regressed</td><td>{len(report.regressed_findings)}</td></tr>
    <tr class="changed-row"><td>Changed</td><td>{len(report.changed_findings)}</td></tr>
    <tr class="unchanged-row"><td>Unchanged</td><td>{len(report.unchanged_findings)}</td></tr>
  </table>
</div>
{_section("New Findings", report.new_findings, "new-row")}
{_section("Fixed Findings", report.fixed_findings, "fixed-row")}
{_section("Regressed Findings", report.regressed_findings, "regressed-row")}
{_section("Changed Findings", report.changed_findings, "changed-row")}
{_section("Unchanged Findings", report.unchanged_findings, "unchanged-row")}
{sla_section}
</body></html>"""
        return html

    def save(self, report: DeltaReport, path: str) -> None:
        """Save JSON and Markdown representations of *report* to *path*."""
        os.makedirs(path, exist_ok=True)
        base = f"delta_{report.scan_id_new}"
        json_path = os.path.join(path, f"{base}.json")
        md_path = os.path.join(path, f"{base}.md")
        with open(json_path, "w", encoding="utf-8") as fh:
            fh.write(self.to_json(report))
        with open(md_path, "w", encoding="utf-8") as fh:
            fh.write(self.to_markdown(report))

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _finding_fingerprint(finding: dict) -> str:
        """Stable SHA-256 fingerprint linking the same issue across scans."""
        raw = (
            f"{finding.get('title', '').lower()}"
            f"::{finding.get('host', '').lower()}"
            f"::{finding.get('vuln_type', '').lower()}"
        )
        return hashlib.sha256(raw.encode()).hexdigest()

    def _to_delta(
        self,
        finding: dict,
        status: str,
        old_finding: dict | None = None,
    ) -> FindingDelta:
        old_sev = old_finding.get("severity") if old_finding else None
        return FindingDelta(
            status=status,
            finding_id=finding.get("id", self._finding_fingerprint(finding)),
            title=finding.get("title", ""),
            severity=finding.get("severity", "LOW"),
            old_severity=old_sev,
            host=finding.get("host", ""),
            description=finding.get("description", ""),
            cvss_score=finding.get("cvss_score"),
            mitre_ttps=finding.get("mitre_ttps", []),
            first_seen=finding.get("first_seen", ""),
            last_seen=finding.get("last_seen", ""),
        )

    def _classify_findings(
        self,
        old_findings: list[dict],
        new_findings: list[dict],
    ) -> tuple[list[FindingDelta], list[FindingDelta], list[FindingDelta], list[FindingDelta], list[FindingDelta]]:
        """Classify findings into (new, fixed, regressed, changed, unchanged).

        A finding is matched across scans by its stable fingerprint
        (title + host + vuln_type).  Within matched pairs:

        * REGRESSED  — fingerprint matches, severity worsened (higher rank)
        * CHANGED    — fingerprint matches, CVSS score or description changed
        * UNCHANGED  — fingerprint matches, nothing significant changed
        """
        old_by_fp: dict[str, dict] = {self._finding_fingerprint(f): f for f in old_findings}
        new_by_fp: dict[str, dict] = {self._finding_fingerprint(f): f for f in new_findings}

        new_list:       list[FindingDelta] = []
        fixed_list:     list[FindingDelta] = []
        regressed_list: list[FindingDelta] = []
        changed_list:   list[FindingDelta] = []
        unchanged_list: list[FindingDelta] = []

        # Findings in new scan
        for fp, nf in new_by_fp.items():
            if fp not in old_by_fp:
                new_list.append(self._to_delta(nf, "NEW"))
            else:
                of = old_by_fp[fp]
                old_rank = _SEVERITY_ORDER.get(of.get("severity", "LOW").upper(), 0)
                new_rank = _SEVERITY_ORDER.get(nf.get("severity", "LOW").upper(), 0)
                if new_rank > old_rank:
                    # Severity worsened
                    regressed_list.append(self._to_delta(nf, "REGRESSED", of))
                elif self._is_changed(of, nf):
                    changed_list.append(self._to_delta(nf, "CHANGED", of))
                else:
                    unchanged_list.append(self._to_delta(nf, "UNCHANGED", of))

        # Findings in old scan not in new scan = FIXED
        for fp, of in old_by_fp.items():
            if fp not in new_by_fp:
                fixed_list.append(self._to_delta(of, "FIXED"))

        return new_list, fixed_list, regressed_list, changed_list, unchanged_list

    @staticmethod
    def _is_changed(old_finding: dict, new_finding: dict) -> bool:
        """Return True when a matched finding has meaningfully changed."""
        old_cvss = old_finding.get("cvss_score")
        new_cvss = new_finding.get("cvss_score")
        if old_cvss != new_cvss:
            return True
        old_desc = (old_finding.get("description") or "").strip()
        new_desc = (new_finding.get("description") or "").strip()
        # Significant change = more than 20 characters difference in description length
        if abs(len(old_desc) - len(new_desc)) > 20:
            return True
        return False

    def _check_sla_breaches(
        self,
        findings: list[FindingDelta],
        scan_timestamp: str,
    ) -> list[dict]:
        """Return findings where elapsed time since first_seen exceeds SLA."""
        breaches: list[dict] = []
        now = datetime.datetime.now(datetime.timezone.utc)
        for f in findings:
            sla_limit = self.sla_days.get(f.severity.upper())
            if sla_limit is None:
                continue
            first_seen_str = f.first_seen
            if not first_seen_str:
                continue
            try:
                first_seen = datetime.datetime.fromisoformat(
                    first_seen_str.replace("Z", "+00:00")
                )
                if first_seen.tzinfo is None:
                    first_seen = first_seen.replace(tzinfo=datetime.timezone.utc)
                elapsed_days = (now - first_seen).days
                if elapsed_days > sla_limit:
                    breaches.append(
                        {
                            "finding_id": f.finding_id,
                            "title": f.title,
                            "severity": f.severity,
                            "days_overdue": elapsed_days - sla_limit,
                            "sla_limit": sla_limit,
                        }
                    )
            except (ValueError, TypeError):
                continue
        return breaches

    def _compute_risk_trend(
        self,
        old_scan: dict,
        new_scan: dict,
        new_count: int,
        fixed_count: int,
        regressed_count: int,
    ) -> str:
        """Return WORSENING / IMPROVING / STABLE based on critical+high balance."""
        old_findings = old_scan.get("findings", [])
        new_findings = new_scan.get("findings", [])

        old_ch = sum(
            1 for f in old_findings
            if f.get("severity", "").upper() in ("CRITICAL", "HIGH")
        )
        new_ch = sum(
            1 for f in new_findings
            if f.get("severity", "").upper() in ("CRITICAL", "HIGH")
        )

        if new_ch > old_ch or regressed_count > 0:
            return "WORSENING"
        if new_ch < old_ch or fixed_count > new_count:
            return "IMPROVING"
        return "STABLE"

    @staticmethod
    def _severity_delta(severity: str, new_findings: list[FindingDelta], fixed_findings: list[FindingDelta]) -> int:
        """Compute net delta for a single severity level."""
        added = sum(1 for f in new_findings if f.severity.upper() == severity)
        removed = sum(1 for f in fixed_findings if f.severity.upper() == severity)
        return added - removed


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

import unittest


def _make_scan(scan_id: str, target: str, findings: list[dict], timestamp: str | None = None) -> dict:
    return {
        "scan_id": scan_id,
        "target": target,
        "timestamp": timestamp or "2026-01-01T00:00:00+00:00",
        "findings": findings,
    }


def _make_finding(
    title: str = "SQL Injection",
    host: str = "10.0.0.1",
    vuln_type: str = "sqli",
    severity: str = "HIGH",
    cvss_score: float | None = 8.1,
    description: str = "classic sqli",
    first_seen: str = "2025-01-01T00:00:00+00:00",
    last_seen: str = "2026-01-01T00:00:00+00:00",
    mitre_ttps: list[str] | None = None,
) -> dict:
    return {
        "id": hashlib.sha256(title.encode()).hexdigest()[:8],
        "title": title,
        "host": host,
        "vuln_type": vuln_type,
        "severity": severity,
        "cvss_score": cvss_score,
        "description": description,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "mitre_ttps": mitre_ttps or ["T1190"],
    }


class TestDeltaReport(unittest.TestCase):

    def setUp(self):
        self.gen = DeltaReportGenerator()

    # --- Fingerprint stability ---

    def test_fingerprint_stability(self):
        """Same title/host/vuln_type always produce the same fingerprint."""
        f = _make_finding()
        fp1 = DeltaReportGenerator._finding_fingerprint(f)
        fp2 = DeltaReportGenerator._finding_fingerprint(dict(f))
        self.assertEqual(fp1, fp2)

    def test_fingerprint_case_insensitive(self):
        """Fingerprint is case-insensitive."""
        f1 = _make_finding(title="SQL Injection", host="10.0.0.1", vuln_type="sqli")
        f2 = _make_finding(title="sql injection", host="10.0.0.1", vuln_type="SQLI")
        self.assertEqual(
            DeltaReportGenerator._finding_fingerprint(f1),
            DeltaReportGenerator._finding_fingerprint(f2),
        )

    def test_fingerprint_different_host(self):
        """Different host produces different fingerprint."""
        f1 = _make_finding(host="10.0.0.1")
        f2 = _make_finding(host="10.0.0.2")
        self.assertNotEqual(
            DeltaReportGenerator._finding_fingerprint(f1),
            DeltaReportGenerator._finding_fingerprint(f2),
        )

    def test_fingerprint_is_sha256_hex(self):
        """Fingerprint is a 64-character hex string."""
        fp = DeltaReportGenerator._finding_fingerprint(_make_finding())
        self.assertEqual(len(fp), 64)
        int(fp, 16)  # must be valid hex

    # --- Classification ---

    def test_new_finding_detected(self):
        """A finding in new_scan not in old_scan is NEW."""
        old = _make_scan("s1", "t", [])
        new = _make_scan("s2", "t", [_make_finding()])
        report = self.gen.generate(old, new)
        self.assertEqual(len(report.new_findings), 1)
        self.assertEqual(report.new_findings[0].status, "NEW")

    def test_fixed_finding_detected(self):
        """A finding in old_scan not in new_scan is FIXED."""
        old = _make_scan("s1", "t", [_make_finding()])
        new = _make_scan("s2", "t", [])
        report = self.gen.generate(old, new)
        self.assertEqual(len(report.fixed_findings), 1)
        self.assertEqual(report.fixed_findings[0].status, "FIXED")

    def test_unchanged_finding_detected(self):
        """Same finding in both scans with no meaningful change is UNCHANGED."""
        f = _make_finding()
        old = _make_scan("s1", "t", [f])
        new = _make_scan("s2", "t", [f])
        report = self.gen.generate(old, new)
        self.assertEqual(len(report.unchanged_findings), 1)
        self.assertEqual(report.unchanged_findings[0].status, "UNCHANGED")

    def test_regression_detected(self):
        """Same finding with severity increase is REGRESSED."""
        f_old = _make_finding(severity="MEDIUM")
        f_new = _make_finding(severity="CRITICAL")
        old = _make_scan("s1", "t", [f_old])
        new = _make_scan("s2", "t", [f_new])
        report = self.gen.generate(old, new)
        self.assertEqual(len(report.regressed_findings), 1)
        self.assertEqual(report.regressed_findings[0].old_severity, "MEDIUM")
        self.assertEqual(report.regressed_findings[0].severity, "CRITICAL")

    def test_changed_finding_detected(self):
        """Same fingerprint but different CVSS score is CHANGED."""
        f_old = _make_finding(cvss_score=5.0)
        f_new = _make_finding(cvss_score=7.5)
        old = _make_scan("s1", "t", [f_old])
        new = _make_scan("s2", "t", [f_new])
        report = self.gen.generate(old, new)
        self.assertEqual(len(report.changed_findings), 1)

    def test_mixed_classification(self):
        """Multiple findings spread across categories."""
        f_fixed = _make_finding(title="Old Bug", host="1.1.1.1", vuln_type="xss")
        f_new = _make_finding(title="New Bug", host="2.2.2.2", vuln_type="rce")
        f_unch = _make_finding(title="Stable Bug", host="3.3.3.3", vuln_type="info")
        old = _make_scan("s1", "t", [f_fixed, f_unch])
        new = _make_scan("s2", "t", [f_new, f_unch])
        report = self.gen.generate(old, new)
        self.assertEqual(len(report.fixed_findings), 1)
        self.assertEqual(len(report.new_findings), 1)
        self.assertEqual(len(report.unchanged_findings), 1)

    # --- SLA breach detection ---

    def test_sla_breach_critical(self):
        """CRITICAL finding older than 7 days triggers SLA breach."""
        old_date = (
            datetime.datetime.now(datetime.timezone.utc)
            - datetime.timedelta(days=30)
        ).isoformat()
        f = _make_finding(severity="CRITICAL", first_seen=old_date)
        old = _make_scan("s1", "t", [])
        new = _make_scan("s2", "t", [f])
        report = self.gen.generate(old, new)
        self.assertEqual(len(report.sla_breaches), 1)
        self.assertGreater(report.sla_breaches[0]["days_overdue"], 0)

    def test_sla_no_breach_within_limit(self):
        """Finding within SLA window does not trigger breach."""
        recent = (
            datetime.datetime.now(datetime.timezone.utc)
            - datetime.timedelta(days=3)
        ).isoformat()
        f = _make_finding(severity="CRITICAL", first_seen=recent)
        old = _make_scan("s1", "t", [])
        new = _make_scan("s2", "t", [f])
        report = self.gen.generate(old, new)
        self.assertEqual(len(report.sla_breaches), 0)

    def test_sla_custom_limits(self):
        """Custom SLA days are respected."""
        gen = DeltaReportGenerator(sla_days={"CRITICAL": 1})
        two_days_ago = (
            datetime.datetime.now(datetime.timezone.utc)
            - datetime.timedelta(days=2)
        ).isoformat()
        f = _make_finding(severity="CRITICAL", first_seen=two_days_ago)
        old = _make_scan("s1", "t", [])
        new = _make_scan("s2", "t", [f])
        report = gen.generate(old, new)
        self.assertEqual(len(report.sla_breaches), 1)

    # --- Risk trend ---

    def test_risk_trend_worsening(self):
        """More critical/high in new scan means WORSENING."""
        old = _make_scan("s1", "t", [_make_finding(severity="LOW")])
        new = _make_scan("s2", "t", [
            _make_finding(title="A", severity="CRITICAL"),
            _make_finding(title="B", host="2.2.2.2", severity="CRITICAL"),
        ])
        report = self.gen.generate(old, new)
        self.assertEqual(report.risk_trend, "WORSENING")

    def test_risk_trend_improving(self):
        """Fewer critical/high in new scan means IMPROVING."""
        old = _make_scan("s1", "t", [
            _make_finding(title="A", severity="CRITICAL"),
            _make_finding(title="B", host="2.2.2.2", severity="HIGH"),
        ])
        new = _make_scan("s2", "t", [])
        report = self.gen.generate(old, new)
        self.assertEqual(report.risk_trend, "IMPROVING")

    def test_risk_trend_stable(self):
        """Same profile = STABLE."""
        f = _make_finding(severity="MEDIUM")
        old = _make_scan("s1", "t", [f])
        new = _make_scan("s2", "t", [f])
        report = self.gen.generate(old, new)
        self.assertEqual(report.risk_trend, "STABLE")

    # --- JSON serialization ---

    def test_json_round_trip(self):
        """to_json produces valid JSON with expected top-level keys."""
        f = _make_finding()
        report = self.gen.generate(
            _make_scan("s1", "t", [f]),
            _make_scan("s2", "t", [f]),
        )
        data = json.loads(self.gen.to_json(report))
        for key in ("scan_id_old", "scan_id_new", "new_findings", "fixed_findings",
                    "risk_trend", "sla_breaches"):
            self.assertIn(key, data)

    # --- Markdown output ---

    def test_markdown_output_has_sections(self):
        """Markdown output contains expected section headers."""
        f = _make_finding()
        report = self.gen.generate(
            _make_scan("s1", "t", []),
            _make_scan("s2", "t", [f]),
        )
        md = self.gen.to_markdown(report)
        self.assertIn("# Delta Report", md)
        self.assertIn("## Summary", md)
        self.assertIn("New", md)

    def test_markdown_table_has_five_rows(self):
        """Summary table has exactly 5 category rows."""
        report = self.gen.generate(_make_scan("s1", "t", []), _make_scan("s2", "t", []))
        md = self.gen.to_markdown(report)
        self.assertIn("| New |", md)
        self.assertIn("| Fixed |", md)
        self.assertIn("| Regressed |", md)
        self.assertIn("| Changed |", md)
        self.assertIn("| Unchanged |", md)

    # --- HTML output ---

    def test_html_output_contains_key_sections(self):
        """HTML contains both new-row and fixed-row CSS classes."""
        old = _make_scan("s1", "t", [_make_finding(title="Old", vuln_type="xss")])
        new = _make_scan("s2", "t", [_make_finding(title="New", vuln_type="rce")])
        report = self.gen.generate(old, new)
        html = self.gen.to_html(report)
        self.assertIn("new-row", html)
        self.assertIn("fixed-row", html)
        self.assertIn("New Findings", html)
        self.assertIn("Fixed Findings", html)

    def test_html_contains_risk_trend(self):
        """HTML contains the risk trend value."""
        report = self.gen.generate(_make_scan("s1", "t", []), _make_scan("s2", "t", []))
        html = self.gen.to_html(report)
        self.assertIn(report.risk_trend, html)


if __name__ == "__main__":
    unittest.main()
