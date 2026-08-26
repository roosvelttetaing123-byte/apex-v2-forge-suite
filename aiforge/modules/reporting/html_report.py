"""HTML report generation — produce a standalone assessment report from scan findings."""
from __future__ import annotations

import html
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence, ordinary_finding_projection
from common.finding import Finding, Severity
from common.version import VERSION

SEVERITY_COLORS = {
    "Critical":      "#dc2626",
    "High":          "#ea580c",
    "Medium":        "#d97706",
    "Low":           "#2563eb",
    "Informational": "#6b7280",
}

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]


class HtmlReport(BaseModule):
    """HTML report — generate a standalone HTML assessment report."""

    NAME        = "html_report"
    DESCRIPTION = "Generate standalone HTML security assessment report with charts and findings"
    PHASE       = 8
    TAGS        = ["reporting", "html"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()

        all_findings = [
            ordinary_finding_projection(finding)
            for finding in self.config.extra.get("all_findings", [])
        ]
        if not all_findings:
            self.log.info("No findings to report")
            return self._make_result(start, skipped=True, skip_reason="no findings")

        report_path = self.results_dir / "aiforge_report.html"
        report_path.parent.mkdir(parents=True, exist_ok=True)

        severity_counts = {s: 0 for s in SEVERITY_ORDER}
        for f in all_findings:
            sev = f.get("severity", "Informational")
            if sev in severity_counts:
                severity_counts[sev] += 1

        target = self.config.target
        scan_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        total = len(all_findings)

        findings_html = self._render_findings(all_findings)
        chart_data = json.dumps(severity_counts)

        report = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AIForge Assessment Report — {html.escape(target)}</title>
<style>
  :root {{
    --bg: #0f172a; --surface: #1e293b; --border: #334155;
    --text: #e2e8f0; --muted: #94a3b8;
    --critical: {SEVERITY_COLORS["Critical"]};
    --high: {SEVERITY_COLORS["High"]};
    --medium: {SEVERITY_COLORS["Medium"]};
    --low: {SEVERITY_COLORS["Low"]};
    --info: {SEVERITY_COLORS["Informational"]};
  }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: 'Inter', 'Segoe UI', system-ui, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; }}
  .container {{ max-width: 1100px; margin: 0 auto; padding: 2rem; }}
  header {{ text-align: center; padding: 3rem 0; border-bottom: 1px solid var(--border); }}
  header h1 {{ font-size: 2rem; font-weight: 700; }}
  header .meta {{ color: var(--muted); margin-top: 0.5rem; }}
  .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 1rem; margin: 2rem 0; }}
  .stat {{ background: var(--surface); border-radius: 12px; padding: 1.5rem; text-align: center; border: 1px solid var(--border); }}
  .stat .count {{ font-size: 2.5rem; font-weight: 700; }}
  .stat .label {{ color: var(--muted); font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; }}
  .finding {{ background: var(--surface); border-radius: 12px; padding: 1.5rem; margin: 1rem 0; border-left: 4px solid; border-color: var(--border); }}
  .finding.Critical {{ border-color: var(--critical); }}
  .finding.High {{ border-color: var(--high); }}
  .finding.Medium {{ border-color: var(--medium); }}
  .finding.Low {{ border-color: var(--low); }}
  .finding.Informational {{ border-color: var(--info); }}
  .finding h3 {{ font-size: 1.1rem; margin-bottom: 0.5rem; }}
  .badge {{ display: inline-block; padding: 2px 10px; border-radius: 999px; font-size: 0.75rem; font-weight: 600; color: #fff; }}
  .badge.Critical {{ background: var(--critical); }}
  .badge.High {{ background: var(--high); }}
  .badge.Medium {{ background: var(--medium); }}
  .badge.Low {{ background: var(--low); }}
  .badge.Informational {{ background: var(--info); }}
  .detail {{ color: var(--muted); font-size: 0.9rem; margin: 0.5rem 0; }}
  .detail strong {{ color: var(--text); }}
  pre {{ background: #0d1117; padding: 1rem; border-radius: 8px; overflow-x: auto; font-size: 0.85rem; margin: 0.5rem 0; }}
  .section-title {{ font-size: 1.5rem; margin: 2.5rem 0 1rem; padding-bottom: 0.5rem; border-bottom: 1px solid var(--border); }}
  footer {{ text-align: center; color: var(--muted); padding: 3rem 0 1rem; font-size: 0.8rem; }}
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>AIForge Security Assessment</h1>
    <div class="meta">Target: {html.escape(target)} | Scan: {scan_time} | Findings: {total}</div>
  </header>

  <div class="summary">
    <div class="stat"><div class="count" style="color:var(--critical)">{severity_counts["Critical"]}</div><div class="label">Critical</div></div>
    <div class="stat"><div class="count" style="color:var(--high)">{severity_counts["High"]}</div><div class="label">High</div></div>
    <div class="stat"><div class="count" style="color:var(--medium)">{severity_counts["Medium"]}</div><div class="label">Medium</div></div>
    <div class="stat"><div class="count" style="color:var(--low)">{severity_counts["Low"]}</div><div class="label">Low</div></div>
    <div class="stat"><div class="count" style="color:var(--info)">{severity_counts["Informational"]}</div><div class="label">Info</div></div>
    <div class="stat"><div class="count">{total}</div><div class="label">Total</div></div>
  </div>

  <h2 class="section-title">Findings</h2>
  {findings_html}

  <footer>
    Generated by AIForge v{VERSION} | forge-suite | {scan_time}
  </footer>
</div>
</body>
</html>"""

        report_path.write_text(report, encoding="utf-8")
        self.log.info("HTML report written to %s", report_path)

        self.new_finding(
            title="Assessment Report Generated",
            severity=Severity.INFORMATIONAL,
            description=f"HTML report: {report_path}",
            reproduction_steps=["Open report in browser"],
            remediation="N/A",
            references=[],
            evidence=Evidence(extra={"report_path": str(report_path), "finding_count": total}),
            target=self.config.target,
        )

        return self._make_result(start)

    def _render_findings(self, findings: list[dict[str, Any]]) -> str:
        ordinary_findings = [
            ordinary_finding_projection(finding) for finding in findings
        ]
        parts: list[str] = []
        # Sort by severity
        order = {s: i for i, s in enumerate(SEVERITY_ORDER)}
        ordinary_findings.sort(
            key=lambda f: order.get(f.get("severity", "Informational"), 99)
        )

        for f in ordinary_findings:
            sev = f.get("severity", "Informational")
            title = html.escape(f.get("title", "Untitled"))
            module = html.escape(f.get("module", ""))
            desc = html.escape(f.get("description", ""))
            remed = html.escape(f.get("remediation", ""))
            cvss31 = f.get("cvss_v31_score", "")
            cvss40 = f.get("cvss_v40_score", "")
            refs = f.get("references", [])

            cvss_str = ""
            if cvss31:
                cvss_str += f"CVSS 3.1: {cvss31}"
            if cvss40:
                cvss_str += f" | CVSS 4.0: {cvss40}"

            steps = f.get("reproduction_steps", [])
            steps_html = "".join(f"<li>{html.escape(s)}</li>" for s in steps)
            refs_html = ", ".join(html.escape(r) for r in refs)

            parts.append(f"""
  <div class="finding {sev}">
    <h3><span class="badge {sev}">{sev}</span> {title}</h3>
    <div class="detail"><strong>Module:</strong> {module} {f"| {cvss_str}" if cvss_str else ""}</div>
    <div class="detail">{desc}</div>
    {"<div class='detail'><strong>Steps:</strong><ol>" + steps_html + "</ol></div>" if steps_html else ""}
    <div class="detail"><strong>Remediation:</strong> {remed}</div>
    {"<div class='detail'><strong>References:</strong> " + refs_html + "</div>" if refs_html else ""}
  </div>""")
        return "\n".join(parts)


class TestHtmlReport:
    def test_severity_colors_complete(self) -> None:
        for s in SEVERITY_ORDER:
            assert s in SEVERITY_COLORS

    def test_render_findings(self) -> None:
        mod = HtmlReport.__new__(HtmlReport)
        result = mod._render_findings([{
            "title": "Test", "severity": "High",
            "module": "test", "description": "desc",
            "remediation": "fix", "references": ["ref1"],
        }])
        assert "Test" in result
        assert "High" in result
