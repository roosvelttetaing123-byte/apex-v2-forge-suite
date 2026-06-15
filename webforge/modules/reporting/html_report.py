"""HTML report generator — self-contained HTML from findings list."""
from __future__ import annotations

import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.finding import Finding, Severity

SEVERITY_COLORS = {
    Severity.CRITICAL:      "#8B0000",
    Severity.HIGH:          "#CC3300",
    Severity.MEDIUM:        "#FF8C00",
    Severity.LOW:           "#4CAF50",
    Severity.INFORMATIONAL: "#2196F3",
}

SEVERITY_ORDER = [
    Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
    Severity.LOW, Severity.INFORMATIONAL,
]


def _sev_badge(sev: Severity) -> str:
    color = SEVERITY_COLORS.get(sev, "#999")
    return (
        f'<span style="background:{color};color:#fff;padding:2px 8px;'
        f'border-radius:3px;font-size:0.85em;font-weight:bold;">{sev.value}</span>'
    )


def _count_by_severity(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {s.value: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    return counts


def generate_html(
    findings: list[Finding],
    target: str = "",
    scan_start: str = "",
    scan_end: str = "",
    assessor: str = "WebForge",
) -> str:
    """Generate self-contained HTML report string from findings list."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    counts = _count_by_severity(findings)
    total = len(findings)

    # Executive summary rows
    exec_rows = "".join(
        f'<tr><td style="color:{SEVERITY_COLORS[s]}"><b>{s.value}</b></td>'
        f'<td style="text-align:center">{counts[s.value]}</td></tr>'
        for s in SEVERITY_ORDER
    )

    # Sort findings by severity then title
    sorted_findings = sorted(
        findings,
        key=lambda f: (SEVERITY_ORDER.index(f.severity), f.title),
    )

    detail_blocks = []
    for idx, f in enumerate(sorted_findings, 1):
        repro_html = "".join(
            f"<li>{step}</li>" for step in (f.reproduction_steps or [])
        )
        refs_html = "".join(
            f'<li><a href="{r}" style="color:#1a73e8">{r}</a></li>'
            if r.startswith("http") else f"<li>{r}</li>"
            for r in (f.references or [])
        )
        mitre_html = ", ".join(f.mitre_attack) if f.mitre_attack else "N/A"
        cvss_str = (
            f"{f.cvss_v31_vector} (Score: {f.cvss_v31_score})"
            if f.cvss_v31_vector else "N/A"
        )
        screenshot = ""
        if f.evidence and f.evidence.screenshot_path:
            screenshot = (
                f'<p><b>Screenshot:</b><br>'
                f'<img src="{f.evidence.screenshot_path}" style="max-width:100%;border:1px solid #ddd;" /></p>'
            )
        evidence_extra = ""
        if f.evidence and f.evidence.extra:
            items = "".join(
                f"<li><b>{k}:</b> {v}</li>"
                for k, v in f.evidence.extra.items()
            )
            evidence_extra = f"<ul>{items}</ul>"

        detail_blocks.append(f"""
        <div style="border:1px solid #ddd;border-radius:6px;margin:18px 0;padding:18px;background:#fafafa;">
          <h3 style="margin:0 0 8px 0;">#{idx} — {f.title} &nbsp;{_sev_badge(f.severity)}</h3>
          <table style="width:100%;font-size:0.9em;border-collapse:collapse;">
            <tr><td style="width:150px;color:#555;padding:4px 0"><b>Finding ID</b></td><td>{f.id}</td></tr>
            <tr><td style="color:#555;padding:4px 0"><b>Target</b></td><td>{f.target}</td></tr>
            <tr><td style="color:#555;padding:4px 0"><b>Module</b></td><td>{f.module}</td></tr>
            <tr><td style="color:#555;padding:4px 0"><b>CVSS 3.1</b></td><td>{cvss_str}</td></tr>
            <tr><td style="color:#555;padding:4px 0"><b>MITRE ATT&amp;CK</b></td><td>{mitre_html}</td></tr>
            <tr><td style="color:#555;padding:4px 0"><b>Discovered</b></td><td>{f.discovered_at.strftime("%Y-%m-%d %H:%M UTC")}</td></tr>
          </table>
          <h4 style="margin:14px 0 4px 0">Description</h4>
          <p style="margin:0;white-space:pre-wrap">{f.description}</p>
          <h4 style="margin:14px 0 4px 0">Reproduction Steps</h4>
          <ol>{repro_html}</ol>
          <h4 style="margin:14px 0 4px 0">Remediation</h4>
          <p style="margin:0;background:#e8f5e9;padding:10px;border-radius:4px">{f.remediation}</p>
          <h4 style="margin:14px 0 4px 0">References</h4>
          <ul>{refs_html}</ul>
          {screenshot}
          {evidence_extra}
        </div>""")

    details_html = "\n".join(detail_blocks)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>WebForge Security Assessment Report</title>
  <style>
    body{{font-family:Segoe UI,Arial,sans-serif;margin:0;padding:0;background:#f4f4f4;color:#222;}}
    .page{{max-width:1100px;margin:30px auto;background:#fff;padding:40px 50px;border-radius:8px;box-shadow:0 2px 12px #0002;}}
    h1{{color:#1a237e;margin-bottom:4px;}} h2{{color:#283593;border-bottom:2px solid #e3e3e3;padding-bottom:6px;}}
    table{{border-collapse:collapse;width:100%;}} th,td{{border:1px solid #ddd;padding:8px 12px;text-align:left;}}
    th{{background:#1a237e;color:#fff;}} tr:nth-child(even){{background:#f9f9f9;}}
    .footer{{text-align:center;font-size:0.8em;color:#888;margin-top:40px;}}
  </style>
</head>
<body>
<div class="page">
  <h1>WebForge Security Assessment Report</h1>
  <p style="color:#555">Target: <b>{target}</b> &nbsp;|&nbsp; Generated: <b>{now}</b> &nbsp;|&nbsp; Assessor: <b>{assessor}</b></p>
  <p>Scan Start: {scan_start or "N/A"} &nbsp;|&nbsp; Scan End: {scan_end or "N/A"}</p>

  <h2>Executive Summary</h2>
  <p>Total findings: <b>{total}</b></p>
  <table style="width:300px">
    <tr><th>Severity</th><th>Count</th></tr>
    {exec_rows}
  </table>

  <h2>Detailed Findings</h2>
  {details_html if details_html else "<p>No findings recorded.</p>"}

  <div class="footer">Generated by WebForge &mdash; MPTC Cambodia Security Training</div>
</div>
</body>
</html>"""


class HtmlReport(BaseModule):
    """Generate self-contained HTML report from accumulated findings."""

    NAME        = "html_report"
    DESCRIPTION = "Generate self-contained HTML report from findings"
    PHASE       = 99
    TAGS        = ["reporting"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        findings: list[Finding] = self.config.extra.get("findings", [])
        target   = self.config.extra.get("target", self.config.target)
        out_path = Path(self.config.extra.get("output_path", self.results_dir / "report.html"))
        out_path.parent.mkdir(parents=True, exist_ok=True)

        html = generate_html(
            findings=findings,
            target=target,
            scan_start=self.config.extra.get("scan_start", ""),
            scan_end=self.config.extra.get("scan_end", ""),
            assessor=self.config.extra.get("assessor", "WebForge"),
        )
        out_path.write_text(html, encoding="utf-8")
        self.log.info("HTML report written to %s (%d findings)", out_path, len(findings))
        return self._make_result(start)
