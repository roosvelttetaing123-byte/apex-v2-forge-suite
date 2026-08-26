"""NetForge HTML Report — self-contained HTML from accumulated findings.

Network pentest oriented: shows host/port/service tables, attack chain
summary, credentialed check results, and verified evidence derivatives.

Mirrors WebForge's HTML reporter architecture but adapted for network
infrastructure findings (CVE matches, service misconfigs, lateral
movement paths, credential harvesting results).
"""
from __future__ import annotations

import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import (
    EvidenceCaptureError,
    ordinary_evidence_artifacts,
    ordinary_finding_projection,
)
from common.finding import Finding, Severity
from common.version import VERSION


# ── Severity theming ─────────────────────────────────────────────────────────

SEVERITY_COLORS = {
    Severity.CRITICAL:      "#7030A0",
    Severity.HIGH:          "#CC3300",
    Severity.MEDIUM:        "#FF8C00",
    Severity.LOW:           "#4CAF50",
    Severity.INFORMATIONAL: "#2196F3",
}

SEVERITY_TEXT_COLORS = {
    Severity.CRITICAL:      "#fff",
    Severity.HIGH:          "#fff",
    Severity.MEDIUM:        "#000",
    Severity.LOW:           "#fff",
    Severity.INFORMATIONAL: "#fff",
}

SEVERITY_ORDER = [
    Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
    Severity.LOW, Severity.INFORMATIONAL,
]


def _sev_badge(sev: Severity) -> str:
    bg = SEVERITY_COLORS.get(sev, "#999")
    fg = SEVERITY_TEXT_COLORS.get(sev, "#fff")
    return (
        f'<span style="background:{bg};color:{fg};padding:2px 10px;'
        f'border-radius:3px;font-size:0.85em;font-weight:bold;">{sev.value}</span>'
    )


def _confidence_badge(conf: str) -> str:
    colors = {
        "HIGH":       "#27ae60",
        "MEDIUM":     "#f39c12",
        "LOW":        "#e67e22",
        "UNVERIFIED": "#95a5a6",
    }
    bg = colors.get(conf.upper(), "#95a5a6")
    return (
        f'<span style="background:{bg};color:#fff;padding:2px 8px;'
        f'border-radius:3px;font-size:0.8em;">{_escape(conf)}</span>'
    )


def _escape(text: str) -> str:
    return (text
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))


def _ordinary_html_finding(value: Any) -> SimpleNamespace:
    projected = ordinary_finding_projection(value)
    try:
        severity = Severity(str(projected.get("severity") or "Informational"))
        discovered_at = datetime.fromisoformat(
            str(
                projected.get("discovered_at")
                or projected.get("timestamp")
                or ""
            ).replace("Z", "+00:00")
        )
    except (TypeError, ValueError) as exc:
        raise EvidenceCaptureError(
            "ordinary report finding metadata is invalid"
        ) from exc
    defaults: dict[str, Any] = {
        "confidence": "UNVERIFIED",
        "cvss_v31_score": None,
        "cvss_v31_vector": None,
        "cvss_v40_score": None,
        "cvss_v40_vector": None,
        "description": "",
        "id": "",
        "mitre_attack": [],
        "module": "",
        "port": None,
        "references": [],
        "remediation": "",
        "reproduction_steps": [],
        "service": None,
        "tags": [],
        "target": "",
        "title": "",
        "vpr": None,
        "vpr_priority": None,
        "vpr_score": None,
    }
    defaults.update(projected)
    defaults["severity"] = severity
    defaults["discovered_at"] = discovered_at
    defaults["evidence_artifacts"] = ordinary_evidence_artifacts(
        projected["evidence"]
    )
    return SimpleNamespace(**defaults)


def _count_by_severity(findings: list[Any]) -> dict[str, int]:
    counts: dict[str, int] = {s.value: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    return counts


def _group_by_host(findings: list[Any]) -> dict[str, list[Any]]:
    """Group findings by target host for the host summary table."""
    groups: dict[str, list[Any]] = defaultdict(list)
    for f in findings:
        host = f.target or "unknown"
        groups[host].append(f)
    return dict(groups)


# ── HTML Generator ───────────────────────────────────────────────────────────

def generate_html(
    findings: list[Finding],
    target: str = "",
    scan_start: str = "",
    scan_end: str = "",
    assessor: str = "NetForge",
    engagement: str = "",
    mode: str = "",
    live_hosts: list[str] | None = None,
    open_ports: dict[str, Any] | None = None,
    credentials_found: int = 0,
    attack_chain_stats: dict[str, Any] | None = None,
) -> str:
    """Generate self-contained HTML report for NetForge network assessment."""
    ordinary_findings = [_ordinary_html_finding(finding) for finding in findings]
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    counts = _count_by_severity(ordinary_findings)
    total = len(ordinary_findings)

    # ── Executive Summary: severity table ─────────────────────────────────
    exec_rows = "".join(
        f'<tr><td style="color:{SEVERITY_COLORS[s]}"><b>{s.value}</b></td>'
        f'<td style="text-align:center;font-size:1.3em;font-weight:bold">{counts[s.value]}</td></tr>'
        for s in SEVERITY_ORDER
    )

    # ── Summary badges ────────────────────────────────────────────────────
    summary_badges = "".join(
        f'<span style="background:{SEVERITY_COLORS[s]};color:{SEVERITY_TEXT_COLORS[s]};'
        f'padding:8px 16px;margin:4px;border-radius:6px;font-weight:bold;font-size:1.1em;">'
        f'{s.value}: {counts[s.value]}</span>'
        for s in SEVERITY_ORDER if counts[s.value] > 0
    )

    # ── Host summary table ────────────────────────────────────────────────
    host_groups = _group_by_host(ordinary_findings)
    host_rows = ""
    for host, host_findings in sorted(host_groups.items()):
        h_counts = {s.value: 0 for s in SEVERITY_ORDER}
        ports_seen: set[int] = set()
        for f in host_findings:
            h_counts[f.severity.value] = h_counts.get(f.severity.value, 0) + 1
            if f.port:
                ports_seen.add(f.port)
        port_str = ", ".join(str(p) for p in sorted(ports_seen)[:10])
        if len(ports_seen) > 10:
            port_str += f" (+{len(ports_seen) - 10} more)"
        host_rows += (
            f'<tr>'
            f'<td><b>{_escape(host)}</b></td>'
            f'<td style="text-align:center;color:#7030A0;font-weight:bold">{h_counts["Critical"]}</td>'
            f'<td style="text-align:center;color:#CC3300;font-weight:bold">{h_counts["High"]}</td>'
            f'<td style="text-align:center;color:#FF8C00;font-weight:bold">{h_counts["Medium"]}</td>'
            f'<td style="text-align:center;color:#4CAF50">{h_counts["Low"]}</td>'
            f'<td style="text-align:center;color:#2196F3">{h_counts["Informational"]}</td>'
            f'<td style="font-size:0.85em;color:#666">{port_str}</td>'
            f'</tr>'
        )

    host_summary_html = f"""
    <h2>Host Summary</h2>
    <table style="width:100%">
      <tr>
        <th>Host</th><th style="width:60px">Crit</th><th style="width:60px">High</th>
        <th style="width:60px">Med</th><th style="width:60px">Low</th>
        <th style="width:60px">Info</th><th>Ports</th>
      </tr>
      {host_rows}
    </table>
    """ if host_rows else ""

    # ── Attack chain summary (red team mode) ──────────────────────────────
    chain_html = ""
    if attack_chain_stats:
        chain_html = f"""
    <h2>Attack Chain Summary</h2>
    <div style="background:#1a1a2e;color:#e0e0e0;padding:18px;border-radius:8px;font-family:monospace">
      <table style="border:none;color:#e0e0e0;width:auto">
        <tr><td style="border:none;padding:4px 16px 4px 0;color:#e74c3c"><b>Hosts Compromised</b></td>
            <td style="border:none;font-size:1.2em">{_escape(str(attack_chain_stats.get('compromised_hosts', 0)))}</td></tr>
        <tr><td style="border:none;padding:4px 16px 4px 0;color:#f39c12"><b>Credentials Harvested</b></td>
            <td style="border:none;font-size:1.2em">{_escape(str(attack_chain_stats.get('valid_creds', credentials_found)))}</td></tr>
        <tr><td style="border:none;padding:4px 16px 4px 0;color:#3498db"><b>Lateral Paths</b></td>
            <td style="border:none;font-size:1.2em">{_escape(str(attack_chain_stats.get('lateral_moves', 0)))}</td></tr>
        <tr><td style="border:none;padding:4px 16px 4px 0;color:#2ecc71"><b>Persistence Installed</b></td>
            <td style="border:none;font-size:1.2em">{_escape(str(attack_chain_stats.get('persistence_count', 0)))}</td></tr>
      </table>
    </div>
    """

    # ── Sort findings by severity, then by CVSS score (descending) ────────
    sorted_findings = sorted(
        ordinary_findings,
        key=lambda f: (
            SEVERITY_ORDER.index(f.severity) if f.severity in SEVERITY_ORDER else 99,
            -(f.cvss_v31_score or 0),
            f.title,
        ),
    )

    # ── Detailed finding blocks ───────────────────────────────────────────
    detail_blocks = []
    for idx, f in enumerate(sorted_findings, 1):
        repro_html = "".join(
            f"<li><code>{_escape(step)}</code></li>" for step in (f.reproduction_steps or [])
        )
        refs_html = "".join(
            f'<li><a href="{_escape(r)}" style="color:#1a73e8">{_escape(r)}</a></li>'
            if r.startswith(("http://", "https://")) else f"<li>{_escape(r)}</li>"
            for r in (f.references or [])
        )
        mitre_html = (
            ", ".join(_escape(item) for item in f.mitre_attack)
            if f.mitre_attack
            else "N/A"
        )
        tags_html = " ".join(
            f'<span style="background:#e8eaf6;color:#3949ab;padding:1px 6px;'
            f'border-radius:3px;font-size:0.75em;margin-right:4px">{_escape(t)}</span>'
            for t in (f.tags or [])
        )

        # CVSS display
        cvss31_str = (
            f"{_escape(f.cvss_v31_vector)} (<b>{_escape(str(f.cvss_v31_score))}</b>)"
            if f.cvss_v31_vector else "N/A"
        )
        cvss40_str = (
            f"{_escape(f.cvss_v40_vector)} (<b>{_escape(str(f.cvss_v40_score))}</b>)"
            if f.cvss_v40_vector else "N/A"
        )

        # VPR display
        vpr_str = ""
        if f.vpr_score is not None:
            vpr_str = (
                f'<tr><td style="color:#555;padding:4px 0"><b>VPR Score</b></td>'
                f'<td>{_escape(str(f.vpr_score))} '
                f'({_escape(str(f.vpr_priority or f.vpr or ""))})</td></tr>'
            )

        evidence_html = "".join(
            (
                "<h4>Evidence Derivative — "
                + _escape(str(artifact["capture_kind"]).replace("_", " ").title())
                + "</h4><pre style=\"background:#1e1e1e;color:#d4d4d4;"
                "padding:10px;border-radius:4px;overflow-x:auto;"
                "font-size:0.85em;max-height:300px\">"
                + _escape(str(artifact["derivative"]))
                + "</pre>"
            )
            for artifact in f.evidence_artifacts
        )

        # Port/service line
        port_service = ""
        if f.port or f.service:
            parts = []
            if f.port:
                parts.append(f"Port {f.port}")
            if f.service:
                parts.append(f.service)
            port_service = (
                f'<tr><td style="color:#555;padding:4px 0"><b>Port / Service</b></td>'
                f'<td>{_escape(" / ".join(parts))}</td></tr>'
            )

        detail_blocks.append(f"""
        <div style="border:1px solid #ddd;border-radius:8px;margin:20px 0;padding:20px;background:#fafafa;
                    border-left:4px solid {SEVERITY_COLORS.get(f.severity, '#999')}">
          <h3 style="margin:0 0 8px 0">#{idx} — {_escape(f.title)} &nbsp;{_sev_badge(f.severity)}
              &nbsp;{_confidence_badge(f.confidence)}</h3>
          {tags_html}
          <table style="width:100%;font-size:0.9em;border-collapse:collapse;margin-top:10px">
            <tr><td style="width:150px;color:#555;padding:4px 0"><b>Finding ID</b></td><td style="font-family:monospace;font-size:0.85em">{_escape(f.id)}</td></tr>
            <tr><td style="color:#555;padding:4px 0"><b>Target</b></td><td>{_escape(f.target)}</td></tr>
            {port_service}
            <tr><td style="color:#555;padding:4px 0"><b>Module</b></td><td>{_escape(f.module)}</td></tr>
            <tr><td style="color:#555;padding:4px 0"><b>CVSS 3.1</b></td><td>{cvss31_str}</td></tr>
            <tr><td style="color:#555;padding:4px 0"><b>CVSS 4.0</b></td><td>{cvss40_str}</td></tr>
            {vpr_str}
            <tr><td style="color:#555;padding:4px 0"><b>MITRE ATT&amp;CK</b></td><td>{mitre_html}</td></tr>
            <tr><td style="color:#555;padding:4px 0"><b>Discovered</b></td><td>{f.discovered_at.strftime("%Y-%m-%d %H:%M UTC")}</td></tr>
          </table>
          <h4 style="margin:14px 0 4px 0">Description</h4>
          <p style="margin:0;white-space:pre-wrap;line-height:1.5">{_escape(f.description)}</p>
          <h4 style="margin:14px 0 4px 0">Reproduction Steps</h4>
          <ol>{repro_html}</ol>
          <h4 style="margin:14px 0 4px 0">Remediation</h4>
          <p style="margin:0;background:#e8f5e9;padding:12px;border-radius:4px;border-left:3px solid #4caf50">{_escape(f.remediation)}</p>
          <h4 style="margin:14px 0 4px 0">References</h4>
          <ul>{refs_html}</ul>
          {evidence_html}
        </div>""")

    details_html = "\n".join(detail_blocks)

    # ── Engagement metadata bar ───────────────────────────────────────────
    mode_badge = ""
    if mode:
        mode_color = "#e74c3c" if "red" in mode.lower() else "#3498db"
        mode_badge = (
            f'&nbsp;|&nbsp; Mode: <span style="background:{mode_color};color:#fff;'
            f'padding:2px 8px;border-radius:3px;font-weight:bold">{_escape(mode.upper())}</span>'
        )

    live_hosts_str = ""
    if live_hosts:
        live_hosts_str = f"&nbsp;|&nbsp; Live Hosts: <b>{len(live_hosts)}</b>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>NetForge Network Security Assessment — {_escape(engagement or target)}</title>
  <style>
    body{{font-family:'Segoe UI',system-ui,Arial,sans-serif;margin:0;padding:0;background:#f0f2f5;color:#222;}}
    .page{{max-width:1200px;margin:30px auto;background:#fff;padding:40px 50px;border-radius:8px;
           box-shadow:0 4px 20px rgba(0,0,0,0.08);}}
    h1{{color:#1a237e;margin-bottom:4px;font-size:1.8em;}}
    h2{{color:#283593;border-bottom:2px solid #e3e3e3;padding-bottom:8px;margin-top:30px;}}
    table{{border-collapse:collapse;width:100%;margin:10px 0;}}
    th,td{{border:1px solid #ddd;padding:8px 12px;text-align:left;}}
    th{{background:#1a237e;color:#fff;font-weight:600;}}
    tr:nth-child(even){{background:#f9f9f9;}}
    pre{{margin:0;}}
    code{{background:#f4f4f4;padding:1px 4px;border-radius:2px;font-size:0.9em;}}
    .meta{{background:#f8f9fa;padding:14px 18px;border-radius:6px;border-left:4px solid #1a237e;
           margin-bottom:20px;font-size:0.95em;color:#555;}}
    .classification{{text-align:center;padding:8px;background:#7030A0;color:#fff;font-weight:bold;
                     font-size:0.85em;letter-spacing:1px;margin-bottom:20px;border-radius:4px;}}
    .summary-badges{{margin:15px 0;}}
    .footer{{text-align:center;font-size:0.8em;color:#888;margin-top:40px;padding-top:20px;
             border-top:1px solid #eee;}}
    @media print {{
      .page{{box-shadow:none;margin:0;padding:20px;}}
      body{{background:#fff;}}
    }}
  </style>
</head>
<body>
<div class="page">
  <div class="classification">CONFIDENTIAL — FOR AUTHORIZED USE ONLY</div>
  <h1>NetForge Network Security Assessment Report</h1>
  <div class="meta">
    Target: <b>{_escape(target)}</b> &nbsp;|&nbsp;
    Engagement: <b>{_escape(engagement or "N/A")}</b> &nbsp;|&nbsp;
    Assessor: <b>{_escape(assessor)}</b> &nbsp;|&nbsp;
    Generated: <b>{now}</b>
    {mode_badge}{live_hosts_str}
    <br>Scan Start: {_escape(str(scan_start or "N/A"))} &nbsp;|&nbsp; Scan End: {_escape(str(scan_end or "N/A"))}
  </div>

  <h2>Executive Summary</h2>
  <div class="summary-badges">{summary_badges}</div>
  <p>Total findings: <b>{total}</b></p>
  <table style="width:350px">
    <tr><th>Severity</th><th style="text-align:center">Count</th></tr>
    {exec_rows}
  </table>

  {host_summary_html}
  {chain_html}

  <h2>Detailed Findings</h2>
  {details_html if details_html else "<p>No findings recorded.</p>"}

  <div class="footer">
    Generated by NetForge v{VERSION} APEX &mdash; Network Penetration &amp; Red Team Framework<br>
    FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY
  </div>
</div>
</body>
</html>"""


# ── Module wrapper ───────────────────────────────────────────────────────────

class HtmlReport(BaseModule):
    """Generate self-contained HTML report from accumulated NetForge findings."""

    NAME        = "html_report"
    DESCRIPTION = "Generate self-contained HTML report for NetForge assessments"
    PHASE       = 14
    TAGS        = ["reporting", "html"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        findings: list[Finding] = self.config.extra.get("findings", [])
        target   = self.config.extra.get("target", self.config.target)
        out_path = Path(self.config.extra.get(
            "output_path", self.results_dir / "netforge_report.html"
        ))
        out_path.parent.mkdir(parents=True, exist_ok=True)

        html = generate_html(
            findings=findings,
            target=target,
            scan_start=self.config.extra.get("scan_start", ""),
            scan_end=self.config.extra.get("scan_end", ""),
            assessor=self.config.extra.get("assessor", "NetForge"),
            engagement=self.config.extra.get("engagement", self.config.engagement),
            mode=self.config.extra.get("mode", ""),
            live_hosts=self.config.extra.get("live_hosts"),
            open_ports=self.config.extra.get("open_ports"),
            credentials_found=self.config.extra.get("credentials_found", 0),
            attack_chain_stats=self.config.extra.get("attack_chain_stats"),
        )
        out_path.write_text(html, encoding="utf-8")
        self.log.info("HTML report written to %s (%d findings)", out_path, len(findings))
        return self._make_result(start)


# ── Tests ────────────────────────────────────────────────────────────────────

class TestHtmlReport:
    def test_phase(self) -> None:
        assert HtmlReport.PHASE == 14

    def test_generate_html_empty(self) -> None:
        html = generate_html([], target="10.0.0.0/24")
        assert "<!DOCTYPE html>" in html
        assert "No findings recorded" in html
        assert "NetForge" in html

    def test_severity_badge(self) -> None:
        badge = _sev_badge(Severity.CRITICAL)
        assert "Critical" in badge
        assert "#7030A0" in badge

    def test_escape(self) -> None:
        assert "&lt;script&gt;" == _escape("<script>")
        assert "&amp;" in _escape("&")
