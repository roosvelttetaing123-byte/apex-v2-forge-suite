"""NetForge PDF Report — professional PDF generation for network assessments.

Uses reportlab for PDF construction with proper typography, severity-coded
tables, host breakdowns, and attack chain visualization.

Falls back to a markdown stub if reportlab isn't installed.
"""
from __future__ import annotations

import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.finding import Finding, Severity
from common.version import VERSION


# ── Severity theming ─────────────────────────────────────────────────────────

_SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]

_SEVERITY_RGB = {
    "Critical":      (0.44, 0.19, 0.63),   # #7030A0
    "High":          (0.80, 0.20, 0.00),   # #CC3300
    "Medium":        (1.00, 0.55, 0.00),   # #FF8C00
    "Low":           (0.30, 0.69, 0.31),   # #4CAF50
    "Informational": (0.13, 0.59, 0.95),   # #2196F3
}

_CONFIDENCE_RGB = {
    "HIGH":       (0.15, 0.68, 0.38),
    "MEDIUM":     (0.95, 0.61, 0.07),
    "LOW":        (0.90, 0.49, 0.13),
    "UNVERIFIED": (0.58, 0.65, 0.65),
}


def _finding_to_dict(f: Any) -> dict:
    """Normalize a finding to a dict regardless of input type."""
    if isinstance(f, dict):
        return f
    if hasattr(f, "to_dict"):
        return f.to_dict()
    return {"title": str(getattr(f, "title", "")), "severity": "Informational"}


def generate_pdf(
    findings: list[dict],
    target: str,
    output_path: Path,
    engagement: str = "",
    mode: str = "",
    live_hosts: list[str] | None = None,
    credentials_found: int = 0,
    attack_chain_stats: dict[str, Any] | None = None,
) -> None:
    """Generate a professional PDF report from findings dicts."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            PageBreak, HRFlowable,
        )
        from reportlab.lib.units import mm, inch
    except ImportError:
        # Fallback: write a markdown summary
        lines = [
            f"# NetForge Network Security Assessment Report",
            f"",
            f"**Target:** {target}",
            f"**Engagement:** {engagement or 'N/A'}",
            f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
            f"**Total Findings:** {len(findings)}",
            f"",
            f"_PDF generation requires: `pip install reportlab`_",
            f"",
        ]
        for i, f in enumerate(findings, 1):
            lines.append(f"## {i}. [{f.get('severity', '')}] {f.get('title', '')}")
            lines.append(f"**Target:** {f.get('target', '')} | **CVSS:** {f.get('cvss_v31_score', 'N/A')}")
            lines.append(f"{f.get('description', '')[:500]}")
            lines.append("")
        output_path.write_text("\n".join(lines), encoding="utf-8")
        return

    scan_date = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    doc = SimpleDocTemplate(
        str(output_path), pagesize=A4,
        topMargin=20*mm, bottomMargin=20*mm,
        leftMargin=20*mm, rightMargin=20*mm,
    )
    styles = getSampleStyleSheet()
    story: list[Any] = []

    # ── Custom styles ─────────────────────────────────────────────────────
    title_style = ParagraphStyle(
        "nf_title", parent=styles["Title"],
        fontSize=22, spaceAfter=4, textColor=colors.HexColor("#1a237e"),
    )
    h2_style = ParagraphStyle(
        "nf_h2", parent=styles["Heading2"],
        fontSize=15, spaceAfter=6, textColor=colors.HexColor("#283593"),
        borderPadding=(0, 0, 4, 0),
    )
    h3_style = ParagraphStyle(
        "nf_h3", parent=styles["Heading3"],
        fontSize=11, spaceAfter=3,
    )
    body_style = ParagraphStyle(
        "nf_body", parent=styles["BodyText"],
        fontSize=9, leading=12,
    )
    meta_style = ParagraphStyle(
        "nf_meta", parent=styles["BodyText"],
        fontSize=9, textColor=colors.HexColor("#555555"),
    )
    code_style = ParagraphStyle(
        "nf_code", parent=styles["Code"],
        fontSize=7, leading=9, backColor=colors.HexColor("#f4f4f4"),
        borderPadding=(4, 4, 4, 4),
    )
    classification_style = ParagraphStyle(
        "nf_class", parent=styles["Normal"],
        fontSize=8, alignment=TA_CENTER, textColor=colors.white,
        backColor=colors.HexColor("#7030A0"),
        borderPadding=(6, 6, 6, 6),
        spaceAfter=12,
    )

    # ── Classification banner ─────────────────────────────────────────────
    story.append(Paragraph(
        "CONFIDENTIAL — FOR AUTHORIZED USE ONLY",
        classification_style,
    ))
    story.append(Spacer(1, 4*mm))

    # ── Title ─────────────────────────────────────────────────────────────
    story.append(Paragraph("NetForge Network Security Assessment Report", title_style))
    story.append(Spacer(1, 2*mm))

    # ── Metadata ──────────────────────────────────────────────────────────
    meta_parts = [f"<b>Target:</b> {target}"]
    if engagement:
        meta_parts.append(f"<b>Engagement:</b> {engagement}")
    if mode:
        meta_parts.append(f"<b>Mode:</b> {mode.upper()}")
    meta_parts.append(f"<b>Date:</b> {scan_date}")
    meta_parts.append(f"<b>Findings:</b> {len(findings)}")
    if live_hosts:
        meta_parts.append(f"<b>Live Hosts:</b> {len(live_hosts)}")
    story.append(Paragraph(" &nbsp;|&nbsp; ".join(meta_parts), meta_style))
    story.append(Spacer(1, 8*mm))

    # ── Executive Summary ─────────────────────────────────────────────────
    story.append(Paragraph("Executive Summary", h2_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e3e3e3")))
    story.append(Spacer(1, 3*mm))

    counts = {s: sum(1 for f in findings if f.get("severity") == s) for s in _SEVERITY_ORDER}
    summary_data = [["Severity", "Count"]]
    for s in _SEVERITY_ORDER:
        if counts[s] > 0:
            summary_data.append([s, str(counts[s])])

    if len(summary_data) > 1:
        t = Table(summary_data, colWidths=[80*mm, 30*mm])
        t_style = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a237e")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ("ALIGN", (1, 0), (1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]
        # Color-code severity rows
        for row_idx, row in enumerate(summary_data[1:], 1):
            sev = row[0]
            r, g, b = _SEVERITY_RGB.get(sev, (0.5, 0.5, 0.5))
            t_style.append(("TEXTCOLOR", (0, row_idx), (0, row_idx), colors.Color(r, g, b)))
            t_style.append(("FONTNAME", (0, row_idx), (0, row_idx), "Helvetica-Bold"))

        t.setStyle(TableStyle(t_style))
        story.append(t)
    else:
        story.append(Paragraph("No findings detected.", body_style))

    story.append(Spacer(1, 8*mm))

    # ── Attack chain summary (red team mode) ──────────────────────────────
    if attack_chain_stats:
        story.append(Paragraph("Attack Chain Summary", h2_style))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e3e3e3")))
        story.append(Spacer(1, 3*mm))
        chain_data = [
            ["Metric", "Value"],
            ["Hosts Compromised", str(attack_chain_stats.get("compromised_hosts", 0))],
            ["Credentials Harvested", str(attack_chain_stats.get("valid_creds", credentials_found))],
            ["Lateral Paths", str(attack_chain_stats.get("lateral_moves", 0))],
            ["Persistence Installed", str(attack_chain_stats.get("persistence_count", 0))],
        ]
        ct = Table(chain_data, colWidths=[80*mm, 30*mm])
        ct.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("TEXTCOLOR", (0, 1), (-1, -1), colors.HexColor("#333333")),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
        ]))
        story.append(ct)
        story.append(Spacer(1, 8*mm))

    # ── Detailed Findings ─────────────────────────────────────────────────
    story.append(Paragraph("Detailed Findings", h2_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e3e3e3")))
    story.append(Spacer(1, 3*mm))

    sorted_findings = sorted(
        findings,
        key=lambda f: (
            _SEVERITY_ORDER.index(f.get("severity", "Informational"))
            if f.get("severity", "Informational") in _SEVERITY_ORDER else 99,
            -(float(f.get("cvss_v31_score") or 0)),
        ),
    )

    for idx, f in enumerate(sorted_findings, 1):
        sev = f.get("severity", "Informational")
        r, g, b = _SEVERITY_RGB.get(sev, (0.5, 0.5, 0.5))
        sev_color = colors.Color(r, g, b)

        # Finding header
        header = (
            f'<font color="#{int(r*255):02x}{int(g*255):02x}{int(b*255):02x}">'
            f'[{sev}]</font> {f.get("title", "")}'
        )
        story.append(Paragraph(header, h3_style))

        # Metadata line
        meta_items = []
        if f.get("target"):
            meta_items.append(f'<b>Target:</b> {f["target"]}')
        if f.get("port"):
            meta_items.append(f'<b>Port:</b> {f["port"]}')
        if f.get("service"):
            meta_items.append(f'<b>Service:</b> {f["service"]}')
        if f.get("cvss_v31_score"):
            meta_items.append(f'<b>CVSS 3.1:</b> {f["cvss_v31_score"]}')
        if f.get("cvss_v40_score"):
            meta_items.append(f'<b>CVSS 4.0:</b> {f["cvss_v40_score"]}')
        if f.get("module"):
            meta_items.append(f'<b>Module:</b> {f["module"]}')
        if f.get("confidence"):
            meta_items.append(f'<b>Confidence:</b> {f["confidence"]}')
        if f.get("vpr_score"):
            meta_items.append(f'<b>VPR:</b> {f["vpr_score"]}')
        story.append(Paragraph(" | ".join(meta_items), meta_style))
        story.append(Spacer(1, 2*mm))

        # Description
        desc = f.get("description", "")
        if desc:
            story.append(Paragraph(desc[:2000], body_style))
            story.append(Spacer(1, 2*mm))

        # Reproduction steps
        steps = f.get("reproduction_steps", [])
        if steps:
            story.append(Paragraph("<b>Reproduction Steps:</b>", body_style))
            for i, s in enumerate(steps, 1):
                story.append(Paragraph(f"{i}. <font face='Courier' size='7'>{s}</font>", body_style))

        # MITRE ATT&CK
        mitre = f.get("mitre_attack", [])
        if mitre:
            story.append(Paragraph(f'<b>MITRE ATT&amp;CK:</b> {", ".join(mitre)}', body_style))

        # Remediation
        remediation = f.get("remediation", "")
        if remediation:
            story.append(Paragraph(f'<b>Remediation:</b> {remediation}', body_style))

        # References
        refs = f.get("references", [])
        if refs:
            ref_str = ", ".join(refs[:5])
            story.append(Paragraph(f'<b>References:</b> {ref_str}', meta_style))

        story.append(Spacer(1, 6*mm))
        story.append(HRFlowable(
            width="100%", thickness=0.5,
            color=colors.HexColor("#eeeeee"), spaceAfter=4,
        ))

    # ── Footer ────────────────────────────────────────────────────────────
    story.append(Spacer(1, 10*mm))
    footer_style = ParagraphStyle(
        "nf_footer", parent=styles["Normal"],
        fontSize=7, alignment=TA_CENTER, textColor=colors.HexColor("#999999"),
    )
    story.append(Paragraph(
        f"Generated by NetForge v{VERSION} APEX — Network Penetration &amp; Red Team Framework<br/>"
        "FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY",
        footer_style,
    ))

    doc.build(story)


# ── Module wrapper ───────────────────────────────────────────────────────────

class PdfReport(BaseModule):
    """Generate professional PDF report for NetForge assessments."""

    NAME        = "pdf_report"
    DESCRIPTION = "Generate PDF assessment report for NetForge"
    PHASE       = 14
    TAGS        = ["reporting", "pdf"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        findings_raw: list = self.config.extra.get("findings", [])
        normalized = [_finding_to_dict(f) for f in findings_raw]

        if not normalized:
            return self._make_result(start, skipped=True, skip_reason="no findings")

        out_dir = Path(self.config.extra.get("output_dir", self.results_dir))
        out_dir.mkdir(parents=True, exist_ok=True)
        out_file = out_dir / "netforge_report.pdf"

        generate_pdf(
            findings=normalized,
            target=self.config.target,
            output_path=out_file,
            engagement=self.config.extra.get("engagement", self.config.engagement),
            mode=self.config.extra.get("mode", ""),
            live_hosts=self.config.extra.get("live_hosts"),
            credentials_found=self.config.extra.get("credentials_found", 0),
            attack_chain_stats=self.config.extra.get("attack_chain_stats"),
        )
        self.log.info("PDF report written: %s (%d findings)", out_file, len(normalized))
        return self._make_result(start)


# ── Tests ────────────────────────────────────────────────────────────────────

class TestPdfReport:
    def test_phase(self) -> None:
        assert PdfReport.PHASE == 14

    def test_finding_to_dict_from_dict(self) -> None:
        d = {"title": "test", "severity": "High"}
        assert _finding_to_dict(d) == d

    def test_severity_rgb_coverage(self) -> None:
        for s in _SEVERITY_ORDER:
            assert s in _SEVERITY_RGB
