"""PDF report generator using reportlab."""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult

_SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]
_SEVERITY_RGB = {
    "Critical":      (0.86, 0.15, 0.15),
    "High":          (0.92, 0.35, 0.05),
    "Medium":        (0.85, 0.47, 0.02),
    "Low":           (0.15, 0.39, 0.92),
    "Informational": (0.42, 0.45, 0.50),
}


def generate_pdf(findings: list[dict], target: str, output_path: Path) -> None:
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib import colors
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.units import mm
    except ImportError:
        output_path.write_text(f"# PDF generation requires: pip install reportlab\nTarget: {target}\nFindings: {len(findings)}\n")
        return

    from datetime import datetime, timezone
    scan_date = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    doc = SimpleDocTemplate(str(output_path), pagesize=A4, topMargin=20*mm, bottomMargin=20*mm)
    styles = getSampleStyleSheet()
    story = []

    title_style = ParagraphStyle("title", parent=styles["Title"], fontSize=20, spaceAfter=6)
    h2_style    = ParagraphStyle("h2", parent=styles["Heading2"], fontSize=14, spaceAfter=4)
    h3_style    = ParagraphStyle("h3", parent=styles["Heading3"], fontSize=11, spaceAfter=3)
    body_style  = styles["BodyText"]

    story.append(Paragraph("WebForge Security Assessment Report", title_style))
    story.append(Paragraph(f"Target: {target} &nbsp;|&nbsp; Date: {scan_date}", body_style))
    story.append(Spacer(1, 8*mm))

    counts = {s: sum(1 for f in findings if f.get("severity") == s) for s in _SEVERITY_ORDER}
    story.append(Paragraph("Executive Summary", h2_style))
    summary_data = [["Severity", "Count"]] + [[s, str(counts[s])] for s in _SEVERITY_ORDER if counts[s]]
    t = Table(summary_data, colWidths=[80*mm, 30*mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
    ]))
    story.append(t)
    story.append(Spacer(1, 8*mm))

    sorted_findings = sorted(findings, key=lambda f: _SEVERITY_ORDER.index(f.get("severity", "Informational")))
    story.append(Paragraph("Detailed Findings", h2_style))

    for f in sorted_findings:
        sev   = f.get("severity", "Informational")
        r, g, b = _SEVERITY_RGB.get(sev, (0.42, 0.45, 0.50))
        sev_color = colors.Color(r, g, b)
        story.append(Paragraph(f'<font color="#{int(r*255):02x}{int(g*255):02x}{int(b*255):02x}">[{sev}]</font> {f.get("title","")}', h3_style))
        story.append(Paragraph(f'<b>Target:</b> {f.get("target","")} | <b>CVSS:</b> {f.get("cvss_v31_score","")} | <b>Module:</b> {f.get("module","")}', body_style))
        story.append(Paragraph(f.get("description", ""), body_style))

        steps = f.get("reproduction_steps", [])
        if steps:
            story.append(Paragraph("<b>Reproduction Steps:</b>", body_style))
            for i, s in enumerate(steps, 1):
                story.append(Paragraph(f"{i}. {s}", body_style))

        story.append(Paragraph(f'<b>Remediation:</b> {f.get("remediation","")}', body_style))
        story.append(Spacer(1, 4*mm))

    doc.build(story)


class PdfReport(BaseModule):
    NAME        = "pdf_report"
    DESCRIPTION = "Generate PDF assessment report using reportlab"
    PHASE       = 99
    TAGS        = ["reporting"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        findings_raw: list[dict] = self.config.extra.get("findings", [])
        if not findings_raw:
            return self._make_result(start, skipped=True, skip_reason="no findings")

        out_dir = Path(self.config.extra.get("output_dir", self.results_dir))
        out_dir.mkdir(parents=True, exist_ok=True)
        out_file = out_dir / "webforge_report.pdf"
        generate_pdf(findings_raw, self.config.target, out_file)
        self.log.info("PDF report written: %s", out_file)
        return self._make_result(start)
