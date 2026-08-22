"""PDF report generation — produce a professional PDF assessment report.

Uses ReportLab for PDF generation. Falls back to HTML-to-text if ReportLab
is not installed.
"""
from __future__ import annotations

import html
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
from common.version import VERSION

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]
SEVERITY_RGB = {
    "Critical":      (0.86, 0.15, 0.15),
    "High":          (0.92, 0.35, 0.05),
    "Medium":        (0.85, 0.47, 0.02),
    "Low":           (0.15, 0.39, 0.92),
    "Informational": (0.42, 0.45, 0.50),
}


class PdfReport(BaseModule):
    """PDF report — generate a professional PDF security assessment."""

    NAME        = "pdf_report"
    DESCRIPTION = "Generate PDF security assessment report with executive summary and detailed findings"
    PHASE       = 8
    TAGS        = ["reporting", "pdf"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()

        all_findings: list[dict[str, Any]] = self.config.extra.get("all_findings", [])
        if not all_findings:
            self.log.info("No findings to report")
            return self._make_result(start, skipped=True, skip_reason="no findings")

        report_path = self.results_dir / "aiforge_report.pdf"
        report_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            self._generate_reportlab(all_findings, report_path)
        except ImportError:
            self.log.info("ReportLab not installed, generating text-based PDF fallback")
            self._generate_text_fallback(all_findings, report_path)

        self.log.info("PDF report written to %s", report_path)

        self.new_finding(
            title="PDF Assessment Report Generated",
            severity=Severity.INFORMATIONAL,
            description=f"PDF report: {report_path}",
            reproduction_steps=["Open PDF report"],
            remediation="N/A",
            references=[],
            evidence=Evidence(extra={"report_path": str(report_path), "finding_count": len(all_findings)}),
            target=self.config.target,
        )

        return self._make_result(start)

    def _generate_reportlab(self, findings: list[dict[str, Any]], output: Path) -> None:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import cm, mm
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            PageBreak, HRFlowable,
        )

        doc = SimpleDocTemplate(
            str(output), pagesize=A4,
            leftMargin=2*cm, rightMargin=2*cm,
            topMargin=2*cm, bottomMargin=2*cm,
        )

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle("CustomTitle", parent=styles["Title"], fontSize=24, spaceAfter=12)
        heading_style = ParagraphStyle("CustomH2", parent=styles["Heading2"], fontSize=14, spaceBefore=18, spaceAfter=8)
        body_style = styles["BodyText"]
        small_style = ParagraphStyle("Small", parent=body_style, fontSize=8, textColor=colors.grey)

        target = self.config.target
        scan_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        severity_counts = {s: 0 for s in SEVERITY_ORDER}
        for f in findings:
            sev = f.get("severity", "Informational")
            if sev in severity_counts:
                severity_counts[sev] += 1

        story: list[Any] = []

        # Title
        story.append(Paragraph("AIForge Security Assessment Report", title_style))
        story.append(Paragraph(f"Target: {target}", body_style))
        story.append(Paragraph(f"Date: {scan_time}", body_style))
        story.append(Paragraph(f"Total Findings: {len(findings)}", body_style))
        story.append(Spacer(1, 20))

        # Executive Summary
        story.append(Paragraph("Executive Summary", heading_style))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.grey))
        story.append(Spacer(1, 8))

        summary_data = [["Severity", "Count"]]
        for sev in SEVERITY_ORDER:
            summary_data.append([sev, str(severity_counts[sev])])
        summary_data.append(["Total", str(len(findings))])

        summary_table = Table(summary_data, colWidths=[8*cm, 4*cm])
        summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -2), [colors.white, colors.HexColor("#f8fafc")]),
            ("BACKGROUND", (0, -1), (-1, -1), colors.HexColor("#e2e8f0")),
            ("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"),
            ("ALIGN", (1, 0), (1, -1), "CENTER"),
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 20))

        # Detailed Findings
        story.append(Paragraph("Detailed Findings", heading_style))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.grey))
        story.append(Spacer(1, 8))

        order = {s: i for i, s in enumerate(SEVERITY_ORDER)}
        findings.sort(key=lambda f: order.get(f.get("severity", "Informational"), 99))

        for i, f in enumerate(findings, 1):
            sev = f.get("severity", "Informational")
            r, g, b = SEVERITY_RGB.get(sev, (0.5, 0.5, 0.5))
            sev_color = colors.Color(r, g, b)

            story.append(Paragraph(
                f'<font color="#{int(r*255):02x}{int(g*255):02x}{int(b*255):02x}">'
                f"[{sev}]</font> {i}. {f.get('title', 'Untitled')}",
                ParagraphStyle("FindingTitle", parent=styles["Heading3"], fontSize=11),
            ))

            story.append(Paragraph(f"<b>Module:</b> {f.get('module', 'N/A')}", body_style))

            cvss31 = f.get("cvss_v31_score")
            cvss40 = f.get("cvss_v40_score")
            if cvss31 or cvss40:
                cvss_parts = []
                if cvss31:
                    cvss_parts.append(f"CVSS 3.1: {cvss31}")
                if cvss40:
                    cvss_parts.append(f"CVSS 4.0: {cvss40}")
                story.append(Paragraph(f"<b>Score:</b> {' | '.join(cvss_parts)}", body_style))

            desc = f.get("description", "")[:800]
            story.append(Paragraph(f"<b>Description:</b> {desc}", body_style))

            remed = f.get("remediation", "")
            if remed:
                story.append(Paragraph(f"<b>Remediation:</b> {remed}", body_style))

            refs = f.get("references", [])
            if refs:
                story.append(Paragraph(f"<b>References:</b> {', '.join(refs)}", body_style))

            story.append(Spacer(1, 12))

        # Footer
        story.append(Spacer(1, 30))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.grey))
        story.append(Paragraph(f"Generated by AIForge v{VERSION} | {scan_time}", small_style))

        doc.build(story)

    def _generate_text_fallback(self, findings: list[dict[str, Any]], output: Path) -> None:
        """Plain-text fallback when ReportLab is not available."""
        target = self.config.target
        scan_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        lines: list[str] = [
            "=" * 60,
            "AIFORGE SECURITY ASSESSMENT REPORT",
            "=" * 60,
            f"Target: {target}",
            f"Date: {scan_time}",
            f"Total Findings: {len(findings)}",
            "",
        ]

        severity_counts = {s: 0 for s in SEVERITY_ORDER}
        for f in findings:
            sev = f.get("severity", "Informational")
            if sev in severity_counts:
                severity_counts[sev] += 1

        lines.append("EXECUTIVE SUMMARY")
        lines.append("-" * 40)
        for sev in SEVERITY_ORDER:
            lines.append(f"  {sev}: {severity_counts[sev]}")
        lines.append("")

        lines.append("DETAILED FINDINGS")
        lines.append("-" * 40)

        order = {s: i for i, s in enumerate(SEVERITY_ORDER)}
        findings.sort(key=lambda f: order.get(f.get("severity", "Informational"), 99))

        for i, f in enumerate(findings, 1):
            sev = f.get("severity", "Informational")
            lines.append(f"\n[{sev}] {i}. {f.get('title', 'Untitled')}")
            lines.append(f"  Module: {f.get('module', 'N/A')}")
            lines.append(f"  {f.get('description', '')[:500]}")
            lines.append(f"  Remediation: {f.get('remediation', 'N/A')}")

        lines.append(f"\nGenerated by AIForge v{VERSION} | {scan_time}")

        # Write as .txt alongside the .pdf path
        txt_path = output.with_suffix(".txt")
        txt_path.write_text("\n".join(lines), encoding="utf-8")
        self.log.info("Text fallback report: %s (install reportlab for PDF)", txt_path)


class TestPdfReport:
    def test_severity_rgb(self) -> None:
        for s in SEVERITY_ORDER:
            assert s in SEVERITY_RGB
            r, g, b = SEVERITY_RGB[s]
            assert 0 <= r <= 1 and 0 <= g <= 1 and 0 <= b <= 1

    def test_text_fallback(self, tmp_path: Path) -> None:
        from common.config import BaseForgeConfig
        from common.scope import Scope
        from common.db import create_db

        cfg = BaseForgeConfig(target="https://example.com")
        cfg.extra["all_findings"] = [{"title": "Test", "severity": "High", "module": "t", "description": "d"}]
        scope = Scope(["0.0.0.0/0"])
        session = create_db(tmp_path / "test.db")
        mod = PdfReport(cfg, scope, session, tmp_path)
        mod._generate_text_fallback(cfg.extra["all_findings"], tmp_path / "report.pdf")
        assert (tmp_path / "report.txt").exists()
        session.close()
