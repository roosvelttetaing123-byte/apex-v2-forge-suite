"""PDF Report — ADForge findings to PDF using reportlab or HTML-to-PDF."""
from __future__ import annotations
import html as html_mod, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from common.base_module import BaseModule, ModuleResult

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4}

class PdfReport(BaseModule):
    NAME = "pdf_report"
    DESCRIPTION = "Generate PDF report from ADForge findings"
    PHASE = 14
    TAGS = ["reporting", "pdf"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        findings = self.config.extra.get("findings", [])
        if not findings:
            return self._make_result(start, skipped=True, skip_reason="no findings")

        out_dir = Path(self.config.extra.get("output_dir", self.results_dir))
        out_dir.mkdir(parents=True, exist_ok=True)
        out_file = out_dir / "adforge_report.pdf"

        try:
            self._generate_reportlab(findings, out_file)
        except ImportError:
            # Fallback: generate HTML-based PDF placeholder
            self._generate_html_pdf(findings, out_file)

        self.log.info("PDF report: %s (%d findings)", out_file, len(findings))
        return self._make_result(start)

    def _generate_reportlab(self, findings: list, out_file: Path) -> None:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib import colors
        from datetime import datetime, timezone

        doc = SimpleDocTemplate(str(out_file), pagesize=A4)
        styles = getSampleStyleSheet()
        elements = []

        elements.append(Paragraph("ADForge Security Report", styles["Title"]))
        elements.append(Paragraph(
            f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} | "
            f"Target: {self.config.target} | "
            f"Findings: {len(findings)}", styles["Normal"]))
        elements.append(Spacer(1, 20))

        # Sort by severity
        sorted_findings = sorted(findings,
            key=lambda f: SEVERITY_ORDER.get(str(f.get("severity", "INFORMATIONAL")).split(".")[-1].upper(), 9))

        sev_colors = {
            "CRITICAL": colors.red, "HIGH": colors.orangered,
            "MEDIUM": colors.orange, "LOW": colors.blue, "INFORMATIONAL": colors.grey}

        for i, f in enumerate(sorted_findings[:50], 1):
            sev = str(f.get("severity", "INFORMATIONAL")).split(".")[-1].upper()
            title = str(f.get("title", "?"))
            desc = str(f.get("description", ""))[:500]
            remed = str(f.get("remediation", ""))[:300]
            color = sev_colors.get(sev, colors.grey)

            elements.append(Paragraph(f"<b>#{i} [{sev}] {html_mod.escape(title)}</b>", styles["Heading3"]))
            elements.append(Paragraph(html_mod.escape(desc), styles["Normal"]))
            if remed:
                elements.append(Paragraph(f"<i>Remediation: {html_mod.escape(remed)}</i>", styles["Normal"]))
            elements.append(Spacer(1, 10))

        doc.build(elements)

    def _generate_html_pdf(self, findings: list, out_file: Path) -> None:
        # Fallback: write a text-based report
        lines = ["ADForge Security Report", "=" * 40, ""]
        for i, f in enumerate(findings[:50], 1):
            sev = str(f.get("severity", "INFORMATIONAL")).split(".")[-1].upper()
            lines.append(f"#{i} [{sev}] {f.get('title', '?')}")
            lines.append(f"  {f.get('description', '')[:200]}")
            lines.append(f"  Remediation: {f.get('remediation', '')[:200]}")
            lines.append("")
        out_file.with_suffix(".txt").write_text("\n".join(lines), encoding="utf-8")
        self.log.info("reportlab not available — wrote text fallback")

class TestPdfReport:
    def test_phase(self) -> None: assert PdfReport.PHASE == 14
