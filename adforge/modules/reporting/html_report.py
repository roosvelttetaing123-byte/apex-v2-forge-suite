"""HTML Report — ADForge findings to styled HTML report."""
from __future__ import annotations
import html as html_mod, sys, time
from datetime import datetime, timezone
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from common.base_module import BaseModule, ModuleResult

SEVERITY_COLORS = {
    "CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#ca8a04",
    "LOW": "#2563eb", "INFORMATIONAL": "#6b7280",
}

class HtmlReport(BaseModule):
    NAME = "html_report"
    DESCRIPTION = "Generate styled HTML report from ADForge findings"
    PHASE = 14
    TAGS = ["reporting", "html"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        findings = self.config.extra.get("findings", [])
        if not findings:
            return self._make_result(start, skipped=True, skip_reason="no findings")

        out_dir = Path(self.config.extra.get("output_dir", self.results_dir))
        out_dir.mkdir(parents=True, exist_ok=True)

        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        domain = self.config.extra.get("domain", "Unknown")
        target = self.config.target

        sev_counts = {}
        for f in findings:
            s = str(f.get("severity", "INFORMATIONAL")).split(".")[-1].upper()
            sev_counts[s] = sev_counts.get(s, 0) + 1

        parts = [f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>ADForge Report — {html_mod.escape(domain)}</title>
<style>
body {{ font-family: 'Segoe UI', sans-serif; margin: 2em; background: #f8fafc; color: #1e293b; }}
h1 {{ color: #0f172a; border-bottom: 3px solid #3b82f6; padding-bottom: .5em; }}
.summary {{ display: flex; gap: 1em; margin: 1em 0; }}
.stat {{ padding: 1em 2em; border-radius: 8px; color: white; font-weight: bold; text-align: center; min-width: 120px; }}
.finding {{ background: white; border: 1px solid #e2e8f0; border-radius: 8px; margin: 1em 0; padding: 1.5em; box-shadow: 0 1px 3px rgba(0,0,0,.1); }}
.finding h3 {{ margin-top: 0; }}
.sev-badge {{ display: inline-block; padding: 2px 10px; border-radius: 4px; color: white; font-size: .85em; font-weight: bold; }}
.desc {{ background: #f1f5f9; padding: 1em; border-radius: 4px; margin: .5em 0; white-space: pre-wrap; font-size: .9em; }}
.remediation {{ border-left: 3px solid #22c55e; padding-left: 1em; margin: .5em 0; }}
.cvss {{ font-family: monospace; font-size: .85em; color: #475569; }}
</style></head><body>
<h1>🛡️ ADForge Security Report</h1>
<p><strong>Domain:</strong> {html_mod.escape(domain)} | <strong>Target:</strong> {html_mod.escape(target)} | <strong>Date:</strong> {now}</p>
<div class="summary">"""]

        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]:
            count = sev_counts.get(sev, 0)
            color = SEVERITY_COLORS.get(sev, "#6b7280")
            parts.append(f'<div class="stat" style="background:{color}">{sev}<br>{count}</div>')

        parts.append(f'</div><h2>{len(findings)} Finding(s)</h2>')

        for i, f in enumerate(findings, 1):
            sev = str(f.get("severity", "INFORMATIONAL")).split(".")[-1].upper()
            color = SEVERITY_COLORS.get(sev, "#6b7280")
            title = html_mod.escape(str(f.get("title", "?")))
            desc = html_mod.escape(str(f.get("description", "")))
            remed = html_mod.escape(str(f.get("remediation", "")))
            cvss31 = html_mod.escape(str(f.get("cvss_v31_vector", "")))
            cvss40 = html_mod.escape(str(f.get("cvss_v40_vector", "")))

            parts.append(f"""<div class="finding">
<h3>#{i} {title}</h3>
<span class="sev-badge" style="background:{color}">{sev}</span>
<span class="cvss">CVSS 3.1: {cvss31}</span> | <span class="cvss">CVSS 4.0: {cvss40}</span>
<div class="desc">{desc}</div>
<div class="remediation"><strong>Remediation:</strong> {remed}</div>
</div>""")

        parts.append("</body></html>")
        out_file = out_dir / "adforge_report.html"
        out_file.write_text("\n".join(parts), encoding="utf-8")
        self.log.info("HTML report: %s (%d findings)", out_file, len(findings))
        return self._make_result(start)

class TestHtmlReport:
    def test_phase(self) -> None: assert HtmlReport.PHASE == 14
