"""Base report orchestrator — generates HTML, PDF, JSON, CSV from findings."""
from __future__ import annotations

import base64
import csv
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    _JINJA2_AVAILABLE = True
except ImportError:
    _JINJA2_AVAILABLE = False

_TEMPLATE_DIR = Path(__file__).parent / "templates"

log = logging.getLogger(__name__)

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}


class BaseReporter:
    """Base reporter that serializes findings to multiple output formats."""

    def __init__(
        self,
        findings: list[dict[str, Any]],
        results_dir: Path,
        engagement: str = "default",
        target: str = "",
        tester: str = "anonymous",
        framework: str = "forge",
        formats: list[str] | None = None,
    ) -> None:
        self.findings     = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", ""), 99))
        self.results_dir  = results_dir
        self.engagement   = engagement
        self.target       = target
        self.tester       = tester
        self.framework    = framework
        self.formats      = formats or ["html", "pdf", "json", "csv"]
        self.generated_at = datetime.now(timezone.utc).isoformat()
        results_dir.mkdir(parents=True, exist_ok=True)

    def generate_all(self) -> dict[str, str]:
        """Generate all configured report formats.

        Returns:
            Dict mapping format name to output file path.
        """
        paths: dict[str, str] = {}
        for fmt in self.formats:
            try:
                method = getattr(self, f"generate_{fmt}", None)
                if method:
                    path = method()
                    if path:
                        paths[fmt] = path
                        log.info("Report generated: %s → %s", fmt, path)
            except Exception as exc:
                log.error("Report generation failed for %s: %s", fmt, exc)
        return paths

    def generate_json(self) -> str:
        """Generate JSON findings export."""
        out = {
            "generated_at": self.generated_at,
            "engagement":   self.engagement,
            "target":       self.target,
            "tester":       self.tester,
            "framework":    self.framework,
            "total":        len(self.findings),
            "summary":      self._severity_summary(),
            "findings":     self.findings,
        }
        path = self.results_dir / "findings.json"
        path.write_text(json.dumps(out, indent=2, default=str), encoding="utf-8")
        return str(path)

    def generate_csv(self) -> str:
        """Generate CSV findings export."""
        path = self.results_dir / "findings.csv"
        fields = ["id", "title", "severity", "cvss_v31_score", "target",
                  "port", "service", "module", "discovered_at"]
        with path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(self.findings)
        return str(path)

    def generate_html(self) -> str:
        """Generate a self-contained HTML report via Jinja2 template (falls back to inline)."""
        path = self.results_dir / "report.html"
        html = self._build_html_jinja2() if _JINJA2_AVAILABLE else self._build_html_inline()
        path.write_text(html, encoding="utf-8")
        return str(path)

    def generate_pdf(self) -> str | None:
        """Generate PDF report from HTML via WeasyPrint."""
        try:
            from weasyprint import HTML as WeasyprintHTML
            html_path = self.results_dir / "report.html"
            if not html_path.exists():
                self.generate_html()
            pdf_path = self.results_dir / "report.pdf"
            WeasyprintHTML(filename=str(html_path)).write_pdf(str(pdf_path))
            return str(pdf_path)
        except ImportError:
            log.warning("WeasyPrint not installed — PDF generation skipped")
            return None
        except Exception as exc:
            log.error("PDF generation failed: %s", exc)
            return None

    def _build_html_jinja2(self) -> str:
        """Render the report via Jinja2 template with auto-escaped output."""
        env = Environment(
            loader=FileSystemLoader(str(_TEMPLATE_DIR)),
            autoescape=select_autoescape(["html", "j2"]),
        )
        template = env.get_template("report.html.j2")

        # Embed screenshots as base64 data URIs so the HTML is self-contained
        enriched: list[dict[str, Any]] = []
        for f in self.findings:
            row = dict(f)
            ev = dict(f.get("evidence") or {})
            sp = ev.get("screenshot_path")
            if sp and Path(sp).exists():
                data = base64.b64encode(Path(sp).read_bytes()).decode()
                ev["screenshot_b64"] = f"data:image/png;base64,{data}"
            row["evidence"] = ev
            enriched.append(row)

        return template.render(
            framework=self.framework,
            engagement=self.engagement,
            target=self.target,
            tester=self.tester,
            generated_at=self.generated_at,
            findings=enriched,
            summary=self._severity_summary(),
            severity_colors=self._SEVERITY_COLORS,
        )

    def _severity_summary(self) -> dict[str, int]:
        """Return count of findings per severity level."""
        summary: dict[str, int] = {
            "Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0
        }
        for f in self.findings:
            sev = f.get("severity", "Informational")
            summary[sev] = summary.get(sev, 0) + 1
        return summary

    _SEVERITY_COLORS: dict[str, str] = {
        "Critical":      "#7030A0",
        "High":          "#FF0000",
        "Medium":        "#FF9900",
        "Low":           "#FFFF00",
        "Informational": "#92D050",
    }

    def _severity_color(self, severity: str) -> str:
        return self._SEVERITY_COLORS.get(severity, "#CCCCCC")

    def _build_html_inline(self) -> str:
        """Build self-contained HTML report string."""
        summary = self._severity_summary()
        rows = ""
        for i, f in enumerate(self.findings, 1):
            sev = f.get("severity", "Informational")
            color = self._severity_color(sev)
            text_color = "#FFFFFF" if sev in ("Critical", "High") else "#000000"
            ev = f.get("evidence", {})
            screenshot_html = ""
            if ev.get("screenshot_path"):
                sp = Path(ev["screenshot_path"])
                if sp.exists():
                    data = base64.b64encode(sp.read_bytes()).decode()
                    screenshot_html = (
                        f'<br><strong>Screenshot (POC):</strong><br>'
                        f'<img src="data:image/png;base64,{data}" '
                        f'style="max-width:800px;border:2px solid red;" />'
                    )
            request_html = ""
            if ev.get("request_raw"):
                request_html = (
                    f'<br><strong>Request:</strong><pre style="background:#1e1e1e;color:#d4d4d4;'
                    f'padding:8px;overflow:auto">{self._escape(ev["request_raw"])}</pre>'
                )
            response_html = ""
            if ev.get("response_raw"):
                response_html = (
                    f'<br><strong>Response:</strong><pre style="background:#1e1e1e;color:#d4d4d4;'
                    f'padding:8px;overflow:auto">{self._escape(str(ev["response_raw"])[:2000])}</pre>'
                )
            steps = "".join(
                f"<li>{self._escape(s)}</li>"
                for s in f.get("reproduction_steps", [])
            )
            refs = ", ".join(f.get("references", []))
            mitre = ", ".join(f.get("mitre_attack", []))
            cvss = f.get("cvss_v31_score", "")
            rows += f"""
            <tr>
              <td>{i}</td>
              <td><strong>{self._escape(f.get('title',''))}</strong></td>
              <td style="background:{color};color:{text_color};text-align:center;font-weight:bold">
                {self._escape(sev)}</td>
              <td>{self._escape(str(cvss))}</td>
              <td>{self._escape(f.get('target',''))}</td>
              <td>{self._escape(str(f.get('port','') or ''))}</td>
              <td>{self._escape(f.get('module',''))}</td>
            </tr>
            <tr><td colspan="7" style="background:#f9f9f9;padding:12px">
              <strong>Description:</strong> {self._escape(f.get('description',''))}<br>
              <strong>Reproduction:</strong><ol>{steps}</ol>
              <strong>Remediation:</strong> {self._escape(f.get('remediation',''))}<br>
              <strong>References:</strong> {self._escape(refs)}<br>
              <strong>MITRE ATT&CK:</strong> {self._escape(mitre)}
              {screenshot_html}{request_html}{response_html}
            </td></tr>"""

        summary_bars = ""
        for sev, count in summary.items():
            if count > 0:
                color = self._severity_color(sev)
                tc = "#fff" if sev in ("Critical", "High") else "#000"
                summary_bars += (
                    f'<span style="background:{color};color:{tc};padding:6px 12px;'
                    f'margin:4px;border-radius:4px;font-weight:bold">'
                    f'{sev}: {count}</span>'
                )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{self._escape(self.framework)} Report — {self._escape(self.engagement)}</title>
<style>
  body{{font-family:Arial,sans-serif;margin:0;padding:20px;background:#f5f5f5}}
  h1{{color:#333;border-bottom:3px solid #e74c3c;padding-bottom:10px}}
  .meta{{background:#fff;padding:15px;border-radius:6px;margin-bottom:20px;border-left:4px solid #e74c3c}}
  table{{width:100%;border-collapse:collapse;background:#fff;border-radius:6px;overflow:hidden}}
  th{{background:#2c3e50;color:#fff;padding:10px;text-align:left}}
  td{{padding:8px 10px;border-bottom:1px solid #eee;vertical-align:top}}
  tr:hover td{{background:#f0f0f0}}
  pre{{margin:0;white-space:pre-wrap;word-break:break-all;font-size:12px;border-radius:4px}}
  img{{border-radius:4px}}
  .summary{{margin-bottom:15px}}
</style>
</head>
<body>
<h1>{self._escape(self.framework.upper())} — Penetration Test Report</h1>
<div class="meta">
  <strong>Engagement:</strong> {self._escape(self.engagement)} &nbsp;|&nbsp;
  <strong>Target:</strong> {self._escape(self.target)} &nbsp;|&nbsp;
  <strong>Tester:</strong> {self._escape(self.tester)} &nbsp;|&nbsp;
  <strong>Generated:</strong> {self.generated_at} &nbsp;|&nbsp;
  <strong>Total Findings:</strong> {len(self.findings)}
</div>
<div class="summary">{summary_bars}</div>
<table>
  <thead><tr>
    <th>#</th><th>Vulnerability</th><th>Severity</th><th>CVSS</th>
    <th>Target</th><th>Port</th><th>Module</th>
  </tr></thead>
  <tbody>{rows}</tbody>
</table>
<p style="color:#999;font-size:11px;margin-top:20px">
  Generated by {self._escape(self.framework)} — FOR AUTHORIZED USE ONLY
</p>
</body></html>"""

    @staticmethod
    def _escape(text: str) -> str:
        return (text
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;"))


class TestReporter:
    """Unit tests for reporter module."""

    def _sample_findings(self) -> list[dict]:
        return [{
            "id": "abc123", "title": "SQL Injection", "severity": "High",
            "cvss_v31_score": 8.8, "target": "https://example.com",
            "port": 443, "service": "https", "module": "sqli_scanner",
            "description": "SQLi found", "reproduction_steps": ["Step 1"],
            "remediation": "Use parameterized queries", "references": ["CWE-89"],
            "mitre_attack": ["TA0001/T1190"], "discovered_at": "2024-01-01T00:00:00Z",
            "evidence": {}, "operator_confirmed": False, "tags": [],
        }]

    def test_generate_json(self, tmp_path: Path) -> None:
        r = BaseReporter(self._sample_findings(), tmp_path, formats=["json"])
        paths = r.generate_all()
        assert "json" in paths
        data = json.loads(Path(paths["json"]).read_text())
        assert data["total"] == 1

    def test_generate_csv(self, tmp_path: Path) -> None:
        r = BaseReporter(self._sample_findings(), tmp_path, formats=["csv"])
        paths = r.generate_all()
        assert "csv" in paths
        content = Path(paths["csv"]).read_text()
        assert "SQL Injection" in content

    def test_generate_html(self, tmp_path: Path) -> None:
        r = BaseReporter(self._sample_findings(), tmp_path, formats=["html"])
        paths = r.generate_all()
        assert "html" in paths
        content = Path(paths["html"]).read_text()
        assert "SQL Injection" in content
        assert "<!DOCTYPE html>" in content
