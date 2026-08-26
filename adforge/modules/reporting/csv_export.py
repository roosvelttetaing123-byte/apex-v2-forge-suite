"""CSV Export — ADForge findings to CSV."""
from __future__ import annotations
import csv, io, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from common.base_module import BaseModule, ModuleResult
from common.evidence import ordinary_finding_projection

COLUMNS = ["id", "title", "severity", "cvss_v31_score", "cvss_v31_vector",
           "cvss_v40_vector", "target", "module", "description",
           "remediation", "mitre_attack", "references", "discovered_at"]

def findings_to_csv(findings: list[dict]) -> str:
    findings = [ordinary_finding_projection(finding) for finding in findings]
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=COLUMNS, extrasaction="ignore")
    writer.writeheader()
    for f in findings:
        row = {
            "id": f.get("id", ""),
            "title": f.get("title", ""),
            "severity": str(f.get("severity", "")),
            "cvss_v31_score": f.get("cvss_v31_score", ""),
            "cvss_v31_vector": f.get("cvss_v31_vector", ""),
            "cvss_v40_vector": f.get("cvss_v40_vector", ""),
            "target": f.get("target", ""),
            "module": f.get("module", ""),
            "description": f.get("description", ""),
            "remediation": f.get("remediation", ""),
            "mitre_attack": "; ".join(f.get("mitre_attack", [])),
            "references": "; ".join(f.get("references", [])),
            "discovered_at": f.get("discovered_at", ""),
        }
        writer.writerow(row)
    return buf.getvalue()

class CsvExport(BaseModule):
    NAME = "csv_export"
    DESCRIPTION = "Export ADForge findings to CSV"
    PHASE = 14
    TAGS = ["reporting", "csv"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        findings = self.config.extra.get("findings", [])
        if not findings:
            return self._make_result(start, skipped=True, skip_reason="no findings")
        out_dir = Path(self.config.extra.get("output_dir", self.results_dir))
        out_dir.mkdir(parents=True, exist_ok=True)
        out_file = out_dir / "adforge_findings.csv"
        out_file.write_text(findings_to_csv(findings), encoding="utf-8")
        self.log.info("CSV exported: %s (%d rows)", out_file, len(findings))
        return self._make_result(start)

class TestCsvExport:
    def test_columns(self) -> None: assert "cvss_v40_vector" in COLUMNS
    def test_phase(self) -> None: assert CsvExport.PHASE == 14
