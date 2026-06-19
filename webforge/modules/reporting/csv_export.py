"""CSV export for WebForge findings."""
from __future__ import annotations

import csv
import io
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult

COLUMNS = ["id", "title", "severity", "cvss_score", "cvss_vector", "target",
           "module", "port", "service", "description", "remediation",
           "mitre_attack", "references", "discovered_at"]


def findings_to_csv(findings: list[dict]) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=COLUMNS, extrasaction="ignore")
    writer.writeheader()
    for f in findings:
        row = {
            "id":           f.get("id", ""),
            "title":        f.get("title", ""),
            "severity":     f.get("severity", ""),
            "cvss_score":   f.get("cvss_v31_score", ""),
            "cvss_vector":  f.get("cvss_v31_vector", ""),
            "target":       f.get("target", ""),
            "module":       f.get("module", ""),
            "port":         f.get("port", ""),
            "service":      f.get("service", ""),
            "description":  f.get("description", ""),
            "remediation":  f.get("remediation", ""),
            "mitre_attack": "; ".join(f.get("mitre_attack", [])),
            "references":   "; ".join(f.get("references", [])),
            "discovered_at": f.get("discovered_at", ""),
        }
        writer.writerow(row)
    return buf.getvalue()


class CsvExport(BaseModule):
    NAME        = "csv_export"
    DESCRIPTION = "Export findings to CSV"
    PHASE       = 99
    TAGS        = ["reporting"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        findings_raw: list[dict] = self.config.extra.get("findings", [])
        if not findings_raw:
            return self._make_result(start, skipped=True, skip_reason="no findings")

        out_dir = Path(self.config.extra.get("output_dir", self.results_dir))
        out_dir.mkdir(parents=True, exist_ok=True)
        out_file = out_dir / "webforge_findings.csv"
        out_file.write_text(findings_to_csv(findings_raw), encoding="utf-8")
        self.log.info("CSV exported: %s (%d rows)", out_file, len(findings_raw))
        return self._make_result(start)
