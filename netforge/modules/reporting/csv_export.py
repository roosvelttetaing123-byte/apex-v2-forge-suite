"""NetForge CSV Export — structured CSV from accumulated findings.

Exports all findings with full metadata for spreadsheet analysis,
import into ticketing systems, or data pipeline consumption.
"""
from __future__ import annotations

import csv
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.finding import Finding


# All columns we export — ordered for readability in Excel/Sheets
_CSV_FIELDS = [
    "id", "title", "severity", "confidence", "status",
    "cvss_v31_score", "cvss_v40_score", "vpr_score", "vpr_priority",
    "target", "port", "service", "url", "module",
    "description", "remediation",
    "cvss_v31_vector", "cvss_v40_vector",
    "mitre_attack", "references", "tags",
    "discovered_at", "operator_confirmed",
]


def _finding_to_row(f: Any) -> dict:
    """Convert a Finding or dict to a flat CSV-ready dict."""
    if isinstance(f, dict):
        d = f
    elif hasattr(f, "to_dict"):
        d = f.to_dict()
    else:
        d = {"title": str(getattr(f, "title", "")), "severity": "Informational"}

    # Flatten list fields to semicolon-separated strings
    for key in ("mitre_attack", "references", "tags", "reproduction_steps"):
        val = d.get(key)
        if isinstance(val, list):
            d[key] = "; ".join(str(v) for v in val)

    return d


class CsvExport(BaseModule):
    """Export NetForge findings to structured CSV with full metadata."""

    NAME        = "csv_export"
    DESCRIPTION = "Export NetForge findings to CSV for analysis/import"
    PHASE       = 14
    TAGS        = ["reporting", "csv"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        findings_raw: list = self.config.extra.get("findings", self.findings)

        out_path = self.results_dir / "netforge_findings.csv"
        out_path.parent.mkdir(parents=True, exist_ok=True)

        rows = [_finding_to_row(f) for f in findings_raw]

        with out_path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=_CSV_FIELDS, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)

        self.log.info("CSV export: %s (%d findings)", out_path, len(rows))
        return self._make_result(start)


# ── Tests ────────────────────────────────────────────────────────────────────

class TestCsvExport:
    def test_phase(self) -> None:
        assert CsvExport.PHASE == 14

    def test_finding_to_row_dict(self) -> None:
        d = {"title": "test", "mitre_attack": ["T1190", "T1059"]}
        row = _finding_to_row(d)
        assert row["mitre_attack"] == "T1190; T1059"

    def test_finding_to_row_flattens_lists(self) -> None:
        d = {"references": ["CVE-2024-0001", "https://example.com"]}
        row = _finding_to_row(d)
        assert "CVE-2024-0001; https://example.com" == row["references"]
