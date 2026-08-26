"""JSON report exporter for WebForge findings."""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import ordinary_finding_projection


class JsonExport(BaseModule):
    """JSON findings exporter."""

    NAME        = "json_export"
    DESCRIPTION = "Export findings to JSON format"
    PHASE       = 12
    TAGS        = ["reporting", "json"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        findings = [ordinary_finding_projection(finding) for finding in self.findings]

        out_path = self.results_dir / "report.json"
        out_path.write_text(
            json.dumps(
                {
                    "engagement": self.config.extra.get("engagement", "Unknown"),
                    "target":     self.config.target,
                    "tester":     self.config.extra.get("tester", "Anonymous"),
                    "findings":   findings,
                    "total":      len(findings),
                    "generated":  time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        self.log.info("JSON report written: %s", out_path)
        return self._make_result(start)
