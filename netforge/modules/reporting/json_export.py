"""NetForge JSON report exporter."""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import ordinary_finding_projection


class JsonExport(BaseModule):
    """NetForge JSON findings exporter."""

    NAME        = "json_export"
    DESCRIPTION = "Export NetForge findings to JSON"
    PHASE       = 8
    TAGS        = ["reporting", "json"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()

        out_path = self.results_dir / "netforge_report.json"
        findings = [ordinary_finding_projection(f) for f in self.findings]

        out_path.write_text(
            json.dumps(
                {
                    "framework":  "NetForge",
                    "engagement": self.config.extra.get("engagement", "Unknown"),
                    "target":     self.config.target,
                    "findings":   findings,
                    "total":      len(findings),
                    "open_ports": self.config.extra.get("open_ports", {}),
                    "live_hosts": self.config.extra.get("live_hosts", []),
                    "generated":  time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        self.log.info("NetForge JSON report: %s", out_path)
        return self._make_result(start)
