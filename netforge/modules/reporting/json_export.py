"""NetForge JSON report exporter."""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult


class JsonExport(BaseModule):
    """NetForge JSON findings exporter."""

    NAME        = "json_export"
    DESCRIPTION = "Export NetForge findings to JSON"
    PHASE       = 8
    TAGS        = ["reporting", "json"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()

        def _serialize(obj):
            if hasattr(obj, "value"):
                return obj.value
            return str(obj)

        out_path = self.results_dir / "netforge_report.json"
        findings = []
        for f in self.findings:
            try:
                from dataclasses import asdict
                findings.append(asdict(f))
            except Exception:
                findings.append({"title": str(getattr(f, "title", ""))})

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
                default=_serialize,
            ),
            encoding="utf-8",
        )
        self.log.info("NetForge JSON report: %s", out_path)
        return self._make_result(start)
