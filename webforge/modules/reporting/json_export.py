"""JSON report exporter for WebForge findings."""
from __future__ import annotations

import json
import sys
import time
from dataclasses import asdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.finding import Finding


class JsonExport(BaseModule):
    """JSON findings exporter."""

    NAME        = "json_export"
    DESCRIPTION = "Export findings to JSON format"
    PHASE       = 12
    TAGS        = ["reporting", "json"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        findings = [f.__dict__ if not hasattr(f, '__dataclass_fields__') else asdict(f)
                    for f in self.findings]

        # Custom serializer for non-serializable types
        def _serializer(obj):
            if hasattr(obj, "value"):
                return obj.value
            return str(obj)

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
                default=_serializer,
            ),
            encoding="utf-8",
        )
        self.log.info("JSON report written: %s", out_path)
        return self._make_result(start)
