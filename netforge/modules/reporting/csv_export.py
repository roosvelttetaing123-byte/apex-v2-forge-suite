"""CSV Export module."""
from __future__ import annotations
import sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from common.base_module import BaseModule, ModuleResult
from common.finding import Severity
from common.evidence import Evidence

class CsvExport(BaseModule):
    NAME = "csv_export"
    DESCRIPTION = "Generate CSV export for NetForge"
    PHASE = 8
    TAGS = ["reporting", "csv"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target
        self.log.info("Generating NetForge CSV export")
        return self._make_result(start)

class TestCsvExport:
    def test_phase(self): assert CsvExport.PHASE == 8
