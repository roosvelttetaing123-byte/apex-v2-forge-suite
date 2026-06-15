"""HTML Report module."""
from __future__ import annotations
import sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from common.base_module import BaseModule, ModuleResult
from common.finding import Severity
from common.evidence import Evidence

class HtmlReport(BaseModule):
    NAME = "html_report"
    DESCRIPTION = "Generate HTML report for NetForge"
    PHASE = 8
    TAGS = ["reporting", "html"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target
        self.log.info("Generating NetForge HTML report")
        return self._make_result(start)

class TestHtmlReport:
    def test_phase(self): assert HtmlReport.PHASE == 8
