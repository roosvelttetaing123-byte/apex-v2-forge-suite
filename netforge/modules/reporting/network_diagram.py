"""Network Diagram module."""
from __future__ import annotations
import sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from common.base_module import BaseModule, ModuleResult
from common.finding import Severity
from common.evidence import Evidence

class NetworkDiagram(BaseModule):
    NAME = "network_diagram"
    DESCRIPTION = "Generate network diagram from discovery data"
    PHASE = 8
    TAGS = ["reporting", "diagram"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target
        self.log.info("Generating NetForge Network Diagram")
        return self._make_result(start)

class TestNetworkDiagram:
    def test_phase(self): assert NetworkDiagram.PHASE == 8
