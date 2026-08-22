"""Gate-0 containment for external BloodHound collectors."""
from __future__ import annotations

import time

from common.base_module import BaseModule, ModuleResult


class BloodhoundExport(BaseModule):
    """Keep secret-bearing external collection inert pending a protected adapter."""

    NAME = "bloodhound_export"
    DESCRIPTION = "BloodHound collection disabled pending protected credential adapter"
    PHASE = 14
    TAGS = ["reporting", "bloodhound", "graph", "attack-path"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        if not self.config.extra.get("bloodhound_enabled", False):
            return self._make_result(
                start,
                skipped=True,
                skip_reason="--bloodhound not set",
            )
        return self._make_result(
            start,
            skipped=True,
            skip_reason="protected BloodHound credential adapter unavailable at Gate 0",
        )


class TestBloodhoundExport:
    def test_name(self) -> None:
        assert BloodhoundExport.NAME == "bloodhound_export"
