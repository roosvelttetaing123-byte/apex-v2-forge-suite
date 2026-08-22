"""Gate-0 containment for the legacy secretsdump workflow."""
from __future__ import annotations

import time

from common.base_module import BaseModule, ModuleResult


CVSS_SECRETSDUMP = "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N"
CVSS40_SECRETSDUMP = "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"


class Secretsdump(BaseModule):
    """Keep hash extraction and artifact creation fail-closed at Gate 0."""

    NAME = "secretsdump"
    DESCRIPTION = "Secretsdump disabled pending protected credential/artifact adapter"
    PHASE = 13
    TAGS = ["post", "dcsync", "secretsdump", "hashes", "mitre-T1003.003"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        if not self.config.extra.get("dcsync_enabled", False):
            return self._make_result(
                start,
                skipped=True,
                skip_reason="--dcsync not set",
            )
        return self._make_result(
            start,
            skipped=True,
            skip_reason=(
                "protected secretsdump credential and artifact adapter "
                "unavailable at Gate 0"
            ),
        )


class TestSecretsdump:
    def test_cvss_vector(self) -> None:
        assert CVSS_SECRETSDUMP.startswith("CVSS:3.1")
