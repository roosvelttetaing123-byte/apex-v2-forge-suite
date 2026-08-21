"""Gate-0 containment for the legacy AS-REP credential workflow.

Requesting crackable AS-REP material remains disabled until ADForge has an
in-process protected credential adapter and a bounded protected-artifact
lifecycle.  No LDAP, Kerberos, subprocess, temporary-file, report, or finding
side effect is retained on the registered module path.
"""
from __future__ import annotations

import time

from common.base_module import BaseModule, ModuleResult


CVSS_ASREP = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
CVSS40_ASREP = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
UAC_DONT_REQUIRE_PREAUTH = 0x400000
ETYPE_RC4_HMAC = 23
ETYPE_AES128 = 17
ETYPE_AES256 = 18
_DISABLED_REASON = "protected AS-REP credential and artifact adapters unavailable at Gate 0"


def format_asrep_hash(
    username: str,
    domain: str,
    etype: int,
    cipher_bytes: bytes,
) -> str | None:
    """Retain deterministic fixture formatting without performing credential use."""
    realm = domain.upper()
    if etype == ETYPE_RC4_HMAC:
        if len(cipher_bytes) <= 16:
            checksum = cipher_bytes.hex()
            data = ""
        else:
            checksum = cipher_bytes[-16:].hex()
            data = cipher_bytes[:-16].hex()
        return f"$krb5asrep$23${username}@{realm}:{checksum}${data}"
    if etype == ETYPE_AES128:
        checksum = cipher_bytes[-12:].hex()
        data = cipher_bytes[:-12].hex()
        return f"$krb5asrep$17${username}@{realm}:{checksum}${data}"
    if etype == ETYPE_AES256:
        checksum = cipher_bytes[-12:].hex()
        data = cipher_bytes[:-12].hex()
        return f"$krb5asrep$18${username}@{realm}:{checksum}${data}"
    return None


class AsrepRoast(BaseModule):
    """Fail-closed placeholder for the contained AS-REP workflow."""

    NAME = "asrep_roast"
    DESCRIPTION = "AS-REP credential use disabled pending protected adapters"
    PHASE = 5
    TAGS = ["attacks", "asrep", "kerberos", "credential", "mitre-T1558.004"]

    async def run(self) -> ModuleResult:
        return self._make_result(
            time.monotonic(),
            skipped=True,
            skip_reason=_DISABLED_REASON,
        )

    async def _enum_asrep_accounts(self, domain: str, dc_ip: str) -> list[str]:
        """Do not perform credentialed LDAP discovery from ordinary config."""
        del domain, dc_ip
        return []

    async def _roast_accounts(
        self,
        usernames: list[str],
        domain: str,
        dc_ip: str,
    ) -> list[str]:
        """Do not request or retain crackable material."""
        del usernames, domain, dc_ip
        return []

    async def _roast_impacket(
        self,
        usernames: list[str],
        domain: str,
        dc_ip: str,
    ) -> list[str]:
        """The direct Kerberos path remains inert at Gate 0."""
        del usernames, domain, dc_ip
        return []

    async def _roast_cli(
        self,
        usernames: list[str],
        domain: str,
        dc_ip: str,
    ) -> list[str]:
        """The secret-bearing subprocess fallback remains disabled."""
        del usernames, domain, dc_ip
        return []


class TestAsrepRoast:
    def test_cvss_vector(self) -> None:
        assert CVSS_ASREP.startswith("CVSS:3.1")
        assert "/AV:N/" in CVSS_ASREP
        assert "PR:N" in CVSS_ASREP

    def test_uac_flag(self) -> None:
        assert UAC_DONT_REQUIRE_PREAUTH == 0x400000
        assert UAC_DONT_REQUIRE_PREAUTH == (1 << 22)

    def test_phase(self) -> None:
        assert AsrepRoast.PHASE == 5

    def test_tags(self) -> None:
        assert "mitre-T1558.004" in AsrepRoast.TAGS
