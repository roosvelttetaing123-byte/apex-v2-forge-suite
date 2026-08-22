"""Gate-0 containment for the legacy Kerberoast credential workflow.

SPN/TGS credential use and crackable-hash artifacts remain disabled until an
in-process protected credential adapter and protected artifact lifecycle are
available.  No external command or credential-bearing fallback is retained.
"""
from __future__ import annotations

import time

from common.base_module import BaseModule, ModuleResult


CVSS_KERBEROAST = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
CVSS40_KERBEROAST = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
ETYPE_RC4_HMAC = 23
ETYPE_AES256_CTS = 18
_DISABLED_REASON = "protected AD credential adapter unavailable at Gate 0"


class Kerberoast(BaseModule):
    """Fail-closed placeholder for the contained Kerberoast workflow."""

    NAME = "kerberoast"
    DESCRIPTION = "Kerberoast credential use disabled pending protected adapter"
    PHASE = 5
    TAGS = ["kerberoast", "kerberos", "credential", "mitre-T1558.003"]

    async def run(self) -> ModuleResult:
        return self._make_result(
            time.monotonic(),
            skipped=True,
            skip_reason=_DISABLED_REASON,
        )

    async def _enum_spn_accounts(self, domain: str, dc_ip: str) -> list[dict]:
        """Do not perform credentialed LDAP discovery from ordinary config."""
        del domain, dc_ip
        return []

    async def _request_tgs(
        self,
        username: str,
        spn: str,
        domain: str,
        dc_ip: str,
    ) -> None:
        """Do not request tickets until protected credential use is integrated."""
        del username, spn, domain, dc_ip
        return None

    async def _impacket_cli_fallback(
        self,
        username: str,
        spn: str,
        domain: str,
        dc_ip: str,
    ) -> None:
        """Secret-bearing subprocess fallback remains disabled."""
        del username, spn, domain, dc_ip
        return None

    def _format_tgs_hash(
        self,
        username: str,
        domain: str,
        spn: str,
        tgs: bytes,
        cipher: object,
    ) -> str:
        """Retain deterministic fixture formatting without any credential use."""
        etype = getattr(cipher, "enctype", ETYPE_RC4_HMAC)
        if isinstance(tgs, bytes) and len(tgs) > 16:
            checksum = tgs[-16:].hex()
            data = tgs[:-16].hex()
        elif isinstance(tgs, bytes):
            checksum = tgs.hex()
            data = ""
        else:
            return ""
        if etype == ETYPE_AES256_CTS:
            return f"$krb5tgs$18$*{username}${domain.upper()}${spn}*${checksum}${data}"
        return f"$krb5tgs$23$*{username}${domain.upper()}${spn}*${checksum}${data}"

    def _has_creds(self) -> bool:
        return bool(
            self.config.extra.get("username")
            and (self.config.extra.get("password") or self.config.extra.get("hash"))
        )


class TestKerberoast:
    def test_has_creds_true(self) -> None:
        mod = Kerberoast.__new__(Kerberoast)
        mod.config = type("C", (), {"extra": {"username": "u", "password": "p"}})()
        assert mod._has_creds() is True

    def test_has_creds_false(self) -> None:
        mod = Kerberoast.__new__(Kerberoast)
        mod.config = type("C", (), {"extra": {}})()
        assert mod._has_creds() is False

    def test_format_hash_rc4(self) -> None:
        mod = Kerberoast.__new__(Kerberoast)
        result = mod._format_tgs_hash(
            "svc_sql",
            "CORP.LOCAL",
            "MSSQLSvc/dc01:1433",
            b"\xab" * 100,
            type("C", (), {"enctype": 23})(),
        )
        assert result.startswith("$krb5tgs$23$")

    def test_format_hash_aes(self) -> None:
        mod = Kerberoast.__new__(Kerberoast)
        result = mod._format_tgs_hash(
            "svc_iis",
            "CORP.LOCAL",
            "HTTP/web01",
            b"\xcd" * 80,
            type("C", (), {"enctype": 18})(),
        )
        assert result.startswith("$krb5tgs$18$")

    def test_cvss_vector(self) -> None:
        from common.finding import cvss31_score

        assert cvss31_score(CVSS_KERBEROAST) >= 7.0

    def test_phase(self) -> None:
        assert Kerberoast.PHASE == 5
