"""Contained legacy Kerberos client pending protected policy adapters."""
from __future__ import annotations

from typing import NoReturn

from common.outbound_policy import OutboundDenied, OutboundReason


def _deny_unmigrated_kerberos_effect() -> NoReturn:
    """Keep every legacy Kerberos effect inert at Gate 0."""
    raise OutboundDenied(OutboundReason.OUTBOUND_POLICY_UNSUPPORTED)


class KerberosClient:
    """Compatibility shell with no retained credential material or effects."""

    def __init__(self, domain: str, dc_ip: str, username: str = "", password: str = "", nt_hash: str = "") -> None:
        # Preserve the legacy construction signature without retaining either
        # caller-owned secret.  A future adapter must accept only a protected
        # reference resolved behind an exact target-bound authorization.
        del password, nt_hash
        self.domain   = domain
        self.dc_ip    = dc_ip
        self.username = username

    async def get_tgt(self) -> bytes | None:
        _deny_unmigrated_kerberos_effect()

    async def get_np_users(self) -> list[str]:
        """AS-REP roast — get hashes for accounts without pre-auth."""
        _deny_unmigrated_kerberos_effect()

    async def get_spn_hashes(self, users: list[str] | None = None) -> list[str]:
        """Kerberoast — request TGS tickets for SPN accounts."""
        _deny_unmigrated_kerberos_effect()
