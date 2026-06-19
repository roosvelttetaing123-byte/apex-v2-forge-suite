"""Null session check — anonymous LDAP and SMB access."""
from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_NULL_SESSION = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
CVSS40_NULL_SESSION = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
class NullSession(BaseModule):
    """Null session / anonymous LDAP and SMB access checker."""

    NAME        = "null_session"
    DESCRIPTION = "Test for anonymous LDAP bind and SMB null session access"
    PHASE       = 1
    TAGS        = ["unauth", "null-session", "ldap", "smb", "cwe-306"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        dc_ip  = self.config.extra.get("dc", self.config.target)
        domain = self.config.extra.get("domain", "")

        if not self.check_scope(dc_ip):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        await asyncio.gather(
            self._check_ldap_anonymous(dc_ip, domain),
            self._check_smb_null(dc_ip, domain),
        )
        return self._make_result(start)

    async def _check_ldap_anonymous(self, dc_ip: str, domain: str) -> None:
        """Test anonymous LDAP bind and query domain info."""
        try:
            from ldap3 import Server, Connection, ANONYMOUS, ALL, SUBTREE
            server = Server(dc_ip, get_info=ALL, connect_timeout=10)
            conn = Connection(server, authentication=ANONYMOUS, raise_exceptions=False)
            result = conn.bind()

            if result and conn.result.get("description", "").lower() == "success":
                # Try to enumerate some info
                base_dn = ",".join(f"DC={p}" for p in domain.split(".")) if domain else ""
                info_found = []

                if base_dn:
                    conn.search(
                        base_dn,
                        "(objectClass=domain)",
                        attributes=["name", "defaultNamingContext"],
                    )
                    if conn.entries:
                        info_found.append(f"Domain: {conn.entries[0]}")

                conn.unbind()

                ev = Evidence(
                    extra={
                        "dc_ip":      dc_ip,
                        "anonymous":  True,
                        "info_found": info_found,
                    }
                )
                self.new_finding(
                    title=f"Anonymous LDAP Bind Allowed — {dc_ip}",
                    severity=Severity.MEDIUM,
                    description=(
                        f"Domain controller {dc_ip} allows anonymous LDAP bind. "
                        "An unauthenticated attacker can query domain information."
                        + (f"\nInformation discovered: {info_found}" if info_found else "")
                    ),
                    reproduction_steps=[
                        f"ldapsearch -H ldap://{dc_ip} -x -b '' -s base",
                    ],
                    remediation=(
                        "Disable anonymous LDAP access. "
                        "Configure DSHeuristics to restrict anonymous LDAP queries."
                    ),
                    references=["CWE-306", "MS KB2000705"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_NULL_SESSION,
                    cvss_v40_vector=CVSS40_NULL_SESSION,
                    target=dc_ip,
                )
        except ImportError:
            self.log.info("ldap3 not installed — skipping LDAP null session check")
        except Exception as exc:
            self.log.debug("LDAP null session check failed: %s", exc)

    async def _check_smb_null(self, dc_ip: str, domain: str) -> None:
        """Test SMB null session."""
        try:
            from impacket.smbconnection import SMBConnection
            smb = SMBConnection(dc_ip, dc_ip, timeout=10)
            smb.login("", "")  # null session
            shares = smb.listShares()
            share_names = [s["shi1_netname"].rstrip("\x00") for s in shares]
            smb.logoff()

            if share_names:
                ev = Evidence(
                    extra={
                        "dc_ip":   dc_ip,
                        "shares":  share_names,
                    }
                )
                self.new_finding(
                    title=f"SMB Null Session — Share Listing Allowed ({dc_ip})",
                    severity=Severity.MEDIUM,
                    description=(
                        f"SMB null session allowed on {dc_ip}. "
                        f"Shares visible without credentials: {', '.join(share_names)}"
                    ),
                    reproduction_steps=[
                        f"smbclient -L //{dc_ip} -N",
                        f"crackmapexec smb {dc_ip} -u '' -p '' --shares",
                    ],
                    remediation=(
                        "Set RestrictAnonymous = 2 and RestrictAnonymousSAM = 1 in registry/GPO. "
                        "Block anonymous access via GPO."
                    ),
                    references=["CWE-306"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_NULL_SESSION,
                    cvss_v40_vector=CVSS40_NULL_SESSION,
                    target=dc_ip,
                )
        except ImportError:
            pass
        except Exception as exc:
            self.log.debug("SMB null session check: %s", exc)


class TestNullSession:
    def test_cvss_vector(self) -> None:
        assert CVSS_NULL_SESSION.startswith("CVSS:3.1")
