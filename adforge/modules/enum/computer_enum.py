"""Computer Enumeration — domain-joined computers, OS versions, stale objects.

Enumerates: all computer objects, OS types/versions, stale (inactive) computers,
unconstrained delegation machines, LAPS status.
"""
from __future__ import annotations

import sys
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
from adforge.core.ldap_client import LdapClient

CVSS_INFO   = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"
CVSS40_INFO = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
CVSS_STALE  = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"
CVSS40_STALE = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N"

COMPUTER_ATTRS = [
    "sAMAccountName", "dNSHostName", "operatingSystem", "operatingSystemVersion",
    "operatingSystemServicePack", "lastLogonTimestamp", "whenCreated",
    "userAccountControl", "ms-Mcs-AdmPwd", "ms-Mcs-AdmPwdExpirationTime",
    "msDS-AllowedToDelegateTo", "distinguishedName",
]

UAC_TRUSTED_FOR_DELEGATION = 0x80000

STALE_DAYS = 90  # Computers not logging in for 90+ days


class ComputerEnum(BaseModule):
    """Domain computer enumerator — OS versions, stale objects, delegation."""

    NAME        = "computer_enum"
    DESCRIPTION = "Enumerate computers: OS versions, stale objects, unconstrained delegation, LAPS"
    PHASE       = 2
    TAGS        = ["enum", "computers", "ldap", "mitre-T1018"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        domain = self.config.extra.get("domain", "")
        dc_ip  = self.config.extra.get("dc", self.config.target)

        if not self.check_scope(dc_ip):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        client = LdapClient(
            dc_ip=dc_ip, domain=domain,
            username=self.config.extra.get("username", ""),
            password=self.config.extra.get("password", ""),
            nt_hash=self.config.extra.get("hash", ""),
        )

        if not client.connect():
            return self._make_result(start)

        try:
            await self.rate_limit()
            computers = client.search(
                "(objectCategory=computer)", COMPUTER_ATTRS,
            )
            self.log.info("Found %d domain computer(s)", len(computers))

            os_counts: dict[str, int] = {}
            stale: list[dict] = []
            unconstrained_deleg: list[str] = []
            laps_computers: list[str] = []
            no_laps: list[str] = []
            now = datetime.now(timezone.utc)
            stale_cutoff = now - timedelta(days=STALE_DAYS)

            for comp in computers:
                name = str(comp.get("sAMAccountName", "?"))
                os_name = str(comp.get("operatingSystem", "Unknown") or "Unknown")
                uac = int(str(comp.get("userAccountControl", 0) or 0))

                os_counts[os_name] = os_counts.get(os_name, 0) + 1

                # Stale check
                last_logon = comp.get("lastLogonTimestamp")
                if last_logon:
                    try:
                        if isinstance(last_logon, (int, float)) and last_logon > 0:
                            ll = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=last_logon // 10)
                            if ll < stale_cutoff:
                                stale.append({"name": name, "os": os_name, "days": (now - ll).days})
                    except Exception:
                        pass

                # Unconstrained delegation
                if uac & UAC_TRUSTED_FOR_DELEGATION:
                    if not name.upper().endswith("$") or "DC" not in name.upper():
                        unconstrained_deleg.append(name)

                # LAPS
                laps_pwd = comp.get("ms-Mcs-AdmPwd")
                if laps_pwd:
                    laps_computers.append(name)
                else:
                    no_laps.append(name)

            # OS distribution report
            ev = Evidence(
                extra={
                    "total_computers": len(computers),
                    "os_distribution": os_counts,
                    "stale_count": len(stale),
                    "unconstrained_delegation": unconstrained_deleg,
                },
            )
            self.new_finding(
                title=f"Domain Computers — {len(computers)} systems, {len(os_counts)} OS types",
                severity=Severity.INFORMATIONAL,
                description=(
                    f"Domain computer inventory ({len(computers)} systems):\n"
                    + "\n".join(f"  {os}: {count}" for os, count in sorted(os_counts.items(), key=lambda x: -x[1]))
                ),
                reproduction_steps=["Get-ADComputer -Filter * -Properties OperatingSystem | Group OperatingSystem"],
                remediation="Ensure all systems are running supported OS versions.",
                references=["MITRE T1018"],
                evidence=ev,
                cvss_v31_vector=CVSS_INFO,
                cvss_v40_vector=CVSS40_INFO,
                mitre_attack=["TA0007/T1018"],
                target=dc_ip,
            )

            # Stale computers
            if stale:
                ev = Evidence(extra={"stale_computers": stale[:30]})
                self.new_finding(
                    title=f"Stale Computer Accounts — {len(stale)} inactive >{STALE_DAYS} days",
                    severity=Severity.MEDIUM,
                    description=(
                        f"{len(stale)} computer(s) have not logged in for {STALE_DAYS}+ days:\n"
                        + "\n".join(f"  {s['name']} ({s['os']}) — {s['days']}d inactive" for s in stale[:10])
                    ),
                    reproduction_steps=["Get-ADComputer -Filter {LastLogonDate -lt (Get-Date).AddDays(-90)}"],
                    remediation="Disable or remove stale computer accounts.",
                    references=["CWE-672"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_STALE,
                    cvss_v40_vector=CVSS40_STALE,
                    target=dc_ip,
                )

            # Unconstrained delegation
            if unconstrained_deleg:
                ev = Evidence(extra={"unconstrained": unconstrained_deleg})
                self.new_finding(
                    title=f"Unconstrained Delegation — {len(unconstrained_deleg)} non-DC computers",
                    severity=Severity.HIGH,
                    description=(
                        f"Non-DC computers with unconstrained delegation: {', '.join(unconstrained_deleg[:10])}. "
                        "Compromising these machines allows capturing TGTs of any user that authenticates to them."
                    ),
                    reproduction_steps=[
                        "Get-ADComputer -Filter {TrustedForDelegation -eq $true} | Select Name",
                    ],
                    remediation="Remove unconstrained delegation. Use constrained or RBCD instead.",
                    references=["MITRE T1558", "CWE-284"],
                    evidence=ev,
                    cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                    cvss_v40_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
                    target=dc_ip,
                )

            self.config.extra["domain_computers"] = computers
            self.config.extra["unconstrained_delegation"] = unconstrained_deleg

        finally:
            client.disconnect()

        return self._make_result(start)


class TestComputerEnum:
    def test_stale_days(self) -> None:
        assert STALE_DAYS == 90

    def test_uac_flag(self) -> None:
        assert UAC_TRUSTED_FOR_DELEGATION == 0x80000

    def test_phase(self) -> None:
        assert ComputerEnum.PHASE == 2
