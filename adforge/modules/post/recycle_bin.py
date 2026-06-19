"""Recycle Bin Check — AD Recycle Bin status and deleted object enumeration."""
from __future__ import annotations
import sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
from adforge.core.ldap_client import LdapClient

CVSS_NO_BIN = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:L"
CVSS40_NO_BIN = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:L/VA:L/SC:N/SI:N/SA:N"
CVSS_INFO = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"
CVSS40_INFO = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"

class RecycleBin(BaseModule):
    NAME = "recycle_bin"
    DESCRIPTION = "AD: check Recycle Bin status, enumerate deleted objects for intel"
    PHASE = 13
    TAGS = ["post", "hygiene", "recoverability"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        dc_ip = self.config.extra.get("dc", self.config.target)
        domain = self.config.extra.get("domain", "")
        if not self.check_scope(dc_ip):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        client = LdapClient(dc_ip=dc_ip, domain=domain,
            username=self.config.extra.get("username", ""),
            password=self.config.extra.get("password", ""),
            nt_hash=self.config.extra.get("hash", ""))
        if not client.connect(): return self._make_result(start)

        try:
            # Check if AD Recycle Bin is enabled
            await self.rate_limit()
            config_dn = f"CN=Configuration,{client.base_dn}"
            optional_features = client.search(
                "(cn=Recycle Bin Feature)",
                ["cn", "msDS-EnabledFeatureBL"],
                search_base=f"CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,{config_dn}")

            recycle_bin_enabled = False
            if optional_features:
                enabled_bl = optional_features[0].get("msDS-EnabledFeatureBL")
                if enabled_bl:
                    recycle_bin_enabled = True

            if not recycle_bin_enabled:
                ev = Evidence(extra={"recycle_bin_enabled": False})
                self.new_finding(
                    title="AD Recycle Bin Not Enabled — no object recovery",
                    severity=Severity.MEDIUM,
                    description=(
                        "Active Directory Recycle Bin is NOT enabled. "
                        "Without it, accidentally or maliciously deleted objects (users, groups, OUs) "
                        "cannot be easily recovered. This also means an attacker who deletes "
                        "accounts cannot be trivially reverted."
                    ),
                    reproduction_steps=["Get-ADOptionalFeature -Filter {Name -eq 'Recycle Bin Feature'}"],
                    remediation="Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target <forest>",
                    references=["CWE-693"],
                    evidence=ev, cvss_v31_vector=CVSS_NO_BIN, cvss_v40_vector=CVSS40_NO_BIN,
                    target=dc_ip)
            else:
                # Enumerate deleted objects for intel
                await self.rate_limit()
                deleted = client.search(
                    "(&(isDeleted=TRUE)(objectCategory=person))",
                    ["cn", "sAMAccountName", "whenChanged", "isDeleted"],
                    search_base=f"CN=Deleted Objects,{client.base_dn}")

                deleted_count = len(deleted) if deleted else 0
                ev = Evidence(extra={
                    "recycle_bin_enabled": True,
                    "deleted_users": deleted_count,
                    "sample": [str(d.get("cn", "?"))[:40] for d in (deleted or [])[:10]],
                })
                self.new_finding(
                    title=f"AD Recycle Bin Enabled — {deleted_count} deleted user(s)",
                    severity=Severity.INFORMATIONAL,
                    description=(
                        f"AD Recycle Bin is enabled. {deleted_count} deleted user objects found.\n"
                        "Deleted objects may contain useful information for attackers (old accounts, SPNs)."
                    ),
                    reproduction_steps=["Get-ADObject -Filter {isDeleted -eq $true} -IncludeDeletedObjects"],
                    remediation="Periodically purge old deleted objects beyond tombstone lifetime.",
                    references=["CWE-693"],
                    evidence=ev, cvss_v31_vector=CVSS_INFO, cvss_v40_vector=CVSS40_INFO,
                    target=dc_ip)
        finally:
            client.disconnect()
        return self._make_result(start)

class TestRecycleBin:
    def test_phase(self) -> None: assert RecycleBin.PHASE == 13
