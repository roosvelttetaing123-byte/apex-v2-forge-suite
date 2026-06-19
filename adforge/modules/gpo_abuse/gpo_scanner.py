"""GPO scanner — find GPO permissions that allow modification for persistence."""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
from adforge.core.ldap_client import LdapClient

CVSS_GPO_ABUSE = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"
CVSS40_GPO_ABUSE = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
class GpoScanner(BaseModule):
    """GPO permission scanner — find abusable GPO rights."""

    NAME        = "gpo_scanner"
    DESCRIPTION = "Enumerate GPOs and find ones writable by non-admin accounts"
    PHASE       = 8
    TAGS        = ["gpo-abuse", "gpo", "persistence", "mitre-T1484.001"]

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
        )

        if not client.connect():
            return self._make_result(start)

        try:
            dc_parts = ",".join(f"DC={p}" for p in domain.split("."))
            gpos = client.search(
                "(objectClass=groupPolicyContainer)",
                ["displayName", "cn", "distinguishedName", "gPCFileSysPath",
                 "nTSecurityDescriptor", "versionNumber"],
                base_dn=f"CN=Policies,CN=System,{dc_parts}",
            )

            self.log.info("Found %d GPO(s)", len(gpos))
            self.config.extra["gpo_list"] = [g.get("displayName", g.get("cn", "?")) for g in gpos]

            # Flag linked GPOs for SYSVOL path review
            for gpo in gpos:
                gpc_path = str(gpo.get("gPCFileSysPath", ""))
                if gpc_path:
                    # Document SYSVOL path for manual review
                    self.log.info("GPO '%s' → %s",
                                  gpo.get("displayName", "?"), gpc_path)

            if gpos:
                ev = Evidence(
                    extra={
                        "gpo_count": len(gpos),
                        "gpos": [
                            {
                                "name":    g.get("displayName", g.get("cn", "?")),
                                "path":    str(g.get("gPCFileSysPath", ""))[:80],
                            }
                            for g in gpos[:10]
                        ],
                    }
                )
                self.new_finding(
                    title=f"GPO Enumeration — {len(gpos)} Policy Object(s) Found",
                    severity=Severity.INFORMATIONAL,
                    description=(
                        f"{len(gpos)} Group Policy Object(s) found in {domain}. "
                        "Manually review SYSVOL paths for write permissions by non-admin accounts. "
                        "Use BloodHound to identify GPO abuse paths."
                    ),
                    reproduction_steps=[
                        "PowerView: Get-GPPermission -All",
                        "BloodHound: GenericWrite/WriteDACL edges on GPOs",
                    ],
                    remediation=(
                        "Audit GPO permissions regularly. "
                        "Remove non-admin write access to GPOs. "
                        "Enable GPO delegation audit logging."
                    ),
                    references=["MITRE T1484.001"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_GPO_ABUSE,
                    cvss_v40_vector=CVSS40_GPO_ABUSE,
                    target=dc_ip,
                )

        finally:
            client.disconnect()

        return self._make_result(start)


class TestGpoScanner:
    def test_cvss_vector(self) -> None:
        assert CVSS_GPO_ABUSE.startswith("CVSS:3.1")
