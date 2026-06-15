"""DCshadow detection and pre-flight checks."""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_DCSHADOW = "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H"
CVSS40_DCSHADOW = "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
class Dcshadow(BaseModule):
    """DCshadow attack pre-flight check and guidance."""

    NAME        = "dcshadow"
    DESCRIPTION = "Check prerequisites for DCshadow attack — detect unmonitored replication"
    PHASE       = 5
    TAGS        = ["attacks", "dcshadow", "persistence", "replication", "mitre-T1207"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        domain = self.config.extra.get("domain", "")
        dc_ip  = self.config.extra.get("dc", self.config.target)

        if not self.check_scope(dc_ip):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        # DCshadow requires DA credentials and a Windows machine in the domain
        # We check prerequisites and document
        has_da = self.config.extra.get("has_domain_admin", False)
        results_dir = Path(self.config.extra.get("results_dir", "/tmp"))

        confirmed = self.confirm_action(
            module=self.NAME,
            action=f"Check DCshadow prerequisites and document attack path on {domain}",
            target=domain,
            risk=(
                "DETECTION: DCshadow causes replication traffic. "
                "Only proceed in authorized engagements where full domain compromise is in scope."
            ),
        )
        if not confirmed:
            return self._make_result(start, skipped=True, skip_reason="operator declined")

        ev = Evidence(
            extra={
                "domain":      domain,
                "dc_ip":       dc_ip,
                "has_da_creds": has_da,
                "technique":   "DCshadow",
            }
        )
        self.new_finding(
            title="DCshadow Attack Vector — Domain Admin Privileges Available",
            severity=Severity.CRITICAL if has_da else Severity.INFORMATIONAL,
            description=(
                "DCshadow is a domain persistence technique that requires Domain Admin privileges. "
                "It registers a rogue Domain Controller and pushes malicious changes via AD replication, "
                "bypassing most security monitoring.\n\n"
                "Prerequisites:\n"
                "1. Domain Admin (or equivalent) credentials\n"
                "2. A domain-joined machine with DC-level network access\n"
                "3. Ability to register SPN on a machine account\n\n"
                "What DCshadow can do:\n"
                "- Add users to privileged groups (without Event 4728)\n"
                "- Modify SIDHistory (for backdoor DA access)\n"
                "- Set password for any account\n"
                "- Modify ACLs\n\n"
                f"{'PREREQUISITES MET — attack is possible.' if has_da else 'Credentials do not appear to be DA — verify.'}\n\n"
                "Tool: mimikatz lsadump::dcshadow"
            ),
            reproduction_steps=[
                "# On a domain-joined machine as DA:",
                "mimikatz # lsadump::dcshadow /object:CN=BackdoorUser,CN=Users,DC=corp,DC=local "
                "/attribute:SIDHistory /value:S-1-5-21-...-519",
                "# In a second process:",
                "mimikatz # lsadump::dcshadow /push",
            ],
            remediation=(
                "Monitor for: Event 4929 (replication deletion), 4928 (replication source), "
                "unexpected DCs in Sites and Services. "
                "Use Microsoft Defender for Identity to detect DCshadow. "
                "Enable Privileged Identity Management (PIM) to limit DA usage."
            ),
            references=["MITRE T1207", "CVE-2018-0886 related", "Benjamin Delpy DCshadow research"],
            evidence=ev,
            cvss_v31_vector=CVSS_DCSHADOW,
            cvss_v40_vector=CVSS40_DCSHADOW,
            mitre_attack=["TA0003/T1207"],
            target=dc_ip,
            operator_confirmed=True,
        )

        return self._make_result(start)


class TestDcShadow:
    def test_cvss_vector(self) -> None:
        assert CVSS_DCSHADOW.startswith("CVSS:3.1")
        assert "C:H/I:H/A:H" in CVSS_DCSHADOW
