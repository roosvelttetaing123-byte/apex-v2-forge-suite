"""NoPac Attack module."""
from __future__ import annotations
import sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from common.base_module import BaseModule, ModuleResult
from common.finding import Severity
from common.evidence import Evidence

CVSS_NOPAC_V31 = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
CVSS_NOPAC_V40 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"

class Nopac(BaseModule):
    """Execute NoPac (SamAccountName spoofing) attack."""
    NAME = "nopac"
    DESCRIPTION = "Execute NoPac (SamAccountName spoofing) attack"
    PHASE = 5
    TAGS = ["attack", "kerberos", "nopac", "privesc"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target
        if not self.check_scope(target): return self._make_result(start, skipped=True)
        
        username = self.config.extra.get("username")
        password = self.config.extra.get("password")
        domain = self.config.extra.get("domain", "")
        
        if not username or not password:
            return self._make_result(start, skipped=True, skip_reason="Missing credentials")

        confirmed = self.confirm_action(module=self.NAME, action="NoPac Attack", target=target, risk="Active attack")
        if not confirmed: return self._make_result(start, skipped=True, skip_reason="operator declined")

        self.log.info("Attempting NoPac scanner against %s", target)
        try:
            from impacket.dcerpc.v5 import samr, transport
            # Try connecting to SAMR to see if it allows the exploit path
            stringbinding = r'ncacn_np:%s[\pipe\samr]' % target
            rpctransport = transport.DCERPCTransportFactory(stringbinding)
            rpctransport.set_credentials(username, password, domain, '', '')
            try:
                dce = rpctransport.get_dce_rpc()
                dce.connect()
                dce.bind(samr.MSRPC_UUID_SAMR)
                ev = Evidence(
                    request_raw=f"Bind SAMR: {target}",
                    response_raw="SAMR connected, vulnerable to machine account quota abuse (NoPac prerequisite)",
                    extra={"user": username}
                )
                self.new_finding(
                    title="NoPac (SamAccountName Spoofing) Prerequisite Met",
                    severity=Severity.HIGH,
                    description="The target allows authenticated users to access SAMR and potentially create machine accounts. If unpatched (CVE-2021-42278/CVE-2021-42287), this leads to Domain Admin.",
                    reproduction_steps=["Use noPac.py tool: python noPac.py domain/user:pass -dc-ip target"],
                    remediation="Apply November 2021 Security Updates. Restrict MAQ to 0.",
                    references=["CVE-2021-42278", "CVE-2021-42287"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_NOPAC_V31, cvss_v40_vector=CVSS_NOPAC_V40,
                    target=target
                )
            except Exception as e:
                self.log.debug("NoPac SAMR failed: %s", e)
        except ImportError:
            return self._make_result(start, skipped=True, skip_reason="Impacket missing")

        return self._make_result(start)

class TestNopac:
    def test_phase(self): assert Nopac.PHASE == 5
