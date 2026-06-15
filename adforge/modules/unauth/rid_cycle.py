"""RID Cycling module."""
from __future__ import annotations
import sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_RID_V31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
CVSS_RID_V40 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"

class RidCycle(BaseModule):
    NAME = "rid_cycle"
    DESCRIPTION = "Enumerate users via RPC null session (RID Cycling)"
    PHASE = 1
    TAGS = ["unauth", "rpc", "enum"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target
        if not self.check_scope(target): return self._make_result(start, skipped=True)

        try:
            from impacket.dcerpc.v5 import transport, samr, epm
            from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_NONE
            
            stringbinding = epm.hept_map(target, samr.MSRPC_UUID_SAMR, protocol='ncacn_np')
            rpctransport = transport.DCERPCTransportFactory(stringbinding)
            rpctransport.set_credentials('', '', '', '', '')
            
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(samr.MSRPC_UUID_SAMR)
            
            ev = Evidence(
                request_raw="Null Session SAMR Bind",
                response_raw="Successfully bound to SAMR as anonymous",
            )
            
            self.new_finding(
                title="RPC Null Session Allowed (RID Cycling)",
                severity=Severity.MEDIUM,
                description="The target allows anonymous null sessions to connect to the SAMR RPC interface, permitting enumeration of users and groups via RID cycling.",
                reproduction_steps=[f"rpcclient -U '' -N {target} -c enumdomusers"],
                remediation="Restrict anonymous access to named pipes and SAM. Set RestrictAnonymous=1 or 2.",
                references=["MITRE T1087.002"],
                evidence=ev,
                cvss_v31_vector=CVSS_RID_V31, cvss_v40_vector=CVSS_RID_V40, target=target
            )
            
        except Exception as e:
            self.log.debug("RID cycling failed: %s", e)

        return self._make_result(start)

class TestRidCycle:
    def test_phase(self): assert RidCycle.PHASE == 1
