"""DFS Coerce Attack module."""
from __future__ import annotations
import sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from common.base_module import BaseModule, ModuleResult
from common.finding import Severity
from common.evidence import Evidence

CVSS_DFS_V31 = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
CVSS_DFS_V40 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"

class Dfscoerce(BaseModule):
    NAME = "dfscoerce"
    DESCRIPTION = "Execute DFS Coerce NTLM attack"
    PHASE = 7
    TAGS = ["attack", "coercion", "dfscoerce"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target
        if not self.check_scope(target): return self._make_result(start, skipped=True)
        confirmed = self.confirm_action(module=self.NAME, action="DFS Coerce", target=target, risk="Active coercion")
        if not confirmed: return self._make_result(start, skipped=True, skip_reason="operator declined")

        try:
            from impacket.dcerpc.v5 import transport, epm
            MSRPC_UUID_DFSNM = '4fc742e0-4a10-11cf-8273-00aa004ae673'
            stringbinding = epm.hept_map(target, MSRPC_UUID_DFSNM, protocol='ncacn_np')
            rpctransport = transport.DCERPCTransportFactory(stringbinding)
            try:
                dce = rpctransport.get_dce_rpc()
                dce.connect()
                dce.bind(MSRPC_UUID_DFSNM)
                ev = Evidence(
                    request_raw="Bind to DFSNM RPC",
                    response_raw="Successful bind to MS-DFSNM",
                )
                self.new_finding(
                    title="DFS Coerce Vulnerability",
                    severity=Severity.HIGH,
                    description="The target exposes MS-DFSNM which can be used to coerce authentication.",
                    reproduction_steps=["python dfscoerce.py listener target"],
                    remediation="Disable DFS Namespace service if unused. Filter RPC.",
                    references=["CVE-2022-26923"],
                    evidence=ev, cvss_v31_vector=CVSS_DFS_V31, cvss_v40_vector=CVSS_DFS_V40, target=target
                )
            except Exception as e:
                pass
        except ImportError:
            pass

        return self._make_result(start)

class TestDfscoerce:
    def test_phase(self): assert Dfscoerce.PHASE == 7
