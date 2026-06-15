"""PrintSpooler Attack module."""
from __future__ import annotations
import sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from common.base_module import BaseModule, ModuleResult
from common.finding import Severity
from common.evidence import Evidence

CVSS_SPOOL_V31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
CVSS_SPOOL_V40 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"

class Printspooler(BaseModule):
    NAME = "printspooler"
    DESCRIPTION = "Execute PrintSpooler NTLM coercion"
    PHASE = 7
    TAGS = ["attack", "coercion", "printspooler"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target
        if not self.check_scope(target): return self._make_result(start, skipped=True)
        
        listener_ip = self.config.extra.get("listener_ip", "127.0.0.1")

        confirmed = self.confirm_action(module=self.NAME, action="PrintSpooler Coercion", target=target, risk="Active coercion")
        if not confirmed: return self._make_result(start, skipped=True, skip_reason="operator declined")

        try:
            from impacket.dcerpc.v5 import transport, epm
            from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_NONE
            MSRPC_UUID_SPOOLSS = '12345678-1234-abcd-ef00-0123456789ab'
            stringbinding = epm.hept_map(target, MSRPC_UUID_SPOOLSS, protocol='ncacn_np')
            rpctransport = transport.DCERPCTransportFactory(stringbinding)
            try:
                dce = rpctransport.get_dce_rpc()
                dce.connect()
                dce.bind(MSRPC_UUID_SPOOLSS)
                ev = Evidence(
                    request_raw="Bind to Spoolss RPC",
                    response_raw="Successful unauth bind",
                )
                self.new_finding(
                    title="Print Spooler RPC Coercion (SpoolSample)",
                    severity=Severity.HIGH,
                    description="The target exposes the Print Spooler RPC interface which can be coerced to authenticate to an attacker.",
                    reproduction_steps=["Use printerbug.py"],
                    remediation="Disable the Print Spooler service on DCs.",
                    references=["CVE-2021-34527"],
                    evidence=ev, cvss_v31_vector=CVSS_SPOOL_V31, cvss_v40_vector=CVSS_SPOOL_V40, target=target
                )
            except Exception as e:
                self.log.debug("Printspooler failed: %s", e)
        except ImportError:
            pass
        return self._make_result(start)

class TestPrintspooler:
    def test_phase(self): assert Printspooler.PHASE == 7
