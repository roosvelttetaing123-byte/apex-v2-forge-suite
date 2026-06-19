"""WMI Exec module."""
from __future__ import annotations
import sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from common.base_module import BaseModule, ModuleResult
from common.finding import Severity
from common.evidence import Evidence

CVSS_WMI_V31 = "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"
CVSS_WMI_V40 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"

class WmiExec(BaseModule):
    NAME = "wmi_exec"
    DESCRIPTION = "Execute commands via WMI"
    PHASE = 12
    TAGS = ["lateral", "wmi"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target
        if not self.check_scope(target): return self._make_result(start, skipped=True)
        
        username = self.config.extra.get("username")
        password = self.config.extra.get("password")
        hashes = self.config.extra.get("hashes")
        domain = self.config.extra.get("domain", "")

        if not username or (not password and not hashes):
            return self._make_result(start, skipped=True, skip_reason="Missing credentials")

        confirmed = self.confirm_action(module=self.NAME, action="WMI Exec", target=target, risk="Executing commands via WMI")
        if not confirmed: return self._make_result(start, skipped=True, skip_reason="operator declined")

        try:
            from impacket.dcerpc.v5.dcomrt import DCOMConnection
            from impacket.dcerpc.v5.dcom import wmi
            from impacket.dcerpc.v5.dtypes import NULL
            
            lmhash, nthash = "", ""
            if hashes:
                if ":" in hashes: lmhash, nthash = hashes.split(":")
                else: nthash = hashes

            dcom = DCOMConnection(target, username, password, domain, lmhash, nthash, None, oxidResolver=True)
            iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
            iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
            iWbemServices = iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
            
            # WMI execution successful
            ev = Evidence(request_raw="DCOM WMI Connection", response_raw="Successfully connected to //./root/cimv2")
            self.new_finding(
                title="WMI Remote Execution Permitted",
                severity=Severity.HIGH,
                description="The provided credentials have WMI remote execution privileges on the target, allowing lateral movement.",
                reproduction_steps=[f"wmiexec.py {domain}/{username}:{password}@{target}"],
                remediation="Restrict WMI access to authorized administrative hosts only.",
                references=["MITRE T1047"],
                evidence=ev, cvss_v31_vector=CVSS_WMI_V31, cvss_v40_vector=CVSS_WMI_V40, target=target
            )
            iWbemServices.RemRelease()
            dcom.disconnect()
        except Exception as e:
            self.log.debug("WMI exec failed: %s", e)

        return self._make_result(start)

class TestWmiExec:
    def test_phase(self): assert WmiExec.PHASE == 12
