"""BitLocker Check — enumerate BitLocker recovery keys stored in AD."""
from __future__ import annotations
import sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
from adforge.core.ldap_client import LdapClient

CVSS_BL = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
CVSS40_BL = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"

class BitlockerCheck(BaseModule):
    NAME = "bitlocker_check"
    DESCRIPTION = "BitLocker: enumerate recovery keys stored in AD, check read access"
    PHASE = 13
    TAGS = ["post", "bitlocker", "cwe-312"]

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
            await self.rate_limit()
            # BitLocker recovery keys are stored as msFVE-RecoveryInformation objects
            bl_keys = client.search(
                "(objectClass=msFVE-RecoveryInformation)",
                ["cn", "msFVE-RecoveryPassword", "msFVE-VolumeGuid", "whenCreated"])

            if bl_keys:
                readable_keys = []
                for key in bl_keys:
                    pwd = key.get("msFVE-RecoveryPassword")
                    if pwd:
                        # Redact the actual key but note it's readable
                        readable_keys.append({
                            "cn": str(key.get("cn", "?")),
                            "volume": str(key.get("msFVE-VolumeGuid", "?"))[:20],
                            "preview": str(pwd)[:8] + "..." if pwd else "?",
                        })

                if readable_keys:
                    ev = Evidence(extra={"readable_keys": len(readable_keys)})
                    self.new_finding(
                        title=f"BitLocker Recovery Keys Readable — {len(readable_keys)} key(s)",
                        severity=Severity.HIGH,
                        description=(
                            f"Current user can read {len(readable_keys)} BitLocker recovery key(s) from AD.\n"
                            "These keys can decrypt any BitLocker-protected volume on domain-joined machines.\n\n"
                            "An attacker with physical access or stolen disk images can use these keys "
                            "to decrypt entire volumes."
                        ),
                        reproduction_steps=[
                            "Get-ADObject -Filter {objectClass -eq 'msFVE-RecoveryInformation'} "
                            "-Properties msFVE-RecoveryPassword",
                        ],
                        remediation=(
                            "1. Restrict BitLocker key read access (delegate to specific admin groups)\n"
                            "2. Use MBAM or modern management for key escrow\n"
                            "3. Audit who reads recovery keys (Event ID 4662)"
                        ),
                        references=["CWE-312", "MITRE T1552"],
                        evidence=ev, cvss_v31_vector=CVSS_BL, cvss_v40_vector=CVSS40_BL,
                        mitre_attack=["TA0006/T1552"],
                        target=dc_ip)
                else:
                    self.log.info("BitLocker keys exist but not readable by current user")
            else:
                self.log.info("No BitLocker recovery keys stored in AD")
        finally:
            client.disconnect()
        return self._make_result(start)

class TestBitlockerCheck:
    def test_phase(self) -> None: assert BitlockerCheck.PHASE == 13
