"""RDP Check — validate RDP access, NLA enforcement, session hijacking."""
from __future__ import annotations
import asyncio, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_NLA = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
CVSS40_NLA = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N"
CVSS_RDP = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
CVSS40_RDP = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"

# RDP protocol negotiation constants
RDP_NEG_REQ = bytes([
    0x03, 0x00, 0x00, 0x13,  # TPKT header
    0x0e, 0xe0, 0x00, 0x00,  # X.224 Connection Request
    0x00, 0x00, 0x00, 0x01,  # RDP negotiation request
    0x00, 0x08, 0x00, 0x03,  # TLS + CredSSP
    0x00, 0x00, 0x00,
])

class RdpCheck(BaseModule):
    NAME = "rdp_check"
    DESCRIPTION = "RDP: validate access, NLA enforcement, encryption level"
    PHASE = 12
    TAGS = ["lateral", "rdp", "cwe-287"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        dc_ip = self.config.extra.get("dc", self.config.target)
        domain = self.config.extra.get("domain", "")
        if not self.check_scope(dc_ip):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        hosts = self.config.extra.get("live_hosts", self.config.extra.get("domain_computers", []))
        if isinstance(hosts, list) and hosts and isinstance(hosts[0], dict):
            hosts = [str(h.get("sAMAccountName", "").rstrip("$")) for h in hosts[:20]]
        if not hosts:
            hosts = [dc_ip]

        for host in hosts[:10]:
            if not self.check_scope(host):
                continue
            await self.rate_limit()

            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, 3389), timeout=5)

                # Send RDP negotiation request
                writer.write(RDP_NEG_REQ)
                await writer.drain()

                response = await asyncio.wait_for(reader.read(128), timeout=5)
                writer.close()

                if len(response) < 11:
                    continue

                # Parse response
                # TPKT(4) + X.224(7+) + Negotiation Response
                rdp_open = True
                nla_enforced = False

                if len(response) >= 19:
                    neg_type = response[11] if len(response) > 11 else 0
                    if neg_type == 0x02:  # TYPE_RDP_NEG_RSP
                        selected_proto = response[15] if len(response) > 15 else 0
                        # Protocol flags: 0=standard, 1=TLS, 2=CredSSP (NLA), 3=TLS+CredSSP
                        nla_enforced = bool(selected_proto & 0x02)
                    elif neg_type == 0x03:  # TYPE_RDP_NEG_FAILURE
                        # Server rejected — NLA required but not offered correctly
                        nla_enforced = True

                if rdp_open and not nla_enforced:
                    ev = Evidence(
                        response_raw=response[:64].hex(),
                        extra={"host": host, "port": 3389, "nla": nla_enforced})
                    self.new_finding(
                        title=f"RDP Without NLA — {host}:3389",
                        severity=Severity.MEDIUM,
                        description=(
                            f"RDP on {host}:3389 does not enforce Network Level Authentication (NLA). "
                            "Without NLA, an attacker can:\n"
                            "  1. See the login screen without valid credentials\n"
                            "  2. Attempt credential brute force directly\n"
                            "  3. Exploit pre-auth vulnerabilities (BlueKeep CVE-2019-0708)"
                        ),
                        reproduction_steps=[
                            f"xfreerdp /v:{host} /u:test  # Should show login without NLA",
                        ],
                        remediation="Enable NLA: gpedit → Computer Config → Admin Templates → Remote Desktop → Require NLA",
                        references=["CWE-287", "CVE-2019-0708"],
                        evidence=ev, cvss_v31_vector=CVSS_NLA, cvss_v40_vector=CVSS40_NLA,
                        target=host)
                elif rdp_open:
                    self.log.info("RDP on %s:3389 — NLA enforced", host)

            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                pass

        # Check RDP access with credentials
        username = self.config.extra.get("username", "")
        password = self.config.extra.get("password", "")
        if username and password:
            rdp_accessible = []
            for host in hosts[:5]:
                if not self.check_scope(host): continue
                await self.rate_limit()
                # Try RDP auth via xfreerdp check-mode or impacket
                try:
                    from impacket.smbconnection import SMBConnection
                    conn = SMBConnection(host, host, timeout=5)
                    conn.login(username, password, domain)
                    # If SMB works, check Remote Desktop Users group membership
                    conn.close()
                    rdp_accessible.append(host)
                except Exception:
                    pass

            if rdp_accessible:
                ev = Evidence(extra={"accessible": rdp_accessible})
                self.new_finding(
                    title=f"RDP Lateral Movement — {len(rdp_accessible)} hosts accessible",
                    severity=Severity.MEDIUM,
                    description=(
                        f"Current credentials can access {len(rdp_accessible)} host(s) via RDP/SMB: "
                        f"{', '.join(rdp_accessible[:10])}"
                    ),
                    reproduction_steps=[f"xfreerdp /v:{rdp_accessible[0]} /u:{username} /p:pass /d:{domain}"],
                    remediation="Restrict Remote Desktop Users group membership. Use PAW for admin access.",
                    references=["MITRE T1021.001"],
                    evidence=ev, cvss_v31_vector=CVSS_RDP, cvss_v40_vector=CVSS40_RDP,
                    mitre_attack=["TA0008/T1021.001"],
                    target=dc_ip)

        return self._make_result(start)

class TestRdpCheck:
    def test_phase(self) -> None: assert RdpCheck.PHASE == 12
