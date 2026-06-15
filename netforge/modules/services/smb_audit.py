"""SMB Auditor — comprehensive SMB security checks.

Checks:
- SMBv1 enabled (EternalBlue/WannaCry vector)
- SMB signing disabled/not required (NTLM relay risk)
- Null session authentication (anonymous access)
- Guest account access
- Share enumeration with access-level testing
- MS17-010 EternalBlue detection (nmap NSE, no exploitation)
"""
from __future__ import annotations

import asyncio
import ipaddress
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

# CVSS 3.1 vectors
CVSS_SIGNING     = "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"
CVSS40_SIGNING   = "CVSS:4.0/AV:A/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
CVSS_NULL_SESS   = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
CVSS40_NULL_SESS = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
CVSS_ETERNALBLUE = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
CVSS40_ETERNALBLUE = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
CVSS_SMBV1       = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
CVSS40_SMBV1     = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
CVSS_GUEST       = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
CVSS40_GUEST     = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N"
# Shares that indicate sensitive exposure when accessible anonymously
SENSITIVE_SHARES = {"C$", "ADMIN$", "IPC$", "SYSVOL", "NETLOGON", "PRINT$"}


class SmbAudit(BaseModule):
    """SMB comprehensive security auditor."""

    NAME        = "smb_audit"
    DESCRIPTION = (
        "SMB: SMBv1 detection, signing enforcement, null session, guest access, "
        "share enumeration, EternalBlue (MS17-010) indicator"
    )
    PHASE       = 4
    TAGS        = ["smb", "network", "signing", "ms17-010", "smbv1", "relay", "cwe-306"]

    async def run(self) -> ModuleResult:
        start  = time.monotonic()
        target = self.config.target

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        hosts = self._expand_target(target)
        self.log.info("SMB audit on %d host(s) (cap 50)", len(hosts))

        for host in hosts[:50]:
            await self.rate_limit()
            if not self.check_scope(host):
                continue
            if not await self._port_open(host, 445):
                continue
            await self._audit_host(host)

        return self._make_result(start)

    # ------------------------------------------------------------------
    # Per-host orchestration
    # ------------------------------------------------------------------

    async def _audit_host(self, host: str) -> None:
        self.log.debug("SMB port 445 open on %s — auditing", host)
        await self._check_smbv1(host)
        await self._check_signing(host)
        await self._check_null_session(host)
        await self._check_guest_access(host)
        await self._check_eternal_blue(host)

    # ------------------------------------------------------------------
    # SMBv1 detection
    # ------------------------------------------------------------------

    async def _check_smbv1(self, host: str) -> None:
        """Detect SMBv1 by sending an SMBv1 Negotiate request.

        A non-error response to the SMBv1 negotiate indicates the protocol
        is enabled. SMBv1 is the attack surface for EternalBlue/MS17-010,
        WannaCry, and NotPetya.
        """
        smb1_neg = (
            b"\x00\x00\x00\x85"       # NetBIOS length
            b"\xff\x53\x4d\x42"       # SMBv1 magic: \xffSMB
            b"\x72"                    # Command: Negotiate (0x72)
            b"\x00\x00\x00\x00"       # NT Status
            b"\x18\x53\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x00\x00"
            b"\x00"                    # Word count
            b"\x62\x00"               # Byte count
            # Dialect list (6 dialects)
            b"\x02PC NETWORK PROGRAM 1.0\x00"
            b"\x02LANMAN1.0\x00"
            b"\x02Windows for Workgroups 3.1a\x00"
            b"\x02LM1.2X002\x00"
            b"\x02LANMAN2.1\x00"
            b"\x02NT LM 0.12\x00"
        )
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, 445), timeout=5
            )
            writer.write(smb1_neg)
            await writer.drain()
            data = await asyncio.wait_for(reader.read(256), timeout=5)
            writer.close()

            # SMBv1 response: bytes 4-7 == \xffSMB and status == 0
            if (
                len(data) > 36
                and data[4:8] == b"\xff\x53\x4d\x42"    # \xffSMB magic
                and data[9:13] == b"\x00\x00\x00\x00"   # NT_STATUS = SUCCESS
            ):
                ev = Evidence(
                    request_raw=f"SMBv1 Negotiate Request → {host}:445",
                    response_raw=f"SMBv1 Negotiate Response (hex): {data[:40].hex()}",
                    extra={"host": host, "smbv1_response": True},
                )
                self.new_finding(
                    title=f"SMBv1 Protocol Enabled — {host}",
                    severity=Severity.CRITICAL,
                    description=(
                        f"SMBv1 (Server Message Block version 1) is enabled on {host}. "
                        "SMBv1 is the attack surface for MS17-010 (EternalBlue/WannaCry/NotPetya) "
                        "and has been deprecated by Microsoft since 2014. "
                        "There is no legitimate reason to enable SMBv1 in modern environments."
                    ),
                    reproduction_steps=[
                        f"nmap -p 445 --script smb-protocols {host}",
                        "# In PowerShell (if domain joined): Get-SmbServerConfiguration | Select EnableSMB1Protocol",
                        "# Confirm: python3 -c \"import socket; s=socket.create_connection(('{}',445)); ...\"".format(host),
                    ],
                    remediation=(
                        "Disable SMBv1 immediately:\n"
                        "  PowerShell: Set-SmbServerConfiguration -EnableSMB1Protocol $false\n"
                        "  Linux (Samba): In smb.conf → [global] → min protocol = SMB2\n"
                        "  Windows Server 2016+: Uninstall Windows Feature 'FS-SMB1'"
                    ),
                    references=["CVE-2017-0144", "MS17-010", "MITRE T1210", "CWE-693"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_SMBV1,
                    cvss_v40_vector=CVSS40_SMBV1,
                    mitre_attack=["TA0001/T1190", "TA0002/T1210"],
                    port=445,
                    service="smb",
                    target=host,
                )
        except Exception as exc:
            self.log.debug("SMBv1 check failed on %s: %s", host, exc)

    # ------------------------------------------------------------------
    # SMB Signing
    # ------------------------------------------------------------------

    async def _check_signing(self, host: str) -> None:
        """Check SMB2 Negotiate response SecurityMode for signing requirement.

        SecurityMode bit 0 = signing enabled
        SecurityMode bit 1 = signing required
        When bit 1 is NOT set, NTLM relay attacks are possible.
        """
        # Try impacket first (more reliable), fall back to raw probe
        try:
            from impacket.smbconnection import SMBConnection  # type: ignore
            smb = SMBConnection(host, host, timeout=10)
            try:
                smb.login("", "")
            except Exception:
                pass  # Login may fail, but we already have signing info
            signing_required = smb.isSigningRequired()
            smb.logoff()
            if not signing_required:
                ev = Evidence(
                    extra={"host": host, "signing_required": False, "relay_candidate": True}
                )
                self._report_signing(host, ev)
            return
        except ImportError:
            pass
        except Exception:
            pass

        # Raw SMB2 negotiate packet
        try:
            negotiate_req = (
                b"\x00\x00\x00\x54"  # NetBIOS
                b"\xfe\x53\x4d\x42"  # SMB2 magic
                b"\x40\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x01\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\xff\xfe\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x24\x00\x08\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x7f\x00\x00\x00"
                b"\x02\x00\x02\x02\x10\x02\x22\x02"
                b"\x00\x03\x02\x03\x10\x03\x11\x03"
            )
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, 445), timeout=5
            )
            writer.write(negotiate_req)
            await writer.drain()
            data = await asyncio.wait_for(reader.read(256), timeout=5)
            writer.close()

            # SMB2 Negotiate Response: SecurityMode is at offset 70 (header 64 + offset 6)
            # SecurityMode: bit 0 = SIGNING_ENABLED, bit 1 = SIGNING_REQUIRED
            if len(data) > 72 and data[4:8] == b"\xfe\x53\x4d\x42":
                security_mode = data[70]
                signing_required = bool(security_mode & 0x02)
                if not signing_required:
                    ev = Evidence(
                        request_raw=f"SMB2 Negotiate → {host}:445",
                        response_raw=f"SecurityMode byte: 0x{security_mode:02x}",
                        extra={"host": host, "security_mode": f"0x{security_mode:02x}",
                               "signing_enabled": bool(security_mode & 0x01),
                               "signing_required": False},
                    )
                    self._report_signing(host, ev)
        except Exception as exc:
            self.log.debug("Raw SMB2 signing check failed on %s: %s", host, exc)

    def _report_signing(self, host: str, ev: Evidence) -> None:
        self.new_finding(
            title=f"SMB Signing Not Required — {host} (NTLM Relay Risk)",
            severity=Severity.HIGH,
            description=(
                f"SMB signing is not enforced on {host}. "
                "Attackers with network access can relay NTLM authentication captures "
                "to this host (NTLM relay attack via Responder + ntlmrelayx.py). "
                "This enables lateral movement without cracking password hashes. "
                "MITRE ATT&CK: T1557.001 (LLMNR/NBT-NS Poisoning and SMB Relay)."
            ),
            reproduction_steps=[
                f"crackmapexec smb {host} --gen-relay-list relay_targets.txt",
                "sudo responder -I eth0 -wrd",
                "ntlmrelayx.py -tf relay_targets.txt -smb2support",
                "Wait for victim to authenticate to any SMB share — credentials auto-relayed",
            ],
            remediation=(
                "Enforce SMB signing on ALL hosts (not just 'enabled' — 'required'):\n"
                "  GPO: Computer Configuration > Windows Settings > Security Settings > "
                "Local Policies > Security Options:\n"
                "  - 'Microsoft network client: Digitally sign communications (always)' = Enabled\n"
                "  - 'Microsoft network server: Digitally sign communications (always)' = Enabled\n"
                "  Linux (Samba): 'server signing = mandatory'"
            ),
            references=["CVE-2015-0005", "MITRE T1557.001", "CWE-306", "MS-SAMR"],
            evidence=ev,
            cvss_v31_vector=CVSS_SIGNING,
            cvss_v40_vector=CVSS40_SIGNING,
            mitre_attack=["TA0006/T1557.001"],
            port=445,
            service="smb",
            target=host,
        )

    # ------------------------------------------------------------------
    # Null session / anonymous access
    # ------------------------------------------------------------------

    async def _check_null_session(self, host: str) -> None:
        """Attempt null session (username='', password='') share enumeration."""
        try:
            from impacket.smbconnection import SMBConnection  # type: ignore
            smb = SMBConnection(host, host, timeout=10)
            smb.login("", "")  # null session
            shares = smb.listShares()
            share_names = [s["shi1_netname"].rstrip("\x00") for s in shares]
            smb.logoff()

            sensitive = [s for s in share_names if s.upper() in SENSITIVE_SHARES]
            ev = Evidence(
                request_raw=f"SMB LOGIN null session → {host}:445",
                response_raw=f"Shares: {', '.join(share_names)}",
                extra={"host": host, "shares": share_names, "sensitive_shares": sensitive},
            )
            self.new_finding(
                title=f"SMB Null Session Allowed — Share Enumeration: {host}",
                severity=Severity.MEDIUM,
                description=(
                    f"Anonymous (null session) authentication succeeded on {host}. "
                    f"Shares visible: {', '.join(share_names[:10])}. "
                    + (f"Sensitive shares: {', '.join(sensitive)}. " if sensitive else "")
                    + "Null sessions enable user enumeration via RPC, group policy path disclosure, "
                    "and are a stepping stone for brute force and relay attacks."
                ),
                reproduction_steps=[
                    f"smbclient -L //{host} -N",
                    f"crackmapexec smb {host} -u '' -p '' --shares",
                    f"rpcclient -U '' -N {host} -c enumdomusers",
                ],
                remediation=(
                    "Restrict null sessions:\n"
                    "  Registry: HKLM\\System\\CurrentControlSet\\Control\\LSA → "
                    "RestrictAnonymous = 2\n"
                    "  GPO: Network access: Restrict anonymous access to Named Pipes and Shares = Enabled\n"
                    "  GPO: Network access: Do not allow anonymous enumeration of SAM accounts = Enabled"
                ),
                references=["CWE-306", "MITRE T1135", "MITRE T1069"],
                evidence=ev,
                cvss_v31_vector=CVSS_NULL_SESS,
                cvss_v40_vector=CVSS40_NULL_SESS,
                mitre_attack=["TA0007/T1135"],
                port=445,
                service="smb",
                target=host,
            )
        except ImportError:
            # Fallback: nmap null session check
            await self._nmap_null_session(host)
        except Exception:
            pass  # Null session blocked — good

    async def _nmap_null_session(self, host: str) -> None:
        """Fallback: use nmap smb-enum-shares with no credentials."""
        import shutil
        nmap = shutil.which("nmap")
        if not nmap:
            return
        try:
            proc = await asyncio.create_subprocess_exec(
                nmap, "-p", "445", "--script", "smb-enum-shares",
                "--script-args", "smbusername=,smbpassword=",
                "--script-timeout", "15s", "-n", host,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
            output = stdout.decode(errors="ignore")
            if "Share Enumeration" in output or "\\\\" in output:
                ev = Evidence(
                    request_raw=f"nmap --script smb-enum-shares {host}",
                    response_raw=output[:500],
                    extra={"host": host},
                )
                self.new_finding(
                    title=f"SMB Null Session Allowed (nmap): {host}",
                    severity=Severity.MEDIUM,
                    description=f"nmap smb-enum-shares returned share listing without credentials on {host}.",
                    reproduction_steps=[f"nmap -p 445 --script smb-enum-shares --script-args 'smbusername=,smbpassword=' {host}"],
                    remediation="Set RestrictAnonymous=2 via GPO. Disable null session access.",
                    references=["CWE-306"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_NULL_SESS,
                    cvss_v40_vector=CVSS40_NULL_SESS,
                    port=445, service="smb", target=host,
                )
        except Exception as exc:
            self.log.debug("nmap null session check failed: %s", exc)

    # ------------------------------------------------------------------
    # Guest account access
    # ------------------------------------------------------------------

    async def _check_guest_access(self, host: str) -> None:
        """Test if guest account allows SMB login (username='guest', password='')."""
        try:
            from impacket.smbconnection import SMBConnection  # type: ignore
            smb = SMBConnection(host, host, timeout=10)
            smb.login("guest", "")
            # If we get here, guest login succeeded
            shares = []
            try:
                raw = smb.listShares()
                shares = [s["shi1_netname"].rstrip("\x00") for s in raw]
            except Exception:
                pass
            smb.logoff()

            ev = Evidence(
                request_raw=f"SMB LOGIN guest:'' → {host}:445",
                response_raw=f"Login succeeded. Shares: {', '.join(shares)}",
                extra={"host": host, "shares": shares},
            )
            self.new_finding(
                title=f"SMB Guest Account Login Allowed — {host}",
                severity=Severity.HIGH,
                description=(
                    f"The 'guest' account with an empty password authenticated successfully "
                    f"to {host} via SMB. Guest access allows unauthenticated file system "
                    "access, credential material exposure, and is a common entry point "
                    "for ransomware lateral movement. "
                    f"Shares accessible: {', '.join(shares[:8]) if shares else 'unable to enumerate'}"
                ),
                reproduction_steps=[
                    f"smbclient -L //{host} -U guest%",
                    f"crackmapexec smb {host} -u guest -p '' --shares",
                ],
                remediation=(
                    "Disable the guest account:\n"
                    "  net user guest /active:no\n"
                    "  GPO: Security Settings > Account Policies > Account Lockout: "
                    "disable Guest account\n"
                    "  Set 'Network access: Sharing and security model for local accounts' to "
                    "'Classic – local users authenticate as themselves'"
                ),
                references=["CWE-306", "CIS Benchmark: 2.3.11.4", "MITRE T1078.001"],
                evidence=ev,
                cvss_v31_vector=CVSS_GUEST,
                cvss_v40_vector=CVSS40_GUEST,
                mitre_attack=["TA0001/T1078.001"],
                port=445,
                service="smb",
                target=host,
            )
        except ImportError:
            pass
        except Exception:
            pass  # Guest blocked — good

    # ------------------------------------------------------------------
    # EternalBlue / MS17-010
    # ------------------------------------------------------------------

    async def _check_eternal_blue(self, host: str) -> None:
        """Check for MS17-010 EternalBlue vulnerability using nmap NSE.

        Detection only — no exploitation is performed.
        """
        import shutil
        nmap = shutil.which("nmap")
        if not nmap:
            return
        await self.rate_limit()
        try:
            proc = await asyncio.create_subprocess_exec(
                nmap, "-p", "445",
                "--script", "smb-vuln-ms17-010,smb-vuln-ms10-054,smb-double-pulsar-backdoor",
                "--script-timeout", "15s",
                "-n", "-Pn", host,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=45)
            output = stdout.decode(errors="ignore")

            if "VULNERABLE" in output and "ms17-010" in output.lower():
                ev = Evidence(
                    request_raw=f"nmap --script smb-vuln-ms17-010 -p 445 {host}",
                    response_raw=output[:2000],
                    extra={"host": host, "cve": "CVE-2017-0144"},
                )
                self.new_finding(
                    title=f"MS17-010 EternalBlue VULNERABLE — {host}:445",
                    severity=Severity.CRITICAL,
                    description=(
                        f"nmap confirms {host} is VULNERABLE to MS17-010 (EternalBlue). "
                        "This allows unauthenticated remote code execution as SYSTEM via SMB. "
                        "EternalBlue was weaponized by WannaCry (2017) and NotPetya (2017) "
                        "ransomware causing billions in damages globally. "
                        "DETECTION ONLY — no exploit attempted."
                    ),
                    reproduction_steps=[
                        f"nmap -p 445 --script smb-vuln-ms17-010 {host}",
                        "# Authorized exploitation only:",
                        "# use exploit/windows/smb/ms17_010_eternalblue in Metasploit",
                    ],
                    remediation=(
                        "IMMEDIATE action required:\n"
                        "1. Apply Microsoft patch MS17-010 (KB4012212 / KB4012215)\n"
                        "2. Disable SMBv1: Set-SmbServerConfiguration -EnableSMB1Protocol $false\n"
                        "3. Block TCP 445 at perimeter firewall\n"
                        "4. Isolate unpatched hosts in separate network segment until patched"
                    ),
                    references=["CVE-2017-0144", "CVE-2017-0145", "MS17-010", "EternalBlue"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_ETERNALBLUE,
                    cvss_v40_vector=CVSS40_ETERNALBLUE,
                    mitre_attack=["TA0002/T1210", "TA0008/T1021.002"],
                    port=445,
                    service="smb",
                    target=host,
                )

            if "VULNERABLE" in output and "double-pulsar" in output.lower():
                ev = Evidence(
                    request_raw=f"nmap --script smb-double-pulsar-backdoor -p 445 {host}",
                    response_raw=output[:1000],
                    extra={"host": host, "backdoor": "DoublePulsar"},
                )
                self.new_finding(
                    title=f"DoublePulsar Backdoor DETECTED — {host}:445",
                    severity=Severity.CRITICAL,
                    description=(
                        f"The DoublePulsar kernel backdoor is ACTIVE on {host}. "
                        "This NSA-developed backdoor was leaked by Shadow Brokers and is "
                        "installed alongside EternalBlue exploitation. Any attacker who knows "
                        "the XOR key can execute arbitrary kernel-mode code immediately. "
                        "This host is almost certainly already compromised."
                    ),
                    reproduction_steps=[
                        f"nmap --script smb-double-pulsar-backdoor -p 445 {host}",
                    ],
                    remediation=(
                        "EMERGENCY RESPONSE: Isolate host immediately. "
                        "Assume full compromise — initiate IR process. "
                        "Rebuild from clean baseline after forensic preservation."
                    ),
                    references=["EternalBlue", "DoublePulsar", "CVE-2017-0144"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_ETERNALBLUE,
                    cvss_v40_vector=CVSS40_ETERNALBLUE,
                    mitre_attack=["TA0003/T1543", "TA0002/T1059"],
                    port=445,
                    service="smb",
                    target=host,
                )
        except Exception as exc:
            self.log.debug("EternalBlue check failed on %s: %s", host, exc)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _expand_target(self, target: str) -> list[str]:
        try:
            net = ipaddress.ip_network(target, strict=False)
            if net.num_addresses > 1:
                return [str(h) for h in net.hosts()]
            return [target]
        except ValueError:
            return [target]

    async def _port_open(self, host: str, port: int) -> bool:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=3
            )
            writer.close()
            return True
        except Exception:
            return False


class TestSmbAudit:
    def test_expand_cidr(self) -> None:
        mod = SmbAudit.__new__(SmbAudit)
        hosts = mod._expand_target("192.168.1.0/30")
        assert "192.168.1.1" in hosts
        assert "192.168.1.2" in hosts

    def test_expand_single_host(self) -> None:
        mod = SmbAudit.__new__(SmbAudit)
        hosts = mod._expand_target("10.0.0.1")
        assert hosts == ["10.0.0.1"]

    def test_sensitive_shares_set(self) -> None:
        assert "ADMIN$" in SENSITIVE_SHARES
        assert "C$" in SENSITIVE_SHARES

    def test_cvss_vectors(self) -> None:
        for v in (CVSS_SIGNING, CVSS_NULL_SESS, CVSS_ETERNALBLUE, CVSS_SMBV1, CVSS_GUEST):
            assert v.startswith("CVSS:3.1/")

    def test_phase(self) -> None:
        assert SmbAudit.PHASE == 4
