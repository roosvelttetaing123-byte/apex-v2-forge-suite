"""Zerologon (CVE-2020-1472) detection — safe probe only, NO exploitation.

CVE-2020-1472: Netlogon elevation of privilege via cryptographic flaw in
AES-CFB8 — an attacker can authenticate as the DC machine account by sending
all-zero client credentials (probability 1 in 256 per attempt).

This module:
 1. Checks if Netlogon RPC is accessible (safe Netlogon challenge probe)
 2. Checks FullSecureChannelProtection registry value via SMB/WinReg (requires credentials)
 3. Reports patch status and enforcement mode
 Does NOT exploit — no machine account password is changed.
"""
from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_ZEROLOGON = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
CVSS40_ZEROLOGON = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
class Zerologon(BaseModule):
    """Zerologon CVE-2020-1472 detection (safe probe only — detection, no exploit)."""

    NAME        = "zerologon"
    DESCRIPTION = "Detect Zerologon (CVE-2020-1472) via safe Netlogon negotiation probe — NO exploit"
    PHASE       = 4
    TAGS        = ["vuln-checks", "zerologon", "netlogon", "cve-2020-1472", "mitre-T1190"]

    async def run(self) -> ModuleResult:
        start  = time.monotonic()
        dc_ip  = self.config.extra.get("dc", self.config.target)
        domain = self.config.extra.get("domain", "")

        if not self.check_scope(dc_ip):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        # Run all checks concurrently
        await asyncio.gather(
            self._check_via_impacket(dc_ip, domain),
            self._check_enforcement_mode(dc_ip, domain),
            self._check_nmap(dc_ip),
        )
        return self._make_result(start)

    async def _check_via_impacket(self, dc_ip: str, domain: str) -> None:
        """Safe probe: send Netlogon ServerReqChallenge — check if anonymous challenge is accepted.

        We only test whether the Netlogon pipe is accessible and the challenge is accepted.
        We do NOT attempt to authenticate with zeroed credentials.
        """
        await self.rate_limit()
        try:
            from impacket.dcerpc.v5 import nrpc, transport

            dc_name = domain.split(".")[0].upper() if domain else "DC"
            string_binding = f"ncacn_np:{dc_ip}[\\PIPE\\NETLOGON]"
            rpctransport = transport.DCERPCTransportFactory(string_binding)
            rpctransport.setRemoteHost(dc_ip)
            rpctransport.set_connect_timeout(10)

            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(nrpc.MSRPC_UUID_NRPC)

            # Safe probe: test if server accepts an anonymous Netlogon challenge
            resp = nrpc.hNetrServerReqChallenge(
                dce,
                f"\\\\{dc_name}\x00",
                f"{dc_name}\x00",
                b"\x00" * 8,
            )
            error_code = resp["ErrorCode"]
            dce.disconnect()

            if error_code == 0:
                # The Netlogon service accepted the challenge. This is expected even on
                # patched systems — the zero-password authentication should fail.
                # We report this for awareness, noting that definitive confirmation
                # requires either the nmap script or Secura's checker tool.
                self.log.info(
                    "Zerologon probe: Netlogon challenge accepted on %s (error_code=0). "
                    "Verify patch via enforcement mode check or nmap script.",
                    dc_ip,
                )
                # Only generate INFORMATIONAL here — enforcement mode check generates HIGH/CRITICAL
                self._report_netlogon_accessible(dc_ip, error_code)
            else:
                self.log.info(
                    "Zerologon probe: Netlogon returned error_code=0x%x on %s — likely restricted",
                    error_code, dc_ip,
                )

        except ImportError:
            self.log.debug("impacket not available for Zerologon check")
        except Exception as exc:
            self.log.debug("Zerologon impacket probe: %s", exc)

    async def _check_nmap(self, dc_ip: str) -> None:
        """Use nmap smb-vuln-cve-2020-1472 script for definitive detection."""
        import shutil
        nmap = shutil.which("nmap")
        if not nmap:
            return

        await self.rate_limit()
        try:
            proc = await asyncio.create_subprocess_exec(
                nmap, "-p", "445", "--script", "smb-vuln-cve-2020-1472",
                "--script-timeout", "15s", "-oN", "-", dc_ip,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=40)
            output = stdout.decode()
            if "VULNERABLE" in output:
                self._report_zerologon_vulnerable(dc_ip, "nmap smb-vuln-cve-2020-1472", output[:600])
            elif "smb-vuln-cve-2020-1472" in output and "NOT VULNERABLE" in output:
                self.log.info("Zerologon nmap: DC %s NOT vulnerable per nmap script", dc_ip)
        except asyncio.TimeoutError:
            self.log.debug("Zerologon nmap check timed out on %s", dc_ip)
        except Exception as exc:
            self.log.debug("nmap Zerologon check failed: %s", exc)

    async def _check_enforcement_mode(self, dc_ip: str, domain: str) -> None:
        """Check Zerologon enforcement mode via remote registry (requires SMB credentials).

        Registry key: HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters
        Value: FullSecureChannelProtection (DWORD)
          0 = Not set / Compatibility mode (vulnerable to legacy machines using weak channel)
          1 = Enforcement mode ENABLED (patched, blocks non-compliant Netlogon)

        NOTE: The initial KB4566123 (Aug 2020) patch introduces compatibility mode.
        Full enforcement was automatic from Nov 2021 cumulative updates onward for
        Server 2019/2022. Older OSes require manual registry setting.
        """
        user   = self.config.extra.get("username", "")
        passwd = self.config.extra.get("password", "")
        nthash = self.config.extra.get("hash", "")

        if not user:
            self.log.debug("No credentials for Zerologon enforcement mode check — skipping registry probe")
            return

        await self.rate_limit()
        try:
            from impacket.smbconnection import SMBConnection
            from impacket.dcerpc.v5 import rrp, transport

            smb = SMBConnection(dc_ip, dc_ip, timeout=10)
            try:
                if nthash:
                    lm_h = ""
                    nt_h = nthash if ":" not in nthash else nthash.split(":", 1)[1]
                    smb.login(user, "", domain, lm_h, nt_h)
                else:
                    smb.login(user, passwd, domain)
            except Exception as login_exc:
                self.log.debug("SMB login failed for Zerologon reg check: %s", login_exc)
                return

            rpctransport = transport.SMBTransport(
                dc_ip, filename=r"\winreg", smb_connection=smb
            )
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(rrp.MSRPC_UUID_RRP)

            ans = rrp.hOpenLocalMachine(dce)
            reg_handle = ans["phKey"]

            key_path = r"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
            try:
                ans2 = rrp.hBaseRegOpenKey(dce, reg_handle, key_path)
                key_handle = ans2["phkResult"]
                try:
                    val = rrp.hBaseRegQueryValue(
                        dce, key_handle, "FullSecureChannelProtection"
                    )
                    enforcement = int(val[1])
                except Exception:
                    enforcement = None  # Value doesn't exist = not configured

                rrp.hBaseRegCloseKey(dce, key_handle)
                rrp.hBaseRegCloseKey(dce, reg_handle)
                dce.disconnect()
                smb.logoff()

                if enforcement is None or enforcement != 1:
                    self.new_finding(
                        title=f"Zerologon — Enforcement Mode NOT Enabled on {dc_ip} "
                              f"(FullSecureChannelProtection="
                              f"{'<not set>' if enforcement is None else enforcement})",
                        severity=Severity.HIGH,
                        description=(
                            f"Zerologon (CVE-2020-1472) enforcement mode is not active on {dc_ip}.\n\n"
                            f"FullSecureChannelProtection = "
                            f"{'<not configured>' if enforcement is None else enforcement} "
                            "(expected: 1).\n\n"
                            "CVE-2020-1472 patch has TWO phases:\n"
                            "  Phase 1 (KB4566123, Aug 2020): Compatibility mode — adds logging only, "
                            "  does NOT block vulnerable Netlogon connections.\n"
                            "  Phase 2 (Enforcement): FullSecureChannelProtection=1 — rejects "
                            "  non-compliant clients. Required for full protection.\n\n"
                            "Without enforcement mode, legacy devices using the weak Netlogon "
                            "channel can still be exploited, and the domain remains at risk."
                        ),
                        reproduction_steps=[
                            f"reg query \\\\{dc_ip}\\HKLM\\SYSTEM\\CurrentControlSet\\"
                            "Services\\Netlogon\\Parameters /v FullSecureChannelProtection",
                            "# Safe verification tool (Secura):",
                            "python3 zerologon_tester.py <dc_name> <dc_ip>",
                            "# nmap (safe):",
                            f"nmap -p 445 --script smb-vuln-cve-2020-1472 {dc_ip}",
                        ],
                        remediation=(
                            "1. Apply cumulative security update (KB4566123 or later) immediately.\n"
                            "2. Set enforcement mode:\n"
                            r"   reg add HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
                            " /v FullSecureChannelProtection /t REG_DWORD /d 1 /f\n"
                            "3. Test in compatibility mode first (FullSecureChannelProtection=0) "
                            "   to identify non-compliant devices, then enforce (=1).\n"
                            "4. Ensure ALL domain controllers are patched and enforcing."
                        ),
                        references=[
                            "CVE-2020-1472",
                            "KB4566123",
                            "KB4571694",
                            "https://www.secura.com/blog/zero-logon",
                            "MITRE TA0001/T1190",
                        ],
                        evidence=Evidence(extra={
                            "dc_ip":      dc_ip,
                            "reg_value":  enforcement,
                            "expected":   1,
                            "key_path":   key_path,
                        }),
                        cvss_v31_vector=CVSS_ZEROLOGON,
                        cvss_v40_vector=CVSS40_ZEROLOGON,
                        mitre_attack=["TA0001/T1190"],
                        target=dc_ip,
                    )
                else:
                    self.log.info(
                        "Zerologon: enforcement mode IS enabled on %s "
                        "(FullSecureChannelProtection=1) — PATCHED",
                        dc_ip,
                    )

            except Exception as key_exc:
                self.log.debug("Registry key read failed: %s", key_exc)
                try:
                    rrp.hBaseRegCloseKey(dce, reg_handle)
                    dce.disconnect()
                    smb.logoff()
                except Exception:
                    pass

        except ImportError:
            self.log.debug("impacket not available for Zerologon enforcement mode check")
        except Exception as exc:
            self.log.debug("Zerologon enforcement check failed: %s", exc)

    def _report_netlogon_accessible(self, dc_ip: str, error_code: int) -> None:
        """Report that Netlogon is accessible — needs manual verification."""
        self.new_finding(
            title=f"Zerologon — Netlogon Accessible on {dc_ip}: Manual Patch Verification Required",
            severity=Severity.INFORMATIONAL,
            description=(
                f"Netlogon service is accessible on {dc_ip} (challenge accepted, error_code={error_code}). "
                "This is expected on both patched and unpatched systems. "
                "Definitive Zerologon vulnerability status requires the nmap script or "
                "the Secura PoC tool (safe tester).\n\n"
                "DETECTION NOTE: Active exploitation was NOT attempted by this module."
            ),
            reproduction_steps=[
                "# Safe check (no exploitation):",
                "python3 zerologon_tester.py <dc_name> <dc_ip>",
                f"nmap -p 445 --script smb-vuln-cve-2020-1472 {dc_ip}",
            ],
            remediation=(
                "Apply MS KB4566123 or later. Enable FullSecureChannelProtection=1 on all DCs."
            ),
            references=["CVE-2020-1472", "MITRE TA0001/T1190"],
            evidence=Evidence(extra={"dc_ip": dc_ip, "probe": "NetrServerReqChallenge", "error_code": error_code}),
            cvss_v31_vector=CVSS_ZEROLOGON,
            cvss_v40_vector=CVSS40_ZEROLOGON,
            mitre_attack=["TA0001/T1190"],
            target=dc_ip,
        )

    def _report_zerologon_vulnerable(self, dc_ip: str, method: str, details: str) -> None:
        """Report confirmed Zerologon vulnerability (from nmap script)."""
        self.new_finding(
            title=f"Zerologon (CVE-2020-1472) — VULNERABLE ({dc_ip}) via {method}",
            severity=Severity.CRITICAL,
            description=(
                f"DC {dc_ip} is VULNERABLE to Zerologon (CVE-2020-1472). "
                "Detection method: {method}.\n\n"
                "An unauthenticated attacker can authenticate as the DC machine account "
                "by exploiting the AES-CFB8 cryptographic flaw in the Netlogon protocol. "
                "This allows resetting the DC machine account password and achieving "
                "full domain compromise via DCSync.\n\n"
                "CVSS 10.0. DETECTION ONLY — this module did NOT exploit the vulnerability."
            ),
            reproduction_steps=[
                "# Safe verification ONLY — do NOT run exploit in production:",
                "python3 zerologon_tester.py <dc_name> <dc_ip>  # safe, read-only",
                "# After patching, verify with the same tool",
            ],
            remediation=(
                "CRITICAL: Apply KB4566123 IMMEDIATELY. "
                "This vulnerability allows full domain compromise without any credentials. "
                "After patching, set FullSecureChannelProtection=1 and run the safe tester to confirm."
            ),
            references=["CVE-2020-1472", "Secura Zerologon whitepaper", "MITRE TA0001/T1190"],
            evidence=Evidence(
                response_raw=details[:500],
                extra={"dc_ip": dc_ip, "method": method},
            ),
            cvss_v31_vector=CVSS_ZEROLOGON,
            cvss_v40_vector=CVSS40_ZEROLOGON,
            mitre_attack=["TA0001/T1190"],
            target=dc_ip,
        )


class TestZerologon:
    def test_cvss_vector(self) -> None:
        assert CVSS_ZEROLOGON.startswith("CVSS:3.1")
        assert "C:H/I:H/A:H" in CVSS_ZEROLOGON
        assert "S:C" in CVSS_ZEROLOGON

    def test_cvss_score(self) -> None:
        from common.finding import cvss31_score
        score = cvss31_score(CVSS_ZEROLOGON)
        assert score >= 9.0, f"Expected CRITICAL score, got {score}"

    def test_phase(self) -> None:
        assert Zerologon.PHASE == 4  # VulnChecks

    def test_tags(self) -> None:
        assert "cve-2020-1472" in Zerologon.TAGS
        assert "mitre-T1190" in Zerologon.TAGS
