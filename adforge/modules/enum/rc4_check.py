"""RC4 / AES enforcement check — detect RC4-enabled Kerberos encryption."""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
from adforge.core.ldap_client import LdapClient

CVSS_RC4 = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
CVSS40_RC4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
# msDS-SupportedEncryptionTypes bit flags
ETYPE_DES_CBC_CRC  = 0x01
ETYPE_DES_CBC_MD5  = 0x02
ETYPE_RC4_HMAC     = 0x04
ETYPE_AES128       = 0x08
ETYPE_AES256       = 0x10
ETYPE_AES256_SK    = 0x20  # AES-256 with support for Session Key

# Ideal: only AES128 + AES256 (no RC4, no DES)
ETYPE_AES_ONLY = ETYPE_AES128 | ETYPE_AES256


class Rc4Check(BaseModule):
    """Check whether RC4 (etype 23) Kerberos encryption is still enabled across the domain."""

    NAME        = "rc4_check"
    DESCRIPTION = "Enumerate msDS-SupportedEncryptionTypes on DCs and domain; flag RC4/DES enablement"
    PHASE       = 3
    TAGS        = ["enum", "kerberos", "rc4", "encryption", "hardening", "mitre-T1558"]

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
            await self._check_encryption_types(client, domain, dc_ip)
        finally:
            client.disconnect()

        return self._make_result(start)

    async def _check_encryption_types(
        self, client: LdapClient, domain: str, dc_ip: str
    ) -> None:
        # Check domain object
        domain_entries = client.search(
            "(objectClass=domain)",
            ["msDS-SupportedEncryptionTypes", "name"],
        )

        # Check DC machine accounts
        dc_accounts = client.search(
            "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
            ["sAMAccountName", "msDS-SupportedEncryptionTypes", "operatingSystem"],
        )

        # Check krbtgt account specifically (its enc types determine ticket options)
        krbtgt = client.search(
            "(sAMAccountName=krbtgt)",
            ["msDS-SupportedEncryptionTypes", "userAccountControl"],
        )

        def _parse_etypes(val: object) -> int:
            try:
                return int(str(val or 0))
            except (ValueError, TypeError):
                return 0

        def _describe(etypes: int) -> str:
            parts = []
            if etypes & ETYPE_DES_CBC_CRC:  parts.append("DES-CBC-CRC")
            if etypes & ETYPE_DES_CBC_MD5:  parts.append("DES-CBC-MD5")
            if etypes & ETYPE_RC4_HMAC:     parts.append("RC4-HMAC(etype23)")
            if etypes & ETYPE_AES128:       parts.append("AES128")
            if etypes & ETYPE_AES256:       parts.append("AES256")
            if etypes & ETYPE_AES256_SK:    parts.append("AES256-SK")
            return ", ".join(parts) if parts else f"raw=0x{etypes:x}"

        results: list[dict] = []
        rc4_enabled_objects: list[str] = []
        des_enabled_objects: list[str] = []

        for entry in (
            domain_entries + dc_accounts + (krbtgt or [])
        ):
            name   = str(entry.get("sAMAccountName") or entry.get("name") or "domain")
            etypes = _parse_etypes(entry.get("msDS-SupportedEncryptionTypes"))

            # 0 means "use default" — on most DCs default still includes RC4
            effective_rc4 = bool(etypes == 0 or etypes & ETYPE_RC4_HMAC)
            has_des       = bool(etypes & (ETYPE_DES_CBC_CRC | ETYPE_DES_CBC_MD5))

            results.append({
                "name":         name,
                "enc_types":    f"0x{etypes:x}",
                "described":    _describe(etypes),
                "rc4_enabled":  effective_rc4,
                "des_enabled":  has_des,
                "aes_only":     not effective_rc4 and not has_des and bool(etypes & (ETYPE_AES128 | ETYPE_AES256)),
            })
            if effective_rc4:
                rc4_enabled_objects.append(name)
            if has_des:
                des_enabled_objects.append(name)

        # Store for downstream modules (golden/silver ticket know which etypes work)
        self.config.extra["rc4_enabled"] = bool(rc4_enabled_objects)
        self.config.extra["aes_only_domain"] = not bool(rc4_enabled_objects)

        ev = Evidence(extra={
            "objects_checked":     len(results),
            "rc4_enabled_on":      rc4_enabled_objects,
            "des_enabled_on":      des_enabled_objects,
            "details":             results,
        })

        if rc4_enabled_objects:
            self.new_finding(
                title=f"RC4 Kerberos Encryption Enabled ({len(rc4_enabled_objects)} object(s))",
                severity=Severity.MEDIUM,
                description=(
                    f"RC4-HMAC (etype 23) is still enabled on: {rc4_enabled_objects}.\n\n"
                    "Impact on attack surface:\n"
                    "• Kerberoasting: RC4-encrypted TGS tickets are faster to crack offline\n"
                    "• Golden/Silver tickets: RC4-based forgery is detectable on AES-only DCs "
                    "but WORKS on RC4-enabled DCs\n"
                    "• Pass-the-Hash: RC4 = NTLM hash, usable directly\n"
                    "• AS-REP roasting: RC4 hashes are etype 23 (weaker than AES etype 18)\n\n"
                    "Note: msDS-SupportedEncryptionTypes = 0 means 'use default' "
                    "which historically includes RC4 unless the 'Refuse RC4' GPO is set."
                ),
                reproduction_steps=[
                    "# Verify from domain-joined host:",
                    "Get-ADComputer -Filter * -Properties msDS-SupportedEncryptionTypes | "
                    "Where {!($_.msDS-SupportedEncryptionTypes -band 0x18)}",
                    "# Check DC registry (requires admin):",
                    f"reg query \\\\{dc_ip}\\HKLM\\SYSTEM\\CurrentControlSet\\Services\\Kdc "
                    "/v SupportedEncryptionTypes",
                ],
                remediation=(
                    "Disable RC4 via GPO: Computer Config → Windows Settings → "
                    "Security Settings → Local Policies → Security Options → "
                    "'Network security: Configure encryption types allowed for Kerberos' → "
                    "Uncheck DES and RC4, leave only AES128 + AES256.\n\n"
                    "Set msDS-SupportedEncryptionTypes = 0x18 (AES128+AES256) on all accounts.\n"
                    "Verify compatibility before enforcing — some legacy services require RC4."
                ),
                references=[
                    "MITRE T1558",
                    "CIS AD Benchmark L1",
                    "https://docs.microsoft.com/windows-server/security/kerberos/preventing-kerberos-change-password-that-uses-rc4-secret-keys",
                ],
                evidence=ev,
                cvss_v31_vector=CVSS_RC4,
                cvss_v40_vector=CVSS40_RC4,
                mitre_attack=["TA0006/T1558"],
                target=dc_ip,
            )

        if des_enabled_objects:
            self.new_finding(
                title=f"DES Kerberos Encryption Enabled ({len(des_enabled_objects)} object(s))",
                severity=Severity.HIGH,
                description=(
                    f"DES encryption (etype 1/3) is enabled on: {des_enabled_objects}. "
                    "DES was deprecated in RFC 6649 and is trivially broken. "
                    "These objects are at high risk for offline cracking of Kerberos tickets."
                ),
                reproduction_steps=[
                    "Get-ADUser -Filter * -Properties msDS-SupportedEncryptionTypes | "
                    "Where {$_.msDS-SupportedEncryptionTypes -band 0x3}",
                ],
                remediation=(
                    "Remove DES encryption types from all accounts. "
                    "Set msDS-SupportedEncryptionTypes to at minimum 0x18 (AES only)."
                ),
                references=["RFC 6649", "MITRE T1558"],
                evidence=Evidence(extra={"des_objects": des_enabled_objects}),
                cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                mitre_attack=["TA0006/T1558"],
                target=dc_ip,
            )

        if not rc4_enabled_objects and not des_enabled_objects:
            self.log.info(
                "RC4 check: domain appears AES-only — golden/silver RC4 tickets will likely fail"
            )


class TestRc4Check:
    def test_etype_flags(self) -> None:
        assert ETYPE_RC4_HMAC == 0x04
        assert ETYPE_AES256   == 0x10
        assert ETYPE_AES_ONLY == 0x18

    def test_cvss(self) -> None:
        assert CVSS_RC4.startswith("CVSS:3.1")
