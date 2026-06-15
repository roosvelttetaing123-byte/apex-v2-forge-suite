"""ADCS ESC9 — CT_FLAG_NO_SECURITY_EXTENSION enables certificate impersonation."""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
from adforge.core.ldap_client import LdapClient

CVSS_ESC9 = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"
CVSS40_ESC9 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
# CT_FLAG_NO_SECURITY_EXTENSION prevents szOID_NTDS_CA_SECURITY_EXT from
# being embedded in issued certificates. Without this OID the DC falls back
# to weak (UPN-based) certificate mapping, which is exploitable.
CT_FLAG_NO_SECURITY_EXTENSION = 0x80000


class Esc9Check(BaseModule):
    """ADCS ESC9 — No Security Extension flag allows certificate-based impersonation."""

    NAME        = "esc9_check"
    DESCRIPTION = "Check ADCS for ESC9: CT_FLAG_NO_SECURITY_EXTENSION on templates + weak mapping"
    PHASE       = 11
    TAGS        = ["adcs", "esc9", "certificate", "privilege-escalation", "mitre-T1649"]

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
            await self._check_templates(client, domain, dc_ip)
        finally:
            client.disconnect()

        return self._make_result(start)

    async def _check_templates(self, client: LdapClient, domain: str, dc_ip: str) -> None:
        dc_parts   = ",".join(f"DC={p}" for p in domain.split("."))
        config_nc  = f"CN=Configuration,{dc_parts}"
        templates_dn = f"CN=Certificate Templates,CN=Public Key Services,CN=Services,{config_nc}"

        templates = client.search(
            "(objectClass=pKICertificateTemplate)",
            ["cn", "msPKI-Enrollment-Flag", "msPKI-Certificate-Name-Flag",
             "pKIExtendedKeyUsage", "nTSecurityDescriptor"],
            base_dn=templates_dn,
        )

        CLIENT_AUTH_OIDS = {"1.3.6.1.5.5.7.3.2", "1.3.6.1.4.1.311.20.2.2", "2.5.29.37.0"}

        for t in templates:
            name  = t.get("cn", "Unknown")
            eflag = int(str(t.get("msPKI-Enrollment-Flag") or 0))
            nflag = int(str(t.get("msPKI-Certificate-Name-Flag") or 0))
            eku   = t.get("pKIExtendedKeyUsage", [])
            if isinstance(eku, str):
                eku = [eku]

            no_sec_ext = bool(eflag & CT_FLAG_NO_SECURITY_EXTENSION)
            # Also vulnerable if enrollee supplies subject (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 1)
            enrollee_supplies = bool(nflag & 1)
            has_client_auth   = any(o in str(eku) for o in CLIENT_AUTH_OIDS)

            if no_sec_ext and has_client_auth:
                attack_path = (
                    "Requires GenericWrite on any user account OR attacker-created machine account.\n"
                    "With GenericWrite: change target's userPrincipalName to impersonated user's UPN, "
                    "request cert, revert UPN, auth as victim."
                    if not enrollee_supplies
                    else "Enrollee supplies SAN — can directly specify any UPN."
                )
                ev = Evidence(extra={
                    "template":              name,
                    "no_security_extension": True,
                    "enrollee_supplies_san": enrollee_supplies,
                    "has_client_auth_eku":   True,
                    "eku":                   str(eku)[:100],
                    "attack_path":           attack_path,
                })
                self.new_finding(
                    title=f"ADCS ESC9 — No Security Extension on Template '{name}'",
                    severity=Severity.CRITICAL,
                    description=(
                        f"Template '{name}' has CT_FLAG_NO_SECURITY_EXTENSION (0x80000) set. "
                        "Certificates issued from this template will NOT contain "
                        "szOID_NTDS_CA_SECURITY_EXT, forcing the DC to use weak UPN-based "
                        "certificate mapping. Combined with write access to any user's "
                        "userPrincipalName, this enables full account impersonation.\n\n"
                        f"{attack_path}"
                    ),
                    reproduction_steps=[
                        "# Step 1: Modify victim's UPN (requires GenericWrite):",
                        f"Set-ADUser -Identity victim -UserPrincipalName 'admin@{domain}'",
                        f"# Step 2: Request certificate from template '{name}':",
                        f"certipy req -u attacker@{domain} -p 'Pass' -ca <ca-name> -template '{name}'",
                        "# Step 3: Revert UPN, authenticate with cert:",
                        f"Set-ADUser -Identity victim -UserPrincipalName 'victim@{domain}'",
                        f"certipy auth -pfx admin.pfx -dc-ip {dc_ip}",
                    ],
                    remediation=(
                        "Remove CT_FLAG_NO_SECURITY_EXTENSION from template enrollment flags. "
                        "Enable StrongCertificateBindingEnforcement (registry) on all DCs. "
                        "Apply KB5014754 patch. "
                        "Monitor for UPN changes followed by certificate requests (Event 4887)."
                    ),
                    references=[
                        "SpecterOps ESC9 research 2023",
                        "KB5014754",
                        "MITRE T1649",
                        "https://posts.specterops.io/certificates-and-pwnage-and-patches-oh-my-8ae0f4304c1d",
                    ],
                    evidence=ev,
                    cvss_v31_vector=CVSS_ESC9,
                    cvss_v40_vector=CVSS40_ESC9,
                    mitre_attack=["TA0004/T1649"],
                    target=dc_ip,
                )


class TestEsc9Check:
    def test_flag_value(self) -> None:
        assert CT_FLAG_NO_SECURITY_EXTENSION == 0x80000

    def test_cvss(self) -> None:
        assert CVSS_ESC9.startswith("CVSS:3.1")
