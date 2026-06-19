"""ADCS ESC1 check — misconfigured certificate templates allowing privilege escalation."""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
from adforge.core.ldap_client import LdapClient

CVSS_ESC1 = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"
CVSS40_ESC1 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
# OID for Client Authentication EKU
CLIENT_AUTH_OID = "1.3.6.1.5.5.7.3.2"
SMART_CARD_AUTH_OID = "1.3.6.1.4.1.311.20.2.2"
ANY_PURPOSE_OID = "2.5.29.37.0"


class Esc1Check(BaseModule):
    """ADCS ESC1 — misconfigured certificate templates."""

    NAME        = "esc1_check"
    DESCRIPTION = "Check ADCS for ESC1: templates allowing enrollees to specify SAN"
    PHASE       = 11
    TAGS        = ["adcs", "esc1", "certificate", "privilege-escalation", "mitre-T1649"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
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

    async def _check_templates(
        self, client: LdapClient, domain: str, dc_ip: str
    ) -> None:
        """Search ADCS certificate templates for ESC1 conditions."""
        dc_parts = ",".join(f"DC={p}" for p in domain.split("."))
        config_nc = f"CN=Configuration,{dc_parts}"
        templates_dn = f"CN=Certificate Templates,CN=Public Key Services,CN=Services,{config_nc}"

        templates = client.search(
            "(objectClass=pKICertificateTemplate)",
            [
                "cn", "displayName", "msPKI-Certificate-Name-Flag",
                "msPKI-Enrollment-Flag", "pKIExtendedKeyUsage",
                "nTSecurityDescriptor", "msPKI-RA-Signature",
                "msPKI-Private-Key-Flag",
            ],
            base_dn=templates_dn,
        )

        self.log.info("Found %d certificate templates", len(templates))

        for template in templates:
            await self._analyze_template(template, domain, dc_ip)

    async def _analyze_template(
        self, template: dict, domain: str, dc_ip: str
    ) -> None:
        name = template.get("cn", template.get("displayName", "Unknown"))

        # CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 1
        name_flag = int(str(template.get("msPKI-Certificate-Name-Flag", 0) or 0))
        enrollee_supplies_subject = bool(name_flag & 1)

        # Check EKU for Client Auth
        eku = template.get("pKIExtendedKeyUsage", [])
        if isinstance(eku, str):
            eku = [eku]
        has_client_auth = any(
            oid in str(eku) for oid in [CLIENT_AUTH_OID, SMART_CARD_AUTH_OID, ANY_PURPOSE_OID]
        )

        # CT_FLAG_PEND_ALL_REQUESTS = 2 (manager approval)
        enroll_flag = int(str(template.get("msPKI-Enrollment-Flag", 0) or 0))
        requires_approval = bool(enroll_flag & 2)

        # RA signature required
        ra_sig = int(str(template.get("msPKI-RA-Signature", 0) or 0))

        if (enrollee_supplies_subject and has_client_auth and
                not requires_approval and ra_sig == 0):
            ev = Evidence(
                extra={
                    "template_name":          name,
                    "enrollee_supplies_san":  True,
                    "has_client_auth_eku":    True,
                    "requires_approval":      requires_approval,
                    "ra_signature_required":  ra_sig,
                    "eku":                    str(eku)[:100],
                }
            )
            self.new_finding(
                title=f"ADCS ESC1 — Misconfigured Template '{name}'",
                severity=Severity.CRITICAL,
                description=(
                    f"Certificate template '{name}' is vulnerable to ESC1 (ADCS privilege escalation). "
                    "Any enrolled user can request a certificate with an arbitrary SAN (Subject Alternative Name), "
                    "including Domain Admin UPN, allowing impersonation and domain compromise.\n\n"
                    "Conditions met:\n"
                    "✓ Enrollee can supply SAN (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)\n"
                    "✓ Client Authentication EKU present\n"
                    "✓ No manager approval required\n"
                    "✓ No RA signature required"
                ),
                reproduction_steps=[
                    f"# Request cert with DA SAN:",
                    f"certipy req -u lowpriv@{domain} -p 'Password' -ca <ca-name> -template '{name}'",
                    f"  -upn administrator@{domain} -dc-ip {dc_ip}",
                    "certipy auth -pfx administrator.pfx -dc-ip {dc_ip}",
                ],
                remediation=(
                    f"For template '{name}':\n"
                    "1. Uncheck 'Supply in request' in Subject Name tab\n"
                    "2. Enable Manager Approval (CT_FLAG_PEND_ALL_REQUESTS)\n"
                    "3. Add RA signature requirement\n"
                    "4. Remove Client Authentication EKU if not needed"
                ),
                references=[
                    "SpecterOps ADCS Attack Research",
                    "MITRE T1649",
                    "https://posts.specterops.io/certified-pre-owned-d95910965cd2",
                ],
                evidence=ev,
                cvss_v31_vector=CVSS_ESC1,
                cvss_v40_vector=CVSS40_ESC1,
                mitre_attack=["TA0004/T1649"],
                target=dc_ip,
            )


class TestEsc1Check:
    def test_client_auth_oid(self) -> None:
        assert CLIENT_AUTH_OID == "1.3.6.1.5.5.7.3.2"

    def test_cvss_vector(self) -> None:
        assert CVSS_ESC1.startswith("CVSS:3.1")
