"""ADCS ESC13 — OID group link grants group membership via certificate enrollment."""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
from adforge.core.ldap_client import LdapClient

CVSS_ESC13 = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"
CVSS40_ESC13 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
class Esc13Check(BaseModule):
    """ADCS ESC13 — OID group link: enrolling in a template grants group membership."""

    NAME        = "esc13_check"
    DESCRIPTION = "Check ADCS for ESC13: msPKI-Certificate-Policy OID linked to privileged group"
    PHASE       = 11
    TAGS        = ["adcs", "esc13", "certificate", "privilege-escalation", "mitre-T1649"]

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
            await self._check_oid_links(client, domain, dc_ip)
        finally:
            client.disconnect()

        return self._make_result(start)

    async def _check_oid_links(self, client: LdapClient, domain: str, dc_ip: str) -> None:
        dc_parts    = ",".join(f"DC={p}" for p in domain.split("."))
        config_nc   = f"CN=Configuration,{dc_parts}"
        templates_dn = f"CN=Certificate Templates,CN=Public Key Services,CN=Services,{config_nc}"
        oid_dn      = f"CN=OID,CN=Public Key Services,CN=Services,{config_nc}"

        # Find templates with certificate policies
        templates = client.search(
            "(&(objectClass=pKICertificateTemplate)(msPKI-Certificate-Policy=*))",
            ["cn", "msPKI-Certificate-Policy", "msPKI-Enrollment-Flag",
             "pKIExtendedKeyUsage", "nTSecurityDescriptor"],
            base_dn=templates_dn,
        )

        if not templates:
            self.log.info("No templates with msPKI-Certificate-Policy found")
            return

        # Find OID objects with group links
        oid_objects = client.search(
            "(msDS-OIDToGroupLink=*)",
            ["cn", "msPKI-Cert-Template-OID", "msDS-OIDToGroupLink", "displayName"],
            base_dn=oid_dn,
        )

        # Build OID → group mapping
        oid_group_map: dict[str, str] = {}
        for oid_obj in oid_objects:
            oid_val   = str(oid_obj.get("msPKI-Cert-Template-OID") or "")
            group_dn  = str(oid_obj.get("msDS-OIDToGroupLink") or "")
            if oid_val and group_dn:
                oid_group_map[oid_val] = group_dn

        self.log.info("Found %d OID-to-group links", len(oid_group_map))

        for t in templates:
            name     = t.get("cn", "Unknown")
            policies = t.get("msPKI-Certificate-Policy", [])
            if isinstance(policies, str):
                policies = [policies]

            for policy_oid in policies:
                policy_oid_str = str(policy_oid)
                if policy_oid_str in oid_group_map:
                    linked_group = oid_group_map[policy_oid_str]
                    # Determine if the linked group is privileged
                    priv_keywords = {
                        "domain admin", "enterprise admin", "schema admin",
                        "account operator", "backup operator", "administrator",
                    }
                    is_priv = any(kw in linked_group.lower() for kw in priv_keywords)

                    ev = Evidence(extra={
                        "template":     name,
                        "policy_oid":   policy_oid_str,
                        "linked_group": linked_group,
                        "is_privileged": is_priv,
                    })
                    self.new_finding(
                        title=f"ADCS ESC13 — Template '{name}' OID Linked to Group",
                        severity=Severity.CRITICAL if is_priv else Severity.HIGH,
                        description=(
                            f"Template '{name}' has msPKI-Certificate-Policy OID '{policy_oid_str}' "
                            f"linked (via msDS-OIDToGroupLink) to AD group: '{linked_group}'.\n\n"
                            "Any principal who can enroll in this template will automatically "
                            "receive group membership in the linked group when the certificate "
                            "is used for Kerberos authentication. This is a direct privilege "
                            "escalation if the linked group is privileged."
                        ),
                        reproduction_steps=[
                            f"# Enroll in template '{name}' (as any permitted user):",
                            f"certipy req -u lowpriv@{domain} -p 'Pass' -ca <ca-name> "
                            f"-template '{name}'",
                            f"# Authenticate — Kerberos will include group membership:",
                            f"certipy auth -pfx lowpriv.pfx -dc-ip {dc_ip}",
                            "# Verify group membership in TGT PAC",
                        ],
                        remediation=(
                            "Remove the msDS-OIDToGroupLink from the OID object, OR "
                            "restrict enrollment on the template to only users who should "
                            "have the linked group membership. "
                            "Review all OID objects: "
                            f"Get-ADObject -Filter * -SearchBase '{oid_dn}' "
                            "-Properties msDS-OIDToGroupLink"
                        ),
                        references=[
                            "SpecterOps ESC13 research 2024",
                            "MITRE T1649",
                        ],
                        evidence=ev,
                        cvss_v31_vector=CVSS_ESC13,
                        cvss_v40_vector=CVSS40_ESC13,
                        mitre_attack=["TA0004/T1649"],
                        target=dc_ip,
                    )


class TestEsc13Check:
    def test_cvss(self) -> None:
        assert CVSS_ESC13.startswith("CVSS:3.1")

    def test_priv_keywords(self) -> None:
        keywords = {"domain admin", "enterprise admin"}
        assert all(kw in {"domain admin", "enterprise admin", "schema admin",
                          "account operator", "backup operator", "administrator"}
                   for kw in keywords)
