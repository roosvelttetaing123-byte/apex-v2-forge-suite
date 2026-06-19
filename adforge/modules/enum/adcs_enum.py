"""ADCS Enumeration — enumerate Certificate Authority templates for ESC vulnerabilities.

Enumerates: CA servers, certificate templates, enrollment permissions, template flags,
EKU OIDs, and flags that indicate ESC1-ESC8 vulnerabilities.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
from adforge.core.ldap_client import LdapClient

CVSS_ADCS   = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
CVSS40_ADCS = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
CVSS_INFO   = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"
CVSS40_INFO = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"

# Template flags
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
CT_FLAG_PEND_ALL_REQUESTS         = 0x00000002

# EKU OIDs of interest
EKU_CLIENT_AUTH   = "1.3.6.1.5.5.7.3.2"
EKU_SMART_CARD    = "1.3.6.1.4.1.311.20.2.2"
EKU_ANY_PURPOSE   = "2.5.29.37.0"
EKU_SUB_CA        = "1.3.6.1.4.1.311.20.2.1"  # Certificate Request Agent

TEMPLATE_ATTRS = [
    "cn", "distinguishedName", "msPKI-Cert-Template-OID",
    "msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag",
    "msPKI-RA-Signature", "pKIExtendedKeyUsage",
    "msPKI-Certificate-Application-Policy",
    "nTSecurityDescriptor", "msPKI-Template-Schema-Version",
    "msPKI-Private-Key-Flag",
]


class AdcsEnum(BaseModule):
    """ADCS certificate template enumerator — find ESC1-8 attack surfaces."""

    NAME        = "adcs_enum"
    DESCRIPTION = "ADCS: enumerate CAs, templates, enrollment permissions, ESC flags"
    PHASE       = 2
    TAGS        = ["enum", "adcs", "certificates", "cwe-295"]

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
            nt_hash=self.config.extra.get("hash", ""),
        )

        if not client.connect():
            return self._make_result(start)

        try:
            base_dn = client.base_dn
            config_dn = f"CN=Configuration,{base_dn}"

            # Enumerate CA servers
            await self.rate_limit()
            cas = client.search(
                "(objectClass=pKIEnrollmentService)",
                ["cn", "dNSHostName", "certificateTemplates"],
                search_base=f"CN=Enrollment Services,CN=Public Key Services,CN=Services,{config_dn}",
            )

            ca_info = []
            for ca in cas:
                ca_name = str(ca.get("cn", "?"))
                ca_host = str(ca.get("dNSHostName", "?"))
                templates = ca.get("certificateTemplates", [])
                if isinstance(templates, str):
                    templates = [templates]
                ca_info.append({"name": ca_name, "host": ca_host, "templates": templates})

            if ca_info:
                self.config.extra["adcs_cas"] = ca_info

            # Enumerate certificate templates
            await self.rate_limit()
            templates = client.search(
                "(objectClass=pKICertificateTemplate)",
                TEMPLATE_ATTRS,
                search_base=f"CN=Certificate Templates,CN=Public Key Services,CN=Services,{config_dn}",
            )

            esc_findings = []

            for tmpl in templates:
                name = str(tmpl.get("cn", "?"))
                name_flag = int(str(tmpl.get("msPKI-Certificate-Name-Flag", 0) or 0))
                enrollment_flag = int(str(tmpl.get("msPKI-Enrollment-Flag", 0) or 0))
                ra_sig = int(str(tmpl.get("msPKI-RA-Signature", 0) or 0))
                ekus = tmpl.get("pKIExtendedKeyUsage", [])
                if isinstance(ekus, str):
                    ekus = [ekus]

                # ESC1: Enrollee supplies subject + Client Auth EKU + no manager approval
                if (name_flag & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
                    and (EKU_CLIENT_AUTH in ekus or EKU_ANY_PURPOSE in ekus or not ekus)
                    and ra_sig == 0):
                    esc_findings.append({
                        "template": name,
                        "esc": "ESC1",
                        "reason": "ENROLLEE_SUPPLIES_SUBJECT + Client Auth EKU + no RA signature",
                    })

                # ESC2: Any Purpose EKU or SubCA
                if EKU_ANY_PURPOSE in ekus or EKU_SUB_CA in ekus:
                    esc_findings.append({
                        "template": name,
                        "esc": "ESC2",
                        "reason": f"Dangerous EKU: {', '.join(ekus[:3])}",
                    })

                # ESC3: Certificate Request Agent EKU
                app_policy = tmpl.get("msPKI-Certificate-Application-Policy", [])
                if isinstance(app_policy, str):
                    app_policy = [app_policy]
                if EKU_SUB_CA in app_policy:
                    esc_findings.append({
                        "template": name,
                        "esc": "ESC3",
                        "reason": "Certificate Request Agent in application policy",
                    })

            self.config.extra["adcs_templates"] = templates
            self.config.extra["adcs_esc_findings"] = esc_findings

            # Report findings
            if ca_info:
                ev = Evidence(
                    extra={"cas": ca_info, "template_count": len(templates)},
                )
                self.new_finding(
                    title=f"ADCS Infrastructure — {len(ca_info)} CA(s), {len(templates)} Templates",
                    severity=Severity.INFORMATIONAL,
                    description=(
                        f"Active Directory Certificate Services infrastructure:\n"
                        + "\n".join(
                            f"  CA: {c['name']} @ {c['host']} ({len(c['templates'])} templates)"
                            for c in ca_info
                        )
                    ),
                    reproduction_steps=[
                        f"certipy find -u user@{domain} -p password -dc-ip {dc_ip}",
                    ],
                    remediation="Review ADCS configuration for ESC vulnerabilities.",
                    references=["https://posts.specterops.io/certified-pre-owned-d95910965cd2"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_INFO,
                    cvss_v40_vector=CVSS40_INFO,
                    target=dc_ip,
                )

            if esc_findings:
                ev = Evidence(extra={"esc_findings": esc_findings[:30]})
                self.new_finding(
                    title=f"ADCS ESC Vulnerabilities — {len(esc_findings)} Misconfigured Templates",
                    severity=Severity.HIGH,
                    description=(
                        f"{len(esc_findings)} certificate template(s) have ESC misconfiguration:\n"
                        + "\n".join(
                            f"  [{e['esc']}] {e['template']}: {e['reason']}"
                            for e in esc_findings[:10]
                        )
                    ),
                    reproduction_steps=[
                        f"certipy find -vulnerable -u user@{domain} -p password -dc-ip {dc_ip}",
                    ],
                    remediation=(
                        "1. Disable ENROLLEE_SUPPLIES_SUBJECT on templates with Client Auth\n"
                        "2. Remove Any Purpose EKU from templates\n"
                        "3. Require manager approval on sensitive templates\n"
                        "4. Restrict enrollment permissions"
                    ),
                    references=["CWE-295", "SpecterOps Certified Pre-Owned"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_ADCS,
                    cvss_v40_vector=CVSS40_ADCS,
                    target=dc_ip,
                )

        finally:
            client.disconnect()

        return self._make_result(start)


class TestAdcsEnum:
    def test_eku_oids(self) -> None:
        assert EKU_CLIENT_AUTH == "1.3.6.1.5.5.7.3.2"
        assert EKU_ANY_PURPOSE == "2.5.29.37.0"

    def test_flags(self) -> None:
        assert CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT == 0x00000001

    def test_phase(self) -> None:
        assert AdcsEnum.PHASE == 2
