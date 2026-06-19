"""ESC2 Check — Any Purpose EKU or SubCA certificate template misconfiguration."""
from __future__ import annotations
import sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
from adforge.core.ldap_client import LdapClient

CVSS_ESC2 = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
CVSS40_ESC2 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
EKU_ANY_PURPOSE = "2.5.29.37.0"
EKU_SUB_CA = "1.3.6.1.4.1.311.20.2.1"

class Esc2Check(BaseModule):
    NAME = "esc2_check"
    DESCRIPTION = "ESC2: Any Purpose EKU or SubCA — allows certificate misuse"
    PHASE = 11
    TAGS = ["adcs", "esc2", "certificates", "cwe-295"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        dc_ip = self.config.extra.get("dc", self.config.target)
        domain = self.config.extra.get("domain", "")
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
            config_dn = f"CN=Configuration,{client.base_dn}"
            await self.rate_limit()
            templates = client.search(
                "(objectClass=pKICertificateTemplate)",
                ["cn", "pKIExtendedKeyUsage", "msPKI-Certificate-Application-Policy",
                 "msPKI-RA-Signature", "msPKI-Enrollment-Flag"],
                search_base=f"CN=Certificate Templates,CN=Public Key Services,CN=Services,{config_dn}",
            )

            vulnerable = []
            for tmpl in templates:
                name = str(tmpl.get("cn", "?"))
                ekus = tmpl.get("pKIExtendedKeyUsage", [])
                if isinstance(ekus, str):
                    ekus = [ekus]

                if EKU_ANY_PURPOSE in ekus or EKU_SUB_CA in ekus:
                    reason = "Any Purpose EKU" if EKU_ANY_PURPOSE in ekus else "SubCA EKU"
                    vulnerable.append({"template": name, "reason": reason, "ekus": ekus[:5]})

            if vulnerable:
                ev = Evidence(extra={"vulnerable": vulnerable})
                self.new_finding(
                    title=f"ESC2 — {len(vulnerable)} templates with Any Purpose/SubCA EKU",
                    severity=Severity.HIGH,
                    description=(
                        f"Templates vulnerable to ESC2:\n"
                        + "\n".join(f"  {v['template']}: {v['reason']}" for v in vulnerable[:10])
                        + "\n\nAny Purpose EKU allows the certificate to be used for ANY purpose "
                        "(client auth, server auth, code signing, etc.)."
                    ),
                    reproduction_steps=[
                        f"certipy find -vulnerable -u user@{domain} -p pass -dc-ip {dc_ip}",
                        f"certipy req -u user@{domain} -p pass -target {dc_ip} "
                        f"-template {vulnerable[0]['template']} -ca <CA>",
                    ],
                    remediation="Remove Any Purpose and SubCA EKUs. Set specific EKUs per template.",
                    references=["CWE-295", "SpecterOps ESC2"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_ESC2, cvss_v40_vector=CVSS40_ESC2,
                    target=dc_ip,
                )
        finally:
            client.disconnect()
        return self._make_result(start)

class TestEsc2Check:
    def test_ekus(self) -> None:
        assert EKU_ANY_PURPOSE == "2.5.29.37.0"
    def test_phase(self) -> None:
        assert Esc2Check.PHASE == 11
