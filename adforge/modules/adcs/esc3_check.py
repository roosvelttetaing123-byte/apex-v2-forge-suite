"""ESC3 — Certificate Request Agent EKU abuse."""
from __future__ import annotations
import sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
from adforge.core.ldap_client import LdapClient

CVSS = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
CVSS40 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
EKU_CERT_REQUEST_AGENT = "1.3.6.1.4.1.311.20.2.1"

class Esc3Check(BaseModule):
    NAME = "esc3_check"
    DESCRIPTION = "ESC3: Certificate Request Agent allows enrollment on behalf of others"
    PHASE = 11
    TAGS = ["adcs", "esc3", "certificates"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        dc_ip = self.config.extra.get("dc", self.config.target)
        domain = self.config.extra.get("domain", "")
        if not self.check_scope(dc_ip):
            return self._make_result(start, skipped=True, skip_reason="out of scope")
        client = LdapClient(dc_ip=dc_ip, domain=domain, username=self.config.extra.get("username", ""), password=self.config.extra.get("password", ""), nt_hash=self.config.extra.get("hash", ""))
        if not client.connect(): return self._make_result(start)
        try:
            config_dn = f"CN=Configuration,{client.base_dn}"
            await self.rate_limit()
            templates = client.search("(objectClass=pKICertificateTemplate)",
                ["cn", "pKIExtendedKeyUsage", "msPKI-Certificate-Application-Policy", "msPKI-RA-Signature"],
                search_base=f"CN=Certificate Templates,CN=Public Key Services,CN=Services,{config_dn}")
            vulnerable = []
            for tmpl in templates:
                name = str(tmpl.get("cn", "?"))
                ekus = tmpl.get("pKIExtendedKeyUsage", [])
                app_policy = tmpl.get("msPKI-Certificate-Application-Policy", [])
                if isinstance(ekus, str): ekus = [ekus]
                if isinstance(app_policy, str): app_policy = [app_policy]
                ra_sig = int(str(tmpl.get("msPKI-RA-Signature", 0) or 0))
                if EKU_CERT_REQUEST_AGENT in ekus or EKU_CERT_REQUEST_AGENT in app_policy:
                    vulnerable.append({"template": name, "ra_signature_required": ra_sig})
            if vulnerable:
                ev = Evidence(extra={"vulnerable": vulnerable})
                self.new_finding(
                    title=f"ESC3 — {len(vulnerable)} templates with Certificate Request Agent",
                    severity=Severity.HIGH,
                    description=(
                        f"Templates with Certificate Request Agent EKU:\n"
                        + "\n".join(f"  {v['template']} (RA sig: {v['ra_signature_required']})" for v in vulnerable[:10])
                        + "\n\nAn attacker can enroll for a Certificate Request Agent certificate, "
                        "then use it to request certificates on behalf of ANY user (including Domain Admin)."
                    ),
                    reproduction_steps=[
                        f"certipy req -u user@{domain} -p pass -target {dc_ip} -template {vulnerable[0]['template']}",
                        f"certipy req -u user@{domain} -p pass -target {dc_ip} -template User -on-behalf-of admin",
                    ],
                    remediation="Remove Enrollment Agent EKU. Restrict enrollment agent permissions via CA configuration.",
                    references=["CWE-295", "SpecterOps ESC3"],
                    evidence=ev, cvss_v31_vector=CVSS, cvss_v40_vector=CVSS40, target=dc_ip)
        finally:
            client.disconnect()
        return self._make_result(start)

class TestEsc3Check:
    def test_phase(self) -> None: assert Esc3Check.PHASE == 11
