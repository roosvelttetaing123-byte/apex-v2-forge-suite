"""ESC4 — Vulnerable certificate template ACLs (write permissions)."""
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

class Esc4Check(BaseModule):
    NAME = "esc4_check"
    DESCRIPTION = "ESC4: Vulnerable template ACLs — low-priv users can modify templates"
    PHASE = 11
    TAGS = ["adcs", "esc4", "acl"]

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
                ["cn", "nTSecurityDescriptor", "distinguishedName"],
                search_base=f"CN=Certificate Templates,CN=Public Key Services,CN=Services,{config_dn}")

            # Check which templates have write permissions for low-privilege principals
            # This requires SD parsing similar to acl_enum
            esc_templates = self.config.extra.get("adcs_esc_findings", [])
            esc4_templates = [e for e in esc_templates if e.get("esc") == "ESC4"]

            # If not already found by adcs_enum, check template SDs
            if not esc4_templates:
                import struct
                WRITE_PROPERTY = 0x00000020
                GENERIC_ALL = 0x10000000
                GENERIC_WRITE = 0x40000000
                WRITE_DACL = 0x00040000

                for tmpl in templates:
                    name = str(tmpl.get("cn", "?"))
                    sd = tmpl.get("nTSecurityDescriptor")
                    if not sd or not isinstance(sd, bytes) or len(sd) < 20:
                        continue
                    # Check for non-admin write access in the DACL
                    try:
                        offset_dacl = struct.unpack("<I", sd[16:20])[0]
                        if offset_dacl == 0 or offset_dacl >= len(sd):
                            continue
                        acl = sd[offset_dacl:]
                        if len(acl) < 8:
                            continue
                        ace_count = struct.unpack("<H", acl[4:6])[0]
                        pos = 8
                        for _ in range(min(ace_count, 200)):
                            if pos + 8 > len(acl): break
                            ace_type = acl[pos]
                            ace_size = struct.unpack("<H", acl[pos+2:pos+4])[0]
                            if ace_size < 4 or pos + ace_size > len(acl): break
                            if ace_type == 0:  # ACCESS_ALLOWED
                                mask = struct.unpack("<I", acl[pos+4:pos+8])[0]
                                if mask & (WRITE_PROPERTY | GENERIC_ALL | GENERIC_WRITE | WRITE_DACL):
                                    # Check SID is not a well-known admin SID
                                    sid_data = acl[pos+8:pos+ace_size]
                                    if len(sid_data) >= 8:
                                        sub_auth_count = sid_data[1]
                                        if sub_auth_count >= 2:
                                            last_sub = struct.unpack("<I", sid_data[8+(sub_auth_count-1)*4:12+(sub_auth_count-1)*4])[0] if 12+(sub_auth_count-1)*4 <= len(sid_data) else 0
                                            # Not SYSTEM/Admins/Enterprise Admins
                                            if last_sub not in (18, 544, 512, 519):
                                                esc4_templates.append({"template": name, "esc": "ESC4"})
                                                break
                            pos += ace_size
                    except Exception:
                        pass

            if esc4_templates:
                ev = Evidence(extra={"esc4_templates": esc4_templates[:20]})
                self.new_finding(
                    title=f"ESC4 — {len(esc4_templates)} templates with writable ACLs",
                    severity=Severity.HIGH,
                    description=(
                        f"Templates with write access for non-admin principals:\n"
                        + "\n".join(f"  {t['template']}" for t in esc4_templates[:10])
                        + "\n\nAn attacker can modify the template to enable ENROLLEE_SUPPLIES_SUBJECT, "
                        "add Client Auth EKU, and then request a certificate as any user (ESC1 via ESC4)."
                    ),
                    reproduction_steps=[
                        f"certipy find -vulnerable -u user@{domain} -p pass -dc-ip {dc_ip}",
                        "# Modify template then exploit as ESC1",
                    ],
                    remediation="Restrict template ACLs. Only CA admins should have write access.",
                    references=["CWE-284", "SpecterOps ESC4"],
                    evidence=ev, cvss_v31_vector=CVSS, cvss_v40_vector=CVSS40, target=dc_ip)
        finally:
            client.disconnect()
        return self._make_result(start)

class TestEsc4Check:
    def test_phase(self) -> None: assert Esc4Check.PHASE == 11
