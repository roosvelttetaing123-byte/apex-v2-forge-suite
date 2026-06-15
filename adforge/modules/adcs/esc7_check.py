"""ESC7 — CA Manager approval + Officer rights abuse."""
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

class Esc7Check(BaseModule):
    NAME = "esc7_check"
    DESCRIPTION = "ESC7: CA officer/manager rights abuse — manage certificates permission"
    PHASE = 11
    TAGS = ["adcs", "esc7", "acl"]

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
            cas = client.search(
                "(objectClass=pKIEnrollmentService)",
                ["cn", "nTSecurityDescriptor", "dNSHostName"],
                search_base=f"CN=Enrollment Services,CN=Public Key Services,CN=Services,{config_dn}")

            # ESC7: Check if non-admin has ManageCA or ManageCertificates on the CA object
            # ManageCA = right to change CA configuration
            # ManageCertificates = right to approve/deny pending requests
            import struct
            MANAGE_CA = 0x00000001
            MANAGE_CERTS = 0x00000002

            for ca in cas:
                ca_name = str(ca.get("cn", "?"))
                sd = ca.get("nTSecurityDescriptor")
                if not sd or not isinstance(sd, bytes) or len(sd) < 20:
                    continue

                try:
                    offset_dacl = struct.unpack("<I", sd[16:20])[0]
                    if offset_dacl == 0 or offset_dacl >= len(sd):
                        continue
                    acl = sd[offset_dacl:]
                    if len(acl) < 8:
                        continue
                    ace_count = struct.unpack("<H", acl[4:6])[0]
                    pos = 8
                    dangerous = []
                    for _ in range(min(ace_count, 200)):
                        if pos + 8 > len(acl): break
                        ace_type = acl[pos]
                        ace_size = struct.unpack("<H", acl[pos+2:pos+4])[0]
                        if ace_size < 4 or pos + ace_size > len(acl): break
                        if ace_type == 0:
                            mask = struct.unpack("<I", acl[pos+4:pos+8])[0]
                            if mask & (MANAGE_CA | MANAGE_CERTS):
                                rights = []
                                if mask & MANAGE_CA: rights.append("ManageCA")
                                if mask & MANAGE_CERTS: rights.append("ManageCertificates")
                                dangerous.append({"rights": rights})
                        pos += ace_size

                    if dangerous:
                        ev = Evidence(extra={"ca": ca_name, "dangerous_aces": len(dangerous)})
                        self.new_finding(
                            title=f"ESC7 — {ca_name}: ManageCA/ManageCertificates to non-admin",
                            severity=Severity.HIGH,
                            description=(
                                f"CA {ca_name} has {len(dangerous)} ACE(s) granting ManageCA or ManageCertificates.\n"
                                "ManageCA: attacker can enable EDITF_ATTRIBUTESUBJECTALTNAME2 (→ ESC6)\n"
                                "ManageCertificates: attacker can approve pending certificate requests"
                            ),
                            reproduction_steps=[
                                f"certipy find -vulnerable -u user@{domain} -p pass -dc-ip {dc_ip}",
                                f"# ManageCA → enable SAN: certipy ca -ca '{ca_name}' -enable-template SubCA",
                            ],
                            remediation="Restrict ManageCA and ManageCertificates to CA admins only.",
                            references=["CWE-284", "SpecterOps ESC7"],
                            evidence=ev, cvss_v31_vector=CVSS, cvss_v40_vector=CVSS40, target=dc_ip)
                except Exception:
                    pass
        finally:
            client.disconnect()
        return self._make_result(start)

class TestEsc7Check:
    def test_phase(self) -> None: assert Esc7Check.PHASE == 11
