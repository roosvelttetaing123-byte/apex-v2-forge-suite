"""LDAP Anon module."""
from __future__ import annotations
import sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_LDAP_V31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
CVSS_LDAP_V40 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"

class LdapAnon(BaseModule):
    NAME = "ldap_anon"
    DESCRIPTION = "Check for LDAP anonymous bind and rootDSE read"
    PHASE = 1
    TAGS = ["unauth", "ldap"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target
        if not self.check_scope(target): return self._make_result(start, skipped=True)

        try:
            import ldap3
            server = ldap3.Server(target, get_info=ldap3.ALL)
            conn = ldap3.Connection(server, auto_bind=True, receive_timeout=5)
            
            # Auto bind anonymous
            if conn.bound:
                ev = Evidence(
                    request_raw="Anonymous bind to LDAP",
                    response_raw=str(server.info) if server.info else "Bound successfully, no info",
                )
                
                # Check what we can actually read
                conn.search('', '(objectclass=*)', ldap3.BASE, attributes=['*'])
                can_read_base = len(conn.entries) > 0
                
                self.new_finding(
                    title="LDAP Anonymous Bind Allowed",
                    severity=Severity.MEDIUM if can_read_base else Severity.LOW,
                    description=f"The LDAP service allows anonymous binding. Can read base objects: {can_read_base}.",
                    reproduction_steps=[f"ldapsearch -x -h {target} -s base -b ''"],
                    remediation="Disable anonymous LDAP binding.",
                    references=["CWE-284"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_LDAP_V31, cvss_v40_vector=CVSS_LDAP_V40, target=target
                )
            conn.unbind()
        except Exception as e:
            self.log.debug("LDAP anon failed: %s", e)

        return self._make_result(start)

class TestLdapAnon:
    def test_phase(self): assert LdapAnon.PHASE == 1
