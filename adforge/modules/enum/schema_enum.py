"""Schema Enumeration — AD schema version, custom attributes, extensions."""
from __future__ import annotations
import sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
from adforge.core.ldap_client import LdapClient

CVSS_INFO = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"
CVSS40_INFO = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"

# Schema versions to Windows Server mapping
SCHEMA_VERSIONS = {
    87: "Windows Server 2022+", 88: "Windows Server 2022 22H2",
    69: "Windows Server 2012 R2", 56: "Windows Server 2012",
    47: "Windows Server 2008 R2", 44: "Windows Server 2008",
    31: "Windows Server 2003 R2", 30: "Windows Server 2003",
}

class SchemaEnum(BaseModule):
    NAME = "schema_enum"
    DESCRIPTION = "Enumerate AD schema version, functional levels, custom attributes"
    PHASE = 2
    TAGS = ["enum", "schema", "ldap"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        domain = self.config.extra.get("domain", "")
        dc_ip = self.config.extra.get("dc", self.config.target)
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
            await self.rate_limit()
            # Query RootDSE for functional levels
            rootdse = client.search(
                "(objectClass=*)",
                ["domainFunctionality", "forestFunctionality", "domainControllerFunctionality",
                 "rootDomainNamingContext", "configurationNamingContext", "schemaNamingContext"],
                search_base="",
                search_scope="BASE",
            )

            domain_level = "?"
            forest_level = "?"
            schema_version = 0

            if rootdse:
                r = rootdse[0]
                domain_level = str(r.get("domainFunctionality", "?"))
                forest_level = str(r.get("forestFunctionality", "?"))

            # Get schema version
            await self.rate_limit()
            schema_dn = f"CN=Schema,CN=Configuration,{client.base_dn}"
            schema_results = client.search(
                "(objectClass=dMD)",
                ["objectVersion", "whenChanged"],
                search_base=schema_dn,
            )

            if schema_results:
                schema_version = int(str(schema_results[0].get("objectVersion", 0) or 0))

            os_version = SCHEMA_VERSIONS.get(schema_version, f"Unknown (schema v{schema_version})")

            ev = Evidence(
                extra={
                    "domain_functional_level": domain_level,
                    "forest_functional_level": forest_level,
                    "schema_version": schema_version,
                    "os_version": os_version,
                },
            )
            self.new_finding(
                title=f"AD Schema — v{schema_version} ({os_version})",
                severity=Severity.INFORMATIONAL,
                description=(
                    f"Active Directory schema and functional levels:\n"
                    f"  Schema version: {schema_version} ({os_version})\n"
                    f"  Domain functional level: {domain_level}\n"
                    f"  Forest functional level: {forest_level}"
                ),
                reproduction_steps=[
                    "Get-ADRootDSE | Select domainFunctionality,forestFunctionality",
                    f"Get-ADObject 'CN=Schema,CN=Configuration,{client.base_dn}' -Properties objectVersion",
                ],
                remediation="Ensure forest/domain functional levels are current.",
                references=["CWE-693"],
                evidence=ev,
                cvss_v31_vector=CVSS_INFO, cvss_v40_vector=CVSS40_INFO,
                target=dc_ip,
            )

            self.config.extra["schema_version"] = schema_version
            self.config.extra["domain_functional_level"] = domain_level
        finally:
            client.disconnect()
        return self._make_result(start)

class TestSchemaEnum:
    def test_versions(self) -> None:
        assert 87 in SCHEMA_VERSIONS
    def test_phase(self) -> None:
        assert SchemaEnum.PHASE == 2
