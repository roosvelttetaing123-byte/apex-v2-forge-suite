"""Trust Enumeration — domain/forest trusts, trust directions, SID filtering."""
from __future__ import annotations
import sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
from adforge.core.ldap_client import LdapClient

CVSS_TRUST = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
CVSS40_TRUST = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
CVSS_INFO = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"
CVSS40_INFO = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"

TRUST_DIRECTION = {0: "Disabled", 1: "Inbound", 2: "Outbound", 3: "Bidirectional"}
TRUST_TYPE = {1: "Windows NT", 2: "Active Directory", 3: "MIT Kerberos"}
TRUST_ATTRS = [
    "cn", "trustPartner", "trustDirection", "trustType",
    "trustAttributes", "flatName", "distinguishedName",
]

# trustAttributes flags
TRUST_ATTRIB_NON_TRANSITIVE = 0x01
TRUST_ATTRIB_FILTER_SIDS    = 0x04
TRUST_ATTRIB_FOREST          = 0x08
TRUST_ATTRIB_WITHIN_FOREST   = 0x20


class TrustEnum(BaseModule):
    NAME = "trust_enum"
    DESCRIPTION = "Enumerate domain/forest trusts, directions, SID filtering status"
    PHASE = 2
    TAGS = ["enum", "trusts", "ldap", "mitre-T1482"]

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
            trusts = client.search("(objectClass=trustedDomain)", TRUST_ATTRS)
            self.log.info("Found %d trust(s)", len(trusts))

            trust_data = []
            sid_filter_missing = []

            for trust in trusts:
                partner = str(trust.get("trustPartner", "?"))
                direction = int(str(trust.get("trustDirection", 0) or 0))
                ttype = int(str(trust.get("trustType", 0) or 0))
                attribs = int(str(trust.get("trustAttributes", 0) or 0))

                sid_filtering = bool(attribs & TRUST_ATTRIB_FILTER_SIDS)
                is_forest = bool(attribs & TRUST_ATTRIB_FOREST)
                transitive = not bool(attribs & TRUST_ATTRIB_NON_TRANSITIVE)

                info = {
                    "partner": partner,
                    "direction": TRUST_DIRECTION.get(direction, f"Unknown({direction})"),
                    "type": TRUST_TYPE.get(ttype, f"Unknown({ttype})"),
                    "sid_filtering": sid_filtering,
                    "forest_trust": is_forest,
                    "transitive": transitive,
                }
                trust_data.append(info)

                # Flag trusts without SID filtering (allows SID history attacks)
                if not sid_filtering and direction in (1, 3):  # Inbound or Bidirectional
                    sid_filter_missing.append(info)

            if trust_data:
                ev = Evidence(extra={"trusts": trust_data})
                self.new_finding(
                    title=f"Domain Trusts — {len(trust_data)} trust(s)",
                    severity=Severity.INFORMATIONAL,
                    description=(
                        f"Domain trust relationships:\n"
                        + "\n".join(
                            f"  {t['partner']}: {t['direction']} ({t['type']})"
                            + (" [FOREST]" if t['forest_trust'] else "")
                            + (" [NO SID FILTER]" if not t['sid_filtering'] else "")
                            for t in trust_data
                        )
                    ),
                    reproduction_steps=[
                        "Get-ADTrust -Filter * | Select Name,Direction,TrustType,SIDFilteringForestAware",
                        f"nltest /domain_trusts /all_trusts /v",
                    ],
                    remediation="Review trust relationships. Enable SID filtering on all external trusts.",
                    references=["MITRE T1482"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_INFO, cvss_v40_vector=CVSS40_INFO,
                    mitre_attack=["TA0007/T1482"],
                    target=dc_ip,
                )

            if sid_filter_missing:
                ev = Evidence(extra={"trusts_no_sid_filter": sid_filter_missing})
                self.new_finding(
                    title=f"SID Filtering Disabled — {len(sid_filter_missing)} trust(s) vulnerable to SID History",
                    severity=Severity.HIGH,
                    description=(
                        f"{len(sid_filter_missing)} trust(s) lack SID filtering:\n"
                        + "\n".join(f"  {t['partner']} ({t['direction']})" for t in sid_filter_missing)
                        + "\n\nWithout SID filtering, an attacker in the trusted domain can "
                        "inject SID History to impersonate any user in this domain (Golden Ticket + SID History)."
                    ),
                    reproduction_steps=[
                        "# Exploit: mimikatz kerberos::golden /sid:S-trusted /sids:S-target-enterprise-admins",
                    ],
                    remediation="Enable SID filtering: netdom trust /quarantine:yes",
                    references=["MITRE T1134.005", "CWE-284"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_TRUST, cvss_v40_vector=CVSS40_TRUST,
                    target=dc_ip,
                )

            self.config.extra["domain_trusts"] = trust_data
        finally:
            client.disconnect()
        return self._make_result(start)

class TestTrustEnum:
    def test_direction_map(self) -> None:
        assert TRUST_DIRECTION[3] == "Bidirectional"
    def test_phase(self) -> None:
        assert TrustEnum.PHASE == 2
