"""Domain enumeration — collect domain-wide information via LDAP.

Enumerates: domain functional level, password policy, account lockout policy,
domain trusts, privileged groups membership, ms-DS-MachineAccountQuota.
"""
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

CVSS_INFO   = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"
CVSS40_INFO = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
CVSS_MEDIUM = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
CVSS40_MEDIUM = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
CVSS_HIGH   = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
CVSS40_HIGH = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
# Domain functional levels (msDS-Behavior-Version)
DOMAIN_FUNCTIONAL_LEVELS = {
    0: "Windows 2000 Native",
    1: "Windows Server 2003 Interim",
    2: "Windows Server 2003",
    3: "Windows Server 2008",
    4: "Windows Server 2008 R2",
    5: "Windows Server 2012",
    6: "Windows Server 2012 R2",
    7: "Windows Server 2016/2019/2022",
}

# Groups that grant very high privileges in AD
PRIVILEGED_GROUPS = [
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Backup Operators",
    "Account Operators",
    "Server Operators",
    "Print Operators",
    "DNSAdmins",
    "Group Policy Creator Owners",
]


class DomainEnum(BaseModule):
    """Active Directory domain information enumerator."""

    NAME        = "domain_enum"
    DESCRIPTION = (
        "Enumerate domain: functional level, password policy, trusts, "
        "privileged groups, and MachineAccountQuota"
    )
    PHASE       = 2
    TAGS        = ["enum", "ldap", "domain", "active-directory", "mitre-T1087.002"]

    async def run(self) -> ModuleResult:
        start  = time.monotonic()
        domain = self.config.extra.get("domain", "")
        dc_ip  = self.config.extra.get("dc", self.config.target)

        if not self.check_scope(dc_ip):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        client = LdapClient(
            dc_ip=dc_ip,
            domain=domain,
            username=self.config.extra.get("username", ""),
            password=self.config.extra.get("password", ""),
            nt_hash=self.config.extra.get("hash", ""),
        )

        if not client.connect():
            self.log.warning("LDAP connection failed to %s", dc_ip)
            return self._make_result(start)

        try:
            await self.rate_limit()
            await self._enum_domain_info(client, domain, dc_ip)

            await self.rate_limit()
            await self._enum_domain_trusts(client, domain, dc_ip)

            await self.rate_limit()
            await self._enum_privileged_groups(client, domain, dc_ip)

        finally:
            client.disconnect()

        return self._make_result(start)

    async def _enum_domain_info(
        self, client: LdapClient, domain: str, dc_ip: str
    ) -> None:
        """Enumerate base domain object attributes."""
        dc_parts = ",".join(f"DC={p}" for p in domain.split("."))

        entries = client.search(
            "(objectClass=domain)",
            [
                "name", "dc", "distinguishedName",
                "lockoutThreshold", "lockoutObservationWindow", "lockoutDuration",
                "minPwdLength", "pwdHistoryLength", "maxPwdAge", "minPwdAge",
                "pwdProperties",  # complexity flag (bit 1 = complexity enabled)
                "ms-DS-MachineAccountQuota",
                "msDS-Behavior-Version",  # domain functional level
                "objectSid",
            ],
            base_dn=dc_parts,
            search_scope="BASE",
        )

        if not entries:
            # Fall back to standard get_domain_info
            entries = [client.get_domain_info()]

        info = entries[0] if entries else {}
        self.config.extra["domain_info"] = info
        self.log.info("Domain info retrieved: %s", {k: v for k, v in info.items() if k != "objectSid"})

        threshold      = int(str(info.get("lockoutThreshold", 0) or 0))
        min_pwd        = int(str(info.get("minPwdLength", 0) or 0))
        quota          = int(str(info.get("ms-DS-MachineAccountQuota", 0) or 0))
        pwd_complexity = int(str(info.get("pwdProperties", 0) or 0))
        func_level_raw = int(str(info.get("msDS-Behavior-Version", 7) or 7))
        func_level_str = DOMAIN_FUNCTIONAL_LEVELS.get(func_level_raw, f"Unknown (level {func_level_raw})")
        complexity_enabled = bool(pwd_complexity & 1)

        # Publish for spray module
        self.config.extra["lockout_threshold"]  = threshold
        self.config.extra["domain_func_level"]  = func_level_raw

        self.log.info(
            "Domain: %s | Functional Level: %s | Lockout: %d | MinPwdLen: %d | Complexity: %s | MAQ: %d",
            domain, func_level_str, threshold, min_pwd, complexity_enabled, quota,
        )

        # ── No account lockout policy ─────────────────────────────────────────
        if threshold == 0:
            self.new_finding(
                title="No Account Lockout Policy — Brute-Force/Spray Unrestricted",
                severity=Severity.HIGH,
                description=(
                    f"Domain {domain} has no account lockout policy (lockoutThreshold = 0). "
                    "Password spray and brute-force attacks will NEVER trigger account lockout, "
                    "allowing unlimited authentication attempts against any account."
                ),
                reproduction_steps=[
                    f"impacket-GetUserSPNs {domain}/lowpriv:pass -dc-ip {dc_ip}",
                    f"crackmapexec smb {dc_ip} -u users.txt -p passwords.txt --continue-on-success",
                ],
                remediation=(
                    "Set account lockout threshold to 5-10 attempts.\n"
                    "Set lockout observation window to at least 30 minutes.\n"
                    "Group Policy: Computer Configuration → Windows Settings → Security Settings → "
                    "Account Policies → Account Lockout Policy."
                ),
                references=["MITRE TA0006/T1110", "CWE-307"],
                evidence=Evidence(extra={"threshold": threshold, "domain": domain}),
                cvss_v31_vector=CVSS_HIGH,
                cvss_v40_vector=CVSS40_HIGH,
                mitre_attack=["TA0006/T1110"],
                target=dc_ip,
            )

        # ── Weak minimum password length ──────────────────────────────────────
        if min_pwd < 12:
            self.new_finding(
                title=f"Minimum Password Length Too Short ({min_pwd} characters)",
                severity=Severity.MEDIUM,
                description=(
                    f"Domain minimum password length is {min_pwd} characters. "
                    "NIST SP 800-63B recommends at least 8 characters; "
                    "Microsoft and CIS recommend at least 14 characters for privileged accounts."
                ),
                reproduction_steps=["Group Policy: Account Policies → Password Policy → Minimum password length"],
                remediation="Set minimum password length to at least 14 characters.",
                references=["NIST SP 800-63B", "CWE-521", "CIS Control 5"],
                evidence=Evidence(extra={"min_pwd_length": min_pwd}),
                cvss_v31_vector=CVSS_MEDIUM,
                cvss_v40_vector=CVSS40_MEDIUM,
                target=dc_ip,
            )

        # ── No password complexity ────────────────────────────────────────────
        if not complexity_enabled:
            self.new_finding(
                title="Password Complexity Not Required",
                severity=Severity.MEDIUM,
                description=(
                    "Domain password complexity requirements are disabled (pwdProperties bit 0 = 0). "
                    "Users can set simple dictionary passwords without mixed character sets."
                ),
                reproduction_steps=["Group Policy: Account Policies → Password Policy → Password must meet complexity requirements"],
                remediation="Enable password complexity requirements.",
                references=["NIST SP 800-63B", "CWE-521"],
                evidence=Evidence(extra={"pwd_properties": pwd_complexity}),
                cvss_v31_vector=CVSS_MEDIUM,
                cvss_v40_vector=CVSS40_MEDIUM,
                target=dc_ip,
            )

        # ── Machine Account Quota ─────────────────────────────────────────────
        if quota > 0:
            self.new_finding(
                title=f"ms-DS-MachineAccountQuota = {quota} — Domain Users Can Create Machine Accounts",
                severity=Severity.MEDIUM,
                description=(
                    f"ms-DS-MachineAccountQuota = {quota}. "
                    f"Any authenticated domain user can add up to {quota} computer account(s) to the domain. "
                    "This enables NoPac (CVE-2021-42278/42287), RBCD attacks, and other "
                    "privilege escalation paths that require a controlled machine account."
                ),
                reproduction_steps=[
                    f"addcomputer.py -computer-name 'FAKEMACHINE$' -computer-pass 'Pass123!' "
                    f"{domain}/{self.config.extra.get('username','user')}:"
                    f"{self.config.extra.get('password','pass')} -dc-ip {dc_ip}",
                ],
                remediation=(
                    "Set ms-DS-MachineAccountQuota to 0 on the domain object. "
                    "Use Tier 0 admin accounts for computer object creation via AD delegation."
                ),
                references=["MITRE TA0004/T1136.002", "CVE-2021-42278"],
                evidence=Evidence(extra={"quota": quota}),
                cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N",
                mitre_attack=["TA0004/T1136.002"],
                target=dc_ip,
            )

        # ── Functional level informational ────────────────────────────────────
        self.new_finding(
            title=f"Domain Functional Level: {func_level_str}",
            severity=Severity.INFORMATIONAL,
            description=(
                f"Domain {domain} is running at functional level {func_level_raw} "
                f"({func_level_str}). "
                + (
                    "WARNING: Low functional levels may limit security features "
                    "(e.g., Protected Users group, Kerberos Armoring). "
                    if func_level_raw < 6 else
                    "Modern functional level — all security features available."
                )
            ),
            reproduction_steps=["Get-ADDomain | Select DomainMode"],
            remediation=(
                "Raise domain functional level to Windows Server 2016 (level 7) or higher "
                "to unlock Protected Users security group, Kerberos Armoring (FAST), "
                "and other modern security features."
                if func_level_raw < 7 else "No action required."
            ),
            references=["https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/active-directory-functional-levels"],
            evidence=Evidence(extra={
                "functional_level": func_level_raw,
                "functional_level_name": func_level_str,
            }),
            cvss_v31_vector=CVSS_INFO,
            cvss_v40_vector=CVSS40_INFO,
            target=dc_ip,
        )

    async def _enum_domain_trusts(
        self, client: LdapClient, domain: str, dc_ip: str
    ) -> None:
        """Enumerate domain trusts."""
        dc_parts = ",".join(f"DC={p}" for p in domain.split("."))
        system_dn = f"CN=System,{dc_parts}"

        trusts = client.search(
            "(objectClass=trustedDomain)",
            ["name", "trustDirection", "trustType", "trustAttributes",
             "flatName", "securityIdentifier"],
            base_dn=system_dn,
        )

        if not trusts:
            self.log.info("No domain trusts found")
            return

        self.log.info("Found %d domain trust(s)", len(trusts))
        trust_details = []
        for trust in trusts:
            trust_name      = str(trust.get("name", "?"))
            trust_direction = int(str(trust.get("trustDirection", 0) or 0))
            trust_type      = int(str(trust.get("trustType", 0) or 0))
            trust_attrs     = int(str(trust.get("trustAttributes", 0) or 0))

            # trustDirection: 1=Inbound, 2=Outbound, 3=Bidirectional
            direction_str = {1: "Inbound", 2: "Outbound", 3: "Bidirectional"}.get(
                trust_direction, f"Unknown({trust_direction})"
            )
            # trustAttributes flags
            forest_trust    = bool(trust_attrs & 0x8)
            sid_filter      = not bool(trust_attrs & 0x4)  # 0x4 = SID filtering disabled
            within_forest   = bool(trust_attrs & 0x20)

            trust_details.append({
                "name":          trust_name,
                "direction":     direction_str,
                "forest_trust":  forest_trust,
                "sid_filtering": sid_filter,
                "within_forest": within_forest,
                "attributes":    f"0x{trust_attrs:x}",
            })

        # Check for dangerous trust configurations
        no_sid_filter = [t for t in trust_details if not t.get("sid_filtering")]
        bidirectional  = [t for t in trust_details if t.get("direction") == "Bidirectional"]

        ev = Evidence(extra={"trusts": trust_details})

        severity = Severity.HIGH if no_sid_filter else Severity.MEDIUM
        self.new_finding(
            title=f"Domain Trusts Enumerated — {len(trusts)} Trust(s) Found",
            severity=severity,
            description=(
                f"Domain {domain} has {len(trusts)} trust relationship(s):\n"
                + "\n".join(
                    f"  • {t['name']} [{t['direction']}, forest={t['forest_trust']}, "
                    f"SID-filtering={t['sid_filtering']}]"
                    for t in trust_details[:10]
                )
                + (
                    f"\n\nWARNING: {len(no_sid_filter)} trust(s) have SID filtering disabled "
                    f"({', '.join(t['name'] for t in no_sid_filter)}) — "
                    "SID history injection attacks are possible across these trusts."
                    if no_sid_filter else ""
                )
                + (
                    f"\n\nNOTE: {len(bidirectional)} bidirectional trust(s) — "
                    "both domains have full transitive trust. "
                    "Compromise of either domain affects both."
                    if bidirectional else ""
                )
            ),
            reproduction_steps=[
                f"nltest /domain_trusts /v",
                "Get-ADTrust -Filter * | Select Name,Direction,TrustAttributes",
                f"impacket-GetADUsers -all {domain}/{self.config.extra.get('username','user')}:"
                f"{self.config.extra.get('password','pass')} -dc-ip {dc_ip}",
            ],
            remediation=(
                "1. Enable SID filtering on all external trusts.\n"
                "2. Review bidirectional trusts — can they be reduced to one-way?\n"
                "3. Use selective authentication on forest trusts.\n"
                "4. Mark trust accounts with 'Account is sensitive and cannot be delegated'."
            ),
            references=[
                "MITRE TA0003/T1482",
                "https://attack.mitre.org/techniques/T1482/",
            ],
            evidence=ev,
            cvss_v31_vector="CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:N" if no_sid_filter else CVSS_INFO,
            mitre_attack=["TA0003/T1482"],
            target=dc_ip,
        )

    async def _enum_privileged_groups(
        self, client: LdapClient, domain: str, dc_ip: str
    ) -> None:
        """Enumerate membership of high-privilege AD groups."""
        dc_parts = ",".join(f"DC={p}" for p in domain.split("."))
        group_summary: dict[str, list[str]] = {}

        for group_name in PRIVILEGED_GROUPS:
            await self.rate_limit()
            members = client.search(
                f"(&(objectClass=user)(memberOf=CN={group_name},CN=Users,{dc_parts}))",
                ["sAMAccountName", "distinguishedName"],
            )
            # Also check Builtin container
            if not members:
                members = client.search(
                    f"(&(objectClass=user)(memberOf=CN={group_name},CN=Builtin,{dc_parts}))",
                    ["sAMAccountName"],
                )

            if members:
                names = [str(m.get("sAMAccountName", "?")) for m in members]
                group_summary[group_name] = names
                self.log.info("Group '%s': %d member(s): %s", group_name, len(names), names[:5])

        if group_summary:
            self.config.extra["privileged_groups"] = group_summary
            total_priv = sum(len(v) for v in group_summary.values())
            # Deduplicate (one user may be in multiple groups)
            all_priv_users = list({u for members in group_summary.values() for u in members})

            self.new_finding(
                title=f"Privileged Group Membership Enumerated — {len(all_priv_users)} Unique Privileged Users",
                severity=Severity.INFORMATIONAL,
                description=(
                    f"Privileged group membership summary for domain {domain}:\n"
                    + "\n".join(
                        f"  • {grp}: {', '.join(members[:5])}"
                        + (f" (+{len(members)-5} more)" if len(members) > 5 else "")
                        for grp, members in group_summary.items()
                    )
                    + f"\n\n{len(all_priv_users)} unique privileged user(s) identified."
                ),
                reproduction_steps=[
                    "PowerView: Get-DomainGroupMember -Identity 'Domain Admins' -Recurse",
                    "Get-ADGroupMember 'Domain Admins' -Recursive | Select SamAccountName",
                ],
                remediation=(
                    "Review all privileged group members — remove unnecessary members. "
                    "Apply Tiered Administration model (Tier 0 for DA/EA/SA). "
                    "Require Just-In-Time (JIT) privileged access via PAM solutions."
                ),
                references=["MITRE TA0004/T1078.002", "CIS Control 5"],
                evidence=Evidence(extra={"group_summary": group_summary, "all_priv_users": all_priv_users}),
                cvss_v31_vector=CVSS_INFO,
                cvss_v40_vector=CVSS40_INFO,
                mitre_attack=["TA0004/T1078.002"],
                target=dc_ip,
            )


class TestDomainEnum:
    def test_cvss_info(self) -> None:
        assert CVSS_INFO.startswith("CVSS:3.1")

    def test_functional_levels(self) -> None:
        assert DOMAIN_FUNCTIONAL_LEVELS[7] == "Windows Server 2016/2019/2022"
        assert DOMAIN_FUNCTIONAL_LEVELS[0] == "Windows 2000 Native"

    def test_privileged_groups_list(self) -> None:
        assert "Domain Admins" in PRIVILEGED_GROUPS
        assert "Enterprise Admins" in PRIVILEGED_GROUPS
        assert "Schema Admins" in PRIVILEGED_GROUPS
        assert "Backup Operators" in PRIVILEGED_GROUPS
        assert "DNSAdmins" in PRIVILEGED_GROUPS

    def test_phase(self) -> None:
        assert DomainEnum.PHASE == 2
