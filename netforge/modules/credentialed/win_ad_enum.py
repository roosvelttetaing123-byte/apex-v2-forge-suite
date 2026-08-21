"""Windows Active Directory Enumeration and Misconfiguration Audit — credentialed WinRM.

Detects delegation abuse vectors, weak password policy, AdminSDHolder issues,
account hygiene problems, LAPS deployment, and privileged group sprawl.

Nessus equivalent: Plugin 210763 (Active Directory Security Audit).
"""
from __future__ import annotations

import csv
import io
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_CRIT = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"
CVSS_HIGH  = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
CVSS_MED   = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
CVSS_LOW   = "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N"

# ── PowerShell queries ───────────────────────────────────────────────────────

_PS_UNCONSTRAINED_DELEGATION = (
    # Filter out Domain Controllers: DCs always have TrustedForDelegation=True by design.
    # We exclude them by PrimaryGroupID=516 (Domain Controllers group) which is reliable
    # regardless of which OU the DC account lives in (handles custom/renamed DC OUs).
    # We also exclude the standard OU=Domain Controllers path as belt-and-suspenders.
    "Get-ADComputer -Filter {TrustedForDelegation -eq $true} "
    "-Properties TrustedForDelegation,OperatingSystem,DistinguishedName,PrimaryGroupID | "
    "Where-Object { $_.PrimaryGroupID -ne 516 -and $_.DistinguishedName -notmatch 'OU=Domain Controllers' } | "
    "Select-Object Name,OperatingSystem,DistinguishedName,PrimaryGroupID | "
    "ConvertTo-Csv -NoTypeInformation"
)

_PS_CONSTRAINED_DELEGATION = (
    "Get-ADObject -Filter {'msDS-AllowedToDelegateTo' -like '*'} "
    "-Properties Name,objectClass,SamAccountName,'msDS-AllowedToDelegateTo' | "
    "Select-Object Name,objectClass,SamAccountName,"
    "@{N='DelegateTo';E={($_.'msDS-AllowedToDelegateTo' -join '|')}} | "
    "ConvertTo-Csv -NoTypeInformation"
)

_PS_PASSWORD_POLICY = (
    "Get-ADDefaultDomainPasswordPolicy | "
    "Select-Object MinPasswordLength,PasswordHistoryCount,MaxPasswordAge,"
    "MinPasswordAge,LockoutThreshold,LockoutDuration,ComplexityEnabled | "
    "ConvertTo-Csv -NoTypeInformation"
)

_PS_NEVER_EXPIRES = (
    # ResultSetSize limits output for large domains (50K+ users).
    # Without this, a domain with 10K never-expires accounts causes
    # WinRM session timeout or Python OOM during CSV parsing.
    "Get-ADUser -Filter {PasswordNeverExpires -eq $true -and Enabled -eq $true} "
    "-Properties PasswordNeverExpires,PasswordLastSet,LastLogonDate "
    "-ResultSetSize 2000 | "
    "Select-Object Name,SamAccountName,PasswordLastSet,LastLogonDate | "
    "ConvertTo-Csv -NoTypeInformation"
)

_PS_GUEST_ACCOUNT = (
    "Get-ADUser Guest -Properties Enabled,LastLogonDate,PasswordLastSet | "
    "Select-Object SamAccountName,Enabled,LastLogonDate,PasswordLastSet | "
    "ConvertTo-Csv -NoTypeInformation"
)

_PS_DA_MEMBERS = (
    "Get-ADGroupMember -Identity 'Domain Admins' -Recursive | "
    "Where-Object { $_.objectClass -eq 'user' } | "
    "ForEach-Object { "
    "  $u = Get-ADUser $_.SamAccountName -Properties LastLogonDate,PasswordLastSet,Enabled; "
    "  [PSCustomObject]@{ "
    "    Name=$u.Name; SamAccountName=$u.SamAccountName; "
    "    Enabled=$u.Enabled; LastLogonDate=$u.LastLogonDate; "
    "    PasswordLastSet=$u.PasswordLastSet "
    "  } "
    "} | ConvertTo-Csv -NoTypeInformation"
)

_PS_EA_MEMBERS = (
    "try { "
    "Get-ADGroupMember -Identity 'Enterprise Admins' -Recursive | "
    "Where-Object { $_.objectClass -eq 'user' } | "
    "Select-Object Name,SamAccountName | ConvertTo-Csv -NoTypeInformation "
    "} catch { 'NOT_FOUND' }"
)

_PS_SCHEMA_MEMBERS = (
    "try { "
    "Get-ADGroupMember -Identity 'Schema Admins' -Recursive | "
    "Where-Object { $_.objectClass -eq 'user' } | "
    "Select-Object Name,SamAccountName | ConvertTo-Csv -NoTypeInformation "
    "} catch { 'NOT_FOUND' }"
)

_PS_LAPS_CHECK = (
    "$lapsDeployed = $false; "
    "$sample = Get-ADComputer -Filter * -Properties 'ms-Mcs-AdmPwd' -ResultSetSize 50 | "
    "Where-Object { $_.PSObject.Properties.Name -contains 'ms-Mcs-AdmPwd' }; "
    "$count = ($sample | Measure-Object).Count; "
    "[PSCustomObject]@{ LAPSDeployed=($count -gt 0); SampleCount=$count } | "
    "ConvertTo-Csv -NoTypeInformation"
)

_PS_REVERSIBLE_ENCRYPTION = (
    "Get-ADUser -Filter {AllowReversiblePasswordEncryption -eq $true} "
    "-Properties AllowReversiblePasswordEncryption,PasswordLastSet | "
    "Select-Object Name,SamAccountName,PasswordLastSet | "
    "ConvertTo-Csv -NoTypeInformation"
)

_PS_ADMINSDHOLDER = (
    "# Get accounts with AdminCount=1 but not in current protected groups "
    "$protectedGroups = @('Domain Admins','Enterprise Admins','Schema Admins',"
    "'Administrators','Account Operators','Backup Operators','Print Operators',"
    "'Server Operators','Group Policy Creator Owners','Replicator','KRBTGT'); "
    "$protectedMembers = @(); "
    "foreach ($g in $protectedGroups) { "
    "  try { $protectedMembers += (Get-ADGroupMember $g -Recursive -ErrorAction SilentlyContinue | "
    "    Where-Object { $_.objectClass -eq 'user' } | Select-Object -ExpandProperty SamAccountName) "
    "  } catch {} "
    "}; "
    "$protectedMembers = $protectedMembers | Select-Object -Unique; "
    "Get-ADUser -Filter {AdminCount -eq 1} -Properties AdminCount | "
    "Where-Object { $_.SamAccountName -notin $protectedMembers } | "
    "Select-Object Name,SamAccountName | ConvertTo-Csv -NoTypeInformation"
)


def _parse_csv_rows(output: str | None) -> list[dict[str, str]]:
    """Parse PowerShell ConvertTo-Csv -NoTypeInformation output into list of dicts.

    Uses Python's csv module for correct handling of quoted fields, embedded
    commas, and escaped quotes — critical in enterprise AD environments where
    DistinguishedNames, descriptions, and group memberships contain commas.
    """
    text = (output or "").strip()
    if not text:
        return []
    # Strip the #TYPE line that ConvertTo-Csv sometimes emits
    lines = text.splitlines()
    if lines and lines[0].startswith("#TYPE"):
        text = "\n".join(lines[1:]).strip()
    if not text:
        return []
    try:
        reader = csv.DictReader(io.StringIO(text), restval="")
        return [dict(row) for row in reader]
    except (csv.Error, StopIteration, KeyError):
        return []


def _days_since(date_str: str) -> int | None:
    """Return number of days since a date string, or None if unparseable.

    Handles PowerShell date formats across OS locales (US, UK, ISO 8601)
    and both 12-hour and 24-hour clocks without fragile string truncation.
    Uses timezone-aware datetime.now(timezone.utc) instead of the deprecated
    datetime.utcnow() (removed in Python 3.12+).
    """
    date_str = (date_str or "").strip()
    if not date_str:
        return None
    for fmt in (
        "%m/%d/%Y %I:%M:%S %p",   # US 12h:  6/15/2024 3:45:22 PM
        "%Y-%m-%d %H:%M:%S",       # ISO:     2024-06-15 15:45:22
        "%m/%d/%Y %H:%M:%S",       # US 24h:  6/15/2024 15:45:22
        "%d/%m/%Y %H:%M:%S",       # UK/EU:   15/06/2024 15:45:22
        "%Y-%m-%dT%H:%M:%S",       # ISO8601: 2024-06-15T15:45:22
        "%Y-%m-%d",                 # date:    2024-06-15
        "%m/%d/%Y",                 # US date: 6/15/2024
    ):
        try:
            dt = datetime.strptime(date_str, fmt)
            delta = datetime.now(timezone.utc) - dt.replace(tzinfo=timezone.utc)
            return max(delta.days, 0)
        except ValueError:
            continue
    # Fallback: trim trailing sub-second precision then retry
    # e.g. "2024-06-15T15:45:22.1234567" -> "2024-06-15T15:45:22"
    if len(date_str) > 19:
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
            try:
                dt = datetime.strptime(date_str[:19], fmt)
                delta = datetime.now(timezone.utc) - dt.replace(tzinfo=timezone.utc)
                return max(delta.days, 0)
            except ValueError:
                continue
    return None


# Service account name pattern — used to separate service accounts from human
# accounts in never-expires and inactive-DA checks to prevent FP inflation.
# Prefixed names (svc_, sa_, srv_, app_) are always service accounts.
# Bare-word prefixes (service, sql, iis, etc.) require a delimiter to avoid
# matching human accounts like 'servicedesk', 'webber', or 'taskforce'.
_SVC_PATTERN = re.compile(
    r'^(svc[_\-]|srv[_\-]|sa[_\-]|app[_\-]|service[_\-.]|sql[_\-.]|iis[_\-.]|'
    r'web[_\-.]|backup[_\-.]|monitor[_\-.]|scan[_\-.]|agent[_\-.]|task[_\-.])',
    re.IGNORECASE,
)


class WinAdEnum(BaseModule):
    NAME        = "win_ad_enum"
    DESCRIPTION = "WinRM credentialed: Active Directory misconfiguration audit — delegation, policy, LAPS, privileged groups"
    PHASE       = 5
    TAGS        = ["credentialed", "windows", "active-directory", "domain", "enumeration"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        transport_mgr = self.config.extra.get("transport_manager")
        if not transport_mgr or not transport_mgr.has_creds("winrm"):
            return self._make_result(start, skipped=True, skip_reason="no WinRM credentials")

        hosts = self.config.extra.get("live_hosts", [self.config.target])
        for host in hosts[:10]:
            if not self.check_scope(host):
                continue
            await self.rate_limit()
            session = await transport_mgr.get_winrm_session(host)
            if not session:
                continue

            winrm = transport_mgr.winrm

            # Verify RSAT/AD module is available
            check = await winrm.execute(session, "Get-ADDomain | Select-Object -ExpandProperty DNSRoot")
            if not check.success or not check.stdout.strip():
                continue

            domain = check.stdout.strip()

            await self._check_unconstrained_delegation(host, domain, winrm, session)
            await self._check_constrained_delegation(host, domain, winrm, session)
            await self._check_password_policy(host, domain, winrm, session)
            await self._check_never_expires(host, domain, winrm, session)
            await self._check_guest_account(host, domain, winrm, session)
            await self._check_privileged_groups(host, domain, winrm, session)
            await self._check_laps(host, domain, winrm, session)
            await self._check_reversible_encryption(host, domain, winrm, session)
            await self._check_adminsdholder(host, domain, winrm, session)
            # Domain-wide — one host sufficient
            break

        return self._make_result(start)

    # ── Unconstrained delegation ─────────────────────────────────────────────

    async def _check_unconstrained_delegation(self, host: str, domain: str, winrm, session) -> None:
        """Detect non-DC computer accounts with unconstrained Kerberos delegation."""
        result = await winrm.execute(session, _PS_UNCONSTRAINED_DELEGATION)
        if not result.success:
            return

        rows = _parse_csv_rows(result.stdout)
        if not rows:
            return

        computers = [r.get("Name", "unknown") for r in rows]

        self.new_finding(
            title=f"Unconstrained Kerberos Delegation on {len(rows)} Non-DC Computer(s) — {host}",
            severity=Severity.CRITICAL,
            description=(
                f"{len(rows)} non-Domain-Controller computer account(s) have TrustedForDelegation=True "
                f"(unconstrained Kerberos delegation). When a domain user authenticates to a service "
                f"on these systems, their TGT is cached in LSASS. An attacker who compromises these "
                f"hosts can extract those TGTs and impersonate any user who connected — including "
                f"Domain Admins and privileged service accounts.\n\n"
                f"By combining with a print spooler or other coercion technique (PrinterBug, "
                f"PetitPotam) to force DC authentication to these hosts, a full domain compromise "
                f"can be achieved from low-privilege access to these computers.\n\n"
                f"Vulnerable computers: {', '.join(computers)}"
            ),
            reproduction_steps=[
                f"# Step 1: Compromise a machine with unconstrained delegation (e.g., {computers[0]})",
                "# Step 2: Coerce DC to authenticate to compromised host:",
                f"python3 printerbug.py {domain}/lowpriv:Password1@{host} <compromised-host-ip>",
                "# OR: python3 PetitPotam.py -u lowpriv -p Password1 <compromised-host-ip> <DC-IP>",
                "# Step 3: Capture TGT with Rubeus on compromised host (as SYSTEM):",
                "Rubeus.exe monitor /interval:5 /filteruser:DC01$",
                "# Step 4: Pass the TGT:",
                "Rubeus.exe ptt /ticket:<base64_ticket>",
                "# Step 5: DCSync:",
                f"secretsdump.py -k -just-dc {domain}/DC01$@{host}",
            ],
            remediation=(
                "1. Remove unconstrained delegation from all non-DC computers: "
                "Set-ADComputer <name> -TrustedForDelegation $false. "
                "2. If delegation is required, migrate to constrained delegation "
                "(msDS-AllowedToDelegateTo) or resource-based constrained delegation (RBCD). "
                "3. Add all sensitive accounts (DAs, SAs) to the Protected Users security group "
                "— this prevents their TGTs from being delegated. "
                "4. Block MS-RPRN and MS-EFSR at the firewall to prevent coercion."
            ),
            references=[
                "https://attack.mitre.org/techniques/T1134/001/",
                "https://github.com/topotam/PetitPotam",
                "https://dirkjanm.io/krbrelayx-unconstrained-delegation-abuse-toolkit/",
            ],
            evidence=Evidence(extra={
                "host": host,
                "domain": domain,
                "unconstrained_computers": rows[:20],
                "computer_names": computers[:20],
            }),
            cvss_v31_vector=CVSS_CRIT,
            mitre_attack=["TA0006/T1558", "TA0004/T1134.001", "TA0008/T1021.006"],
            target=host, service="winrm", confidence="HIGH",
        )

    # ── Constrained delegation to sensitive services ─────────────────────────

    async def _check_constrained_delegation(self, host: str, domain: str, winrm, session) -> None:
        """Flag constrained delegation entries targeting DCs or sensitive SPNs."""
        result = await winrm.execute(session, _PS_CONSTRAINED_DELEGATION)
        if not result.success:
            return

        rows = _parse_csv_rows(result.stdout)
        if not rows:
            return

        # Flag accounts delegating to DC-only services or sensitive SPNs.
        # DC-only services: ldap/, gc/ (Global Catalog) only exist on DCs
        # so we don't need hostname heuristics for those.
        # For generic services (cifs/, host/, rpc/), we need hostname matching.
        dc_only_services = re.compile(r'(ldap/|gc/)', re.IGNORECASE)
        dc_hostname_pattern = re.compile(
            r'(cifs/|host/|rpc/|wsman/|http/|krbtgt).*?'
            r'(dc\d|dc-|pdc|bdc|domaincontroller|adds|adsrv|corpdc|addc)',
            re.IGNORECASE
        )
        sensitive_entries: list[dict] = []

        for row in rows:
            delegate_to = row.get("DelegateTo", "")
            if dc_only_services.search(delegate_to) or dc_hostname_pattern.search(delegate_to):
                sensitive_entries.append(row)

        # Also flag ALL constrained delegation entries for informational awareness
        if rows:
            self.new_finding(
                title=f"Constrained Delegation Configured on {len(rows)} Account(s) — {host}",
                severity=Severity.MEDIUM if not sensitive_entries else Severity.HIGH,
                description=(
                    f"{len(rows)} account(s) have constrained Kerberos delegation configured "
                    f"(msDS-AllowedToDelegateTo). Accounts with constrained delegation can "
                    f"impersonate any user to the listed services using S4U2Proxy. "
                    + (
                        f"\n\n{len(sensitive_entries)} entries delegate to sensitive services "
                        f"(DCs/LDAP/CIFS), enabling potential privilege escalation: "
                        + ", ".join(r.get("Name", "?") for r in sensitive_entries[:5])
                        if sensitive_entries else ""
                    )
                    + f"\n\nAll delegating accounts: "
                    + ", ".join(r.get("Name", "?") for r in rows[:15])
                ),
                reproduction_steps=[
                    "# Abuse constrained delegation with getST.py (impacket):",
                    f"getST.py -spn 'cifs/dc01.{domain}' -impersonate administrator "
                    f"-dc-ip {host} '{domain}/svcaccount:password'",
                    "export KRB5CCNAME=administrator.ccache",
                    f"secretsdump.py -k -no-pass {domain}/administrator@dc01.{domain}",
                ],
                remediation=(
                    "1. Audit all constrained delegation entries annually. "
                    "2. Remove delegation to sensitive services (LDAP/CIFS on DCs) unless "
                    "business-justified and documented. "
                    "3. Migrate to Resource-Based Constrained Delegation (RBCD) for better "
                    "least-privilege control. "
                    "4. Add sensitive service accounts to Protected Users group. "
                    "5. Monitor Event ID 4769 (TGS) with S4U extensions."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1134/001/",
                    "https://github.com/fortra/impacket",
                    "https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html",
                ],
                evidence=Evidence(extra={
                    "host": host,
                    "domain": domain,
                    "all_entries": rows[:30],
                    "sensitive_entries": sensitive_entries[:10],
                }),
                cvss_v31_vector=CVSS_HIGH if sensitive_entries else CVSS_MED,
                mitre_attack=["TA0006/T1558", "TA0004/T1134.001"],
                target=host, service="winrm", confidence="HIGH",
            )

    # ── Password policy ──────────────────────────────────────────────────────

    async def _check_password_policy(self, host: str, domain: str, winrm, session) -> None:
        """Detect weak domain password policy settings."""
        result = await winrm.execute(session, _PS_PASSWORD_POLICY)
        if not result.success:
            return

        rows = _parse_csv_rows(result.stdout)
        if not rows:
            return

        row = rows[0]
        issues: list[str] = []

        try:
            min_len = int(row.get("MinPasswordLength", "0"))
            if min_len < 12:
                issues.append(f"MinPasswordLength={min_len} (CIS benchmark: >=12, NIST: >=15)")
        except ValueError:
            pass

        complexity = row.get("ComplexityEnabled", "False")
        if complexity.lower() in ("false", "0"):
            issues.append("PasswordComplexity=Disabled")

        try:
            lockout = int(row.get("LockoutThreshold", "0"))
            if lockout == 0:
                issues.append("LockoutThreshold=0 (no lockout — brute force unrestricted)")
            elif lockout > 10:
                issues.append(f"LockoutThreshold={lockout} (CIS: <=5)")
        except ValueError:
            pass

        try:
            history = int(row.get("PasswordHistoryCount", "0"))
            if history < 10:
                issues.append(f"PasswordHistoryCount={history} (CIS: >=24)")
        except ValueError:
            pass

        if not issues:
            return

        severity = Severity.HIGH if any("no lockout" in i or "MinPasswordLength" in i for i in issues) else Severity.MEDIUM

        self.new_finding(
            title=f"Weak Domain Password Policy ({len(issues)} Issue(s)) — {host}",
            severity=severity,
            description=(
                f"The default domain password policy for '{domain}' has {len(issues)} weakness(es) "
                f"that increase the risk of credential compromise:\n\n"
                + "\n".join(f"  - {issue}" for issue in issues)
                + f"\n\nWeak password policies facilitate successful brute-force attacks, "
                f"password spray attacks, and hash cracking after credential exposure."
            ),
            reproduction_steps=[
                f"Enter-PSSession {host}",
                "Get-ADDefaultDomainPasswordPolicy | Format-List *",
                "# Spray attack using weak policy's lack of lockout:",
                f"kerbrute passwordspray --dc {host} -d {domain} users.txt 'Winter2024!'",
            ],
            remediation=(
                "Apply via 'Default Domain Policy' GPO or Fine-Grained Password Policy: "
                "1. MinPasswordLength = 14+ characters (NIST SP 800-63B recommends >=15). "
                "2. Enable PasswordComplexity. "
                "3. LockoutThreshold = 5 (CIS L1 Windows Server benchmark). "
                "4. LockoutDuration = 15+ minutes. "
                "5. PasswordHistoryCount = 24. "
                "6. Consider NIST SP 800-63B guidance: remove forced rotation, "
                "instead check against compromised password lists."
            ),
            references=[
                "CIS Microsoft Windows Server 2022 Benchmark v2.0 — Section 1.1",
                "NIST SP 800-63B Digital Identity Guidelines",
                "https://attack.mitre.org/techniques/T1110/003/",
            ],
            evidence=Evidence(extra={
                "host": host,
                "domain": domain,
                "policy": dict(row),
                "issues": issues,
            }),
            cvss_v31_vector=CVSS_HIGH if severity == Severity.HIGH else CVSS_MED,
            mitre_attack=["TA0006/T1110.003", "TA0006/T1110.001"],
            target=host, service="winrm", confidence="HIGH",
        )

    # ── Never-expiring passwords ─────────────────────────────────────────────

    async def _check_never_expires(self, host: str, domain: str, winrm, session) -> None:
        """Count enabled user accounts with PasswordNeverExpires=True."""
        result = await winrm.execute(session, _PS_NEVER_EXPIRES)
        if not result.success:
            return

        rows = _parse_csv_rows(result.stdout)
        if not rows:
            return

        # Separate service accounts from human accounts.
        # Service accounts legitimately use PasswordNeverExpires; counting them
        # alongside human accounts inflates the finding in enterprise domains.
        human_rows = [r for r in rows if not _SVC_PATTERN.match(r.get("SamAccountName", ""))]
        svc_rows   = [r for r in rows if _SVC_PATTERN.match(r.get("SamAccountName", ""))]

        # Report if HUMAN account count exceeds threshold
        threshold = 20
        if len(human_rows) < threshold:
            return

        svc_note = (
            f"\n\nNote: {len(svc_rows)} service account(s) with PasswordNeverExpires were excluded from "
            f"this count (expected for service accounts). Consider migrating them to gMSA."
            if svc_rows else ""
        )

        self.new_finding(
            title=f"Human Accounts with Non-Expiring Passwords ({len(human_rows)} accounts) — {host}",
            severity=Severity.MEDIUM,
            description=(
                f"{len(human_rows)} enabled human user accounts in '{domain}' have PasswordNeverExpires=True "
                f"(excludes {len(svc_rows)} service accounts matching svc_/sa_/srv_ patterns). "
                f"Non-expiring passwords persist indefinitely after compromise. "
                f"In breach scenarios, attackers may hold access for months or years using "
                f"credentials that were leaked, phished, or cracked long ago. "
                f"NIST SP 800-63B and CIS Controls recommend against mandatory rotation but "
                f"still require immediate reset on compromise — non-expiring policies often "
                f"indicate accounts that are never audited or reviewed for compromise indicators."
                + svc_note
            ),
            reproduction_steps=[
                f"Enter-PSSession {host}",
                "Get-ADUser -Filter {PasswordNeverExpires -eq $true -and Enabled -eq $true} "
                "-Properties PasswordLastSet | Sort-Object PasswordLastSet | "
                "Select-Object -First 20 | Format-Table Name,SamAccountName,PasswordLastSet",
            ],
            remediation=(
                "1. Review all accounts with PasswordNeverExpires=True — justify each one. "
                "2. Convert service accounts to Managed Service Accounts (gMSA) where possible. "
                "3. For human accounts, enable password expiration. "
                "4. Implement Have I Been Pwned / HIBP checks on password change via "
                "Enzoic or Microsoft's Azure AD Password Protection. "
                "5. Run: Get-ADUser -Filter {PasswordNeverExpires -eq $true} | "
                "Set-ADUser -PasswordNeverExpires $false (after validating impact)."
            ),
            references=[
                "NIST SP 800-63B Section 5.1.1",
                "CIS Control 5.2",
                "https://attack.mitre.org/techniques/T1078/",
            ],
            evidence=Evidence(extra={
                "host": host,
                "domain": domain,
                "human_count": len(human_rows),
                "service_count": len(svc_rows),
                "sample_accounts": [
                    {"sam": r.get("SamAccountName"), "name": r.get("Name"), "pwd_set": r.get("PasswordLastSet")}
                    for r in human_rows[:30]
                ],
            }),
            cvss_v31_vector=CVSS_MED,
            mitre_attack=["TA0006/T1078.002"],
            target=host, service="winrm", confidence="HIGH",
        )

    # ── Guest account ────────────────────────────────────────────────────────

    async def _check_guest_account(self, host: str, domain: str, winrm, session) -> None:
        """Detect if the built-in Guest account is enabled."""
        result = await winrm.execute(session, _PS_GUEST_ACCOUNT)
        if not result.success:
            return

        rows = _parse_csv_rows(result.stdout)
        if not rows:
            return

        row = rows[0]
        enabled = row.get("Enabled", "False")

        if str(enabled).strip().lower() not in ("true", "1"):
            return

        self.new_finding(
            title=f"Built-in Guest Account Enabled — {host}",
            severity=Severity.HIGH,
            description=(
                f"The built-in Guest account is enabled in the '{domain}' domain. "
                f"The Guest account has no password by default and provides unauthenticated "
                f"access to domain resources. It can be used for anonymous enumeration of "
                f"domain objects, accessing shares configured with guest permissions, "
                f"and in some configurations as a stepping stone for lateral movement. "
                f"All CIS benchmarks and Microsoft security baselines require this account "
                f"to be disabled."
            ),
            reproduction_steps=[
                f"# Test guest access from attacker machine:",
                f"smbclient -L //{host} -U 'Guest%'",
                f"enum4linux -a {host}",
                f"# Check accessible shares:",
                f"smbclient //{host}/SYSVOL -U 'Guest%'",
            ],
            remediation=(
                "Disable the Guest account: "
                "Disable-ADAccount -Identity Guest "
                "(or via GPO: Computer Configuration → Windows Settings → "
                "Security Settings → Local Policies → Security Options → "
                "'Accounts: Guest account status' = Disabled). "
                "Verify the account is disabled: Get-ADUser Guest -Properties Enabled."
            ),
            references=[
                "CIS Microsoft Windows Server 2022 Benchmark — 2.3.1.2",
                "https://attack.mitre.org/techniques/T1078.003/",
                "MS Security Baseline for Windows Server 2022",
            ],
            evidence=Evidence(extra={
                "host": host,
                "domain": domain,
                "guest_account": dict(row),
            }),
            cvss_v31_vector=CVSS_HIGH,
            mitre_attack=["TA0001/T1078.003"],
            target=host, service="winrm", confidence="HIGH",
        )

    # ── Privileged group audit ───────────────────────────────────────────────

    async def _check_privileged_groups(self, host: str, domain: str, winrm, session) -> None:
        """Audit DA/EA/Schema Admins membership — flag bloat and service accounts."""
        da_result = await winrm.execute(session, _PS_DA_MEMBERS)
        ea_result = await winrm.execute(session, _PS_EA_MEMBERS)
        sa_result = await winrm.execute(session, _PS_SCHEMA_MEMBERS)

        da_rows = _parse_csv_rows(da_result.stdout) if da_result.success else []
        ea_rows = _parse_csv_rows(ea_result.stdout) if ea_result.success else []
        sa_rows = _parse_csv_rows(sa_result.stdout) if sa_result.success else []

        # Flag if DA membership exceeds threshold
        da_threshold = 20
        svc_pattern = re.compile(r'^(svc_|svc-|service|sa_|sa-|app_|app-)', re.IGNORECASE)

        da_service_accounts = [r for r in da_rows if svc_pattern.match(r.get("SamAccountName", ""))]

        # Inactive DA members (not logged in 180+ days).
        # 60 days was too aggressive — service accounts authenticate via Kerberos
        # (which doesn't update LastLogonDate for interactive logon), so they
        # legitimately show stale dates. 180 days aligns with NIST 800-53 AC-2.
        inactive_da: list[dict] = []
        for row in da_rows:
            sam = row.get("SamAccountName", "")
            # Skip service accounts — they don't do interactive logons
            if _SVC_PATTERN.match(sam):
                continue
            logon_age = _days_since(row.get("LastLogonDate", ""))
            if logon_age is None or logon_age >= 180:
                inactive_da.append({
                    "sam": sam,
                    "name": row.get("Name"),
                    "last_logon": row.get("LastLogonDate"),
                    "logon_age_days": logon_age,
                    "enabled": row.get("Enabled"),
                })

        issues: list[str] = []
        if len(da_rows) > da_threshold:
            issues.append(f"Domain Admins has {len(da_rows)} members (>{da_threshold} threshold)")
        if da_service_accounts:
            issues.append(
                f"{len(da_service_accounts)} service account(s) in Domain Admins: "
                + ", ".join(r.get("SamAccountName", "?") for r in da_service_accounts[:5])
            )
        if len(ea_rows) > 5:
            issues.append(f"Enterprise Admins has {len(ea_rows)} members (should be <=5)")
        if len(sa_rows) > 5:
            issues.append(f"Schema Admins has {len(sa_rows)} members (should be <=2)")
        if inactive_da:
            issues.append(
                f"{len(inactive_da)} Domain Admin accounts inactive 180+ days"
            )

        if not issues:
            return

        # Determine severity — service accounts in DA or excessive membership is critical
        has_svcacct = bool(da_service_accounts)
        severity = Severity.CRITICAL if has_svcacct else Severity.HIGH

        self.new_finding(
            title=f"Privileged Group Membership Issues ({len(issues)}) — {host}",
            severity=severity,
            description=(
                f"Privileged group membership audit for '{domain}' identified {len(issues)} issue(s):\n\n"
                + "\n".join(f"  - {issue}" for issue in issues)
                + f"\n\nDomain Admins: {len(da_rows)} members | "
                f"Enterprise Admins: {len(ea_rows)} members | "
                f"Schema Admins: {len(sa_rows)} members"
                + (
                    f"\n\nService accounts in Domain Admins are particularly dangerous: "
                    f"if the service account's credentials are compromised (e.g., via Kerberoasting, "
                    f"memory scraping, or config file exposure), the attacker immediately gains "
                    f"full domain admin access."
                    if da_service_accounts else ""
                )
            ),
            reproduction_steps=[
                f"Enter-PSSession {host}",
                "Get-ADGroupMember -Identity 'Domain Admins' -Recursive | "
                "Where-Object { $_.objectClass -eq 'user' }",
                "# Check for service account naming patterns:",
                "Get-ADGroupMember -Identity 'Domain Admins' -Recursive | "
                "Where-Object { $_.SamAccountName -match '^(svc|service|app|sa)' }",
            ],
            remediation=(
                "1. Remove all service accounts from Domain Admins — services never need DA. "
                "2. Reduce DA membership to the minimum required (ideally <5 accounts). "
                "3. Disable or remove inactive DA accounts after confirming they are unused. "
                "4. Enroll all DA accounts in PAW (Privileged Access Workstation) program. "
                "5. Add DA accounts to Protected Users security group. "
                "6. Schema Admins should have 0 permanent members — add/remove for specific tasks only."
            ),
            references=[
                "https://attack.mitre.org/techniques/T1078.002/",
                "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models",
                "CIS Control 5.4 — Use Dedicated Workstations",
                "MITRE D3FEND — Privileged Account Protection",
            ],
            evidence=Evidence(extra={
                "host": host,
                "domain": domain,
                "da_count": len(da_rows),
                "ea_count": len(ea_rows),
                "sa_count": len(sa_rows),
                "service_accounts_in_da": [r.get("SamAccountName") for r in da_service_accounts],
                "inactive_da_members": inactive_da[:20],
                "issues": issues,
            }),
            cvss_v31_vector=CVSS_CRIT if has_svcacct else CVSS_HIGH,
            mitre_attack=["TA0004/T1078.002", "TA0003/T1098"],
            target=host, service="winrm", confidence="HIGH",
        )

    # ── LAPS deployment check ────────────────────────────────────────────────

    async def _check_laps(self, host: str, domain: str, winrm, session) -> None:
        """Check if LAPS is deployed across domain computers."""
        result = await winrm.execute(session, _PS_LAPS_CHECK)
        if not result.success:
            return

        rows = _parse_csv_rows(result.stdout)
        if not rows:
            return

        row = rows[0]
        laps_deployed = str(row.get("LAPSDeployed", "False")).strip().lower() in ("true", "1")

        if laps_deployed:
            return  # LAPS is deployed — good

        self.new_finding(
            title=f"LAPS (Local Administrator Password Solution) Not Deployed — {host}",
            severity=Severity.HIGH,
            description=(
                f"Microsoft Local Administrator Password Solution (LAPS) is not deployed in the "
                f"'{domain}' domain. Without LAPS, local Administrator accounts on domain-joined "
                f"computers share the same password (or have no password). "
                f"An attacker who compromises one workstation can use its local admin hash to "
                f"authenticate to all other workstations via Pass-the-Hash — enabling rapid "
                f"lateral movement across the entire domain without ever touching domain credentials.\n\n"
                f"This is a primary enabler of lateral movement in ransomware attacks."
            ),
            reproduction_steps=[
                "# Verify LAPS status:",
                "Get-ADComputer -Filter * -Properties 'ms-Mcs-AdmPwd' | "
                "Where-Object { $_.'ms-Mcs-AdmPwd' } | Measure-Object",
                "# Without LAPS, test for shared local admin password:",
                f"crackmapexec smb {host}/24 -u Administrator -H <local_admin_hash> --local-auth",
                "# Pass-the-Hash lateral movement:",
                f"smbexec.py -hashes :<NTLM_hash> .\\Administrator@<target>",
            ],
            remediation=(
                "1. Deploy Microsoft LAPS v2 (Windows LAPS, built into Windows Server 2022/Win11): "
                "Enable-LapsADSchema && Set-LapsADComputerSelfPermission -Identity 'OU=Workstations,DC=...'. "
                "2. For legacy environments, use the downloadable LAPS MSI. "
                "3. Configure LAPS via GPO: Computer Config → Admin Templates → LAPS. "
                "4. Set password rotation every 30 days, complexity enabled. "
                "5. Restrict 'ms-Mcs-AdmPwd' attribute read access to IT Admins only — "
                "prevent tier violation where workstation users can read server LAPS passwords."
            ),
            references=[
                "https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview",
                "https://attack.mitre.org/techniques/T1550.002/",
                "CIS Control 5.3 — Use Unique Passwords",
                "https://github.com/dafthack/DomainPasswordSpray",
            ],
            evidence=Evidence(extra={
                "host": host,
                "domain": domain,
                "laps_deployed": False,
                "ms_mcs_admPwd_present": False,
            }),
            cvss_v31_vector=CVSS_HIGH,
            mitre_attack=["TA0008/T1550.002", "TA0006/T1003.002"],
            target=host, service="winrm", confidence="HIGH",
        )

    # ── Reversible encryption ────────────────────────────────────────────────

    async def _check_reversible_encryption(self, host: str, domain: str, winrm, session) -> None:
        """Detect accounts with AllowReversiblePasswordEncryption enabled."""
        result = await winrm.execute(session, _PS_REVERSIBLE_ENCRYPTION)
        if not result.success:
            return

        rows = _parse_csv_rows(result.stdout)
        if not rows:
            return

        accounts = [
            {"sam": r.get("SamAccountName"), "name": r.get("Name"), "pwd_set": r.get("PasswordLastSet")}
            for r in rows
        ]

        self.new_finding(
            title=f"Reversible Password Encryption Enabled on {len(rows)} Account(s) — {host}",
            severity=Severity.CRITICAL,
            description=(
                f"{len(rows)} account(s) have AllowReversiblePasswordEncryption enabled. "
                f"This flag causes Active Directory to store passwords in a weakly encrypted form "
                f"equivalent to plaintext (using a static reversible encryption key). "
                f"An attacker with DCSync privileges or direct NTDS.dit access can recover "
                f"the plaintext password for these accounts — bypassing NTLM hash cracking entirely. "
                f"This flag is historically used for legacy CHAP authentication protocols "
                f"which are no longer in widespread use.\n\n"
                f"Affected accounts: "
                + ", ".join(a["sam"] for a in accounts[:10])
            ),
            reproduction_steps=[
                "# Verify affected accounts:",
                "Get-ADUser -Filter {AllowReversiblePasswordEncryption -eq $true} | "
                "Select-Object Name,SamAccountName",
                "# If DCSync access obtained, recover plaintext:",
                f"secretsdump.py -just-dc-user <sam> {domain}/da_user:password@{host}",
                "# Look for supplementalCredentials attribute in NTDS.dit dump",
            ],
            remediation=(
                "1. Disable reversible encryption on all affected accounts: "
                "Get-ADUser -Filter {AllowReversiblePasswordEncryption -eq $true} | "
                "Set-ADUser -AllowReversiblePasswordEncryption $false. "
                "2. Immediately reset passwords for all affected accounts. "
                "3. Ensure the domain policy does not set 'Store passwords using reversible encryption': "
                "GPO → Computer Config → Windows Settings → Security Settings → Account Policies → "
                "Password Policy → 'Store passwords using reversible encryption for all users' = Disabled. "
                "4. Investigate which applications required CHAP authentication — migrate to modern protocols."
            ),
            references=[
                "https://attack.mitre.org/techniques/T1003.003/",
                "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption",
                "CIS Windows Server Benchmark — 1.1.7",
            ],
            evidence=Evidence(extra={
                "host": host,
                "domain": domain,
                "affected_accounts": accounts[:30],
            }),
            cvss_v31_vector=CVSS_CRIT,
            mitre_attack=["TA0006/T1003.003"],
            target=host, service="winrm", confidence="HIGH",
        )

    # ── AdminSDHolder orphans ────────────────────────────────────────────────

    async def _check_adminsdholder(self, host: str, domain: str, winrm, session) -> None:
        """Detect accounts with AdminCount=1 that are not in any protected group."""
        result = await winrm.execute(session, _PS_ADMINSDHOLDER)
        if not result.success:
            return

        rows = _parse_csv_rows(result.stdout)
        if not rows:
            return

        orphans = [
            {"sam": r.get("SamAccountName"), "name": r.get("Name")}
            for r in rows
        ]

        self.new_finding(
            title=f"AdminSDHolder Orphan Accounts ({len(orphans)}) — AdminCount=1 Outside Protected Groups — {host}",
            severity=Severity.HIGH,
            description=(
                f"{len(orphans)} account(s) have AdminCount=1 but are not members of any currently "
                f"protected group (Domain Admins, Enterprise Admins, etc.). "
                f"AdminCount=1 marks accounts protected by AdminSDHolder, meaning the SDProp process "
                f"overrides their ACLs every 60 minutes, removing inheritance and setting restrictive "
                f"permissions from the AdminSDHolder object. "
                f"Orphaned accounts with AdminCount=1 retain these non-inheriting ACLs permanently "
                f"even after removal from privileged groups — attackers can exploit these "
                f"misconfigured ACLs for persistence or privilege escalation if they can write "
                f"to the AdminSDHolder object.\n\n"
                f"Orphaned accounts: "
                + ", ".join(o["sam"] for o in orphans[:15])
            ),
            reproduction_steps=[
                "# Identify orphaned AdminCount accounts:",
                "Get-ADUser -Filter {AdminCount -eq 1} -Properties AdminCount | "
                "Select-Object Name,SamAccountName",
                "# Check ACL on one of these accounts for unexpected writable ACEs:",
                "Get-Acl 'AD:CN=<username>,CN=Users,DC=domain,DC=local' | "
                "Select-Object -ExpandProperty Access",
            ],
            remediation=(
                "1. Reset AdminCount to 0 on orphaned accounts: "
                "Get-ADUser -Filter {AdminCount -eq 1} | "
                "<filter out actual protected members> | "
                "Set-ADObject -Replace @{adminCount=0}. "
                "2. Re-enable ACL inheritance on these accounts: "
                "$acl = Get-Acl 'AD:CN=<user>,...'; "
                "$acl.SetAccessRuleProtection($false, $true); Set-Acl ... $acl. "
                "3. Review each orphan to determine if it was previously over-privileged. "
                "4. Audit AdminSDHolder ACL for unexpected ACEs: "
                "Get-Acl 'AD:CN=AdminSDHolder,CN=System,DC=domain,DC=local'"
            ),
            references=[
                "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory",
                "https://attack.mitre.org/techniques/T1098/",
                "https://adsecurity.org/?p=2786",
            ],
            evidence=Evidence(extra={
                "host": host,
                "domain": domain,
                "orphaned_adminsdholder_accounts": orphans[:30],
            }),
            cvss_v31_vector=CVSS_HIGH,
            mitre_attack=["TA0003/T1098", "TA0004/T1078.002"],
            target=host, service="winrm", confidence="MEDIUM",
        )
