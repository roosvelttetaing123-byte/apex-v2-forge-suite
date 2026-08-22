"""Windows Kerberos Misconfiguration Audit — credentialed WinRM check.

Detects Kerberoastable accounts, AS-REP Roastable accounts, stale/privileged
Kerberoastable service accounts, weak encryption types, and Golden Ticket risk.

Nessus equivalent: Plugin 210765 (Active Directory Kerberoastable Accounts).
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
CVSS_MED   = "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N"

# ── PowerShell queries ───────────────────────────────────────────────────────

_PS_KERBEROASTABLE = (
    # -like '*' correctly matches non-null SPN; -ne '$null' compares to the
    # literal string "$null" and returns ALL accounts — a false-negative bug.
    # MemberOf removed (DA cross-reference uses separate _PS_DA_MEMBERS query).
    "Get-ADUser -Filter {ServicePrincipalName -like '*'} "
    "-Properties ServicePrincipalName,PasswordLastSet,LastLogonDate,Enabled | "
    "Where-Object { $_.Enabled -eq $true -and $_.SamAccountName -ne 'krbtgt' } | "
    "Select-Object Name,SamAccountName,"
    "@{N='SPN';E={($_.ServicePrincipalName -join '|')}},PasswordLastSet,LastLogonDate | "
    "ConvertTo-Csv -NoTypeInformation"
)

_PS_ASREPROASTABLE = (
    # LDAP filter for DONT_REQUIRE_PREAUTH (UAC bit 0x400000 = 4194304).
    # More reliable across PowerShell versions than -Filter {DoesNotRequirePreAuth}
    # which can silently fail on PS v2/v3 AD provider implementations.
    "Get-ADUser -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=4194304)' "
    "-Properties DoesNotRequirePreAuth,PasswordLastSet,Enabled | "
    "Where-Object { $_.Enabled -eq $true } | "
    "Select-Object Name,SamAccountName,PasswordLastSet | "
    "ConvertTo-Csv -NoTypeInformation"
)

_PS_KRBTGT_AGE = (
    "Get-ADUser krbtgt -Properties PasswordLastSet,PasswordNeverExpires | "
    "Select-Object SamAccountName,PasswordLastSet,PasswordNeverExpires | "
    "ConvertTo-Csv -NoTypeInformation"
)

_PS_DA_MEMBERS = (
    "Get-ADGroupMember -Identity 'Domain Admins' -Recursive | "
    "Where-Object { $_.objectClass -eq 'user' } | "
    "Select-Object Name,SamAccountName,distinguishedName | "
    "ConvertTo-Csv -NoTypeInformation"
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

_PS_RC4_CHECK = (
    "$domain = Get-ADDomain; "
    "$domainObj = Get-ADObject $domain.DistinguishedName "
    "-Properties 'msDS-SupportedEncryptionTypes'; "
    "[PSCustomObject]@{ "
    "Domain = $domain.DNSRoot; "
    "SupportedEncTypes = $domainObj.'msDS-SupportedEncryptionTypes' "
    "} | ConvertTo-Csv -NoTypeInformation"
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


class WinKerberosAudit(BaseModule):
    NAME        = "win_kerberos_audit"
    DESCRIPTION = "WinRM credentialed: Kerberos misconfiguration audit — Kerberoast, ASREPRoast, Golden Ticket"
    PHASE       = 5
    TAGS        = ["credentialed", "windows", "kerberos", "asreproast", "kerberoast", "ad"]

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

            # Verify this host has AD PowerShell module available
            check = await winrm.execute(session, "Get-ADDomain | Select-Object -ExpandProperty DNSRoot")
            if not check.success or not check.stdout.strip():
                continue

            domain = check.stdout.strip()

            # Collect DA/EA members for cross-referencing
            da_rows = await self._get_da_members(host, winrm, session)
            da_sams = {r.get("SamAccountName", "").lower() for r in da_rows}

            await self._check_kerberoastable(host, domain, winrm, session, da_sams)
            await self._check_asreproastable(host, domain, winrm, session)
            await self._check_krbtgt_age(host, domain, winrm, session)
            await self._check_rc4(host, domain, winrm, session)
            # Domain-wide audit — only one host needed
            break

        return self._make_result(start)

    # ── DA member helper ────────────────────────────────────────────────────

    async def _get_da_members(self, host: str, winrm, session) -> list[dict[str, str]]:
        result = await winrm.execute(session, _PS_DA_MEMBERS)
        if not result.success:
            return []
        return _parse_csv_rows(result.stdout)

    # ── Kerberoastable ──────────────────────────────────────────────────────

    async def _check_kerberoastable(
        self, host: str, domain: str, winrm, session, da_sams: set[str]
    ) -> None:
        """Detect Kerberoastable accounts, stale ones, and privileged ones."""
        result = await winrm.execute(session, _PS_KERBEROASTABLE)
        if not result.success:
            return

        rows = _parse_csv_rows(result.stdout)
        if not rows:
            return

        stale_threshold_days = 90
        stale_accounts: list[dict] = []
        privileged_accounts: list[dict] = []
        all_accounts: list[dict] = []

        for row in rows:
            sam = row.get("SamAccountName", "")
            name = row.get("Name", "")
            spn = row.get("SPN", "")
            pwd_last_set = row.get("PasswordLastSet", "")
            last_logon = row.get("LastLogonDate", "")

            pwd_age = _days_since(pwd_last_set)
            logon_age = _days_since(last_logon) if last_logon else None

            entry = {
                "sam": sam,
                "name": name,
                "spn": spn,
                "password_last_set": pwd_last_set,
                "last_logon": last_logon,
                "pwd_age_days": pwd_age,
                "logon_age_days": logon_age,
                "is_privileged": sam.lower() in da_sams,
            }
            all_accounts.append(entry)

            # Stale: not logged in for 90+ days
            if logon_age is not None and logon_age >= stale_threshold_days:
                stale_accounts.append(entry)
            elif logon_age is None and last_logon == "":
                # Never logged in — also stale
                stale_accounts.append(entry)

            # Privileged: in Domain Admins
            if entry["is_privileged"]:
                privileged_accounts.append(entry)

        # Finding 1: All Kerberoastable accounts
        if all_accounts:
            self.new_finding(
                title=f"Kerberoastable Service Accounts ({len(all_accounts)}) — {host}",
                severity=Severity.HIGH,
                description=(
                    f"{len(all_accounts)} enabled user account(s) with ServicePrincipalNames set "
                    f"are vulnerable to Kerberoasting (T1558.003). Any authenticated domain user "
                    f"can request Kerberos TGS tickets for these accounts and attempt offline "
                    f"password cracking (hashcat/john). RC4-encrypted tickets crack significantly "
                    f"faster than AES tickets.\n\n"
                    f"Accounts: "
                    + ", ".join(
                        f"{a['sam']} (SPNs: {a['spn'][:60]}, "
                        f"pwd age: {a['pwd_age_days']}d)"
                        for a in all_accounts[:10]
                    )
                ),
                reproduction_steps=[
                    f"# Request TGS tickets for all Kerberoastable accounts:",
                    f"GetUserSPNs.py {domain}/lowpriv:Password1 -dc-ip {host} -request -outputfile kerberoast.hashes",
                    f"# Crack offline with hashcat:",
                    "hashcat -m 13100 kerberoast.hashes /usr/share/wordlists/rockyou.txt -r OneRuleToRuleThemAll.rule",
                    f"# Alternative with Rubeus (from domain-joined host):",
                    "Rubeus.exe kerberoast /outfile:hashes.txt /format:hashcat",
                ],
                remediation=(
                    "1. Set strong, random passwords (25+ chars) on all service accounts with SPNs. "
                    "2. Migrate service accounts to Managed Service Accounts (MSA/gMSA) — "
                    "passwords are 240-char random, auto-rotated, and not Kerberoastable in practice. "
                    "3. Enable AES-only encryption on service accounts: "
                    "Set-ADUser <sam> -KerberosEncryptionType AES256 (removes RC4 support). "
                    "4. Audit and remove unnecessary SPNs. "
                    "5. Monitor Event ID 4769 (TGS requested) for RC4 (etype=0x17) spikes."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1558/003/",
                    "https://github.com/fortra/impacket",
                    "https://github.com/GhostPack/Rubeus",
                    "CVE-NA — by-design Kerberos feature abuse",
                ],
                evidence=Evidence(extra={
                    "host": host,
                    "domain": domain,
                    "total_kerberoastable": len(all_accounts),
                    "accounts": all_accounts[:30],
                }),
                cvss_v31_vector=CVSS_HIGH,
                mitre_attack=["TA0006/T1558.003"],
                target=host, service="winrm", confidence="HIGH",
            )

        # Finding 2: Stale Kerberoastable accounts
        if stale_accounts:
            self.new_finding(
                title=f"Stale Kerberoastable Accounts ({len(stale_accounts)}, >{stale_threshold_days}d inactive) — {host}",
                severity=Severity.HIGH,
                description=(
                    f"{len(stale_accounts)} Kerberoastable account(s) have not logged in for "
                    f"{stale_threshold_days}+ days. Stale service accounts frequently retain weak, "
                    f"unchanged passwords (often set years ago before password complexity was enforced). "
                    f"Cracked passwords for these accounts are unlikely to trigger immediate incident "
                    f"response as the accounts show no recent activity.\n\n"
                    + "\n".join(
                        f"  {a['sam']}: last logon {a['last_logon'] or 'never'}, "
                        f"pwd age {a['pwd_age_days']}d"
                        for a in stale_accounts[:10]
                    )
                ),
                reproduction_steps=[
                    f"GetUserSPNs.py {domain}/lowpriv:Password1 -dc-ip {host} -request -outputfile stale_kerberoast.hashes",
                    "hashcat -m 13100 stale_kerberoast.hashes /usr/share/wordlists/rockyou.txt",
                ],
                remediation=(
                    "1. Disable or delete stale service accounts not required for active services. "
                    "2. For required accounts, rotate passwords to 25+ char random strings. "
                    "3. Implement a quarterly service account review process. "
                    "4. Migrate to gMSA where possible."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1558/003/",
                ],
                evidence=Evidence(extra={
                    "host": host,
                    "stale_threshold_days": stale_threshold_days,
                    "stale_accounts": stale_accounts[:20],
                }),
                cvss_v31_vector=CVSS_HIGH,
                mitre_attack=["TA0006/T1558.003"],
                target=host, service="winrm", confidence="HIGH",
            )

        # Finding 3: Privileged Kerberoastable accounts (DA members with SPN)
        if privileged_accounts:
            self.new_finding(
                title=f"HIGH-PRIVILEGE Kerberoastable Accounts in Domain Admins ({len(privileged_accounts)}) — {host}",
                severity=Severity.CRITICAL,
                description=(
                    f"{len(privileged_accounts)} account(s) are simultaneously members of Domain Admins "
                    f"AND have ServicePrincipalNames set, making them Kerberoastable. "
                    f"Successful offline cracking of any of these accounts results in immediate "
                    f"full domain compromise. This is the highest-risk Kerberoasting scenario.\n\n"
                    + "\n".join(
                        f"  {a['sam']}: SPN={a['spn'][:80]}, pwd age={a['pwd_age_days']}d"
                        for a in privileged_accounts[:10]
                    )
                ),
                reproduction_steps=[
                    f"# Target only privileged accounts:",
                    f"GetUserSPNs.py {domain}/lowpriv:Password1 -dc-ip {host} -request "
                    + " ".join(f"-usersfile {a['sam']}" for a in privileged_accounts[:3]),
                    "hashcat -m 13100 da_kerberoast.hashes /usr/share/wordlists/rockyou.txt -r best64.rule",
                    "# Use cracked credentials for full domain compromise:",
                    f"secretsdump.py {domain}/<cracked_da>:<password>@{host}",
                ],
                remediation=(
                    "1. IMMEDIATELY remove SPN(s) from Domain Admin accounts — DAs should not run services. "
                    "2. Create separate, non-privileged service accounts for services currently using DA accounts. "
                    "3. Enforce least privilege: service accounts must not be in privileged groups. "
                    "4. If SPNs are legacy and no longer needed, remove them via: "
                    "Set-ADUser <sam> -ServicePrincipalNames @{Remove='<SPN>'}."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1558/003/",
                    "CIS Control 5.4 — Use Dedicated Workstations for Privileged Access",
                ],
                evidence=Evidence(extra={
                    "host": host,
                    "privileged_kerberoastable": privileged_accounts[:20],
                }),
                cvss_v31_vector=CVSS_CRIT,
                mitre_attack=["TA0006/T1558.003", "TA0004/T1078.002"],
                target=host, service="winrm", confidence="HIGH",
            )

    # ── ASREPRoastable ──────────────────────────────────────────────────────

    async def _check_asreproastable(self, host: str, domain: str, winrm, session) -> None:
        """Detect accounts with DONT_REQUIRE_PREAUTH (AS-REP Roastable)."""
        result = await winrm.execute(session, _PS_ASREPROASTABLE)
        if not result.success:
            return

        rows = _parse_csv_rows(result.stdout)
        if not rows:
            return

        accounts = [
            {
                "sam": r.get("SamAccountName", ""),
                "name": r.get("Name", ""),
                "pwd_last_set": r.get("PasswordLastSet", ""),
                "pwd_age_days": _days_since(r.get("PasswordLastSet", "")),
            }
            for r in rows
        ]

        # Severity calibration: 1-4 accounts → HIGH (isolated misconfiguration),
        # 5+ accounts → CRITICAL (suggests systemic/domain-wide misconfiguration)
        domain_wide = len(accounts) >= 5
        severity = Severity.HIGH if not domain_wide else Severity.CRITICAL

        self.new_finding(
            title=f"AS-REP Roastable Accounts ({len(accounts)}){' — SYSTEMIC/DOMAIN-WIDE' if domain_wide else ''} — {host}",
            severity=severity,
            description=(
                f"{len(accounts)} account(s) have Kerberos pre-authentication disabled "
                f"(UF_DONT_REQUIRE_PREAUTH / DoesNotRequirePreAuth). An unauthenticated attacker "
                f"can request AS-REP responses for these accounts and crack the encrypted "
                f"component offline without providing any credentials.\n\n"
                + (
                    f"SYSTEMIC RISK: Having {len(accounts)} accounts in this state (threshold: 5+) "
                    f"suggests this may be a misconfigured domain-wide setting or bulk GPO application "
                    f"rather than individual account configuration — warranting urgent review.\n\n"
                    if domain_wide else
                    f"Severity is HIGH (isolated: {len(accounts)} account(s)). "
                    f"Would escalate to CRITICAL if 5+ accounts are affected.\n\n"
                )
                + f"Affected accounts ({len(accounts)}): "
                + ", ".join(
                    f"{a['sam']} (pwd age: {a['pwd_age_days']}d)" for a in accounts[:10]
                )
            ),
            reproduction_steps=[
                f"# No credentials required — unauthenticated AS-REP roast:",
                f"GetNPUsers.py {domain}/ -usersfile users.txt -dc-ip {host} -no-pass -format hashcat -outputfile asreproast.hashes",
                f"# Or enumerate and request simultaneously:",
                f"GetNPUsers.py {domain}/lowpriv:Password1 -dc-ip {host} -request -format hashcat",
                "hashcat -m 18200 asreproast.hashes /usr/share/wordlists/rockyou.txt",
            ],
            remediation=(
                "1. Enable Kerberos pre-authentication on all accounts: "
                "Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} | "
                "Set-ADAccountControl -DoesNotRequirePreAuth $false. "
                "2. Audit why pre-auth was disabled — legacy applications rarely require it. "
                "3. Immediately rotate passwords for affected accounts. "
                "4. Monitor Event ID 4768 (AS-REQ) for accounts where pre-auth is legitimately disabled."
            ),
            references=[
                "https://attack.mitre.org/techniques/T1558/004/",
                "https://github.com/fortra/impacket",
                "https://github.com/HarmJ0y/ASREPRoast",
            ],
            evidence=Evidence(extra={
                "host": host,
                "domain": domain,
                "asreproastable_count": len(accounts),
                "accounts": accounts[:30],
                "domain_wide_risk": domain_wide,
            }),
            cvss_v31_vector=CVSS_CRIT if domain_wide else CVSS_HIGH,
            mitre_attack=["TA0006/T1558.004"],
            target=host, service="winrm", confidence="HIGH",
        )

    # ── krbtgt password age ─────────────────────────────────────────────────

    async def _check_krbtgt_age(self, host: str, domain: str, winrm, session) -> None:
        """Detect stale krbtgt password — Golden Ticket persistence risk."""
        result = await winrm.execute(session, _PS_KRBTGT_AGE)
        if not result.success:
            return

        rows = _parse_csv_rows(result.stdout)
        if not rows:
            return

        row = rows[0]
        pwd_last_set = row.get("PasswordLastSet", "")
        pwd_age = _days_since(pwd_last_set)

        threshold = 180  # 180 days NIST/Microsoft recommendation

        if pwd_age is None or pwd_age < threshold:
            return

        self.new_finding(
            title=f"krbtgt Password Not Rotated in {pwd_age} Days (Golden Ticket Risk) — {host}",
            severity=Severity.MEDIUM,
            description=(
                f"The krbtgt account password has not been rotated since {pwd_last_set} "
                f"({pwd_age} days ago). The krbtgt password is used to sign all Kerberos tickets "
                f"in the domain. If an attacker has previously compromised the krbtgt NTLM hash "
                f"(e.g., via DCSync), they can forge Golden Tickets that remain valid until the "
                f"password is rotated TWICE. An undetected compromise may still grant persistent "
                f"access. Microsoft recommends rotating krbtgt at least every 180 days.\n\n"
                f"CALIBRATION NOTE: krbtgt staleness is near-universal in real environments — "
                f"Windows provides no automatic rotation mechanism and the rotation procedure "
                f"requires careful planning to avoid domain authentication outages. This finding "
                f"is rated MEDIUM (not HIGH) because exploitation requires a prior krbtgt hash "
                f"compromise (DCSync-level access), making it a persistence risk rather than an "
                f"independent exploit path. Escalate to HIGH if evidence of prior DC compromise exists."
            ),
            reproduction_steps=[
                "# If krbtgt hash is known (e.g., from previous compromise via DCSync):",
                f"ticketer.py -nthash <krbtgt_hash> -domain-sid <domain_sid> -domain {domain} administrator",
                "export KRB5CCNAME=administrator.ccache",
                f"psexec.py -k -no-pass {domain}/administrator@{host}",
                "# Golden tickets forged with old hash remain valid until krbtgt is rotated twice",
            ],
            remediation=(
                "1. Reset krbtgt password immediately using the Microsoft krbtgt Reset Script: "
                "https://github.com/microsoft/New-KrbtgtKeys.ps1 "
                "(must run twice within 10 hours to invalidate all existing tickets). "
                "2. Establish a recurring procedure to rotate krbtgt every 90-180 days. "
                "3. After rotation, monitor for Event ID 4769 failures indicating cached Golden Tickets. "
                "4. Review privileged access that occurred during the stale period."
            ),
            references=[
                "https://attack.mitre.org/techniques/T1558/001/",
                "https://github.com/microsoft/New-KrbtgtKeys.ps1",
                "MS-KILE: Kerberos Protocol Extensions",
                "https://adsecurity.org/?p=483",
            ],
            evidence=Evidence(extra={
                "host": host,
                "domain": domain,
                "krbtgt_password_last_set": pwd_last_set,
                "age_days": pwd_age,
                "threshold_days": threshold,
            }),
            cvss_v31_vector=CVSS_MED,
            mitre_attack=["TA0006/T1558.001"],
            target=host, service="winrm", confidence="HIGH",
        )

    # ── RC4 encryption allowed ──────────────────────────────────────────────

    async def _check_rc4(self, host: str, domain: str, winrm, session) -> None:
        """Detect if RC4 (etype 23/0x17) is still allowed domain-wide."""
        result = await winrm.execute(session, _PS_RC4_CHECK)
        if not result.success:
            return

        rows = _parse_csv_rows(result.stdout)
        if not rows:
            return

        row = rows[0]
        enc_types_raw = row.get("SupportedEncTypes", "")

        try:
            enc_types = int(enc_types_raw) if enc_types_raw.strip() else 0
        except ValueError:
            return

        # Bit flags: RC4_HMAC_MD5 = 0x4 (bit 2), AES128 = 0x8, AES256 = 0x10
        # If enc_types is 0 (not set), the domain defaults to supporting RC4
        rc4_allowed = (enc_types == 0) or bool(enc_types & 0x4)
        if not rc4_allowed:
            return

        self.new_finding(
            title=f"RC4 Kerberos Encryption Allowed Domain-Wide — {host}",
            severity=Severity.MEDIUM,
            description=(
                f"The domain '{domain}' allows RC4-HMAC (etype 0x17/23) for Kerberos encryption "
                f"(msDS-SupportedEncryptionTypes = {enc_types_raw or 'not set, defaults to RC4'}). "
                f"RC4 is a weak cipher that allows Kerberoasting hashes to be cracked significantly "
                f"faster than AES tickets. When an attacker requests a TGS, the KDC will downgrade "
                f"to RC4 if the service account supports it, even if AES is also supported. "
                f"RC4 Kerberoast hashes crack 10-20x faster than AES-256 on modern GPUs."
            ),
            reproduction_steps=[
                "# Force RC4 downgrade in Kerberoasting:",
                f"GetUserSPNs.py {domain}/lowpriv:Password1 -dc-ip {host} -request -etype rc4",
                "# RC4 hash ($krb5tgs$23$) cracks ~10x faster than AES ($krb5tgs$18$):",
                "hashcat -m 13100 rc4_hashes.txt wordlist.txt  # RC4 = etype 23",
                "# vs hashcat -m 19700 aes_hashes.txt wordlist.txt  # AES256 = etype 18",
            ],
            remediation=(
                "1. Set msDS-SupportedEncryptionTypes on the domain object to support AES only: "
                "Set-ADObject (Get-ADDomain).DistinguishedName "
                "-Replace @{'msDS-SupportedEncryptionTypes'=24}  # AES128+AES256 only. "
                "2. Test impact on legacy systems before enforcing — Windows XP/2003 require RC4. "
                "3. Set AES encryption on individual service accounts: "
                "Set-ADUser <sam> -KerberosEncryptionType AES256. "
                "4. Enable 'Network security: Configure encryption types allowed for Kerberos' GPO "
                "to AES128/AES256 only after testing legacy compatibility."
            ),
            references=[
                "https://attack.mitre.org/techniques/T1558/003/",
                "MS-KILE Section 3.3.5.6",
                "https://adsecurity.org/?p=2716",
                "CIS Benchmark for Windows Server — Kerberos Encryption Policy",
            ],
            evidence=Evidence(extra={
                "host": host,
                "domain": domain,
                "msDS_SupportedEncryptionTypes": enc_types_raw,
                "enc_types_int": enc_types,
                "rc4_bit_set": bool(enc_types & 0x4),
                "enc_types_unset_defaults_rc4": enc_types == 0,
            }),
            cvss_v31_vector=CVSS_MED,
            mitre_attack=["TA0006/T1558.003"],
            target=host, service="winrm", confidence="HIGH",
        )
