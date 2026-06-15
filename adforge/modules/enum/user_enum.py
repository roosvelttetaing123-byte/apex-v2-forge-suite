"""User enumeration — collect all domain users with security-relevant attributes.

Enumerates: enabled/disabled users, password-never-expires, no-preauth, adminCount=1,
stale passwords (pwdLastSet > 90 days), credentials in description field.
"""
from __future__ import annotations

import sys
import time
from datetime import datetime, timezone, timedelta
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
USER_ATTRIBUTES = [
    "sAMAccountName", "userPrincipalName", "cn", "displayName",
    "mail", "memberOf", "userAccountControl", "lastLogonTimestamp",
    "pwdLastSet", "description", "adminCount", "servicePrincipalName",
    "msDS-SupportedEncryptionTypes", "distinguishedName",
    "whenCreated", "logonCount",
]

# User Account Control (UAC) flags
UAC_ACCOUNT_DISABLED        = 0x0002
UAC_PASSWORD_NOT_REQUIRED   = 0x0020
UAC_NORMAL_ACCOUNT          = 0x0200
UAC_PASSWORD_NEVER_EXPIRES  = 0x10000
UAC_SMARTCARD_REQUIRED      = 0x40000
UAC_DONT_REQUIRE_PREAUTH    = 0x400000

# Stale password threshold (days)
PWD_STALE_DAYS = 365


class UserEnum(BaseModule):
    """Domain user enumerator — comprehensive security attribute analysis."""

    NAME        = "user_enum"
    DESCRIPTION = "Enumerate all domain users; flag high-risk accounts (no preauth, no expiry, stale pwd, etc.)"
    PHASE       = 2
    TAGS        = ["enum", "users", "ldap", "active-directory", "mitre-T1087.002"]

    async def run(self) -> ModuleResult:
        start  = time.monotonic()
        domain = self.config.extra.get("domain", "")
        dc_ip  = self.config.extra.get("dc", self.config.target)

        if not self.check_scope(dc_ip):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        client = LdapClient(
            dc_ip=dc_ip, domain=domain,
            username=self.config.extra.get("username", ""),
            password=self.config.extra.get("password", ""),
            nt_hash=self.config.extra.get("hash", ""),
        )

        if not client.connect():
            self.log.warning("LDAP connection failed to %s", dc_ip)
            return self._make_result(start)

        try:
            await self.rate_limit()
            users = client.search(
                "(&(objectCategory=person)(objectClass=user))",
                USER_ATTRIBUTES,
            )
            self.log.info("Found %d domain user object(s)", len(users))

            # Populate shared state for downstream modules
            enabled_users = [
                u.get("sAMAccountName", "")
                for u in users
                if u.get("sAMAccountName") and
                not (int(str(u.get("userAccountControl", 0) or 0)) & UAC_ACCOUNT_DISABLED)
            ]
            self.config.extra["domain_users"]  = enabled_users
            self.config.extra["user_objects"]  = users

            # Analyze and generate findings
            self._analyze_users(users, domain, dc_ip)

        finally:
            client.disconnect()

        return self._make_result(start)

    def _analyze_users(
        self, users: list[dict], domain: str, dc_ip: str
    ) -> None:
        no_preauth:  list[str] = []
        no_expiry:   list[str] = []
        no_pwd_req:  list[str] = []
        desc_creds:  list[str] = []
        stale_pwd:   list[dict] = []
        admin_users: list[str] = []
        disabled:    list[str] = []

        now_utc = datetime.now(timezone.utc)
        stale_cutoff = now_utc - timedelta(days=PWD_STALE_DAYS)

        for user in users:
            name = str(user.get("sAMAccountName", "?") or "?")
            uac  = int(str(user.get("userAccountControl", 0) or 0))
            desc = str(user.get("description", "") or "")

            is_disabled = bool(uac & UAC_ACCOUNT_DISABLED)
            if is_disabled:
                disabled.append(name)

            # DONT_REQUIRE_PREAUTH — AS-REP roastable
            if uac & UAC_DONT_REQUIRE_PREAUTH and not is_disabled:
                no_preauth.append(name)

            # PASSWORD_NEVER_EXPIRES
            if uac & UAC_PASSWORD_NEVER_EXPIRES and not is_disabled:
                no_expiry.append(name)

            # PASSWORD_NOT_REQUIRED — blank password allowed
            if uac & UAC_PASSWORD_NOT_REQUIRED and not is_disabled:
                no_pwd_req.append(name)

            # adminCount=1 — protected by SDProp (high-privilege account)
            if int(str(user.get("adminCount") or 0)) == 1:
                admin_users.append(name)

            # Credentials in description field
            desc_lower = desc.lower()
            for kw in ["password", "passwd", "pwd", "pass:", "cred", "secret", "token"]:
                if kw in desc_lower:
                    desc_creds.append(f"{name}: {desc[:80]}")
                    break

            # Stale password — pwdLastSet older than PWD_STALE_DAYS
            pwd_last_set = user.get("pwdLastSet")
            if pwd_last_set and not is_disabled:
                try:
                    if isinstance(pwd_last_set, datetime):
                        pls = pwd_last_set.replace(tzinfo=timezone.utc) if pwd_last_set.tzinfo is None else pwd_last_set
                    elif isinstance(pwd_last_set, (int, float)):
                        # Windows FILETIME: 100-nanosecond intervals since 1601-01-01
                        if pwd_last_set > 0:
                            pls = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=pwd_last_set // 10)
                        else:
                            pls = None
                    else:
                        pls = None

                    if pls and pls < stale_cutoff:
                        age_days = (now_utc - pls).days
                        stale_pwd.append({"name": name, "age_days": age_days, "last_set": str(pls.date())})
                except Exception:
                    pass

        # Publish for downstream modules
        self.config.extra["no_preauth_accounts"] = no_preauth
        self.config.extra["admin_count_users"]   = admin_users

        # ── Finding: AS-REP Roastable accounts ──────────────────────────────────
        if no_preauth:
            self.new_finding(
                title=f"AS-REP Roastable Accounts ({len(no_preauth)}) — Kerberos Pre-Auth Disabled",
                severity=Severity.HIGH,
                description=(
                    f"{len(no_preauth)} account(s) have Kerberos pre-authentication disabled "
                    f"(UF_DONT_REQUIRE_PREAUTH): {', '.join(no_preauth[:10])}{'...' if len(no_preauth) > 10 else ''}.\n\n"
                    "These accounts can be AS-REP Roasted WITHOUT any credentials — an attacker "
                    "sends an AS-REQ with no PA-DATA and receives an encrypted hash to crack offline."
                ),
                reproduction_steps=[
                    f"impacket-GetNPUsers {domain}/ -no-pass -usersfile users.txt -dc-ip {dc_ip}",
                    "hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt",
                ],
                remediation=(
                    "Enable Kerberos pre-authentication on ALL accounts "
                    "(uncheck 'Do not require Kerberos preauthentication' in AD)."
                ),
                references=["MITRE TA0006/T1558.004", "CWE-287"],
                evidence=Evidence(extra={"accounts": no_preauth, "count": len(no_preauth)}),
                cvss_v31_vector=CVSS_HIGH,
                cvss_v40_vector=CVSS40_HIGH,
                mitre_attack=["TA0006/T1558.004"],
                target=dc_ip,
            )

        # ── Finding: Password Never Expires ─────────────────────────────────────
        if no_expiry:
            # Filter to highlight privileged accounts in the list
            priv_no_expiry = [u for u in no_expiry if u in admin_users]
            self.new_finding(
                title=f"Password Never Expires — {len(no_expiry)} Account(s)",
                severity=Severity.MEDIUM,
                description=(
                    f"{len(no_expiry)} account(s) have 'Password Never Expires' set: "
                    f"{', '.join(no_expiry[:10])}.\n\n"
                    + (
                        f"CRITICAL: {len(priv_no_expiry)} privileged (adminCount=1) accounts: "
                        f"{', '.join(priv_no_expiry[:5])}. "
                        if priv_no_expiry else ""
                    ) +
                    "Accounts without password expiration retain the same password indefinitely, "
                    "significantly increasing the window for credential-based attacks."
                ),
                reproduction_steps=[
                    "PowerShell: Get-ADUser -Filter {PasswordNeverExpires -eq $true} "
                    "-Properties PasswordNeverExpires,AdminCount | Select Name,AdminCount",
                ],
                remediation=(
                    "1. Enable password expiration for all user accounts.\n"
                    "2. Use gMSA for service accounts (auto-rotating 256-bit passwords).\n"
                    "3. If expiration must be disabled, require very strong passwords (30+ chars)."
                ),
                references=["CWE-521", "NIST SP 800-63B"],
                evidence=Evidence(extra={"accounts": no_expiry, "privileged": priv_no_expiry}),
                cvss_v31_vector=CVSS_INFO,
                cvss_v40_vector=CVSS40_INFO,
                target=dc_ip,
            )

        # ── Finding: Password Not Required (blank password allowed) ─────────────
        if no_pwd_req:
            self.new_finding(
                title=f"Password Not Required — {len(no_pwd_req)} Account(s) Allow Blank Passwords",
                severity=Severity.HIGH,
                description=(
                    f"{len(no_pwd_req)} account(s) have UF_PASSWD_NOTREQD set: "
                    f"{', '.join(no_pwd_req[:10])}.\n\n"
                    "These accounts may have an empty/blank password. "
                    "This allows unauthenticated access if the account has no password set."
                ),
                reproduction_steps=[
                    "crackmapexec smb <dc_ip> -u <account> -p '' --shares",
                    "net use \\\\<dc>\\<share> '' /user:<domain>\\<account>",
                ],
                remediation=(
                    "Set a strong password for all accounts with UF_PASSWD_NOTREQD. "
                    "Remove the flag and enforce password complexity via Group Policy."
                ),
                references=["MITRE TA0001/T1078", "CWE-521"],
                evidence=Evidence(extra={"accounts": no_pwd_req}),
                cvss_v31_vector=CVSS_HIGH,
                cvss_v40_vector=CVSS40_HIGH,
                mitre_attack=["TA0001/T1078"],
                target=dc_ip,
            )

        # ── Finding: Credentials in description field ────────────────────────────
        if desc_creds:
            self.new_finding(
                title=f"Credentials in User Description Field ({len(desc_creds)} Account(s))",
                severity=Severity.CRITICAL,
                description=(
                    f"Password-like strings found in the LDAP description field of "
                    f"{len(desc_creds)} account(s): "
                    f"{'; '.join(desc_creds[:5])}.\n\n"
                    "LDAP description is readable by ALL authenticated domain users. "
                    "Admins commonly store service account passwords here for 'convenience' — "
                    "this is directly readable by any domain account without elevated privileges."
                ),
                reproduction_steps=[
                    "ldapsearch -H ldap://<dc> -b DC=corp,DC=local -D user@corp.local -W "
                    "'(objectClass=user)' description",
                    "PowerView: Get-DomainUser -Properties SamAccountName,Description | "
                    "Where {$_.description -ne $null}",
                ],
                remediation=(
                    "Remove all passwords/credentials from description fields immediately. "
                    "Rotate any credentials that were stored there."
                ),
                references=["MITRE TA0006/T1552.001", "CWE-312"],
                evidence=Evidence(extra={"accounts": desc_creds[:20]}),
                cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                mitre_attack=["TA0006/T1552.001"],
                target=dc_ip,
            )

        # ── Finding: Stale passwords ─────────────────────────────────────────────
        if stale_pwd:
            # Highlight any with adminCount=1
            priv_stale = [u for u in stale_pwd if u["name"] in admin_users]
            self.new_finding(
                title=f"Stale Passwords (>{PWD_STALE_DAYS} Days) — {len(stale_pwd)} Account(s)",
                severity=Severity.MEDIUM if not priv_stale else Severity.HIGH,
                description=(
                    f"{len(stale_pwd)} enabled account(s) have passwords older than "
                    f"{PWD_STALE_DAYS} days.\n\n"
                    + (
                        f"PRIVILEGED accounts with stale passwords: "
                        f"{', '.join(u['name'] for u in priv_stale[:5])}.\n\n"
                        if priv_stale else ""
                    ) +
                    "Sample: " + ", ".join(
                        f"{u['name']} ({u['age_days']}d)" for u in stale_pwd[:10]
                    ) +
                    "\n\nStale passwords increase the exposure window for credential-based attacks. "
                    "Accounts not actively used should be reviewed for disabling."
                ),
                reproduction_steps=[
                    "PowerShell: Get-ADUser -Filter {Enabled -eq $true} "
                    "-Properties PasswordLastSet | Where {$_.PasswordLastSet -lt (Get-Date).AddDays(-365)}",
                ],
                remediation=(
                    f"1. Enforce password expiration policy (max {PWD_STALE_DAYS} days).\n"
                    "2. Force password reset for accounts with stale passwords.\n"
                    "3. Disable accounts not used in >90 days."
                ),
                references=["NIST SP 800-63B", "CWE-521"],
                evidence=Evidence(extra={
                    "stale_accounts": stale_pwd[:20],
                    "privileged_stale": priv_stale[:10],
                }),
                cvss_v31_vector=CVSS_INFO,
                cvss_v40_vector=CVSS40_INFO,
                target=dc_ip,
            )

        # ── Finding: adminCount=1 summary ────────────────────────────────────────
        if admin_users:
            self.log.info(
                "adminCount=1 users (protected by SDProp): %s",
                ", ".join(admin_users[:20]),
            )
            self.new_finding(
                title=f"Protected Accounts (adminCount=1) — {len(admin_users)} Users",
                severity=Severity.INFORMATIONAL,
                description=(
                    f"{len(admin_users)} user account(s) have adminCount=1, "
                    "indicating they are (or were) members of a protected group "
                    "(Domain Admins, Enterprise Admins, etc.) and have their ACL managed "
                    "by the SDProp background process.\n\n"
                    f"Accounts: {', '.join(admin_users[:20])}\n\n"
                    "NOTE: adminCount=1 is NOT removed when accounts are removed from "
                    "protected groups — 'orphaned' adminCount accounts retain restricted ACLs "
                    "without the corresponding group membership and may be attack targets."
                ),
                reproduction_steps=[
                    "PowerView: Get-DomainUser -AdminCount | Select SamAccountName,MemberOf",
                    "ldapsearch ... '(adminCount=1)' sAMAccountName memberOf",
                ],
                remediation=(
                    "Audit adminCount=1 accounts — verify they should have protected status. "
                    "Remove orphaned adminCount=1 accounts from high-privilege groups. "
                    "Run SDProp manually if stale: repadmin /syncall"
                ),
                references=["MITRE TA0004/T1078.002", "https://adsecurity.org/?p=2120"],
                evidence=Evidence(extra={"admin_accounts": admin_users}),
                cvss_v31_vector=CVSS_INFO,
                cvss_v40_vector=CVSS40_INFO,
                mitre_attack=["TA0004/T1078.002"],
                target=dc_ip,
            )

        self.log.info(
            "User analysis: %d total, preauth_disabled=%d, no_expiry=%d, "
            "no_pwd_req=%d, desc_creds=%d, stale_pwd=%d, adminCount1=%d, disabled=%d",
            len(users), len(no_preauth), len(no_expiry),
            len(no_pwd_req), len(desc_creds), len(stale_pwd), len(admin_users), len(disabled),
        )


class TestUserEnum:
    def test_uac_flags(self) -> None:
        assert UAC_PASSWORD_NEVER_EXPIRES == 0x10000
        assert UAC_DONT_REQUIRE_PREAUTH   == 0x400000
        assert UAC_PASSWORD_NOT_REQUIRED  == 0x0020
        assert UAC_ACCOUNT_DISABLED       == 0x0002

    def test_user_attributes_complete(self) -> None:
        assert "sAMAccountName"  in USER_ATTRIBUTES
        assert "adminCount"      in USER_ATTRIBUTES
        assert "pwdLastSet"      in USER_ATTRIBUTES
        assert "userAccountControl" in USER_ATTRIBUTES
        assert "description"     in USER_ATTRIBUTES

    def test_phase(self) -> None:
        assert UserEnum.PHASE == 2

    def test_stale_days(self) -> None:
        assert PWD_STALE_DAYS == 365
