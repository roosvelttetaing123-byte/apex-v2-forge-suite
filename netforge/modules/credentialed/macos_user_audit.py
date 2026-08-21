"""macOS User and Privilege Audit — SSH credentialed check.

Audits macOS user accounts and privilege configuration via SSH including:
  - Admin group membership
  - UID 0 accounts
  - Empty password accounts
  - Sudoers NOPASSWD entries
  - Guest account status
  - Password policy
  - SSH authorized_keys audit
  - Cron jobs
  - Setuid binaries
"""
from __future__ import annotations

import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_CRIT  = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
CVSS_HIGH  = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
CVSS_MED   = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"
CVSS_LOW   = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"

# Known legitimate macOS setuid binaries (non-exhaustive, based on macOS 14/15 defaults)
KNOWN_MACOS_SUID = {
    "/usr/bin/at",
    "/usr/bin/atq",
    "/usr/bin/atrm",
    "/usr/bin/batch",
    "/usr/bin/crontab",
    "/usr/bin/login",
    "/usr/bin/newgrp",
    "/usr/bin/passwd",
    "/usr/bin/rlogin",
    "/usr/bin/rsh",
    "/usr/bin/su",
    "/usr/bin/sudo",
    "/usr/bin/wall",
    "/usr/bin/write",
    "/usr/lib/sa/sadc",
    "/usr/libexec/security_authtrampoline",
    "/usr/sbin/traceroute",
    "/usr/sbin/traceroute6",
    "/bin/ps",
    "/sbin/mount_nfs",
    "/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent",
}

# System service accounts to exclude from "admin users" concern
MACOS_SYSTEM_ACCOUNTS = {
    "_amavisd", "_appinstalld", "_appserver", "_appleevents", "_appowner",
    "_appstore", "_ard", "_assetcache", "_astris", "_audioclocksyncd",
    "_avbdeviced", "_calendar", "_captiveagent", "_ces", "_cmiodalassistants",
    "_coreaudiod", "_coreml", "_ctkd", "_cvmsroot", "_cvs", "_cyrus",
    "_datadetectors", "_dbserver", "_demod", "_devicemgr", "_displaypolicyd",
    "_distnote", "_dovecot", "_dpaudio", "_dtrace", "_eppc", "_findmydevice",
    "_ftp", "_games", "_geod", "_hidd", "_iconservices", "_installcoordinationd",
    "_installer", "_jabber", "_kadmin_admin", "_kadmin_changepw", "_krb_anonymous",
    "_krb_changepw", "_krb_kadmin", "_krb_kerberos", "_krb_krbtgt", "_krbfast",
    "_launchservicesd", "_lda", "_locationd", "_logd", "_lp", "_mailman",
    "_mbsetupuser", "_mcxalr", "_mdnsresponder", "_mobileasset", "_mysql",
    "_netbios", "_netstatistics", "_networkd", "_nsurlsessiond", "_nsurlstoraged",
    "_ondemand", "_postfix", "_postgres", "_qtss", "_reportsmemory", "_rmd",
    "_sandbox", "_screensaver", "_securityagent", "_softwareupdate", "_spotlight",
    "_sshd", "_svn", "_taskgated", "_teamsserver", "_timed", "_timezone",
    "_tokend", "_trustd", "_trustevaluationagent", "_unknown", "_update_sharing",
    "_usbmuxd", "_uucp", "_warmd", "_webauthserver", "_windowserver",
    "_www", "_wwwproxy", "_xserverdocs",
    "daemon", "nobody", "root",
}


class MacosUserAudit(BaseModule):
    NAME        = "macos_user_audit"
    DESCRIPTION = "SSH credentialed: macOS user accounts, privilege, sudo, authorized_keys, suid audit"
    PHASE       = 5
    TAGS        = ["credentialed", "macos", "users", "privilege", "compliance"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        transport_mgr = self.config.extra.get("transport_manager")
        if not transport_mgr or not transport_mgr.has_creds("ssh"):
            return self._make_result(start, skipped=True, skip_reason="no SSH credentials")

        hosts = self.config.extra.get("live_hosts", [self.config.target])
        for host in hosts[:30]:
            if not self.check_scope(host):
                continue
            await self.rate_limit()
            session = await transport_mgr.get_ssh_session(host)
            if not session:
                continue

            # Verify this is macOS before running macOS-specific checks
            os_check = await transport_mgr.ssh.execute(session, "uname -s")
            if "Darwin" not in (os_check.stdout or ""):
                continue

            await self._audit_host(host, transport_mgr.ssh, session)

        return self._make_result(start)

    async def _audit_host(self, host: str, ssh, session) -> None:
        """Run all macOS user and privilege checks."""
        await self._check_admin_users(host, ssh, session)
        await self._check_uid0_accounts(host, ssh, session)
        await self._check_empty_passwords(host, ssh, session)
        await self._check_sudoers_nopasswd(host, ssh, session)
        await self._check_guest_account(host, ssh, session)
        await self._check_password_policy(host, ssh, session)
        await self._check_authorized_keys(host, ssh, session)
        await self._check_cron_jobs(host, ssh, session)
        await self._check_suid_binaries(host, ssh, session)

    # ── Check 1: Admin group members ─────────────────────────────────────────

    async def _check_admin_users(self, host: str, ssh, session) -> None:
        """List all users in the admin group."""
        result = await ssh.execute(
            session,
            "dscl . -read /Groups/admin GroupMembership 2>/dev/null"
        )
        raw = (result.stdout or "").strip()
        if not raw or not result.success:
            return

        # Output: "GroupMembership: user1 user2 ..."
        members = []
        for line in raw.splitlines():
            if "GroupMembership:" in line:
                parts = line.replace("GroupMembership:", "").split()
                members = [u.strip() for u in parts if u.strip() and u not in MACOS_SYSTEM_ACCOUNTS]

        if len(members) > 3:
            # More than a few admin users is concerning
            self.new_finding(
                title=f"Excessive Local Admin Users ({len(members)}) — {host}",
                severity=Severity.MEDIUM,
                description=(
                    f"Found {len(members)} user(s) in the macOS admin group on {host}: "
                    f"{', '.join(members[:15])}. "
                    f"Admin group members can use sudo for privilege escalation to root "
                    f"without any additional barriers if standard sudo configuration is in place. "
                    f"The principle of least privilege requires that only users who genuinely "
                    f"need local admin rights are granted them. Excessive admin accounts increase "
                    f"the blast radius of any credential compromise."
                ),
                reproduction_steps=[
                    f"ssh {host}",
                    "dscl . -read /Groups/admin GroupMembership",
                    "# List all users who can sudo/gain root",
                ],
                remediation=(
                    "Remove unnecessary users from the admin group: "
                    "sudo dscl . -delete /Groups/admin GroupMembership <username>. "
                    "Or: System Settings → Users & Groups → change user from Administrator to Standard. "
                    "Review each admin account and confirm business justification."
                ),
                references=[
                    "CWE-250",
                    "CIS macOS Benchmark 5.6",
                    "https://attack.mitre.org/techniques/T1078.003/",
                ],
                evidence=Evidence(extra={"host": host, "admin_users": members[:30]}),
                cvss_v31_vector=CVSS_MED,
                mitre_attack=["TA0004/T1078.003"],
                target=host, service="ssh", confidence="HIGH",
            )

    # ── Check 2: UID 0 accounts ──────────────────────────────────────────────

    async def _check_uid0_accounts(self, host: str, ssh, session) -> None:
        """Find accounts with UID 0 other than root."""
        result = await ssh.execute(
            session,
            "dscl . -list /Users UniqueID 2>/dev/null | awk '$2 == 0 {print $1}'"
        )
        raw = (result.stdout or "").strip()
        if not raw or not result.success:
            return

        uid0_users = [u.strip() for u in raw.splitlines() if u.strip() and u.strip() != "root"]
        if uid0_users:
            self.new_finding(
                title=f"Non-Root Accounts With UID 0 Found — {host}",
                severity=Severity.CRITICAL,
                description=(
                    f"Found {len(uid0_users)} account(s) with UID 0 (root equivalent) "
                    f"besides the root account on {host}: {', '.join(uid0_users)}. "
                    f"UID 0 accounts have full unrestricted root access to the system. "
                    f"These accounts bypass all permission checks. Their presence outside of "
                    f"the built-in root account is almost always a sign of backdoor "
                    f"installation or intentional privilege escalation. "
                    f"This technique is commonly used by attackers for persistence (T1098)."
                ),
                reproduction_steps=[
                    f"ssh {host}",
                    "dscl . -list /Users UniqueID | awk '$2 == 0 {print $1}'",
                    "# Or: awk -F: '$3 == 0' /etc/passwd",
                ],
                remediation=(
                    "1. Remove or change the UID of all non-root UID 0 accounts immediately. "
                    "2. Change UID: sudo dscl . -change /Users/<user> UniqueID 0 <new_uid>. "
                    "3. Investigate how the account received UID 0 — likely indicator of compromise. "
                    "4. Initiate incident response procedures."
                ),
                references=[
                    "CWE-250",
                    "CIS macOS Benchmark 5.6.1",
                    "https://attack.mitre.org/techniques/T1098/",
                ],
                evidence=Evidence(extra={"host": host, "uid0_accounts": uid0_users}),
                cvss_v31_vector=CVSS_CRIT,
                mitre_attack=["TA0003/T1098", "TA0004/T1068"],
                target=host, service="ssh", confidence="HIGH",
            )

    # ── Check 3: Empty password accounts ─────────────────────────────────────

    async def _check_empty_passwords(self, host: str, ssh, session) -> None:
        """Detect accounts with empty or trivially weak password fields."""
        result = await ssh.execute(
            session,
            "dscl . -list /Users Password 2>/dev/null | grep -v '\\*'"
        )
        raw = (result.stdout or "").strip()
        if not raw or not result.success:
            return

        # Filter out system accounts and accounts with "*" (locked/shadow)
        empty_pw_users = []
        for line in raw.splitlines():
            parts = line.split()
            if not parts:
                continue
            username = parts[0]
            password_field = parts[1] if len(parts) > 1 else ""
            # Skip system accounts
            if username in MACOS_SYSTEM_ACCOUNTS or username.startswith("_"):
                continue
            # Empty password field (no password set)
            if password_field == "" or (len(parts) == 1):
                empty_pw_users.append(username)

        if empty_pw_users:
            self.new_finding(
                title=f"User Accounts With No Password Set — {host}",
                severity=Severity.CRITICAL,
                description=(
                    f"Found {len(empty_pw_users)} user account(s) with no password configured "
                    f"on {host}: {', '.join(empty_pw_users[:10])}. "
                    f"Accounts without passwords can be accessed without authentication "
                    f"via SSH (if PermitEmptyPasswords is enabled) or locally via terminal. "
                    f"An attacker on the same network can switch to these accounts without "
                    f"any credential knowledge."
                ),
                reproduction_steps=[
                    f"ssh {host}",
                    "dscl . -list /Users Password",
                    "# Accounts without '*' in password field have empty/no passwords",
                    f"# Try: ssh {empty_pw_users[0]}@{host} (with empty password)",
                ],
                remediation=(
                    "Set strong passwords for all user accounts: "
                    "sudo passwd <username>. "
                    "Lock unused accounts: sudo dscl . -create /Users/<user> AuthenticationAuthority ';DisabledUser;'. "
                    "Ensure PermitEmptyPasswords no is set in sshd_config."
                ),
                references=[
                    "CWE-521",
                    "CIS macOS Benchmark 5.6.2",
                    "https://attack.mitre.org/techniques/T1078/",
                ],
                evidence=Evidence(extra={"host": host, "empty_password_users": empty_pw_users[:20]}),
                cvss_v31_vector=CVSS_CRIT,
                mitre_attack=["TA0001/T1078", "TA0006/T1110"],
                target=host, service="ssh", confidence="MEDIUM",
            )

    # ── Check 4: Sudoers NOPASSWD ────────────────────────────────────────────

    async def _check_sudoers_nopasswd(self, host: str, ssh, session) -> None:
        """Find NOPASSWD entries in sudoers that allow passwordless privilege escalation."""
        result = await ssh.execute(
            session,
            "grep -rn NOPASSWD /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v '^#'"
        )
        raw = (result.stdout or "").strip()
        if not raw or not result.success:
            return

        nopasswd_lines = [l.strip() for l in raw.splitlines() if l.strip() and "NOPASSWD" in l]
        if nopasswd_lines:
            # Check if any line grants unrestricted root (ALL = (ALL) NOPASSWD: ALL)
            is_full_root = any(
                re.search(r'ALL\s*=\s*\(ALL.*\)\s*NOPASSWD\s*:\s*ALL', line)
                for line in nopasswd_lines
            )
            severity = Severity.CRITICAL if is_full_root else Severity.HIGH

            self.new_finding(
                title=f"Sudoers NOPASSWD Entries Found ({'Full Root' if is_full_root else 'Restricted'}) — {host}",
                severity=severity,
                description=(
                    f"Found {len(nopasswd_lines)} NOPASSWD sudo rule(s) on {host}. "
                    + ("One or more rules grant UNRESTRICTED root access (ALL=(ALL) NOPASSWD:ALL). " if is_full_root else "")
                    + "NOPASSWD sudo rules allow the specified users to run commands as root "
                    f"without entering a password. This eliminates the authentication barrier "
                    f"for privilege escalation — any attacker who compromises the user's session "
                    f"(via phishing, RCE, credential theft) immediately gains root access. "
                    f"\n\nEntries found:\n"
                    + "\n".join(f"  {l}" for l in nopasswd_lines[:10])
                ),
                reproduction_steps=[
                    f"ssh <user>@{host}",
                    "sudo -l  # Shows NOPASSWD entries available to current user",
                    "sudo su  # Elevate to root without password (if ALL=(ALL) NOPASSWD:ALL)",
                    "# Or run specific allowed command: sudo <allowed-command>",
                ],
                remediation=(
                    "1. Remove ALL=(ALL) NOPASSWD:ALL rules — these grant unrestricted passwordless root. "
                    "2. For service accounts that legitimately need passwordless sudo, "
                    "scope it to only the specific commands required, not ALL. "
                    "3. Edit sudoers safely: sudo visudo. "
                    "4. Consider using sudo with timestamp-based caching (5min timeout) "
                    "rather than NOPASSWD for interactive users."
                ),
                references=[
                    "CWE-269",
                    "CIS macOS Benchmark 5.4",
                    "https://attack.mitre.org/techniques/T1548/003/",
                ],
                evidence=Evidence(extra={
                    "host": host,
                    "nopasswd_entries": nopasswd_lines[:20],
                    "full_root_access": is_full_root,
                }),
                cvss_v31_vector=CVSS_CRIT if is_full_root else CVSS_HIGH,
                mitre_attack=["TA0004/T1548.003"],
                target=host, service="ssh", confidence="HIGH",
            )

    # ── Check 5: Guest account ───────────────────────────────────────────────

    async def _check_guest_account(self, host: str, ssh, session) -> None:
        """Check if the Guest account is enabled."""
        result = await ssh.execute(
            session,
            "dscl . -read /Users/Guest 2>/dev/null | grep -i 'AuthenticationAuthority\\|UserShell\\|RealName'"
        )
        raw = (result.stdout or "").strip()

        if not raw or not result.success:
            # Try alternative approach
            result2 = await ssh.execute(
                session,
                "defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null"
            )
            raw2 = (result2.stdout or "").strip()
            if raw2 == "1":
                guest_enabled = True
            elif raw2 == "0":
                guest_enabled = False
            else:
                # No clear result, skip
                return
        else:
            # If dscl returned Guest account data without DisabledUser, it's enabled
            guest_enabled = "DisabledUser" not in raw and bool(raw)

        if guest_enabled:
            self.new_finding(
                title=f"Guest Account Enabled — {host}",
                severity=Severity.MEDIUM,
                description=(
                    f"The Guest account is enabled on {host}. "
                    f"The macOS Guest account allows unauthenticated access to a temporary "
                    f"user session. While Apple limits Guest access (no persistent storage), "
                    f"the Guest account can still be used to: access network file shares if "
                    f"guest sharing is enabled, run applications, attempt to bypass screen lock "
                    f"via Safari and local file URI bugs, and in some configurations access "
                    f"data not properly protected by per-user permissions. "
                    f"For corporate-managed Macs, the Guest account should always be disabled."
                ),
                reproduction_steps=[
                    f"ssh {host}",
                    "defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled",
                    "# 1 = enabled, 0 = disabled",
                    "# Or check login screen: Guest login option is visible",
                ],
                remediation=(
                    "Disable the Guest account: "
                    "sudo defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool false. "
                    "Or: System Settings → Users & Groups → disable Guest User. "
                    "For MDM-managed devices, enforce via configuration profile."
                ),
                references=[
                    "CIS macOS Benchmark 5.6.3",
                    "https://support.apple.com/guide/mac-help/set-up-a-guest-user-on-mac-mh11389/mac",
                ],
                evidence=Evidence(extra={"host": host, "guest_account_enabled": True}),
                cvss_v31_vector=CVSS_MED,
                mitre_attack=["TA0001/T1078.001"],
                target=host, service="ssh", confidence="MEDIUM",
            )

    # ── Check 6: Password policy ─────────────────────────────────────────────

    async def _check_password_policy(self, host: str, ssh, session) -> None:
        """Check macOS password policy configuration."""
        result = await ssh.execute(
            session,
            "pwpolicy -getaccountpolicies 2>/dev/null | head -60"
        )
        raw = (result.stdout or "").strip()

        # If pwpolicy returns empty or just "Getting global account policies", no policy is set
        no_policy = (
            not raw
            or "Getting global account policies" in raw
            or "No account policies" in raw.lower()
            or not result.success
        )

        if no_policy:
            # Also check loginwindow defaults for minimal policy hints
            result2 = await ssh.execute(
                session,
                "defaults read /Library/Preferences/com.apple.loginwindow 2>/dev/null | "
                "grep -i -E '(password|timeout|lock)'"
            )
            raw2 = (result2.stdout or "").strip()

            self.new_finding(
                title=f"No macOS Password Policy Configured — {host}",
                severity=Severity.MEDIUM,
                description=(
                    f"No system-wide password policy (via pwpolicy) is configured on {host}. "
                    f"Without a password policy, user accounts are not required to use minimum "
                    f"password length, complexity, history, or expiry. This allows users to set "
                    f"trivially weak passwords that are vulnerable to offline brute-force after "
                    f"credential capture. "
                    f"Enterprise macOS deployments should enforce password policy via MDM "
                    f"(Jamf, Mosyle, Kandji) Passcode profiles."
                ),
                reproduction_steps=[
                    f"ssh {host}",
                    "pwpolicy -getaccountpolicies",
                    "# No output or 'No account policies' = no password policy",
                ],
                remediation=(
                    "Configure password policy via MDM passcode profile (recommended for enterprise): "
                    "Minimum length: 12+, complexity: require mixed case + digit + special, "
                    "history: 10, max age: 90 days. "
                    "Or via pwpolicy for local policy (limited, prefer MDM): "
                    "sudo pwpolicy -setaccountpolicies <policy.plist>."
                ),
                references=[
                    "CIS macOS Benchmark 5.2",
                    "NIST SP 800-53 IA-5",
                ],
                evidence=Evidence(extra={
                    "host": host,
                    "password_policy": None,
                    "loginwindow_hints": raw2[:200] if raw2 else "",
                }),
                cvss_v31_vector=CVSS_MED,
                target=host, service="ssh", confidence="HIGH",
            )

    # ── Check 7: SSH authorized_keys audit ───────────────────────────────────

    async def _check_authorized_keys(self, host: str, ssh, session) -> None:
        """Find all SSH authorized_keys files and flag unexpected ones."""
        result = await ssh.execute(
            session,
            "find /Users /var/root -name 'authorized_keys' -type f 2>/dev/null"
        )
        raw = (result.stdout or "").strip()
        if not raw or not result.success:
            return

        authkey_files = [l.strip() for l in raw.splitlines() if l.strip()]
        if not authkey_files:
            return

        # Read each authorized_keys file for key count and content preview
        key_details = []
        for filepath in authkey_files[:10]:
            key_result = await ssh.execute(
                session,
                f"wc -l < {filepath} 2>/dev/null; head -3 {filepath} 2>/dev/null"
            )
            key_raw = (key_result.stdout or "").strip()
            lines = key_raw.splitlines()
            key_count = int(lines[0].strip()) if lines and lines[0].strip().isdigit() else 0
            preview = lines[1][:80] if len(lines) > 1 else ""
            key_details.append({
                "path": filepath,
                "key_count": key_count,
                "preview": preview,
            })

        self.new_finding(
            title=f"SSH authorized_keys Files Present — Review Required ({len(authkey_files)} file(s)) — {host}",
            severity=Severity.INFO,
            description=(
                f"Found {len(authkey_files)} SSH authorized_keys file(s) on {host}. "
                f"authorized_keys is the standard SSH mechanism for passwordless key-based "
                f"authentication and its presence is expected on managed systems. "
                f"This finding is informational — a manual review is required to confirm that "
                f"each key belongs to an authorized user with a documented business need. "
                f"Unauthorized keys are a known persistence mechanism (T1098.004): an attacker "
                f"who plants their public key retains access even after password resets. "
                f"\n\nFiles found:\n"
                + "\n".join(
                    f"  {d['path']} ({d['key_count']} key(s)): {d['preview']}"
                    for d in key_details[:10]
                )
            ),
            reproduction_steps=[
                f"ssh {host}",
                "find /Users /var/root -name 'authorized_keys' -type f",
                "cat /Users/<user>/.ssh/authorized_keys",
                "# Each line is a public key with optional comment (should identify key owner)",
            ],
            remediation=(
                "1. Review each key in every authorized_keys file and verify it belongs to "
                "an authorized user with a documented business need. "
                "2. Remove unrecognized keys immediately. "
                "3. Restrict SSH key access: if possible, manage SSH keys via MDM or a "
                "central key management system. "
                "4. Set permissions: chmod 600 ~/.ssh/authorized_keys; chmod 700 ~/.ssh"
            ),
            references=[
                "CWE-732",
                "https://attack.mitre.org/techniques/T1098/004/",
                "CIS macOS Benchmark 5.2.9",
            ],
            evidence=Evidence(extra={
                "host": host,
                "authorized_keys_files": key_details[:10],
            }),
            cvss_v31_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
            mitre_attack=["TA0003/T1098.004"],
            target=host, service="ssh", confidence="LOW",
        )

    # ── Check 8: Cron jobs ───────────────────────────────────────────────────

    async def _check_cron_jobs(self, host: str, ssh, session) -> None:
        """Enumerate user and system cron jobs and flag unexpected entries."""
        # Get list of non-system users
        users_result = await ssh.execute(
            session,
            "dscl . -list /Users 2>/dev/null | grep -v '^_'"
        )
        users_raw = (users_result.stdout or "").strip()
        users = [u.strip() for u in users_raw.splitlines()
                 if u.strip() and u.strip() not in MACOS_SYSTEM_ACCOUNTS]

        cron_entries = []

        # Check per-user crontabs
        for user in users[:20]:
            if not user:
                continue
            cron_result = await ssh.execute(
                session,
                f"crontab -u {user} -l 2>/dev/null | grep -v '^#' | grep -v '^$'"
            )
            cron_raw = (cron_result.stdout or "").strip()
            if cron_raw and cron_result.success:
                for line in cron_raw.splitlines():
                    if line.strip():
                        cron_entries.append({"user": user, "cron": line.strip()[:200]})

        # Check /etc/crontab and /var/at/tabs/
        system_cron_result = await ssh.execute(
            session,
            "cat /etc/crontab 2>/dev/null | grep -v '^#' | grep -v '^$'; "
            "ls /var/at/tabs/ 2>/dev/null"
        )
        sys_raw = (system_cron_result.stdout or "").strip()
        if sys_raw:
            for line in sys_raw.splitlines():
                if line.strip() and not line.startswith("#"):
                    cron_entries.append({"user": "system", "cron": line.strip()[:200]})

        if cron_entries:
            # Require download-then-execute patterns to avoid FP on legitimate health-check
            # cron jobs that use curl/wget for monitoring. Single-tool presence alone is not
            # sufficient — it must be combined with a shell pipe/exec indicator or
            # an inherently dangerous primitive (mkfifo, eval, /tmp/ execution).
            def _is_suspicious(cron_cmd: str) -> bool:
                c = cron_cmd.lower()
                # Download-then-execute: curl/wget piped to a shell
                if re.search(r"(curl|wget)\s.*\|\s*(ba)?sh", c):
                    return True
                # Download-then-execute: wget -O- / curl -s ... | sh variant
                if re.search(r"(curl|wget)\s.*(bash|sh)\b", c) and "|" in c:
                    return True
                # base64 decode piped into shell
                if re.search(r"base64\s.*\|\s*(ba)?sh", c):
                    return True
                if "base64" in c and re.search(r"\|\s*(ba)?sh", c):
                    return True
                # Raw eval with dynamic content
                if re.search(r"eval\s*[\(\$`]", c):
                    return True
                # mkfifo / netcat backdoor pattern
                if "mkfifo" in c and ("nc " in c or "ncat" in c or "bash" in c):
                    return True
                # Execute binary from /tmp
                if re.search(r"/tmp/\S+\.(sh|py|pl|rb|elf|bin)\b", c):
                    return True
                # Pure mkfifo (named pipe creation — unusual in cron)
                if "mkfifo" in c:
                    return True
                return False

            suspicious = [e for e in cron_entries if _is_suspicious(e["cron"])]

            severity = Severity.HIGH if suspicious else Severity.LOW

            self.new_finding(
                title=f"Cron Jobs Found on macOS — {'Suspicious Entries Detected' if suspicious else str(len(cron_entries)) + ' entries'} — {host}",
                severity=severity,
                description=(
                    f"Found {len(cron_entries)} cron job(s) on {host}. "
                    + (f"{len(suspicious)} entries contain potentially suspicious commands "
                       f"(curl/wget/python/base64/netcat/bash -c). " if suspicious else "")
                    + "On macOS, cron is less commonly used than LaunchDaemons/LaunchAgents. "
                    f"Unexpected cron jobs can indicate persistence mechanisms (T1053.003). "
                    f"\n\nCron entries:\n"
                    + "\n".join(
                        f"  [{e['user']}] {e['cron']}"
                        + (" *** SUSPICIOUS ***" if e in suspicious else "")
                        for e in cron_entries[:15]
                    )
                ),
                reproduction_steps=[
                    f"ssh {host}",
                    "for u in $(dscl . -list /Users | grep -v '^_'); do crontab -u $u -l 2>/dev/null; done",
                    "cat /etc/crontab",
                ],
                remediation=(
                    "1. Verify each cron job is authorized and documented. "
                    "2. Remove any unauthorized cron jobs: crontab -u <user> -e. "
                    "3. Investigate any cron job containing network access tools (curl/wget) "
                    "or obfuscated commands (base64). These are common malware persistence mechanisms. "
                    "4. Consider using LaunchDaemons with proper plist signing for legitimate scheduled tasks."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1053/003/",
                    "CIS macOS Benchmark 6.1.1",
                ],
                evidence=Evidence(extra={
                    "host": host,
                    "cron_entries": cron_entries[:30],
                    "suspicious_entries": suspicious[:10],
                }),
                cvss_v31_vector=CVSS_HIGH if suspicious else CVSS_LOW,
                mitre_attack=["TA0003/T1053.003"],
                target=host, service="ssh", confidence="HIGH" if suspicious else "MEDIUM",
            )

    # ── Check 9: Setuid binaries ─────────────────────────────────────────────

    async def _check_suid_binaries(self, host: str, ssh, session) -> None:
        """Find setuid binaries and compare against known-good macOS list."""
        result = await ssh.execute(
            session,
            "find / -perm -4000 -type f 2>/dev/null | head -50"
        )
        raw = (result.stdout or "").strip()
        if not raw or not result.success:
            return

        found_suid = {l.strip() for l in raw.splitlines() if l.strip()}

        # Find unexpected suid binaries (not in known macOS set)
        unexpected = sorted(found_suid - KNOWN_MACOS_SUID)

        if unexpected:
            # Higher severity for things in writable locations or /tmp
            in_writable = [p for p in unexpected if any(
                p.startswith(prefix) for prefix in
                ["/tmp/", "/var/folders/", "/Users/", "/opt/", "/usr/local/"]
            )]
            severity = Severity.CRITICAL if in_writable else Severity.MEDIUM

            self.new_finding(
                title=f"Unexpected Setuid Binaries Found ({len(unexpected)}) — {host}",
                severity=severity,
                description=(
                    f"Found {len(unexpected)} setuid binary/binaries not in the known macOS default "
                    f"setuid list on {host}:\n"
                    + "\n".join(f"  {p}" for p in unexpected[:20])
                    + ("\n\nCRITICAL: Some setuid binaries are in writable/user directories: "
                       + ", ".join(in_writable[:5]) if in_writable else "")
                    + "\n\nSetuid binaries run with the file owner's privileges (typically root) "
                    f"regardless of who executes them. Unexpected setuid binaries are a primary "
                    f"privilege escalation and rootkit persistence technique (T1548.001). "
                    f"Attackers copy shells or exploit-specific binaries with the setuid bit set "
                    f"to maintain root access."
                ),
                reproduction_steps=[
                    f"ssh {host}",
                    "find / -perm -4000 -type f 2>/dev/null",
                    "# Compare against Apple-signed binaries:",
                    f"codesign -v --deep {unexpected[0]} 2>&1" if unexpected else "",
                    "ls -la " + " ".join(unexpected[:5]),
                ],
                remediation=(
                    "1. For each unexpected setuid binary: "
                    "   a. Verify the binary is legitimately installed by a known application. "
                    "   b. Check code signature: codesign -dv --verbose=4 <path>. "
                    "   c. Remove or clear setuid bit if not required: chmod -s <path>. "
                    "2. For binaries in user-writable directories: remove immediately and "
                    "investigate for active compromise. "
                    "3. Cross-reference with installed applications and package managers (Homebrew). "
                    "4. Implement periodic setuid auditing via MDM compliance policy."
                ),
                references=[
                    "CWE-250",
                    "https://attack.mitre.org/techniques/T1548/001/",
                    "CIS macOS Benchmark 6.1",
                ],
                evidence=Evidence(extra={
                    "host": host,
                    "unexpected_suid": unexpected[:30],
                    "in_writable_locations": in_writable[:10],
                }),
                cvss_v31_vector=CVSS_CRIT if in_writable else CVSS_MED,
                mitre_attack=["TA0004/T1548.001", "TA0003/T1574"],
                target=host, service="ssh", confidence="HIGH",
            )
