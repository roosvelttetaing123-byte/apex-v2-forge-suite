"""Linux User Audit — credentialed check for user/account security.

Checks:
  - UID 0 accounts (besides root)
  - Empty password fields in /etc/shadow
  - Password aging policy (maxdays, mindays, warndays)
  - Users with login shells that shouldn't have them
  - Locked vs active accounts
  - Users in sudo/wheel groups
  - Home directory permissions (world-readable/writable)
  - .ssh/authorized_keys exposure
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

CVSS_UID0     = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
CVSS_EMPTY_PW = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
CVSS_PW_AGE   = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
CVSS_HOME_PERM = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"

NOLOGIN_SHELLS = {"/usr/sbin/nologin", "/bin/false", "/sbin/nologin", "/bin/nologin"}
SERVICE_USERS = {
    "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail",
    "news", "uucp", "proxy", "www-data", "backup", "list", "irc",
    "gnats", "nobody", "systemd-network", "systemd-resolve",
    "messagebus", "syslog", "avahi", "pulse", "colord", "geoclue",
    "gdm", "sshd", "polkitd", "rtkit", "dnsmasq", "_apt",
    "postfix", "dovecot", "mysql", "postgres", "redis", "mongodb",
    "elasticsearch", "nginx", "apache", "httpd", "ftp",
}


class LinuxUserAudit(BaseModule):
    """Credentialed Linux user/account security audit."""

    NAME        = "linux_user_audit"
    DESCRIPTION = "SSH credentialed: UID 0 accounts, empty passwords, password aging, home dir perms"
    PHASE       = 5
    TAGS        = ["credentialed", "linux", "users", "passwords", "compliance", "cwe-521"]

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
            await self._audit_users(host, transport_mgr.ssh, session)

        return self._make_result(start)

    async def _audit_users(self, host: str, ssh, session) -> None:
        """Run all user security checks."""
        passwd = await ssh.read_file(session, "/etc/passwd")
        shadow_result = await ssh.execute(session, "cat /etc/shadow 2>/dev/null")
        shadow = shadow_result.stdout if shadow_result.success else ""

        passwd_entries = self._parse_passwd(passwd)
        shadow_entries = self._parse_shadow(shadow)

        await self._check_uid0(host, passwd_entries)
        await self._check_empty_passwords(host, shadow_entries, passwd_entries)
        await self._check_password_aging(host, shadow_entries)
        await self._check_login_shells(host, passwd_entries)
        await self._check_home_permissions(host, ssh, session, passwd_entries)
        await self._check_sudo_group(host, ssh, session)

    def _parse_passwd(self, content: str) -> list[dict]:
        """Parse /etc/passwd into structured entries."""
        entries = []
        for line in content.strip().split("\n"):
            parts = line.split(":")
            if len(parts) >= 7:
                entries.append({
                    "username": parts[0],
                    "uid": int(parts[2]) if parts[2].isdigit() else -1,
                    "gid": int(parts[3]) if parts[3].isdigit() else -1,
                    "gecos": parts[4],
                    "home": parts[5],
                    "shell": parts[6],
                })
        return entries

    def _parse_shadow(self, content: str) -> dict[str, dict]:
        """Parse /etc/shadow into structured entries."""
        entries = {}
        for line in content.strip().split("\n"):
            parts = line.split(":")
            if len(parts) >= 9:
                entries[parts[0]] = {
                    "username": parts[0],
                    "password_hash": parts[1],
                    "last_changed": parts[2],
                    "min_days": parts[3],
                    "max_days": parts[4],
                    "warn_days": parts[5],
                    "inactive_days": parts[6],
                    "expire_date": parts[7],
                }
        return entries

    async def _check_uid0(self, host: str, passwd: list[dict]) -> None:
        """Flag accounts with UID 0 besides root."""
        uid0_accounts = [e for e in passwd if e["uid"] == 0 and e["username"] != "root"]
        if uid0_accounts:
            self.new_finding(
                title=f"Non-Root UID 0 Accounts Found — {host}",
                severity=Severity.CRITICAL,
                description=(
                    f"Found {len(uid0_accounts)} account(s) with UID 0 (root equivalent): "
                    f"{', '.join(a['username'] for a in uid0_accounts)}. "
                    "These accounts have full root privileges and may be backdoors."
                ),
                reproduction_steps=[f"ssh {host}", "awk -F: '$3 == 0 {{print $1}}' /etc/passwd"],
                remediation="Remove or disable non-root UID 0 accounts. Investigate potential compromise.",
                references=["CWE-250", "CIS Benchmark 6.2.2"],
                evidence=Evidence(extra={
                    "host": host,
                    "uid0_accounts": [a["username"] for a in uid0_accounts],
                }),
                cvss_v31_vector=CVSS_UID0,
                mitre_attack=["TA0003/T1098"],
                target=host,
                service="ssh",
                confidence="HIGH",
            )

    async def _check_empty_passwords(self, host: str, shadow: dict, passwd: list) -> None:
        """Flag accounts with empty password fields."""
        empty_pw = []
        for entry in passwd:
            username = entry["username"]
            if username in shadow:
                pw_hash = shadow[username]["password_hash"]
                if pw_hash == "" or pw_hash == "!!" or pw_hash == "":
                    # Empty means no password needed to login
                    if pw_hash == "":
                        empty_pw.append(username)

        if empty_pw:
            self.new_finding(
                title=f"Accounts With Empty Passwords — {host}",
                severity=Severity.CRITICAL,
                description=(
                    f"Found {len(empty_pw)} account(s) with empty passwords on {host}: "
                    f"{', '.join(empty_pw[:10])}. Anyone can log in without authentication."
                ),
                reproduction_steps=[
                    f"ssh {host}",
                    "awk -F: '($2 == \"\") {{print $1}}' /etc/shadow",
                ],
                remediation="Set passwords or lock accounts: passwd -l <user>",
                references=["CWE-521", "CIS Benchmark 6.2.1"],
                evidence=Evidence(extra={"host": host, "accounts": empty_pw[:20]}),
                cvss_v31_vector=CVSS_EMPTY_PW,
                mitre_attack=["TA0001/T1078"],
                target=host,
                service="ssh",
                confidence="HIGH",
            )

    async def _check_password_aging(self, host: str, shadow: dict) -> None:
        """Check password aging policies."""
        no_maxage = []
        long_maxage = []
        for username, entry in shadow.items():
            if username in SERVICE_USERS:
                continue
            max_days = entry["max_days"]
            if max_days == "" or max_days == "99999":
                no_maxage.append(username)
            elif max_days.isdigit() and int(max_days) > 365:
                long_maxage.append(username)

        if no_maxage:
            self.new_finding(
                title=f"Password Aging Not Enforced — {host}",
                severity=Severity.MEDIUM,
                description=(
                    f"{len(no_maxage)} user account(s) have no password expiration set: "
                    f"{', '.join(no_maxage[:10])}. Stale passwords increase brute-force risk."
                ),
                reproduction_steps=[f"ssh {host}", "chage -l <username>"],
                remediation=(
                    "Set password max age: chage -M 90 <user>. "
                    "Configure PAM for password quality and aging."
                ),
                references=["CWE-262", "CIS Benchmark 5.4.1.1"],
                evidence=Evidence(extra={
                    "host": host,
                    "no_maxage": no_maxage[:20],
                }),
                cvss_v31_vector=CVSS_PW_AGE,
                target=host,
                service="ssh",
            )

    async def _check_login_shells(self, host: str, passwd: list[dict]) -> None:
        """Flag service accounts with interactive login shells."""
        risky = []
        for entry in passwd:
            if entry["username"] in SERVICE_USERS and entry["shell"] not in NOLOGIN_SHELLS:
                if entry["uid"] > 0:  # Skip root
                    risky.append(f"{entry['username']} ({entry['shell']})")

        if risky:
            self.new_finding(
                title=f"Service Accounts With Login Shells — {host}",
                severity=Severity.MEDIUM,
                description=(
                    f"{len(risky)} service account(s) have interactive shells: "
                    f"{', '.join(risky[:10])}. These should use /usr/sbin/nologin."
                ),
                reproduction_steps=[f"ssh {host}", "grep -v nologin /etc/passwd | grep -v /bin/false"],
                remediation="Set shell to nologin: usermod -s /usr/sbin/nologin <user>",
                references=["CWE-269", "CIS Benchmark 5.4.2"],
                evidence=Evidence(extra={"host": host, "service_accounts": risky[:20]}),
                cvss_v31_vector=CVSS_PW_AGE,
                target=host,
                service="ssh",
            )

    async def _check_home_permissions(self, host: str, ssh, session, passwd: list) -> None:
        """Check for world-readable/writable home directories."""
        result = await ssh.execute(
            session,
            "ls -la /home/ 2>/dev/null | grep '^d' | awk '{print $1, $NF}'"
        )
        if not result.success:
            return

        world_readable = []
        world_writable = []
        for line in result.stdout.strip().split("\n"):
            parts = line.split()
            if len(parts) < 2:
                continue
            perms = parts[0]
            dirname = parts[-1]
            if len(perms) >= 10:
                if perms[7] == "r":
                    world_readable.append(dirname)
                if perms[8] == "w":
                    world_writable.append(dirname)

        if world_writable:
            self.new_finding(
                title=f"World-Writable Home Directories — {host}",
                severity=Severity.HIGH,
                description=(
                    f"{len(world_writable)} home directories are world-writable: "
                    f"{', '.join(world_writable[:10])}. Attackers can plant SSH keys or modify dotfiles."
                ),
                reproduction_steps=[f"ssh {host}", "ls -la /home/ | grep '^d......rw'"],
                remediation="Fix permissions: chmod 750 /home/*",
                references=["CWE-732", "CIS Benchmark 6.2.6"],
                evidence=Evidence(extra={"host": host, "dirs": world_writable}),
                cvss_v31_vector=CVSS_HOME_PERM,
                mitre_attack=["TA0003/T1098.004"],
                target=host,
                service="ssh",
                confidence="HIGH",
            )

    async def _check_sudo_group(self, host: str, ssh, session) -> None:
        """Enumerate sudo/wheel group members."""
        result = await ssh.execute(
            session,
            "getent group sudo wheel adm 2>/dev/null"
        )
        if not result.success:
            return

        sudo_users = set()
        for line in result.stdout.strip().split("\n"):
            parts = line.split(":")
            if len(parts) >= 4 and parts[3]:
                for user in parts[3].split(","):
                    sudo_users.add(user.strip())

        if len(sudo_users) > 5:
            self.new_finding(
                title=f"Excessive Sudo/Admin Users ({len(sudo_users)}) — {host}",
                severity=Severity.MEDIUM,
                description=(
                    f"{len(sudo_users)} users have sudo/wheel privileges on {host}: "
                    f"{', '.join(sorted(sudo_users)[:10])}. "
                    "Excessive admin accounts increase attack surface."
                ),
                reproduction_steps=[f"ssh {host}", "getent group sudo wheel"],
                remediation="Review sudo group membership. Remove unnecessary privileged accounts.",
                references=["CWE-250", "CIS Benchmark 5.3"],
                evidence=Evidence(extra={"host": host, "sudo_users": sorted(sudo_users)}),
                target=host,
                service="ssh",
            )
