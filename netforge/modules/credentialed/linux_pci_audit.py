"""Linux PCI DSS v4.0 Compliance Audit — credentialed checks via SSH.

Covers:
  - PCI Req 1: Firewall/ACL — iptables/nftables/ufw rules, default deny
  - PCI Req 2: Secure Defaults — unnecessary services, cleartext protocols
  - PCI Req 6: Secure Systems — patch currency, WAF presence
  - PCI Req 7: Access Control — sudoers audit, NOPASSWD (critical PCI violation)
  - PCI Req 8: Authentication — password policy, root SSH login, sshd config
  - PCI Req 10: Logging — auditd/rsyslog status, log retention (logrotate)
  - PCI Req 12: Policy — NTP time synchronization
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

# CVSS vectors
CVSS_CRITICAL    = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
CVSS_HIGH_NET    = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
CVSS_HIGH_LOCAL  = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
CVSS_MEDIUM      = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N"
CVSS_MEDIUM_LOC  = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"
CVSS_LOW         = "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N"

# Cleartext/insecure service ports that violate PCI Req 2
INSECURE_PORTS = {
    "21":  "FTP — cleartext file transfer",
    "23":  "Telnet — cleartext remote shell",
    "513": "rlogin — cleartext remote login",
    "514": "rsh/syslog — cleartext remote shell / unencrypted syslog",
    "69":  "TFTP — unauthenticated file transfer",
    "110": "POP3 — cleartext email (unless STARTTLS negotiated)",
    "143": "IMAP — cleartext email (unless STARTTLS negotiated)",
}


class LinuxPciAudit(BaseModule):
    """PCI DSS v4.0 compliance checks for Linux hosts via SSH."""

    NAME        = "linux_pci_audit"
    DESCRIPTION = (
        "SSH credentialed PCI DSS v4.0 checks: firewall, insecure services, patch currency, "
        "sudoers, password policy, SSH config, audit logging, log retention, NTP"
    )
    PHASE       = 5
    TAGS        = ["credentialed", "linux", "pci", "pci-dss", "compliance"]

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
            await self._audit_host(host, transport_mgr.ssh, session)

        return self._make_result(start)

    async def _audit_host(self, host: str, ssh, session) -> None:
        """Run all PCI DSS v4.0 requirement checks against a single host."""
        await self._check_firewall(host, ssh, session)
        await self._check_insecure_services(host, ssh, session)
        await self._check_patch_currency(host, ssh, session)
        await self._check_waf_presence(host, ssh, session)
        await self._check_sudoers(host, ssh, session)
        await self._check_password_policy(host, ssh, session)
        await self._check_ssh_config(host, ssh, session)
        await self._check_audit_logging(host, ssh, session)
        await self._check_log_retention(host, ssh, session)
        await self._check_ntp_sync(host, ssh, session)

    # -------------------------------------------------------------------------
    # PCI Requirement 1 — Firewall and ACL
    # -------------------------------------------------------------------------

    async def _check_firewall(self, host: str, ssh, session) -> None:
        """PCI Req 1.3 / 1.3.2 — Firewall rules must exist with default deny."""
        # Check iptables
        ipt_result = await ssh.execute(session, "iptables -L -n 2>/dev/null | head -20")
        nft_result = await ssh.execute(session, "nft list ruleset 2>/dev/null | head -20")
        ufw_result = await ssh.execute(session, "ufw status verbose 2>/dev/null")

        has_iptables  = ipt_result.success and ipt_result.stdout.strip()
        has_nftables  = nft_result.success and nft_result.stdout.strip() and \
                        "Error" not in nft_result.stdout
        has_ufw       = ufw_result.success and "Status: active" in ufw_result.stdout
        has_firewalld_result = await ssh.execute(
            session, "systemctl is-active firewalld 2>/dev/null"
        )
        has_firewalld = has_firewalld_result.success and \
                        "active" in has_firewalld_result.stdout.strip().lower() and \
                        "inactive" not in has_firewalld_result.stdout.strip().lower()

        if not any([has_iptables, has_nftables, has_ufw, has_firewalld]):
            self.new_finding(
                title=f"PCI Req 1.3 — No Firewall Configured — {host}",
                severity=Severity.CRITICAL,
                description=(
                    f"No active firewall was detected on {host}. "
                    "PCI DSS v4.0 Requirement 1.3 mandates that firewall rules restrict "
                    "inbound and outbound traffic to only that which is necessary. "
                    "Without a firewall, any service listening on the host is accessible "
                    "to all network sources, directly violating PCI DSS network segmentation "
                    "requirements and enabling unrestricted lateral movement."
                ),
                reproduction_steps=[
                    f"ssh {host}",
                    "iptables -L -n",
                    "nft list ruleset",
                    "ufw status",
                    "systemctl is-active firewalld",
                ],
                remediation=(
                    "Install and configure a host-based firewall:\n"
                    "  apt-get install ufw && ufw default deny incoming && "
                    "ufw default deny outgoing\n"
                    "  ufw allow <required_services>/tcp\n"
                    "  ufw enable\n"
                    "Or configure iptables with an explicit default DROP policy:\n"
                    "  iptables -P INPUT DROP\n"
                    "  iptables -P FORWARD DROP\n"
                    "  iptables -P OUTPUT DROP\n"
                    "  iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT\n"
                    "  iptables -A INPUT -p tcp --dport 22 -j ACCEPT"
                ),
                references=[
                    "PCI DSS v4.0 Requirement 1.3",
                    "PCI DSS v4.0 Requirement 1.3.2",
                    "CWE-1188",
                ],
                evidence=Evidence(extra={
                    "host": host,
                    "iptables_output": ipt_result.stdout[:300],
                    "ufw_output": ufw_result.stdout[:200],
                }),
                cvss_v31_vector=CVSS_CRITICAL,
                mitre_attack=["TA0001/T1190", "TA0008/T1021"],
                target=host, service="ssh", confidence="HIGH",
            )
            return  # No point checking default-deny if firewall is absent

        # Check for default ACCEPT/ALLOW policy (no default deny)
        await self._check_default_deny(host, ssh, session, ipt_result.stdout, ufw_result.stdout)

    async def _check_default_deny(
        self,
        host: str,
        ssh,
        session,
        iptables_out: str,
        ufw_out: str,
    ) -> None:
        """PCI Req 1.3.2 — Inbound/outbound traffic must default to deny."""
        default_accept = False

        # Check iptables default policies
        for line in iptables_out.split("\n"):
            if re.match(r'^Chain\s+(INPUT|FORWARD)\s+\(policy\s+ACCEPT\)', line):
                default_accept = True
                break

        # Check ufw — "Default: allow" or missing deny
        if "Default: allow" in ufw_out or (ufw_out and "deny (incoming)" not in ufw_out.lower()):
            if "Status: active" in ufw_out:
                default_accept = True

        if default_accept:
            self.new_finding(
                title=f"PCI Req 1.3.2 — Firewall Default Policy Is ACCEPT (Not Deny) — {host}",
                severity=Severity.CRITICAL,
                description=(
                    f"The firewall on {host} has a default ACCEPT policy for INPUT or FORWARD "
                    "chains. PCI DSS v4.0 Requirement 1.3.2 requires that inbound and outbound "
                    "traffic defaults to deny-all, with only explicitly required traffic allowed. "
                    "A default ACCEPT policy negates the protection of all specific DENY rules "
                    "and allows any service not explicitly blocked."
                ),
                reproduction_steps=[
                    f"ssh {host}",
                    "iptables -L -n | grep -E 'Chain (INPUT|FORWARD|OUTPUT)'",
                    "ufw status verbose",
                ],
                remediation=(
                    "Set iptables default policy to DROP:\n"
                    "  iptables -P INPUT DROP\n"
                    "  iptables -P FORWARD DROP\n"
                    "  iptables -P OUTPUT DROP\n"
                    "Then explicitly allow required traffic:\n"
                    "  iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT\n"
                    "  iptables -A INPUT -p tcp --dport 22 -j ACCEPT  # SSH only\n"
                    "Persist: iptables-save > /etc/iptables/rules.v4"
                ),
                references=[
                    "PCI DSS v4.0 Requirement 1.3.2",
                    "CWE-1188",
                ],
                evidence=Evidence(extra={
                    "host": host,
                    "iptables_chains": iptables_out[:500],
                    "ufw_status": ufw_out[:300],
                }),
                cvss_v31_vector=CVSS_CRITICAL,
                mitre_attack=["TA0001/T1190"],
                target=host, service="ssh", confidence="HIGH",
            )

    # -------------------------------------------------------------------------
    # PCI Requirement 2 — Secure Defaults
    # -------------------------------------------------------------------------

    async def _check_insecure_services(self, host: str, ssh, session) -> None:
        """PCI Req 2.2.4 / 2.2.5 — No cleartext/insecure services should be running."""
        # Build a single grep for all insecure ports
        port_pattern = "|".join(f":{p}" for p in INSECURE_PORTS)
        result = await ssh.execute(
            session,
            f"ss -tlnp 2>/dev/null | grep -E '{port_pattern}'"
        )
        if not result.success or not result.stdout.strip():
            return

        found_services = []
        for line in result.stdout.strip().split("\n"):
            if not line.strip():
                continue
            for port, desc in INSECURE_PORTS.items():
                if f":{port}" in line or f":{port} " in line:
                    found_services.append(f"Port {port} ({desc}): {line.strip()[:100]}")
                    break

        if found_services:
            self.new_finding(
                title=f"PCI Req 2.2.4 — Insecure Cleartext Services Running — {host}",
                severity=Severity.CRITICAL,
                description=(
                    f"{len(found_services)} insecure cleartext service(s) are listening on {host}. "
                    "PCI DSS v4.0 Requirement 2.2.4 prohibits all unnecessary, insecure, or "
                    "non-console administrative access. Requirement 2.2.5 requires all such "
                    "services to be removed or replaced with secure alternatives.\n"
                    "Cleartext services transmit cardholder data and credentials in plaintext, "
                    "enabling trivial eavesdropping and credential theft on any network segment.\n"
                    "Found: " + "; ".join(found_services[:5])
                ),
                reproduction_steps=[
                    f"ssh {host}",
                    f"ss -tlnp | grep -E '{port_pattern}'",
                ],
                remediation=(
                    "Disable and remove cleartext services:\n"
                    "  FTP: systemctl disable --now vsftpd; apt-get purge vsftpd\n"
                    "  Telnet: systemctl disable --now telnetd; apt-get purge telnetd\n"
                    "  rsh/rlogin: systemctl disable --now rsh-server; apt-get purge rsh-server\n"
                    "Replace with encrypted alternatives:\n"
                    "  FTP -> SFTP (built into OpenSSH)\n"
                    "  Telnet -> SSH\n"
                    "  rsh/rlogin -> SSH"
                ),
                references=[
                    "PCI DSS v4.0 Requirement 2.2.4",
                    "PCI DSS v4.0 Requirement 2.2.5",
                    "CWE-319",
                    "NIST SP 800-52",
                ],
                evidence=Evidence(extra={
                    "host": host,
                    "insecure_services": found_services,
                    "raw_ss_output": result.stdout[:500],
                }),
                cvss_v31_vector=CVSS_CRITICAL,
                mitre_attack=["TA0006/T1040", "TA0001/T1133"],
                target=host, service="ssh", confidence="HIGH",
            )

        # PCI Req 2.2.1 — Count total listening services (excessive services = audit flag)
        await self._check_listening_service_count(host, ssh, session)

    async def _check_listening_service_count(self, host: str, ssh, session) -> None:
        """PCI Req 2.2.1 — Only necessary services should be running."""
        result = await ssh.execute(session, "ss -tlnp 2>/dev/null | grep -c LISTEN || echo 0")
        if not result.success:
            return
        try:
            count = int(result.stdout.strip())
        except ValueError:
            return

        # More than 15 listening services on a production host warrants review
        if count > 15:
            detail_result = await ssh.execute(session, "ss -tlnp 2>/dev/null")
            self.new_finding(
                title=f"PCI Req 2.2.1 — Excessive Listening Services ({count}) — {host}",
                severity=Severity.MEDIUM,
                description=(
                    f"{count} services are listening for network connections on {host}. "
                    "PCI DSS v4.0 Requirement 2.2.1 requires that only necessary system "
                    "components and services are enabled. Each listening service is an "
                    "attack surface — unnecessary services should be disabled."
                ),
                reproduction_steps=[
                    f"ssh {host}",
                    "ss -tlnp",
                    "systemctl list-units --type=service --state=active",
                ],
                remediation=(
                    "Enumerate all listening services and disable those not required:\n"
                    "  ss -tlnp  # identify services\n"
                    "  systemctl disable --now <service_name>  # for each unnecessary service\n"
                    "Document the required services in the system configuration baseline."
                ),
                references=[
                    "PCI DSS v4.0 Requirement 2.2.1",
                    "CWE-1188",
                ],
                evidence=Evidence(extra={
                    "host": host,
                    "listening_count": count,
                    "service_list": detail_result.stdout[:800] if detail_result.success else "",
                }),
                cvss_v31_vector=CVSS_MEDIUM,
                mitre_attack=["TA0007/T1049"],
                target=host, service="ssh", confidence="MEDIUM",
            )

    # -------------------------------------------------------------------------
    # PCI Requirement 6 — Secure Systems and Software
    # -------------------------------------------------------------------------

    async def _check_patch_currency(self, host: str, ssh, session) -> None:
        """PCI Req 6.3.3 — All security patches must be applied."""
        # Check last apt/yum cache update time as a proxy for patch currency
        apt_result = await ssh.execute(
            session,
            "stat --format='%Y' /var/cache/apt/pkgcache.bin 2>/dev/null || "
            "stat --format='%Y' /var/cache/yum/ 2>/dev/null || "
            "stat --format='%Y' /var/cache/dnf/ 2>/dev/null"
        )
        last_update_epoch = None
        if apt_result.success and apt_result.stdout.strip():
            try:
                last_update_epoch = int(apt_result.stdout.strip().split("\n")[0])
            except ValueError:
                pass

        # Also check for pending security updates
        pending_result = await ssh.execute(
            session,
            "apt list --upgradable 2>/dev/null | grep -c security || "
            "yum check-update --security 2>/dev/null | grep -c '^[a-zA-Z]' || "
            "dnf check-update --security 2>/dev/null | grep -c '^[a-zA-Z]' || echo 0"
        )
        pending_count = 0
        if pending_result.success:
            try:
                pending_count = int(pending_result.stdout.strip().split("\n")[0])
            except ValueError:
                pass

        # Check if last update was more than 30 days ago
        if last_update_epoch is not None:
            days_since_update = (time.time() - last_update_epoch) / 86400
            if days_since_update > 30:
                self.new_finding(
                    title=f"PCI Req 6.3.3 — Package Cache Stale ({int(days_since_update)} days) — {host}",
                    severity=Severity.HIGH,
                    description=(
                        f"The package manager cache on {host} was last refreshed "
                        f"{int(days_since_update)} days ago. "
                        "PCI DSS v4.0 Requirement 6.3.3 requires that all applicable security "
                        "patches/updates are installed within one month of release. "
                        "A stale package cache indicates patches are not being regularly reviewed "
                        "and applied."
                    ),
                    reproduction_steps=[
                        f"ssh {host}",
                        "stat /var/cache/apt/pkgcache.bin",
                        "apt list --upgradable 2>/dev/null | grep security",
                    ],
                    remediation=(
                        "Update package lists and apply security patches:\n"
                        "  apt-get update && apt-get upgrade -y  # Debian/Ubuntu\n"
                        "  yum update -y --security  # RHEL/CentOS\n"
                        "Configure automatic security updates:\n"
                        "  apt-get install unattended-upgrades\n"
                        "  dpkg-reconfigure unattended-upgrades"
                    ),
                    references=[
                        "PCI DSS v4.0 Requirement 6.3.3",
                        "CWE-1104",
                    ],
                    evidence=Evidence(extra={
                        "host": host,
                        "days_since_cache_update": int(days_since_update),
                        "pending_security_patches": pending_count,
                    }),
                    cvss_v31_vector=CVSS_HIGH_NET,
                    mitre_attack=["TA0001/T1190"],
                    target=host, service="ssh", confidence="MEDIUM",
                )

        if pending_count > 0:
            self.new_finding(
                title=f"PCI Req 6.3.3 — {pending_count} Security Patches Pending — {host}",
                severity=Severity.HIGH,
                description=(
                    f"{pending_count} security patches are pending application on {host}. "
                    "PCI DSS v4.0 Requirement 6.3.3 requires security patches to be applied "
                    "within one month of release (critical patches within one month, "
                    "all others within three months). Unpatched vulnerabilities in the "
                    "cardholder data environment are a direct PCI compliance violation."
                ),
                reproduction_steps=[
                    f"ssh {host}",
                    "apt list --upgradable 2>/dev/null | grep security",
                ],
                remediation=(
                    "Apply security patches immediately:\n"
                    "  apt-get update && apt-get upgrade -y\n"
                    "Or for specific packages:\n"
                    "  apt-get install --only-upgrade <package>"
                ),
                references=[
                    "PCI DSS v4.0 Requirement 6.3.3",
                    "CWE-1104",
                ],
                evidence=Evidence(extra={
                    "host": host,
                    "pending_security_updates": pending_count,
                }),
                cvss_v31_vector=CVSS_HIGH_NET,
                mitre_attack=["TA0001/T1190"],
                target=host, service="ssh", confidence="HIGH",
            )

    async def _check_waf_presence(self, host: str, ssh, session) -> None:
        """PCI Req 6.4.2 — Web-facing applications must have WAF protection."""
        # Check for Apache with mod_security
        apache_waf = await ssh.execute(
            session,
            "apache2ctl -M 2>/dev/null | grep -i 'mod_security\\|security2' || "
            "apachectl -M 2>/dev/null | grep -i 'security'"
        )
        # Check for nginx with modsecurity or naxsi
        nginx_waf = await ssh.execute(
            session,
            "nginx -V 2>&1 | grep -i 'modsecurity\\|naxsi' || "
            "grep -r 'ModSecurityEnabled\\|SecRuleEngine' /etc/nginx/ 2>/dev/null | head -3"
        )
        # Check if a web server is actually running
        web_server = await ssh.execute(
            session,
            "systemctl is-active apache2 nginx httpd 2>/dev/null | grep -c active || echo 0"
        )

        web_running = False
        if web_server.success:
            try:
                web_running = int(web_server.stdout.strip()) > 0
            except ValueError:
                pass

        if not web_running:
            return  # No web server = WAF check not applicable

        has_waf = (
            (apache_waf.success and apache_waf.stdout.strip()) or
            (nginx_waf.success and nginx_waf.stdout.strip())
        )

        if not has_waf:
            self.new_finding(
                title=f"PCI Req 6.4.2 — Web-Facing Application Has No WAF — {host}",
                severity=Severity.HIGH,
                description=(
                    f"A web server is running on {host} but no Web Application Firewall (WAF) "
                    "module was detected (no ModSecurity/mod_security2 in Apache, no NAXSI in nginx). "
                    "PCI DSS v4.0 Requirement 6.4.2 requires that web-facing applications are "
                    "protected by an automated technical solution (WAF or other) to prevent known attacks. "
                    "Without a WAF, web applications are exposed to OWASP Top 10 attacks including "
                    "SQL injection, XSS, and CSRF."
                ),
                reproduction_steps=[
                    f"ssh {host}",
                    "apache2ctl -M | grep -i security",
                    "nginx -V 2>&1 | grep modsecurity",
                    "systemctl is-active apache2 nginx",
                ],
                remediation=(
                    "Deploy a Web Application Firewall:\n"
                    "For Apache:\n"
                    "  apt-get install libapache2-mod-security2\n"
                    "  a2enmod security2\n"
                    "  cp /etc/modsecurity/modsecurity.conf-recommended "
                    "/etc/modsecurity/modsecurity.conf\n"
                    "  sed -i 's/DetectionOnly/On/' /etc/modsecurity/modsecurity.conf\n"
                    "Download OWASP CRS: git clone "
                    "https://github.com/coreruleset/coreruleset /etc/modsecurity/crs/\n"
                    "Alternatively, deploy a network-level WAF (CloudFlare, AWS WAF, F5)."
                ),
                references=[
                    "PCI DSS v4.0 Requirement 6.4.2",
                    "OWASP Top 10 2021",
                    "CWE-693",
                ],
                evidence=Evidence(extra={
                    "host": host,
                    "apache_waf_check": apache_waf.stdout[:300],
                    "nginx_waf_check": nginx_waf.stdout[:300],
                }),
                cvss_v31_vector=CVSS_HIGH_NET,
                mitre_attack=["TA0001/T1190"],
                target=host, service="ssh", confidence="MEDIUM",
            )

    # -------------------------------------------------------------------------
    # PCI Requirement 7 — Access Control
    # -------------------------------------------------------------------------

    async def _check_sudoers(self, host: str, ssh, session) -> None:
        """PCI Req 7.2.1 — Access restricted to need-to-know; NOPASSWD is critical violation."""
        # Read sudoers and sudoers.d
        sudoers_result = await ssh.execute(session, "cat /etc/sudoers 2>/dev/null")
        sudoers_d_result = await ssh.execute(
            session, "cat /etc/sudoers.d/* 2>/dev/null"
        )
        full_sudoers = (sudoers_result.stdout if sudoers_result.success else "") + \
                      "\n" + (sudoers_d_result.stdout if sudoers_d_result.success else "")

        nopasswd_entries = []
        all_all_entries  = []
        broad_entries    = []

        for line in full_sudoers.split("\n"):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            # NOPASSWD — critical PCI violation
            if "NOPASSWD" in stripped:
                nopasswd_entries.append(stripped[:120])

            # ALL=(ALL) ALL or ALL=(ALL:ALL) ALL — unrestricted root access
            if re.search(r'\bALL\s*=\s*\(ALL[^)]*\)\s*(NOPASSWD:\s*)?ALL\b', stripped):
                user = stripped.split()[0] if stripped.split() else "?"
                if user.lstrip("%").lower() not in ("root", "sudo", "wheel", "admin"):
                    all_all_entries.append(stripped[:120])

            # Broad access to shells or package managers
            if re.search(r'\b(bash|sh|zsh|python|perl|ruby|apt|yum|dnf|pip)\b', stripped) and \
               "NOPASSWD" not in stripped:
                broad_entries.append(stripped[:120])

        if nopasswd_entries:
            self.new_finding(
                title=f"PCI Req 7.2.1 — CRITICAL: NOPASSWD Sudo — PCI Violation — {host}",
                severity=Severity.CRITICAL,
                description=(
                    f"NOPASSWD sudo entries were found on {host}. This is a critical PCI DSS "
                    "violation under Requirement 7.2.1 (restrict access to need-to-know). "
                    "NOPASSWD sudo allows any process running as the affected user — including "
                    "malware, web shells, or compromised services — to escalate to root without "
                    "any authentication barrier. This entirely bypasses PCI Req 8 authentication "
                    "requirements for privileged access.\n"
                    f"Entries: {'; '.join(nopasswd_entries[:5])}"
                ),
                reproduction_steps=[
                    f"ssh {host}",
                    "grep -r NOPASSWD /etc/sudoers /etc/sudoers.d/ 2>/dev/null",
                    "# As any user with the grant: sudo <command> (no password prompt)",
                ],
                remediation=(
                    "Remove ALL NOPASSWD entries from sudoers:\n"
                    "  visudo  # remove NOPASSWD: from all entries\n"
                    "  # Remove files: rm /etc/sudoers.d/<file_with_nopasswd>\n"
                    "Require password for all sudo operations. If service accounts need "
                    "elevated access, use specific command whitelists with password required."
                ),
                references=[
                    "PCI DSS v4.0 Requirement 7.2.1",
                    "PCI DSS v4.0 Requirement 8.2.1",
                    "CWE-250",
                    "CWE-269",
                ],
                evidence=Evidence(extra={
                    "host": host,
                    "nopasswd_entries": nopasswd_entries[:10],
                }),
                cvss_v31_vector=CVSS_CRITICAL,
                mitre_attack=["TA0004/T1548.003"],
                target=host, service="ssh", confidence="HIGH",
            )

        if all_all_entries:
            self.new_finding(
                title=f"PCI Req 7.2.1 — Unrestricted Root Sudo Grants — {host}",
                severity=Severity.HIGH,
                description=(
                    f"{len(all_all_entries)} non-standard accounts have unrestricted root sudo "
                    f"access on {host}: {'; '.join(all_all_entries[:3])}. "
                    "PCI DSS v4.0 Requirement 7.2.1 requires access to be granted only based "
                    "on business need. Unrestricted ALL=(ALL) sudo grants violate least-privilege "
                    "and create privilege escalation paths for any compromised account."
                ),
                reproduction_steps=[
                    f"ssh {host}",
                    "grep -E 'ALL=.*ALL.*ALL' /etc/sudoers /etc/sudoers.d/*",
                ],
                remediation=(
                    "Replace broad ALL=(ALL) ALL grants with specific command lists:\n"
                    "  visudo\n"
                    "  # Change: user ALL=(ALL) ALL\n"
                    "  # To: user ALL=(ALL) /usr/bin/specific_command\n"
                    "Document each grant with business justification."
                ),
                references=[
                    "PCI DSS v4.0 Requirement 7.2.1",
                    "CWE-250",
                ],
                evidence=Evidence(extra={
                    "host": host,
                    "unrestricted_entries": all_all_entries[:10],
                }),
                cvss_v31_vector=CVSS_HIGH_LOCAL,
                mitre_attack=["TA0004/T1548.003"],
                target=host, service="ssh", confidence="HIGH",
            )

    # -------------------------------------------------------------------------
    # PCI Requirement 8 — Authentication
    # -------------------------------------------------------------------------

    async def _check_password_policy(self, host: str, ssh, session) -> None:
        """PCI Req 8.3.6 / 8.3.9 — Password minimum length, history, complexity."""
        max_days_result = await ssh.execute(
            session, "grep ^PASS_MAX_DAYS /etc/login.defs 2>/dev/null"
        )
        min_days_result = await ssh.execute(
            session, "grep ^PASS_MIN_DAYS /etc/login.defs 2>/dev/null"
        )
        minlen_result = await ssh.execute(
            session,
            "grep -E '^\\s*minlen' /etc/security/pwquality.conf 2>/dev/null"
        )
        remember_result = await ssh.execute(
            session,
            "grep -E 'remember' /etc/pam.d/common-password /etc/pam.d/system-auth 2>/dev/null | "
            "head -3"
        )

        # Parse values
        max_days = None
        m = re.search(r'PASS_MAX_DAYS\s+(\d+)', max_days_result.stdout)
        if m:
            max_days = int(m.group(1))

        min_days = None
        m = re.search(r'PASS_MIN_DAYS\s+(\d+)', min_days_result.stdout)
        if m:
            min_days = int(m.group(1))

        minlen = None
        m = re.search(r'minlen\s*=\s*(\d+)', minlen_result.stdout)
        if m:
            minlen = int(m.group(1))

        remember = None
        m = re.search(r'remember\s*=\s*(\d+)', remember_result.stdout)
        if m:
            remember = int(m.group(1))

        # PCI Req 8.3.6 — Min 12 chars
        if minlen is None or minlen < 12:
            self.new_finding(
                title=f"PCI Req 8.3.6 — Password Minimum Length < 12 — {host}",
                severity=Severity.HIGH,
                description=(
                    f"Password minimum length is "
                    f"{'not configured' if minlen is None else minlen} on {host}. "
                    "PCI DSS v4.0 Requirement 8.3.6 requires passwords to be at least 12 "
                    "characters (or 8 if MFA is deployed). Short passwords dramatically "
                    "reduce the time to crack captured NTLM/bcrypt/SHA hashes."
                ),
                reproduction_steps=[
                    f"ssh {host}",
                    "grep minlen /etc/security/pwquality.conf",
                ],
                remediation=(
                    "Set in /etc/security/pwquality.conf: minlen = 12\n"
                    "Ensure pam_pwquality is in /etc/pam.d/common-password:\n"
                    "  password requisite pam_pwquality.so retry=3"
                ),
                references=[
                    "PCI DSS v4.0 Requirement 8.3.6",
                    "CWE-521",
                    "NIST SP 800-63B",
                ],
                evidence=Evidence(extra={"host": host, "min_length": minlen}),
                cvss_v31_vector=CVSS_HIGH_LOCAL,
                mitre_attack=["TA0006/T1110"],
                target=host, service="ssh", confidence="HIGH",
            )

        # PCI Req 8.3.9 — Passwords must differ from last 4
        if remember is None or remember < 4:
            self.new_finding(
                title=f"PCI Req 8.3.9 — Password History Not Enforced (< 4) — {host}",
                severity=Severity.MEDIUM,
                description=(
                    f"PAM password history ('remember') is "
                    f"{'not configured' if remember is None else remember} on {host}. "
                    "PCI DSS v4.0 Requirement 8.3.9 requires passwords to differ from the "
                    "last four previously used passwords. Without history enforcement, "
                    "users can immediately reuse compromised passwords."
                ),
                reproduction_steps=[
                    f"ssh {host}",
                    "grep remember /etc/pam.d/common-password /etc/pam.d/system-auth",
                ],
                remediation=(
                    "Add/update in /etc/pam.d/common-password:\n"
                    "  password required pam_pwhistory.so remember=4 use_authtok\n"
                    "Or for Debian/Ubuntu, add 'remember=4' to the pam_unix line."
                ),
                references=[
                    "PCI DSS v4.0 Requirement 8.3.9",
                    "CWE-262",
                ],
                evidence=Evidence(extra={"host": host, "remember": remember}),
                cvss_v31_vector=CVSS_MEDIUM_LOC,
                target=host, service="ssh", confidence="HIGH",
            )

        # PCI Req 8.3.6 — Max age not > 90 days for PCI environments
        if max_days is None or max_days == 99999 or max_days > 90:
            self.new_finding(
                title=f"PCI Req 8.3.6 — Password Max Age Exceeds 90 Days — {host}",
                severity=Severity.MEDIUM,
                description=(
                    f"PASS_MAX_DAYS is "
                    f"{'not configured' if max_days is None else max_days} on {host}. "
                    "PCI DSS v4.0 Requirement 8.3.6 recommends password expiry no longer than "
                    "90 days for passwords protecting cardholder data environment access. "
                    "Long-lived passwords extend the usable window of compromised credentials."
                ),
                reproduction_steps=[
                    f"ssh {host}",
                    "grep ^PASS_MAX_DAYS /etc/login.defs",
                ],
                remediation=(
                    "Set in /etc/login.defs: PASS_MAX_DAYS 90\n"
                    "Apply retroactively: chage --maxdays 90 <username>"
                ),
                references=[
                    "PCI DSS v4.0 Requirement 8.3.6",
                    "CWE-262",
                ],
                evidence=Evidence(extra={"host": host, "pass_max_days": max_days}),
                cvss_v31_vector=CVSS_MEDIUM_LOC,
                target=host, service="ssh", confidence="HIGH",
            )

    async def _check_ssh_config(self, host: str, ssh, session) -> None:
        """PCI Req 8.6.1 — Root SSH login must be disabled (PermitRootLogin no)."""
        sshd_result = await ssh.execute(
            session,
            "grep -i PermitRootLogin /etc/ssh/sshd_config 2>/dev/null | "
            "grep -v '^#' | head -5"
        )

        # Check effective configuration (includes sshd_config.d)
        effective_result = await ssh.execute(
            session,
            "sshd -T 2>/dev/null | grep -i permitrootlogin || "
            "grep -ri PermitRootLogin /etc/ssh/sshd_config.d/ 2>/dev/null"
        )

        config_output = (sshd_result.stdout + "\n" + effective_result.stdout).lower()

        root_login_allowed = False
        if not config_output.strip():
            # Default is typically 'prohibit-password' (allows key auth), which PCI still flags
            root_login_allowed = True
        elif "permitrootlogin no" in config_output:
            root_login_allowed = False
        elif "permitrootlogin without-password" in config_output or \
             "permitrootlogin prohibit-password" in config_output:
            # Key-based root login still allowed — PCI violation
            root_login_allowed = True
        elif "permitrootlogin yes" in config_output:
            root_login_allowed = True

        if root_login_allowed:
            severity = Severity.HIGH
            config_val = "PermitRootLogin yes/without-password/prohibit-password or not configured"
            m = re.search(r'permitrootlogin\s+(\S+)', config_output)
            if m:
                config_val = f"PermitRootLogin {m.group(1)}"

            self.new_finding(
                title=f"PCI Req 8.6.1 — Root SSH Login Permitted — {host}",
                severity=severity,
                description=(
                    f"SSH root login is not disabled on {host} ({config_val}). "
                    "PCI DSS v4.0 Requirement 8.6.1 requires that direct root login is "
                    "restricted to specific, authorized admin systems. Permitting root SSH "
                    "login eliminates individual accountability (impossible to know which "
                    "person authenticated as root) and allows attackers who obtain root "
                    "credentials or SSH keys to log in directly."
                ),
                reproduction_steps=[
                    f"ssh {host}",
                    "grep PermitRootLogin /etc/ssh/sshd_config",
                    "sshd -T | grep permitrootlogin",
                ],
                remediation=(
                    "Disable root SSH login in /etc/ssh/sshd_config:\n"
                    "  PermitRootLogin no\n"
                    "Restart SSH: systemctl restart sshd\n"
                    "Ensure all admins use named accounts and sudo for privilege escalation.\n"
                    "If emergency root access is needed, restrict to specific source IPs:\n"
                    "  Match Address 10.0.0.5\n"
                    "    PermitRootLogin yes"
                ),
                references=[
                    "PCI DSS v4.0 Requirement 8.6.1",
                    "CWE-250",
                    "NIST SP 800-53 AC-6",
                ],
                evidence=Evidence(extra={
                    "host": host,
                    "sshd_config": sshd_result.stdout[:300],
                    "effective_config": effective_result.stdout[:300],
                }),
                cvss_v31_vector=CVSS_HIGH_LOCAL,
                mitre_attack=["TA0004/T1078.003"],
                target=host, service="ssh", confidence="HIGH",
            )

        # Additional SSH checks
        await self._check_ssh_protocol_security(host, ssh, session)

    async def _check_ssh_protocol_security(self, host: str, ssh, session) -> None:
        """Check SSH protocol-level security settings for PCI compliance."""
        effective = await ssh.execute(
            session,
            "sshd -T 2>/dev/null | grep -E "
            "'protocol|passwordauthentication|pubkeyauthentication|"
            "permitemptypasswords|maxauthtries|clientaliveinterval'"
        )
        if not effective.success or not effective.stdout.strip():
            return

        config = effective.stdout.lower()
        issues = []

        # Empty passwords
        if "permitemptypasswords yes" in config:
            issues.append("PermitEmptyPasswords yes — allows blank-password logins")

        # Max auth tries should be low
        m = re.search(r'maxauthtries\s+(\d+)', config)
        if m and int(m.group(1)) > 4:
            issues.append(f"MaxAuthTries {m.group(1)} — should be <= 4")

        # No client timeout
        m = re.search(r'clientaliveinterval\s+(\d+)', config)
        if m and int(m.group(1)) == 0:
            issues.append("ClientAliveInterval 0 — no session timeout configured")

        if issues:
            self.new_finding(
                title=f"PCI Req 8 — SSH Misconfiguration — {host}",
                severity=Severity.MEDIUM,
                description=(
                    f"SSH has {len(issues)} PCI-relevant misconfigurations on {host}: "
                    + "; ".join(issues)
                ),
                reproduction_steps=[
                    f"ssh {host}",
                    "sshd -T | grep -E 'maxauthtries|permitemptypasswords|clientalive'",
                ],
                remediation=(
                    "In /etc/ssh/sshd_config, set:\n"
                    "  PermitEmptyPasswords no\n"
                    "  MaxAuthTries 4\n"
                    "  ClientAliveInterval 300\n"
                    "  ClientAliveCountMax 0\n"
                    "Restart: systemctl restart sshd"
                ),
                references=[
                    "PCI DSS v4.0 Requirement 8.3",
                    "CWE-307",
                ],
                evidence=Evidence(extra={
                    "host": host,
                    "issues": issues,
                    "sshd_config": effective.stdout[:500],
                }),
                cvss_v31_vector=CVSS_MEDIUM,
                target=host, service="ssh", confidence="HIGH",
            )

    # -------------------------------------------------------------------------
    # PCI Requirement 10 — Log and Monitor All Access
    # -------------------------------------------------------------------------

    async def _check_audit_logging(self, host: str, ssh, session) -> None:
        """PCI Req 10.2 — Audit logging must be configured and active."""
        auditd_result   = await ssh.execute(session, "systemctl is-active auditd 2>/dev/null")
        rsyslog_result  = await ssh.execute(session, "systemctl is-active rsyslog 2>/dev/null")
        syslog_ng_result = await ssh.execute(session, "systemctl is-active syslog-ng 2>/dev/null")

        auditd_active  = auditd_result.success and "active" in auditd_result.stdout.strip().lower() \
                         and "inactive" not in auditd_result.stdout.strip().lower()
        syslog_active  = (rsyslog_result.success and "active" in rsyslog_result.stdout.strip().lower()) or \
                         (syslog_ng_result.success and "active" in syslog_ng_result.stdout.strip().lower())

        if not auditd_active:
            self.new_finding(
                title=f"PCI Req 10.2 — auditd Not Running — {host}",
                severity=Severity.HIGH,
                description=(
                    f"auditd is not active on {host} (status: {auditd_result.stdout.strip()}). "
                    "PCI DSS v4.0 Requirement 10.2 requires audit trails for all access to "
                    "system components. Without auditd, there is no kernel-level record of "
                    "authentication events, privilege escalation, file access, or system calls. "
                    "This is a direct PCI DSS audit log requirement violation."
                ),
                reproduction_steps=[
                    f"ssh {host}",
                    "systemctl is-active auditd",
                    "systemctl status auditd",
                ],
                remediation=(
                    "Install and activate auditd:\n"
                    "  apt-get install auditd\n"
                    "  systemctl enable --now auditd\n"
                    "Deploy PCI-required audit rules covering:\n"
                    "  -w /etc/passwd -p wa -k identity\n"
                    "  -w /etc/shadow -p wa -k identity\n"
                    "  -w /etc/sudoers -p wa -k actions\n"
                    "  -a always,exit -F arch=b64 -S open -k data_access"
                ),
                references=[
                    "PCI DSS v4.0 Requirement 10.2",
                    "PCI DSS v4.0 Requirement 10.2.1",
                    "CWE-223",
                    "NIST SP 800-53 AU-2",
                ],
                evidence=Evidence(extra={
                    "host": host,
                    "auditd_status": auditd_result.stdout.strip(),
                }),
                cvss_v31_vector=CVSS_HIGH_LOCAL,
                mitre_attack=["TA0005/T1562.001"],
                target=host, service="ssh", confidence="HIGH",
            )

        if not syslog_active:
            self.new_finding(
                title=f"PCI Req 10.2 — No Syslog Service Running — {host}",
                severity=Severity.HIGH,
                description=(
                    f"No syslog service (rsyslog or syslog-ng) is active on {host}. "
                    "PCI DSS v4.0 Requirement 10.2 requires that all access to system "
                    "components is logged. Without syslog, application-level events, "
                    "service events, and system messages are not captured or forwarded "
                    "to a centralized log server."
                ),
                reproduction_steps=[
                    f"ssh {host}",
                    "systemctl is-active rsyslog syslog-ng",
                ],
                remediation=(
                    "Install and enable rsyslog:\n"
                    "  apt-get install rsyslog\n"
                    "  systemctl enable --now rsyslog\n"
                    "Configure remote log forwarding to a centralized syslog server:\n"
                    "  echo '*.* @@logserver.company.com:514' >> /etc/rsyslog.conf\n"
                    "  systemctl restart rsyslog"
                ),
                references=[
                    "PCI DSS v4.0 Requirement 10.2",
                    "PCI DSS v4.0 Requirement 10.5.1",
                    "CWE-223",
                ],
                evidence=Evidence(extra={
                    "host": host,
                    "rsyslog_status": rsyslog_result.stdout.strip(),
                }),
                cvss_v31_vector=CVSS_HIGH_LOCAL,
                target=host, service="ssh", confidence="HIGH",
            )

    async def _check_log_retention(self, host: str, ssh, session) -> None:
        """PCI Req 10.5 / 10.7 — Log retention must be configured (minimum 12 months)."""
        logrotate_result = await ssh.execute(
            session,
            "grep -E '^\\s*rotate' /etc/logrotate.conf /etc/logrotate.d/* 2>/dev/null | "
            "head -10"
        )
        if not logrotate_result.success or not logrotate_result.stdout.strip():
            self.new_finding(
                title=f"PCI Req 10.5 — Log Rotation Not Configured — {host}",
                severity=Severity.MEDIUM,
                description=(
                    f"No logrotate 'rotate' directive was found on {host}. "
                    "PCI DSS v4.0 Requirement 10.5 requires audit logs to be retained for "
                    "at least 12 months, with the most recent 3 months available for "
                    "immediate analysis. Without logrotate, logs may fill the disk (causing "
                    "DoS) or be lost without a defined retention policy."
                ),
                reproduction_steps=[
                    f"ssh {host}",
                    "grep rotate /etc/logrotate.conf",
                    "ls /etc/logrotate.d/",
                ],
                remediation=(
                    "Configure logrotate for 12-month retention:\n"
                    "  In /etc/logrotate.conf, set: rotate 52  (weekly rotation = ~12 months)\n"
                    "  Or: rotate 366  (daily rotation = 12 months)\n"
                    "Configure offsite/SIEM log forwarding for long-term retention:\n"
                    "  Forward to Splunk/ELK/Sentinel with 12-month retention policy."
                ),
                references=[
                    "PCI DSS v4.0 Requirement 10.5",
                    "PCI DSS v4.0 Requirement 10.7",
                    "CWE-223",
                ],
                evidence=Evidence(extra={
                    "host": host,
                    "logrotate_output": logrotate_result.stdout[:300],
                }),
                cvss_v31_vector=CVSS_MEDIUM_LOC,
                mitre_attack=["TA0005/T1070.002"],
                target=host, service="ssh", confidence="MEDIUM",
            )
            return

        # Parse minimum rotation value
        min_rotate = None
        for line in logrotate_result.stdout.split("\n"):
            m = re.search(r'rotate\s+(\d+)', line)
            if m:
                val = int(m.group(1))
                if min_rotate is None or val < min_rotate:
                    min_rotate = val

        # Check if rotation frequency combined with count achieves 12 months
        # We can't know frequency easily, but flag if rotate count < 12
        if min_rotate is not None and min_rotate < 12:
            self.new_finding(
                title=f"PCI Req 10.5 — Log Retention May Be Insufficient ({min_rotate} rotations) — {host}",
                severity=Severity.MEDIUM,
                description=(
                    f"The minimum logrotate 'rotate' value found on {host} is {min_rotate}. "
                    "Depending on the rotation frequency (weekly/monthly/daily), this may "
                    "not provide the PCI DSS v4.0 required 12-month log retention. "
                    "PCI Req 10.5.1 requires 12 months with 3 months immediately accessible."
                ),
                reproduction_steps=[
                    f"ssh {host}",
                    "grep -r rotate /etc/logrotate.conf /etc/logrotate.d/",
                    "ls -lh /var/log/",
                ],
                remediation=(
                    "Increase logrotate retention counts:\n"
                    "  weekly rotation: rotate 52  # 12 months\n"
                    "  monthly rotation: rotate 12  # 12 months\n"
                    "  daily rotation: rotate 365  # 12 months\n"
                    "Configure centralized SIEM/log management for long-term retention."
                ),
                references=[
                    "PCI DSS v4.0 Requirement 10.5.1",
                    "CWE-223",
                ],
                evidence=Evidence(extra={
                    "host": host,
                    "min_rotate_count": min_rotate,
                    "logrotate_config": logrotate_result.stdout[:500],
                }),
                cvss_v31_vector=CVSS_MEDIUM_LOC,
                target=host, service="ssh", confidence="MEDIUM",
            )

    # -------------------------------------------------------------------------
    # PCI Requirement 12 — Support Information Security
    # -------------------------------------------------------------------------

    async def _check_ntp_sync(self, host: str, ssh, session) -> None:
        """PCI Req 12 — NTP must be synchronized (time accuracy required for log integrity)."""
        timedatectl_result = await ssh.execute(
            session,
            "timedatectl status 2>/dev/null | grep -E 'NTP|synchronized|Network time'"
        )
        ntpq_result = await ssh.execute(
            session,
            "ntpq -p 2>/dev/null | head -5 || chronyc tracking 2>/dev/null | head -5"
        )

        synced = False
        if timedatectl_result.success and timedatectl_result.stdout.strip():
            output = timedatectl_result.stdout.lower()
            if "synchronized: yes" in output or "ntp synchronized: yes" in output or \
               "system clock synchronized: yes" in output:
                synced = True
        elif ntpq_result.success and ntpq_result.stdout.strip():
            # ntpq shows synchronized peers
            for line in ntpq_result.stdout.split("\n"):
                if line.startswith("*"):  # * = currently synced peer
                    synced = True
                    break
            # chronyc tracking
            if "reference id" in ntpq_result.stdout.lower() and "stratum" in ntpq_result.stdout.lower():
                synced = True

        if not synced:
            self.new_finding(
                title=f"PCI Req 12 — NTP Not Synchronized — {host}",
                severity=Severity.MEDIUM,
                description=(
                    f"NTP synchronization is not confirmed on {host}. "
                    "PCI DSS v4.0 Requirement 12.8.5 (and prior Req 10.4) requires time "
                    "synchronization for all system clocks in the cardholder data environment. "
                    "Inaccurate timestamps undermine log correlation, forensic investigation, "
                    "and compliance audit trails — making it impossible to accurately sequence "
                    "events during a security incident."
                ),
                reproduction_steps=[
                    f"ssh {host}",
                    "timedatectl status",
                    "ntpq -p",
                    "chronyc tracking",
                ],
                remediation=(
                    "Install and enable NTP synchronization:\n"
                    "Using systemd-timesyncd (simplest):\n"
                    "  systemctl enable --now systemd-timesyncd\n"
                    "  timedatectl set-ntp true\n"
                    "Using chrony (recommended for PCI environments):\n"
                    "  apt-get install chrony\n"
                    "  systemctl enable --now chronyd\n"
                    "Configure time servers in /etc/chrony.conf:\n"
                    "  server 0.pool.ntp.org iburst\n"
                    "  server 1.pool.ntp.org iburst"
                ),
                references=[
                    "PCI DSS v4.0 Requirement 10.6.1",
                    "PCI DSS v4.0 Requirement 10.6.3",
                    "CWE-367",
                ],
                evidence=Evidence(extra={
                    "host": host,
                    "timedatectl": timedatectl_result.stdout[:300],
                    "ntp_status": ntpq_result.stdout[:300],
                }),
                cvss_v31_vector=CVSS_MEDIUM_LOC,
                mitre_attack=["TA0005/T1070"],
                target=host, service="ssh", confidence="MEDIUM",
            )
