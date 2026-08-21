"""Linux CIS Benchmark Audit — CIS Linux Benchmark v3.0 Level 1 checks via SSH.

Covers:
  - Filesystem: unused kernel modules, /tmp partition, mount options, AIDE
  - Network: IP forwarding, ICMP redirects, packet redirect, IPv6 RA
  - Services: xinetd/telnet/rsh/avahi/Xorg/LDAP
  - User Accounts: password policy, expiry, system accounts, root login
  - Logging: auditd, rsyslog
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
CVSS_HIGH_AUTH  = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
CVSS_HIGH_NET   = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
CVSS_MEDIUM     = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"
CVSS_MEDIUM_NET = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N"
CVSS_LOW        = "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N"

# Unused filesystem modules that should be disabled per CIS 1.1.1
UNUSED_FILESYSTEMS = [
    "cramfs", "freevxfs", "jffs2", "hfs", "hfsplus", "squashfs", "udf",
]

# Insecure legacy services that should not be running per CIS 2.1
INSECURE_SERVICES = [
    "xinetd", "telnet", "rsh-server", "rlogin", "rexec",
    "nis", "tftp", "talk", "chargen", "daytime", "echo",
]


class LinuxCisAudit(BaseModule):
    """CIS Linux Benchmark v3.0 Level 1 compliance checks via SSH."""

    NAME        = "linux_cis_audit"
    DESCRIPTION = (
        "SSH credentialed CIS Linux Benchmark v3.0 Level 1 checks: filesystem, network, "
        "services, user accounts, logging"
    )
    PHASE       = 5
    TAGS        = ["credentialed", "linux", "cis", "compliance", "benchmark"]

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
        """Run all CIS Level 1 check groups against a single host."""
        await self._check_filesystem(host, ssh, session)
        await self._check_network(host, ssh, session)
        await self._check_services(host, ssh, session)
        await self._check_user_accounts(host, ssh, session)
        await self._check_logging(host, ssh, session)

    # -------------------------------------------------------------------------
    # CIS Section 1 — Filesystem Configuration
    # -------------------------------------------------------------------------

    async def _check_filesystem(self, host: str, ssh, session) -> None:
        """CIS 1.1.x — filesystem hardening checks."""
        await self._check_unused_filesystems(host, ssh, session)
        await self._check_tmp_partition(host, ssh, session)
        await self._check_tmp_nodev(host, ssh, session)
        await self._check_aide_installed(host, ssh, session)

    async def _check_unused_filesystems(self, host: str, ssh, session) -> None:
        """CIS 1.1.1 — Unused filesystems should be disabled via modprobe."""
        enabled_fs = []
        for fs in UNUSED_FILESYSTEMS:
            await self.rate_limit()
            result = await ssh.execute(session, f"modprobe -n -v {fs} 2>/dev/null")
            if not result.success:
                continue
            output = result.stdout.strip()
            # Compliant = "install /bin/true" or no kernel module found
            if output and "install /bin/true" not in output and "not found" not in output.lower():
                enabled_fs.append(fs)

        if enabled_fs:
            self.new_finding(
                title=f"CIS 1.1.1 — Unused Filesystems Enabled — {host}",
                severity=Severity.MEDIUM,
                description=(
                    f"The following unused filesystem kernel modules are loadable on {host}: "
                    f"{', '.join(enabled_fs)}. These increase attack surface for filesystem-based "
                    "exploitation. CIS Benchmark requires they be disabled via modprobe blacklist."
                ),
                reproduction_steps=[
                    f"ssh {host}",
                    f"modprobe -n -v {enabled_fs[0]}",
                ],
                remediation=(
                    "For each filesystem, add to /etc/modprobe.d/cis.conf:\n"
                    "  install <fs> /bin/true\n"
                    "Example: echo 'install cramfs /bin/true' >> /etc/modprobe.d/cis.conf\n"
                    "Run: modprobe -r <fs> to unload if currently loaded."
                ),
                references=[
                    "CIS Linux Benchmark v3.0 — Section 1.1.1",
                    "CWE-1188",
                ],
                evidence=Evidence(extra={"host": host, "enabled_filesystems": enabled_fs}),
                cvss_v31_vector=CVSS_MEDIUM,
                mitre_attack=["TA0005/T1211"],
                target=host, service="ssh", confidence="HIGH",
            )

    async def _check_tmp_partition(self, host: str, ssh, session) -> None:
        """CIS 1.1.6 — /tmp should be on a separate partition or mounted as tmpfs."""
        # CIS-compliant states: /tmp on a separate disk partition OR mounted as tmpfs
        fstab_result = await ssh.execute(session, "grep -E '\\s/tmp\\s' /etc/fstab 2>/dev/null")
        mount_result = await ssh.execute(session, "mount | grep ' /tmp ' 2>/dev/null")

        # Compliant if fstab has a /tmp entry (separate partition or explicit tmpfs)
        fstab_entry = fstab_result.stdout.strip() if fstab_result.success else ""
        # Or if /tmp is currently mounted as tmpfs (systemd-managed tmpfs is also compliant)
        mount_entry = mount_result.stdout.strip() if mount_result.success else ""
        tmpfs_active = "tmpfs" in mount_entry.lower() or "tmpfs" in fstab_entry.lower()
        separate_partition = bool(fstab_entry) and not ("none" in fstab_entry.lower() and not "tmpfs" in fstab_entry.lower())

        if not (separate_partition or tmpfs_active):
            self.new_finding(
                title=f"CIS 1.1.6 — /tmp Not on Separate Partition or tmpfs — {host}",
                severity=Severity.MEDIUM,
                description=(
                    f"/tmp is not configured as a separate partition or tmpfs mount on {host}. "
                    "CIS Benchmark accepts either a dedicated disk partition or a tmpfs mount for "
                    "/tmp (both allow enforcement of noexec/nodev/nosuid mount options). "
                    "Without isolation, /tmp shares space with / and cannot have independent "
                    "mount options, enabling attackers to store and execute malicious files in /tmp."
                ),
                reproduction_steps=[
                    f"ssh {host}",
                    "grep -E '\\s/tmp\\s' /etc/fstab",
                    "mount | grep /tmp",
                ],
                remediation=(
                    "Mount /tmp as tmpfs with restrictive options (CIS-compliant):\n"
                    "  Add to /etc/fstab: tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0\n"
                    "  mount -o remount /tmp\n"
                    "Or configure a dedicated /tmp partition during OS provisioning."
                ),
                references=[
                    "CIS Linux Benchmark v3.0 — Section 1.1.6",
                    "CWE-732",
                ],
                evidence=Evidence(extra={
                    "host": host,
                    "fstab_output": fstab_entry[:300],
                    "mount_output": mount_entry[:300],
                }),
                cvss_v31_vector=CVSS_MEDIUM,
                mitre_attack=["TA0005/T1036"],
                target=host, service="ssh", confidence="HIGH",
            )

    async def _check_tmp_nodev(self, host: str, ssh, session) -> None:
        """CIS 1.1.8 — /tmp must be mounted with nodev option."""
        result = await ssh.execute(session, "mount | grep ' /tmp ' | grep -v nodev 2>/dev/null")
        if result.success and result.stdout.strip():
            self.new_finding(
                title=f"CIS 1.1.8 — /tmp Mounted Without nodev — {host}",
                severity=Severity.MEDIUM,
                description=(
                    f"/tmp on {host} is mounted without the nodev option. "
                    "This allows device files to be created in /tmp, which can be leveraged "
                    "for privilege escalation via device node exploitation."
                ),
                reproduction_steps=[
                    f"ssh {host}",
                    "mount | grep /tmp",
                ],
                remediation=(
                    "Remount /tmp with nodev: mount -o remount,nodev /tmp\n"
                    "Persist in /etc/fstab by adding nodev to the /tmp mount options."
                ),
                references=[
                    "CIS Linux Benchmark v3.0 — Section 1.1.8",
                    "CWE-732",
                ],
                evidence=Evidence(extra={"host": host, "mount_output": result.stdout[:500]}),
                cvss_v31_vector=CVSS_MEDIUM,
                target=host, service="ssh", confidence="HIGH",
            )

    async def _check_aide_installed(self, host: str, ssh, session) -> None:
        """CIS 1.3.1 — AIDE file integrity monitoring should be installed."""
        result = await ssh.execute(
            session,
            "which aide 2>/dev/null || dpkg -l aide 2>/dev/null | grep '^ii' || "
            "rpm -q aide 2>/dev/null"
        )
        if not result.success or not result.stdout.strip():
            self.new_finding(
                title=f"CIS 1.3.1 — AIDE Not Installed — {host}",
                severity=Severity.MEDIUM,
                description=(
                    f"AIDE (Advanced Intrusion Detection Environment) is not installed on {host}. "
                    "AIDE provides file integrity monitoring to detect unauthorized changes to "
                    "system files, a critical control for detecting post-compromise persistence."
                ),
                reproduction_steps=[
                    f"ssh {host}",
                    "which aide || dpkg -l aide",
                ],
                remediation=(
                    "Install AIDE: apt-get install aide aide-common\n"
                    "Initialize the database: aideinit\n"
                    "cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db\n"
                    "Schedule daily checks: crontab -e -> '0 5 * * * /usr/bin/aide --check'"
                ),
                references=[
                    "CIS Linux Benchmark v3.0 — Section 1.3.1",
                    "CWE-665",
                    "NIST SP 800-53 SI-7",
                ],
                evidence=Evidence(extra={"host": host, "check_output": result.stdout[:200]}),
                cvss_v31_vector=CVSS_MEDIUM,
                mitre_attack=["TA0005/T1070"],
                target=host, service="ssh", confidence="HIGH",
            )

    # -------------------------------------------------------------------------
    # CIS Section 3 — Network Configuration
    # -------------------------------------------------------------------------

    async def _check_network(self, host: str, ssh, session) -> None:
        """CIS 3.x — network hardening sysctl checks."""
        await self._check_sysctl_zero(
            host, ssh, session,
            param="net.ipv4.ip_forward",
            cis_ref="3.1.1",
            title="IP Forwarding Enabled",
            description=(
                "IP forwarding (net.ipv4.ip_forward=1) is enabled on this host. "
                "For pure application/database servers this is not expected and allows an attacker "
                "who compromises the host to route traffic through it, pivoting into adjacent "
                "network segments.\n"
                "NOTE: This is EXPECTED and intentional on routers, NAT gateways, VPN servers, "
                "Docker hosts, and Kubernetes nodes. Verify the system role before treating "
                "this as a confirmed finding."
            ),
            remediation=(
                "If this host is NOT a router, VPN gateway, or container orchestration node, "
                "disable IP forwarding:\n"
                "  sysctl -w net.ipv4.ip_forward=0\n"
                "  echo 'net.ipv4.ip_forward = 0' >> /etc/sysctl.d/60-cis.conf\n"
                "  sysctl -p /etc/sysctl.d/60-cis.conf\n"
                "If this host IS a router/VPN/Kubernetes node, document the exception."
            ),
            cvss=CVSS_MEDIUM,
            severity=Severity.MEDIUM,
            mitre=["TA0008/T1021"],
        )
        await self._check_sysctl_zero(
            host, ssh, session,
            param="net.ipv4.conf.all.send_redirects",
            cis_ref="3.1.2",
            title="ICMP Send Redirects Enabled",
            description=(
                "The kernel is configured to send ICMP redirects. An attacker on the local "
                "network can exploit this to silently redirect traffic through a malicious host "
                "(man-in-the-middle)."
            ),
            remediation=(
                "sysctl -w net.ipv4.conf.all.send_redirects=0\n"
                "sysctl -w net.ipv4.conf.default.send_redirects=0\n"
                "echo 'net.ipv4.conf.all.send_redirects = 0' >> /etc/sysctl.d/60-cis.conf"
            ),
            cvss=CVSS_HIGH_NET,
            severity=Severity.HIGH,
            mitre=["TA0009/T1557"],
        )
        await self._check_sysctl_zero(
            host, ssh, session,
            param="net.ipv4.conf.all.accept_redirects",
            cis_ref="3.2.2",
            title="ICMP Redirects Accepted",
            description=(
                "The kernel accepts ICMP redirect messages, which can be sent by an attacker "
                "to manipulate the routing table and redirect traffic through a malicious host."
            ),
            remediation=(
                "sysctl -w net.ipv4.conf.all.accept_redirects=0\n"
                "sysctl -w net.ipv4.conf.default.accept_redirects=0\n"
                "echo 'net.ipv4.conf.all.accept_redirects = 0' >> /etc/sysctl.d/60-cis.conf"
            ),
            cvss=CVSS_HIGH_NET,
            severity=Severity.HIGH,
            mitre=["TA0009/T1557"],
        )
        await self._check_sysctl_zero(
            host, ssh, session,
            param="net.ipv6.conf.all.accept_ra",
            cis_ref="3.3.4",
            title="IPv6 Router Advertisements Accepted",
            description=(
                "The host accepts IPv6 Router Advertisement (RA) messages. An attacker on the "
                "local network can send rogue RAs to redirect IPv6 traffic and perform "
                "man-in-the-middle attacks."
            ),
            remediation=(
                "sysctl -w net.ipv6.conf.all.accept_ra=0\n"
                "sysctl -w net.ipv6.conf.default.accept_ra=0\n"
                "echo 'net.ipv6.conf.all.accept_ra = 0' >> /etc/sysctl.d/60-cis.conf"
            ),
            cvss=CVSS_MEDIUM_NET,
            severity=Severity.MEDIUM,
            mitre=["TA0009/T1557"],
        )

    async def _check_sysctl_zero(
        self,
        host: str,
        ssh,
        session,
        param: str,
        cis_ref: str,
        title: str,
        description: str,
        remediation: str,
        cvss: str,
        severity: Severity,
        mitre: list[str],
    ) -> None:
        """Check that a sysctl parameter is set to 0 (disabled)."""
        result = await ssh.execute(session, f"sysctl {param} 2>/dev/null")
        if not result.success or not result.stdout.strip():
            return
        # Expected format: "net.ipv4.ip_forward = 0"
        m = re.search(r'=\s*(\d+)', result.stdout)
        if m and m.group(1) != "0":
            self.new_finding(
                title=f"CIS {cis_ref} — {title} — {host}",
                severity=severity,
                description=f"{description}\nCurrent value: {result.stdout.strip()}",
                reproduction_steps=[
                    f"ssh {host}",
                    f"sysctl {param}",
                ],
                remediation=remediation,
                references=[
                    f"CIS Linux Benchmark v3.0 — Section {cis_ref}",
                    "CWE-16",
                ],
                evidence=Evidence(extra={"host": host, "param": param, "value": m.group(1)}),
                cvss_v31_vector=cvss,
                mitre_attack=mitre,
                target=host, service="ssh", confidence="HIGH",
            )

    # -------------------------------------------------------------------------
    # CIS Section 2 — Services
    # -------------------------------------------------------------------------

    async def _check_services(self, host: str, ssh, session) -> None:
        """CIS 2.x — unnecessary/insecure service checks."""
        await self._check_insecure_services(host, ssh, session)
        await self._check_xorg(host, ssh, session)
        await self._check_avahi(host, ssh, session)
        await self._check_ldap_server(host, ssh, session)

    async def _check_insecure_services(self, host: str, ssh, session) -> None:
        """CIS 2.1 — Legacy insecure services should not be installed/enabled."""
        enabled = []
        for svc in INSECURE_SERVICES:
            await self.rate_limit()
            result = await ssh.execute(
                session,
                f"systemctl is-enabled {svc} 2>/dev/null || "
                f"dpkg -l {svc} 2>/dev/null | grep '^ii'"
            )
            output = result.stdout.strip().lower()
            if not output:
                continue
            # Only flag explicitly enabled services or installed packages.
            # "static" = unit file has no [Install] section (socket-activated) — NOT the same
            # as enabled. "indirect" = enabled via a dependency — also intentional.
            # "masked" = explicitly disabled. "disabled" = not started at boot.
            # We only flag "enabled" or "enabled-runtime" (explicitly enabled by admin)
            # plus "ii" from dpkg (package installed on Debian/Ubuntu).
            is_systemd_enabled = output in ("enabled", "enabled-runtime")
            is_dpkg_installed   = output.startswith("ii")
            if (is_systemd_enabled or is_dpkg_installed) and \
               "disabled" not in output and "not-found" not in output:
                enabled.append(svc)

        if enabled:
            self.new_finding(
                title=f"CIS 2.1 — Insecure Legacy Services Enabled — {host}",
                severity=Severity.HIGH,
                description=(
                    f"The following insecure legacy services are enabled on {host}: "
                    f"{', '.join(enabled)}. These services transmit data in cleartext "
                    "and have numerous known vulnerabilities. They should be replaced with "
                    "encrypted alternatives (SSH instead of telnet/rsh/rlogin)."
                ),
                reproduction_steps=[
                    f"ssh {host}",
                    f"systemctl is-enabled {enabled[0]}",
                ],
                remediation=(
                    "Disable and remove each service:\n"
                    "  systemctl disable --now <service>\n"
                    "  apt-get purge <package> / yum remove <package>\n"
                    "Use SSH for remote administration instead of telnet/rsh/rlogin."
                ),
                references=[
                    "CIS Linux Benchmark v3.0 — Section 2.1",
                    "CWE-319",
                    "NIST SP 800-53 SC-8",
                ],
                evidence=Evidence(extra={"host": host, "enabled_services": enabled}),
                cvss_v31_vector=CVSS_HIGH_NET,
                mitre_attack=["TA0006/T1040", "TA0001/T1133"],
                target=host, service="ssh", confidence="HIGH",
            )

    async def _check_xorg(self, host: str, ssh, session) -> None:
        """CIS 2.2.2 — Xorg / X11 server should not be installed on servers."""
        result = await ssh.execute(
            session,
            "dpkg -l 'xserver-xorg*' 2>/dev/null | grep '^ii' || "
            "rpm -qa 'xorg-x11-server*' 2>/dev/null"
        )
        if result.success and result.stdout.strip():
            pkgs = [l.split()[1] for l in result.stdout.strip().split("\n")
                    if l.startswith("ii") or (l.strip() and "xorg" in l.lower())]
            if pkgs:
                self.new_finding(
                    title=f"CIS 2.2.2 — X Window System (Xorg) Installed — {host}",
                    severity=Severity.LOW,
                    description=(
                        f"Xorg/X11 server packages are installed on {host}: {', '.join(pkgs[:5])}. "
                        "CIS Benchmark recommends removing Xorg from servers. Xorg has a history of "
                        "local privilege escalation vulnerabilities (device access, setuid helpers).\n"
                        "NOTE: This may be intentional on desktop workstations, VNC/remote-desktop "
                        "servers, or jump-box hosts. Verify the system role before treating "
                        "this as a confirmed finding — on desktop/GUI systems this is expected."
                    ),
                    reproduction_steps=[
                        f"ssh {host}",
                        "dpkg -l 'xserver-xorg*'",
                    ],
                    remediation=(
                        "On headless servers where a GUI is not required:\n"
                        "  apt-get purge xserver-xorg*\n"
                        "  systemctl set-default multi-user.target\n"
                        "On desktop/VNC hosts, this finding can be accepted as a risk exception "
                        "with documented business justification."
                    ),
                    references=[
                        "CIS Linux Benchmark v3.0 — Section 2.2.2",
                        "CWE-269",
                    ],
                    evidence=Evidence(extra={"host": host, "packages": pkgs[:10]}),
                    cvss_v31_vector=CVSS_LOW,
                    target=host, service="ssh", confidence="MEDIUM",
                )

    async def _check_avahi(self, host: str, ssh, session) -> None:
        """CIS 2.2.3 — Avahi daemon (mDNS) should be disabled on servers."""
        result = await ssh.execute(session, "systemctl is-enabled avahi-daemon 2>/dev/null")
        if not result.success:
            return
        output = result.stdout.strip().lower()
        # Only flag if explicitly enabled — not masked/disabled/static
        if output not in ("enabled", "enabled-runtime"):
            return
        self.new_finding(
            title=f"CIS 2.2.3 — Avahi mDNS Daemon Enabled — {host}",
            severity=Severity.LOW,
            description=(
                f"Avahi mDNS/DNS-SD daemon is enabled on {host}. "
                "Avahi broadcasts service discovery information on the local network, "
                "potentially leaking host/service details. It also has a CVE history "
                "(CVE-2021-3502 heap overflow, CVE-2023-38473 assertion DoS).\n"
                "NOTE: Avahi is required in some enterprise environments for mDNS/DNS-SD "
                "service discovery (e.g., network printing, Apple Bonjour compatibility, "
                "CUPS, avahi-enabled applications). Verify whether mDNS discovery is "
                "a business requirement before disabling."
            ),
            reproduction_steps=[
                f"ssh {host}",
                "systemctl is-enabled avahi-daemon",
                "systemctl status avahi-daemon",
            ],
            remediation=(
                "If mDNS service discovery is not required on this host:\n"
                "  systemctl disable --now avahi-daemon\n"
                "  apt-get purge avahi-daemon\n"
                "If Avahi is required, ensure it is patched and restrict its interfaces "
                "via /etc/avahi/avahi-daemon.conf (allow-interfaces=lo)."
            ),
            references=[
                "CIS Linux Benchmark v3.0 — Section 2.2.3",
                "CVE-2021-3502",
                "CVE-2023-38473",
                "CWE-200",
            ],
            evidence=Evidence(extra={"host": host, "status": output}),
            cvss_v31_vector=CVSS_LOW,
            target=host, service="ssh", confidence="MEDIUM",
        )

    async def _check_ldap_server(self, host: str, ssh, session) -> None:
        """CIS 2.2.7 — LDAP server (slapd) should not be installed unless required."""
        result = await ssh.execute(
            session,
            "dpkg -l slapd 2>/dev/null | grep '^ii' || rpm -q openldap-servers 2>/dev/null"
        )
        if result.success and result.stdout.strip() and "not installed" not in result.stdout.lower():
            self.new_finding(
                title=f"CIS 2.2.7 — LDAP Server (slapd) Installed — {host}",
                severity=Severity.MEDIUM,
                description=(
                    f"An LDAP server (slapd/OpenLDAP) is installed on {host}. "
                    "LDAP servers should only be present on dedicated directory servers. "
                    "Unnecessary LDAP services expand the attack surface and may expose "
                    "directory data if misconfigured."
                ),
                reproduction_steps=[
                    f"ssh {host}",
                    "dpkg -l slapd",
                    "ldapsearch -x -H ldap://localhost -b '' -s base 2>/dev/null",
                ],
                remediation=(
                    "If LDAP server is not required, remove it:\n"
                    "  systemctl disable --now slapd\n"
                    "  apt-get purge slapd ldap-utils\n"
                    "If required, ensure it is properly secured and network access restricted."
                ),
                references=[
                    "CIS Linux Benchmark v3.0 — Section 2.2.7",
                    "CWE-1188",
                ],
                evidence=Evidence(extra={"host": host, "pkg_output": result.stdout[:300]}),
                cvss_v31_vector=CVSS_MEDIUM,
                target=host, service="ssh", confidence="HIGH",
            )

    # -------------------------------------------------------------------------
    # CIS Section 5 — Access, Authentication, Authorization
    # -------------------------------------------------------------------------

    async def _check_user_accounts(self, host: str, ssh, session) -> None:
        """CIS 5.x — password policy, account hardening, root login restrictions."""
        await self._check_password_min_length(host, ssh, session)
        await self._check_password_complexity(host, ssh, session)
        await self._check_password_expiry_max(host, ssh, session)
        await self._check_password_expiry_min(host, ssh, session)
        await self._check_system_accounts_shell(host, ssh, session)
        await self._check_root_login_console(host, ssh, session)

    async def _check_password_min_length(self, host: str, ssh, session) -> None:
        """CIS 5.3.1 — Password minimum length >= 14."""
        result = await ssh.execute(
            session,
            "grep -E '^\\s*minlen' /etc/security/pwquality.conf 2>/dev/null"
        )
        minlen = None
        if result.success and result.stdout.strip():
            m = re.search(r'minlen\s*=\s*(\d+)', result.stdout)
            if m:
                minlen = int(m.group(1))

        if minlen is None or minlen < 14:
            self.new_finding(
                title=f"CIS 5.3.1 — Password Minimum Length < 14 — {host}",
                severity=Severity.HIGH,
                description=(
                    f"Password minimum length is {'not configured' if minlen is None else minlen} "
                    f"on {host}. CIS Benchmark requires minlen >= 14. Short passwords are "
                    "vulnerable to brute force and dictionary attacks."
                ),
                reproduction_steps=[
                    f"ssh {host}",
                    "grep minlen /etc/security/pwquality.conf",
                ],
                remediation=(
                    "Set minimum password length in /etc/security/pwquality.conf:\n"
                    "  minlen = 14\n"
                    "Ensure /etc/pam.d/common-password includes: "
                    "pam_pwquality.so retry=3"
                ),
                references=[
                    "CIS Linux Benchmark v3.0 — Section 5.3.1",
                    "CWE-521",
                    "NIST SP 800-63B",
                ],
                evidence=Evidence(extra={
                    "host": host,
                    "configured_minlen": minlen,
                    "raw_output": result.stdout[:200],
                }),
                cvss_v31_vector=CVSS_HIGH_AUTH,
                mitre_attack=["TA0006/T1110"],
                target=host, service="ssh", confidence="HIGH",
            )

    async def _check_password_complexity(self, host: str, ssh, session) -> None:
        """CIS 5.3.2 — Password complexity requirements must be configured."""
        result = await ssh.execute(
            session,
            "grep -E '^\\s*(minclass|dcredit|ucredit|ocredit|lcredit)' "
            "/etc/security/pwquality.conf 2>/dev/null"
        )
        complexity_settings = result.stdout.strip() if result.success else ""

        issues = []
        if not complexity_settings:
            issues.append("No complexity requirements configured in /etc/security/pwquality.conf")
        else:
            # Check dcredit — should be -1 or less (require at least 1 digit)
            m = re.search(r'dcredit\s*=\s*(-?\d+)', complexity_settings)
            if m and int(m.group(1)) >= 0:
                issues.append(f"dcredit = {m.group(1)} (should be negative to require digits)")
            # Check ucredit — require uppercase
            m = re.search(r'ucredit\s*=\s*(-?\d+)', complexity_settings)
            if m and int(m.group(1)) >= 0:
                issues.append(f"ucredit = {m.group(1)} (should be negative to require uppercase)")
            # Check minclass
            m = re.search(r'minclass\s*=\s*(\d+)', complexity_settings)
            if m and int(m.group(1)) < 3:
                issues.append(f"minclass = {m.group(1)} (should be >= 3)")

        if issues:
            self.new_finding(
                title=f"CIS 5.3.2 — Insufficient Password Complexity — {host}",
                severity=Severity.HIGH,
                description=(
                    f"Password complexity is insufficient on {host}: "
                    + "; ".join(issues)
                    + ". Without complexity requirements, passwords are more susceptible "
                    "to dictionary and brute force attacks."
                ),
                reproduction_steps=[
                    f"ssh {host}",
                    "grep -E 'minclass|dcredit|ucredit|ocredit|lcredit' "
                    "/etc/security/pwquality.conf",
                ],
                remediation=(
                    "Configure /etc/security/pwquality.conf:\n"
                    "  minclass = 4\n"
                    "  dcredit = -1\n"
                    "  ucredit = -1\n"
                    "  ocredit = -1\n"
                    "  lcredit = -1"
                ),
                references=[
                    "CIS Linux Benchmark v3.0 — Section 5.3.2",
                    "CWE-521",
                ],
                evidence=Evidence(extra={
                    "host": host,
                    "issues": issues,
                    "config": complexity_settings[:500],
                }),
                cvss_v31_vector=CVSS_HIGH_AUTH,
                mitre_attack=["TA0006/T1110"],
                target=host, service="ssh", confidence="HIGH",
            )

    async def _check_password_expiry_max(self, host: str, ssh, session) -> None:
        """CIS 5.4.1.1 — Maximum password age should be <= 365 days."""
        result = await ssh.execute(
            session, "grep ^PASS_MAX_DAYS /etc/login.defs 2>/dev/null"
        )
        max_days = None
        if result.success and result.stdout.strip():
            m = re.search(r'PASS_MAX_DAYS\s+(\d+)', result.stdout)
            if m:
                max_days = int(m.group(1))

        if max_days is None or max_days > 365 or max_days == 99999:
            self.new_finding(
                title=f"CIS 5.4.1.1 — Password Max Age Not Enforced — {host}",
                severity=Severity.HIGH,
                description=(
                    f"PASS_MAX_DAYS is set to "
                    f"{'not configured' if max_days is None else max_days} on {host}. "
                    "Passwords with no expiry or expiry > 365 days remain valid indefinitely, "
                    "increasing the window of exposure for compromised credentials."
                ),
                reproduction_steps=[
                    f"ssh {host}",
                    "grep ^PASS_MAX_DAYS /etc/login.defs",
                ],
                remediation=(
                    "Set in /etc/login.defs: PASS_MAX_DAYS 90\n"
                    "Apply to existing accounts: chage --maxdays 90 <username>"
                ),
                references=[
                    "CIS Linux Benchmark v3.0 — Section 5.4.1.1",
                    "CWE-262",
                ],
                evidence=Evidence(extra={"host": host, "pass_max_days": max_days}),
                cvss_v31_vector=CVSS_HIGH_AUTH,
                mitre_attack=["TA0006/T1078"],
                target=host, service="ssh", confidence="HIGH",
            )

    async def _check_password_expiry_min(self, host: str, ssh, session) -> None:
        """CIS 5.4.1.2 — Minimum password age should be >= 7 days."""
        result = await ssh.execute(
            session, "grep ^PASS_MIN_DAYS /etc/login.defs 2>/dev/null"
        )
        min_days = None
        if result.success and result.stdout.strip():
            m = re.search(r'PASS_MIN_DAYS\s+(\d+)', result.stdout)
            if m:
                min_days = int(m.group(1))

        if min_days is None or min_days < 7:
            self.new_finding(
                title=f"CIS 5.4.1.2 — Password Minimum Age Not Enforced — {host}",
                severity=Severity.MEDIUM,
                description=(
                    f"PASS_MIN_DAYS is set to "
                    f"{'not configured' if min_days is None else min_days} on {host}. "
                    "A minimum age < 7 days allows users to immediately change passwords back, "
                    "circumventing password history requirements."
                ),
                reproduction_steps=[
                    f"ssh {host}",
                    "grep ^PASS_MIN_DAYS /etc/login.defs",
                ],
                remediation=(
                    "Set in /etc/login.defs: PASS_MIN_DAYS 7\n"
                    "Apply to existing accounts: chage --mindays 7 <username>"
                ),
                references=[
                    "CIS Linux Benchmark v3.0 — Section 5.4.1.2",
                    "CWE-262",
                ],
                evidence=Evidence(extra={"host": host, "pass_min_days": min_days}),
                cvss_v31_vector=CVSS_MEDIUM,
                target=host, service="ssh", confidence="HIGH",
            )

    async def _check_system_accounts_shell(self, host: str, ssh, session) -> None:
        """CIS 5.4.2 — System accounts (UID < 1000) should have non-interactive shells."""
        result = await ssh.execute(
            session,
            "awk -F: '($3 < 1000) {print $1\": \"$7}' /etc/passwd 2>/dev/null | "
            "grep -v '/sbin/nologin\\|/bin/false\\|/usr/sbin/nologin'"
        )
        if not result.success:
            return

        interactive_accounts = []
        for line in result.stdout.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            # Exclude root — it's expected to have a shell
            if line.startswith("root:"):
                continue
            interactive_accounts.append(line[:80])

        if interactive_accounts:
            self.new_finding(
                title=f"CIS 5.4.2 — System Accounts Have Interactive Shells — {host}",
                severity=Severity.HIGH,
                description=(
                    f"{len(interactive_accounts)} system accounts on {host} have interactive "
                    "login shells. System service accounts should use /sbin/nologin or "
                    "/bin/false to prevent interactive login if compromised."
                ),
                reproduction_steps=[
                    f"ssh {host}",
                    "awk -F: '($3 < 1000) {print $1\": \"$7}' /etc/passwd",
                ],
                remediation=(
                    "For each non-root system account, set a non-interactive shell:\n"
                    "  usermod -s /sbin/nologin <account>\n"
                    "Or: chsh -s /usr/sbin/nologin <account>"
                ),
                references=[
                    "CIS Linux Benchmark v3.0 — Section 5.4.2",
                    "CWE-250",
                ],
                evidence=Evidence(extra={
                    "host": host,
                    "accounts": interactive_accounts[:20],
                }),
                cvss_v31_vector=CVSS_HIGH_AUTH,
                mitre_attack=["TA0004/T1078"],
                target=host, service="ssh", confidence="HIGH",
            )

    async def _check_root_login_console(self, host: str, ssh, session) -> None:
        """CIS 5.5 — Root login should be restricted to console via pam_securetty."""
        result = await ssh.execute(
            session,
            "grep -E '^[^#].*pam_securetty' /etc/pam.d/login 2>/dev/null"
        )
        if not result.success or not result.stdout.strip():
            # Also check securetty file exists
            tty_result = await ssh.execute(session, "test -s /etc/securetty && echo exists")
            has_securetty = tty_result.success and "exists" in tty_result.stdout

            self.new_finding(
                title=f"CIS 5.5 — Root Login Not Restricted to Console — {host}",
                severity=Severity.HIGH,
                description=(
                    f"pam_securetty is not configured in /etc/pam.d/login on {host}. "
                    "Without this, root can log in from any terminal or network connection. "
                    f"/etc/securetty {'exists' if has_securetty else 'is missing'}."
                ),
                reproduction_steps=[
                    f"ssh {host}",
                    "grep pam_securetty /etc/pam.d/login",
                    "cat /etc/securetty",
                ],
                remediation=(
                    "Add to /etc/pam.d/login (before other auth lines):\n"
                    "  auth requisite pam_securetty.so\n"
                    "Ensure /etc/securetty lists only approved console TTYs (tty1, tty2, etc.).\n"
                    "Also ensure /etc/ssh/sshd_config has: PermitRootLogin no"
                ),
                references=[
                    "CIS Linux Benchmark v3.0 — Section 5.5",
                    "CWE-250",
                ],
                evidence=Evidence(extra={
                    "host": host,
                    "pam_output": result.stdout[:300],
                    "has_securetty": has_securetty,
                }),
                cvss_v31_vector=CVSS_HIGH_AUTH,
                mitre_attack=["TA0004/T1078.003"],
                target=host, service="ssh", confidence="HIGH",
            )

    # -------------------------------------------------------------------------
    # CIS Section 4 — Logging and Auditing
    # -------------------------------------------------------------------------

    async def _check_logging(self, host: str, ssh, session) -> None:
        """CIS 4.x — audit logging and syslog checks."""
        await self._check_auditd_installed(host, ssh, session)
        await self._check_auditd_running(host, ssh, session)
        await self._check_rsyslog(host, ssh, session)

    async def _check_auditd_installed(self, host: str, ssh, session) -> None:
        """CIS 4.1.1.1 — auditd should be installed."""
        result = await ssh.execute(
            session,
            "dpkg -l auditd 2>/dev/null | grep '^ii' || rpm -q audit 2>/dev/null"
        )
        if not result.success or not result.stdout.strip() or "not installed" in result.stdout.lower():
            self.new_finding(
                title=f"CIS 4.1.1.1 — auditd Not Installed — {host}",
                severity=Severity.HIGH,
                description=(
                    f"auditd is not installed on {host}. Without auditd, there is no kernel-level "
                    "audit trail for security-relevant events (authentication, privilege use, "
                    "file access). This prevents forensic investigation after a compromise."
                ),
                reproduction_steps=[
                    f"ssh {host}",
                    "dpkg -l auditd",
                    "systemctl status auditd",
                ],
                remediation=(
                    "Install and enable auditd:\n"
                    "  apt-get install auditd audispd-plugins\n"
                    "  systemctl enable --now auditd\n"
                    "Deploy CIS audit rules: /etc/audit/rules.d/cis.rules"
                ),
                references=[
                    "CIS Linux Benchmark v3.0 — Section 4.1.1.1",
                    "CWE-223",
                    "NIST SP 800-53 AU-2",
                ],
                evidence=Evidence(extra={"host": host, "check_output": result.stdout[:200]}),
                cvss_v31_vector=CVSS_HIGH_AUTH,
                mitre_attack=["TA0005/T1562.001"],
                target=host, service="ssh", confidence="HIGH",
            )

    async def _check_auditd_running(self, host: str, ssh, session) -> None:
        """CIS 4.1.2 — auditd should be enabled and running."""
        result = await ssh.execute(session, "systemctl is-active auditd 2>/dev/null")
        status = result.stdout.strip().lower()
        if status not in ("active",):
            self.new_finding(
                title=f"CIS 4.1.2 — auditd Not Running — {host}",
                severity=Severity.HIGH,
                description=(
                    f"auditd service status is '{status}' on {host}. "
                    "auditd must be active to capture kernel audit events. "
                    "A stopped audit daemon leaves the system blind to privilege escalation, "
                    "authentication failures, and file tampering."
                ),
                reproduction_steps=[
                    f"ssh {host}",
                    "systemctl is-active auditd",
                    "journalctl -u auditd --no-pager -n 20",
                ],
                remediation=(
                    "Enable and start auditd:\n"
                    "  systemctl enable --now auditd\n"
                    "Verify: systemctl is-active auditd"
                ),
                references=[
                    "CIS Linux Benchmark v3.0 — Section 4.1.2",
                    "CWE-223",
                ],
                evidence=Evidence(extra={"host": host, "auditd_status": status}),
                cvss_v31_vector=CVSS_HIGH_AUTH,
                mitre_attack=["TA0005/T1562.001"],
                target=host, service="ssh", confidence="HIGH",
            )

    async def _check_rsyslog(self, host: str, ssh, session) -> None:
        """CIS 4.2.1 — rsyslog should be configured to capture auth events."""
        result = await ssh.execute(
            session,
            r"grep -E '^\*\.\*|auth|authpriv' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null"
        )
        if not result.success or not result.stdout.strip():
            self.new_finding(
                title=f"CIS 4.2.1 — rsyslog Not Configured for Auth Logging — {host}",
                severity=Severity.MEDIUM,
                description=(
                    f"No auth/authpriv or wildcard log directives found in rsyslog configuration "
                    f"on {host}. Authentication events (login attempts, sudo use, su) may not be "
                    "captured, impeding incident detection and forensic investigation."
                ),
                reproduction_steps=[
                    f"ssh {host}",
                    r"grep -E '^\*\.\*|auth|authpriv' /etc/rsyslog.conf",
                ],
                remediation=(
                    "Add to /etc/rsyslog.conf or /etc/rsyslog.d/auth.conf:\n"
                    "  auth,authpriv.* /var/log/auth.log\n"
                    "  *.* /var/log/syslog\n"
                    "Restart rsyslog: systemctl restart rsyslog"
                ),
                references=[
                    "CIS Linux Benchmark v3.0 — Section 4.2.1",
                    "CWE-223",
                    "NIST SP 800-53 AU-3",
                ],
                evidence=Evidence(extra={"host": host, "rsyslog_output": result.stdout[:500]}),
                cvss_v31_vector=CVSS_MEDIUM,
                mitre_attack=["TA0005/T1562.006"],
                target=host, service="ssh", confidence="MEDIUM",
            )
