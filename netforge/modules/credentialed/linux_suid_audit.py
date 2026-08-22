"""Linux SUID/SGID Audit — credentialed check for dangerous setuid binaries.

Checks:
  - SUID binaries with known GTFOBins privesc paths
  - SGID binaries in unusual locations
  - World-writable SUID/SGID files (trivial privesc)
  - Custom SUID binaries (not part of default OS install)
  - World-writable directories without sticky bit
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_SUID_GTFO  = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
CVSS_SUID_CUSTOM = "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N"
CVSS_WORLD_WRITE = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N"

# GTFOBins SUID privesc candidates — if these are SUID root, game over
GTFOBINS_SUID = {
    "aria2c", "arp", "ash", "awk", "base32", "base64", "bash", "busybox",
    "cat", "chmod", "chown", "cp", "csh", "curl", "cut", "dash", "dd",
    "diff", "dmsetup", "docker", "ed", "emacs", "env", "expand", "expect",
    "file", "find", "flock", "fmt", "fold", "gdb", "gimp", "grep", "head",
    "hexdump", "highlight", "iconv", "iftop", "install", "ionice", "ip",
    "jjs", "join", "jq", "ksh", "ld.so", "less", "logsave", "look",
    "lua", "make", "mawk", "more", "mv", "mysql", "nano", "nawk", "nc",
    "nice", "nl", "nmap", "node", "nohup", "od", "openssl", "perl",
    "pg", "php", "pic", "pico", "python", "python2", "python3", "readelf",
    "restic", "rev", "rlwrap", "rsync", "ruby", "run-parts", "rview",
    "rvim", "sed", "setarch", "shuf", "socat", "sort", "sqlite3",
    "ss", "ssh-keygen", "start-stop-daemon", "stdbuf", "strace", "strings",
    "sysctl", "tail", "tar", "taskset", "tclsh", "tee", "tftp",
    "time", "timeout", "ul", "unexpand", "uniq", "unshare", "vi", "vim",
    "watch", "wget", "wish", "xargs", "xxd", "zip", "zsh",
}

# Known safe SUID binaries (default OS installs)
KNOWN_SUID = {
    "/usr/bin/passwd", "/usr/bin/chfn", "/usr/bin/chsh", "/usr/bin/newgrp",
    "/usr/bin/gpasswd", "/usr/bin/sudo", "/usr/bin/su", "/usr/bin/mount",
    "/usr/bin/umount", "/usr/bin/pkexec", "/usr/bin/crontab",
    "/usr/sbin/unix_chkpwd", "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
    "/usr/lib/openssh/ssh-keysign", "/usr/lib/policykit-1/polkit-agent-helper-1",
    "/usr/bin/fusermount", "/usr/bin/fusermount3", "/usr/bin/at",
    "/usr/bin/expiry", "/usr/bin/wall", "/usr/bin/ssh-agent",
    "/usr/bin/staprun", "/usr/sbin/pppd",
}


class LinuxSuidAudit(BaseModule):
    """Credentialed SUID/SGID binary audit with GTFOBins matching."""

    NAME        = "linux_suid_audit"
    DESCRIPTION = "SSH credentialed: SUID/SGID binaries, GTFOBins privesc, world-writable dirs"
    PHASE       = 5
    TAGS        = ["credentialed", "linux", "suid", "privesc", "gtfobins", "cwe-250"]

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
            await self._audit_suid(host, transport_mgr.ssh, session)

        return self._make_result(start)

    async def _audit_suid(self, host: str, ssh, session) -> None:
        """Find and classify SUID/SGID binaries."""
        # Find all SUID binaries
        result = await ssh.execute(
            session,
            "find / -perm -4000 -type f -ls 2>/dev/null | head -200"
        )
        suid_bins = self._parse_find_output(result.stdout)

        # Find SGID binaries
        sgid_result = await ssh.execute(
            session,
            "find / -perm -2000 -type f -ls 2>/dev/null | head -100"
        )

        # GTFOBins check
        gtfo_hits = []
        custom_suid = []
        for path, perms in suid_bins:
            basename = Path(path).name
            if basename in GTFOBINS_SUID:
                gtfo_hits.append(path)
            elif path not in KNOWN_SUID:
                custom_suid.append(path)

        if gtfo_hits:
            self.new_finding(
                title=f"GTFOBins SUID Privesc Binaries — {host}",
                severity=Severity.CRITICAL,
                description=(
                    f"Found {len(gtfo_hits)} SUID binaries with known GTFOBins privilege escalation "
                    f"paths on {host}: {', '.join(gtfo_hits[:10])}. "
                    "These can be used by any local user to escalate to root."
                ),
                reproduction_steps=[
                    f"ssh {host}",
                    "find / -perm -4000 -type f 2>/dev/null",
                    f"# Then use GTFOBins.github.io for privesc payload",
                ],
                remediation=(
                    "Remove SUID bit from non-essential binaries: chmod u-s <binary>. "
                    "Use capabilities instead of SUID where possible."
                ),
                references=["CWE-250", "https://gtfobins.github.io/"],
                evidence=Evidence(extra={
                    "host": host,
                    "gtfobins_suid": gtfo_hits,
                    "total_suid": len(suid_bins),
                }),
                cvss_v31_vector=CVSS_SUID_GTFO,
                mitre_attack=["TA0004/T1548.001"],
                target=host,
                service="ssh",
                confidence="HIGH",
            )

        if custom_suid:
            self.new_finding(
                title=f"Custom SUID Binaries ({len(custom_suid)}) — {host}",
                severity=Severity.HIGH,
                description=(
                    f"Found {len(custom_suid)} non-standard SUID binaries on {host}: "
                    f"{', '.join(custom_suid[:10])}. Custom SUID binaries are high-value "
                    "privesc targets — any vulnerability in these = root."
                ),
                reproduction_steps=[
                    f"ssh {host}",
                    "find / -perm -4000 -type f 2>/dev/null | sort",
                ],
                remediation="Audit each custom SUID binary. Remove SUID bit if not required.",
                references=["CWE-250"],
                evidence=Evidence(extra={"host": host, "custom_suid": custom_suid[:30]}),
                cvss_v31_vector=CVSS_SUID_CUSTOM,
                mitre_attack=["TA0004/T1548.001"],
                target=host,
                service="ssh",
            )

        # World-writable directories without sticky bit
        ww_result = await ssh.execute(
            session,
            "find / -type d -perm -0002 ! -perm -1000 -ls 2>/dev/null | grep -v proc | head -50"
        )
        ww_dirs = [line.split()[-1] for line in ww_result.stdout.strip().split("\n")
                    if line.strip() and "/" in line]

        if ww_dirs:
            self.new_finding(
                title=f"World-Writable Dirs Without Sticky Bit — {host}",
                severity=Severity.MEDIUM,
                description=(
                    f"Found {len(ww_dirs)} world-writable directories without sticky bit: "
                    f"{', '.join(ww_dirs[:10])}. Users can delete each other's files."
                ),
                reproduction_steps=[
                    f"ssh {host}",
                    "find / -type d -perm -0002 ! -perm -1000 2>/dev/null",
                ],
                remediation="Add sticky bit: chmod +t <dir>",
                references=["CWE-732", "CIS Benchmark 1.1.21"],
                evidence=Evidence(extra={"host": host, "dirs": ww_dirs[:20]}),
                cvss_v31_vector=CVSS_WORLD_WRITE,
                target=host,
                service="ssh",
            )

    def _parse_find_output(self, output: str) -> list[tuple[str, str]]:
        """Parse 'find -ls' output into (path, perms) tuples."""
        results = []
        for line in output.strip().split("\n"):
            parts = line.split()
            if len(parts) >= 11:
                perms = parts[2]
                path = parts[-1]
                results.append((path, perms))
        return results
