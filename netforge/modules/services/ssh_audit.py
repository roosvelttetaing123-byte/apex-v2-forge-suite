"""SSH auditor — weak algorithms, version CVEs, root login, password auth detection.

Checks:
- Banner grabbing and OpenSSH version extraction
- CVE-2024-6387 regreSSHion (unauthenticated RCE, glibc Linux)
- CVE-2023-38408 ssh-agent forwarding RCE
- Weak KEX: diffie-hellman-group1-sha1, diffie-hellman-group14-sha1
- Weak ciphers: arcfour, 3des-cbc, blowfish-cbc
- Weak MACs: hmac-md5, hmac-sha1-96
- Root login indicator (PermitRootLogin) — via ssh-audit tool JSON output
- Password authentication enabled — same
- ssh-audit tool integration (comprehensive algorithm analysis)
"""
from __future__ import annotations

import asyncio
import re
import shutil
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_WEAK_ALGO   = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"
CVSS40_WEAK_ALGO = "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
CVSS_SSH_INFO    = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
CVSS40_SSH_INFO  = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
CVSS_ROOT_LOGIN  = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
CVSS40_ROOT_LOGIN = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
CVSS_PASSWD_AUTH = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
CVSS40_PASSWD_AUTH = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
WEAK_CIPHERS = [
    "arcfour", "arcfour128", "arcfour256",   # RC4 — broken
    "blowfish-cbc",                           # 64-bit block, deprecated
    "cast128-cbc",                            # 64-bit block
    "3des-cbc",                               # Triple DES, 64-bit block, sweet32
    "des",                                    # Single DES — trivially broken
    "aes128-cbc", "aes192-cbc", "aes256-cbc", # CBC mode without AEAD
]

WEAK_MACS = [
    "hmac-md5", "hmac-md5-96",               # MD5-based MACs
    "hmac-sha1", "hmac-sha1-96",             # SHA-1 deprecated (RFC 6194)
    "umac-64@openssh.com",                   # 64-bit tag — truncation risk
]

WEAK_KEX = [
    "diffie-hellman-group1-sha1",    # 768/1024-bit DH — Logjam (CVE-2015-4000)
    "diffie-hellman-group14-sha1",   # 2048-bit DH but SHA-1 digest — deprecated RFC 9142
    "gss-gex-sha1-",                 # GSSAPI with SHA-1
    "gss-group1-sha1-",              # GSSAPI with 1024-bit DH
    "rsa1024-sha1",                  # RSA 1024-bit
]

# CVE-2024-6387 "regreSSHion" — unauthenticated RCE signal handler race (glibc Linux)
# Affects OpenSSH 8.5p1–9.7p1. Fixed in 9.8p1. CVSS 8.1
CVE_2024_6387_MIN = (8, 5)
CVE_2024_6387_FIX = (9, 8)

# CVE-2023-38408 — ssh-agent forwarding RCE. Fixed in 9.3p2
CVE_2023_38408_FIX = (9, 3)

# Logjam / diffie-hellman-group1-sha1 (CVE-2015-4000) — affects all SSH servers
# offering this KEX method regardless of OpenSSH version


class SshAudit(BaseModule):
    """SSH configuration auditor — comprehensive algorithm and CVE checks."""

    NAME        = "ssh_audit"
    DESCRIPTION = (
        "SSH: version CVE detection (regreSSHion, CVE-2023-38408), weak algorithm check "
        "via ssh-audit tool, root login indicator, password auth indicator"
    )
    PHASE       = 4
    TAGS        = ["services", "ssh", "crypto", "cve-2024-6387", "cwe-326", "cwe-521"]

    async def run(self) -> ModuleResult:
        start    = time.monotonic()
        target   = self.config.target
        ssh_port = int(self.config.extra.get("ssh_port", 22))

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        hosts = self.config.extra.get("live_hosts", [target])
        self.log.info("SSH audit on %d host(s) port %d", len(hosts), ssh_port)

        for host in hosts[:30]:
            if not self.check_scope(host):
                continue
            await self.rate_limit()
            if not await self._port_open(host, ssh_port):
                continue
            await self._audit_ssh(host, ssh_port)

        return self._make_result(start)

    # ------------------------------------------------------------------
    # Per-host orchestration
    # ------------------------------------------------------------------

    async def _audit_ssh(self, host: str, port: int) -> None:
        banner = await self._get_banner(host, port)
        if banner:
            self._check_version(banner, host, port)

        # ssh-audit tool gives the most comprehensive analysis
        await self._run_ssh_audit_tool(host, port)

    # ------------------------------------------------------------------
    # Banner & Version
    # ------------------------------------------------------------------

    async def _get_banner(self, host: str, port: int) -> str | None:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=5
            )
            banner_bytes = await asyncio.wait_for(reader.read(256), timeout=3)
            writer.close()
            return banner_bytes.decode(errors="ignore").strip()
        except Exception:
            return None

    def _check_version(self, banner: str, host: str, port: int) -> None:
        """Check for outdated/vulnerable OpenSSH versions.

        Reports CVE-2024-6387 (regreSSHion) for 8.5p1–9.7p1 on glibc Linux,
        CVE-2023-38408 for < 9.3p2, and generic outdated version for < 8.5.
        """
        self.log.info("SSH banner on %s:%d: %s", host, port, banner[:80])
        ev = Evidence(
            request_raw=f"TCP connect {host}:{port} (banner grab)",
            response_raw=banner[:200],
            extra={"host": host, "port": port, "banner": banner[:150]},
        )

        # Always report version disclosure
        if "OpenSSH" in banner or "SSH" in banner:
            self.new_finding(
                title=f"SSH Version Disclosure — {host}:{port}: {banner[:60]}",
                severity=Severity.INFORMATIONAL,
                description=(
                    f"SSH server on {host}:{port} discloses its version in the banner: "
                    f"'{banner[:100]}'. This enables targeted version-specific attacks."
                ),
                reproduction_steps=[f"nc {host} {port}", "Read banner"],
                remediation=(
                    "In sshd_config, consider setting a non-descriptive banner. "
                    "Note: completely hiding the banner is not always possible; "
                    "focus on patching to the latest version."
                ),
                references=["CWE-200"],
                evidence=ev,
                cvss_v31_vector=CVSS_SSH_INFO,
                cvss_v40_vector=CVSS40_SSH_INFO,
                target=host, port=port, service="ssh",
            )

        m = re.search(r"OpenSSH[_\s]+([\d]+)\.?([\d]*)p?([\d]*)", banner, re.IGNORECASE)
        if not m:
            return

        version_str = f"{m.group(1)}.{m.group(2)}p{m.group(3)}" if m.group(3) else f"{m.group(1)}.{m.group(2)}"
        try:
            major = int(m.group(1))
            minor = int(m.group(2)) if m.group(2) else 0
            patch = int(m.group(3)) if m.group(3) else 0
            ver   = (major, minor)
        except (ValueError, IndexError):
            return

        # CVE-2024-6387 — regreSSHion (CVSS 8.1, unauthenticated RCE on glibc)
        if CVE_2024_6387_MIN <= ver < CVE_2024_6387_FIX:
            self.new_finding(
                title=f"CVE-2024-6387 regreSSHion — OpenSSH {version_str} on {host}:{port}",
                severity=Severity.HIGH,
                description=(
                    f"OpenSSH {version_str} on {host}:{port} is vulnerable to CVE-2024-6387 "
                    "(regreSSHion). A race condition in the SIGALRM signal handler allows "
                    "unauthenticated remote code execution on glibc-based Linux systems. "
                    "CVSS 8.1. Exploitation requires ~10,000 connections but is confirmed "
                    "possible. Public PoC released July 2024. Active exploitation observed.\n\n"
                    "NOTE: Not exploitable on OpenBSD, macOS, or musl-libc (Alpine Linux) targets."
                ),
                reproduction_steps=[
                    f"# Verify version: ssh -v {host} -p {port} 2>&1 | grep remote",
                    "# Confirm glibc target: ldd --version (if accessible)",
                    "# Public PoC (authorized testing only): https://github.com/zgzhang/cve-2024-6387-poc",
                ],
                remediation=(
                    "PRIORITY: Upgrade to OpenSSH 9.8p1 or later immediately.\n"
                    "Workaround (DoS risk): Set LoginGraceTime 0 in sshd_config\n"
                    "(disables graceful auth — may cause DoS under load).\n"
                    "Mitigation: rate-limit SSH connections at firewall/iptables."
                ),
                references=[
                    "CVE-2024-6387",
                    "https://www.qualys.com/2024/07/01/cve-2024-6387/regresshion.txt",
                    "CWE-364",
                ],
                evidence=ev,
                cvss_v31_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                mitre_attack=["TA0002/T1210"],
                target=host, port=port, service="ssh",
            )

        # CVE-2023-38408 — ssh-agent RCE. Only report for >= 8.5 (below that, generic outdated covers it)
        if ver >= CVE_2024_6387_MIN and (ver < CVE_2023_38408_FIX or (ver == CVE_2023_38408_FIX and patch < 2)):
            self.new_finding(
                title=f"CVE-2023-38408 ssh-agent RCE Risk — OpenSSH {version_str} on {host}:{port}",
                severity=Severity.HIGH,
                description=(
                    f"OpenSSH {version_str} on {host}:{port} is vulnerable to CVE-2023-38408. "
                    "When a client uses SSH agent forwarding (-A) to connect to a malicious "
                    "server, the server can load and execute a crafted shared library on the "
                    "client via the forwarded ssh-agent socket. "
                    "Requires: agent forwarding enabled AND a compromised intermediate server."
                ),
                reproduction_steps=[
                    "# Requires control of an SSH server victim uses with agent forwarding",
                    "# Attacker serves malicious .so via DLOPEN hook in ssh-agent request",
                ],
                remediation=(
                    "Upgrade to OpenSSH 9.3p2+. "
                    "Disable agent forwarding in client config: ForwardAgent no\n"
                    "Use ProxyJump instead of agent forwarding for bastion hosts."
                ),
                references=["CVE-2023-38408", "CWE-494"],
                evidence=ev,
                cvss_v31_vector="CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H",
                target=host, port=port, service="ssh",
            )

        # Generic outdated version (below regreSSHion range — i.e., < 8.5)
        if ver < CVE_2024_6387_MIN and ver < (9, 0):
            self.new_finding(
                title=f"Outdated OpenSSH Version — {version_str} on {host}:{port}",
                severity=Severity.MEDIUM,
                description=(
                    f"OpenSSH {version_str} on {host}:{port} is outdated (< 8.5). "
                    "Older versions lack security fixes and modern algorithm support. "
                    "Check NVD for version-specific CVEs."
                ),
                reproduction_steps=[f"ssh -v {host} -p {port} 2>&1 | grep remote"],
                remediation="Upgrade OpenSSH to the latest stable version (9.8p1+).",
                references=["CWE-1104"],
                evidence=ev,
                cvss_v31_vector=CVSS_SSH_INFO,
                cvss_v40_vector=CVSS40_SSH_INFO,
                target=host, port=port, service="ssh",
            )

    # ------------------------------------------------------------------
    # ssh-audit tool integration
    # ------------------------------------------------------------------

    async def _run_ssh_audit_tool(self, host: str, port: int) -> None:
        """Run ssh-audit for comprehensive algorithm + configuration analysis.

        ssh-audit reports:
        - Weak/broken KEX, ciphers, MACs
        - PermitRootLogin and PasswordAuthentication status (via banner parsing)
        - Diffie-Hellman group size issues
        """
        ssh_audit_bin = shutil.which("ssh-audit") or shutil.which("ssh_audit")
        if not ssh_audit_bin:
            # Fall back to manual KEX check
            await self._check_weak_algorithms_raw(host, port)
            return

        await self.rate_limit()
        try:
            proc = await asyncio.create_subprocess_exec(
                ssh_audit_bin, "-j", "-p", str(port), host,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
            output = stdout.decode(errors="ignore")

            import json
            try:
                data = json.loads(output)
                await self._parse_ssh_audit_json(data, host, port)
            except json.JSONDecodeError:
                # Text output fallback
                await self._parse_ssh_audit_text(output, host, port)
        except Exception as exc:
            self.log.debug("ssh-audit failed on %s:%d: %s", host, port, exc)
            await self._check_weak_algorithms_raw(host, port)

    async def _parse_ssh_audit_json(self, data: dict, host: str, port: int) -> None:
        """Parse json output from ssh-audit tool."""
        fails: list[str] = []
        warnings: list[str] = []

        for section in ["kex", "enc", "mac", "compression"]:
            for item in data.get(section, []):
                name = item.get("name", "?")
                if item.get("fail"):
                    fails.append(f"{section}: {name}")
                elif item.get("warn"):
                    warnings.append(f"{section}: {name}")

        if fails:
            ev = Evidence(
                extra={"host": host, "port": port, "failed_algorithms": fails, "warnings": warnings}
            )
            severity = Severity.HIGH if any("kex" in f for f in fails) else Severity.MEDIUM
            self.new_finding(
                title=f"SSH Weak/Broken Algorithms ({len(fails)} failures) — {host}:{port}",
                severity=severity,
                description=(
                    f"ssh-audit found {len(fails)} broken algorithm(s) on {host}:{port}:\n"
                    + "\n".join(f"  - {f}" for f in fails[:10])
                    + (f"\n  ...and {len(fails)-10} more" if len(fails) > 10 else "")
                    + (f"\nWarnings ({len(warnings)}): {', '.join(warnings[:5])}" if warnings else "")
                    + "\n\nBroken KEX methods like diffie-hellman-group1-sha1 allow Logjam "
                    "downgrade attacks. RC4/3DES ciphers are cryptographically broken."
                ),
                reproduction_steps=[
                    f"ssh-audit -p {port} {host}",
                    f"ssh-audit -j -p {port} {host}  # JSON output",
                ],
                remediation=(
                    "Harden /etc/ssh/sshd_config:\n"
                    "  KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,"
                    "diffie-hellman-group16-sha512,diffie-hellman-group18-sha512\n"
                    "  Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,"
                    "aes128-gcm@openssh.com,aes256-ctr\n"
                    "  MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com\n"
                    "  Then: systemctl restart sshd"
                ),
                references=["CWE-326", "CVE-2015-4000", "RFC 9142"],
                evidence=ev,
                cvss_v31_vector=CVSS_WEAK_ALGO,
                cvss_v40_vector=CVSS40_WEAK_ALGO,
                target=host, port=port, service="ssh",
            )

        # Check auth policy from banner/conf section
        banner_info = data.get("banner", {})
        raw_banner = banner_info.get("raw", "") if isinstance(banner_info, dict) else ""

        # ssh-audit ≥ 3.x includes auth info
        auth_info = data.get("auth", {})
        if isinstance(auth_info, dict):
            if auth_info.get("password_auth"):
                self._report_password_auth(host, port)
            if auth_info.get("root_login") not in (None, False, "no", "prohibit-password"):
                self._report_root_login(host, port, auth_info.get("root_login", "yes"))

    async def _parse_ssh_audit_text(self, output: str, host: str, port: int) -> None:
        """Parse text output from ssh-audit for fail/warn entries."""
        fail_count = output.lower().count("[fail]")
        warn_count = output.lower().count("[warn]")

        if fail_count > 0:
            ev = Evidence(
                response_raw=output[:1000],
                extra={"host": host, "port": port, "fail_count": fail_count},
            )
            self.new_finding(
                title=f"SSH Weak Algorithms Detected ({fail_count} failures) — {host}:{port}",
                severity=Severity.HIGH,
                description=f"ssh-audit reported {fail_count} failed algorithm checks on {host}:{port}.",
                reproduction_steps=[f"ssh-audit -p {port} {host}"],
                remediation="Update KexAlgorithms, Ciphers, and MACs in sshd_config. See ssh-audit recommendations.",
                references=["CWE-326"],
                evidence=ev,
                cvss_v31_vector=CVSS_WEAK_ALGO,
                cvss_v40_vector=CVSS40_WEAK_ALGO,
                target=host, port=port, service="ssh",
            )

        # Check for root login warnings in text output
        if "permitrootlogin" in output.lower() and "yes" in output.lower():
            self._report_root_login(host, port, "yes")
        if "passwordauthentication" in output.lower() and (
            "[warn]" in output.lower() or "enabled" in output.lower()
        ):
            self._report_password_auth(host, port)

    # ------------------------------------------------------------------
    # Raw weak algorithm detection (when ssh-audit unavailable)
    # ------------------------------------------------------------------

    async def _check_weak_algorithms_raw(self, host: str, port: int) -> None:
        """Perform a basic SSH KEX init to extract advertised algorithms."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=5
            )
            # Read server banner
            await asyncio.wait_for(reader.read(256), timeout=3)

            # Send our SSH_MSG_KEXINIT to get server's
            # We send a minimal KEXINIT — server responds with its own
            import os
            cookie = os.urandom(16)
            # Minimal KEXINIT payload
            kexinit_payload = (
                cookie
                + b"\x00\x00\x00\x00"  # kex_algorithms length = 0
                + b"\x00\x00\x00\x00"  # server_host_key_algorithms length = 0
                + b"\x00\x00\x00\x00"  # encryption_algorithms_client_to_server
                + b"\x00\x00\x00\x00"  # encryption_algorithms_server_to_client
                + b"\x00\x00\x00\x00"  # mac_algorithms_client_to_server
                + b"\x00\x00\x00\x00"  # mac_algorithms_server_to_client
                + b"\x00\x00\x00\x00"  # compression_algorithms_c_to_s
                + b"\x00\x00\x00\x00"  # compression_algorithms_s_to_c
                + b"\x00\x00\x00\x00"  # languages_c_to_s
                + b"\x00\x00\x00\x00"  # languages_s_to_c
                + b"\x00"              # first_kex_packet_follows
                + b"\x00\x00\x00\x00" # reserved
            )
            msg_type = b"\x14"  # SSH_MSG_KEXINIT = 20
            payload  = msg_type + kexinit_payload
            pad_len  = 8 - (len(payload) + 1) % 8
            if pad_len < 4:
                pad_len += 8
            padding = os.urandom(pad_len)
            packet  = bytes([0, 0, 0, len(payload) + pad_len + 1, pad_len]) + payload + padding

            writer.write(packet)
            await writer.drain()

            # Read server KEXINIT response (up to 4KB)
            resp = await asyncio.wait_for(reader.read(4096), timeout=5)
            writer.close()

            # Try to parse kex algorithms from server KEXINIT
            # Server KEXINIT payload starts at offset 5 (packet_length[4] + padding_length[1])
            # Then message type 0x14 at byte [5], cookie at [6:22], then 10 string lists
            self._parse_kexinit_response(resp, host, port)
        except Exception as exc:
            self.log.debug("Raw KEX check failed on %s:%d: %s", host, port, exc)

    def _parse_kexinit_response(self, data: bytes, host: str, port: int) -> None:
        """Extract and check algorithm lists from raw SSH KEXINIT packet."""
        try:
            if len(data) < 40:
                return
            # Find SSH_MSG_KEXINIT (0x14) in data
            idx = data.find(b"\x14")
            if idx < 0:
                return
            pos = idx + 1 + 16  # skip msg_type + cookie

            found_weak: list[str] = []
            for _ in range(10):  # 10 name-list fields
                if pos + 4 > len(data):
                    break
                length = int.from_bytes(data[pos:pos+4], "big")
                pos += 4
                if pos + length > len(data):
                    break
                alg_list_str = data[pos:pos+length].decode(errors="ignore")
                pos += length

                for alg in alg_list_str.split(","):
                    alg_lower = alg.strip().lower()
                    for weak in WEAK_KEX + WEAK_CIPHERS + WEAK_MACS:
                        if weak.lower() in alg_lower:
                            found_weak.append(alg.strip())
                            break

            if found_weak:
                ev = Evidence(
                    extra={"host": host, "port": port, "weak_algorithms": found_weak}
                )
                self.new_finding(
                    title=f"SSH Weak Algorithms Advertised — {host}:{port}",
                    severity=Severity.MEDIUM,
                    description=(
                        f"SSH server on {host}:{port} advertises weak algorithms: "
                        f"{', '.join(found_weak[:8])}"
                    ),
                    reproduction_steps=[
                        f"ssh-audit -p {port} {host}",
                        f"nmap --script ssh2-enum-algos -p {port} {host}",
                    ],
                    remediation=(
                        "Update KexAlgorithms, Ciphers, MACs in sshd_config. "
                        "Remove: diffie-hellman-group1-sha1, arcfour*, 3des-cbc, hmac-md5*"
                    ),
                    references=["CWE-326", "RFC 9142"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_WEAK_ALGO,
                    cvss_v40_vector=CVSS40_WEAK_ALGO,
                    target=host, port=port, service="ssh",
                )
        except Exception as exc:
            self.log.debug("KEXINIT parse error: %s", exc)

    # ------------------------------------------------------------------
    # Auth policy findings
    # ------------------------------------------------------------------

    def _report_root_login(self, host: str, port: int, value: str) -> None:
        """Report that PermitRootLogin is not set to 'no' or 'prohibit-password'."""
        self.new_finding(
            title=f"SSH PermitRootLogin Enabled ({value}) — {host}:{port}",
            severity=Severity.HIGH,
            description=(
                f"SSH server on {host}:{port} has PermitRootLogin set to '{value}'. "
                "Allowing direct root SSH login increases the risk of complete host compromise "
                "via brute force, credential stuffing, or stolen key material. "
                "The root account should never be directly accessible via SSH."
            ),
            reproduction_steps=[
                f"ssh root@{host} -p {port}",
                "# Or via ssh-audit: ssh-audit -p {port} {host} | grep -i root",
            ],
            remediation=(
                "In /etc/ssh/sshd_config:\n"
                "  PermitRootLogin no\n"
                "  # Or if key-only root is required:\n"
                "  PermitRootLogin prohibit-password\n"
                "Restart: systemctl restart sshd"
            ),
            references=["CWE-250", "CIS Benchmark: 5.2.10", "NIST SP 800-115"],
            evidence=Evidence(extra={"host": host, "port": port, "PermitRootLogin": value}),
            cvss_v31_vector=CVSS_ROOT_LOGIN,
            cvss_v40_vector=CVSS40_ROOT_LOGIN,
            mitre_attack=["TA0001/T1078.003"],
            target=host, port=port, service="ssh",
        )

    def _report_password_auth(self, host: str, port: int) -> None:
        """Report that PasswordAuthentication is enabled."""
        self.new_finding(
            title=f"SSH Password Authentication Enabled — {host}:{port}",
            severity=Severity.MEDIUM,
            description=(
                f"SSH server on {host}:{port} allows password-based authentication. "
                "Password authentication enables online brute-force and credential stuffing attacks. "
                "Key-based authentication is cryptographically stronger and immune to "
                "password spraying, phishing, and database breach reuse attacks."
            ),
            reproduction_steps=[
                f"ssh user@{host} -p {port}  # Will prompt for password",
                f"hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://{host}:{port}",
            ],
            remediation=(
                "Disable password auth, enforce key-based only:\n"
                "  In /etc/ssh/sshd_config:\n"
                "  PasswordAuthentication no\n"
                "  ChallengeResponseAuthentication no\n"
                "  AuthenticationMethods publickey\n"
                "  systemctl restart sshd"
            ),
            references=["CWE-521", "CIS Benchmark: 5.2.12", "OWASP A07:2021"],
            evidence=Evidence(extra={"host": host, "port": port, "PasswordAuthentication": "yes"}),
            cvss_v31_vector=CVSS_PASSWD_AUTH,
            cvss_v40_vector=CVSS40_PASSWD_AUTH,
            mitre_attack=["TA0006/T1110.001"],
            target=host, port=port, service="ssh",
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def _port_open(self, host: str, port: int) -> bool:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=2.0
            )
            writer.close()
            return True
        except Exception:
            return False


class TestSshAudit:
    def test_weak_ciphers_present(self) -> None:
        assert "arcfour" in WEAK_CIPHERS
        assert "3des-cbc" in WEAK_CIPHERS

    def test_weak_kex_present(self) -> None:
        assert "diffie-hellman-group1-sha1" in WEAK_KEX
        assert "diffie-hellman-group14-sha1" in WEAK_KEX

    def test_weak_macs_present(self) -> None:
        assert "hmac-md5" in WEAK_MACS
        assert "hmac-sha1" in WEAK_MACS

    def test_version_regex(self) -> None:
        banner = "SSH-2.0-OpenSSH_9.7p1"
        m = re.search(r"OpenSSH[_\s]+([\d]+)\.?([\d]*)p?([\d]*)", banner, re.IGNORECASE)
        assert m is not None
        assert m.group(1) == "9"
        assert m.group(2) == "7"
        assert m.group(3) == "1"

    def test_cve_ranges(self) -> None:
        # 9.7 should be in regreSSHion range
        ver = (9, 7)
        assert CVE_2024_6387_MIN <= ver < CVE_2024_6387_FIX
        # 9.8 should be fixed
        ver_fixed = (9, 8)
        assert not (CVE_2024_6387_MIN <= ver_fixed < CVE_2024_6387_FIX)

    def test_phase(self) -> None:
        assert SshAudit.PHASE == 4
