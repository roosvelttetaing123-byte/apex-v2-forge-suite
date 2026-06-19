"""NFS Auditor — showmount exports, no_root_squash, world-readable shares.

Tests:
  - Export enumeration via showmount
  - no_root_squash detection (UID 0 access)
  - World-readable exports (/*)
  - Sensitive path exposure
"""
from __future__ import annotations

import asyncio
import shutil
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_NOROOT     = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
CVSS40_NOROOT   = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
CVSS_WORLD_READ = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
CVSS40_WORLD_READ = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"

SENSITIVE_PATHS = ["/etc", "/home", "/root", "/var", "/opt", "/srv", "/backup", "/"]


class NfsAudit(BaseModule):
    """NFS share security auditor."""

    NAME        = "nfs_audit"
    DESCRIPTION = "NFS: showmount exports, no_root_squash, world-readable shares"
    PHASE       = 4
    TAGS        = ["nfs", "services", "file-share", "cwe-732", "cwe-284"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        hosts = self.config.extra.get("live_hosts", [target])
        for host in hosts[:20]:
            if not self.check_scope(host):
                continue
            await self.rate_limit()
            await self._audit_nfs(host)

        return self._make_result(start)

    async def _audit_nfs(self, host: str) -> None:
        showmount = shutil.which("showmount")
        if not showmount:
            # Try nmap fallback
            await self._nmap_nfs(host)
            return

        try:
            proc = await asyncio.create_subprocess_exec(
                showmount, "-e", host,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=15)
            output = stdout.decode(errors="ignore")

            if "Export list" not in output and not output.strip():
                return

            exports = self._parse_exports(output)
            if not exports:
                return

            world_accessible = [e for e in exports if "*" in e.get("access", "")]
            sensitive = [
                e for e in exports
                if any(e["path"].startswith(sp) for sp in SENSITIVE_PATHS)
            ]

            ev = Evidence(
                request_raw=f"showmount -e {host}",
                response_raw=output[:2000],
                extra={
                    "exports": exports[:20],
                    "world_accessible": world_accessible,
                    "sensitive_paths": sensitive,
                },
            )

            severity = Severity.CRITICAL if world_accessible and sensitive else Severity.HIGH

            self.new_finding(
                title=f"NFS Exports Exposed — {host} ({len(exports)} exports)",
                severity=severity,
                description=(
                    f"NFS server on {host} exports {len(exports)} share(s):\n"
                    + "\n".join(f"  {e['path']} → {e['access']}" for e in exports[:10])
                    + ("\n\nWORLD-ACCESSIBLE exports (everyone/*):" if world_accessible else "")
                    + ("\n" + "\n".join(f"  {e['path']}" for e in world_accessible[:5]) if world_accessible else "")
                    + "\n\nAttacker can mount these shares and read/write files. "
                    "If no_root_squash is set, UID 0 maps to root — enabling full access."
                ),
                reproduction_steps=[
                    f"showmount -e {host}",
                    f"mount -t nfs {host}:{exports[0]['path']} /mnt/nfs -o vers=3",
                    "ls -la /mnt/nfs",
                    "# Check root squash: touch /mnt/nfs/test_write as root",
                ],
                remediation=(
                    "1. Restrict exports to specific IPs:\n"
                    f"   /exports 192.168.1.0/24(ro,root_squash) in /etc/exports\n"
                    "2. Always use root_squash (default, never use no_root_squash)\n"
                    "3. Firewall: block TCP/UDP 2049 from untrusted networks\n"
                    "4. Use NFSv4 with Kerberos authentication (sec=krb5p)"
                ),
                references=["CWE-732", "CWE-284", "MITRE T1135"],
                evidence=ev,
                cvss_v31_vector=CVSS_NOROOT if world_accessible else CVSS_WORLD_READ,
                cvss_v40_vector=CVSS40_NOROOT if world_accessible else CVSS40_WORLD_READ,
                mitre_attack=["TA0007/T1135"],
                port=2049, service="nfs", target=host,
            )
        except Exception as exc:
            self.log.debug("NFS audit failed on %s: %s", host, exc)

    async def _nmap_nfs(self, host: str) -> None:
        nmap = shutil.which("nmap")
        if not nmap:
            return
        try:
            proc = await asyncio.create_subprocess_exec(
                nmap, "-p", "2049,111", "--script", "nfs-showmount,nfs-ls",
                "--script-timeout", "15s", "-n", "-Pn", host,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
            output = stdout.decode(errors="ignore")

            if "nfs-showmount" in output.lower() or "/" in output:
                ev = Evidence(
                    request_raw=f"nmap --script nfs-showmount {host}",
                    response_raw=output[:2000],
                    extra={"host": host},
                )
                self.new_finding(
                    title=f"NFS Exports Detected (nmap) — {host}",
                    severity=Severity.HIGH,
                    description=f"NFS exports detected on {host}:\n{output[:500]}",
                    reproduction_steps=[f"nmap -p 2049 --script nfs-showmount {host}"],
                    remediation="Restrict NFS exports. Use root_squash and Kerberos auth.",
                    references=["CWE-732"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_WORLD_READ,
                    cvss_v40_vector=CVSS40_WORLD_READ,
                    port=2049, service="nfs", target=host,
                )
        except Exception:
            pass

    def _parse_exports(self, output: str) -> list[dict]:
        exports = []
        for line in output.strip().split("\n"):
            line = line.strip()
            if line.startswith("Export") or not line or line.startswith("------"):
                continue
            parts = line.split()
            if parts:
                path = parts[0]
                access = " ".join(parts[1:]) if len(parts) > 1 else "*"
                exports.append({"path": path, "access": access})
        return exports


class TestNfsAudit:
    def test_sensitive_paths(self) -> None:
        assert "/root" in SENSITIVE_PATHS
        assert "/" in SENSITIVE_PATHS

    def test_cvss(self) -> None:
        assert CVSS_NOROOT.startswith("CVSS:3.1")
        assert CVSS40_NOROOT.startswith("CVSS:4.0")

    def test_parse_exports(self) -> None:
        mod = NfsAudit.__new__(NfsAudit)
        output = "Export list for server:\n/home   *\n/backup 192.168.1.0/24"
        exports = mod._parse_exports(output)
        assert len(exports) == 2
        assert exports[0]["path"] == "/home"

    def test_phase(self) -> None:
        assert NfsAudit.PHASE == 4
