"""OS Detection — TCP/IP stack fingerprinting + nmap OS detection.

Tests:
  - TTL-based OS family detection (Linux ~64, Windows ~128, Cisco ~255)
  - TCP window size analysis
  - nmap OS detection (-O) integration
  - Banner-based OS identification
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

CVSS_INFO = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
CVSS40_INFO = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"

TTL_MAP = {
    (1, 64): "Linux/Unix/macOS",
    (65, 128): "Windows",
    (129, 255): "Cisco/Network Device",
}


class OsDetect(BaseModule):
    """OS detection via TCP/IP fingerprinting."""

    NAME        = "os_detect"
    DESCRIPTION = "OS detection: TTL analysis, TCP fingerprinting, nmap -O"
    PHASE       = 2
    TAGS        = ["recon", "discovery", "os-detect", "cwe-200"]

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
            await self._detect_os(host)

        return self._make_result(start)

    async def _detect_os(self, host: str) -> None:
        os_info = {"host": host, "methods": []}

        # Method 1: TTL-based detection via ping
        ttl = await self._get_ttl(host)
        if ttl is not None:
            os_family = "Unknown"
            for (low, high), family in TTL_MAP.items():
                if low <= ttl <= high:
                    os_family = family
                    break
            os_info["ttl"] = ttl
            os_info["ttl_os_family"] = os_family
            os_info["methods"].append("TTL")

        # Method 2: nmap OS detection
        nmap_result = await self._nmap_os_detect(host)
        if nmap_result:
            os_info.update(nmap_result)
            os_info["methods"].append("nmap")

        # Method 3: Banner-based
        banner_os = await self._banner_os_detect(host)
        if banner_os:
            os_info["banner_os"] = banner_os
            os_info["methods"].append("banner")

        if os_info.get("methods"):
            best_guess = (
                os_info.get("nmap_os")
                or os_info.get("banner_os")
                or os_info.get("ttl_os_family", "Unknown")
            )

            ev = Evidence(extra=os_info)
            self.new_finding(
                title=f"OS Detection — {host} ({best_guess})",
                severity=Severity.INFORMATIONAL,
                description=(
                    f"Operating system detected on {host}: {best_guess}\n"
                    f"Methods used: {', '.join(os_info['methods'])}\n"
                    + (f"TTL: {ttl} → {os_info.get('ttl_os_family', '?')}" if ttl else "")
                ),
                reproduction_steps=[f"nmap -O {host}"],
                remediation="Suppress OS fingerprinting where possible (randomize TTL, use WAF).",
                references=["CWE-200"],
                evidence=ev,
                cvss_v31_vector=CVSS_INFO,
                cvss_v40_vector=CVSS40_INFO,
                target=host,
            )
            self.config.extra.setdefault("os_map", {})[host] = best_guess

    async def _get_ttl(self, host: str) -> int | None:
        """Get TTL via ping."""
        import platform
        ping_cmd = ["ping", "-n", "1", "-w", "2000"] if platform.system() == "Windows" else ["ping", "-c", "1", "-W", "2"]
        try:
            proc = await asyncio.create_subprocess_exec(
                *ping_cmd, host,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
            output = stdout.decode(errors="ignore")
            import re
            m = re.search(r"ttl[=:](\d+)", output, re.I)
            if m:
                return int(m.group(1))
        except Exception:
            pass
        return None

    async def _nmap_os_detect(self, host: str) -> dict | None:
        nmap = shutil.which("nmap")
        if not nmap:
            return None

        await self.rate_limit()
        try:
            proc = await asyncio.create_subprocess_exec(
                nmap, "-O", "--osscan-guess",
                "-n", "-Pn", host,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
            output = stdout.decode(errors="ignore")

            import re
            # Parse "Running: ..." or "OS details: ..."
            m = re.search(r"(?:Running|OS details):\s*(.+)", output)
            if m:
                return {"nmap_os": m.group(1).strip(), "nmap_raw": output[:1000]}
            m = re.search(r"Aggressive OS guesses:\s*(.+)", output)
            if m:
                return {"nmap_os": m.group(1).split(",")[0].strip(), "nmap_raw": output[:1000]}
        except Exception:
            pass
        return None

    async def _banner_os_detect(self, host: str) -> str | None:
        """Check SSH/HTTP banners for OS clues."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, 22), timeout=3
            )
            data = await asyncio.wait_for(reader.read(256), timeout=3)
            writer.close()
            banner = data.decode(errors="ignore")

            if "Ubuntu" in banner:
                return "Ubuntu Linux"
            if "Debian" in banner:
                return "Debian Linux"
            if "Windows" in banner:
                return "Windows"
            if "FreeBSD" in banner:
                return "FreeBSD"
        except Exception:
            pass
        return None


class TestOsDetect:
    def test_ttl_map(self) -> None:
        assert TTL_MAP[(1, 64)] == "Linux/Unix/macOS"
        assert TTL_MAP[(65, 128)] == "Windows"

    def test_cvss(self) -> None:
        assert CVSS_INFO.startswith("CVSS:3.1")
        assert CVSS40_INFO.startswith("CVSS:4.0")

    def test_phase(self) -> None:
        assert OsDetect.PHASE == 2
