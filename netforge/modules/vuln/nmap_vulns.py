"""Nmap vulnerability scanner — run nmap NSE vuln scripts on discovered hosts."""
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

CVSS_VULN = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
CVSS40_VULN = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
VULN_SCRIPTS = [
    "vuln",
    "smb-vuln-ms17-010",
    "smb-vuln-cve2009-3103",
    "rdp-vuln-ms12-020",
    "ssl-heartbleed",
    "ssl-poodle",
    "ssl-drown",
    "ftp-anon",
    "ftp-vsftpd-backdoor",
    "ms-sql-empty-password",
    "mysql-empty-password",
    "vnc-info",
    "http-shellshock",
    "http-slowloris-check",
]


class NmapVulns(BaseModule):
    """Nmap NSE vulnerability script runner."""

    NAME        = "nmap_vulns"
    DESCRIPTION = "Run nmap NSE vulnerability scripts against open ports"
    PHASE       = 5
    TAGS        = ["vuln", "nmap", "nse", "network"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()

        nmap = shutil.which("nmap")
        if not nmap:
            self.log.warning("nmap not found — skipping vuln scan")
            return self._make_result(start, skipped=True, skip_reason="nmap not installed")

        hosts = self.config.extra.get("live_hosts", [self.config.target])
        open_ports_map = self.config.extra.get("open_ports", {})

        for host in hosts[:10]:
            ports = open_ports_map.get(host, [])
            port_list = ",".join(str(p["port"]) for p in ports) if ports else "top50"
            await self._scan_host(host, port_list, nmap)

        return self._make_result(start)

    async def _scan_host(self, host: str, ports: str, nmap: str) -> None:
        if not self.check_scope(host):
            return

        await self.rate_limit()
        self.log.info("Running nmap vuln scripts on %s", host)

        cmd = [
            nmap, "-sV", "--script", "vuln",
            "-p", ports,
            "--script-timeout", "30s",
            "--max-rtt-timeout", "2000ms",
            "-oN", "-",
            host,
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
            output = stdout.decode()

            # Parse VULNERABLE findings
            vulns = self._parse_nmap_output(output, host)
            for vuln in vulns:
                ev = Evidence(
                    response_raw=vuln["details"][:1000],
                    extra={"host": host, "script": vuln["script"], "port": vuln.get("port")},
                )
                self.new_finding(
                    title=f"Nmap NSE: {vuln['script']} VULNERABLE on {host}",
                    severity=Severity.HIGH,
                    description=(
                        f"nmap script '{vuln['script']}' reported VULNERABLE on {host}. "
                        f"Details: {vuln['details'][:200]}"
                    ),
                    reproduction_steps=[
                        f"nmap -sV --script {vuln['script']} -p {vuln.get('port', 'auto')} {host}",
                    ],
                    remediation="Apply vendor patches for identified vulnerability.",
                    references=[vuln.get("cve", ""), "nmap.org/nsedoc"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_VULN,
                    cvss_v40_vector=CVSS40_VULN,
                    target=host,
                    port=int(vuln.get("port", 0)) if str(vuln.get("port", "")).isdigit() else None,
                )

        except asyncio.TimeoutError:
            self.log.warning("nmap timed out on %s", host)
        except Exception as exc:
            self.log.debug("nmap vuln scan failed: %s", exc)

    def _parse_nmap_output(self, output: str, host: str) -> list[dict]:
        vulns: list[dict] = []
        current_script = None
        current_port   = None
        details_lines: list[str] = []

        for line in output.splitlines():
            # Port detection
            port_match = re.match(r"(\d+)/tcp\s+open", line)
            if port_match:
                current_port = port_match.group(1)

            # Script start
            script_match = re.match(r"\|\s*([\w-]+):", line)
            if script_match:
                if current_script and "VULNERABLE" in "\n".join(details_lines):
                    vulns.append({
                        "script":  current_script,
                        "port":    current_port,
                        "details": "\n".join(details_lines),
                        "cve":     self._extract_cve(details_lines),
                    })
                current_script = script_match.group(1)
                details_lines  = [line]
            elif current_script and line.startswith("|"):
                details_lines.append(line)

        # Check last script
        if current_script and "VULNERABLE" in "\n".join(details_lines):
            vulns.append({
                "script":  current_script,
                "port":    current_port,
                "details": "\n".join(details_lines),
                "cve":     self._extract_cve(details_lines),
            })

        return vulns

    def _extract_cve(self, lines: list[str]) -> str:
        for line in lines:
            m = re.search(r"CVE-\d{4}-\d{4,}", line)
            if m:
                return m.group(0)
        return ""


class TestNmapVulns:
    def test_parse_nmap_empty(self) -> None:
        mod = NmapVulns.__new__(NmapVulns)
        result = mod._parse_nmap_output("", "192.168.1.1")
        assert result == []

    def test_extract_cve(self) -> None:
        mod = NmapVulns.__new__(NmapVulns)
        lines = ["| CVE-2017-0144", "|   State: VULNERABLE"]
        assert mod._extract_cve(lines) == "CVE-2017-0144"
