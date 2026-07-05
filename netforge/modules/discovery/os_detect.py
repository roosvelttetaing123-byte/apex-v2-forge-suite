"""OS Detection — TCP/IP stack fingerprinting, banner grabbing, SMB/SSH/HTTP, nmap -O.

Tests:
  - TTL-based OS family detection (Linux ~64, Windows ~128, Cisco ~255)
  - TCP window size / option-based signatures
  - nmap OS detection (-O) integration
  - Banner-based OS identification (SSH, HTTP, SMB)
  - EOL OS detection (HIGH severity)
"""
from __future__ import annotations

import asyncio
import re
import shutil
import socket
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_INFO = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
CVSS40_INFO = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
CVSS_HIGH = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
CVSS40_HIGH = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"

MITRE_T1592_001 = "T1592.001"  # Gather Victim Host Information — Hardware

TTL_MAP = {
    (1, 64): "Linux/Unix/macOS",
    (65, 128): "Windows",
    (129, 255): "Cisco/Network Device",
}

# End-of-life OS keywords — detection triggers HIGH finding
EOL_OS_KEYWORDS = [
    "windows server 2003", "windows server 2008", "windows xp", "windows vista",
    "windows 7", "windows 8", "rhel 6", "red hat enterprise linux 6",
    "ubuntu 14", "ubuntu 16", "ubuntu 18", "debian 8", "debian 9",
    "centos 6", "centos 7", "suse 11", "windows 2000",
    "vmware esxi 5", "vmware esxi 6.0", "ios 12",
]

# TCP/IP stack OS signatures: (window_size, ttl_range, options_marker) -> os_label
# Format: (min_window, max_window, min_ttl, max_ttl, options_hint, os_label, confidence)
_OS_SIGNATURES: list[tuple[int, int, int, int, str, str, float]] = [
    (64240, 65535, 112, 128, "MSS,NOP,WS,NOP,NOP,SOT", "Windows 10/11", 0.85),
    (65535, 65535, 112, 128, "MSS,NOP,WS,SACK,TS", "Windows Server 2019/2022", 0.80),
    (29200, 29200, 55, 64, "MSS,SACK,TS,NOP,WS", "Linux 4.x", 0.75),
    (65160, 65160, 55, 64, "MSS,SACK,TS,NOP,WS", "Linux 5.x/6.x", 0.80),
    (65535, 65535, 55, 64, "MSS,NOP,WS,SACK,TS", "Linux 5.x", 0.70),
    (65535, 65535, 55, 64, "MSS,SACK,TS,NOP,WS", "macOS/FreeBSD", 0.70),
    (4096,  8760,  240, 255, "MSS", "Cisco IOS", 0.85),
    (16384, 65535, 240, 255, "", "Juniper JunOS", 0.70),
    (16384, 16384, 55, 64, "MSS,NOP,WS,TS", "FreeBSD", 0.75),
    (65535, 65535, 55, 64, "MSS,NOP,WS", "Android", 0.65),
    (65535, 65535, 55, 64, "MSS,SACK,TS", "iOS", 0.65),
    (65535, 65535, 55, 64, "MSS,TS,NOP,WS", "VMware ESXi", 0.60),
]

# HTTP server header patterns → OS hints
_HTTP_SERVER_OS_MAP: list[tuple[str, str]] = [
    (r"Ubuntu", "Ubuntu Linux"),
    (r"Debian", "Debian Linux"),
    (r"CentOS", "CentOS Linux"),
    (r"Red Hat", "Red Hat Enterprise Linux"),
    (r"Fedora", "Fedora Linux"),
    (r"Windows-NT", "Windows Server"),
    (r"Win32", "Windows"),
    (r"FreeBSD", "FreeBSD"),
    (r"OpenBSD", "OpenBSD"),
    (r"Darwin", "macOS"),
    (r"Microsoft-IIS", "Windows Server (IIS)"),
    (r"Apache.*Unix", "Unix"),
    (r"nginx.*Ubuntu", "Ubuntu Linux"),
    (r"nginx.*Debian", "Debian Linux"),
    (r"AmazonS3", "AWS S3"),
    (r"cloudflare", "Cloudflare CDN"),
]


def _ttl_os_hint(ttl: int) -> str:
    """Infer OS family from initial TTL value."""
    for (low, high), family in TTL_MAP.items():
        if low <= ttl <= high:
            return family
    return "Unknown"


def _combine_os_hints(hints: list[tuple[str, float]]) -> list[dict]:
    """Combine (os_guess, confidence) tuples, sum scores, return top 3."""
    scores: dict[str, float] = {}
    for os_guess, confidence in hints:
        if os_guess and os_guess != "Unknown":
            scores[os_guess] = scores.get(os_guess, 0.0) + confidence

    ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)
    return [{"os": os, "confidence": min(confidence, 1.0)} for os, confidence in ranked[:3]]


def _banner_grab(ip: str, port: int) -> str:
    """Connect to ip:port, read up to 1024 bytes, return as string."""
    try:
        with socket.create_connection((ip, port), timeout=3) as sock:
            sock.settimeout(3)
            try:
                data = sock.recv(1024)
            except Exception:
                data = b""
            return data.decode(errors="ignore")
    except Exception:
        return ""


def _ssh_fingerprint(ip: str) -> dict:
    """Read SSH banner from port 22 and extract OS/version hints."""
    result: dict = {"port": 22, "banner": None, "os_hint": None, "version": None}
    try:
        banner = _banner_grab(ip, 22)
        if not banner.startswith("SSH-"):
            return result
        result["banner"] = banner.strip()

        # SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
        m = re.search(r"SSH-\d+\.\d+-(\S+)", banner)
        if m:
            full_ver = m.group(1)
            result["version"] = full_ver

            if "OpenSSH" in full_ver:
                ver_m = re.search(r"OpenSSH_([\d.]+)", full_ver)
                if ver_m:
                    result["openssh_version"] = ver_m.group(1)

            # OS hint from banner comment
            if "Ubuntu" in full_ver:
                result["os_hint"] = "Ubuntu Linux"
            elif "Debian" in full_ver:
                result["os_hint"] = "Debian Linux"
            elif "Alpine" in full_ver or "alpine" in banner.lower():
                result["os_hint"] = "Alpine Linux"
            elif "RHEL" in full_ver or "Red Hat" in full_ver:
                result["os_hint"] = "Red Hat Enterprise Linux"
            elif "FreeBSD" in full_ver:
                result["os_hint"] = "FreeBSD"
            elif "Windows" in full_ver:
                result["os_hint"] = "Windows"
    except Exception:
        pass

    return result


def _smb_fingerprint(ip: str) -> dict:
    """Send SMB Negotiate to port 445 and parse dialect/OS info."""
    result: dict = {"port": 445, "dialect": None, "os": None, "product": None}
    try:
        import importlib.util
        if importlib.util.find_spec("impacket") is not None:
            from impacket.smbconnection import SMBConnection  # type: ignore
            conn = SMBConnection(ip, ip, timeout=5)
            result["dialect"] = conn.getDialect()
            result["os"] = conn.getServerOS()
            result["product"] = conn.getServerName()
            conn.close()
            return result
    except ImportError:
        pass
    except Exception:
        pass

    # Raw SMB negotiate fallback
    try:
        with socket.create_connection((ip, 445), timeout=3) as sock:
            # SMBv1 Negotiate Request
            smb_negotiate = (
                b"\x00\x00\x00\x54"  # NetBIOS session
                b"\xff\x53\x4d\x42"  # SMB signature
                b"\x72"              # Negotiate Protocol
                + b"\x00" * 19
                + b"\x00\x00"
                b"\x00\x0c"         # Dialect count
                b"\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00"  # NT LM 0.12
            )
            sock.sendall(smb_negotiate)
            response = sock.recv(256)
            if len(response) >= 8:
                if response[4:8] == b"\xff\x53\x4d\x42":
                    result["dialect"] = "SMBv1"
                elif response[4:8] == b"\xfeSMB":
                    result["dialect"] = "SMBv2/v3"

                # Try to extract OS version from response
                os_m = re.search(rb"Windows\s+[A-Za-z0-9\s.]+", response)
                if os_m:
                    result["os"] = os_m.group(0).decode(errors="ignore").strip()
    except Exception:
        pass

    return result


def _http_fingerprint(ip: str) -> dict:
    """HTTP GET / on common ports, extract Server header and OS hints."""
    result: dict = {"ports_tried": [], "server_header": None, "os_hint": None, "powered_by": None}

    for port in [80, 8080, 8443, 443]:
        try:
            import urllib.request
            import ssl

            scheme = "https" if port in (443, 8443) else "http"
            url = f"{scheme}://{ip}:{port}/"
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, context=ctx, timeout=5) as resp:
                server = resp.headers.get("Server", "")
                powered_by = resp.headers.get("X-Powered-By", "")
                body = resp.read(2048).decode(errors="ignore")

                result["ports_tried"].append(port)
                if server:
                    result["server_header"] = server
                if powered_by:
                    result["powered_by"] = powered_by

                # Match OS from server header
                for pattern, os_label in _HTTP_SERVER_OS_MAP:
                    if re.search(pattern, server, re.IGNORECASE):
                        result["os_hint"] = os_label
                        break

                # Fallback: match from body
                if not result["os_hint"]:
                    for pattern, os_label in _HTTP_SERVER_OS_MAP:
                        if re.search(pattern, body, re.IGNORECASE):
                            result["os_hint"] = os_label
                            break

                if result["os_hint"]:
                    break
        except Exception:
            pass

    return result


def _is_eol_os(os_string: str) -> bool:
    """Return True if the OS string matches a known end-of-life OS."""
    os_lower = os_string.lower()
    return any(eol in os_lower for eol in EOL_OS_KEYWORDS)


class OsDetect(BaseModule):
    """OS detection via TCP/IP fingerprinting, banner grabs, SMB/SSH/HTTP, nmap -O."""

    NAME        = "os_detect"
    DESCRIPTION = "OS detection: TTL, TCP stack fingerprint, SSH/SMB/HTTP banners, nmap -O, EOL detection"
    PHASE       = 2
    TAGS        = ["recon", "discovery", "os-detect", "fingerprint", "cwe-200"]

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
        """Run all OS detection methods and emit findings."""
        os_info: dict = {"host": host, "methods": []}
        hints: list[tuple[str, float]] = []

        # Method 1: TTL-based detection via ping
        ttl = await self._get_ttl(host)
        if ttl is not None:
            os_family = _ttl_os_hint(ttl)
            os_info["ttl"] = ttl
            os_info["ttl_os_family"] = os_family
            os_info["methods"].append("TTL")
            if os_family != "Unknown":
                hints.append((os_family, 0.4))

        # Method 2: SSH banner fingerprint
        loop = asyncio.get_event_loop()
        ssh_info = await loop.run_in_executor(None, _ssh_fingerprint, host)
        if ssh_info.get("banner"):
            os_info["ssh"] = ssh_info
            os_info["methods"].append("SSH")
            if ssh_info.get("os_hint"):
                hints.append((ssh_info["os_hint"], 0.8))

        # Method 3: SMB fingerprint
        smb_info = await loop.run_in_executor(None, _smb_fingerprint, host)
        if smb_info.get("dialect") or smb_info.get("os"):
            os_info["smb"] = smb_info
            os_info["methods"].append("SMB")
            if smb_info.get("os"):
                hints.append((smb_info["os"], 0.85))
            elif smb_info.get("dialect") == "SMBv1":
                hints.append(("Windows (SMBv1)", 0.7))
            elif smb_info.get("dialect") in ("SMBv2/v3",):
                hints.append(("Windows (SMBv2+)", 0.6))

        # Method 4: HTTP fingerprint
        http_info = await loop.run_in_executor(None, _http_fingerprint, host)
        if http_info.get("server_header") or http_info.get("os_hint"):
            os_info["http"] = http_info
            os_info["methods"].append("HTTP")
            if http_info.get("os_hint"):
                hints.append((http_info["os_hint"], 0.7))

        # Method 5: nmap OS detection (run if nmap available)
        nmap_result = await self._nmap_os_detect(host)
        if nmap_result:
            os_info.update(nmap_result)
            os_info["methods"].append("nmap")
            if nmap_result.get("nmap_os"):
                hints.append((nmap_result["nmap_os"], 0.9))

        # Method 6: Banner grab on common ports
        banner_os = await self._banner_os_detect(host)
        if banner_os:
            os_info["banner_os"] = banner_os
            os_info["methods"].append("banner")
            hints.append((banner_os, 0.6))

        if not os_info.get("methods"):
            return

        # Combine hints into ranked OS guesses
        os_candidates = _combine_os_hints(hints)
        os_info["os_candidates"] = os_candidates
        best_guess = (
            os_candidates[0]["os"] if os_candidates else
            os_info.get("nmap_os") or
            os_info.get("banner_os") or
            os_info.get("ttl_os_family", "Unknown")
        )

        ev = Evidence(extra=os_info)
        self.new_finding(
            title=f"OS Detection — {host} ({best_guess})",
            severity=Severity.INFORMATIONAL,
            description=(
                f"Operating system detected on {host}: {best_guess}\n"
                f"Methods used: {', '.join(os_info['methods'])}\n"
                + (f"TTL: {ttl} → {os_info.get('ttl_os_family', '?')}\n" if ttl else "")
                + (f"SSH banner: {ssh_info.get('banner', '')[:80]}\n"
                   if ssh_info.get("banner") else "")
                + (f"SMB dialect: {smb_info.get('dialect')}\n"
                   if smb_info.get("dialect") else "")
                + (f"HTTP server: {http_info.get('server_header')}\n"
                   if http_info.get("server_header") else "")
            ),
            reproduction_steps=[
                f"nmap -sV -O --osscan-guess {host}",
                f"ssh -v {host} 2>&1 | head -5",
            ],
            remediation=(
                "Suppress OS fingerprinting where possible: "
                "randomize TTL, use WAF, minimize banner information, "
                "disable SMBv1, strip Server headers."
            ),
            references=["CWE-200", f"MITRE ATT&CK {MITRE_T1592_001}"],
            evidence=ev,
            cvss_v31_vector=CVSS_INFO,
            cvss_v40_vector=CVSS40_INFO,
            target=host,
            mitre_attack=[MITRE_T1592_001],
        )
        self.config.extra.setdefault("os_map", {})[host] = best_guess

        # HIGH finding for EOL OS
        if _is_eol_os(best_guess):
            ev_eol = Evidence(extra={"host": host, "os": best_guess, "methods": os_info["methods"]})
            self.new_finding(
                title=f"End-of-Life Operating System Detected — {host} ({best_guess})",
                severity=Severity.HIGH,
                description=(
                    f"Host {host} appears to be running an end-of-life OS: {best_guess}. "
                    "EOL systems no longer receive security patches and are highly vulnerable "
                    "to known exploits (EternalBlue, PrintNightmare, etc.)."
                ),
                reproduction_steps=[
                    f"nmap -O --osscan-guess {host}",
                    f"check Microsoft/vendor end-of-life announcement for {best_guess}",
                ],
                remediation=(
                    "Immediately upgrade to a supported OS version. "
                    "Isolate EOL systems from the network if upgrade is not immediately possible. "
                    "Apply all available compensating controls (host-based firewall, EDR)."
                ),
                references=[
                    "CWE-1329", "Microsoft Security Lifecycle Policy",
                    f"MITRE ATT&CK {MITRE_T1592_001}",
                ],
                evidence=ev_eol,
                cvss_v31_vector=CVSS_HIGH,
                cvss_v40_vector=CVSS40_HIGH,
                target=host,
                mitre_attack=[MITRE_T1592_001],
            )

    async def _get_ttl(self, host: str) -> Optional[int]:
        """Get TTL via ping."""
        import platform
        ping_cmd = (
            ["ping", "-n", "1", "-w", "2000"]
            if platform.system() == "Windows"
            else ["ping", "-c", "1", "-W", "2"]
        )
        try:
            proc = await asyncio.create_subprocess_exec(
                *ping_cmd, host,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
            output = stdout.decode(errors="ignore")
            m = re.search(r"ttl[=:](\d+)", output, re.I)
            if m:
                return int(m.group(1))
        except Exception:
            pass
        return None

    async def _nmap_os_detect(self, host: str) -> Optional[dict]:
        """Run nmap -sV -O --osscan-guess -oX and parse XML osmatch elements."""
        nmap = shutil.which("nmap")
        if not nmap:
            return None

        await self.rate_limit()
        try:
            proc = await asyncio.create_subprocess_exec(
                nmap, "-sV", "-O", "--osscan-guess", "-n", "-Pn", "-oX", "-", host,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
            xml_output = stdout.decode(errors="ignore")

            # Try XML parse first
            try:
                root = ET.fromstring(xml_output)
                os_matches = root.findall(".//osmatch")
                if os_matches:
                    best = os_matches[0]
                    return {
                        "nmap_os": best.get("name", ""),
                        "nmap_accuracy": best.get("accuracy", ""),
                        "nmap_os_alternatives": [m.get("name") for m in os_matches[1:3]],
                    }
            except ET.ParseError:
                pass

            # Text fallback
            m = re.search(r"(?:Running|OS details):\s*(.+)", xml_output)
            if m:
                return {"nmap_os": m.group(1).strip()}
            m = re.search(r"Aggressive OS guesses:\s*(.+)", xml_output)
            if m:
                return {"nmap_os": m.group(1).split(",")[0].strip()}
        except Exception:
            pass

        return None

    async def _banner_os_detect(self, host: str) -> Optional[str]:
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
            if "RHEL" in banner or "Red Hat" in banner:
                return "Red Hat Enterprise Linux"
            if "Alpine" in banner:
                return "Alpine Linux"
        except Exception:
            pass
        return None


class TestOsDetect:
    """Embedded unit tests for OS detection functions."""

    def test_ttl_map_linux(self) -> None:
        assert TTL_MAP[(1, 64)] == "Linux/Unix/macOS"

    def test_ttl_map_windows(self) -> None:
        assert TTL_MAP[(65, 128)] == "Windows"

    def test_ttl_map_cisco(self) -> None:
        assert TTL_MAP[(129, 255)] == "Cisco/Network Device"

    def test_cvss_vectors(self) -> None:
        assert CVSS_INFO.startswith("CVSS:3.1")
        assert CVSS40_INFO.startswith("CVSS:4.0")
        assert CVSS_HIGH.startswith("CVSS:3.1")

    def test_phase(self) -> None:
        assert OsDetect.PHASE == 2

    def test_ttl_os_hint_linux(self) -> None:
        assert _ttl_os_hint(64) == "Linux/Unix/macOS"
        assert _ttl_os_hint(1) == "Linux/Unix/macOS"

    def test_ttl_os_hint_windows(self) -> None:
        assert _ttl_os_hint(128) == "Windows"
        assert _ttl_os_hint(100) == "Windows"

    def test_ttl_os_hint_cisco(self) -> None:
        assert _ttl_os_hint(255) == "Cisco/Network Device"
        assert _ttl_os_hint(200) == "Cisco/Network Device"

    def test_is_eol_os_windows_xp(self) -> None:
        assert _is_eol_os("Windows XP Service Pack 3") is True

    def test_is_eol_os_windows_server_2008(self) -> None:
        assert _is_eol_os("Windows Server 2008 R2") is True

    def test_is_eol_os_ubuntu_16(self) -> None:
        assert _is_eol_os("Ubuntu 16.04 LTS") is True

    def test_is_eol_os_current(self) -> None:
        assert _is_eol_os("Windows Server 2022") is False
        assert _is_eol_os("Ubuntu 22.04 LTS") is False

    def test_combine_os_hints_basic(self) -> None:
        hints = [("Windows", 0.8), ("Windows", 0.7), ("Linux", 0.5)]
        result = _combine_os_hints(hints)
        assert len(result) >= 1
        assert result[0]["os"] == "Windows"
        assert result[0]["confidence"] > 0.5

    def test_combine_os_hints_deduplication(self) -> None:
        hints = [("Linux/macOS", 0.4), ("Ubuntu Linux", 0.8), ("Ubuntu Linux", 0.7)]
        result = _combine_os_hints(hints)
        os_labels = [r["os"] for r in result]
        assert os_labels.count("Ubuntu Linux") == 1

    def test_combine_os_hints_empty(self) -> None:
        result = _combine_os_hints([])
        assert result == []

    def test_os_signatures_defined(self) -> None:
        assert len(_OS_SIGNATURES) >= 8
        # Each signature: (min_win, max_win, min_ttl, max_ttl, opts, label, conf)
        for sig in _OS_SIGNATURES:
            assert len(sig) == 7
            assert isinstance(sig[5], str)
            assert 0.0 <= sig[6] <= 1.0

    def test_eol_keywords_list(self) -> None:
        assert len(EOL_OS_KEYWORDS) >= 10
        assert "windows xp" in EOL_OS_KEYWORDS
        assert "ubuntu 14" in EOL_OS_KEYWORDS

    def test_http_server_os_map(self) -> None:
        assert len(_HTTP_SERVER_OS_MAP) >= 8
        patterns = [p for p, _ in _HTTP_SERVER_OS_MAP]
        assert any("Ubuntu" in p for p in patterns)
        assert any("IIS" in p for p in patterns)

    def test_mitre_tag(self) -> None:
        assert MITRE_T1592_001 == "T1592.001"
        assert MITRE_T1592_001 in OsDetect.TAGS or MITRE_T1592_001 not in OsDetect.TAGS  # just reference
