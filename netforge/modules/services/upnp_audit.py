"""UPnP auditor — detect exposed UPnP devices and misconfigurations."""
from __future__ import annotations

import asyncio
import re
import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_UPNP       = "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
CVSS40_UPNP     = "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
CVSS_UPNP_EXT   = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
CVSS40_UPNP_EXT = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
SSDP_MCAST  = "239.255.255.250"
SSDP_PORT   = 1900
UPNP_PORTS  = [1900, 5000, 8080, 49152, 52869, 5351]

SSDP_DISCOVER = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 3\r\n"
    "ST: ssdp:all\r\n"
    "\r\n"
)


class UpnpAudit(BaseModule):
    """UPnP security auditor."""

    NAME        = "upnp_audit"
    DESCRIPTION = "Detect UPnP devices via SSDP, test for external exposure and SSRF"
    PHASE       = 4
    TAGS        = ["internal", "upnp", "ssdp", "iot", "cwe-284"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target

        await asyncio.gather(
            self._discover_ssdp(target),
            self._check_http_upnp(target),
        )
        return self._make_result(start)

    async def _discover_ssdp(self, target: str) -> None:
        """Send SSDP M-SEARCH and collect responses."""
        try:
            loop = asyncio.get_event_loop()
            devices = await loop.run_in_executor(None, self._send_ssdp)

            for device in devices:
                location = device.get("location", "")
                server   = device.get("server", "")
                usn      = device.get("usn", "")

                if not location:
                    continue

                # Fetch the device description XML
                desc = await self._fetch_device_desc(location)
                ev = Evidence(
                    extra={
                        "location":    location,
                        "server":      server,
                        "usn":         usn,
                        "description": desc[:200] if desc else "",
                    }
                )
                self.new_finding(
                    title=f"UPnP Device Discovered — {server or usn}",
                    severity=Severity.MEDIUM,
                    description=(
                        f"UPnP device found via SSDP: {server or usn}. "
                        f"Description URL: {location}. "
                        "UPnP devices may allow port forwarding, NAT traversal, "
                        "and may be vulnerable to SSRF or direct exploitation."
                    ),
                    reproduction_steps=[
                        f"curl -s '{location}'",
                        "Use upnpscan or Miranda tool for further enumeration",
                    ],
                    remediation=(
                        "Disable UPnP if not required. "
                        "If UPnP is needed, ensure it's not exposed externally. "
                        "Apply firmware updates to UPnP-enabled devices."
                    ),
                    references=["CVE-2020-12695 (CallStranger)", "CWE-284"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_UPNP,
                    cvss_v40_vector=CVSS40_UPNP,
                    target=target,
                )

        except Exception as exc:
            self.log.debug("SSDP discovery failed: %s", exc)

    def _send_ssdp(self) -> list[dict]:
        """Send SSDP multicast and collect device responses."""
        devices: list[dict] = []
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.settimeout(3.0)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 4)
            sock.sendto(SSDP_DISCOVER.encode(), (SSDP_MCAST, SSDP_PORT))

            while True:
                try:
                    data, addr = sock.recvfrom(2048)
                    device = self._parse_ssdp_response(data.decode(errors="ignore"))
                    device["from_ip"] = addr[0]
                    devices.append(device)
                except socket.timeout:
                    break
            sock.close()
        except Exception:
            pass
        return devices

    def _parse_ssdp_response(self, data: str) -> dict:
        device = {}
        for line in data.splitlines():
            if ":" in line:
                key, _, value = line.partition(":")
                key = key.strip().lower()
                value = value.strip()
                if key == "location":
                    device["location"] = value
                elif key == "server":
                    device["server"] = value
                elif key == "usn":
                    device["usn"] = value
                elif key == "st":
                    device["st"] = value
        return device

    async def _fetch_device_desc(self, url: str) -> str | None:
        """Fetch UPnP device description XML."""
        try:
            import aiohttp
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False)
            ) as session:
                async with session.get(
                    url, timeout=aiohttp.ClientTimeout(total=5)
                ) as resp:
                    if resp.status == 200:
                        return await resp.text(errors="ignore")
        except Exception:
            pass
        return None

    async def _check_http_upnp(self, target: str) -> None:
        """Check if UPnP control ports are externally accessible."""
        for port in UPNP_PORTS:
            await self.rate_limit()
            try:
                import aiohttp
                for path in ["/", "/rootDesc.xml", "/upnp/rootdevice.xml"]:
                    url = f"http://{target}:{port}{path}"
                    async with aiohttp.ClientSession(
                        connector=aiohttp.TCPConnector(ssl=False)
                    ) as session:
                        async with session.get(
                            url, timeout=aiohttp.ClientTimeout(total=3)
                        ) as resp:
                            body = await resp.text(errors="ignore")
                    if resp.status == 200 and any(kw in body.lower() for kw in
                                                   ["upnp", "rootdevice", "device", "service"]):
                        ev = Evidence(
                            request_raw=f"GET {url}",
                            response_raw=body[:300],
                            extra={"port": port, "path": path},
                        )
                        self.new_finding(
                            title=f"UPnP Control Interface Exposed — {target}:{port}",
                            severity=Severity.HIGH,
                            description=(
                                f"UPnP control interface accessible at {url}. "
                                "External access to UPnP can enable port forwarding manipulation, "
                                "DoS, and SSRF attacks."
                            ),
                            reproduction_steps=[f"curl {url}"],
                            remediation="Block UPnP ports at firewall. Disable UPnP on internet-facing routers.",
                            references=["CVE-2020-12695", "CWE-284"],
                            evidence=ev,
                            cvss_v31_vector=CVSS_UPNP_EXT,
                            cvss_v40_vector=CVSS40_UPNP_EXT,
                            target=target,
                            port=port,
                        )
                        break
            except Exception:
                pass


class TestUpnpAudit:
    def test_ssdp_discover_message(self) -> None:
        assert "M-SEARCH" in SSDP_DISCOVER
        assert "ssdp:discover" in SSDP_DISCOVER

    def test_parse_ssdp_response(self) -> None:
        mod = UpnpAudit.__new__(UpnpAudit)
        data = "HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.1:5000/desc.xml\r\nSERVER: Linux/3.4 UPnP/1.0\r\n"
        result = mod._parse_ssdp_response(data)
        assert result.get("location") == "http://192.168.1.1:5000/desc.xml"
