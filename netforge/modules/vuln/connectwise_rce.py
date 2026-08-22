"""ConnectWise ScreenConnect RCE exposure checks.

Passive detector for ScreenConnect/ConnectWise Control instances associated
with CVE-2024-1709 and CVE-2024-1708. It fingerprints product exposure and
reports vulnerable version indicators when available; it does not attempt
authentication bypass or exploit validation.
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

CVSS_CONNECTWISE = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
SCREENCONNECT_MARKERS = (
    "screenconnect",
    "connectwise control",
    "connectwise screenconnect",
    "/screenconnect/",
    "relay.ashx",
    "hostpage.aspx",
)
VERSION_RE = re.compile(r"(?:ScreenConnect|ConnectWise(?: Control)?)\D+(\d+\.\d+(?:\.\d+)*)", re.I)


def _detect_screenconnect(body: str, headers: dict[str, str] | None = None) -> bool:
    haystack = f"{body[:8192]} {' '.join(f'{k}: {v}' for k, v in (headers or {}).items())}".lower()
    return any(marker in haystack for marker in SCREENCONNECT_MARKERS)


def _extract_version(body: str, headers: dict[str, str] | None = None) -> str:
    haystack = f"{body[:8192]}\n" + "\n".join(f"{k}: {v}" for k, v in (headers or {}).items())
    match = VERSION_RE.search(haystack)
    return match.group(1) if match else ""


def _version_tuple(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", version))


def _known_vulnerable_version(version: str) -> bool:
    """Return True for versions below the fixed 23.9.8 release line."""
    if not version:
        return False
    return _version_tuple(version) < (23, 9, 8)


class ConnectwiseRce(BaseModule):
    NAME = "connectwise_rce"
    DESCRIPTION = "ConnectWise ScreenConnect CVE-2024-1709/1708 exposure and vulnerable-version detector"
    PHASE = 6
    TAGS = ["vuln", "cve-2024-1709", "cve-2024-1708", "connectwise", "screenconnect", "rce"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        hosts = self.config.extra.get("live_hosts", [self.config.target])
        for host in hosts[:20]:
            if not self.check_scope(host):
                continue
            await self.rate_limit()
            await self._probe(host)
        return self._make_result(start)

    async def _probe(self, host: str) -> None:
        import aiohttp

        probes = (
            (443, "https", "/"),
            (443, "https", "/Host"),
            (8040, "http", "/"),
            (8041, "https", "/"),
            (80, "http", "/"),
        )
        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            for port, scheme, path in probes:
                url = f"{scheme}://{host}:{port}{path}"
                try:
                    async with session.get(url, ssl=False, allow_redirects=True) as resp:
                        body = await resp.text(errors="ignore")
                        headers = dict(resp.headers)
                except Exception:
                    continue

                if not _detect_screenconnect(body, headers):
                    continue

                version = _extract_version(body, headers)
                vulnerable = _known_vulnerable_version(version)
                severity = Severity.CRITICAL if vulnerable else Severity.HIGH
                confidence = "HIGH" if vulnerable else "MEDIUM"
                self.new_finding(
                    title=(
                        f"ConnectWise ScreenConnect Vulnerable Version — {host}:{port}"
                        if vulnerable
                        else f"ConnectWise ScreenConnect Exposed — Verify CVE-2024-1709 — {host}:{port}"
                    ),
                    severity=severity,
                    description=(
                        f"ConnectWise ScreenConnect is exposed at {url}. "
                        "CVE-2024-1709 is an authentication bypass that can lead to remote code execution, "
                        "and CVE-2024-1708 is a path traversal issue. "
                        f"Observed version: {version or 'unknown'}."
                    ),
                    reproduction_steps=[
                        f"curl -k '{url}'",
                        "Confirm ScreenConnect product/version from response headers or login page assets",
                    ],
                    remediation=(
                        "Upgrade ScreenConnect to 23.9.8 or later, verify no unauthorized users/extensions exist, "
                        "and restrict administrative access to trusted networks."
                    ),
                    references=["CVE-2024-1709", "CVE-2024-1708"],
                    evidence=Evidence(
                        request_raw=f"GET {url}",
                        response_raw=body[:1000],
                        extra={
                            "host": host,
                            "port": port,
                            "version": version,
                            "known_vulnerable_version": vulnerable,
                        },
                    ),
                    cvss_v31_vector=CVSS_CONNECTWISE,
                    mitre_attack=["TA0001/T1190"],
                    target=host,
                    port=port,
                    service="http",
                    confidence=confidence,
                )
                return


class TestConnectwiseRce:
    def test_detect_screenconnect_marker(self) -> None:
        assert _detect_screenconnect("<title>ConnectWise Control</title>", {})

    def test_extract_version(self) -> None:
        assert _extract_version("ScreenConnect 23.9.7") == "23.9.7"

    def test_known_vulnerable_version(self) -> None:
        assert _known_vulnerable_version("23.9.7") is True
        assert _known_vulnerable_version("23.9.8") is False
