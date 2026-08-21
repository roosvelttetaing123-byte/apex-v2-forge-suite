"""File upload bypass scanner — test for unrestricted file upload vulnerabilities."""
from __future__ import annotations

import asyncio
import io
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.confirm_gate import confirm
from common.evidence import Evidence
from common.finding import Severity
from common.fp_reducer import FPReducer, Confidence

CVSS_UPLOAD_RCE   = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"
CVSS40_UPLOAD_RCE = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
CVSS_UPLOAD_STORE = "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N"
CVSS40_UPLOAD_STORE = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N"
# Simple PHP webshell — detection probe only, not weaponized
PROBE_SHELL_PHP  = "<?php echo 'FORGE_UPLOAD_TEST_' . md5('forge'); ?>"
PROBE_SHELL_ASPX = "<% Response.Write(\"FORGE_UPLOAD_TEST_\"+System.Security.Cryptography.MD5.Create().ComputeHash(System.Text.Encoding.UTF8.GetBytes(\"forge\"))) %>"

WEBSHELL_RESPONSE = "FORGE_UPLOAD_TEST_"

BYPASS_CONTENT_TYPES = [
    "image/jpeg",
    "image/png",
    "image/gif",
    "application/octet-stream",
    "text/plain",
    "application/x-php",
]

BYPASS_FILENAMES = [
    "shell.php",
    "shell.php.jpg",
    "shell.php%00.jpg",
    "shell.php5",
    "shell.phtml",
    "shell.pHp",
    "shell.PHP",
    "shell.php.;jpg",
    "shell.asp",
    "shell.aspx",
    "shell.jsp",
    ".php",
]

UPLOAD_PATHS = [
    "/upload", "/api/upload", "/file/upload", "/image/upload",
    "/media/upload", "/avatar", "/profile/avatar",
    "/api/v1/upload", "/api/files",
    "/admin/upload", "/cms/upload",
]


class UploadBypass(BaseModule):
    """File upload security bypass scanner."""

    NAME        = "upload_bypass"
    DESCRIPTION = "Test file upload endpoints for unrestricted upload bypasses"
    PHASE       = 8
    TAGS        = ["file", "upload", "rce", "cwe-434", "owasp-a03"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        self._fp = FPReducer(
            collab_client=self.config.extra.get("collab_client"),
            headers=self.config.extra.get("session_headers", {}),
        )
        # Find upload endpoints
        upload_endpoints = await self._find_upload_endpoints(target)
        if not upload_endpoints:
            self.log.info("No upload endpoints found")
            return self._make_result(start)

        confirmed = self.confirm_action(
            module=self.NAME,
            action=f"Test {len(upload_endpoints)} upload endpoint(s) for bypass vulnerabilities",
            target=target,
            risk="Uploads inert probe files (PHP echo statement, no exploit payload).",
        )
        if not confirmed:
            return self._make_result(start, skipped=True, skip_reason="operator declined")

        sem = asyncio.Semaphore(2)
        tasks = [self._test_upload(url, target, sem) for url in upload_endpoints]
        await asyncio.gather(*tasks, return_exceptions=True)

        return self._make_result(start)

    async def _find_upload_endpoints(self, target: str) -> list[str]:
        found: list[str] = []
        crawled = self.config.extra.get("crawled_urls", [])

        # Check crawled URLs for upload forms
        for url in crawled[:50]:
            for form in self.config.extra.get("found_forms", []):
                if form.get("url") == url:
                    action = form.get("action", "")
                    if any(kw in action.lower() or kw in url.lower()
                           for kw in ["upload", "file", "avatar", "image", "media"]):
                        full_action = action if action.startswith("http") else f"{target.rstrip('/')}/{action.lstrip('/')}"
                        found.append(full_action)

        # Probe known upload paths
        for path in UPLOAD_PATHS:
            url = f"{target}{path}"
            await self.rate_limit()
            status, _ = await self._get(url)
            if status in (200, 405):
                found.append(url)

        return list(dict.fromkeys(found))

    async def _test_upload(self, url: str, target: str, sem: asyncio.Semaphore) -> None:
        async with sem:
            if not self.check_scope(url):
                return

            # Test each bypass technique
            for filename in BYPASS_FILENAMES[:5]:
                for content_type in BYPASS_CONTENT_TYPES[:3]:
                    await self.rate_limit()

                    upload_result = await self._attempt_upload(
                        url, filename, content_type,
                        PROBE_SHELL_PHP.encode()
                    )

                    if upload_result and upload_result.get("success"):
                        file_url = upload_result.get("file_url", "")

                        # If we got a file URL, try to execute it
                        executed = False
                        if file_url and self.check_scope(file_url):
                            resp_text = await self._fetch_text(file_url)
                            if resp_text and WEBSHELL_RESPONSE in resp_text:
                                executed = True

                        severity = Severity.CRITICAL if executed else Severity.HIGH
                        ev = Evidence(
                            extra={
                                "upload_url":    url,
                                "filename":      filename,
                                "content_type":  content_type,
                                "file_url":      file_url,
                                "executed":      executed,
                            }
                        )

                        if executed:
                            ev.screenshot_path = self.capture_screenshot(
                                file_url, finding_id="upload_rce"
                            )

                        self.new_finding(
                            title=(
                                f"Unrestricted File Upload — RCE Confirmed ({filename})"
                                if executed else
                                f"Unrestricted File Upload — {filename} Accepted"
                            ),
                            severity=severity,
                            description=(
                                f"File '{filename}' with Content-Type '{content_type}' "
                                f"was accepted at {url}. "
                                + ("The uploaded probe was EXECUTED, confirming Remote Code Execution."
                                   if executed else
                                   "Upload was accepted — server-side execution not confirmed but file stored.")
                            ),
                            reproduction_steps=[
                                f"curl -X POST {url} -F 'file=@shell.php' -F 'content_type={content_type}'",
                                f"Access: {file_url}",
                            ],
                            remediation=(
                                "Validate file type server-side using magic bytes (not filename/Content-Type). "
                                "Rename files on upload — never preserve user-supplied filenames. "
                                "Store uploaded files outside web root or use a separate storage service. "
                                "Strip executable permissions from upload directory."
                            ),
                            references=["CWE-434", "OWASP A03:2021"],
                            evidence=ev,
                            cvss_v31_vector=CVSS_UPLOAD_RCE if executed else CVSS_UPLOAD_STORE,
                            cvss_v40_vector=CVSS40_UPLOAD_RCE,
                            mitre_attack=["TA0002/T1505.003"],
                            target=target,
                            url=url,
                            operator_confirmed=True,
                        )
                        return  # One finding per endpoint

    async def _attempt_upload(
        self, url: str, filename: str, content_type: str, content: bytes
    ) -> dict | None:
        try:
            import aiohttp
            data = aiohttp.FormData()
            data.add_field(
                "file", io.BytesIO(content),
                filename=filename,
                content_type=content_type,
            )
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False)
            ) as session:
                async with session.post(
                    url, data=data, timeout=aiohttp.ClientTimeout(total=15)
                ) as resp:
                    body = await resp.text(errors="ignore")

                    if resp.status in (200, 201):
                        # Try to extract uploaded file URL from response
                        file_url = self._extract_file_url(body, url)
                        return {"success": True, "status": resp.status, "file_url": file_url}
                    return None
        except Exception:
            return None

    def _extract_file_url(self, body: str, upload_url: str) -> str:
        patterns = [
            r'"url"\s*:\s*"([^"]+)"',
            r'"path"\s*:\s*"([^"]+)"',
            r'"file"\s*:\s*"([^"]+)"',
            r'"location"\s*:\s*"([^"]+)"',
            r'src=["\']([^"\']*(?:shell|upload|php)[^"\']*)["\']',
        ]
        for pattern in patterns:
            m = re.search(pattern, body, re.IGNORECASE)
            if m:
                url = m.group(1)
                if not url.startswith("http"):
                    base = "/".join(upload_url.split("/")[:3])
                    url = f"{base}/{url.lstrip('/')}"
                return url
        return ""

    async def _get(self, url: str) -> tuple[int, str]:
        try:
            import aiohttp
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False)
            ) as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    return resp.status, await resp.text(errors="ignore")
        except Exception:
            return 0, ""

    async def _fetch_text(self, url: str) -> str | None:
        try:
            import aiohttp
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False)
            ) as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                    if resp.status == 200:
                        return await resp.text(errors="ignore")
        except Exception:
            pass
        return None


class TestUploadBypass:
    def test_bypass_filenames_not_empty(self) -> None:
        assert len(BYPASS_FILENAMES) >= 5
        assert "shell.php" in BYPASS_FILENAMES

    def test_probe_shell_not_weaponized(self) -> None:
        # Probe should only echo, not execute system commands
        assert "system(" not in PROBE_SHELL_PHP
        assert "exec(" not in PROBE_SHELL_PHP
        assert "echo" in PROBE_SHELL_PHP

    def test_extract_file_url(self) -> None:
        mod = UploadBypass.__new__(UploadBypass)
        body = '{"url": "/uploads/shell.php", "status": "ok"}'
        url = mod._extract_file_url(body, "https://example.com/upload")
        assert "shell.php" in url
