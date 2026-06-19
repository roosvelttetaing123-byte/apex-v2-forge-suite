"""DNS reconnaissance — zone transfer, subdomain enum, SPF/DMARC checks."""
from __future__ import annotations

import asyncio
import shutil
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_ZONE_TRANSFER = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
CVSS40_ZONE_TRANSFER = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
CVSS_SPF_MISSING   = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N"
CVSS40_SPF_MISSING = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:H/VA:N/SC:N/SI:N/SA:N"
RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "PTR"]


class DnsRecon(BaseModule):
    """DNS reconnaissance module."""

    NAME        = "dns_recon"
    DESCRIPTION = "DNS enumeration: zone transfer, SPF/DMARC, subdomain records"
    PHASE       = 2
    TAGS        = ["external", "dns", "recon", "cwe-200"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target

        # Extract domain
        from urllib.parse import urlparse
        parsed = urlparse(target if "://" in target else f"http://{target}")
        domain = parsed.netloc.split(":")[0] or target

        if not self.check_scope(domain):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        self.log.info("DNS recon on %s", domain)

        await asyncio.gather(
            self._enumerate_records(domain),
            self._test_zone_transfer(domain),
            self._check_email_security(domain),
        )
        return self._make_result(start)

    async def _enumerate_records(self, domain: str) -> None:
        """Enumerate standard DNS records."""
        records: dict[str, list[str]] = {}

        dig = shutil.which("dig")
        if not dig:
            self.log.info("dig not found — skipping DNS enumeration")
            return

        for rtype in RECORD_TYPES:
            await self.rate_limit()
            try:
                proc = await asyncio.create_subprocess_exec(
                    dig, "+short", rtype, domain,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
                results = [line.strip() for line in stdout.decode().splitlines() if line.strip()]
                if results:
                    records[rtype] = results
            except Exception:
                pass

        self.config.extra["dns_records"] = records
        self.log.info("DNS records found: %s", list(records.keys()))

        # Report nameservers for zone transfer testing
        if "NS" in records:
            self.config.extra["nameservers"] = records["NS"]

    async def _test_zone_transfer(self, domain: str) -> None:
        """Attempt DNS zone transfer (AXFR)."""
        nameservers = self.config.extra.get("nameservers", [])
        if not nameservers:
            return

        dig = shutil.which("dig")
        if not dig:
            return

        for ns in nameservers[:3]:
            await self.rate_limit()
            ns_host = ns.rstrip(".")
            try:
                proc = await asyncio.create_subprocess_exec(
                    dig, "AXFR", domain, f"@{ns_host}",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
                output = stdout.decode()

                # Zone transfer succeeded if we get more than just error/SOA
                lines = [l for l in output.splitlines() if l and not l.startswith(";")]
                if len(lines) > 3 and "Transfer failed" not in output:
                    ev = Evidence(
                        response_raw=output[:2000],
                        extra={
                            "domain":      domain,
                            "nameserver":  ns_host,
                            "record_count": len(lines),
                        },
                    )
                    self.new_finding(
                        title=f"DNS Zone Transfer Successful — {domain} via {ns_host}",
                        severity=Severity.HIGH,
                        description=(
                            f"DNS zone transfer (AXFR) succeeded from {ns_host} for {domain}. "
                            f"{len(lines)} DNS record(s) exposed including all subdomains, "
                            "internal hosts, and mail servers."
                        ),
                        reproduction_steps=[
                            f"dig AXFR {domain} @{ns_host}",
                        ],
                        remediation=(
                            "Configure nameservers to reject AXFR from unauthorized sources. "
                            "Only allow zone transfers to trusted secondary nameservers."
                        ),
                        references=["CWE-200", "OWASP Testing Guide OTG-INFO-001"],
                        evidence=ev,
                        cvss_v31_vector=CVSS_ZONE_TRANSFER,
                        cvss_v40_vector=CVSS40_ZONE_TRANSFER,
                        mitre_attack=["TA0007/T1590.002"],
                        target=domain,
                    )
            except Exception:
                pass

    async def _check_email_security(self, domain: str) -> None:
        """Check SPF, DMARC, and DKIM records."""
        dig = shutil.which("dig")
        if not dig:
            return

        # SPF
        await self.rate_limit()
        try:
            proc = await asyncio.create_subprocess_exec(
                dig, "+short", "TXT", domain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
            txt_records = stdout.decode()

            has_spf = "v=spf1" in txt_records
            if not has_spf:
                self.new_finding(
                    title=f"SPF Record Missing — {domain}",
                    severity=Severity.MEDIUM,
                    description=(
                        f"No SPF record found for {domain}. "
                        "Without SPF, anyone can send emails claiming to be from this domain, "
                        "enabling phishing and spoofing attacks."
                    ),
                    reproduction_steps=[f"dig TXT {domain} | grep spf"],
                    remediation=(
                        "Add an SPF TXT record: v=spf1 include:example.com ~all\n"
                        "Use -all (hard fail) for strict enforcement."
                    ),
                    references=["RFC 7208", "CWE-269"],
                    evidence=Evidence(extra={"domain": domain, "txt_records": txt_records[:200]}),
                    cvss_v31_vector=CVSS_SPF_MISSING,
                    cvss_v40_vector=CVSS40_SPF_MISSING,
                    target=domain,
                )

        except Exception:
            pass

        # DMARC
        await self.rate_limit()
        try:
            proc = await asyncio.create_subprocess_exec(
                dig, "+short", "TXT", f"_dmarc.{domain}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
            dmarc = stdout.decode()

            if "v=DMARC1" not in dmarc:
                self.new_finding(
                    title=f"DMARC Record Missing — {domain}",
                    severity=Severity.MEDIUM,
                    description=(
                        f"No DMARC record found for {domain}. "
                        "Without DMARC, email spoofing and phishing using this domain is harder to detect."
                    ),
                    reproduction_steps=[f"dig TXT _dmarc.{domain}"],
                    remediation=(
                        "Add DMARC record: v=DMARC1; p=reject; rua=mailto:dmarc@{domain}\n"
                        "Start with p=none to monitor, then move to p=quarantine, then p=reject."
                    ),
                    references=["RFC 7489"],
                    evidence=Evidence(extra={"domain": domain}),
                    cvss_v31_vector=CVSS_SPF_MISSING,
                    cvss_v40_vector=CVSS40_SPF_MISSING,
                    target=domain,
                )
        except Exception:
            pass


class TestDnsRecon:
    def test_record_types(self) -> None:
        assert "MX" in RECORD_TYPES
        assert "NS" in RECORD_TYPES
        assert "TXT" in RECORD_TYPES

    def test_cvss_vectors(self) -> None:
        assert CVSS_ZONE_TRANSFER.startswith("CVSS:3.1")
