"""Email security checks — SPF, DKIM, DMARC from web/DNS context."""
from __future__ import annotations

import re
import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

import aiohttp

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_NO_SPF   = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N"
CVSS_NO_DMARC = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N"
CVSS_NO_DKIM  = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:M/A:N"
CVSS_WEAK_SPF = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:M/A:N"


class EmailSecurity(BaseModule):
    """Email security auditor — SPF, DKIM, DMARC DNS record analysis."""

    NAME        = "email_security"
    DESCRIPTION = "Check domain SPF/DKIM/DMARC records for email spoofing protection"
    PHASE       = 10
    TAGS        = ["advanced", "email", "spf", "dmarc", "dkim", "owasp-a05", "cwe-290"]

    async def run(self) -> ModuleResult:
        """Resolve domain from target and check email security DNS records."""
        start  = time.monotonic()
        target = self.config.target.rstrip("/")

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        domain = self._extract_domain(target)
        if not domain:
            self.log.warning("Could not extract domain from %s", target)
            return self._make_result(start)

        self.log.info("Checking email security records for domain: %s", domain)

        spf_records   = await self._query_txt(domain)
        dmarc_records = await self._query_txt(f"_dmarc.{domain}")
        dkim_records  = await self._query_txt(f"default._domainkey.{domain}")
        # Additional 2024-2025 email security checks
        mta_sts_records = await self._query_txt(f"_mta-sts.{domain}")
        tls_rpt_records = await self._query_txt(f"_smtp._tls.{domain}")
        bimi_records    = await self._query_txt(f"default._bimi.{domain}")

        await self._audit_spf(domain, spf_records, target)
        await self._audit_dmarc(domain, dmarc_records, target)
        await self._audit_dkim(domain, dkim_records, target)
        await self._audit_mta_sts(domain, mta_sts_records, target)
        await self._audit_tls_rpt(domain, tls_rpt_records, target)
        await self._probe_extra_dkim_selectors(domain, target)

        return self._make_result(start)

    def _extract_domain(self, target: str) -> str:
        """Extract the hostname from a URL, preserving subdomains.

        Email security records (SPF, DMARC, DKIM) should be checked on the
        actual sending domain, not stripped to the registrable domain.
        e.g. https://francotech.gov.kh  → francotech.gov.kh  (not gov.kh)
        """
        target = re.sub(r"^https?://", "", target)
        return target.split("/")[0].split(":")[0]

    async def _query_txt(self, name: str) -> list[str]:
        """Query TXT records via socket (DNS over system resolver)."""
        await self.rate_limit()
        try:
            import dns.resolver  # type: ignore[import]
            answers = dns.resolver.resolve(name, "TXT")
            return [str(r) for r in answers]
        except Exception:
            pass
        # Fallback: try subprocess nslookup
        try:
            import asyncio
            proc = await asyncio.create_subprocess_exec(
                "dig", "+short", "TXT", name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
            lines = stdout.decode(errors="ignore").strip().splitlines()
            return [l.strip('"') for l in lines if l.strip()]
        except Exception:
            return []

    async def _audit_spf(self, domain: str, records: list[str], target: str) -> None:
        """Check SPF record existence and strength."""
        spf = [r for r in records if "v=spf1" in r.lower()]

        if not spf:
            ev = Evidence(
                request_raw=f"DNS TXT {domain}",
                response_raw="No SPF record found",
                extra={"domain": domain, "all_txt": records[:5]},
            )
            self.new_finding(
                title=f"No SPF Record: {domain}",
                severity=Severity.HIGH,
                description=(
                    f"The domain '{domain}' has no SPF (Sender Policy Framework) TXT record. "
                    "Without SPF, anyone can send email appearing to originate from this domain, "
                    "enabling phishing and email spoofing attacks."
                ),
                reproduction_steps=[
                    f"Run: dig TXT {domain}",
                    "Observe no v=spf1 record in output",
                ],
                remediation=(
                    "Create a TXT record: "
                    f"{domain} IN TXT \"v=spf1 include:_spf.youremail.com ~all\""
                ),
                references=["RFC 7208", "CWE-290", "OWASP A05:2021"],
                evidence=ev,
                cvss_v31_vector=CVSS_NO_SPF,
                target=target,
            )
            return

        spf_val = spf[0]
        # Check for permissive +all
        if "+all" in spf_val or spf_val.endswith(" all") and not any(
            q in spf_val for q in ["-all", "~all", "?all"]
        ):
            ev = Evidence(
                request_raw=f"DNS TXT {domain}",
                response_raw=spf_val,
                extra={"spf": spf_val},
            )
            self.new_finding(
                title=f"Weak SPF Record (+all): {domain}",
                severity=Severity.HIGH,
                description=(
                    f"The SPF record for '{domain}' uses '+all', which allows ANY server "
                    "to send mail on behalf of the domain. This provides no protection "
                    "against email spoofing."
                ),
                reproduction_steps=[
                    f"Run: dig TXT {domain}",
                    f"Observe SPF: {spf_val}",
                ],
                remediation=(
                    "Change the SPF qualifier to '-all' (hard fail) or '~all' (soft fail)."
                ),
                references=["RFC 7208", "CWE-290"],
                evidence=ev,
                cvss_v31_vector=CVSS_WEAK_SPF,
                target=target,
            )

    async def _audit_dmarc(self, domain: str, records: list[str], target: str) -> None:
        """Check DMARC record existence and policy strength."""
        dmarc = [r for r in records if "v=dmarc1" in r.lower()]

        if not dmarc:
            ev = Evidence(
                request_raw=f"DNS TXT _dmarc.{domain}",
                response_raw="No DMARC record found",
                extra={"domain": domain},
            )
            self.new_finding(
                title=f"No DMARC Record: {domain}",
                severity=Severity.HIGH,
                description=(
                    f"The domain '{domain}' has no DMARC record at _dmarc.{domain}. "
                    "Without DMARC, there is no policy to handle emails that fail "
                    "SPF or DKIM checks, enabling phishing attacks."
                ),
                reproduction_steps=[
                    f"Run: dig TXT _dmarc.{domain}",
                    "Observe no DMARC record",
                ],
                remediation=(
                    f"Create: _dmarc.{domain} IN TXT \"v=DMARC1; p=quarantine; "
                    "rua=mailto:dmarc@yourdomain.com\""
                ),
                references=["RFC 7489", "CWE-290"],
                evidence=ev,
                cvss_v31_vector=CVSS_NO_DMARC,
                target=target,
            )
            return

        dmarc_val = dmarc[0]
        # Check policy level
        policy_match = re.search(r"p=(none|quarantine|reject)", dmarc_val, re.I)
        if policy_match and policy_match.group(1).lower() == "none":
            ev = Evidence(
                request_raw=f"DNS TXT _dmarc.{domain}",
                response_raw=dmarc_val,
                extra={"dmarc": dmarc_val},
            )
            self.new_finding(
                title=f"DMARC Policy Set to 'none' (Monitor Only): {domain}",
                severity=Severity.MEDIUM,
                description=(
                    f"The DMARC policy for '{domain}' is set to 'p=none', which means "
                    "failing emails are not quarantined or rejected. "
                    "Email spoofing is still possible despite the DMARC record."
                ),
                reproduction_steps=[
                    f"Run: dig TXT _dmarc.{domain}",
                    f"Observe: {dmarc_val}",
                ],
                remediation=(
                    "Upgrade DMARC policy to 'p=quarantine' or 'p=reject' after "
                    "reviewing rua reports to minimize false positives."
                ),
                references=["RFC 7489", "CWE-290"],
                evidence=ev,
                cvss_v31_vector=CVSS_WEAK_SPF,
                target=target,
            )

    async def _audit_dkim(self, domain: str, records: list[str], target: str) -> None:
        """Check for DKIM records."""
        if not records:
            ev = Evidence(
                request_raw=f"DNS TXT default._domainkey.{domain}",
                response_raw="No DKIM record found at default selector",
                extra={"domain": domain},
            )
            self.new_finding(
                title=f"No DKIM Record at Default Selector: {domain}",
                severity=Severity.MEDIUM,
                description=(
                    f"No DKIM public key was found at default._domainkey.{domain}. "
                    "Without DKIM, outbound emails cannot be cryptographically signed, "
                    "reducing recipient trust and enabling header tampering."
                ),
                reproduction_steps=[
                    f"Run: dig TXT default._domainkey.{domain}",
                    "Observe no DKIM record",
                ],
                remediation=(
                    "Configure DKIM signing in your mail server and publish the "
                    "public key TXT record at selector._domainkey.yourdomain.com"
                ),
                references=["RFC 6376", "CWE-290"],
                evidence=ev,
                cvss_v31_vector=CVSS_NO_DKIM,
                target=target,
            )


    async def _audit_mta_sts(self, domain: str, records: list[str], target: str) -> None:
        """Check for MTA-STS (RFC 8461) — enforces TLS for inbound SMTP."""
        mta_sts = [r for r in records if "v=sts1" in r.lower()]
        if not mta_sts:
            # Also probe the HTTPS policy file
            policy_url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
            policy_found = False
            try:
                import aiohttp as _aiohttp
                async with _aiohttp.ClientSession(
                    connector=_aiohttp.TCPConnector(ssl=False)
                ) as session:
                    await self.rate_limit()
                    async with session.get(
                        policy_url, timeout=_aiohttp.ClientTimeout(total=5)
                    ) as resp:
                        if resp.status == 200:
                            policy_found = True
            except Exception:
                pass

            if not policy_found:
                self.new_finding(
                    title=f"MTA-STS Not Configured: {domain}",
                    severity=Severity.MEDIUM,
                    description=(
                        f"Domain '{domain}' has no MTA-STS policy (RFC 8461). "
                        "Without MTA-STS, inbound SMTP connections may be downgraded "
                        "to cleartext by an active attacker (SMTP STARTTLS stripping). "
                        "MTA-STS requires remote MTAs to use TLS when delivering to your domain."
                    ),
                    reproduction_steps=[
                        f"dig TXT _mta-sts.{domain}",
                        f"curl https://mta-sts.{domain}/.well-known/mta-sts.txt",
                    ],
                    remediation=(
                        f"Create: _mta-sts.{domain} IN TXT \"v=STSv1; id=20260101T000000Z;\"\n"
                        f"Publish policy at https://mta-sts.{domain}/.well-known/mta-sts.txt\n"
                        "Pair with SMTP TLS Reporting (_smtp._tls) to monitor failures."
                    ),
                    references=["RFC 8461", "CWE-319"],
                    evidence=Evidence(extra={"domain": domain, "mta_sts_found": False}),
                    cvss_v31_vector=CVSS_WEAK_SPF,
                    target=target,
                )
        else:
            # Check policy mode
            policy_txt = mta_sts[0]
            if "enforce" not in policy_txt.lower():
                self.new_finding(
                    title=f"MTA-STS Not in 'enforce' Mode: {domain}",
                    severity=Severity.LOW,
                    description=(
                        f"MTA-STS is configured but not in 'enforce' mode: {policy_txt[:100]}. "
                        "Only 'enforce' mode actually blocks STARTTLS-stripped connections."
                    ),
                    reproduction_steps=[f"curl https://mta-sts.{domain}/.well-known/mta-sts.txt"],
                    remediation="Set 'mode: enforce' in the MTA-STS policy file.",
                    references=["RFC 8461"],
                    evidence=Evidence(extra={"policy": policy_txt}),
                    cvss_v31_vector=CVSS_WEAK_SPF,
                    target=target,
                )

    async def _audit_tls_rpt(self, domain: str, records: list[str], target: str) -> None:
        """Check for SMTP TLS Reporting (RFC 8460) — visibility into TLS delivery failures."""
        tls_rpt = [r for r in records if "v=tlsrpt1" in r.lower()]
        if not tls_rpt:
            self.new_finding(
                title=f"SMTP TLS Reporting (TLS-RPT) Not Configured: {domain}",
                severity=Severity.LOW,
                description=(
                    f"Domain '{domain}' has no TLS-RPT record at _smtp._tls.{domain} (RFC 8460). "
                    "Without TLS-RPT, failures in MTA-STS or DANE enforcement go unnoticed, "
                    "hiding active downgrade attacks from domain owners."
                ),
                reproduction_steps=[f"dig TXT _smtp._tls.{domain}"],
                remediation=(
                    f"Create: _smtp._tls.{domain} IN TXT "
                    "\"v=TLSRPTv1; rua=mailto:tls-rpt@yourdomain.com\""
                ),
                references=["RFC 8460"],
                evidence=Evidence(extra={"domain": domain}),
                cvss_v31_vector=CVSS_NO_DKIM,
                target=target,
            )

    async def _probe_extra_dkim_selectors(self, domain: str, target: str) -> None:
        """Probe common DKIM selectors — leaked selectors reveal email infrastructure."""
        common_selectors = [
            "google", "amazonses", "sendgrid", "mailchimp", "mandrill",
            "selector1", "selector2", "k1", "k2", "s1", "s2",
            "dkim", "mail", "email", "smtp", "mimecast", "proofpoint",
        ]
        found_selectors: list[str] = []
        for selector in common_selectors:
            records = await self._query_txt(f"{selector}._domainkey.{domain}")
            if records and any("v=dkim1" in r.lower() for r in records):
                found_selectors.append(selector)

        if len(found_selectors) > 1:
            self.new_finding(
                title=f"Multiple DKIM Selectors Found — Email Vendor Disclosure: {domain}",
                severity=Severity.INFO,
                description=(
                    f"Found {len(found_selectors)} DKIM selectors for '{domain}': "
                    f"{', '.join(found_selectors)}. "
                    "Each selector reveals an email service provider (ESPs, cloud mail services). "
                    "Old/unused selectors with weak RSA keys (<1024 bits) are crackable."
                ),
                reproduction_steps=[
                    f"dig TXT {sel}._domainkey.{domain}" for sel in found_selectors[:3]
                ],
                remediation=(
                    "Remove DKIM selectors for decommissioned email services. "
                    "Rotate DKIM keys annually and use at least 2048-bit RSA or Ed25519. "
                    "Enumerate selectors via Google Workspace (selector1/selector2 reveal GSuite)."
                ),
                references=["RFC 6376", "CWE-200"],
                evidence=Evidence(extra={"selectors": found_selectors, "domain": domain}),
                cvss_v31_vector=CVSS_NO_DKIM,
                target=target,
            )


class TestEmailSecurity:
    def test_cvss_vectors(self) -> None:
        for v in (CVSS_NO_SPF, CVSS_NO_DMARC, CVSS_NO_DKIM, CVSS_WEAK_SPF):
            assert v.startswith("CVSS:3.1/")

    def test_extract_domain(self) -> None:
        mod = EmailSecurity.__new__(EmailSecurity)
        assert mod._extract_domain("https://www.example.com/path") == "example.com"
        assert mod._extract_domain("http://sub.target.org:8080/x") == "target.org"
