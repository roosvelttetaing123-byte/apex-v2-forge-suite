"""Subdomain takeover detection — check for dangling DNS CNAME records."""
from __future__ import annotations

import asyncio
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_TAKEOVER = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N"

# Service fingerprints for unclaimed resources
TAKEOVER_FINGERPRINTS: list[tuple[str, str, str]] = [
    ("GitHub Pages",    r"github\.io",       "There isn't a GitHub Pages site here"),
    ("Heroku",          r"herokuapp\.com",    "No such app"),
    ("AWS S3",          r"s3\.amazonaws\.com","NoSuchBucket"),
    ("AWS CloudFront",  r"cloudfront\.net",  "ERROR: The request could not be satisfied"),
    ("Azure Websites",  r"azurewebsites\.net","404 Web Site not found"),
    ("Shopify",         r"myshopify\.com",   "Sorry, this shop is currently unavailable"),
    ("Tumblr",          r"tumblr\.com",      "There's nothing here"),
    ("Fastly",          r"fastly\.net",       "Fastly error: unknown domain"),
    ("Zendesk",         r"zendesk\.com",     "Help Center Closed"),
    ("WordPress",       r"wordpress\.com",   "Do you want to register"),
    ("Ghost",           r"ghost\.io",        "The thing you were looking for is no longer here"),
    ("Surge",           r"surge\.sh",        "project not found"),
    ("Bitbucket",       r"bitbucket\.io",    "Repository not found"),
    ("Readme.io",       r"readme\.io",       "Project doesnt exist"),
    ("Cargo",           r"cargocollective\.com","404 Not Found"),
    ("Acquia",          r"acquia-sites\.com","The site you are looking for could not be found"),
    ("Pantheon",        r"pantheonsite\.io", "The gods are wise"),
    ("WP Engine",       r"wpengine\.com",    "The site you were looking for couldn't be found"),
]


class SubdomainTakeover(BaseModule):
    """Subdomain takeover vulnerability detection."""

    NAME        = "subdomain_takeover"
    DESCRIPTION = "Detect subdomain takeover via dangling CNAME DNS records"
    PHASE       = 1
    TAGS        = ["recon", "subdomain", "takeover", "dns", "cwe-350"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        domain = self._extract_domain(target)
        subdomains = await self._enumerate_subdomains(domain)
        subdomains.append(domain)  # Also check root

        self.log.info("Checking %d subdomains for takeover", len(subdomains))

        sem = asyncio.Semaphore(5)
        tasks = [self._check_takeover(sub, target, sem) for sub in subdomains]
        await asyncio.gather(*tasks, return_exceptions=True)

        return self._make_result(start)

    async def _enumerate_subdomains(self, domain: str) -> list[str]:
        """Use DNS brute force and any previously discovered subdomains."""
        subdomains: list[str] = []
        prefixes = ["www", "mail", "dev", "staging", "api", "app", "admin",
                    "beta", "test", "old", "legacy", "static", "cdn", "assets",
                    "shop", "store", "blog", "wiki", "docs", "support"]

        tasks = [self._resolve_dns(f"{prefix}.{domain}") for prefix in prefixes]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for prefix, result in zip(prefixes, results):
            if isinstance(result, str) and result:
                subdomains.append(f"{prefix}.{domain}")

        return subdomains

    async def _resolve_dns(self, hostname: str) -> str:
        """Resolve DNS and return CNAME chain if any."""
        try:
            import socket
            loop = asyncio.get_event_loop()
            results = await loop.getaddrinfo(hostname, None)
            return hostname if results else ""
        except Exception:
            return ""

    async def _check_takeover(
        self, subdomain: str, original_target: str, sem: asyncio.Semaphore
    ) -> None:
        async with sem:
            await self.rate_limit()
            # Get CNAME chain
            cname = await self._get_cname(subdomain)
            if not cname:
                return

            # Check if the CNAME points to a known takeover-prone service
            for service_name, service_pattern, fingerprint in TAKEOVER_FINGERPRINTS:
                if re.search(service_pattern, cname, re.IGNORECASE):
                    # Verify by fetching the subdomain and checking for the fingerprint
                    body = await self._fetch_body(f"http://{subdomain}")
                    if body and fingerprint.lower() in body.lower():
                        ev = Evidence(
                            response_raw=body[:500],
                            extra={
                                "subdomain": subdomain,
                                "cname":     cname,
                                "service":   service_name,
                                "fingerprint": fingerprint,
                            },
                        )
                        ev.screenshot_path = await self.capture_screenshot(
                            f"http://{subdomain}", finding_id=f"takeover_{subdomain}"
                        )
                        self.new_finding(
                            title=f"Subdomain Takeover Possible — {subdomain} ({service_name})",
                            severity=Severity.HIGH,
                            description=(
                                f"Subdomain {subdomain} has a CNAME pointing to {cname} "
                                f"({service_name}), but the resource does not exist. "
                                "An attacker can register the resource and serve malicious "
                                "content under the victim's domain, bypassing CSP and same-origin policy."
                            ),
                            reproduction_steps=[
                                f"dig CNAME {subdomain}",
                                f"Response indicates: {fingerprint}",
                                f"Register the {service_name} resource to take over",
                            ],
                            remediation=(
                                f"Remove the DNS CNAME record for {subdomain} immediately, or "
                                f"reclaim the {service_name} resource it points to. "
                                "Regularly audit DNS records for dangling CNAMEs."
                            ),
                            references=["CWE-350", "MITRE T1584.001"],
                            evidence=ev,
                            cvss_v31_vector=CVSS_TAKEOVER,
                            mitre_attack=["TA0001/T1584.001"],
                            target=original_target,
                            url=f"http://{subdomain}",
                        )
                    break

    async def _get_cname(self, hostname: str) -> str:
        """Get CNAME record via dig or nslookup."""
        import shutil
        dig = shutil.which("dig")
        if dig:
            try:
                proc = await asyncio.create_subprocess_exec(
                    dig, "+short", "CNAME", hostname,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
                return stdout.decode().strip()
            except Exception:
                pass
        return ""

    async def _fetch_body(self, url: str) -> str | None:
        try:
            import aiohttp
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False)
            ) as session:
                async with session.get(
                    url, timeout=aiohttp.ClientTimeout(total=8), allow_redirects=True
                ) as resp:
                    return await resp.text(errors="ignore")
        except Exception:
            return None

    def _extract_domain(self, target: str) -> str:
        from urllib.parse import urlparse
        return urlparse(target).netloc.split(":")[0]


class TestSubdomainTakeover:
    def test_fingerprints_not_empty(self) -> None:
        assert len(TAKEOVER_FINGERPRINTS) > 5

    def test_extract_domain(self) -> None:
        mod = SubdomainTakeover.__new__(SubdomainTakeover)
        assert mod._extract_domain("https://example.com/path") == "example.com"

    def test_service_patterns_compile(self) -> None:
        for _, pattern, _ in TAKEOVER_FINGERPRINTS:
            compiled = re.compile(pattern, re.IGNORECASE)
            assert compiled is not None
