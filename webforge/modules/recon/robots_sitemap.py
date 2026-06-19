"""Robots.txt and sitemap.xml analyzer — extract hidden paths and structure."""
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

CVSS_DISCLOSURE = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
CVSS40_DISCLOSURE = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
class RobotsSitemap(BaseModule):
    """Robots.txt and sitemap.xml analyzer."""

    NAME        = "robots_sitemap"
    DESCRIPTION = "Parse robots.txt and sitemap.xml to discover disallowed and hidden paths"
    PHASE       = 1
    TAGS        = ["recon", "robots", "sitemap", "owasp-a01"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        await asyncio.gather(
            self._check_robots(target),
            self._check_sitemap(target),
            self._check_security_txt(target),
        )
        return self._make_result(start)

    async def _check_robots(self, target: str) -> None:
        content = await self._fetch(f"{target}/robots.txt")
        if not content:
            return

        disallowed: list[str] = []
        sitemaps:   list[str] = []
        allowed:    list[str] = []

        for line in content.splitlines():
            line = line.strip()
            if line.lower().startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path and path != "/":
                    disallowed.append(path)
            elif line.lower().startswith("allow:"):
                path = line.split(":", 1)[1].strip()
                if path:
                    allowed.append(path)
            elif line.lower().startswith("sitemap:"):
                url = line.split(":", 1)[1].strip()
                if url:
                    sitemaps.append(url)

        # Store for other modules
        self.config.extra["robots_disallowed"] = disallowed
        self.config.extra["robots_sitemaps"]   = sitemaps

        # Probe disallowed paths (often the most interesting ones!)
        interesting: list[str] = []
        for path in disallowed:
            status = await self._check_path(target, path)
            if status in (200, 403):
                interesting.append(f"{path} ({status})")

        if disallowed or sitemaps:
            ev = Evidence(
                response_raw=content[:2000],
                extra={
                    "disallowed":   disallowed,
                    "sitemaps":     sitemaps,
                    "accessible":   interesting,
                },
            )
            severity = Severity.MEDIUM if interesting else Severity.LOW
            self.new_finding(
                title=f"robots.txt Reveals Hidden Paths ({len(disallowed)} disallowed)",
                severity=severity,
                description=(
                    f"robots.txt found at {target}/robots.txt. "
                    f"{len(disallowed)} disallowed path(s) discovered. "
                    f"{len(interesting)} of these return HTTP 200/403 and may be accessible. "
                    "Disallowed paths in robots.txt are a common recon goldmine."
                ),
                reproduction_steps=[
                    f"curl {target}/robots.txt",
                    f"Disallowed: {', '.join(disallowed[:10])}",
                    f"Accessible: {', '.join(interesting[:5])}",
                ],
                remediation=(
                    "Do not rely on robots.txt for security — it is public by design. "
                    "Protect sensitive paths with proper authentication, not just disallow rules."
                ),
                references=["CWE-200"],
                evidence=ev,
                cvss_v31_vector=CVSS_DISCLOSURE,
                cvss_v40_vector=CVSS40_DISCLOSURE,
                mitre_attack=["TA0007/T1590"],
                target=target,
                url=f"{target}/robots.txt",
            )

        # Follow sitemap references
        for sitemap_url in sitemaps[:3]:
            await self._process_sitemap(target, sitemap_url)

    async def _check_sitemap(self, target: str) -> None:
        content = await self._fetch(f"{target}/sitemap.xml")
        if content:
            await self._process_sitemap(target, f"{target}/sitemap.xml", content)

    async def _process_sitemap(
        self, target: str, sitemap_url: str, content: str | None = None
    ) -> None:
        if content is None:
            content = await self._fetch(sitemap_url)
        if not content:
            return

        urls = re.findall(r"<loc>([^<]+)</loc>", content)
        # Look for interesting admin/API paths in the sitemap
        interesting = [u for u in urls if any(
            kw in u.lower() for kw in
            ["admin", "api", "internal", "debug", "test", "dev", "management", "config"]
        )]

        # Store all sitemap URLs
        existing = self.config.extra.get("sitemap_urls", [])
        existing.extend(urls[:200])
        self.config.extra["sitemap_urls"] = list(dict.fromkeys(existing))

        if interesting:
            ev = Evidence(
                response_raw=content[:1000],
                extra={"sitemap_url": sitemap_url, "interesting_paths": interesting[:20]},
            )
            self.new_finding(
                title=f"Sensitive URLs in Sitemap — {sitemap_url.split('/')[-1]}",
                severity=Severity.LOW,
                description=(
                    f"Sitemap at {sitemap_url} contains {len(urls)} URL(s). "
                    f"{len(interesting)} appear sensitive (admin/api/internal): "
                    f"{', '.join(interesting[:5])}"
                ),
                reproduction_steps=[f"curl {sitemap_url}"],
                remediation="Exclude sensitive/internal paths from public sitemaps.",
                references=["CWE-200"],
                evidence=ev,
                cvss_v31_vector=CVSS_DISCLOSURE,
                cvss_v40_vector=CVSS40_DISCLOSURE,
                target=target,
                url=sitemap_url,
            )

    async def _check_security_txt(self, target: str) -> None:
        for path in ["/.well-known/security.txt", "/security.txt"]:
            content = await self._fetch(f"{target}{path}")
            if content and ("Contact:" in content or "contact:" in content):
                ev = Evidence(
                    response_raw=content[:500],
                    extra={"path": path},
                )
                self.new_finding(
                    title="security.txt Found",
                    severity=Severity.INFORMATIONAL,
                    description=(
                        f"security.txt found at {target}{path}. "
                        "This file provides security contact/policy information per RFC 9116."
                    ),
                    reproduction_steps=[f"curl {target}{path}"],
                    remediation="Ensure security.txt is intentional and contact info is current.",
                    references=["RFC 9116"],
                    evidence=ev,
                    cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                    target=target,
                    url=f"{target}{path}",
                )
                break

    async def _fetch(self, url: str) -> str | None:
        await self.rate_limit()
        try:
            import aiohttp
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False)
            ) as session:
                async with session.get(
                    url, timeout=aiohttp.ClientTimeout(total=8),
                    headers={"User-Agent": "Mozilla/5.0"}
                ) as resp:
                    if resp.status == 200:
                        return await resp.text(errors="ignore")
        except Exception:
            pass
        return None

    async def _check_path(self, target: str, path: str) -> int:
        await self.rate_limit()
        try:
            import aiohttp
            url = f"{target}{path}" if path.startswith("/") else f"{target}/{path}"
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False)
            ) as session:
                async with session.get(
                    url, timeout=aiohttp.ClientTimeout(total=5), allow_redirects=False
                ) as resp:
                    return resp.status
        except Exception:
            return 0


class TestRobotsSitemap:
    def test_parse_robots_disallowed(self) -> None:
        content = "User-agent: *\nDisallow: /admin\nDisallow: /private\nSitemap: https://example.com/sitemap.xml"
        disallowed = [line.split(":", 1)[1].strip()
                      for line in content.splitlines()
                      if line.lower().startswith("disallow:")]
        assert "/admin" in disallowed
        assert "/private" in disallowed

    def test_parse_sitemap_urls(self) -> None:
        xml = "<urlset><url><loc>https://example.com/admin</loc></url></urlset>"
        urls = re.findall(r"<loc>([^<]+)</loc>", xml)
        assert "https://example.com/admin" in urls
