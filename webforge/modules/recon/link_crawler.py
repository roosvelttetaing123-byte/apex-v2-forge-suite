"""Link crawler — crawl target and build URL map for other modules."""
from __future__ import annotations

import asyncio
import re
import sys
import time
from pathlib import Path
from urllib.parse import urljoin, urlparse, urlencode, parse_qs

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.finding import Severity
from common.evidence import Evidence

CVSS_FORMS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
CVSS40_FORMS = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
class LinkCrawler(BaseModule):
    """Breadth-first crawler — discovers URLs, forms, and parameters."""

    NAME        = "link_crawler"
    DESCRIPTION = "Crawl target to discover all URLs, forms, and parameter inputs"
    PHASE       = 1
    TAGS        = ["recon", "crawl", "spider", "owasp-a01"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        self.log.info("Crawling %s (max 200 pages)", target)
        visited: set[str] = set()
        queue: list[str] = [target]
        forms_found: list[dict] = []
        params_found: set[str] = set()

        depth = 0
        max_depth = 3
        max_pages = 200

        while queue and len(visited) < max_pages:
            depth += 1
            if depth > max_depth:
                break
            current_batch = queue[:20]
            queue = queue[20:]

            sem = asyncio.Semaphore(5)
            results = await asyncio.gather(
                *[self._crawl_page(url, target, visited, sem) for url in current_batch
                  if url not in visited],
                return_exceptions=True
            )
            for result in results:
                if isinstance(result, dict):
                    queue.extend(result.get("links", []))
                    forms_found.extend(result.get("forms", []))
                    params_found.update(result.get("params", []))

        # Store discovered data for other modules
        all_urls = list(visited)
        self.config.extra["crawled_urls"]   = all_urls
        self.config.extra["found_forms"]    = forms_found
        self.config.extra["found_params"]   = list(params_found)

        self.log.info(
            "Crawl complete: %d URLs, %d forms, %d params",
            len(all_urls), len(forms_found), len(params_found)
        )

        if forms_found:
            ev = Evidence(
                extra={
                    "total_urls":   len(all_urls),
                    "total_forms":  len(forms_found),
                    "total_params": len(params_found),
                    "sample_forms": forms_found[:3],
                }
            )
            self.new_finding(
                title=f"Forms Discovered — {len(forms_found)} input surface(s)",
                severity=Severity.INFORMATIONAL,
                description=(
                    f"Found {len(forms_found)} HTML form(s) and {len(params_found)} unique "
                    f"parameter name(s) across {len(all_urls)} crawled pages. "
                    "These are injection/auth testing entry points."
                ),
                reproduction_steps=[
                    f"Crawl: curl -s {target} | grep '<form'",
                    f"Parameters found: {', '.join(sorted(params_found)[:20])}",
                ],
                remediation="Ensure all form inputs have server-side validation and CSRF protection.",
                references=["OWASP A01:2021"],
                evidence=ev,
                cvss_v31_vector=CVSS_FORMS,
                cvss_v40_vector=CVSS40_FORMS,
                target=target,
            )

        return self._make_result(start)

    async def _crawl_page(
        self, url: str, base_target: str, visited: set[str], sem: asyncio.Semaphore
    ) -> dict:
        async with sem:
            if url in visited:
                return {}
            visited.add(url)
            await self.rate_limit()
            try:
                import aiohttp
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False)
                ) as session:
                    async with session.get(
                        url,
                        timeout=aiohttp.ClientTimeout(total=10),
                        allow_redirects=True,
                        headers={"User-Agent": "Mozilla/5.0"},
                    ) as resp:
                        if resp.status != 200:
                            return {}
                        ctype = resp.headers.get("Content-Type", "")
                        if "text/html" not in ctype:
                            return {}
                        html = await resp.text(errors="ignore")

                links  = self._extract_links(html, url, base_target)
                forms  = self._extract_forms(html, url)
                params = self._extract_params(url)

                return {"links": links, "forms": forms, "params": params}
            except Exception:
                return {}

    def _extract_links(self, html: str, base_url: str, target: str) -> list[str]:
        links: list[str] = []
        base_parsed = urlparse(target)
        for m in re.finditer(r'href=["\']([^"\'#\s]{3,200})["\']', html, re.IGNORECASE):
            href = m.group(1)
            full = urljoin(base_url, href)
            parsed = urlparse(full)
            if parsed.netloc == base_parsed.netloc and full not in links:
                links.append(full)
        return links[:50]

    def _extract_forms(self, html: str, page_url: str) -> list[dict]:
        forms: list[dict] = []
        for fm in re.finditer(
            r'<form([^>]*)>(.*?)</form>', html, re.IGNORECASE | re.DOTALL
        ):
            attrs  = fm.group(1)
            body   = fm.group(2)
            action = re.search(r'action=["\']([^"\']+)["\']', attrs, re.IGNORECASE)
            method = re.search(r'method=["\']([^"\']+)["\']', attrs, re.IGNORECASE)
            inputs = re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', body, re.IGNORECASE)
            forms.append({
                "url":    page_url,
                "action": action.group(1) if action else page_url,
                "method": (method.group(1) if method else "get").upper(),
                "inputs": inputs,
            })
        return forms

    def _extract_params(self, url: str) -> set[str]:
        parsed = urlparse(url)
        return set(parse_qs(parsed.query).keys())


class TestLinkCrawler:
    def test_extract_links(self) -> None:
        mod = LinkCrawler.__new__(LinkCrawler)
        html = '<a href="/page1">link</a><a href="https://other.com">ext</a>'
        links = mod._extract_links(html, "https://example.com", "https://example.com")
        assert any("page1" in l for l in links)
        assert not any("other.com" in l for l in links)

    def test_extract_params(self) -> None:
        mod = LinkCrawler.__new__(LinkCrawler)
        params = mod._extract_params("https://example.com/search?q=test&page=1")
        assert "q" in params
        assert "page" in params

    def test_extract_forms(self) -> None:
        mod = LinkCrawler.__new__(LinkCrawler)
        html = '<form action="/login" method="POST"><input name="user"><input name="pass"></form>'
        forms = mod._extract_forms(html, "https://example.com/login")
        assert len(forms) == 1
        assert "user" in forms[0]["inputs"]
