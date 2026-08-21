"""Link crawler — crawl target and build URL map for other modules."""
from __future__ import annotations

import asyncio
import random
import re
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse, urlunparse, urlencode, parse_qs

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.finding import Severity
from common.evidence import Evidence

CVSS_FORMS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
CVSS40_FORMS = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
]

_RETRY_COUNT = 3
_RETRY_BASE_DELAY = 0.5

_JS_MAX_FILES = 30
_JS_MAX_BYTES = 500 * 1024

_SPA_FRAMEWORK_PATTERNS = re.compile(
    r'(?:react(?:\.min)?\.js|vue(?:\.min)?\.js|angular(?:\.min)?\.js|'
    r'next/dist|nuxt\.js|ember\.js|svelte\.js|_next/static|__nuxt)',
    re.IGNORECASE,
)

_JS_API_PATTERNS = [
    re.compile(
        r'fetch\s*\(\s*["\`]([^"\'`\s]{4,300})["\`]',
        re.IGNORECASE,
    ),
    re.compile(
        r'axios\s*\.\s*(?:get|post|put|delete|patch|request)\s*\(\s*["\`]([^"\'`\s]{4,300})["\`]',
        re.IGNORECASE,
    ),
    re.compile(
        r'\$\s*\.\s*(?:ajax\s*\(\s*\{[^}]{0,200}url\s*:\s*["\`]([^"\'`\s]{4,300})["\`]|'
        r'(?:get|post)\s*\(\s*["\`]([^"\'`\s]{4,300})["\`])',
        re.IGNORECASE,
    ),
    re.compile(
        r'\.open\s*\(\s*["\`](?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)["\`]\s*,\s*["\`]([^"\'`\s]{4,300})["\`]',
        re.IGNORECASE,
    ),
    re.compile(
        r'(?:url|endpoint|path|baseURL|baseUrl)\s*:\s*["\`]([^"\'`\s]{2,300})["\`]',
        re.IGNORECASE,
    ),
    re.compile(
        r'["\`](/(?:api|v\d+|graphql|rest|gql|rpc|service|endpoint)[^"\'`\s]{0,200})["\`]',
        re.IGNORECASE,
    ),
    re.compile(
        r'\{\s*path\s*:\s*["\`](/[^"\'`\s]{1,200})["\`]',
        re.IGNORECASE,
    ),
]

_TEMPLATE_LITERAL_RE = re.compile(
    r'`(/(?:api|v\d+|graphql|rest|gql|rpc|service|endpoint)[^`\s]{0,200})`',
    re.IGNORECASE,
)
_TEMPLATE_EXPR_RE = re.compile(r'\$\{[^}]+\}')

_SPA_DATA_PATTERNS = [
    re.compile(r'<script[^>]+id=["\']__NEXT_DATA__["\'][^>]*>(.*?)</script>', re.IGNORECASE | re.DOTALL),
    re.compile(r'window\.__INITIAL_STATE__\s*=\s*({.{0,50000}})\s*(?:;|</script>)', re.DOTALL),
    re.compile(r'window\.__REDUX_STATE__\s*=\s*({.{0,50000}})\s*(?:;|</script>)', re.DOTALL),
    re.compile(r'window\.__APP_STATE__\s*=\s*({.{0,50000}})\s*(?:;|</script>)', re.DOTALL),
]

_JSON_URL_RE = re.compile(r'"(?:url|href|path|endpoint|route|src|action)"\s*:\s*"(/[^"]{1,300})"', re.IGNORECASE)


def _normalize_url(url: str) -> str:
    """Deduplicate URLs regardless of query param order or trailing slash."""
    try:
        p = urlparse(url)
        qs = parse_qs(p.query, keep_blank_values=True)
        sorted_qs = urlencode(sorted(qs.items()), doseq=True)
        path = p.path.rstrip("/") or "/"
        return urlunparse((p.scheme, p.netloc, path, p.params, sorted_qs, ""))
    except Exception:
        return url


def _same_origin(url: str, target_parsed: Any) -> bool:
    return urlparse(url).netloc == target_parsed.netloc


def _normalize_template(raw: str) -> str:
    """Replace ${...} interpolations with {} placeholder for dedup."""
    return _TEMPLATE_EXPR_RE.sub("{}", raw)


class LinkCrawler(BaseModule):
    """Breadth-first crawler — discovers URLs, forms, parameters, and JS API endpoints."""

    NAME        = "link_crawler"
    DESCRIPTION = "Crawl target to discover all URLs, forms, and parameter inputs"
    PHASE       = 1
    TAGS        = ["recon", "crawl", "spider", "owasp-a01"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        max_depth   = getattr(self.config, "crawl_max_depth",   6)
        max_pages   = getattr(self.config, "crawl_max_pages",   500)
        concurrency = getattr(self.config, "crawl_concurrency", 10)
        timeout_s   = getattr(self.config, "crawl_timeout",     15)
        batch_size  = 20

        self.log.info("Crawling %s (max %d pages, depth %d)", target, max_pages, max_depth)

        visited_norm: set[str] = set()
        visited_urls: dict[str, str] = {}
        queue: list[tuple[str, int]] = [(target, 0)]
        forms_found: list[dict] = []
        params_found: set[str] = set()
        js_endpoints: set[str] = set()
        js_src_urls: set[str] = set()
        hidden_form_fields: dict[str, list[dict]] = {}

        async with self.http_session(timeout=timeout_s) as session:
            for url in await self._fetch_sitemap(target, session, timeout_s):
                queue.append((url, 1))

            sem = asyncio.Semaphore(concurrency)
            while queue and len(visited_norm) < max_pages:
                current_batch = [
                    (url, depth) for url, depth in queue[:batch_size]
                    if _normalize_url(url) not in visited_norm
                ]
                queue = queue[batch_size:]
                if not current_batch:
                    continue

                results = await asyncio.gather(
                    *[
                        self._crawl_page(url, depth, target, visited_norm, visited_urls, sem, session, timeout_s)
                        for url, depth in current_batch
                    ],
                    return_exceptions=True,
                )
                for result in results:
                    if isinstance(result, dict):
                        for link, link_depth in result.get("links", []):
                            if link_depth <= max_depth:
                                queue.append((link, link_depth))
                        forms_found.extend(result.get("forms", []))
                        params_found.update(result.get("params", []))
                        js_endpoints.update(result.get("js_endpoints", []))
                        js_src_urls.update(result.get("js_src_urls", set()))
                        for action, hidden in result.get("hidden_form_fields", {}).items():
                            hidden_form_fields.setdefault(action, []).extend(hidden)

            ext_js_endpoints, js_files_analyzed = await self._extract_js_file_endpoints(
                js_src_urls, target, session, sem, timeout_s
            )
            js_endpoints.update(ext_js_endpoints)

        all_urls = list(visited_urls.values())
        self.config.extra["crawled_urls"]       = all_urls
        self.config.extra["found_forms"]        = forms_found
        self.config.extra["found_params"]       = list(params_found)
        self.config.extra["js_api_endpoints"]   = list(js_endpoints)
        self.config.extra["hidden_form_fields"] = hidden_form_fields
        self.config.extra["js_files_analyzed"]  = js_files_analyzed

        self.log.info(
            "Crawl complete: %d URLs, %d forms, %d params, %d JS endpoints, %d JS files analyzed",
            len(all_urls), len(forms_found), len(params_found), len(js_endpoints), js_files_analyzed,
        )

        if forms_found:
            ev = Evidence(
                extra={
                    "total_urls":        len(all_urls),
                    "total_forms":       len(forms_found),
                    "total_params":      len(params_found),
                    "js_api_endpoints":  len(js_endpoints),
                    "js_files_analyzed": js_files_analyzed,
                    "sample_forms":      forms_found[:3],
                }
            )
            self.new_finding(
                title=f"Forms Discovered — {len(forms_found)} input surface(s)",
                severity=Severity.INFORMATIONAL,
                description=(
                    f"Found {len(forms_found)} HTML form(s) and {len(params_found)} unique "
                    f"parameter name(s) across {len(all_urls)} crawled pages. "
                    f"Also discovered {len(js_endpoints)} JS API endpoint(s) "
                    f"(including {js_files_analyzed} external JS files parsed). "
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

    # ------------------------------------------------------------------
    # Pre-seed
    # ------------------------------------------------------------------

    async def _fetch_sitemap(self, target: str, session: Any, timeout_s: int) -> list[str]:
        """Pre-seed queue from sitemap.xml and robots.txt."""
        import aiohttp
        urls: list[str] = []
        for path in ("/sitemap.xml", "/robots.txt"):
            try:
                async with session.get(
                    target + path,
                    timeout=aiohttp.ClientTimeout(total=timeout_s),
                    headers={"User-Agent": random.choice(_USER_AGENTS)},
                    allow_redirects=True,
                ) as resp:
                    if resp.status != 200:
                        continue
                    text = await resp.text(errors="ignore")
                    if path.endswith(".xml"):
                        for m in re.finditer(r"<loc>\s*([^<\s]+)\s*</loc>", text):
                            u = m.group(1).strip()
                            if u.startswith(target):
                                urls.append(u)
                    else:
                        for m in re.finditer(r"(?:Allow|Disallow):\s*(/[^\s*]+)", text):
                            part = m.group(1).strip()
                            if part and part != "/":
                                urls.append(urljoin(target, part))
            except Exception:
                pass
        return urls[:100]

    # ------------------------------------------------------------------
    # Per-page crawl
    # ------------------------------------------------------------------

    async def _crawl_page(
        self,
        url: str,
        depth: int,
        base_target: str,
        visited_norm: set[str],
        visited_urls: dict[str, str],
        sem: asyncio.Semaphore,
        session: Any,
        timeout_s: int,
    ) -> dict:
        norm = _normalize_url(url)
        async with sem:
            if norm in visited_norm:
                return {}
            visited_norm.add(norm)
            visited_urls[norm] = url
            await self.rate_limit()
            html = await self._fetch_with_retry(url, session, timeout_s)

        if not html:
            return {}

        forms = self._extract_forms_deep(html, url)
        hidden_by_action: dict[str, list[dict]] = {}
        for form in forms:
            if form.get("hidden_inputs"):
                hidden_by_action.setdefault(form["action"], []).extend(form["hidden_inputs"])

        return {
            "links":              self._extract_links(html, url, base_target, depth),
            "forms":              forms,
            "params":             self._extract_params(url),
            "js_endpoints":       self._extract_js_endpoints(html, url, base_target)
                                  | self._extract_spa_state_endpoints(html, url, base_target),
            "js_src_urls":        self._collect_js_src_urls(html, url, base_target),
            "hidden_form_fields": hidden_by_action,
        }

    async def _fetch_with_retry(self, url: str, session: Any, timeout_s: int) -> str | None:
        import aiohttp
        for attempt in range(_RETRY_COUNT):
            delay = 0.0
            try:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=timeout_s),
                    allow_redirects=True,
                    headers={"User-Agent": random.choice(_USER_AGENTS)},
                ) as resp:
                    if resp.status == 429:
                        delay = _RETRY_BASE_DELAY * (2 ** attempt)
                    elif resp.status != 200:
                        return None
                    elif "text/html" not in resp.headers.get("Content-Type", ""):
                        return None
                    else:
                        return await resp.text(errors="ignore")
            except asyncio.TimeoutError:
                delay = _RETRY_BASE_DELAY * (2 ** attempt)
            except Exception:
                break
            if delay and attempt < _RETRY_COUNT - 1:
                await asyncio.sleep(delay)
        return None

    # ------------------------------------------------------------------
    # Link extraction
    # ------------------------------------------------------------------

    def _extract_links(self, html: str, base_url: str, target: str, depth: int) -> list[tuple[str, int]]:
        seen: set[str] = set()
        links: list[tuple[str, int]] = []
        base_parsed = urlparse(target)
        next_depth = depth + 1

        def _add(href: str) -> None:
            if not href or len(href) < 2 or len(href) > 300:
                return
            full = urljoin(base_url, href)
            n = _normalize_url(full)
            if n in seen or not _same_origin(full, base_parsed):
                return
            seen.add(n)
            links.append((full, next_depth))

        for m in re.finditer(r'href=["\']([^"\'#\s]{2,300})["\']', html, re.IGNORECASE):
            _add(m.group(1))

        for m in re.finditer(
            r'data-(?:href|url|link|route|path)=["\']([^"\'#\s]{2,300})["\']',
            html, re.IGNORECASE,
        ):
            _add(m.group(1))

        for m in re.finditer(r'action=["\']([^"\'#\s]{2,300})["\']', html, re.IGNORECASE):
            _add(m.group(1))

        for m in re.finditer(r'<(?:iframe|frame)[^>]+src=["\']([^"\'#\s]{2,300})["\']', html, re.IGNORECASE):
            _add(m.group(1))

        for m in re.finditer(
            r'<meta[^>]+http-equiv=["\']refresh["\'][^>]+content=["\'][^"\']*url=([^"\'>\s]+)',
            html, re.IGNORECASE,
        ):
            _add(m.group(1).rstrip('"\''))
        for m in re.finditer(
            r'<meta[^>]+content=["\'][^"\']*url=([^"\'>\s]+)[^>]+http-equiv=["\']refresh["\']',
            html, re.IGNORECASE,
        ):
            _add(m.group(1).rstrip('"\''))

        for m in re.finditer(
            r'<link[^>]+rel=["\']canonical["\'][^>]+href=["\']([^"\'#\s]{2,300})["\']',
            html, re.IGNORECASE,
        ):
            _add(m.group(1))
        for m in re.finditer(
            r'<link[^>]+href=["\']([^"\'#\s]{2,300})["\'][^>]+rel=["\']canonical["\']',
            html, re.IGNORECASE,
        ):
            _add(m.group(1))

        for script_m in re.finditer(r'<script[^>]*>(.*?)</script>', html, re.IGNORECASE | re.DOTALL):
            for m in re.finditer(r'"(?:url|href|path|src|action)"\s*:\s*"(/[^"]{1,300})"', script_m.group(1)):
                _add(m.group(1))

        for m in re.finditer(r'url\(["\']?(/[^"\')\s]{2,300})["\']?\)', html, re.IGNORECASE):
            candidate = urljoin(base_url, m.group(1))
            if _same_origin(candidate, base_parsed):
                _add(m.group(1))

        for comment_m in re.finditer(r'<!--(.*?)-->', html, re.DOTALL):
            for m in re.finditer(
                r'(?:href|url|src|link|path)\s*[=:]\s*["\']?(/[^\s"\'><]{2,200})',
                comment_m.group(1),
            ):
                _add(m.group(1))

        return links

    # ------------------------------------------------------------------
    # Form extraction (deep)
    # ------------------------------------------------------------------

    def _extract_forms_deep(self, html: str, page_url: str) -> list[dict]:
        """Extract forms with full input detail: types, hidden fields, select options, enctype."""
        forms: list[dict] = []
        for fm in re.finditer(r'<form([^>]*)>(.*?)</form>', html, re.IGNORECASE | re.DOTALL):
            attrs, body = fm.group(1), fm.group(2)
            action_m  = re.search(r'action=["\']([^"\']+)["\']',  attrs, re.IGNORECASE)
            method_m  = re.search(r'method=["\']([^"\']+)["\']',  attrs, re.IGNORECASE)
            enctype_m = re.search(r'enctype=["\']([^"\']+)["\']', attrs, re.IGNORECASE)

            raw_action   = action_m.group(1)  if action_m  else page_url
            form_action  = urljoin(page_url, raw_action)
            if not self.check_scope(form_action):
                continue
            form_method  = (method_m.group(1) if method_m  else "get").upper()
            form_enctype = enctype_m.group(1) if enctype_m else "application/x-www-form-urlencoded"
            is_multipart = "multipart" in form_enctype.lower()

            all_inputs: list[str] = []
            hidden_inputs: list[dict] = []
            typed_inputs: list[dict] = []

            for inp in re.finditer(r'<input([^>]*)>', body, re.IGNORECASE):
                inp_attrs = inp.group(1)
                name_m  = re.search(r'name=["\']([^"\']+)["\']',  inp_attrs, re.IGNORECASE)
                type_m  = re.search(r'type=["\']([^"\']+)["\']',  inp_attrs, re.IGNORECASE)
                value_m = re.search(r'value=["\']([^"\']*)["\']', inp_attrs, re.IGNORECASE)
                name  = name_m.group(1)  if name_m  else None
                itype = (type_m.group(1) if type_m  else "text").lower()
                value = value_m.group(1) if value_m else ""
                if name:
                    all_inputs.append(name)
                    typed_inputs.append({"name": name, "type": itype, "value": value})
                    if itype == "hidden":
                        hidden_inputs.append({"name": name, "value": value})

            for ta in re.finditer(r'<textarea([^>]*)>', body, re.IGNORECASE):
                name_m = re.search(r'name=["\']([^"\']+)["\']', ta.group(1), re.IGNORECASE)
                if name_m:
                    name = name_m.group(1)
                    all_inputs.append(name)
                    typed_inputs.append({"name": name, "type": "textarea", "value": ""})

            for sel in re.finditer(r'<select([^>]*)>(.*?)</select>', body, re.IGNORECASE | re.DOTALL):
                sel_attrs, sel_body = sel.group(1), sel.group(2)
                name_m = re.search(r'name=["\']([^"\']+)["\']', sel_attrs, re.IGNORECASE)
                if name_m:
                    name = name_m.group(1)
                    all_inputs.append(name)
                    option_values = re.findall(r'<option[^>]*value=["\']([^"\']*)["\']', sel_body, re.IGNORECASE)
                    typed_inputs.append({"name": name, "type": "select", "options": option_values})

            forms.append({
                "url":           page_url,
                "action":        form_action,
                "method":        form_method,
                "enctype":       form_enctype,
                "multipart":     is_multipart,
                "inputs":        all_inputs,
                "typed_inputs":  typed_inputs,
                "hidden_inputs": hidden_inputs,
            })
        return forms

    def _extract_forms(self, html: str, page_url: str) -> list[dict]:
        return self._extract_forms_deep(html, page_url)

    # ------------------------------------------------------------------
    # Parameter extraction
    # ------------------------------------------------------------------

    def _extract_params(self, url: str) -> set[str]:
        return set(parse_qs(urlparse(url).query).keys())

    # ------------------------------------------------------------------
    # Inline JS endpoint extraction
    # ------------------------------------------------------------------

    def _extract_js_endpoints(self, html: str, base_url: str, target: str) -> set[str]:
        """Extract likely API endpoints from inline <script> blocks."""
        endpoints: set[str] = set()
        base_parsed = urlparse(target)
        for script_m in re.finditer(r'<script[^>]*>(.*?)</script>', html, re.IGNORECASE | re.DOTALL):
            js = script_m.group(1)
            endpoints.update(self._parse_js_for_endpoints(js, base_url, base_parsed))
        return endpoints

    def _parse_js_for_endpoints(self, js: str, base_url: str, base_parsed: Any) -> set[str]:
        """Core JS endpoint extraction logic — shared between inline and external JS files."""
        endpoints: set[str] = set()

        for pattern in _JS_API_PATTERNS:
            for m in pattern.finditer(js):
                raw = next((g for g in m.groups() if g), None)
                if not raw:
                    continue
                if raw.startswith("/") or raw.startswith(base_url):
                    full = urljoin(base_url, raw)
                    if _same_origin(full, base_parsed):
                        endpoints.add(full)

        for m in _TEMPLATE_LITERAL_RE.finditer(js):
            skeleton = _normalize_template(m.group(1))
            full = urljoin(base_url, skeleton)
            if _same_origin(full, base_parsed):
                endpoints.add(full)

        return endpoints

    # ------------------------------------------------------------------
    # External JS file collection and parsing
    # ------------------------------------------------------------------

    def _collect_js_src_urls(self, html: str, base_url: str, target: str) -> set[str]:
        """Collect same-origin <script src="..."> URLs from a page."""
        base_parsed = urlparse(target)
        urls: set[str] = set()
        for m in re.finditer(r'<script[^>]+src=["\']([^"\'#\s]{4,300})["\']', html, re.IGNORECASE):
            full = urljoin(base_url, m.group(1))
            if _same_origin(full, base_parsed) and full.split("?")[0].endswith(".js"):
                urls.add(full)
        return urls

    async def _extract_js_file_endpoints(
        self,
        js_src_urls: set[str],
        target: str,
        session: Any,
        sem: asyncio.Semaphore,
        timeout_s: int,
    ) -> tuple[set[str], int]:
        """Fetch up to _JS_MAX_FILES external JS files and extract API endpoints."""
        base_parsed = urlparse(target)
        selected = list(js_src_urls)[:_JS_MAX_FILES]
        if not selected:
            return set(), 0

        async def _fetch_js(url: str) -> str | None:
            try:
                async with sem:
                    async with session.get(
                        url,
                        timeout=timeout_s,
                        allow_redirects=True,
                        headers={"User-Agent": random.choice(_USER_AGENTS)},
                    ) as resp:
                        if resp.status != 200:
                            return None
                        ct = resp.headers.get("Content-Type", "")
                        if ct and "html" in ct:
                            return None
                        body = await resp.read()
                        return body[:_JS_MAX_BYTES].decode("utf-8", errors="ignore")
            except Exception:
                return None

        results = await asyncio.gather(*[_fetch_js(url) for url in selected], return_exceptions=True)

        endpoints: set[str] = set()
        analyzed = 0
        for js_content in results:
            if not isinstance(js_content, str) or not js_content:
                continue
            analyzed += 1
            endpoints.update(self._parse_js_for_endpoints(js_content, target, base_parsed))

        return endpoints, analyzed

    # ------------------------------------------------------------------
    # SPA state extraction
    # ------------------------------------------------------------------

    def _extract_spa_state_endpoints(self, html: str, base_url: str, target: str) -> set[str]:
        """
        Extract route paths from SPA bootstrap JSON blobs embedded in HTML.
        Handles __NEXT_DATA__, window.__INITIAL_STATE__, window.__REDUX_STATE__,
        and window.__APP_STATE__.
        """
        base_parsed = urlparse(target)
        endpoints: set[str] = set()

        for pattern in _SPA_DATA_PATTERNS:
            for m in pattern.finditer(html):
                blob = m.group(1)
                for url_m in _JSON_URL_RE.finditer(blob):
                    full = urljoin(base_url, url_m.group(1))
                    if _same_origin(full, base_parsed):
                        endpoints.add(full)

        return endpoints


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestLinkCrawler:
    def _make(self) -> "LinkCrawler":
        from common.scope import Scope

        module = LinkCrawler.__new__(LinkCrawler)
        module.scope = Scope(["example.com"])
        return module

    # -- existing tests (preserved) --

    def test_extract_links(self) -> None:
        mod = self._make()
        html = '<a href="/page1">link</a><a href="https://other.com">ext</a>'
        links = mod._extract_links(html, "https://example.com", "https://example.com", 0)
        assert any("page1" in l for l, _ in links)
        assert not any("other.com" in l for l, _ in links)

    def test_extract_links_data_attrs(self) -> None:
        mod = self._make()
        html = '<div data-href="/spa/route">nav</div>'
        links = mod._extract_links(html, "https://example.com", "https://example.com", 0)
        assert any("spa/route" in l for l, _ in links)

    def test_extract_params(self) -> None:
        mod = self._make()
        params = mod._extract_params("https://example.com/search?q=test&page=1")
        assert "q" in params
        assert "page" in params

    def test_extract_forms(self) -> None:
        mod = self._make()
        html = '<form action="/login" method="POST"><input name="user"><textarea name="msg"></textarea></form>'
        forms = mod._extract_forms(html, "https://example.com/login")
        assert len(forms) == 1
        assert "user" in forms[0]["inputs"]
        assert "msg" in forms[0]["inputs"]

    def test_extract_js_endpoints(self) -> None:
        mod = self._make()
        html = '<script>fetch("/api/v1/users").then(r=>r.json())</script>'
        endpoints = mod._extract_js_endpoints(html, "https://example.com", "https://example.com")
        assert any("api/v1/users" in e for e in endpoints)

    def test_normalize_url(self) -> None:
        a = _normalize_url("https://example.com/page?b=2&a=1")
        b = _normalize_url("https://example.com/page?a=1&b=2")
        assert a == b

    # -- new tests --

    def test_extract_links_iframe_src(self) -> None:
        mod = self._make()
        html = '<iframe src="/embed/player"></iframe>'
        links = mod._extract_links(html, "https://example.com", "https://example.com", 0)
        assert any("embed/player" in l for l, _ in links)

    def test_extract_links_meta_refresh(self) -> None:
        mod = self._make()
        html = '<meta http-equiv="refresh" content="0;url=/new-location">'
        links = mod._extract_links(html, "https://example.com", "https://example.com", 0)
        assert any("new-location" in l for l, _ in links)

    def test_extract_links_canonical(self) -> None:
        mod = self._make()
        html = '<link rel="canonical" href="/articles/foo">'
        links = mod._extract_links(html, "https://example.com", "https://example.com", 0)
        assert any("articles/foo" in l for l, _ in links)

    def test_extract_links_json_in_script(self) -> None:
        mod = self._make()
        html = '<script>var cfg = {"url":"/dashboard/overview"};</script>'
        links = mod._extract_links(html, "https://example.com", "https://example.com", 0)
        assert any("dashboard/overview" in l for l, _ in links)

    def test_extract_links_html_comment(self) -> None:
        mod = self._make()
        html = '<!-- old api path=/internal/v1/debug -->'
        links = mod._extract_links(html, "https://example.com", "https://example.com", 0)
        assert any("internal/v1/debug" in l for l, _ in links)

    def test_extract_forms_deep_hidden_inputs(self) -> None:
        mod = self._make()
        html = (
            '<form action="/submit" method="POST">'
            '<input type="hidden" name="_csrf" value="abc123">'
            '<input type="hidden" name="state" value="xyz">'
            '<input type="text" name="username">'
            '</form>'
        )
        forms = mod._extract_forms_deep(html, "https://example.com")
        assert len(forms) == 1
        f = forms[0]
        assert f["method"] == "POST"
        assert "_csrf" in f["inputs"]
        assert "username" in f["inputs"]
        hidden_names = [h["name"] for h in f["hidden_inputs"]]
        assert "_csrf" in hidden_names
        assert "state" in hidden_names
        hidden_vals = {h["name"]: h["value"] for h in f["hidden_inputs"]}
        assert hidden_vals["_csrf"] == "abc123"

    def test_extract_forms_deep_select_options(self) -> None:
        mod = self._make()
        html = (
            '<form action="/search">'
            '<select name="category">'
            '<option value="news">News</option>'
            '<option value="sports">Sports</option>'
            '</select>'
            '</form>'
        )
        forms = mod._extract_forms_deep(html, "https://example.com")
        assert len(forms) == 1
        f = forms[0]
        assert "category" in f["inputs"]
        typed = {t["name"]: t for t in f["typed_inputs"]}
        assert typed["category"]["type"] == "select"
        assert "news" in typed["category"]["options"]
        assert "sports" in typed["category"]["options"]

    def test_extract_forms_deep_multipart(self) -> None:
        mod = self._make()
        html = '<form action="/upload" method="POST" enctype="multipart/form-data"><input name="file"></form>'
        forms = mod._extract_forms_deep(html, "https://example.com")
        assert forms[0]["multipart"] is True
        assert forms[0]["enctype"] == "multipart/form-data"

    def test_parse_js_for_endpoints_axios(self) -> None:
        mod = self._make()
        js = 'axios.get("/api/v2/orders").then(console.log)'
        base_parsed = urlparse("https://example.com")
        eps = mod._parse_js_for_endpoints(js, "https://example.com", base_parsed)
        assert any("api/v2/orders" in e for e in eps)

    def test_parse_js_for_endpoints_xhr(self) -> None:
        mod = self._make()
        js = 'var x = new XMLHttpRequest(); x.open("GET", "/api/users", true);'
        base_parsed = urlparse("https://example.com")
        eps = mod._parse_js_for_endpoints(js, "https://example.com", base_parsed)
        assert any("api/users" in e for e in eps)

    def test_parse_js_for_endpoints_router_path(self) -> None:
        mod = self._make()
        js = 'const routes = [{ path: "/users/:id", component: User }];'
        base_parsed = urlparse("https://example.com")
        eps = mod._parse_js_for_endpoints(js, "https://example.com", base_parsed)
        assert any("users/:id" in e for e in eps)

    def test_parse_js_for_endpoints_url_key(self) -> None:
        mod = self._make()
        js = 'const cfg = { endpoint: "/api/graphql", timeout: 3000 };'
        base_parsed = urlparse("https://example.com")
        eps = mod._parse_js_for_endpoints(js, "https://example.com", base_parsed)
        assert any("graphql" in e for e in eps)

    def test_parse_js_for_endpoints_template_literal(self) -> None:
        mod = self._make()
        js = 'const url = `/api/${version}/users/${id}`;'
        base_parsed = urlparse("https://example.com")
        eps = mod._parse_js_for_endpoints(js, "https://example.com", base_parsed)
        assert any("api/{}/users/{}" in e for e in eps)

    def test_collect_js_src_urls(self) -> None:
        mod = self._make()
        html = (
            '<script src="/static/app.js"></script>'
            '<script src="https://cdn.other.com/lib.js"></script>'
            '<script src="/static/vendor.js?v=2"></script>'
        )
        urls = mod._collect_js_src_urls(html, "https://example.com", "https://example.com")
        assert any("app.js" in u for u in urls)
        assert any("vendor.js" in u for u in urls)
        assert not any("cdn.other.com" in u for u in urls)

    def test_extract_spa_state_endpoints_next_data(self) -> None:
        mod = self._make()
        html = (
            '<script id="__NEXT_DATA__" type="application/json">'
            '{"props":{"pageProps":{}},"page":"/dashboard","path":"/dashboard",'
            '"query":{},"buildId":"xyz"}'
            '</script>'
        )
        eps = mod._extract_spa_state_endpoints(html, "https://example.com", "https://example.com")
        assert any("dashboard" in e for e in eps)

    def test_normalize_template(self) -> None:
        result = _normalize_template("/api/${version}/users/${id}")
        assert result == "/api/{}/users/{}"
