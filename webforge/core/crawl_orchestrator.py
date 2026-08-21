"""Two-phase crawl orchestrator — HTTP sweep + deep browser discovery.

Combines fast aiohttp BFS (Phase 1) with Playwright JS rendering (Phase 2)
to achieve Acunetix-level crawl coverage: SPA routes, AJAX endpoints,
shadow DOM, WebSocket URLs, API schemas, and source maps.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse, urlunparse, urlencode, parse_qs

log = logging.getLogger("webforge.crawl_orchestrator")

# ── Static extension reject-list ─────────────────────────────────────────────

_STATIC_EXTS = frozenset(
    ".png .jpg .jpeg .gif .bmp .webp .svg .ico "
    ".pdf .zip .tar .gz .7z .rar "
    ".woff .woff2 .ttf .eot .otf "
    ".mp4 .mp3 .avi .mov .webm "
    ".css .map "
    ".doc .docx .xls .xlsx .ppt .pptx".split()
)

_REJECT_SCHEMES = frozenset({"mailto", "javascript", "tel", "ftp", "data", "blob"})

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
]

# Well-known API schema probe paths
_API_SCHEMA_PATHS = [
    "/openapi.json",
    "/openapi.yaml",
    "/swagger.json",
    "/swagger.yaml",
    "/api/openapi.json",
    "/api/swagger.json",
    "/api-docs",
    "/api/v1/openapi.json",
    "/api/v2/openapi.json",
    "/_next/static/chunks/pages-manifest.json",
    "/api/schema/",
    "/docs/api/",
]

_GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/gql"]

_GRAPHQL_INTROSPECTION = json.dumps({
    "query": "{ __schema { queryType { name } types { name kind } } }"
})

# SPA route interceptor — injected before page navigation
_SPA_INTERCEPTOR_JS = """
(function() {
    if (window.__FORGE_ROUTES__) return;
    window.__FORGE_ROUTES__ = new Set();
    window.__FORGE_HISTORY_CALLS__ = [];

    const origPush = history.pushState;
    const origReplace = history.replaceState;

    history.pushState = function(state, title, url) {
        if (url) window.__FORGE_ROUTES__.add(String(url));
        window.__FORGE_HISTORY_CALLS__.push({method:'pushState', url: String(url||''), ts: Date.now()});
        return origPush.call(this, state, title, url);
    };
    history.replaceState = function(state, title, url) {
        if (url) window.__FORGE_ROUTES__.add(String(url||''));
        return origReplace.call(this, state, title, url);
    };

    window.addEventListener('hashchange', function(e) {
        window.__FORGE_ROUTES__.add(location.href);
    });
    window.addEventListener('popstate', function(e) {
        window.__FORGE_ROUTES__.add(location.href);
    });
})();
"""

# Click-discovery selectors — ordered from low-risk to higher-risk
_CLICK_SELECTORS = [
    "nav a[href]:not([href^='http'])",
    "[role='tab']",
    "[role='menuitem']",
    "[role='treeitem']",
    "button:not([type='submit']):not([type='reset'])",
    ".tab",
    ".nav-link",
    ".sidebar-item",
    "[data-toggle='tab']",
    "[data-bs-toggle='tab']",
]

_MAX_CLICKS_PER_PAGE = 20
_CLICK_WAIT_MS = 500


# ── URL utilities ─────────────────────────────────────────────────────────────

def _normalize_url(url: str) -> str:
    """Canonical URL form: sorted query params, no trailing slash."""
    try:
        p = urlparse(url)
        if p.scheme in _REJECT_SCHEMES:
            return ""
        qs = parse_qs(p.query, keep_blank_values=True)
        sorted_qs = urlencode(sorted(qs.items()), doseq=True)
        path = p.path.rstrip("/") or "/"
        return urlunparse((p.scheme, p.netloc, path, p.params, sorted_qs, ""))
    except Exception:
        return url


def _url_ext(url: str) -> str:
    """Return lower-case file extension from URL path, including the dot."""
    path = urlparse(url).path
    if "." in path:
        return "." + path.rsplit(".", 1)[-1].lower()
    return ""


# ── Scope Policy ─────────────────────────────────────────────────────────────

@dataclass
class ScopePolicy:
    base_url: str
    include_subdomains: bool = False
    exclude_patterns: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        parsed = urlparse(self.base_url)
        self._base_netloc = parsed.netloc.lower()
        self._base_scheme = parsed.scheme.lower()
        # Strip port for subdomain matching
        self._base_host = self._base_netloc.split(":")[0]
        self._compiled_excludes = [re.compile(p) for p in self.exclude_patterns]

    def in_scope(self, url: str) -> bool:
        try:
            p = urlparse(url)
        except Exception:
            return False

        if p.scheme in _REJECT_SCHEMES:
            return False
        if not p.scheme or not p.netloc:
            return False

        ext = _url_ext(url)
        if ext in _STATIC_EXTS:
            return False

        netloc = p.netloc.lower()
        host = netloc.split(":")[0]

        if self.include_subdomains:
            if host != self._base_host and not host.endswith("." + self._base_host):
                return False
        else:
            if netloc != self._base_netloc:
                return False

        for pattern in self._compiled_excludes:
            if pattern.search(url):
                return False

        return True


# ── DOM fingerprinting ────────────────────────────────────────────────────────

def _dom_fingerprint(html: str) -> str:
    """Structural fingerprint: tag sequence stripped of attributes and text.

    Pages that differ only in dynamic content (IDs, counters, tokens) share
    the same fingerprint and need not be deep-crawled redundantly.
    """
    tags: list[str] = []
    for m in re.finditer(r"<(/?\w+)[^>]*>", html):
        tag = m.group(1).lower()
        # Skip inline noise that produces spurious uniqueness
        if tag not in {"script", "style", "meta", "link", "br", "img", "input"}:
            tags.append(f"<{tag}>")
        if len(tags) >= 500:
            break
    structural = "".join(tags)
    return hashlib.sha256(structural.encode("utf-8", "ignore")).hexdigest()[:16]


# ── CrawlResult ───────────────────────────────────────────────────────────────

@dataclass
class CrawlResult:
    target: str
    total_urls: int = 0
    total_forms: int = 0
    total_params: int = 0
    api_endpoints: list[str] = field(default_factory=list)
    ws_endpoints: list[str] = field(default_factory=list)
    sse_endpoints: list[str] = field(default_factory=list)
    runtime_routes: list[str] = field(default_factory=list)
    source_map_paths: list[str] = field(default_factory=list)
    openapi_endpoints: list[str] = field(default_factory=list)
    graphql_types: list[str] = field(default_factory=list)
    dom_fingerprints: dict[str, str] = field(default_factory=dict)
    forms: list[dict] = field(default_factory=list)
    all_urls: list[str] = field(default_factory=list)
    js_files: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    elapsed_seconds: float = 0.0

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "total_urls": self.total_urls,
            "total_forms": self.total_forms,
            "total_params": self.total_params,
            "api_endpoints": self.api_endpoints,
            "ws_endpoints": self.ws_endpoints,
            "sse_endpoints": self.sse_endpoints,
            "runtime_routes": self.runtime_routes,
            "source_map_paths": self.source_map_paths,
            "openapi_endpoints": self.openapi_endpoints,
            "graphql_types": self.graphql_types,
            "dom_fingerprints": self.dom_fingerprints,
            "forms": self.forms,
            "all_urls": self.all_urls,
            "js_files": self.js_files,
            "errors": self.errors,
            "elapsed_seconds": round(self.elapsed_seconds, 2),
        }

    def summary(self) -> str:
        lines = [
            f"Target:          {self.target}",
            f"URLs discovered: {self.total_urls}",
            f"Forms:           {self.total_forms}",
            f"Unique params:   {self.total_params}",
            f"AJAX endpoints:  {len(self.api_endpoints)}",
            f"WebSocket URLs:  {len(self.ws_endpoints)}",
            f"Runtime routes:  {len(self.runtime_routes)}",
            f"OpenAPI routes:  {len(self.openapi_endpoints)}",
            f"GraphQL types:   {len(self.graphql_types)}",
            f"JS files:        {len(self.js_files)}",
            f"Source maps:     {len(self.source_map_paths)}",
            f"Elapsed:         {self.elapsed_seconds:.1f}s",
        ]
        return "\n".join(lines)


# ── CrawlOrchestrator ─────────────────────────────────────────────────────────

class CrawlOrchestrator:
    """Two-phase crawl controller: HTTP sweep -> deep browser discovery.

    Phase 1: aiohttp BFS, 300-page cap, 15 concurrent workers.
    Phase 2: Playwright JS render with SPA route interception, click discovery,
             shadow DOM extraction, and WebSocket tracking.

    Results from Phase 2 feed a second BFS pass to surface server-side routes
    reachable only after JS navigation.
    """

    def __init__(
        self,
        target: str,
        results_dir: Path,
        *,
        max_http_pages: int = 300,
        max_browser_pages: int = 150,
        http_concurrency: int = 15,
        browser_concurrency: int = 3,
        timeout_s: int = 15,
        include_subdomains: bool = False,
        exclude_patterns: list[str] | None = None,
        storage_state_path: str | None = None,
        headless: bool = True,
        proxy: str | None = None,
        use_browser: bool = True,
    ) -> None:
        self.target = target.rstrip("/")
        self.results_dir = Path(results_dir)
        self.max_http_pages = max_http_pages
        self.max_browser_pages = max_browser_pages
        self.http_concurrency = http_concurrency
        self.browser_concurrency = browser_concurrency
        self.timeout_s = timeout_s
        self.storage_state_path = storage_state_path
        self.headless = headless
        self.proxy = proxy
        self.use_browser = use_browser

        self._scope = ScopePolicy(
            base_url=self.target,
            include_subdomains=include_subdomains,
            exclude_patterns=exclude_patterns or [],
        )

        self._result = CrawlResult(target=self.target)
        self._visited_norm: set[str] = set()
        self._all_urls: dict[str, str] = {}      # normalized -> canonical
        self._forms: list[dict] = []
        self._params: set[str] = set()
        self._ajax_endpoints: set[str] = set()
        self._ws_endpoints: set[str] = set()
        self._sse_endpoints: set[str] = set()
        self._runtime_routes: set[str] = set()
        self._source_maps: set[str] = set()
        self._js_files: set[str] = set()
        self._dom_fps: dict[str, str] = {}
        self._fp_seen: set[str] = set()           # fingerprints seen — dedup near-dupes

        # Browser engine is imported conditionally
        self._browser_available: bool = False
        self._BrowserEngine: Any = None
        try:
            from webforge.core.browser_engine import BrowserEngine
            self._browser_available = use_browser and BrowserEngine.available()
            self._BrowserEngine = BrowserEngine if self._browser_available else None
        except Exception:
            pass

        import random
        self._random = random

    # ── Public entry point ────────────────────────────────────────────────────

    async def run(self) -> CrawlResult:
        t0 = time.monotonic()
        # Gate 2 crawler depth is outside Task 003.  This legacy orchestrator
        # still owns direct aiohttp/browser paths, so keep it inert rather than
        # imply those paths inherit the new policy.
        self._result.errors.append("outbound_policy_unsupported")
        self._result.elapsed_seconds = time.monotonic() - t0
        return self._result
        self.results_dir.mkdir(parents=True, exist_ok=True)
        log.info("[crawl] Starting Phase 1 HTTP sweep: %s", self.target)

        phase1_urls = await self._phase1_http_sweep()
        log.info("[crawl] Phase 1 complete: %d URLs", len(phase1_urls))

        # API schema discovery runs concurrently with Phase 2
        schema_task = asyncio.create_task(self._discover_api_schemas())

        if self._browser_available and self.use_browser:
            log.info("[crawl] Starting Phase 2 browser deep-crawl (%d URLs)", len(phase1_urls))
            await self._phase2_browser_deep(phase1_urls)

            # Second HTTP sweep over runtime-discovered routes not yet visited
            new_routes = self._runtime_routes - set(self._all_urls.values())
            if new_routes:
                log.info(
                    "[crawl] Phase 2 discovered %d new routes; running supplemental HTTP sweep",
                    len(new_routes),
                )
                await self._http_sweep_urls(new_routes, extra_cap=100)
        else:
            log.info("[crawl] Browser unavailable or disabled — skipping Phase 2")

        schema_data = await schema_task

        self._result.elapsed_seconds = time.monotonic() - t0
        self._result.all_urls = sorted(self._all_urls.values())
        self._result.total_urls = len(self._result.all_urls)
        self._result.forms = self._forms
        self._result.total_forms = len(self._forms)
        self._result.total_params = len(self._params)
        self._result.api_endpoints = sorted(self._ajax_endpoints)
        self._result.ws_endpoints = sorted(self._ws_endpoints)
        self._result.sse_endpoints = sorted(self._sse_endpoints)
        self._result.runtime_routes = sorted(self._runtime_routes)
        self._result.source_map_paths = sorted(self._source_maps)
        self._result.js_files = sorted(self._js_files)
        self._result.dom_fingerprints = self._dom_fps
        self._result.openapi_endpoints = schema_data.get("openapi_endpoints", [])
        self._result.graphql_types = schema_data.get("graphql_types", [])

        log.info("[crawl] Complete.\n%s", self._result.summary())
        return self._result

    # ── Phase 1: HTTP BFS sweep ───────────────────────────────────────────────

    async def _phase1_http_sweep(self) -> set[str]:
        import aiohttp

        queue: list[tuple[str, int]] = [(self.target, 0)]
        conn = aiohttp.TCPConnector(ssl=False, limit=self.http_concurrency * 2)

        async with aiohttp.ClientSession(connector=conn) as session:
            # Pre-seed from sitemap + robots.txt
            for u in await self._fetch_sitemap_urls(session):
                norm = _normalize_url(u)
                if norm and norm not in self._visited_norm and self._scope.in_scope(u):
                    queue.append((u, 1))

            sem = asyncio.Semaphore(self.http_concurrency)

            while queue and len(self._visited_norm) < self.max_http_pages:
                batch: list[tuple[str, int]] = []
                while queue and len(batch) < 30:
                    url, depth = queue.pop(0)
                    norm = _normalize_url(url)
                    if norm and norm not in self._visited_norm:
                        batch.append((url, depth))

                if not batch:
                    continue

                tasks = [
                    self._crawl_page_http(url, depth, sem, session)
                    for url, depth in batch
                ]
                results = await asyncio.gather(*tasks, return_exceptions=True)

                for res in results:
                    if not isinstance(res, dict):
                        continue
                    for link, d in res.get("links", []):
                        norm = _normalize_url(link)
                        if norm and norm not in self._visited_norm and len(self._visited_norm) < self.max_http_pages:
                            queue.append((link, d))
                    self._forms.extend(res.get("forms", []))
                    self._params.update(res.get("params", set()))
                    self._ajax_endpoints.update(res.get("js_endpoints", set()))
                    self._source_maps.update(res.get("source_maps", set()))
                    self._js_files.update(res.get("js_files", set()))

        return set(self._all_urls.values())

    async def _http_sweep_urls(self, urls: set[str], extra_cap: int = 100) -> None:
        """Targeted HTTP sweep of a specific URL set — used for Phase 2 follow-up."""
        import aiohttp

        sem = asyncio.Semaphore(self.http_concurrency)
        conn = aiohttp.TCPConnector(ssl=False, limit=self.http_concurrency * 2)
        count = 0

        async with aiohttp.ClientSession(connector=conn) as session:
            tasks = []
            for url in urls:
                if count >= extra_cap:
                    break
                norm = _normalize_url(url)
                if not norm or norm in self._visited_norm:
                    continue
                tasks.append(self._crawl_page_http(url, 0, sem, session))
                count += 1

            results = await asyncio.gather(*tasks, return_exceptions=True)
            for res in results:
                if not isinstance(res, dict):
                    continue
                self._forms.extend(res.get("forms", []))
                self._params.update(res.get("params", set()))
                self._ajax_endpoints.update(res.get("js_endpoints", set()))

    async def _crawl_page_http(
        self,
        url: str,
        depth: int,
        sem: asyncio.Semaphore,
        session: Any,
    ) -> dict:
        import aiohttp

        norm = _normalize_url(url)
        async with sem:
            if norm in self._visited_norm:
                return {}
            self._visited_norm.add(norm)
            self._all_urls[norm] = url

            try:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=self.timeout_s),
                    allow_redirects=True,
                    headers={"User-Agent": self._random.choice(_USER_AGENTS)},
                    ssl=False,
                ) as resp:
                    ctype = resp.headers.get("Content-Type", "")
                    if resp.status not in range(200, 400):
                        return {}
                    if "text/html" not in ctype and "text/plain" not in ctype:
                        return {}
                    html = await resp.text(errors="ignore")
            except Exception as exc:
                log.debug("[phase1] Fetch failed %s: %s", url, exc)
                return {}

        return {
            "links": self._extract_links_html(html, url, depth),
            "forms": self._extract_forms_html(html, url),
            "params": self._extract_params_url(url),
            "js_endpoints": self._extract_js_endpoints_html(html, url),
            "source_maps": self._extract_source_maps(html, url),
            "js_files": self._extract_script_urls(html, url),
        }

    # ── HTML extraction helpers ───────────────────────────────────────────────

    def _extract_links_html(self, html: str, base_url: str, depth: int) -> list[tuple[str, int]]:
        seen: set[str] = set()
        links: list[tuple[str, int]] = []
        next_depth = depth + 1

        def _add(href: str) -> None:
            if not href or len(href) < 2 or len(href) > 400:
                return
            full = urljoin(base_url, href.strip())
            if not self._scope.in_scope(full):
                return
            norm = _normalize_url(full)
            if not norm or norm in seen or norm in self._visited_norm:
                return
            seen.add(norm)
            links.append((full, next_depth))

        for m in re.finditer(r'href=["\']([^"\'#\s]{2,400})["\']', html, re.IGNORECASE):
            _add(m.group(1))
        for m in re.finditer(r'data-(?:href|url|link|route|path)=["\']([^"\'#\s]{2,400})["\']', html, re.IGNORECASE):
            _add(m.group(1))
        for m in re.finditer(r'action=["\']([^"\'#\s]{2,400})["\']', html, re.IGNORECASE):
            _add(m.group(1))
        # React Router / Vue Router "to" props rendered into HTML
        for m in re.finditer(r'\bto=["\'](/[^"\']{1,300})["\']', html, re.IGNORECASE):
            _add(m.group(1))

        return links

    def _extract_forms_html(self, html: str, page_url: str) -> list[dict]:
        forms: list[dict] = []
        for fm in re.finditer(r"<form([^>]*)>(.*?)</form>", html, re.IGNORECASE | re.DOTALL):
            attrs, body = fm.group(1), fm.group(2)
            action = re.search(r'action=["\']([^"\']+)["\']', attrs, re.IGNORECASE)
            method = re.search(r'method=["\']([^"\']+)["\']', attrs, re.IGNORECASE)
            enctype = re.search(r'enctype=["\']([^"\']+)["\']', attrs, re.IGNORECASE)
            inputs = re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', body, re.IGNORECASE)
            textareas = re.findall(r'<textarea[^>]+name=["\']([^"\']+)["\']', body, re.IGNORECASE)
            selects = re.findall(r'<select[^>]+name=["\']([^"\']+)["\']', body, re.IGNORECASE)
            raw_action = action.group(1) if action else page_url
            full_action = urljoin(page_url, raw_action)
            if not self._scope.in_scope(full_action):
                continue
            forms.append({
                "url": page_url,
                "action": full_action,
                "method": (method.group(1) if method else "GET").upper(),
                "enctype": enctype.group(1) if enctype else "application/x-www-form-urlencoded",
                "inputs": inputs + textareas + selects,
            })
            self._params.update(inputs + textareas + selects)
        return forms

    def _extract_params_url(self, url: str) -> set[str]:
        return set(parse_qs(urlparse(url).query).keys())

    def _extract_js_endpoints_html(self, html: str, base_url: str) -> set[str]:
        endpoints: set[str] = set()
        base_host = urlparse(self.target).netloc
        for script_m in re.finditer(r"<script[^>]*>(.*?)</script>", html, re.IGNORECASE | re.DOTALL):
            js = script_m.group(1)
            # String literals that look like internal API paths
            for m in re.finditer(
                r'["\`](/(?:api|v\d+|graphql|rest|gql|rpc|service|endpoint|query|mutation)[^"\'`\s]{0,200})["\`]',
                js, re.IGNORECASE,
            ):
                full = urljoin(base_url, m.group(1))
                if urlparse(full).netloc == base_host:
                    endpoints.add(full)
            # fetch/axios/http call strings
            for m in re.finditer(
                r'(?:fetch|axios\.(?:get|post|put|delete|patch)|http\.(?:get|post))\s*\(\s*["\`]([^"\'`\s]{4,300})["\`]',
                js, re.IGNORECASE,
            ):
                u = m.group(1)
                if u.startswith("/") or u.startswith(self.target):
                    full = urljoin(base_url, u)
                    if urlparse(full).netloc == base_host:
                        endpoints.add(full)
        return endpoints

    def _extract_source_maps(self, html: str, base_url: str) -> set[str]:
        maps: set[str] = set()
        for m in re.finditer(r"sourceMappingURL=([^\s'\"]+\.map)", html):
            maps.add(urljoin(base_url, m.group(1)))
        for m in re.finditer(r'["\']([^"\']+\.js\.map)["\']', html):
            full = urljoin(base_url, m.group(1))
            if self._scope.in_scope(full):
                maps.add(full)
        return maps

    def _extract_script_urls(self, html: str, base_url: str) -> set[str]:
        js_files: set[str] = set()
        base_host = urlparse(self.target).netloc
        for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE):
            full = urljoin(base_url, m.group(1))
            if urlparse(full).netloc == base_host:
                js_files.add(full)
        return js_files

    # ── Sitemap pre-seeding ───────────────────────────────────────────────────

    async def _fetch_sitemap_urls(self, session: Any) -> list[str]:
        import aiohttp
        urls: list[str] = []
        for path in ("/sitemap.xml", "/robots.txt"):
            try:
                async with session.get(
                    self.target + path,
                    timeout=aiohttp.ClientTimeout(total=self.timeout_s),
                    headers={"User-Agent": self._random.choice(_USER_AGENTS)},
                    allow_redirects=True,
                    ssl=False,
                ) as resp:
                    if resp.status != 200:
                        continue
                    text = await resp.text(errors="ignore")
                    if path.endswith(".xml"):
                        for m in re.finditer(r"<loc>\s*([^<\s]+)\s*</loc>", text):
                            u = m.group(1).strip()
                            if u.startswith(self.target):
                                urls.append(u)
                    else:
                        for m in re.finditer(r"(?:Allow|Disallow):\s*(/[^\s*]+)", text):
                            part = m.group(1).strip()
                            if part and part != "/":
                                urls.append(urljoin(self.target, part))
            except Exception:
                pass
        return urls[:150]

    # ── Phase 2: Deep browser crawl ───────────────────────────────────────────

    async def _phase2_browser_deep(self, urls: set[str]) -> None:
        """JS-rendered crawl over the Phase 1 URL set.

        Playwright contexts are memory-heavy; browser_concurrency defaults to 3
        to avoid OOM. Each URL receives: render, SPA route capture, click
        discovery, shadow DOM link extraction, AJAX/WebSocket collection.
        """
        if not self._BrowserEngine:
            return

        target_urls = list(urls)[: self.max_browser_pages]
        sem = asyncio.Semaphore(self.browser_concurrency)

        engine = self._BrowserEngine(
            results_dir=self.results_dir,
            headless=self.headless,
            proxy=self.proxy,
            storage_state=self.storage_state_path,
            timeout_ms=self.timeout_s * 1000,
        )

        try:
            await engine.start()
            tasks = [
                self._browser_process_url(url, engine, sem)
                for url in target_urls
            ]
            await asyncio.gather(*tasks, return_exceptions=True)
        except Exception as exc:
            log.error("[phase2] Browser engine error: %s", exc)
        finally:
            try:
                await engine.close()
            except Exception:
                pass

    async def _browser_process_url(self, url: str, engine: Any, sem: asyncio.Semaphore) -> None:
        async with sem:
            try:
                await self._browser_crawl_single(url, engine)
            except Exception as exc:
                log.debug("[phase2] Error processing %s: %s", url, exc)

    async def _browser_crawl_single(self, url: str, engine: Any) -> None:
        """Render one URL and extract all browser-only artifacts."""
        if not engine._context:
            return

        page = await engine._context.new_page()
        ajax: set[str] = set()
        ws: set[str] = set()

        def _on_response(resp: Any) -> None:
            try:
                req = resp.request
                rtype = req.resource_type
                resp_url = resp.url
                if rtype in {"xhr", "fetch"} and self._scope.in_scope(resp_url):
                    ajax.add(resp_url)
                    ct = resp.headers.get("content-type", "")
                    if "event-stream" in ct:
                        self._sse_endpoints.add(resp_url)
            except Exception:
                pass

        def _on_ws(ws_conn: Any) -> None:
            try:
                if self._scope.in_scope(ws_conn.url):
                    ws.add(ws_conn.url)
            except Exception:
                pass

        page.on("response", _on_response)
        page.on("websocket", _on_ws)

        try:
            await page.add_init_script(_SPA_INTERCEPTOR_JS)
            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=self.timeout_s * 1000)
            except Exception as exc:
                log.debug("[phase2] Navigation failed %s: %s", url, exc)
                return

            try:
                await page.wait_for_load_state("networkidle", timeout=min(self.timeout_s * 1000, 8000))
            except Exception:
                await page.wait_for_timeout(1000)

            html = await page.content()

            # DOM fingerprint dedup — skip near-duplicate pages
            fp = _dom_fingerprint(html)
            self._dom_fps[url] = fp
            if fp in self._fp_seen:
                log.debug("[phase2] Near-duplicate skipped: %s (fp=%s)", url, fp)
                return
            self._fp_seen.add(fp)

            # Rendered anchor + data-attr links
            try:
                rendered_links = await page.evaluate("""() => {
                    const s = new Set();
                    for (const a of document.links) { if (a.href) s.add(a.href); }
                    for (const el of document.querySelectorAll('[data-href],[data-url],[data-route],[data-path]')) {
                        const v = el.getAttribute('data-href') || el.getAttribute('data-url') ||
                                  el.getAttribute('data-route') || el.getAttribute('data-path');
                        if (v) s.add(v);
                    }
                    for (const el of document.querySelectorAll('[to]')) {
                        const t = el.getAttribute('to');
                        if (t && (t.startsWith('/') || t.startsWith('http'))) s.add(t);
                    }
                    return [...s].filter(Boolean);
                }""")
                for link in rendered_links:
                    full = urljoin(page.url, link)
                    if self._scope.in_scope(full):
                        norm = _normalize_url(full)
                        if norm and norm not in self._visited_norm:
                            self._all_urls[norm] = full
            except Exception:
                pass

            # Shadow DOM links
            try:
                shadow_links = await page.evaluate("""() => {
                    const links = [];
                    for (const el of document.querySelectorAll('*')) {
                        if (el.shadowRoot) {
                            for (const a of el.shadowRoot.querySelectorAll('a[href]')) {
                                links.push(a.href);
                            }
                        }
                    }
                    return links;
                }""")
                for link in shadow_links:
                    full = urljoin(page.url, link)
                    if self._scope.in_scope(full):
                        norm = _normalize_url(full)
                        if norm and norm not in self._visited_norm:
                            self._all_urls[norm] = full
                            self._runtime_routes.add(full)
            except Exception:
                pass

            self._source_maps.update(self._extract_source_maps(html, page.url))
            self._js_files.update(self._extract_script_urls(html, page.url))

            # Click discovery + SPA route capture
            click_routes = await self._click_discover(page, page.url)
            self._runtime_routes.update(click_routes)

            spa_routes = await self._extract_spa_routes(page)
            self._runtime_routes.update(spa_routes)

            for r in spa_routes | click_routes:
                if self._scope.in_scope(r):
                    norm = _normalize_url(r)
                    if norm and norm not in self._visited_norm:
                        self._all_urls[norm] = r

            # Rendered DOM forms
            try:
                rendered_forms = await page.evaluate("""() =>
                    Array.from(document.forms).map(form => ({
                        action: form.action || location.href,
                        method: (form.method || 'GET').toUpperCase(),
                        inputs: Array.from(form.querySelectorAll('input, textarea, select'))
                            .map(el => el.name || el.id).filter(Boolean)
                    }))
                """)
                for f in rendered_forms:
                    action = urljoin(page.url, str(f.get("action") or page.url))
                    if self._scope.in_scope(action):
                        self._forms.append({"url": url, **f, "action": action})
                        self._params.update(f.get("inputs", []))
            except Exception:
                pass

        finally:
            self._ajax_endpoints.update(ajax)
            self._ws_endpoints.update(ws)
            try:
                await page.close()
            except Exception:
                pass

    # ── Click-discovery engine ────────────────────────────────────────────────

    async def _click_discover(self, page: Any, base_url: str) -> set[str]:
        """Click interactive non-submit elements to trigger SPA navigation.

        Iterates _CLICK_SELECTORS in priority order. After each click waits
        _CLICK_WAIT_MS for the SPA router to commit a new history entry, then
        reads window.__FORGE_ROUTES__. If the page navigated away it goes back
        before continuing, preserving the click context.
        """
        discovered: set[str] = set()
        click_count = 0

        for selector in _CLICK_SELECTORS:
            if click_count >= _MAX_CLICKS_PER_PAGE:
                break
            try:
                elements = await page.query_selector_all(selector)
                for el in elements[: _MAX_CLICKS_PER_PAGE - click_count]:
                    try:
                        is_visible = await el.is_visible()
                        if not is_visible:
                            continue

                        # Guard: never click submit/reset buttons
                        el_type = (await el.get_attribute("type") or "").lower()
                        if el_type in {"submit", "reset"}:
                            continue

                        url_before = page.url
                        await el.click(timeout=2000, force=False)
                        await page.wait_for_timeout(_CLICK_WAIT_MS)

                        routes = await self._extract_spa_routes(page)
                        discovered.update(routes)

                        if page.url != url_before:
                            discovered.add(page.url)
                            try:
                                await page.go_back(timeout=3000)
                                await page.wait_for_timeout(300)
                            except Exception:
                                try:
                                    await page.goto(base_url, wait_until="domcontentloaded", timeout=8000)
                                    await page.wait_for_timeout(500)
                                except Exception:
                                    return discovered

                        click_count += 1
                    except Exception:
                        continue
            except Exception:
                continue

        return discovered

    # ── SPA route extraction ──────────────────────────────────────────────────

    async def _extract_spa_routes(self, page: Any) -> set[str]:
        """Read routes captured by the SPA interceptor init script."""
        routes: set[str] = set()
        try:
            raw = await page.evaluate(
                "() => window.__FORGE_ROUTES__ ? [...window.__FORGE_ROUTES__] : []"
            )
            for r in raw:
                if not r:
                    continue
                full = urljoin(page.url, r)
                if self._scope.in_scope(full):
                    routes.add(full)
        except Exception:
            pass
        return routes

    # ── API schema discovery ──────────────────────────────────────────────────

    async def _discover_api_schemas(self) -> dict:
        """Probe well-known API documentation and schema endpoints.

        Concurrently hits OpenAPI/Swagger spec paths and GraphQL introspection.
        Returns:
            openapi_endpoints: list[str]  — route paths parsed from specs
            graphql_types:     list[str]  — type names from introspection
        """
        import aiohttp

        openapi_endpoints: list[str] = []
        graphql_types: list[str] = []

        conn = aiohttp.TCPConnector(ssl=False, limit=10)
        timeout = aiohttp.ClientTimeout(total=min(self.timeout_s, 10))

        async with aiohttp.ClientSession(connector=conn, timeout=timeout) as session:
            schema_tasks = [
                self._probe_openapi(session, self.target + path)
                for path in _API_SCHEMA_PATHS
            ]
            schema_results = await asyncio.gather(*schema_tasks, return_exceptions=True)
            for res in schema_results:
                if isinstance(res, list):
                    openapi_endpoints.extend(res)

            gql_tasks = [
                self._probe_graphql(session, self.target + path)
                for path in _GRAPHQL_PATHS
            ]
            gql_results = await asyncio.gather(*gql_tasks, return_exceptions=True)
            for res in gql_results:
                if isinstance(res, list):
                    graphql_types.extend(res)

        return {
            "openapi_endpoints": sorted(set(openapi_endpoints)),
            "graphql_types": sorted(set(graphql_types)),
        }

    async def _probe_openapi(self, session: Any, url: str) -> list[str]:
        """Fetch a potential OpenAPI/Swagger spec and return its path keys."""
        try:
            async with session.get(
                url,
                headers={
                    "User-Agent": self._random.choice(_USER_AGENTS),
                    "Accept": "application/json, application/yaml, */*",
                },
                allow_redirects=True,
                ssl=False,
            ) as resp:
                if resp.status != 200:
                    return []
                ctype = resp.headers.get("Content-Type", "")
                is_schema_url = any(
                    url.endswith(s) for s in (".json", ".yaml", "/api-docs", "/schema/", "/docs/api/")
                )
                if "json" not in ctype and "yaml" not in ctype and not is_schema_url:
                    return []
                text = await resp.text(errors="ignore")

                try:
                    data = json.loads(text)
                except Exception:
                    # Minimal YAML: extract indented path keys under "paths:"
                    paths: list[str] = []
                    in_paths = False
                    for line in text.splitlines():
                        if re.match(r"^paths\s*:", line):
                            in_paths = True
                            continue
                        if in_paths:
                            if re.match(r"^\S", line) and not line.strip().startswith("/"):
                                break
                            m = re.match(r"^\s{2}(/[^\s:]+)", line)
                            if m:
                                paths.append(m.group(1))
                    return paths[:500]

                if "openapi" in data or "swagger" in data:
                    raw_paths = data.get("paths", {})
                    if isinstance(raw_paths, dict):
                        log.info("[api-schema] OpenAPI spec at %s: %d paths", url, len(raw_paths))
                        return list(raw_paths.keys())[:500]

                # Next.js pages manifest: { "/route": ["chunk.js"], ... }
                if isinstance(data, dict) and all(isinstance(v, list) for v in data.values()):
                    pages = [k for k in data if k.startswith("/")]
                    if pages:
                        log.info("[api-schema] Next.js manifest at %s: %d pages", url, len(pages))
                        return pages[:500]

        except Exception as exc:
            log.debug("[api-schema] Probe failed %s: %s", url, exc)

        return []

    async def _probe_graphql(self, session: Any, url: str) -> list[str]:
        """POST minimal introspection query; return non-built-in type names."""
        try:
            async with session.post(
                url,
                data=_GRAPHQL_INTROSPECTION,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "User-Agent": self._random.choice(_USER_AGENTS),
                },
                ssl=False,
            ) as resp:
                if resp.status not in {200, 400}:
                    return []
                text = await resp.text(errors="ignore")
                try:
                    data = json.loads(text)
                except Exception:
                    return []

                schema = (data.get("data") or {}).get("__schema", {})
                if not schema:
                    return []

                types = schema.get("types", [])
                type_names = [
                    t["name"] for t in types
                    if isinstance(t, dict) and t.get("name") and not t["name"].startswith("__")
                ]
                if type_names:
                    log.info("[api-schema] GraphQL introspection OK %s: %d types", url, len(type_names))
                return type_names[:200]

        except Exception as exc:
            log.debug("[api-schema] GraphQL probe failed %s: %s", url, exc)

        return []


# ── Unit tests ────────────────────────────────────────────────────────────────

class TestCrawlOrchestrator:
    """Unit tests — no network, no browser required."""

    # ── ScopePolicy ──────────────────────────────────────────────────────────

    def test_scope_same_origin_in(self) -> None:
        sp = ScopePolicy("https://example.com")
        assert sp.in_scope("https://example.com/page")
        assert sp.in_scope("https://example.com/api/v1/users")

    def test_scope_different_origin_out(self) -> None:
        sp = ScopePolicy("https://example.com")
        assert not sp.in_scope("https://evil.com/page")
        assert not sp.in_scope("https://sub.example.com/page")

    def test_scope_subdomains_enabled(self) -> None:
        sp = ScopePolicy("https://example.com", include_subdomains=True)
        assert sp.in_scope("https://api.example.com/v1/data")
        assert sp.in_scope("https://deep.sub.example.com/page")
        assert not sp.in_scope("https://notexample.com/page")

    def test_scope_rejects_static_ext(self) -> None:
        sp = ScopePolicy("https://example.com")
        assert not sp.in_scope("https://example.com/logo.png")
        assert not sp.in_scope("https://example.com/font.woff2")
        assert not sp.in_scope("https://example.com/doc.pdf")

    def test_scope_rejects_bad_schemes(self) -> None:
        sp = ScopePolicy("https://example.com")
        assert not sp.in_scope("mailto:admin@example.com")
        assert not sp.in_scope("javascript:void(0)")
        assert not sp.in_scope("tel:+15551234567")

    def test_scope_exclude_patterns(self) -> None:
        sp = ScopePolicy(
            "https://example.com",
            exclude_patterns=[r"/logout", r"/admin/"],
        )
        assert not sp.in_scope("https://example.com/logout")
        assert not sp.in_scope("https://example.com/admin/users")
        assert sp.in_scope("https://example.com/profile")

    def test_scope_js_extension_in_scope(self) -> None:
        sp = ScopePolicy("https://example.com")
        # .js is not in the static reject list — JS files are crawled
        assert sp.in_scope("https://example.com/app.js")

    def test_scope_port_match(self) -> None:
        sp = ScopePolicy("https://example.com:8443")
        assert sp.in_scope("https://example.com:8443/page")
        assert not sp.in_scope("https://example.com:9000/page")

    # ── DOM fingerprint ───────────────────────────────────────────────────────

    def test_dom_fingerprint_deterministic(self) -> None:
        html = "<html><body><div><ul><li>A</li><li>B</li></ul></div></body></html>"
        assert _dom_fingerprint(html) == _dom_fingerprint(html)
        assert len(_dom_fingerprint(html)) == 16

    def test_dom_fingerprint_structural_match(self) -> None:
        html_a = "<html><body><div><p>Hello world</p></div></body></html>"
        html_b = "<html><body><div><p>Completely different content</p></div></body></html>"
        assert _dom_fingerprint(html_a) == _dom_fingerprint(html_b)

    def test_dom_fingerprint_structural_diff(self) -> None:
        html_a = "<html><body><div><p>text</p></div></body></html>"
        html_b = "<html><body><div><p>text</p><span>extra</span></div></body></html>"
        assert _dom_fingerprint(html_a) != _dom_fingerprint(html_b)

    def test_dom_fingerprint_empty(self) -> None:
        fp = _dom_fingerprint("")
        assert isinstance(fp, str)
        assert len(fp) == 16

    def test_dom_fingerprint_ignores_dynamic_ids(self) -> None:
        html_a = '<html><body><div id="uuid-abc123">token: aaa</div></body></html>'
        html_b = '<html><body><div id="uuid-xyz999">token: zzz</div></body></html>'
        assert _dom_fingerprint(html_a) == _dom_fingerprint(html_b)

    # ── URL normalization ─────────────────────────────────────────────────────

    def test_normalize_url_sorts_params(self) -> None:
        a = _normalize_url("https://example.com/search?b=2&a=1")
        b = _normalize_url("https://example.com/search?a=1&b=2")
        assert a == b

    def test_normalize_url_strips_trailing_slash(self) -> None:
        a = _normalize_url("https://example.com/page/")
        b = _normalize_url("https://example.com/page")
        assert a == b

    def test_normalize_url_preserves_path_and_params(self) -> None:
        n = _normalize_url("https://example.com/api/v1/users?active=true")
        assert "/api/v1/users" in n
        assert "active=true" in n

    def test_normalize_url_rejects_bad_scheme(self) -> None:
        assert _normalize_url("javascript:alert(1)") == ""
        assert _normalize_url("mailto:x@y.com") == ""

    # ── CrawlResult ──────────────────────────────────────────────────────────

    def test_crawl_result_to_dict_fields(self) -> None:
        r = CrawlResult(
            target="https://example.com",
            total_urls=42,
            total_forms=5,
            api_endpoints=["https://example.com/api/v1/data"],
        )
        d = r.to_dict()
        assert d["target"] == "https://example.com"
        assert d["total_urls"] == 42
        assert d["total_forms"] == 5
        assert "https://example.com/api/v1/data" in d["api_endpoints"]

    def test_crawl_result_summary_contains_key_fields(self) -> None:
        r = CrawlResult(target="https://example.com", total_urls=100, elapsed_seconds=12.5)
        s = r.summary()
        assert "100" in s
        assert "12.5" in s
        assert "https://example.com" in s

    def test_crawl_result_elapsed_rounds(self) -> None:
        r = CrawlResult(target="https://t.com", elapsed_seconds=3.141592)
        d = r.to_dict()
        assert d["elapsed_seconds"] == 3.14

    # ── HTML extraction (no network) ──────────────────────────────────────────

    def _make_orchestrator(self) -> "CrawlOrchestrator":
        import tempfile
        tmp = Path(tempfile.mkdtemp())
        return CrawlOrchestrator("https://example.com", tmp, use_browser=False)

    def test_extract_links_same_origin_only(self) -> None:
        orch = self._make_orchestrator()
        html = '<a href="/page1">P1</a><a href="https://evil.com/x">ext</a>'
        links = orch._extract_links_html(html, "https://example.com", 0)
        hrefs = [u for u, _ in links]
        assert any("page1" in h for h in hrefs)
        assert not any("evil.com" in h for h in hrefs)

    def test_extract_links_data_attrs(self) -> None:
        orch = self._make_orchestrator()
        html = '<div data-href="/spa/route">nav</div>'
        links = orch._extract_links_html(html, "https://example.com", 0)
        assert any("spa/route" in u for u, _ in links)

    def test_extract_forms_parses_all_field_types(self) -> None:
        orch = self._make_orchestrator()
        html = (
            '<form action="/login" method="POST">'
            '<input name="username"><input name="password">'
            '<textarea name="bio"></textarea>'
            '<select name="role"></select>'
            '</form>'
        )
        forms = orch._extract_forms_html(html, "https://example.com")
        assert len(forms) == 1
        assert "username" in forms[0]["inputs"]
        assert "password" in forms[0]["inputs"]
        assert "bio" in forms[0]["inputs"]
        assert "role" in forms[0]["inputs"]
        assert forms[0]["method"] == "POST"

    def test_extract_forms_populates_params(self) -> None:
        orch = self._make_orchestrator()
        html = '<form><input name="search_q"></form>'
        orch._extract_forms_html(html, "https://example.com")
        assert "search_q" in orch._params

    def test_extract_js_endpoints_fetch(self) -> None:
        orch = self._make_orchestrator()
        html = '<script>fetch("/api/v1/users").then(r=>r.json())</script>'
        eps = orch._extract_js_endpoints_html(html, "https://example.com")
        assert any("api/v1/users" in e for e in eps)

    def test_extract_js_endpoints_axios(self) -> None:
        orch = self._make_orchestrator()
        html = '<script>axios.get("/api/products")</script>'
        eps = orch._extract_js_endpoints_html(html, "https://example.com")
        assert any("api/products" in e for e in eps)

    def test_extract_source_maps_inline_comment(self) -> None:
        orch = self._make_orchestrator()
        html = "//# sourceMappingURL=app.js.map\n"
        maps = orch._extract_source_maps(html, "https://example.com/static/")
        assert any("app.js.map" in m for m in maps)

    def test_extract_script_urls(self) -> None:
        orch = self._make_orchestrator()
        html = '<script src="/static/bundle.js"></script>'
        js = orch._extract_script_urls(html, "https://example.com")
        assert any("bundle.js" in f for f in js)

    def test_extract_params_from_url(self) -> None:
        orch = self._make_orchestrator()
        params = orch._extract_params_url("https://example.com/search?q=test&page=1")
        assert "q" in params
        assert "page" in params
