"""Playwright browser engine for authenticated and JavaScript-heavy web scans."""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import hashlib
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

from common.outbound_policy import OutboundDenied, OutboundPolicy, OutboundReason

log = logging.getLogger("webforge.browser")


@dataclass
class BrowserSnapshot:
    """Rendered browser state captured from a target page."""
    url: str
    final_url: str = ""
    title: str = ""
    html: str = ""
    framework: str = ""
    forms: list[dict[str, Any]] = field(default_factory=list)
    links: list[str] = field(default_factory=list)
    ajax_endpoints: list[str] = field(default_factory=list)
    js_resources: list[str] = field(default_factory=list)
    shadow_dom: list[dict[str, Any]] = field(default_factory=list)
    websocket_endpoints: list[str] = field(default_factory=list)
    storage_state_path: str = ""
    error: str = ""
    # ── Acunetix-grade additions ──
    page_requests: list[dict[str, Any]] = field(default_factory=list)
    asset_requests: list[dict[str, Any]] = field(default_factory=list)
    api_requests: list[dict[str, Any]] = field(default_factory=list)
    ws_endpoints: list[str] = field(default_factory=list)
    post_requests: list[dict[str, Any]] = field(default_factory=list)
    sse_endpoints: list[str] = field(default_factory=list)
    source_map_paths: list[str] = field(default_factory=list)
    asset_manifest_files: list[str] = field(default_factory=list)
    runtime_routes: list[str] = field(default_factory=list)
    worker_scripts: list[str] = field(default_factory=list)
    dom_fingerprint: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "final_url": self.final_url,
            "title": self.title,
            "framework": self.framework,
            "forms": self.forms,
            "links": self.links,
            "ajax_endpoints": self.ajax_endpoints,
            "js_resources": self.js_resources,
            "shadow_dom": self.shadow_dom,
            "websocket_endpoints": self.websocket_endpoints,
            "storage_state_path": self.storage_state_path,
            "error": self.error,
            "page_requests": self.page_requests,
            "asset_requests": self.asset_requests,
            "api_requests": self.api_requests,
            "ws_endpoints": self.ws_endpoints,
            "post_requests": self.post_requests,
            "sse_endpoints": self.sse_endpoints,
            "source_map_paths": self.source_map_paths,
            "asset_manifest_files": self.asset_manifest_files,
            "runtime_routes": self.runtime_routes,
            "worker_scripts": self.worker_scripts,
            "dom_fingerprint": self.dom_fingerprint,
        }


# Worker constructor intercept — injected before page navigation so the hook is
# in place before any Worker() calls execute during page init.
_WORKER_INTERCEPT_JS = """
(function() {
    if (window.__FORGE_WORKER_HOOK__) return;
    window.__FORGE_WORKER_HOOK__ = true;
    const _OrigWorker = window.Worker;
    window.Worker = function(url, opts) {
        window.__FORGE_WORKERS__ = window.__FORGE_WORKERS__ || [];
        window.__FORGE_WORKERS__.push(String(url));
        return new _OrigWorker(url, opts);
    };
    window.Worker.prototype = _OrigWorker.prototype;
})();
"""


class BrowserEngine:
    """Small Playwright wrapper used by WebForge crawlers and auth replay."""

    def __init__(
        self,
        results_dir: Path,
        browser: str = "chromium",
        headless: bool = True,
        timeout_ms: int = 30000,
        proxy: str | None = None,
        storage_state: str | None = None,
        outbound_policy: OutboundPolicy | None = None,
    ) -> None:
        self.results_dir = results_dir
        self.browser_name = browser
        self.headless = headless
        self.timeout_ms = timeout_ms
        self.proxy = proxy
        self.storage_state = storage_state
        self.outbound_policy = outbound_policy
        self._browser_policy: OutboundPolicy | None = None
        self._playwright: Any = None
        self._browser: Any = None
        self._context: Any = None

    async def __aenter__(self) -> "BrowserEngine":
        await self.start()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.close()

    @classmethod
    def available(cls) -> bool:
        try:
            import playwright.async_api  # noqa: F401
            return True
        except Exception:
            return False

    async def start(self) -> None:
        """Start Playwright browser/context."""
        self._browser_policy = self._prepare_browser_policy()
        initial = self._browser_policy.prepare_destination(
            self._browser_policy.context.authorized_target,
            action_kind="browser.navigation",
        )
        try:
            from playwright.async_api import async_playwright
        except ImportError as exc:
            raise RuntimeError("Playwright is not installed. Install requirements and run: playwright install chromium") from exc

        self._playwright = await async_playwright().start()
        browser_type = getattr(self._playwright, self.browser_name, self._playwright.chromium)
        launch_args: dict[str, Any] = {"headless": self.headless}
        route = self._browser_policy.context.route
        assert route is not None
        launch_args["proxy"] = {"server": route.proxy_url}
        self._browser = await browser_type.launch(**launch_args)
        ctx_args: dict[str, Any] = {
            "ignore_https_errors": not initial.verify_tls,
            "service_workers": "block",
        }
        if self.storage_state and Path(self.storage_state).exists():
            ctx_args["storage_state"] = self.storage_state
        self._context = await self._browser.new_context(**ctx_args)
        await self._context.route("**/*", self._route_request)
        self._context.set_default_timeout(self.timeout_ms)

    def _prepare_browser_policy(self) -> OutboundPolicy:
        # Playwright cannot consume the per-request resolved-IP permit or apply
        # TLS verification independently per origin.  A generic loopback proxy
        # is therefore not an enforcement boundary.  Keep active browsing
        # visibly unsupported until a versioned permit-aware browser proxy is
        # available and tested end to end.
        raise OutboundDenied(OutboundReason.UNSUPPORTED_ROUTE_TRANSPORT)

    async def _route_request(self, route: Any, request: Any) -> None:
        assert self._browser_policy is not None
        try:
            self._browser_policy.prepare_destination(
                str(request.url),
                action_kind="browser.navigation",
            )
        except OutboundDenied:
            await route.abort("blockedbyclient")
            return
        await route.continue_()

    def authorize_navigation(self, url: str) -> None:
        """Validate a browser destination before a goto/click side effect."""
        policy = self._browser_policy or self._prepare_browser_policy()
        policy.prepare_destination(url, action_kind="browser.navigation")

    async def close(self) -> None:
        if self._context:
            await self._context.close()
        if self._browser:
            await self._browser.close()
        if self._playwright:
            await self._playwright.stop()

    async def render(self, url: str, wait_idle_ms: int = 750) -> BrowserSnapshot:
        """Render a URL and return discovered browser artifacts."""
        if not self._context:
            await self.start()
        page = await self._context.new_page()

        # Inject Worker constructor intercept before any page script runs.
        await page.add_init_script(_WORKER_INTERCEPT_JS)

        ajax: set[str] = set()
        ws_urls: set[str] = set()
        page_reqs: list[dict[str, Any]] = []
        asset_reqs: list[dict[str, Any]] = []
        api_reqs: list[dict[str, Any]] = []
        post_reqs: list[dict[str, Any]] = []
        sse_eps: list[str] = []

        def _track_websocket(ws: Any) -> None:
            try:
                ws_urls.add(ws.url)
            except Exception:
                pass

        page.on("websocket", _track_websocket)

        def _track_response(resp: Any) -> None:
            try:
                req = resp.request
                rtype = req.resource_type
                entry: dict[str, Any] = {
                    "url": resp.url,
                    "status": resp.status,
                    "content_type": resp.headers.get("content-type", ""),
                    "method": req.method,
                }
                if rtype == "document":
                    page_reqs.append(entry)
                elif rtype in {"script", "stylesheet"}:
                    asset_reqs.append(entry)
                elif rtype in {"xhr", "fetch"}:
                    ajax.add(resp.url)
                    api_reqs.append(entry)
                elif rtype == "eventsource":
                    sse_eps.append(resp.url)

                if req.method == "POST":
                    post_reqs.append({
                        "url": resp.url,
                        "status": resp.status,
                        "content_type": entry["content_type"],
                        "resource_type": rtype,
                    })
            except Exception:
                pass

        page.on("response", _track_response)
        snap = BrowserSnapshot(url=url)
        try:
            if self._playwright is not None:
                self.authorize_navigation(url)
            await page.goto(url, wait_until="domcontentloaded")
            try:
                await page.wait_for_load_state("networkidle", timeout=min(self.timeout_ms, 10000))
            except Exception:
                await page.wait_for_timeout(wait_idle_ms)

            snap.final_url = page.url
            snap.title = await page.title()
            snap.html = await page.content()
            snap.framework = await self._detect_framework(page)
            snap.forms = await self._extract_forms(page)
            snap.links = await self._extract_links(page, page.url)
            snap.js_resources = await self._extract_scripts(page, page.url)
            snap.shadow_dom = await self._extract_shadow_dom(page)
            snap.ajax_endpoints = sorted(ajax)
            snap.websocket_endpoints = sorted(ws_urls)

            # ── Acunetix-grade enrichment ──
            snap.page_requests = page_reqs
            snap.asset_requests = asset_reqs
            snap.api_requests = api_reqs
            snap.ws_endpoints = sorted(ws_urls)
            snap.post_requests = post_reqs
            snap.sse_endpoints = list(dict.fromkeys(sse_eps))

            try:
                snap.source_map_paths = await self._extract_source_maps(page)
            except Exception as exc:
                log.debug("Source map extraction failed: %s", exc)

            try:
                snap.asset_manifest_files = await self._detect_asset_manifest(page)
            except Exception as exc:
                log.debug("Asset manifest detection failed: %s", exc)

            try:
                snap.runtime_routes = await self._extract_runtime_routes(page)
            except Exception as exc:
                log.debug("Runtime route extraction failed: %s", exc)

            try:
                workers_raw = await page.evaluate("window.__FORGE_WORKERS__ || []")
                snap.worker_scripts = list(dict.fromkeys(str(w) for w in (workers_raw or [])))
            except Exception as exc:
                log.debug("Worker script extraction failed: %s", exc)

            try:
                snap.dom_fingerprint = await self._compute_dom_fingerprint(page)
            except Exception as exc:
                log.debug("DOM fingerprint computation failed: %s", exc)

            state_path = self.results_dir / "browser_storage_state.json"
            self.results_dir.mkdir(parents=True, exist_ok=True)
            await self._context.storage_state(path=str(state_path))
            snap.storage_state_path = str(state_path)
        except Exception as exc:
            snap.error = str(exc)
            log.debug("Browser render failed for %s: %s", url, exc)
        finally:
            await page.close()
        return snap

    async def login(
        self,
        login_url: str,
        username: str = "",
        password: str = "",
        username_selector: str = "input[type=email], input[name*=user], input[name*=email], input[type=text]",
        password_selector: str = "input[type=password]",
        submit_selector: str = "button[type=submit], input[type=submit], button",
    ) -> BrowserSnapshot:
        """Replay a simple username/password login flow and export storage state."""
        if not self._context:
            await self.start()
        page = await self._context.new_page()
        snap = BrowserSnapshot(url=login_url)
        try:
            if self._playwright is not None:
                self.authorize_navigation(login_url)
            await page.goto(login_url, wait_until="domcontentloaded")
            if username:
                await page.locator(username_selector).first.fill(username)
            if password:
                await page.locator(password_selector).first.fill(password)
            await page.locator(submit_selector).first.click()
            try:
                await page.wait_for_load_state("networkidle", timeout=min(self.timeout_ms, 10000))
            except Exception:
                await page.wait_for_timeout(1000)
            state_path = self.results_dir / "auth_storage_state.json"
            await self._context.storage_state(path=str(state_path))
            snap = await self.render(page.url)
            snap.storage_state_path = str(state_path)
        except Exception as exc:
            snap.error = str(exc)
            log.debug("Browser login failed for %s: %s", login_url, exc)
        finally:
            await page.close()
        return snap

    async def _detect_framework(self, page: Any) -> str:
        return await page.evaluate(
            """() => {
                if (window.__REACT_DEVTOOLS_GLOBAL_HOOK__ || document.querySelector('[data-reactroot], [data-reactid]')) return 'react';
                if (window.angular || document.querySelector('[ng-version], [ng-app]')) return 'angular';
                if (window.__VUE__ || document.querySelector('[data-v-app]')) return 'vue';
                if (document.querySelector('#__next, [data-nextjs-scroll-focus-boundary]')) return 'nextjs';
                if (document.querySelector('#__nuxt')) return 'nuxt';
                if (window.__svelte || document.querySelector('[data-svelte-h]')) return 'svelte';
                if (window.Alpine || document.querySelector('[x-data]')) return 'alpine';
                if (document.querySelector('[hx-get], [hx-post], [hx-put], [hx-delete], [data-hx-get]')) return 'htmx';
                if (window.Ember || document.querySelector('div[id^="ember"]')) return 'ember';
                return '';
            }"""
        )

    async def _extract_forms(self, page: Any) -> list[dict[str, Any]]:
        return await page.evaluate(
            """() => Array.from(document.forms).map(form => ({
                action: form.action || location.href,
                method: (form.method || 'GET').toUpperCase(),
                inputs: Array.from(form.querySelectorAll('input, textarea, select')).map(el => el.name || el.id).filter(Boolean)
            }))"""
        )

    async def _extract_links(self, page: Any, base_url: str) -> list[str]:
        links = await page.evaluate("""() => {
            const urls = new Set();
            for (const a of document.links) { if (a.href) urls.add(a.href); }
            for (const el of document.querySelectorAll('[data-href],[data-url],[data-route],[data-path],[data-link]')) {
                const url = el.getAttribute('data-href') || el.getAttribute('data-url') ||
                            el.getAttribute('data-route') || el.getAttribute('data-path') ||
                            el.getAttribute('data-link');
                if (url) urls.add(url);
            }
            for (const el of document.querySelectorAll('[to]')) {
                const to = el.getAttribute('to');
                if (to && (to.startsWith('/') || to.startsWith('http'))) urls.add(to);
            }
            return [...urls].filter(Boolean);
        }""")
        return sorted({urljoin(base_url, link) for link in links if _same_origin(base_url, link)})

    async def _extract_scripts(self, page: Any, base_url: str) -> list[str]:
        scripts = await page.evaluate("() => Array.from(document.scripts).map(s => s.src).filter(Boolean)")
        return sorted({urljoin(base_url, src) for src in scripts if _same_origin(base_url, src)})

    async def _extract_shadow_dom(self, page: Any) -> list[dict[str, Any]]:
        """Return basic metadata for open Shadow DOM roots on the rendered page."""
        return await page.evaluate(
            """() => Array.from(document.querySelectorAll('*'))
                .filter(el => el.shadowRoot)
                .slice(0, 200)
                .map(el => ({
                    host: el.tagName.toLowerCase() + (el.id ? '#' + el.id : ''),
                    mode: el.shadowRoot.mode || 'open',
                    text: (el.shadowRoot.textContent || '').trim().slice(0, 500),
                    forms: Array.from(el.shadowRoot.querySelectorAll('form')).length,
                    links: Array.from(el.shadowRoot.querySelectorAll('a[href]')).map(a => a.href).slice(0, 20),
                    inputs: Array.from(el.shadowRoot.querySelectorAll('input, textarea, select'))
                        .map(input => input.name || input.id || input.type || '')
                        .filter(Boolean)
                        .slice(0, 50)
                }))"""
        )

    async def _extract_source_maps(self, page: Any) -> list[str]:
        """Fetch JS source maps and return the original source file paths they expose.

        Source map `sources` arrays reveal internal file structure — component names,
        route files, API service modules — that wouldn't be visible from the bundle.
        """
        script_urls: list[str] = await page.evaluate(
            "() => Array.from(document.scripts).map(s => s.src).filter(Boolean)"
        )

        discovered: list[str] = []
        cap = 10
        size_limit = 2 * 1024 * 1024  # 2 MB

        for script_url in script_urls[:cap]:
            if not _same_origin(page.url, script_url):
                continue
            try:
                abs_script = urljoin(page.url, script_url)
                # Fetch only the tail of the JS file — sourceMappingURL is always last.
                js_tail = await page.evaluate(
                    """async (u) => {
                        try {
                            const r = await fetch(u, {credentials: 'include'});
                            if (!r.ok) return null;
                            const text = await r.text();
                            return text.slice(-512);
                        } catch(e) { return null; }
                    }""",
                    abs_script,
                )
                if not js_tail:
                    continue
                map_url: str | None = None
                for line in reversed(js_tail.splitlines()):
                    line = line.strip()
                    if line.startswith("//# sourceMappingURL="):
                        raw = line[len("//# sourceMappingURL="):].strip()
                        if raw.startswith("data:"):
                            break
                        map_url = urljoin(abs_script, raw)
                        break
                if not map_url:
                    continue

                map_data = await page.evaluate(
                    """async (u, limit) => {
                        try {
                            const r = await fetch(u, {credentials: 'include'});
                            if (!r.ok) return null;
                            const buf = await r.arrayBuffer();
                            if (buf.byteLength > limit) return null;
                            return new TextDecoder().decode(buf);
                        } catch(e) { return null; }
                    }""",
                    map_url,
                    size_limit,
                )
                if not map_data:
                    continue
                parsed = json.loads(map_data)
                sources: list[str] = parsed.get("sources", [])
                discovered.extend(str(s) for s in sources if s)
            except Exception as exc:
                log.debug("Source map fetch failed for %s: %s", script_url, exc)

        return list(dict.fromkeys(discovered))

    async def _detect_asset_manifest(self, page: Any) -> list[str]:
        """Probe well-known bundler manifest paths and return all discovered file entries.

        Manifests from webpack, Vite, Next.js and CRA expose route structure and chunk
        names that reveal the application's internal architecture without any JS execution.
        """
        parsed_origin = urlparse(page.url)
        origin = f"{parsed_origin.scheme}://{parsed_origin.netloc}"

        probe_paths = [
            "/asset-manifest.json",
            "/static/js/manifest.json",
            "/build/asset-manifest.json",
            "/_next/static/chunks/pages-manifest.json",
            "/_next/static/development/_buildManifest.js",
            "/vite-manifest.json",
            "/.vite/manifest.json",
            "/manifest.json",
        ]

        found: list[str] = []
        for path in probe_paths:
            probe_url = origin + path
            try:
                result = await page.evaluate(
                    """async (u) => {
                        try {
                            const r = await fetch(u, {credentials: 'include'});
                            if (!r.ok) return null;
                            const ct = r.headers.get('content-type') || '';
                            if (!ct.includes('json') && !ct.includes('javascript')) return null;
                            return await r.text();
                        } catch(e) { return null; }
                    }""",
                    probe_url,
                )
                if not result:
                    continue
                try:
                    data = json.loads(result)
                except json.JSONDecodeError:
                    # _buildManifest.js wraps a JSON literal in a JS assignment; extract path strings.
                    for token in result.split('"'):
                        if token.startswith(("/_next/", "/static/", "/build/")):
                            found.append(token)
                    continue

                def _collect_strings(obj: Any) -> None:
                    if isinstance(obj, str) and (obj.startswith("/") or obj.endswith(".js") or obj.endswith(".css")):
                        found.append(obj)
                    elif isinstance(obj, dict):
                        for v in obj.values():
                            _collect_strings(v)
                    elif isinstance(obj, list):
                        for item in obj:
                            _collect_strings(item)

                _collect_strings(data)
            except Exception as exc:
                log.debug("Asset manifest probe failed for %s: %s", probe_url, exc)

        return list(dict.fromkeys(found))

    async def _extract_runtime_routes(self, page: Any) -> list[str]:
        """Extract client-side route paths from React Router, Next.js, Vue Router, and Angular.

        These are routes the application declares in JS — not necessarily linked from HTML —
        making them invisible to traditional crawlers but fully accessible to an authenticated
        attacker navigating the SPA directly.
        """
        routes: list[str] = await page.evaluate(
            """() => {
                const paths = new Set();

                // React Router v5/v6
                try {
                    if (window.__REACT_ROUTER_STATE__) {
                        const rs = window.__REACT_ROUTER_STATE__;
                        const routes = rs.routes || (rs.router && rs.router.routes) || [];
                        (function walk(r) {
                            if (!r) return;
                            if (Array.isArray(r)) { r.forEach(walk); return; }
                            if (r.path) paths.add(r.path);
                            if (r.children) walk(r.children);
                        })(routes);
                    }
                } catch(e) {}

                // Next.js
                try {
                    const nd = window.__NEXT_DATA__;
                    if (nd) {
                        if (nd.page) paths.add(nd.page);
                        if (nd.router && nd.router.pathname) paths.add(nd.router.pathname);
                        const pages = nd.buildManifest && nd.buildManifest.pages;
                        if (pages) Object.keys(pages).forEach(function(p) { paths.add(p); });
                    }
                } catch(e) {}

                // Vue Router
                try {
                    const vr = window.__vue_router__;
                    if (vr && typeof vr.getRoutes === 'function') {
                        vr.getRoutes().forEach(function(r) { if (r.path) paths.add(r.path); });
                    }
                } catch(e) {}
                try {
                    const va = window.__vue_app__;
                    if (va) {
                        const gp = va._context && va._context.config && va._context.config.globalProperties;
                        const router = gp ? gp.$router : null;
                        if (router && typeof router.getRoutes === 'function') {
                            router.getRoutes().forEach(function(r) { if (r.path) paths.add(r.path); });
                        }
                    }
                } catch(e) {}

                // Angular
                try {
                    const ngEl = document.querySelector('[ng-version]') || document.body;
                    if (window.ng && typeof window.ng.getComponent === 'function') {
                        const ctx = window.ng.getContext && window.ng.getContext(ngEl);
                        if (ctx && ctx.injector) {
                            const router = ctx.injector.get && ctx.injector.get('Router');
                            if (router && router.config) {
                                (function walkAng(cfg) {
                                    if (!cfg) return;
                                    cfg.forEach(function(r) {
                                        if (r.path !== undefined) paths.add('/' + r.path);
                                        if (r.children) walkAng(r.children);
                                    });
                                })(router.config);
                            }
                        }
                    }
                } catch(e) {}

                // Generic — scan well-known window route properties
                try {
                    var KEYS = ['routes', 'router', '$router', '__router__', '_router'];
                    for (var i = 0; i < KEYS.length; i++) {
                        var obj = window[KEYS[i]];
                        if (!obj) continue;
                        if (Array.isArray(obj)) {
                            obj.forEach(function(r) { if (r && typeof r.path === 'string') paths.add(r.path); });
                        } else if (obj && Array.isArray(obj.routes)) {
                            obj.routes.forEach(function(r) { if (r && typeof r.path === 'string') paths.add(r.path); });
                        } else if (obj && typeof obj.getRoutes === 'function') {
                            obj.getRoutes().forEach(function(r) { if (r && typeof r.path === 'string') paths.add(r.path); });
                        }
                    }
                } catch(e) {}

                return Array.from(paths).filter(function(p) { return typeof p === 'string' && p.length > 0; });
            }"""
        )
        return list(dict.fromkeys(routes))

    async def _compute_dom_fingerprint(self, page: Any) -> str:
        """Compute a structural SHA-256 fingerprint of the DOM for deduplication.

        Uses tag names and id/class structure without text content so that pages
        with the same layout but different data (e.g. paginated item lists) hash
        identically and get deduplicated by the crawl orchestrator.
        """
        structural_string: str = await page.evaluate(
            """() => {
                function walk(node, depth) {
                    if (!node || depth > 8) return '';
                    var tag = node.tagName ? node.tagName.toLowerCase() : '';
                    if (!tag) return '';
                    var id = node.id ? '#' + node.id : '';
                    var cls = node.classList && node.classList.length
                        ? '.' + Array.from(node.classList).slice(0, 3).join('.')
                        : '';
                    var children = Array.from(node.children || []);
                    if (children.length === 0) return tag + id + cls;
                    var parts = [];
                    var i = 0;
                    while (i < children.length) {
                        var cur = children[i].tagName;
                        var count = 1;
                        while (i + count < children.length && children[i + count].tagName === cur) count++;
                        var childStr = count > 1
                            ? (cur.toLowerCase() + '*' + count)
                            : walk(children[i], depth + 1);
                        parts.push(childStr);
                        i += count;
                    }
                    return tag + id + cls + '{' + parts.join(',') + '}';
                }
                try {
                    return walk(document.body, 0).slice(0, 8192);
                } catch(e) { return ''; }
            }"""
        )
        if not structural_string:
            return ""
        return hashlib.sha256(structural_string.encode("utf-8", "ignore")).hexdigest()


def _same_origin(base_url: str, candidate: str) -> bool:
    try:
        base = urlparse(base_url)
        cand = urlparse(urljoin(base_url, candidate))
        return base.netloc == cand.netloc
    except Exception:
        return False


class TestBrowserEngine:
    def test_availability_probe_returns_bool(self) -> None:
        assert isinstance(BrowserEngine.available(), bool)

    def test_snapshot_serializes(self) -> None:
        snap = BrowserSnapshot(url="https://example.com", framework="react")
        data = snap.to_dict()
        assert data["url"] == "https://example.com"
        assert data["framework"] == "react"

    def test_taint_result_serializes(self) -> None:
        r = DOMTaintResult(url="https://example.com", flows=[
            {"source": "location.hash", "sink": "innerHTML", "payload": "#<img src=x>"}
        ])
        d = r.to_dict()
        assert d["total_flows"] == 1
        assert d["flows"][0]["source"] == "location.hash"

    def test_snapshot_new_fields_default(self) -> None:
        snap = BrowserSnapshot(url="https://example.com")
        assert snap.source_map_paths == []
        assert snap.asset_manifest_files == []
        assert snap.runtime_routes == []
        assert snap.worker_scripts == []
        assert snap.sse_endpoints == []
        assert snap.post_requests == []
        assert snap.dom_fingerprint == ""
        assert snap.page_requests == []
        assert snap.asset_requests == []
        assert snap.api_requests == []
        assert snap.ws_endpoints == []

    def test_snapshot_to_dict_includes_new_fields(self) -> None:
        snap = BrowserSnapshot(
            url="https://example.com",
            source_map_paths=["src/App.tsx"],
            asset_manifest_files=["/static/js/main.abc123.js"],
            runtime_routes=["/dashboard", "/users/:id"],
            worker_scripts=["https://example.com/sw.js"],
            sse_endpoints=["https://example.com/events"],
            post_requests=[{"url": "https://example.com/api/login", "status": 200, "content_type": "application/json", "resource_type": "fetch"}],
            dom_fingerprint="abcdef1234567890",
            page_requests=[{"url": "https://example.com/", "status": 200, "content_type": "text/html", "method": "GET"}],
            api_requests=[{"url": "https://example.com/api/v1/users", "status": 200, "content_type": "application/json", "method": "GET"}],
        )
        d = snap.to_dict()
        assert d["source_map_paths"] == ["src/App.tsx"]
        assert d["asset_manifest_files"] == ["/static/js/main.abc123.js"]
        assert d["runtime_routes"] == ["/dashboard", "/users/:id"]
        assert d["worker_scripts"] == ["https://example.com/sw.js"]
        assert d["sse_endpoints"] == ["https://example.com/events"]
        assert len(d["post_requests"]) == 1
        assert d["dom_fingerprint"] == "abcdef1234567890"
        assert len(d["page_requests"]) == 1
        assert len(d["api_requests"]) == 1

    def test_dom_fingerprint_is_sha256_hex(self) -> None:
        sample = "body{div.container{ul{li*5}}}"
        digest = hashlib.sha256(sample.encode()).hexdigest()
        assert len(digest) == 64
        assert all(c in "0123456789abcdef" for c in digest)

    def test_same_origin_helper(self) -> None:
        assert _same_origin("https://example.com/app", "https://example.com/api/v1") is True
        assert _same_origin("https://example.com/app", "https://evil.com/steal") is False
        assert _same_origin("https://example.com/app", "/relative/path") is True
        assert _same_origin("https://example.com", "https://sub.example.com/x") is False


# ══════════════════════════════════════════════════════════════════════
# DOM XSS TAINT TRACKING — Playwright Instrumentation
# ══════════════════════════════════════════════════════════════════════

@dataclass
class DOMTaintResult:
    """Result of DOM XSS taint tracking analysis."""
    url: str
    canary: str = ""
    flows: list[dict[str, Any]] = field(default_factory=list)
    mutations: list[dict[str, Any]] = field(default_factory=list)
    canary_executions: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "canary": self.canary,
            "total_flows": len(self.flows),
            "total_mutations": len(self.mutations),
            "total_canary_executions": len(self.canary_executions),
            "flows": self.flows,
            "mutations": self.mutations,
            "canary_executions": self.canary_executions,
            "errors": self.errors,
        }


# JavaScript taint tracking instrumentation — injected into page before navigation.
# Intercepts dangerous sinks and records when attacker-controllable source data
# reaches them. This catches DOM XSS that static analysis misses (runtime data flows).
_TAINT_TRACKING_JS_TEMPLATE = r"""
(function() {
    'use strict';
    if (window.__FORGE_TAINT_TRACKER__) return;
    window.__FORGE_TAINT_TRACKER__ = true;

    const TAINT_LOG = [];
    const CANARY_LOG = [];
    const MUTATION_LOG = [];

    // Canary tokens are deterministic per scan and passive: no callback or alert is generated.
    const CANARY = __FORGE_CANARY_PLACEHOLDER__;
    window.__FORGE_CANARY__ = CANARY;

    // Sources to monitor — attacker-controllable inputs
    function decodeMaybe(value) {
        try { return decodeURIComponent(value || ''); } catch(e) { return value || ''; }
    }

    function getSourceCandidates() {
        const candidates = [];
        function add(source, value) {
            if (value && String(value).length > 1) {
                candidates.push({source: source, value: String(value)});
            }
        }
        try {
            const rawHash = location.hash.slice(1) || '';
            add('location.hash', rawHash);
            add('location.hash', decodeMaybe(rawHash));
        } catch(e) {}
        try {
            const rawSearch = location.search.slice(1) || '';
            add('location.search', rawSearch);
            add('location.search', decodeMaybe(rawSearch));
            const params = new URLSearchParams(location.search);
            for (const val of params.values()) add('location.search', val);
        } catch(e) {}
        try { add('location.href', location.href); } catch(e) {}
        try { add('document.referrer', document.referrer); } catch(e) {}
        try { add('document.URL', document.URL); } catch(e) {}
        try { add('document.cookie', document.cookie); } catch(e) {}
        try { add('window.name', window.name); } catch(e) {}
        return candidates;
    }

    function findSource(data) {
        if (data === null || data === undefined) return null;
        const text = String(data);
        if (text.length < 2) return null;
        for (const candidate of getSourceCandidates()) {
            if (candidate.value && candidate.value.length > 1 && text.includes(candidate.value)) {
                return candidate;
            }
        }
        return null;
    }

    function recordFlow(sinkName, data, element) {
        const matchedSource = findSource(data);
        const text = String(data);
        if (matchedSource) {
            const flow = {
                source: matchedSource.source,
                source_value: matchedSource.value.slice(0, 200),
                sink: sinkName,
                sink_data: text.slice(0, 500),
                element: element ? (element.tagName || '') + (element.id ? '#'+element.id : '') : '',
                canary_present: text.includes(CANARY),
                timestamp: Date.now(),
            };
            TAINT_LOG.push(flow);
        }
        if (text.includes(CANARY)) {
            CANARY_LOG.push({
                sink: sinkName,
                kind: 'sink_observed',
                executed: false,
                data: text.slice(0, 500),
                timestamp: Date.now(),
            });
        }
    }

    // ── Sink Hooks ──

    // innerHTML / outerHTML
    const origInnerHTMLDesc = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
    if (origInnerHTMLDesc && origInnerHTMLDesc.set) {
        Object.defineProperty(Element.prototype, 'innerHTML', {
            set: function(val) {
                recordFlow('innerHTML', val, this);
                return origInnerHTMLDesc.set.call(this, val);
            },
            get: origInnerHTMLDesc.get,
            configurable: true,
        });
    }

    const origOuterHTMLDesc = Object.getOwnPropertyDescriptor(Element.prototype, 'outerHTML');
    if (origOuterHTMLDesc && origOuterHTMLDesc.set) {
        Object.defineProperty(Element.prototype, 'outerHTML', {
            set: function(val) {
                recordFlow('outerHTML', val, this);
                return origOuterHTMLDesc.set.call(this, val);
            },
            get: origOuterHTMLDesc.get,
            configurable: true,
        });
    }

    // document.write / writeln
    const origWrite = document.write.bind(document);
    const origWriteln = document.writeln.bind(document);
    document.write = function(...args) {
        args.forEach(a => recordFlow('document.write', a, null));
        return origWrite(...args);
    };
    document.writeln = function(...args) {
        args.forEach(a => recordFlow('document.writeln', a, null));
        return origWriteln(...args);
    };

    // eval
    const origEval = window.eval;
    window.eval = function(code) {
        recordFlow('eval', code, null);
        return origEval.call(window, code);
    };

    // setTimeout / setInterval with string arg
    const origSetTimeout = window.setTimeout;
    const origSetInterval = window.setInterval;
    window.setTimeout = function(fn, delay, ...args) {
        if (typeof fn === 'string') recordFlow('setTimeout(string)', fn, null);
        return origSetTimeout.call(window, fn, delay, ...args);
    };
    window.setInterval = function(fn, delay, ...args) {
        if (typeof fn === 'string') recordFlow('setInterval(string)', fn, null);
        return origSetInterval.call(window, fn, delay, ...args);
    };

    // insertAdjacentHTML
    const origInsertAdj = Element.prototype.insertAdjacentHTML;
    Element.prototype.insertAdjacentHTML = function(position, text) {
        recordFlow('insertAdjacentHTML', text, this);
        return origInsertAdj.call(this, position, text);
    };

    function summarizeNode(node) {
        if (!node) return '';
        if (node.nodeType === 3) return node.textContent || '';
        if (node.outerHTML) return node.outerHTML;
        if (node.textContent) return node.textContent;
        return '';
    }

    function recordMutation(node, mutationType, attributeName) {
        const text = summarizeNode(node);
        if (!text) return;
        const matchedSource = findSource(text);
        const hasCanary = text.includes(CANARY);
        if (!matchedSource && !hasCanary) return;
        MUTATION_LOG.push({
            source: matchedSource ? matchedSource.source : '',
            source_value: matchedSource ? matchedSource.value.slice(0, 200) : '',
            mutation_type: mutationType,
            attribute: attributeName || '',
            element: node && node.tagName ? node.tagName.toLowerCase() : '',
            html: text.slice(0, 500),
            canary_present: hasCanary,
            timestamp: Date.now(),
        });
        if (hasCanary) {
            CANARY_LOG.push({
                sink: 'DOMMutation',
                kind: 'mutation_observed',
                executed: false,
                data: text.slice(0, 500),
                timestamp: Date.now(),
            });
        }
    }

    // DOM Mutation Observer — catch dynamic XSS
    const observer = new MutationObserver(mutations => {
        for (const m of mutations) {
            if (m.type === 'childList') {
                for (const node of m.addedNodes) {
                    recordMutation(node, 'childList', '');
                }
            } else if (m.type === 'attributes') {
                recordMutation(m.target, 'attributes', m.attributeName || '');
            } else if (m.type === 'characterData') {
                recordMutation(m.target, 'characterData', '');
            }
        }
    });
    observer.observe(document.documentElement || document.body || document, {
        attributes: true, childList: true, characterData: true, subtree: true,
    });

    // Expose results for Playwright to read
    window.__FORGE_TAINT_RESULTS__ = function() {
        return {
            flows: TAINT_LOG,
            mutations: MUTATION_LOG,
            canary_executions: CANARY_LOG,
            canary: CANARY,
        };
    };
})();
"""


def _build_taint_tracking_script(canary: str) -> str:
    """Return browser-side instrumentation with a deterministic passive canary."""
    return _TAINT_TRACKING_JS_TEMPLATE.replace("__FORGE_CANARY_PLACEHOLDER__", json.dumps(canary))


def _dom_taint_canary(url: str) -> str:
    digest = hashlib.sha256(url.encode("utf-8", "ignore")).hexdigest()[:12].upper()
    return f"FORGETAINT_{digest}"


# DOM XSS test payloads — injected via URL sources as passive canary markers.
_DOM_XSS_SOURCE_PAYLOADS = [
    ("#forge-dom-canary-{canary}", "location.hash marker"),
    ("#<forge-canary data-token=\"{canary}\"></forge-canary>", "location.hash HTML marker"),
    ("#\" data-forge-canary=\"{canary}", "location.hash attribute marker"),
    ("?q=forge-dom-canary-{canary}", "location.search marker"),
    ("?q=<forge-canary data-token=\"{canary}\"></forge-canary>", "location.search HTML marker"),
    ("?html=%3Cforge-canary%20data-token%3D%22{canary}%22%3E%3C%2Fforge-canary%3E", "location.search encoded HTML marker"),
    ("?callback=forgeDomCanary_{canary}", "location.search script marker"),
    ("?msg=forge-dom-canary-{canary}", "location.search message marker"),
]


async def dom_xss_taint_scan(
    engine: BrowserEngine,
    url: str,
    extra_payloads: list[tuple[str, str]] | None = None,
    wait_ms: int = 2000,
    max_payloads: int = 10,
) -> DOMTaintResult:
    """Run DOM XSS taint tracking scan via Playwright.

    Injects source-sink instrumentation, then navigates with various
    attacker-controlled payloads in URL hash/query. Detects:
    1. Source-to-sink data flows (taint tracking)
    2. DOM mutations with attacker-controlled content
    3. Canary execution (confirmed XSS)

    Args:
        engine:         Initialized BrowserEngine.
        url:            Target URL to scan.
        extra_payloads: Additional (suffix, description) pairs to test.
        wait_ms:        Milliseconds to wait after navigation for JS execution.
        max_payloads:   Maximum payloads to test (performance cap).

    Returns:
        DOMTaintResult with discovered flows, mutations, and canary hits.
    """
    if not engine._context:
        await engine.start()

    canary = _dom_taint_canary(url)
    result = DOMTaintResult(url=url, canary=canary)
    payloads = list(_DOM_XSS_SOURCE_PAYLOADS[:max_payloads])
    if extra_payloads:
        payloads.extend(extra_payloads[:5])

    for suffix, desc in payloads:
        page = await engine._context.new_page()
        try:
            # Inject taint tracking BEFORE page loads via addInitScript
            await page.add_init_script(_build_taint_tracking_script(canary))

            # Navigate with payload injected into URL
            test_url = url.rstrip("/") + suffix.format(canary=canary)
            try:
                if engine._playwright is not None:
                    engine.authorize_navigation(test_url)
                await page.goto(test_url, wait_until="domcontentloaded", timeout=15000)
            except Exception as exc:
                result.errors.append(f"Navigation failed for {desc}: {exc}")
                continue

            # Wait for JS execution and DOM mutations
            await page.wait_for_timeout(wait_ms)

            # Also trigger hash change events for SPA routers
            try:
                await page.evaluate("window.dispatchEvent(new HashChangeEvent('hashchange'))")
                await page.wait_for_timeout(500)
            except Exception:
                pass

            # Collect taint results
            try:
                taint_data = await page.evaluate("window.__FORGE_TAINT_RESULTS__ ? window.__FORGE_TAINT_RESULTS__() : null")
            except Exception:
                taint_data = None

            if taint_data:
                for flow in taint_data.get("flows", []):
                    item = dict(flow)
                    item["payload_desc"] = desc
                    item["test_url"] = test_url[:300]
                    result.flows.append(item)
                for mut in taint_data.get("mutations", []):
                    item = dict(mut)
                    item["payload_desc"] = desc
                    item["test_url"] = test_url[:300]
                    result.mutations.append(item)
                for cex in taint_data.get("canary_executions", []):
                    item = dict(cex)
                    item["payload_desc"] = desc
                    item["canary"] = taint_data.get("canary", canary)
                    item["test_url"] = test_url[:300]
                    result.canary_executions.append(item)

        except Exception as exc:
            result.errors.append(f"Taint scan error for {desc}: {exc}")
        finally:
            try:
                await page.close()
            except Exception:
                pass

    return result
