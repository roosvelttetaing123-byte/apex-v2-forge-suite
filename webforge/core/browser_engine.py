"""Playwright browser engine for authenticated and JavaScript-heavy web scans."""
from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

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
    storage_state_path: str = ""
    error: str = ""

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
            "storage_state_path": self.storage_state_path,
            "error": self.error,
        }


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
    ) -> None:
        self.results_dir = results_dir
        self.browser_name = browser
        self.headless = headless
        self.timeout_ms = timeout_ms
        self.proxy = proxy
        self.storage_state = storage_state
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
        try:
            from playwright.async_api import async_playwright
        except ImportError as exc:
            raise RuntimeError("Playwright is not installed. Install requirements and run: playwright install chromium") from exc

        self._playwright = await async_playwright().start()
        browser_type = getattr(self._playwright, self.browser_name, self._playwright.chromium)
        launch_args: dict[str, Any] = {"headless": self.headless}
        if self.proxy:
            launch_args["proxy"] = {"server": self.proxy}
        self._browser = await browser_type.launch(**launch_args)
        ctx_args: dict[str, Any] = {"ignore_https_errors": True}
        if self.storage_state and Path(self.storage_state).exists():
            ctx_args["storage_state"] = self.storage_state
        self._context = await self._browser.new_context(**ctx_args)
        self._context.set_default_timeout(self.timeout_ms)

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
        ajax: set[str] = set()

        def _track_response(resp: Any) -> None:
            try:
                req = resp.request
                if req.resource_type in {"xhr", "fetch"}:
                    ajax.add(resp.url)
            except Exception:
                pass

        page.on("response", _track_response)
        snap = BrowserSnapshot(url=url)
        try:
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
            snap.ajax_endpoints = sorted(ajax)
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
                if (document.querySelector('#__next')) return 'nextjs';
                if (document.querySelector('#__nuxt')) return 'nuxt';
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
        links = await page.evaluate("() => Array.from(document.links).map(a => a.href).filter(Boolean)")
        return sorted({urljoin(base_url, link) for link in links if _same_origin(base_url, link)})

    async def _extract_scripts(self, page: Any, base_url: str) -> list[str]:
        scripts = await page.evaluate("() => Array.from(document.scripts).map(s => s.src).filter(Boolean)")
        return sorted({urljoin(base_url, src) for src in scripts if _same_origin(base_url, src)})


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

