"""WebForge HTTP session manager — aiohttp with retry, proxy, rate limiting."""
from __future__ import annotations

import asyncio
import logging
import re
import ssl
import time
from typing import Any

import aiohttp
from aiohttp import ClientSession, ClientTimeout, TCPConnector

from common.config import BaseForgeConfig

log = logging.getLogger(__name__)


class ForgeSession:
    """Managed aiohttp session with retry, proxy support, and rate limiting."""

    def __init__(
        self,
        rate: float = 10.0,
        proxy: str | None = None,
        timeout: int = 30,
        verify_ssl: bool = False,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
    ) -> None:
        self.rate = rate
        self.proxy = proxy
        self.timeout = ClientTimeout(total=timeout)
        self.verify_ssl = verify_ssl
        self.base_headers: dict[str, str] = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
            "Accept-Encoding": "gzip, deflate",  # avoid brotli — not natively decoded by aiohttp
            **(headers or {}),
        }
        self.base_cookies = cookies or {}
        self._session: ClientSession | None = None
        self._last_request: float = 0.0
        self.request_count: int = 0

    async def __aenter__(self) -> "ForgeSession":
        await self.start()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.close()

    async def start(self) -> None:
        """Create the underlying aiohttp session."""
        ssl_ctx = ssl.create_default_context()
        if not self.verify_ssl:
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
        connector = TCPConnector(ssl=ssl_ctx, limit=50, limit_per_host=10)
        self._session = ClientSession(
            connector=connector,
            timeout=self.timeout,
            headers=self.base_headers,
            cookies=self.base_cookies,
        )

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()

    async def _rate_limit(self) -> None:
        if self.rate <= 0:
            return
        min_interval = 1.0 / self.rate
        elapsed = time.monotonic() - self._last_request
        if elapsed < min_interval:
            await asyncio.sleep(min_interval - elapsed)
        self._last_request = time.monotonic()

    async def get(self, url: str, **kwargs: Any) -> aiohttp.ClientResponse:
        """Rate-limited GET request."""
        return await self._request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> aiohttp.ClientResponse:
        """Rate-limited POST request."""
        return await self._request("POST", url, **kwargs)

    async def _request(
        self, method: str, url: str, retries: int = 3, **kwargs: Any
    ) -> aiohttp.ClientResponse:
        """Execute a rate-limited HTTP request with exponential backoff retry."""
        assert self._session, "Session not started — use async with ForgeSession()"
        await self._rate_limit()
        kwargs.setdefault("proxy", self.proxy)
        kwargs.setdefault("allow_redirects", True)
        last_exc: Exception | None = None
        for attempt in range(retries):
            try:
                resp = await self._session.request(method, url, **kwargs)
                self.request_count += 1
                if resp.status == 429:
                    wait = min(2 ** attempt * 2, 30)
                    log.debug("Rate limited by server — waiting %ds", wait)
                    await asyncio.sleep(wait)
                    continue
                return resp
            except asyncio.TimeoutError as exc:
                last_exc = exc
                await asyncio.sleep(2 ** attempt)
            except aiohttp.ClientError as exc:
                last_exc = exc
                await asyncio.sleep(1)
        raise last_exc or RuntimeError(f"Request failed after {retries} retries: {url}")

    def update_headers(self, headers: dict[str, str]) -> None:
        """Update session headers (e.g., after login)."""
        self.base_headers.update(headers)
        if self._session:
            self._session.headers.update(headers)

    def update_cookies(self, cookies: dict[str, str]) -> None:
        """Update session cookies."""
        self.base_cookies.update(cookies)
        if self._session:
            self._session.cookie_jar.update_cookies(cookies)

    @classmethod
    def from_config(
        cls,
        config: BaseForgeConfig,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        include_auth: bool = True,
        timeout: int = 30,
    ) -> "ForgeSession":
        """Create a ForgeSession with proxy, rate, auth headers, and cookies."""
        merged_headers: dict[str, str] = {}
        merged_cookies: dict[str, str] = {}
        if include_auth:
            merged_headers.update(config.extra.get("session_headers", {}) or {})
            token = config.extra.get("token") or config.extra.get("jwt_token")
            if token and "Authorization" not in merged_headers:
                merged_headers["Authorization"] = f"Bearer {token}"

            cookie_header = (
                config.extra.get("cookie")
                or (config.extra.get("session_headers", {}) or {}).get("Cookie")
            )
            if cookie_header and "Cookie" not in merged_headers:
                merged_headers["Cookie"] = _clean_cookie_header(str(cookie_header))
            merged_cookies.update(config.extra.get("session_cookies", {}) or {})
            if cookie_header:
                merged_cookies.update(_parse_cookie_header(str(cookie_header)))

        merged_headers.update(headers or {})
        merged_cookies.update(cookies or {})
        return cls(
            rate=config.rate.requests_per_second,
            proxy=config.extra.get("proxy") or config.proxy,
            timeout=timeout,
            headers=merged_headers,
            cookies=merged_cookies,
        )


def _parse_cookie_header(value: str) -> dict[str, str]:
    cleaned = _clean_cookie_header(value)
    parsed: dict[str, str] = {}
    for part in cleaned.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        name, cookie_value = part.split("=", 1)
        name = name.strip()
        if name.lower() in {"path", "domain", "expires", "max-age", "secure", "httponly", "samesite"}:
            continue
        parsed[name] = cookie_value.strip()
    return parsed


def _clean_cookie_header(value: str) -> str:
    return re.sub(r"^cookie:\s*", "", value.strip(), flags=re.IGNORECASE)


class TestForgeSession:
    def test_init(self) -> None:
        s = ForgeSession(rate=5.0)
        assert s.rate == 5.0
        assert s._session is None

    def test_headers_contain_ua(self) -> None:
        s = ForgeSession()
        assert "User-Agent" in s.base_headers
