"""WebForge HTTP session manager — aiohttp with retry, proxy, rate limiting."""
from __future__ import annotations

import asyncio
import logging
import re
import time
from typing import Any

import aiohttp

from common.config import BaseForgeConfig
from common.outbound_policy import (
    OutboundDenied,
    OutboundPolicy,
    OutboundReason,
    PolicyHttpClient,
    PolicyResponse,
    _normalized_proxy_origin,
)

log = logging.getLogger(__name__)


class ForgeSession:
    """Managed aiohttp session with retry, proxy support, and rate limiting."""

    def __init__(
        self,
        rate: float = 10.0,
        proxy: str | None = None,
        timeout: int = 30,
        verify_ssl: bool = True,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        cookie_provenance: dict[str, dict[str, Any]] | None = None,
        outbound_policy: OutboundPolicy | None = None,
    ) -> None:
        self.rate = rate
        self.proxy = proxy
        self.timeout = float(timeout)
        self.verify_ssl = verify_ssl
        self.outbound_policy = outbound_policy
        self.base_headers: dict[str, str] = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
            "Accept-Encoding": "gzip, deflate",  # avoid brotli — not natively decoded by aiohttp
            **(headers or {}),
        }
        self.base_cookies = cookies or {}
        self.cookie_provenance = cookie_provenance or {}
        self._session: PolicyHttpClient | None = None
        self._last_request: float = 0.0
        self.request_count: int = 0

    async def __aenter__(self) -> "ForgeSession":
        await self.start()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.close()

    async def start(self) -> None:
        """Create the policy client without session-wide credential defaults."""
        if self.outbound_policy is None:
            raise OutboundDenied(OutboundReason.AUTHORIZATION_INVALID)
        if not self.verify_ssl and not self.outbound_policy.context.lab_only_insecure_tls:
            raise OutboundDenied(OutboundReason.INSECURE_TLS_NOT_AUTHORIZED)
        if self.proxy:
            route = self.outbound_policy.context.route
            if route is None:
                raise OutboundDenied(OutboundReason.ROUTE_REQUIRED)
            if _normalized_proxy_origin(self.proxy) != route.proxy_url:
                raise OutboundDenied(OutboundReason.ROUTE_BINDING_MISMATCH)
        self._session = PolicyHttpClient(
            self.outbound_policy,
            headers=self.base_headers,
            cookies=self.base_cookies,
            cookie_provenance=self.cookie_provenance,
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

    async def get(self, url: str, **kwargs: Any) -> PolicyResponse:
        """Rate-limited GET request."""
        return await self._request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> PolicyResponse:
        """Rate-limited POST request."""
        return await self._request("POST", url, **kwargs)

    async def _request(
        self, method: str, url: str, retries: int = 3, **kwargs: Any
    ) -> PolicyResponse:
        """Execute a rate-limited request through the canonical policy client."""
        assert self._session, "Session not started — use async with ForgeSession()"
        await self._rate_limit()
        kwargs.setdefault("allow_redirects", True)
        kwargs.setdefault("retries", max(0, retries - 1))
        kwargs.setdefault("timeout", self.timeout)
        response = await self._session.request(method, url, **kwargs)
        self.request_count += 1
        return response

    def update_headers(self, headers: dict[str, str]) -> None:
        """Update session headers (e.g., after login)."""
        self.base_headers.update(headers)
        if self._session:
            self._session.update_headers(headers)

    def update_cookies(
        self,
        cookies: dict[str, str],
        *,
        cookie_provenance: dict[str, dict[str, Any]] | None = None,
    ) -> None:
        """Update session cookies."""
        self.base_cookies.update(cookies)
        if cookie_provenance:
            self.cookie_provenance.update(cookie_provenance)
        if self._session:
            self._session.update_cookies(
                cookies,
                cookie_provenance=cookie_provenance,
            )

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
        outbound_policy = config.extra.get("outbound_policy")
        if not isinstance(outbound_policy, OutboundPolicy):
            outbound_policy = None
        return cls(
            rate=config.rate.requests_per_second,
            proxy=config.extra.get("proxy") or config.proxy,
            timeout=timeout,
            headers=merged_headers,
            cookies=merged_cookies,
            cookie_provenance=(
                config.extra.get("session_cookie_provenance", {})
                if include_auth
                else {}
            ),
            outbound_policy=outbound_policy,
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
