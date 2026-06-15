"""NetForge HTTP Session — pooled connections with OpSec integration.

Replaces the old session.py that created a new aiohttp session per request
(insane overhead, obvious detection signature). Now uses a singleton
connection pool with OpSec jitter, cookie persistence, and proper lifecycle.

Usage:
    async with NetForgeSession.create(opsec_profile) as session:
        status, body, headers = await session.get(url)
        status, body, headers = await session.post(url, data=payload)

    # Or use the global pool (initialized once at startup):
    session = await get_session()
    status, body, headers = await session.get(url)
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

log = logging.getLogger("forge.netforge.session")

# Lazy import — opsec may not be initialized yet at import time
_opsec_module = None


def _get_opsec():
    """Lazy import to avoid circular dependency."""
    global _opsec_module
    if _opsec_module is None:
        from netforge.core.opsec import get_opsec
        _opsec_module = get_opsec
    return _opsec_module()


class NetForgeSession:
    """Async HTTP session with connection pooling and OpSec integration.

    Key improvements over old session.py:
    - Singleton aiohttp.ClientSession — reused across ALL requests
    - Connection pool limits per host (configurable)
    - OpSec jitter between requests
    - Cookie jar persistence across requests
    - Randomized User-Agent per request (stealth mode)
    - Proper async lifecycle (startup/shutdown)
    """

    def __init__(
        self,
        max_connections: int = 20,
        max_per_host: int = 5,
        timeout: float = 15.0,
        proxy: str | None = None,
        verify_ssl: bool = False,
    ) -> None:
        self._max_connections = max_connections
        self._max_per_host = max_per_host
        self._timeout = timeout
        self._proxy = proxy
        self._verify_ssl = verify_ssl
        self._session = None
        self._request_count = 0
        self._last_request_time = 0.0

    async def _ensure_session(self) -> Any:
        """Create the aiohttp session lazily — once, then reuse."""
        if self._session is None or self._session.closed:
            try:
                import aiohttp
                connector = aiohttp.TCPConnector(
                    limit=self._max_connections,
                    limit_per_host=self._max_per_host,
                    ssl=self._verify_ssl,
                    ttl_dns_cache=300,     # Cache DNS for 5 min
                    enable_cleanup_closed=True,
                )
                timeout = aiohttp.ClientTimeout(total=self._timeout)
                # Cookie jar persists across requests — important for
                # web service auditing where auth tokens are in cookies
                self._session = aiohttp.ClientSession(
                    connector=connector,
                    timeout=timeout,
                    cookie_jar=aiohttp.CookieJar(unsafe=True),
                )
                log.debug(
                    "HTTP session pool created (max=%d, per_host=%d)",
                    self._max_connections, self._max_per_host,
                )
            except ImportError:
                log.warning("aiohttp not available — HTTP requests will fail")
                return None
        return self._session

    async def _apply_opsec(self) -> dict[str, str]:
        """Apply OpSec controls before each request.

        Returns headers dict with randomized User-Agent.
        """
        try:
            opsec = _get_opsec()
            await opsec.jitter()
            await opsec.maybe_inject_decoy()
            opsec.record_request()
            return {"User-Agent": opsec.get_user_agent()}
        except Exception:
            return {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

    async def get(self, url: str, **kwargs: Any) -> tuple[int, str, dict]:
        """Make a GET request through the pooled session.

        Returns (status_code, body_text, response_headers).
        """
        session = await self._ensure_session()
        if session is None:
            return 0, "aiohttp not available", {}

        opsec_headers = await self._apply_opsec()
        headers = {**opsec_headers, **kwargs.pop("headers", {})}

        try:
            async with session.get(
                url, proxy=self._proxy, headers=headers, **kwargs
            ) as resp:
                body = await resp.text(errors="ignore")
                self._request_count += 1
                return resp.status, body, dict(resp.headers)
        except Exception as exc:
            return 0, str(exc), {}

    async def post(self, url: str, **kwargs: Any) -> tuple[int, str, dict]:
        """Make a POST request through the pooled session."""
        session = await self._ensure_session()
        if session is None:
            return 0, "aiohttp not available", {}

        opsec_headers = await self._apply_opsec()
        headers = {**opsec_headers, **kwargs.pop("headers", {})}

        try:
            async with session.post(
                url, proxy=self._proxy, headers=headers, **kwargs
            ) as resp:
                body = await resp.text(errors="ignore")
                self._request_count += 1
                return resp.status, body, dict(resp.headers)
        except Exception as exc:
            return 0, str(exc), {}

    async def head(self, url: str, **kwargs: Any) -> tuple[int, dict]:
        """Make a HEAD request — returns (status, headers) only."""
        session = await self._ensure_session()
        if session is None:
            return 0, {}

        opsec_headers = await self._apply_opsec()
        headers = {**opsec_headers, **kwargs.pop("headers", {})}

        try:
            async with session.head(
                url, proxy=self._proxy, headers=headers, **kwargs
            ) as resp:
                self._request_count += 1
                return resp.status, dict(resp.headers)
        except Exception as exc:
            return 0, {}

    async def raw_request(
        self, method: str, url: str, **kwargs: Any
    ) -> tuple[int, str, dict]:
        """Make an arbitrary HTTP request."""
        session = await self._ensure_session()
        if session is None:
            return 0, "aiohttp not available", {}

        opsec_headers = await self._apply_opsec()
        headers = {**opsec_headers, **kwargs.pop("headers", {})}

        try:
            async with session.request(
                method, url, proxy=self._proxy, headers=headers, **kwargs
            ) as resp:
                body = await resp.text(errors="ignore")
                self._request_count += 1
                return resp.status, body, dict(resp.headers)
        except Exception as exc:
            return 0, str(exc), {}

    async def close(self) -> None:
        """Close the session pool. Call at scan end."""
        if self._session and not self._session.closed:
            await self._session.close()
            # Wait for SSL cleanup
            await asyncio.sleep(0.25)
            log.debug("HTTP session pool closed (%d requests made)", self._request_count)

    @property
    def stats(self) -> dict:
        return {
            "requests": self._request_count,
            "pool_size": self._max_connections,
            "per_host": self._max_per_host,
            "session_active": self._session is not None and not self._session.closed,
        }

    # Context manager for clean lifecycle
    async def __aenter__(self) -> "NetForgeSession":
        await self._ensure_session()
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()

    @classmethod
    async def create(
        cls,
        max_connections: int = 20,
        max_per_host: int = 5,
        timeout: float = 15.0,
        proxy: str | None = None,
        verify_ssl: bool = False,
    ) -> "NetForgeSession":
        """Factory method — creates and initializes the session."""
        session = cls(
            max_connections=max_connections,
            max_per_host=max_per_host,
            timeout=timeout,
            proxy=proxy,
            verify_ssl=verify_ssl,
        )
        await session._ensure_session()
        return session


# ======================================================================
# Global singleton — one session pool for the entire scan
# ======================================================================

_global_session: NetForgeSession | None = None


async def get_session(**kwargs: Any) -> NetForgeSession:
    """Get or create the global HTTP session pool.

    First call creates the pool. Subsequent calls return the same instance.
    """
    global _global_session
    if _global_session is None or (_global_session._session and _global_session._session.closed):
        _global_session = await NetForgeSession.create(**kwargs)
    return _global_session


async def close_session() -> None:
    """Close the global session pool. Call at scan end."""
    global _global_session
    if _global_session:
        await _global_session.close()
        _global_session = None


# ======================================================================
# Tests
# ======================================================================

class TestNetForgeSession:
    """Unit tests for the session pool."""

    def test_session_creates(self) -> None:
        s = NetForgeSession()
        assert s._request_count == 0
        assert s._session is None

    def test_stats(self) -> None:
        s = NetForgeSession(max_connections=30, max_per_host=10)
        stats = s.stats
        assert stats["pool_size"] == 30
        assert stats["per_host"] == 10
        assert stats["requests"] == 0

    def test_default_config(self) -> None:
        s = NetForgeSession()
        assert s._max_connections == 20
        assert s._max_per_host == 5
        assert s._timeout == 15.0
