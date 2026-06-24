"""Authenticated scan helpers for WebForge browser sessions.

Provides:
    • AuthRecorder    — Playwright login replay + storage state export
    • SessionHealth   — Mid-scan session expiry detection + auto re-auth
    • LoginScript     — YAML/dict login sequence executor (multi-step flows)
    • Token extraction from storage state (Bearer, JWT, CSRF, session cookies)
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from webforge.core.browser_engine import BrowserEngine, BrowserSnapshot

log = logging.getLogger("webforge.auth")


@dataclass
class AuthReplayResult:
    """Result of a login replay or auth-state import."""
    authenticated: bool
    storage_state_path: str = ""
    headers: dict[str, str] | None = None
    cookies: dict[str, str] | None = None
    tokens: dict[str, str] = field(default_factory=dict)
    snapshot: dict[str, Any] | None = None
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "authenticated": self.authenticated,
            "storage_state_path": self.storage_state_path,
            "headers": self.headers or {},
            "cookies": self.cookies or {},
            "tokens": self.tokens,
            "snapshot": self.snapshot or {},
            "error": self.error,
        }


# ── Login sequence steps (for multi-step SSO / MFA flows) ────────────────────

@dataclass
class LoginStep:
    """A single step in a login sequence."""
    action: str       # "fill", "click", "wait", "navigate", "screenshot"
    selector: str = ""
    value: str = ""
    timeout_ms: int = 5000


def parse_login_script(raw: list[dict[str, Any]]) -> list[LoginStep]:
    """Parse a YAML/JSON login script into typed steps.

    Example YAML format::

        - action: navigate
          value: https://target.com/login
        - action: fill
          selector: input[name=username]
          value: admin
        - action: fill
          selector: input[type=password]
          value: P@ssw0rd!
        - action: click
          selector: button[type=submit]
        - action: wait
          timeout_ms: 3000
    """
    steps: list[LoginStep] = []
    for entry in raw:
        steps.append(LoginStep(
            action=entry.get("action", "wait"),
            selector=entry.get("selector", ""),
            value=entry.get("value", ""),
            timeout_ms=entry.get("timeout_ms", 5000),
        ))
    return steps


# ── Session health checker ───────────────────────────────────────────────────

class SessionHealthChecker:
    """Detect mid-scan session expiry and trigger re-authentication.

    Usage::

        checker = SessionHealthChecker(
            target="https://app.example.com",
            auth_indicator="/dashboard",
            unauth_indicators=["/login", "401", "session expired"],
        )
        # Periodically during scan:
        if not await checker.is_healthy(session):
            await checker.re_authenticate(recorder, login_url, user, pw)
    """

    def __init__(
        self,
        target: str,
        auth_indicator: str = "",
        unauth_indicators: list[str] | None = None,
        check_interval_s: float = 120.0,
        max_retries: int = 3,
    ) -> None:
        self.target = target.rstrip("/")
        self.auth_indicator = auth_indicator
        self.unauth_indicators = unauth_indicators or [
            "login", "sign-in", "signin", "401", "403",
            "session expired", "session_expired", "unauthorized",
        ]
        self.check_interval = check_interval_s
        self.max_retries = max_retries
        self._last_check = 0.0
        self._fail_count = 0

    async def is_healthy(self, http_session: Any) -> bool:
        """Probe the target to verify our session is still valid."""
        now = time.monotonic()
        if now - self._last_check < self.check_interval:
            return True  # Not time to check yet

        self._last_check = now
        try:
            import aiohttp
            timeout = aiohttp.ClientTimeout(total=10)
            async with http_session.get(
                self.target, timeout=timeout, allow_redirects=False
            ) as resp:
                # 302 redirect to login = session dead
                if resp.status in (401, 403):
                    log.warning("Session health: %d — session likely expired", resp.status)
                    self._fail_count += 1
                    return False

                if resp.status in (301, 302, 307, 308):
                    location = resp.headers.get("Location", "")
                    if any(ind in location.lower() for ind in self.unauth_indicators):
                        log.warning("Session health: redirect to %s — session expired", location)
                        self._fail_count += 1
                        return False

                # Check body for auth indicators
                body = await resp.text(errors="ignore")
                body_lower = body.lower()
                if any(ind in body_lower for ind in self.unauth_indicators):
                    log.warning("Session health: unauth indicator in response body")
                    self._fail_count += 1
                    return False

                if self.auth_indicator and self.auth_indicator.lower() not in body_lower:
                    log.warning("Session health: auth indicator '%s' missing from response", self.auth_indicator)
                    self._fail_count += 1
                    return False

                self._fail_count = 0
                return True

        except Exception as exc:
            log.debug("Session health check failed: %s", exc)
            self._fail_count += 1
            return self._fail_count < 2  # Allow one transient failure

    async def re_authenticate(
        self,
        recorder: "AuthRecorder",
        login_url: str,
        username: str = "",
        password: str = "",
        browser: str = "chromium",
    ) -> AuthReplayResult:
        """Re-run login flow and return fresh auth state."""
        if self._fail_count > self.max_retries:
            log.error("Session re-auth exceeded max retries (%d)", self.max_retries)
            return AuthReplayResult(authenticated=False, error="Max re-auth retries exceeded")

        log.info("Re-authenticating session (attempt %d/%d)", self._fail_count, self.max_retries)
        result = await recorder.replay_login(login_url, username, password, browser)
        if result.authenticated:
            self._fail_count = 0
            log.info("Session re-authenticated successfully")
        else:
            log.warning("Session re-auth failed: %s", result.error)
        return result


# ── Auth recorder ────────────────────────────────────────────────────────────

class AuthRecorder:
    """Replay simple browser login flows and convert storage state for scanners."""

    def __init__(self, results_dir: Path, proxy: str | None = None) -> None:
        self.results_dir = results_dir
        self.proxy = proxy

    async def replay_login(
        self,
        login_url: str,
        username: str = "",
        password: str = "",
        browser: str = "chromium",
    ) -> AuthReplayResult:
        if not BrowserEngine.available():
            return AuthReplayResult(
                authenticated=False,
                error="Playwright unavailable. Install requirements and run: playwright install chromium",
            )
        try:
            async with BrowserEngine(self.results_dir, browser=browser, proxy=self.proxy) as engine:
                snap = await engine.login(login_url, username=username, password=password)
            state_path = Path(snap.storage_state_path) if snap.storage_state_path else None
            headers, cookies = self._headers_cookies_from_state(state_path) if state_path else ({}, {})
            tokens = self._extract_tokens(state_path) if state_path else {}
            return AuthReplayResult(
                authenticated=not bool(snap.error),
                storage_state_path=snap.storage_state_path,
                headers=headers,
                cookies=cookies,
                tokens=tokens,
                snapshot=snap.to_dict(),
                error=snap.error,
            )
        except Exception as exc:
            return AuthReplayResult(authenticated=False, error=str(exc))

    async def replay_script(
        self,
        login_script: list[LoginStep],
        browser: str = "chromium",
    ) -> AuthReplayResult:
        """Execute a multi-step login script via Playwright."""
        if not BrowserEngine.available():
            return AuthReplayResult(
                authenticated=False,
                error="Playwright unavailable",
            )
        try:
            async with BrowserEngine(self.results_dir, browser=browser, proxy=self.proxy) as engine:
                if not engine._context:
                    await engine.start()
                page = await engine._context.new_page()
                try:
                    for step in login_script:
                        await self._execute_step(page, step)

                    # Export storage state after login flow completes
                    state_path = self.results_dir / "auth_storage_state.json"
                    self.results_dir.mkdir(parents=True, exist_ok=True)
                    await engine._context.storage_state(path=str(state_path))

                    headers, cookies = self._headers_cookies_from_state(state_path)
                    tokens = self._extract_tokens(state_path)
                    snap = BrowserSnapshot(url=page.url)
                    snap.storage_state_path = str(state_path)
                    return AuthReplayResult(
                        authenticated=True,
                        storage_state_path=str(state_path),
                        headers=headers,
                        cookies=cookies,
                        tokens=tokens,
                        snapshot=snap.to_dict(),
                    )
                finally:
                    await page.close()
        except Exception as exc:
            return AuthReplayResult(authenticated=False, error=str(exc))

    async def _execute_step(self, page: Any, step: LoginStep) -> None:
        """Execute a single login step on the Playwright page."""
        if step.action == "navigate":
            await page.goto(step.value, wait_until="domcontentloaded")
        elif step.action == "fill":
            await page.locator(step.selector).first.fill(step.value)
        elif step.action == "click":
            await page.locator(step.selector).first.click()
        elif step.action == "wait":
            try:
                await page.wait_for_load_state("networkidle", timeout=step.timeout_ms)
            except Exception:
                await page.wait_for_timeout(step.timeout_ms)
        elif step.action == "screenshot":
            ss_path = self.results_dir / "evidence" / "screenshots" / f"login_step_{step.value or 'capture'}.png"
            ss_path.parent.mkdir(parents=True, exist_ok=True)
            await page.screenshot(path=str(ss_path))
        elif step.action == "select":
            await page.locator(step.selector).first.select_option(step.value)
        elif step.action == "check":
            await page.locator(step.selector).first.check()
        else:
            log.warning("Unknown login step action: %s", step.action)

    def import_storage_state(self, path: Path) -> AuthReplayResult:
        headers, cookies = self._headers_cookies_from_state(path)
        tokens = self._extract_tokens(path)
        return AuthReplayResult(
            authenticated=path.exists(),
            storage_state_path=str(path),
            headers=headers,
            cookies=cookies,
            tokens=tokens,
            error="" if path.exists() else f"storage state not found: {path}",
        )

    def _headers_cookies_from_state(self, path: Path | None) -> tuple[dict[str, str], dict[str, str]]:
        if not path or not path.exists():
            return {}, {}
        data = json.loads(path.read_text(encoding="utf-8"))
        cookies = {
            c.get("name", ""): c.get("value", "")
            for c in data.get("cookies", [])
            if c.get("name")
        }
        headers: dict[str, str] = {}
        if cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
        return headers, cookies

    def _extract_tokens(self, path: Path | None) -> dict[str, str]:
        """Pull Bearer, JWT, CSRF tokens from Playwright storage state.

        Checks:
            1. localStorage for common token keys (auth_token, access_token, jwt, etc.)
            2. Cookies for known token cookie names (XSRF-TOKEN, csrf_token, etc.)
        """
        if not path or not path.exists():
            return {}

        data = json.loads(path.read_text(encoding="utf-8"))
        tokens: dict[str, str] = {}

        # localStorage entries
        token_keys = {
            "token", "access_token", "auth_token", "jwt", "jwt_token",
            "id_token", "bearer", "session_token", "api_token", "apiKey",
        }
        csrf_keys = {
            "csrf", "csrf_token", "csrftoken", "xsrf", "xsrf_token",
            "_csrf", "_csrf_token", "x-csrf-token",
        }

        for origin in data.get("origins", []):
            for ls in origin.get("localStorage", []):
                key_lower = ls.get("name", "").lower()
                value = ls.get("value", "")
                if not value:
                    continue
                if any(ck in key_lower for ck in csrf_keys):
                    tokens["csrf"] = value
                elif any(tk in key_lower for tk in token_keys):
                    # Detect if it's a JWT
                    if value.count(".") == 2 and value.startswith("eyJ"):
                        tokens["jwt"] = value
                    else:
                        tokens["bearer"] = value

        # Cookie-based tokens
        csrf_cookie_names = {"xsrf-token", "csrf_token", "csrftoken", "_csrf"}
        session_cookie_names = {"session", "sessionid", "connect.sid", "sid", "phpsessid"}
        for cookie in data.get("cookies", []):
            cname = cookie.get("name", "").lower()
            cval = cookie.get("value", "")
            if cname in csrf_cookie_names:
                tokens.setdefault("csrf", cval)
            elif cname in session_cookie_names:
                tokens.setdefault("session_cookie", cval)
            # JWT in cookie
            if cval.count(".") == 2 and cval.startswith("eyJ"):
                tokens.setdefault("jwt", cval)

        return tokens

    def build_auth_headers(self, result: AuthReplayResult) -> dict[str, str]:
        """Build HTTP headers from an auth result for use by HTTP-based scanners."""
        headers: dict[str, str] = {}
        if result.headers:
            headers.update(result.headers)

        # Add Bearer/JWT if discovered
        if result.tokens.get("jwt"):
            headers["Authorization"] = f"Bearer {result.tokens['jwt']}"
        elif result.tokens.get("bearer"):
            headers["Authorization"] = f"Bearer {result.tokens['bearer']}"

        # Add CSRF header if discovered
        if result.tokens.get("csrf"):
            headers["X-CSRF-Token"] = result.tokens["csrf"]
            headers["X-XSRF-Token"] = result.tokens["csrf"]

        return headers


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestAuthRecorder:
    def test_missing_storage_state(self, tmp_path: Path) -> None:
        rec = AuthRecorder(tmp_path)
        result = rec.import_storage_state(tmp_path / "missing.json")
        assert result.authenticated is False

    def test_extract_tokens_jwt(self, tmp_path: Path) -> None:
        state = {
            "cookies": [
                {"name": "session", "value": "abc123", "domain": "test.com", "path": "/"},
            ],
            "origins": [
                {"origin": "https://test.com", "localStorage": [
                    {"name": "access_token", "value": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig123"},
                    {"name": "csrf_token", "value": "tok_csrf_abc"},
                ]},
            ],
        }
        path = tmp_path / "state.json"
        path.write_text(json.dumps(state))
        rec = AuthRecorder(tmp_path)
        tokens = rec._extract_tokens(path)
        assert tokens["jwt"].startswith("eyJ")
        assert tokens["csrf"] == "tok_csrf_abc"
        assert "session_cookie" in tokens

    def test_build_auth_headers(self) -> None:
        rec = AuthRecorder(Path("/tmp"))
        result = AuthReplayResult(
            authenticated=True,
            tokens={"jwt": "eyJtest.eyJbody.sig", "csrf": "abc123"},
        )
        headers = rec.build_auth_headers(result)
        assert "Authorization" in headers
        assert headers["Authorization"].startswith("Bearer eyJ")
        assert headers["X-CSRF-Token"] == "abc123"

    def test_parse_login_script(self) -> None:
        raw = [
            {"action": "navigate", "value": "https://app.test.com/login"},
            {"action": "fill", "selector": "input[name=email]", "value": "admin@test.com"},
            {"action": "fill", "selector": "input[type=password]", "value": "secret"},
            {"action": "click", "selector": "button[type=submit]"},
            {"action": "wait", "timeout_ms": 3000},
        ]
        steps = parse_login_script(raw)
        assert len(steps) == 5
        assert steps[0].action == "navigate"
        assert steps[1].value == "admin@test.com"
        assert steps[4].timeout_ms == 3000

    def test_session_health_init(self) -> None:
        checker = SessionHealthChecker(
            target="https://app.test.com",
            auth_indicator="/dashboard",
        )
        assert checker.target == "https://app.test.com"
        assert checker.max_retries == 3
