"""Authenticated scan helpers for WebForge browser sessions.

Provides:
    • AuthRecorder    — Playwright login replay + storage state export
    • SessionHealth   — Mid-scan session expiry detection + auto re-auth
    • LoginScript     — YAML/dict login sequence executor (multi-step flows)
    • Token extraction from storage state (Bearer, JWT, CSRF, session cookies)
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from common.outbound_policy import (
    cookie_path_matches,
    cookie_provenance_matches_destination,
    normalize_destination,
)
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
    credential_origin: str = ""
    cookie_provenance: dict[str, dict[str, Any]] = field(default_factory=dict)
    token_provenance: dict[str, str] = field(default_factory=dict)
    snapshot: dict[str, Any] | None = None
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "authenticated": self.authenticated,
            "storage_state_path": self.storage_state_path,
            "headers": self.headers or {},
            "cookies": self.cookies or {},
            "tokens": self.tokens,
            "credential_origin": self.credential_origin,
            "cookie_provenance": self.cookie_provenance,
            "token_provenance": self.token_provenance,
            "snapshot": self.snapshot or {},
            "error": self.error,
        }


def _normalized_destination_or_none(url: str) -> Any | None:
    try:
        return normalize_destination(str(url))
    except Exception:
        return None


def _cookie_domain(raw_domain: Any) -> tuple[str, bool] | None:
    value = str(raw_domain or "").strip().rstrip(".")
    domain_scoped = value.startswith(".")
    value = value.lstrip(".")
    if not value:
        return None
    host_value = f"[{value}]" if ":" in value and not value.startswith("[") else value
    destination = _normalized_destination_or_none(f"https://{host_value}/")
    if destination is None:
        return None
    try:
        is_ip = bool(ipaddress.ip_address(destination.host))
    except ValueError:
        is_ip = False
    if is_ip and domain_scoped:
        return None
    return destination.host, domain_scoped


def cookie_provenance_matches_target(
    provenance: Mapping[str, Any] | None,
    target_url: str,
) -> bool:
    """Revalidate retained cookie scope before flattened state is applied."""
    return cookie_provenance_matches_destination(provenance, target_url)


def filter_cookies_for_target(
    cookie_records: Any,
    target_url: str,
) -> tuple[dict[str, str], dict[str, dict[str, Any]]]:
    """Retain only unambiguous cookies the browser would send to target_url."""
    destination = _normalized_destination_or_none(target_url)
    if destination is None or not isinstance(cookie_records, list):
        return {}, {}
    request_path = urlsplit(destination.url).path or "/"
    candidates: dict[str, set[tuple[str, str, bool, str, bool]]] = {}
    for raw_cookie in cookie_records:
        if not isinstance(raw_cookie, Mapping):
            continue
        name = str(raw_cookie.get("name", ""))
        value = str(raw_cookie.get("value", ""))
        domain_info = _cookie_domain(raw_cookie.get("domain"))
        if not name or not value or domain_info is None:
            continue
        domain, domain_scoped = domain_info
        if domain_scoped:
            domain_matches = (
                destination.host == domain
                or destination.host.endswith(f".{domain}")
            )
        else:
            domain_matches = destination.host == domain
        path = str(raw_cookie.get("path") or "/")
        secure_value = raw_cookie.get("secure", False)
        if type(secure_value) is not bool:
            continue
        secure = secure_value
        if (
            not domain_matches
            or not cookie_path_matches(request_path, path)
            or (secure and destination.scheme != "https")
        ):
            continue
        candidates.setdefault(name, set()).add(
            (value, domain, not domain_scoped, path, secure)
        )

    cookies: dict[str, str] = {}
    provenance: dict[str, dict[str, Any]] = {}
    for name in sorted(candidates):
        records = candidates[name]
        if len(records) != 1:
            continue
        value, domain, host_only, path, secure = next(iter(records))
        record = {
            "origin": destination.origin,
            "domain": domain,
            "host_only": host_only,
            "path": path,
            "secure": secure,
        }
        if not cookie_provenance_matches_target(record, target_url):
            continue
        cookies[name] = value
        provenance[name] = record
    return cookies, provenance


def _resolved_token_candidates(
    candidates: Mapping[str, set[str]],
) -> dict[str, str]:
    resolved = {
        name: next(iter(values))
        for name, values in candidates.items()
        if len(values) == 1
    }
    jwt = resolved.get("jwt")
    bearer = resolved.get("bearer")
    if jwt and bearer:
        if jwt == bearer:
            resolved.pop("bearer", None)
        else:
            resolved.pop("jwt", None)
            resolved.pop("bearer", None)
    return resolved


def _token_candidates_from_values(tokens: Any) -> dict[str, set[str]]:
    candidates: dict[str, set[str]] = {}
    if not isinstance(tokens, Mapping):
        return candidates
    for name in ("jwt", "bearer", "csrf", "session_cookie"):
        value = tokens.get(name)
        if value:
            candidates.setdefault(name, set()).add(str(value))
    return candidates


def filter_captured_session_credentials(
    session_data: Mapping[str, Any],
    target_url: str,
) -> tuple[
    dict[str, str],
    dict[str, dict[str, Any]],
    dict[str, str],
    dict[str, str],
]:
    """Filter a legacy Selenium capture before applying it to an HTTP client."""
    destination = _normalized_destination_or_none(target_url)
    if destination is None:
        return {}, {}, {}, {}
    cookies, cookie_provenance = filter_cookies_for_target(
        session_data.get("cookies", []),
        target_url,
    )
    post_login = _normalized_destination_or_none(
        str(session_data.get("post_login_url", ""))
    )
    tokens: dict[str, str] = {}
    token_provenance: dict[str, str] = {}
    if post_login is not None and post_login.origin == destination.origin:
        tokens = _resolved_token_candidates(
            _token_candidates_from_values(session_data.get("detected_tokens", {}))
        )
        token_provenance = {name: destination.origin for name in tokens}
    return cookies, cookie_provenance, tokens, token_provenance


def extract_storage_tokens_for_target(
    storage_state: Mapping[str, Any],
    target_url: str,
    _retained_cookies: Mapping[str, str],
) -> tuple[dict[str, str], dict[str, str]]:
    """Extract only exact-origin localStorage token candidates.

    Cookie values remain cookies so their Domain, Path, and Secure provenance
    cannot be widened into origin-wide authorization or CSRF headers.
    """
    destination = _normalized_destination_or_none(target_url)
    if destination is None:
        return {}, {}
    candidates: dict[str, set[str]] = {}
    token_keys = {
        "token", "access_token", "auth_token", "jwt", "jwt_token",
        "id_token", "bearer", "session_token", "api_token", "apikey",
    }
    csrf_keys = {
        "csrf", "csrf_token", "csrftoken", "xsrf", "xsrf_token",
        "_csrf", "_csrf_token", "x-csrf-token",
    }
    origins = storage_state.get("origins", [])
    if isinstance(origins, list):
        for raw_origin in origins:
            if not isinstance(raw_origin, Mapping):
                continue
            source = _normalized_destination_or_none(str(raw_origin.get("origin", "")))
            if source is None or source.origin != destination.origin:
                continue
            local_storage = raw_origin.get("localStorage", [])
            if not isinstance(local_storage, list):
                continue
            for item in local_storage:
                if not isinstance(item, Mapping):
                    continue
                key_lower = str(item.get("name", "")).lower()
                value = str(item.get("value", ""))
                if not value:
                    continue
                if any(key in key_lower for key in csrf_keys):
                    candidates.setdefault("csrf", set()).add(value)
                elif any(key in key_lower for key in token_keys):
                    kind = (
                        "jwt"
                        if value.count(".") == 2 and value.startswith("eyJ")
                        else "bearer"
                    )
                    candidates.setdefault(kind, set()).add(value)

    tokens = _resolved_token_candidates(candidates)
    return tokens, {name: destination.origin for name in tokens}


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
        target_url: str | None = None,
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
            effective_target = target_url or snap.url
            (
                headers,
                cookies,
                tokens,
                credential_origin,
                cookie_provenance,
                token_provenance,
            ) = self._credentials_from_state(state_path, effective_target)
            return AuthReplayResult(
                authenticated=not bool(snap.error),
                storage_state_path=snap.storage_state_path,
                headers=headers,
                cookies=cookies,
                tokens=tokens,
                credential_origin=credential_origin,
                cookie_provenance=cookie_provenance,
                token_provenance=token_provenance,
                snapshot=snap.to_dict(),
                error=snap.error,
            )
        except Exception as exc:
            return AuthReplayResult(authenticated=False, error=str(exc))

    async def replay_script(
        self,
        login_script: list[LoginStep],
        browser: str = "chromium",
        target_url: str | None = None,
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

                    snap = BrowserSnapshot(url=page.url)
                    snap.storage_state_path = str(state_path)
                    (
                        headers,
                        cookies,
                        tokens,
                        credential_origin,
                        cookie_provenance,
                        token_provenance,
                    ) = self._credentials_from_state(
                        state_path,
                        target_url or page.url,
                    )
                    return AuthReplayResult(
                        authenticated=True,
                        storage_state_path=str(state_path),
                        headers=headers,
                        cookies=cookies,
                        tokens=tokens,
                        credential_origin=credential_origin,
                        cookie_provenance=cookie_provenance,
                        token_provenance=token_provenance,
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

    def import_storage_state(self, path: Path, target_url: str = "") -> AuthReplayResult:
        if not path.exists():
            return AuthReplayResult(
                authenticated=False,
                storage_state_path=str(path),
                error=f"storage state not found: {path}",
            )
        if _normalized_destination_or_none(target_url) is None:
            return AuthReplayResult(
                authenticated=False,
                storage_state_path=str(path),
                error="target origin required for storage-state credential import",
            )
        try:
            (
                headers,
                cookies,
                tokens,
                credential_origin,
                cookie_provenance,
                token_provenance,
            ) = self._credentials_from_state(path, target_url)
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
            return AuthReplayResult(
                authenticated=False,
                storage_state_path=str(path),
                error=f"invalid storage state: {exc}",
            )
        return AuthReplayResult(
            authenticated=True,
            storage_state_path=str(path),
            headers=headers,
            cookies=cookies,
            tokens=tokens,
            credential_origin=credential_origin,
            cookie_provenance=cookie_provenance,
            token_provenance=token_provenance,
        )

    def _credentials_from_state(
        self,
        path: Path | None,
        target_url: str,
    ) -> tuple[
        dict[str, str],
        dict[str, str],
        dict[str, str],
        str,
        dict[str, dict[str, Any]],
        dict[str, str],
    ]:
        destination = _normalized_destination_or_none(target_url)
        if not path or not path.exists() or destination is None:
            return {}, {}, {}, "", {}, {}
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, Mapping):
            raise ValueError("storage state must be an object")
        cookies, cookie_provenance = filter_cookies_for_target(
            data.get("cookies", []),
            target_url,
        )
        tokens, token_provenance = extract_storage_tokens_for_target(
            data,
            target_url,
            cookies,
        )
        headers: dict[str, str] = {}
        if cookies:
            headers["Cookie"] = "; ".join(
                f"{name}={value}" for name, value in sorted(cookies.items())
            )
        return (
            headers,
            cookies,
            tokens,
            destination.origin,
            cookie_provenance,
            token_provenance,
        )

    def _headers_cookies_from_state(
        self,
        path: Path | None,
        target_url: str,
    ) -> tuple[dict[str, str], dict[str, str]]:
        headers, cookies, *_ = self._credentials_from_state(path, target_url)
        return headers, cookies

    def _extract_tokens(self, path: Path | None, target_url: str) -> dict[str, str]:
        """Pull only exact-target-origin tokens from Playwright storage state."""
        _, _, tokens, *_ = self._credentials_from_state(path, target_url)
        return tokens

    def build_auth_headers(
        self,
        result: AuthReplayResult,
        target_url: str,
    ) -> dict[str, str]:
        """Revalidate credential provenance and build target-bound headers."""
        destination = _normalized_destination_or_none(target_url)
        if destination is None or result.credential_origin != destination.origin:
            return {}
        cookies = {
            name: value
            for name, value in (result.cookies or {}).items()
            if cookie_provenance_matches_target(
                result.cookie_provenance.get(name),
                target_url,
            )
        }
        tokens = {
            name: value
            for name, value in result.tokens.items()
            if result.token_provenance.get(name) == destination.origin
        }
        headers: dict[str, str] = {}
        if cookies:
            headers["Cookie"] = "; ".join(
                f"{name}={value}" for name, value in sorted(cookies.items())
            )
        if tokens.get("jwt"):
            headers["Authorization"] = f"Bearer {tokens['jwt']}"
        elif tokens.get("bearer"):
            headers["Authorization"] = f"Bearer {tokens['bearer']}"
        if tokens.get("csrf"):
            headers["X-CSRF-Token"] = tokens["csrf"]
            headers["X-XSRF-Token"] = tokens["csrf"]
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
        tokens = rec._extract_tokens(path, "https://test.com/")
        assert tokens["jwt"].startswith("eyJ")
        assert tokens["csrf"] == "tok_csrf_abc"
        assert "session_cookie" not in tokens

    def test_build_auth_headers(self) -> None:
        rec = AuthRecorder(Path("/tmp"))
        result = AuthReplayResult(
            authenticated=True,
            tokens={"jwt": "eyJtest.eyJbody.sig", "csrf": "abc123"},
            credential_origin="https://test.com:443",
            token_provenance={
                "jwt": "https://test.com:443",
                "csrf": "https://test.com:443",
            },
        )
        headers = rec.build_auth_headers(result, "https://test.com/")
        assert "Authorization" in headers
        assert headers["Authorization"].startswith("Bearer eyJ")
        assert headers["X-CSRF-Token"] == "abc123"

    def test_parse_login_script(self) -> None:
        raw: list[dict[str, Any]] = [
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
