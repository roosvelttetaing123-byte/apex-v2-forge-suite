"""Session bridge — captures authenticated session after manual login (SSO, MFA, etc.)."""
from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

SUPPORTED_LOGIN_TYPES = [
    "Form-based login",
    "SSO (Okta, Azure AD, Google Workspace, ADFS, Ping)",
    "SAML 2.0",
    "Multi-factor authentication (OTP, push, hardware token)",
    "FIDO2 / WebAuthn / YubiKey",
    "CAPTCHA-protected login",
    "QR code login",
    "Smart card / certificate login",
    "Any custom JavaScript-heavy login flow",
]


def capture_session(
    login_url: str,
    output_path: Path,
    wait_url: str | None = None,
    timeout_s: int = 300,
    headless: bool = False,
    outbound_policy: Any = None,
) -> dict[str, Any] | None:
    """Open a visible browser, wait for manual login, capture session.

    Args:
        login_url:   URL to navigate to for login.
        output_path: Path to save session.json.
        wait_url:    If set, auto-detect login complete when browser reaches this URL.
        timeout_s:   Max seconds to wait for manual login.
        headless:    Should always be False for manual login (visible window needed).

    Returns:
        Session dict with cookies, localStorage tokens, and auth headers.
    """
    # Selenium cannot consume the resolved-IP permit or enforce target-bound
    # TLS per navigation.  Keep this direct helper inert instead of allowing a
    # caller to bypass the WebForge launcher gate.
    log.error("Session capture disabled: outbound_policy_unsupported")
    return None

    from webforge.core.browser_detect import build_driver, get_browser_config

    cfg = get_browser_config()
    if cfg is None:
        log.error("No browser available for session capture")
        return None

    print("\n" + "╔" + "═" * 62 + "╗")
    print("║  MANUAL LOGIN REQUIRED" + " " * 39 + "║")
    print("║" + " " * 62 + "║")
    print("║  A browser window is opening. Please log in now.        ║")
    print("║  Supported:                                             ║")
    print("║    • SSO (Okta, Azure AD, Google, ADFS, Ping)          ║")
    print("║    • MFA (OTP, push, hardware token, FIDO2)            ║")
    print("║    • CAPTCHA, QR code, smart card, biometric           ║")
    print("║" + " " * 62 + "║")
    if wait_url:
        print(f"║  Auto-detect: waiting for redirect to:                  ║")
        print(f"║    {wait_url[:55]:<55}  ║")
    else:
        print("║  When login is COMPLETE and you see the dashboard,      ║")
        print("║  press Enter in this terminal to capture the session.   ║")
    print("╚" + "═" * 62 + "╝\n")

    driver = None
    try:
        driver = build_driver(config=cfg, headless=False)
        driver.get(login_url)
        print(f"[*] Browser opened: {login_url}")
        print(f"[*] Using: {cfg}")

        if wait_url:
            print(f"[*] Waiting for redirect to: {wait_url}")
            deadline = time.monotonic() + timeout_s
            while time.monotonic() < deadline:
                if driver.current_url.startswith(wait_url):
                    print(f"[+] Login detected — redirected to: {driver.current_url}")
                    break
                time.sleep(1)
            else:
                print(f"[!] Timeout ({timeout_s}s) waiting for redirect")
        else:
            try:
                input("\n[*] Press Enter when login is complete... ")
            except (EOFError, KeyboardInterrupt):
                pass

        session_data = _extract_session(driver, login_url)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(session_data, indent=2), encoding="utf-8")

        _print_session_summary(session_data)
        print(f"\n[+] Session saved: {output_path}")
        print(f"[*] Run: python webforge.py --target <url> --session {output_path}\n")
        return session_data

    except Exception as exc:
        log.error("Session capture failed: %s", exc)
        return None
    finally:
        if driver:
            time.sleep(2)
            try:
                driver.quit()
            except Exception:
                pass


def _extract_session(driver: Any, login_url: str) -> dict[str, Any]:
    """Extract all session data from browser after login."""
    cookies = driver.get_cookies()

    # Extract localStorage
    local_storage: dict[str, str] = {}
    try:
        ls = driver.execute_script(
            "var items = {}; for (var i=0; i<localStorage.length; i++) { "
            "var k = localStorage.key(i); items[k] = localStorage.getItem(k); } return items;"
        )
        local_storage = ls or {}
    except Exception:
        pass

    # Extract sessionStorage
    session_storage: dict[str, str] = {}
    try:
        ss = driver.execute_script(
            "var items = {}; for (var i=0; i<sessionStorage.length; i++) { "
            "var k = sessionStorage.key(i); items[k] = sessionStorage.getItem(k); } return items;"
        )
        session_storage = ss or {}
    except Exception:
        pass

    # Detect auth tokens
    detected: dict[str, str | None] = {
        "bearer": None, "jwt": None, "csrf": None, "session_id": None
    }
    token_keys = ["token", "auth", "jwt", "bearer", "access_token", "id_token",
                  "authorization", "api_key", "apikey"]
    csrf_keys  = ["csrf", "xsrf", "antiforgery", "_token"]

    all_kv = {**local_storage, **session_storage}
    all_kv.update({c["name"]: c["value"] for c in cookies})

    for k, v in all_kv.items():
        kl = k.lower()
        if any(t in kl for t in token_keys):
            if v and len(v) > 10:
                if _is_jwt(v):
                    detected["jwt"] = v
                else:
                    detected["bearer"] = v
        if any(t in kl for t in csrf_keys):
            detected["csrf"] = v
        if "session" in kl and "id" in kl:
            detected["session_id"] = v

    return {
        "captured_at":       datetime.now(timezone.utc).isoformat(),
        "login_url":         login_url,
        "post_login_url":    driver.current_url,
        "cookies":           cookies,
        "localStorage":      local_storage,
        "sessionStorage":    session_storage,
        "detected_tokens":   detected,
        "selenium_cookies":  cookies,  # ready for driver.add_cookie()
    }


def _is_jwt(value: str) -> bool:
    """Check if a string looks like a JWT (3 base64 parts separated by dots)."""
    parts = value.split(".")
    return len(parts) == 3 and all(len(p) > 0 for p in parts)


def _print_session_summary(session: dict[str, Any]) -> None:
    """Print a summary of captured session to terminal."""
    print("\n[+] SESSION CAPTURED:")
    print(f"    Cookies:      {len(session.get('cookies', []))}")
    print(f"    localStorage: {len(session.get('localStorage', {}))}")
    print(f"    sessionStorage:{len(session.get('sessionStorage', {}))}")
    tokens = session.get("detected_tokens", {})
    for t, v in tokens.items():
        if v:
            print(f"    {t.upper()}: {'*' * min(len(v), 8)}...{v[-4:] if len(v) > 8 else v}")


def load_session(session_path: Path) -> dict[str, Any] | None:
    """Load a previously captured session from JSON file."""
    if not session_path.exists():
        log.error("Session file not found: %s", session_path)
        return None
    try:
        return json.loads(session_path.read_text(encoding="utf-8"))
    except Exception as exc:
        log.error("Failed to load session: %s", exc)
        return None


def apply_session_to_forge(
    session_data: dict[str, Any],
    forge_session: Any,
    *,
    target_url: str = "",
) -> None:
    """Apply only revalidated target-bound capture state to ForgeSession."""
    from webforge.core.auth_recorder import filter_captured_session_credentials

    if not target_url:
        log.error("Captured session not applied: target origin is required")
        return
    cookies, cookie_provenance, tokens, _ = filter_captured_session_credentials(
        session_data,
        target_url,
    )
    if cookies:
        try:
            forge_session.update_cookies(
                cookies,
                cookie_provenance=cookie_provenance,
            )
        except TypeError:
            log.error(
                "Captured session not applied: client cannot preserve cookie provenance"
            )
            return

    headers: dict[str, str] = {}
    if tokens.get("jwt"):
        headers["Authorization"] = f"Bearer {tokens['jwt']}"
    elif tokens.get("bearer"):
        headers["Authorization"] = f"Bearer {tokens['bearer']}"
    if tokens.get("csrf"):
        headers["X-CSRF-Token"] = tokens["csrf"]
        headers["X-Requested-With"] = "XMLHttpRequest"
    if headers:
        forge_session.update_headers(headers)


class TestSessionBridge:
    def test_is_jwt(self) -> None:
        assert _is_jwt("eyJhbGc.eyJzdWI.SflKxw") is True
        assert _is_jwt("not-a-jwt") is False

    def test_load_session_missing(self, tmp_path: Path) -> None:
        result = load_session(tmp_path / "nonexistent.json")
        assert result is None

    def test_load_session_valid(self, tmp_path: Path) -> None:
        p = tmp_path / "sess.json"
        p.write_text('{"captured_at": "2024-01-01", "cookies": []}')
        result = load_session(p)
        assert result is not None
        assert "cookies" in result
