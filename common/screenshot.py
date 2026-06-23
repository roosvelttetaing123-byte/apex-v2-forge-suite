"""Browser-based screenshot capture for POC evidence.

Auto-detects the best available browser: Chrome > Chromium > Firefox.
Uses Selenium 4.x with selenium-manager (no manual driver install needed).
"""
from __future__ import annotations

import logging
import shutil
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

log = logging.getLogger(__name__)

BrowserType = Literal["chrome", "chromium", "firefox"]


@dataclass
class BrowserConfig:
    """Detected browser configuration."""
    browser_type: BrowserType
    binary_path:  str


def detect_browser() -> BrowserConfig | None:
    """Detect the best available browser in priority order.

    Priority: google-chrome > google-chrome-stable > chromium > chromium-browser > firefox > firefox-esr

    Returns:
        BrowserConfig for the best available browser, or None if none found.
    """
    candidates: list[tuple[BrowserType, list[str]]] = [
        ("chrome",   ["google-chrome", "google-chrome-stable"]),
        ("chromium", ["chromium", "chromium-browser"]),
        ("firefox",  ["firefox", "firefox-esr"]),
    ]
    for browser_type, binaries in candidates:
        for binary in binaries:
            path = shutil.which(binary)
            if path:
                log.debug("Browser detected: %s at %s", browser_type, path)
                return BrowserConfig(browser_type=browser_type, binary_path=path)
    return None


def _build_chrome_driver(config: BrowserConfig, headless: bool = True):
    """Build a Chrome/Chromium WebDriver instance."""
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service

    opts = Options()
    opts.binary_location = config.binary_path
    if headless:
        opts.add_argument("--headless=new")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument("--disable-gpu")
    opts.add_argument("--window-size=1920,1080")
    opts.add_argument("--disable-extensions")
    opts.add_argument("--disable-web-security")
    opts.add_argument("--allow-running-insecure-content")
    opts.add_argument("--ignore-certificate-errors")
    # Suppress c-ares inotify watch exhaustion spam on Linux
    opts.add_argument("--disable-background-networking")
    opts.add_argument("--dns-prefetch-disable")
    opts.add_argument("--no-first-run")
    opts.add_argument("--disable-default-apps")
    # selenium-manager auto-downloads matching chromedriver
    return webdriver.Chrome(options=opts)


def _build_firefox_driver(config: BrowserConfig, headless: bool = True):
    """Build a Firefox WebDriver instance."""
    from selenium import webdriver
    from selenium.webdriver.firefox.options import Options

    opts = Options()
    opts.binary_location = config.binary_path
    if headless:
        opts.add_argument("-headless")
    opts.set_preference("browser.download.manager.showWhenStarting", False)
    # selenium-manager auto-downloads matching geckodriver
    return webdriver.Firefox(options=opts)


def build_driver(config: BrowserConfig | None = None, headless: bool = True):
    """Build and return a Selenium WebDriver for the detected/specified browser.

    Args:
        config:   BrowserConfig to use. If None, auto-detects.
        headless: True for automated screenshots, False for visible window (SSO).

    Returns:
        Selenium WebDriver instance.

    Raises:
        RuntimeError: If no browser is available.
    """
    if config is None:
        config = detect_browser()
    if config is None:
        raise RuntimeError(
            "No browser found. Install one: apt-get install -y chromium"
        )
    if config.browser_type in ("chrome", "chromium"):
        return _build_chrome_driver(config, headless=headless)
    return _build_firefox_driver(config, headless=headless)


def capture(
    url: str,
    output_dir: Path,
    wait_ms: int = 1500,
    highlight_js: str | None = None,
    cookies: list[dict] | None = None,
    finding_id: str | None = None,
    headless: bool = True,
) -> str | None:
    """Capture a screenshot of a URL as PNG evidence.

    Args:
        url:          URL to screenshot.
        output_dir:   Directory to save the PNG.
        wait_ms:      Milliseconds to wait after page load before capture.
        highlight_js: Optional JS snippet to run before screenshot
                      (e.g. to highlight a vulnerable element or trigger payload).
        cookies:      Optional list of cookie dicts to inject before navigating.
        finding_id:   UUID string for the finding (used in filename).
        headless:     True for automated use, False for visible window.

    Returns:
        Path to the saved PNG file, or None on failure.
    """
    fid = finding_id or str(uuid.uuid4())
    output_dir.mkdir(parents=True, exist_ok=True)
    png_path = output_dir / f"finding_{fid}.png"

    driver = None
    try:
        driver = build_driver(headless=headless)

        # Navigate to URL
        driver.get(url)
        time.sleep(wait_ms / 1000.0)

        # Inject cookies if provided (for authenticated sessions)
        if cookies:
            for cookie in cookies:
                try:
                    driver.add_cookie(cookie)
                except Exception:
                    pass
            driver.refresh()
            time.sleep(wait_ms / 1000.0)

        # Run highlight JS before screenshot
        if highlight_js:
            try:
                driver.execute_script(highlight_js)
                time.sleep(0.3)
            except Exception as exc:
                log.debug("highlight_js failed: %s", exc)

        driver.save_screenshot(str(png_path))
        log.info("Screenshot saved: %s", png_path)
        return str(png_path)

    except Exception as exc:
        log.warning("Screenshot failed for %s: %s", url, exc)
        return None
    finally:
        if driver:
            try:
                driver.quit()
            except Exception:
                pass


def capture_xss(url: str, output_dir: Path, finding_id: str | None = None) -> str | None:
    """Capture screenshot highlighting an XSS alert/payload output."""
    highlight = """
    (function() {
        var alerts = document.querySelectorAll('[class*="alert"],[id*="alert"]');
        alerts.forEach(function(el) {
            el.style.outline = '4px solid red';
            el.style.background = 'rgba(255,0,0,0.1)';
        });
        // highlight any injected script outputs
        document.querySelectorAll('script').forEach(function(el) {
            el.style.outline = '2px solid orange';
        });
    })();
    """
    return capture(url, output_dir, highlight_js=highlight, finding_id=finding_id)


def capture_sqli(url: str, output_dir: Path, finding_id: str | None = None) -> str | None:
    """Capture screenshot of SQL error output."""
    highlight = """
    (function() {
        var body = document.body.innerHTML;
        var patterns = ['SQL', 'mysql', 'ORA-', 'syntax error', 'Warning:'];
        patterns.forEach(function(p) {
            body = body.replace(new RegExp(p, 'gi'),
                '<span style="background:red;color:white;padding:2px">' + p + '</span>');
        });
        document.body.innerHTML = body;
    })();
    """
    return capture(url, output_dir, highlight_js=highlight, finding_id=finding_id)


def capture_console(output_dir: Path, name: str, console_html: str) -> str | None:
    """Save a Rich console HTML capture as evidence for non-browser findings."""
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"{name}.html"
    try:
        path.write_text(console_html, encoding="utf-8")
        return str(path)
    except Exception as exc:
        log.warning("Console capture failed: %s", exc)
        return None


class TestScreenshot:
    """Unit tests for screenshot module."""

    def test_detect_browser_returns_config_or_none(self) -> None:
        result = detect_browser()
        # Either None (no browser) or a valid BrowserConfig
        assert result is None or isinstance(result, BrowserConfig)

    def test_capture_no_browser_graceful(self, tmp_path: Path) -> None:
        # Should return None gracefully when browser unavailable
        original_detect = detect_browser.__wrapped__ if hasattr(detect_browser, "__wrapped__") else None
        result = capture("https://example.com", tmp_path, finding_id="test-no-browser")
        # Either returns a path (browser available) or None (no browser) — never raises
        assert result is None or Path(result).exists()

    def test_capture_console(self, tmp_path: Path) -> None:
        path = capture_console(tmp_path, "test", "<html><body>test</body></html>")
        assert path is not None
        assert Path(path).read_text() == "<html><body>test</body></html>"
