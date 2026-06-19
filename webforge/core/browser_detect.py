"""Browser detection for WebForge — finds best available browser for Selenium."""
from __future__ import annotations

import shutil
import logging
from dataclasses import dataclass
from typing import Literal

log = logging.getLogger(__name__)

BrowserType = Literal["chrome", "chromium", "firefox"]

_BROWSER_CANDIDATES: list[tuple[BrowserType, list[str]]] = [
    ("chrome",   ["google-chrome", "google-chrome-stable"]),
    ("chromium", ["chromium", "chromium-browser"]),
    ("firefox",  ["firefox", "firefox-esr"]),
]


@dataclass
class BrowserConfig:
    browser_type: BrowserType
    binary_path:  str

    def __str__(self) -> str:
        return f"{self.browser_type} @ {self.binary_path}"


def get_browser_config() -> BrowserConfig | None:
    """Detect the best available browser. Priority: Chrome > Chromium > Firefox."""
    for browser_type, binaries in _BROWSER_CANDIDATES:
        for binary in binaries:
            path = shutil.which(binary)
            if path:
                log.info("Browser detected: %s at %s", browser_type, path)
                return BrowserConfig(browser_type=browser_type, binary_path=path)
    log.warning("No browser found — screenshots and SSO bridge unavailable")
    return None


def build_driver(config: BrowserConfig | None = None, headless: bool = True):
    """Build a Selenium WebDriver for the detected browser.

    Args:
        config:   BrowserConfig to use. Auto-detects if None.
        headless: True for automated screenshots, False for visible SSO window.

    Returns:
        Selenium WebDriver.

    Raises:
        RuntimeError: If no browser available.
    """
    if config is None:
        config = get_browser_config()
    if config is None:
        raise RuntimeError(
            "No browser found. Install: apt-get install -y chromium"
        )

    if config.browser_type in ("chrome", "chromium"):
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        opts = Options()
        opts.binary_location = config.binary_path
        if headless:
            opts.add_argument("--headless=new")
        for arg in ["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu",
                    "--window-size=1920,1080", "--disable-extensions",
                    "--ignore-certificate-errors", "--allow-running-insecure-content"]:
            opts.add_argument(arg)
        return webdriver.Chrome(options=opts)

    else:  # firefox
        from selenium import webdriver
        from selenium.webdriver.firefox.options import Options
        opts = Options()
        opts.binary_location = config.binary_path
        if headless:
            opts.add_argument("-headless")
        return webdriver.Firefox(options=opts)


def print_browser_status() -> None:
    """Print detected browser info to console."""
    cfg = get_browser_config()
    if cfg:
        print(f"[+] Browser: {cfg}")
    else:
        print("[!] No browser detected — install chromium for screenshot/SSO features")


class TestBrowserDetect:
    def test_detect_returns_config_or_none(self) -> None:
        result = get_browser_config()
        assert result is None or isinstance(result, BrowserConfig)

    def test_browser_config_str(self) -> None:
        cfg = BrowserConfig("chromium", "/usr/bin/chromium")
        assert "chromium" in str(cfg)
