#!/usr/bin/env python3
"""session_capture.py — Standalone SSO / manual login session capture tool.

Run this BEFORE webforge.py when the target uses SSO, MFA, CAPTCHA,
hardware tokens, or any login type automation cannot handle.

Usage:
  python session_capture.py --target https://app.corp.com/login
  python session_capture.py --target https://app.corp.com/login --output session.json
  python session_capture.py --target https://app.corp.com/login --wait-url https://app.corp.com/dashboard

Then run WebForge with the captured session:
  python webforge.py --target https://app.corp.com --session session.json
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from webforge.core.browser_detect import get_browser_config, print_browser_status
from webforge.core.session_bridge import capture_session, SUPPORTED_LOGIN_TYPES


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Capture authenticated session after manual login (SSO/MFA/etc.)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="\n".join([
            "Supported login types:",
            *[f"  • {t}" for t in SUPPORTED_LOGIN_TYPES],
            "",
            "Example:",
            "  python session_capture.py --target https://app.corp.com/login",
            "  python webforge.py --target https://app.corp.com --session session.json",
        ])
    )
    parser.add_argument("--target",   required=True,             help="Login URL to open in browser")
    parser.add_argument("--output",   default="session.json",    help="Output session file (default: session.json)")
    parser.add_argument("--wait-url", default=None,              help="Auto-detect login completion when browser reaches this URL")
    parser.add_argument("--timeout",  type=int, default=300,     help="Max wait seconds (default: 300)")
    parser.add_argument("--browser",  default=None,              help="Force browser: chrome|chromium|firefox (default: auto)")
    args = parser.parse_args()

    print("\n[*] forge-suite — Session Capture Tool")
    print("[*] FOR AUTHORIZED PENETRATION TESTING ONLY\n")

    print_browser_status()

    if args.browser:
        from webforge.core.browser_detect import BrowserConfig, get_browser_config as gbc
        import shutil
        binaries = {
            "chrome":   ["google-chrome", "google-chrome-stable"],
            "chromium": ["chromium", "chromium-browser"],
            "firefox":  ["firefox", "firefox-esr"],
        }
        b_type = args.browser.lower()
        if b_type not in binaries:
            print(f"[!] Unknown browser: {args.browser}. Use: chrome|chromium|firefox")
            sys.exit(1)
        path = None
        for binary in binaries[b_type]:
            path = shutil.which(binary)
            if path:
                break
        if not path:
            print(f"[!] Browser '{args.browser}' not found")
            sys.exit(1)
        from webforge.core.browser_detect import BrowserConfig
        cfg = BrowserConfig(browser_type=b_type, binary_path=path)  # type: ignore
    else:
        cfg = None

    output = Path(args.output)
    result = capture_session(
        login_url=args.target,
        output_path=output,
        wait_url=args.wait_url,
        timeout_s=args.timeout,
        headless=False,
    )

    if result is None:
        print("[!] Session capture failed")
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
