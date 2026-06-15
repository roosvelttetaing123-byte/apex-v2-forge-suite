"""CMS detection — WordPress, Joomla, Drupal, Magento, Struts fingerprinting."""
from __future__ import annotations

import asyncio
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

import aiohttp

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_CMS_VERSION = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
CVSS_CMS_EXPOSED = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"

CMS_SIGNATURES: list[dict] = [
    {
        "name": "WordPress",
        "paths": ["/wp-login.php", "/wp-admin/", "/wp-content/", "/xmlrpc.php"],
        "headers": {"X-Powered-By": r"WordPress"},
        "body_patterns": [r"/wp-content/", r"wp-json", r"WordPress\s+[\d.]+"],
        # Path probing: content that must appear in the path response body to confirm
        "path_body_patterns": {
            "/wp-login.php": [r"user_login", r"wp-submit", r"WordPress"],
            "/xmlrpc.php":   [r"xmlrpc", r"XML-RPC"],
            "/wp-admin/":    [r"wp-login", r"wp-admin"],
        },
        "version_pattern": r'<meta name="generator" content="WordPress\s+([\d.]+)"',
        "references": ["CWE-200", "OWASP A05:2021"],
    },
    {
        "name": "Joomla",
        "paths": ["/administrator/", "/components/", "/modules/", "/index.php?option=com_users"],
        "headers": {},
        "body_patterns": [r"Joomla", r"/media/jui/", r"com_content"],
        "path_body_patterns": {
            "/administrator/": [r"Joomla", r"com_login", r"mod_login"],
        },
        "version_pattern": r'<meta name="generator" content="Joomla!\s*([\d.]+)"',
        "references": ["CWE-200", "OWASP A05:2021"],
    },
    {
        "name": "Drupal",
        "paths": ["/user/login", "/sites/default/", "/core/misc/drupal.js"],
        "headers": {"X-Generator": r"Drupal"},
        "body_patterns": [r"Drupal\.settings", r"/sites/default/files/", r"drupal\.js"],
        "path_body_patterns": {
            "/core/misc/drupal.js": [r"Drupal"],
            "/user/login":         [r"Drupal", r"user-login"],
        },
        "version_pattern": r'<meta name="generator" content="Drupal\s*([\d.]+)"',
        "references": ["CWE-200", "OWASP A05:2021"],
    },
    {
        "name": "Magento",
        "paths": ["/admin/", "/skin/frontend/", "/js/mage/", "/downloader/"],
        "headers": {},
        "body_patterns": [r"Mage\.Cookies", r"/skin/frontend/default/", r"\bMagento\b"],
        "path_body_patterns": {
            "/admin/":         [r"\bMagento\b", r"Mage\.Cookies", r"Mage\.Menu"],
            "/skin/frontend/": [r"\bMagento\b", r"Mage\.Cookies"],
            "/js/mage/":       [r"Mage\.", r"\bmagento\b"],
            "/downloader/":    [r"\bMagento\b", r"Mage\."],
        },
        "version_pattern": r"Magento/([\d.]+)",
        "references": ["CWE-200", "OWASP A05:2021"],
    },
    {
        "name": "Apache Struts",
        "paths": ["/struts/", "/.action", "/.do"],
        "headers": {"X-Powered-By": r"Struts"},
        "body_patterns": [r"struts\.apache\.org", r"webwork"],
        "path_body_patterns": {
            "/.do":     [r"struts", r"webwork", r"action"],
            "/.action": [r"struts", r"webwork", r"action"],
        },
        "version_pattern": r"Struts/([\d.]+)",
        "references": ["CWE-200", "CVE-2017-5638", "OWASP A06:2021"],
    },
    {
        "name": "Laravel",
        "paths": ["/laravel/", "/.env"],
        "headers": {"X-Powered-By": r"PHP"},
        "body_patterns": [r"laravel_session", r"XSRF-TOKEN", r"csrf-token.*laravel"],
        "path_body_patterns": {
            "/.env": [r"APP_KEY", r"APP_ENV", r"DB_PASSWORD", r"DB_HOST"],
        },
        "version_pattern": r"Laravel/([\d.]+)",
        "references": ["CWE-200", "OWASP A05:2021"],
    },
    {
        "name": "Django",
        "paths": ["/admin/", "/static/admin/"],
        "headers": {"X-Framework": r"Django"},
        "body_patterns": [r"csrfmiddlewaretoken", r"django", r"Django administration"],
        "path_body_patterns": {
            "/admin/":        [r"Django administration", r"csrfmiddlewaretoken"],
            "/static/admin/": [r"django"],
        },
        "version_pattern": r"Django/([\d.]+)",
        "references": ["CWE-200", "OWASP A05:2021"],
    },
    {
        "name": "Strapi",
        "paths": ["/admin/", "/cms/admin/", "/strapi/admin/", "/cms/api/", "/strapi/api/"],
        "headers": {"X-Powered-By": r"Strapi"},
        "body_patterns": [r"strapi", r"Strapi"],
        "path_body_patterns": {
            "/cms/admin/":   [r"strapi", r"Strapi"],
            "/cms/api/":     [r"strapi", r"Forbidden", r"ForbiddenError"],
            "/strapi/api/":  [r"strapi", r"Forbidden"],
        },
        "version_pattern": r"strapi@([\d.]+)",
        "references": ["CWE-200", "OWASP A05:2021"],
    },
]

# SPA frameworks return HTTP 200 with the app shell for every unmatched route.
# These signatures identify SPA shells — if a homepage matches, path-based
# probing must use path_body_patterns to confirm real content.
SPA_INDICATORS = [
    r'<script[^>]+type=["\']module["\']',
    r'<div[^>]+id=["\']root["\']',
    r'<div[^>]+id=["\']app["\']',
    r'__NEXT_DATA__',
    r'window\.__nuxt__',
]


class CmsDetect(BaseModule):
    """CMS detection module — fingerprints common web platforms."""

    NAME        = "cms_detect"
    DESCRIPTION = "Detect CMS (WordPress/Joomla/Drupal/Magento/Struts) and version"
    PHASE       = 1
    TAGS        = ["recon", "cms", "fingerprint", "owasp-a05", "cwe-200"]

    async def run(self) -> ModuleResult:
        """Fingerprint the target for known CMS platforms."""
        start = time.monotonic()
        target = self.config.target.rstrip("/")

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        self.log.info("Starting CMS detection on %s", target)

        connector = aiohttp.TCPConnector(ssl=False)
        timeout   = aiohttp.ClientTimeout(total=10)
        headers   = {
            "User-Agent": "Mozilla/5.0 (forge-suite cms_detect)",
            "Accept-Encoding": "gzip, deflate",  # avoid brotli — not supported by aiohttp
        }

        async with aiohttp.ClientSession(connector=connector, timeout=timeout, headers=headers) as session:
            # Fetch homepage for body-pattern matching
            home_body = ""
            home_headers: dict = {}
            try:
                await self.rate_limit()
                async with session.get(target) as resp:
                    home_body    = await resp.text(errors="ignore")
                    home_headers = dict(resp.headers)
            except Exception as exc:
                self.log.warning("Failed to fetch homepage: %s", exc)

            # Detect SPA shells so path-probing uses content validation
            is_spa = any(re.search(pat, home_body, re.I) for pat in SPA_INDICATORS)
            if is_spa:
                self.log.info("SPA shell detected — path probing will validate response body")

            for cms in CMS_SIGNATURES:
                await self._check_cms(session, target, cms, home_body, home_headers, is_spa)

        return self._make_result(start)

    async def _check_cms(
        self,
        session: aiohttp.ClientSession,
        target: str,
        cms: dict,
        home_body: str,
        home_headers: dict,
        is_spa: bool = False,
    ) -> None:
        """Check if the target matches a given CMS signature."""
        matched   = False
        version   = "unknown"
        probe_url = target

        # Header matching (always reliable)
        for header_name, pattern in cms.get("headers", {}).items():
            val = home_headers.get(header_name, "")
            if re.search(pattern, val, re.I):
                matched = True

        # Body pattern matching on homepage (skip for SPA — home body is app shell)
        if not is_spa:
            for pattern in cms.get("body_patterns", []):
                if re.search(pattern, home_body, re.I):
                    matched = True
                    break

        # Version extraction from homepage (only if matched via body/headers)
        if matched:
            ver_pat = cms.get("version_pattern", "")
            if ver_pat:
                m = re.search(ver_pat, home_body, re.I)
                if m:
                    version = m.group(1)

        # Path probing — for SPAs, response body must confirm CMS-specific content
        path_body_patterns: dict = cms.get("path_body_patterns", {})
        for path in cms.get("paths", []):
            url = f"{target}{path}"
            if not self.check_scope(url):
                continue
            try:
                await self.rate_limit()
                async with session.get(url, allow_redirects=False) as resp:
                    if resp.status not in (200, 301, 302, 403):
                        continue
                    body = await resp.text(errors="ignore")
                    content_type = resp.headers.get("Content-Type", "")

                    # For SPA sites every unmatched URL returns index.html with HTTP 200.
                    # Only accept a path hit when body content confirms the CMS is real.
                    confirm_patterns = path_body_patterns.get(path, [])
                    if is_spa:
                        if not confirm_patterns:
                            # No patterns defined — can't distinguish SPA shell from real
                            # content; skip this path entirely on SPA targets.
                            continue
                        body_confirmed = any(
                            re.search(pat, body, re.I) for pat in confirm_patterns
                        )
                        if not body_confirmed:
                            continue  # SPA returned its shell — not a real CMS path
                    elif confirm_patterns:
                        # Non-SPA but explicit patterns defined — still validate
                        if not any(re.search(pat, body, re.I) for pat in confirm_patterns):
                            continue

                    matched = True
                    probe_url = url
                    ver_pat = cms.get("version_pattern", "")
                    if ver_pat:
                        m = re.search(ver_pat, body, re.I)
                        if m:
                            version = m.group(1)
            except Exception:
                pass

        if matched:
            ev = Evidence(
                request_raw=f"GET {probe_url} HTTP/1.1",
                response_raw=home_body[:500],
                extra={"cms": cms["name"], "version": version},
            )
            self.new_finding(
                title=f"CMS Detected: {cms['name']} (version: {version})",
                severity=Severity.INFORMATIONAL,
                description=(
                    f"The target appears to be running {cms['name']} version {version}. "
                    "Knowing the CMS version enables targeted vulnerability research."
                ),
                reproduction_steps=[
                    f"Browse to {probe_url}",
                    f"Observe {cms['name']} indicators in response headers/body",
                ],
                remediation=(
                    "Remove or obfuscate CMS version information from HTTP responses "
                    "and HTML source. Keep the CMS and all plugins up to date."
                ),
                references=cms["references"],
                evidence=ev,
                cvss_v31_vector=CVSS_CMS_VERSION,
                target=target,
            )
            self.log.info("CMS detected: %s v%s on %s", cms["name"], version, target)


class TestCmsDetect:
    def test_signature_list_non_empty(self) -> None:
        assert len(CMS_SIGNATURES) >= 5

    def test_each_cms_has_required_keys(self) -> None:
        required = {"name", "paths", "body_patterns", "version_pattern", "references"}
        for cms in CMS_SIGNATURES:
            assert required.issubset(cms.keys()), f"Missing keys in {cms.get('name')}"

    def test_cvss_vectors_format(self) -> None:
        for vec in (CVSS_CMS_VERSION, CVSS_CMS_EXPOSED):
            assert vec.startswith("CVSS:3.1/")
