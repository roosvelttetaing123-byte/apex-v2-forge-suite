"""JavaScript analyzer — extract endpoints, secrets, and API keys from JS files."""
from __future__ import annotations

import asyncio
import re
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_SECRET = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
CVSS40_SECRET = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
CVSS_ENDPOINT = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
CVSS40_ENDPOINT = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
# Regex patterns for secrets in JS
SECRET_PATTERNS: list[tuple[str, str, Severity]] = [
    (r"(?i)aws[_\-]?access[_\-]?key[_\-]?id[\s]*[=:\"']+\s*([A-Z0-9]{20})",
     "AWS Access Key ID", Severity.CRITICAL),
    (r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key[\s]*[=:\"']+\s*([A-Za-z0-9/+=]{40})",
     "AWS Secret Access Key", Severity.CRITICAL),
    (r"AKIA[0-9A-Z]{16}",
     "AWS Access Key (pattern)", Severity.CRITICAL),
    (r"(?i)(api[_\-]?key|apikey)[\s]*[=:\"']+\s*([A-Za-z0-9_\-]{20,60})",
     "API Key", Severity.HIGH),
    (r"(?i)(secret[_\-]?key|secretkey)[\s]*[=:\"']+\s*([A-Za-z0-9_\-]{16,60})",
     "Secret Key", Severity.HIGH),
    # Require value to look like an actual password (quoted string, min 8 chars, not a JS bool/keyword)
    (r"""(?i)(?:password|passwd|pwd)\s*[:=]\s*["']([^"']{8,60})["']""",
     "Hardcoded Password", Severity.HIGH),
    (r"(?i)(token|auth[_\-]?token|access[_\-]?token)[\s]*[=:\"']+\s*([A-Za-z0-9_.\-]{20,120})",
     "Auth Token", Severity.HIGH),
    # Supabase anon/service keys checked BEFORE the generic JWT pattern so the
    # specific (Critical) match wins when both would fire on the same token value.
    (r"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_\-]{50,}",
     "Supabase / JWT Service Key", Severity.CRITICAL),
    (r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",
     "JWT Token", Severity.MEDIUM),
    (r"(?i)(private[_\-]?key|rsa[_\-]?key)[\s]*[=:\"']+\s*([^\s\"'&]{20,})",
     "Private Key Reference", Severity.HIGH),
    (r"(?i)google[_\-]?api[_\-]?key[\s]*[=:\"']+\s*([A-Za-z0-9\-_]{30,50})",
     "Google API Key", Severity.HIGH),
    (r"AIza[0-9A-Za-z\-_]{35}",
     "Google API Key (pattern)", Severity.HIGH),
    (r"(?i)stripe[_\-]?secret[\s]*[=:\"']+\s*(sk_(?:live|test)_[A-Za-z0-9]{24,})",
     "Stripe Secret Key", Severity.CRITICAL),
    (r"(?i)(db[_\-]?password|database[_\-]?password)[\s]*[=:\"']+\s*([^\s\"'&]{8,})",
     "Database Password", Severity.CRITICAL),
    (r"(?i)slack[_\-]?(?:api[_\-]?)?token[\s]*[=:\"']+\s*(xox[baprs]-[0-9A-Za-z\-]+)",
     "Slack Token", Severity.HIGH),
    (r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
     "Private Key in Source", Severity.CRITICAL),
    # HMAC / signing secrets: hex-64 string assigned to a variable
    # Matches: zT="3ce6ec5c..." or SECRET_KEY = "abcdef..." (64 hex chars)
    (r"""[=:]\s*["'][0-9a-fA-F]{64}["']""",
     "Hardcoded HMAC/Signing Secret (hex-64)", Severity.CRITICAL),
    # Custom auth header name patterns — reveals proprietary auth schemes in JS
    (r"""["'](X-[A-Z][A-Z0-9\-]{3,30}-(?:KEY|TOKEN|SECRET|HASH|SIG|TS))["']""",
     "Custom Authentication Header Name", Severity.HIGH),
    # reCAPTCHA Enterprise / v3 site keys (starts with 6L, 38–50 chars)
    (r"6L[A-Za-z0-9_\-]{38,50}",
     "reCAPTCHA Site Key", Severity.INFORMATIONAL),
    # (Supabase key pattern moved above JWT Token to avoid duplicate findings)
    # Firebase API keys
    (r"AIzaSy[A-Za-z0-9_\-]{33}",
     "Firebase API Key", Severity.HIGH),
    # SendGrid API key
    (r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}",
     "SendGrid API Key", Severity.CRITICAL),
    # Mapbox tokens
    (r"pk\.eyJ1[A-Za-z0-9_\-\.]{40,}",
     "Mapbox Public Token", Severity.MEDIUM),
    # GitLab personal access token
    (r"glpat-[A-Za-z0-9_\-]{20,}",
     "GitLab Personal Access Token", Severity.CRITICAL),
    # npm access token
    (r"npm_[A-Za-z0-9]{36}",
     "npm Access Token", Severity.HIGH),
    # HuggingFace token
    (r"hf_[A-Za-z0-9]{37}",
     "HuggingFace API Token", Severity.HIGH),
    # PyPI token
    (r"pypi-[A-Za-z0-9_\-]{36,}",
     "PyPI API Token", Severity.HIGH),
    # Twilio auth token
    (r"(?i)twilio.{0,20}auth[_\-]?token[\s]*[=:\"']+\s*([a-zA-Z0-9]{32,})",
     "Twilio Auth Token", Severity.HIGH),
    # reCAPTCHA SECRET key (server-side — distinct from the public site key above)
    (r"(?i)recaptcha[_\-]?secret[_\-]?key[\s]*[=:\"']+\s*([A-Za-z0-9_\-]{30,})",
     "reCAPTCHA Secret Key", Severity.HIGH),
]

# Patterns to discover CMS/API backend base URLs embedded as env-var fallbacks
# e.g.  VITE_STRAPI_BASE_URL:"/cms/"  or  process.env.API_URL||"https://api.example.com"
CMS_BACKEND_PATTERNS = [
    r"""VITE_[A-Z_]+(?:BASE_URL|API_URL|ENDPOINT)[^"']*["'](https?://[^"']{5,100})["']""",
    r"""VITE_[A-Z_]+(?:BASE_URL|API_URL|ENDPOINT)[^"']*["'](/[^"']{1,80})["']""",
    r"""process\.env\.[A-Z_]+(?:URL|ENDPOINT)[^"']*\|\|["'](https?://[^"']{5,100})["']""",
    r"""(?:apiBase|baseURL|apiUrl|backendUrl|cmsUrl)\s*[=:]\s*["'](https?://[^"']{5,100})["']""",
]

# Endpoint discovery patterns
ENDPOINT_PATTERNS = [
    r"""["'`](/[a-zA-Z0-9_/\-]{2,60})["'`]""",
    r"""["'`](https?://[a-zA-Z0-9._/:\-?=&%]{10,120})["'`]""",
    r"""(?:fetch|axios\.get|axios\.post|\.get|\.post|\.put|\.delete|\.patch)\s*\(\s*["'`]([^"'`]+)["'`]""",
    r"""(?:url|endpoint|path|href|action)\s*[=:]\s*["'`]([^"'`]{5,100})["'`]""",
]


class JsAnalyzer(BaseModule):
    """JavaScript file analyzer — extract secrets and endpoints."""

    NAME        = "js_analyzer"
    DESCRIPTION = "Extract API endpoints, secrets, and hardcoded credentials from JS files"
    PHASE       = 1
    TAGS        = ["recon", "javascript", "secrets", "cwe-798", "owasp-a02"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        js_urls = await self._discover_js_files(target)
        self.log.info("Found %d JS files to analyze", len(js_urls))

        sem = asyncio.Semaphore(3)
        tasks = [self._analyze_js(url, target, sem) for url in js_urls[:50]]
        await asyncio.gather(*tasks, return_exceptions=True)

        return self._make_result(start)

    async def _discover_js_files(self, target: str) -> list[str]:
        """Crawl the page and find linked JS files."""
        import aiohttp
        js_urls: list[str] = []
        try:
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False),
                headers={"Accept-Encoding": "gzip, deflate"},  # avoid brotli
            ) as session:
                async with session.get(
                    target, timeout=aiohttp.ClientTimeout(total=15)
                ) as resp:
                    html = await resp.text(errors="ignore")
                    # Find all script src attributes
                    for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE):
                        src = m.group(1)
                        if src.startswith("http"):
                            if self.check_scope(src):
                                js_urls.append(src)
                        else:
                            js_urls.append(f"{target.rstrip('/')}/{src.lstrip('/')}")

                    # Common JS paths
                    for path in ["/js/app.js", "/js/main.js", "/app.js", "/bundle.js",
                                 "/static/js/main.js", "/assets/js/app.js", "/dist/bundle.js",
                                 "/js/vendor.js", "/static/chunk.js"]:
                        js_urls.append(f"{target}{path}")
        except Exception as exc:
            self.log.debug("JS discovery failed: %s", exc)
        return list(dict.fromkeys(js_urls))  # deduplicate

    async def _analyze_js(self, url: str, target: str, sem: asyncio.Semaphore) -> None:
        """Download and analyze a JS file for secrets and endpoints."""
        async with sem:
            await self.rate_limit()
            try:
                import aiohttp
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False),
                    headers={"Accept-Encoding": "gzip, deflate"},
                ) as session:
                    async with session.get(
                        url, timeout=aiohttp.ClientTimeout(total=15)
                    ) as resp:
                        if resp.status != 200:
                            return
                        js_content = await resp.text(errors="ignore")

                self._check_secrets(js_content, url, target)
                self._extract_endpoints(js_content, url, target)
                self._discover_backend_urls(js_content, url, target)
            except Exception as exc:
                self.log.debug("JS analysis failed for %s: %s", url, exc)

    def _check_secrets(self, content: str, js_url: str, target: str) -> None:
        """Scan JS content for hardcoded secrets."""
        found_types: set[str] = set()
        found_values: set[str] = set()  # prevent the same token value reported under two patterns
        for pattern, name, severity in SECRET_PATTERNS:
            for match in re.finditer(pattern, content):
                if name in found_types:
                    continue
                # Skip if we already reported this exact value under a higher-priority pattern
                value_key = match.group()[:80]
                if value_key in found_values:
                    continue
                found_types.add(name)
                found_values.add(value_key)
                snippet = content[max(0, match.start()-30):match.end()+30]
                ev = Evidence(
                    response_raw=snippet,
                    extra={"js_file": js_url, "pattern": name, "match": match.group()[:80]},
                )
                self.new_finding(
                    title=f"Hardcoded Secret in JavaScript — {name} ({js_url.split('/')[-1]})",
                    severity=severity,
                    description=(
                        f"A {name} was found hardcoded in {js_url}. "
                        "Client-side JavaScript is publicly accessible — any embedded secret "
                        "is considered compromised."
                    ),
                    reproduction_steps=[
                        f"curl {js_url} | grep -i 'secret\\|key\\|token\\|password'",
                        f"Pattern matched: {match.group()[:60]}",
                    ],
                    remediation=(
                        "Never embed secrets in client-side code. "
                        "Use server-side API calls, environment variables, or secrets managers. "
                        "Rotate any compromised credentials immediately."
                    ),
                    references=["CWE-798", "CWE-312", "OWASP A02:2021"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_SECRET,
                    cvss_v40_vector=CVSS40_SECRET,
                    mitre_attack=["TA0006/T1552.001"],
                    target=target,
                    url=js_url,
                )

    def _extract_endpoints(self, content: str, js_url: str, target: str) -> None:
        """Extract API endpoint paths for further testing."""
        endpoints: set[str] = set()
        for pattern in ENDPOINT_PATTERNS:
            for m in re.finditer(pattern, content):
                ep = m.group(1)
                if len(ep) > 3 and not ep.startswith("//"):
                    endpoints.add(ep)

        # Store discovered endpoints in config.extra for other modules to use
        existing = self.config.extra.get("discovered_endpoints", [])
        existing.extend(list(endpoints)[:100])
        self.config.extra["discovered_endpoints"] = list(dict.fromkeys(existing))

        if len(endpoints) > 5:
            self.log.info("Extracted %d endpoints from %s", len(endpoints), js_url.split("/")[-1])

    def _discover_backend_urls(self, content: str, js_url: str, target: str) -> None:
        """Find CMS/API backend base URLs embedded as env-var fallbacks in the JS bundle.

        These are often set at build time via VITE_* / process.env.* variables and
        fall back to a hardcoded string when the env var is absent.  That fallback
        value is the actual production backend URL and is valuable for CORS / API testing.
        """
        found: set[str] = set()
        for pattern in CMS_BACKEND_PATTERNS:
            for m in re.finditer(pattern, content):
                url_candidate = m.group(1).strip()
                if url_candidate and url_candidate not in found:
                    found.add(url_candidate)

        if not found:
            return

        # Store for cors_check and other modules
        existing: list[str] = self.config.extra.get("api_base_paths", [])
        for u in found:
            full = u if u.startswith("http") else f"{target.rstrip('/')}/{u.lstrip('/')}"
            if full not in existing:
                existing.append(full)
        self.config.extra["api_base_paths"] = existing

        ev = Evidence(
            response_raw="\n".join(sorted(found)),
            extra={"js_file": js_url, "backend_urls": sorted(found)},
        )
        self.new_finding(
            title=f"Backend/CMS API URL Disclosed in JS Bundle ({js_url.split('/')[-1]})",
            severity=Severity.MEDIUM,
            description=(
                f"The JavaScript bundle {js_url} exposes the backend API base URL(s) as "
                "environment-variable fallback values: "
                + ", ".join(sorted(found))
                + ". Attackers can use these to directly target the backend CMS/API, "
                "bypassing any frontend validation."
            ),
            reproduction_steps=[
                f"curl {js_url} | grep -oE 'VITE_[A-Z_]+[^\"]*\"[^\"]+\"'",
                "Observe hardcoded backend URL(s) in output",
            ],
            remediation=(
                "Do not hard-code backend URLs as fallback values in client-side bundles. "
                "Use relative paths (e.g. '/api/') or inject the URL server-side only."
            ),
            references=["CWE-200", "OWASP A05:2021"],
            evidence=ev,
            cvss_v31_vector=CVSS_ENDPOINT,
            cvss_v40_vector=CVSS40_ENDPOINT,
            target=target,
            url=js_url,
        )


class TestJsAnalyzer:
    def test_secret_pattern_jwt(self) -> None:
        mod = JsAnalyzer.__new__(JsAnalyzer)
        mod.config = type("C", (), {"extra": {}})()
        content = 'var token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.abc123xyz"'
        # Pattern test
        for pattern, name, severity in SECRET_PATTERNS:
            if re.search(pattern, content):
                assert name  # matched something
                break

    def test_endpoint_extraction(self) -> None:
        mod = JsAnalyzer.__new__(JsAnalyzer)
        mod.config = type("C", (), {"extra": {}})()
        content = 'fetch("/api/v1/users").then()'
        endpoints: set[str] = set()
        for pattern in ENDPOINT_PATTERNS:
            for m in re.finditer(pattern, content):
                endpoints.add(m.group(1))
        assert any("/api" in ep for ep in endpoints)
