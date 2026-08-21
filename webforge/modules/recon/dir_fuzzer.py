"""Directory / path fuzzer — brute-force hidden paths with wordlist and smart extensions."""
from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence, save_http_evidence
from common.finding import Severity

CVSS_DIR_LISTING  = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
CVSS40_DIR_LISTING = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
CVSS_SENSITIVE    = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
CVSS40_SENSITIVE  = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
CVSS_ADMIN_PANEL  = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
CVSS40_ADMIN_PANEL = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N"
INTERESTING_EXTENSIONS = [".php", ".asp", ".aspx", ".jsp", ".bak", ".old",
                           ".txt", ".log", ".sql", ".config", ".env", ".json",
                           ".xml", ".yaml", ".yml", ".zip", ".tar.gz", ".backup"]

SENSITIVE_PATHS = {
    "/.env", "/.git/HEAD", "/web.config", "/phpinfo.php", "/info.php",
    "/server-status", "/server-info", "/.htaccess", "/.htpasswd",
    "/wp-config.php", "/config.php", "/database.yml", "/settings.py",
    "/application.properties", "/.DS_Store", "/Thumbs.db",
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/backup.zip", "/backup.tar.gz", "/dump.sql", "/db.sql",
    "/adminer.php", "/phpmyadmin/", "/phpMyAdmin/", "/_profiler/",
}

ADMIN_PATHS = {
    "/admin", "/admin/", "/administrator", "/wp-admin", "/cpanel",
    "/panel", "/dashboard", "/manage", "/management", "/control",
    "/backend", "/secure", "/staff", "/manager", "/system",
}

DEFAULT_WORDLIST = [
    "admin", "login", "wp-admin", "administrator", "panel", "dashboard",
    "api", "v1", "v2", "v3", "api/v1", "api/v2", "api/v3",
    "static", "assets", "files", "uploads", "media", "images",
    "config", "configuration", "settings", "setup", "install",
    "backup", "backups", "bak", "old", "archive", "archives",
    "tmp", "temp", "cache", "logs", "log", "debug",
    "test", "dev", "development", "staging", "qa",
    "user", "users", "account", "accounts", "profile", "profiles",
    "register", "signup", "signin", "logout", "auth",
    "docs", "doc", "documentation", "swagger", "openapi",
    "health", "status", "ping", "metrics", "monitoring",
    "console", "terminal", "shell", "cmd",
    "phpinfo", "info", "phpMyAdmin", "phpmyadmin", "adminer",
    ".git", ".env", ".htaccess", "robots.txt", "sitemap.xml",
    "server-status", "server-info", "crossdomain.xml",
    "wp-content", "wp-includes", "wp-login",
]


class DirFuzzer(BaseModule):
    """Directory and path fuzzer — discovers hidden endpoints and sensitive files."""

    NAME        = "dir_fuzzer"
    DESCRIPTION = "Brute-force hidden directories and files using wordlist + smart detection"
    PHASE       = 1
    TAGS        = ["recon", "directory", "fuzzing", "cwe-200", "owasp-a01"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        wordlist = self._load_wordlist()
        self.log.info("Dir fuzzing %s with %d paths", target, len(wordlist))

        # Detect SPA catch-all routing once; pass fingerprint to all sub-checks
        # so they can skip paths that just return the app shell.
        self._spa_fp = await self._spa_fingerprint(target)
        if self._spa_fp:
            self.log.info("SPA catch-all detected — filtering false-positive admin/sensitive findings")
        self._soft404_fps = await self._soft_404_fingerprints(target)
        if self._soft404_fps:
            self.log.info("Soft-404/firewall baseline detected — filtering placeholder responses")

        await self._check_known_sensitive(target)
        await self._check_admin_panels(target)

        sem = asyncio.Semaphore(5)
        tasks = [self._probe(target, path, sem) for path in wordlist]
        await asyncio.gather(*tasks, return_exceptions=True)

        return self._make_result(start)

    async def _check_known_sensitive(self, target: str) -> None:
        """Check a fixed set of high-value sensitive paths."""
        spa_fp = getattr(self, "_spa_fp", None)
        for path in SENSITIVE_PATHS:
            await self.rate_limit()
            try:
                async with self._session() as session:
                    async with session.get(
                        f"{target}{path}", allow_redirects=False, timeout=8
                    ) as resp:
                        if resp.status in (200, 206):
                            body = await resp.text(errors="ignore")
                            # Skip if the response is just the SPA shell —
                            # Vercel/Next.js returns index.html for all unknown paths.
                            if self._is_spa_body(body, spa_fp):
                                continue
                            if self._is_placeholder_response(body, resp.status, resp.headers):
                                continue
                            if not self._has_sensitive_content(path, body):
                                self.log.debug("Skipping %s: no path-specific sensitive evidence", path)
                                continue
                            await self._report_sensitive(target, path, resp.status, body, resp.headers)
            except Exception:
                pass

    async def _check_admin_panels(self, target: str) -> None:
        """Check admin panel paths."""
        spa_fp = getattr(self, "_spa_fp", None)
        for path in ADMIN_PATHS:
            await self.rate_limit()
            try:
                async with self._session() as session:
                    async with session.get(
                        f"{target}{path}", allow_redirects=True, timeout=8
                    ) as resp:
                        if resp.status in (200, 401, 403):
                            body = await resp.text(errors="ignore")
                            # A 200 that returns the same body as a random non-existent
                            # path is the SPA catch-all, not a real admin interface.
                            if resp.status == 200 and self._is_spa_body(body, spa_fp):
                                continue
                            if self._is_placeholder_response(body, resp.status, resp.headers):
                                continue
                            title = self._extract_title(body)
                            if resp.status == 200 and not self._looks_like_admin_panel(path, title, body):
                                continue
                            ev = Evidence(
                                request_raw=f"GET {path} HTTP/1.1\nHost: {target}",
                                response_raw=body[:500],
                                extra={"path": path, "status": resp.status, "title": title},
                            )
                            self.new_finding(
                                title=f"Admin Panel Detected — {path} ({resp.status})",
                                severity=Severity.MEDIUM,
                                description=(
                                    f"An administrative interface was found at {target}{path} "
                                    f"(HTTP {resp.status}). Title: '{title}'. "
                                    "Admin panels exposed to the internet increase attack surface significantly."
                                ),
                                reproduction_steps=[f"curl -i {target}{path}"],
                                remediation=(
                                    "Restrict admin panel access by IP whitelist. "
                                    "Add MFA to all admin interfaces. "
                                    "Consider moving admin interfaces off public-facing hosts."
                                ),
                                references=["OWASP A01:2021", "CWE-200"],
                                evidence=ev,
                                cvss_v31_vector=CVSS_ADMIN_PANEL,
                                cvss_v40_vector=CVSS40_ADMIN_PANEL,
                                mitre_attack=["TA0007/T1590"],
                                target=target,
                                url=f"{target}{path}",
                            )
            except Exception:
                pass

    async def _probe(self, target: str, path: str, sem: asyncio.Semaphore) -> None:
        """Probe a single path and report interesting findings."""
        clean_path = f"/{path.lstrip('/')}"
        async with sem:
            await self.rate_limit()
            try:
                async with self._session() as session:
                    async with session.get(
                        f"{target}{clean_path}", allow_redirects=False, timeout=8
                    ) as resp:
                        if resp.status == 200:
                            body = await resp.text(errors="ignore")
                            ctype = resp.headers.get("Content-Type", "")

                            # Directory listing
                            if "Index of /" in body or "Directory listing" in body:
                                if self._is_placeholder_response(body, resp.status, resp.headers):
                                    return
                                ev = Evidence(
                                    request_raw=f"GET {clean_path} HTTP/1.1",
                                    response_raw=body[:1000],
                                    extra={"path": clean_path, "status": 200},
                                )
                                ev.screenshot_path = self.capture_screenshot(
                                    f"{target}{clean_path}", finding_id=f"dirlist_{clean_path}"
                                )
                                self.new_finding(
                                    title=f"Directory Listing Enabled — {clean_path}",
                                    severity=Severity.LOW,
                                    description=(
                                        f"Directory listing is enabled at {target}{clean_path}. "
                                        "This exposes internal file structure and may reveal sensitive files."
                                    ),
                                    reproduction_steps=[f"curl {target}{clean_path}"],
                                    remediation="Disable directory listing in web server configuration.",
                                    references=["CWE-548"],
                                    evidence=ev,
                                    cvss_v31_vector=CVSS_DIR_LISTING,
                                    cvss_v40_vector=CVSS40_DIR_LISTING,
                                    target=target,
                                    url=f"{target}{clean_path}",
                                )
            except Exception:
                pass

    async def _report_sensitive(
        self, target: str, path: str, status: int, body: str, headers: Any
    ) -> None:
        """Report a sensitive file finding."""
        severity = Severity.HIGH
        description = f"Sensitive file/path accessible at {target}{path} (HTTP {status})."

        # Standard web files are NOT sensitive — downgrade
        if path in ("/robots.txt", "/sitemap.xml", "/crossdomain.xml",
                     "/clientaccesspolicy.xml", "/favicon.ico"):
            severity = Severity.INFORMATIONAL
            description = f"Standard web file found at {target}{path} (HTTP {status})."
            if path == "/robots.txt" and any(
                kw in body.lower() for kw in ("admin", "internal", "secret", "private", "api/v")
            ):
                severity = Severity.LOW
                description += " robots.txt leaks potentially sensitive paths."
        elif ".env" in path:
            severity = Severity.CRITICAL
            description += " .env files often contain database credentials, API keys, and secrets."
        elif ".git" in path:
            severity = Severity.HIGH
            description += " Exposed .git directory allows source code reconstruction."
        elif "config" in path.lower() or "settings" in path.lower():
            severity = Severity.HIGH
            description += " Configuration files may contain credentials and internal paths."
        elif path.endswith((".sql", ".dump")):
            severity = Severity.CRITICAL
            description += " Database dumps contain sensitive data and credentials."
        elif "backup" in path.lower() or ".bak" in path:
            severity = Severity.HIGH
            description += " Backup files may contain source code or configuration."

        ev = Evidence(
            request_raw=f"GET {path} HTTP/1.1\nHost: {target}",
            response_raw=body[:500],
            extra={"path": path, "status": status, "size": len(body)},
        )
        ev.screenshot_path = self.capture_screenshot(
            f"{target}{path}", finding_id=f"sensitive_{path.replace('/', '_')}"
        )
        self.new_finding(
            title=f"Sensitive File Exposed — {path}",
            severity=severity,
            description=description,
            reproduction_steps=[f"curl -i {target}{path}"],
            remediation=(
                "Remove or restrict access to sensitive files. "
                "Add deny rules in .htaccess/nginx/Apache config. "
                "Ensure .git, .env, and config files are never deployed to web roots."
            ),
            references=["CWE-200", "CWE-538", "OWASP A01:2021"],
            evidence=ev,
            cvss_v31_vector=CVSS_SENSITIVE,
            cvss_v40_vector=CVSS40_SENSITIVE,
            mitre_attack=["TA0007/T1083"],
            target=target,
            url=f"{target}{path}",
        )

    def _session(self):
        """Get aiohttp session from config."""
        import aiohttp
        connector = aiohttp.TCPConnector(ssl=False)
        return aiohttp.ClientSession(connector=connector, headers={"User-Agent": "Mozilla/5.0"})

    def _extract_title(self, html: str) -> str:
        import re
        m = re.search(r"<title[^>]*>([^<]+)</title>", html, re.IGNORECASE)
        return m.group(1).strip()[:80] if m else ""

    def _load_wordlist(self) -> list[str]:
        wl_path = (
            Path(__file__).parent.parent.parent
            / "data" / "wordlists" / "directories.txt"
        )
        if wl_path.exists():
            lines = wl_path.read_text().splitlines()
            return [l.strip() for l in lines if l.strip() and not l.startswith("#")]
        return DEFAULT_WORDLIST

    def _is_placeholder_response(self, body: str, status: int, headers: Any) -> bool:
        """Filter WAF/firewall block pages and unknown-path soft responses."""
        if self._is_waf_placeholder(body, status, headers):
            return True
        return self._is_soft_404_body(
            body,
            status,
            getattr(self, "_soft404_fps", set()),
        )

    def _has_sensitive_content(self, path: str, body: str) -> bool:
        """Require content-specific proof before reporting sensitive path exposure."""
        lower_path = path.lower()
        sample = body[:12000]
        sample_lower = sample.lower()
        if ".env" in lower_path:
            return any(
                token in sample
                for token in ("APP_KEY=", "APP_SECRET=", "DB_PASSWORD=", "DATABASE_URL=", "AWS_SECRET_ACCESS_KEY=")
            )
        if ".git/head" in lower_path:
            return "ref: refs/heads/" in sample_lower or sample.strip().startswith(("ref:", "000000"))
        if lower_path.endswith((".htaccess", ".htpasswd")):
            return any(token in sample_lower for token in ("rewriteengine", "authuserfile", "authtype", "require valid-user"))
        if "phpinfo" in lower_path or lower_path.endswith("/info.php"):
            return "php version" in sample_lower and "phpinfo()" in sample_lower
        if "server-status" in lower_path:
            return "apache server status" in sample_lower or "server uptime" in sample_lower
        if "server-info" in lower_path:
            return "apache server information" in sample_lower or "server settings" in sample_lower
        if "web.config" in lower_path:
            return "<configuration" in sample_lower or "<system.webserver" in sample_lower
        if lower_path.endswith((".sql", ".dump")):
            return any(token in sample_lower for token in ("create table", "insert into", "mysqldump", "postgresql database dump"))
        if "backup" in lower_path or lower_path.endswith((".bak", ".zip", ".tar.gz", ".backup")):
            ctype = sample[:4]
            return ctype.startswith(("PK", "\x1f\x8b")) or len(body) > 4096
        if lower_path.endswith((".json", ".yaml", ".yml", ".xml", ".config")):
            return any(token in sample_lower for token in ("password", "secret", "connectionstring", "api_key", "apikey"))
        return len(body.strip()) > 0

    def _looks_like_admin_panel(self, path: str, title: str, body: str) -> bool:
        """Avoid treating every HTTP 200 app shell as an admin panel."""
        haystack = f"{path} {title} {body[:2000]}".lower()
        admin_terms = ("admin", "administrator", "dashboard", "control panel", "management", "sign in", "login")
        return any(term in haystack for term in admin_terms)


class TestDirFuzzer:
    def test_load_wordlist_fallback(self) -> None:
        mod = DirFuzzer.__new__(DirFuzzer)
        mod.config = type("C", (), {"extra": {}})()
        wl = mod._load_wordlist()
        assert isinstance(wl, list)
        assert len(wl) > 0

    def test_extract_title(self) -> None:
        mod = DirFuzzer.__new__(DirFuzzer)
        html = "<html><head><title>Admin Panel</title></head></html>"
        assert mod._extract_title(html) == "Admin Panel"

    def test_extract_title_missing(self) -> None:
        mod = DirFuzzer.__new__(DirFuzzer)
        assert mod._extract_title("<html></html>") == ""
