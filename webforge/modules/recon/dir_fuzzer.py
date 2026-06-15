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
CVSS_SENSITIVE    = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
CVSS_ADMIN_PANEL  = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"

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

        self._catchall = False
        wordlist = self._load_wordlist()
        self.log.info("Dir fuzzing %s with %d paths", target, len(wordlist))

        # Detect catch-all SPA (returns 200 for random paths — all results would be FPs)
        self._catchall = await self._detect_catchall(target)
        if self._catchall:
            self.log.info("Catch-all SPA detected — suppressing 200 admin/dir findings")

        # First check the sensitive/admin paths
        await self._check_known_sensitive(target)
        await self._check_admin_panels(target)

        # Then fuzz with wordlist (rate-limited)
        sem = asyncio.Semaphore(5)
        tasks = [self._probe(target, path, sem) for path in wordlist]
        await asyncio.gather(*tasks, return_exceptions=True)

        return self._make_result(start)

    async def _detect_catchall(self, target: str) -> bool:
        """Return True if the server returns 200 for a random non-existent path (SPA catch-all)."""
        import uuid
        canary = f"/forge-canary-{uuid.uuid4().hex[:10]}"
        try:
            async with self._session() as session:
                async with session.get(f"{target}{canary}", allow_redirects=True, timeout=8) as resp:
                    if resp.status == 200:
                        body = await resp.text(errors="ignore")
                        home_title = ""
                        try:
                            async with session.get(target, allow_redirects=True, timeout=8) as hr:
                                home_body = await hr.text(errors="ignore")
                                home_title = self._extract_title(home_body)
                        except Exception:
                            pass
                        canary_title = self._extract_title(body)
                        if canary_title and canary_title == home_title:
                            return True
                        if len(body) > 500:
                            return True
        except Exception:
            pass
        return False

    async def _check_known_sensitive(self, target: str) -> None:
        """Check a fixed set of high-value sensitive paths."""
        for path in SENSITIVE_PATHS:
            await self.rate_limit()
            try:
                async with self._session() as session:
                    async with session.get(
                        f"{target}{path}", allow_redirects=False, timeout=8
                    ) as resp:
                        if resp.status in (200, 206):
                            body = await resp.text(errors="ignore")
                            if self._catchall:
                                # Validate content looks real, not SPA index
                                if path == "/.git/HEAD" and "ref:" not in body:
                                    continue
                                if path == "/.env" and "=" not in body:
                                    continue
                                if ".bak" in path or ".sql" in path or ".zip" in path:
                                    if len(body) < 100:
                                        continue
                            await self._report_sensitive(target, path, resp.status, body, resp.headers)
            except Exception:
                pass

    async def _check_admin_panels(self, target: str) -> None:
        """Check admin panel paths."""
        for path in ADMIN_PATHS:
            await self.rate_limit()
            try:
                async with self._session() as session:
                    async with session.get(
                        f"{target}{path}", allow_redirects=True, timeout=8
                    ) as resp:
                        # For catch-all SPAs, only report 401/403 (actual auth gates)
                        if self._catchall and resp.status == 200:
                            continue
                        if resp.status in (200, 401, 403):
                            body = await resp.text(errors="ignore")
                            title = self._extract_title(body)
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
                                ev = Evidence(
                                    request_raw=f"GET {clean_path} HTTP/1.1",
                                    response_raw=body[:1000],
                                    extra={"path": clean_path, "status": 200},
                                )
                                ev.screenshot_path = await self.capture_screenshot(
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

        if ".env" in path:
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
        ev.screenshot_path = await self.capture_screenshot(
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
