"""Backup File Scanner — discovers exposed backup, temp, and config files.

Nessus equivalent: 11424, 10932 (Backup file disclosure).
"""
from __future__ import annotations

import asyncio
import time
from typing import Any

from common.base_module import BaseModule, ModuleResult
from common.finding import Severity
from common.fp_reducer import FPReducer, Confidence

BACKUP_EXTENSIONS = [
    ".bak", ".backup", ".old", ".orig", ".save", ".swp", ".swo",
    ".tmp", ".temp", "~", ".copy", ".1", ".2",
    ".sql", ".sql.gz", ".sql.bz2", ".dump",
    ".tar", ".tar.gz", ".tgz", ".zip", ".rar", ".7z",
    ".log", ".logs",
]

SENSITIVE_FILES = [
    "web.config", "web.config.bak", "web.config.old",
    "appsettings.json", "appsettings.json.bak",
    "config.php", "config.php.bak", "wp-config.php.bak",
    ".htaccess", ".htaccess.bak", ".htpasswd",
    "database.yml", "database.yml.bak",
    "settings.py", "settings.py.bak",
    "application.properties", "application.yml",
    "Dockerfile", "docker-compose.yml",
    ".env.example", ".env.dev", ".env.staging",
    "id_rsa", "id_dsa", "id_ed25519",
    "server.key", "server.crt", "privkey.pem",
    "backup.sql", "dump.sql", "db_backup.sql",
]

CVSS_BACKUP = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
CVSS40_BACKUP = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"


class BackupFileCheck(BaseModule):
    """Backup file scanner — discovers exposed backup and temp files."""

    NAME        = "backup_file_check"
    DESCRIPTION = "Backup/temp file discovery: .bak, .old, .swp, config backups"
    PHASE       = 2
    TAGS        = ["recon", "owasp-a01", "backup-files", "cwe-530"]

    async def run(self) -> ModuleResult:
        start  = time.monotonic()
        target = self.config.target.rstrip("/")

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        self.log.info("Starting backup file scan on %s", target)
        self._fp = FPReducer(
            collab_client=self.config.extra.get("collab_client"),
            headers=self.config.extra.get("session_headers", {}),
        )

        from webforge.core.session import ForgeSession
        async with ForgeSession.from_config(self.config) as session:
            # Get baseline 404 for comparison
            resp = await session.get(f"{target}/forge_nonexistent_baseline_404")
            baseline_body = await resp.text()
            self._baseline_len = len(baseline_body)
            self._baseline_status = resp.status

            sem = asyncio.Semaphore(8)
            tasks = []

            # Check backup versions of crawled pages
            crawled = self.config.extra.get("crawled_urls", [])[:20]
            for url in crawled:
                for ext in BACKUP_EXTENSIONS[:8]:
                    tasks.append(self._check_backup(session, url + ext, sem))

            # Check known sensitive files
            for fname in SENSITIVE_FILES:
                tasks.append(self._check_backup(session, f"{target}/{fname}", sem))

            await asyncio.gather(*tasks, return_exceptions=True)

        return self._make_result(start)

    async def _check_backup(self, session: Any, url: str, sem: asyncio.Semaphore) -> None:
        async with sem:
            try:
                await self.rate_limit()
                resp = await session.get(url, allow_redirects=False)
                if resp.status == 200:
                    body = await resp.text()
                    # Verify not a custom 404
                    if len(body) > 50 and abs(len(body) - self._baseline_len) > 100:
                        if resp.status != self._baseline_status or len(body) != self._baseline_len:
                            severity = Severity.HIGH if any(x in url.lower() for x in [".env", "config", "key", "pem", "sql", "passwd"]) else Severity.MEDIUM
                            from common.evidence import Evidence
                            ev = Evidence(
                                request_raw=f"GET {url}",
                                response_raw=body[:500],
                            )
                            self.new_finding(
                                title=f"Backup/Sensitive File Exposed — {url.split('/')[-1]}",
                                severity=severity,
                                description=f"Accessible file at {url} ({len(body)} bytes). May contain source code, credentials, or configuration data.",
                                reproduction_steps=[f"GET {url}"],
                                remediation="Remove backup files from web-accessible directories. Add .bak/.old to web server deny rules.",
                                references=["CWE-530", "CWE-538", "OWASP A01:2021"],
                                evidence=ev,
                                cvss_v31_vector=CVSS_BACKUP,
                                cvss_v40_vector=CVSS40_BACKUP,
                                target=self.config.target,
                            )
            except Exception:
                pass
