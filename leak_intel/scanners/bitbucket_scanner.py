"""Bitbucket OSINT Scanner — search repos, commits, and snippets for leaked secrets.

API key: BITBUCKET_USER + BITBUCKET_APP_PASSWORD env vars.

FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import logging
import re
import time
from typing import Any

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
from common.redaction import redact_secret_fragments

log = logging.getLogger("forge.leak_intel.bitbucket_scanner")

_SECRET_PATTERNS: list[tuple[str, str, str]] = [
    ("AWS Access Key",  r"AKIA[0-9A-Z]{16}",                          "aws_access_key"),
    ("AWS Secret Key",  r"(?i)aws_secret_access_key\s*[=:]\s*\S{40}", "aws_secret_key"),
    ("Private Key",     r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----", "private_key"),
    ("Generic API Key", r"(?i)(?:api[_-]?key|apikey)\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{16,}['\"]?", "api_key"),
    ("Generic Secret",  r"(?i)(?:secret|password|passwd|pwd)\s*[=:]\s*['\"]?[^\s'\"]{8,}['\"]?", "generic_secret"),
    ("Database URL",    r"(?i)(?:postgres|mysql|mongodb)://[^\s'\"]+", "db_url"),
    ("JWT Token",       r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-+/=]{10,}", "jwt"),
    ("Internal URL",    r"https?://(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)[:/]", "internal_url"),
]


class BitbucketScanner(BaseModule):
    """Search Bitbucket for leaked secrets in a target workspace."""

    NAME        = "bitbucket_scanner"
    DESCRIPTION = "Bitbucket API OSINT — repos, commits, snippets secret scanner"
    PHASE       = 0
    TAGS        = ["osint", "leak_intel", "bitbucket", "recon"]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._user = ""
        self._app_password = ""
        self._api_base = "https://api.bitbucket.org/2.0"
        self._workspace = self.config.extra.get("bitbucket_workspace") or self._extract_workspace()

    def _extract_workspace(self) -> str:
        target = self.config.target.replace("https://", "").replace("http://", "")
        return target.split(".")[0] if "." in target else target

    def _auth(self) -> Any:
        if self._user and self._app_password:
            import aiohttp
            return aiohttp.BasicAuth(self._user, self._app_password)
        return None

    async def run(self) -> ModuleResult:
        start = time.monotonic()

        if not self._workspace:
            return self._make_result(start, skipped=True, skip_reason="No Bitbucket workspace derivable")

        self.log.info("Scanning Bitbucket for secrets: workspace=%s", self._workspace)

        try:
            import aiohttp
        except ImportError:
            return self._make_result(start, skipped=True, skip_reason="aiohttp not installed")

        auth = self._auth()
        async with aiohttp.ClientSession(auth=auth) as session:
            repos = await self._list_repos(session)
            for repo in repos[:15]:
                slug = repo.get("slug", "")
                await self._search_repo_source(session, slug)
                await self._search_repo_commits(session, slug)

        return self._make_result(start)

    async def _list_repos(self, session: Any) -> list[dict]:
        url = f"{self._api_base}/repositories/{self._workspace}"
        try:
            await self.rate_limit()
            async with session.get(url, params={"pagelen": "15"},
                                    timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status != 200:
                    return []
                data = await resp.json()
                return data.get("values", [])
        except Exception as exc:
            self.log.debug("Repo list error (%s)", type(exc).__name__)
            return []

    async def _search_repo_source(self, session: Any, slug: str) -> None:
        """Walk the repo source tree looking for sensitive files."""
        sensitive_files = [".env", "config.json", "credentials", "secrets.yml", ".npmrc", ".pypirc"]
        url = f"{self._api_base}/repositories/{self._workspace}/{slug}/src"

        try:
            await self.rate_limit()
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status != 200:
                    return
                data = await resp.json()

            for entry in data.get("values", []):
                path = entry.get("path", "")
                if any(path.endswith(sf) or sf in path for sf in sensitive_files):
                    file_url = entry.get("links", {}).get("self", {}).get("href", "")
                    if file_url:
                        await self.rate_limit()
                        await self._scan_bitbucket_file(session, file_url, slug, path)
        except Exception as exc:
            self.log.debug("Source tree error (%s)", type(exc).__name__)

    async def _scan_bitbucket_file(self, session: Any, file_url: str, slug: str, path: str) -> None:
        try:
            async with session.get(file_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status != 200:
                    return
                content = await resp.text()

            for secret_name, pattern, tag in _SECRET_PATTERNS:
                matches = [match.group(0) for match in re.finditer(pattern, content)]
                if matches:
                    safe_workspace = redact_secret_fragments(self._workspace, matches)
                    safe_slug = redact_secret_fragments(slug, matches)
                    safe_path = redact_secret_fragments(path, matches)
                    self.new_finding(
                        title=f"Bitbucket Secret Leak: {secret_name} in {safe_workspace}/{safe_slug}",
                        severity=Severity.HIGH if tag in ("aws_access_key", "private_key") else Severity.MEDIUM,
                        description=f"Found {secret_name} in {safe_workspace}/{safe_slug}/{safe_path}.",
                        reproduction_steps=[f"1. Navigate to repo {safe_slug}, file {safe_path}"],
                        remediation="Rotate credential, scrub history, add .gitignore rules.",
                        references=["https://support.atlassian.com/bitbucket-cloud/docs/variables-and-secrets/"],
                        evidence=Evidence(extra={"repo": safe_slug, "file": safe_path, "secret_type": tag}),
                        tags=["osint", "leak", "bitbucket", tag],
                        mitre_attack=["T1552.001"],
                        cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                    )
        except Exception as exc:
            self.log.debug("File scan error (%s)", type(exc).__name__)

    async def _search_repo_commits(self, session: Any, slug: str) -> None:
        url = f"{self._api_base}/repositories/{self._workspace}/{slug}/commits"
        try:
            await self.rate_limit()
            async with session.get(url, params={"pagelen": "15"},
                                    timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status != 200:
                    return
                data = await resp.json()

            for commit in data.get("values", [])[:15]:
                msg = commit.get("message", "")
                for secret_name, pattern, tag in _SECRET_PATTERNS:
                    matches = [match.group(0) for match in re.finditer(pattern, msg)]
                    if matches:
                        safe_slug = redact_secret_fragments(slug, matches)
                        safe_hash = redact_secret_fragments(commit.get("hash", ""), matches)
                        self.new_finding(
                            title=f"Bitbucket Commit Secret: {secret_name} in {safe_slug}",
                            severity=Severity.MEDIUM,
                            description=f"Commit message contains {secret_name} in {safe_slug}.",
                            reproduction_steps=[f"1. View commit: {safe_hash[:12]}"],
                            remediation="Rotate credential, rewrite history.",
                            references=["https://support.atlassian.com/bitbucket-cloud/"],
                            evidence=Evidence(extra={"commit_hash": safe_hash, "repo": safe_slug}),
                            tags=["osint", "leak", "bitbucket", "commit", tag],
                            mitre_attack=["T1552.001"],
                        )
        except Exception as exc:
            self.log.debug("Commit search error (%s)", type(exc).__name__)


import aiohttp  # noqa: E402
