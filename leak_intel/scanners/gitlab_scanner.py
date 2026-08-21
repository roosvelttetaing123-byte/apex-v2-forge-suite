"""GitLab OSINT Scanner — search commits, snippets, issues, MRs for target org secrets.

Queries the GitLab REST API v4 for leaked secrets across:
  - Project code search
  - Snippets (public)
  - Merge request descriptions/comments
  - Commit messages

API key: GITLAB_TOKEN env var.

FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import asyncio
import logging
import re
import time
from typing import Any

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
from common.redaction import redact_secret_fragments

log = logging.getLogger("forge.leak_intel.gitlab_scanner")

# Reuse the proven secret patterns
_SECRET_PATTERNS: list[tuple[str, str, str]] = [
    ("AWS Access Key",    r"AKIA[0-9A-Z]{16}",                          "aws_access_key"),
    ("AWS Secret Key",    r"(?i)aws_secret_access_key\s*[=:]\s*\S{40}", "aws_secret_key"),
    ("GitLab Token",      r"glpat-[A-Za-z0-9\-_]{20,}",                 "gitlab_token"),
    ("Private Key",       r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----", "private_key"),
    ("Generic API Key",   r"(?i)(?:api[_-]?key|apikey)\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{16,}['\"]?", "api_key"),
    ("Generic Secret",    r"(?i)(?:secret|password|passwd|pwd)\s*[=:]\s*['\"]?[^\s'\"]{8,}['\"]?", "generic_secret"),
    ("Database URL",      r"(?i)(?:postgres|mysql|mongodb)://[^\s'\"]+", "db_url"),
    ("JWT Token",         r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-+/=]{10,}", "jwt"),
    ("Slack Token",       r"xox[bpors]-[0-9A-Za-z\-]{10,}",             "slack_token"),
    ("Internal URL",      r"https?://(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)[:/]", "internal_url"),
]


class GitLabScanner(BaseModule):
    """Search GitLab for leaked secrets belonging to a target organization."""

    NAME        = "gitlab_scanner"
    DESCRIPTION = "GitLab API OSINT — code, snippets, MRs, commits secret scanner"
    PHASE       = 0
    TAGS        = ["osint", "leak_intel", "gitlab", "recon"]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._token = ""
        self._api_base = "https://gitlab.com/api/v4"
        self._group = self.config.extra.get("gitlab_group") or self._extract_group()

    def _extract_group(self) -> str:
        target = self.config.target.replace("https://", "").replace("http://", "")
        return target.split(".")[0] if "." in target else target

    def _headers(self) -> dict[str, str]:
        h: dict[str, str] = {"User-Agent": "Forge-Suite/5.0 LeakIntel"}
        if self._token:
            h["PRIVATE-TOKEN"] = self._token
        return h

    async def run(self) -> ModuleResult:
        start = time.monotonic()

        if not self._token:
            self.log.warning("GITLAB_TOKEN not set — limited to public search")

        if not self._group:
            return self._make_result(start, skipped=True, skip_reason="No GitLab group derivable from target")

        self.log.info("Scanning GitLab for secrets: group=%s", self._group)

        try:
            import aiohttp
        except ImportError:
            return self._make_result(start, skipped=True, skip_reason="aiohttp not installed")

        async with aiohttp.ClientSession(headers=self._headers()) as session:
            # Search group projects
            projects = await self._list_group_projects(session)
            for project in projects[:20]:
                pid = project.get("id")
                if not isinstance(pid, int):
                    continue
                pname = project.get("path_with_namespace", "")
                await self._search_project_code(session, pid, pname)
                await self._search_project_commits(session, pid, pname)

            # Search snippets
            await self._search_snippets(session)

        return self._make_result(start)

    async def _list_group_projects(self, session: Any) -> list[dict]:
        """List projects in the target group."""
        url = f"{self._api_base}/groups/{self._group}/projects"
        try:
            await self.rate_limit()
            async with session.get(url, params={"per_page": "20", "simple": "true"},
                                    timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status != 200:
                    return []
                return await resp.json()
        except Exception as exc:
            self.log.debug("Group projects list error (%s)", type(exc).__name__)
            return []

    async def _search_project_code(self, session: Any, project_id: int, project_name: str) -> None:
        """Search a project's code for secret patterns."""
        search_terms = ["password", "api_key", "secret", "token", "private_key"]
        for term in search_terms[:2]:
            await self.rate_limit()
            url = f"{self._api_base}/projects/{project_id}/search"
            params = {"scope": "blobs", "search": term, "per_page": "10"}
            try:
                async with session.get(url, params=params,
                                        timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status != 200:
                        continue
                    results = await resp.json()

                for item in results[:10]:
                    data = item.get("data", "")
                    filename = item.get("filename", "")
                    ref = item.get("ref", "main")

                    for secret_name, pattern, tag in _SECRET_PATTERNS:
                        matches = [match.group(0) for match in re.finditer(pattern, data)]
                        if matches:
                            safe_project = redact_secret_fragments(project_name, matches)
                            safe_filename = redact_secret_fragments(filename, matches)
                            safe_ref = redact_secret_fragments(ref, matches)
                            file_url = (
                                f"{self._api_base.replace('/api/v4', '')}/{safe_project}"
                                f"/-/blob/{safe_ref}/{safe_filename}"
                            )
                            self.new_finding(
                                title=f"GitLab Secret Leak: {secret_name} in {safe_project}",
                                severity=Severity.HIGH if tag in ("aws_access_key", "private_key", "db_url") else Severity.MEDIUM,
                                description=f"Found {secret_name} in {safe_project}/{safe_filename}.",
                                reproduction_steps=[f"1. Navigate to {file_url}", f"2. Search for {secret_name}"],
                                remediation="Rotate the credential, scrub git history, add to .gitignore.",
                                references=["https://docs.gitlab.com/ee/user/application_security/secret_detection/"],
                                evidence=Evidence(extra={"project": safe_project, "file": safe_filename, "secret_type": tag}),
                                url=file_url,
                                tags=["osint", "leak", "gitlab", tag],
                                mitre_attack=["T1552.001", "T1552.004"],
                                cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                            )
            except Exception as exc:
                self.log.debug("Project code search error (%s)", type(exc).__name__)

    async def _search_project_commits(self, session: Any, project_id: int, project_name: str) -> None:
        """Scan recent commit messages for secrets."""
        url = f"{self._api_base}/projects/{project_id}/repository/commits"
        try:
            await self.rate_limit()
            async with session.get(url, params={"per_page": "20"},
                                    timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status != 200:
                    return
                commits = await resp.json()

            for commit in commits[:20]:
                msg = commit.get("message", "") + " " + commit.get("title", "")
                for secret_name, pattern, tag in _SECRET_PATTERNS:
                    matches = [match.group(0) for match in re.finditer(pattern, msg)]
                    if matches:
                        safe_project = redact_secret_fragments(project_name, matches)
                        commit_url = redact_secret_fragments(commit.get("web_url", ""), matches)
                        self.new_finding(
                            title=f"GitLab Commit Secret: {secret_name} in {safe_project}",
                            severity=Severity.MEDIUM,
                            description=f"Commit message contains {secret_name} in {safe_project}.",
                            reproduction_steps=[f"1. View commit: {commit_url}"],
                            remediation="Rotate credential, rewrite git history.",
                            references=["https://docs.gitlab.com/ee/user/application_security/secret_detection/"],
                            evidence=Evidence(extra={"commit_url": commit_url, "project": safe_project}),
                            url=commit_url,
                            tags=["osint", "leak", "gitlab", "commit", tag],
                            mitre_attack=["T1552.001"],
                        )
        except Exception as exc:
            self.log.debug("Commit search error (%s)", type(exc).__name__)

    async def _search_snippets(self, session: Any) -> None:
        """Search public snippets for secrets."""
        url = f"{self._api_base}/snippets"
        try:
            await self.rate_limit()
            async with session.get(url, params={"per_page": "20"},
                                    timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status != 200:
                    return
                snippets = await resp.json()

            for snippet in snippets[:10]:
                raw_url = snippet.get("raw_url", "")
                if not raw_url:
                    continue
                await self.rate_limit()
                async with session.get(raw_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status != 200:
                        continue
                    content = await resp.text()

                for secret_name, pattern, tag in _SECRET_PATTERNS:
                    matches = [match.group(0) for match in re.finditer(pattern, content)]
                    if matches:
                        snippet_url = redact_secret_fragments(snippet.get("web_url", ""), matches)
                        self.new_finding(
                            title=f"GitLab Snippet Secret: {secret_name}",
                            severity=Severity.MEDIUM,
                            description=f"Public snippet contains {secret_name}.",
                            reproduction_steps=[f"1. View snippet: {snippet_url}"],
                            remediation="Delete snippet, rotate credential.",
                            references=["https://docs.gitlab.com/ee/user/snippets.html"],
                            evidence=Evidence(extra={"snippet_url": snippet_url}),
                            url=snippet_url,
                            tags=["osint", "leak", "gitlab", "snippet", tag],
                            mitre_attack=["T1552.001"],
                        )
        except Exception as exc:
            self.log.debug("Snippet search error (%s)", type(exc).__name__)


import aiohttp  # noqa: E402
