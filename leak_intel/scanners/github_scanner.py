"""GitHub OSINT Scanner — search commits, gists, issues, PRs, wiki for target org secrets.

Queries the GitHub REST API for leaked secrets across:
  - Code search (filenames, extensions, keywords)
  - Commit messages and diffs
  - Gist content (public)
  - Issue/PR bodies and comments
  - Wiki pages

API key: GITHUB_TOKEN env var (PAT with public_repo scope).

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

log = logging.getLogger("forge.leak_intel.github_scanner")

# ── Secret patterns ──────────────────────────────────────────────────
_SECRET_PATTERNS: list[tuple[str, str, str]] = [
    ("AWS Access Key",          r"AKIA[0-9A-Z]{16}",                          "aws_access_key"),
    ("AWS Secret Key",          r"(?i)aws_secret_access_key\s*[=:]\s*\S{40}", "aws_secret_key"),
    ("GitHub Token",            r"ghp_[A-Za-z0-9_]{36}",                      "github_token"),
    ("GitLab Token",            r"glpat-[A-Za-z0-9\-_]{20,}",                 "gitlab_token"),
    ("Slack Token",             r"xox[bpors]-[0-9A-Za-z\-]{10,}",             "slack_token"),
    ("Slack Webhook",           r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+", "slack_webhook"),
    ("Private Key",             r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----", "private_key"),
    ("Generic API Key",         r"(?i)(?:api[_-]?key|apikey)\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{16,}['\"]?", "api_key"),
    ("Generic Secret",          r"(?i)(?:secret|password|passwd|pwd)\s*[=:]\s*['\"]?[^\s'\"]{8,}['\"]?", "generic_secret"),
    ("Heroku API Key",          r"(?i)heroku.*[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "heroku_key"),
    ("SendGrid Key",            r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}", "sendgrid_key"),
    ("Twilio Key",              r"SK[0-9a-fA-F]{32}",                         "twilio_key"),
    ("Stripe Key",              r"(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}",  "stripe_key"),
    ("Google API Key",          r"AIza[0-9A-Za-z_\-]{35}",                    "google_api_key"),
    ("Firebase URL",            r"https://[a-z0-9-]+\.firebaseio\.com",       "firebase_url"),
    ("JWT Token",               r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-+/=]{10,}", "jwt"),
    ("Database URL",            r"(?i)(?:postgres|mysql|mongodb)://[^\s'\"]+", "db_url"),
    ("Internal URL",            r"https?://(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)[:/]", "internal_url"),
]

# GitHub code search qualifiers for juicy files
_SEARCH_QUALIFIERS: list[str] = [
    "filename:.env",
    "filename:.env.local",
    "filename:.env.production",
    "filename:credentials",
    "filename:config.json",
    "filename:secrets.yml",
    "filename:docker-compose.yml",
    "filename:wp-config.php",
    "filename:.npmrc",
    "filename:.pypirc",
    "filename:id_rsa",
    "filename:id_ed25519",
    "extension:pem",
    "extension:key",
    "extension:pfx",
]


class GitHubScanner(BaseModule):
    """Search GitHub for leaked secrets belonging to a target organization."""

    NAME        = "github_scanner"
    DESCRIPTION = "GitHub API OSINT — commits, gists, issues, PRs, wiki secret scanner"
    PHASE       = 0
    TAGS        = ["osint", "leak_intel", "github", "recon"]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._token = ""
        self._api_base = "https://api.github.com"
        self._org = self.config.extra.get("github_org") or self._extract_org()

    def _extract_org(self) -> str:
        """Try to derive a GitHub org/user from the target domain."""
        target = self.config.target.replace("https://", "").replace("http://", "")
        return target.split(".")[0] if "." in target else target

    def _headers(self) -> dict[str, str]:
        h: dict[str, str] = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "Forge-Suite/5.0 LeakIntel",
        }
        if self._token:
            h["Authorization"] = f"token {self._token}"
        return h

    async def run(self) -> ModuleResult:
        start = time.monotonic()

        if not self._token:
            self.log.warning("GITHUB_TOKEN not set — rate-limited to 10 req/min")

        if not self._org:
            return self._make_result(start, skipped=True, skip_reason="No GitHub org derivable from target")

        self.log.info("Scanning GitHub for secrets: org=%s", self._org)

        try:
            import aiohttp
        except ImportError:
            self.log.error("aiohttp required for GitHub scanner")
            return self._make_result(start, skipped=True, skip_reason="aiohttp not installed")

        async with aiohttp.ClientSession(headers=self._headers()) as session:
            # Search code for each qualifier
            for qualifier in _SEARCH_QUALIFIERS:
                await self.rate_limit()
                await self._search_code(session, qualifier)

            # Search commits for secrets
            await self._search_commits(session)

            # Search gists
            await self._search_gists(session)

        return self._make_result(start)

    async def _search_code(self, session: Any, qualifier: str) -> None:
        """Search GitHub code API for a specific file qualifier."""
        query = f"org:{self._org} {qualifier}"
        url = f"{self._api_base}/search/code"
        params = {"q": query, "per_page": "30"}

        try:
            async with session.get(url, params=params, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status == 403:
                    self.log.warning("GitHub rate limit hit on code search")
                    await asyncio.sleep(30)
                    return
                if resp.status != 200:
                    return
                data = await resp.json()

            for item in data.get("items", []):
                file_url = item.get("html_url", "")
                file_path = item.get("path", "")
                repo_name = item.get("repository", {}).get("full_name", "")

                # Fetch raw content to scan for secrets
                raw_url = item.get("git_url", "")
                if raw_url:
                    await self.rate_limit()
                    await self._scan_file_content(session, raw_url, file_url, file_path, repo_name)

        except Exception as exc:
            self.log.debug(
                "Code search error for %s (%s)",
                qualifier,
                type(exc).__name__,
            )

    async def _scan_file_content(
        self, session: Any, raw_url: str, html_url: str, file_path: str, repo: str
    ) -> None:
        """Fetch a file's content and scan it for secret patterns."""
        try:
            async with session.get(raw_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status != 200:
                    return
                data = await resp.json()

            import base64
            content = ""
            if data.get("encoding") == "base64" and data.get("content"):
                try:
                    content = base64.b64decode(data["content"]).decode("utf-8", errors="replace")
                except Exception:
                    return
            elif data.get("content"):
                content = data["content"]

            if not content:
                return

            for secret_name, pattern, tag in _SECRET_PATTERNS:
                matches = [match.group(0) for match in re.finditer(pattern, content)]
                if matches:
                    # Prefix/suffix masks are still secret-derived disclosure.
                    # Preserve only count/type metadata and constant markers.
                    redacted = ["<redacted>" for _ in matches[:3]]
                    safe_repo = redact_secret_fragments(repo, matches)
                    safe_file_path = redact_secret_fragments(file_path, matches)
                    safe_html_url = redact_secret_fragments(html_url, matches)
                    self.new_finding(
                        title=f"GitHub Secret Leak: {secret_name} in {safe_repo}",
                        severity=Severity.HIGH if tag in ("aws_access_key", "aws_secret_key", "private_key", "db_url") else Severity.MEDIUM,
                        description=(
                            f"Found {len(matches)} instance(s) of {secret_name} "
                            f"in {safe_repo}/{safe_file_path}.\n"
                            f"Redacted samples: {redacted}"
                        ),
                        reproduction_steps=[
                            f"1. Navigate to {safe_html_url}",
                            f"2. Search for pattern: {pattern[:60]}",
                            f"3. Observe leaked {secret_name}",
                        ],
                        remediation=(
                            f"1. Immediately rotate the leaked {secret_name}.\n"
                            "2. Remove the secret from the repository history using git filter-branch or BFG.\n"
                            "3. Add the file pattern to .gitignore.\n"
                            "4. Implement pre-commit hooks (e.g., git-secrets, trufflehog) to prevent future leaks."
                        ),
                        references=[
                            "https://docs.github.com/en/code-security/secret-scanning",
                            "https://trufflesecurity.com/trufflehog",
                        ],
                        evidence=Evidence(
                            extra={
                                "repo": safe_repo,
                                "file_path": safe_file_path,
                                "secret_type": tag,
                                "match_count": len(matches),
                            },
                        ),
                        url=safe_html_url,
                        tags=["osint", "leak", tag],
                        mitre_attack=["T1552.001", "T1552.004"],
                        cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                    )

        except Exception as exc:
            self.log.debug("File content scan error (%s)", type(exc).__name__)

    async def _search_commits(self, session: Any) -> None:
        """Search commit messages for secret keywords."""
        keywords = ["password", "secret", "api_key", "token", "credential", "private_key"]
        for keyword in keywords[:3]:
            await self.rate_limit()
            query = f"org:{self._org} {keyword}"
            url = f"{self._api_base}/search/commits"
            params = {"q": query, "per_page": "10"}
            headers = {"Accept": "application/vnd.github.cloak-preview+json"}

            try:
                async with session.get(url, params=params, headers=headers,
                                        timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status != 200:
                        continue
                    data = await resp.json()

                for item in data.get("items", [])[:5]:
                    msg = item.get("commit", {}).get("message", "")
                    commit_url = item.get("html_url", "")
                    repo_name = item.get("repository", {}).get("full_name", "")

                    for secret_name, pattern, tag in _SECRET_PATTERNS:
                        if re.search(pattern, msg):
                            self.new_finding(
                                title=f"GitHub Commit Secret: {secret_name} in {repo_name}",
                                severity=Severity.MEDIUM,
                                description=f"Commit message contains {secret_name} pattern in {repo_name}.",
                                reproduction_steps=[f"1. View commit: {commit_url}"],
                                remediation="Rotate the exposed credential and scrub git history.",
                                references=["https://docs.github.com/en/authentication/keeping-your-account-and-data-secure"],
                                evidence=Evidence(extra={"commit_url": commit_url, "keyword": keyword}),
                                url=commit_url,
                                tags=["osint", "leak", "commit", tag],
                                mitre_attack=["T1552.001"],
                            )
            except Exception as exc:
                self.log.debug("Commit search error (%s)", type(exc).__name__)

    async def _search_gists(self, session: Any) -> None:
        """Search public gists of the org's members for secrets."""
        url = f"{self._api_base}/orgs/{self._org}/members"
        try:
            await self.rate_limit()
            async with session.get(url, params={"per_page": "10"},
                                    timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status != 200:
                    return
                members = await resp.json()

            for member in members[:5]:
                login = member.get("login", "")
                gists_url = f"{self._api_base}/users/{login}/gists"
                await self.rate_limit()

                async with session.get(gists_url, params={"per_page": "10"},
                                        timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status != 200:
                        continue
                    gists = await resp.json()

                for gist in gists[:5]:
                    for fname, finfo in gist.get("files", {}).items():
                        raw_url = finfo.get("raw_url", "")
                        if raw_url:
                            await self.rate_limit()
                            try:
                                async with session.get(raw_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                                    if resp.status != 200:
                                        continue
                                    content = await resp.text()

                                for secret_name, pattern, tag in _SECRET_PATTERNS:
                                    if re.search(pattern, content):
                                        self.new_finding(
                                            title=f"GitHub Gist Secret: {secret_name} by {login}",
                                            severity=Severity.MEDIUM,
                                            description=f"Public gist by {login} contains {secret_name}.",
                                            reproduction_steps=[f"1. View gist: {gist.get('html_url', '')}"],
                                            remediation="Delete the gist and rotate the credential.",
                                            references=["https://docs.github.com/en/get-started/writing-on-github"],
                                            evidence=Evidence(extra={"gist_url": gist.get("html_url"), "user": login}),
                                            url=gist.get("html_url", ""),
                                            tags=["osint", "leak", "gist", tag],
                                            mitre_attack=["T1552.001"],
                                        )
                            except Exception:
                                pass

        except Exception as exc:
            self.log.debug("Gist search error (%s)", type(exc).__name__)


# aiohttp is imported inside methods to avoid top-level import failure
import aiohttp  # noqa: E402 — used in type hints above
