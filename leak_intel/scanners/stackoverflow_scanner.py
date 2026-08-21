"""StackOverflow Scanner — search code snippets from target domain for embedded creds.

Searches StackOverflow for questions/answers mentioning the target domain,
then scans code blocks for leaked credentials.

No API key required (but STACKOVERFLOW_API_KEY increases rate limit).

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

log = logging.getLogger("forge.leak_intel.stackoverflow_scanner")

_SECRET_PATTERNS: list[tuple[str, str, str]] = [
    ("AWS Access Key",  r"AKIA[0-9A-Z]{16}",                          "aws_access_key"),
    ("Private Key",     r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----", "private_key"),
    ("API Key",         r"(?i)(?:api[_-]?key|apikey)\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{16,}['\"]?", "api_key"),
    ("Password",        r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"]?[^\s'\"]{8,}['\"]?", "password"),
    ("Database URL",    r"(?i)(?:postgres|mysql|mongodb)://[^\s'\"]+", "db_url"),
    ("JWT Token",       r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-+/=]{10,}", "jwt"),
    ("Internal URL",    r"https?://(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)[:/]", "internal_url"),
    ("Connection String", r"(?i)(?:Server|Data Source)\s*=\s*[^;]+;\s*(?:User Id|uid)\s*=\s*[^;]+;\s*(?:Password|pwd)\s*=\s*[^;]+", "connection_string"),
]


class StackOverflowScanner(BaseModule):
    """Search StackOverflow for code snippets leaking target credentials."""

    NAME        = "stackoverflow_scanner"
    DESCRIPTION = "StackOverflow OSINT — code snippet credential scanning for target domain"
    PHASE       = 0
    TAGS        = ["osint", "leak_intel", "stackoverflow", "recon"]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._api_key = ""

    async def run(self) -> ModuleResult:
        start = time.monotonic()

        domain = self._extract_domain()
        if not domain:
            return self._make_result(start, skipped=True, skip_reason="No domain derivable from target")

        self.log.info("Scanning StackOverflow for code leaks mentioning: %s", domain)

        try:
            import aiohttp
        except ImportError:
            return self._make_result(start, skipped=True, skip_reason="aiohttp not installed")

        async with aiohttp.ClientSession() as session:
            await self._search_questions(session, domain)

        return self._make_result(start)

    async def _search_questions(self, session: Any, domain: str) -> None:
        """Search StackOverflow for questions mentioning the target domain."""
        base_url = "https://api.stackexchange.com/2.3/search/advanced"
        params: dict[str, str] = {
            "order": "desc",
            "sort": "relevance",
            "q": domain,
            "site": "stackoverflow",
            "filter": "withbody",
            "pagesize": "25",
        }
        if self._api_key:
            params["key"] = self._api_key

        try:
            await self.rate_limit()
            async with session.get(base_url, params=params,
                                    timeout=aiohttp.ClientTimeout(total=20)) as resp:
                if resp.status != 200:
                    self.log.warning("StackOverflow API returned %d", resp.status)
                    return
                data = await resp.json()

            for item in data.get("items", [])[:20]:
                body = item.get("body", "")
                title = item.get("title", "")
                link = item.get("link", "")
                question_id = item.get("question_id", "")

                # Scan question body for secrets
                self._scan_content(body, title, link, "question")

                # Also fetch answers for this question
                if question_id:
                    await self.rate_limit()
                    await self._fetch_answers(session, question_id, domain)

        except Exception as exc:
            self.log.debug("StackOverflow search error (%s)", type(exc).__name__)

    async def _fetch_answers(self, session: Any, question_id: int, domain: str) -> None:
        """Fetch answers for a question and scan for secrets."""
        url = f"https://api.stackexchange.com/2.3/questions/{question_id}/answers"
        params: dict[str, str] = {
            "order": "desc",
            "sort": "votes",
            "site": "stackoverflow",
            "filter": "withbody",
            "pagesize": "10",
        }
        if self._api_key:
            params["key"] = self._api_key

        try:
            async with session.get(url, params=params,
                                    timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status != 200:
                    return
                data = await resp.json()

            for answer in data.get("items", [])[:5]:
                body = answer.get("body", "")
                link = answer.get("link", f"https://stackoverflow.com/a/{answer.get('answer_id', '')}")
                self._scan_content(body, f"Answer #{answer.get('answer_id', '')}", link, "answer")

        except Exception as exc:
            self.log.debug("Answer fetch error (%s)", type(exc).__name__)

    def _scan_content(self, body: str, title: str, link: str, content_type: str) -> None:
        """Scan HTML body content for secret patterns."""
        # Strip HTML tags for pattern matching
        clean = re.sub(r"<[^>]+>", " ", body)
        clean = re.sub(r"&\w+;", " ", clean)

        for secret_name, pattern, tag in _SECRET_PATTERNS:
            matches = [match.group(0) for match in re.finditer(pattern, clean)]
            if matches:
                # Masking prefixes still discloses credential-derived bytes.
                # Retain only count/type metadata in ordinary findings.
                redacted = ["<redacted>" for _ in matches[:3]]
                safe_link = redact_secret_fragments(link, matches)
                self.new_finding(
                    title=f"StackOverflow Credential Leak: {secret_name} in {content_type}",
                    severity=Severity.MEDIUM if tag in ("api_key", "password", "db_url") else Severity.LOW,
                    description=(
                        f"StackOverflow {content_type} contains {secret_name}.\n"
                        f"Redacted: {redacted}"
                    ),
                    reproduction_steps=[
                        f"1. View: {safe_link}",
                        f"2. Search for {secret_name} pattern",
                    ],
                    remediation="Rotate the exposed credential. Edit/flag the SO post.",
                    references=[safe_link],
                    evidence=Evidence(
                        extra={
                            "link": safe_link,
                            "content_type": content_type,
                            "secret_type": tag,
                        }
                    ),
                    url=safe_link,
                    tags=["osint", "stackoverflow", "leak", tag],
                    mitre_attack=["T1552.001"],
                )

    def _extract_domain(self) -> str:
        target = self.config.target.replace("https://", "").replace("http://", "")
        target = target.split("/")[0].split(":")[0]
        parts = target.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return target


import aiohttp  # noqa: E402
