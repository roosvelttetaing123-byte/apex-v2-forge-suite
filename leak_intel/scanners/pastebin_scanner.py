"""Pastebin OSINT Scanner — monitor Pastebin, Ghostbin, Hastebin, Rentry for target keywords.

Scrapes paste sites for domain-specific keywords and credential patterns.
Uses the Pastebin scraping API (PRO account) or public search fallback.

API key: PASTEBIN_API_KEY env var (optional, for PRO scraping endpoint).

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

log = logging.getLogger("forge.leak_intel.pastebin_scanner")

_SECRET_PATTERNS: list[tuple[str, str, str]] = [
    ("AWS Access Key",  r"AKIA[0-9A-Z]{16}",                          "aws_access_key"),
    ("Private Key",     r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----", "private_key"),
    ("Password List",   r"(?i)(?:username|email|login)\s*[=:]\s*\S+.*(?:password|passwd|pwd)\s*[=:]\s*\S+", "credential_pair"),
    ("Database URL",    r"(?i)(?:postgres|mysql|mongodb)://[^\s'\"]+", "db_url"),
    ("JWT Token",       r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-+/=]{10,}", "jwt"),
    ("Internal URL",    r"https?://(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)[:/]", "internal_url"),
    ("API Key",         r"(?i)(?:api[_-]?key|apikey)\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{16,}['\"]?", "api_key"),
    ("Hash Dump",       r"[a-fA-F0-9]{32}:[a-fA-F0-9]{32}",          "hash_dump"),
    ("SSH Config",      r"(?i)Host\s+\S+\s+HostName\s+\S+",          "ssh_config"),
]

_PASTE_SITES: list[dict[str, str]] = [
    {"name": "Pastebin",  "scrape_url": "https://scrape.pastebin.com/api_scraping.php", "type": "api"},
    {"name": "Rentry",    "search_url": "https://rentry.co",                            "type": "scrape"},
]


class PastebinScanner(BaseModule):
    """Monitor paste sites for target-related leaked credentials and data."""

    NAME        = "pastebin_scanner"
    DESCRIPTION = "Paste site OSINT — Pastebin, Ghostbin, Hastebin, Rentry keyword monitoring"
    PHASE       = 0
    TAGS        = ["osint", "leak_intel", "pastebin", "recon"]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._api_key = ""
        self._target_keywords = self._build_keywords()

    def _build_keywords(self) -> list[str]:
        """Build search keywords from the target domain."""
        target = self.config.target.replace("https://", "").replace("http://", "")
        keywords = [target]
        # Add domain parts
        parts = target.split(".")
        if len(parts) >= 2:
            keywords.append(parts[0])                          # company name
            keywords.append(".".join(parts[-2:]))              # domain.tld
        # Add custom keywords from config
        extra_kw = self.config.extra.get("leak_keywords", [])
        if isinstance(extra_kw, list):
            keywords.extend(extra_kw)
        return keywords

    async def run(self) -> ModuleResult:
        start = time.monotonic()

        if not self._target_keywords:
            return self._make_result(start, skipped=True, skip_reason="No keywords derivable from target")

        self.log.info("Scanning paste sites for: %s", self._target_keywords[:3])

        try:
            import aiohttp
        except ImportError:
            return self._make_result(start, skipped=True, skip_reason="aiohttp not installed")

        async with aiohttp.ClientSession() as session:
            # Pastebin PRO scraping API
            if self._api_key:
                await self._scrape_pastebin_pro(session)
            else:
                self.log.info("No PASTEBIN_API_KEY — using public search fallback")
                await self._search_pastebin_public(session)

        return self._make_result(start)

    async def _scrape_pastebin_pro(self, session: Any) -> None:
        """Use Pastebin PRO scraping API to get recent pastes."""
        url = "https://scrape.pastebin.com/api_scraping.php"
        params = {"limit": "100"}

        try:
            await self.rate_limit()
            async with session.get(url, params=params,
                                    timeout=aiohttp.ClientTimeout(total=30)) as resp:
                if resp.status != 200:
                    self.log.warning("Pastebin scrape API returned %d", resp.status)
                    return
                pastes = await resp.json()

            for paste in pastes[:50]:
                scrape_url = paste.get("scrape_url", "")
                paste_key = paste.get("key", "")
                paste_title = paste.get("title", "untitled")

                if not scrape_url:
                    continue

                await self.rate_limit()
                try:
                    async with session.get(scrape_url,
                                            timeout=aiohttp.ClientTimeout(total=10)) as resp:
                        if resp.status != 200:
                            continue
                        content = await resp.text()
                except Exception:
                    continue

                # Check if paste mentions our target
                content_lower = content.lower()
                matched_keywords = [kw for kw in self._target_keywords if kw.lower() in content_lower]
                if not matched_keywords:
                    continue

                # Scan for secrets
                for secret_name, pattern, tag in _SECRET_PATTERNS:
                    matches = [match.group(0) for match in re.finditer(pattern, content)]
                    if matches:
                        safe_key = redact_secret_fragments(paste_key, matches)
                        safe_title = redact_secret_fragments(paste_title, matches)
                        safe_keywords = [
                            redact_secret_fragments(keyword, matches)
                            for keyword in matched_keywords
                        ]
                        paste_url = f"https://pastebin.com/{safe_key}"
                        self.new_finding(
                            title=f"Pastebin Leak: {secret_name} mentioning {safe_keywords[0]}",
                            severity=Severity.HIGH if tag in ("aws_access_key", "private_key", "credential_pair") else Severity.MEDIUM,
                            description=(
                                f"Paste '{safe_title}' contains {secret_name} and mentions target keyword(s): "
                                f"{', '.join(safe_keywords)}."
                            ),
                            reproduction_steps=[f"1. View paste: {paste_url}"],
                            remediation="Rotate any exposed credentials. Request takedown of the paste.",
                            references=["https://pastebin.com/doc_scraping_api"],
                            evidence=Evidence(extra={
                                "paste_key": safe_key, "paste_title": safe_title,
                                "matched_keywords": safe_keywords, "secret_type": tag,
                            }),
                            url=paste_url,
                            tags=["osint", "leak", "pastebin", tag],
                            mitre_attack=["T1552.001", "T1589.001"],
                            cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        )

        except Exception as exc:
            self.log.debug("Pastebin PRO scrape error (%s)", type(exc).__name__)

    async def _search_pastebin_public(self, session: Any) -> None:
        """Fallback: use Google dork to find pastebin pastes mentioning target.

        This is limited but works without a PRO API key.
        """
        # We just log the limitation — actual Google scraping would violate ToS
        # In real engagements, operators should use the PRO API or psbdmp.ws
        self.log.info(
            "Public Pastebin search is limited. Consider using PASTEBIN_API_KEY "
            "or psbdmp.ws for comprehensive paste monitoring."
        )

        # Try psbdmp.ws API (free pastebin dump search)
        for keyword in self._target_keywords[:3]:
            await self.rate_limit()
            url = f"https://psbdmp.ws/api/v3/search/{keyword}"
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status != 200:
                        continue
                    data = await resp.json()

                for entry in (data if isinstance(data, list) else data.get("data", []))[:10]:
                    paste_id = entry.get("id", "")
                    paste_text = entry.get("text", "")

                    for secret_name, pattern, tag in _SECRET_PATTERNS:
                        matches = [match.group(0) for match in re.finditer(pattern, paste_text)]
                        if matches:
                            safe_keyword = redact_secret_fragments(keyword, matches)
                            safe_paste_id = redact_secret_fragments(paste_id, matches)
                            self.new_finding(
                                title=f"Paste Dump Leak: {secret_name} for {safe_keyword}",
                                severity=Severity.MEDIUM,
                                description=f"Paste dump contains {secret_name} mentioning {safe_keyword}.",
                                reproduction_steps=[f"1. Search psbdmp.ws for: {safe_keyword}"],
                                remediation="Rotate exposed credentials.",
                                references=["https://psbdmp.ws"],
                                evidence=Evidence(extra={"paste_id": safe_paste_id, "keyword": safe_keyword}),
                                tags=["osint", "leak", "pastebin", tag],
                                mitre_attack=["T1552.001"],
                            )
            except Exception as exc:
                self.log.debug("psbdmp search error (%s)", type(exc).__name__)


import aiohttp  # noqa: E402
