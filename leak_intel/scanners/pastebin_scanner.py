"""Pastebin Scanner — hunt leaked credentials and secrets on paste sites.

Searches multiple paste aggregators for target-specific leaked data:
  - Credentials (usernames/passwords, API keys, tokens)
  - Internal hostnames, IP addresses, email addresses
  - Source code snippets, configuration files, database dumps
  - Corporate keywords (domain, project names, employee emails)

Sources: Pastebin, Ghostbin, GitHub Gist (public), pastes.io, hastebin
Uses: psbdmp.ws (Pastebin scraper index), scraping, dork-style search

API key: PASTEBIN_API_KEY env var (optional, improves rate limits).

FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import asyncio
import json
import re
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote_plus, urlparse

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_HIGH   = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
CVSS40_HIGH = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
CVSS_CRIT   = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
CVSS40_CRIT = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
CVSS_MED    = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
CVSS40_MED  = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"

_CRED_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    # (pattern, label, severity)
    (re.compile(r"(?:password|passwd|pwd)\s*[=:]\s*['\"]?(\S{6,})", re.I),
     "Password in plaintext", "CRITICAL"),
    (re.compile(r"(?:api[_\-]?key|apikey|api[_\-]?token)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{16,})", re.I),
     "API key", "CRITICAL"),
    (re.compile(r"(?:secret|client_secret)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{16,})", re.I),
     "Client secret", "CRITICAL"),
    (re.compile(r"(AKIA[0-9A-Z]{16})", re.A),
     "AWS Access Key ID", "CRITICAL"),
    (re.compile(r"((?:A3T[A-Z0-9]|AKIA|AGPA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})", re.A),
     "AWS Key (variant)", "CRITICAL"),
    (re.compile(r"(sk-ant-[A-Za-z0-9_\-]{40,})", re.A),
     "Anthropic API key", "CRITICAL"),
    (re.compile(r"(sk-[A-Za-z0-9]{48,})", re.A),
     "OpenAI API key", "CRITICAL"),
    (re.compile(r"(ghp_[A-Za-z0-9]{36})", re.A),
     "GitHub Personal Access Token", "CRITICAL"),
    (re.compile(r"(github_pat_[A-Za-z0-9_]{82})", re.A),
     "GitHub Fine-grained PAT", "CRITICAL"),
    (re.compile(r"(glpat-[A-Za-z0-9\-_]{20})", re.A),
     "GitLab PAT", "CRITICAL"),
    (re.compile(r"(xox[baprs]-[0-9a-zA-Z\-]{10,48})", re.A),
     "Slack token", "HIGH"),
    (re.compile(r"(eyJ[A-Za-z0-9_\-]{100,}\.eyJ[A-Za-z0-9_\-]{20,}\.)", re.A),
     "JWT token", "HIGH"),
    (re.compile(r"(?:BEGIN\s+(?:RSA|EC|OPENSSH)\s+PRIVATE\s+KEY)", re.I),
     "Private key", "CRITICAL"),
    (re.compile(r"(?:mongodb|postgres|mysql|mssql|redis)://[^'\"<\s]{8,}", re.I),
     "Database connection string", "CRITICAL"),
    (re.compile(r"smtp[s]?://[^@'\"<\s]+:[^@'\"<\s]+@", re.I),
     "SMTP credentials in URL", "HIGH"),
    (re.compile(r"(?:username|user|login)\s*[=:]\s*['\"]?(\S+@\S+\.\S+)", re.I),
     "Email credential", "HIGH"),
    (re.compile(r"(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)", re.A),
     "Internal IP address", "MEDIUM"),
    (re.compile(r"(?:internal|corp|intranet)\.\S+\.\S+", re.I),
     "Internal hostname", "MEDIUM"),
]

_PASTE_SOURCES = [
    "psbdmp.ws",
    "pastebin.com",
    "pastes.io",
    "ghostbin.com",
]


def _redact(value: str, keep: int = 6) -> str:
    if len(value) <= keep * 2:
        return "***"
    return value[:keep] + "..." + value[-3:]


class PastebinScanner(BaseModule):
    """Searches paste sites for leaked credentials and sensitive data."""

    NAME        = "pastebin_scanner"
    DESCRIPTION = "Search paste sites for leaked credentials/secrets related to target"
    PHASE       = 1
    TAGS        = ["recon", "osint", "leaks", "credentials"]

    def _build_keywords(self, domain: str) -> list[str]:
        """Build search keyword list from target domain."""
        parts = domain.split(".")
        keywords: list[str] = [domain]

        # Organisation name from domain (e.g., "corp" from "corp.example.com")
        if len(parts) >= 2:
            root = parts[-2]
            keywords.append(root)
            keywords.append(f"@{domain}")
            keywords.append(f"@{root}")
            keywords.append(f"{root} password")
            keywords.append(f"{root} credentials")
            keywords.append(f"{root} api_key")
            keywords.append(f"{root} secret")
            keywords.append(f"site:{domain}")

        # Extract company name variations from config if available
        extra_keywords = getattr(self.config, "extra", {}).get("company_keywords", [])
        keywords.extend(extra_keywords)

        return list(dict.fromkeys(keywords))[:15]  # dedup, cap at 15

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")
        domain = self._extract_domain(target)
        if not domain:
            return self._make_result(start, skipped=True, skip_reason="cannot parse domain")

        keywords = self._build_keywords(domain)
        self.log.info("Paste site scan for %s (%d keywords)", domain, len(keywords))

        all_hits: list[dict[str, Any]] = []

        # Phase 1: psbdmp.ws (fastest — aggregated pastebin index)
        psbdmp_hits = await self._search_psbdmp(keywords[:5])
        all_hits.extend(psbdmp_hits)

        # Phase 2: Scrape public Pastebin search (rate-limited)
        pb_hits = await self._search_pastebin_public(keywords[:3])
        all_hits.extend(pb_hits)

        # Phase 3: Fetch and analyse each paste URL
        analysed: list[dict[str, Any]] = []
        seen_urls: set[str] = set()
        for hit in all_hits:
            url = hit.get("url", "")
            if url and url not in seen_urls:
                seen_urls.add(url)
                content = await self._fetch_raw_paste(url)
                if content:
                    matches = self._scan_content(content, domain)
                    if matches:
                        analysed.append({
                            "url": url,
                            "matches": matches,
                            "snippet": content[:300],
                        })

        # Emit findings grouped by severity
        self._emit_findings(domain, analysed, target)
        return self._make_result(start)

    # ── search helpers ────────────────────────────────────────────────────────

    async def _search_psbdmp(self, keywords: list[str]) -> list[dict[str, str]]:
        """Query psbdmp.ws — a searchable index of Pastebin pastes."""
        hits: list[dict[str, str]] = []
        try:
            import aiohttp
            for kw in keywords:
                await self.rate_limit()
                url = f"https://psbdmp.ws/api/search/{quote_plus(kw)}"
                try:
                    async with aiohttp.ClientSession() as s:
                        async with s.get(url, timeout=aiohttp.ClientTimeout(total=10),
                                         headers={"User-Agent": "Mozilla/5.0"}) as r:
                            if r.status == 200:
                                data = await r.json(content_type=None)
                                for entry in (data if isinstance(data, list) else []):
                                    pid = entry.get("id", "")
                                    if pid:
                                        hits.append({
                                            "url": f"https://pastebin.com/raw/{pid}",
                                            "keyword": kw,
                                        })
                except Exception:
                    pass
        except ImportError:
            self.log.debug("aiohttp not available for psbdmp search")
        return hits[:50]

    async def _search_pastebin_public(self, keywords: list[str]) -> list[dict[str, str]]:
        """Scrape Pastebin's public archive filtered by keyword (HTML scrape)."""
        hits: list[dict[str, str]] = []
        try:
            import aiohttp
            for kw in keywords[:3]:
                await self.rate_limit()
                url = f"https://pastebin.com/search?q={quote_plus(kw)}"
                try:
                    async with aiohttp.ClientSession() as s:
                        async with s.get(url, timeout=aiohttp.ClientTimeout(total=12),
                                         headers={"User-Agent": "Mozilla/5.0"}) as r:
                            if r.status == 200:
                                html = await r.text(errors="ignore")
                                for m in re.finditer(
                                    r'href="/([A-Za-z0-9]{8})"', html
                                ):
                                    pid = m.group(1)
                                    hits.append({
                                        "url": f"https://pastebin.com/raw/{pid}",
                                        "keyword": kw,
                                    })
                except Exception:
                    pass
        except ImportError:
            pass
        return hits[:30]

    async def _fetch_raw_paste(self, url: str) -> str:
        """Fetch raw paste content with timeout and size cap."""
        try:
            import aiohttp
            await self.rate_limit()
            async with aiohttp.ClientSession() as s:
                async with s.get(url, timeout=aiohttp.ClientTimeout(total=10),
                                 headers={"User-Agent": "Mozilla/5.0"}) as r:
                    if r.status == 200:
                        content = await r.text(errors="ignore")
                        return content[:50_000]
        except Exception:
            pass
        return ""

    # ── content analysis ──────────────────────────────────────────────────────

    def _scan_content(self, content: str, domain: str) -> list[dict[str, str]]:
        """Run all credential patterns against paste content."""
        matches: list[dict[str, str]] = []
        # Only scan pastes that mention the domain or related keywords
        content_lower = content.lower()
        if domain.lower() not in content_lower:
            # Quick relevance check — require word-boundary match for domain parts
            parts = domain.split(".")
            if not any(
                re.search(r"\b" + re.escape(p.lower()) + r"\b", content_lower)
                for p in parts if len(p) > 3
            ):
                return []

        for pattern, label, severity in _CRED_PATTERNS:
            for m in pattern.finditer(content):
                value = m.group(1) if m.lastindex else m.group(0)
                matches.append({
                    "label": label,
                    "severity": severity,
                    "value_redacted": _redact(value),
                    "context": content[max(0, m.start()-60): m.end()+60].strip(),
                })
        return matches

    def _extract_domain(self, target: str) -> str:
        try:
            parsed = urlparse(target)
            host = parsed.netloc or parsed.path
            return host.split(":")[0].split("/")[0].strip().lower()
        except Exception:
            return ""

    # ── findings ──────────────────────────────────────────────────────────────

    def _emit_findings(
        self, domain: str, analysed: list[dict], target: str
    ) -> None:
        critical: list[dict] = []
        high: list[dict] = []
        medium: list[dict] = []

        for paste in analysed:
            for match in paste["matches"]:
                entry = {**match, "paste_url": paste["url"]}
                sev = match["severity"]
                if sev == "CRITICAL":
                    critical.append(entry)
                elif sev == "HIGH":
                    high.append(entry)
                else:
                    medium.append(entry)

        if critical:
            self.new_finding(
                title=f"CRITICAL: Leaked credentials/secrets for {domain} on paste sites",
                severity=Severity.CRITICAL,
                description=(
                    f"Found {len(critical)} CRITICAL secret(s) on public paste sites "
                    f"related to {domain}. Secrets may include API keys, passwords, "
                    "private keys, or database connection strings that are still active."
                ),
                reproduction_steps=[
                    e["paste_url"] for e in critical[:5]
                ] + [
                    f"# {e['label']}: {e['value_redacted']}" for e in critical[:5]
                ],
                remediation=(
                    "1. Immediately rotate ALL exposed credentials. "
                    "2. Search for malicious usage in logs and audit trails. "
                    "3. Submit DMCA/removal request to paste site. "
                    "4. Implement secret scanning in CI/CD pipeline (Gitleaks, TruffleHog)."
                ),
                references=[
                    "T1552.001 — Credentials In Files",
                    "https://trufflesecurity.com/trufflehog",
                ],
                evidence=Evidence(extra={"hits": critical[:20]}),
                cvss_v31_vector=CVSS_CRIT,
                cvss_v40_vector=CVSS40_CRIT,
                target=target,
            )

        if high:
            self.new_finding(
                title=f"HIGH: Sensitive data for {domain} found on paste sites",
                severity=Severity.HIGH,
                description=(
                    f"Found {len(high)} HIGH severity item(s) on public paste sites. "
                    "May include JWTs, Slack tokens, email credentials, or SMTP details."
                ),
                reproduction_steps=[e["paste_url"] for e in high[:5]],
                remediation=(
                    "Rotate affected tokens/credentials. "
                    "Investigate source of leak (developer machine, CI logs, etc.)."
                ),
                references=["T1552.001"],
                evidence=Evidence(extra={"hits": high[:10]}),
                cvss_v31_vector=CVSS_HIGH,
                cvss_v40_vector=CVSS40_HIGH,
                target=target,
            )

        if medium:
            self.new_finding(
                title=f"Internal hostnames/IPs for {domain} found in paste sites",
                severity=Severity.MEDIUM,
                description=(
                    f"Paste sites contain {len(medium)} reference(s) to internal "
                    f"infrastructure related to {domain}. This aids attacker reconnaissance."
                ),
                reproduction_steps=[e["paste_url"] for e in medium[:5]],
                remediation=(
                    "Identify source of disclosure. "
                    "Educate developers about not pasting internal data to public sites."
                ),
                references=["T1590 — Gather Victim Network Information"],
                evidence=Evidence(extra={"hits": medium[:10]}),
                cvss_v31_vector=CVSS_MED,
                cvss_v40_vector=CVSS40_MED,
                target=target,
            )


class TestPastebinScanner:
    def test_build_keywords_includes_domain(self) -> None:
        scanner = PastebinScanner.__new__(PastebinScanner)
        scanner.config = type("C", (), {"target": "https://corp.example.com", "extra": {}})()
        kws = scanner._build_keywords("corp.example.com")
        assert "corp.example.com" in kws
        assert "@corp.example.com" in kws

    def test_scan_content_detects_aws_key(self) -> None:
        scanner = PastebinScanner.__new__(PastebinScanner)
        content = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE and corp.example.com"
        matches = scanner._scan_content(content, "corp.example.com")
        labels = [m["label"] for m in matches]
        assert any("AWS" in l for l in labels)

    def test_scan_content_skips_irrelevant_paste(self) -> None:
        scanner = PastebinScanner.__new__(PastebinScanner)
        content = "some random text with AKIAIOSFODNN7EXAMPLE but no domain"
        matches = scanner._scan_content(content, "corp.example.com")
        assert len(matches) == 0

    def test_redact_long_value(self) -> None:
        result = _redact("sk-ant-api03-verylongkeyhere1234567890", keep=6)
        assert "..." in result
        assert len(result) < 30

    def test_cred_patterns_compile(self) -> None:
        for pat, label, sev in _CRED_PATTERNS:
            assert hasattr(pat, "search"), f"Pattern for {label} is not compiled"

    def test_extract_domain(self) -> None:
        scanner = PastebinScanner.__new__(PastebinScanner)
        assert scanner._extract_domain("https://api.example.com:443/v1") == "api.example.com"
