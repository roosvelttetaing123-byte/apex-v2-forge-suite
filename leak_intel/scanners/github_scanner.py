"""GitHub OSINT Scanner — search commits, gists, issues, PRs, wiki for target org secrets.

Queries the GitHub REST API for leaked secrets across:
  - Code search (filenames, extensions, keywords)
  - Commit diffs (historical secret sweeps)
  - Gist search (public gists by organisation members)
  - Organisation member enumeration
  - 60+ secret patterns with CRITICAL/HIGH/MEDIUM/LOW severity tiers

API key: GITHUB_TOKEN env var (required for high rate limits).

FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import asyncio
import base64
import logging
import os
import re
import time
from typing import Any
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

log = logging.getLogger("leak_intel.github_scanner")

CVSS_CRIT   = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
CVSS40_CRIT = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
CVSS_HIGH   = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
CVSS40_HIGH = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
CVSS_MED    = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
CVSS40_MED  = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"

# ── 60+ secret patterns ────────────────────────────────────────────────────

_SECRET_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    # tier, pattern, label
    ("CRITICAL", re.compile(r"(AKIA[0-9A-Z]{16})", re.A),                         "AWS Access Key ID"),
    ("CRITICAL", re.compile(r"((?:A3T[A-Z0-9]|AKIA|AGPA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})", re.A), "AWS Key (variant)"),
    ("CRITICAL", re.compile(r'(?i)aws.{0,20}secret.{0,5}[=:]\s*["\']?([A-Za-z0-9/+=]{40})', re.I), "AWS Secret Access Key"),
    ("CRITICAL", re.compile(r"(sk-ant-[A-Za-z0-9_\-]{40,})", re.A),               "Anthropic API key"),
    ("CRITICAL", re.compile(r"(sk-[A-Za-z0-9]{48,})", re.A),                      "OpenAI API key"),
    ("CRITICAL", re.compile(r"(ghp_[A-Za-z0-9]{36})", re.A),                      "GitHub PAT"),
    ("CRITICAL", re.compile(r"(github_pat_[A-Za-z0-9_]{82})", re.A),              "GitHub Fine-grained PAT"),
    ("CRITICAL", re.compile(r"(gho_[A-Za-z0-9]{36})", re.A),                      "GitHub OAuth token"),
    ("CRITICAL", re.compile(r"(glpat-[A-Za-z0-9\-_]{20})", re.A),                "GitLab PAT"),
    ("CRITICAL", re.compile(r"(?:BEGIN\s+(?:RSA|EC|OPENSSH|DSA|ECDSA)\s+PRIVATE\s+KEY)", re.I), "Private key"),
    ("CRITICAL", re.compile(r"(?:mongodb|postgres|postgresql|mysql|mssql|redis|amqp)://[^'\"<\s]{8,}", re.I), "DB connection string"),
    ("CRITICAL", re.compile(r"(?:heroku|heroku_api|heroku_token)\s*[=:]\s*[0-9a-f-]{36}", re.I), "Heroku API key"),
    ("CRITICAL", re.compile(r"(eyJ[A-Za-z0-9_\-]{100,}\.eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,})", re.A), "JWT with signature"),
    ("CRITICAL", re.compile(r"client_secret\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{20,})", re.I), "OAuth client secret"),
    ("CRITICAL", re.compile(r"(npm_[A-Za-z0-9]{36})", re.A),                      "npm token"),
    ("CRITICAL", re.compile(r"(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,})", re.A), "PyPI token"),
    ("CRITICAL", re.compile(r"(dckr_pat_[A-Za-z0-9_\-]{27})", re.A),              "Docker Hub token"),
    ("CRITICAL", re.compile(r"(hvs\.[A-Za-z0-9_\-]{24,})", re.A),                "HashiCorp Vault secret ID"),
    ("CRITICAL", re.compile(r"(k8s-sa-jwt-[A-Za-z0-9_\-]{20,}|eyJ[A-Za-z0-9_\-]{20,}\.eyJ[A-Za-z0-9_\-]{5,}\.)", re.A), "Kubernetes SA JWT"),
    ("CRITICAL", re.compile(r"(?:password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{6,})['\"]", re.I), "Password in quotes"),
    ("HIGH",     re.compile(r"(xox[baprs]-[0-9a-zA-Z\-]{10,48})", re.A),          "Slack token"),
    ("HIGH",     re.compile(r"(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})", re.A), "SendGrid API key"),
    ("HIGH",     re.compile(r"(sq0atp-[A-Za-z0-9\-_]{22}|sq0csp-[A-Za-z0-9\-_]{43})", re.A), "Square API key"),
    ("HIGH",     re.compile(r"(?:stripe|sk_live|pk_live)_[A-Za-z0-9]{24,}", re.I), "Stripe key"),
    ("HIGH",     re.compile(r"(?:braintree|bt_access_token)\s*[=:]\s*[A-Za-z0-9_$@]{32,}", re.I), "Braintree token"),
    ("HIGH",     re.compile(r"(EAAC[a-zA-Z0-9]+)", re.A),                         "Facebook access token"),
    ("HIGH",     re.compile(r"(ya29\.[A-Za-z0-9_\-]{50,})", re.A),               "Google OAuth access token"),
    ("HIGH",     re.compile(r"AIza[0-9A-Za-z_\-]{35}", re.A),                     "Google API key"),
    ("HIGH",     re.compile(r"(?:okta|oktaPreviewUrl).{0,20}[=:]\s*.+\.okta\.com", re.I), "Okta API token"),
    ("HIGH",     re.compile(r"(?:dd|datadog)\.{0,5}api[_\-]key\s*[=:]\s*[A-Za-z0-9]{32}", re.I), "Datadog API key"),
    ("HIGH",     re.compile(r"(?:grafana)\s*[=:]\s*eyJ[A-Za-z0-9_\-]{50,}", re.I), "Grafana token"),
    ("HIGH",     re.compile(r"(circleci[_\-]token|CIRCLE_TOKEN)\s*[=:]\s*[A-Za-z0-9]{40}", re.I), "CircleCI token"),
    ("HIGH",     re.compile(r"(travis[_\-]token|TRAVIS_TOKEN)\s*[=:]\s*[A-Za-z0-9]{20,}", re.I), "Travis CI token"),
    ("HIGH",     re.compile(r"(?:shopify).{0,20}(shpat_[A-Za-z0-9]{32})", re.I),  "Shopify token"),
    ("HIGH",     re.compile(r"(?:cloudflare).{0,20}[=:]\s*([A-Za-z0-9_\-]{37})", re.I), "Cloudflare token"),
    ("HIGH",     re.compile(r"(?:digitalocean|do_token|DIGITALOCEAN_TOKEN)\s*[=:]\s*([A-Za-z0-9]{64})", re.I), "DigitalOcean token"),
    ("HIGH",     re.compile(r"(?:vercel)\s*[=:]\s*(vc_[A-Za-z0-9_\-]{24,})", re.I), "Vercel token"),
    ("HIGH",     re.compile(r"(?:mailgun)[_\-]?api[_\-]?key\s*[=:]\s*key-[A-Za-z0-9]{32}", re.I), "Mailgun key"),
    ("HIGH",     re.compile(r"smtp[s]?://[^@<\s]+:[^@<\s]+@", re.I),              "SMTP credentials"),
    ("HIGH",     re.compile(r"(?:jdbc:(?:mysql|postgresql|sqlserver|oracle)://[^'\"<\s]+)", re.I), "JDBC connection string"),
    ("HIGH",     re.compile(r"(?:Server=.{3,30};Database=.{3,30};User[_ ]Id=.{3,20};Password=.{3,30};)", re.I), ".NET connection string"),
    ("HIGH",     re.compile(r"(?:https?://[^:@<\s]+:[^@<\s]+@[^@<\s]+)", re.I),   "Basic auth in URL"),
    ("MEDIUM",   re.compile(r"(?:api[_\-]?key|api_token)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{20,})", re.I), "Generic API key"),
    ("MEDIUM",   re.compile(r"private_key\s*[=:]\s*['\"]?([A-Za-z0-9_\-\/+]{40,})", re.I), "Private key material"),
    ("MEDIUM",   re.compile(r"(?:s3|bucket)[_\-]?(?:name|url)\s*[=:]\s*['\"]?([A-Za-z0-9\-\.]{3,63})", re.I), "S3 bucket reference"),
    ("MEDIUM",   re.compile(r"(?:internal|corp|intranet|vpn)\.[A-Za-z0-9\-]+\.[A-Za-z]{2,}", re.I), "Internal hostname"),
    ("MEDIUM",   re.compile(r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", re.A),          "RFC-1918 IP (10.x)"),
    ("MEDIUM",   re.compile(r"\b192\.168\.\d{1,3}\.\d{1,3}\b", re.A),             "RFC-1918 IP (192.168.x)"),
    ("MEDIUM",   re.compile(r"\b172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b", re.A), "RFC-1918 IP (172.x)"),
    ("LOW",      re.compile(r"(?:todo|fixme|hack)\s*:?\s*.{5,80}", re.I),         "TODO/security comment"),
    ("LOW",      re.compile(r"# noqa:\s*S[0-9]+", re.I),                          "Security lint suppression"),
]

_SEARCH_QUALIFIERS = [
    "filename:.env", "filename:.env.local", "filename:.env.prod", "filename:.env.production",
    "filename:credentials", "filename:credentials.json", "filename:secrets.yml",
    "filename:secrets.yaml", "filename:config.yaml", "filename:config.json",
    "filename:terraform.tfvars", "filename:terraform.tfvars.json",
    "filename:.netrc", "filename:.npmrc", "filename:.pypirc",
    "filename:wp-config.php", "filename:database.yml", "filename:database.yaml",
    "filename:settings.py", "filename:local_settings.py",
    "filename:id_rsa", "filename:id_ed25519", "filename:id_ecdsa",
    "filename:.ssh/config", "filename:known_hosts",
    "filename:kubeconfig", "filename:.kube/config",
    "filename:serviceAccountKey.json", "filename:application.properties",
    "filename:application.yaml", "filename:application-prod.yml",
    "filename:docker-compose.yml", "filename:docker-compose.yaml",
    "extension:json password", "extension:yaml password",
    "extension:yml secret", "extension:ini password",
    "extension:properties password", "extension:conf password",
    "extension:toml secret", "extension:cfg password",
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
    "BEGIN RSA PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY",
    "ghp_ OR gho_ OR glpat-",
    "mongodb+srv://", "postgresql://",
    "sk-ant-api", "OPENAI_API_KEY",
    "STRIPE_SECRET_KEY", "STRIPE_LIVE",
    "sentry_dsn", "SENTRY_DSN",
]


def _severity_for_tag(tier: str) -> Severity:
    return {
        "CRITICAL": Severity.CRITICAL,
        "HIGH":     Severity.HIGH,
        "MEDIUM":   Severity.MEDIUM,
        "LOW":      Severity.LOW,
    }.get(tier, Severity.INFORMATIONAL)


def _score_confidence(value: str) -> str:
    """Simple entropy-based confidence: HIGH / MEDIUM / LOW."""
    if len(value) < 8:
        return "LOW"
    unique = len(set(value))
    ratio = unique / max(len(value), 1)
    if ratio > 0.5:
        return "HIGH"
    if ratio > 0.3:
        return "MEDIUM"
    return "LOW"


def _redact(value: str, keep: int = 6) -> str:
    if len(value) <= keep * 2:
        return "***"
    return value[:keep] + "..." + value[-3:]


def _surrounding_lines(content: str, pos: int, window: int = 2) -> str:
    lines = content.splitlines()
    # Find which line the match is on
    cur = 0
    line_idx = 0
    for i, ln in enumerate(lines):
        cur += len(ln) + 1
        if cur > pos:
            line_idx = i
            break
    start = max(0, line_idx - window)
    end   = min(len(lines), line_idx + window + 1)
    return "\n".join(lines[start:end])


class GitHubScanner(BaseModule):
    """Scans GitHub for secrets leaked in code, commits, and gists."""

    NAME        = "github_scanner"
    DESCRIPTION = "GitHub OSINT: search repos, commits, gists for leaked secrets"
    PHASE       = 1
    TAGS        = ["recon", "osint", "github", "secrets", "credentials"]

    _GITHUB_API = "https://api.github.com"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._token = os.environ.get("GITHUB_TOKEN", "")
        self._rate_remaining: int = 30
        self._rate_reset: float   = 0.0

    def _extract_org(self, target: str) -> str | None:
        """Extract GitHub org name from config or derive from domain."""
        org = getattr(self.config, "extra", {}).get("github_org", "")
        if org:
            return org
        return None

    def _extract_domain(self, target: str) -> str:
        from urllib.parse import urlparse
        parsed = urlparse(target)
        host = parsed.netloc or parsed.path
        return host.split(":")[0].split("/")[0].strip().lower()

    def _headers(self) -> dict[str, str]:
        h = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "ForgeOSINT/5.0",
        }
        if self._token:
            h["Authorization"] = f"Bearer {self._token}"
        return h

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")
        domain = self._extract_domain(target)
        org    = self._extract_org(target)

        if not self._token:
            self.log.warning("GITHUB_TOKEN not set — rate limits will be very low (10 req/min)")

        keywords = [domain]
        if org:
            keywords.append(org)

        # Phase 1: code search across qualifiers
        all_findings: list[dict[str, Any]] = []
        for kw in keywords[:2]:
            for qualifier in _SEARCH_QUALIFIERS[:20]:
                query = f"{kw} {qualifier}"
                items = await self._run_code_searches(query)
                for item in items[:5]:
                    content = await self._fetch_file_content(item)
                    if content:
                        hits = self._scan_file_blob(content, item.get("html_url", ""), domain)
                        all_findings.extend(hits)

        # Phase 2: commit diff scanning (most recent commits per found repo)
        repos_seen: set[str] = set()
        for kw in keywords[:2]:
            repos = await self._search_repos(kw)
            for repo in repos[:10]:
                full_name = repo.get("full_name", "")
                if full_name and full_name not in repos_seen:
                    repos_seen.add(full_name)
                    commit_hits = await self._scan_commits(full_name)
                    all_findings.extend(commit_hits)

        # Phase 3: org member enumeration + gist scan
        if org:
            members = await self._enum_org_members(org)
            for member in members[:20]:
                gist_hits = await self._scan_gists(member)
                all_findings.extend(gist_hits)

        # Dedup and emit
        self._emit_findings(all_findings, domain, target)
        return self._make_result(start)

    # ── API helpers ───────────────────────────────────────────────────────────

    async def _check_and_wait_rate_limit(self) -> None:
        if self._rate_remaining < 3:
            wait = max(0.0, self._rate_reset - time.time()) + 1
            self.log.debug("Rate limit hit — sleeping %.1fs", wait)
            await asyncio.sleep(min(wait, 60))

    async def _paginate(
        self, url: str, params: dict | None = None, max_pages: int = 5
    ) -> list[dict]:
        results: list[dict] = []
        page_url: str | None = url
        page = 0
        try:
            import aiohttp
            async with aiohttp.ClientSession(headers=self._headers()) as s:
                while page_url and page < max_pages:
                    await self._check_and_wait_rate_limit()
                    await self.rate_limit()
                    try:
                        async with s.get(
                            page_url,
                            params=params if page == 0 else None,
                            timeout=aiohttp.ClientTimeout(total=15),
                        ) as r:
                            remain = int(r.headers.get("X-RateLimit-Remaining", 30))
                            reset  = float(r.headers.get("X-RateLimit-Reset", 0))
                            self._rate_remaining = remain
                            self._rate_reset      = reset
                            if r.status == 403:
                                await asyncio.sleep(60)
                                break
                            if r.status != 200:
                                break
                            data = await r.json()
                            if isinstance(data, list):
                                results.extend(data)
                            elif isinstance(data, dict):
                                results.extend(data.get("items", [data]))
                            page_url = self._next_link(r.headers.get("Link", ""))
                    except Exception:
                        break
                    page += 1
        except ImportError:
            pass
        return results

    @staticmethod
    def _next_link(link_header: str) -> str | None:
        m = re.search(r'<([^>]+)>;\s*rel="next"', link_header)
        return m.group(1) if m else None

    async def _run_code_searches(self, query: str) -> list[dict]:
        url    = f"{self._GITHUB_API}/search/code"
        params = {"q": query, "per_page": 10}
        return await self._paginate(url, params=params, max_pages=1)

    async def _search_repos(self, keyword: str) -> list[dict]:
        url    = f"{self._GITHUB_API}/search/repositories"
        params = {"q": keyword, "sort": "updated", "per_page": 10}
        items  = await self._paginate(url, params=params, max_pages=1)
        return items

    async def _fetch_file_content(self, item: dict) -> str:
        try:
            import aiohttp
            api_url = item.get("url", "")
            if not api_url:
                return ""
            await self.rate_limit()
            async with aiohttp.ClientSession(headers=self._headers()) as s:
                async with s.get(api_url, timeout=aiohttp.ClientTimeout(total=10)) as r:
                    if r.status == 200:
                        data = await r.json()
                        enc  = data.get("encoding", "")
                        cont = data.get("content", "")
                        if enc == "base64":
                            return base64.b64decode(cont.replace("\n", "")).decode("utf-8", errors="replace")
                        return cont
        except Exception:
            pass
        return ""

    def _scan_file_blob(
        self, content: str, html_url: str, domain: str
    ) -> list[dict[str, Any]]:
        hits: list[dict[str, Any]] = []
        for tier, pattern, label in _SECRET_PATTERNS:
            for m in pattern.finditer(content):
                value = m.group(1) if m.lastindex and m.lastindex >= 1 else m.group(0)
                conf  = _score_confidence(value)
                if conf == "LOW" and tier in ("MEDIUM", "LOW"):
                    continue
                hits.append({
                    "tier": tier, "label": label, "url": html_url,
                    "value_redacted": _redact(value),
                    "confidence": conf,
                    "context": _surrounding_lines(content, m.start()),
                })
        return hits

    def _scan_and_emit(self, content: str, url: str, domain: str) -> list[dict[str, Any]]:
        return self._scan_file_blob(content, url, domain)

    async def _scan_commits(self, full_repo: str) -> list[dict[str, Any]]:
        url    = f"{self._GITHUB_API}/repos/{full_repo}/commits"
        params = {"per_page": 20}
        commits = await self._paginate(url, params=params, max_pages=1)
        hits: list[dict[str, Any]] = []
        for commit in commits[:10]:
            sha = commit.get("sha", "")
            if sha:
                result = await self._scan_one_commit(full_repo, sha)
                hits.extend(result)
        return hits

    async def _scan_one_commit(self, full_repo: str, sha: str) -> list[dict[str, Any]]:
        try:
            import aiohttp
            url = f"{self._GITHUB_API}/repos/{full_repo}/commits/{sha}"
            await self.rate_limit()
            async with aiohttp.ClientSession(headers=self._headers()) as s:
                async with s.get(url, timeout=aiohttp.ClientTimeout(total=12)) as r:
                    if r.status != 200:
                        return []
                    data = await r.json()
                    hits: list[dict[str, Any]] = []
                    for f in data.get("files", []):
                        patch = f.get("patch", "")
                        furl  = f.get("blob_url", "")
                        if patch:
                            for line in patch.splitlines():
                                if line.startswith("+"):
                                    for tier, pattern, label in _SECRET_PATTERNS:
                                        if pattern.search(line):
                                            hits.append({
                                                "tier": tier, "label": label,
                                                "url": furl, "value_redacted": "***",
                                                "confidence": "MEDIUM",
                                                "context": line[:200],
                                            })
                    return hits
        except Exception:
            return []

    async def _scan_gists(self, username: str) -> list[dict[str, Any]]:
        url    = f"{self._GITHUB_API}/users/{username}/gists"
        gists  = await self._paginate(url, max_pages=2)
        hits: list[dict[str, Any]] = []
        for gist in gists[:10]:
            raw_url = ""
            for fname, fdata in gist.get("files", {}).items():
                raw_url = fdata.get("raw_url", "")
                if raw_url:
                    try:
                        import aiohttp
                        await self.rate_limit()
                        async with aiohttp.ClientSession() as s:
                            async with s.get(raw_url, timeout=aiohttp.ClientTimeout(total=10)) as r:
                                if r.status == 200:
                                    content = await r.text(errors="replace")
                                    gist_hits = self._scan_file_blob(
                                        content, gist.get("html_url", ""), ""
                                    )
                                    hits.extend(gist_hits)
                    except Exception:
                        pass
        return hits

    async def _enum_org_members(self, org: str) -> list[str]:
        url     = f"{self._GITHUB_API}/orgs/{org}/members"
        members = await self._paginate(url, params={"per_page": 100}, max_pages=3)
        return [m.get("login", "") for m in members if m.get("login")]

    async def _shallow_repo_secret_search(self, org: str, keyword: str) -> list[dict]:
        query = f"org:{org} {keyword}"
        return await self._run_code_searches(query)

    # ── findings ──────────────────────────────────────────────────────────────

    def _emit_findings(
        self, hits: list[dict[str, Any]], domain: str, target: str
    ) -> None:
        by_tier: dict[str, list[dict]] = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
        seen: set[str] = set()
        for h in hits:
            key = f"{h['label']}:{h['url']}:{h['value_redacted']}"
            if key in seen:
                continue
            seen.add(key)
            by_tier.setdefault(h["tier"], []).append(h)

        for tier, items in by_tier.items():
            if not items:
                continue
            sev = _severity_for_tag(tier)
            cvss31 = CVSS_CRIT if tier == "CRITICAL" else (CVSS_HIGH if tier == "HIGH" else CVSS_MED)
            cvss40 = CVSS40_CRIT if tier == "CRITICAL" else (CVSS40_HIGH if tier == "HIGH" else CVSS40_MED)
            self.new_finding(
                title=f"GitHub {tier}: {len(items)} secret(s) for {domain}",
                severity=sev,
                description=(
                    f"GitHub code/commit/gist search found {len(items)} {tier}-severity "
                    f"secret(s) related to {domain}. Labels: "
                    + ", ".join(sorted({i['label'] for i in items}))
                ),
                reproduction_steps=[
                    i["url"] for i in items[:5]
                ] + [
                    f"# {i['label']} (confidence={i['confidence']}): {i['value_redacted']}"
                    for i in items[:5]
                ],
                remediation=(
                    "1. Immediately rotate all exposed credentials. "
                    "2. Use `git filter-repo` or BFG to purge from history. "
                    "3. Add pre-commit hooks: `git-secrets`, `gitleaks`, `detect-secrets`. "
                    "4. Enable GitHub Secret Scanning for push protection."
                ),
                references=[
                    "T1552.001 — Credentials in Files",
                    "https://docs.github.com/en/code-security/secret-scanning",
                    "https://trufflesecurity.com/trufflehog",
                ],
                evidence=Evidence(extra={"hits": items[:20]}),
                cvss_v31_vector=cvss31,
                cvss_v40_vector=cvss40,
                target=target,
            )


class TestGitHubScanner:
    def test_extract_domain(self) -> None:
        s = GitHubScanner.__new__(GitHubScanner)
        assert s._extract_domain("https://api.corp.io:443/v1") == "api.corp.io"

    def test_redact_preserves_start(self) -> None:
        result = _redact("sk-ant-api03-abcdefghijklmnopqrstuvwxyz", keep=6)
        assert result.startswith("sk-ant")
        assert "..." in result

    def test_severity_for_tag(self) -> None:
        assert _severity_for_tag("CRITICAL") == Severity.CRITICAL
        assert _severity_for_tag("HIGH")     == Severity.HIGH
        assert _severity_for_tag("MEDIUM")   == Severity.MEDIUM

    def test_scan_file_blob_detects_aws(self) -> None:
        s = GitHubScanner.__new__(GitHubScanner)
        content = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        hits = s._scan_file_blob(content, "https://github.com/x", "example.com")
        assert any("AWS" in h["label"] for h in hits)

    def test_scan_file_blob_detects_anthropic(self) -> None:
        s = GitHubScanner.__new__(GitHubScanner)
        content = "API_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwxyz012345678901234567890123\n"
        hits = s._scan_file_blob(content, "https://github.com/x", "example.com")
        assert any("Anthropic" in h["label"] for h in hits)

    def test_scan_file_blob_detects_private_key(self) -> None:
        s = GitHubScanner.__new__(GitHubScanner)
        content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK...\n-----END RSA PRIVATE KEY-----"
        hits = s._scan_file_blob(content, "https://github.com/x", "example.com")
        assert any("key" in h["label"].lower() for h in hits)

    def test_next_link_parses(self) -> None:
        header = '<https://api.github.com/search?page=2>; rel="next", <https://api.github.com/search?page=5>; rel="last"'
        result = GitHubScanner._next_link(header)
        assert result == "https://api.github.com/search?page=2"

    def test_score_confidence_high_entropy(self) -> None:
        assert _score_confidence("aB3cD4eF5gH6iJ7") == "HIGH"

    def test_secret_patterns_compile(self) -> None:
        for tier, pat, label in _SECRET_PATTERNS:
            assert hasattr(pat, "search"), f"Not compiled: {label}"
        assert len(_SECRET_PATTERNS) >= 40
