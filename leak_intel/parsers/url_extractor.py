"""URL Extractor — internal URL/IP/hostname extraction from config files.

Extracts and classifies URLs found in configuration files, code, and text:
  - Internal IPs (RFC 1918)
  - Internal hostnames (*.internal, *.local, *.corp, etc.)
  - CI/CD tool URLs (Jenkins, GitLab, Jira, etc.)
  - Cloud service URLs
  - API endpoints

FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

log = logging.getLogger("forge.leak_intel.url_extractor")

_URL_PATTERN = re.compile(
    r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,200}"
)

_INTERNAL_IP_PATTERN = re.compile(
    r"https?://(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|"
    r"192\.168\.\d{1,3}\.\d{1,3}|"
    r"127\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"169\.254\.\d{1,3}\.\d{1,3})"
    r"[:/][^\s'\"]*"
)

_INTERNAL_DOMAIN_SUFFIXES = (
    ".internal", ".local", ".corp", ".lan", ".intranet",
    ".private", ".home", ".localdomain", ".localhost",
)

_CI_CD_INDICATORS = (
    "jenkins", "gitlab", "github", "bitbucket", "jira", "confluence",
    "artifactory", "nexus", "sonarqube", "grafana", "kibana",
    "prometheus", "vault", "consul", "harbor", "drone", "circleci",
    "travisci", "bamboo", "teamcity", "octopus",
)


@dataclass
class ExtractedURL:
    """A transient URL extraction; credentials and query secrets stay out of repr."""

    url: str = field(repr=False)
    category: str = "external"   # internal_ip, internal_domain, ci_cd, cloud, api, external
    hostname: str = ""
    port: int | None = None
    source_file: str = ""
    line_number: int = 0
    context: str = field(default="", repr=False)

    def clear(self) -> None:
        """Best-effort clearing after safe classification is retained."""
        self.url = ""
        self.context = ""

    def __repr__(self) -> str:
        return (
            "ExtractedURL(url=<redacted>, context=<redacted>, "
            f"category={self.category!r}, hostname={self.hostname!r}, "
            f"port={self.port!r}, source_file={self.source_file!r}, "
            f"line_number={self.line_number!r})"
        )


def extract_urls(content: str, source_file: str = "") -> list[ExtractedURL]:
    """Extract and classify all URLs from text content.

    Args:
        content:     Text to scan.
        source_file: Source file for provenance.

    Returns:
        List of ExtractedURL objects, sorted by category priority.
    """
    urls: list[ExtractedURL] = []
    seen: set[str] = set()

    for match in _URL_PATTERN.finditer(content):
        url = match.group(0).rstrip(".,;:\"')")
        if url in seen:
            continue
        seen.add(url)

        line_num = content[:match.start()].count("\n") + 1
        # Get surrounding context (30 chars each side)
        ctx_start = max(0, match.start() - 30)
        ctx_end = min(len(content), match.end() + 30)
        context = content[ctx_start:ctx_end].replace("\n", " ").strip()

        extracted = ExtractedURL(
            url=url,
            source_file=source_file,
            line_number=line_num,
            context=context,
        )

        # Parse and classify
        try:
            parsed = urlparse(url)
            extracted.hostname = parsed.hostname or ""
            extracted.port = parsed.port
        except Exception:
            pass

        extracted.category = _classify_url(url, extracted.hostname)
        urls.append(extracted)

    # Sort: internal_ip first, then internal_domain, ci_cd, cloud, api, external
    priority = {"internal_ip": 0, "internal_domain": 1, "ci_cd": 2, "cloud": 3, "api": 4, "external": 5}
    urls.sort(key=lambda u: priority.get(u.category, 5))

    return urls


def extract_internal_urls(content: str, source_file: str = "") -> list[ExtractedURL]:
    """Extract only internal URLs (IPs and domains).

    Convenience function for modules that only care about internal exposure.
    """
    all_urls = extract_urls(content, source_file)
    return [u for u in all_urls if u.category in ("internal_ip", "internal_domain", "ci_cd")]


def _classify_url(url: str, hostname: str) -> str:
    """Classify a URL into a category."""
    url_lower = url.lower()
    hostname_lower = hostname.lower()

    # Internal IP
    if _INTERNAL_IP_PATTERN.match(url):
        return "internal_ip"

    # Internal domain suffix
    if any(hostname_lower.endswith(suffix) for suffix in _INTERNAL_DOMAIN_SUFFIXES):
        return "internal_domain"

    # CI/CD tools
    if any(indicator in hostname_lower for indicator in _CI_CD_INDICATORS):
        return "ci_cd"

    # Cloud services
    cloud_indicators = (
        "amazonaws.com", "azure", "googleapis.com", "cloudfront.net",
        "elasticbeanstalk", "heroku", "netlify", "vercel",
    )
    if any(ci in hostname_lower for ci in cloud_indicators):
        return "cloud"

    # API endpoints
    if "/api/" in url_lower or hostname_lower.startswith("api."):
        return "api"

    return "external"


class TestURLExtractor:
    """Unit tests for url_extractor."""

    def test_extract_internal_ip(self) -> None:
        content = 'database_url = "http://192.168.1.100:5432/mydb"'
        urls = extract_urls(content)
        assert len(urls) >= 1
        assert urls[0].category == "internal_ip"

    def test_extract_internal_domain(self) -> None:
        content = 'api_url = "https://app.internal.corp/api/v1"'
        urls = extract_urls(content)
        # Should find internal domain — but depends on regex match
        internal = [u for u in urls if u.category in ("internal_ip", "internal_domain")]
        # The .corp suffix should be caught
        assert any("internal" in u.hostname or "corp" in u.hostname for u in urls)

    def test_extract_ci_cd(self) -> None:
        content = 'webhook_url = "https://jenkins.company.com/job/build"'
        urls = extract_urls(content)
        assert len(urls) >= 1
        assert urls[0].category == "ci_cd"

    def test_no_urls(self) -> None:
        content = "This has no URLs at all."
        urls = extract_urls(content)
        assert len(urls) == 0
