"""ProfileParser — Malleable C2 Profile System.

YAML-based malleable profiles that control how beacon traffic looks on the wire.
Each profile defines HTTP GET/POST behavior, headers, body transforms, URIs,
user-agents, and timing parameters.

This is the Forge equivalent of Cobalt Strike's Malleable C2 profile language,
but using YAML instead of a custom DSL — because life's too short for yet
another proprietary config format.

Profile Structure:
    name: "office365"
    description: "Mimics Office 365 traffic"
    http_get:
        uri: ["/api/v2.0/me/messages", "/owa/service.svc"]
        headers:
            Host: "outlook.office365.com"
            Accept: "application/json"
        body_transform: base64
    http_post:
        uri: ["/api/v2.0/me/sendmail"]
        headers:
            Content-Type: "application/json"
        body_transform: json_envelope
    beacon:
        sleep: 60
        jitter: 37
        user_agents: [...]
    ssl:
        certificate: {}
        ja3: {}

Usage:
    profile = load_profile("office365")
    # Or from file:
    profile = ProfileParser.from_file("/path/to/custom.yaml")
    # Apply to listener:
    listener.set_profile(profile)

FOR AUTHORIZED RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import copy
import hashlib
import json
import logging
import os
import random
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

log = logging.getLogger("forge.c2.profiles")


# ══════════════════════════════════════════════════════════════════════
# ENUMS & CONSTANTS
# ══════════════════════════════════════════════════════════════════════

class BodyTransform(str, Enum):
    """How to encode beacon data in HTTP body."""
    NONE         = "none"
    BASE64       = "base64"
    BASE64URL    = "base64url"
    JSON_ENVELOPE = "json_envelope"
    XML_ENVELOPE = "xml_envelope"
    PREPEND_APPEND = "prepend_append"
    NETBIOS      = "netbios"       # NetBIOS encoding (a-p for each nibble)
    MASK         = "mask"          # XOR mask with random key


class DataLocation(str, Enum):
    """Where beacon data is placed in the request/response."""
    BODY     = "body"
    HEADER   = "header"
    URI_PATH = "uri_path"
    COOKIE   = "cookie"
    URI_PARAM = "uri_param"


# ══════════════════════════════════════════════════════════════════════
# DATA MODELS
# ══════════════════════════════════════════════════════════════════════

@dataclass
class HttpConfig:
    """Configuration for an HTTP verb (GET or POST)."""
    uri: list[str] = field(default_factory=lambda: ["/"])
    headers: dict[str, str] = field(default_factory=dict)
    body_transform: BodyTransform = BodyTransform.BASE64
    data_location: DataLocation = DataLocation.BODY
    prepend: str = ""           # Prepend to body (before beacon data)
    append: str = ""            # Append to body (after beacon data)
    parameter: str = ""         # Query parameter name for URI_PARAM location
    header_name: str = ""       # Header name for HEADER location
    cookie_name: str = ""       # Cookie name for COOKIE location
    content_type: str = ""      # Explicit Content-Type override

    def random_uri(self) -> str:
        """Get a random URI from the configured list."""
        return random.choice(self.uri) if self.uri else "/"


@dataclass
class BeaconConfig:
    """Beacon timing and behavior configuration."""
    sleep: int = 60               # Base sleep time in seconds
    jitter: int = 37              # Jitter percentage (0-50)
    max_retry: int = 3            # Max consecutive failures before failover
    kill_date: str = ""           # ISO date after which beacon self-destructs
    user_agents: list[str] = field(default_factory=list)
    pipe_name: str = ""           # SMB pipe name for P2P
    spawn_to_x86: str = r"C:\Windows\SysWOW64\rundll32.exe"
    spawn_to_x64: str = r"C:\Windows\System32\rundll32.exe"
    process_inject_min_alloc: int = 17500
    process_inject_transform_prepend: str = ""
    data_jitter: int = 100        # Random bytes appended to messages

    def random_ua(self) -> str:
        """Get a random User-Agent."""
        if self.user_agents:
            return random.choice(self.user_agents)
        return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

    def sleep_with_jitter(self) -> float:
        """Calculate sleep time with jitter."""
        if self.jitter <= 0:
            return float(self.sleep)
        jitter_range = self.sleep * (self.jitter / 100.0)
        return self.sleep + random.uniform(-jitter_range, jitter_range)


@dataclass
class SSLConfig:
    """SSL/TLS configuration for HTTPS listeners."""
    keystore: str = ""
    password: str = ""
    # JA3 fingerprint components (for evasion)
    ja3_cipher_suites: list[str] = field(default_factory=list)
    ja3_extensions: list[str] = field(default_factory=list)
    # Certificate fields for self-signed certs
    cert_cn: str = ""
    cert_org: str = ""
    cert_unit: str = ""
    cert_location: str = ""
    cert_state: str = ""
    cert_country: str = ""
    cert_validity: int = 365      # Days


@dataclass
class DNSConfig:
    """DNS C2 configuration."""
    dns_idle: str = "0.0.0.0"
    dns_sleep: int = 0
    dns_max_txt: int = 252
    dns_ttl: int = 1
    dns_stager_prepend: str = ""
    dns_stager_subhost: str = ""
    beacon_type: str = "dns-txt"  # dns-txt, dns, dns6


@dataclass
class MalleableProfile:
    """Complete malleable C2 profile.

    Defines how all beacon communications look on the wire.
    """
    name: str = "default"
    description: str = ""
    author: str = ""
    version: str = "1.0"

    # HTTP configuration
    http_get: HttpConfig = field(default_factory=HttpConfig)
    http_post: HttpConfig = field(default_factory=HttpConfig)
    http_stager: HttpConfig = field(default_factory=HttpConfig)

    # Beacon behavior
    beacon: BeaconConfig = field(default_factory=BeaconConfig)

    # SSL/TLS
    ssl: SSLConfig = field(default_factory=SSLConfig)

    # DNS
    dns: DNSConfig = field(default_factory=DNSConfig)

    # Global headers applied to all requests
    global_headers: dict[str, str] = field(default_factory=dict)

    # Custom HTTP response headers
    server_headers: dict[str, str] = field(default_factory=dict)

    # Hash for deduplication
    _hash: str = ""

    def compute_hash(self) -> str:
        """Compute a unique hash for this profile."""
        data = json.dumps(self.to_dict(), sort_keys=True).encode()
        self._hash = hashlib.sha256(data).hexdigest()[:12]
        return self._hash

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "name": self.name,
            "description": self.description,
            "author": self.author,
            "version": self.version,
            "http_get": {
                "uri": self.http_get.uri,
                "headers": self.http_get.headers,
                "body_transform": self.http_get.body_transform.value,
                "data_location": self.http_get.data_location.value,
                "prepend": self.http_get.prepend,
                "append": self.http_get.append,
            },
            "http_post": {
                "uri": self.http_post.uri,
                "headers": self.http_post.headers,
                "body_transform": self.http_post.body_transform.value,
                "data_location": self.http_post.data_location.value,
                "prepend": self.http_post.prepend,
                "append": self.http_post.append,
            },
            "beacon": {
                "sleep": self.beacon.sleep,
                "jitter": self.beacon.jitter,
                "user_agents": self.beacon.user_agents,
                "kill_date": self.beacon.kill_date,
            },
            "ssl": {
                "cert_cn": self.ssl.cert_cn,
                "cert_org": self.ssl.cert_org,
            },
            "dns": {
                "beacon_type": self.dns.beacon_type,
                "dns_idle": self.dns.dns_idle,
            },
        }


# ══════════════════════════════════════════════════════════════════════
# PARSER
# ══════════════════════════════════════════════════════════════════════

class ProfileParser:
    """Parse malleable C2 profiles from YAML or dict."""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MalleableProfile:
        """Parse a profile from a dictionary."""
        profile = MalleableProfile()

        # Metadata
        profile.name = data.get("name", "custom")
        profile.description = data.get("description", "")
        profile.author = data.get("author", "")
        profile.version = str(data.get("version", "1.0"))

        # HTTP GET
        if "http_get" in data:
            profile.http_get = cls._parse_http_config(data["http_get"])

        # HTTP POST
        if "http_post" in data:
            profile.http_post = cls._parse_http_config(data["http_post"])

        # HTTP Stager
        if "http_stager" in data:
            profile.http_stager = cls._parse_http_config(data["http_stager"])

        # Beacon
        if "beacon" in data:
            profile.beacon = cls._parse_beacon_config(data["beacon"])

        # SSL
        if "ssl" in data:
            profile.ssl = cls._parse_ssl_config(data["ssl"])

        # DNS
        if "dns" in data:
            profile.dns = cls._parse_dns_config(data["dns"])

        # Global headers
        profile.global_headers = data.get("global_headers", {})
        profile.server_headers = data.get("server_headers", {})

        profile.compute_hash()
        return profile

    @classmethod
    def from_file(cls, path: str | Path) -> MalleableProfile:
        """Load a profile from a YAML file."""
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Profile not found: {path}")

        # Try YAML first, fall back to JSON
        content = path.read_text()
        try:
            import yaml
            data = yaml.safe_load(content)
        except ImportError:
            # No PyYAML — try JSON
            data = json.loads(content)

        if not isinstance(data, dict):
            raise ValueError(f"Profile must be a YAML/JSON object, got {type(data).__name__}")

        return cls.from_dict(data)

    @classmethod
    def _parse_http_config(cls, data: dict[str, Any]) -> HttpConfig:
        """Parse HTTP verb configuration."""
        config = HttpConfig()

        uri = data.get("uri", ["/"])
        config.uri = uri if isinstance(uri, list) else [uri]

        config.headers = data.get("headers", {})
        config.prepend = data.get("prepend", "")
        config.append = data.get("append", "")
        config.parameter = data.get("parameter", "")
        config.header_name = data.get("header_name", "")
        config.cookie_name = data.get("cookie_name", "")
        config.content_type = data.get("content_type", "")

        bt = data.get("body_transform", "base64")
        try:
            config.body_transform = BodyTransform(bt)
        except ValueError:
            config.body_transform = BodyTransform.BASE64

        dl = data.get("data_location", "body")
        try:
            config.data_location = DataLocation(dl)
        except ValueError:
            config.data_location = DataLocation.BODY

        return config

    @classmethod
    def _parse_beacon_config(cls, data: dict[str, Any]) -> BeaconConfig:
        """Parse beacon timing configuration."""
        config = BeaconConfig()
        config.sleep = int(data.get("sleep", 60))
        config.jitter = min(50, max(0, int(data.get("jitter", 37))))
        config.max_retry = int(data.get("max_retry", 3))
        config.kill_date = data.get("kill_date", "")
        config.data_jitter = int(data.get("data_jitter", 100))

        ua = data.get("user_agents", [])
        config.user_agents = ua if isinstance(ua, list) else [ua]

        config.spawn_to_x86 = data.get("spawn_to_x86", config.spawn_to_x86)
        config.spawn_to_x64 = data.get("spawn_to_x64", config.spawn_to_x64)
        config.pipe_name = data.get("pipe_name", "")

        return config

    @classmethod
    def _parse_ssl_config(cls, data: dict[str, Any]) -> SSLConfig:
        """Parse SSL/TLS configuration."""
        config = SSLConfig()
        config.keystore = data.get("keystore", "")
        config.password = data.get("password", "")
        config.cert_cn = data.get("cert_cn", data.get("cn", ""))
        config.cert_org = data.get("cert_org", data.get("org", ""))
        config.cert_unit = data.get("cert_unit", data.get("unit", ""))
        config.cert_location = data.get("cert_location", data.get("location", ""))
        config.cert_state = data.get("cert_state", data.get("state", ""))
        config.cert_country = data.get("cert_country", data.get("country", ""))
        config.cert_validity = int(data.get("cert_validity", 365))

        config.ja3_cipher_suites = data.get("ja3_cipher_suites", [])
        config.ja3_extensions = data.get("ja3_extensions", [])

        return config

    @classmethod
    def _parse_dns_config(cls, data: dict[str, Any]) -> DNSConfig:
        """Parse DNS C2 configuration."""
        config = DNSConfig()
        config.dns_idle = data.get("dns_idle", "0.0.0.0")
        config.dns_sleep = int(data.get("dns_sleep", 0))
        config.dns_max_txt = int(data.get("dns_max_txt", 252))
        config.dns_ttl = int(data.get("dns_ttl", 1))
        config.beacon_type = data.get("beacon_type", "dns-txt")
        return config


# ══════════════════════════════════════════════════════════════════════
# 5 BUILT-IN PROFILES
# ══════════════════════════════════════════════════════════════════════

_OFFICE365_PROFILE = {
    "name": "office365",
    "description": "Mimics Microsoft Office 365 / Outlook Web traffic. "
                   "URIs match real O365 REST API endpoints. "
                   "Headers include O365-specific correlation IDs.",
    "author": "ForgeTeam",
    "http_get": {
        "uri": [
            "/api/v2.0/me/messages",
            "/api/v2.0/me/mailfolders/inbox/messages",
            "/api/v2.0/me/events",
            "/owa/service.svc?action=GetConversationItems",
            "/EWS/Exchange.asmx",
        ],
        "headers": {
            "Host": "outlook.office365.com",
            "Accept": "application/json; odata.metadata=minimal",
            "X-AnchorMailbox": "user@contoso.com",
            "X-ClientId": "1A2B3C4D-5E6F-7A8B-9C0D-1E2F3A4B5C6D",
            "client-request-id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        },
        "body_transform": "json_envelope",
        "data_location": "body",
    },
    "http_post": {
        "uri": [
            "/api/v2.0/me/sendmail",
            "/api/v2.0/me/messages",
            "/owa/service.svc?action=CreateItem",
        ],
        "headers": {
            "Host": "outlook.office365.com",
            "Content-Type": "application/json; charset=utf-8",
            "Accept": "application/json",
        },
        "body_transform": "json_envelope",
    },
    "beacon": {
        "sleep": 60,
        "jitter": 37,
        "user_agents": [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
            "Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.17126; Pro)",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Teams/1.6.00.23461",
        ],
    },
    "ssl": {
        "cert_cn": "outlook.office365.com",
        "cert_org": "Microsoft Corporation",
        "cert_unit": "Microsoft IT",
        "cert_location": "Redmond",
        "cert_state": "WA",
        "cert_country": "US",
    },
    "server_headers": {
        "Server": "Microsoft-IIS/10.0",
        "X-Powered-By": "ASP.NET",
        "X-AspNet-Version": "4.0.30319",
        "request-id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    },
}

_AMAZON_PROFILE = {
    "name": "amazon",
    "description": "Mimics Amazon AWS / CloudFront CDN traffic. "
                   "URIs match S3 and CloudFront patterns.",
    "author": "ForgeTeam",
    "http_get": {
        "uri": [
            "/latest/dynamic/instance-identity/document",
            "/latest/meta-data/iam/security-credentials/",
            "/v20180820/resources",
            "/assets/css/style.css",
            "/images/G/01/x-locale/common/transparent-pixel.gif",
        ],
        "headers": {
            "Host": "d3xxxxxxxxxx.cloudfront.net",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "X-Amz-Cf-Id": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        },
        "body_transform": "base64",
    },
    "http_post": {
        "uri": [
            "/api/2.0/files/upload",
            "/v2/assets",
            "/uploads/",
        ],
        "headers": {
            "Host": "d3xxxxxxxxxx.cloudfront.net",
            "Content-Type": "application/octet-stream",
            "X-Amz-Content-Sha256": "UNSIGNED-PAYLOAD",
        },
        "body_transform": "base64",
    },
    "beacon": {
        "sleep": 45,
        "jitter": 25,
        "user_agents": [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        ],
    },
    "ssl": {
        "cert_cn": "*.cloudfront.net",
        "cert_org": "Amazon",
        "cert_unit": "Server CA 1B",
        "cert_country": "US",
    },
    "server_headers": {
        "Server": "CloudFront",
        "X-Cache": "Hit from cloudfront",
        "X-Amz-Cf-Pop": "IAD89-C1",
        "Via": "1.1 xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.cloudfront.net (CloudFront)",
    },
}

_SLACK_PROFILE = {
    "name": "slack",
    "description": "Mimics Slack workspace API traffic. "
                   "URIs match Slack Web API endpoints.",
    "author": "ForgeTeam",
    "http_get": {
        "uri": [
            "/api/conversations.list",
            "/api/conversations.history",
            "/api/users.list",
            "/api/rtm.connect",
            "/api/team.info",
        ],
        "headers": {
            "Host": "slack.com",
            "Accept": "application/json",
            "X-Slack-Req-Id": "a1b2c3d4-5e6f-7890-abcd-ef1234567890",
        },
        "body_transform": "json_envelope",
        "data_location": "cookie",
        "cookie_name": "d",
    },
    "http_post": {
        "uri": [
            "/api/chat.postMessage",
            "/api/files.upload",
            "/api/chat.update",
        ],
        "headers": {
            "Host": "slack.com",
            "Content-Type": "application/json; charset=utf-8",
        },
        "body_transform": "json_envelope",
    },
    "beacon": {
        "sleep": 30,
        "jitter": 20,
        "user_agents": [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
            "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)",
        ],
    },
    "ssl": {
        "cert_cn": "*.slack.com",
        "cert_org": "Slack Technologies, LLC",
        "cert_country": "US",
    },
    "server_headers": {
        "Server": "Apache",
        "X-Slack-Backend": "r",
        "X-Via": "haproxy-www-ghcv",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
    },
}

_CLOUDFRONT_PROFILE = {
    "name": "cloudfront",
    "description": "Generic CDN / CloudFront traffic pattern. "
                   "Designed for domain fronting scenarios.",
    "author": "ForgeTeam",
    "http_get": {
        "uri": [
            "/assets/bundle.min.js",
            "/static/css/main.css",
            "/media/images/hero.webp",
            "/fonts/roboto-v30-latin-regular.woff2",
            "/favicon.ico",
        ],
        "headers": {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "Cache-Control": "no-cache",
        },
        "body_transform": "base64",
        "data_location": "cookie",
        "cookie_name": "__cf_bm",
    },
    "http_post": {
        "uri": [
            "/api/analytics/event",
            "/api/v1/telemetry",
            "/beacon",
        ],
        "headers": {
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        "body_transform": "json_envelope",
    },
    "beacon": {
        "sleep": 90,
        "jitter": 40,
        "user_agents": [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.85 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        ],
    },
    "ssl": {
        "cert_cn": "*.example.com",
        "cert_org": "Example Corp",
        "cert_country": "US",
    },
    "server_headers": {
        "Server": "cloudflare",
        "CF-RAY": "xxxxxxxxxxxxxxxx-IAD",
        "CF-Cache-Status": "HIT",
        "Alt-Svc": 'h3=":443"; ma=86400',
    },
}

_GENERIC_CDN_PROFILE = {
    "name": "generic_cdn",
    "description": "Minimalist CDN-like profile. Low noise, high compatibility. "
                   "Good default for most engagements.",
    "author": "ForgeTeam",
    "http_get": {
        "uri": [
            "/cdn-cgi/scripts/bundle.js",
            "/static/chunks/main.js",
            "/assets/app.css",
            "/_next/data/build-id/page.json",
        ],
        "headers": {
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
        },
        "body_transform": "base64",
    },
    "http_post": {
        "uri": [
            "/api/v1/events",
            "/collect",
            "/t",
        ],
        "headers": {
            "Content-Type": "text/plain;charset=UTF-8",
        },
        "body_transform": "base64",
    },
    "beacon": {
        "sleep": 60,
        "jitter": 30,
        "user_agents": [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        ],
    },
    "server_headers": {
        "Server": "nginx",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "SAMEORIGIN",
    },
}


# ══════════════════════════════════════════════════════════════════════
# PROFILE REGISTRY
# ══════════════════════════════════════════════════════════════════════

BUILTIN_PROFILES: dict[str, dict[str, Any]] = {
    "office365": _OFFICE365_PROFILE,
    "amazon": _AMAZON_PROFILE,
    "slack": _SLACK_PROFILE,
    "cloudfront": _CLOUDFRONT_PROFILE,
    "generic_cdn": _GENERIC_CDN_PROFILE,
}


def get_builtin_profile(name: str) -> MalleableProfile:
    """Get a built-in profile by name."""
    data = BUILTIN_PROFILES.get(name)
    if data is None:
        available = ", ".join(BUILTIN_PROFILES.keys())
        raise ValueError(f"Unknown profile: {name}. Available: {available}")
    return ProfileParser.from_dict(copy.deepcopy(data))


def load_profile(name_or_path: str) -> MalleableProfile:
    """Load a profile by name (built-in) or file path.

    Priority:
        1. Check built-in profiles
        2. Check builtins/ directory for YAML files
        3. Try as absolute/relative file path
    """
    # 1. Built-in
    if name_or_path in BUILTIN_PROFILES:
        return get_builtin_profile(name_or_path)

    # 2. Builtins directory
    builtins_dir = Path(__file__).parent / "builtins"
    for ext in (".yaml", ".yml", ".json"):
        candidate = builtins_dir / f"{name_or_path}{ext}"
        if candidate.exists():
            return ProfileParser.from_file(candidate)

    # 3. File path
    path = Path(name_or_path)
    if path.exists():
        return ProfileParser.from_file(path)

    # 4. Check FORGE_PROFILES_DIR env var
    profiles_dir = os.environ.get("FORGE_PROFILES_DIR", "")
    if profiles_dir:
        for ext in (".yaml", ".yml", ".json"):
            candidate = Path(profiles_dir) / f"{name_or_path}{ext}"
            if candidate.exists():
                return ProfileParser.from_file(candidate)

    available = ", ".join(BUILTIN_PROFILES.keys())
    raise ValueError(
        f"Profile not found: {name_or_path}\n"
        f"Built-in profiles: {available}\n"
        f"Or provide a path to a .yaml/.json profile file."
    )


def list_profiles() -> list[dict[str, str]]:
    """List all available profiles (built-in + custom files)."""
    profiles = []

    # Built-in
    for name, data in BUILTIN_PROFILES.items():
        profiles.append({
            "name": name,
            "description": data.get("description", ""),
            "author": data.get("author", ""),
            "source": "built-in",
        })

    # Custom files from builtins directory
    builtins_dir = Path(__file__).parent / "builtins"
    if builtins_dir.exists():
        for f in builtins_dir.iterdir():
            if f.suffix in (".yaml", ".yml", ".json") and f.stem not in BUILTIN_PROFILES:
                profiles.append({
                    "name": f.stem,
                    "description": f"Custom profile from {f.name}",
                    "author": "",
                    "source": str(f),
                })

    return profiles
