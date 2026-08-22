"""Env File Parser — extract secrets from .env file patterns.

Parses .env / dotenv files and extracts:
  - KEY=VALUE pairs
  - Inline comments (strips them)
  - Multiline values (quoted)
  - Secret classification by key naming convention

FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger("forge.leak_intel.env_parser")

# Keys that almost certainly contain secrets
_HIGH_SENSITIVITY_KEYS = {
    "aws_secret_access_key", "aws_access_key_id", "database_url", "db_password",
    "db_pass", "secret_key", "private_key", "api_secret", "client_secret",
    "jwt_secret", "encryption_key", "master_key", "signing_key",
    "smtp_password", "mail_password", "redis_password", "mongo_password",
    "postgres_password", "mysql_password", "mssql_password",
}

_MEDIUM_SENSITIVITY_KEYS = {
    "api_key", "apikey", "api_token", "access_token", "auth_token",
    "bearer_token", "github_token", "gitlab_token", "slack_token",
    "sendgrid_api_key", "stripe_key", "twilio_auth_token",
    "sentry_dsn", "firebase_api_key", "google_api_key",
}


@dataclass
class EnvSecret:
    """A transient secret extracted from a .env file."""

    key: str
    value: str = field(repr=False)
    sensitivity: str = "LOW"      # HIGH / MEDIUM / LOW
    line_number: int = 0
    source_file: str = ""

    def redacted_value(self) -> str:
        """Return a constant placeholder with no value-derived fragments."""
        return "<redacted>"

    def clear(self) -> None:
        """Best-effort clearing after transfer to a protected reference."""
        self.value = ""

    def __repr__(self) -> str:
        return (
            f"EnvSecret(key={self.key!r}, value=<redacted>, "
            f"sensitivity={self.sensitivity!r}, line_number={self.line_number!r}, "
            f"source_file={self.source_file!r})"
        )


def parse_env_content(content: str, source_file: str = "") -> list[EnvSecret]:
    """Parse .env file content and extract secrets.

    Args:
        content:     Raw .env file text.
        source_file: Source filename for provenance.

    Returns:
        List of EnvSecret objects.
    """
    secrets: list[EnvSecret] = []

    for line_num, line in enumerate(content.splitlines(), start=1):
        line = line.strip()

        # Skip comments and empty lines
        if not line or line.startswith("#"):
            continue

        # Parse KEY=VALUE (supports quotes, inline comments)
        match = re.match(
            r"""^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:
                "([^"]*)"         |  # double-quoted
                '([^']*)'         |  # single-quoted
                ([^\s#]*)            # unquoted (stop at space or #)
            )""",
            line,
            re.VERBOSE,
        )

        if not match:
            continue

        key = match.group(1)
        value = match.group(2) or match.group(3) or match.group(4) or ""

        if not value or value.lower() in ("", "changeme", "todo", "xxx", "placeholder"):
            continue

        # Classify sensitivity
        key_lower = key.lower()
        if key_lower in _HIGH_SENSITIVITY_KEYS:
            sensitivity = "HIGH"
        elif key_lower in _MEDIUM_SENSITIVITY_KEYS:
            sensitivity = "MEDIUM"
        elif any(kw in key_lower for kw in ("secret", "password", "passwd", "pwd", "token", "key", "credential")):
            sensitivity = "MEDIUM"
        else:
            sensitivity = "LOW"

        secrets.append(EnvSecret(
            key=key,
            value=value,
            sensitivity=sensitivity,
            line_number=line_num,
            source_file=source_file,
        ))

    return secrets


def parse_env_file(filepath: str) -> list[EnvSecret]:
    """Parse a .env file from disk.

    Args:
        filepath: Path to the .env file.

    Returns:
        List of EnvSecret objects.
    """
    try:
        from pathlib import Path
        content = Path(filepath).read_text(encoding="utf-8", errors="replace")
        return parse_env_content(content, source_file=filepath)
    except Exception as exc:
        # This module may be used with a plain stdlib logger that has no Forge
        # redaction filter.  Neither the path nor exception text is safe here:
        # decoder/filesystem errors can echo source content or credentials.
        log.error("Failed to parse env file (%s)", type(exc).__name__)
        return []


class TestEnvParser:
    """Unit tests for env_parser."""

    def test_basic_parse(self) -> None:
        content = """
# Database config
DB_HOST=localhost
DB_PASSWORD="super_secret_pass"
API_KEY='my-api-key-1234567890'
EMPTY_VAR=
"""
        secrets = parse_env_content(content, source_file="test.env")
        assert len(secrets) >= 2
        keys = {s.key for s in secrets}
        assert "DB_PASSWORD" in keys
        assert "API_KEY" in keys

    def test_sensitivity_classification(self) -> None:
        content = "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        secrets = parse_env_content(content)
        assert len(secrets) == 1
        assert secrets[0].sensitivity == "HIGH"

    def test_redaction(self) -> None:
        s = EnvSecret(key="TEST", value="mysupersecretvalue")
        redacted = s.redacted_value()
        assert redacted == "<redacted>"
        for fragment in ("mysupersecretvalue", "mys", "lue"):
            assert fragment not in redacted

    def test_skip_placeholders(self) -> None:
        content = "SECRET=changeme\nOTHER=todo\n"
        secrets = parse_env_content(content)
        assert len(secrets) == 0
