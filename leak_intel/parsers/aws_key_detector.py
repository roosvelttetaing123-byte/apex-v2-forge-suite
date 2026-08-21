"""AWS key detector with credential validation intentionally disabled at Gate 0.

Detection remains local and side-effect free. Raw key material may be held only
long enough for the caller to move it behind a protected credential reference.
Direct AWS STS validation is not an approved provider boundary; callers must use
``CredentialTester`` with an injected allowlisted provider, exact scope,
credential-use approval, rate bounds, and audit.
"""
from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass, field

from common.redaction import redact_secret_fragments

log = logging.getLogger("forge.leak_intel.aws_key_detector")

# AWS key patterns
_AKIA_PATTERN = re.compile(r"(AKIA[0-9A-Z]{16})")
_SECRET_PATTERN = re.compile(
    r"(?i)(?:aws_secret_access_key|aws_secret|secret_key)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"
)
_SESSION_TOKEN_PATTERN = re.compile(
    r"(?i)(?:aws_session_token|session_token)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{100,})['\"]?"
)


@dataclass
class AWSKeyFinding:
    """Transient detected key material; secret fields are hidden from repr."""

    access_key: str = field(repr=False)
    secret_key: str | None = field(default=None, repr=False)
    session_token: str | None = field(default=None, repr=False)
    source_file: str = ""
    line_number: int = 0
    is_valid: bool | None = None
    account_id: str = ""
    arn: str = ""
    user_id: str = ""

    def __post_init__(self) -> None:
        transient = tuple(
            value
            for value in (self.access_key, self.secret_key, self.session_token)
            if value
        )
        self.source_file = redact_secret_fragments(self.source_file, transient)
        self.account_id = redact_secret_fragments(self.account_id, transient)
        self.arn = redact_secret_fragments(self.arn, transient)
        self.user_id = redact_secret_fragments(self.user_id, transient)

    def redacted_access_key(self) -> str:
        if not self.access_key:
            return ""
        # Access-key identifiers are credential material too; never preserve
        # their prefix/suffix in an ordinary result.
        digest = hashlib.sha256(
            self.access_key.encode("utf-8", "replace")
        ).hexdigest()
        return f"sha256:{digest}"

    def redacted_secret_key(self) -> str:
        if not self.secret_key:
            return ""
        # A masked prefix/suffix is still secret-derived material.  Preserve
        # correlation without exposing any credential characters.
        digest = hashlib.sha256(
            self.secret_key.encode("utf-8", "replace")
        ).hexdigest()
        return f"sha256:{digest}"

    def clear(self) -> None:
        """Best-effort clearing after material moves behind a reference."""
        self.access_key = ""
        self.secret_key = None
        self.session_token = None

    def __repr__(self) -> str:
        return (
            "AWSKeyFinding(access_key=<redacted>, secret_key=<redacted>, "
            "session_token=<redacted>, "
            f"source_file={self.source_file!r}, line_number={self.line_number!r}, "
            f"is_valid={self.is_valid!r})"
        )


def detect_aws_keys(content: str, source_file: str = "") -> list[AWSKeyFinding]:
    """Scan text content for AWS access keys and associated secrets.

    Args:
        content:     Text content to scan.
        source_file: Source file path for provenance.

    Returns:
        List of AWSKeyFinding objects.
    """
    findings: list[AWSKeyFinding] = []
    seen_keys: set[str] = set()

    # Find all AKIA keys
    for match in _AKIA_PATTERN.finditer(content):
        access_key = match.group(1)
        if access_key in seen_keys:
            continue
        seen_keys.add(access_key)

        # Try to find the associated secret key nearby (within 500 chars)
        start = max(0, match.start() - 200)
        end = min(len(content), match.end() + 500)
        context = content[start:end]

        secret_key = None
        secret_match = _SECRET_PATTERN.search(context)
        if secret_match:
            secret_key = secret_match.group(1)

        session_token = None
        token_match = _SESSION_TOKEN_PATTERN.search(context)
        if token_match:
            session_token = token_match.group(1)

        # Calculate line number
        line_num = content[:match.start()].count("\n") + 1

        findings.append(AWSKeyFinding(
            access_key=access_key,
            secret_key=secret_key,
            session_token=session_token,
            source_file=source_file,
            line_number=line_num,
        ))

    return findings


async def validate_aws_key(finding: AWSKeyFinding) -> AWSKeyFinding:
    """Fail closed: direct external credential validation is not authorized.

    Work Package 007 permits validation only through ``CredentialTester`` and
    its injected safe-provider boundary. Keeping this compatibility symbol
    inert prevents library callers from bypassing that policy.
    """
    del finding
    raise PermissionError(
        "direct AWS credential validation is disabled; use the authorized provider boundary"
    )


class TestAWSKeyDetector:
    """Unit tests for aws_key_detector."""

    def test_detect_akia(self) -> None:
        content = "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        findings = detect_aws_keys(content)
        assert len(findings) == 1
        assert findings[0].access_key == "AKIAIOSFODNN7EXAMPLE"

    def test_detect_with_secret(self) -> None:
        content = (
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
            "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        )
        findings = detect_aws_keys(content)
        assert len(findings) == 1
        assert findings[0].secret_key is not None

    def test_redaction(self) -> None:
        f = AWSKeyFinding(access_key="AKIAIOSFODNN7EXAMPLE")
        rendered = f.redacted_access_key()
        assert rendered.startswith("sha256:")
        assert "AKIAIOSF" not in rendered
        assert "MPLE" not in rendered
        assert "AKIAIOSFODNN7EXAMPLE" not in rendered

    def test_no_match(self) -> None:
        content = "This is just regular text with no AWS keys."
        findings = detect_aws_keys(content)
        assert len(findings) == 0
