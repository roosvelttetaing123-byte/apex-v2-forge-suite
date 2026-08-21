"""Central secret redaction for every ordinary Forge trust boundary.

This module deliberately protects ordinary logs, events, findings, reports,
exports, subprocess metadata, and mutable database fields.  It is not an
evidence-custody system: Work Package 102 owns protected-original storage.
"""
from __future__ import annotations

import json
import logging
import os
import re
import threading
from dataclasses import asdict, is_dataclass
from typing import Any, Iterable, Mapping


REDACTED = "<redacted>"

_SAFE_REFERENCE = re.compile(
    r"^(?:(?:cred|credential|artifact):[A-Za-z0-9._:+/-]{8,240}|"
    r"sha256:[0-9a-f]{64})$"
)
_SENSITIVE_FIELD = re.compile(
    r"(?:password|passwd|pwd|secret|token|bearer|cookie|authorization|auth[_-]?(?:key|token)|"
    r"api[_-]?key|access[_-]?key|private[_-]?key|passphrase|community|session[_-]?id|"
    r"connection[_-]?string|client[_-]?secret|nt[_-]?hash|lm[_-]?hash|hash(?:es)?|"
    r"credential(?:s)?|key[_-]?material)",
    re.IGNORECASE,
)
_SAFE_REFERENCE_FIELDS = frozenset(
    {
        "credential_ref",
        "credential_reference",
        "secret_ref",
        "secret_reference",
        "protected_reference",
        "artifact_reference",
    }
)
_SAFE_IDENTIFIER = re.compile(r"^authz-[0-9a-f]{32}$")
_SAFE_IDENTIFIER_FIELDS = frozenset(
    {
        "authorization_decision_id",
        "high_risk_child_decision_id",
        "parent_decision_id",
    }
)

_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:ENCRYPTED |RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
    r"[\s\S]*?(?:-----END (?:ENCRYPTED |RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----|\Z)",
    re.IGNORECASE,
)
_SENSITIVE_HEADER = re.compile(
    r"(?im)^(\s*(?:authorization|proxy-authorization|cookie|set-cookie|"
    r"x-api-key|x-auth-token)\s*:\s*)[^\r\n]*"
)
_AUTH_SCHEME = re.compile(
    r"(?i)\b(bearer|basic|token)\s+[A-Za-z0-9._~+/=-]+"
)
_KEY_VALUE = re.compile(
    r"(?i)(\b(?:password|passwd|pwd|secret|token|bearer|api[_-]?key|access[_-]?key|"
    r"private[_-]?key|passphrase|connection[_-]?string|client[_-]?secret|"
    r"nt[_-]?hash|lm[_-]?hash|cookie)\b\s*[:=]\s*)"
    r"(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;\r\n]+)"
)
_URL_USERINFO = re.compile(
    r"(?i)([a-z][a-z0-9+.-]*://)([^/@\s:]+):([^/@\s]+)@"
)
_QUERY_VALUE = re.compile(
    r"(?i)([?&](?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|"
    r"client[_-]?secret|cookie)=)[^&#\s]+"
)
_JWT = re.compile(
    r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b"
)
_KNOWN_TOKEN = re.compile(
    r"\b(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|"
    r"glpat-[A-Za-z0-9_-]{20,}|sk_(?:live|test)_[A-Za-z0-9]{20,}|"
    r"xox[baprs]-[A-Za-z0-9-]{20,})\b"
)
_HASH_MATERIAL = re.compile(
    r"(?i)(?<![A-Za-z0-9])(?<!job-)(?<!run-)(?<!scan-)(?<!event-)(?<!agent-)(?:[0-9a-f]{32}:[0-9a-f]{32}|"
    r"\$krb5(?:tgs|asrep)\$[^\s]+|\$2[aby]\$[^\s]+|[0-9a-f]{32,128})(?![A-Za-z0-9])"
)
_CANARY = re.compile(
    r"\b(?:CANARY|SENSITIVE_CANARY|SECRET_CANARY)[A-Z0-9_:@./+-]*\b",
    re.IGNORECASE,
)

_configured_fields: set[str] = {
    item.strip().lower()
    for item in os.environ.get("FORGE_SENSITIVE_FIELDS", "").split(",")
    if item.strip()
}
_configured_values: set[str] = set()
_configuration_lock = threading.RLock()


def configure_sensitive_fields(fields: Iterable[str]) -> None:
    """Add deployment-specific field names to the central policy."""
    with _configuration_lock:
        _configured_fields.update(
            str(field).strip().lower() for field in fields if str(field).strip()
        )


def register_sensitive_values(values: Iterable[str]) -> None:
    """Register runtime canaries/secrets that lack a recognizable label.

    Values are retained only in process memory and are never serialized by this
    module.  Callers should register the shortest complete secret value needed.
    """
    with _configuration_lock:
        _configured_values.update(
            str(value) for value in values if isinstance(value, str) and value
        )


def clear_sensitive_values() -> None:
    """Clear runtime literal registrations (primarily for deterministic tests)."""
    with _configuration_lock:
        _configured_values.clear()


def _is_sensitive_field(key: str) -> bool:
    normalized = key.strip().lower()
    with _configuration_lock:
        configured = normalized in _configured_fields
    return configured or bool(_SENSITIVE_FIELD.search(normalized))


def _is_safe_reference(key: str, value: Any) -> bool:
    return (
        key.strip().lower() in _SAFE_REFERENCE_FIELDS
        and isinstance(value, str)
        and bool(_SAFE_REFERENCE.fullmatch(value))
    )


def _is_safe_identifier(key: str, value: Any) -> bool:
    return (
        key.strip().lower() in _SAFE_IDENTIFIER_FIELDS
        and isinstance(value, str)
        and bool(_SAFE_IDENTIFIER.fullmatch(value))
    )


def redact_text(value: str) -> str:
    """Redact secrets embedded in free-form, multiline text."""
    if not value:
        return value
    if _SAFE_REFERENCE.fullmatch(value):
        return value

    rendered = value
    with _configuration_lock:
        literals = tuple(sorted(_configured_values, key=len, reverse=True))
    for literal in literals:
        rendered = rendered.replace(literal, REDACTED)

    # Match complete PEM blocks and malformed/truncated blocks alike.  Once a
    # private-key header is observed without a footer, the remaining value is
    # treated as key material and removed through the end of the string.
    rendered = _PRIVATE_KEY.sub(REDACTED, rendered)
    rendered = _SENSITIVE_HEADER.sub(lambda match: match.group(1) + REDACTED, rendered)
    rendered = _AUTH_SCHEME.sub(lambda match: f"{match.group(1)} {REDACTED}", rendered)
    rendered = _KEY_VALUE.sub(lambda match: match.group(1) + REDACTED, rendered)
    rendered = _URL_USERINFO.sub(lambda match: match.group(1) + REDACTED + ":" + REDACTED + "@", rendered)
    rendered = _QUERY_VALUE.sub(lambda match: match.group(1) + REDACTED, rendered)
    rendered = _JWT.sub(REDACTED, rendered)
    rendered = _KNOWN_TOKEN.sub(REDACTED, rendered)
    rendered = _HASH_MATERIAL.sub(REDACTED, rendered)
    rendered = _CANARY.sub(REDACTED, rendered)
    return rendered


def redact_secret_fragments(
    value: Any,
    secrets: Iterable[str],
    *,
    min_fragment: int = 8,
) -> str:
    """Remove exact secrets and secret-derived identifier fragments from text.

    Ordinary redaction catches complete, labelled values.  Metadata supplied
    alongside a detected credential can still contain a prefix or suffix of
    that credential (for example in a file name, URL, or username).  Compare
    alphanumeric metadata tokens with the transient complete values and remove
    only tokens that are proven substrings of those values.
    """
    rendered = redact_text(str(value))
    complete = tuple(
        sorted(
            {
                str(secret)
                for secret in secrets
                if isinstance(secret, str) and secret
            },
            key=len,
            reverse=True,
        )
    )
    for secret in complete:
        rendered = rendered.replace(secret, REDACTED)
    threshold = max(4, int(min_fragment))
    tokens = {
        token
        for token in re.findall(rf"[A-Za-z0-9]{{{threshold},}}", rendered)
        if token.lower() != "redacted"
    }
    for token in sorted(tokens, key=len, reverse=True):
        if any(token in secret for secret in complete):
            rendered = rendered.replace(token, REDACTED)
    return redact_text(rendered)


def redact_exception(exc: BaseException) -> str:
    """Return a redacted exception chain without traceback locals."""
    chain: list[str] = []
    current: BaseException | None = exc
    seen: set[int] = set()
    while current is not None and len(chain) < 8 and id(current) not in seen:
        seen.add(id(current))
        chain.append(redact_text(str(current)))
        if current.__cause__ is not None:
            current = current.__cause__
        elif current.__suppress_context__:
            current = None
        else:
            current = current.__context__
    return " caused by ".join(chain)


def redact_value(value: Any, _seen: set[int] | None = None) -> Any:
    """Recursively redact mappings, sequences, dataclasses, objects, and errors."""
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, bytes):
        return redact_text(value.decode("utf-8", errors="replace"))
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, BaseException):
        return redact_exception(value)

    seen = set() if _seen is None else _seen
    identity = id(value)
    if identity in seen:
        return "<redacted-cycle>"
    seen.add(identity)
    try:
        if isinstance(value, Mapping):
            output: dict[str, Any] = {}
            for raw_key, item in value.items():
                key = redact_text(str(raw_key))
                if _is_safe_reference(key, item) or _is_safe_identifier(key, item):
                    output[key] = item
                elif _is_sensitive_field(key):
                    output[key] = REDACTED
                else:
                    output[key] = redact_value(item, seen)
            return output
        if is_dataclass(value) and not isinstance(value, type):
            return redact_value(asdict(value), seen)
        if isinstance(value, (list, tuple, set, frozenset)):
            return [redact_value(item, seen) for item in value]
        if hasattr(value, "__dict__"):
            return redact_value(vars(value), seen)
        return redact_text(str(value))
    finally:
        seen.discard(identity)


def redacted_json_dumps(value: Any, **kwargs: Any) -> str:
    """Serialize only the redacted form of a value."""
    return json.dumps(redact_value(value), **kwargs)


class RedactionFilter(logging.Filter):
    """Logging filter that sanitizes message args, extras, and exceptions."""

    _STANDARD = frozenset(logging.makeLogRecord({}).__dict__)

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:
            message = str(record.msg)
        if record.exc_info and isinstance(record.exc_info[1], BaseException):
            message = f"{message} | exception={redact_exception(record.exc_info[1])}"
            record.exc_info = None
            record.exc_text = None
        record.msg = redact_text(message)
        record.args = ()
        for key, item in list(record.__dict__.items()):
            if key not in self._STANDARD and key not in {"message", "asctime"}:
                record.__dict__[key] = redact_value(item)
        return True


_FILTER = RedactionFilter()


def redaction_filter() -> RedactionFilter:
    """Return the shared filter instance for all handlers."""
    return _FILTER


_DISPATCH_REDACTION_MARKER = "_forge_redacts_before_handler_dispatch"


def install_logging_redaction() -> None:
    """Redact each record once immediately before logging dispatch.

    Handler filters alone leave root handlers, propagated records, handlers
    installed later, and ``logging.lastResort`` outside the policy.  Wrapping
    ``Logger.callHandlers`` covers those routes after ``extra`` fields have
    been attached to the record and before any handler receives it.

    Preserve a previously installed implementation and mark the wrapper so
    module reloads or repeated setup calls remain idempotent.
    """
    with _configuration_lock:
        current = logging.Logger.callHandlers
        if getattr(current, _DISPATCH_REDACTION_MARKER, False):
            return

        def _redacting_call_handlers(
            logger: logging.Logger,
            record: logging.LogRecord,
        ) -> None:
            redaction_filter().filter(record)
            current(logger, record)

        setattr(_redacting_call_handlers, _DISPATCH_REDACTION_MARKER, True)
        setattr(logging.Logger, "callHandlers", _redacting_call_handlers)


install_logging_redaction()
