"""Ordered, reversible migrations for the Task 101 canonical schema.

The legacy ``common.db`` schema remains available to existing callers.  This
module owns only the additive canonical tables and a small legacy-record
archive.  Each step is journaled before execution and marked applied only in
the same transaction as its DDL/data changes.  A process interrupted after
the journal write is safely recovered by replaying the idempotent step.
"""
from __future__ import annotations

import json
import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

from sqlalchemy import Connection, Engine, event

from common.redaction import is_sensitive_identifier, redact_value


_LEGACY_CANARY = re.compile(r"(?i)\b[A-Z0-9_]*CANARY[A-Z0-9_:@./+\-]*\b")
_LEGACY_SECRET_KEY = re.compile(
    r"(?i)(?:password|passwd|pwd|secret|token|cookie|credential|private[_-]?key|"
    r"api[_-]?key|access[_-]?key|passphrase|authorization|envelope)"
)
_LEGACY_PAYLOAD_BYTES = 16_384
_CANONICAL_TABLES = (
    "canonical_tenants", "canonical_clients", "canonical_projects",
    "canonical_engagements", "canonical_operators", "canonical_roles",
    "canonical_scope_decisions", "canonical_jobs", "canonical_actions",
    "canonical_intelligence_sources", "canonical_provenance",
    "canonical_feed_snapshots", "canonical_check_pack_snapshots",
    "canonical_module_versions", "canonical_module_executions",
    "canonical_assets", "canonical_observations", "canonical_artifact_refs",
    "canonical_findings", "canonical_retests", "canonical_reports",
    "canonical_report_memberships", "canonical_exports", "canonical_events",
    "canonical_logs", "canonical_legacy_records",
)
_TASK102_METADATA_TABLES = (
    "canonical_artifact_manifests",
    "canonical_observation_artifacts",
    "canonical_finding_observations",
    "canonical_evidence_access_audit",
)
_LEGACY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+\-]{0,127}$")
_SERVER_AUTHORIZATION_ID_RE = re.compile(r"^authz-[0-9a-f]{32}$")
_SHA256_REF_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_TASK102_FINDING_STATUSES = (
    "open",
    "in_progress",
    "verified",
    "false_positive",
    "remediated",
    "accepted_risk",
    "unknown",
)
_CANONICAL_FINDING_TRIGGER_NAMES = frozenset(
    {
        "canonical_export_source_guard",
        "canonical_export_source_update_guard",
        "canonical_finding_observation_tenant_guard",
        "canonical_findings_identity_guard_update",
        "canonical_findings_lineage_guard_delete",
        "canonical_metadata_bound_guard_canonical_findings",
        "canonical_metadata_bound_update_guard_canonical_findings",
        "canonical_metadata_integrity_guard_insert_canonical_findings",
        "canonical_metadata_integrity_guard_update_canonical_findings",
        "canonical_retest_source_guard",
        "canonical_retest_source_update_guard",
        "canonical_schema_version_guard_canonical_findings",
        "canonical_schema_version_update_guard_canonical_findings",
    }
)


def _redact_legacy(value: Any) -> Any:
    """Recursively redact legacy values, including JSON-in-text columns."""
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            rendered_key = str(key)
            if _LEGACY_SECRET_KEY.search(rendered_key):
                result[rendered_key] = "<redacted>"
            else:
                result[rendered_key] = _redact_legacy(item)
        return result
    if isinstance(value, list):
        return [_redact_legacy(item) for item in value]
    if isinstance(value, str):
        rendered = redact_value(value)
        if isinstance(rendered, str):
            rendered = _LEGACY_CANARY.sub("<redacted>", rendered)
            try:
                decoded = json.loads(rendered)
            except (TypeError, json.JSONDecodeError):
                return rendered
            if isinstance(decoded, (Mapping, list)):
                return json.dumps(_redact_legacy(decoded), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return rendered
    return redact_value(value)


def _legacy_identifier(value: Any, *, prefix: str) -> str:
    """Return a bounded, non-secret key for an archived legacy row.

    Legacy tenant and row identifiers were not trust-boundary values in Gate
    0 and may contain credentials, canaries, whitespace, or arbitrary user
    input.  They are used as relational keys by the canonical archive, so a
    redacted display value is not sufficient: it could collide and it could
    still preserve a secret fragment.  Keep ordinary bounded identifiers for
    compatibility; derive a deterministic opaque digest whenever redaction or
    normalization is required.  The original value remains available only in
    the recursively redacted payload.
    """
    raw = str(value or "").strip() or "legacy"
    rendered = _redact_legacy(raw)
    if not isinstance(rendered, str):
        rendered = str(rendered)
    if rendered != raw or not _LEGACY_ID_RE.fullmatch(raw):
        # Hash the raw value only to produce an opaque lookup key.  The raw
        # value is never written to a canonical column or migration journal.
        return f"{prefix}-opaque-{hashlib.sha256(raw.encode('utf-8')).hexdigest()}"
    return raw


def _legacy_payload_json(value: Any) -> str:
    """Render a bounded, redacted diagnostic payload for the archive."""
    rendered = json.dumps(_redact_legacy(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    if len(rendered.encode("utf-8")) <= _LEGACY_PAYLOAD_BYTES:
        return rendered
    import hashlib

    return json.dumps(
        {
            "truncated": True,
            "digest": "sha256:" + hashlib.sha256(rendered.encode("utf-8")).hexdigest(),
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _legacy_text(
    value: Any,
    default: str = "legacy",
    *,
    limit: int = 300,
    maximum: int | None = None,
) -> str:
    """Return bounded redacted text suitable for a canonical column.

    Gate-0 columns are not canonical trust-boundary inputs.  Normalization
    therefore never copies an unbounded value directly into a canonical row;
    it redacts first and truncates only after the redaction pass.  The full
    (also bounded) diagnostic payload remains in ``canonical_legacy_records``.
    """
    bound = limit if maximum is None else maximum
    if not isinstance(bound, int) or bound < 1:
        raise ValueError("legacy text bound must be positive")
    rendered = _redact_legacy(default if value is None else value)
    if not isinstance(rendered, str):
        rendered = str(rendered)
    rendered = rendered.strip() or default
    return rendered[:bound]


def _legacy_timestamp(value: Any) -> str:
    """Normalize a legacy timestamp to an explicit UTC ISO representation."""
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            parsed = datetime.now(timezone.utc)
    else:
        parsed = datetime.now(timezone.utc)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _legacy_json_list(value: Any) -> list[str]:
    """Read a legacy JSON list without allowing malformed input to abort migration."""
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (TypeError, json.JSONDecodeError):
            return []
    if not isinstance(value, (list, tuple)):
        return []
    return [_legacy_text(item, default="legacy-module", limit=200) for item in value if item]


def _legacy_digest(value: Any) -> str:
    """Digest a redacted representation, never a secret-bearing raw value."""
    rendered = _legacy_payload_json(value)
    return "sha256:" + hashlib.sha256(rendered.encode("utf-8")).hexdigest()


def _canonical_legacy_key(value: Any, *, kind: str, tenant_id: str) -> str:
    """Derive a deterministic opaque surrogate for a legacy structural ID.

    Gate-0 identifiers were client-controlled and are not safe to reuse as
    canonical primary keys.  A tenant-bound digest preserves deterministic
    re-runs and joins related migrated rows without exposing or trusting the
    original value.
    """
    raw = str(value or "").strip() or "legacy"
    seed = tenant_id + "\x00" + raw
    return f"legacy-{kind}-{hashlib.sha256(seed.encode('utf-8')).hexdigest()}"


CANONICAL_MIGRATION_PREFIX = "canonical"
CANONICAL_SCHEMA_VERSION = "forge-canonical-v1"
# Evidence custody is an additive, reversible boundary.  Canonical contract
# rows remain on ``forge-canonical-v1`` so existing adapters do not silently
# change their wire version when custody is upgraded.
EVIDENCE_SCHEMA_VERSION = "forge-evidence-v1"
# Task 103 is an additive single-node control-plane boundary.  Canonical wire
# records remain on ``forge-canonical-v1`` while the lifecycle extension,
# attempts, leases, events, and attempt-bound observation links are versioned
# independently by the migration journal.
JOB_STATE_SCHEMA_VERSION = "forge-jobs-v1"
CURRENT_SCHEMA_VERSION = CANONICAL_SCHEMA_VERSION
JOURNAL_TABLE = "canonical_migration_journal"


class MigrationError(RuntimeError):
    """A canonical migration could not be applied or reversed."""


class MigrationInterruptedError(MigrationError):
    """A deliberately interrupted migration remains recoverable."""


class UnsupportedMigrationError(MigrationError):
    """A requested schema boundary is not supported."""


def _insert_or_validate_legacy(
    connection: Connection,
    table: str,
    values: Mapping[str, Any],
    *,
    identity_columns: tuple[str, ...],
    ignore_columns: tuple[str, ...] = ("created_at", "migrated_at"),
    label: str,
) -> bool:
    """Insert one deterministic legacy surrogate or validate the exact row.

    ``INSERT OR IGNORE`` alone lets an attacker preoccupy a derived ID (or a
    secondary unique key) and silently redirect migrated lineage.  All names
    passed here are module-owned constants; values remain bound parameters.
    Timestamps generated during migration are excluded so a byte-identical
    replay remains idempotent.
    """
    identifier = re.compile(r"^[a-z_][a-z0-9_]*$")
    if not identifier.fullmatch(table) or not values:
        raise MigrationError("invalid legacy surrogate specification")
    columns = tuple(values)
    if any(not identifier.fullmatch(column) for column in columns):
        raise MigrationError("invalid legacy surrogate column")
    if not identity_columns or any(column not in values for column in identity_columns):
        raise MigrationError("legacy surrogate identity is incomplete")

    placeholders = ",".join("?" for _ in columns)
    result = connection.exec_driver_sql(
        f"INSERT OR IGNORE INTO {table}({','.join(columns)}) VALUES({placeholders})",
        tuple(values[column] for column in columns),
    )
    if result.rowcount:
        return True

    compared = tuple(column for column in columns if column not in ignore_columns)
    where = " AND ".join(f"{column}=?" for column in identity_columns)
    row = connection.exec_driver_sql(
        f"SELECT {','.join(compared)} FROM {table} WHERE {where}",
        tuple(values[column] for column in identity_columns),
    ).mappings().first()
    if row is None:
        raise MigrationError(
            f"legacy {label} surrogate collides with an existing canonical row"
        )

    def semantic(value: Any, column: str) -> Any:
        if column.endswith("_json"):
            try:
                parsed = json.loads(str(value))
                return json.dumps(
                    parsed,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                    allow_nan=False,
                )
            except (TypeError, ValueError) as exc:
                raise MigrationError(
                    f"legacy {label} surrogate has malformed canonical JSON"
                ) from exc
        return value

    mismatched = [
        column
        for column in compared
        if semantic(row[column], column) != semantic(values[column], column)
    ]
    if mismatched:
        raise MigrationError(
            f"legacy {label} surrogate collides with semantically different "
            f"canonical data"
        )
    return False


def _normalize_legacy_records_in_transaction(
    connection: Connection,
    *,
    evidence_boundary_available: bool | None = None,
) -> int:
    """Normalize Gate-0 rows into canonical control-plane records.

    The archive is retained for byte-level diagnostic provenance, but it is
    not the canonical data model.  This adapter creates the records for which
    Gate-0 supplied enough information and marks incomplete claims as
    ``unknown``/``not_authorized`` rather than manufacturing authorization.
    Synthetic context is deterministic and explicitly tagged as reduced; it
    lets downstream lineage remain queryable without asserting that legacy
    data was complete.
    """

    tables = {
        str(row[0])
        for row in connection.exec_driver_sql(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    if evidence_boundary_available is None:
        evidence_boundary_available = bool(
            JOURNAL_TABLE in tables
            and connection.exec_driver_sql(
                f"SELECT 1 FROM {JOURNAL_TABLE} "
                "WHERE version=? AND state='applied' LIMIT 1",
                (EVIDENCE_SCHEMA_VERSION,),
            ).fetchone()
        )
    known = {
        name: [str(row[1]) for row in connection.exec_driver_sql(
            f"PRAGMA table_info({name})"
        ).fetchall()]
        for name in (
            "authorization_decisions",
            "authorization_consumptions",
            "authorization_execution_claims",
            "audit_logs",
            "scan_jobs",
            "findings",
        )
        if name in tables
    }
    rows: dict[str, list[dict[str, Any]]] = {}
    for table, columns in known.items():
        rows[table] = [
            {columns[index]: row[index] for index in range(len(columns))}
            for row in connection.exec_driver_sql(f"SELECT * FROM {table}").fetchall()
        ]

    inserted = 0
    tenant_ids: dict[str, str] = {}
    engagement_ids: dict[tuple[str, str], str] = {}
    operator_ids: dict[tuple[str, str], str] = {}
    role_ids: dict[tuple[str, str], str] = {}
    job_ids: dict[tuple[str, str], str] = {}
    module_ids: dict[tuple[str, str], str] = {}
    asset_ids: dict[tuple[str, str], str] = {}
    observation_ids: dict[tuple[str, str], str] = {}
    artifact_ids: dict[tuple[str, str], str] = {}
    scope_ids: dict[tuple[str, str], str] = {}
    authorized_jobs: dict[tuple[str, str], list[dict[str, Any]]] = {}

    def normalized_timestamp(value: Any) -> datetime | None:
        if isinstance(value, datetime):
            parsed = value
        elif isinstance(value, str):
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                return None
        else:
            return None
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    def validated_legacy_authorization_envelope(
        data: Mapping[str, Any],
    ) -> Any | None:
        """Return one exact Gate-0 envelope, or ``None`` on any mismatch."""
        from common.action_authorization import (
            ActionAuthorizationEnvelope,
            MAX_FUTURE_SKEW_SECONDS,
        )
        from common.confirm_gate import (
            ActionConfirmation,
            CONFIRMATION_SCHEMA_VERSION,
            DEFAULT_CONFIRMATION_MAX_AGE_SECONDS,
        )

        raw_envelope = data.get("envelope_json")
        if not isinstance(raw_envelope, str):
            return None
        try:
            decoded = json.loads(raw_envelope)
            envelope = ActionAuthorizationEnvelope.from_value(decoded)
        except (TypeError, ValueError, json.JSONDecodeError):
            return None

        string_fields = (
            "schema_version",
            "decision_id",
            "parent_decision_id",
            "tenant_id",
            "engagement_id",
            "run_id",
            "job_id",
            "action_id",
            "operator_id",
            "operator_role",
            "action_kind",
            "engine",
            "module_id",
            "requested_target",
            "resolved_target",
            "scope_snapshot",
            "scope_policy_version",
            "scope_decision",
            "scope_reason_code",
            "decision_outcome",
            "reason_code",
            "binding_digest",
        )
        for field in string_fields:
            if str(data.get(field) or "") != str(getattr(envelope, field)):
                return None
        for field in ("issued_at", "expires_at"):
            row_timestamp = normalized_timestamp(data.get(field))
            envelope_timestamp = normalized_timestamp(getattr(envelope, field))
            if row_timestamp is None or row_timestamp != envelope_timestamp:
                return None

        if envelope.decision_outcome == "allow":
            confirmed_at = normalized_timestamp(envelope.confirmed_at)
            issued_at = normalized_timestamp(envelope.issued_at)
            expires_at = normalized_timestamp(envelope.expires_at)
            if confirmed_at is None or issued_at is None or expires_at is None:
                return None
            confirmation_age = (issued_at - confirmed_at).total_seconds()
            if (
                confirmation_age > DEFAULT_CONFIRMATION_MAX_AGE_SECONDS
                or confirmation_age < -MAX_FUTURE_SKEW_SECONDS
                or expires_at
                > confirmed_at
                + timedelta(seconds=DEFAULT_CONFIRMATION_MAX_AGE_SECONDS)
            ):
                return None
            try:
                confirmation = ActionConfirmation.from_value(
                    {
                        "schema_version": CONFIRMATION_SCHEMA_VERSION,
                        "confirmed": True,
                        "job_id": envelope.job_id,
                        "target": envelope.resolved_target,
                        "engine": envelope.engine,
                        "action": envelope.action_kind,
                        "issued_at": envelope.confirmed_at,
                        "binding_digest": str(data.get("confirmation_digest") or ""),
                    }
                )
            except (TypeError, ValueError):
                return None
            if not confirmation.has_valid_binding():
                return None
        return envelope

    def has_exact_execution_lineage(envelope: Any) -> bool:
        """Require one matching consumption and one matching execution claim."""
        if envelope.decision_outcome != "allow" or envelope.single_use is not True:
            return False
        consumptions = [
            row
            for row in rows.get("authorization_consumptions", [])
            if str(row.get("decision_id") or "") == envelope.decision_id
        ]
        claims = [
            row
            for row in rows.get("authorization_execution_claims", [])
            if str(row.get("decision_id") or "") == envelope.decision_id
        ]
        if len(consumptions) != 1 or len(claims) != 1:
            return False
        consumption = consumptions[0]
        claim = claims[0]
        boundary = str(consumption.get("boundary") or "")
        if not boundary or str(claim.get("boundary") or "") != boundary:
            return False
        issued_at = normalized_timestamp(envelope.issued_at)
        expires_at = normalized_timestamp(envelope.expires_at)
        consumed_at = normalized_timestamp(consumption.get("consumed_at"))
        claimed_at = normalized_timestamp(claim.get("claimed_at"))
        if (
            issued_at is None
            or expires_at is None
            or consumed_at is None
            or claimed_at is None
            or not issued_at <= consumed_at <= claimed_at <= expires_at
        ):
            return False
        expected = {
            "decision_id": envelope.decision_id,
            "tenant_id": envelope.tenant_id,
            "job_id": envelope.job_id,
            "action_id": envelope.action_id,
            "envelope_digest": envelope.binding_digest,
        }
        return bool(
            all(str(consumption.get(field) or "") == value for field, value in expected.items())
            and all(str(claim.get(field) or "") == value for field, value in expected.items())
            and str(consumption.get("result_id") or "") == envelope.action_id
        )

    def exact_scan_job_binding(
        data: Mapping[str, Any],
        envelope: Any,
    ) -> bool:
        """Bind a legacy scan row to every execution-authoritative field."""
        from common.action_authorization import (
            _safe_target_for_binding,
            module_set_binding,
        )

        raw_target = data.get("target")
        if not isinstance(raw_target, str) or not raw_target.strip():
            return False
        target_binding = _safe_target_for_binding(raw_target)
        modules = _legacy_json_list(data.get("modules"))
        frameworks = _legacy_json_list(data.get("frameworks"))
        expected_module = str(envelope.module_id or "")
        module_matches = (
            module_set_binding(modules) == expected_module
            if expected_module.startswith("module-set-")
            else modules == ([expected_module] if expected_module else [])
        )
        return bool(
            str(data.get("authorization_state") or "").strip().lower() == "allow"
            and str(data.get("authorization_decision_id") or "") == envelope.decision_id
            and str(data.get("authorization_action_id") or "") == envelope.action_id
            and target_binding == envelope.requested_target
            and target_binding == envelope.resolved_target
            and module_matches
            and frameworks == [envelope.engine]
        )

    def canonical_tenant(data: Mapping[str, Any]) -> tuple[str, bool]:
        source = data.get("tenant_id")
        complete = bool(
            isinstance(source, str)
            and source.strip()
            and _LEGACY_ID_RE.fullmatch(source.strip())
            and _redact_legacy(source) == source
        )
        value = _canonical_legacy_key(source or "default", kind="tenant", tenant_id="forge-legacy")
        tenant_ids.setdefault(value, value)
        _insert_or_validate_legacy(
            connection,
            "canonical_tenants",
            {
                "id": value,
                "schema_version": CANONICAL_SCHEMA_VERSION,
                "name": _legacy_text(source or value, limit=300),
                "created_at": _now(),
                "metadata_json": '{"legacy":true}',
            },
            identity_columns=("id",),
            label="tenant",
        )
        return value, complete

    def engagement(
        tenant: str,
        source: Any,
        *,
        fallback: str,
        reduced: bool = False,
    ) -> str:
        raw = source if isinstance(source, str) and source.strip() else fallback
        identifier = _canonical_legacy_key(raw, kind="engagement", tenant_id=tenant)
        key = (tenant, identifier)
        engagement_ids.setdefault(key, identifier)
        metadata = json.dumps(
            {"legacy": True, "claim_state": "reduced" if reduced else "complete"},
            sort_keys=True,
            separators=(",", ":"),
        )
        _insert_or_validate_legacy(
            connection,
            "canonical_engagements",
            {
                "id": identifier,
                "tenant_id": tenant,
                "project_id": None,
                "schema_version": CANONICAL_SCHEMA_VERSION,
                "name": _legacy_text(source or fallback, limit=300),
                "status": "unknown" if reduced else "planned",
                "created_at": _now(),
                "metadata_json": metadata,
            },
            identity_columns=("tenant_id", "id"),
            label="engagement",
        )
        return identifier

    def operator(
        tenant: str,
        source: Any,
        *,
        fallback: str = "legacy-operator",
    ) -> str:
        identifier = _canonical_legacy_key(source or fallback, kind="operator", tenant_id=tenant)
        key = (tenant, identifier)
        operator_ids.setdefault(key, identifier)
        _insert_or_validate_legacy(
            connection,
            "canonical_operators",
            {
                "id": identifier,
                "tenant_id": tenant,
                "schema_version": CANONICAL_SCHEMA_VERSION,
                "display_name": _legacy_text(source or fallback, limit=200),
                "external_ref": None,
                "created_at": _now(),
                "metadata_json": '{"legacy":true}',
            },
            identity_columns=("tenant_id", "id"),
            label="operator",
        )
        return identifier

    def role(tenant: str, source: Any) -> str:
        identifier = _canonical_legacy_key(source or "legacy-role", kind="role", tenant_id=tenant)
        key = (tenant, identifier)
        role_ids.setdefault(key, identifier)
        _insert_or_validate_legacy(
            connection,
            "canonical_roles",
            {
                "id": identifier,
                "tenant_id": tenant,
                "schema_version": CANONICAL_SCHEMA_VERSION,
                "name": _legacy_text(source or "legacy-role", limit=100),
                "created_at": _now(),
                "metadata_json": '{"legacy":true}',
            },
            identity_columns=("tenant_id", "id"),
            label="role",
        )
        return identifier

    def module_version(tenant: str, module: Any, *, version: Any = "legacy") -> str:
        module_name = _legacy_text(module or "legacy-module", default="legacy-module", limit=200)
        version_name = _legacy_text(version or "legacy", default="legacy", limit=100)
        identity = f"{module_name}:{version_name}"
        identifier = _canonical_legacy_key(identity, kind="module-version", tenant_id=tenant)
        key = (tenant, identifier)
        module_ids.setdefault(key, identifier)
        _insert_or_validate_legacy(
            connection,
            "canonical_module_versions",
            {
                "id": identifier,
                "tenant_id": tenant,
                "schema_version": CANONICAL_SCHEMA_VERSION,
                "module_id": module_name,
                "version": version_name,
                "module_kind": "legacy",
                "manifest_digest": None,
                "policy_version": "legacy",
                "intelligence_snapshot_id": None,
                "check_pack_snapshot_id": None,
                "provenance_id": None,
                "created_at": _now(),
                "metadata_json": '{"legacy":true}',
            },
            identity_columns=("tenant_id", "id"),
            label="module version",
        )
        return identifier

    def asset(tenant: str, target: Any, *, key_hint: str) -> str:
        raw = _legacy_text(target or key_hint, default=key_hint, limit=1000)
        lowered = raw.lower()
        kind = "url" if lowered.startswith(("http://", "https://")) else "host"
        identity = raw.lower() if kind == "host" else raw
        identifier = _canonical_legacy_key(f"{kind}:{identity}", kind="asset", tenant_id=tenant)
        key = (tenant, f"{kind}:{identity}")
        asset_ids.setdefault(key, identifier)
        _insert_or_validate_legacy(
            connection,
            "canonical_assets",
            {
                "id": identifier,
                "tenant_id": tenant,
                "schema_version": CANONICAL_SCHEMA_VERSION,
                "kind": kind,
                "identity_key": identity,
                "display_name": raw[:2000],
                "canonical_uri": raw if kind == "url" else None,
                "created_at": _now(),
                "metadata_json": '{"legacy":true}',
            },
            identity_columns=("tenant_id", "id"),
            label="asset",
        )
        return identifier

    def job(
        tenant: str,
        source_id: Any,
        *,
        engagement_source: Any,
        target: Any,
        module: Any,
        status: Any,
        reduced: bool,
    ) -> tuple[str, str, str, str, str]:
        raw_id = source_id or f"legacy-{_legacy_digest({'target': target, 'module': module})[7:23]}"
        identifier = _canonical_legacy_key(raw_id, kind="job", tenant_id=tenant)
        engagement_id = engagement(
            tenant,
            engagement_source,
            fallback=f"{identifier}-engagement",
            reduced=reduced,
        )
        module_id = module_version(tenant, module or "legacy-module")
        asset_id = asset(tenant, target or "legacy-target", key_hint=identifier)
        key = (tenant, identifier)
        job_ids.setdefault(key, identifier)
        mapped_status = (
            "unknown_not_authorized"
            if reduced
            else {
                "planned": "planned",
                "pending": "pending_approval",
                "queued": "queued",
                "running": "running",
                "completed": "completed",
                "partial": "partial",
                "failed": "failed",
            }.get(str(status or "").lower(), "planned")
        )
        _insert_or_validate_legacy(
            connection,
            "canonical_jobs",
            {
                "id": identifier,
                "tenant_id": tenant,
                "engagement_id": engagement_id,
                "schema_version": CANONICAL_SCHEMA_VERSION,
                "job_kind": _legacy_text(
                    module or "legacy", default="legacy", limit=100
                ),
                "status": mapped_status,
                "created_at": _now(),
                "metadata_json": json.dumps(
                    {
                        "legacy": True,
                        "claim_state": "reduced" if reduced else "complete",
                    },
                    separators=(",", ":"),
                ),
            },
            identity_columns=("tenant_id", "id"),
            label="job",
        )
        return identifier, engagement_id, module_id, asset_id, mapped_status

    def observation(
        tenant: str,
        source_id: Any,
        *,
        engagement_id: str,
        job_id: str,
        module_id: str,
        asset_id: str,
        reduced: bool,
        status: str = "not_tested",
    ) -> str:
        identifier = _canonical_legacy_key(source_id or f"{job_id}:observation", kind="observation", tenant_id=tenant)
        key = (tenant, identifier)
        observation_ids.setdefault(key, identifier)
        observation_values: dict[str, Any] = {
            "id": identifier,
            "tenant_id": tenant,
            "engagement_id": engagement_id,
            "job_id": job_id,
            "module_version_id": module_id,
            "module_execution_id": None,
            "asset_id": asset_id,
            "action_id": None,
            "intelligence_snapshot_id": None,
            "provenance_id": None,
            "schema_version": CANONICAL_SCHEMA_VERSION,
            "status": "not_authorized" if reduced else status,
            "observed_at": _now(),
            "created_at": _now(),
            "metadata_json": json.dumps(
                {
                    "legacy": True,
                    "claim_state": "reduced" if reduced else "complete",
                },
                separators=(",", ":"),
            ),
        }
        observation_columns = {
            str(row[1])
            for row in connection.exec_driver_sql(
                "PRAGMA table_info(canonical_observations)"
            ).fetchall()
        }
        observation_values.update(
            {
                name: value
                for name, value in {
                    "proof_type": "unknown",
                    "collection_status": "unknown",
                    "check_id": None,
                    "route": None,
                    "parameter": None,
                    "location": None,
                    "identity_ref": None,
                }.items()
                if name in observation_columns
            }
        )
        _insert_or_validate_legacy(
            connection,
            "canonical_observations",
            observation_values,
            identity_columns=("tenant_id", "id"),
            ignore_columns=("created_at", "observed_at"),
            label="observation",
        )
        return identifier

    def write_action(
        *,
        tenant: str,
        raw_action: Any,
        engagement_id: str,
        job_id: str,
        decision_id: str,
        action_kind: Any,
        complete: bool,
    ) -> str:
        action_id = _canonical_legacy_key(
            raw_action, kind="action", tenant_id=tenant
        )
        _insert_or_validate_legacy(
            connection,
            "canonical_actions",
            {
                "id": action_id,
                "tenant_id": tenant,
                "engagement_id": engagement_id,
                "job_id": job_id,
                "schema_version": CANONICAL_SCHEMA_VERSION,
                "action_kind": _legacy_text(
                    action_kind or "legacy-action",
                    default="legacy-action",
                    limit=100,
                ),
                "authorization_decision_id": decision_id if complete else None,
                "created_at": _now(),
                "metadata_json": json.dumps(
                    {
                        "legacy": True,
                        "claim_state": "complete" if complete else "unknown",
                    },
                    separators=(",", ":"),
                ),
            },
            identity_columns=("tenant_id", "id"),
            label="action",
        )
        return action_id

    pending_authorizations: list[dict[str, Any]] = []

    # Authorization decisions are normalized first so their exact envelope,
    # consumption, and execution truth can be reused by matching jobs/actions.
    for data in rows.get("authorization_decisions", []):
        tenant, tenant_complete = canonical_tenant(data)
        raw_decision = data.get("decision_id") or data.get("id") or data.get("sequence")
        decision_id = _canonical_legacy_key(raw_decision or "legacy", kind="scope", tenant_id=tenant)
        raw_engagement = data.get("engagement_id") or data.get("engagement")
        engagement_id = engagement(tenant, raw_engagement, fallback=f"{decision_id}-engagement", reduced=not bool(raw_engagement))
        raw_operator = data.get("operator_id") or data.get("operator")
        operator_id = operator(tenant, raw_operator)
        role_id = role(tenant, data.get("operator_role") or data.get("role"))
        # Gate-0 authorization rows may carry both the normalized decision
        # and the older scope-decision label.  Neither field is authoritative
        # on its own: a contradictory pair (or a missing pair) must never be
        # promoted to an allow during migration.  Deny is also kept reduced
        # unless the two source claims agree, so the archive remains truthful.
        decision_value = {
            "allow": "allow", "allowed": "allow",
            "deny": "deny", "denied": "deny",
        }.get(str(data.get("decision_outcome") or "").strip().lower())
        scope_value = {
            "allow": "allow", "allowed": "allow",
            "deny": "deny", "denied": "deny",
        }.get(str(data.get("scope_decision") or data.get("outcome") or "").strip().lower())
        outcome = (
            decision_value
            if decision_value is not None and scope_value == decision_value
            else "unknown"
        )
        envelope = validated_legacy_authorization_envelope(data)
        complete = bool(
            tenant_complete
            and isinstance(raw_decision, str)
            and _LEGACY_ID_RE.fullmatch(raw_decision.strip())
            and isinstance(raw_engagement, str)
            and _LEGACY_ID_RE.fullmatch(raw_engagement.strip())
            and isinstance(raw_operator, str)
            and _LEGACY_ID_RE.fullmatch(raw_operator.strip())
            and (
                _redact_legacy(raw_decision) == raw_decision
                # ``redact_value`` intentionally treats authz handles as
                # protected references; a server-generated authz identifier
                # is nevertheless a safe structural key, not a credential.
                or (
                    _SERVER_AUTHORIZATION_ID_RE.fullmatch(raw_decision.strip())
                    and not is_sensitive_identifier(raw_decision.strip())
                )
            )
            and _redact_legacy(raw_engagement) == raw_engagement
            and _redact_legacy(raw_operator) == raw_operator
            and data.get("scope_policy_version")
            and outcome in {"allow", "deny"}
            and envelope is not None
        )
        if not complete:
            outcome = "unknown"
        execution_complete = bool(
            complete
            and outcome == "allow"
            and envelope is not None
            and has_exact_execution_lineage(envelope)
        )
        if execution_complete and data.get("job_id"):
            authorized_jobs.setdefault(
                (tenant, str(data.get("job_id")).strip()), []
            ).append(
                {
                    "envelope": envelope,
                    "decision_id": decision_id,
                    "engagement_id": engagement_id,
                    "raw_action": data.get("action_id"),
                    "action_kind": data.get("action_kind"),
                }
            )
        scope_ids[(tenant, str(raw_decision or decision_id))] = decision_id
        _insert_or_validate_legacy(
            connection,
            "canonical_scope_decisions",
            {
                "id": decision_id,
                "tenant_id": tenant,
                "engagement_id": engagement_id,
                "operator_id": operator_id,
                "role_id": role_id,
                "schema_version": CANONICAL_SCHEMA_VERSION,
                "outcome": outcome,
                "policy_version": _legacy_text(
                    data.get("scope_policy_version") or "legacy-unknown",
                    default="legacy-unknown",
                    limit=100,
                ),
                "decision_reason": _legacy_text(
                    data.get("scope_reason_code")
                    or data.get("reason_code")
                    or "legacy-reduced",
                    default="legacy-reduced",
                    limit=2000,
                ),
                "decided_at": _legacy_timestamp(
                    data.get("issued_at") or data.get("timestamp")
                ),
                "created_at": _legacy_timestamp(
                    data.get("recorded_at") or data.get("issued_at")
                ),
                "metadata_json": json.dumps(
                    {
                        "legacy": True,
                        "claim_state": "complete" if complete else "unknown",
                    },
                    separators=(",", ":"),
                ),
            },
            identity_columns=("tenant_id", "id"),
            ignore_columns=("created_at", "decided_at"),
            label="scope decision",
        )
        if data.get("job_id"):
            pending_authorizations.append(
                {
                    "tenant": tenant,
                    "raw_job_id": str(data.get("job_id")).strip(),
                    "raw_action": data.get("action_id"),
                    "action_kind": data.get("action_kind"),
                    "module": data.get("module_id")
                    or data.get("engine")
                    or "legacy-module",
                    "target": data.get("resolved_target")
                    or data.get("requested_target")
                    or decision_id,
                    "decision_id": decision_id,
                }
            )

    # Jobs are normalized even when no authorization row exists.  Such rows
    # receive ``unknown_not_authorized`` and a reduced observation, never an
    # implicit allow.
    processed_job_keys: set[tuple[str, str]] = set()
    for data in rows.get("scan_jobs", []):
        tenant, tenant_complete = canonical_tenant(data)
        modules = _legacy_json_list(data.get("modules"))
        frameworks = _legacy_json_list(data.get("frameworks"))
        module = modules[0] if modules else (
            frameworks[0] if frameworks else "legacy-module"
        )
        raw_job_id = str(data.get("id") or data.get("job_id") or "").strip()
        processed_job_keys.add((tenant, raw_job_id))
        bindings = authorized_jobs.get((tenant, raw_job_id), [])
        exact_bindings = [
            binding
            for binding in bindings
            if exact_scan_job_binding(data, binding["envelope"])
        ]
        # More than one match is ambiguous even if all rows look individually
        # valid.  A single exact envelope/consumption/claim chain is required.
        binding = exact_bindings[0] if len(exact_bindings) == 1 else None
        reduced = not tenant_complete or binding is None
        if binding is not None:
            envelope = binding["envelope"]
            engagement_source = envelope.engagement_id
            module = envelope.module_id or envelope.engine
        else:
            engagement_source = data.get("engagement") or data.get(
                "engagement_id"
            )
        job_id, engagement_id, module_id, asset_id, mapped_status = job(
            tenant,
            raw_job_id,
            engagement_source=engagement_source,
            target=data.get("target") or "legacy-target",
            module=module,
            status=data.get("status"),
            reduced=reduced,
        )
        if binding is not None and binding["raw_action"]:
            write_action(
                tenant=tenant,
                raw_action=binding["raw_action"],
                engagement_id=engagement_id,
                job_id=job_id,
                decision_id=binding["decision_id"],
                action_kind=binding["action_kind"],
                complete=True,
            )
        observation(
            tenant,
            f"{job_id}:observation",
            engagement_id=engagement_id,
            job_id=job_id,
            module_id=module_id,
            asset_id=asset_id,
            reduced=reduced,
            status="observed" if mapped_status == "completed" else "not_tested",
        )

    # Preserve authorization-only legacy rows as explicitly unbound/reduced.
    # Without an exact scan row there is no trustworthy target/module/job
    # state to promote, even when the decision envelope itself was valid.
    for pending in pending_authorizations:
        key = (pending["tenant"], pending["raw_job_id"])
        if key in processed_job_keys:
            continue
        job_id, engagement_id, _module_id, _asset_id, _ = job(
            pending["tenant"],
            pending["raw_job_id"],
            engagement_source=None,
            target=pending["target"],
            module=pending["module"],
            status="planned",
            reduced=True,
        )
        if pending["raw_action"]:
            write_action(
                tenant=pending["tenant"],
                raw_action=pending["raw_action"],
                engagement_id=engagement_id,
                job_id=job_id,
                decision_id=pending["decision_id"],
                action_kind=pending["action_kind"],
                complete=False,
            )

    # Task 101 has no durable evidence boundary and therefore archives legacy
    # findings without manufacturing canonical observation/artifact lineage.
    # Once the Task 102 evidence tables are being applied, preserve the live
    # v2 behavior: materialize only reduced/unknown custody references and
    # never invent artifact bytes, digests, integrity, or authorization.
    for data in rows.get("findings", []) if evidence_boundary_available else ():
        tenant, tenant_complete = canonical_tenant(data)
        raw_finding = data.get("id") or data.get("finding_id") or data.get("dedup_key")
        finding_id = _canonical_legacy_key(raw_finding or "legacy", kind="finding", tenant_id=tenant)
        legacy_finding_key = _legacy_text(
            data.get("dedup_key") or "", default="", limit=300
        ) or None
        legacy_identity_key = "finding-v1:legacy"
        module = data.get("module") or "legacy-module"
        target = data.get("target") or data.get("url") or "legacy-target"
        source_job = data.get("last_seen_run") or data.get("engagement") or f"{finding_id}-job"
        # Legacy ``FindingModel`` rows do not carry the canonical observation,
        # artifact, authorization, and module-execution bindings.  They must
        # therefore remain reduced/unknown even when their display fields look
        # complete.  A future migration may set this explicit marker only
        # after independently verifying the complete Gate-0 graph.
        complete = bool(
            tenant_complete
            and data.get("canonical_lineage_verified") is True
            and data.get("title")
            and data.get("description")
            and data.get("target")
            and module
        )
        job_id, engagement_id, module_id, asset_id, _ = job(
            tenant,
            source_job,
            engagement_source=data.get("engagement") or data.get("engagement_id"),
            target=target,
            module=module,
            status="completed",
            reduced=not complete,
        )
        obs_id = observation(
            tenant,
            f"{finding_id}:observation",
            engagement_id=engagement_id,
            job_id=job_id,
            module_id=module_id,
            asset_id=asset_id,
            reduced=not complete,
            status="observed" if complete else "not_authorized",
        )
        artifact_id = _canonical_legacy_key(f"{finding_id}:artifact", kind="artifact", tenant_id=tenant)
        artifact_ids[(tenant, finding_id)] = artifact_id
        # Legacy rows do not provide durable artifact bytes.  Do not invent a
        # digest for the redacted metadata payload; preserve the artifact
        # reference while explicitly recording unknown integrity/protection.
        digest = None
        artifact_columns = {
            str(row[1])
            for row in connection.exec_driver_sql(
                "PRAGMA table_info(canonical_artifact_refs)"
            ).fetchall()
        }
        artifact_metadata = {
            "legacy": True,
            "claim_state": "complete" if complete else "reduced",
            "integrity_state": "unknown",
            "protection_state": "legacy_unknown",
        }
        artifact_values: dict[str, Any] = {
            "id": artifact_id,
            "tenant_id": tenant,
            "observation_id": obs_id,
            "schema_version": CANONICAL_SCHEMA_VERSION,
            "reference": f"artifact:{artifact_id}",
            "digest": digest,
            "media_type": "application/json",
            "size": 0,
            "redaction_state": "unknown",
            "encryption_state": "unknown",
            "collected_at": _legacy_timestamp(data.get("discovered_at")),
            "created_at": _legacy_timestamp(data.get("discovered_at")),
            "metadata_json": json.dumps(artifact_metadata, separators=(",", ":")),
        }
        task102_artifact_defaults: dict[str, Any] = {
            "collector_id": "unknown",
            "collector_version": "unknown",
            "source_target": "unknown",
            "source_asset_id": None,
            "redaction_version": "unknown",
            "protection_state": "legacy_unknown",
            "signer_state": "unsigned",
            "integrity_state": "unknown",
            "retention_class": "default",
            "retention_expires_at": None,
            "protected_original_authorization_ref": None,
            "derivative_reference": None,
        }
        # A v2 replay must validate every migration-owned custody default,
        # while a v2-first apply can only bind columns already present before
        # the post-migration repair step.
        artifact_values.update(
            {
                name: value
                for name, value in task102_artifact_defaults.items()
                if name in artifact_columns
            }
        )
        _insert_or_validate_legacy(
            connection,
            "canonical_artifact_refs",
            artifact_values,
            identity_columns=("tenant_id", "id"),
            ignore_columns=("created_at", "collected_at"),
            label="artifact reference",
        )
        severity = str(data.get("severity") or "informational").lower()
        if severity not in {"critical", "high", "medium", "low", "informational"}:
            severity = "informational"
        status = str(data.get("status") or "unknown").lower()
        if status not in {"open", "verified", "false_positive", "remediated", "unknown"} or not complete:
            status = "unknown"
        finding_values: dict[str, Any] = {
                "id": finding_id,
                "tenant_id": tenant,
                "observation_id": obs_id,
                "artifact_id": artifact_id,
                "schema_version": CANONICAL_SCHEMA_VERSION,
                "title": _legacy_text(
                    data.get("title") or "legacy finding",
                    default="legacy finding",
                    limit=500,
                ),
                "severity": severity,
                "description": _legacy_text(
                    data.get("description") or "Legacy finding with reduced context",
                    default="Legacy finding with reduced context",
                    limit=8000,
                ),
                "status": status,
                "finding_key": legacy_finding_key,
                "created_at": _legacy_timestamp(data.get("discovered_at")),
                "metadata_json": json.dumps(
                    {
                        "legacy": True,
                        "claim_state": "complete" if complete else "reduced",
                    },
                    separators=(",", ":"),
                ),
        }
        finding_columns = {
            str(row[1])
            for row in connection.exec_driver_sql(
                "PRAGMA table_info(canonical_findings)"
            ).fetchall()
        }
        if "dedup_key" in finding_columns:
            finding_values["dedup_key"] = None
        _insert_or_validate_legacy(
            connection,
            "canonical_findings",
            finding_values,
            identity_columns=("tenant_id", "id"),
            ignore_columns=(
                "created_at",
                "title",
                "severity",
                "description",
                "status",
                "metadata_json",
            ),
            label="finding",
        )
        # The source-link table belongs to the Task 102 migration.  Task 101
        # can be replayed from an older database before that table exists, so
        # defer this optional link until the additive migration has installed
        # it.  The canonical observation/artifact/finding rows above remain
        # fully transactional and are never dropped.
        if connection.exec_driver_sql(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='canonical_finding_observations'"
        ).fetchone() is not None:
            link_columns = {
                str(row[1])
                for row in connection.exec_driver_sql(
                    "PRAGMA table_info(canonical_finding_observations)"
                ).fetchall()
            }
            persisted_finding = connection.exec_driver_sql(
                "SELECT created_at, dedup_key FROM canonical_findings "
                "WHERE tenant_id=? AND id=?",
                (tenant, finding_id),
            ).fetchone()
            if persisted_finding is None:
                raise MigrationError("legacy finding source row is missing")
            link_created_at = str(persisted_finding[0])
            link_identity_key = str(persisted_finding[1] or legacy_identity_key)
            link_metadata = json.dumps(
                {"legacy": True, "integrity_state": "unknown"},
                separators=(",", ":"),
            )
            if {"identity_key", "first_seen_at", "last_seen_at"} <= link_columns:
                _insert_or_validate_legacy(
                    connection,
                    "canonical_finding_observations",
                    {
                        "tenant_id": tenant,
                        "finding_id": finding_id,
                        "observation_id": obs_id,
                        "artifact_id": artifact_id,
                        "identity_key": link_identity_key,
                        "first_seen_at": link_created_at,
                        "last_seen_at": link_created_at,
                        "created_at": link_created_at,
                        "metadata_json": link_metadata,
                    },
                    identity_columns=("tenant_id", "finding_id", "observation_id"),
                    ignore_columns=("created_at",),
                    label="finding observation",
                )
            else:
                _insert_or_validate_legacy(
                    connection,
                    "canonical_finding_observations",
                    {
                        "tenant_id": tenant,
                        "finding_id": finding_id,
                        "observation_id": obs_id,
                        "artifact_id": artifact_id,
                        "created_at": link_created_at,
                        "metadata_json": link_metadata,
                    },
                    identity_columns=("tenant_id", "finding_id", "observation_id"),
                    ignore_columns=("created_at",),
                    label="finding observation",
                )

    # Audit rows become canonical events.  If an audit event has no usable job
    # relationship, a reduced synthetic job is created so the event remains
    # tenant-scoped and queryable without pretending it authorized work.
    for data in rows.get("audit_logs", []):
        tenant, tenant_complete = canonical_tenant(data)
        event_source = data.get("object_id") or data.get("id") or "legacy-audit"
        job_id, engagement_id, _module_id, _asset_id, _ = job(
            tenant,
            event_source,
            engagement_source=data.get("engagement_id"),
            target=data.get("object_id") or "legacy-audit",
            module="legacy-audit",
            status="planned",
            reduced=not tenant_complete,
        )
        actor_id = operator(tenant, data.get("operator"))
        level = str(data.get("status") or "info").lower()
        if level not in {"debug", "info", "warning", "error", "critical"}:
            level = "info"
        event_id = _canonical_legacy_key(data.get("id") or event_source, kind="event", tenant_id=tenant)
        _insert_or_validate_legacy(
            connection,
            "canonical_events",
            {
                "id": event_id,
                "tenant_id": tenant,
                "job_id": job_id,
                "actor_id": actor_id,
                "schema_version": CANONICAL_SCHEMA_VERSION,
                "event_type": _legacy_text(
                    data.get("action") or "legacy.audit",
                    default="legacy.audit",
                    limit=160,
                ),
                "level": level,
                "created_at": _legacy_timestamp(data.get("timestamp")),
                "metadata_json": json.dumps(
                    {
                        "legacy": True,
                        "claim_state": (
                            "complete" if tenant_complete else "reduced"
                        ),
                    },
                    separators=(",", ":"),
                ),
            },
            identity_columns=("tenant_id", "id"),
            ignore_columns=("created_at",),
            label="event",
        )

    return inserted


def archive_legacy_records(bind: Engine | Connection) -> int:
    """Copy legacy control-plane rows into a fail-closed archive.

    Legacy rows are deliberately *not* promoted into canonical authorization,
    findings, or lineage.  They retain redacted diagnostic payloads and an
    ``unknown``/``not_authorized`` claim state so missing Gate-0 context can
    never become an implicit allow or verified finding.  The operation is
    idempotent on ``(tenant_id, record_kind, legacy_id)``.
    """
    if isinstance(bind, Connection) and bind.in_transaction():
        raise MigrationError(
            "archive_legacy_records cannot mutate a borrowed active transaction"
        )
    connection, owned = _as_connection(bind)
    count = 0
    try:
        _ensure_journal(connection)
        if connection.in_transaction():
            connection.commit()
        tables = {
            str(row[0])
            for row in connection.exec_driver_sql(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        if connection.in_transaction():
            connection.commit()
        known = (
            ("authorization_decisions", "authorization"),
            ("authorization_consumptions", "authorization_consumption"),
            (
                "authorization_execution_claims",
                "authorization_execution_claim",
            ),
            ("audit_logs", "audit"),
            ("scan_jobs", "job"),
            ("findings", "finding"),
        )
        with connection.begin():
            _normalize_legacy_records_in_transaction(connection)
            for table, record_kind in known:
                if table not in tables:
                    continue
                columns = [str(row[1]) for row in connection.exec_driver_sql(f"PRAGMA table_info({table})").fetchall()]
                if not columns:
                    continue
                rows = connection.exec_driver_sql(f"SELECT * FROM {table}").fetchall()
                for row in rows:
                    data = {columns[index]: row[index] for index in range(len(columns))}
                    tenant = _canonical_legacy_key(data.get("tenant_id") or "default", kind="tenant", tenant_id="forge-legacy")
                    legacy_id = _legacy_identifier(
                        data.get("id")
                        or data.get("consumption_id")
                        or data.get("claim_id")
                        or data.get("decision_id")
                        or data.get("job_id")
                        or data.get("finding_id")
                        or data.get("run_id")
                        or data.get("sequence")
                        or "legacy",
                        prefix=f"legacy-{record_kind}",
                    )
                    outcome = str(data.get("decision_outcome") or data.get("outcome") or "").lower()
                    claim_state = "not_authorized" if outcome in {"deny", "denied", "not_authorized"} else ("unknown" if record_kind == "authorization" else "reduced")
                    payload = _redact_legacy(data)
                    rendered = _legacy_payload_json(payload if isinstance(payload, Mapping) else {})
                    _insert_or_validate_legacy(
                        connection,
                        "canonical_tenants",
                        {
                            "id": tenant,
                            "schema_version": CANONICAL_SCHEMA_VERSION,
                            "name": _legacy_text(
                                data.get("tenant_id") or tenant, limit=300
                            ),
                            "created_at": _now(),
                            "metadata_json": '{"legacy":true}',
                        },
                        identity_columns=("id",),
                        label="tenant",
                    )
                    was_inserted = _insert_or_validate_legacy(
                        connection,
                        "canonical_legacy_records",
                        {
                            "tenant_id": tenant,
                            "record_kind": record_kind,
                            "legacy_id": legacy_id,
                            "claim_state": claim_state,
                            "schema_version": CANONICAL_SCHEMA_VERSION,
                            "payload_json": rendered,
                            "migrated_at": _now(),
                        },
                        identity_columns=("tenant_id", "record_kind", "legacy_id"),
                        label="archive record",
                    )
                    count += int(was_inserted)
        return count
    finally:
        if owned:
            connection.close()


@dataclass(frozen=True)
class Migration:
    version: str
    order: int
    upgrade_sql: tuple[str, ...]
    downgrade_sql: tuple[str, ...]
    description: str


def _sha256_guard(value: str) -> str:
    """Return an exact SQLite expression for a canonical sha256 digest."""
    return (
        f"length({value}) = 71 AND substr({value}, 1, 7) = 'sha256:' "
        f"AND substr({value}, 8) GLOB '[0-9a-f]*' "
        f"AND substr({value}, 8) NOT GLOB '*[^0-9a-f]*'"
    )


def _opaque_reference_guard(value: str) -> str:
    """Return an exact SQLite expression for an opaque reference handle."""
    prefix = f"substr({value}, 1, instr({value}, ':') - 1)"
    suffix = f"substr({value}, instr({value}, ':') + 1)"
    return (
        f"instr({value}, ':') > 0 AND ("
        f"(length({suffix}) BETWEEN 1 AND 240 "
        f"AND {prefix} IN ('artifact','credential','cred','secret','source') "
        f"AND {suffix} GLOB '[-A-Za-z0-9._:+/]*' "
        f"AND {suffix} NOT GLOB '*[^-A-Za-z0-9._:+/]*') "
        f"OR ({prefix} = 'sha256' AND length({suffix}) = 64 "
        f"AND {suffix} GLOB '[0-9a-f]*' "
        f"AND {suffix} NOT GLOB '*[^0-9a-f]*')"
        f")"
    )


_MODULE_VERSION_IMMUTABILITY_GUARD = """
        CREATE TRIGGER IF NOT EXISTS canonical_module_version_immutable_guard_update
        BEFORE UPDATE ON canonical_module_versions
        WHEN NEW.id IS NOT OLD.id
          OR NEW.tenant_id IS NOT OLD.tenant_id
          OR NEW.schema_version IS NOT OLD.schema_version
          OR NEW.module_id IS NOT OLD.module_id
          OR NEW.version IS NOT OLD.version
          OR NEW.module_kind IS NOT OLD.module_kind
          OR NEW.manifest_digest IS NOT OLD.manifest_digest
          OR NEW.policy_version IS NOT OLD.policy_version
          OR NEW.intelligence_snapshot_id IS NOT OLD.intelligence_snapshot_id
          OR NEW.check_pack_snapshot_id IS NOT OLD.check_pack_snapshot_id
          OR NEW.provenance_id IS NOT OLD.provenance_id
          OR NEW.created_at IS NOT OLD.created_at
        BEGIN SELECT RAISE(ABORT, 'canonical module version identity is immutable'); END
        """


def _immutable_update_guard(
    table: str,
    label: str,
    columns: tuple[str, ...],
) -> str:
    comparisons = "\n          OR ".join(
        f"NEW.{column} IS NOT OLD.{column}" for column in columns
    )
    return f"""
        CREATE TRIGGER IF NOT EXISTS {table}_semantic_immutable_guard_update
        BEFORE UPDATE ON {table}
        WHEN {comparisons}
        BEGIN SELECT RAISE(ABORT, '{label} identity is immutable'); END
        """


_METADATA_RELATIONSHIP_KEYS = (
    "id",
    "tenant_id",
    "client_id",
    "project_id",
    "engagement_id",
    "operator_id",
    "role_id",
    "scope_decision_id",
    "authorization_decision_id",
    "run_id",
    "execution_id",
    "attempt_id",
    "job_id",
    "action_id",
    "module_version_id",
    "module_execution_id",
    "intelligence_snapshot_id",
    "feed_snapshot_id",
    "check_pack_snapshot_id",
    "asset_id",
    "source_asset_id",
    "observation_id",
    "source_observation_id",
    "artifact_id",
    "finding_id",
    "retest_id",
    "report_id",
    "export_id",
    "source_id",
    "provenance_id",
    "manifest_id",
    "actor_id",
    "created_by",
    "parent_id",
)


def _metadata_relationship_exists(value: str) -> str:
    """Return recursive SQLite metadata-key and relationship rejection."""
    key = "CAST(j.key AS TEXT)"
    normalized = f"lower(trim({key}))"
    for separator in ("-", " ", ".", "/", ":", "\\"):
        normalized = f"replace({normalized}, '{separator}', '_')"
    collapsed = f"replace({normalized}, '_', '')"
    names = ",".join(f"'{name}'" for name in _METADATA_RELATIONSHIP_KEYS)
    collapsed_names = ",".join(
        f"'{name.replace('_', '')}'" for name in _METADATA_RELATIONSHIP_KEYS
    )
    return (
        f"EXISTS(SELECT 1 FROM json_tree({value}) AS j "
        "WHERE j.key IS NOT NULL AND ("
        f"length({key})=0 OR length({key})>64 "
        f"OR {key} GLOB '*[^A-Za-z0-9_]*' "
        f"OR {normalized} IN ({names}) "
        f"OR {collapsed} IN ({collapsed_names}) "
        f"OR {normalized} GLOB '*_id' OR {normalized} GLOB '*_ids' "
        f"OR {key} GLOB '*[a-z0-9]Id' OR {key} GLOB '*[a-z0-9]Ids' "
        f"OR {key} GLOB '*[a-z0-9]ID' OR {key} GLOB '*[a-z0-9]IDs'"
        "))"
    )


def _metadata_invalid(value: str) -> str:
    """Return the metadata rejection predicate for a row or trigger value."""
    return (
        f"length(CAST({value} AS BLOB)) > 16384 "
        f"OR json_valid({value})=0 "
        f"OR CASE WHEN json_valid({value})=1 "
        f"THEN json_type({value})<>'object' ELSE 0 END "
        f"OR CASE WHEN json_valid({value})=1 THEN "
        f"{_metadata_relationship_exists(value)} ELSE 0 END"
    )


def _metadata_integrity_guard_sql(
    tables: tuple[str, ...] = _CANONICAL_TABLES,
) -> tuple[str, ...]:
    """Enforce metadata object shape, byte bound, and relationship isolation."""
    statements: list[str] = []
    for table in tables:
        if table == "canonical_legacy_records":
            continue
        invalid = _metadata_invalid("NEW.metadata_json")
        statements.extend(
            (
                f"""
                CREATE TRIGGER IF NOT EXISTS canonical_metadata_integrity_guard_insert_{table}
                BEFORE INSERT ON {table}
                WHEN {invalid}
                BEGIN SELECT RAISE(ABORT, 'canonical metadata is invalid'); END
                """,
                f"""
                CREATE TRIGGER IF NOT EXISTS canonical_metadata_integrity_guard_update_{table}
                BEFORE UPDATE OF metadata_json ON {table}
                WHEN {invalid}
                BEGIN SELECT RAISE(ABORT, 'canonical metadata is invalid'); END
                """,
            )
        )
    return tuple(statements)


def _audit_existing_canonical_rows(connection: Connection) -> None:
    """Reject invalid rows before accepting or repairing a v1 schema.

    Triggers protect future writes but cannot retroactively validate rows that
    predate a guard.  Keep this audit read-only and fail closed without
    rewriting evidence or guessing a repair.
    """
    tables = {
        str(row[0])
        for row in connection.exec_driver_sql(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }

    for table in _CANONICAL_TABLES + _TASK102_METADATA_TABLES:
        if table not in tables:
            continue
        if connection.exec_driver_sql(
            f"PRAGMA foreign_key_check({table})"
        ).fetchone() is not None:
            raise MigrationError(
                f"existing canonical rows violate foreign keys in {table}"
            )
        if table != "canonical_legacy_records" and connection.exec_driver_sql(
            f"SELECT 1 FROM {table} AS c "
            f"WHERE {_metadata_invalid('c.metadata_json')} LIMIT 1"
        ).fetchone() is not None:
            raise MigrationError(
                f"existing canonical metadata is invalid in {table}"
            )

    relationship_checks = (
        (
            {"canonical_engagements", "canonical_tenants"},
            """
            SELECT 1 FROM canonical_engagements e
            WHERE NOT EXISTS(
              SELECT 1 FROM canonical_tenants t WHERE t.id=e.tenant_id
            ) LIMIT 1
            """,
            "existing canonical engagement tenant is missing",
        ),
        (
            {"canonical_reports", "canonical_tenants"},
            """
            SELECT 1 FROM canonical_reports r
            WHERE NOT EXISTS(
              SELECT 1 FROM canonical_tenants t WHERE t.id=r.tenant_id
            ) LIMIT 1
            """,
            "existing canonical report tenant is missing",
        ),
        (
            {
                "canonical_provenance",
                "canonical_intelligence_sources",
                "canonical_feed_snapshots",
                "canonical_check_pack_snapshots",
            },
            """
            SELECT 1 FROM canonical_provenance p
            WHERE p.source_type NOT IN (
                'intelligence_source','feed_snapshot','check_pack_snapshot'
              )
              OR (p.source_type='intelligence_source' AND NOT EXISTS(
                SELECT 1 FROM canonical_intelligence_sources s
                WHERE s.tenant_id=p.tenant_id AND s.id=p.source_id
              ))
              OR (p.source_type='feed_snapshot' AND NOT EXISTS(
                SELECT 1 FROM canonical_feed_snapshots f
                WHERE f.tenant_id=p.tenant_id AND f.id=p.source_id
                  AND f.digest=p.digest
              ))
              OR (p.source_type='check_pack_snapshot' AND NOT EXISTS(
                SELECT 1 FROM canonical_check_pack_snapshots c
                WHERE c.tenant_id=p.tenant_id AND c.id=p.source_id
                  AND c.digest=p.digest
              ))
            LIMIT 1
            """,
            "existing canonical provenance source is mismatched",
        ),
        (
            {
                "canonical_module_versions",
                "canonical_provenance",
                "canonical_feed_snapshots",
                "canonical_check_pack_snapshots",
            },
            """
            SELECT 1 FROM canonical_module_versions mv
            WHERE mv.provenance_id IS NOT NULL AND NOT EXISTS(
              SELECT 1 FROM canonical_provenance p
              WHERE p.tenant_id=mv.tenant_id AND p.id=mv.provenance_id
                AND (
                  (p.source_type='intelligence_source'
                    AND mv.intelligence_snapshot_id IS NULL
                    AND mv.check_pack_snapshot_id IS NULL)
                  OR (p.source_type='feed_snapshot'
                    AND mv.intelligence_snapshot_id=p.source_id
                    AND EXISTS(
                      SELECT 1 FROM canonical_feed_snapshots f
                      WHERE f.tenant_id=mv.tenant_id AND f.id=p.source_id
                        AND f.digest=p.digest))
                  OR (p.source_type='check_pack_snapshot'
                    AND mv.check_pack_snapshot_id=p.source_id
                    AND EXISTS(
                      SELECT 1 FROM canonical_check_pack_snapshots c
                      WHERE c.tenant_id=mv.tenant_id AND c.id=p.source_id
                        AND c.digest=p.digest))
                )
            ) LIMIT 1
            """,
            "existing canonical module provenance is mismatched",
        ),
        (
            {"canonical_module_executions", "canonical_module_versions"},
            """
            SELECT 1 FROM canonical_module_executions me
            WHERE NOT EXISTS(
              SELECT 1 FROM canonical_module_versions mv
              WHERE mv.tenant_id=me.tenant_id AND mv.id=me.module_version_id
                AND COALESCE(me.intelligence_snapshot_id, '') =
                    COALESCE(mv.intelligence_snapshot_id, '')
                AND COALESCE(me.check_pack_snapshot_id, '') =
                    COALESCE(mv.check_pack_snapshot_id, '')
                AND COALESCE(me.provenance_id, '') =
                    COALESCE(mv.provenance_id, '')
            ) LIMIT 1
            """,
            "existing canonical module execution snapshot is mismatched",
        ),
        (
            {"canonical_observations", "canonical_module_versions"},
            """
            SELECT 1 FROM canonical_observations o
            WHERE (o.intelligence_snapshot_id IS NOT NULL
                   OR o.provenance_id IS NOT NULL)
              AND NOT EXISTS(
                SELECT 1 FROM canonical_module_versions mv
                WHERE mv.tenant_id=o.tenant_id AND mv.id=o.module_version_id
                  AND COALESCE(o.intelligence_snapshot_id, '') =
                      COALESCE(mv.intelligence_snapshot_id, '')
                  AND COALESCE(o.provenance_id, '') =
                      COALESCE(mv.provenance_id, '')
              ) LIMIT 1
            """,
            "existing canonical observation snapshot is mismatched",
        ),
        (
            {
                "canonical_finding_observations",
                "canonical_findings",
                "canonical_observations",
                "canonical_artifact_refs",
            },
            """
            SELECT 1 FROM canonical_finding_observations link
            WHERE NOT EXISTS(
                SELECT 1 FROM canonical_findings f
                WHERE f.tenant_id=link.tenant_id AND f.id=link.finding_id
              )
              OR NOT EXISTS(
                SELECT 1 FROM canonical_observations o
                WHERE o.tenant_id=link.tenant_id AND o.id=link.observation_id
              )
              OR (link.artifact_id IS NOT NULL AND NOT EXISTS(
                SELECT 1 FROM canonical_artifact_refs a
                WHERE a.tenant_id=link.tenant_id AND a.id=link.artifact_id
                  AND a.observation_id=link.observation_id
              ))
            LIMIT 1
            """,
            "existing canonical finding-observation custody is mismatched",
        ),
        (
            {
                "canonical_observation_artifacts",
                "canonical_observations",
                "canonical_artifact_refs",
            },
            """
            SELECT 1 FROM canonical_observation_artifacts link
            WHERE NOT EXISTS(
                SELECT 1 FROM canonical_observations o
                WHERE o.tenant_id=link.tenant_id AND o.id=link.observation_id
              )
              OR NOT EXISTS(
                SELECT 1 FROM canonical_artifact_refs a
                WHERE a.tenant_id=link.tenant_id AND a.id=link.artifact_id
                  AND a.observation_id=link.observation_id
              )
            LIMIT 1
            """,
            "existing canonical observation-artifact custody is mismatched",
        ),
        (
            {
                "canonical_artifact_manifests",
                "canonical_artifact_refs",
                "canonical_observations",
                "canonical_assets",
            },
            f"""
            SELECT 1 FROM canonical_artifact_manifests m
            WHERE m.id<>m.artifact_id
              OR NOT ({_sha256_guard('m.sha256')})
              OR NOT ({_sha256_guard('m.derivative_sha256')})
              OR NOT ({_sha256_guard('m.manifest_digest')})
              OR NOT EXISTS(
                SELECT 1 FROM canonical_artifact_refs a
                WHERE a.tenant_id=m.tenant_id AND a.id=m.artifact_id
                  AND a.observation_id=m.observation_id
              )
              OR NOT EXISTS(
                SELECT 1 FROM canonical_observations o
                WHERE o.tenant_id=m.tenant_id AND o.id=m.observation_id
              )
              OR (m.source_asset_id IS NOT NULL AND NOT EXISTS(
                SELECT 1 FROM canonical_assets a
                WHERE a.tenant_id=m.tenant_id AND a.id=m.source_asset_id
              ))
            LIMIT 1
            """,
            "existing canonical artifact manifest custody is mismatched",
        ),
        (
            {"canonical_evidence_access_audit", "canonical_artifact_refs"},
            """
            SELECT 1 FROM canonical_evidence_access_audit access
            WHERE NOT EXISTS(
                SELECT 1 FROM canonical_artifact_refs a
                WHERE a.tenant_id=access.tenant_id AND a.id=access.artifact_id
                  AND a.observation_id=access.observation_id
              )
              OR (access.access_kind='protected_original'
                  AND access.authorization_ref IS NULL)
            LIMIT 1
            """,
            "existing canonical evidence-access custody is mismatched",
        ),
    )
    for required, sql, message in relationship_checks:
        if required <= tables and connection.exec_driver_sql(
            sql
        ).fetchone() is not None:
            raise MigrationError(message)

    if "canonical_artifact_refs" in tables and connection.exec_driver_sql(
        "SELECT 1 FROM canonical_artifact_refs a "
        "WHERE NOT (" + _opaque_reference_guard("a.reference") + ") "
        "OR (a.digest IS NOT NULL AND NOT (" + _sha256_guard("a.digest") + ")) "
        "LIMIT 1"
    ).fetchone() is not None:
        raise MigrationError("existing canonical artifact custody is malformed")

    if "canonical_findings" in tables:
        finding_columns = {
            str(row[1])
            for row in connection.exec_driver_sql(
                "PRAGMA table_info(canonical_findings)"
            ).fetchall()
        }
        if "dedup_key" in finding_columns and connection.exec_driver_sql(
            "SELECT 1 FROM canonical_findings WHERE dedup_key IS NOT NULL "
            "GROUP BY tenant_id,dedup_key HAVING COUNT(*)>1 LIMIT 1"
        ).fetchone() is not None:
            raise MigrationError("existing canonical finding dedup identity collides")


def _snapshot_lineage_runtime_guard_sql() -> tuple[str, ...]:
    """Reinstall exact snapshot-lineage triggers on every reconciliation."""
    return (
        "DROP TRIGGER IF EXISTS canonical_module_execution_snapshot_guard_insert",
        """
        CREATE TRIGGER canonical_module_execution_snapshot_guard_insert
        BEFORE INSERT ON canonical_module_executions
        WHEN NOT EXISTS(
          SELECT 1 FROM canonical_module_versions mv
          WHERE mv.tenant_id=NEW.tenant_id AND mv.id=NEW.module_version_id
            AND COALESCE(NEW.intelligence_snapshot_id, '') = COALESCE(mv.intelligence_snapshot_id, '')
            AND COALESCE(NEW.check_pack_snapshot_id, '') = COALESCE(mv.check_pack_snapshot_id, '')
            AND COALESCE(NEW.provenance_id, '') = COALESCE(mv.provenance_id, '')
        )
        BEGIN SELECT RAISE(ABORT, 'module execution snapshot lineage mismatch'); END
        """,
        "DROP TRIGGER IF EXISTS canonical_module_execution_snapshot_guard_update",
        """
        CREATE TRIGGER canonical_module_execution_snapshot_guard_update
        BEFORE UPDATE OF tenant_id, module_version_id, intelligence_snapshot_id, check_pack_snapshot_id, provenance_id ON canonical_module_executions
        WHEN NOT EXISTS(
          SELECT 1 FROM canonical_module_versions mv
          WHERE mv.tenant_id=NEW.tenant_id AND mv.id=NEW.module_version_id
            AND COALESCE(NEW.intelligence_snapshot_id, '') = COALESCE(mv.intelligence_snapshot_id, '')
            AND COALESCE(NEW.check_pack_snapshot_id, '') = COALESCE(mv.check_pack_snapshot_id, '')
            AND COALESCE(NEW.provenance_id, '') = COALESCE(mv.provenance_id, '')
        )
        BEGIN SELECT RAISE(ABORT, 'module execution snapshot lineage mismatch'); END
        """,
        "DROP TRIGGER IF EXISTS canonical_observation_snapshot_guard_insert",
        """
        CREATE TRIGGER canonical_observation_snapshot_guard_insert
        BEFORE INSERT ON canonical_observations
        WHEN (NEW.intelligence_snapshot_id IS NOT NULL OR NEW.provenance_id IS NOT NULL)
          AND NOT EXISTS(
          SELECT 1 FROM canonical_module_versions mv
          WHERE mv.tenant_id=NEW.tenant_id AND mv.id=NEW.module_version_id
            AND COALESCE(NEW.intelligence_snapshot_id, '') = COALESCE(mv.intelligence_snapshot_id, '')
            AND COALESCE(NEW.provenance_id, '') = COALESCE(mv.provenance_id, '')
        )
        BEGIN SELECT RAISE(ABORT, 'observation snapshot lineage mismatch'); END
        """,
        "DROP TRIGGER IF EXISTS canonical_observation_snapshot_guard_update",
        """
        CREATE TRIGGER canonical_observation_snapshot_guard_update
        BEFORE UPDATE OF tenant_id, module_version_id, intelligence_snapshot_id, provenance_id ON canonical_observations
        WHEN (NEW.intelligence_snapshot_id IS NOT NULL OR NEW.provenance_id IS NOT NULL)
          AND NOT EXISTS(
          SELECT 1 FROM canonical_module_versions mv
          WHERE mv.tenant_id=NEW.tenant_id AND mv.id=NEW.module_version_id
            AND COALESCE(NEW.intelligence_snapshot_id, '') = COALESCE(mv.intelligence_snapshot_id, '')
            AND COALESCE(NEW.provenance_id, '') = COALESCE(mv.provenance_id, '')
        )
        BEGIN SELECT RAISE(ABORT, 'observation snapshot lineage mismatch'); END
        """,
    )


def _runtime_guard_sql() -> tuple[str, ...]:
    """Return safety guards that must also repair already-applied schemas."""
    digest_tables = (
        ("canonical_provenance", "provenance"),
        ("canonical_feed_snapshots", "feed snapshot"),
        ("canonical_check_pack_snapshots", "check-pack snapshot"),
    )


    statements: list[str] = [
        _MODULE_VERSION_IMMUTABILITY_GUARD,
        """
        CREATE TRIGGER IF NOT EXISTS canonical_engagement_tenant_guard_insert
        BEFORE INSERT ON canonical_engagements
        WHEN NOT EXISTS(
          SELECT 1 FROM canonical_tenants WHERE id=NEW.tenant_id
        )
        BEGIN SELECT RAISE(ABORT, 'engagement tenant is missing'); END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS canonical_engagement_tenant_guard_update
        BEFORE UPDATE OF tenant_id ON canonical_engagements
        WHEN NOT EXISTS(
          SELECT 1 FROM canonical_tenants WHERE id=NEW.tenant_id
        )
        BEGIN SELECT RAISE(ABORT, 'engagement tenant is missing'); END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS canonical_report_tenant_guard_insert
        BEFORE INSERT ON canonical_reports
        WHEN NOT EXISTS(
          SELECT 1 FROM canonical_tenants WHERE id=NEW.tenant_id
        )
        BEGIN SELECT RAISE(ABORT, 'report tenant is missing'); END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS canonical_report_tenant_guard_update
        BEFORE UPDATE OF tenant_id ON canonical_reports
        WHEN NOT EXISTS(
          SELECT 1 FROM canonical_tenants WHERE id=NEW.tenant_id
        )
        BEGIN SELECT RAISE(ABORT, 'report tenant is missing'); END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS canonical_module_version_provenance_guard_insert
        BEFORE INSERT ON canonical_module_versions
        WHEN NEW.provenance_id IS NOT NULL AND NOT EXISTS(
          SELECT 1 FROM canonical_provenance p
          WHERE p.tenant_id=NEW.tenant_id AND p.id=NEW.provenance_id
            AND (
              (p.source_type='intelligence_source'
                AND NEW.intelligence_snapshot_id IS NULL
                AND NEW.check_pack_snapshot_id IS NULL)
              OR (p.source_type='feed_snapshot'
                AND NEW.intelligence_snapshot_id=p.source_id
                AND EXISTS(
                  SELECT 1 FROM canonical_feed_snapshots f
                  WHERE f.tenant_id=NEW.tenant_id AND f.id=p.source_id
                    AND f.digest=p.digest))
              OR (p.source_type='check_pack_snapshot'
                AND NEW.check_pack_snapshot_id=p.source_id
                AND EXISTS(
                  SELECT 1 FROM canonical_check_pack_snapshots c
                  WHERE c.tenant_id=NEW.tenant_id AND c.id=p.source_id
                    AND c.digest=p.digest))
            )
        )
        BEGIN SELECT RAISE(ABORT, 'module version provenance snapshot mismatch'); END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS canonical_module_version_provenance_guard_update
        BEFORE UPDATE OF tenant_id, intelligence_snapshot_id, check_pack_snapshot_id, provenance_id
        ON canonical_module_versions
        WHEN NEW.provenance_id IS NOT NULL AND NOT EXISTS(
          SELECT 1 FROM canonical_provenance p
          WHERE p.tenant_id=NEW.tenant_id AND p.id=NEW.provenance_id
            AND (
              (p.source_type='intelligence_source'
                AND NEW.intelligence_snapshot_id IS NULL
                AND NEW.check_pack_snapshot_id IS NULL)
              OR (p.source_type='feed_snapshot'
                AND NEW.intelligence_snapshot_id=p.source_id
                AND EXISTS(
                  SELECT 1 FROM canonical_feed_snapshots f
                  WHERE f.tenant_id=NEW.tenant_id AND f.id=p.source_id
                    AND f.digest=p.digest))
              OR (p.source_type='check_pack_snapshot'
                AND NEW.check_pack_snapshot_id=p.source_id
                AND EXISTS(
                  SELECT 1 FROM canonical_check_pack_snapshots c
                  WHERE c.tenant_id=NEW.tenant_id AND c.id=p.source_id
                    AND c.digest=p.digest))
            )
        )
        BEGIN SELECT RAISE(ABORT, 'module version provenance snapshot mismatch'); END
        """,
        "DROP TRIGGER IF EXISTS canonical_provenance_source_guard",
        """
        CREATE TRIGGER canonical_provenance_source_guard
        BEFORE INSERT ON canonical_provenance
        BEGIN
          SELECT CASE
            WHEN NEW.source_type='intelligence_source' AND NOT EXISTS(
              SELECT 1 FROM canonical_intelligence_sources
              WHERE tenant_id=NEW.tenant_id AND id=NEW.source_id)
            THEN RAISE(ABORT, 'canonical provenance source is missing')
            WHEN NEW.source_type='feed_snapshot' AND NOT EXISTS(
              SELECT 1 FROM canonical_feed_snapshots
              WHERE tenant_id=NEW.tenant_id AND id=NEW.source_id
                AND digest=NEW.digest)
            THEN RAISE(ABORT, 'canonical provenance feed is missing or mismatched')
            WHEN NEW.source_type='check_pack_snapshot' AND NOT EXISTS(
              SELECT 1 FROM canonical_check_pack_snapshots
              WHERE tenant_id=NEW.tenant_id AND id=NEW.source_id
                AND digest=NEW.digest)
            THEN RAISE(ABORT, 'canonical provenance check pack is missing or mismatched')
          END;
        END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS canonical_provenance_normalized_source_guard_insert
        BEFORE INSERT ON canonical_provenance
        WHEN NEW.source_type NOT IN (
          'intelligence_source', 'feed_snapshot', 'check_pack_snapshot'
        )
        BEGIN SELECT RAISE(ABORT, 'canonical provenance source type is unsupported'); END
        """,
        _immutable_update_guard(
            "canonical_provenance",
            "canonical provenance",
            ("id", "tenant_id", "source_type", "source_id", "digest", "schema_version", "created_at"),
        ),
        _immutable_update_guard(
            "canonical_feed_snapshots",
            "canonical feed snapshot",
            ("id", "tenant_id", "source_id", "schema_version", "version", "digest", "created_at"),
        ),
        _immutable_update_guard(
            "canonical_check_pack_snapshots",
            "canonical check-pack snapshot",
            ("id", "tenant_id", "source_id", "schema_version", "version", "digest", "created_at"),
        ),
        _immutable_update_guard(
            "canonical_assets",
            "canonical asset",
            ("id", "tenant_id", "schema_version", "kind", "identity_key", "canonical_uri", "created_at"),
        ),
        _immutable_update_guard(
            "canonical_scope_decisions",
            "canonical scope decision",
            (
                "id",
                "tenant_id",
                "engagement_id",
                "operator_id",
                "role_id",
                "schema_version",
                "outcome",
                "policy_version",
                "decision_reason",
                "decided_at",
                "created_at",
            ),
        ),
    ]
    for table, label in digest_tables:
        statements.extend(
            (
                f"""
                CREATE TRIGGER IF NOT EXISTS {table}_digest_guard_insert
                BEFORE INSERT ON {table}
                WHEN NOT ({_sha256_guard('NEW.digest')})
                BEGIN SELECT RAISE(ABORT, '{label} digest must be sha256:<64 lowercase hex>'); END
                """,
                f"""
                CREATE TRIGGER IF NOT EXISTS {table}_digest_guard_update
                BEFORE UPDATE OF digest ON {table}
                WHEN NOT ({_sha256_guard('NEW.digest')})
                BEGIN SELECT RAISE(ABORT, '{label} digest must be sha256:<64 lowercase hex>'); END
                """,
            )
        )
    statements.extend(
        (
            """
            CREATE TRIGGER IF NOT EXISTS canonical_module_version_manifest_digest_guard_insert
            BEFORE INSERT ON canonical_module_versions
            WHEN NEW.manifest_digest IS NOT NULL
              AND NOT (length(NEW.manifest_digest) = 71
                AND substr(NEW.manifest_digest, 1, 7) = 'sha256:'
                AND substr(NEW.manifest_digest, 8) GLOB '[0-9a-f]*'
                AND substr(NEW.manifest_digest, 8) NOT GLOB '*[^0-9a-f]*')
            BEGIN SELECT RAISE(ABORT, 'module manifest digest must be sha256:<64 lowercase hex>'); END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS canonical_artifact_reference_guard_insert
            BEFORE INSERT ON canonical_artifact_refs
            WHEN NOT (""" + _opaque_reference_guard("NEW.reference") + """)
            BEGIN SELECT RAISE(ABORT, 'artifact reference must be an opaque handle'); END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS canonical_artifact_reference_guard_update
            BEFORE UPDATE OF reference ON canonical_artifact_refs
            WHEN NOT (""" + _opaque_reference_guard("NEW.reference") + """)
            BEGIN SELECT RAISE(ABORT, 'artifact reference must be an opaque handle'); END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS canonical_artifact_digest_guard_insert
            BEFORE INSERT ON canonical_artifact_refs
            WHEN NEW.digest IS NOT NULL AND NOT (""" + _sha256_guard("NEW.digest") + """)
            BEGIN SELECT RAISE(ABORT, 'artifact digest must be sha256:<64 lowercase hex>'); END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS canonical_artifact_digest_guard_update
            BEFORE UPDATE OF digest ON canonical_artifact_refs
            WHEN NEW.digest IS NOT NULL AND NOT (""" + _sha256_guard("NEW.digest") + """)
            BEGIN SELECT RAISE(ABORT, 'artifact digest must be sha256:<64 lowercase hex>'); END
            """,
        )
    )
    statements.extend(_snapshot_lineage_runtime_guard_sql())
    statements.extend(_metadata_integrity_guard_sql())
    return tuple(statements)


def _expand_task102_finding_status_constraint(connection: Connection) -> None:
    """Atomically extend the v1 finding workflow constraint for Task 102.

    SQLite cannot alter a CHECK constraint in place.  The evidence migration
    therefore rebuilds only this table, with foreign-key enforcement disabled
    for the duration of one transaction, and refuses to commit unless the
    complete database passes ``foreign_key_check``.  Task 102 repair then
    recreates the finding indexes and runtime guards.
    """
    table_sql_row = connection.exec_driver_sql(
        "SELECT sql FROM sqlite_master "
        "WHERE type='table' AND name='canonical_findings'"
    ).fetchone()
    if table_sql_row is None:
        if connection.in_transaction():
            connection.commit()
        return
    table_sql = str(table_sql_row[0] or "")
    if all(f"'{status}'" in table_sql for status in _TASK102_FINDING_STATUSES):
        if connection.in_transaction():
            connection.commit()
        return
    expected_columns = {
        "id",
        "tenant_id",
        "observation_id",
        "artifact_id",
        "schema_version",
        "title",
        "severity",
        "description",
        "status",
        "finding_key",
        "created_at",
        "metadata_json",
        "dedup_key",
    }
    actual_columns = {
        str(row[1])
        for row in connection.exec_driver_sql(
            "PRAGMA table_info(canonical_findings)"
        ).fetchall()
    }
    if actual_columns != expected_columns:
        if connection.in_transaction():
            connection.rollback()
        raise MigrationError(
            "canonical finding status repair encountered an unexpected schema"
        )
    successor = "canonical_findings_task102_status_successor"
    if connection.exec_driver_sql(
        "SELECT 1 FROM sqlite_master WHERE name=?",
        (successor,),
    ).fetchone() is not None:
        if connection.in_transaction():
            connection.rollback()
        raise MigrationError(
            "canonical finding status repair successor already exists"
        )
    finding_triggers = connection.exec_driver_sql(
        "SELECT name,sql FROM sqlite_master WHERE type='trigger' "
        "AND (tbl_name='canonical_findings' "
        "OR lower(sql) LIKE '%canonical_findings%') ORDER BY name"
    ).fetchall()
    unexpected_triggers = {
        str(row[0]) for row in finding_triggers
    } - _CANONICAL_FINDING_TRIGGER_NAMES
    if unexpected_triggers or any(row[1] is None for row in finding_triggers):
        if connection.in_transaction():
            connection.rollback()
        raise MigrationError(
            "canonical finding status repair encountered an unexpected trigger"
        )
    if connection.in_transaction():
        connection.commit()
    connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
    if connection.in_transaction():
        connection.commit()
    foreign_keys_disabled = int(
        connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one()
    ) == 0
    if connection.in_transaction():
        connection.commit()
    if not foreign_keys_disabled:
        raise MigrationError(
            "canonical finding status repair could not suspend foreign keys"
        )
    columns = (
        "id,tenant_id,observation_id,artifact_id,schema_version,title,severity,"
        "description,status,finding_key,created_at,metadata_json,dedup_key"
    )
    try:
        with connection.begin():
            connection.exec_driver_sql(
                f"""
                CREATE TABLE {successor} (
                    id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    observation_id TEXT NOT NULL,
                    artifact_id TEXT NOT NULL,
                    schema_version TEXT NOT NULL,
                    title TEXT NOT NULL CHECK(length(title) BETWEEN 1 AND 500),
                    severity TEXT NOT NULL CHECK(severity IN ('critical','high','medium','low','informational')),
                    description TEXT NOT NULL CHECK(length(description) BETWEEN 1 AND 8000),
                    status TEXT NOT NULL CHECK(status IN ('open','in_progress','verified','false_positive','remediated','accepted_risk','unknown')),
                    finding_key TEXT,
                    created_at TEXT NOT NULL,
                    metadata_json TEXT NOT NULL DEFAULT '{{}}',
                    dedup_key TEXT,
                    UNIQUE(tenant_id, id),
                    UNIQUE(tenant_id, id, observation_id),
                    FOREIGN KEY(tenant_id, observation_id) REFERENCES canonical_observations(tenant_id, id) ON DELETE RESTRICT,
                    FOREIGN KEY(tenant_id, artifact_id, observation_id) REFERENCES canonical_artifact_refs(tenant_id, id, observation_id) ON DELETE RESTRICT
                )
                """
            )
            connection.exec_driver_sql(
                f"INSERT INTO {successor} ({columns}) "
                f"SELECT {columns} FROM canonical_findings"
            )
            for trigger_name, _trigger_sql in finding_triggers:
                connection.exec_driver_sql(
                    f"DROP TRIGGER IF EXISTS {trigger_name}"
                )
            connection.exec_driver_sql("DROP TABLE canonical_findings")
            connection.exec_driver_sql(
                f"ALTER TABLE {successor} RENAME TO canonical_findings"
            )
            for _trigger_name, trigger_sql in finding_triggers:
                connection.exec_driver_sql(str(trigger_sql))
            if connection.exec_driver_sql("PRAGMA foreign_key_check").fetchall():
                raise MigrationError(
                    "canonical finding status repair failed foreign-key verification"
                )
    finally:
        if connection.in_transaction():
            connection.rollback()
        connection.exec_driver_sql("PRAGMA foreign_keys=ON")
        if connection.in_transaction():
            connection.commit()
        foreign_keys_enabled = int(
            connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one()
        ) == 1
        if connection.in_transaction():
            connection.commit()
        if not foreign_keys_enabled:
            raise MigrationError(
                "canonical finding status repair did not restore foreign keys"
            )


def _task102_schema_repair(connection: Connection) -> None:
    """Add Task 102 custody columns/tables to already-applied v1 databases."""
    def columns(table: str) -> set[str]:
        return {str(row[1]) for row in connection.exec_driver_sql(f"PRAGMA table_info({table})").fetchall()}

    additions: dict[str, tuple[tuple[str, str], ...]] = {
        "canonical_observations": (
            ("proof_type", "TEXT NOT NULL DEFAULT 'unknown'"),
            ("collection_status", "TEXT NOT NULL DEFAULT 'unknown'"),
            ("check_id", "TEXT"), ("route", "TEXT"), ("parameter", "TEXT"),
            ("location", "TEXT"), ("identity_ref", "TEXT"),
        ),
        "canonical_artifact_refs": (
            ("collector_id", "TEXT NOT NULL DEFAULT 'unknown'"),
            ("collector_version", "TEXT NOT NULL DEFAULT 'unknown'"),
            ("source_target", "TEXT NOT NULL DEFAULT 'unknown'"),
            ("source_asset_id", "TEXT"), ("redaction_version", "TEXT NOT NULL DEFAULT 'unknown'"),
            ("protection_state", "TEXT NOT NULL DEFAULT 'reference_only'"),
            ("signer_state", "TEXT NOT NULL DEFAULT 'unsigned'"),
            ("integrity_state", "TEXT NOT NULL DEFAULT 'sha256_verified'"),
            ("retention_class", "TEXT NOT NULL DEFAULT 'default'"),
            ("retention_expires_at", "TEXT"),
            ("protected_original_authorization_ref", "TEXT"),
            ("derivative_reference", "TEXT"), ("manifest_digest", "TEXT"),
        ),
        "canonical_findings": (("dedup_key", "TEXT"),),
    }
    existing_tables = {str(row[0]) for row in connection.exec_driver_sql("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    for table, table_columns in additions.items():
        if table not in existing_tables:
            continue
        known = columns(table)
        for name, declaration in table_columns:
            if name not in known:
                connection.exec_driver_sql(f"ALTER TABLE {table} ADD COLUMN {name} {declaration}")
    # Some combined pre-acceptance candidates added Task 102 columns to v1
    # rows using optimistic defaults.  A legacy artifact with no digest has
    # neither verified integrity nor retained protected bytes.  Correct only
    # that narrowly identifiable legacy/default combination before restoring
    # append-only guards; do not rewrite ordinary evidence rows.
    connection.exec_driver_sql(
        "DROP TRIGGER IF EXISTS canonical_artifact_refs_append_only_update"
    )
    connection.exec_driver_sql(
        "DROP TRIGGER IF EXISTS canonical_artifact_refs_custody_immutable_update"
    )
    artifact_columns = columns("canonical_artifact_refs")
    if {"integrity_state", "protection_state"} <= artifact_columns:
        connection.exec_driver_sql(
            "UPDATE canonical_artifact_refs "
            "SET integrity_state='unknown', protection_state='legacy_unknown' "
            "WHERE digest IS NULL AND json_valid(metadata_json)=1 "
            "AND json_extract(metadata_json, '$.legacy')=1 "
            "AND integrity_state IN ('sha256_verified','unknown') "
            "AND protection_state IN ('reference_only','unknown')"
        )
    connection.exec_driver_sql("""
        CREATE TABLE IF NOT EXISTS canonical_finding_observations (
            tenant_id TEXT NOT NULL, finding_id TEXT NOT NULL, observation_id TEXT NOT NULL,
            artifact_id TEXT, created_at TEXT NOT NULL, metadata_json TEXT NOT NULL DEFAULT '{}',
            PRIMARY KEY(tenant_id, finding_id, observation_id),
            UNIQUE(tenant_id, finding_id, observation_id, artifact_id),
            FOREIGN KEY(tenant_id, finding_id) REFERENCES canonical_findings(tenant_id, id) ON DELETE RESTRICT,
            FOREIGN KEY(tenant_id, observation_id) REFERENCES canonical_observations(tenant_id, id) ON DELETE RESTRICT,
            FOREIGN KEY(tenant_id, artifact_id, observation_id) REFERENCES canonical_artifact_refs(tenant_id, id, observation_id) ON DELETE RESTRICT
        )
    """)
    # Older Task 102 candidates created the source-link table with only the
    # minimal six columns.  Repair it in place before creating indexes or
    # backfilling links so replays remain idempotent and never reference a
    # missing column.
    link_columns = columns("canonical_finding_observations")
    for name, declaration in (
        ("identity_key", "TEXT NOT NULL DEFAULT ''"),
        ("first_seen_at", "TEXT NOT NULL DEFAULT '1970-01-01T00:00:00Z'"),
        ("last_seen_at", "TEXT NOT NULL DEFAULT '1970-01-01T00:00:00Z'"),
    ):
        if name not in link_columns:
            connection.exec_driver_sql(
                f"ALTER TABLE canonical_finding_observations ADD COLUMN {name} {declaration}"
            )
    connection.exec_driver_sql(
        "DROP TRIGGER IF EXISTS canonical_finding_observations_append_only_update"
    )
    connection.exec_driver_sql(
        "DROP TRIGGER IF EXISTS canonical_finding_observations_no_update"
    )
    # Enrich only the exact defaults introduced by the historical six-column
    # table repair.  Existing metadata and artifact ownership remain intact.
    connection.exec_driver_sql(
        "UPDATE canonical_finding_observations AS link "
        "SET identity_key=COALESCE((SELECT NULLIF(f.dedup_key,'') FROM canonical_findings f "
        "WHERE f.tenant_id=link.tenant_id AND f.id=link.finding_id), "
        "'finding-v1:legacy'), first_seen_at=link.created_at, "
        "last_seen_at=link.created_at "
        "WHERE link.identity_key='' "
        "AND link.first_seen_at='1970-01-01T00:00:00Z' "
        "AND link.last_seen_at='1970-01-01T00:00:00Z' "
        "AND EXISTS(SELECT 1 FROM canonical_findings f "
        "WHERE f.tenant_id=link.tenant_id AND f.id=link.finding_id)"
    )
    # Preserve links for canonical rows that pre-date the additive table.  A
    # missing digest or legacy artifact is represented by its existing opaque
    # reference; no new evidence bytes or fabricated integrity is created.
    backfill_rows = connection.exec_driver_sql(
        """
        SELECT f.tenant_id, f.id AS finding_id, f.observation_id, f.artifact_id,
               COALESCE(NULLIF(f.dedup_key, ''), 'finding-v1:legacy') AS identity_key,
               f.created_at, f.dedup_key AS finding_dedup_key
        FROM canonical_findings AS f
        """
    ).mappings().all()
    for row in backfill_rows:
        values = {
            "tenant_id": row["tenant_id"],
            "finding_id": row["finding_id"],
            "observation_id": row["observation_id"],
            "artifact_id": row["artifact_id"],
            "identity_key": row["identity_key"],
            "first_seen_at": row["created_at"],
            "last_seen_at": row["created_at"],
            "created_at": row["created_at"],
            "metadata_json": '{"legacy":true,"integrity_state":"unknown"}',
        }
        existing = connection.exec_driver_sql(
            "SELECT artifact_id,identity_key,first_seen_at,last_seen_at,"
            "created_at,metadata_json FROM canonical_finding_observations "
            "WHERE tenant_id=? AND finding_id=? AND observation_id=?",
            (row["tenant_id"], row["finding_id"], row["observation_id"]),
        ).mappings().one_or_none()
        if existing is None:
            _insert_or_validate_legacy(
                connection,
                "canonical_finding_observations",
                values,
                identity_columns=("tenant_id", "finding_id", "observation_id"),
                label="finding observation backfill",
            )
            continue
        try:
            existing_metadata = json.loads(str(existing["metadata_json"]))
        except (TypeError, json.JSONDecodeError) as exc:
            raise MigrationError("canonical finding source metadata is invalid") from exc
        # The link marker is append-only custody data; finding metadata is a
        # mutable workflow field and must not weaken strict legacy-link replay.
        # Any attempted legacy marker, including a type-confused value such as
        # integer 1, remains on the strict comparison path and is rejected.
        if row["finding_dedup_key"] is None or (
            isinstance(existing_metadata, Mapping) and "legacy" in existing_metadata
        ):
            _insert_or_validate_legacy(
                connection,
                "canonical_finding_observations",
                values,
                identity_columns=("tenant_id", "finding_id", "observation_id"),
                label="legacy finding observation backfill",
            )
        elif (
            existing["artifact_id"] != row["artifact_id"]
            or existing["identity_key"] != row["identity_key"]
            or not isinstance(existing["identity_key"], str)
            or not existing["identity_key"]
            or not all(
                isinstance(existing[field], str) and existing[field]
                for field in ("first_seen_at", "last_seen_at", "created_at")
            )
        ):
            raise MigrationError("existing canonical finding source link is mismatched")
    connection.exec_driver_sql("""
        CREATE TABLE IF NOT EXISTS canonical_evidence_access_audit (
            id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, artifact_id TEXT NOT NULL, observation_id TEXT NOT NULL,
            access_kind TEXT NOT NULL CHECK(access_kind IN ('redacted_derivative','protected_original')),
            authorization_ref TEXT, accessed_at TEXT NOT NULL, metadata_json TEXT NOT NULL DEFAULT '{}',
            FOREIGN KEY(tenant_id, artifact_id, observation_id) REFERENCES canonical_artifact_refs(tenant_id, id, observation_id) ON DELETE RESTRICT
        )
    """)
    for statement in (
        "CREATE INDEX IF NOT EXISTS ix_canonical_finding_lineage ON canonical_findings(tenant_id, observation_id, artifact_id)",
        "CREATE INDEX IF NOT EXISTS ix_canonical_finding_dedup ON canonical_findings(tenant_id, dedup_key)",
        "CREATE INDEX IF NOT EXISTS ix_canonical_finding_observation_lineage ON canonical_finding_observations(tenant_id, finding_id, observation_id)",
        "CREATE INDEX IF NOT EXISTS ix_canonical_finding_observation_seen ON canonical_finding_observations(tenant_id, finding_id, last_seen_at)",
        "CREATE INDEX IF NOT EXISTS ix_canonical_evidence_audit ON canonical_evidence_access_audit(tenant_id, artifact_id, accessed_at)",
    ):
        connection.exec_driver_sql(statement)
    immutable: dict[str, tuple[str, ...]] = {
        "canonical_observations": ("id", "tenant_id", "engagement_id", "job_id", "module_version_id", "module_execution_id", "asset_id", "action_id", "intelligence_snapshot_id", "provenance_id", "schema_version", "status", "observed_at", "created_at", "proof_type", "collection_status", "check_id", "route", "parameter", "location", "identity_ref", "metadata_json"),
        "canonical_artifact_refs": ("id", "tenant_id", "observation_id", "schema_version", "reference", "digest", "media_type", "size", "redaction_state", "encryption_state", "collected_at", "created_at", "collector_id", "collector_version", "source_target", "source_asset_id", "redaction_version", "protection_state", "signer_state", "integrity_state", "retention_class", "retention_expires_at", "protected_original_authorization_ref", "derivative_reference", "manifest_digest", "metadata_json"),
    }
    for table, fields in immutable.items():
        if table == "canonical_artifact_refs":
            # Replace the pre-Task-102 guard so one NULL -> verified manifest
            # binding is possible; all other identity/custody mutations remain
            # rejected.
            connection.exec_driver_sql(
                "DROP TRIGGER IF EXISTS canonical_artifact_refs_custody_immutable_update"
            )
        comparisons = " OR ".join(
            f"NEW.{field} IS NOT OLD.{field}"
            for field in fields
            if field != "manifest_digest"
        )
        if table == "canonical_artifact_refs":
            comparisons += (
                " OR (NEW.manifest_digest IS NOT OLD.manifest_digest AND NOT ("
                "OLD.manifest_digest IS NULL AND NEW.manifest_digest IS NOT NULL "
                f"AND ({_sha256_guard('NEW.manifest_digest')})))"
            )
        connection.exec_driver_sql(f"CREATE TRIGGER IF NOT EXISTS {table}_custody_immutable_update BEFORE UPDATE ON {table} WHEN {comparisons} BEGIN SELECT RAISE(ABORT, 'immutable custody record is immutable'); END")
        connection.exec_driver_sql(f"CREATE TRIGGER IF NOT EXISTS {table}_custody_no_delete BEFORE DELETE ON {table} BEGIN SELECT RAISE(ABORT, 'immutable custody record cannot be deleted'); END")
    connection.exec_driver_sql("CREATE TRIGGER IF NOT EXISTS canonical_finding_observations_no_update BEFORE UPDATE ON canonical_finding_observations BEGIN SELECT RAISE(ABORT, 'finding observation links are immutable'); END")
    connection.exec_driver_sql("CREATE TRIGGER IF NOT EXISTS canonical_finding_observations_no_delete BEFORE DELETE ON canonical_finding_observations BEGIN SELECT RAISE(ABORT, 'finding observation links cannot be deleted'); END")
    connection.exec_driver_sql(
        "DROP TRIGGER IF EXISTS canonical_finding_observation_tenant_guard"
    )
    connection.exec_driver_sql(
        """
        CREATE TRIGGER canonical_finding_observation_tenant_guard
        BEFORE INSERT ON canonical_finding_observations
        WHEN NOT EXISTS(
          SELECT 1 FROM canonical_findings f
          WHERE f.tenant_id=NEW.tenant_id AND f.id=NEW.finding_id)
          OR NOT EXISTS(
          SELECT 1 FROM canonical_observations o
          WHERE o.tenant_id=NEW.tenant_id AND o.id=NEW.observation_id)
          OR (NEW.artifact_id IS NOT NULL AND NOT EXISTS(
          SELECT 1 FROM canonical_artifact_refs a
          WHERE a.tenant_id=NEW.tenant_id AND a.id=NEW.artifact_id
            AND a.observation_id=NEW.observation_id))
        BEGIN SELECT RAISE(ABORT, 'finding observation tenant lineage mismatch'); END
        """
    )
    connection.exec_driver_sql("CREATE TRIGGER IF NOT EXISTS canonical_evidence_access_audit_no_update BEFORE UPDATE ON canonical_evidence_access_audit BEGIN SELECT RAISE(ABORT, 'evidence access audit is append-only'); END")
    connection.exec_driver_sql("CREATE TRIGGER IF NOT EXISTS canonical_evidence_access_audit_no_delete BEFORE DELETE ON canonical_evidence_access_audit BEGIN SELECT RAISE(ABORT, 'evidence access audit cannot be deleted'); END")
    connection.exec_driver_sql(
        """
        CREATE TRIGGER IF NOT EXISTS canonical_artifact_source_asset_guard_insert
        BEFORE INSERT ON canonical_artifact_refs
        WHEN NEW.source_asset_id IS NOT NULL AND NOT EXISTS(
            SELECT 1 FROM canonical_assets
            WHERE tenant_id=NEW.tenant_id AND id=NEW.source_asset_id
        )
        BEGIN SELECT RAISE(ABORT, 'artifact source asset tenant lineage mismatch'); END
        """
    )
    connection.exec_driver_sql(
        """
        CREATE TRIGGER IF NOT EXISTS canonical_artifact_source_asset_guard_update
        BEFORE UPDATE OF tenant_id, source_asset_id ON canonical_artifact_refs
        WHEN NEW.source_asset_id IS NOT NULL AND NOT EXISTS(
            SELECT 1 FROM canonical_assets
            WHERE tenant_id=NEW.tenant_id AND id=NEW.source_asset_id
        )
        BEGIN SELECT RAISE(ABORT, 'artifact source asset tenant lineage mismatch'); END
        """
    )
    connection.exec_driver_sql(
        "DROP TRIGGER IF EXISTS canonical_artifact_refs_append_only_update"
    )
    connection.exec_driver_sql(
        """
        CREATE TRIGGER canonical_artifact_refs_append_only_update
        BEFORE UPDATE ON canonical_artifact_refs
        WHEN NEW.id IS NOT OLD.id OR NEW.tenant_id IS NOT OLD.tenant_id
          OR NEW.observation_id IS NOT OLD.observation_id
          OR NEW.schema_version IS NOT OLD.schema_version
          OR NEW.reference IS NOT OLD.reference OR NEW.digest IS NOT OLD.digest
          OR NEW.media_type IS NOT OLD.media_type OR NEW.size IS NOT OLD.size
          OR NEW.redaction_state IS NOT OLD.redaction_state
          OR NEW.encryption_state IS NOT OLD.encryption_state
          OR NEW.collected_at IS NOT OLD.collected_at OR NEW.created_at IS NOT OLD.created_at
          OR NEW.collector_id IS NOT OLD.collector_id
          OR NEW.collector_version IS NOT OLD.collector_version
          OR NEW.source_target IS NOT OLD.source_target
          OR NEW.source_asset_id IS NOT OLD.source_asset_id
          OR NEW.redaction_version IS NOT OLD.redaction_version
          OR NEW.protection_state IS NOT OLD.protection_state
          OR NEW.signer_state IS NOT OLD.signer_state
          OR NEW.integrity_state IS NOT OLD.integrity_state
          OR NEW.retention_class IS NOT OLD.retention_class
          OR NEW.retention_expires_at IS NOT OLD.retention_expires_at
          OR NEW.protected_original_authorization_ref IS NOT OLD.protected_original_authorization_ref
          OR NEW.derivative_reference IS NOT OLD.derivative_reference
          OR NEW.metadata_json IS NOT OLD.metadata_json
          OR NOT (OLD.manifest_digest IS NULL AND NEW.manifest_digest IS NOT NULL
            AND length(NEW.manifest_digest)=71
            AND substr(NEW.manifest_digest,1,7)='sha256:'
            AND NEW.manifest_digest GLOB 'sha256:*')
        BEGIN SELECT RAISE(ABORT, 'canonical artifact references are immutable'); END
        """
    )
    if "canonical_artifact_manifests" in existing_tables:
        connection.exec_driver_sql(
            """
            CREATE TRIGGER IF NOT EXISTS canonical_artifact_manifest_digest_guard_insert
            BEFORE INSERT ON canonical_artifact_manifests
            WHEN NOT ({sha256} AND {derivative} AND {manifest})
            BEGIN SELECT RAISE(ABORT, 'artifact manifest digest must be sha256:<64 lowercase hex>'); END
            """.format(
                sha256=_sha256_guard("NEW.sha256"),
                derivative=_sha256_guard("NEW.derivative_sha256"),
                manifest=_sha256_guard("NEW.manifest_digest"),
            )
        )
        connection.exec_driver_sql(
            """
            CREATE TRIGGER IF NOT EXISTS canonical_artifact_manifest_digest_guard_update
            BEFORE UPDATE OF sha256, derivative_sha256, manifest_digest ON canonical_artifact_manifests
            WHEN NOT ({sha256} AND {derivative} AND {manifest})
            BEGIN SELECT RAISE(ABORT, 'artifact manifest digest must be sha256:<64 lowercase hex>'); END
            """.format(
                sha256=_sha256_guard("NEW.sha256"),
                derivative=_sha256_guard("NEW.derivative_sha256"),
                manifest=_sha256_guard("NEW.manifest_digest"),
            )
        )

    repaired_tables = {
        str(row[0])
        for row in connection.exec_driver_sql(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    guarded_task102_tables = tuple(
        table for table in _TASK102_METADATA_TABLES if table in repaired_tables
    )
    for statement in _metadata_integrity_guard_sql(guarded_task102_tables):
        connection.exec_driver_sql(statement)


def _task102_database_custody_root(connection: Connection) -> Path | None:
    """Resolve the server-owned custody sibling for a file-backed SQLite DB."""
    for _sequence, name, raw_path in connection.exec_driver_sql(
        "PRAGMA database_list"
    ).fetchall():
        if str(name) != "main" or not raw_path:
            continue
        database_path = Path(str(raw_path))
        if not database_path.is_absolute():
            return None
        return database_path.parent / "evidence-custody"
    return None


def _task102_migrate_legacy_evidence(connection: Connection) -> int:
    """Move available legacy evidence bytes into canonical local custody.

    The Task 101 normalization intentionally creates an unknown placeholder
    artifact because it has no byte store.  Once the Task 102 tables and
    guards exist, this successor preserves each verifiably available legacy
    payload as a protected original plus an ordinary redacted derivative,
    links it to the already-migrated observation, and clears mutable raw/path
    columns only in the same database transaction.  Missing or unsafe legacy
    paths remain represented by the existing unknown placeholder.
    """
    tables = {
        str(row[0])
        for row in connection.exec_driver_sql(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    required_tables = {
        "findings",
        "canonical_findings",
        "canonical_observations",
        "canonical_artifact_refs",
        "canonical_artifact_manifests",
        "canonical_observation_artifacts",
    }
    if not required_tables <= tables:
        if connection.in_transaction():
            connection.commit()
        return 0
    finding_columns = {
        str(row[1])
        for row in connection.exec_driver_sql(
            "PRAGMA table_info(findings)"
        ).fetchall()
    }
    raw_columns = tuple(
        column
        for column in (
            "request_raw",
            "response_raw",
            "screenshot_path",
            "console_capture_path",
            "pcap_path",
        )
        if column in finding_columns
    )
    if not raw_columns or "id" not in finding_columns:
        if connection.in_transaction():
            connection.commit()
        return 0
    selected_columns = tuple(
        column
        for column in (
            "id",
            "tenant_id",
            "target",
            "url",
            "module",
            "verification",
            *raw_columns,
        )
        if column in finding_columns
    )
    legacy_rows = connection.exec_driver_sql(
        "SELECT " + ",".join(selected_columns) + " FROM findings ORDER BY id"
    ).mappings().all()
    if connection.in_transaction():
        connection.commit()

    from common.db import _legacy_evidence_payloads, _strip_legacy_raw_evidence
    from common.evidence_custody import (
        ArtifactNotFound,
        EvidenceCustodyStore,
    )

    custody_root = _task102_database_custody_root(connection)
    if connection.in_transaction():
        connection.commit()
    stores: dict[str, Any] = {}
    migrated = 0
    evidence_field_names = frozenset(raw_columns)

    def store_for_tenant(tenant_id: str) -> Any | None:
        if custody_root is None:
            return None
        store = stores.get(tenant_id)
        if store is None:
            store = EvidenceCustodyStore(custody_root, tenant_id)
            stores[tenant_id] = store
        return store

    for legacy_row in legacy_rows:
        data = dict(legacy_row)
        direct_present = any(
            data.get(column) not in (None, "") for column in raw_columns
        )
        decoded_verification: Any = None
        verification_value = data.get("verification")
        if isinstance(verification_value, str) and verification_value:
            try:
                decoded_verification = json.loads(verification_value)
            except (TypeError, json.JSONDecodeError):
                decoded_verification = None

        payloads: list[tuple[str, bytes, str]] = [
            (field, payload, media_type)
            for field, payload, media_type in _legacy_evidence_payloads(data)
        ]
        nested_sensitive_found = False
        visited_nodes = 0

        def collect_nested(value: Any, path: tuple[str, ...] = ()) -> None:
            nonlocal nested_sensitive_found, visited_nodes
            visited_nodes += 1
            if visited_nodes > 1_000 or len(path) > 8:
                raise MigrationError(
                    "legacy verification evidence exceeds migration bounds"
                )
            if isinstance(value, Mapping):
                for raw_key, child in value.items():
                    key = str(raw_key).strip().lower()
                    child_path = (*path, key or "field")
                    if key in evidence_field_names:
                        nested_sensitive_found = True
                        origin = ".".join(child_path)
                        origin_token = hashlib.sha256(
                            origin.encode("utf-8")
                        ).hexdigest()[:12]
                        for _field, payload, media_type in _legacy_evidence_payloads(
                            {key: child}
                        ):
                            payloads.append(
                                (
                                    f"verification_{key}_{origin_token}",
                                    payload,
                                    media_type,
                                )
                            )
                    else:
                        collect_nested(child, child_path)
            elif isinstance(value, (list, tuple)):
                for index, child in enumerate(value):
                    collect_nested(child, (*path, str(index)))

        if isinstance(decoded_verification, (Mapping, list, tuple)):
            collect_nested(decoded_verification)
        if len(payloads) > 64:
            raise MigrationError(
                "legacy finding contains too many evidence payloads"
            )
        if not direct_present and not nested_sensitive_found:
            # A legacy finding with unavailable evidence still has a valid
            # canonical default-read projection.  Initialize its private,
            # server-owned tenant custody namespace during migration so the
            # dashboard read boundary never needs to create filesystem state.
            if custody_root is not None:
                unavailable_tenant_id = _canonical_legacy_key(
                    data.get("tenant_id") or "default",
                    kind="tenant",
                    tenant_id="forge-legacy",
                )
                store_for_tenant(unavailable_tenant_id)
            continue
        if payloads and custody_root is None:
            raise MigrationError(
                "available legacy evidence requires a file-backed custody root"
            )

        raw_tenant = data.get("tenant_id") or "default"
        tenant_id = _canonical_legacy_key(
            raw_tenant,
            kind="tenant",
            tenant_id="forge-legacy",
        )
        raw_finding = data.get("id")
        finding_id = _canonical_legacy_key(
            raw_finding or "legacy",
            kind="finding",
            tenant_id=tenant_id,
        )
        canonical_row = connection.exec_driver_sql(
            "SELECT f.observation_id,f.metadata_json,o.asset_id,a.display_name "
            "FROM canonical_findings f "
            "JOIN canonical_observations o ON o.tenant_id=f.tenant_id "
            "AND o.id=f.observation_id "
            "JOIN canonical_assets a ON a.tenant_id=o.tenant_id "
            "AND a.id=o.asset_id "
            "WHERE f.tenant_id=? AND f.id=?",
            (tenant_id, finding_id),
        ).mappings().one_or_none()
        if connection.in_transaction():
            connection.commit()
        if canonical_row is None:
            raise MigrationError(
                "legacy evidence has no canonical finding observation"
            )
        try:
            finding_metadata = json.loads(str(canonical_row["metadata_json"]))
        except (TypeError, json.JSONDecodeError) as exc:
            raise MigrationError(
                "legacy canonical finding metadata is invalid"
            ) from exc
        if not isinstance(finding_metadata, Mapping) or finding_metadata.get(
            "legacy"
        ) is not True:
            raise MigrationError(
                "legacy evidence target is not migration-owned"
            )

        observation_id = str(canonical_row["observation_id"])
        asset_id = str(canonical_row["asset_id"])
        source_target = _legacy_text(
            data.get("target")
            or data.get("url")
            or canonical_row["display_name"]
            or "legacy-target",
            default="legacy-target",
            limit=2_000,
        )
        store = store_for_tenant(tenant_id)
        if store is None:
            raise MigrationError(
                "available legacy evidence requires a file-backed custody root"
            )

        staged: list[tuple[str, Any]] = []
        rollback_candidates: list[tuple[Any, Any]] = []
        try:
            for capture_kind, payload, media_type in payloads:
                identity_seed = "\x00".join(
                    (tenant_id, finding_id, capture_kind)
                )
                identity_digest = hashlib.sha256(
                    identity_seed.encode("utf-8")
                ).hexdigest()
                artifact_id = f"artifact:{identity_digest[:48]}"
                authorization_ref = (
                    "authorization:legacy-migration:" + identity_digest[:48]
                )
                created_manifest = False
                try:
                    manifest = store.get_manifest(artifact_id)
                except ArtifactNotFound:
                    manifest = store.store_artifact(
                        payload,
                        source_observation_id=observation_id,
                        collector_id="collector:legacy-migration",
                        media_type=media_type,
                        source_target=source_target,
                        source_asset_id=asset_id,
                        retain_original=True,
                        protected_original_authorization_ref=authorization_ref,
                        retention_class="legacy",
                        metadata={
                            "capture_kind": capture_kind,
                            "legacy": True,
                            "migration": "task102",
                        },
                        artifact_id=artifact_id,
                    )
                    created_manifest = True
                else:
                    manifest = store.verify(artifact_id)
                    expected_digest = "sha256:" + hashlib.sha256(payload).hexdigest()
                    if (
                        manifest.sha256 != expected_digest
                        or manifest.byte_size != len(payload)
                        or manifest.tenant_id != tenant_id
                        or manifest.source_observation_id != observation_id
                        or manifest.source_asset_id != asset_id
                        or manifest.collector_id != "collector:legacy-migration"
                        or manifest.media_type != media_type
                        or manifest.protection_state != "protected_original"
                        or manifest.protected_original_authorization_ref
                        != authorization_ref
                        or manifest.metadata.get("capture_kind") != capture_kind
                        or manifest.metadata.get("legacy") is not True
                    ):
                        raise MigrationError(
                            "legacy custody artifact identity is mismatched"
                        )
                staged.append((capture_kind, manifest))
                if created_manifest:
                    rollback_candidates.append((store, manifest))

            if connection.in_transaction():
                connection.commit()
            with connection.begin():
                next_sequence = int(
                    connection.exec_driver_sql(
                        "SELECT COALESCE(MAX(sequence),-1)+1 "
                        "FROM canonical_observation_artifacts "
                        "WHERE tenant_id=? AND observation_id=?",
                        (tenant_id, observation_id),
                    ).scalar_one()
                )
                for capture_kind, manifest in staged:
                    artifact_metadata = json.dumps(
                        {
                            "capture_kind": capture_kind,
                            "legacy": True,
                            "migration": "task102",
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    _insert_or_validate_legacy(
                        connection,
                        "canonical_artifact_refs",
                        {
                            "id": manifest.artifact_id,
                            "tenant_id": tenant_id,
                            "observation_id": observation_id,
                            "schema_version": CANONICAL_SCHEMA_VERSION,
                            "reference": manifest.artifact_id,
                            "digest": manifest.sha256,
                            "media_type": manifest.media_type,
                            "size": manifest.byte_size,
                            "redaction_state": manifest.redaction_state,
                            "encryption_state": manifest.encryption_state,
                            "collected_at": manifest.collected_at,
                            "created_at": manifest.collected_at,
                            "metadata_json": artifact_metadata,
                            "collector_id": manifest.collector_id,
                            "collector_version": "forge-legacy-migration-v1",
                            "source_target": manifest.source_target or "unknown",
                            "source_asset_id": manifest.source_asset_id,
                            "redaction_version": manifest.redaction_version,
                            "protection_state": manifest.protection_state,
                            "signer_state": manifest.signer_state,
                            "integrity_state": manifest.integrity_state,
                            "retention_class": manifest.retention_class,
                            "retention_expires_at": manifest.retention_expires_at,
                            "protected_original_authorization_ref": (
                                manifest.protected_original_authorization_ref
                            ),
                            "derivative_reference": (
                                manifest.derivative_artifact_id
                            ),
                            "manifest_digest": manifest.manifest_digest,
                        },
                        identity_columns=("tenant_id", "id"),
                        label="legacy custody artifact",
                    )
                    manifest_metadata = manifest.metadata
                    _insert_or_validate_legacy(
                        connection,
                        "canonical_artifact_manifests",
                        {
                            "id": manifest.artifact_id,
                            "tenant_id": tenant_id,
                            "artifact_id": manifest.artifact_id,
                            "observation_id": observation_id,
                            "schema_version": manifest.schema_version,
                            "sha256": manifest.sha256,
                            "byte_size": manifest.byte_size,
                            "media_type": manifest.media_type,
                            "collected_at": manifest.collected_at,
                            "collector_id": manifest.collector_id,
                            "source_target": manifest.source_target,
                            "source_asset_id": manifest.source_asset_id,
                            "redaction_state": manifest.redaction_state,
                            "redaction_version": manifest.redaction_version,
                            "protection_state": manifest.protection_state,
                            "encryption_state": manifest.encryption_state,
                            "signer_state": manifest.signer_state,
                            "integrity_state": manifest.integrity_state,
                            "retention_class": manifest.retention_class,
                            "retention_expires_at": (
                                manifest.retention_expires_at
                            ),
                            "protected_original_authorization_ref": (
                                manifest.protected_original_authorization_ref
                            ),
                            "original_relative_path": (
                                manifest.original_relative_path
                            ),
                            "derivative_relative_path": (
                                manifest.derivative_relative_path
                            ),
                            "derivative_artifact_id": (
                                manifest.derivative_artifact_id
                            ),
                            "derivative_sha256": manifest.derivative_sha256,
                            "derivative_size": manifest.derivative_size,
                            "manifest_digest": manifest.manifest_digest,
                            "created_at": manifest.collected_at,
                            "metadata_json": json.dumps(
                                manifest_metadata,
                                sort_keys=True,
                                separators=(",", ":"),
                            ),
                        },
                        identity_columns=("tenant_id", "artifact_id"),
                        label="legacy custody manifest",
                    )
                    existing_link = connection.exec_driver_sql(
                        "SELECT sequence FROM canonical_observation_artifacts "
                        "WHERE tenant_id=? AND observation_id=? AND artifact_id=?",
                        (tenant_id, observation_id, manifest.artifact_id),
                    ).scalar_one_or_none()
                    sequence = (
                        int(existing_link)
                        if existing_link is not None
                        else next_sequence
                    )
                    if existing_link is None:
                        next_sequence += 1
                    _insert_or_validate_legacy(
                        connection,
                        "canonical_observation_artifacts",
                        {
                            "tenant_id": tenant_id,
                            "observation_id": observation_id,
                            "artifact_id": manifest.artifact_id,
                            "role": "legacy",
                            "sequence": sequence,
                            "created_at": manifest.collected_at,
                            "metadata_json": json.dumps(
                                {
                                    "legacy": True,
                                    "manifest_digest": manifest.manifest_digest,
                                },
                                sort_keys=True,
                                separators=(",", ":"),
                            ),
                        },
                        identity_columns=(
                            "tenant_id",
                            "observation_id",
                            "artifact_id",
                        ),
                        label="legacy observation artifact",
                    )

                assignments = [f"{column}=NULL" for column in raw_columns]
                parameters: list[Any] = []
                if "verification" in finding_columns:
                    sanitized_verification: Any = {}
                    if isinstance(decoded_verification, (Mapping, list, tuple)):
                        sanitized_verification = _strip_legacy_raw_evidence(
                            decoded_verification
                        )
                    assignments.append("verification=?")
                    parameters.append(
                        json.dumps(
                            sanitized_verification,
                            sort_keys=True,
                            separators=(",", ":"),
                            ensure_ascii=True,
                        )
                    )
                parameters.append(raw_finding)
                where = "id=?"
                if "tenant_id" in finding_columns:
                    where += " AND tenant_id=?"
                    parameters.append(data.get("tenant_id") or "default")
                result = connection.exec_driver_sql(
                    "UPDATE findings SET "
                    + ",".join(assignments)
                    + " WHERE "
                    + where,
                    tuple(parameters),
                )
                if result.rowcount != 1:
                    raise MigrationError(
                        "legacy evidence mutable-row clearing failed"
                    )
            migrated += 1
        except Exception as exc:
            if connection.in_transaction():
                connection.rollback()
            rollback_errors: list[Exception] = []
            for staged_store, manifest in reversed(rollback_candidates):
                try:
                    staged_store.rollback_artifact(
                        manifest.artifact_id,
                        expected_manifest_digest=manifest.manifest_digest,
                    )
                except Exception as rollback_exc:
                    rollback_errors.append(rollback_exc)
            if rollback_errors:
                raise MigrationError(
                    "legacy evidence migration rollback did not complete"
                ) from rollback_errors[0]
            raise
    return migrated


def _reconcile_task102_postmigration(connection: Connection) -> None:
    """Replay every idempotent Task 102 repair and custody successor."""
    with connection.begin():
        _audit_existing_canonical_rows(connection)
        # Complete additive v2 repair before SQLite reparses every trigger
        # during the finding-table CHECK rebuild.
        _task102_schema_repair(connection)
    _expand_task102_finding_status_constraint(connection)
    with connection.begin():
        _task102_schema_repair(connection)
        _audit_existing_canonical_rows(connection)
        for statement in _runtime_guard_sql():
            connection.exec_driver_sql(statement)
    _task102_migrate_legacy_evidence(connection)
    with connection.begin():
        _audit_existing_canonical_rows(connection)


def _table_sql() -> tuple[str, ...]:
    # Every owned child carries tenant_id and references (tenant_id, id) on
    # its parent.  This is intentionally raw SQL: SQLAlchemy's legacy models
    # predate composite ownership and must remain source-compatible.
    return (
        """
        CREATE TABLE IF NOT EXISTS canonical_tenants (
            id TEXT PRIMARY KEY,
            schema_version TEXT NOT NULL,
            name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 300),
            created_at TEXT NOT NULL,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            UNIQUE(id, id)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS canonical_clients (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            schema_version TEXT NOT NULL,
            name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 300),
            created_at TEXT NOT NULL,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            UNIQUE(tenant_id, id),
            FOREIGN KEY(tenant_id) REFERENCES canonical_tenants(id) ON DELETE RESTRICT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS canonical_projects (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            client_id TEXT NOT NULL,
            schema_version TEXT NOT NULL,
            name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 300),
            created_at TEXT NOT NULL,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            UNIQUE(tenant_id, id),
            UNIQUE(tenant_id, client_id, id),
            FOREIGN KEY(tenant_id, client_id) REFERENCES canonical_clients(tenant_id, id) ON DELETE RESTRICT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS canonical_engagements (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            project_id TEXT,
            schema_version TEXT NOT NULL,
            name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 300),
            status TEXT NOT NULL CHECK(status IN ('planned','active','closed','unknown')),
            created_at TEXT NOT NULL,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            UNIQUE(tenant_id, id),
            UNIQUE(tenant_id, project_id, id),
            FOREIGN KEY(tenant_id) REFERENCES canonical_tenants(id) ON DELETE RESTRICT,
            FOREIGN KEY(tenant_id, project_id) REFERENCES canonical_projects(tenant_id, id) ON DELETE RESTRICT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS canonical_operators (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            schema_version TEXT NOT NULL,
            display_name TEXT NOT NULL CHECK(length(display_name) BETWEEN 1 AND 200),
            external_ref TEXT,
            created_at TEXT NOT NULL,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            UNIQUE(tenant_id, id),
            FOREIGN KEY(tenant_id) REFERENCES canonical_tenants(id) ON DELETE RESTRICT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS canonical_roles (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            schema_version TEXT NOT NULL,
            name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 100),
            created_at TEXT NOT NULL,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            UNIQUE(tenant_id, id),
            UNIQUE(tenant_id, name),
            FOREIGN KEY(tenant_id) REFERENCES canonical_tenants(id) ON DELETE RESTRICT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS canonical_scope_decisions (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            engagement_id TEXT NOT NULL,
            operator_id TEXT NOT NULL,
            role_id TEXT,
            schema_version TEXT NOT NULL,
            outcome TEXT NOT NULL CHECK(outcome IN ('allow','deny','unknown')),
            policy_version TEXT NOT NULL,
            decision_reason TEXT NOT NULL DEFAULT '',
            decided_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            UNIQUE(tenant_id, id),
            FOREIGN KEY(tenant_id, engagement_id) REFERENCES canonical_engagements(tenant_id, id) ON DELETE RESTRICT,
            FOREIGN KEY(tenant_id, operator_id) REFERENCES canonical_operators(tenant_id, id) ON DELETE RESTRICT,
            FOREIGN KEY(tenant_id, role_id) REFERENCES canonical_roles(tenant_id, id) ON DELETE RESTRICT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS canonical_jobs (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            engagement_id TEXT NOT NULL,
            schema_version TEXT NOT NULL,
            job_kind TEXT NOT NULL CHECK(length(job_kind) BETWEEN 1 AND 100),
            status TEXT NOT NULL CHECK(status IN ('planned','pending_approval','queued','running','unknown_not_authorized','failed','partial','completed')),
            created_at TEXT NOT NULL,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            UNIQUE(tenant_id, id),
            UNIQUE(tenant_id, engagement_id, id),
            FOREIGN KEY(tenant_id, engagement_id) REFERENCES canonical_engagements(tenant_id, id) ON DELETE RESTRICT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS canonical_actions (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            engagement_id TEXT NOT NULL,
            job_id TEXT NOT NULL,
            schema_version TEXT NOT NULL,
            action_kind TEXT NOT NULL CHECK(length(action_kind) BETWEEN 1 AND 100),
            authorization_decision_id TEXT,
            created_at TEXT NOT NULL,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            UNIQUE(tenant_id, id),
            UNIQUE(tenant_id, engagement_id, job_id, id),
            FOREIGN KEY(tenant_id, engagement_id) REFERENCES canonical_engagements(tenant_id, id) ON DELETE RESTRICT,
            FOREIGN KEY(tenant_id, job_id) REFERENCES canonical_jobs(tenant_id, id) ON DELETE RESTRICT,
            FOREIGN KEY(tenant_id, engagement_id, job_id) REFERENCES canonical_jobs(tenant_id, engagement_id, id) ON DELETE RESTRICT,
            FOREIGN KEY(tenant_id, authorization_decision_id) REFERENCES canonical_scope_decisions(tenant_id, id) ON DELETE RESTRICT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS canonical_intelligence_sources (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            schema_version TEXT NOT NULL,
            name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 300),
            source_kind TEXT NOT NULL CHECK(length(source_kind) BETWEEN 1 AND 100),
            created_at TEXT NOT NULL,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            UNIQUE(tenant_id, id),
            FOREIGN KEY(tenant_id) REFERENCES canonical_tenants(id) ON DELETE RESTRICT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS canonical_provenance (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            source_type TEXT NOT NULL CHECK(source_type IN ('intelligence_source','feed_snapshot','check_pack_snapshot')),
            source_id TEXT NOT NULL,
            digest TEXT NOT NULL CHECK(digest GLOB 'sha256:*'),
            schema_version TEXT NOT NULL,
            created_at TEXT NOT NULL,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            UNIQUE(tenant_id, id),
            FOREIGN KEY(tenant_id) REFERENCES canonical_tenants(id) ON DELETE RESTRICT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS canonical_feed_snapshots (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            source_id TEXT NOT NULL,
            schema_version TEXT NOT NULL,
            version TEXT NOT NULL CHECK(length(version) BETWEEN 1 AND 100),
            digest TEXT NOT NULL CHECK(digest GLOB 'sha256:*'),
            created_at TEXT NOT NULL,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            UNIQUE(tenant_id, id),
            FOREIGN KEY(tenant_id, source_id) REFERENCES canonical_intelligence_sources(tenant_id, id) ON DELETE RESTRICT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS canonical_check_pack_snapshots (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            source_id TEXT NOT NULL,
            schema_version TEXT NOT NULL,
            version TEXT NOT NULL CHECK(length(version) BETWEEN 1 AND 100),
            digest TEXT NOT NULL CHECK(digest GLOB 'sha256:*'),
            created_at TEXT NOT NULL,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            UNIQUE(tenant_id, id),
            FOREIGN KEY(tenant_id, source_id) REFERENCES canonical_intelligence_sources(tenant_id, id) ON DELETE RESTRICT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS canonical_module_versions (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            schema_version TEXT NOT NULL,
            module_id TEXT NOT NULL CHECK(length(module_id) BETWEEN 1 AND 200),
            version TEXT NOT NULL CHECK(length(version) BETWEEN 1 AND 100),
            module_kind TEXT NOT NULL CHECK(length(module_kind) BETWEEN 1 AND 40),
            manifest_digest TEXT,
            policy_version TEXT,
            intelligence_snapshot_id TEXT,
            check_pack_snapshot_id TEXT,
            provenance_id TEXT,
            created_at TEXT NOT NULL,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            UNIQUE(tenant_id, id),
            UNIQUE(tenant_id, module_id, version),
            FOREIGN KEY(tenant_id) REFERENCES canonical_tenants(id) ON DELETE RESTRICT,
            FOREIGN KEY(tenant_id, intelligence_snapshot_id) REFERENCES canonical_feed_snapshots(tenant_id, id) ON DELETE RESTRICT,
            FOREIGN KEY(tenant_id, check_pack_snapshot_id) REFERENCES canonical_check_pack_snapshots(tenant_id, id) ON DELETE RESTRICT,
            FOREIGN KEY(tenant_id, provenance_id) REFERENCES canonical_provenance(tenant_id, id) ON DELETE RESTRICT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS canonical_module_executions (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            job_id TEXT NOT NULL,
            module_version_id TEXT NOT NULL,
            schema_version TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('planned','queued','running','completed','failed','partial','canceled')),
            intelligence_snapshot_id TEXT,
            check_pack_snapshot_id TEXT,
            provenance_id TEXT,
            created_at TEXT NOT NULL,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            UNIQUE(tenant_id, id),
            UNIQUE(tenant_id, job_id, module_version_id, id),
            FOREIGN KEY(tenant_id, job_id) REFERENCES canonical_jobs(tenant_id, id) ON DELETE RESTRICT,
            FOREIGN KEY(tenant_id, module_version_id) REFERENCES canonical_module_versions(tenant_id, id) ON DELETE RESTRICT,
            FOREIGN KEY(tenant_id, intelligence_snapshot_id) REFERENCES canonical_feed_snapshots(tenant_id, id) ON DELETE RESTRICT,
            FOREIGN KEY(tenant_id, check_pack_snapshot_id) REFERENCES canonical_check_pack_snapshots(tenant_id, id) ON DELETE RESTRICT,
            FOREIGN KEY(tenant_id, provenance_id) REFERENCES canonical_provenance(tenant_id, id) ON DELETE RESTRICT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS canonical_assets (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            schema_version TEXT NOT NULL,
            kind TEXT NOT NULL CHECK(kind IN ('host','url','service','application','account','domain_object','cloud_resource','model_endpoint','beacon')),
            identity_key TEXT NOT NULL CHECK(length(identity_key) BETWEEN 1 AND 1000),
            display_name TEXT NOT NULL CHECK(length(display_name) BETWEEN 1 AND 2000),
            canonical_uri TEXT,
            created_at TEXT NOT NULL,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            UNIQUE(tenant_id, id),
            UNIQUE(tenant_id, kind, identity_key),
            FOREIGN KEY(tenant_id) REFERENCES canonical_tenants(id) ON DELETE RESTRICT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS canonical_observations (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            engagement_id TEXT NOT NULL,
            job_id TEXT NOT NULL,
            module_version_id TEXT NOT NULL,
            module_execution_id TEXT,
            asset_id TEXT NOT NULL,
            action_id TEXT,
            intelligence_snapshot_id TEXT,
            provenance_id TEXT,
            schema_version TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('observed','no_finding','not_applicable','not_tested','partial','failed','canceled','not_authorized')),
            observed_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            UNIQUE(tenant_id, id),
            UNIQUE(tenant_id, id, module_version_id),
            FOREIGN KEY(tenant_id, engagement_id, job_id) REFERENCES canonical_jobs(tenant_id, engagement_id, id) ON DELETE RESTRICT,
            FOREIGN KEY(tenant_id, job_id, module_version_id, module_execution_id) REFERENCES canonical_module_executions(tenant_id, job_id, module_version_id, id) ON DELETE RESTRICT,
            FOREIGN KEY(tenant_id, engagement_id, job_id, action_id) REFERENCES canonical_actions(tenant_id, engagement_id, job_id, id) ON DELETE RESTRICT,
            FOREIGN KEY(tenant_id, engagement_id) REFERENCES canonical_engagements(tenant_id, id) ON DELETE RESTRICT,
            FOREIGN KEY(tenant_id, job_id) REFERENCES canonical_jobs(tenant_id, id) ON DELETE RESTRICT,
            FOREIGN KEY(tenant_id, module_version_id) REFERENCES canonical_module_versions(tenant_id, id) ON DELETE RESTRICT,
            FOREIGN KEY(tenant_id, module_execution_id) REFERENCES canonical_module_executions(tenant_id, id) ON DELETE RESTRICT,
            FOREIGN KEY(tenant_id, asset_id) REFERENCES canonical_assets(tenant_id, id) ON DELETE RESTRICT,
            FOREIGN KEY(tenant_id, action_id) REFERENCES canonical_actions(tenant_id, id) ON DELETE RESTRICT,
            FOREIGN KEY(tenant_id, intelligence_snapshot_id) REFERENCES canonical_feed_snapshots(tenant_id, id) ON DELETE RESTRICT,
            FOREIGN KEY(tenant_id, provenance_id) REFERENCES canonical_provenance(tenant_id, id) ON DELETE RESTRICT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS canonical_artifact_refs (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            observation_id TEXT NOT NULL,
            schema_version TEXT NOT NULL,
            reference TEXT NOT NULL CHECK(
                length(reference) BETWEEN 1 AND 2000 AND
                (reference GLOB 'artifact:*' OR reference GLOB 'credential:*' OR
                 reference GLOB 'cred:*' OR reference GLOB 'secret:*' OR
                 reference GLOB 'source:*' OR reference GLOB 'sha256:*')
            ),
            digest TEXT CHECK(digest IS NULL OR (length(digest)=71 AND digest GLOB 'sha256:*')),
            media_type TEXT NOT NULL CHECK(length(media_type) BETWEEN 1 AND 200),
            size INTEGER NOT NULL CHECK(size >= 0),
            redaction_state TEXT NOT NULL CHECK(redaction_state IN ('redacted','not_applicable','unknown')),
            encryption_state TEXT NOT NULL CHECK(length(encryption_state) BETWEEN 1 AND 40),
            collected_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            UNIQUE(tenant_id, id),
            UNIQUE(tenant_id, id, observation_id),
            FOREIGN KEY(tenant_id, observation_id) REFERENCES canonical_observations(tenant_id, id) ON DELETE RESTRICT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS canonical_findings (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            observation_id TEXT NOT NULL,
            artifact_id TEXT NOT NULL,
            schema_version TEXT NOT NULL,
            title TEXT NOT NULL CHECK(length(title) BETWEEN 1 AND 500),
            severity TEXT NOT NULL CHECK(severity IN ('critical','high','medium','low','informational')),
            description TEXT NOT NULL CHECK(length(description) BETWEEN 1 AND 8000),
            status TEXT NOT NULL CHECK(status IN ('open','verified','false_positive','remediated','unknown')),
            finding_key TEXT,
            created_at TEXT NOT NULL,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            UNIQUE(tenant_id, id),
            UNIQUE(tenant_id, id, observation_id),
            FOREIGN KEY(tenant_id, observation_id) REFERENCES canonical_observations(tenant_id, id) ON DELETE RESTRICT,
            FOREIGN KEY(tenant_id, artifact_id, observation_id) REFERENCES canonical_artifact_refs(tenant_id, id, observation_id) ON DELETE RESTRICT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS canonical_retests (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            finding_id TEXT NOT NULL,
            source_observation_id TEXT NOT NULL,
            job_id TEXT,
            schema_version TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('not_run','fixed','still_vulnerable','inconclusive','failed','not_authorized','unsupported')),
            created_at TEXT NOT NULL,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            UNIQUE(tenant_id, id),
            FOREIGN KEY(tenant_id, finding_id, source_observation_id) REFERENCES canonical_findings(tenant_id, id, observation_id) ON DELETE RESTRICT,
            FOREIGN KEY(tenant_id, source_observation_id) REFERENCES canonical_observations(tenant_id, id) ON DELETE RESTRICT,
            FOREIGN KEY(tenant_id, job_id) REFERENCES canonical_jobs(tenant_id, id) ON DELETE RESTRICT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS canonical_reports (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            schema_version TEXT NOT NULL,
            name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 300),
            version INTEGER NOT NULL CHECK(version >= 1),
            status TEXT NOT NULL CHECK(status IN ('draft','final','archived')),
            created_by TEXT,
            created_at TEXT NOT NULL,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            UNIQUE(tenant_id, id),
            FOREIGN KEY(tenant_id) REFERENCES canonical_tenants(id) ON DELETE RESTRICT,
            FOREIGN KEY(tenant_id, created_by) REFERENCES canonical_operators(tenant_id, id) ON DELETE RESTRICT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS canonical_report_memberships (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            report_id TEXT NOT NULL,
            finding_id TEXT NOT NULL,
            observation_id TEXT NOT NULL,
            schema_version TEXT NOT NULL,
            created_at TEXT NOT NULL,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            UNIQUE(tenant_id, id),
            UNIQUE(tenant_id, report_id, finding_id),
            FOREIGN KEY(tenant_id, report_id) REFERENCES canonical_reports(tenant_id, id) ON DELETE RESTRICT,
            FOREIGN KEY(tenant_id, finding_id, observation_id) REFERENCES canonical_findings(tenant_id, id, observation_id) ON DELETE RESTRICT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS canonical_exports (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            finding_id TEXT NOT NULL,
            source_observation_id TEXT NOT NULL,
            report_id TEXT,
            provenance_id TEXT,
            schema_version TEXT NOT NULL,
            format TEXT NOT NULL CHECK(length(format) BETWEEN 1 AND 60),
            status TEXT NOT NULL CHECK(status IN ('created','completed','partial','failed','canceled')),
            created_at TEXT NOT NULL,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            UNIQUE(tenant_id, id),
            FOREIGN KEY(tenant_id, finding_id, source_observation_id) REFERENCES canonical_findings(tenant_id, id, observation_id) ON DELETE RESTRICT,
            FOREIGN KEY(tenant_id, report_id) REFERENCES canonical_reports(tenant_id, id) ON DELETE RESTRICT,
            FOREIGN KEY(tenant_id, provenance_id) REFERENCES canonical_provenance(tenant_id, id) ON DELETE RESTRICT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS canonical_events (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            job_id TEXT NOT NULL,
            actor_id TEXT,
            schema_version TEXT NOT NULL,
            event_type TEXT NOT NULL CHECK(length(event_type) BETWEEN 1 AND 160),
            level TEXT NOT NULL CHECK(level IN ('debug','info','warning','error','critical')),
            created_at TEXT NOT NULL,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            UNIQUE(tenant_id, id),
            FOREIGN KEY(tenant_id, job_id) REFERENCES canonical_jobs(tenant_id, id) ON DELETE RESTRICT,
            FOREIGN KEY(tenant_id, actor_id) REFERENCES canonical_operators(tenant_id, id) ON DELETE RESTRICT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS canonical_logs (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            job_id TEXT NOT NULL,
            schema_version TEXT NOT NULL,
            message TEXT NOT NULL CHECK(length(message) BETWEEN 1 AND 8000),
            level TEXT NOT NULL CHECK(level IN ('debug','info','warning','error','critical')),
            created_at TEXT NOT NULL,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            UNIQUE(tenant_id, id),
            FOREIGN KEY(tenant_id, job_id) REFERENCES canonical_jobs(tenant_id, id) ON DELETE RESTRICT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS canonical_legacy_records (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            record_kind TEXT NOT NULL,
            legacy_id TEXT NOT NULL,
            claim_state TEXT NOT NULL CHECK(claim_state IN ('unknown','reduced','not_authorized')),
            schema_version TEXT NOT NULL,
            payload_json TEXT NOT NULL DEFAULT '{}',
            migrated_at TEXT NOT NULL,
            UNIQUE(tenant_id, record_kind, legacy_id),
            FOREIGN KEY(tenant_id) REFERENCES canonical_tenants(id) ON DELETE RESTRICT
        )
        """,
        "CREATE INDEX IF NOT EXISTS ix_canonical_observation_lineage ON canonical_observations(tenant_id, engagement_id, job_id, module_version_id, asset_id)",
        "CREATE INDEX IF NOT EXISTS ix_canonical_finding_lineage ON canonical_findings(tenant_id, observation_id, artifact_id)",
        "CREATE INDEX IF NOT EXISTS ix_canonical_asset_identity ON canonical_assets(tenant_id, kind, identity_key)",
        "CREATE INDEX IF NOT EXISTS ix_canonical_legacy_kind ON canonical_legacy_records(tenant_id, record_kind)",
        """
        CREATE TRIGGER IF NOT EXISTS canonical_action_lineage_guard_insert
        BEFORE INSERT ON canonical_actions
        BEGIN
          SELECT CASE WHEN NOT EXISTS(
            SELECT 1 FROM canonical_jobs
            WHERE tenant_id=NEW.tenant_id AND id=NEW.job_id
              AND engagement_id=NEW.engagement_id)
            THEN RAISE(ABORT, 'action engagement does not match job') END;
        END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS canonical_action_lineage_guard_update
        BEFORE UPDATE ON canonical_actions
        BEGIN
          SELECT CASE WHEN NOT EXISTS(
            SELECT 1 FROM canonical_jobs
            WHERE tenant_id=NEW.tenant_id AND id=NEW.job_id
              AND engagement_id=NEW.engagement_id)
            THEN RAISE(ABORT, 'action engagement does not match job') END;
        END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS canonical_action_authorization_guard_insert
        BEFORE INSERT ON canonical_actions
        WHEN NEW.authorization_decision_id IS NOT NULL AND NOT EXISTS(
          SELECT 1 FROM canonical_scope_decisions
          WHERE tenant_id=NEW.tenant_id AND id=NEW.authorization_decision_id
            AND engagement_id=NEW.engagement_id)
        BEGIN SELECT RAISE(ABORT, 'action authorization engagement mismatch'); END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS canonical_action_authorization_guard_update
        BEFORE UPDATE OF tenant_id, engagement_id, authorization_decision_id ON canonical_actions
        WHEN NEW.authorization_decision_id IS NOT NULL AND NOT EXISTS(
          SELECT 1 FROM canonical_scope_decisions
          WHERE tenant_id=NEW.tenant_id AND id=NEW.authorization_decision_id
            AND engagement_id=NEW.engagement_id)
        BEGIN SELECT RAISE(ABORT, 'action authorization engagement mismatch'); END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS canonical_observation_lineage_guard_insert
        BEFORE INSERT ON canonical_observations
        BEGIN
          SELECT CASE WHEN NOT EXISTS(
            SELECT 1 FROM canonical_jobs
            WHERE tenant_id=NEW.tenant_id AND id=NEW.job_id
              AND engagement_id=NEW.engagement_id)
            THEN RAISE(ABORT, 'observation engagement does not match job') END;
          SELECT CASE WHEN NEW.module_execution_id IS NOT NULL AND NOT EXISTS(
            SELECT 1 FROM canonical_module_executions
            WHERE tenant_id=NEW.tenant_id AND id=NEW.module_execution_id
              AND job_id=NEW.job_id AND module_version_id=NEW.module_version_id)
            THEN RAISE(ABORT, 'observation module execution lineage mismatch') END;
          SELECT CASE WHEN NEW.action_id IS NOT NULL AND NOT EXISTS(
            SELECT 1 FROM canonical_actions
            WHERE tenant_id=NEW.tenant_id AND id=NEW.action_id
              AND job_id=NEW.job_id AND engagement_id=NEW.engagement_id)
            THEN RAISE(ABORT, 'observation action lineage mismatch') END;
        END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS canonical_observation_lineage_guard_update
        BEFORE UPDATE ON canonical_observations
        BEGIN
          SELECT CASE WHEN NOT EXISTS(
            SELECT 1 FROM canonical_jobs
            WHERE tenant_id=NEW.tenant_id AND id=NEW.job_id
              AND engagement_id=NEW.engagement_id)
            THEN RAISE(ABORT, 'observation engagement does not match job') END;
          SELECT CASE WHEN NEW.module_execution_id IS NOT NULL AND NOT EXISTS(
            SELECT 1 FROM canonical_module_executions
            WHERE tenant_id=NEW.tenant_id AND id=NEW.module_execution_id
              AND job_id=NEW.job_id AND module_version_id=NEW.module_version_id)
            THEN RAISE(ABORT, 'observation module execution lineage mismatch') END;
          SELECT CASE WHEN NEW.action_id IS NOT NULL AND NOT EXISTS(
            SELECT 1 FROM canonical_actions
            WHERE tenant_id=NEW.tenant_id AND id=NEW.action_id
              AND job_id=NEW.job_id AND engagement_id=NEW.engagement_id)
            THEN RAISE(ABORT, 'observation action lineage mismatch') END;
        END
        """,
        # Polymorphic provenance is constrained by triggers rather than an
        # unchecked type/string relationship.
        """
        CREATE TRIGGER IF NOT EXISTS canonical_provenance_source_guard
        BEFORE INSERT ON canonical_provenance
        BEGIN
          SELECT CASE
            WHEN NEW.source_type='intelligence_source' AND NOT EXISTS(
              SELECT 1 FROM canonical_intelligence_sources WHERE tenant_id=NEW.tenant_id AND id=NEW.source_id)
            THEN RAISE(ABORT, 'canonical provenance source is missing')
            WHEN NEW.source_type='feed_snapshot' AND NOT EXISTS(
              SELECT 1 FROM canonical_feed_snapshots
              WHERE tenant_id=NEW.tenant_id AND id=NEW.source_id
                AND digest=NEW.digest)
            THEN RAISE(ABORT, 'canonical provenance feed is missing or mismatched')
            WHEN NEW.source_type='check_pack_snapshot' AND NOT EXISTS(
              SELECT 1 FROM canonical_check_pack_snapshots
              WHERE tenant_id=NEW.tenant_id AND id=NEW.source_id
                AND digest=NEW.digest)
            THEN RAISE(ABORT, 'canonical provenance check pack is missing or mismatched')
          END;
        END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS canonical_provenance_source_update_guard
        BEFORE UPDATE OF tenant_id, source_type, source_id ON canonical_provenance
        WHEN NEW.tenant_id <> OLD.tenant_id
          OR NEW.source_type <> OLD.source_type
          OR NEW.source_id <> OLD.source_id
        BEGIN
          SELECT RAISE(ABORT, 'canonical provenance source is immutable');
        END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS canonical_retest_source_guard
        BEFORE INSERT ON canonical_retests
        WHEN NOT EXISTS(
          SELECT 1 FROM canonical_findings f
          WHERE f.tenant_id=NEW.tenant_id AND f.id=NEW.finding_id
            AND f.observation_id=NEW.source_observation_id)
        BEGIN SELECT RAISE(ABORT, 'retest source observation does not match finding'); END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS canonical_retest_source_update_guard
        BEFORE UPDATE OF tenant_id, finding_id, source_observation_id ON canonical_retests
        WHEN NOT EXISTS(
          SELECT 1 FROM canonical_findings f
          WHERE f.tenant_id=NEW.tenant_id AND f.id=NEW.finding_id
            AND f.observation_id=NEW.source_observation_id)
        BEGIN SELECT RAISE(ABORT, 'retest source observation does not match finding'); END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS canonical_export_source_guard
        BEFORE INSERT ON canonical_exports
        WHEN NOT EXISTS(
          SELECT 1 FROM canonical_findings f
          WHERE f.tenant_id=NEW.tenant_id AND f.id=NEW.finding_id
            AND f.observation_id=NEW.source_observation_id)
        BEGIN SELECT RAISE(ABORT, 'export source observation does not match finding'); END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS canonical_export_source_update_guard
        BEFORE UPDATE OF tenant_id, finding_id, source_observation_id ON canonical_exports
        WHEN NOT EXISTS(
          SELECT 1 FROM canonical_findings f
          WHERE f.tenant_id=NEW.tenant_id AND f.id=NEW.finding_id
            AND f.observation_id=NEW.source_observation_id)
        BEGIN SELECT RAISE(ABORT, 'export source observation does not match finding'); END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS canonical_module_execution_snapshot_guard_insert
        BEFORE INSERT ON canonical_module_executions
        WHEN NOT EXISTS(
          SELECT 1 FROM canonical_module_versions mv
          WHERE mv.tenant_id=NEW.tenant_id AND mv.id=NEW.module_version_id
            AND COALESCE(NEW.intelligence_snapshot_id, '') = COALESCE(mv.intelligence_snapshot_id, '')
            AND COALESCE(NEW.check_pack_snapshot_id, '') = COALESCE(mv.check_pack_snapshot_id, '')
            AND COALESCE(NEW.provenance_id, '') = COALESCE(mv.provenance_id, '')
        )
        BEGIN SELECT RAISE(ABORT, 'module execution snapshot lineage mismatch'); END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS canonical_module_execution_snapshot_guard_update
        BEFORE UPDATE OF tenant_id, module_version_id, intelligence_snapshot_id, check_pack_snapshot_id, provenance_id ON canonical_module_executions
        WHEN NOT EXISTS(
          SELECT 1 FROM canonical_module_versions mv
          WHERE mv.tenant_id=NEW.tenant_id AND mv.id=NEW.module_version_id
            AND COALESCE(NEW.intelligence_snapshot_id, '') = COALESCE(mv.intelligence_snapshot_id, '')
            AND COALESCE(NEW.check_pack_snapshot_id, '') = COALESCE(mv.check_pack_snapshot_id, '')
            AND COALESCE(NEW.provenance_id, '') = COALESCE(mv.provenance_id, '')
        )
        BEGIN SELECT RAISE(ABORT, 'module execution snapshot lineage mismatch'); END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS canonical_observation_snapshot_guard_insert
        BEFORE INSERT ON canonical_observations
        WHEN (NEW.intelligence_snapshot_id IS NOT NULL OR NEW.provenance_id IS NOT NULL)
          AND NOT EXISTS(
          SELECT 1 FROM canonical_module_versions mv
          WHERE mv.tenant_id=NEW.tenant_id AND mv.id=NEW.module_version_id
            AND COALESCE(NEW.intelligence_snapshot_id, '') = COALESCE(mv.intelligence_snapshot_id, '')
            AND COALESCE(NEW.provenance_id, '') = COALESCE(mv.provenance_id, '')
        )
        BEGIN SELECT RAISE(ABORT, 'observation snapshot lineage mismatch'); END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS canonical_observation_snapshot_guard_update
        BEFORE UPDATE OF tenant_id, module_version_id, intelligence_snapshot_id, provenance_id ON canonical_observations
        WHEN (NEW.intelligence_snapshot_id IS NOT NULL OR NEW.provenance_id IS NOT NULL)
          AND NOT EXISTS(
          SELECT 1 FROM canonical_module_versions mv
          WHERE mv.tenant_id=NEW.tenant_id AND mv.id=NEW.module_version_id
            AND COALESCE(NEW.intelligence_snapshot_id, '') = COALESCE(mv.intelligence_snapshot_id, '')
            AND COALESCE(NEW.provenance_id, '') = COALESCE(mv.provenance_id, '')
        )
        BEGIN SELECT RAISE(ABORT, 'observation snapshot lineage mismatch'); END
        """,
    ) + _runtime_guard_sql() + tuple(
        f"""
        CREATE TRIGGER IF NOT EXISTS canonical_schema_version_guard_{table}
        BEFORE INSERT ON {table}
        WHEN NEW.schema_version <> '{CANONICAL_SCHEMA_VERSION}'
        BEGIN SELECT RAISE(ABORT, 'unsupported canonical schema version'); END
        """
        for table in _CANONICAL_TABLES
    ) + tuple(
        f"""
        CREATE TRIGGER IF NOT EXISTS canonical_metadata_bound_guard_{table}
        BEFORE INSERT ON {table}
        WHEN length(CAST(NEW.metadata_json AS BLOB)) > 16384
        BEGIN SELECT RAISE(ABORT, 'canonical metadata exceeds bound'); END
        """
        for table in _CANONICAL_TABLES
        if table != "canonical_legacy_records"
    ) + tuple(
        f"""
        CREATE TRIGGER IF NOT EXISTS canonical_metadata_bound_update_guard_{table}
        BEFORE UPDATE OF metadata_json ON {table}
        WHEN length(CAST(NEW.metadata_json AS BLOB)) > 16384
        BEGIN SELECT RAISE(ABORT, 'canonical metadata exceeds bound'); END
        """
        for table in _CANONICAL_TABLES
        if table != "canonical_legacy_records"
    ) + (
        """
        CREATE TRIGGER IF NOT EXISTS canonical_legacy_payload_bound_guard_insert
        BEFORE INSERT ON canonical_legacy_records
        WHEN length(CAST(NEW.payload_json AS BLOB)) > 16384
        BEGIN SELECT RAISE(ABORT, 'legacy archive payload exceeds bound'); END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS canonical_legacy_payload_bound_guard_update
        BEFORE UPDATE OF payload_json ON canonical_legacy_records
        WHEN length(CAST(NEW.payload_json AS BLOB)) > 16384
        BEGIN SELECT RAISE(ABORT, 'legacy archive payload exceeds bound'); END
        """,
    ) + tuple(
        f"""
        CREATE TRIGGER IF NOT EXISTS canonical_schema_version_update_guard_{table}
        BEFORE UPDATE OF schema_version ON {table}
        WHEN NEW.schema_version <> OLD.schema_version
          OR NEW.schema_version <> '{CANONICAL_SCHEMA_VERSION}'
        BEGIN SELECT RAISE(ABORT, 'canonical schema version is immutable'); END
        """
        for table in _CANONICAL_TABLES
    )


def _drop_sql() -> tuple[str, ...]:
    # Reverse dependency order.  No evidence is cascaded by normal product
    # operations; this explicit downgrade is an administrative migration API.
    return tuple(
        f"DROP TABLE IF EXISTS {table}"
        for table in (
            "canonical_logs", "canonical_events", "canonical_exports",
            "canonical_report_memberships", "canonical_reports", "canonical_retests",
            "canonical_findings", "canonical_artifact_refs", "canonical_observations",
            "canonical_assets", "canonical_module_executions", "canonical_module_versions",
            "canonical_check_pack_snapshots", "canonical_feed_snapshots", "canonical_provenance",
            "canonical_intelligence_sources", "canonical_actions", "canonical_jobs",
            "canonical_scope_decisions", "canonical_roles", "canonical_operators",
            "canonical_engagements", "canonical_projects", "canonical_clients",
            "canonical_legacy_records", "canonical_tenants",
        )
    )


def _evidence_table_sql() -> tuple[str, ...]:
    """Create the append-only custody and source-link tables.

    Artifact bytes never enter these tables.  They hold only integrity-bound
    manifests and normalized ownership links; the local custody store owns the
    protected original and redacted derivative files.
    """
    return (
        """
        ALTER TABLE canonical_findings ADD COLUMN dedup_key TEXT
        """,
        """
        CREATE TABLE IF NOT EXISTS canonical_evidence_access_audit (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            artifact_id TEXT NOT NULL,
            observation_id TEXT NOT NULL,
            access_kind TEXT NOT NULL CHECK(access_kind IN ('redacted_derivative','protected_original')),
            authorization_ref TEXT,
            accessed_at TEXT NOT NULL,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            FOREIGN KEY(tenant_id, artifact_id, observation_id) REFERENCES canonical_artifact_refs(tenant_id, id, observation_id) ON DELETE RESTRICT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS canonical_artifact_manifests (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            artifact_id TEXT NOT NULL,
            observation_id TEXT NOT NULL,
            schema_version TEXT NOT NULL CHECK(schema_version='forge-evidence-v1'),
            sha256 TEXT NOT NULL CHECK(length(sha256)=71 AND substr(sha256,1,7)='sha256:'),
            byte_size INTEGER NOT NULL CHECK(byte_size >= 0),
            media_type TEXT NOT NULL CHECK(length(media_type) BETWEEN 1 AND 200),
            collected_at TEXT NOT NULL,
            collector_id TEXT NOT NULL CHECK(length(collector_id) BETWEEN 1 AND 200),
            source_target TEXT,
            source_asset_id TEXT,
            redaction_state TEXT NOT NULL CHECK(redaction_state IN ('redacted','not_applicable','unknown')),
            redaction_version TEXT NOT NULL,
            protection_state TEXT NOT NULL CHECK(protection_state IN ('protected_original','not_retained','legacy_unknown')),
            encryption_state TEXT NOT NULL,
            signer_state TEXT NOT NULL,
            integrity_state TEXT NOT NULL CHECK(integrity_state IN ('verified','unknown','failed')),
            retention_class TEXT NOT NULL,
            retention_expires_at TEXT,
            protected_original_authorization_ref TEXT,
            original_relative_path TEXT,
            derivative_relative_path TEXT NOT NULL,
            derivative_artifact_id TEXT NOT NULL,
            derivative_sha256 TEXT NOT NULL CHECK(length(derivative_sha256)=71 AND substr(derivative_sha256,1,7)='sha256:'),
            derivative_size INTEGER NOT NULL CHECK(derivative_size >= 0),
            manifest_digest TEXT NOT NULL CHECK(length(manifest_digest)=71 AND substr(manifest_digest,1,7)='sha256:'),
            created_at TEXT NOT NULL,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            UNIQUE(tenant_id, artifact_id),
            UNIQUE(tenant_id, id),
            FOREIGN KEY(tenant_id, artifact_id) REFERENCES canonical_artifact_refs(tenant_id, id) ON DELETE RESTRICT,
            FOREIGN KEY(tenant_id, observation_id) REFERENCES canonical_observations(tenant_id, id) ON DELETE RESTRICT,
            FOREIGN KEY(tenant_id, source_asset_id) REFERENCES canonical_assets(tenant_id, id) ON DELETE RESTRICT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS canonical_observation_artifacts (
            tenant_id TEXT NOT NULL,
            observation_id TEXT NOT NULL,
            artifact_id TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('primary','supporting','derivative','legacy')),
            sequence INTEGER NOT NULL DEFAULT 0 CHECK(sequence >= 0),
            created_at TEXT NOT NULL,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            PRIMARY KEY(tenant_id, observation_id, artifact_id),
            FOREIGN KEY(tenant_id, observation_id) REFERENCES canonical_observations(tenant_id, id) ON DELETE RESTRICT,
            FOREIGN KEY(tenant_id, artifact_id, observation_id) REFERENCES canonical_artifact_refs(tenant_id, id, observation_id) ON DELETE RESTRICT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS canonical_finding_observations (
            tenant_id TEXT NOT NULL,
            finding_id TEXT NOT NULL,
            observation_id TEXT NOT NULL,
            artifact_id TEXT,
            identity_key TEXT NOT NULL,
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            PRIMARY KEY(tenant_id, finding_id, observation_id),
            FOREIGN KEY(tenant_id, finding_id) REFERENCES canonical_findings(tenant_id, id) ON DELETE RESTRICT,
            FOREIGN KEY(tenant_id, observation_id) REFERENCES canonical_observations(tenant_id, id) ON DELETE RESTRICT,
            FOREIGN KEY(tenant_id, artifact_id, observation_id) REFERENCES canonical_artifact_refs(tenant_id, id, observation_id) ON DELETE RESTRICT
        )
        """,
        "CREATE UNIQUE INDEX IF NOT EXISTS ux_canonical_finding_dedup ON canonical_findings(tenant_id, dedup_key) WHERE dedup_key IS NOT NULL",
        # Keep the migration replay-safe for databases that already contain
        # the early six-column source-link table.  The repair phase adds the
        # first/last-seen dimensions and its richer index after the DDL step.
        "CREATE INDEX IF NOT EXISTS ix_canonical_finding_observation_source ON canonical_finding_observations(tenant_id, finding_id, observation_id)",
        "CREATE INDEX IF NOT EXISTS ix_canonical_observation_artifact_source ON canonical_observation_artifacts(tenant_id, observation_id, sequence)",
        "CREATE INDEX IF NOT EXISTS ix_canonical_artifact_manifest_observation ON canonical_artifact_manifests(tenant_id, observation_id)",
        """
        CREATE TRIGGER IF NOT EXISTS canonical_artifact_manifest_digest_guard_insert
        BEFORE INSERT ON canonical_artifact_manifests
        WHEN NOT ({sha256} AND {derivative} AND {manifest})
        BEGIN SELECT RAISE(ABORT, 'artifact manifest digest must be sha256:<64 lowercase hex>'); END
        """.format(
            sha256=_sha256_guard("NEW.sha256"),
            derivative=_sha256_guard("NEW.derivative_sha256"),
            manifest=_sha256_guard("NEW.manifest_digest"),
        ),
        """
        CREATE TRIGGER IF NOT EXISTS canonical_artifact_manifest_digest_guard_update
        BEFORE UPDATE OF sha256, derivative_sha256, manifest_digest ON canonical_artifact_manifests
        WHEN NOT ({sha256} AND {derivative} AND {manifest})
        BEGIN SELECT RAISE(ABORT, 'artifact manifest digest must be sha256:<64 lowercase hex>'); END
        """.format(
            sha256=_sha256_guard("NEW.sha256"),
            derivative=_sha256_guard("NEW.derivative_sha256"),
            manifest=_sha256_guard("NEW.manifest_digest"),
        ),
        # Observation and artifact identity is append-only.  Findings remain
        # mutable workflow summaries, but identity and source lineage cannot
        # be rewritten or deleted underneath a report/retest.
        """
        CREATE TRIGGER IF NOT EXISTS canonical_observations_append_only_update
        BEFORE UPDATE ON canonical_observations
        BEGIN SELECT RAISE(ABORT, 'canonical observations are immutable'); END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS canonical_observations_append_only_delete
        BEFORE DELETE ON canonical_observations
        BEGIN SELECT RAISE(ABORT, 'canonical observations cannot be deleted'); END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS canonical_artifact_refs_append_only_update
        BEFORE UPDATE ON canonical_artifact_refs
        WHEN NEW.id IS NOT OLD.id OR NEW.tenant_id IS NOT OLD.tenant_id
          OR NEW.observation_id IS NOT OLD.observation_id
          OR NEW.schema_version IS NOT OLD.schema_version
          OR NEW.reference IS NOT OLD.reference OR NEW.digest IS NOT OLD.digest
          OR NEW.media_type IS NOT OLD.media_type OR NEW.size IS NOT OLD.size
          OR NEW.redaction_state IS NOT OLD.redaction_state
          OR NEW.encryption_state IS NOT OLD.encryption_state
          OR NEW.collected_at IS NOT OLD.collected_at OR NEW.created_at IS NOT OLD.created_at
          OR NEW.collector_id IS NOT OLD.collector_id
          OR NEW.collector_version IS NOT OLD.collector_version
          OR NEW.source_target IS NOT OLD.source_target
          OR NEW.source_asset_id IS NOT OLD.source_asset_id
          OR NEW.redaction_version IS NOT OLD.redaction_version
          OR NEW.protection_state IS NOT OLD.protection_state
          OR NEW.signer_state IS NOT OLD.signer_state
          OR NEW.integrity_state IS NOT OLD.integrity_state
          OR NEW.retention_class IS NOT OLD.retention_class
          OR NEW.retention_expires_at IS NOT OLD.retention_expires_at
          OR NEW.protected_original_authorization_ref IS NOT OLD.protected_original_authorization_ref
          OR NEW.derivative_reference IS NOT OLD.derivative_reference
          OR NEW.metadata_json IS NOT OLD.metadata_json
          OR NOT (OLD.manifest_digest IS NULL AND NEW.manifest_digest IS NOT NULL
            AND ({manifest_digest_guard}))
        BEGIN SELECT RAISE(ABORT, 'canonical artifact references are immutable'); END
        """.format(
            manifest_digest_guard=_sha256_guard("NEW.manifest_digest")
        ),
        """
        CREATE TRIGGER IF NOT EXISTS canonical_artifact_refs_append_only_delete
        BEFORE DELETE ON canonical_artifact_refs
        BEGIN SELECT RAISE(ABORT, 'canonical artifact references cannot be deleted'); END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS canonical_artifact_manifests_append_only_update
        BEFORE UPDATE ON canonical_artifact_manifests
        BEGIN SELECT RAISE(ABORT, 'artifact manifests are immutable'); END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS canonical_artifact_manifests_append_only_delete
        BEFORE DELETE ON canonical_artifact_manifests
        BEGIN SELECT RAISE(ABORT, 'artifact manifests cannot be deleted'); END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS canonical_observation_artifacts_append_only_update
        BEFORE UPDATE ON canonical_observation_artifacts
        BEGIN SELECT RAISE(ABORT, 'observation artifact links are immutable'); END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS canonical_observation_artifacts_append_only_delete
        BEFORE DELETE ON canonical_observation_artifacts
        BEGIN SELECT RAISE(ABORT, 'observation artifact links cannot be deleted'); END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS canonical_finding_observations_append_only_update
        BEFORE UPDATE ON canonical_finding_observations
        BEGIN SELECT RAISE(ABORT, 'finding observation links are immutable'); END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS canonical_finding_observations_append_only_delete
        BEFORE DELETE ON canonical_finding_observations
        BEGIN SELECT RAISE(ABORT, 'finding observation links cannot be deleted'); END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS canonical_evidence_access_audit_append_only_update
        BEFORE UPDATE ON canonical_evidence_access_audit
        BEGIN SELECT RAISE(ABORT, 'evidence access audit is append-only'); END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS canonical_evidence_access_audit_append_only_delete
        BEFORE DELETE ON canonical_evidence_access_audit
        BEGIN SELECT RAISE(ABORT, 'evidence access audit cannot be deleted'); END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS canonical_findings_identity_guard_update
        BEFORE UPDATE ON canonical_findings
        WHEN NEW.id IS NOT OLD.id OR NEW.tenant_id IS NOT OLD.tenant_id
          OR NEW.observation_id IS NOT OLD.observation_id OR NEW.artifact_id IS NOT OLD.artifact_id
          OR NEW.schema_version IS NOT OLD.schema_version OR NEW.finding_key IS NOT OLD.finding_key
          OR NEW.dedup_key IS NOT OLD.dedup_key OR NEW.created_at IS NOT OLD.created_at
        BEGIN SELECT RAISE(ABORT, 'canonical finding identity is immutable'); END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS canonical_findings_lineage_guard_delete
        BEFORE DELETE ON canonical_findings
        BEGIN SELECT RAISE(ABORT, 'canonical findings cannot be deleted; close workflow state instead'); END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS canonical_artifact_manifest_tenant_guard
        BEFORE INSERT ON canonical_artifact_manifests
        WHEN NOT EXISTS(
          SELECT 1 FROM canonical_artifact_refs a
          WHERE a.tenant_id=NEW.tenant_id AND a.id=NEW.artifact_id
            AND a.observation_id=NEW.observation_id)
        BEGIN SELECT RAISE(ABORT, 'artifact manifest lineage mismatch'); END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS canonical_observation_artifact_tenant_guard
        BEFORE INSERT ON canonical_observation_artifacts
        WHEN NOT EXISTS(
          SELECT 1 FROM canonical_artifact_refs a
          WHERE a.tenant_id=NEW.tenant_id AND a.id=NEW.artifact_id
            AND a.observation_id=NEW.observation_id)
        BEGIN SELECT RAISE(ABORT, 'observation artifact lineage mismatch'); END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS canonical_finding_observation_tenant_guard
        BEFORE INSERT ON canonical_finding_observations
        WHEN NOT EXISTS(
          SELECT 1 FROM canonical_findings f
          WHERE f.tenant_id=NEW.tenant_id AND f.id=NEW.finding_id)
          OR NOT EXISTS(
          SELECT 1 FROM canonical_observations o
          WHERE o.tenant_id=NEW.tenant_id AND o.id=NEW.observation_id)
          OR (NEW.artifact_id IS NOT NULL AND NOT EXISTS(
          SELECT 1 FROM canonical_artifact_refs a
          WHERE a.tenant_id=NEW.tenant_id AND a.id=NEW.artifact_id
            AND a.observation_id=NEW.observation_id))
        BEGIN SELECT RAISE(ABORT, 'finding observation tenant lineage mismatch'); END
        """,
    )


def _evidence_drop_sql() -> tuple[str, ...]:
    return (
        "DROP TRIGGER IF EXISTS canonical_finding_observation_tenant_guard",
        "DROP TRIGGER IF EXISTS canonical_observation_artifact_tenant_guard",
        "DROP TRIGGER IF EXISTS canonical_artifact_manifest_tenant_guard",
        "DROP TRIGGER IF EXISTS canonical_artifact_manifest_digest_guard_update",
        "DROP TRIGGER IF EXISTS canonical_artifact_manifest_digest_guard_insert",
        "DROP TRIGGER IF EXISTS canonical_findings_lineage_guard_delete",
        "DROP TRIGGER IF EXISTS canonical_findings_identity_guard_update",
        "DROP TRIGGER IF EXISTS canonical_finding_observations_append_only_delete",
        "DROP TRIGGER IF EXISTS canonical_finding_observations_append_only_update",
        "DROP TRIGGER IF EXISTS canonical_evidence_access_audit_append_only_delete",
        "DROP TRIGGER IF EXISTS canonical_evidence_access_audit_append_only_update",
        "DROP TRIGGER IF EXISTS canonical_observation_artifacts_append_only_delete",
        "DROP TRIGGER IF EXISTS canonical_observation_artifacts_append_only_update",
        "DROP TRIGGER IF EXISTS canonical_artifact_manifests_append_only_delete",
        "DROP TRIGGER IF EXISTS canonical_artifact_manifests_append_only_update",
        "DROP TRIGGER IF EXISTS canonical_artifact_refs_append_only_delete",
        "DROP TRIGGER IF EXISTS canonical_artifact_refs_append_only_update",
        "DROP TRIGGER IF EXISTS canonical_artifact_refs_custody_immutable_update",
        "DROP TRIGGER IF EXISTS canonical_artifact_refs_custody_no_delete",
        "DROP TRIGGER IF EXISTS canonical_artifact_source_asset_guard_insert",
        "DROP TRIGGER IF EXISTS canonical_artifact_source_asset_guard_update",
        "DROP TRIGGER IF EXISTS canonical_observations_append_only_delete",
        "DROP TRIGGER IF EXISTS canonical_observations_append_only_update",
        "DROP INDEX IF EXISTS ix_canonical_artifact_manifest_observation",
        "DROP INDEX IF EXISTS ix_canonical_observation_artifact_source",
        "DROP INDEX IF EXISTS ix_canonical_finding_observation_source",
        "DROP INDEX IF EXISTS ux_canonical_finding_dedup",
        "DROP INDEX IF EXISTS ix_canonical_evidence_audit",
        "DROP TABLE IF EXISTS canonical_evidence_access_audit",
        "DROP TABLE IF EXISTS canonical_finding_observations",
        "DROP TABLE IF EXISTS canonical_observation_artifacts",
        "DROP TABLE IF EXISTS canonical_artifact_manifests",
        # SQLite cannot DROP COLUMN on all supported versions.  The dedup
        # column is harmless on downgrade and remains nullable/unused; this
        # keeps the reverse migration safe for existing v1 databases.
    )


def _job_state_table_sql() -> tuple[str, ...]:
    """Create the Task 103 single-node lifecycle and agent authority.

    The tables extend the accepted canonical job identity instead of creating a
    second job namespace.  JSON columns are bounded input/projection metadata;
    every relationship and authority field has its own typed column.
    """

    return (
        """
        CREATE TABLE IF NOT EXISTS durable_job_state_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS durable_job_state_agents (
            tenant_id TEXT NOT NULL,
            id TEXT NOT NULL,
            key_id TEXT NOT NULL,
            credential_digest TEXT NOT NULL,
            enrollment_hint_digest TEXT,
            mtls_subject_digest TEXT,
            display_name TEXT NOT NULL DEFAULT '',
            host_label TEXT NOT NULL DEFAULT '',
            platform_label TEXT NOT NULL DEFAULT '',
            version_label TEXT NOT NULL DEFAULT '',
            active_scan_enabled INTEGER NOT NULL DEFAULT 0
                CHECK(active_scan_enabled IN (0,1)),
            state TEXT NOT NULL DEFAULT 'idle'
                CHECK(state IN ('idle','online','running','paused','offline','revoked')),
            version INTEGER NOT NULL DEFAULT 0 CHECK(version >= 0),
            issued_at REAL NOT NULL,
            last_seen_at REAL NOT NULL,
            revoked_at REAL,
            PRIMARY KEY(tenant_id,id),
            UNIQUE(tenant_id,key_id),
            UNIQUE(tenant_id,credential_digest),
            FOREIGN KEY(tenant_id) REFERENCES canonical_tenants(id) ON DELETE RESTRICT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS durable_job_state_agent_engines (
            tenant_id TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            engine TEXT NOT NULL,
            PRIMARY KEY(tenant_id,agent_id,engine),
            FOREIGN KEY(tenant_id,agent_id)
                REFERENCES durable_job_state_agents(tenant_id,id) ON DELETE RESTRICT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS durable_job_state_agent_capabilities (
            tenant_id TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            capability TEXT NOT NULL,
            PRIMARY KEY(tenant_id,agent_id,capability),
            FOREIGN KEY(tenant_id,agent_id)
                REFERENCES durable_job_state_agents(tenant_id,id) ON DELETE RESTRICT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS durable_job_state_agent_scope (
            tenant_id TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            sequence INTEGER NOT NULL CHECK(sequence >= 0),
            scope_kind TEXT NOT NULL CHECK(scope_kind IN ('allow','exclude')),
            scope_entry TEXT NOT NULL,
            PRIMARY KEY(tenant_id,agent_id,scope_kind,sequence),
            UNIQUE(tenant_id,agent_id,scope_kind,scope_entry),
            FOREIGN KEY(tenant_id,agent_id)
                REFERENCES durable_job_state_agents(tenant_id,id) ON DELETE RESTRICT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS durable_job_state_jobs (
            tenant_id TEXT NOT NULL,
            id TEXT NOT NULL,
            engagement_id TEXT NOT NULL,
            run_id TEXT NOT NULL,
            job_kind TEXT NOT NULL,
            target TEXT NOT NULL DEFAULT '',
            authorization_decision_id TEXT,
            authorization_action_id TEXT,
            assigned_agent_id TEXT,
            idempotency_key TEXT,
            request_identity TEXT NOT NULL,
            parent_id TEXT,
            state TEXT NOT NULL CHECK(state IN (
                'planned','pending_approval','queued','leased','running',
                'paused','canceling','canceled','partial','failed',
                'completed','expired','orphaned'
            )),
            payload_json TEXT NOT NULL DEFAULT '{}'
                CHECK(length(CAST(payload_json AS BLOB)) <= 1048576),
            metadata_json TEXT NOT NULL DEFAULT '{}'
                CHECK(length(CAST(metadata_json AS BLOB)) <= 16384),
            max_attempts INTEGER NOT NULL DEFAULT 1 CHECK(max_attempts > 0),
            required_work INTEGER NOT NULL DEFAULT 0 CHECK(required_work >= 0),
            completed_work INTEGER NOT NULL DEFAULT 0 CHECK(completed_work >= 0),
            skipped_work INTEGER NOT NULL DEFAULT 0 CHECK(skipped_work >= 0),
            failed_work INTEGER NOT NULL DEFAULT 0 CHECK(failed_work >= 0),
            truncated_work INTEGER NOT NULL DEFAULT 0 CHECK(truncated_work >= 0),
            uncollected_work INTEGER NOT NULL DEFAULT 0 CHECK(uncollected_work >= 0),
            version INTEGER NOT NULL DEFAULT 0 CHECK(version >= 0),
            control_version INTEGER NOT NULL DEFAULT 0 CHECK(control_version >= 0),
            paused_from_state TEXT,
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL,
            started_at REAL,
            terminal_at REAL,
            terminal_reason TEXT,
            terminal_reason_code TEXT,
            terminal_actor TEXT,
            error_reason TEXT,
            result_ref TEXT,
            PRIMARY KEY(tenant_id,id),
            UNIQUE(tenant_id,id,engagement_id),
            FOREIGN KEY(tenant_id,id)
                REFERENCES canonical_jobs(tenant_id,id) ON DELETE RESTRICT,
            FOREIGN KEY(tenant_id,engagement_id,id)
                REFERENCES canonical_jobs(tenant_id,engagement_id,id) ON DELETE RESTRICT,
            FOREIGN KEY(tenant_id,parent_id)
                REFERENCES durable_job_state_jobs(tenant_id,id) ON DELETE RESTRICT,
            FOREIGN KEY(tenant_id,assigned_agent_id)
                REFERENCES durable_job_state_agents(tenant_id,id) ON DELETE RESTRICT
        )
        """,
        """
        CREATE UNIQUE INDEX IF NOT EXISTS durable_job_state_uq_job_idempotency
            ON durable_job_state_jobs(tenant_id,idempotency_key)
            WHERE idempotency_key IS NOT NULL
        """,
        """
        CREATE INDEX IF NOT EXISTS durable_job_state_ix_job_state
            ON durable_job_state_jobs(tenant_id,state,updated_at)
        """,
        """
        CREATE TABLE IF NOT EXISTS durable_job_state_job_authorizations (
            tenant_id TEXT NOT NULL,
            job_id TEXT NOT NULL,
            authorization_decision_id TEXT NOT NULL,
            authorization_action_id TEXT NOT NULL,
            framework TEXT NOT NULL,
            generation INTEGER NOT NULL DEFAULT 1 CHECK(generation > 0),
            active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
            is_primary INTEGER NOT NULL DEFAULT 0 CHECK(is_primary IN (0,1)),
            PRIMARY KEY(tenant_id,job_id,authorization_decision_id),
            UNIQUE(tenant_id,job_id,framework,generation),
            FOREIGN KEY(tenant_id,job_id)
                REFERENCES durable_job_state_jobs(tenant_id,id) ON DELETE RESTRICT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS durable_job_state_attempts (
            tenant_id TEXT NOT NULL,
            id TEXT NOT NULL,
            job_id TEXT NOT NULL,
            number INTEGER NOT NULL CHECK(number > 0),
            idempotency_key TEXT NOT NULL,
            delivery_idempotency_key TEXT NOT NULL,
            run_id TEXT NOT NULL,
            authorization_decision_id TEXT,
            state TEXT NOT NULL CHECK(state IN (
                'leased','running','paused','canceling','completed','partial',
                'failed','expired','canceled','orphaned'
            )),
            worker_id TEXT NOT NULL,
            control_boot_id TEXT,
            lease_token_digest TEXT,
            lease_generation INTEGER NOT NULL DEFAULT 1 CHECK(lease_generation > 0),
            lease_expires_at REAL,
            lease_max_expires_at REAL,
            launch_nonce TEXT NOT NULL,
            control_version INTEGER NOT NULL DEFAULT 0 CHECK(control_version >= 0),
            started_at REAL,
            finished_at REAL,
            result_ref TEXT,
            result_identity TEXT,
            error_reason TEXT,
            error_reason_code TEXT,
            version INTEGER NOT NULL DEFAULT 0 CHECK(version >= 0),
            PRIMARY KEY(tenant_id,id),
            UNIQUE(tenant_id,job_id,number),
            UNIQUE(tenant_id,job_id,idempotency_key),
            UNIQUE(tenant_id,job_id,delivery_idempotency_key),
            UNIQUE(tenant_id,launch_nonce),
            FOREIGN KEY(tenant_id,job_id)
                REFERENCES durable_job_state_jobs(tenant_id,id) ON DELETE RESTRICT
        )
        """,
        """
        CREATE UNIQUE INDEX IF NOT EXISTS durable_job_state_uq_active_attempt
            ON durable_job_state_attempts(tenant_id,job_id)
            WHERE state IN ('leased','running','paused','canceling')
        """,
        """
        CREATE TABLE IF NOT EXISTS durable_job_state_leases (
            tenant_id TEXT NOT NULL,
            attempt_id TEXT NOT NULL,
            job_id TEXT NOT NULL,
            token_digest TEXT NOT NULL,
            owner_id TEXT NOT NULL,
            generation INTEGER NOT NULL DEFAULT 1 CHECK(generation > 0),
            issued_at REAL NOT NULL,
            expires_at REAL NOT NULL,
            revoked_at REAL,
            revoke_reason TEXT,
            PRIMARY KEY(tenant_id,attempt_id),
            FOREIGN KEY(tenant_id,attempt_id)
                REFERENCES durable_job_state_attempts(tenant_id,id) ON DELETE RESTRICT,
            FOREIGN KEY(tenant_id,job_id)
                REFERENCES durable_job_state_jobs(tenant_id,id) ON DELETE RESTRICT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS durable_job_state_events (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            job_id TEXT NOT NULL,
            attempt_id TEXT,
            event_type TEXT NOT NULL,
            from_state TEXT,
            to_state TEXT,
            actor TEXT NOT NULL,
            actor_role TEXT NOT NULL,
            authorization_decision_id TEXT,
            reason TEXT NOT NULL,
            reason_code TEXT NOT NULL,
            idempotency_key TEXT,
            job_version INTEGER NOT NULL CHECK(job_version >= 0),
            data_json TEXT NOT NULL DEFAULT '{}'
                CHECK(length(CAST(data_json AS BLOB)) <= 16384),
            occurred_at REAL NOT NULL,
            FOREIGN KEY(tenant_id,job_id)
                REFERENCES durable_job_state_jobs(tenant_id,id) ON DELETE RESTRICT,
            FOREIGN KEY(tenant_id,attempt_id)
                REFERENCES durable_job_state_attempts(tenant_id,id) ON DELETE RESTRICT
        )
        """,
        """
        CREATE UNIQUE INDEX IF NOT EXISTS durable_job_state_uq_event_idempotency
            ON durable_job_state_events(tenant_id,job_id,idempotency_key)
            WHERE idempotency_key IS NOT NULL
        """,
        """
        CREATE TABLE IF NOT EXISTS durable_job_state_logs (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id TEXT NOT NULL,
            job_id TEXT NOT NULL,
            attempt_id TEXT,
            level TEXT NOT NULL,
            message TEXT NOT NULL CHECK(length(CAST(message AS BLOB)) <= 8192),
            data_json TEXT NOT NULL DEFAULT '{}'
                CHECK(length(CAST(data_json AS BLOB)) <= 16384),
            occurred_at REAL NOT NULL,
            FOREIGN KEY(tenant_id,job_id)
                REFERENCES durable_job_state_jobs(tenant_id,id) ON DELETE RESTRICT,
            FOREIGN KEY(tenant_id,attempt_id)
                REFERENCES durable_job_state_attempts(tenant_id,id) ON DELETE RESTRICT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS durable_job_state_work_plan (
            tenant_id TEXT NOT NULL,
            job_id TEXT NOT NULL,
            work_key TEXT NOT NULL,
            required INTEGER NOT NULL DEFAULT 1 CHECK(required IN (0,1)),
            created_at REAL NOT NULL,
            PRIMARY KEY(tenant_id,job_id,work_key),
            FOREIGN KEY(tenant_id,job_id)
                REFERENCES durable_job_state_jobs(tenant_id,id) ON DELETE RESTRICT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS durable_job_state_work_items (
            tenant_id TEXT NOT NULL,
            job_id TEXT NOT NULL,
            attempt_id TEXT,
            attempt_scope TEXT NOT NULL,
            work_key TEXT NOT NULL,
            state TEXT NOT NULL CHECK(state IN (
                'pending','completed','skipped','failed','truncated','uncollected'
            )),
            required INTEGER NOT NULL DEFAULT 1 CHECK(required IN (0,1)),
            reason TEXT,
            observation_id TEXT,
            result_ref TEXT,
            updated_at REAL NOT NULL,
            PRIMARY KEY(tenant_id,job_id,attempt_scope,work_key),
            FOREIGN KEY(tenant_id,job_id)
                REFERENCES durable_job_state_jobs(tenant_id,id) ON DELETE RESTRICT,
            FOREIGN KEY(tenant_id,attempt_id)
                REFERENCES durable_job_state_attempts(tenant_id,id) ON DELETE RESTRICT
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS durable_job_state_ix_work_observation
            ON durable_job_state_work_items(tenant_id,observation_id)
            WHERE observation_id IS NOT NULL
        """,
        """
        CREATE TABLE IF NOT EXISTS durable_job_state_deliveries (
            tenant_id TEXT NOT NULL,
            attempt_id TEXT NOT NULL,
            job_id TEXT NOT NULL,
            idempotency_key TEXT NOT NULL,
            state TEXT NOT NULL DEFAULT 'reserved'
                CHECK(state IN ('reserved','custodied','accepted','rejected')),
            payload_identity TEXT NOT NULL,
            observation_id TEXT NOT NULL,
            artifact_id TEXT NOT NULL,
            result_ref TEXT,
            result_identity TEXT,
            manifest_digest TEXT NOT NULL,
            outcome TEXT NOT NULL
                CHECK(outcome IN ('success','failure','canceled','partial')),
            work_json TEXT NOT NULL,
            run_truth_json TEXT NOT NULL,
            reserved_at REAL NOT NULL,
            accepted_at REAL,
            PRIMARY KEY(tenant_id,attempt_id,idempotency_key),
            UNIQUE(tenant_id,observation_id),
            UNIQUE(tenant_id,artifact_id),
            FOREIGN KEY(tenant_id,attempt_id)
                REFERENCES durable_job_state_attempts(tenant_id,id) ON DELETE RESTRICT,
            FOREIGN KEY(tenant_id,job_id)
                REFERENCES durable_job_state_jobs(tenant_id,id) ON DELETE RESTRICT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS durable_job_state_terminal_proofs (
            tenant_id TEXT NOT NULL,
            job_id TEXT NOT NULL,
            attempt_id TEXT NOT NULL,
            proof_type TEXT NOT NULL
                CHECK(proof_type IN ('observation_receipt','run_truth')),
            outcome TEXT NOT NULL
                CHECK(outcome IN ('success','failure','canceled','partial')),
            proof_identity TEXT NOT NULL,
            coverage_identity TEXT NOT NULL,
            result_ref TEXT NOT NULL,
            recorded_at REAL NOT NULL,
            PRIMARY KEY(tenant_id,attempt_id,proof_type,proof_identity),
            FOREIGN KEY(tenant_id,job_id)
                REFERENCES durable_job_state_jobs(tenant_id,id) ON DELETE RESTRICT,
            FOREIGN KEY(tenant_id,attempt_id)
                REFERENCES durable_job_state_attempts(tenant_id,id) ON DELETE RESTRICT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS durable_job_state_children (
            tenant_id TEXT NOT NULL,
            parent_id TEXT NOT NULL,
            child_id TEXT NOT NULL,
            identity_key TEXT NOT NULL,
            required INTEGER NOT NULL DEFAULT 1 CHECK(required IN (0,1)),
            created_at REAL NOT NULL,
            PRIMARY KEY(tenant_id,parent_id,identity_key),
            UNIQUE(tenant_id,parent_id,child_id),
            FOREIGN KEY(tenant_id,parent_id)
                REFERENCES durable_job_state_jobs(tenant_id,id) ON DELETE RESTRICT,
            FOREIGN KEY(tenant_id,child_id)
                REFERENCES durable_job_state_jobs(tenant_id,id) ON DELETE RESTRICT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS durable_job_state_child_processes (
            tenant_id TEXT NOT NULL,
            job_id TEXT NOT NULL,
            attempt_id TEXT NOT NULL,
            identity_key TEXT NOT NULL,
            launch_nonce TEXT NOT NULL,
            pid INTEGER NOT NULL,
            start_token TEXT NOT NULL,
            boot_id TEXT NOT NULL,
            command_digest TEXT NOT NULL,
            state TEXT NOT NULL DEFAULT 'running'
                CHECK(state IN ('running','paused','canceling','stopped','orphaned')),
            return_code INTEGER,
            cancel_requested_at REAL,
            stopped_at REAL,
            escalation_count INTEGER NOT NULL DEFAULT 0 CHECK(escalation_count >= 0),
            PRIMARY KEY(tenant_id,attempt_id,identity_key),
            UNIQUE(tenant_id,launch_nonce,pid,start_token,command_digest,boot_id),
            FOREIGN KEY(tenant_id,job_id)
                REFERENCES durable_job_state_jobs(tenant_id,id) ON DELETE RESTRICT,
            FOREIGN KEY(tenant_id,attempt_id)
                REFERENCES durable_job_state_attempts(tenant_id,id) ON DELETE RESTRICT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS durable_job_state_launch_intents (
            tenant_id TEXT NOT NULL,
            job_id TEXT NOT NULL,
            attempt_id TEXT NOT NULL,
            identity_key TEXT NOT NULL,
            launch_nonce TEXT NOT NULL,
            state TEXT NOT NULL DEFAULT 'reserved'
                CHECK(state IN ('reserved','registered','abandoned')),
            created_at REAL NOT NULL,
            registered_at REAL,
            PRIMARY KEY(tenant_id,attempt_id,identity_key),
            UNIQUE(tenant_id,launch_nonce),
            FOREIGN KEY(tenant_id,job_id)
                REFERENCES durable_job_state_jobs(tenant_id,id) ON DELETE RESTRICT,
            FOREIGN KEY(tenant_id,attempt_id)
                REFERENCES durable_job_state_attempts(tenant_id,id) ON DELETE RESTRICT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS durable_job_state_cache_imports (
            tenant_id TEXT NOT NULL,
            cache_kind TEXT NOT NULL,
            source_identity TEXT NOT NULL,
            imported_at REAL NOT NULL,
            result TEXT NOT NULL,
            detail_json TEXT NOT NULL DEFAULT '{}'
                CHECK(length(CAST(detail_json AS BLOB)) <= 16384),
            PRIMARY KEY(tenant_id,cache_kind,source_identity),
            FOREIGN KEY(tenant_id) REFERENCES canonical_tenants(id) ON DELETE RESTRICT
        )
        """,
        """
        ALTER TABLE canonical_observations ADD COLUMN attempt_id TEXT
        """,
        """
        CREATE TRIGGER IF NOT EXISTS canonical_observation_attempt_guard_insert
        BEFORE INSERT ON canonical_observations
        WHEN NEW.attempt_id IS NOT NULL AND NOT EXISTS(
            SELECT 1 FROM durable_job_state_attempts a
            WHERE a.tenant_id=NEW.tenant_id AND a.id=NEW.attempt_id
              AND a.job_id=NEW.job_id
        )
        BEGIN SELECT RAISE(ABORT, 'observation attempt lineage mismatch'); END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS canonical_observation_attempt_guard_update
        BEFORE UPDATE OF tenant_id,job_id,attempt_id ON canonical_observations
        WHEN NEW.attempt_id IS NOT NULL AND NOT EXISTS(
            SELECT 1 FROM durable_job_state_attempts a
            WHERE a.tenant_id=NEW.tenant_id AND a.id=NEW.attempt_id
              AND a.job_id=NEW.job_id
        )
        BEGIN SELECT RAISE(ABORT, 'observation attempt lineage mismatch'); END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS durable_job_state_jobs_no_delete
        BEFORE DELETE ON durable_job_state_jobs
        BEGIN SELECT RAISE(ABORT, 'durable job history cannot be deleted'); END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS durable_job_state_job_identity_immutable
        BEFORE UPDATE OF tenant_id,id,engagement_id,job_kind,target,
            assigned_agent_id,idempotency_key,request_identity,parent_id,
            max_attempts,required_work,created_at
        ON durable_job_state_jobs
        BEGIN SELECT RAISE(ABORT, 'durable job identity is immutable'); END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS durable_job_state_terminal_immutable
        BEFORE UPDATE OF state ON durable_job_state_jobs
        WHEN OLD.state IN ('canceled','partial','failed','completed')
          AND NEW.state <> OLD.state
        BEGIN SELECT RAISE(ABORT, 'durable terminal state is immutable'); END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS durable_job_state_attempts_no_delete
        BEFORE DELETE ON durable_job_state_attempts
        BEGIN SELECT RAISE(ABORT, 'durable attempt history cannot be deleted'); END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS durable_job_state_attempt_identity_immutable
        BEFORE UPDATE OF tenant_id,id,job_id,number,idempotency_key,
            delivery_idempotency_key,run_id,authorization_decision_id,
            worker_id,control_boot_id,lease_max_expires_at,launch_nonce
        ON durable_job_state_attempts
        BEGIN SELECT RAISE(ABORT, 'durable attempt identity is immutable'); END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS durable_job_state_lease_identity_immutable
        BEFORE UPDATE OF tenant_id,attempt_id,job_id,owner_id
        ON durable_job_state_leases
        BEGIN SELECT RAISE(ABORT, 'durable lease identity is immutable'); END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS durable_job_state_authorization_identity_immutable
        BEFORE UPDATE OF tenant_id,job_id,authorization_decision_id,
            authorization_action_id,framework,generation,is_primary
        ON durable_job_state_job_authorizations
        BEGIN SELECT RAISE(ABORT, 'durable authorization history is immutable'); END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS durable_job_state_authorization_no_reactivation
        BEFORE UPDATE OF active ON durable_job_state_job_authorizations
        WHEN NEW.active <> OLD.active
          AND NOT (OLD.active=1 AND NEW.active=0)
        BEGIN SELECT RAISE(ABORT, 'durable authorization cannot be reactivated'); END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS durable_job_state_authorization_no_delete
        BEFORE DELETE ON durable_job_state_job_authorizations
        BEGIN SELECT RAISE(ABORT, 'durable authorization history cannot be deleted'); END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS durable_job_state_events_no_update
        BEFORE UPDATE ON durable_job_state_events
        BEGIN SELECT RAISE(ABORT, 'durable job events are append-only'); END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS durable_job_state_events_no_delete
        BEFORE DELETE ON durable_job_state_events
        BEGIN SELECT RAISE(ABORT, 'durable job events cannot be deleted'); END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS durable_job_state_logs_no_update
        BEFORE UPDATE ON durable_job_state_logs
        BEGIN SELECT RAISE(ABORT, 'durable job logs are append-only'); END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS durable_job_state_logs_no_delete
        BEFORE DELETE ON durable_job_state_logs
        BEGIN SELECT RAISE(ABORT, 'durable job logs cannot be deleted'); END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS durable_job_state_work_no_update
        BEFORE UPDATE ON durable_job_state_work_items
        BEGIN SELECT RAISE(ABORT, 'durable work history is append-only'); END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS durable_job_state_work_plan_no_update
        BEFORE UPDATE ON durable_job_state_work_plan
        BEGIN SELECT RAISE(ABORT, 'durable work plan is immutable'); END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS durable_job_state_work_plan_no_delete
        BEFORE DELETE ON durable_job_state_work_plan
        BEGIN SELECT RAISE(ABORT, 'durable work plan cannot be deleted'); END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS durable_job_state_work_no_delete
        BEFORE DELETE ON durable_job_state_work_items
        BEGIN SELECT RAISE(ABORT, 'durable work history cannot be deleted'); END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS durable_job_state_proofs_no_update
        BEFORE UPDATE ON durable_job_state_terminal_proofs
        BEGIN SELECT RAISE(ABORT, 'durable terminal proofs are append-only'); END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS durable_job_state_proofs_no_delete
        BEFORE DELETE ON durable_job_state_terminal_proofs
        BEGIN SELECT RAISE(ABORT, 'durable terminal proofs cannot be deleted'); END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS durable_job_state_deliveries_no_delete
        BEFORE DELETE ON durable_job_state_deliveries
        BEGIN SELECT RAISE(ABORT, 'durable deliveries cannot be deleted'); END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS durable_job_state_delivery_accepted_immutable
        BEFORE UPDATE ON durable_job_state_deliveries
        WHEN OLD.state='accepted'
        BEGIN SELECT RAISE(ABORT, 'accepted delivery is immutable'); END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS durable_job_state_children_no_update
        BEFORE UPDATE ON durable_job_state_children
        BEGIN SELECT RAISE(ABORT, 'durable child linkage is append-only'); END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS durable_job_state_children_no_delete
        BEFORE DELETE ON durable_job_state_children
        BEGIN SELECT RAISE(ABORT, 'durable child linkage cannot be deleted'); END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS durable_job_state_process_identity_immutable
        BEFORE UPDATE OF tenant_id,job_id,attempt_id,identity_key,launch_nonce,
            pid,start_token,boot_id,command_digest
        ON durable_job_state_child_processes
        BEGIN SELECT RAISE(ABORT, 'durable process identity is immutable'); END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS durable_job_state_process_no_delete
        BEFORE DELETE ON durable_job_state_child_processes
        BEGIN SELECT RAISE(ABORT, 'durable process history cannot be deleted'); END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS durable_job_state_launch_identity_immutable
        BEFORE UPDATE OF tenant_id,job_id,attempt_id,identity_key,launch_nonce,
            created_at
        ON durable_job_state_launch_intents
        BEGIN SELECT RAISE(ABORT, 'durable launch identity is immutable'); END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS durable_job_state_launch_no_delete
        BEFORE DELETE ON durable_job_state_launch_intents
        BEGIN SELECT RAISE(ABORT, 'durable launch history cannot be deleted'); END
        """,
    )


def _job_state_drop_sql() -> tuple[str, ...]:
    """Logically reverse an empty Task 103 boundary in dependency order."""

    return (
        "DROP TRIGGER IF EXISTS durable_job_state_launch_no_delete",
        "DROP TRIGGER IF EXISTS durable_job_state_launch_identity_immutable",
        "DROP TRIGGER IF EXISTS durable_job_state_process_no_delete",
        "DROP TRIGGER IF EXISTS durable_job_state_process_identity_immutable",
        "DROP TRIGGER IF EXISTS durable_job_state_children_no_delete",
        "DROP TRIGGER IF EXISTS durable_job_state_children_no_update",
        "DROP TRIGGER IF EXISTS durable_job_state_delivery_accepted_immutable",
        "DROP TRIGGER IF EXISTS durable_job_state_deliveries_no_delete",
        "DROP TRIGGER IF EXISTS durable_job_state_proofs_no_delete",
        "DROP TRIGGER IF EXISTS durable_job_state_proofs_no_update",
        "DROP TRIGGER IF EXISTS durable_job_state_work_no_delete",
        "DROP TRIGGER IF EXISTS durable_job_state_work_no_update",
        "DROP TRIGGER IF EXISTS durable_job_state_work_plan_no_delete",
        "DROP TRIGGER IF EXISTS durable_job_state_work_plan_no_update",
        "DROP TRIGGER IF EXISTS durable_job_state_logs_no_delete",
        "DROP TRIGGER IF EXISTS durable_job_state_logs_no_update",
        "DROP TRIGGER IF EXISTS durable_job_state_events_no_delete",
        "DROP TRIGGER IF EXISTS durable_job_state_events_no_update",
        "DROP TRIGGER IF EXISTS durable_job_state_attempts_no_delete",
        "DROP TRIGGER IF EXISTS durable_job_state_lease_identity_immutable",
        "DROP TRIGGER IF EXISTS durable_job_state_attempt_identity_immutable",
        "DROP TRIGGER IF EXISTS durable_job_state_authorization_no_delete",
        "DROP TRIGGER IF EXISTS durable_job_state_authorization_no_reactivation",
        "DROP TRIGGER IF EXISTS durable_job_state_authorization_identity_immutable",
        "DROP TRIGGER IF EXISTS durable_job_state_terminal_immutable",
        "DROP TRIGGER IF EXISTS durable_job_state_job_identity_immutable",
        "DROP TRIGGER IF EXISTS durable_job_state_jobs_no_delete",
        "DROP TRIGGER IF EXISTS canonical_observation_attempt_guard_update",
        "DROP TRIGGER IF EXISTS canonical_observation_attempt_guard_insert",
        "DROP TABLE IF EXISTS durable_job_state_cache_imports",
        "DROP TABLE IF EXISTS durable_job_state_launch_intents",
        "DROP TABLE IF EXISTS durable_job_state_child_processes",
        "DROP TABLE IF EXISTS durable_job_state_children",
        "DROP TABLE IF EXISTS durable_job_state_terminal_proofs",
        "DROP TABLE IF EXISTS durable_job_state_deliveries",
        "DROP TABLE IF EXISTS durable_job_state_work_items",
        "DROP TABLE IF EXISTS durable_job_state_work_plan",
        "DROP TABLE IF EXISTS durable_job_state_logs",
        "DROP TABLE IF EXISTS durable_job_state_events",
        "DROP TABLE IF EXISTS durable_job_state_leases",
        "DROP TABLE IF EXISTS durable_job_state_attempts",
        "DROP TABLE IF EXISTS durable_job_state_job_authorizations",
        "DROP TABLE IF EXISTS durable_job_state_jobs",
        "DROP TABLE IF EXISTS durable_job_state_agent_scope",
        "DROP TABLE IF EXISTS durable_job_state_agent_capabilities",
        "DROP TABLE IF EXISTS durable_job_state_agent_engines",
        "DROP TABLE IF EXISTS durable_job_state_agents",
        "DROP TABLE IF EXISTS durable_job_state_meta",
        # SQLite cannot safely drop the additive nullable attempt_id column on
        # every supported version.  It remains unused after logical downgrade.
    )


MIGRATIONS: tuple[Migration, ...] = (
    Migration(
        version=CANONICAL_SCHEMA_VERSION,
        order=101,
        upgrade_sql=_table_sql(),
        downgrade_sql=_drop_sql(),
        description="Task 101 canonical tenant-safe data contracts",
    ),
    Migration(
        version=EVIDENCE_SCHEMA_VERSION,
        order=102,
        upgrade_sql=_evidence_table_sql(),
        downgrade_sql=_evidence_drop_sql(),
        description="Task 102 immutable observations and evidence custody",
    ),
    Migration(
        version=JOB_STATE_SCHEMA_VERSION,
        order=103,
        upgrade_sql=_job_state_table_sql(),
        downgrade_sql=_job_state_drop_sql(),
        description="Task 103 durable single-node job state machine",
    ),
)


def _as_connection(bind: Engine | Connection) -> tuple[Connection, bool]:
    if isinstance(bind, Connection):
        return bind, False
    return bind.connect(), True


def _ensure_journal(connection: Connection) -> None:
    if connection.dialect.name == "sqlite":
        # ``create_db`` installs this pragma on every pooled connection, but
        # the migration API is also intentionally usable with a standalone
        # SQLite engine.  Constraints must remain active in that mode too.
        connection.exec_driver_sql("PRAGMA foreign_keys=ON")
    connection.exec_driver_sql(
        f"""
        CREATE TABLE IF NOT EXISTS {JOURNAL_TABLE} (
            version TEXT PRIMARY KEY,
            state TEXT NOT NULL CHECK(state IN ('applying','applied','failed')),
            started_at TEXT NOT NULL,
            completed_at TEXT,
            detail TEXT NOT NULL DEFAULT '{{}}'
        )
        """
    )


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _migration_by_version(version: str) -> Migration:
    for migration in MIGRATIONS:
        if migration.version == version:
            return migration
    raise UnsupportedMigrationError(f"unsupported canonical migration {version}")


class MigrationManager:
    """Apply/reverse canonical migrations with interruption recovery."""

    def __init__(self, bind: Engine | Connection):
        self.bind = bind
        if isinstance(bind, Engine) and not getattr(bind, "_forge_canonical_fk_listener", False):
            # SQLite disables FK enforcement per connection by default.  The
            # product ``create_db`` path already enables it, but the public
            # migration API is also used directly by fixtures and recovery
            # tooling; make that path equally fail-closed.
            @event.listens_for(bind, "connect")
            def _enable_canonical_foreign_keys(dbapi_connection: Any, _record: Any) -> None:
                cursor = dbapi_connection.cursor()
                try:
                    cursor.execute("PRAGMA foreign_keys=ON")
                finally:
                    cursor.close()
            setattr(bind, "_forge_canonical_fk_listener", True)

    @property
    def versions(self) -> tuple[str, ...]:
        return tuple(m.version for m in sorted(MIGRATIONS, key=lambda item: item.order))

    def _connection(self) -> tuple[Connection, bool]:
        return _as_connection(self.bind)

    def _reject_borrowed_transaction(self, operation: str) -> None:
        if isinstance(self.bind, Connection) and self.bind.in_transaction():
            raise MigrationError(
                f"{operation} cannot mutate a borrowed active transaction"
            )

    def current_version(self) -> str | None:
        connection, owned = self._connection()
        had_transaction = connection.in_transaction()
        try:
            _ensure_journal(connection)
            row = connection.exec_driver_sql(
                f"SELECT version FROM {JOURNAL_TABLE} WHERE state='applied' ORDER BY rowid DESC LIMIT 1"
            ).fetchone()
            version: str | None
            if not row:
                version = None
            # ``CURRENT_SCHEMA_VERSION`` is the canonical contract wire
            # version retained for existing callers.  Evidence custody is an
            # additive migration and must not make v1 contract serializers
            # claim a new payload version merely because its tables exist.
            elif str(row[0]) in {
                EVIDENCE_SCHEMA_VERSION,
                JOB_STATE_SCHEMA_VERSION,
            }:
                version = CANONICAL_SCHEMA_VERSION
            else:
                version = str(row[0])
            if not had_transaction and connection.in_transaction():
                connection.commit()
            return version
        except Exception:
            if not had_transaction and connection.in_transaction():
                connection.rollback()
            raise
        finally:
            if owned:
                connection.close()

    @property
    def schema_version(self) -> str | None:
        return self.current_version()

    def journal(self) -> list[dict[str, Any]]:
        connection, owned = self._connection()
        had_transaction = connection.in_transaction()
        try:
            _ensure_journal(connection)
            rows = [
                dict(row._mapping)
                for row in connection.exec_driver_sql(
                    f"SELECT * FROM {JOURNAL_TABLE} ORDER BY rowid"
                ).fetchall()
            ]
            if not had_transaction and connection.in_transaction():
                connection.commit()
            return rows
        except Exception:
            if not had_transaction and connection.in_transaction():
                connection.rollback()
            raise
        finally:
            if owned:
                connection.close()

    def recover(self) -> str | None:
        """Replay any applying/failed step and return the resulting version."""
        self._reject_borrowed_transaction("recover")
        connection, owned = self._connection()
        try:
            _ensure_journal(connection)
            if connection.in_transaction():
                connection.commit()
            applied = {
                str(row[0])
                for row in connection.exec_driver_sql(
                    f"SELECT version FROM {JOURNAL_TABLE} WHERE state='applied'"
                ).fetchall()
            }
            if connection.in_transaction():
                connection.commit()
            if CANONICAL_SCHEMA_VERSION in applied:
                with connection.begin():
                    _audit_existing_canonical_rows(connection)
                    for statement in _runtime_guard_sql():
                        connection.exec_driver_sql(statement)
            pending = connection.exec_driver_sql(
                f"SELECT version FROM {JOURNAL_TABLE} WHERE state IN ('applying','failed') ORDER BY rowid LIMIT 1"
            ).fetchone()
            if connection.in_transaction():
                connection.commit()
            if pending:
                self._apply_one(connection, _migration_by_version(str(pending[0])))
            applied = {
                str(row[0])
                for row in connection.exec_driver_sql(
                    f"SELECT version FROM {JOURNAL_TABLE} WHERE state='applied'"
                ).fetchall()
            }
            if connection.in_transaction():
                connection.commit()
            if CANONICAL_SCHEMA_VERSION in applied:
                if EVIDENCE_SCHEMA_VERSION in applied:
                    _reconcile_task102_postmigration(connection)
                else:
                    with connection.begin():
                        _audit_existing_canonical_rows(connection)
                        for statement in _runtime_guard_sql():
                            connection.exec_driver_sql(statement)
            return self.current_version()
        finally:
            if owned:
                connection.close()

    def upgrade(self, target: str | None = None, *, fail_after: int | None = None) -> str | None:
        target = target or (self.versions[-1] if self.versions else None)
        if target is None or target not in self.versions:
            raise UnsupportedMigrationError(f"unsupported upgrade target {target}")
        self._reject_borrowed_transaction("upgrade")
        connection, owned = self._connection()
        try:
            _ensure_journal(connection)
            if connection.in_transaction():
                connection.commit()
            # An already-applied canonical v1 must pass the read-only audit
            # before recovery is allowed to replay a later migration.  This
            # prevents v2 DDL, repair, or legacy normalization from changing
            # a database whose accepted v1 rows already violate the contract.
            applied_before_recovery = {
                str(row[0])
                for row in connection.exec_driver_sql(
                    f"SELECT version FROM {JOURNAL_TABLE} WHERE state='applied'"
                ).fetchall()
            }
            if connection.in_transaction():
                connection.commit()
            if CANONICAL_SCHEMA_VERSION in applied_before_recovery:
                with connection.begin():
                    _audit_existing_canonical_rows(connection)
                    for statement in _runtime_guard_sql():
                        connection.exec_driver_sql(statement)
            self._recover_on_connection(connection, target=target)
            applied = {str(row[0]) for row in connection.exec_driver_sql(f"SELECT version FROM {JOURNAL_TABLE} WHERE state='applied'").fetchall()}
            if connection.in_transaction():
                connection.commit()
            # Recovery may have completed v1 itself.  Audit and install its
            # current runtime guards before considering any later migration.
            if (
                CANONICAL_SCHEMA_VERSION in applied
                and CANONICAL_SCHEMA_VERSION not in applied_before_recovery
            ):
                with connection.begin():
                    _audit_existing_canonical_rows(connection)
                    for statement in _runtime_guard_sql():
                        connection.exec_driver_sql(statement)
            # SQLAlchemy's SQLite connection autobegins for the read above.
            # Close that read transaction before ``_apply_one`` opens its
            # explicit journal/work transactions; otherwise a fresh
            # connection raises ``InvalidRequestError`` and database
            # initialization fails before the canonical tables are created.
            if connection.in_transaction():
                connection.commit()
            failure_target_available = fail_after is not None
            for migration in sorted(MIGRATIONS, key=lambda item: item.order):
                if migration.version in applied:
                    if migration.version == target:
                        break
                    continue
                self._apply_one(
                    connection,
                    migration,
                    fail_after=fail_after if failure_target_available else None,
                )
                failure_target_available = False
                if migration.version == target:
                    break
            # Task 102 custody repair is a later migration boundary.  Do not
            # materialize its columns/tables when a caller explicitly targets
            # Task 101's canonical v1; doing so would report v1 while the
            # database already contains unjournaled v2 structures.  Once the
            # evidence migration is applied, replay repair/guards on every
            # idempotent upgrade to keep older databases recoverable.
            evidence_applied = EVIDENCE_SCHEMA_VERSION in {
                str(row[0])
                for row in connection.exec_driver_sql(
                    f"SELECT version FROM {JOURNAL_TABLE} WHERE state='applied'"
                ).fetchall()
            }
            if connection.in_transaction():
                connection.commit()
            evidence_boundary = target == EVIDENCE_SCHEMA_VERSION or evidence_applied
            if evidence_boundary:
                _reconcile_task102_postmigration(connection)
            else:
                with connection.begin():
                    _audit_existing_canonical_rows(connection)
                    for statement in _runtime_guard_sql():
                        connection.exec_driver_sql(statement)
            return self.current_version()
        finally:
            if owned:
                connection.close()

    def downgrade(self, target: str | None = None) -> str | None:
        """Reverse to ``None`` (empty) or the requested supported version."""
        if target is not None and target not in self.versions:
            raise UnsupportedMigrationError(f"unsupported downgrade target {target}")
        self._reject_borrowed_transaction("downgrade")
        connection, owned = self._connection()
        try:
            _ensure_journal(connection)
            if connection.in_transaction():
                connection.commit()
            rows = connection.exec_driver_sql(f"SELECT version FROM {JOURNAL_TABLE} WHERE state='applied' ORDER BY rowid DESC").fetchall()
            if connection.in_transaction():
                connection.commit()
            if connection.in_transaction():
                connection.commit()
            keep = set(self.versions[: self.versions.index(target) + 1]) if target else set()
            removing = {str(row[0]) for row in rows} - keep
            if JOB_STATE_SCHEMA_VERSION in removing:
                job_tables = (
                    "durable_job_state_agents",
                    "durable_job_state_jobs",
                    "durable_job_state_job_authorizations",
                    "durable_job_state_attempts",
                    "durable_job_state_leases",
                    "durable_job_state_events",
                    "durable_job_state_logs",
                    "durable_job_state_work_plan",
                    "durable_job_state_work_items",
                    "durable_job_state_deliveries",
                    "durable_job_state_terminal_proofs",
                    "durable_job_state_children",
                    "durable_job_state_child_processes",
                    "durable_job_state_launch_intents",
                    "durable_job_state_cache_imports",
                )
                present_tables = {
                    str(row[0])
                    for row in connection.exec_driver_sql(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    ).fetchall()
                }
                if not set(job_tables) <= present_tables:
                    if connection.in_transaction():
                        connection.rollback()
                    raise MigrationError(
                        "job-state schema downgrade encountered incomplete state"
                    )
                retained_job_state = any(
                    int(
                        connection.exec_driver_sql(
                            f"SELECT COUNT(*) FROM {table}"
                        ).scalar_one()
                    )
                    > 0
                    for table in job_tables
                )
                observation_columns = {
                    str(row[1])
                    for row in connection.exec_driver_sql(
                        "PRAGMA table_info(canonical_observations)"
                    ).fetchall()
                }
                retained_attempt_observations = (
                    "attempt_id" in observation_columns
                    and int(
                        connection.exec_driver_sql(
                            "SELECT COUNT(*) FROM canonical_observations "
                            "WHERE attempt_id IS NOT NULL"
                        ).scalar_one()
                    )
                    > 0
                )
                if connection.in_transaction():
                    connection.rollback()
                if retained_job_state or retained_attempt_observations:
                    raise MigrationError(
                        "job-state schema downgrade would destroy retained history"
                    )
            if EVIDENCE_SCHEMA_VERSION in removing:
                evidence_tables = (
                    "canonical_artifact_manifests",
                    "canonical_observation_artifacts",
                    "canonical_finding_observations",
                    "canonical_evidence_access_audit",
                )
                present_tables = {
                    str(row[0])
                    for row in connection.exec_driver_sql(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    ).fetchall()
                }
                if not set(evidence_tables) <= present_tables:
                    if connection.in_transaction():
                        connection.rollback()
                    raise MigrationError(
                        "evidence schema downgrade encountered incomplete state"
                    )
                retained_lineage = any(
                    int(
                        connection.exec_driver_sql(
                            f"SELECT COUNT(*) FROM {table}"
                        ).scalar_one()
                    )
                    > 0
                    for table in evidence_tables
                )
                if connection.in_transaction():
                    connection.rollback()
                if retained_lineage:
                    raise MigrationError(
                        "evidence schema downgrade would break retained canonical lineage"
                    )
            for row in rows:
                version = str(row[0])
                if version in keep:
                    continue
                migration = _migration_by_version(version)
                with connection.begin():
                    for statement in migration.downgrade_sql:
                        connection.exec_driver_sql(statement)
                    connection.exec_driver_sql(f"DELETE FROM {JOURNAL_TABLE} WHERE version=?", (version,))
            return self.current_version()
        finally:
            if owned:
                connection.close()

    def _recover_on_connection(
        self,
        connection: Connection,
        *,
        target: str | None = None,
    ) -> None:
        row = connection.exec_driver_sql(
            f"SELECT version FROM {JOURNAL_TABLE} WHERE state IN ('applying','failed') ORDER BY rowid LIMIT 1"
        ).fetchone()
        if connection.in_transaction():
            connection.commit()
        if row:
            pending = _migration_by_version(str(row[0]))
            if target is not None and pending.order > _migration_by_version(target).order:
                return
            self._apply_one(connection, pending)

    def _apply_one(self, connection: Connection, migration: Migration, *, fail_after: int | None = None) -> str:
        # Journal state is deliberately committed before the work.  If the
        # process dies after this point, a later upgrade/recover call replays
        # the idempotent DDL and changes the marker to applied.
        with connection.begin():
            connection.exec_driver_sql(
                f"INSERT INTO {JOURNAL_TABLE}(version,state,started_at,detail) VALUES(?,?,?,?) "
                f"ON CONFLICT(version) DO UPDATE SET state='applying', started_at=excluded.started_at, detail=excluded.detail",
                (migration.version, "applying", _now(), json.dumps({"description": migration.description}, sort_keys=True)),
            )
        try:
            with connection.begin():
                for index, statement in enumerate(migration.upgrade_sql):
                    # Legacy archive INSERTs are intentionally optional: a
                    # standalone migration fixture may contain only the
                    # canonical schema, while a product database has the
                    # Gate-0 tables.  Skip only statements that reference a
                    # missing legacy table; never skip canonical DDL or
                    # constraint/index/trigger statements.
                    lowered = statement.lower()
                    if "canonical_legacy_records" in lowered or "legacy_tenants" in lowered:
                        legacy_tables = {
                            str(row[0])
                            for row in connection.exec_driver_sql(
                                "SELECT name FROM sqlite_master WHERE type='table'"
                            ).fetchall()
                        }
                        referenced = {
                            name
                            for name in (
                                "findings",
                                "scan_jobs",
                                "audit_logs",
                                "authorization_decisions",
                                "authorization_consumptions",
                                "authorization_execution_claims",
                            )
                            if name in lowered
                        }
                        if referenced - legacy_tables:
                            continue
                    # SQLite has no ``ADD COLUMN IF NOT EXISTS``.  The
                    # journal can legitimately record an interrupted v2
                    # migration after the column DDL committed, so replay it
                    # only when the column is genuinely absent.
                    if lowered.strip().startswith("alter table canonical_findings add column dedup_key"):
                        finding_columns = {
                            str(row[1])
                            for row in connection.exec_driver_sql(
                                "PRAGMA table_info(canonical_findings)"
                            ).fetchall()
                        }
                        if "dedup_key" in finding_columns:
                            continue
                    if lowered.strip().startswith(
                        "alter table canonical_observations add column attempt_id"
                    ):
                        observation_columns = {
                            str(row[1])
                            for row in connection.exec_driver_sql(
                                "PRAGMA table_info(canonical_observations)"
                            ).fetchall()
                        }
                        if "attempt_id" in observation_columns:
                            continue
                    connection.exec_driver_sql(statement)
                    if fail_after is not None and index >= fail_after:
                        raise MigrationInterruptedError(f"migration interrupted at {migration.version}:{index}")
                # Normalize existing Gate-0 rows before retaining the bounded
                # diagnostic archive.  The archive is not the canonical
                # relationship model; it preserves reduced/unknown truth and
                # redacted source payloads for auditability.
                _normalize_legacy_records_in_transaction(
                    connection,
                    evidence_boundary_available=(
                        migration.version == EVIDENCE_SCHEMA_VERSION
                    ),
                )
                self._archive_legacy_records_in_transaction(connection)
                _audit_existing_canonical_rows(connection)
                connection.exec_driver_sql(
                    f"UPDATE {JOURNAL_TABLE} SET state='applied', completed_at=?, detail=? WHERE version=?",
                    (_now(), json.dumps({"description": migration.description}, sort_keys=True), migration.version),
                )
        except Exception as exc:
            # Preserve a compact, redacted failure marker in a separate
            # transaction; do not leak SQL parameters or credential material.
            with connection.begin():
                connection.exec_driver_sql(
                    f"UPDATE {JOURNAL_TABLE} SET state='failed', detail=? WHERE version=?",
                    (json.dumps({"error": type(exc).__name__}, sort_keys=True), migration.version),
                )
            raise
        return migration.version

    @staticmethod
    def _archive_legacy_records_in_transaction(connection: Connection) -> int:
        tables = {
            str(row[0])
            for row in connection.exec_driver_sql(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        count = 0
        for table, record_kind in (
            ("authorization_decisions", "authorization"),
            ("authorization_consumptions", "authorization_consumption"),
            (
                "authorization_execution_claims",
                "authorization_execution_claim",
            ),
            ("audit_logs", "audit"),
            ("scan_jobs", "job"),
            ("findings", "finding"),
        ):
            if table not in tables:
                continue
            columns = [str(row[1]) for row in connection.exec_driver_sql(f"PRAGMA table_info({table})").fetchall()]
            for row in connection.exec_driver_sql(f"SELECT * FROM {table}").fetchall():
                data = {columns[index]: row[index] for index in range(len(columns))}
                tenant = _canonical_legacy_key(data.get("tenant_id") or "default", kind="tenant", tenant_id="forge-legacy")
                legacy_id = _legacy_identifier(
                    data.get("id")
                    or data.get("consumption_id")
                    or data.get("claim_id")
                    or data.get("decision_id")
                    or data.get("job_id")
                    or data.get("finding_id")
                    or data.get("run_id")
                    or data.get("sequence")
                    or "legacy",
                    prefix=f"legacy-{record_kind}",
                )
                outcome = str(data.get("decision_outcome") or data.get("outcome") or "").lower()
                claim_state = "not_authorized" if outcome in {"deny", "denied", "not_authorized"} else ("unknown" if record_kind == "authorization" else "reduced")
                rendered = _legacy_payload_json(data)
                _insert_or_validate_legacy(
                    connection,
                    "canonical_tenants",
                    {
                        "id": tenant,
                        "schema_version": CANONICAL_SCHEMA_VERSION,
                        "name": _legacy_text(
                            data.get("tenant_id") or tenant, limit=300
                        ),
                        "created_at": _now(),
                        "metadata_json": '{"legacy":true}',
                    },
                    identity_columns=("id",),
                    label="tenant",
                )
                was_inserted = _insert_or_validate_legacy(
                    connection,
                    "canonical_legacy_records",
                    {
                        "tenant_id": tenant,
                        "record_kind": record_kind,
                        "legacy_id": legacy_id,
                        "claim_state": claim_state,
                        "schema_version": CANONICAL_SCHEMA_VERSION,
                        "payload_json": rendered,
                        "migrated_at": _now(),
                    },
                    identity_columns=("tenant_id", "record_kind", "legacy_id"),
                    label="archive record",
                )
                count += int(was_inserted)
        return count


def upgrade(bind: Engine | Connection, target: str | None = None, **kwargs: Any) -> str | None:
    return MigrationManager(bind).upgrade(target, **kwargs)


def downgrade(bind: Engine | Connection, target: str | None = None) -> str | None:
    return MigrationManager(bind).downgrade(target)


def recover(bind: Engine | Connection) -> str | None:
    return MigrationManager(bind).recover()


def current_version(bind: Engine | Connection) -> str | None:
    return MigrationManager(bind).current_version()


def migration_versions() -> tuple[str, ...]:
    return tuple(m.version for m in sorted(MIGRATIONS, key=lambda item: item.order))


__all__ = [
    "CANONICAL_MIGRATION_PREFIX", "CANONICAL_SCHEMA_VERSION", "CURRENT_SCHEMA_VERSION", "EVIDENCE_SCHEMA_VERSION", "JOB_STATE_SCHEMA_VERSION",
    "JOURNAL_TABLE", "MIGRATIONS", "Migration", "MigrationError", "MigrationInterruptedError",
    "MigrationManager", "UnsupportedMigrationError", "current_version", "downgrade", "migration_versions",
    "archive_legacy_records", "recover", "upgrade",
]
