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
from datetime import datetime, timezone
from typing import Any, Mapping

from sqlalchemy import Connection, Engine, event

from common.redaction import redact_value


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
_LEGACY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+\-]{0,127}$")


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
CURRENT_SCHEMA_VERSION = CANONICAL_SCHEMA_VERSION
JOURNAL_TABLE = "canonical_migration_journal"


class MigrationError(RuntimeError):
    """A canonical migration could not be applied or reversed."""


class MigrationInterruptedError(MigrationError):
    """A deliberately interrupted migration remains recoverable."""


class UnsupportedMigrationError(MigrationError):
    """A requested schema boundary is not supported."""


def _normalize_legacy_records_in_transaction(connection: Connection) -> int:
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
    known = {
        name: [str(row[1]) for row in connection.exec_driver_sql(
            f"PRAGMA table_info({name})"
        ).fetchall()]
        for name in (
            "authorization_decisions", "audit_logs", "scan_jobs", "findings"
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
    authorized_job_keys: set[str] = set()

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
        connection.exec_driver_sql(
            "INSERT OR IGNORE INTO canonical_tenants"
            "(id,schema_version,name,created_at,metadata_json) VALUES(?,?,?,?,?)",
            (value, CANONICAL_SCHEMA_VERSION, _legacy_text(source or value, limit=300), _now(), "{}"),
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
        connection.exec_driver_sql(
            "INSERT OR IGNORE INTO canonical_engagements"
            "(id,tenant_id,project_id,schema_version,name,status,created_at,metadata_json)"
            " VALUES(?,?,?,?,?,?,?,?)",
            (
                identifier,
                tenant,
                None,
                CANONICAL_SCHEMA_VERSION,
                _legacy_text(source or fallback, limit=300),
                "unknown" if reduced else "planned",
                _now(),
                metadata,
            ),
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
        connection.exec_driver_sql(
            "INSERT OR IGNORE INTO canonical_operators"
            "(id,tenant_id,schema_version,display_name,external_ref,created_at,metadata_json)"
            " VALUES(?,?,?,?,?,?,?)",
            (
                identifier,
                tenant,
                CANONICAL_SCHEMA_VERSION,
                _legacy_text(source or fallback, limit=200),
                None,
                _now(),
                '{"legacy":true}',
            ),
        )
        return identifier

    def role(tenant: str, source: Any) -> str:
        identifier = _canonical_legacy_key(source or "legacy-role", kind="role", tenant_id=tenant)
        key = (tenant, identifier)
        role_ids.setdefault(key, identifier)
        connection.exec_driver_sql(
            "INSERT OR IGNORE INTO canonical_roles"
            "(id,tenant_id,schema_version,name,created_at,metadata_json)"
            " VALUES(?,?,?,?,?,?)",
            (identifier, tenant, CANONICAL_SCHEMA_VERSION, _legacy_text(source or "legacy-role", limit=100), _now(), '{"legacy":true}'),
        )
        return identifier

    def module_version(tenant: str, module: Any, *, version: Any = "legacy") -> str:
        module_name = _legacy_text(module or "legacy-module", default="legacy-module", limit=200)
        version_name = _legacy_text(version or "legacy", default="legacy", limit=100)
        identity = f"{module_name}:{version_name}"
        identifier = _canonical_legacy_key(identity, kind="module-version", tenant_id=tenant)
        key = (tenant, identifier)
        module_ids.setdefault(key, identifier)
        connection.exec_driver_sql(
            "INSERT OR IGNORE INTO canonical_module_versions"
            "(id,tenant_id,schema_version,module_id,version,module_kind,manifest_digest,policy_version,"
            "intelligence_snapshot_id,check_pack_snapshot_id,provenance_id,created_at,metadata_json)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                identifier,
                tenant,
                CANONICAL_SCHEMA_VERSION,
                module_name,
                version_name,
                "legacy",
                None,
                "legacy",
                None,
                None,
                None,
                _now(),
                '{"legacy":true}',
            ),
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
        connection.exec_driver_sql(
            "INSERT OR IGNORE INTO canonical_assets"
            "(id,tenant_id,schema_version,kind,identity_key,display_name,canonical_uri,created_at,metadata_json)"
            " VALUES(?,?,?,?,?,?,?,?,?)",
            (
                identifier,
                tenant,
                CANONICAL_SCHEMA_VERSION,
                kind,
                identity,
                raw[:2000],
                raw if kind == "url" else None,
                _now(),
                '{"legacy":true}',
            ),
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
        connection.exec_driver_sql(
            "INSERT OR IGNORE INTO canonical_jobs"
            "(id,tenant_id,engagement_id,schema_version,job_kind,status,created_at,metadata_json)"
            " VALUES(?,?,?,?,?,?,?,?)",
            (
                identifier,
                tenant,
                engagement_id,
                CANONICAL_SCHEMA_VERSION,
                _legacy_text(module or "legacy", default="legacy", limit=100),
                mapped_status,
                _now(),
                json.dumps({"legacy": True, "claim_state": "reduced" if reduced else "complete"}, separators=(",", ":")),
            ),
        )
        existing = connection.exec_driver_sql(
            "SELECT engagement_id FROM canonical_jobs WHERE tenant_id=? AND id=?",
            (tenant, identifier),
        ).fetchone()
        if existing is not None:
            engagement_id = str(existing[0])
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
        connection.exec_driver_sql(
            "INSERT OR IGNORE INTO canonical_observations"
            "(id,tenant_id,engagement_id,job_id,module_version_id,module_execution_id,asset_id,action_id,"
            "intelligence_snapshot_id,provenance_id,schema_version,status,observed_at,created_at,metadata_json)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                identifier,
                tenant,
                engagement_id,
                job_id,
                module_id,
                None,
                asset_id,
                None,
                None,
                None,
                CANONICAL_SCHEMA_VERSION,
                "not_authorized" if reduced else status,
                _now(),
                _now(),
                json.dumps({"legacy": True, "claim_state": "reduced" if reduced else "complete"}, separators=(",", ":")),
            ),
        )
        return identifier

    # Authorization decisions are normalized first so their engagement,
    # operator, role, and decision truth can be reused by jobs/actions.
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
        complete = bool(
            tenant_complete
            and isinstance(raw_decision, str)
            and _LEGACY_ID_RE.fullmatch(raw_decision.strip())
            and isinstance(raw_engagement, str)
            and _LEGACY_ID_RE.fullmatch(raw_engagement.strip())
            and isinstance(raw_operator, str)
            and _LEGACY_ID_RE.fullmatch(raw_operator.strip())
            and _redact_legacy(raw_decision) == raw_decision
            and _redact_legacy(raw_engagement) == raw_engagement
            and _redact_legacy(raw_operator) == raw_operator
            and data.get("scope_policy_version")
            and outcome in {"allow", "deny"}
        )
        if not complete and outcome == "allow":
            outcome = "unknown"
        if complete and outcome == "allow" and data.get("job_id"):
            authorized_job_keys.add(
                f"{tenant}\x00{str(data.get('job_id')).strip()}"
            )
        scope_ids[(tenant, str(raw_decision or decision_id))] = decision_id
        connection.exec_driver_sql(
            "INSERT OR IGNORE INTO canonical_scope_decisions"
            "(id,tenant_id,engagement_id,operator_id,role_id,schema_version,outcome,policy_version,"
            "decision_reason,decided_at,created_at,metadata_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                decision_id,
                tenant,
                engagement_id,
                operator_id,
                role_id,
                CANONICAL_SCHEMA_VERSION,
                outcome,
                _legacy_text(data.get("scope_policy_version") or "legacy-unknown", default="legacy-unknown", limit=100),
                _legacy_text(data.get("scope_reason_code") or data.get("reason_code") or "legacy-reduced", default="legacy-reduced", limit=2000),
                _legacy_timestamp(data.get("issued_at") or data.get("timestamp")),
                _legacy_timestamp(data.get("recorded_at") or data.get("issued_at")),
                json.dumps({"legacy": True, "claim_state": "complete" if complete else "unknown"}, separators=(",", ":")),
            ),
        )
        raw_action = data.get("action_id")
        if raw_action:
            action_id = _canonical_legacy_key(raw_action, kind="action", tenant_id=tenant)
            job_source = data.get("job_id") or data.get("run_id") or f"{decision_id}-job"
            job_id, job_engagement, module_id, asset_id, _ = job(
                tenant,
                job_source,
                engagement_source=raw_engagement or engagement_id,
                target=data.get("resolved_target") or data.get("requested_target") or decision_id,
                module=data.get("module_id") or data.get("engine") or "legacy-module",
                status="planned",
                reduced=not complete,
            )
            action_engagement = job_engagement
            connection.exec_driver_sql(
                "INSERT OR IGNORE INTO canonical_actions"
                "(id,tenant_id,engagement_id,job_id,schema_version,action_kind,authorization_decision_id,created_at,metadata_json)"
                " VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    action_id,
                    tenant,
                    action_engagement,
                    job_id,
                    CANONICAL_SCHEMA_VERSION,
                    _legacy_text(data.get("action_kind") or "legacy-action", default="legacy-action", limit=100),
                    decision_id if action_engagement == engagement_id else None,
                    _now(),
                    json.dumps({"legacy": True, "claim_state": "complete" if complete else "unknown"}, separators=(",", ":")),
                ),
            )

    # Jobs are normalized even when no authorization row exists.  Such rows
    # receive ``unknown_not_authorized`` and a reduced observation, never an
    # implicit allow.
    for data in rows.get("scan_jobs", []):
        tenant, tenant_complete = canonical_tenant(data)
        modules = _legacy_json_list(data.get("modules"))
        module = modules[0] if modules else data.get("framework") or "legacy-module"
        raw_auth_state = str(data.get("authorization_state") or "").lower()
        # A client-controlled ``authorization_state=allow`` is not itself
        # evidence of a Gate-0 decision.  Only a normalized, complete allow
        # decision from the same tenant/job can lift a legacy job out of the
        # fail-closed reduced state.
        reduced = (
            not tenant_complete
            or (
                f"{tenant}\x00{str(data.get('id') or data.get('job_id') or '').strip()}"
                not in authorized_job_keys
            )
        )
        job_id, engagement_id, module_id, asset_id, mapped_status = job(
            tenant,
            data.get("id") or data.get("job_id"),
            engagement_source=data.get("engagement") or data.get("engagement_id"),
            target=data.get("target") or "legacy-target",
            module=module,
            status=data.get("status"),
            reduced=reduced,
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

    # Findings get a complete source observation and opaque artifact reference
    # whenever their legacy row contains a usable target/module.  Missing
    # lineage is retained as ``unknown`` metadata and never as verified truth.
    for data in rows.get("findings", []):
        tenant, tenant_complete = canonical_tenant(data)
        raw_finding = data.get("id") or data.get("finding_id") or data.get("dedup_key")
        finding_id = _canonical_legacy_key(raw_finding or "legacy", kind="finding", tenant_id=tenant)
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
        digest = _legacy_digest(data)
        connection.exec_driver_sql(
            "INSERT OR IGNORE INTO canonical_artifact_refs"
            "(id,tenant_id,observation_id,schema_version,reference,digest,media_type,size,redaction_state,encryption_state,collected_at,created_at,metadata_json)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                artifact_id,
                tenant,
                obs_id,
                CANONICAL_SCHEMA_VERSION,
                f"artifact:{artifact_id}",
                digest,
                "application/json",
                0,
                "redacted",
                "reference_only",
                _legacy_timestamp(data.get("discovered_at")),
                _legacy_timestamp(data.get("discovered_at")),
                json.dumps({"legacy": True, "claim_state": "complete" if complete else "reduced"}, separators=(",", ":")),
            ),
        )
        severity = str(data.get("severity") or "informational").lower()
        if severity not in {"critical", "high", "medium", "low", "informational"}:
            severity = "informational"
        status = str(data.get("status") or "unknown").lower()
        if status not in {"open", "verified", "false_positive", "remediated", "unknown"} or not complete:
            status = "unknown"
        connection.exec_driver_sql(
            "INSERT OR IGNORE INTO canonical_findings"
            "(id,tenant_id,observation_id,artifact_id,schema_version,title,severity,description,status,finding_key,created_at,metadata_json)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                finding_id,
                tenant,
                obs_id,
                artifact_id,
                CANONICAL_SCHEMA_VERSION,
                _legacy_text(data.get("title") or "legacy finding", default="legacy finding", limit=500),
                severity,
                _legacy_text(data.get("description") or "Legacy finding with reduced context", default="Legacy finding with reduced context", limit=8000),
                status,
                _legacy_text(data.get("dedup_key") or "", default="", limit=300) or None,
                _legacy_timestamp(data.get("discovered_at")),
                json.dumps({"legacy": True, "claim_state": "complete" if complete else "reduced"}, separators=(",", ":")),
            ),
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
        connection.exec_driver_sql(
            "INSERT OR IGNORE INTO canonical_events"
            "(id,tenant_id,job_id,actor_id,schema_version,event_type,level,created_at,metadata_json)"
            " VALUES(?,?,?,?,?,?,?,?,?)",
            (
                event_id,
                tenant,
                job_id,
                actor_id,
                CANONICAL_SCHEMA_VERSION,
                _legacy_text(data.get("action") or "legacy.audit", default="legacy.audit", limit=160),
                level,
                _legacy_timestamp(data.get("timestamp")),
                json.dumps({"legacy": True, "claim_state": "complete" if tenant_complete else "reduced"}, separators=(",", ":")),
            ),
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
                    connection.exec_driver_sql(
                        "INSERT OR IGNORE INTO canonical_tenants(id,schema_version,name,created_at,metadata_json) VALUES(?,?,?,?,?)",
                        (tenant, CANONICAL_SCHEMA_VERSION, tenant, _now(), "{}"),
                    )
                    result = connection.exec_driver_sql(
                        "INSERT OR IGNORE INTO canonical_legacy_records(tenant_id,record_kind,legacy_id,claim_state,schema_version,payload_json,migrated_at) VALUES(?,?,?,?,?,?,?)",
                        (tenant, record_kind, legacy_id, claim_state, CANONICAL_SCHEMA_VERSION, rendered, _now()),
                    )
                    count += int(result.rowcount or 0)
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


def _runtime_guard_sql() -> tuple[str, ...]:
    """Return safety guards that must also repair already-applied schemas."""
    digest_tables = (
        ("canonical_provenance", "provenance"),
        ("canonical_feed_snapshots", "feed snapshot"),
        ("canonical_check_pack_snapshots", "check-pack snapshot"),
    )
    statements: list[str] = [
        _MODULE_VERSION_IMMUTABILITY_GUARD,
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
            WHEN NOT (""" + _sha256_guard("NEW.digest") + """)
            BEGIN SELECT RAISE(ABORT, 'artifact digest must be sha256:<64 lowercase hex>'); END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS canonical_artifact_digest_guard_update
            BEFORE UPDATE OF digest ON canonical_artifact_refs
            WHEN NOT (""" + _sha256_guard("NEW.digest") + """)
            BEGIN SELECT RAISE(ABORT, 'artifact digest must be sha256:<64 lowercase hex>'); END
            """,
        )
    )
    return tuple(statements)


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
            source_type TEXT NOT NULL CHECK(source_type IN ('intelligence_source','feed_snapshot','check_pack_snapshot','legacy')),
            source_id TEXT NOT NULL,
            digest TEXT NOT NULL CHECK(source_type='legacy' OR digest GLOB 'sha256:*'),
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
            digest TEXT NOT NULL CHECK(digest GLOB 'sha256:*'),
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
              SELECT 1 FROM canonical_feed_snapshots WHERE tenant_id=NEW.tenant_id AND id=NEW.source_id)
            THEN RAISE(ABORT, 'canonical provenance feed is missing')
            WHEN NEW.source_type='check_pack_snapshot' AND NOT EXISTS(
              SELECT 1 FROM canonical_check_pack_snapshots WHERE tenant_id=NEW.tenant_id AND id=NEW.source_id)
            THEN RAISE(ABORT, 'canonical provenance check pack is missing')
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


MIGRATIONS: tuple[Migration, ...] = (
    Migration(
        version=CANONICAL_SCHEMA_VERSION,
        order=101,
        upgrade_sql=_table_sql(),
        downgrade_sql=_drop_sql(),
        description="Task 101 canonical tenant-safe data contracts",
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

    def current_version(self) -> str | None:
        connection, owned = self._connection()
        try:
            _ensure_journal(connection)
            if connection.in_transaction():
                connection.commit()
            row = connection.exec_driver_sql(
                f"SELECT version FROM {JOURNAL_TABLE} WHERE state='applied' ORDER BY rowid DESC LIMIT 1"
            ).fetchone()
            return str(row[0]) if row else None
        finally:
            if owned:
                connection.close()

    @property
    def schema_version(self) -> str | None:
        return self.current_version()

    def journal(self) -> list[dict[str, Any]]:
        connection, owned = self._connection()
        try:
            _ensure_journal(connection)
            if connection.in_transaction():
                connection.commit()
            return [dict(row._mapping) for row in connection.exec_driver_sql(f"SELECT * FROM {JOURNAL_TABLE} ORDER BY rowid").fetchall()]
        finally:
            if owned:
                connection.close()

    def recover(self) -> str | None:
        """Replay any applying/failed step and return the resulting version."""
        connection, owned = self._connection()
        try:
            _ensure_journal(connection)
            if connection.in_transaction():
                connection.commit()
            pending = connection.exec_driver_sql(
                f"SELECT version FROM {JOURNAL_TABLE} WHERE state IN ('applying','failed') ORDER BY rowid LIMIT 1"
            ).fetchone()
            if connection.in_transaction():
                connection.commit()
            if pending:
                return self._apply_one(connection, _migration_by_version(str(pending[0])))
            return self.current_version()
        finally:
            if owned:
                connection.close()

    def upgrade(self, target: str | None = None, *, fail_after: int | None = None) -> str | None:
        target = target or (self.versions[-1] if self.versions else None)
        if target is None or target not in self.versions:
            raise UnsupportedMigrationError(f"unsupported upgrade target {target}")
        connection, owned = self._connection()
        try:
            _ensure_journal(connection)
            if connection.in_transaction():
                connection.commit()
            self._recover_on_connection(connection)
            applied = {str(row[0]) for row in connection.exec_driver_sql(f"SELECT version FROM {JOURNAL_TABLE} WHERE state='applied'").fetchall()}
            if connection.in_transaction():
                connection.commit()
            # SQLAlchemy's SQLite connection autobegins for the read above.
            # Close that read transaction before ``_apply_one`` opens its
            # explicit journal/work transactions; otherwise a fresh
            # connection raises ``InvalidRequestError`` and database
            # initialization fails before the canonical tables are created.
            if connection.in_transaction():
                connection.commit()
            for index, migration in enumerate(sorted(MIGRATIONS, key=lambda item: item.order)):
                if migration.version in applied:
                    if migration.version == target:
                        break
                    continue
                self._apply_one(connection, migration, fail_after=fail_after if index == 0 else None)
                if migration.version == target:
                    break
            # Repair safety triggers on databases that already recorded the
            # canonical migration before a later guard was introduced.  This
            # keeps the migration boundary idempotent without rewriting the
            # canonical contract/schema version or touching legacy tables.
            if connection.in_transaction():
                connection.commit()
            with connection.begin():
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

    def _recover_on_connection(self, connection: Connection) -> None:
        row = connection.exec_driver_sql(
            f"SELECT version FROM {JOURNAL_TABLE} WHERE state IN ('applying','failed') ORDER BY rowid LIMIT 1"
        ).fetchone()
        if connection.in_transaction():
            connection.commit()
        if row:
            self._apply_one(connection, _migration_by_version(str(row[0])))

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
                        referenced = {name for name in ("findings", "scan_jobs", "audit_logs", "authorization_decisions") if name in lowered}
                        if referenced - legacy_tables:
                            continue
                    connection.exec_driver_sql(statement)
                    if fail_after is not None and index >= fail_after:
                        raise MigrationInterruptedError(f"migration interrupted at {migration.version}:{index}")
                # Normalize existing Gate-0 rows before retaining the bounded
                # diagnostic archive.  The archive is not the canonical
                # relationship model; it preserves reduced/unknown truth and
                # redacted source payloads for auditability.
                _normalize_legacy_records_in_transaction(connection)
                self._archive_legacy_records_in_transaction(connection)
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
                connection.exec_driver_sql(
                    "INSERT OR IGNORE INTO canonical_tenants(id,schema_version,name,created_at,metadata_json) VALUES(?,?,?,?,?)",
                    (tenant, CANONICAL_SCHEMA_VERSION, tenant, _now(), "{}"),
                )
                result = connection.exec_driver_sql(
                    "INSERT OR IGNORE INTO canonical_legacy_records(tenant_id,record_kind,legacy_id,claim_state,schema_version,payload_json,migrated_at) VALUES(?,?,?,?,?,?,?)",
                    (tenant, record_kind, legacy_id, claim_state, CANONICAL_SCHEMA_VERSION, rendered, _now()),
                )
                count += int(result.rowcount or 0)
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
    "CANONICAL_MIGRATION_PREFIX", "CANONICAL_SCHEMA_VERSION", "CURRENT_SCHEMA_VERSION",
    "JOURNAL_TABLE", "MIGRATIONS", "Migration", "MigrationError", "MigrationInterruptedError",
    "MigrationManager", "UnsupportedMigrationError", "current_version", "downgrade", "migration_versions",
    "archive_legacy_records", "recover", "upgrade",
]
