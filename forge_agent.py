#!/usr/bin/env python3
"""Forge passive scan agent.

Registers with the dashboard, polls for scoped jobs, and submits redacted
results. The default execution mode is dry-run only; active scanner launch
requires both a queued non-dry-run job and --allow-active-scans locally.
"""
from __future__ import annotations

import argparse
import ctypes
import hmac
import json
import os
import platform
import signal
import socket
import ssl
import subprocess
import sys
import time
import uuid
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib import request, error
from urllib.parse import urlparse

from common.action_authorization import (
    AUTHORIZATION_DB_ENV,
    AUTHORIZATION_ENVELOPES_ENV,
    ActionAuthorizationEnvelope,
    AuthorizationContext,
    AuthorizationReason,
    ConfirmationMethod,
    OperatorRole,
    SafetyMode,
    authorization_runtime_environment_from_facts,
    consume_authorization,
    default_authorization_db_path,
    derive_authorization,
    encode_authorization_envelopes,
    load_authorization_runtime_facts,
    module_set_binding,
    open_authorization_session,
    redact_authorization_value,
    record_boundary_denial,
    record_authorization_denial,
)
from common.confirm_gate import (
    ActionConfirmation,
    LAUNCH_ACTION_ENV,
    LAUNCH_CONFIRMATIONS_ENV,
    LAUNCH_JOB_ID_ENV,
    decide_action,
    encode_launch_confirmations,
)
from common.db import (
    PersistedRunTruthValidationError,
    create_db,
    load_run_collection_truth,
)
from common.scope import ScopeDecision, ScopeReason, decision_for_reason, decide_scope
from common.canonical_evidence import JOB_ATTEMPT_ID_ENV
from common.job_state import (
    JobStateService,
    LeaseError,
    ProcessIdentity,
    ProcessIdentityError,
    TransitionActor,
)
from common.dashboard.server import _DashboardProcessSupervisor
from common.outbound_policy import (
    OutboundDenied,
    OutboundReason,
    scrub_proxy_environment,
)


_DEFAULT_URLOPEN = request.urlopen


class _NoRedirectHandler(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


class LeaseHeartbeatLost(RuntimeError):
    """The current assignment lease could not be renewed while work was active."""


def _install_parent_death_signal(parent_pid: int) -> None:
    """Kill a not-yet-registered Linux child if its Forge-agent parent dies."""

    if os.name != "posix" or not Path("/proc/self").exists():
        raise OSError("parent-death containment is unavailable")
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, "PR_SET_PDEATHSIG failed")
    if os.getppid() != parent_pid:
        os.kill(os.getpid(), signal.SIGKILL)


def _json_request(
    base_url: str,
    path: str,
    *,
    method: str = "GET",
    payload: dict[str, Any] | None = None,
    token: str = "",
    timeout: float = 15.0,
    ssl_context: ssl.SSLContext | None = None,
    outbound_policy: Any = None,
    bootstrap: bool = False,
) -> dict[str, Any]:
    # Agent control-plane traffic requires its own consumed destination policy;
    # scan scope is not authority for the dashboard origin.  The legacy urllib
    # path remains unreachable until registration/poll/result are migrated to
    # the pinned canonical client.
    raise OutboundDenied(OutboundReason.OUTBOUND_POLICY_UNSUPPORTED)

    parsed_base = urlparse(base_url)
    if (
        parsed_base.scheme.lower() not in {"http", "https"}
        or not parsed_base.hostname
        or parsed_base.username is not None
        or parsed_base.password is not None
        or parsed_base.path not in {"", "/"}
        or parsed_base.query
        or parsed_base.fragment
    ):
        raise ValueError("dashboard URL must be one HTTP(S) origin without userinfo")
    body = json.dumps(payload or {}).encode("utf-8") if payload is not None else None
    headers = {"Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers[
            "X-Forge-Agent-Token" if bootstrap else "X-Forge-Agent-Credential"
        ] = token
    req = request.Request(
        base_url.rstrip("/") + path,
        data=body,
        headers=headers,
        method=method,
    )
    urlopen_kwargs: dict[str, Any] = {"timeout": timeout}
    if ssl_context is not None:
        urlopen_kwargs["context"] = ssl_context
    try:
        if request.urlopen is not _DEFAULT_URLOPEN:
            response = request.urlopen(req, **urlopen_kwargs)
        else:
            handlers: list[Any] = [_NoRedirectHandler()]
            if ssl_context is not None:
                handlers.append(request.HTTPSHandler(context=ssl_context))
            response = request.build_opener(*handlers).open(req, timeout=timeout)
        with response as resp:
            raw = resp.read().decode("utf-8", "replace")
            return json.loads(raw) if raw else {}
    except error.HTTPError as exc:
        # The response body is remote-controlled and may contain reflected
        # credentials or authorization material.  Keep only the status class.
        raise RuntimeError(f"dashboard HTTP {exc.code}") from exc


def _validate_tls_options(args: argparse.Namespace) -> None:
    if getattr(args, "client_key", "") and not getattr(args, "client_cert", ""):
        raise ValueError("--client-key requires --client-cert")


def _build_ssl_context(base_url: str, args: argparse.Namespace) -> ssl.SSLContext | None:
    _validate_tls_options(args)
    parsed = urlparse(base_url)
    tls_requested = any(
        (
            getattr(args, "client_cert", ""),
            getattr(args, "client_key", ""),
            getattr(args, "ca_cert", ""),
            getattr(args, "insecure_tls", False),
        )
    )
    if parsed.scheme.lower() != "https" or not tls_requested:
        return None

    context = ssl.create_default_context(cafile=getattr(args, "ca_cert", "") or None)
    if getattr(args, "insecure_tls", False):
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    if getattr(args, "client_cert", ""):
        context.load_cert_chain(
            certfile=args.client_cert,
            keyfile=getattr(args, "client_key", "") or None,
        )
    return context


def _agent_payload(args: argparse.Namespace) -> dict[str, Any]:
    excluded_scope = _scope_argument_values(getattr(args, "exclude", []))
    return {
        "agent_id": args.agent_id,
        "name": args.name or args.agent_id,
        "version": "0.1.0",
        "host": socket.gethostname(),
        "platform": platform.platform(),
        "engines": [item.strip() for item in args.engines.split(",") if item.strip()],
        "capabilities": ["dry_run", "result_streaming", "scoped_jobs"],
        "scope": _scope_argument_values(args.scope),
        "excluded_scope": excluded_scope,
        "active_scan_enabled": args.allow_active_scans,
    }


def _argument_values(value: Any) -> list[str]:
    if isinstance(value, str):
        values = value.split(",")
    elif isinstance(value, list):
        values = value
    else:
        return []
    return [str(item).strip() for item in values if str(item).strip()]


def _scope_argument_values(value: Any) -> list[str]:
    """Preserve malformed scope values so the shared parser can deny them."""
    if isinstance(value, str):
        return [item.strip() for item in value.split(",")]
    if isinstance(value, list):
        if not all(isinstance(item, str) for item in value):
            return ["*"]
        values: list[str] = []
        for item in value:
            values.extend(part.strip() for part in item.split(","))
        return values
    return ["*"] if value is not None else []


def _registration_scope_decision(args: argparse.Namespace) -> ScopeDecision:
    allowed_scope = _scope_argument_values(getattr(args, "scope", []))
    excluded_scope = _scope_argument_values(getattr(args, "exclude", []))
    if not allowed_scope:
        return decide_scope("", allowed_scope, excluded_scope)
    decision = decide_scope(allowed_scope[0], allowed_scope, excluded_scope)
    if decision.reason_code in {
        ScopeReason.MISSING_SCOPE.value,
        ScopeReason.MALFORMED_SCOPE.value,
        ScopeReason.MALFORMED_TARGET.value,
    }:
        return decision
    return decision_for_reason(ScopeReason.ALLOWED)


def _module_argument_values(value: Any) -> list[str] | None:
    """Return bounded module names without coercing attacker-controlled values."""
    if value is None:
        return []
    if isinstance(value, str):
        values = value.split(",")
    elif isinstance(value, list) and all(isinstance(item, str) for item in value):
        values = value
    else:
        return None
    modules = [item.strip() for item in values if item.strip()]
    if len(modules) > 1000 or any(len(item) > 200 for item in modules):
        return None
    return modules


def _job_authorization_db(job: dict[str, Any]) -> Path | None:
    """Resolve only configured or local Forge authorization database paths."""
    configured = os.environ.get(AUTHORIZATION_DB_ENV, "").strip()
    raw = str(job.get("authorization_db") or "").strip()
    if configured:
        configured_path = Path(configured).expanduser().resolve()
        if raw and Path(raw).expanduser().resolve() != configured_path:
            return None
        return configured_path
    if not raw:
        return None
    path = Path(raw).expanduser().resolve()
    roots = (
        Path(__file__).resolve().parent,
        Path.home() / ".local" / "state" / "forge-suite",
    )
    if not any(path == root or path.is_relative_to(root) for root in roots):
        return None
    return path


def _active_job_database(job: dict[str, Any]) -> Path | None:
    """Require the exact server-delivered local SQLite authority for active work."""

    raw = str(job.get("authorization_db") or "").strip()
    if not raw:
        return None
    raw_path = Path(raw).expanduser()
    if raw_path.is_symlink():
        return None
    resolved = _job_authorization_db(job)
    if resolved is None or resolved != raw_path.resolve():
        return None
    try:
        metadata = resolved.stat()
    except OSError:
        return None
    if not resolved.is_file() or resolved.is_symlink() or metadata.st_nlink != 1:
        return None
    if metadata.st_mode & 0o077:
        return None
    return resolved


def _verified_active_run_truth_id(
    job: dict[str, Any],
    engine: str,
    database: Path,
) -> str | None:
    """Return only an exact persisted, signed truth for this assignment."""

    tenant_id = str(job.get("tenant_id") or "").strip()
    job_id = str(job.get("id") or "").strip()
    authorization_run_id = str(job.get("run_id") or "").strip()
    framework = str(engine or "").strip().lower()
    if not all((tenant_id, job_id, authorization_run_id, framework)):
        return None
    run_truth_id = f"{authorization_run_id}:{framework}"
    session = create_db(database)
    try:
        try:
            truth = load_run_collection_truth(
                session,
                run_truth_id,
                tenant_id=tenant_id,
            )
        except PersistedRunTruthValidationError:
            return None
        if (
            truth is None
            or truth.tenant_id != tenant_id
            or truth.job_id != job_id
            or truth.authorization_run_id != authorization_run_id
            or truth.framework != framework
        ):
            return None
        return truth.run_id
    finally:
        session.close()


def _job_runtime_facts(job: dict[str, Any]) -> dict[str, str]:
    """Validate server-generated runtime facts without consulting the envelope."""
    raw = job.get("runtime_context")
    if not isinstance(raw, dict):
        return {}
    try:
        environment = authorization_runtime_environment_from_facts(raw)
    except ValueError:
        return {}
    return load_authorization_runtime_facts(environment)


def _audit_agent_denial(
    job: dict[str, Any],
    decision: ScopeDecision,
    *,
    allowed_scope: Any,
    excluded_scope: Any,
) -> None:
    """Persist one safe local-agent denial before returning to the server."""
    runtime = _job_runtime_facts(job)
    session = open_authorization_session(_job_authorization_db(job))
    try:
        record_boundary_denial(
            session=session,
            reason_code=decision.reason_code,
            action_kind=job.get("action", "scan"),
            engine=job.get("engine", "forge-agent"),
            target=job.get("target"),
            allowed_scope=allowed_scope,
            excluded_scope=excluded_scope,
            tenant_id=runtime.get("tenant_id", "default"),
            engagement_id=runtime.get("engagement_id", "agent-preflight"),
            run_id=runtime.get("run_id", "agent-preflight-run"),
            job_id=job.get("id", "agent-preflight-job"),
            operator_id=runtime.get("operator_id", "forge-agent"),
            operator_role=runtime.get("operator_role", OperatorRole.AGENT.value),
            module_id=module_set_binding(
                _module_argument_values(job.get("modules", [])) or []
            ),
            scope_policy_version=runtime.get(
                "scope_policy_version",
                "scope-policy-v1",
            ),
            safety_mode=job.get("safety_mode", SafetyMode.ACTIVE.value),
        )
    finally:
        session.close()


def _durable_agent_process_context(
    job: dict[str, Any],
    database: Path,
    supervisor: Any,
) -> tuple[JobStateService, dict[str, str]]:
    """Bind one active helper launch to the exact co-resident durable attempt."""

    runtime = _job_runtime_facts(job)
    values = {
        "tenant_id": str(job.get("tenant_id") or runtime.get("tenant_id") or "").strip(),
        "job_id": str(job.get("id") or "").strip(),
        "attempt_id": str(job.get("attempt_id") or "").strip(),
        "worker_id": str(job.get("agent_id") or "").strip(),
        "lease_token": str(job.get("lease_token") or "").strip(),
        "delivery_idempotency_key": str(
            job.get("delivery_idempotency_key") or ""
        ).strip(),
        "attempt_run_id": str(job.get("attempt_run_id") or "").strip(),
        "authorization_id": str(job.get("authorization_id") or "").strip(),
        "identity_key": str(job.get("process_identity_key") or "").strip(),
        "launch_nonce": str(job.get("process_launch_nonce") or "").strip(),
        "control_boot_id": str(
            job.get("process_control_boot_id") or ""
        ).strip(),
    }
    if any(not item for item in values.values()):
        raise ProcessIdentityError("active agent job lacks durable process identity")
    boot_reader = getattr(supervisor, "_boot_id", None)
    local_boot_id = str(boot_reader() if callable(boot_reader) else "").strip()
    if not local_boot_id or not hmac.compare_digest(
        local_boot_id,
        values["control_boot_id"],
    ):
        raise ProcessIdentityError("active agent is outside the leased control boot")

    service = JobStateService(database, process_supervisor=supervisor)
    try:
        durable_job = service.get_job(
            values["job_id"],
            tenant_id=values["tenant_id"],
        )
        if durable_job is None or not hmac.compare_digest(
            str(durable_job.get("assigned_agent_id") or ""),
            values["worker_id"],
        ):
            raise ProcessIdentityError("active agent does not own the durable job")
        attempts = service.list_attempts(
            values["job_id"],
            tenant_id=values["tenant_id"],
        )
        attempt = next(
            (
                item
                for item in attempts
                if hmac.compare_digest(
                    str(item.get("id") or ""),
                    values["attempt_id"],
                )
            ),
            None,
        )
        if attempt is None:
            raise ProcessIdentityError("active agent attempt is not durable")
        expected = {
            "worker_id": values["worker_id"],
            "control_boot_id": values["control_boot_id"],
            "delivery_idempotency_key": values["delivery_idempotency_key"],
            "run_id": values["attempt_run_id"],
            "authorization_decision_id": values["authorization_id"],
        }
        if any(
            not hmac.compare_digest(str(attempt.get(key) or ""), value)
            for key, value in expected.items()
        ):
            raise ProcessIdentityError("active agent attempt binding is inconsistent")
        if not service.validate_lease(
            values["attempt_id"],
            values["lease_token"],
            tenant_id=values["tenant_id"],
            worker_id=values["worker_id"],
        ):
            raise LeaseError("active agent lease is not current")
        intent = service.reserve_process(
            values["job_id"],
            values["attempt_id"],
            values["identity_key"],
            lease_token=values["lease_token"],
            worker_id=values["worker_id"],
            control_boot_id=values["control_boot_id"],
            expected_launch_nonce=values["launch_nonce"],
            tenant_id=values["tenant_id"],
            actor=TransitionActor(
                tenant_id=values["tenant_id"],
                actor_id=values["worker_id"],
                role="agent",
                authorization_decision_id=values["authorization_id"],
            ),
        )
        if str(intent.get("state") or "") != "reserved":
            raise ProcessIdentityError("active agent child was already delivered")
        if any(
            str(row.get("attempt_id") or "") == values["attempt_id"]
            and str(row.get("identity_key") or "") == values["identity_key"]
            for row in service.list_processes(
                values["job_id"],
                tenant_id=values["tenant_id"],
            )
        ):
            raise ProcessIdentityError("active agent child is already registered")
        return service, values
    except BaseException:
        service.close()
        raise


def _safe_job_result(
    job: dict[str, Any],
    allow_active_scans: bool,
    *,
    local_scope: Any,
    local_excluded_scope: Any,
    lease_heartbeat: Callable[[], None] | None = None,
    lease_heartbeat_interval: float = 30.0,
    process_supervisor: Any | None = None,
) -> dict[str, Any]:
    """Run a job safely, defaulting to dry-run evidence only."""
    started = datetime.now(timezone.utc).isoformat()
    raw_dry_run = job.get("dry_run", True)
    dry_run = raw_dry_run if type(raw_dry_run) is bool else True
    raw_engine = job.get("engine")
    raw_target = job.get("target")
    raw_job_id = job.get("id")
    raw_action = job.get("action")
    engine = raw_engine.strip().lower() if isinstance(raw_engine, str) else ""
    target = raw_target.strip() if isinstance(raw_target, str) else ""
    job_id = raw_job_id.strip() if isinstance(raw_job_id, str) else ""
    action = raw_action.strip().lower() if isinstance(raw_action, str) else ""
    allowed_scope = _scope_argument_values(job.get("scope", []))
    job_excluded_scope = _scope_argument_values(job.get("excluded_scope", []))
    agent_scope = _scope_argument_values(local_scope)
    agent_excluded_scope = _scope_argument_values(local_excluded_scope)
    modules = _module_argument_values(job.get("modules", []))
    if not isinstance(raw_target, str):
        decision = decision_for_reason(ScopeReason.MALFORMED_TARGET)
    elif (
        not isinstance(raw_job_id, str)
        or not isinstance(raw_engine, str)
        or not isinstance(raw_action, str)
        or type(raw_dry_run) is not bool
        or type(allow_active_scans) is not bool
        or modules is None
    ):
        decision = decision_for_reason(ScopeReason.INVALID_CONFIRMATION)
    else:
        decision = decide_scope(target, allowed_scope, job_excluded_scope)
        if decision.allowed:
            decision = decide_scope(target, agent_scope, agent_excluded_scope)
        if decision.allowed:
            for entry in allowed_scope:
                decision = decide_scope(entry, agent_scope, agent_excluded_scope)
                if not decision.allowed:
                    break
        if decision.allowed and action != "scan":
            decision = decision_for_reason(ScopeReason.ACTION_MISMATCH)
        if decision.allowed:
            effective_excluded = list(
                dict.fromkeys([*agent_excluded_scope, *job_excluded_scope])
            )
            decision = decide_action(
                target=target,
                allowed_scope=allowed_scope,
                excluded_scope=effective_excluded,
                confirmation=job.get("confirmation"),
                job_id=job_id,
                engine=engine,
                action=action,
                require_confirmation=not dry_run,
            )
    if not decision.allowed:
        _audit_agent_denial(
            job,
            decision,
            allowed_scope=allowed_scope,
            excluded_scope=list(
                dict.fromkeys([*agent_excluded_scope, *job_excluded_scope])
            ),
        )
        return {
            "status": "failed",
            "error": decision.reason_code,
            "result": {
                "job_id": job_id,
                "dry_run": dry_run,
                "authorized": False,
                "scope_decision": decision.to_dict(),
            },
        }

    if dry_run:
        return {
            "status": "completed",
            "result": {
                "started_at": started,
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "dry_run": True,
                "authorized": False,
                "engine": engine,
                "target": target,
                "modules": modules,
                "scope_decision": decision.to_dict(),
                "summary": "Dry-run scope validated; no authorization or scanner process was created.",
                "findings": [],
                "artifacts": [],
            },
        }

    durable_database = _active_job_database(job)
    if durable_database is None:
        return {
            "status": "failed",
            "error": "durable_process_context_invalid",
            "result": {
                "job_id": job_id,
                "dry_run": False,
                "authorized": False,
                "scope_decision": decision.to_dict(),
            },
        }

    raw_authorization = job.get("authorization_envelope")
    try:
        authorization = (
            ActionAuthorizationEnvelope.from_value(raw_authorization)
            if raw_authorization is not None
            else None
        )
    except Exception:
        authorization = None
    module_binding = module_set_binding(modules)
    runtime = _job_runtime_facts(job)
    try:
        safety_mode: SafetyMode | str = SafetyMode(
            str(job.get("safety_mode") or "")
        )
    except ValueError:
        safety_mode = SafetyMode.LOCAL_LAB
    auth_context = AuthorizationContext(
        tenant_id=str(runtime.get("tenant_id") or "runtime-missing-tenant"),
        engagement_id=str(
            runtime.get("engagement_id") or "runtime-missing-engagement"
        ),
        run_id=str(runtime.get("run_id") or "runtime-missing-run"),
        job_id=job_id or "runtime-missing-job",
        operator_id=str(
            runtime.get("operator_id") or "runtime-missing-operator"
        ),
        operator_role=str(
            runtime.get("operator_role") or OperatorRole.SYSTEM.value
        ),
        action_kind="agent.execute",
        engine=engine or "webforge",
        module_id=module_binding,
        requested_target=target or "invalid-target",
        resolved_target=target or "invalid-target",
        allowed_scope=allowed_scope,
        excluded_scope=effective_excluded,
        scope_policy_version=str(
            runtime.get("scope_policy_version") or "runtime-missing-policy"
        ),
        safety_mode=safety_mode,
        credential_approval_required=False,
        network_escalation_approval_required=False,
        high_risk_approval_required=(engine == "aiforge"),
        confirmation_method=ConfirmationMethod.INHERITED,
        confirmed_by=str(runtime.get("operator_id") or ""),
        credential_reference="",
        parent_decision_id=(
            authorization.decision_id if authorization is not None else ""
        ),
    )

    auth_db = _job_authorization_db(job)
    auth_session = open_authorization_session(auth_db)
    try:
        if not allow_active_scans:
            denied = record_authorization_denial(
                session=auth_session,
                context=auth_context,
                reason_code=AuthorizationReason.APPROVAL_MISMATCH,
                parent_decision_id=(authorization.decision_id if authorization else ""),
            )
            return {
                "status": "failed",
                "error": denied.reason_code,
                "result": {
                    "job_id": job_id,
                    "dry_run": False,
                    "authorized": False,
                    "scope_decision": decision.to_dict(),
                },
            }
        consumed = consume_authorization(
            session=auth_session,
            envelope=authorization,
            expected=auth_context,
            boundary="agent.execute",
        )
        if not consumed.allowed or authorization is None:
            return {
                "status": "failed",
                "error": consumed.reason_code,
                "result": {
                    "job_id": job_id,
                    "dry_run": False,
                    "authorized": False,
                    "scope_decision": decision.to_dict(),
                },
            }
        engine_context = AuthorizationContext(
            **{
                **auth_context.__dict__,
                "action_kind": "engine.execute",
                "parent_decision_id": authorization.decision_id,
                "confirmation_method": ConfirmationMethod.INHERITED,
            }
        )
        child = derive_authorization(
            session=auth_session,
            parent_envelope=authorization,
            context=engine_context,
            parent_boundary="agent.execute",
        )
        if not child.allowed:
            return {
                "status": "failed",
                "error": child.reason_code,
                "result": {
                    "job_id": job_id,
                    "dry_run": False,
                    "authorized": False,
                    "scope_decision": decision.to_dict(),
                },
            }
        engine_authorization = child.envelope
    finally:
        auth_session.close()

    confirmation_value = job.get("confirmation")
    if confirmation_value is None:
        local_denial = decision_for_reason(ScopeReason.MISSING_CONFIRMATION)
        return {
            "status": "failed",
            "error": local_denial.reason_code,
            "result": {
                "job_id": job_id,
                "dry_run": False,
                "authorized": False,
                "scope_decision": local_denial.to_dict(),
            },
        }
    confirmation = ActionConfirmation.from_value(confirmation_value)
    effective_excluded = list(
        dict.fromkeys([*agent_excluded_scope, *job_excluded_scope])
    )
    supervisor = process_supervisor or _DashboardProcessSupervisor()
    try:
        durable_service, process_context = _durable_agent_process_context(
            job,
            durable_database,
            supervisor,
        )
    except (LeaseError, ProcessIdentityError, KeyError, ValueError):
        return {
            "status": "failed",
            "error": "durable_process_context_invalid",
            "result": {
                "job_id": job_id,
                "dry_run": False,
                "authorized": False,
                "scope_decision": decision.to_dict(),
            },
        }
    command = _build_scanner_command(
        engine=engine,
        target=target,
        modules=modules or [],
        allowed_scope=allowed_scope,
        excluded_scope=effective_excluded,
    )
    child_env = scrub_proxy_environment(
        {
            key: value
            for key, value in os.environ.copy().items()
            if not key.startswith("FORGE_")
        }
    )
    child_env[LAUNCH_CONFIRMATIONS_ENV] = encode_launch_confirmations([confirmation])
    child_env[LAUNCH_JOB_ID_ENV] = job_id
    child_env[LAUNCH_ACTION_ENV] = "scan"
    child_env[AUTHORIZATION_ENVELOPES_ENV] = encode_authorization_envelopes(
        [engine_authorization]
    )
    child_env[AUTHORIZATION_DB_ENV] = str(auth_db or default_authorization_db_path())
    child_env[JOB_ATTEMPT_ID_ENV] = process_context["attempt_id"]
    child_env[f"{JOB_ATTEMPT_ID_ENV}_LAUNCH_NONCE"] = process_context[
        "launch_nonce"
    ]
    child_env.update(authorization_runtime_environment_from_facts(runtime))

    def _heartbeat() -> None:
        if lease_heartbeat is not None:
            lease_heartbeat()
            return
        renewed = durable_service.renew_lease(
            process_context["attempt_id"],
            process_context["lease_token"],
            lease_seconds=max(1.0, min(60.0, lease_heartbeat_interval * 2)),
            tenant_id=process_context["tenant_id"],
            worker_id=process_context["worker_id"],
            actor=TransitionActor(
                tenant_id=process_context["tenant_id"],
                actor_id=process_context["worker_id"],
                role="agent",
                authorization_decision_id=process_context["authorization_id"],
            ),
        )
        process_context["lease_token"] = str(renewed["lease_token"])
        job["lease_token"] = process_context["lease_token"]

    def _process_started(identity: ProcessIdentity) -> None:
        durable_service.register_process(
            process_context["job_id"],
            process_context["attempt_id"],
            identity,
            lease_token=process_context["lease_token"],
            worker_id=process_context["worker_id"],
            control_boot_id=process_context["control_boot_id"],
            tenant_id=process_context["tenant_id"],
            identity_key=process_context["identity_key"],
            actor=TransitionActor(
                tenant_id=process_context["tenant_id"],
                actor_id=process_context["worker_id"],
                role="agent",
                authorization_decision_id=process_context["authorization_id"],
            ),
        )

    def _process_exited(identity: ProcessIdentity, return_code: int | None) -> None:
        durable_service.record_process_exit(
            process_context["job_id"],
            process_context["attempt_id"],
            identity,
            worker_id=process_context["worker_id"],
            control_boot_id=process_context["control_boot_id"],
            tenant_id=process_context["tenant_id"],
            identity_key=process_context["identity_key"],
            actor=process_context["worker_id"],
            reason="co-resident agent child process exited",
            return_code=return_code,
        )

    try:
        proc = _run_with_lease_heartbeat(
            command,
            cwd=str(Path(__file__).resolve().parent),
            env=child_env,
            heartbeat=_heartbeat,
            heartbeat_interval=lease_heartbeat_interval,
            timeout=3600.0,
            launch_nonce=process_context["launch_nonce"],
            process_supervisor=supervisor,
            process_started=_process_started,
            process_exited=_process_exited,
        )
    except (
        LeaseHeartbeatLost,
        LeaseError,
        ProcessIdentityError,
        OSError,
        subprocess.SubprocessError,
    ):
        try:
            durable_service.abandon_process_launch(
                process_context["job_id"],
                process_context["attempt_id"],
                process_context["identity_key"],
                worker_id=process_context["worker_id"],
                control_boot_id=process_context["control_boot_id"],
                tenant_id=process_context["tenant_id"],
                actor=process_context["worker_id"],
                reason="co-resident agent child launch did not become durable",
            )
        except ProcessIdentityError:
            pass
        durable_service.close()
        return {
            "status": "failed",
            "error": "lease_renewal_failed",
            "lease_lost": True,
            "result": {
                "job_id": job_id,
                "dry_run": False,
                "authorized": False,
                "scope_decision": decision.to_dict(),
            },
        }
    finally:
        if not getattr(durable_service, "_closed", False):
            durable_service.close()
    run_truth_id = _verified_active_run_truth_id(
        job,
        engine,
        durable_database,
    )
    return {
        "status": "completed" if proc.returncode == 0 else "failed",
        "error": None if proc.returncode == 0 else "scanner exited non-zero",
        "result": {
            "started_at": started,
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "dry_run": False,
            "authorized": True,
            "engine": engine,
            "target": target,
            "modules": modules,
            "scope_decision": decision.to_dict(),
            "run_truth_id": run_truth_id,
            "return_code": proc.returncode,
            "log_tail": redact_authorization_value(
                "\n".join(proc.stdout.splitlines()[-120:])
            ),
        },
    }


def _run_with_lease_heartbeat(
    command: list[str],
    *,
    cwd: str,
    env: dict[str, str],
    heartbeat: Callable[[], None],
    heartbeat_interval: float,
    timeout: float,
    launch_nonce: str,
    process_supervisor: Any,
    process_started: Callable[[ProcessIdentity], None],
    process_exited: Callable[[ProcessIdentity, int | None], None],
) -> subprocess.CompletedProcess[str]:
    """Run one durably registered child while rotating its exact lease."""

    interval = max(0.25, min(float(heartbeat_interval), 60.0))
    deadline = time.monotonic() + max(1.0, float(timeout))
    pidfd_open = getattr(os, "pidfd_open", None)
    pidfd_signal = getattr(signal, "pidfd_send_signal", None)
    pidfd_reservation: int | None = None
    if os.name == "posix":
        if not callable(pidfd_open) or not callable(pidfd_signal):
            raise LeaseHeartbeatLost(
                "PID-safe child signaling is unavailable on this worker"
            )
        try:
            pidfd_reservation = int(pidfd_open(os.getpid(), 0))
        except OSError as exc:
            raise LeaseHeartbeatLost(
                "PID-safe child capability could not be reserved"
            ) from exc
    parent_pid = os.getpid()
    popen_options: dict[str, Any] = {
        "cwd": cwd,
        "env": env,
        "stdin": subprocess.DEVNULL,
        "text": True,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.STDOUT,
    }
    if os.name == "posix":
        popen_options["preexec_fn"] = lambda: _install_parent_death_signal(
            parent_pid
        )
    try:
        process = subprocess.Popen(
            command,
            **popen_options,
        )
    except BaseException:
        if pidfd_reservation is not None:
            os.close(pidfd_reservation)
        raise
    process_pid = getattr(process, "pid", None)
    pidfd: int | None = None
    if os.name == "posix" and isinstance(process_pid, int):
        if pidfd_reservation is not None:
            os.close(pidfd_reservation)
            pidfd_reservation = None
        try:
            assert callable(pidfd_open)
            pidfd = int(pidfd_open(process_pid, 0))
        except OSError as exc:
            capture = getattr(process_supervisor, "capture", None)
            captured = (
                capture(process, launch_nonce=launch_nonce)
                if callable(capture)
                else None
            )
            if process.poll() is None and isinstance(captured, ProcessIdentity):
                try:
                    process_supervisor.terminate(captured)
                    process.communicate(timeout=5.0)
                except Exception:
                    pass
            raise LeaseHeartbeatLost(
                "PID-safe child capability could not be acquired"
            ) from exc
    elif pidfd_reservation is not None:
        os.close(pidfd_reservation)
        pidfd_reservation = None
    output = ""
    identity: ProcessIdentity | None = None
    registered = False
    exit_recorded = False

    def _record_exit() -> None:
        nonlocal exit_recorded
        if identity is None or not registered or exit_recorded:
            return
        try:
            process_exited(identity, getattr(process, "returncode", None))
        except Exception as exc:
            raise LeaseHeartbeatLost(
                "child exit could not be persisted"
            ) from exc
        exit_recorded = True

    try:
        capture = getattr(process_supervisor, "capture", None)
        if not callable(capture):
            raise LeaseHeartbeatLost("process identity capture is unavailable")
        identity = capture(process, launch_nonce=launch_nonce)
        if not isinstance(identity, ProcessIdentity):
            raise LeaseHeartbeatLost("child process identity could not be captured")
        try:
            process_started(identity)
        except Exception as exc:
            raise LeaseHeartbeatLost(
                "child process identity could not be persisted"
            ) from exc
        registered = True
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(command, timeout)
            try:
                output, _ = process.communicate(timeout=min(interval, remaining))
                break
            except subprocess.TimeoutExpired:
                try:
                    heartbeat()
                except Exception as exc:
                    raise LeaseHeartbeatLost("lease renewal failed") from exc
        _record_exit()
        return subprocess.CompletedProcess(command, process.returncode, output, None)
    except BaseException:
        if process.poll() is None:
            if pidfd is not None:
                signal.pidfd_send_signal(pidfd, signal.SIGTERM)
            elif os.name == "nt":
                process.send_signal(signal.SIGTERM)
            elif not isinstance(process_pid, int):
                # Inert test doubles have no OS identity. Production POSIX
                # children are never signaled through this branch.
                getattr(process, "terminate")()
            else:
                raise LeaseHeartbeatLost(
                    "refusing to signal a child without a PID capability"
                )
            try:
                tail, _ = process.communicate(timeout=5.0)
                output = tail or output
            except subprocess.TimeoutExpired:
                if pidfd is not None:
                    signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                elif os.name == "nt":
                    process.send_signal(signal.SIGKILL)
                elif not isinstance(process_pid, int):
                    getattr(process, "kill")()
                else:
                    raise LeaseHeartbeatLost(
                        "refusing to kill a child without a PID capability"
                    )
                tail, _ = process.communicate(timeout=1.0)
                output = tail or output
        if process.poll() is not None:
            _record_exit()
        raise
    finally:
        if pidfd is not None:
            os.close(pidfd)


def _lease_heartbeat_interval(job: dict[str, Any]) -> float:
    """Renew comfortably before expiry without creating a tight retry loop."""
    try:
        expiry = datetime.fromisoformat(str(job.get("lease_expires_at") or ""))
        remaining = (expiry - datetime.now(timezone.utc)).total_seconds()
    except (TypeError, ValueError):
        return 30.0
    return max(1.0, min(30.0, remaining / 2.0))


def _build_scanner_command(
    *,
    engine: str,
    target: str,
    modules: list[str],
    allowed_scope: list[str],
    excluded_scope: list[str],
) -> list[str]:
    """Build argv only from values validated by the local execution boundary."""
    root = Path(__file__).resolve().parent
    if engine == "webforge":
        cmd = [sys.executable, str(root / "webforge" / "webforge.py"), "--target", target, "--mode", "blackbox"]
    elif engine == "netforge":
        cmd = [sys.executable, str(root / "netforge" / "netforge.py"), "--target", target, "--mode", "external"]
    elif engine == "aiforge":
        cmd = [
            sys.executable,
            str(root / "aiforge" / "aiforge.py"),
            "--target",
            target,
            "--mode",
            "blackbox",
        ]
    else:
        raise RuntimeError(f"agent engine does not support active launch: {engine}")
    if modules:
        cmd.extend(["--modules", ",".join(modules)])
    for entry in allowed_scope:
        cmd.extend(["--scope", entry])
    for entry in excluded_scope:
        cmd.extend(["--exclude", entry])
    return cmd


def run_agent(args: argparse.Namespace) -> int:
    if getattr(args, "insecure_tls", False):
        print(json.dumps({
            "status": "not_authorized",
            "reason_code": "insecure_tls_not_authorized",
            "detail": "lab-only insecure TLS requires a separate exact authorization",
        }))
        return 2
    scope_decision = _registration_scope_decision(args)
    if not scope_decision.allowed:
        _audit_agent_denial(
            {
                "id": f"agent-register-{getattr(args, 'agent_id', 'unknown')}",
                "engine": "forge-agent",
                "action": "agent.register",
                "target": getattr(args, "dashboard_url", "local-dashboard"),
                "scope": getattr(args, "scope", []),
                "excluded_scope": getattr(args, "exclude", []),
                "safety_mode": SafetyMode.PASSIVE.value,
            },
            scope_decision,
            allowed_scope=getattr(args, "scope", []),
            excluded_scope=getattr(args, "exclude", []),
        )
        print(json.dumps({"status": "not_authorized", "detail": scope_decision.to_dict()}))
        return 2
    print(json.dumps({
        "status": "not_tested",
        "reason_code": "outbound_policy_unsupported",
        "detail": "agent control-plane egress requires a separate consumed outbound policy",
    }))
    return 2
    local_scope = _scope_argument_values(getattr(args, "scope", []))
    local_excluded_scope = _scope_argument_values(getattr(args, "exclude", []))
    token = args.token or os.environ.get("FORGE_AGENT_REGISTRATION_TOKEN", "")
    ssl_context = _build_ssl_context(args.dashboard_url, args)
    payload = _agent_payload(args)
    registered = _json_request(
        args.dashboard_url,
        "/api/v1/agents/register",
        method="POST",
        payload=payload,
        token=token,
        ssl_context=ssl_context,
        bootstrap=True,
    )
    agent_id = str(registered.get("agent", {}).get("id") or args.agent_id)
    credential = str(registered.get("credential") or "")
    if not credential:
        raise RuntimeError("dashboard did not issue an agent credential")
    print(f"registered: {agent_id}")
    while True:
        response = _json_request(
            args.dashboard_url,
            f"/api/v1/agents/{agent_id}/jobs/next",
            token=credential,
            ssl_context=ssl_context,
        )
        job = response.get("job")
        if not job:
            if args.once:
                return 0
            time.sleep(args.interval)
            continue
        def _renew_current_lease() -> None:
            current_token = str(job.get("lease_token") or "")
            if not current_token:
                raise LeaseHeartbeatLost("current lease token is missing")
            renewed = _json_request(
                args.dashboard_url,
                f"/api/v1/agents/{agent_id}/jobs/{job['id']}/lease/renew",
                method="POST",
                payload={
                    "lease_token": current_token,
                    "attempt_id": job.get("attempt_id"),
                },
                token=credential,
                ssl_context=ssl_context,
            )
            replacement = str(renewed.get("job", {}).get("lease_token") or "")
            if not replacement:
                raise LeaseHeartbeatLost("dashboard did not rotate the lease token")
            job["lease_token"] = replacement

        try:
            result = _safe_job_result(
                job,
                args.allow_active_scans,
                local_scope=local_scope,
                local_excluded_scope=local_excluded_scope,
                lease_heartbeat=_renew_current_lease,
                lease_heartbeat_interval=_lease_heartbeat_interval(job),
            )
        except Exception as exc:
            result = {
                "status": "failed",
                "error": f"agent execution failed ({type(exc).__name__})",
                "result": {"job_id": job.get("id")},
            }
        if result.get("lease_lost"):
            if args.once:
                return 2
            time.sleep(args.interval)
            continue
        submission = {
            "lease_token": job.get("lease_token"),
            "delivery_idempotency_key": job.get(
                "delivery_idempotency_key"
            ),
            "outcome": {
                "completed": "success",
                "failed": "failure",
                "canceled": "canceled",
            }.get(str(result.get("status") or ""), "failure"),
            "tenant_id": job.get("tenant_id"),
            "job_id": job.get("id"),
            "agent_id": agent_id,
            "attempt_id": job.get("attempt_id"),
            "run_id": job.get("run_id"),
            "engine": job.get("engine"),
            "capability": job.get("capability"),
            "module_binding": module_set_binding(_module_argument_values(job.get("modules")) or []),
            "target": job.get("target"),
            "authorization_id": job.get("authorization_id"),
            "error": result.get("error"),
            "result": result.get("result"),
            "run_truth_id": (
                result.get("result", {}).get("run_truth_id")
                if isinstance(result.get("result"), dict)
                else None
            ),
        }
        _json_request(
            args.dashboard_url,
            f"/api/v1/agents/{agent_id}/jobs/{job['id']}/result",
            method="POST",
            payload=submission,
            token=credential,
            ssl_context=ssl_context,
        )
        if args.once:
            return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Forge passive scan agent")
    parser.add_argument("--dashboard-url", required=True, help="Dashboard base URL, e.g. http://127.0.0.1:1337")
    parser.add_argument("--agent-id", default=socket.gethostname(), help="Stable agent id")
    parser.add_argument("--name", default="", help="Display name")
    parser.add_argument("--engines", default="webforge,netforge", help="Comma-separated engine capabilities")
    parser.add_argument("--scope", action="append", required=True, help="Authorized scope entry (repeatable)")
    parser.add_argument("--exclude", action="append", default=[], help="Excluded scope entry (repeatable)")
    parser.add_argument("--token", default="", help="Registration token; defaults to FORGE_AGENT_REGISTRATION_TOKEN")
    parser.add_argument("--interval", type=float, default=5.0, help="Poll interval seconds")
    parser.add_argument("--once", action="store_true", help="Register, process at most one job, then exit")
    parser.add_argument("--allow-active-scans", action="store_true", help="Permit non-dry-run queued jobs to launch scanners")
    parser.add_argument("--client-cert", default="", help="Client certificate PEM for dashboard HTTPS")
    parser.add_argument("--client-key", default="", help="Client private key PEM for --client-cert")
    parser.add_argument("--ca-cert", default="", help="CA bundle PEM for dashboard TLS verification")
    parser.add_argument("--insecure-tls", action="store_true", help="Disable dashboard TLS verification for labs")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        _validate_tls_options(args)
    except ValueError as exc:
        parser.error(str(exc))
    return run_agent(args)


if __name__ == "__main__":
    raise SystemExit(main())
