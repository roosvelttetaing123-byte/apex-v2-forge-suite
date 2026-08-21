#!/usr/bin/env python3
"""Forge passive scan agent.

Registers with the dashboard, polls for scoped jobs, and submits redacted
results. The default execution mode is dry-run only; active scanner launch
requires both a queued non-dry-run job and --allow-active-scans locally.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
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
from common.scope import ScopeDecision, ScopeReason, decision_for_reason, decide_scope
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
    if configured:
        return Path(configured).expanduser().resolve()
    raw = str(job.get("authorization_db") or "").strip()
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


def _safe_job_result(
    job: dict[str, Any],
    allow_active_scans: bool,
    *,
    local_scope: Any,
    local_excluded_scope: Any,
    lease_heartbeat: Callable[[], None] | None = None,
    lease_heartbeat_interval: float = 30.0,
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
    child_env.update(authorization_runtime_environment_from_facts(runtime))
    try:
        if lease_heartbeat is None:
            proc = subprocess.run(
                command,
                cwd=str(Path(__file__).resolve().parent),
                env=child_env,
                stdin=subprocess.DEVNULL,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=3600,
            )
        else:
            proc = _run_with_lease_heartbeat(
                command,
                cwd=str(Path(__file__).resolve().parent),
                env=child_env,
                heartbeat=lease_heartbeat,
                heartbeat_interval=lease_heartbeat_interval,
                timeout=3600.0,
            )
    except LeaseHeartbeatLost:
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
) -> subprocess.CompletedProcess[str]:
    """Run one scanner while rotating its lease; stop it if ownership is lost."""
    interval = max(0.25, min(float(heartbeat_interval), 60.0))
    deadline = time.monotonic() + max(1.0, float(timeout))
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    output = ""
    try:
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
        return subprocess.CompletedProcess(command, process.returncode, output, None)
    except BaseException:
        if process.poll() is None:
            process.terminate()
            try:
                tail, _ = process.communicate(timeout=5.0)
                output = tail or output
            except subprocess.TimeoutExpired:
                process.kill()
                tail, _ = process.communicate(timeout=1.0)
                output = tail or output
        raise


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
                payload={"lease_token": current_token},
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
