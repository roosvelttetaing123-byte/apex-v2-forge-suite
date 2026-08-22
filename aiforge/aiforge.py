#!/usr/bin/env python3
"""
AIForge — AI/LLM Security Assessment Framework
=================================================
Red team assessment tool for AI systems: LLMs, chatbots, RAG pipelines,
AI agents, and ML APIs. Tests for OWASP LLM Top 10 2025 vulnerabilities.
v5 APEX: EventBus integration, multi-target, pause/resume/abort.

FOR AUTHORIZED PENETRATION TESTING ONLY.

Usage:
  python aiforge.py --target https://api.target.com/v1/chat --mode blackbox
  python aiforge.py --target https://chatbot.target.com --mode greybox --api-key sk-xxx
  python aiforge.py --target https://target.com/api --mode whitebox --model-info model.yaml
"""
from __future__ import annotations

import argparse
import asyncio
import getpass
import importlib
import os
import sys
import time
import uuid
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent))

from common.auth_prompt import require_authorization
from common.action_authorization import (
    AUTHORIZATION_ENVELOPES_ENV,
    ActionAuthorizationEnvelope,
    AuthorizationContext,
    AuthorizationDecision,
    AuthorizationReason,
    ConfirmationMethod,
    OperatorRole,
    SafetyMode,
    authorization_runtime_environment,
    consume_authorization,
    derive_authorization,
    issue_authorization,
    load_authorization_envelopes,
    load_authorization_runtime_facts,
    module_binding_allows,
    module_set_binding,
    open_authorization_session,
    protected_credential_reference,
    redact_authorization_value,
    record_boundary_denial,
    record_authorization_denial,
    select_authorization_envelope,
    validate_consumed_authorization,
)
from common.config import BaseForgeConfig, load_config
from common.confirm_gate import (
    LAUNCH_CONFIRMATIONS_ENV,
    ActionConfirmation,
    decide_action,
    load_launch_confirmations,
    load_launch_expectation,
    set_auto_confirm,
)
from common.db import create_db, ScanRunModel
from common.finding import Finding
from common.logger import get_logger, phase_banner, console
from common.reporter import BaseReporter
from common.scope import (
    Scope,
    ScopeDecision,
    ScopeReason,
    canonical_target,
    decision_for_reason,
    safe_target_display,
)

from rich.panel import Panel

log = get_logger("aiforge")

from common.version import VERSION
ENGINE_NAME = "aiforge"
DEFAULT_LAUNCH_ACTION = "scan"

DOS_MODULES = {"resource_exhaustion", "rate_limit_test"}
DESTRUCTIVE_MODULES = {"resource_exhaustion"}  # overlap intentional — resource_exhaustion is both


def confirm_dangerous_module(module_name: str, target: str, category: str) -> bool:
    """Big red double-confirmation gate for DoS/destructive modules.

    This CANNOT be bypassed by --auto-confirm. Only --allow-destructive skips it.
    Returns True if operator explicitly types 'YES I UNDERSTAND'.
    """
    safe_target = safe_target_display(target)
    console.print()
    console.print(Panel(
        f"[bold white on red]  WARNING: DESTRUCTIVE / DoS MODULE  [/bold white on red]\n\n"
        f"  Module   : [bold]{module_name}[/bold]\n"
        f"  Target   : [bold]{safe_target}[/bold]\n"
        f"  Category : [bold red]{category.upper()}[/bold red]\n\n"
        f"  This module can cause [bold red]service disruption[/bold red],\n"
        f"  [bold red]resource exhaustion[/bold red], or [bold red]denial of service[/bold red]\n"
        f"  on the target system.\n\n"
        f"  To skip DoS modules entirely, rerun with [cyan]--no-dos[/cyan]\n"
        f"  To skip destructive modules, rerun with [cyan]--no-destructive[/cyan]\n\n"
        f"  Type [bold green]YES I UNDERSTAND[/bold green] to proceed:",
        title="[bold white on red] REQUIRES SECOND CONFIRMATION [/bold white on red]",
        border_style="bold red",
        padding=(1, 3),
    ))

    try:
        answer = input("  > ").strip()
    except (EOFError, KeyboardInterrupt):
        answer = ""

    confirmed = answer == "YES I UNDERSTAND"
    if confirmed:
        console.print(f"[bold red]  Proceeding with {module_name} — operator accepted risk.[/bold red]")
        log.warning("DESTRUCTIVE MODULE %s confirmed by operator on %s", module_name, safe_target)
    else:
        console.print(f"[yellow]  Skipped {module_name} — operator declined.[/yellow]")
        log.info("DESTRUCTIVE MODULE %s skipped by operator on %s", module_name, safe_target)
    return confirmed

MODULE_MAP: dict[str, str] = {
    # Phase 1 — Reconnaissance
    "llm_fingerprint":      "aiforge.modules.recon.llm_fingerprint",
    "system_prompt_extract": "aiforge.modules.recon.system_prompt_extract",
    "guardrail_probe":      "aiforge.modules.recon.guardrail_probe",
    "capability_enum":      "aiforge.modules.recon.capability_enum",
    "model_card_check":     "aiforge.modules.recon.model_card_check",
    # Phase 2 — Prompt Injection
    "direct_inject":        "aiforge.modules.injection.direct_inject",
    "indirect_inject":      "aiforge.modules.injection.indirect_inject",
    "context_overflow":     "aiforge.modules.injection.context_overflow",
    "encoding_bypass":      "aiforge.modules.injection.encoding_bypass",
    "multi_turn_attack":    "aiforge.modules.injection.multi_turn_attack",
    "multilingual_inject":  "aiforge.modules.injection.multilingual_inject",
    # Phase 3 — Jailbreak & Guardrail Bypass
    "jailbreak_test":       "aiforge.modules.jailbreak.jailbreak_test",
    "roleplay_bypass":      "aiforge.modules.jailbreak.roleplay_bypass",
    "token_smuggling":      "aiforge.modules.jailbreak.token_smuggling",
    "output_format_abuse":  "aiforge.modules.jailbreak.output_format_abuse",
    # Phase 4 — Data Exfiltration
    "training_extract":     "aiforge.modules.exfil.training_extract",
    "pii_leak_test":        "aiforge.modules.exfil.pii_leak_test",
    "data_exfil":           "aiforge.modules.exfil.data_exfil",
    "membership_inference": "aiforge.modules.exfil.membership_inference",
    # Phase 5 — Agent/Tool Abuse
    "tool_abuse":           "aiforge.modules.agent.tool_abuse",
    "agent_hijack":         "aiforge.modules.agent.agent_hijack",
    "rag_poison":           "aiforge.modules.agent.rag_poison",
    "function_call_inject": "aiforge.modules.agent.function_call_inject",
    # Phase 6 — Output Manipulation
    "output_manipulation":  "aiforge.modules.output.output_manipulation",
    "hallucination_test":   "aiforge.modules.output.hallucination_test",
    "bias_probe":           "aiforge.modules.output.bias_probe",
    # Phase 7 — DoS & Resource
    "resource_exhaustion":  "aiforge.modules.dos.resource_exhaustion",
    "rate_limit_test":      "aiforge.modules.dos.rate_limit_test",
    # Phase 8 — Reporting
    "html_report":          "aiforge.modules.reporting.html_report",
    "pdf_report":           "aiforge.modules.reporting.pdf_report",
}

CLASS_NAME_MAP: dict[str, str] = {
    "llm_fingerprint":      "LlmFingerprint",
    "system_prompt_extract": "SystemPromptExtract",
    "guardrail_probe":      "GuardrailProbe",
    "capability_enum":      "CapabilityEnum",
    "model_card_check":     "ModelCardCheck",
    "direct_inject":        "DirectInject",
    "indirect_inject":      "IndirectInject",
    "context_overflow":     "ContextOverflow",
    "encoding_bypass":      "EncodingBypass",
    "multi_turn_attack":    "MultiTurnAttack",
    "multilingual_inject":  "MultilingualInject",
    "jailbreak_test":       "JailbreakTest",
    "roleplay_bypass":      "RoleplayBypass",
    "token_smuggling":      "TokenSmuggling",
    "output_format_abuse":  "OutputFormatAbuse",
    "training_extract":     "TrainingExtract",
    "pii_leak_test":        "PiiLeakTest",
    "data_exfil":           "DataExfil",
    "membership_inference": "MembershipInference",
    "tool_abuse":           "ToolAbuse",
    "agent_hijack":         "AgentHijack",
    "rag_poison":           "RagPoison",
    "function_call_inject": "FunctionCallInject",
    "output_manipulation":  "OutputManipulation",
    "hallucination_test":   "HallucinationTest",
    "bias_probe":           "BiasProbe",
    "resource_exhaustion":  "ResourceExhaustion",
    "rate_limit_test":      "RateLimitTest",
    "html_report":          "HtmlReport",
    "pdf_report":           "PdfReport",
}

PHASES: list[dict[str, Any]] = [
    {"number": 1, "name": "AI Reconnaissance", "modules": [
        "llm_fingerprint", "system_prompt_extract", "guardrail_probe",
        "capability_enum", "model_card_check",
    ]},
    {"number": 2, "name": "Prompt Injection", "modules": [
        "direct_inject", "indirect_inject", "context_overflow",
        "encoding_bypass", "multi_turn_attack", "multilingual_inject",
    ]},
    {"number": 3, "name": "Jailbreak & Guardrail Bypass", "modules": [
        "jailbreak_test", "roleplay_bypass", "token_smuggling",
        "output_format_abuse",
    ]},
    {"number": 4, "name": "Data Exfiltration", "modules": [
        "training_extract", "pii_leak_test", "data_exfil",
        "membership_inference",
    ]},
    {"number": 5, "name": "Agent & Tool Abuse", "modules": [
        "tool_abuse", "agent_hijack", "rag_poison", "function_call_inject",
    ]},
    {"number": 6, "name": "Output Manipulation", "modules": [
        "output_manipulation", "hallucination_test", "bias_probe",
    ]},
    {"number": 7, "name": "DoS & Resource Abuse", "modules": [
        "resource_exhaustion", "rate_limit_test",
    ]},
    {"number": 8, "name": "Reporting", "modules": [
        "html_report", "pdf_report",
    ]},
]


# ── EventBus helpers ──────────────────────────────────────────────────

def _get_event_bus(event_bus: Any = None):
    if event_bus is None:
        return None, None, None
    try:
        from common.dashboard.event_bus import Event, EventType
        return event_bus, Event, EventType
    except ImportError:
        return None, None, None


def _emit(bus: Any, Event: Any, EventType: Any, etype: str, source: str = "aiforge", **data: Any) -> None:
    if bus is None:
        return
    try:
        bus.emit(
            Event(
                event_type=EventType(etype),
                data=redact_authorization_value(data),
                source=source,
            )
        )
    except Exception:
        pass


# ── Pause / Resume / Abort control ───────────────────────────────────

class ScanControl:
    def __init__(self) -> None:
        self._paused = asyncio.Event()
        self._paused.set()
        self._aborted = False

    @property
    def is_paused(self) -> bool:
        return not self._paused.is_set()

    @property
    def is_aborted(self) -> bool:
        return self._aborted

    def pause(self) -> None:
        self._paused.clear()
        log.info("Scan PAUSED by operator")

    def resume(self) -> None:
        self._paused.set()
        log.info("Scan RESUMED by operator")

    def abort(self) -> None:
        self._aborted = True
        self._paused.set()
        log.info("Scan ABORTED by operator")

    async def wait_if_paused(self) -> None:
        await self._paused.wait()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="AIForge — AI/LLM Security Assessment Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        allow_abbrev=False,
    )
    parser.add_argument("--target",        required=True,              help="Target AI endpoint URL")
    parser.add_argument("--mode",          default="blackbox",
                        choices=["blackbox", "greybox", "whitebox"],   help="Assessment mode")
    parser.add_argument("--engagement",    default="ai-engagement",    help="Engagement name")
    parser.add_argument("--tester",        default="anonymous",        help="Tester name")
    parser.add_argument("--config",        default=None,               help="Path to aiforge.yaml")
    parser.add_argument("--output",        default=None,               help="Results directory")
    parser.add_argument("--report-format", default="html,pdf",         help="Report formats")
    parser.add_argument("--rate",          type=float, default=5.0,    help="Requests per second")
    parser.add_argument("--api-key",       default=None,               help="API key for authenticated testing")
    parser.add_argument("--api-type",      default="openai",
                        choices=["openai", "anthropic", "azure", "huggingface",
                                 "ollama", "custom", "web"],           help="API type")
    parser.add_argument("--model-name",    default=None,               help="Target model name")
    parser.add_argument("--system-prompt", default=None,               help="Known system prompt (whitebox)")
    parser.add_argument("--model-info",    default=None,               help="Model info YAML (whitebox)")
    parser.add_argument("--proxy",         default=None,               help="HTTP proxy")
    parser.add_argument("--modules",       default=None,               help="Comma-separated modules to run")
    parser.add_argument("--skip-modules",  default=None,               help="Comma-separated modules to skip")
    parser.add_argument("--scope",         action="append", default=[], help="In-scope hosts/CIDRs (repeatable)")
    parser.add_argument("--exclude",       action="append", default=[], help="Excluded hosts/CIDRs (repeatable)")
    parser.add_argument("--auto-confirm",  action="store_true",        help="Skip confirmation gates")
    parser.add_argument("--no-dos",        action="store_true",        help="Skip all DoS/resource exhaustion modules")
    parser.add_argument("--no-destructive", action="store_true",       help="Skip all destructive exploit modules")
    parser.add_argument("--allow-destructive", action="store_true",    help="Pre-approve destructive modules (skip red warning)")
    parser.add_argument("--max-tokens",    type=int, default=2000,     help="Max tokens per request")
    parser.add_argument("--temperature",   type=float, default=0.7,    help="Temperature for generations")
    parser.add_argument("--list-modules",  action="store_true",        help="List modules and exit")
    parser.add_argument("--verbose",       action="store_true",        help="Verbose output")
    parser.add_argument("--quiet",         action="store_true",        help="Suppress UI output")
    parser.add_argument("--dry-run",       action="store_true",        help="Return a local plan without target I/O")
    parser.add_argument("--version",       action="version", version=f"AIForge {VERSION}")
    parser.add_argument("--dashboard-url", default=None,
                        help="Live dashboard URL (e.g. http://localhost:1337) — streams events in real time")
    return parser.parse_args()


def _denied_summary(
    decision: ScopeDecision,
    *,
    dry_run: bool = False,
) -> dict[str, Any]:
    return {
        "status": "not_authorized",
        "findings": 0,
        "errors": [decision.reason],
        "duration": 0.0,
        "dry_run": dry_run,
        "authorized": False,
        "reason_code": decision.reason_code,
        "reason": decision.reason,
    }


def _authorization_denied_summary(decision: AuthorizationDecision) -> dict[str, Any]:
    return {
        "status": "not_authorized",
        "findings": 0,
        "errors": [decision.reason],
        "duration": 0.0,
        "dry_run": False,
        "authorized": False,
        "reason_code": decision.reason_code,
        "reason": decision.reason,
    }


def _print_launch_denial(decision: ScopeDecision) -> None:
    console.print(
        f"[bold red]Launch denied:[/bold red] reason_code={decision.reason_code}; "
        f"{decision.reason}"
    )


def _confirmation_for_target(
    confirmations: list[ActionConfirmation],
    target: str,
) -> ActionConfirmation | None:
    try:
        expected_target = canonical_target(target)
    except ValueError:
        return None
    exact = [
        record
        for record in confirmations
        if record.engine == ENGINE_NAME and record.target == expected_target
    ]
    if len(exact) == 1:
        return exact[0]
    return confirmations[0] if len(confirmations) == 1 else None


def _authorization_context_from_envelope(
    envelope: ActionAuthorizationEnvelope,
    cfg: BaseForgeConfig,
    *,
    action_kind: str,
    module_id: str | None = None,
) -> AuthorizationContext:
    runtime = cfg.extra.get("authorization_runtime")
    if not isinstance(runtime, Mapping):
        runtime = {}
    try:
        operator_role: OperatorRole | str = OperatorRole(
            str(runtime.get("operator_role", ""))
        )
    except ValueError:
        operator_role = OperatorRole.SYSTEM
    try:
        safety_mode: SafetyMode | str = SafetyMode(
            str(runtime.get("safety_mode", ""))
        )
    except ValueError:
        safety_mode = SafetyMode.LOCAL_LAB
    return AuthorizationContext(
        tenant_id=str(runtime.get("tenant_id") or "runtime-missing-tenant"),
        engagement_id=str(runtime.get("engagement_id") or "runtime-missing-engagement"),
        run_id=str(runtime.get("run_id") or "runtime-missing-run"),
        job_id=str(cfg.extra.get("job_id") or "runtime-missing-job"),
        operator_id=str(runtime.get("operator_id") or "runtime-missing-operator"),
        operator_role=operator_role,
        action_kind=action_kind,
        engine=ENGINE_NAME,
        module_id=envelope.module_id if module_id is None else module_id,
        requested_target=cfg.target,
        resolved_target=cfg.target,
        allowed_scope=cfg.extra.get("allowed_scope", []),
        excluded_scope=cfg.extra.get("excluded_scope", []),
        scope_policy_version=str(
            runtime.get("scope_policy_version") or "runtime-missing-policy"
        ),
        safety_mode=safety_mode,
        credential_approval_required=bool(
            cfg.extra.get("runtime_credential_reference")
        ),
        network_escalation_approval_required=False,
        high_risk_approval_required=True,
        confirmation_method=ConfirmationMethod.INHERITED,
        confirmed_by=str(runtime.get("operator_id") or ""),
        credential_reference=str(
            cfg.extra.get("runtime_credential_reference") or ""
        ),
        parent_decision_id=envelope.decision_id,
    )


def _requested_modules(args: argparse.Namespace) -> list[str]:
    return [item.strip() for item in args.modules.split(",") if item.strip()] if args.modules else []


def _credential_reference(args: argparse.Namespace) -> str:
    return protected_credential_reference(
        {"api_key": str(getattr(args, "api_key", "") or "")}
    )


def _audit_scope_denial(
    args: argparse.Namespace,
    decision: ScopeDecision,
    *,
    target: str | None = None,
) -> None:
    if bool(getattr(args, "dry_run", False)):
        return
    runtime = getattr(args, "_authorization_runtime", None)
    if not isinstance(runtime, Mapping):
        runtime = load_authorization_runtime_facts()
    operator_id = str(
        runtime.get("operator_id")
        or getpass.getuser().strip()
        or "operator"
    )
    session = open_authorization_session()
    try:
        record_boundary_denial(
            session=session,
            reason_code=decision.reason_code,
            action_kind=getattr(args, "_launch_action", DEFAULT_LAUNCH_ACTION),
            engine=ENGINE_NAME,
            target=target if target is not None else getattr(args, "target", None),
            allowed_scope=getattr(args, "scope", []),
            excluded_scope=getattr(args, "exclude", []),
            tenant_id=runtime.get(
                "tenant_id",
                os.environ.get("FORGE_TENANT_ID", "default"),
            ),
            engagement_id=runtime.get(
                "engagement_id",
                getattr(args, "engagement", "preflight"),
            ),
            run_id=runtime.get("run_id", "aiforge-preflight-run"),
            job_id=getattr(args, "_launch_job_id", "aiforge-preflight-job"),
            operator_id=operator_id,
            operator_role=runtime.get(
                "operator_role",
                OperatorRole.OPERATOR.value,
            ),
            module_id=module_set_binding(_requested_modules(args)),
            scope_policy_version=runtime.get(
                "scope_policy_version",
                "scope-policy-v1",
            ),
            safety_mode=runtime.get(
                "safety_mode",
                SafetyMode.HIGH_RISK.value,
            ),
            credential_reference=_credential_reference(args),
            high_risk_approval_required=True,
        )
    finally:
        session.close()


def _prepare_cli_confirmation(
    args: argparse.Namespace,
) -> tuple[ScopeDecision, list[ActionConfirmation]]:
    inherited = load_launch_confirmations()
    if not args.dry_run and os.environ.get(LAUNCH_CONFIRMATIONS_ENV) and not inherited:
        return decision_for_reason(ScopeReason.INVALID_CONFIRMATION), []
    inherited_expectation = load_launch_expectation() if inherited else None
    if inherited and inherited_expectation is None:
        return decision_for_reason(ScopeReason.INVALID_CONFIRMATION), []
    job_id, expected_action = inherited_expectation or (
        f"aiforge-cli-{uuid.uuid4().hex}",
        DEFAULT_LAUNCH_ACTION,
    )
    if expected_action != DEFAULT_LAUNCH_ACTION:
        return decision_for_reason(ScopeReason.ACTION_MISMATCH), []
    args._launch_job_id = job_id
    args._launch_action = expected_action
    decision = decide_action(
        target=args.target,
        allowed_scope=args.scope,
        excluded_scope=args.exclude,
        confirmation=None,
        job_id=job_id,
        engine=ENGINE_NAME,
        action=expected_action,
        require_confirmation=False,
    )
    if not decision.allowed or args.dry_run:
        return decision, []

    confirmation = _confirmation_for_target(inherited, args.target)
    if confirmation is None and inherited:
        return decision_for_reason(ScopeReason.MISSING_CONFIRMATION), []
    if confirmation is None:
        if not args.auto_confirm:
            try:
                require_authorization(args.target, "AIForge")
            except SystemExit:
                _audit_scope_denial(
                    args,
                    decision_for_reason(ScopeReason.MISSING_CONFIRMATION),
                    target=args.target,
                )
                raise
        confirmation = ActionConfirmation.create(
            job_id=job_id,
            target=args.target,
            engine=ENGINE_NAME,
            action=expected_action,
        )
    decision = decide_action(
        target=args.target,
        allowed_scope=args.scope,
        excluded_scope=args.exclude,
        confirmation=confirmation,
        job_id=job_id,
        engine=ENGINE_NAME,
        action=expected_action,
    )
    return decision, [confirmation] if decision.allowed else []


def _prepare_engine_authorization(
    args: argparse.Namespace,
    confirmations: list[ActionConfirmation],
) -> tuple[ScopeDecision, ActionAuthorizationEnvelope | None]:
    inherited = load_authorization_envelopes()
    if os.environ.get(AUTHORIZATION_ENVELOPES_ENV) and not inherited:
        denied = decision_for_reason(ScopeReason.INVALID_CONFIRMATION)
        _audit_scope_denial(args, denied, target=args.target)
        return denied, None
    job_id = str(getattr(args, "_launch_job_id", ""))
    module_binding = module_set_binding(_requested_modules(args))
    if inherited:
        selected = select_authorization_envelope(
            inherited,
            job_id=job_id,
            engine=ENGINE_NAME,
            action_kind="engine.execute",
            requested_target=args.target,
            resolved_target=args.target,
            module_id=module_binding,
        )
        if selected is None:
            denied = decision_for_reason(ScopeReason.INVALID_CONFIRMATION)
            _audit_scope_denial(args, denied, target=args.target)
            return denied, None
        return decision_for_reason(ScopeReason.ALLOWED), selected

    confirmation = _confirmation_for_target(confirmations, args.target)
    if confirmation is None:
        return decision_for_reason(ScopeReason.MISSING_CONFIRMATION), None
    operator_id = getpass.getuser().strip() or "operator"
    credential_reference = _credential_reference(args)
    base_context = AuthorizationContext(
        tenant_id=os.environ.get("FORGE_TENANT_ID", "default").strip() or "default",
        engagement_id=str(args.engagement or "default"),
        run_id=f"run-{uuid.uuid4().hex}",
        job_id=job_id,
        operator_id=operator_id,
        operator_role=OperatorRole.OPERATOR,
        action_kind=str(getattr(args, "_launch_action", DEFAULT_LAUNCH_ACTION)),
        engine=ENGINE_NAME,
        module_id=module_binding,
        requested_target=args.target,
        resolved_target=args.target,
        allowed_scope=args.scope,
        excluded_scope=args.exclude,
        safety_mode=SafetyMode.HIGH_RISK,
        credential_approval_required=bool(credential_reference),
        high_risk_approval_required=True,
        credential_reference=credential_reference,
        confirmation_method=(
            ConfirmationMethod.CLI_FLAG
            if args.auto_confirm or args.allow_destructive
            else ConfirmationMethod.CLI_PROMPT
        ),
        confirmed_by=operator_id,
    )
    session = open_authorization_session()
    try:
        issued = issue_authorization(
            session=session,
            context=base_context,
            confirmation=confirmation,
        )
        if not issued.allowed:
            return decision_for_reason(ScopeReason.INVALID_CONFIRMATION), None
        consumed = consume_authorization(
            session=session,
            envelope=issued.envelope,
            expected=base_context,
            boundary="aiforge.cli",
        )
        if not consumed.allowed:
            return decision_for_reason(ScopeReason.INVALID_CONFIRMATION), None
        engine_context = AuthorizationContext(
            **{
                **base_context.__dict__,
                "action_kind": "engine.execute",
                "parent_decision_id": issued.envelope.decision_id,
                "confirmation_method": ConfirmationMethod.INHERITED,
            }
        )
        derived = derive_authorization(
            session=session,
            parent_envelope=issued.envelope,
            context=engine_context,
            parent_boundary="aiforge.cli",
        )
        if not derived.allowed:
            return decision_for_reason(ScopeReason.INVALID_CONFIRMATION), None
        args._authorization_runtime = load_authorization_runtime_facts(
            authorization_runtime_environment(derived.envelope)
        )
        return decision_for_reason(ScopeReason.ALLOWED), derived.envelope
    finally:
        session.close()


def _apply_launch_context(
    cfg: BaseForgeConfig,
    args: argparse.Namespace,
    confirmations: list[ActionConfirmation],
    authorization: ActionAuthorizationEnvelope | None,
) -> None:
    cfg.extra["allowed_scope"] = list(args.scope or [])
    cfg.extra["excluded_scope"] = list(args.exclude or [])
    requested_modules = _requested_modules(args)
    cfg.extra["authorized_requested_modules"] = requested_modules
    cfg.extra["authorization_module_binding"] = module_set_binding(requested_modules)
    runtime = getattr(args, "_authorization_runtime", None)
    if not isinstance(runtime, Mapping):
        runtime = load_authorization_runtime_facts()
    cfg.extra["authorization_runtime"] = dict(runtime)
    cfg.extra["runtime_credential_reference"] = _credential_reference(args)
    confirmation = _confirmation_for_target(confirmations, args.target)
    if confirmation is not None:
        cfg.extra["job_id"] = getattr(args, "_launch_job_id", "")
        cfg.extra["launch_action"] = getattr(args, "_launch_action", "")
        cfg.extra["launch_confirmation"] = confirmation
    if authorization is not None:
        cfg.extra["authorization_envelope"] = authorization


def _launch_decision(cfg: BaseForgeConfig, args: argparse.Namespace) -> ScopeDecision:
    action = str(cfg.extra.get("launch_action") or DEFAULT_LAUNCH_ACTION)
    if action != DEFAULT_LAUNCH_ACTION:
        return decision_for_reason(ScopeReason.ACTION_MISMATCH)
    return decide_action(
        target=cfg.target,
        allowed_scope=cfg.extra.get("allowed_scope", getattr(args, "scope", None)),
        excluded_scope=cfg.extra.get("excluded_scope", getattr(args, "exclude", None)),
        confirmation=cfg.extra.get("launch_confirmation"),
        job_id=str(cfg.extra.get("job_id") or ""),
        engine=ENGINE_NAME,
        action=action,
        require_confirmation=not bool(args.dry_run),
    )


def _consume_engine_authorization(cfg: BaseForgeConfig) -> AuthorizationDecision:
    envelope = cfg.extra.get("authorization_envelope")
    if isinstance(envelope, dict):
        try:
            envelope = ActionAuthorizationEnvelope.from_value(envelope)
        except (TypeError, ValueError):
            pass
    if isinstance(envelope, ActionAuthorizationEnvelope):
        expected = _authorization_context_from_envelope(
            envelope,
            cfg,
            action_kind="engine.execute",
            module_id=str(cfg.extra.get("authorization_module_binding", "")),
        )
    else:
        expected = AuthorizationContext(
            tenant_id="default",
            engagement_id=str(cfg.engagement or "default"),
            run_id=str(cfg.extra.get("job_id") or "legacy-run"),
            job_id=str(cfg.extra.get("job_id") or "legacy-job"),
            operator_id="legacy-operator",
            operator_role=OperatorRole.OPERATOR,
            action_kind="engine.execute",
            engine=ENGINE_NAME,
            module_id="",
            requested_target=cfg.target,
            resolved_target=cfg.target,
            allowed_scope=cfg.extra.get("allowed_scope", []),
            excluded_scope=cfg.extra.get("excluded_scope", []),
            safety_mode=SafetyMode.HIGH_RISK,
            high_risk_approval_required=True,
            confirmation_method=ConfirmationMethod.NONE,
        )
    session = open_authorization_session()
    try:
        if (
            isinstance(envelope, ActionAuthorizationEnvelope)
            and cfg.extra.get("consumed_engine_authorization") == envelope.decision_id
        ):
            return validate_consumed_authorization(
                session=session,
                envelope=envelope,
                expected=expected,
                boundary="aiforge.engine",
            )
        decision = consume_authorization(
            session=session,
            envelope=envelope,
            expected=expected,
            boundary="aiforge.engine",
        )
        if decision.allowed:
            cfg.extra["consumed_engine_authorization"] = decision.envelope.decision_id
        return decision
    finally:
        session.close()


def _authorize_module_execution(
    cfg: BaseForgeConfig,
    parent: ActionAuthorizationEnvelope,
    module_name: str,
) -> AuthorizationDecision:
    context = _authorization_context_from_envelope(
        parent,
        cfg,
        action_kind="module.execute",
        module_id=module_name,
    )
    session = open_authorization_session()
    try:
        if not module_binding_allows(
            parent.module_id,
            cfg.extra.get("authorized_requested_modules", []),
            module_name,
        ):
            return record_authorization_denial(
                session=session,
                context=context,
                reason_code=AuthorizationReason.MODULE_MISMATCH,
                parent_decision_id=parent.decision_id,
            )
        derived = derive_authorization(
            session=session,
            parent_envelope=parent,
            context=context,
            parent_boundary="aiforge.engine",
        )
        if not derived.allowed:
            return derived
        consumed = consume_authorization(
            session=session,
            envelope=derived.envelope,
            expected=context,
            boundary="aiforge.module",
        )
        if consumed.allowed:
            cfg.extra.setdefault("authorized_module_decisions", {})[module_name] = (
                derived.envelope.decision_id
            )
            cfg.extra.setdefault("authorized_module_envelopes", {})[module_name] = (
                derived.envelope
            )
        return consumed
    finally:
        session.close()


def _record_module_denial(
    cfg: BaseForgeConfig,
    parent: ActionAuthorizationEnvelope,
    module_name: str,
) -> None:
    context = _authorization_context_from_envelope(
        parent,
        cfg,
        action_kind="module.execute",
        module_id=module_name,
    )
    session = open_authorization_session()
    try:
        record_authorization_denial(
            session=session,
            context=context,
            reason_code=AuthorizationReason.APPROVAL_MISMATCH,
            parent_decision_id=parent.decision_id,
        )
    finally:
        session.close()


def load_module_class(module_name: str) -> Any:
    module_path = MODULE_MAP.get(module_name)
    class_name  = CLASS_NAME_MAP.get(module_name)
    if not module_path or not class_name:
        return None
    try:
        mod = importlib.import_module(module_path)
        return getattr(mod, class_name, None)
    except ImportError as exc:
        log.debug("Module not yet available: %s — %s", module_name, exc)
        return None


def setup_results_dir(target: str, engagement: str) -> Path:
    from urllib.parse import urlparse
    host = urlparse(target).netloc.replace(":", "_").replace("/", "_") or "ai_target"
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    path = Path(__file__).parent / "results" / f"{engagement}_{host}_{ts}"
    path.mkdir(parents=True, exist_ok=True)
    (path / "evidence").mkdir(parents=True, exist_ok=True)
    return path


async def run_scan(
    cfg: BaseForgeConfig,
    args: argparse.Namespace,
    results_dir: Path,
    event_bus: Any = None,
    scan_control: ScanControl | None = None,
) -> dict[str, Any]:
    """Core scan loop — EventBus wired, pause/resume/abort ready."""
    launch_decision = _launch_decision(cfg, args)
    if not launch_decision.allowed:
        _audit_scope_denial(args, launch_decision, target=cfg.target)
        _print_launch_denial(launch_decision)
        return _denied_summary(launch_decision, dry_run=bool(args.dry_run))
    if args.dry_run:
        return {
            "status": "completed",
            "findings": 0,
            "errors": [],
            "duration": 0.0,
            "dry_run": True,
            "authorized": False,
            "plan": {
                "target": safe_target_display(cfg.target),
                "engine": ENGINE_NAME,
                "authorized": False,
            },
        }

    authorization_decision = _consume_engine_authorization(cfg)
    if not authorization_decision.allowed:
        log.warning(
            "Engine authorization denied reason_code=%s",
            authorization_decision.reason_code,
        )
        return _authorization_denied_summary(authorization_decision)
    engine_authorization = authorization_decision.envelope

    bus, Event, EventType = _get_event_bus(event_bus)
    ctrl = scan_control or ScanControl()
    cfg.extra["outbound_cancellation_check"] = lambda: ctrl.is_aborted

    db_path = results_dir / "aiforge.db"
    db_session = create_db(db_path)

    scope = Scope(
        cfg.extra.get("allowed_scope", args.scope),
        excluded=cfg.extra.get("excluded_scope", args.exclude),
    )

    run_id = engine_authorization.run_id
    run = ScanRunModel(
        id=run_id, framework="aiforge", target=cfg.target,
        mode=cfg.mode, engagement=cfg.engagement, tester=cfg.tester,
    )
    db_session.add(run)
    db_session.commit()

    include = [m.strip() for m in args.modules.split(",")] if args.modules else None
    skip    = [m.strip() for m in args.skip_modules.split(",")] if args.skip_modules else None

    all_module_names = [m for p in PHASES for m in p["modules"]]

    # ── Emit: scan_start ──────────────────────────────────────────────
    _emit(bus, Event, EventType, "scan_start", source="aiforge",
          target=safe_target_display(cfg.target), mode=cfg.mode, engagement=cfg.engagement,
          tester=cfg.tester, framework="AIForge", modules=all_module_names)

    total_modules = sum(len(p["modules"]) for p in PHASES)
    console.print(f"\n[bold cyan]AIForge v{VERSION}[/bold cyan] — Target: [cyan]{cfg.target}[/cyan]")
    console.print(f"Mode: [yellow]{args.mode}[/yellow] | API: {args.api_type} | Phases: {len(PHASES)} | Modules: {total_modules}")

    all_findings: list[Finding] = []
    errors: list[str] = []
    aborted = False
    start_time = time.monotonic()

    for phase in PHASES:
        if phase["name"] == "Reporting":
            continue

        # ── Abort check ───────────────────────────────────────────────
        if ctrl.is_aborted:
            aborted = True
            break

        # ── Pause gate ────────────────────────────────────────────────
        if ctrl.is_paused:
            _emit(bus, Event, EventType, "scan_paused", source="aiforge")
            await ctrl.wait_if_paused()
            if ctrl.is_aborted:
                aborted = True
                break
            _emit(bus, Event, EventType, "scan_resumed", source="aiforge")

        phase_banner(phase["number"], len(PHASES), phase["name"])

        # ── Emit: phase_start ─────────────────────────────────────────
        _emit(bus, Event, EventType, "phase_start", source="aiforge",
              number=phase["number"], name=phase["name"], modules=phase["modules"])

        phase_start = time.monotonic()

        for module_name in phase["modules"]:
            if include and module_name not in include:
                continue
            if skip and module_name in skip:
                continue

            # ── Abort / pause mid-phase ───────────────────────────────
            if ctrl.is_aborted:
                aborted = True
                break
            if ctrl.is_paused:
                _emit(bus, Event, EventType, "scan_paused", source="aiforge")
                await ctrl.wait_if_paused()
                if ctrl.is_aborted:
                    aborted = True
                    break
                _emit(bus, Event, EventType, "scan_resumed", source="aiforge")

            # DoS / destructive safety gates
            is_dos = module_name in DOS_MODULES
            is_destructive = module_name in DESTRUCTIVE_MODULES

            if is_dos and args.no_dos:
                log.info("Skipping DoS module %s (--no-dos)", module_name)
                _emit(bus, Event, EventType, "module_skip", source=module_name,
                      name=module_name, reason="--no-dos")
                continue
            if is_destructive and args.no_destructive:
                log.info("Skipping destructive module %s (--no-destructive)", module_name)
                _emit(bus, Event, EventType, "module_skip", source=module_name,
                      name=module_name, reason="--no-destructive")
                continue

            if (is_dos or is_destructive) and not args.allow_destructive:
                category = "DoS + Destructive" if (is_dos and is_destructive) else ("DoS" if is_dos else "Destructive")
                if not confirm_dangerous_module(module_name, cfg.target, category):
                    _record_module_denial(cfg, engine_authorization, module_name)
                    _emit(bus, Event, EventType, "module_skip", source=module_name,
                          name=module_name, reason="operator declined destructive")
                    continue

            if module_name in MODULE_MAP:
                from common.outbound_policy import evaluate_module_outbound_support
                support = evaluate_module_outbound_support(
                    engine=ENGINE_NAME,
                    module_id=module_name,
                )
                if not support.supported:
                    errors.append(f"{module_name}: {support.reason_code}")
                    _emit(
                        bus, Event, EventType, "module_skip",
                        source=module_name, name=module_name,
                        reason=support.reason_code, outcome=support.outcome,
                    )
                    continue

            cls = load_module_class(module_name)
            if cls is None:
                log.debug("Module not available: %s", module_name)
                _emit(bus, Event, EventType, "module_skip", source=module_name,
                      name=module_name, reason="not built")
                continue

            module_authorization = _authorize_module_execution(
                cfg,
                engine_authorization,
                module_name,
            )
            if not module_authorization.allowed:
                reason = module_authorization.reason_code
                errors.append(f"{module_name}: not authorized ({reason})")
                _emit(
                    bus,
                    Event,
                    EventType,
                    "module_skip",
                    source=module_name,
                    name=module_name,
                    reason=reason,
                )
                continue

            # ── Emit: module_start ────────────────────────────────────
            _emit(bus, Event, EventType, "module_start", source=module_name,
                  name=module_name, phase=phase["number"])

            module_config = cfg.model_copy(deep=False)
            module_config.extra = dict(cfg.extra)
            mod_instance = cls(
                config=module_config, scope=scope, db_session=db_session,
                results_dir=results_dir, run_id=run_id,
            )

            try:
                log.info("Running module: %s", module_name)
                result = await mod_instance.run()
                if ctrl.is_aborted:
                    aborted = True
                    _emit(
                        bus, Event, EventType, "module_skip",
                        source=module_name, name=module_name,
                        reason="cancelled", outcome="canceled",
                    )
                    break
                module_policy = getattr(mod_instance, "outbound_policy", None)
                if module_policy is not None and module_policy.last_denial_reason:
                    from common.outbound_policy import OutboundDenied
                    raise OutboundDenied(module_policy.last_denial_reason)
                from common.base_module import (
                    merge_module_output_extra,
                    module_result_error_text,
                )
                result_error = module_result_error_text(result)
                if result_error:
                    raise RuntimeError(result_error)
                if result is not None and getattr(result, "skipped", False):
                    reason = str(
                        redact_authorization_value(
                            str(getattr(result, "skip_reason", "") or "not_tested")
                        )
                    )
                    _emit(
                        bus,
                        Event,
                        EventType,
                        "module_skip",
                        source=module_name,
                        name=module_name,
                        reason=reason,
                        outcome="not_tested",
                    )
                    continue
                merge_module_output_extra(cfg.extra, module_config.extra)
                if result and result.findings:
                    all_findings.extend(result.findings)

                    _emit(bus, Event, EventType, "module_complete", source=module_name,
                          name=module_name, findings_count=len(result.findings))

                    for finding in result.findings:
                        fd = finding.to_dict()
                        _emit(bus, Event, EventType, "finding_new", source=module_name,
                              **fd)

                    log.info("Module %s: %d findings", module_name, len(result.findings))
                else:
                    _emit(bus, Event, EventType, "module_complete", source=module_name,
                          name=module_name, findings_count=0)

            except Exception as exc:
                if ctrl.is_aborted or getattr(exc, "reason_code", "") == "cancelled":
                    aborted = True
                    _emit(
                        bus, Event, EventType, "module_skip",
                        source=module_name, name=module_name,
                        reason="cancelled", outcome="canceled",
                    )
                    break
                safe_error = str(redact_authorization_value(str(exc)))
                log.error("Module %s failed: %s", module_name, safe_error)
                errors.append(f"{module_name}: {safe_error}")
                _emit(bus, Event, EventType, "module_fail", source=module_name,
                      name=module_name, error=safe_error)

        # ── Emit: phase_complete ──────────────────────────────────────
        phase_duration = time.monotonic() - phase_start
        _emit(bus, Event, EventType, "phase_complete", source="aiforge",
              number=phase["number"], name=phase["name"],
              duration=round(phase_duration, 1))

    status = "aborted" if aborted else ("failed" if errors else "completed")
    run.ended_at = datetime.now(timezone.utc)
    run.status = status
    db_session.commit()

    elapsed = time.monotonic() - start_time

    if aborted:
        _emit(bus, Event, EventType, "scan_aborted", source="aiforge",
              reason="operator", target=safe_target_display(cfg.target),
              findings=len(all_findings), duration=round(elapsed, 1))
    elif errors:
        _emit(bus, Event, EventType, "scan_interrupted", source="aiforge",
              target=safe_target_display(cfg.target), findings=len(all_findings),
              duration=round(elapsed, 1), errors=errors)
    else:
        _emit(bus, Event, EventType, "scan_complete", source="aiforge",
              target=safe_target_display(cfg.target), findings=len(all_findings),
              duration=round(elapsed, 1))

    phase_banner(len(PHASES), len(PHASES), "Reporting")
    formats = [f.strip() for f in args.report_format.split(",")]
    reporter = BaseReporter(
        findings=[f.to_dict() for f in all_findings],
        results_dir=results_dir,
        engagement=cfg.engagement,
        target=cfg.target,
        tester=cfg.tester,
        framework="AIForge",
        formats=formats,
    )
    report_paths = reporter.generate_all()

    label = (
        "AI ASSESSMENT ABORTED"
        if aborted
        else ("AI ASSESSMENT FAILED" if errors else "AI ASSESSMENT COMPLETE")
    )
    color = "yellow" if aborted else ("red" if errors else "green")
    console.print(f"\n[bold {color}]═══ {label} ═══[/bold {color}]")
    console.print(f"  Duration:  {elapsed:.1f}s")
    console.print(f"  Findings:  {len(all_findings)}")
    console.print(f"  Results:   {results_dir}")
    for fmt, path in report_paths.items():
        console.print(f"  Report ({fmt}): {path}")

    db_session.close()

    return {
        "status": status,
        "findings": len(all_findings),
        "errors": errors,
        "duration": round(elapsed, 1),
    }


async def run_for_target(
    target_entry: Any,
    base_args: argparse.Namespace,
    event_bus: Any = None,
    scan_control: ScanControl | None = None,
) -> dict[str, Any]:
    """Entry point for TargetManager multi-target orchestration."""
    import copy
    args = copy.deepcopy(base_args)
    args.target = target_entry.target

    for key in ("rate", "max_tokens", "temperature"):
        if key in target_entry.options and hasattr(args, key):
            setattr(args, key, target_entry.options[key])

    confirmations = list(
        getattr(args, "_launch_confirmations", None) or load_launch_confirmations()
    )
    confirmation = _confirmation_for_target(confirmations, args.target)
    preflight = decide_action(
        target=args.target,
        allowed_scope=args.scope,
        excluded_scope=args.exclude,
        confirmation=confirmation,
        job_id=str(getattr(args, "_launch_job_id", "")),
        engine=ENGINE_NAME,
        action=str(getattr(args, "_launch_action", DEFAULT_LAUNCH_ACTION)),
        require_confirmation=not bool(args.dry_run),
    )
    if not preflight.allowed:
        _audit_scope_denial(args, preflight, target=args.target)
        _print_launch_denial(preflight)
        return _denied_summary(preflight, dry_run=bool(args.dry_run))

    config_path = Path(args.config) if args.config else Path(__file__).parent / "aiforge.yaml"
    cfg = load_config(config_path)
    cfg.target     = args.target
    cfg.engagement = args.engagement
    cfg.tester     = args.tester
    cfg.mode       = args.mode
    cfg.dry_run    = args.dry_run
    cfg.rate.requests_per_second = args.rate
    cfg.verbose    = getattr(args, "verbose", False)
    cfg.quiet      = getattr(args, "quiet", False)
    if args.proxy:
        cfg.proxy = args.proxy
        cfg.extra["proxy"] = args.proxy
    if args.api_key:
        cfg.extra["api_key"] = args.api_key
    cfg.extra["api_type"]     = args.api_type
    cfg.extra["model_name"]   = args.model_name or ""
    cfg.extra["max_tokens"]   = args.max_tokens
    cfg.extra["temperature"]  = args.temperature
    authorization = getattr(args, "_authorization_envelope", None)
    if authorization is None and not args.dry_run:
        authorization = select_authorization_envelope(
            load_authorization_envelopes(),
            job_id=str(getattr(args, "_launch_job_id", "")),
            engine=ENGINE_NAME,
            action_kind="engine.execute",
            requested_target=args.target,
            resolved_target=args.target,
            module_id=module_set_binding(_requested_modules(args)),
        )
    _apply_launch_context(cfg, args, confirmations, authorization)

    if not args.dry_run:
        authorization_decision = _consume_engine_authorization(cfg)
        if not authorization_decision.allowed:
            return _authorization_denied_summary(authorization_decision)

    results_dir = setup_results_dir(args.target, args.engagement)

    return await run_scan(cfg, args, results_dir, event_bus, scan_control)


def _summary_exit_code(summary: Mapping[str, Any] | None) -> int:
    return 0 if summary and summary.get("status") == "completed" else 1


async def main() -> int:
    args = parse_args()

    if args.list_modules:
        console.print("\n[bold cyan]AIForge Modules[/bold cyan]")
        for phase in PHASES:
            console.print(f"\n[bold]Phase {phase['number']}: {phase['name']}[/bold]")
            for mod in phase["modules"]:
                console.print(f"  • {mod}")
        return 0

    launch_decision, confirmations = _prepare_cli_confirmation(args)
    if not launch_decision.allowed:
        _audit_scope_denial(args, launch_decision, target=args.target)
        _print_launch_denial(launch_decision)
        sys.exit(1)
    args._launch_confirmations = confirmations
    if args.dry_run:
        authorization = None
    else:
        auth_decision, authorization = _prepare_engine_authorization(
            args,
            confirmations,
        )
        if not auth_decision.allowed or authorization is None:
            _print_launch_denial(auth_decision)
            sys.exit(1)
    args._authorization_envelope = authorization
    set_auto_confirm(args.auto_confirm)

    config_path = Path(args.config) if args.config else Path(__file__).parent / "aiforge.yaml"
    cfg = load_config(config_path)
    cfg.target     = args.target
    cfg.engagement = args.engagement
    cfg.tester     = args.tester
    cfg.mode       = args.mode
    cfg.dry_run    = args.dry_run
    cfg.rate.requests_per_second = args.rate
    cfg.verbose    = args.verbose
    cfg.quiet      = args.quiet
    if args.proxy:
        cfg.proxy = args.proxy
        cfg.extra["proxy"] = args.proxy
    if args.api_key:
        cfg.extra["api_key"] = args.api_key
    cfg.extra["api_type"]     = args.api_type
    cfg.extra["model_name"]   = args.model_name or ""
    cfg.extra["max_tokens"]   = args.max_tokens
    cfg.extra["temperature"]  = args.temperature
    if args.system_prompt:
        cfg.extra["known_system_prompt"] = args.system_prompt
    if args.model_info:
        cfg.extra["model_info_path"] = args.model_info
    _apply_launch_context(cfg, args, confirmations, authorization)

    if not args.dry_run:
        authorization_decision = _consume_engine_authorization(cfg)
        if not authorization_decision.allowed:
            log.warning(
                "Engine authorization denied reason_code=%s",
                authorization_decision.reason_code,
            )
            sys.exit(1)

    results_dir = setup_results_dir(args.target, args.engagement)
    log.info("Results directory: %s", results_dir)

    if args.dry_run:
        return _summary_exit_code(await run_scan(cfg, args, results_dir))

    # Wire EventBus — remote when dashboard URL given, local otherwise
    event_bus = None
    if args.dashboard_url:
        try:
            from common.dashboard.event_bus import RemoteEventBus
            event_bus = RemoteEventBus(args.dashboard_url, run_id="aiforge")
            if event_bus.start():
                log.info("Dashboard relay active: %s", args.dashboard_url)
            else:
                cfg.extra["dashboard_relay_state"] = event_bus.disabled_reason
                log.warning(
                    "Dashboard relay not authorized: %s",
                    event_bus.disabled_reason,
                )
        except Exception as exc:
            log.warning("RemoteEventBus init failed: %s — events won't reach dashboard", exc)
    else:
        try:
            from common.dashboard.event_bus import EventBus
            event_bus = EventBus(run_id="aiforge")
            event_bus.start()
        except ImportError:
            pass

    summary = await run_scan(cfg, args, results_dir, event_bus=event_bus)

    if event_bus and hasattr(event_bus, "stop"):
        event_bus.stop()
    return _summary_exit_code(summary)


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
