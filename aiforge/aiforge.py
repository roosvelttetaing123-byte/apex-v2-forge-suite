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
import importlib
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent))

from common.auth_prompt import require_authorization
from common.config import BaseForgeConfig, load_config
from common.confirm_gate import set_auto_confirm
from common.db import create_db, ScanRunModel
from common.finding import Finding
from common.logger import get_logger, phase_banner, console
from common.reporter import BaseReporter
from common.scope import Scope

from rich.panel import Panel

log = get_logger("aiforge")

VERSION = "5.0.0"

DOS_MODULES = {"resource_exhaustion", "rate_limit_test"}
DESTRUCTIVE_MODULES = {"resource_exhaustion"}  # overlap intentional — resource_exhaustion is both


def confirm_dangerous_module(module_name: str, target: str, category: str) -> bool:
    """Big red double-confirmation gate for DoS/destructive modules.

    This CANNOT be bypassed by --auto-confirm. Only --allow-destructive skips it.
    Returns True if operator explicitly types 'YES I UNDERSTAND'.
    """
    console.print()
    console.print(Panel(
        f"[bold white on red]  WARNING: DESTRUCTIVE / DoS MODULE  [/bold white on red]\n\n"
        f"  Module   : [bold]{module_name}[/bold]\n"
        f"  Target   : [bold]{target}[/bold]\n"
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
        log.warning("DESTRUCTIVE MODULE %s confirmed by operator on %s", module_name, target)
    else:
        console.print(f"[yellow]  Skipped {module_name} — operator declined.[/yellow]")
        log.info("DESTRUCTIVE MODULE %s skipped by operator on %s", module_name, target)
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
        bus.emit(Event(event_type=EventType(etype), data=data, source=source))
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
    parser.add_argument("--scope",         nargs="*", default=[],      help="In-scope hosts/CIDRs")
    parser.add_argument("--auto-confirm",  action="store_true",        help="Skip confirmation gates")
    parser.add_argument("--no-dos",        action="store_true",        help="Skip all DoS/resource exhaustion modules")
    parser.add_argument("--no-destructive", action="store_true",       help="Skip all destructive exploit modules")
    parser.add_argument("--allow-destructive", action="store_true",    help="Pre-approve destructive modules (skip red warning)")
    parser.add_argument("--max-tokens",    type=int, default=2000,     help="Max tokens per request")
    parser.add_argument("--temperature",   type=float, default=0.7,    help="Temperature for generations")
    parser.add_argument("--list-modules",  action="store_true",        help="List modules and exit")
    parser.add_argument("--verbose",       action="store_true",        help="Verbose output")
    parser.add_argument("--quiet",         action="store_true",        help="Suppress UI output")
    parser.add_argument("--version",       action="version", version=f"AIForge {VERSION}")
    parser.add_argument("--dashboard-url", default=None,
                        help="Live dashboard URL (e.g. http://localhost:1337) — streams events in real time")
    return parser.parse_args()


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
    bus, Event, EventType = _get_event_bus(event_bus)
    ctrl = scan_control or ScanControl()

    db_path = results_dir / "aiforge.db"
    db_session = create_db(db_path)

    scope_targets = [cfg.target] + (args.scope or [])
    scope = Scope(scope_targets)

    run_id = str(uuid.uuid4())
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
          target=cfg.target, mode=cfg.mode, engagement=cfg.engagement,
          tester=cfg.tester, framework="AIForge", modules=all_module_names)

    total_modules = sum(len(p["modules"]) for p in PHASES)
    console.print(f"\n[bold cyan]AIForge v{VERSION}[/bold cyan] — Target: [cyan]{cfg.target}[/cyan]")
    console.print(f"Mode: [yellow]{args.mode}[/yellow] | API: {args.api_type} | Phases: {len(PHASES)} | Modules: {total_modules}")

    all_findings: list[Finding] = []
    errors: list[str] = []
    start_time = time.monotonic()

    for phase in PHASES:
        if phase["name"] == "Reporting":
            continue

        # ── Abort check ───────────────────────────────────────────────
        if ctrl.is_aborted:
            _emit(bus, Event, EventType, "scan_aborted", source="aiforge",
                  reason="operator", target=cfg.target)
            break

        # ── Pause gate ────────────────────────────────────────────────
        if ctrl.is_paused:
            _emit(bus, Event, EventType, "scan_paused", source="aiforge")
            await ctrl.wait_if_paused()
            if ctrl.is_aborted:
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
                break
            if ctrl.is_paused:
                _emit(bus, Event, EventType, "scan_paused", source="aiforge")
                await ctrl.wait_if_paused()
                if ctrl.is_aborted:
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
                    _emit(bus, Event, EventType, "module_skip", source=module_name,
                          name=module_name, reason="operator declined destructive")
                    continue

            cls = load_module_class(module_name)
            if cls is None:
                log.debug("Module not available: %s", module_name)
                _emit(bus, Event, EventType, "module_skip", source=module_name,
                      name=module_name, reason="not built")
                continue

            # ── Emit: module_start ────────────────────────────────────
            _emit(bus, Event, EventType, "module_start", source=module_name,
                  name=module_name, phase=phase["number"])

            mod_instance = cls(
                config=cfg, scope=scope, db_session=db_session,
                results_dir=results_dir, run_id=run_id,
            )

            try:
                log.info("Running module: %s", module_name)
                result = await mod_instance.run()
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
                log.error("Module %s failed: %s", module_name, exc)
                errors.append(f"{module_name}: {exc}")
                _emit(bus, Event, EventType, "module_fail", source=module_name,
                      name=module_name, error=str(exc))

        # ── Emit: phase_complete ──────────────────────────────────────
        phase_duration = time.monotonic() - phase_start
        _emit(bus, Event, EventType, "phase_complete", source="aiforge",
              number=phase["number"], name=phase["name"],
              duration=round(phase_duration, 1))

    run.ended_at = datetime.now(timezone.utc)
    run.status = "completed"
    db_session.commit()

    elapsed = time.monotonic() - start_time

    # ── Emit: scan_complete ───────────────────────────────────────────
    _emit(bus, Event, EventType, "scan_complete", source="aiforge",
          target=cfg.target, findings=len(all_findings), duration=round(elapsed, 1))

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

    console.print(f"\n[bold green]═══ AI ASSESSMENT COMPLETE ═══[/bold green]")
    console.print(f"  Duration:  {elapsed:.1f}s")
    console.print(f"  Findings:  {len(all_findings)}")
    console.print(f"  Results:   {results_dir}")
    for fmt, path in report_paths.items():
        console.print(f"  Report ({fmt}): {path}")

    db_session.close()

    return {
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

    for key, val in target_entry.options.items():
        if hasattr(args, key):
            setattr(args, key, val)

    results_dir = setup_results_dir(args.target, args.engagement)
    config_path = Path(args.config) if args.config else Path(__file__).parent / "aiforge.yaml"
    cfg = load_config(config_path)
    cfg.target     = args.target
    cfg.engagement = args.engagement
    cfg.tester     = args.tester
    cfg.mode       = args.mode
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

    return await run_scan(cfg, args, results_dir, event_bus, scan_control)


async def main() -> None:
    args = parse_args()

    if args.list_modules:
        console.print("\n[bold cyan]AIForge Modules[/bold cyan]")
        for phase in PHASES:
            console.print(f"\n[bold]Phase {phase['number']}: {phase['name']}[/bold]")
            for mod in phase["modules"]:
                console.print(f"  • {mod}")
        return

    require_authorization(args.target, "AIForge")
    set_auto_confirm(args.auto_confirm)

    results_dir = setup_results_dir(args.target, args.engagement)
    log.info("Results directory: %s", results_dir)

    config_path = Path(args.config) if args.config else Path(__file__).parent / "aiforge.yaml"
    cfg = load_config(config_path)
    cfg.target     = args.target
    cfg.engagement = args.engagement
    cfg.tester     = args.tester
    cfg.mode       = args.mode
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

    # Wire EventBus — remote when dashboard URL given, local otherwise
    event_bus = None
    if args.dashboard_url:
        try:
            from common.dashboard.event_bus import RemoteEventBus
            event_bus = RemoteEventBus(args.dashboard_url, run_id="aiforge")
            event_bus.start()
            log.info("Dashboard relay: %s", args.dashboard_url)
        except Exception as exc:
            log.warning("RemoteEventBus init failed: %s — events won't reach dashboard", exc)
    else:
        try:
            from common.dashboard.event_bus import EventBus
            event_bus = EventBus(run_id="aiforge")
            event_bus.start()
        except ImportError:
            pass

    await run_scan(cfg, args, results_dir, event_bus=event_bus)

    if event_bus and hasattr(event_bus, "stop"):
        event_bus.stop()


if __name__ == "__main__":
    asyncio.run(main())
