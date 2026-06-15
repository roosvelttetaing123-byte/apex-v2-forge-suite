"""Operator confirmation gate — required before any active exploitation action."""
from __future__ import annotations

import asyncio
import logging
import sys
from typing import Callable

from rich.console import Console
from rich.panel import Panel

console = Console()
log = logging.getLogger(__name__)

# Global flag — set via --auto-confirm CLI flag (dangerous, documented)
_AUTO_CONFIRM: bool = False


def set_auto_confirm(enabled: bool) -> None:
    """Enable or disable auto-confirm mode. Only set from CLI --auto-confirm flag."""
    global _AUTO_CONFIRM
    _AUTO_CONFIRM = enabled
    if enabled:
        log.warning(
            "AUTO-CONFIRM MODE ENABLED — all confirmation gates will be bypassed automatically",
            extra={"detail": {"auto_confirm": True}},
        )


async def confirm(
    module: str,
    action: str,
    target: str,
    risk: str,
    on_confirm: Callable[[], None] | None = None,
    on_skip: Callable[[], None] | None = None,
) -> bool:
    """Display an operator confirmation prompt before executing a sensitive action.

    This is async so the event loop is not blocked while waiting for input.

    Args:
        module:     Module name requesting confirmation (e.g. 'kerberoast').
        action:     Human-readable description of what will happen.
        target:     The affected target (IP, hostname, object).
        risk:       Description of the risk/impact.
        on_confirm: Optional callback to run if operator confirms.
        on_skip:    Optional callback to run if operator skips.

    Returns:
        True if operator confirmed execution, False if skipped.
    """
    if _AUTO_CONFIRM:
        log.info(
            "AUTO-CONFIRM: %s on %s",
            action,
            target,
            extra={"forge_module": module, "target": target,
                   "operator_confirmed": True, "detail": {"action": action, "auto": True}},
        )
        if on_confirm:
            on_confirm()
        return True

    console.print(Panel(
        f"  [bold yellow]Module  :[/bold yellow] {module}\n"
        f"  [bold yellow]Action  :[/bold yellow] {action}\n"
        f"  [bold yellow]Target  :[/bold yellow] {target}\n"
        f"  [bold red]Risk    :[/bold red] {risk}\n\n"
        f"  Execute this action? ([green]yes[/green]/[red]no[/red]):",
        title="[bold cyan]ACTION REQUIRES OPERATOR CONFIRMATION[/bold cyan]",
        border_style="cyan",
        padding=(1, 2),
    ))

    try:
        # Run blocking input() in a thread so the event loop stays alive.
        answer = await asyncio.to_thread(input, "  Confirm (yes/no): ")
        answer = answer.strip().lower()
    except (EOFError, KeyboardInterrupt):
        answer = "no"

    confirmed = answer == "yes"

    log.info(
        "%s action '%s' on '%s': %s",
        module,
        action,
        target,
        "CONFIRMED" if confirmed else "SKIPPED",
        extra={
            "forge_module": module,
            "target": target,
            "operator_confirmed": confirmed,
            "detail": {"action": action, "risk": risk},
        },
    )

    if confirmed:
        console.print(f"[green]  [+] Executing: {action}[/green]")
        if on_confirm:
            on_confirm()
    else:
        console.print(f"[yellow]  [-] Skipped: {action} (logged as finding)[/yellow]")
        if on_skip:
            on_skip()

    return confirmed


class TestConfirmGate:
    """Unit tests for confirm_gate module."""

    def test_auto_confirm_mode(self) -> None:
        import asyncio
        set_auto_confirm(True)
        result = asyncio.run(confirm(
            module="test", action="test action", target="127.0.0.1",
            risk="low", on_confirm=None, on_skip=None,
        ))
        assert result is True
        set_auto_confirm(False)

    def test_set_auto_confirm(self) -> None:
        set_auto_confirm(True)
        assert _AUTO_CONFIRM is True
        set_auto_confirm(False)
        assert _AUTO_CONFIRM is False

    def test_callbacks_called(self) -> None:
        import asyncio
        called = []
        set_auto_confirm(True)
        asyncio.run(confirm(
            module="test", action="act", target="t", risk="r",
            on_confirm=lambda: called.append("confirmed"),
        ))
        assert "confirmed" in called
        set_auto_confirm(False)
