"""Authorization confirmation prompt — displayed at startup of every forge tool."""
from __future__ import annotations

import sys

from rich.console import Console
from rich.panel import Panel

console = Console()


def require_authorization(target: str, tool_name: str) -> None:
    """Display authorization banner and require explicit 'yes' to continue.

    Args:
        target:    The target being tested.
        tool_name: Name of the tool (e.g. 'WebForge', 'NetForge', 'ADForge').

    Raises:
        SystemExit: If operator does not confirm authorization.
    """
    console.print(Panel(
        f"[bold yellow]  AUTHORIZED PENETRATION TESTING TOOL[/bold yellow]\n\n"
        f"  Tool   : [cyan]{tool_name}[/cyan]\n"
        f"  Target : [cyan]{target}[/cyan]\n\n"
        f"  [bold]You MUST have written authorization to test this target.[/bold]\n"
        f"  Unauthorized testing is illegal and unethical.\n\n"
        f"  Type [green]yes[/green] to confirm authorization, or [red]no[/red] to exit:",
        title="[bold red]⚠  AUTHORIZATION REQUIRED  ⚠[/bold red]",
        border_style="red",
        padding=(1, 2),
    ))

    try:
        answer = input("  Authorization confirmed? (yes/no): ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        console.print("\n[red]Aborted.[/red]")
        sys.exit(1)

    if answer != "yes":
        console.print("\n[red][!] Authorization not confirmed. Exiting.[/red]")
        sys.exit(1)

    console.print(f"\n[green][+] Authorization confirmed. Starting {tool_name}...[/green]\n")


class TestAuthPrompt:
    """Unit tests for auth_prompt module."""

    def test_import(self) -> None:
        from common.auth_prompt import require_authorization
        assert callable(require_authorization)
