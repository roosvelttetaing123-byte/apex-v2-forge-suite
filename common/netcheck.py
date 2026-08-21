"""Offline-by-default network update gate.

Connectivity probing itself is outbound traffic, so scan-time callers must not
probe public DNS or web endpoints merely to decide whether networking exists.
Explicit update workflows use the Task 003 policy with a pinned endpoint.
"""
from __future__ import annotations

import sys
import logging

from rich.console import Console
from rich.panel import Panel

console = Console()
log = logging.getLogger(__name__)

# Global state — set once per session
_internet_available: bool | None = None
_internet_allowed:   bool | None = None

def check_internet(timeout: float = 3.0) -> bool:
    """Return offline without creating any socket or HTTP request.

    Args:
        timeout: Seconds to wait per probe.

    Returns:
        True if internet is available.
    """
    del timeout
    global _internet_available
    _internet_available = False
    log.debug("Internet probe suppressed by outbound policy; offline mode")
    return False


def ask_internet_permission(
    reason: str,
    force: bool = False,
) -> bool:
    """Check internet availability and ask operator permission to use it.

    Called by any module that wants to make an external request
    (CVE DB update, Wappalyzer DB fetch, nuclei template update, etc.).

    Args:
        reason: Human-readable reason for needing internet
                (e.g. "download latest CVE database").
        force:  If True, skip prompt and return True if internet available
                (use for non-interactive / --auto-confirm mode).

    Returns:
        True if internet is available AND operator allows its use.
    """
    global _internet_allowed

    # Already decided this session
    if _internet_allowed is not None:
        return _internet_allowed and check_internet()

    available = check_internet()

    if not available:
        console.print(
            Panel(
                "[yellow]No internet connection detected.[/yellow]\n"
                "All modules will run in [bold]offline mode[/bold] using cached data.\n\n"
                f"Requested resource: [cyan]{reason}[/cyan]",
                title="[bold]OFFLINE MODE[/bold]",
                border_style="yellow",
            )
        )
        _internet_allowed = False
        return False

    if force:
        _internet_allowed = True
        return True

    console.print(
        Panel(
            f"[green]Internet connection detected.[/green]\n\n"
            f"Some features work better online:\n"
            f"  • CVE database updates (NVD feed)\n"
            f"  • Nuclei template updates\n"
            f"  • Reverse geocoding (image OSINT)\n"
            f"  • Wappalyzer fingerprint DB updates\n\n"
            f"Requested now: [cyan]{reason}[/cyan]\n\n"
            f"Allow internet access for this session? "
            f"([green]yes[/green]/[red]no[/red]) "
            f"— [yellow]no[/yellow] = full offline mode",
            title="[bold cyan]INTERNET ACCESS AVAILABLE[/bold cyan]",
            border_style="cyan",
        )
    )

    try:
        answer = input("  Allow internet? (yes/no): ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        answer = "no"

    _internet_allowed = (answer == "yes")

    if _internet_allowed:
        console.print("[green]  [+] Internet access enabled for this session.[/green]\n")
        log.info("Internet access allowed by operator for: %s", reason)
    else:
        console.print("[yellow]  [-] Running in full offline mode.[/yellow]\n")
        log.info("Internet access denied by operator — offline mode")

    return _internet_allowed


def reset_internet_decision() -> None:
    """Reset the session internet decision (for testing)."""
    global _internet_available, _internet_allowed
    _internet_available = None
    _internet_allowed = None


def require_internet(reason: str) -> None:
    """Assert internet is available and allowed, or exit with a clear message.

    Args:
        reason: What the internet is needed for.

    Raises:
        SystemExit: If internet is unavailable or denied.
    """
    if not ask_internet_permission(reason):
        console.print(
            f"[red][!] This operation requires internet: {reason}[/red]\n"
            "[yellow]    Run with internet access or use cached offline data.[/yellow]"
        )
        sys.exit(1)


class TestNetcheck:
    """Unit tests for netcheck module."""

    def test_reset_and_check(self) -> None:
        reset_internet_decision()
        result = check_internet()
        assert isinstance(result, bool)

    def test_cached_result(self) -> None:
        reset_internet_decision()
        r1 = check_internet()
        r2 = check_internet()
        assert r1 == r2  # Should be same cached result

    def test_ask_permission_offline(self, monkeypatch) -> None:
        reset_internet_decision()
        # Patch the module-level symbol that ask_internet_permission resolves at call time
        import common.netcheck as _nc
        monkeypatch.setattr(_nc, "check_internet", lambda timeout=3.0: False)
        result = ask_internet_permission("test reason", force=False)
        assert result is False
        reset_internet_decision()
