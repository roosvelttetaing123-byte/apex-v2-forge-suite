"""Rich terminal War Room dashboard — TUI mirror of the web dashboard.

A full-featured terminal UI for operators who prefer a terminal workflow
over the web dashboard. Uses Rich's Layout, Live, Table, and Panel
widgets for real-time scan visualization.

Launch:
    python forge.py dashboard --tui
    python forge.py dashboard --tui --attach results_dir/

Features:
    - Kill chain pipeline with animated active phase
    - Live findings feed with severity coloring
    - Metrics sparklines (RPS, findings/min, errors)
    - Target status grid with compromise indicators
    - Credential vault (masked secrets)
    - Active sessions panel
    - Operator controls (pause/resume/abort)
    - Module progress tracker
    - Threat timeline with auto-scroll

Requires: pip install rich
"""
from __future__ import annotations

import asyncio
import logging
import signal
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger("forge.dashboard.tui")

# ── Conditional Rich import ───────────────────────────────────────────
try:
    from rich.align import Align
    from rich.columns import Columns
    from rich.console import Console, Group
    from rich.layout import Layout
    from rich.live import Live
    from rich.markup import escape
    from rich.padding import Padding
    from rich.panel import Panel
    from rich.progress import (
        BarColumn,
        Progress,
        SpinnerColumn,
        TextColumn,
        TaskID,
    )
    from rich.table import Table
    from rich.text import Text
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

from common.dashboard.event_bus import Event, EventBus, EventType
from common.dashboard.state_store import StateStore
from common.dashboard.metrics import sparkline as _sparkline_text

# ── Constants ─────────────────────────────────────────────────────────

SEVERITY_COLORS = {
    "Critical": "bold white on red",
    "High":     "bold red",
    "Medium":   "bold yellow",
    "Low":      "bold blue",
    "Info":     "dim",
    "Informational": "dim",
}

SEVERITY_BADGES = {
    "Critical": "[bold white on red] CRIT [/]",
    "High":     "[bold red] HIGH [/]",
    "Medium":   "[bold yellow] MED  [/]",
    "Low":      "[bold blue] LOW  [/]",
    "Info":     "[dim] INFO [/]",
    "Informational": "[dim] INFO [/]",
}

TARGET_STATUS_ICONS = {
    "shell":    "[bold red]🔴 SHELL[/]",
    "pwned":    "[bold #ff8c00]🟠 PWNED[/]",
    "scanning": "[bold white]⚪ SCANNING[/]",
    "clean":    "[bold green]🟢 CLEAN[/]",
    "queued":   "[bold blue]🔵 QUEUED[/]",
}

MODULE_STATUS_ICONS = {
    "queued":   "⏳",
    "running":  "🔄",
    "complete": "✅",
    "failed":   "❌",
    "skipped":  "⏭",
}

SCAN_STATUS_LABELS = {
    "initializing": "[dim]⏳ INITIALIZING[/]",
    "running":      "[bold green]▶ RUNNING[/]",
    "paused":       "[bold yellow]⏸ PAUSED[/]",
    "completed":    "[bold cyan]✅ COMPLETED[/]",
    "interrupted":  "[bold red]⚠ INTERRUPTED[/]",
    "aborted":      "[bold red]⏹ ABORTED[/]",
}

# ANSI sparkline characters for the metrics panel
SPARK_CHARS = "▁▂▃▄▅▆▇█"


def _mini_sparkline(values: list[float], width: int = 20) -> str:
    """Render a sparkline from float values."""
    if not values:
        return "▁" * width
    data = values[-width:]
    mx = max(data) if max(data) > 0 else 1.0
    return "".join(
        SPARK_CHARS[min(int(v / mx * (len(SPARK_CHARS) - 1)), len(SPARK_CHARS) - 1)]
        for v in data
    )


class WarRoomTUI:
    """Rich-based terminal War Room dashboard.

    Mirrors the web dashboard in the terminal using Rich's Live rendering.
    Subscribes to EventBus for real-time updates and renders StateStore
    snapshots at configurable refresh intervals.

    Args:
        event_bus:     EventBus instance for scan events.
        state_store:   StateStore instance for state snapshots.
        refresh_rate:  Dashboard refresh rate in Hz (default 4).
        max_findings:  Max findings to show in the feed (default 20).
    """

    def __init__(
        self,
        event_bus: EventBus | None = None,
        state_store: StateStore | None = None,
        refresh_rate: float = 4.0,
        max_findings: int = 20,
    ) -> None:
        if not HAS_RICH:
            raise ImportError(
                "Rich library not installed. Run: pip install rich"
            )

        self.event_bus = event_bus or EventBus(run_id="tui")
        self.state_store = state_store or StateStore(
            self.event_bus, framework="forge", target="",
        )
        self.refresh_interval = 1.0 / max(refresh_rate, 1.0)
        self.max_findings = max_findings
        self._console = Console()
        self._running = False
        self._paused = False
        self._active_tab = "main"  # main | credentials | sessions | topology
        self._flash_messages: list[tuple[float, str]] = []
        self._key_thread: threading.Thread | None = None

        # Subscribe for flash notifications on critical events
        self.event_bus.subscribe(EventType.FINDING_NEW, self._on_finding_flash)
        self.event_bus.subscribe(EventType.SHELL_SESSION, self._on_shell_flash)
        self.event_bus.subscribe(EventType.TARGET_PWNED, self._on_pwned_flash)
        self.event_bus.subscribe(EventType.CREDENTIAL_FOUND, self._on_cred_flash)

    # ── Flash notification handlers ───────────────────────────────────

    def _on_finding_flash(self, event: Event) -> None:
        sev = event.data.get("severity", "Info")
        if sev in ("Critical", "High"):
            self._flash(f"🚨 {sev.upper()}: {event.data.get('title', 'Finding')}")

    def _on_shell_flash(self, event: Event) -> None:
        self._flash(f"💀 SHELL OBTAINED: {event.data.get('target', '?')}")

    def _on_pwned_flash(self, event: Event) -> None:
        self._flash(f"🏴 TARGET PWNED: {event.data.get('target', '?')}")

    def _on_cred_flash(self, event: Event) -> None:
        self._flash(f"🔑 CREDENTIAL: {event.data.get('account', '?')}")

    def _flash(self, msg: str) -> None:
        """Add a flash message that expires after 5 seconds."""
        self._flash_messages.append((time.monotonic() + 5.0, msg))
        # Prune expired
        now = time.monotonic()
        self._flash_messages = [
            (t, m) for t, m in self._flash_messages if t > now
        ]

    # ── Layout construction ───────────────────────────────────────────

    def _build_layout(self) -> Layout:
        """Build the dashboard layout grid."""
        layout = Layout(name="root")

        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="flash", size=3),
            Layout(name="kill_chain", size=5),
            Layout(name="main", ratio=1),
            Layout(name="bottom", size=14),
            Layout(name="footer", size=3),
        )

        layout["main"].split_row(
            Layout(name="findings", ratio=3),
            Layout(name="targets", ratio=2),
        )

        layout["bottom"].split_row(
            Layout(name="modules", ratio=1),
            Layout(name="metrics", ratio=1),
            Layout(name="timeline", ratio=1),
        )

        return layout

    # ── Panel renderers ───────────────────────────────────────────────

    def _render_header(self) -> Panel:
        """Render the command bar / header panel."""
        snap = self.state_store.snapshot()
        status = snap.get("scan_status", "initializing")
        status_label = SCAN_STATUS_LABELS.get(status, f"[dim]{status}[/]")

        framework = snap.get("framework", "forge").upper()
        target = snap.get("target", "—")
        engagement = snap.get("engagement", "—") or "—"
        elapsed = snap.get("metrics", {}).get("elapsed", "00:00:00")
        eta = snap.get("metrics", {}).get("eta", "calculating...")

        header = Text.assemble(
            ("  ⚔️  FORGE SUITE v5 APEX ", "bold white on #1a1a2e"),
            (f"  {framework} ", "bold cyan"),
            ("  │  ", "dim"),
            (f"Target: {target[:40]} ", "bold white"),
            ("  │  ", "dim"),
            (f"Engagement: {engagement[:20]} ", "dim white"),
            ("  │  ", "dim"),
        )

        status_line = Text.assemble(
            ("  ", ""),
            (f"Status: ", "dim"),
        )
        # Can't combine markup and Text easily, so build raw
        status_text = f"  Status: {status_label}  │  Elapsed: [bold]{elapsed}[/]  │  ETA: [bold]{eta}[/]  │  [dim]P[/]ause  [dim]R[/]esume  [dim]A[/]bort  [dim]Q[/]uit"

        return Panel(
            status_text,
            title="[bold cyan]⚔️  FORGE SUITE v5 APEX — WAR ROOM[/]",
            title_align="left",
            subtitle=f"[dim]{framework} │ {target[:50]}[/]",
            subtitle_align="right",
            border_style="bright_cyan",
            padding=(0, 1),
        )

    def _render_flash(self) -> Panel:
        """Render flash notification bar."""
        now = time.monotonic()
        active = [(t, m) for t, m in self._flash_messages if t > now]
        self._flash_messages = active

        if not active:
            return Panel(
                "[dim]No alerts[/]",
                title="[bold yellow]📡 ALERTS[/]",
                border_style="dim",
                padding=(0, 1),
            )

        # Show latest flash
        _, msg = active[-1]
        blink = "bold yellow" if int(now * 2) % 2 == 0 else "bold red"
        return Panel(
            f"[{blink}]{escape(msg)}[/]",
            title=f"[bold yellow]📡 ALERTS ({len(active)})[/]",
            border_style="bold yellow",
            padding=(0, 1),
        )

    def _render_kill_chain(self) -> Panel:
        """Render the kill chain pipeline visualization."""
        snap = self.state_store.snapshot()
        kc = snap.get("kill_chain", {})
        phases = kc.get("phases", [])

        if not phases:
            return Panel(
                "[dim]Awaiting scan data...[/]",
                title="[bold cyan]🔗 KILL CHAIN[/]",
                border_style="cyan",
            )

        cells = []
        for p in phases:
            name = p.get("name", "?")
            icon = p.get("icon", "?")
            findings = p.get("findings", 0)
            pct = p.get("completion_pct", 0)
            is_active = p.get("is_active", False)
            is_reached = p.get("is_reached", False)

            if is_active:
                # Animated pulse for active phase
                pulse = ">>>" if int(time.monotonic() * 2) % 2 == 0 else "   "
                cell = f"[bold white on #e94560] {pulse} {icon} {name} {pulse} [/]"
            elif is_reached and findings > 0:
                cell = f"[bold white on #2d2d44] {icon} {name}:{findings} [/]"
            elif is_reached:
                cell = f"[bold green on #1a1a2e] {icon} {name} ✓ [/]"
            else:
                cell = f"[dim on #0a0a1a] {icon} {name} · [/]"

            cells.append(cell)

        chain = " → ".join(cells)
        compromise = kc.get("compromise_achieved", False)
        status_icon = "🏴 COMPROMISED" if compromise else "⏳ IN PROGRESS"
        overall = kc.get("overall_completion", 0)

        content = f"{chain}\n[dim]  {status_icon} │ Overall: {overall:.0f}%[/]"

        return Panel(
            content,
            title="[bold cyan]🔗 CYBER KILL CHAIN[/]",
            border_style="cyan",
            padding=(0, 1),
        )

    def _render_findings(self) -> Panel:
        """Render the findings feed panel."""
        snap = self.state_store.snapshot()
        findings = snap.get("findings", [])
        total = snap.get("findings_count", 0)

        table = Table(
            show_header=True,
            header_style="bold cyan",
            border_style="dim",
            expand=True,
            pad_edge=False,
            box=None,
        )
        table.add_column("SEV", width=6, justify="center")
        table.add_column("TITLE", ratio=3)
        table.add_column("MODULE", ratio=1)
        table.add_column("CVSS", width=5, justify="right")

        # Show last N findings, newest first
        visible = findings[-self.max_findings:][::-1]
        for f in visible:
            sev = f.get("severity", "Info")
            badge = SEVERITY_BADGES.get(sev, f"[dim]{sev}[/]")
            title = f.get("title", "—")[:45]
            module = f.get("module", "—")[:15]
            cvss = f.get("cvss_score")
            cvss_str = f"{cvss:.1f}" if cvss else "—"

            sev_color = SEVERITY_COLORS.get(sev, "dim")
            table.add_row(badge, f"[{sev_color}]{escape(title)}[/]", f"[dim]{module}[/]", cvss_str)

        return Panel(
            table,
            title=f"[bold red]🔍 FINDINGS ({total})[/]",
            border_style="red",
            padding=(0, 0),
        )

    def _render_targets(self) -> Panel:
        """Render the target status panel."""
        snap = self.state_store.snapshot()
        targets = snap.get("targets", {})

        table = Table(
            show_header=True,
            header_style="bold cyan",
            border_style="dim",
            expand=True,
            box=None,
        )
        table.add_column("STATUS", width=14)
        table.add_column("TARGET", ratio=2)
        table.add_column("FINDS", width=5, justify="right")
        table.add_column("CREDS", width=5, justify="right")

        for target, info in list(targets.items())[:15]:
            if info.get("shell"):
                status = TARGET_STATUS_ICONS["shell"]
            elif info.get("pwned"):
                status = TARGET_STATUS_ICONS["pwned"]
            else:
                finds = info.get("findings", 0)
                status = TARGET_STATUS_ICONS["clean"] if finds == 0 else TARGET_STATUS_ICONS["scanning"]

            table.add_row(
                status,
                f"[bold]{escape(str(target)[:30])}[/]",
                str(info.get("findings", 0)),
                str(info.get("creds_count", 0)),
            )

        if not targets:
            table.add_row("[dim]—[/]", "[dim]No targets yet[/]", "—", "—")

        return Panel(
            table,
            title=f"[bold #ff8c00]🎯 TARGETS ({len(targets)})[/]",
            border_style="#ff8c00",
            padding=(0, 0),
        )

    def _render_modules(self) -> Panel:
        """Render the module progress panel."""
        snap = self.state_store.snapshot()
        modules = snap.get("modules", {})

        table = Table(
            show_header=True,
            header_style="bold cyan",
            border_style="dim",
            expand=True,
            box=None,
        )
        table.add_column("", width=2)
        table.add_column("MODULE", ratio=2)
        table.add_column("PROGRESS", width=8, justify="right")
        table.add_column("FINDS", width=5, justify="right")
        table.add_column("TIME", width=7, justify="right")

        # Show running modules first, then recent complete
        running = [(n, m) for n, m in modules.items() if m.get("status") == "running"]
        recent = [(n, m) for n, m in modules.items() if m.get("status") != "running"][-8:]

        for name, mod in running + recent:
            status = mod.get("status", "queued")
            icon = MODULE_STATUS_ICONS.get(status, "?")
            pct = mod.get("progress_pct", 0)
            dur = mod.get("duration", 0)
            finds = mod.get("findings_count", 0)

            pct_str = f"{pct:.0f}%" if status == "running" else ""
            dur_str = f"{dur:.1f}s" if dur > 0 else "—"

            style = "bold green" if status == "running" else "dim" if status in ("complete", "skipped") else ""
            table.add_row(
                icon, f"[{style}]{name[:20]}[/]", pct_str, str(finds), dur_str,
            )

        if not modules:
            table.add_row("—", "[dim]No modules running[/]", "", "", "")

        return Panel(
            table,
            title=f"[bold green]📦 MODULES ({len(modules)})[/]",
            border_style="green",
            padding=(0, 0),
        )

    def _render_metrics(self) -> Panel:
        """Render the metrics panel with sparklines."""
        snap = self.state_store.snapshot()
        m = snap.get("metrics", {})

        rps = m.get("requests_per_second", 0)
        rps_60 = m.get("requests_60s_avg", 0)
        total_req = m.get("requests_total", 0)
        errors = m.get("errors_total", 0)
        err_pct = m.get("error_rate_pct", 0)
        waf = m.get("waf_blocks_total", 0)
        bw_in = m.get("bandwidth_in", "0 B")
        bw_out = m.get("bandwidth_out", "0 B")
        finds_total = m.get("findings_total", 0)
        finds_pm = m.get("findings_per_minute", 0)
        elapsed = m.get("elapsed", "00:00:00")
        eta = m.get("eta", "—")

        spark_rps = m.get("sparkline_rps", [])
        spark_finds = m.get("sparkline_findings", [])
        spark_err = m.get("sparkline_errors", [])

        rps_spark = _mini_sparkline(spark_rps, 20)
        finds_spark = _mini_sparkline(spark_finds, 20)
        err_spark = _mini_sparkline(spark_err, 20)

        lines = [
            f"[bold cyan]Requests/s:[/] {rps:.1f}  [dim]avg60: {rps_60:.1f}[/]",
            f"[dim]{rps_spark}[/]",
            f"[bold]Total Requests:[/] {total_req:,}  [bold red]Errors:[/] {errors} ({err_pct:.1f}%)",
            f"[dim]{err_spark}[/]",
            f"[bold yellow]WAF Blocks:[/] {waf}  [bold]Rate Limits:[/] {m.get('rate_limit_hits', 0)}",
            f"[bold green]Findings:[/] {finds_total}  [dim]({finds_pm:.1f}/min)[/]",
            f"[dim]{finds_spark}[/]",
            f"[bold]BW:[/] ↑{bw_out} ↓{bw_in}",
            f"[bold]Elapsed:[/] {elapsed}  [bold]ETA:[/] {eta}",
        ]

        return Panel(
            "\n".join(lines),
            title="[bold magenta]📊 METRICS[/]",
            border_style="magenta",
            padding=(0, 1),
        )

    def _render_timeline(self) -> Panel:
        """Render the threat timeline panel."""
        snap = self.state_store.snapshot()
        timeline = snap.get("timeline", [])

        if not timeline:
            return Panel(
                "[dim]Awaiting events...[/]",
                title="[bold #c39bd3]📜 TIMELINE[/]",
                border_style="#c39bd3",
            )

        lines = []
        type_colors = {
            "scan_start":       "bold green",
            "scan_complete":    "bold cyan",
            "scan_interrupted": "bold red",
            "phase_start":      "bold cyan",
            "module_fail":      "bold red",
            "finding_critical": "bold white on red",
            "finding_high":     "bold red",
            "finding_medium":   "bold yellow",
            "finding_low":      "bold blue",
            "finding_info":     "dim",
            "credential":       "bold #ff8c00",
            "target_pwned":     "bold red",
        }

        for entry in timeline[-10:]:
            t = entry.get("time", "")
            # Extract HH:MM:SS from ISO timestamp
            time_short = t[11:19] if len(t) > 19 else t[:8]
            etype = entry.get("type", "")
            msg = entry.get("message", "")[:40]
            color = type_colors.get(etype, "dim")
            lines.append(f"[dim]{time_short}[/] [{color}]{escape(msg)}[/]")

        return Panel(
            "\n".join(lines),
            title="[bold #c39bd3]📜 TIMELINE[/]",
            border_style="#c39bd3",
            padding=(0, 1),
        )

    def _render_footer(self) -> Panel:
        """Render the footer with hotkeys."""
        return Panel(
            "[dim]  [bold]P[/]ause  │  [bold]R[/]esume  │  [bold]A[/]bort  │  "
            "[bold]1[/] Main  │  [bold]2[/] Credentials  │  [bold]3[/] Sessions  │  "
            "[bold]Q[/]uit[/]",
            border_style="dim",
            padding=(0, 1),
        )

    def _render_credentials_tab(self) -> Panel:
        """Render the credentials vault as a full panel."""
        snap = self.state_store.snapshot()
        creds = snap.get("credentials", [])

        table = Table(
            show_header=True,
            header_style="bold cyan",
            border_style="dim",
            expand=True,
        )
        table.add_column("TYPE", width=12)
        table.add_column("ACCOUNT", ratio=2)
        table.add_column("SECRET", ratio=2)
        table.add_column("TARGET", ratio=2)
        table.add_column("FOUND BY", ratio=1)

        for c in creds[-30:]:
            table.add_row(
                f"[bold]{c.get('cred_type', '?')}[/]",
                escape(str(c.get("account", "—"))),
                f"[dim]{escape(str(c.get('secret', '●●●●')))}[/]",
                escape(str(c.get("target", "—"))[:25]),
                f"[dim]{c.get('discovered_by', '—')}[/]",
            )

        if not creds:
            table.add_row("—", "[dim]No credentials discovered yet[/]", "", "", "")

        return Panel(
            table,
            title=f"[bold #ff8c00]🔑 CREDENTIAL VAULT ({len(creds)})[/]",
            border_style="#ff8c00",
        )

    def _render_sessions_tab(self) -> Panel:
        """Render the active sessions panel."""
        snap = self.state_store.snapshot()
        sessions = snap.get("sessions", [])

        table = Table(
            show_header=True,
            header_style="bold cyan",
            border_style="dim",
            expand=True,
        )
        table.add_column("ID", width=4)
        table.add_column("TARGET", ratio=2)
        table.add_column("TYPE", width=12)
        table.add_column("ACCESS", width=10)
        table.add_column("ESTABLISHED", ratio=1)
        table.add_column("MODULE", ratio=1)

        for s in sessions:
            access = s.get("access_level", "user")
            access_color = "bold red" if access in ("SYSTEM", "root", "DA") else "bold yellow" if access == "admin" else ""
            table.add_row(
                str(s.get("session_id", "?")),
                f"[bold]{escape(str(s.get('target', '—')))}[/]",
                s.get("shell_type", "—"),
                f"[{access_color}]{access}[/]",
                s.get("established", "—")[:19],
                f"[dim]{s.get('module', '—')}[/]",
            )

        if not sessions:
            table.add_row("—", "[dim]No active sessions[/]", "", "", "", "")

        return Panel(
            table,
            title=f"[bold red]💀 ACTIVE SESSIONS ({len(sessions)})[/]",
            border_style="red",
        )

    # ── Main render loop ──────────────────────────────────────────────

    def _render(self) -> Layout:
        """Build the full dashboard layout with current state."""
        layout = self._build_layout()

        layout["header"].update(self._render_header())
        layout["flash"].update(self._render_flash())
        layout["kill_chain"].update(self._render_kill_chain())
        layout["footer"].update(self._render_footer())

        # Tab switching
        if self._active_tab == "credentials":
            layout["findings"].update(self._render_credentials_tab())
            layout["targets"].update(self._render_targets())
        elif self._active_tab == "sessions":
            layout["findings"].update(self._render_sessions_tab())
            layout["targets"].update(self._render_targets())
        else:
            layout["findings"].update(self._render_findings())
            layout["targets"].update(self._render_targets())

        layout["modules"].update(self._render_modules())
        layout["metrics"].update(self._render_metrics())
        layout["timeline"].update(self._render_timeline())

        return layout

    def _handle_input(self) -> None:
        """Background thread: read keyboard input for controls.

        Uses platform-specific non-blocking input. Falls back to
        basic input() if msvcrt/termios unavailable.
        """
        try:
            if sys.platform == "win32":
                import msvcrt
                while self._running:
                    if msvcrt.kbhit():
                        ch = msvcrt.getch().decode("utf-8", errors="ignore").lower()
                        self._process_key(ch)
                    time.sleep(0.05)
            else:
                # Unix: use termios for raw input
                import tty
                import termios
                fd = sys.stdin.fileno()
                old_settings = termios.tcgetattr(fd)
                try:
                    tty.setcbreak(fd)
                    while self._running:
                        import select
                        if select.select([sys.stdin], [], [], 0.05)[0]:
                            ch = sys.stdin.read(1).lower()
                            self._process_key(ch)
                finally:
                    termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        except Exception:
            # Fallback — no interactive controls
            while self._running:
                time.sleep(1)

    def _process_key(self, ch: str) -> None:
        """Process a single keypress."""
        if ch == "q":
            self._running = False
        elif ch == "p":
            self.event_bus.emit_simple(
                EventType.SCAN_PAUSED, source="tui",
            )
            self.state_store.scan_status = "paused"
            self._flash("⏸ Scan PAUSED by operator")
        elif ch == "r":
            self.event_bus.emit_simple(
                EventType.SCAN_RESUMED, source="tui",
            )
            self.state_store.scan_status = "running"
            self._flash("▶ Scan RESUMED")
        elif ch == "a":
            self.event_bus.emit_simple(
                EventType.SCAN_ABORTED, source="tui",
            )
            self.state_store.scan_status = "aborted"
            self._flash("⏹ Scan ABORTED by operator")
        elif ch == "1":
            self._active_tab = "main"
        elif ch == "2":
            self._active_tab = "credentials"
        elif ch == "3":
            self._active_tab = "sessions"

    def start(self) -> None:
        """Start the TUI dashboard (blocking).

        Runs the Rich Live loop until the user presses 'Q' or
        the scan completes.
        """
        self._running = True

        # Start input handler thread
        self._key_thread = threading.Thread(
            target=self._handle_input,
            name="TUI-Input",
            daemon=True,
        )
        self._key_thread.start()

        # Start event bus if not running
        if not self.event_bus._running:
            self.event_bus.start()

        # Handle Ctrl+C gracefully
        def _sigint_handler(sig, frame):
            self._running = False
        signal.signal(signal.SIGINT, _sigint_handler)

        self._console.clear()

        try:
            with Live(
                self._render(),
                console=self._console,
                refresh_per_second=1.0 / self.refresh_interval,
                screen=True,
            ) as live:
                while self._running:
                    live.update(self._render())
                    time.sleep(self.refresh_interval)
        except KeyboardInterrupt:
            pass
        finally:
            self._running = False
            self._console.clear()
            self._console.print("[bold cyan]⚔️  War Room closed. Stay sharp, operator.[/]")

    async def start_async(self) -> None:
        """Async version — runs TUI in a background thread.

        Useful when the TUI needs to coexist with an async scan loop.
        """
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self.start)

    def stop(self) -> None:
        """Signal the TUI to stop."""
        self._running = False


def launch_tui(
    event_bus: EventBus | None = None,
    state_store: StateStore | None = None,
) -> None:
    """Convenience function to launch the TUI dashboard.

    Args:
        event_bus:   EventBus instance for scan events.
        state_store: StateStore instance for state snapshots.
    """
    tui = WarRoomTUI(event_bus=event_bus, state_store=state_store)
    tui.start()


# ── Self-test / demo mode ────────────────────────────────────────────

class TestWarRoomTUI:
    """Smoke tests for TUI components."""

    def test_sparkline(self) -> None:
        result = _mini_sparkline([0, 1, 2, 3, 4, 5], width=6)
        assert len(result) == 6
        assert result[0] == "▁"
        assert result[-1] == "█"

    def test_sparkline_empty(self) -> None:
        result = _mini_sparkline([], width=10)
        assert result == "▁" * 10

    def test_tui_creation(self) -> None:
        if not HAS_RICH:
            return  # Skip if Rich not installed
        bus = EventBus()
        store = StateStore(bus, framework="test", target="10.0.0.1")
        tui = WarRoomTUI(event_bus=bus, state_store=store)
        assert tui._active_tab == "main"
        assert not tui._running

    def test_flash_message(self) -> None:
        if not HAS_RICH:
            return
        bus = EventBus()
        store = StateStore(bus, framework="test", target="10.0.0.1")
        tui = WarRoomTUI(event_bus=bus, state_store=store)
        tui._flash("Test alert")
        assert len(tui._flash_messages) == 1

    def test_layout_build(self) -> None:
        if not HAS_RICH:
            return
        bus = EventBus()
        store = StateStore(bus, framework="test", target="10.0.0.1")
        tui = WarRoomTUI(event_bus=bus, state_store=store)
        layout = tui._build_layout()
        assert "header" in [c.name for c in layout.children]

    def test_render_panels(self) -> None:
        """Verify all panels render without exception."""
        if not HAS_RICH:
            return
        bus = EventBus()
        store = StateStore(bus, framework="netforge", target="10.0.0.0/24")
        tui = WarRoomTUI(event_bus=bus, state_store=store)
        # Each of these should return a Panel without crashing
        tui._render_header()
        tui._render_flash()
        tui._render_kill_chain()
        tui._render_findings()
        tui._render_targets()
        tui._render_modules()
        tui._render_metrics()
        tui._render_timeline()
        tui._render_footer()
        tui._render_credentials_tab()
        tui._render_sessions_tab()
