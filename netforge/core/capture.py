"""Packet capture wrapper using tcpdump."""
from __future__ import annotations

import asyncio
import logging
import shutil
import signal
from pathlib import Path

log = logging.getLogger("forge.netforge.capture")


class PacketCapture:
    """Thin wrapper around tcpdump for traffic capture during assessments."""

    def __init__(self, results_dir: Path) -> None:
        self.results_dir = results_dir
        self._proc: asyncio.subprocess.Process | None = None
        self._outfile: Path | None = None

    async def start(self, iface: str, bpf_filter: str = "", outfile: Path | None = None) -> Path | None:
        if not shutil.which("tcpdump"):
            log.warning("tcpdump not found — packet capture unavailable")
            return None

        self._outfile = outfile or (self.results_dir / "capture.pcap")
        self._outfile.parent.mkdir(parents=True, exist_ok=True)

        cmd = ["tcpdump", "-i", iface, "-w", str(self._outfile), "-n", "-q"]
        if bpf_filter:
            cmd += [bpf_filter]

        try:
            self._proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            log.info("Capture started on %s → %s", iface, self._outfile)
            return self._outfile
        except Exception as exc:
            log.error("Failed to start capture: %s", exc)
            return None

    async def stop(self) -> Path | None:
        if not self._proc:
            return None
        try:
            self._proc.send_signal(signal.SIGINT)
            await asyncio.wait_for(self._proc.wait(), timeout=5)
        except Exception:
            self._proc.kill()
        log.info("Capture stopped: %s", self._outfile)
        return self._outfile

    async def capture_for(self, iface: str, duration_s: float, bpf_filter: str = "", outfile: Path | None = None) -> Path | None:
        path = await self.start(iface, bpf_filter, outfile)
        if not path:
            return None
        await asyncio.sleep(duration_s)
        return await self.stop()
