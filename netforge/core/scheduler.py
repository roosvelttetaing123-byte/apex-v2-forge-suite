"""Phase scheduler — runs phases sequentially with timing and resume support."""
from __future__ import annotations

import asyncio
import json
import logging
import time
from pathlib import Path
from typing import Callable, Awaitable

log = logging.getLogger("forge.netforge.scheduler")


class PhaseScheduler:
    """Runs a list of (name, async_callable) phases with timing and optional resume."""

    def __init__(self, state_file: Path | None = None) -> None:
        self.state_file = state_file
        self._completed: set[str] = set()
        if state_file and state_file.exists():
            try:
                data = json.loads(state_file.read_text())
                self._completed = set(data.get("completed", []))
                log.info("Resume: %d phases already done: %s", len(self._completed), self._completed)
            except Exception:
                pass

    async def run(
        self,
        phases: list[tuple[str, Callable[[], Awaitable]]],
        resume: bool = False,
    ) -> dict[str, float]:
        """Run all phases, skipping completed ones if resume=True.

        Returns dict of {phase_name: duration_seconds}.
        """
        timings: dict[str, float] = {}
        for name, coro_fn in phases:
            if resume and name in self._completed:
                log.info("[SKIP] Phase already done: %s", name)
                continue
            log.info("[START] Phase: %s", name)
            t0 = time.monotonic()
            try:
                await coro_fn()
            except Exception as exc:
                log.error("[ERROR] Phase %s failed: %s", name, exc)
            elapsed = time.monotonic() - t0
            timings[name] = elapsed
            self._completed.add(name)
            self._save_state()
            log.info("[DONE] Phase %s in %.1fs", name, elapsed)
        return timings

    def _save_state(self) -> None:
        if not self.state_file:
            return
        try:
            self.state_file.parent.mkdir(parents=True, exist_ok=True)
            self.state_file.write_text(json.dumps({"completed": list(self._completed)}))
        except Exception as exc:
            log.debug("State save failed: %s", exc)

    def reset(self) -> None:
        self._completed.clear()
        if self.state_file and self.state_file.exists():
            self.state_file.unlink()
