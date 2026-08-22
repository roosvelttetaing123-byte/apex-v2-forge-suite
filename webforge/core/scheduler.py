"""Async task scheduler for WebForge phase execution."""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Any, Coroutine

log = logging.getLogger(__name__)


@dataclass
class TaskResult:
    name:      str
    success:   bool
    duration_s: float
    error:     str | None = None
    data:      Any        = None


class PhaseScheduler:
    """Runs modules sequentially within phases, phases in order."""

    def __init__(self, workers: int = 10, dry_run: bool = False) -> None:
        self.workers = workers
        self.dry_run = dry_run
        self.results: list[TaskResult] = []
        self._semaphore = asyncio.Semaphore(workers)

    async def run_module(
        self,
        name: str,
        coro: Coroutine[Any, Any, Any],
    ) -> TaskResult:
        """Run a single module coroutine with error isolation."""
        if self.dry_run:
            log.info("[DRY RUN] Would run: %s", name)
            # Dry-run deliberately does not execute the supplied coroutine, but
            # it still owns that coroutine object and must close it explicitly.
            coro.close()
            return TaskResult(name=name, success=True, duration_s=0.0, data="dry-run")

        start = time.monotonic()
        try:
            async with self._semaphore:
                data = await coro
            duration = time.monotonic() - start
            result = TaskResult(name=name, success=True, duration_s=duration, data=data)
            log.info("Module completed: %s (%.1fs)", name, duration)
        except Exception as exc:
            duration = time.monotonic() - start
            result = TaskResult(name=name, success=False, duration_s=duration, error=str(exc))
            log.error("Module failed: %s — %s", name, exc)

        self.results.append(result)
        return result

    async def run_phase(
        self,
        phase_name: str,
        tasks: list[tuple[str, Coroutine[Any, Any, Any]]],
        parallel: bool = False,
    ) -> list[TaskResult]:
        """Run all tasks in a phase, optionally in parallel.

        Args:
            phase_name: Name of the phase for logging.
            tasks:      List of (module_name, coroutine) pairs.
            parallel:   If True, run concurrently. Default: sequential.

        Returns:
            List of TaskResult for each task.
        """
        log.info("Starting phase: %s (%d modules)", phase_name, len(tasks))
        phase_results: list[TaskResult] = []

        if parallel:
            coros = [self.run_module(name, coro) for name, coro in tasks]
            raw = await asyncio.gather(*coros, return_exceptions=True)
            phase_results = []
            for r in raw:
                if isinstance(r, BaseException):
                    log.error("Unexpected scheduler error in phase %s: %s", phase_name, r)
                else:
                    phase_results.append(r)
        else:
            for name, coro in tasks:
                result = await self.run_module(name, coro)
                phase_results.append(result)

        success = sum(1 for r in phase_results if r.success)
        log.info("Phase complete: %s — %d/%d succeeded", phase_name, success, len(tasks))
        return phase_results


class TestScheduler:
    def test_dry_run(self) -> None:
        async def dummy() -> str:
            return "result"
        sched = PhaseScheduler(dry_run=True)
        result = asyncio.run(sched.run_module("test", dummy()))
        assert result.success is True
        assert result.data == "dry-run"

    def test_sequential(self) -> None:
        order: list[int] = []
        async def task(n: int) -> int:
            order.append(n)
            return n
        sched = PhaseScheduler()
        tasks = [(f"t{i}", task(i)) for i in range(3)]
        asyncio.run(sched.run_phase("test", tasks, parallel=False))
        assert order == [0, 1, 2]

    def test_error_isolation(self) -> None:
        async def fail() -> None:
            raise RuntimeError("intentional")
        sched = PhaseScheduler()
        result = asyncio.run(sched.run_module("failing", fail()))
        assert result.success is False
        assert "intentional" in (result.error or "")

    def test_parallel_exception_does_not_kill_other_tasks(self) -> None:
        """A BaseException from one parallel task must not cancel the rest."""
        completed: list[str] = []

        async def good(name: str) -> str:
            completed.append(name)
            return name

        async def bad() -> None:
            raise asyncio.CancelledError()

        async def run() -> list[TaskResult]:
            sched = PhaseScheduler()
            tasks = [
                ("good_a", good("a")),
                ("bad",    bad()),
                ("good_b", good("b")),
            ]
            return await sched.run_phase("test_parallel", tasks, parallel=True)

        results = asyncio.run(run())
        # Both good tasks must have completed
        assert "a" in completed
        assert "b" in completed
        # Only the two successful TaskResults are in phase_results
        assert len(results) == 2
        assert all(r.success for r in results)
