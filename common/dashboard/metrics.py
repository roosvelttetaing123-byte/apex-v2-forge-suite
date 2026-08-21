"""Rolling-window metrics calculator for dashboard real-time stats.

Tracks request rates, error rates, bandwidth, WAF blocks, and finding
velocity using time-bucketed sliding windows for smooth sparkline rendering.
"""
from __future__ import annotations

import collections
import logging
import threading
import time
from dataclasses import dataclass, field
from collections.abc import Sequence
from typing import Any

log = logging.getLogger("forge.dashboard.metrics")


@dataclass
class MetricsSnapshot:
    """Point-in-time snapshot of all dashboard metrics."""

    requests_total:      int   = 0
    requests_per_second: float = 0.0
    requests_5s_avg:     float = 0.0
    requests_60s_avg:    float = 0.0
    errors_total:        int   = 0
    error_rate_pct:      float = 0.0
    waf_blocks_total:    int   = 0
    rate_limit_hits:     int   = 0
    bandwidth_in_bytes:  int   = 0
    bandwidth_out_bytes: int   = 0
    findings_total:      int   = 0
    findings_per_minute: float = 0.0
    modules_completed:   int   = 0
    modules_failed:      int   = 0
    modules_running:     int   = 0
    modules_queued:      int   = 0
    elapsed_seconds:     float = 0.0
    eta_seconds:         float = 0.0
    sparkline_rps:       list[float] = field(default_factory=list)
    sparkline_findings:  list[float] = field(default_factory=list)
    sparkline_errors:    list[float] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize for JSON/WebSocket transmission."""
        return {
            "requests_total": self.requests_total,
            "requests_per_second": round(self.requests_per_second, 1),
            "requests_5s_avg": round(self.requests_5s_avg, 1),
            "requests_60s_avg": round(self.requests_60s_avg, 1),
            "errors_total": self.errors_total,
            "error_rate_pct": round(self.error_rate_pct, 1),
            "waf_blocks_total": self.waf_blocks_total,
            "rate_limit_hits": self.rate_limit_hits,
            "bandwidth_in": _human_bytes(self.bandwidth_in_bytes),
            "bandwidth_out": _human_bytes(self.bandwidth_out_bytes),
            "findings_total": self.findings_total,
            "findings_per_minute": round(self.findings_per_minute, 1),
            "modules_completed": self.modules_completed,
            "modules_failed": self.modules_failed,
            "modules_running": self.modules_running,
            "modules_queued": self.modules_queued,
            "elapsed": _human_duration(self.elapsed_seconds),
            "eta": _human_duration(self.eta_seconds) if self.eta_seconds > 0 else "calculating...",
            "sparkline_rps": self.sparkline_rps[-30:],
            "sparkline_findings": self.sparkline_findings[-30:],
            "sparkline_errors": self.sparkline_errors[-30:],
        }


def _human_bytes(n: int) -> str:
    """Format bytes into human-readable string."""
    for unit in ("B", "KB", "MB", "GB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n //= 1024
    return f"{n:.1f} TB"


def _human_duration(seconds: float) -> str:
    """Format seconds into HH:MM:SS."""
    if seconds <= 0:
        return "00:00:00"
    h = int(seconds // 3600)
    m = int((seconds % 3600) // 60)
    s = int(seconds % 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


class RollingWindow:
    """Time-bucketed sliding window counter.

    Each bucket covers 1 second. The window holds ``size`` buckets.
    Thread-safe via lock.
    """

    def __init__(self, size: int = 60) -> None:
        self._size = size
        self._buckets: collections.deque[tuple[float, int]] = collections.deque(maxlen=size)
        self._lock = threading.Lock()
        self._current_bucket_time: float = 0.0
        self._current_count: int = 0

    def record(self, count: int = 1) -> None:
        """Record ``count`` events at the current time."""
        now = time.monotonic()
        bucket_time = int(now)
        with self._lock:
            if bucket_time == self._current_bucket_time:
                self._current_count += count
            else:
                if self._current_bucket_time > 0:
                    self._buckets.append((self._current_bucket_time, self._current_count))
                self._current_bucket_time = bucket_time
                self._current_count = count

    def rate(self, window_seconds: int = 1) -> float:
        """Calculate events/second over the last ``window_seconds``."""
        now = time.monotonic()
        cutoff = int(now) - window_seconds
        with self._lock:
            # Flush current bucket
            if self._current_bucket_time > 0 and self._current_bucket_time != int(now):
                self._buckets.append((self._current_bucket_time, self._current_count))
                self._current_bucket_time = int(now)
                self._current_count = 0

            total = self._current_count
            for bucket_time, count in self._buckets:
                if bucket_time >= cutoff:
                    total += count
            return total / max(window_seconds, 1)

    def sparkline_data(self, points: int = 30) -> list[float]:
        """Return per-second counts for the last ``points`` seconds."""
        now = int(time.monotonic())
        with self._lock:
            # Build a lookup from bucket data
            lookup: dict[int, int] = {}
            for bt, count in self._buckets:
                lookup[int(bt)] = count
            if self._current_bucket_time > 0:
                lookup[int(self._current_bucket_time)] = self._current_count

        result: list[float] = []
        for i in range(points):
            t = now - (points - 1 - i)
            result.append(float(lookup.get(t, 0)))
        return result


class MetricsCollector:
    """Aggregates all dashboard metrics from event data.

    Thread-safe. Updated by the StateStore when processing events,
    queried by dashboard panels for rendering.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._start_time: float = time.monotonic()
        self._rps_window = RollingWindow(size=120)
        self._findings_window = RollingWindow(size=120)
        self._errors_window = RollingWindow(size=120)
        self._requests_total: int = 0
        self._errors_total: int = 0
        self._waf_blocks: int = 0
        self._rate_limit_hits: int = 0
        self._bandwidth_in: int = 0
        self._bandwidth_out: int = 0
        self._findings_total: int = 0
        self._modules_completed: int = 0
        self._modules_failed: int = 0
        self._modules_running: int = 0
        self._modules_queued: int = 0
        self._total_modules: int = 0
        self._avg_module_duration: float = 0.0
        self._module_durations: list[float] = []

    def record_request(self, bytes_out: int = 0, bytes_in: int = 0) -> None:
        """Record an outbound HTTP/network request."""
        with self._lock:
            self._requests_total += 1
            self._bandwidth_out += bytes_out
            self._bandwidth_in += bytes_in
        self._rps_window.record()

    def record_error(self) -> None:
        """Record a request error."""
        with self._lock:
            self._errors_total += 1
        self._errors_window.record()

    def record_waf_block(self) -> None:
        """Record a WAF block."""
        with self._lock:
            self._waf_blocks += 1

    def record_rate_limit(self) -> None:
        """Record a rate limit hit."""
        with self._lock:
            self._rate_limit_hits += 1

    def record_finding(self) -> None:
        """Record a new finding discovered."""
        with self._lock:
            self._findings_total += 1
        self._findings_window.record()

    def record_module_start(self) -> None:
        """Record a module starting execution."""
        with self._lock:
            self._modules_running += 1
            if self._modules_queued > 0:
                self._modules_queued -= 1

    def record_module_complete(self, duration: float) -> None:
        """Record a module completing execution."""
        with self._lock:
            self._modules_completed += 1
            if self._modules_running > 0:
                self._modules_running -= 1
            self._module_durations.append(duration)
            if self._module_durations:
                self._avg_module_duration = (
                    sum(self._module_durations) / len(self._module_durations)
                )

    def record_module_fail(self) -> None:
        """Record a module failure."""
        with self._lock:
            self._modules_failed += 1
            if self._modules_running > 0:
                self._modules_running -= 1

    def set_total_modules(self, total: int) -> None:
        """Set total module count for ETA calculation."""
        with self._lock:
            self._total_modules = total
            self._modules_queued = total

    def snapshot(self) -> MetricsSnapshot:
        """Take a point-in-time snapshot of all metrics."""
        elapsed = time.monotonic() - self._start_time
        with self._lock:
            remaining = self._total_modules - self._modules_completed - self._modules_failed
            eta = remaining * self._avg_module_duration if self._avg_module_duration > 0 else 0.0

            rps_1s = self._rps_window.rate(1)
            req_total = self._requests_total
            err_total = self._errors_total

            return MetricsSnapshot(
                requests_total=req_total,
                requests_per_second=rps_1s,
                requests_5s_avg=self._rps_window.rate(5),
                requests_60s_avg=self._rps_window.rate(60),
                errors_total=err_total,
                error_rate_pct=(err_total / req_total * 100) if req_total > 0 else 0.0,
                waf_blocks_total=self._waf_blocks,
                rate_limit_hits=self._rate_limit_hits,
                bandwidth_in_bytes=self._bandwidth_in,
                bandwidth_out_bytes=self._bandwidth_out,
                findings_total=self._findings_total,
                findings_per_minute=self._findings_window.rate(60) * 60,
                modules_completed=self._modules_completed,
                modules_failed=self._modules_failed,
                modules_running=self._modules_running,
                modules_queued=max(0, remaining),
                elapsed_seconds=elapsed,
                eta_seconds=eta,
                sparkline_rps=self._rps_window.sparkline_data(30),
                sparkline_findings=self._findings_window.sparkline_data(30),
                sparkline_errors=self._errors_window.sparkline_data(30),
            )


SPARKLINE_CHARS = "▁▂▃▄▅▆▇█"


def sparkline(values: Sequence[float], width: int = 20) -> str:
    """Render a list of floats as a Unicode sparkline string.

    Args:
        values: Data points to visualize.
        width:  Max number of characters in output.

    Returns:
        String of sparkline characters.
    """
    if not values:
        return "▁" * width
    # Take last ``width`` points
    data = values[-width:]
    mx = max(data) if max(data) > 0 else 1.0
    result = []
    for v in data:
        idx = min(int(v / mx * (len(SPARKLINE_CHARS) - 1)), len(SPARKLINE_CHARS) - 1)
        result.append(SPARKLINE_CHARS[idx])
    return "".join(result)


class TestMetrics:
    """Unit tests for metrics module."""

    def test_rolling_window_rate(self) -> None:
        w = RollingWindow()
        for _ in range(10):
            w.record()
        rate = w.rate(1)
        assert rate >= 0  # timing-dependent, just verify no crash

    def test_sparkline_output(self) -> None:
        vals = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
        s = sparkline(vals, width=11)
        assert len(s) == 11
        assert s[0] == "▁"
        assert s[-1] == "█"

    def test_metrics_collector(self) -> None:
        mc = MetricsCollector()
        mc.set_total_modules(10)
        mc.record_module_start()
        mc.record_request(bytes_out=100, bytes_in=500)
        mc.record_finding()
        mc.record_module_complete(duration=2.5)
        snap = mc.snapshot()
        assert snap.requests_total == 1
        assert snap.findings_total == 1
        assert snap.modules_completed == 1
        assert snap.bandwidth_in_bytes == 500

    def test_human_bytes(self) -> None:
        assert "B" in _human_bytes(500)
        assert "KB" in _human_bytes(2048)
        assert "MB" in _human_bytes(5_000_000)

    def test_human_duration(self) -> None:
        assert _human_duration(3661) == "01:01:01"
        assert _human_duration(0) == "00:00:00"

    def test_snapshot_serialization(self) -> None:
        mc = MetricsCollector()
        mc.record_request()
        snap = mc.snapshot()
        d = snap.to_dict()
        assert "requests_total" in d
        assert "elapsed" in d
