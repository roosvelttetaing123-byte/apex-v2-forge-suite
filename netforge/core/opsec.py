"""OpSec Profile Engine — operational security controls for NetForge.

Provides configurable evasion and stealth controls that all modules respect:
  - Jitter: randomized sleep between network calls (anti-pattern detection)
  - Thread throttling: max concurrent connections per profile
  - Module order randomization: shuffle execution within phases
  - Decoy traffic injection: mix benign queries to blend in
  - Traffic timing profiles: stealth / normal / aggressive presets

Usage:
    from netforge.core.opsec import OpSecProfile, get_opsec

    profile = get_opsec("stealth")
    await profile.jitter()         # sleep random interval
    async with profile.throttle(): # semaphore-limited concurrency
        await do_network_thing()
"""
from __future__ import annotations

import asyncio
import logging
import os
import random
import struct
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, AsyncIterator

log = logging.getLogger("forge.opsec")


class OpSecLevel(str, Enum):
    """Operational security profiles — pick your poison."""
    STEALTH    = "stealth"
    NORMAL     = "normal"
    AGGRESSIVE = "aggressive"


@dataclass
class OpSecProfile:
    """Operational security configuration.

    Controls timing, concurrency, randomization, and noise generation
    to reduce detection probability during network assessments.

    Attributes:
        level:              The OpSec preset name.
        jitter_min_s:       Minimum jitter sleep (seconds).
        jitter_max_s:       Maximum jitter sleep (seconds).
        max_threads:        Maximum concurrent network operations.
        randomize_modules:  Shuffle module order within phases.
        inject_decoys:      Mix benign DNS queries between real traffic.
        decoy_ratio:        Ratio of decoy queries to real requests (0.0-1.0).
        suppress_console:   Suppress real-time console output (stealth logging).
        ua_randomize:       Randomize HTTP User-Agent strings.
        tcp_jitter:         Add random TCP window size variation.
    """
    level:             OpSecLevel = OpSecLevel.NORMAL
    jitter_min_s:      float      = 0.5
    jitter_max_s:      float      = 3.0
    max_threads:        int       = 10
    randomize_modules: bool       = False
    inject_decoys:     bool       = False
    decoy_ratio:       float      = 0.0
    suppress_console:  bool       = False
    ua_randomize:      bool       = False
    tcp_jitter:        bool       = False

    # Internal state — not user-configurable
    _semaphore: asyncio.Semaphore | None = field(default=None, repr=False)
    _request_count: int                  = field(default=0, repr=False)
    _decoy_count: int                    = field(default=0, repr=False)
    _last_jitter_ts: float               = field(default=0.0, repr=False)

    def __post_init__(self) -> None:
        self._semaphore = asyncio.Semaphore(self.max_threads)

    # ------------------------------------------------------------------
    # Jitter — the money maker
    # ------------------------------------------------------------------

    async def jitter(self) -> None:
        """Sleep a random interval between jitter_min_s and jitter_max_s.

        This is the single most important evasion mechanism. Deterministic
        timing between requests is the #1 signature that automated tools
        leave on SIEMs and IDS. Random jitter breaks temporal correlation.
        """
        if self.jitter_max_s <= 0:
            return

        # Triangular distribution — biases toward the middle, more natural
        # than uniform. Real humans don't have flat timing distributions.
        delay = random.triangular(self.jitter_min_s, self.jitter_max_s)
        self._last_jitter_ts = time.monotonic()

        if delay > 0:
            await asyncio.sleep(delay)

    async def jitter_micro(self) -> None:
        """Ultra-short jitter for within-protocol operations.

        Used between individual packets in multi-step protocol handshakes
        where full jitter would be too slow but zero delay is suspicious.
        """
        micro_delay = random.uniform(0.01, min(0.3, self.jitter_min_s))
        await asyncio.sleep(micro_delay)

    # ------------------------------------------------------------------
    # Thread throttling
    # ------------------------------------------------------------------

    def throttle(self) -> asyncio.Semaphore:
        """Return the concurrency semaphore for this profile.

        Usage:
            async with profile.throttle():
                await do_network_thing()
        """
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self.max_threads)
        return self._semaphore

    # ------------------------------------------------------------------
    # Decoy traffic injection
    # ------------------------------------------------------------------

    async def maybe_inject_decoy(self, target_network: str = "") -> None:
        """Keep legacy decoy mode inert until each destination is authorized.

        Public cover traffic is not part of the inspected target and therefore
        cannot inherit a scan authorization.  The method deliberately performs
        no resolver or socket call.
        """
        del target_network
        if self.inject_decoys:
            log.warning(
                "Decoy traffic disabled: each destination requires separate scope and authorization"
            )
        return

    # ------------------------------------------------------------------
    # Module ordering
    # ------------------------------------------------------------------

    def shuffle_modules(self, modules: list[str]) -> list[str]:
        """Shuffle module execution order if randomization is enabled.

        Returns a new list — does not modify the original.
        Randomized ordering makes the tool's phase-based execution pattern
        less predictable to network defenders watching traffic sequences.
        """
        if not self.randomize_modules:
            return list(modules)
        shuffled = list(modules)
        random.shuffle(shuffled)
        return shuffled

    # ------------------------------------------------------------------
    # User-Agent randomization
    # ------------------------------------------------------------------

    _USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    ]

    def get_user_agent(self) -> str:
        """Return a random realistic User-Agent string."""
        if self.ua_randomize:
            return random.choice(self._USER_AGENTS)
        return self._USER_AGENTS[0]  # Default Chrome on Windows

    # ------------------------------------------------------------------
    # Metrics
    # ------------------------------------------------------------------

    def record_request(self) -> None:
        """Increment the request counter."""
        self._request_count += 1

    @property
    def stats(self) -> dict[str, Any]:
        """Return OpSec operational statistics."""
        return {
            "level": self.level.value,
            "requests": self._request_count,
            "decoys_injected": self._decoy_count,
            "jitter_range": f"{self.jitter_min_s:.1f}-{self.jitter_max_s:.1f}s",
            "max_threads": self.max_threads,
        }


# ======================================================================
# Preset factory
# ======================================================================

_PROFILES: dict[str, OpSecProfile] = {
    "stealth": OpSecProfile(
        level=OpSecLevel.STEALTH,
        jitter_min_s=2.0,
        jitter_max_s=15.0,
        max_threads=3,
        randomize_modules=True,
        inject_decoys=True,
        decoy_ratio=0.3,          # 30% of requests get a decoy query
        suppress_console=True,
        ua_randomize=True,
        tcp_jitter=True,
    ),
    "normal": OpSecProfile(
        level=OpSecLevel.NORMAL,
        jitter_min_s=0.5,
        jitter_max_s=3.0,
        max_threads=10,
        randomize_modules=False,
        inject_decoys=False,
        decoy_ratio=0.0,
        suppress_console=False,
        ua_randomize=True,
        tcp_jitter=False,
    ),
    "aggressive": OpSecProfile(
        level=OpSecLevel.AGGRESSIVE,
        jitter_min_s=0.0,
        jitter_max_s=0.1,
        max_threads=50,
        randomize_modules=False,
        inject_decoys=False,
        decoy_ratio=0.0,
        suppress_console=False,
        ua_randomize=False,
        tcp_jitter=False,
    ),
}

# Global active profile — set once at startup
_active_profile: OpSecProfile = _PROFILES["normal"]


def get_opsec(level: str | None = None) -> OpSecProfile:
    """Get the active OpSec profile, or create one from a level name.

    Args:
        level: Optional profile name ("stealth", "normal", "aggressive").
               If None, returns the current active profile.

    Returns:
        The OpSecProfile instance.
    """
    global _active_profile
    if level is not None:
        level = level.lower().strip()
        if level not in _PROFILES:
            log.warning("Unknown OpSec level '%s' — falling back to 'normal'", level)
            level = "normal"
        _active_profile = _PROFILES[level]
        log.info(
            "OpSec profile: %s (jitter=%.1f-%.1fs, threads=%d, decoys=%s)",
            _active_profile.level.value,
            _active_profile.jitter_min_s,
            _active_profile.jitter_max_s,
            _active_profile.max_threads,
            _active_profile.inject_decoys,
        )
    return _active_profile


def set_opsec(profile: OpSecProfile) -> None:
    """Set a custom OpSec profile as the active profile."""
    global _active_profile
    _active_profile = profile


# ======================================================================
# Tests
# ======================================================================

class TestOpSec:
    """Unit tests for OpSec profile engine."""

    def test_profiles_exist(self) -> None:
        for level in ("stealth", "normal", "aggressive"):
            p = _PROFILES[level]
            assert p.level.value == level

    def test_stealth_has_jitter(self) -> None:
        p = _PROFILES["stealth"]
        assert p.jitter_min_s >= 2.0
        assert p.jitter_max_s >= 10.0
        assert p.max_threads <= 5
        assert p.randomize_modules is True
        assert p.inject_decoys is True

    def test_aggressive_minimal_jitter(self) -> None:
        p = _PROFILES["aggressive"]
        assert p.jitter_max_s <= 0.2
        assert p.max_threads >= 50
        assert p.inject_decoys is False

    def test_shuffle_modules(self) -> None:
        p = OpSecProfile(randomize_modules=True)
        mods = ["a", "b", "c", "d", "e", "f", "g", "h"]
        # Run multiple times — at least one should differ
        results = set()
        for _ in range(20):
            results.add(tuple(p.shuffle_modules(mods)))
        assert len(results) > 1  # Probabilistic but safe with 8 items

    def test_no_shuffle_when_disabled(self) -> None:
        p = OpSecProfile(randomize_modules=False)
        mods = ["a", "b", "c"]
        assert p.shuffle_modules(mods) == mods

    def test_user_agent_randomization(self) -> None:
        p = OpSecProfile(ua_randomize=True)
        agents = {p.get_user_agent() for _ in range(50)}
        assert len(agents) > 1

    def test_user_agent_static(self) -> None:
        p = OpSecProfile(ua_randomize=False)
        agents = {p.get_user_agent() for _ in range(10)}
        assert len(agents) == 1

    def test_get_opsec_fallback(self) -> None:
        profile = get_opsec("nonexistent_garbage")
        assert profile.level == OpSecLevel.NORMAL

    def test_stats(self) -> None:
        p = OpSecProfile()
        s = p.stats
        assert "level" in s
        assert "requests" in s
        assert s["requests"] == 0
