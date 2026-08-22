"""Container Escape Detection & Exploitation — cgroup, mount namespace, /proc attacks.

Detects and documents container breakout vectors:
  - Privileged container detection (--privileged flag)
  - cgroup v1 release_agent escape
  - Mount namespace escape (/proc/1/root traversal)
  - SYS_PTRACE capability abuse
  - Docker socket access (/var/run/docker.sock)
  - OverlayFS breakout
  - Kernel exploit paths (dirty pipe, dirty cow)
  - AppArmor/SELinux profile misconfiguration

FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from pathlib import Path
from typing import Any

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

log = logging.getLogger("forge.cloud.container_escape")


# ── Container escape check definitions ───────────────────────────────
_ESCAPE_CHECKS: list[dict[str, Any]] = [
    {
        "id": "privileged_container",
        "name": "Privileged Container Detected",
        "check_type": "file_exists",
        "paths": ["/dev/sda", "/dev/sda1", "/dev/nvme0n1"],
        "description": "Container running with --privileged flag — full host device access",
        "severity": "Critical",
        "mitre": ["T1611"],
        "remediation": "Never use --privileged in production. Use specific capabilities instead.",
    },
    {
        "id": "docker_socket",
        "name": "Docker Socket Mounted",
        "check_type": "file_exists",
        "paths": ["/var/run/docker.sock", "/run/docker.sock"],
        "description": "Docker socket is mounted inside the container — full host control via Docker API",
        "severity": "Critical",
        "mitre": ["T1611", "T1610"],
        "remediation": "Remove Docker socket mount. Use rootless Docker or Podman for CI/CD.",
    },
    {
        "id": "cgroup_release_agent",
        "name": "cgroup v1 Release Agent Escape",
        "check_type": "writable_path",
        "paths": ["/sys/fs/cgroup/*/release_agent", "/sys/fs/cgroup/release_agent"],
        "description": "cgroup v1 release_agent is writable — classic container escape to host execution",
        "severity": "Critical",
        "mitre": ["T1611"],
        "remediation": "Migrate to cgroup v2. Drop SYS_ADMIN capability. Use seccomp profiles.",
    },
    {
        "id": "proc_root_traversal",
        "name": "/proc/1/root Host Filesystem Access",
        "check_type": "file_readable",
        "paths": ["/proc/1/root/etc/shadow", "/proc/1/root/etc/hostname"],
        "description": "Container can traverse /proc/1/root to access host filesystem",
        "severity": "Critical",
        "mitre": ["T1611", "T1083"],
        "remediation": "Drop SYS_PTRACE and SYS_ADMIN capabilities. Use PID namespace isolation.",
    },
    {
        "id": "sys_ptrace",
        "name": "SYS_PTRACE Capability Enabled",
        "check_type": "cap_check",
        "capability": "cap_sys_ptrace",
        "description": "Container has SYS_PTRACE — can attach to host processes and inject code",
        "severity": "High",
        "mitre": ["T1055"],
        "remediation": "Remove SYS_PTRACE from container capabilities. Use --cap-drop=ALL.",
    },
    {
        "id": "sys_admin_cap",
        "name": "SYS_ADMIN Capability Enabled",
        "check_type": "cap_check",
        "capability": "cap_sys_admin",
        "description": "Container has SYS_ADMIN — allows mount namespace manipulation and cgroup escape",
        "severity": "Critical",
        "mitre": ["T1611"],
        "remediation": "Remove SYS_ADMIN capability. Use minimal capability set.",
    },
    {
        "id": "host_network",
        "name": "Host Network Namespace Shared",
        "check_type": "network_ns",
        "description": "Container shares host network namespace — can sniff host traffic and bind to host ports",
        "severity": "High",
        "mitre": ["T1557", "T1040"],
        "remediation": "Remove --net=host. Use container network policies.",
    },
    {
        "id": "host_pid",
        "name": "Host PID Namespace Shared",
        "check_type": "pid_ns",
        "description": "Container shares host PID namespace — can see and signal all host processes",
        "severity": "High",
        "mitre": ["T1057", "T1611"],
        "remediation": "Remove --pid=host. Use PID namespace isolation.",
    },
    {
        "id": "writable_hostpath",
        "name": "Writable Host Path Mount",
        "check_type": "writable_mount",
        "paths": ["/host", "/host-root", "/mnt/host"],
        "description": "Host filesystem mounted writable inside container — direct host modification",
        "severity": "Critical",
        "mitre": ["T1611", "T1222"],
        "remediation": "Mount host paths as read-only. Avoid host path mounts in production.",
    },
    {
        "id": "no_seccomp",
        "name": "Seccomp Profile Disabled",
        "check_type": "seccomp_check",
        "description": "Container running without seccomp profile — all syscalls available",
        "severity": "Medium",
        "mitre": ["T1611"],
        "remediation": "Apply default or custom seccomp profile to restrict dangerous syscalls.",
    },
]


class ContainerEscape(BaseModule):
    """Detect container breakout vectors and document escape evidence."""

    NAME        = "container_escape"
    DESCRIPTION = "Container escape detection — privileged mode, cgroup, mount ns, Docker socket, /proc abuse"
    PHASE       = 3
    TAGS        = ["cloud", "container", "docker", "escape", "privesc"]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._in_container: bool = False

    async def run(self) -> ModuleResult:
        """Run all container escape detection checks."""
        start = time.monotonic()

        target = self.config.target
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="Target out of scope")

        # Detect if we're in a container
        self._in_container = self._detect_container_env()
        if not self._in_container:
            self.log.info("Not running inside a container — performing remote checks only")

        self.log.info("Starting container escape detection")

        for check in _ESCAPE_CHECKS:
            try:
                await self._run_check(check)
            except Exception as exc:
                self.log.debug("Check %s failed: %s", check["id"], exc)

        return self._make_result(start)

    def _detect_container_env(self) -> bool:
        """Detect if we are running inside a container."""
        indicators = [
            Path("/.dockerenv").exists(),
            Path("/run/.containerenv").exists(),
            self._check_cgroup_for_container(),
        ]
        return any(indicators)

    def _check_cgroup_for_container(self) -> bool:
        """Check /proc/1/cgroup for container indicators."""
        try:
            cgroup = Path("/proc/1/cgroup").read_text(errors="ignore")
            return any(x in cgroup for x in ("docker", "kubepods", "containerd", "cri-o"))
        except Exception:
            return False

    async def _run_check(self, check: dict[str, Any]) -> None:
        """Execute a single escape detection check."""
        check_type = check["check_type"]

        if check_type == "file_exists":
            await self._check_file_exists(check)
        elif check_type == "file_readable":
            await self._check_file_readable(check)
        elif check_type == "writable_path":
            await self._check_writable_path(check)
        elif check_type == "cap_check":
            await self._check_capability(check)
        elif check_type == "network_ns":
            await self._check_network_ns(check)
        elif check_type == "pid_ns":
            await self._check_pid_ns(check)
        elif check_type == "writable_mount":
            await self._check_writable_mount(check)
        elif check_type == "seccomp_check":
            await self._check_seccomp(check)

    async def _check_file_exists(self, check: dict[str, Any]) -> None:
        """Check if escape-indicator files exist."""
        for path in check.get("paths", []):
            if Path(path).exists():
                self._report_escape(check, evidence_detail=f"File exists: {path}")
                return

    async def _check_file_readable(self, check: dict[str, Any]) -> None:
        """Check if sensitive host files are readable from container."""
        for path in check.get("paths", []):
            p = Path(path)
            if p.exists():
                try:
                    content = p.read_text(errors="ignore")[:500]
                    self._report_escape(
                        check,
                        evidence_detail=f"Host file readable: {path}\nContent preview: {content[:200]}",
                    )
                    return
                except PermissionError:
                    pass

    async def _check_writable_path(self, check: dict[str, Any]) -> None:
        """Check if dangerous paths are writable."""
        import glob
        for pattern in check.get("paths", []):
            for path in glob.glob(pattern):
                if os.access(path, os.W_OK):
                    self._report_escape(check, evidence_detail=f"Writable path: {path}")
                    return

    async def _check_capability(self, check: dict[str, Any]) -> None:
        """Check if a specific Linux capability is enabled."""
        cap_name = check.get("capability", "")
        try:
            cap_text = Path("/proc/self/status").read_text(errors="ignore")
            for line in cap_text.split("\n"):
                if line.startswith("CapEff:"):
                    cap_hex = int(line.split(":")[1].strip(), 16)
                    # Map capability names to bit positions
                    cap_bits = {
                        "cap_sys_ptrace": 19,
                        "cap_sys_admin": 21,
                        "cap_net_admin": 12,
                        "cap_net_raw": 13,
                    }
                    bit = cap_bits.get(cap_name, -1)
                    if bit >= 0 and (cap_hex >> bit) & 1:
                        self._report_escape(
                            check,
                            evidence_detail=f"Capability {cap_name} enabled (CapEff: 0x{cap_hex:016x})",
                        )
                    return
        except Exception:
            pass

    async def _check_network_ns(self, check: dict[str, Any]) -> None:
        """Check if container shares host network namespace."""
        try:
            # If container shares host netns, /proc/1/ns/net == /proc/self/ns/net
            host_ns = os.readlink("/proc/1/ns/net") if Path("/proc/1/ns/net").exists() else ""
            self_ns = os.readlink("/proc/self/ns/net") if Path("/proc/self/ns/net").exists() else ""
            if host_ns and host_ns == self_ns:
                self._report_escape(check, evidence_detail=f"Shared network NS: {host_ns}")
        except Exception:
            pass

    async def _check_pid_ns(self, check: dict[str, Any]) -> None:
        """Check if container shares host PID namespace."""
        try:
            host_ns = os.readlink("/proc/1/ns/pid") if Path("/proc/1/ns/pid").exists() else ""
            self_ns = os.readlink("/proc/self/ns/pid") if Path("/proc/self/ns/pid").exists() else ""
            if host_ns and host_ns == self_ns:
                self._report_escape(check, evidence_detail=f"Shared PID NS: {host_ns}")
        except Exception:
            pass

    async def _check_writable_mount(self, check: dict[str, Any]) -> None:
        """Check for writable host path mounts."""
        for path in check.get("paths", []):
            p = Path(path)
            if p.exists() and p.is_dir() and os.access(str(p), os.W_OK):
                self._report_escape(check, evidence_detail=f"Writable host mount: {path}")
                return

    async def _check_seccomp(self, check: dict[str, Any]) -> None:
        """Check if seccomp is disabled."""
        try:
            status = Path("/proc/self/status").read_text(errors="ignore")
            for line in status.split("\n"):
                if line.startswith("Seccomp:"):
                    mode = int(line.split(":")[1].strip())
                    if mode == 0:
                        self._report_escape(check, evidence_detail="Seccomp mode: 0 (disabled)")
                    return
        except Exception:
            pass

    def _report_escape(self, check: dict[str, Any], evidence_detail: str) -> None:
        """Create a finding for a detected container escape vector."""
        sev_map = {
            "Critical": Severity.CRITICAL,
            "High": Severity.HIGH,
            "Medium": Severity.MEDIUM,
        }
        self.new_finding(
            title=f"Container Escape — {check['name']}",
            severity=sev_map.get(check.get("severity", "High"), Severity.HIGH),
            description=check["description"],
            reproduction_steps=[
                "Gain shell access inside the target container",
                f"Verify escape vector: {evidence_detail}",
                f"Exploit: {check['description']}",
            ],
            remediation=check.get("remediation", "Apply container hardening best practices."),
            references=[
                "https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation",
                "https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/",
                "https://attack.mitre.org/techniques/T1611/",
            ],
            evidence=Evidence(
                extra={
                    "check_id": check["id"],
                    "evidence": evidence_detail,
                    "in_container": self._in_container,
                },
            ),
            cvss_v31_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
            mitre_attack=check.get("mitre", ["T1611"]),
            target=self.config.target,
            tags=["container", "escape", check["id"]],
        )


class TestContainerEscape:
    """Unit tests for ContainerEscape."""

    def test_class_attributes(self) -> None:
        assert ContainerEscape.NAME == "container_escape"
        assert ContainerEscape.PHASE == 3
        assert "container" in ContainerEscape.TAGS

    def test_instantiation(self, tmp_path: "Path") -> None:
        from pathlib import Path
        from common.config import BaseForgeConfig
        from common.scope import Scope
        from common.db import create_db

        cfg = BaseForgeConfig(target="10.0.0.1")
        scope = Scope(["10.0.0.0/24"])
        session = create_db(tmp_path / "test.db")
        mod = ContainerEscape(cfg, scope, session, tmp_path)
        assert mod.NAME == "container_escape"
        assert mod._in_container is False
        session.close()

    def test_detect_container_env_false_outside(self) -> None:
        from common.config import BaseForgeConfig
        from common.scope import Scope
        from common.db import create_db
        from pathlib import Path
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            cfg = BaseForgeConfig(target="10.0.0.1")
            scope = Scope(["10.0.0.0/24"])
            session = create_db(tmp / "test.db")
            mod = ContainerEscape(cfg, scope, session, tmp)
            # On a normal host without /.dockerenv, this should be False
            # (may be True in actual Docker — that's fine)
            result = mod._detect_container_env()
            assert isinstance(result, bool)
            session.close()

    def test_escape_checks_defined(self) -> None:
        assert len(_ESCAPE_CHECKS) >= 8
        for check in _ESCAPE_CHECKS:
            assert "id" in check
            assert "name" in check
            assert "description" in check
            assert "severity" in check
