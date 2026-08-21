"""Credential Transport Layer — SSH / SNMPv3 / WinRM backends.

Provides unified remote command execution for credentialed scanning.
Each transport encrypts credentials through CredEngine and never logs
plaintext secrets. Connections are pooled per-host for reuse across
multiple check modules within the same scan.

Transports:
  SSHTransport   — paramiko (sync) / asyncssh (async) key+password auth
  SNMPv3Transport — pysnmp USM authPriv/authNoPriv/noAuthNoPriv
  WinRMTransport  — pywinrm NTLM/Kerberos PowerShell execution

The legacy implementations are retained for compatibility inspection, but
active use is intentionally unavailable until the canonical outbound policy
can issue protocol-specific, DNS-pinned, route-bound connection permits.
Every public and final delegate boundary therefore fails closed with
``outbound_policy_unsupported``.  Cleanup remains available.
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, NoReturn

from common.credential_boundary import (
    CredentialReference,
    CredentialUseApproval,
)
from common.outbound_policy import OutboundDenied, OutboundReason

log = logging.getLogger("forge.cred_transport")


def _deny_unmigrated_credential_transport() -> NoReturn:
    """Keep legacy credential transports inert until policy permits exist."""
    raise OutboundDenied(OutboundReason.OUTBOUND_POLICY_UNSUPPORTED)


class TransportIdentityError(PermissionError):
    """Safe failure for unverified SSH host keys or WinRM certificates."""


@dataclass(frozen=True)
class InsecureTransportApproval:
    """Exact lab-only approval for one invalid transport identity fixture."""

    approval_id: str
    protocol: str
    target: str
    credential_reference: str
    lab_only: bool = True
    audit_enabled: bool = True

    def matches(
        self,
        *,
        protocol: str,
        target: str,
        reference: CredentialReference,
    ) -> bool:
        return (
            bool(self.approval_id)
            and self.protocol == protocol
            and self.target == target
            and self.credential_reference == reference.value
            and self.lab_only is True
            and self.audit_enabled is True
        )


@dataclass(frozen=True)
class TransportIdentityDecision:
    """Non-secret result of transport identity verification."""

    protocol: str
    target: str
    credential_reference: str
    identity_verified: bool
    lab_override_used: bool
    audit_recorded: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "protocol": self.protocol,
            "target": self.target,
            "credential_reference": self.credential_reference,
            "identity_verified": self.identity_verified,
            "lab_override_used": self.lab_override_used,
            "audit_recorded": self.audit_recorded,
        }


def enforce_transport_identity(
    *,
    protocol: str,
    target: str,
    identity_valid: bool,
    credential_reference: CredentialReference | str | None = None,
    credential_approval: CredentialUseApproval | None = None,
    insecure_approval: InsecureTransportApproval | None = None,
    audit_sink: Callable[[dict[str, Any]], bool | None] | None = None,
) -> TransportIdentityDecision:
    """Fail closed unless an invalid lab identity has two exact approvals and audit."""
    normalized_protocol = str(protocol).strip().lower()
    normalized_target = str(target).strip()
    if normalized_protocol not in {"ssh", "winrm"} or not normalized_target:
        raise TransportIdentityError("transport identity policy input is malformed")
    if identity_valid is True:
        reference_value = (
            CredentialReference.parse(credential_reference).value
            if credential_reference
            else ""
        )
        return TransportIdentityDecision(
            protocol=normalized_protocol,
            target=normalized_target,
            credential_reference=reference_value,
            identity_verified=True,
            lab_override_used=False,
            audit_recorded=False,
        )
    if identity_valid is not False:
        raise TransportIdentityError("transport identity state is malformed")

    try:
        reference = CredentialReference.parse(credential_reference)
    except (TypeError, ValueError) as exc:
        raise TransportIdentityError("credential reference is required") from exc
    if (
        credential_approval is None
        or not credential_approval.matches(reference, target=normalized_target)
        or insecure_approval is None
        or not insecure_approval.matches(
            protocol=normalized_protocol,
            target=normalized_target,
            reference=reference,
        )
        or audit_sink is None
    ):
        raise TransportIdentityError(
            "invalid transport identity lacks exact lab approvals and audit"
        )

    audit_record = {
        "event": "lab_transport_identity_override",
        "protocol": normalized_protocol,
        "target": normalized_target,
        "credential_reference": reference.value,
        "credential_use_approval_id": credential_approval.approval_id,
        "insecure_transport_approval_id": insecure_approval.approval_id,
    }
    try:
        recorded = audit_sink(audit_record)
    except Exception as exc:
        raise TransportIdentityError("transport identity override audit failed") from exc
    if recorded is False:
        raise TransportIdentityError("transport identity override audit failed")
    return TransportIdentityDecision(
        protocol=normalized_protocol,
        target=normalized_target,
        credential_reference=reference.value,
        identity_verified=False,
        lab_override_used=True,
        audit_recorded=True,
    )


# ── Result types ─────────────────────────────────────────────────────

@dataclass
class CommandResult:
    """Result of a remote command execution."""
    stdout: str = ""
    stderr: str = ""
    exit_code: int = -1
    duration: float = 0.0
    command: str = ""
    host: str = ""
    transport: str = ""

    @property
    def success(self) -> bool:
        return self.exit_code == 0

    @property
    def output(self) -> str:
        """Combined stdout — most checks only care about this."""
        return self.stdout


@dataclass
class SNMPResult:
    """Result of an SNMP walk/get operation."""
    oid: str = ""
    value: str = ""
    value_type: str = ""
    host: str = ""


@dataclass
class ScanCredential:
    """Operator-supplied credential for credentialed scanning.

    Separate from discovered creds — these are INPUT credentials
    the operator provides to authenticate the scanner itself.
    """
    transport: str          # "ssh" | "snmpv3" | "winrm"
    username: str = ""
    password: str = field(default="", repr=False)
    key_path: str = field(default="", repr=False)  # SSH private key path
    key_passphrase: str = field(default="", repr=False)
    community: str = field(default="", repr=False)  # SNMPv2c fallback
    # SNMPv3 specifics
    auth_protocol: str = "SHA"   # SHA | MD5
    priv_protocol: str = "AES"   # AES | DES | AES256
    auth_passphrase: str = field(default="", repr=False)
    priv_passphrase: str = field(default="", repr=False)
    # WinRM specifics
    domain: str = ""
    auth_type: str = "ntlm"     # ntlm | kerberos | certificate
    port: int = 0               # 0 = use default
    # Targeting
    host_pattern: str = ""      # exact authorized host only

    def wipe(self) -> None:
        """Release references to all secret-bearing credential input fields."""
        # Python strings are immutable, so replace fields rather than writing
        # through their object addresses. TransportManager drops its final
        # object references after this cleanup.
        self.password = ""
        self.key_path = ""
        self.key_passphrase = ""
        self.community = ""
        self.auth_passphrase = ""
        self.priv_passphrase = ""

    def __repr__(self) -> str:
        """Return a representation that cannot reflect operator input."""
        return "ScanCredential(<redacted>)"


# ── Abstract Transport ───────────────────────────────────────────────

class BaseTransport(ABC):
    """Abstract base for all credential transports."""

    TRANSPORT_NAME: str = "base"

    def __init__(self) -> None:
        # Connection pool: host -> session (instance-level, not class-level)
        self._sessions: dict[str, Any] = {}

    @abstractmethod
    async def connect(self, host: str, cred: ScanCredential, port: int = 0) -> Any:
        """Establish authenticated session to host."""

    @abstractmethod
    async def execute(self, session: Any, command: str) -> CommandResult:
        """Execute a command on the remote host."""

    @abstractmethod
    async def read_file(self, session: Any, remote_path: str) -> str:
        """Read a file from the remote host."""

    @abstractmethod
    async def close(self, session: Any) -> None:
        """Close the session."""

    async def get_or_connect(self, host: str, cred: ScanCredential, port: int = 0) -> Any:
        """Get existing session or create new one."""
        _deny_unmigrated_credential_transport()
        key = f"{self.TRANSPORT_NAME}:{host}:{port or 'default'}"
        if key in self._sessions:
            session = self._sessions[key]
            if await self._is_alive(session):
                return session
            # Stale — reconnect
            try:
                await self.close(session)
            except Exception:
                pass
        session = await self.connect(host, cred, port)
        self._sessions[key] = session
        return session

    async def _is_alive(self, session: Any) -> bool:
        """Check if session is still alive. Override per transport."""
        return session is not None

    async def close_all(self) -> None:
        """Close all pooled sessions."""
        try:
            for key, session in list(self._sessions.items()):
                try:
                    await self.close(session)
                except Exception as exc:
                    log.debug(
                        "Failed to close session %s: %s",
                        key,
                        type(exc).__name__,
                    )
        finally:
            # Cancellation is a BaseException on supported Python versions;
            # the finally block still releases every pooled-session reference.
            self._sessions.clear()


# ── SSH Transport ────────────────────────────────────────────────────

class SSHTransport(BaseTransport):
    """SSH transport via paramiko (sync wrapped in executor) or asyncssh."""

    TRANSPORT_NAME = "ssh"

    def __init__(self) -> None:
        super().__init__()

    async def connect(self, host: str, cred: ScanCredential, port: int = 0) -> Any:
        """Connect via SSH — tries key auth first, then password."""
        _deny_unmigrated_credential_transport()
        ssh_port = port or cred.port or 22
        log.info("SSH connecting to %s:%d as %s", host, ssh_port, cred.username)

        loop = asyncio.get_event_loop()
        session = await loop.run_in_executor(
            None, self._connect_sync, host, ssh_port, cred
        )
        return session

    def _connect_sync(self, host: str, port: int, cred: ScanCredential) -> Any:
        """Synchronous paramiko connection."""
        _deny_unmigrated_credential_transport()
        try:
            import paramiko
        except ImportError:
            raise RuntimeError(
                "paramiko not installed — run: pip install paramiko"
            )

        client, connect_kwargs = self._build_connect_plan(
            host,
            port,
            cred,
            paramiko,
        )
        client.connect(**connect_kwargs)
        log.info("SSH session established: %s@%s:%d", cred.username, host, port)
        return {"client": client, "host": host, "port": port, "user": cred.username}

    def _build_connect_plan(
        self,
        host: str,
        port: int,
        cred: ScanCredential,
        paramiko_module: Any,
    ) -> tuple[Any, dict[str, Any]]:
        """Build a no-network SSH plan for secure-default inspection."""
        paramiko = paramiko_module

        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.RejectPolicy())

        connect_kwargs: dict[str, Any] = {
            "hostname": host,
            "port": port,
            "username": cred.username,
            "timeout": 15,
            "allow_agent": False,
            "look_for_keys": False,
            "banner_timeout": 10,
        }

        # Key-based auth takes priority
        if cred.key_path and Path(cred.key_path).is_file():
            try:
                pkey = paramiko.RSAKey.from_private_key_file(
                    cred.key_path,
                    password=cred.key_passphrase or None,
                )
            except paramiko.SSHException:
                try:
                    pkey = paramiko.Ed25519Key.from_private_key_file(
                        cred.key_path,
                        password=cred.key_passphrase or None,
                    )
                except paramiko.SSHException:
                    pkey = paramiko.ECDSAKey.from_private_key_file(
                        cred.key_path,
                        password=cred.key_passphrase or None,
                    )
            connect_kwargs["pkey"] = pkey
        elif cred.password:
            connect_kwargs["password"] = cred.password
        else:
            raise RuntimeError("SSH credential has no approved password or key reference")

        return client, connect_kwargs

    async def execute(self, session: Any, command: str) -> CommandResult:
        """Execute command over SSH."""
        _deny_unmigrated_credential_transport()
        client = session["client"]
        host = session["host"]
        start = time.monotonic()

        loop = asyncio.get_event_loop()
        stdout, stderr, exit_code = await loop.run_in_executor(
            None, self._exec_sync, client, command
        )

        return CommandResult(
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
            duration=time.monotonic() - start,
            command=command,
            host=host,
            transport="ssh",
        )

    def _exec_sync(self, client: Any, command: str) -> tuple[str, str, int]:
        """Synchronous command execution."""
        _deny_unmigrated_credential_transport()
        _, stdout_ch, stderr_ch = client.exec_command(command, timeout=60)
        stdout = stdout_ch.read().decode("utf-8", errors="replace")
        stderr = stderr_ch.read().decode("utf-8", errors="replace")
        exit_code = stdout_ch.channel.recv_exit_status()
        return stdout, stderr, exit_code

    async def read_file(self, session: Any, remote_path: str) -> str:
        """Read file via SFTP."""
        _deny_unmigrated_credential_transport()
        client = session["client"]
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, self._read_file_sync, client, remote_path
        )

    def _read_file_sync(self, client: Any, remote_path: str) -> str:
        """Synchronous SFTP file read."""
        _deny_unmigrated_credential_transport()
        try:
            sftp = client.open_sftp()
            with sftp.open(remote_path, "r") as f:
                content = f.read().decode("utf-8", errors="replace")
            sftp.close()
            return content
        except Exception as exc:
            # Fall back to cat command if SFTP is restricted
            _, stdout, _ = client.exec_command(f"cat {remote_path}", timeout=10)
            return stdout.read().decode("utf-8", errors="replace")

    async def close(self, session: Any) -> None:
        """Close SSH session."""
        try:
            session["client"].close()
        except Exception:
            pass

    async def _is_alive(self, session: Any) -> bool:
        """Check SSH transport is still active."""
        try:
            transport = session["client"].get_transport()
            return transport is not None and transport.is_active()
        except Exception:
            return False


# ── SNMPv3 Transport ─────────────────────────────────────────────────

class SNMPv3Transport(BaseTransport):
    """SNMPv3 USM transport for authenticated SNMP walks."""

    TRANSPORT_NAME = "snmpv3"

    def __init__(self) -> None:
        super().__init__()

    async def connect(self, host: str, cred: ScanCredential, port: int = 0) -> Any:
        """Build SNMPv3 session parameters (no actual TCP connection)."""
        _deny_unmigrated_credential_transport()
        snmp_port = port or cred.port or 161
        log.info("SNMPv3 session for %s:%d user=%s", host, snmp_port, cred.username)

        return {
            "host": host,
            "port": snmp_port,
            "username": cred.username,
            "auth_proto": cred.auth_protocol.upper(),
            "priv_proto": cred.priv_protocol.upper(),
            "auth_pass": cred.auth_passphrase,
            "priv_pass": cred.priv_passphrase,
        }

    async def execute(self, session: Any, command: str) -> CommandResult:
        """Not applicable for SNMP — use snmp_get/snmp_walk instead."""
        _deny_unmigrated_credential_transport()

    async def snmp_get(self, session: Any, oid: str) -> list[SNMPResult]:
        """SNMP GET with SNMPv3 USM authentication."""
        _deny_unmigrated_credential_transport()
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, self._snmp_get_sync, session, oid
        )

    def _snmp_get_sync(self, session: dict, oid: str) -> list[SNMPResult]:
        """Synchronous SNMPv3 GET."""
        _deny_unmigrated_credential_transport()
        try:
            from pysnmp.hlapi import (
                getCmd, SnmpEngine, UsmUserData,
                UdpTransportTarget, ContextData,
                ObjectType, ObjectIdentity,
                usmHMACSHAAuthProtocol, usmHMACMD5AuthProtocol,
                usmAesCfb128Protocol, usmDESPrivProtocol,
            )
        except ImportError:
            log.warning("pysnmp not installed — SNMPv3 transport unavailable")
            return []

        auth_proto = (
            usmHMACSHAAuthProtocol if session["auth_proto"] == "SHA"
            else usmHMACMD5AuthProtocol
        )
        priv_proto = (
            usmAesCfb128Protocol if session["priv_proto"] == "AES"
            else usmDESPrivProtocol
        )

        user_data = UsmUserData(
            session["username"],
            authKey=session["auth_pass"],
            privKey=session["priv_pass"],
            authProtocol=auth_proto,
            privProtocol=priv_proto,
        )

        results: list[SNMPResult] = []
        try:
            error_indication, error_status, _, var_binds = next(
                getCmd(
                    SnmpEngine(),
                    user_data,
                    UdpTransportTarget(
                        (session["host"], session["port"]),
                        timeout=5, retries=1,
                    ),
                    ContextData(),
                    ObjectType(ObjectIdentity(oid)),
                )
            )
            if not error_indication and not error_status:
                for var_bind in var_binds:
                    results.append(SNMPResult(
                        oid=str(var_bind[0]),
                        value=str(var_bind[1]),
                        value_type=type(var_bind[1]).__name__,
                        host=session["host"],
                    ))
        except Exception as exc:
            log.debug("SNMPv3 GET %s failed: %s", oid, type(exc).__name__)

        return results

    async def snmp_walk(self, session: Any, oid: str, max_results: int = 500) -> list[SNMPResult]:
        """SNMP WALK with SNMPv3 USM authentication."""
        _deny_unmigrated_credential_transport()
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, self._snmp_walk_sync, session, oid, max_results
        )

    def _snmp_walk_sync(self, session: dict, oid: str, max_results: int) -> list[SNMPResult]:
        """Synchronous SNMPv3 WALK (GETNEXT iteration)."""
        _deny_unmigrated_credential_transport()
        try:
            from pysnmp.hlapi import (
                nextCmd, SnmpEngine, UsmUserData,
                UdpTransportTarget, ContextData,
                ObjectType, ObjectIdentity,
                usmHMACSHAAuthProtocol, usmHMACMD5AuthProtocol,
                usmAesCfb128Protocol, usmDESPrivProtocol,
            )
        except ImportError:
            return []

        auth_proto = (
            usmHMACSHAAuthProtocol if session["auth_proto"] == "SHA"
            else usmHMACMD5AuthProtocol
        )
        priv_proto = (
            usmAesCfb128Protocol if session["priv_proto"] == "AES"
            else usmDESPrivProtocol
        )

        user_data = UsmUserData(
            session["username"],
            authKey=session["auth_pass"],
            privKey=session["priv_pass"],
            authProtocol=auth_proto,
            privProtocol=priv_proto,
        )

        results: list[SNMPResult] = []
        try:
            for error_indication, error_status, _, var_binds in nextCmd(
                SnmpEngine(),
                user_data,
                UdpTransportTarget(
                    (session["host"], session["port"]),
                    timeout=5, retries=1,
                ),
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
                lexicographicMode=False,
            ):
                if error_indication or error_status:
                    break
                for var_bind in var_binds:
                    results.append(SNMPResult(
                        oid=str(var_bind[0]),
                        value=str(var_bind[1]),
                        value_type=type(var_bind[1]).__name__,
                        host=session["host"],
                    ))
                if len(results) >= max_results:
                    break
        except Exception as exc:
            log.debug("SNMPv3 WALK %s failed: %s", oid, type(exc).__name__)

        return results

    async def read_file(self, session: Any, remote_path: str) -> str:
        """Not applicable for SNMP."""
        _deny_unmigrated_credential_transport()

    async def close(self, session: Any) -> None:
        """SNMP is stateless — nothing to close."""
        pass


# ── WinRM Transport ──────────────────────────────────────────────────

class WinRMTransport(BaseTransport):
    """WinRM transport for Windows credentialed checks via PowerShell."""

    TRANSPORT_NAME = "winrm"

    def __init__(self) -> None:
        super().__init__()

    async def connect(self, host: str, cred: ScanCredential, port: int = 0) -> Any:
        """Establish WinRM session."""
        _deny_unmigrated_credential_transport()
        winrm_port = port or cred.port or 5986
        log.info("WinRM connecting to %s:%d as %s", host, winrm_port, cred.username)

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, self._connect_sync, host, winrm_port, cred
        )

    def _connect_sync(self, host: str, port: int, cred: ScanCredential) -> Any:
        """Synchronous WinRM connection."""
        _deny_unmigrated_credential_transport()
        try:
            import winrm
        except ImportError:
            raise RuntimeError(
                "pywinrm not installed — run: pip install pywinrm"
            )

        endpoint, username, session_kwargs = self._build_session_plan(
            host,
            port,
            cred,
        )
        session = winrm.Session(endpoint, **session_kwargs)

        # Validate connection with a simple command
        try:
            result = session.run_ps("$env:COMPUTERNAME")
            if result.status_code != 0:
                raise RuntimeError("WinRM authentication failed")
        except Exception as exc:
            raise RuntimeError(
                f"WinRM connection failed ({type(exc).__name__})"
            ) from None

        log.info("WinRM session established: %s@%s:%d", username, host, port)
        return {
            "session": session,
            "host": host,
            "port": port,
            "user": username,
        }

    def _build_session_plan(
        self,
        host: str,
        port: int,
        cred: ScanCredential,
    ) -> tuple[str, str, dict[str, Any]]:
        """Build no-network WinRM arguments for secure-default inspection."""
        if port != 5986:
            raise RuntimeError("WinRM over HTTP is unsupported; HTTPS port 5986 is required")
        endpoint = f"https://{host}:{port}/wsman"

        username = cred.username
        if cred.domain and "\\" not in username and "@" not in username:
            username = f"{cred.domain}\\{username}"

        return endpoint, username, {
            "auth": (username, cred.password),
            "transport": cred.auth_type,
            "server_cert_validation": "validate",
            "read_timeout_sec": 60,
            "operation_timeout_sec": 55,
        }

    async def execute(self, session: Any, command: str) -> CommandResult:
        """Execute PowerShell command via WinRM."""
        _deny_unmigrated_credential_transport()
        winrm_session = session["session"]
        host = session["host"]
        start = time.monotonic()

        loop = asyncio.get_event_loop()
        stdout, stderr, exit_code = await loop.run_in_executor(
            None, self._exec_sync, winrm_session, command
        )

        return CommandResult(
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
            duration=time.monotonic() - start,
            command=command,
            host=host,
            transport="winrm",
        )

    def _exec_sync(self, session: Any, command: str) -> tuple[str, str, int]:
        """Synchronous PowerShell execution."""
        _deny_unmigrated_credential_transport()
        result = session.run_ps(command)
        return (
            result.std_out.decode("utf-8", errors="replace"),
            result.std_err.decode("utf-8", errors="replace"),
            result.status_code,
        )

    async def execute_cmd(self, session: Any, command: str) -> CommandResult:
        """Execute CMD command (non-PowerShell) via WinRM."""
        _deny_unmigrated_credential_transport()
        winrm_session = session["session"]
        host = session["host"]
        start = time.monotonic()

        loop = asyncio.get_event_loop()
        stdout, stderr, exit_code = await loop.run_in_executor(
            None, self._exec_cmd_sync, winrm_session, command
        )

        return CommandResult(
            stdout=stdout, stderr=stderr, exit_code=exit_code,
            duration=time.monotonic() - start,
            command=command, host=host, transport="winrm",
        )

    def _exec_cmd_sync(self, session: Any, command: str) -> tuple[str, str, int]:
        """Synchronous CMD execution."""
        _deny_unmigrated_credential_transport()
        result = session.run_cmd(command)
        return (
            result.std_out.decode("utf-8", errors="replace"),
            result.std_err.decode("utf-8", errors="replace"),
            result.status_code,
        )

    async def read_file(self, session: Any, remote_path: str) -> str:
        """Read file via PowerShell Get-Content."""
        _deny_unmigrated_credential_transport()
        result = await self.execute(
            session,
            f"Get-Content -Path '{remote_path}' -Raw -ErrorAction SilentlyContinue"
        )
        return result.stdout if result.success else ""

    async def close(self, session: Any) -> None:
        """WinRM sessions are stateless per-request — nothing to close."""
        pass

    async def _is_alive(self, session: Any) -> bool:
        """Check WinRM session is still valid."""
        try:
            result = await self.execute(session, "$true")
            return result.success
        except Exception:
            return False


# ── Transport Manager ────────────────────────────────────────────────

class TransportManager:
    """Manages all credential transports for a scan run.

    Provides a clean API for modules to get connected sessions
    without worrying about transport details.
    """

    def __init__(self) -> None:
        self._ssh = SSHTransport()
        self._snmpv3 = SNMPv3Transport()
        self._winrm = WinRMTransport()
        self._creds: list[ScanCredential] = []

    def add_credential(self, cred: ScanCredential) -> None:
        """Register a scan credential."""
        if not cred.host_pattern or any(marker in cred.host_pattern for marker in "*?["):
            raise ValueError("credential binding requires one exact authorized host")
        self._creds.append(cred)

    def has_creds(self, transport: str) -> bool:
        """Check if credentials exist for a given transport type."""
        return any(c.transport == transport for c in self._creds)

    def get_cred(self, host: str, transport: str) -> ScanCredential | None:
        """Find best matching credential for host + transport."""
        for cred in self._creds:
            if cred.transport != transport:
                continue
            if host.strip().lower().rstrip(".") == cred.host_pattern.strip().lower().rstrip("."):
                return cred
        return None

    @property
    def ssh(self) -> SSHTransport:
        return self._ssh

    @property
    def snmpv3(self) -> SNMPv3Transport:
        return self._snmpv3

    @property
    def winrm(self) -> WinRMTransport:
        return self._winrm

    async def get_ssh_session(self, host: str, port: int = 0) -> Any | None:
        """Get or create SSH session for host."""
        _deny_unmigrated_credential_transport()
        cred = self.get_cred(host, "ssh")
        if not cred:
            return None
        try:
            return await self._ssh.get_or_connect(host, cred, port)
        except Exception as exc:
            log.warning("SSH connection to %s failed: %s", host, type(exc).__name__)
            return None

    async def get_snmpv3_session(self, host: str, port: int = 0) -> Any | None:
        """Get or create SNMPv3 session for host."""
        _deny_unmigrated_credential_transport()
        cred = self.get_cred(host, "snmpv3")
        if not cred:
            return None
        try:
            return await self._snmpv3.get_or_connect(host, cred, port)
        except Exception as exc:
            log.warning(
                "SNMPv3 session for %s failed: %s",
                host,
                type(exc).__name__,
            )
            return None

    async def get_winrm_session(self, host: str, port: int = 0) -> Any | None:
        """Get or create WinRM session for host."""
        _deny_unmigrated_credential_transport()
        cred = self.get_cred(host, "winrm")
        if not cred:
            return None
        try:
            return await self._winrm.get_or_connect(host, cred, port)
        except Exception as exc:
            log.warning(
                "WinRM connection to %s failed: %s",
                host,
                type(exc).__name__,
            )
            return None

    async def close_all(self) -> None:
        """Close sessions, then wipe and release every registered credential."""
        first_error: BaseException | None = None
        try:
            # Continue cleanup across independent transports even when one is
            # cancelled.  Cancellation is re-raised only after every pool has
            # dropped its session references and every credential is wiped.
            for name, transport in (
                ("ssh", self._ssh),
                ("snmpv3", self._snmpv3),
                ("winrm", self._winrm),
            ):
                try:
                    await transport.close_all()
                except BaseException as exc:
                    log.debug(
                        "Failed to close %s transport: %s",
                        name,
                        type(exc).__name__,
                    )
                    if first_error is None:
                        first_error = exc
            if first_error is not None:
                raise first_error
        finally:
            try:
                for credential in self._creds:
                    credential.wipe()
            finally:
                self._creds.clear()

    # ── Convenience credential registration ──────────────────────────
    # Called by netforge.py's CLI flag handling

    def add_ssh_creds(
        self,
        username: str,
        password: str | None = None,
        key_file: str | None = None,
        key_passphrase: str | None = None,
        port: int = 22,
        host_pattern: str = "",
    ) -> None:
        """Register SSH credentials from CLI flags."""
        self.add_credential(ScanCredential(
            transport="ssh",
            username=username,
            password=password or "",
            key_path=key_file or "",
            key_passphrase=key_passphrase or "",
            port=port,
            host_pattern=host_pattern,
        ))

    def add_snmpv3_creds(
        self,
        username: str,
        auth_passphrase: str | None = None,
        priv_passphrase: str | None = None,
        auth_protocol: str = "SHA",
        priv_protocol: str = "AES",
        port: int = 161,
        host_pattern: str = "",
    ) -> None:
        """Register SNMPv3 credentials from CLI flags."""
        self.add_credential(ScanCredential(
            transport="snmpv3",
            username=username,
            auth_passphrase=auth_passphrase or "",
            priv_passphrase=priv_passphrase or "",
            auth_protocol=auth_protocol,
            priv_protocol=priv_protocol,
            port=port,
            host_pattern=host_pattern,
        ))

    def add_winrm_creds(
        self,
        username: str,
        password: str | None = None,
        domain: str = "",
        port: int = 5986,
        use_ssl: bool = True,
        auth_type: str = "ntlm",
        host_pattern: str = "",
    ) -> None:
        """Register WinRM credentials from CLI flags."""
        if not use_ssl or port != 5986:
            raise ValueError("WinRM requires HTTPS with certificate validation on port 5986")
        actual_port = 5986
        # Extract domain from user@domain or domain\user format
        _domain = domain
        _user = username
        if "\\" in username:
            _domain, _user = username.split("\\", 1)
        elif "@" in username:
            _user, _domain = username.split("@", 1)
        self.add_credential(ScanCredential(
            transport="winrm",
            username=_user,
            password=password or "",
            domain=_domain,
            port=actual_port,
            auth_type=auth_type,
            host_pattern=host_pattern,
        ))


# ── Credential file parser ───────────────────────────────────────────

def parse_cred_file(path: str | Path) -> list[ScanCredential]:
    """Parse a YAML credential file into ScanCredential objects.

    Format:
        credentials:
          - transport: ssh
            host_pattern: "10.0.0.*"
            username: root
            key_path: ~/.ssh/id_rsa
          - transport: snmpv3
            host_pattern: "*"
            username: snmpuser
            auth_passphrase: authpass123
            priv_passphrase: privpass456
          - transport: winrm
            host_pattern: "10.0.0.10"
            username: Administrator
            password: P@ssw0rd
            domain: CORP
    """
    import yaml

    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"Credential file not found: {path}")

    with open(path) as f:
        data = yaml.safe_load(f)

    creds: list[ScanCredential] = []
    for entry in data.get("credentials", []):
        creds.append(ScanCredential(
            transport=entry.get("transport", "ssh"),
            username=entry.get("username", ""),
            password=entry.get("password", ""),
            key_path=entry.get("key_path", ""),
            key_passphrase=entry.get("key_passphrase", ""),
            community=entry.get("community", ""),
            auth_protocol=entry.get("auth_protocol", "SHA"),
            priv_protocol=entry.get("priv_protocol", "AES"),
            auth_passphrase=entry.get("auth_passphrase", ""),
            priv_passphrase=entry.get("priv_passphrase", ""),
            domain=entry.get("domain", ""),
            auth_type=entry.get("auth_type", "ntlm"),
            port=entry.get("port", 0),
            host_pattern=entry.get("host_pattern", ""),
        ))

    return creds
