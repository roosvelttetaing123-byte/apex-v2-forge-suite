"""Protected credential references and ephemeral process handoff helpers."""
from __future__ import annotations

import json
import os
import secrets
import tempfile
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping, MutableMapping

from common.redaction import REDACTED, redact_value


CREDENTIAL_REF_ENV = "FORGE_CREDENTIAL_REF"
CREDENTIAL_FD_ENV = "FORGE_CREDENTIAL_FD"
_SCHEMA = "forge-credential-handoff-v1"
_MAX_HANDOFF_BYTES = 32 * 1024

# Environment variables are an untrusted process boundary.  In particular,
# copying ``os.environ`` and removing a few known proxy names is not a
# containment policy: deployment variables frequently contain provider
# credentials, connection strings, and file-backed secrets under arbitrary
# names.  Keep the default set deliberately small and require callers to name
# every Forge-specific handoff key they intend to pass.
_SAFE_CHILD_ENVIRONMENT_KEYS = frozenset(
    {
        "PATH",
        "LANG",
        "LANGUAGE",
        "LC_ALL",
        "LC_CTYPE",
        "LC_COLLATE",
        "LC_MESSAGES",
        "LC_MONETARY",
        "LC_NUMERIC",
        "LC_TIME",
        "TERM",
        "TZ",
        "PYTHONHASHSEED",
        "PYTHONIOENCODING",
        "PYTHONNOUSERSITE",
        "PYTHONUNBUFFERED",
        "VIRTUAL_ENV",
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "PATHEXT",
    }
)


def minimal_child_environment(
    environment: Mapping[str, str],
    *,
    allowlist: Iterable[str] = (),
) -> dict[str, str]:
    """Return a minimal, explicit environment for a child process.

    ``allowlist`` is intentionally additive and case-sensitive for Forge
    control keys.  Values are copied only when they are strings; malformed
    mapping entries are omitted rather than coerced from arbitrary objects.
    Proxy variables and dynamic-loader controls are never part of the default
    set.  Callers should add only the exact, non-secret runtime handoff keys
    needed by the child (credential pipes are added separately).
    """
    requested = set(_SAFE_CHILD_ENVIRONMENT_KEYS)
    requested.update(str(key) for key in allowlist)
    return {
        str(key): value
        for key, value in environment.items()
        if str(key) in requested and isinstance(value, str)
    }


@dataclass(frozen=True)
class CredentialReference:
    """Opaque, non-secret reference to provider-held credential material."""

    provider: str
    identifier: str

    def __post_init__(self) -> None:
        if not self.provider or not self.identifier:
            raise ValueError("credential reference is incomplete")
        if any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for ch in self.provider):
            raise ValueError("credential reference provider is malformed")
        if any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for ch in self.identifier):
            raise ValueError("credential reference identifier is malformed")

    @classmethod
    def create(cls, provider: str = "memory") -> "CredentialReference":
        return cls(provider=provider, identifier=uuid.uuid4().hex)

    @classmethod
    def parse(cls, value: object) -> "CredentialReference":
        if isinstance(value, cls):
            return value
        raw = str(value or "")
        parts = raw.split(":", 2)
        if len(parts) != 3 or parts[0] != "cred":
            raise ValueError("credential reference is malformed")
        return cls(parts[1], parts[2])

    @property
    def value(self) -> str:
        return f"cred:{self.provider}:{self.identifier}"

    def to_dict(self) -> dict[str, str]:
        return {"credential_reference": self.value}

    def __str__(self) -> str:
        return self.value

    def __repr__(self) -> str:
        return f"CredentialReference({self.value!r})"


@dataclass(frozen=True)
class CredentialUseApproval:
    """Exact approval required by a secret provider before resolution."""

    approval_id: str
    provider: str
    target: str
    credential_reference: str
    max_uses: int = 1

    def matches(self, reference: CredentialReference, *, target: str) -> bool:
        return (
            bool(self.approval_id)
            and self.provider == reference.provider
            and self.target == target
            and self.credential_reference == reference.value
            and 1 <= self.max_uses <= 100
        )


def _wipe_bytearray(value: bytearray) -> None:
    value[:] = b"\x00" * len(value)
    value.clear()


def wipe_mapping(values: MutableMapping[str, Any]) -> None:
    """Best-effort clearing of a resolved transient mapping."""
    for key, value in list(values.items()):
        if isinstance(value, bytearray):
            _wipe_bytearray(value)
        elif isinstance(value, str):
            values[key] = REDACTED
        else:
            values[key] = None
    values.clear()


class InMemorySecretProvider:
    """Single-use provider used by deterministic fixtures and local adapters."""

    def __init__(self, provider_id: str = "memory") -> None:
        self.provider_id = provider_id
        self._values: dict[str, dict[str, bytearray]] = {}
        self.resolve_calls = 0

    def put(self, values: Mapping[str, str]) -> CredentialReference:
        reference = CredentialReference.create(self.provider_id)
        self._values[reference.identifier] = {
            str(key): bytearray(str(value).encode("utf-8"))
            for key, value in values.items()
        }
        return reference

    def discard_all(self) -> None:
        """Wipe every unresolved reference without exposing its value."""
        for stored in self._values.values():
            for value in stored.values():
                _wipe_bytearray(value)
            stored.clear()
        self._values.clear()

    @contextmanager
    def resolve(
        self,
        reference: CredentialReference | str,
        *,
        approval: CredentialUseApproval,
        target: str,
    ) -> Iterator[dict[str, str]]:
        ref = CredentialReference.parse(reference)
        if ref.provider != self.provider_id or not approval.matches(ref, target=target):
            raise PermissionError("credential use approval does not match the reference")
        stored = self._values.pop(ref.identifier, None)
        if stored is None:
            raise KeyError("credential reference is unavailable or already consumed")
        self.resolve_calls += 1
        transient = {
            key: bytes(value).decode("utf-8", errors="replace")
            for key, value in stored.items()
        }
        try:
            yield transient
        finally:
            wipe_mapping(transient)
            for value in stored.values():
                _wipe_bytearray(value)
            stored.clear()


@dataclass
class ProcessCredentialHandoff:
    """Non-secret process metadata for a protected inherited pipe."""

    reference: CredentialReference
    env: dict[str, str]
    pass_fds: tuple[int, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "credential_reference": self.reference.value,
            "environment_keys": sorted(self.env),
            "inherited_fd_count": len(self.pass_fds),
        }


@dataclass
class ProtectedCredentialBundle:
    """One-shot credential bundle that takes ownership of mutable input values."""

    values: Mapping[str, str] = field(repr=False)
    ttl_seconds: int = 30
    reference: CredentialReference = field(default_factory=lambda: CredentialReference.create("pipe"))
    _payload: bytearray = field(init=False, repr=False)
    _consumed: bool = field(default=False, init=False, repr=False)

    def __post_init__(self) -> None:
        if not 1 <= self.ttl_seconds <= 300:
            raise ValueError("credential handoff TTL is outside the permitted range")
        owned_values = {
            str(key): str(value) for key, value in self.values.items()
        }
        payload = {
            "schema_version": _SCHEMA,
            "credential_reference": self.reference.value,
            "expires_at": time.time() + self.ttl_seconds,
            "values": owned_values,
        }
        try:
            encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        finally:
            wipe_mapping(owned_values)
            if isinstance(self.values, MutableMapping):
                wipe_mapping(self.values)
        if len(encoded) > _MAX_HANDOFF_BYTES:
            _wipe_bytearray(bytearray(encoded))
            raise ValueError("credential handoff exceeds the permitted size")
        self._payload = bytearray(encoded)
        self.values = {}

    @contextmanager
    def open_pipe(self) -> Iterator[ProcessCredentialHandoff]:
        if self._consumed:
            raise RuntimeError("credential handoff is single-use")
        self._consumed = True
        read_fd, write_fd = os.pipe()
        try:
            os.set_inheritable(read_fd, True)
            view = memoryview(self._payload)
            written = 0
            while written < len(view):
                written += os.write(write_fd, view[written:])
            view.release()
            os.close(write_fd)
            write_fd = -1
            yield ProcessCredentialHandoff(
                reference=self.reference,
                env={
                    CREDENTIAL_REF_ENV: self.reference.value,
                    CREDENTIAL_FD_ENV: str(read_fd),
                },
                pass_fds=(read_fd,),
            )
        finally:
            if write_fd >= 0:
                try:
                    os.close(write_fd)
                except OSError:
                    pass
            try:
                os.close(read_fd)
            except OSError:
                pass
            _wipe_bytearray(self._payload)

    def wipe(self) -> None:
        _wipe_bytearray(self._payload)

    def __repr__(self) -> str:
        return f"ProtectedCredentialBundle(reference={self.reference!r})"

    def __del__(self) -> None:
        try:
            self.wipe()
        except Exception:
            pass


@contextmanager
def resolved_process_credentials(
    environ: MutableMapping[str, str] | None = None,
) -> Iterator[dict[str, str]]:
    """Resolve one inherited credential pipe and wipe transient values on exit."""
    source = os.environ if environ is None else environ
    reference_raw = source.pop(CREDENTIAL_REF_ENV, "")
    fd_raw = source.pop(CREDENTIAL_FD_ENV, "")
    if not reference_raw and not fd_raw:
        yield {}
        return
    fd = -1
    data = bytearray()
    transient: dict[str, str] = {}
    try:
        # Take ownership of any syntactically valid inherited descriptor before
        # parsing the accompanying reference.  A malformed reference must not
        # leave a secret-bearing descriptor open in the child process.
        try:
            fd = int(fd_raw)
            if fd < 0:
                raise ValueError
        except (TypeError, ValueError) as exc:
            raise ValueError("credential process handoff is malformed") from exc
        try:
            reference = CredentialReference.parse(reference_raw)
        except (TypeError, ValueError) as exc:
            raise ValueError("credential process handoff is malformed") from exc

        while len(data) <= _MAX_HANDOFF_BYTES:
            chunk = os.read(fd, min(4096, _MAX_HANDOFF_BYTES + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        try:
            os.close(fd)
        except OSError:
            pass
        fd = -1
        if len(data) > _MAX_HANDOFF_BYTES:
            raise ValueError("credential process handoff exceeds the permitted size")

        payload = json.loads(bytes(data).decode("utf-8"))
        if (
            not isinstance(payload, dict)
            or payload.get("schema_version") != _SCHEMA
            or payload.get("credential_reference") != reference.value
            or float(payload.get("expires_at", 0)) < time.time()
            or not isinstance(payload.get("values"), dict)
        ):
            raise ValueError("credential process handoff is invalid or expired")
        transient = {
            str(key): str(value) for key, value in payload["values"].items()
        }
        yield transient
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        wipe_mapping(transient)
        _wipe_bytearray(data)


@dataclass
class ProtectedArtifact:
    """Owner-only, bounded-lifetime local artifact."""

    reference: str
    path: Path

    def to_dict(self) -> dict[str, str]:
        return {
            "artifact_reference": self.reference,
            "path": str(self.path),
        }


def _wipe_open_artifact(fd: int) -> None:
    """Best-effort zero and truncate of an already-open private artifact."""
    size = 0
    try:
        size = max(0, os.fstat(fd).st_size)
    except OSError:
        pass
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        remaining = size
        zeroes = b"\x00" * min(64 * 1024, max(1, remaining))
        while remaining:
            count = os.write(fd, zeroes[: min(len(zeroes), remaining)])
            if count <= 0:
                break
            remaining -= count
        os.fsync(fd)
    except OSError:
        pass
    # Truncation is an independent fallback when overwrite or fsync fails.
    try:
        os.ftruncate(fd, 0)
        os.fsync(fd)
    except OSError:
        pass


def _unlink_private_entry(directory_fd: int, name: str) -> None:
    """Remove one entry relative to its pinned private directory."""
    for _attempt in range(3):
        try:
            os.unlink(name, dir_fd=directory_fd)
            return
        except FileNotFoundError:
            return
        except OSError:
            continue


@contextmanager
def protected_artifact(
    data: bytes,
    *,
    suffix: str = "",
    parent: Path | None = None,
) -> Iterator[ProtectedArtifact]:
    """Create a mode-0600 artifact and remove it on every exit path."""
    directory: Path | None = None
    path: Path | None = None
    fd = -1
    directory_fd = -1
    try:
        directory = Path(
            tempfile.mkdtemp(
                prefix="forge-credential-",
                dir=str(parent) if parent else None,
            )
        )
        directory.chmod(0o700)
        directory_fd = os.open(
            directory,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        fd, raw_path = tempfile.mkstemp(
            prefix="artifact-",
            suffix=suffix,
            dir=directory,
        )
        path = Path(raw_path)
        reference = f"artifact:local:{secrets.token_hex(16)}"
        os.fchmod(fd, 0o600)
        written = 0
        while written < len(data):
            count = os.write(fd, data[written:])
            if count <= 0:
                raise OSError("protected artifact write made no progress")
            written += count
        os.fsync(fd)
        # Keep the descriptor pinned across the artifact lifetime.  Cleanup can
        # then wipe the original inode even if its pathname is replaced.
        yield ProtectedArtifact(reference=reference, path=path)
    finally:
        if fd >= 0:
            _wipe_open_artifact(fd)
            try:
                os.close(fd)
            except OSError:
                pass
        if path is not None and directory_fd >= 0:
            _unlink_private_entry(directory_fd, path.name)
        if directory_fd >= 0:
            try:
                os.close(directory_fd)
            except OSError:
                pass
        if directory is not None:
            for _attempt in range(3):
                try:
                    directory.rmdir()
                    break
                except FileNotFoundError:
                    break
                except OSError:
                    continue


def safe_credential_summary(value: Any) -> Any:
    """Expose only references and non-secret provider metadata."""
    return redact_value(value)
