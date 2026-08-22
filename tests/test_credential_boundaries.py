"""Credential-reference, process-handoff, and artifact lifecycle tests."""
from __future__ import annotations

import asyncio
import json
import os
import stat
import sys
from pathlib import Path

import pytest

import common.artifact_io as artifact_io_module
import common.credential_boundary as credential_boundary_module
import netforge.core.cred_engine as cred_engine_module
from common.artifact_io import ArtifactBoundaryError
from common.credential_boundary import (
    CREDENTIAL_FD_ENV,
    CREDENTIAL_REF_ENV,
    CredentialReference,
    CredentialUseApproval,
    InMemorySecretProvider,
    ProtectedCredentialBundle,
    minimal_child_environment,
    protected_artifact,
    resolved_process_credentials,
)
from common.evidence import save_http_evidence
from common.outbound_policy import OutboundDenied, OutboundReason
from netforge.core.cred_transport import (
    InsecureTransportApproval,
    ScanCredential,
    TransportManager,
    TransportIdentityError,
    enforce_transport_identity,
)
from netforge.core.cred_engine import CredEngine
from netforge.netforge import _finalize_credential_engine


SECRET = "CANARY_CREDENTIAL_BOUNDARY_007"


def test_minimal_child_environment_drops_arbitrary_and_proxy_secrets() -> None:
    environment = {
        "PATH": "/usr/bin",
        "LANG": "C.UTF-8",
        "FORGE_TENANT_ID": "tenant-fixture",
        "THIRD_PARTY_PASSWORD": SECRET,
        "DATABASE_URL": f"postgresql://operator:{SECRET}@db.test/fixture",
        "HTTPS_PROXY": f"http://operator:{SECRET}@proxy.test:8080",
        "LD_PRELOAD": "/untrusted/injection.so",
    }

    child = minimal_child_environment(
        environment,
        allowlist={"FORGE_TENANT_ID"},
    )

    assert child == {
        "PATH": "/usr/bin",
        "LANG": "C.UTF-8",
        "FORGE_TENANT_ID": "tenant-fixture",
    }
    assert SECRET not in repr(child)


def test_reference_resolves_only_with_exact_approval_and_never_serializes_value() -> None:
    provider = InMemorySecretProvider("fixture")
    reference = provider.put({"username": "operator", "password": SECRET})

    serialized = json.dumps(reference.to_dict()) + repr(reference)
    assert SECRET not in serialized

    wrong = CredentialUseApproval(
        approval_id="approval-wrong",
        provider="fixture",
        target="wrong.test",
        credential_reference=reference.value,
    )
    with pytest.raises(PermissionError):
        with provider.resolve(reference, approval=wrong, target="target.test"):
            pass
    assert provider.resolve_calls == 0

    exact = CredentialUseApproval(
        approval_id="approval-exact",
        provider="fixture",
        target="target.test",
        credential_reference=reference.value,
    )
    with provider.resolve(reference, approval=exact, target="target.test") as values:
        assert values["password"] == SECRET
    assert values == {}
    assert provider.resolve_calls == 1

    with pytest.raises(KeyError):
        with provider.resolve(reference, approval=exact, target="target.test"):
            pass


def test_process_handoff_keeps_secret_out_of_argv_env_and_metadata() -> None:
    source_values = {"username": "operator", "password": SECRET}
    bundle = ProtectedCredentialBundle(source_values)
    assert source_values == {}
    argv = ["python", "webforge.py", "--credential-ref", bundle.reference.value]

    with bundle.open_pipe() as handoff:
        metadata = json.dumps(handoff.to_dict())
        assert SECRET not in " ".join(argv)
        assert SECRET not in json.dumps(handoff.env)
        assert SECRET not in metadata
        child_env = dict(handoff.env)
        with resolved_process_credentials(child_env) as values:
            assert values["password"] == SECRET
        assert values == {}
        assert child_env == {}

    assert SECRET not in repr(bundle)


def test_malformed_process_handoff_closes_owned_secret_descriptor() -> None:
    read_fd, write_fd = os.pipe()
    try:
        os.set_inheritable(read_fd, True)
        os.write(write_fd, SECRET.encode("utf-8"))
    finally:
        os.close(write_fd)
    child_env = {
        CREDENTIAL_REF_ENV: "malformed-reference",
        CREDENTIAL_FD_ENV: str(read_fd),
    }

    with pytest.raises(ValueError, match="credential process handoff is malformed"):
        with resolved_process_credentials(child_env):
            pytest.fail("malformed handoff unexpectedly resolved")

    assert child_env == {}
    with pytest.raises(OSError):
        os.fstat(read_fd)


@pytest.mark.parametrize("failure", [False, True])
def test_protected_artifact_is_owner_only_and_cleaned_on_all_paths(
    tmp_path: Path,
    failure: bool,
) -> None:
    artifact_path: Path | None = None
    reference = ""
    with pytest.raises(RuntimeError) if failure else _does_not_raise():
        with protected_artifact(SECRET.encode(), suffix=".txt", parent=tmp_path) as artifact:
            artifact_path = artifact.path
            reference = artifact.reference
            assert artifact.path.exists()
            assert artifact.path.stat().st_mode & 0o077 == 0
            assert SECRET not in json.dumps(artifact.to_dict())
            if failure:
                raise RuntimeError("fixture failure")
    assert artifact_path is not None
    assert not artifact_path.exists()
    assert reference.startswith("artifact:local:")


def test_protected_artifact_is_removed_on_cancellation(tmp_path: Path) -> None:
    artifact_path: Path | None = None
    with pytest.raises(asyncio.CancelledError):
        with protected_artifact(SECRET.encode(), parent=tmp_path) as artifact:
            artifact_path = artifact.path
            raise asyncio.CancelledError
    assert artifact_path is not None
    assert not artifact_path.exists()


def test_protected_artifact_cleans_directory_when_setup_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / "protected-parent"
    parent.mkdir(mode=0o700)
    original_chmod = Path.chmod

    def fail_private_directory_chmod(
        path: Path,
        mode: int,
        *,
        follow_symlinks: bool = True,
    ) -> None:
        if path.parent == parent and path.name.startswith("forge-credential-"):
            raise PermissionError("fixture directory chmod failure")
        original_chmod(path, mode, follow_symlinks=follow_symlinks)

    with monkeypatch.context() as scoped:
        scoped.setattr(Path, "chmod", fail_private_directory_chmod)
        with pytest.raises(PermissionError, match="fixture directory chmod failure"):
            with protected_artifact(b"fixture", parent=parent):
                pass
    assert list(parent.iterdir()) == []

    def fail_mkstemp(*_args: object, **_kwargs: object) -> tuple[int, str]:
        raise PermissionError("fixture mkstemp failure")

    with monkeypatch.context() as scoped:
        scoped.setattr(credential_boundary_module.tempfile, "mkstemp", fail_mkstemp)
        with pytest.raises(PermissionError, match="fixture mkstemp failure"):
            with protected_artifact(b"fixture", parent=parent):
                pass
    assert list(parent.iterdir()) == []


def test_protected_artifact_wipes_plaintext_when_unlink_is_denied(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact_path: Path | None = None
    original_unlink = credential_boundary_module.os.unlink

    def deny_artifact_unlink(
        path: os.PathLike[str] | str,
        *,
        dir_fd: int | None = None,
    ) -> None:
        if Path(path).name.startswith("artifact-"):
            raise PermissionError("fixture unlink denial")
        original_unlink(path, dir_fd=dir_fd)

    with monkeypatch.context() as scoped:
        scoped.setattr(credential_boundary_module.os, "unlink", deny_artifact_unlink)
        with protected_artifact(SECRET.encode(), parent=tmp_path) as artifact:
            artifact_path = artifact.path

    assert artifact_path is not None
    assert artifact_path.exists()
    assert artifact_path.read_bytes() == b""
    artifact_directory = artifact_path.parent
    artifact_path.unlink()
    artifact_directory.rmdir()


def test_legacy_credential_helpers_are_inert_at_every_effect_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from adforge.core.kerberos_client import KerberosClient
    from netforge.modules.bruteforce.cred_spray import CredSpray
    from netforge.modules.bruteforce.hydra_wrap import HydraWrap
    from netforge.modules.bruteforce.native_brute import NativeBrute
    from webforge.modules.auth.login_brute import LoginBrute

    effect_calls: list[tuple[str, tuple[object, ...]]] = []

    async def forbidden_effect(*args: object, **_kwargs: object) -> object:
        effect_calls.append(("async", args))
        raise AssertionError("legacy credential effect reached")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", forbidden_effect)
    monkeypatch.setattr(asyncio, "open_connection", forbidden_effect)

    spray = CredSpray.__new__(CredSpray)
    hydra = HydraWrap.__new__(HydraWrap)
    native = NativeBrute.__new__(NativeBrute)
    login = LoginBrute.__new__(LoginBrute)
    for instance in (spray, hydra, native, login):
        # Plain caller-created attributes and reference-looking strings are not
        # capabilities and must never turn a direct helper into an effect path.
        instance.authorization_envelope = object()
        instance.authorization_decision_id = "authz-" + "a" * 32
        instance.runtime_credential_reference = "cred:" + "b" * 32

    async_calls = (
        ("cred_spray.ssh", lambda: spray._try_ssh("127.0.0.1", "operator", SECRET)),
        ("cred_spray.smb", lambda: spray._try_smb("127.0.0.1", "operator", SECRET)),
        (
            "hydra.process",
            lambda: hydra._run_hydra("/fixture/hydra", "127.0.0.1", 22, "ssh"),
        ),
        ("hydra.builtin", lambda: hydra._builtin_brute("127.0.0.1")),
        (
            "native.dispatch",
            lambda: native._try_auth("ssh", "127.0.0.1", 22, "operator", SECRET),
        ),
        ("native.ssh", lambda: native._auth_ssh("127.0.0.1", 22, "operator", SECRET)),
        ("native.ftp", lambda: native._auth_ftp("127.0.0.1", 21, "operator", SECRET)),
        ("native.mysql", lambda: native._auth_mysql("127.0.0.1", 3306, "operator", SECRET)),
        (
            "native.postgres",
            lambda: native._auth_postgres("127.0.0.1", 5432, "operator", SECRET),
        ),
        ("native.redis", lambda: native._auth_redis("127.0.0.1", 6379, "operator", SECRET)),
        (
            "native.mongodb",
            lambda: native._auth_mongodb("127.0.0.1", 27017, "operator", SECRET),
        ),
        ("native.smb", lambda: native._auth_smb("127.0.0.1", 445, "operator", SECRET)),
        ("native.http", lambda: native._auth_http("127.0.0.1", 80, "operator", SECRET)),
        ("native.vnc", lambda: native._auth_vnc("127.0.0.1", 5900, "operator", SECRET)),
        ("native.rdp", lambda: native._auth_rdp("127.0.0.1", 3389, "operator", SECRET)),
        ("login.discovery", lambda: login._find_login_form("https://127.0.0.1/login")),
        (
            "login.post",
            lambda: login._post_login(
                "https://127.0.0.1/login",
                "username",
                "password",
                "operator",
                SECRET,
            ),
        ),
    )
    rendered_errors: list[str] = []
    for name, call in async_calls:
        with pytest.raises(OutboundDenied) as caught:
            asyncio.run(call())
        assert caught.value.reason_code == OutboundReason.OUTBOUND_POLICY_UNSUPPORTED.value, name
        rendered_errors.append(str(caught.value))

    for name, call in (
        (
            "native.mongo_sync",
            lambda: native._mongo_sync("127.0.0.1", 27017, "operator", SECRET),
        ),
        (
            "native.smb_sync",
            lambda: native._smb_sync("127.0.0.1", 445, "operator", SECRET),
        ),
    ):
        with pytest.raises(OutboundDenied) as caught:
            call()
        assert caught.value.reason_code == OutboundReason.OUTBOUND_POLICY_UNSUPPORTED.value, name
        rendered_errors.append(str(caught.value))

    kerberos = KerberosClient(
        "fixture.test",
        "127.0.0.1",
        username="operator",
        password=SECRET,
        nt_hash="0123456789abcdef0123456789abcdef",
    )
    retained = repr(vars(kerberos))
    assert SECRET not in retained
    assert "0123456789abcdef0123456789abcdef" not in retained
    assert "password" not in vars(kerberos)
    assert "nt_hash" not in vars(kerberos)
    for call in (
        kerberos.get_tgt,
        kerberos.get_np_users,
        kerberos.get_spn_hashes,
    ):
        with pytest.raises(OutboundDenied) as caught:
            asyncio.run(call())
        assert caught.value.reason_code == OutboundReason.OUTBOUND_POLICY_UNSUPPORTED.value
        rendered_errors.append(str(caught.value))

    assert effect_calls == []
    assert SECRET not in repr(rendered_errors)


def test_http_evidence_atomically_replaces_symlink_and_preserves_parent_mode(
    tmp_path: Path,
) -> None:
    parent = tmp_path / "caller-owned"
    parent.mkdir(mode=0o755)
    parent.chmod(0o755)
    victim = tmp_path / "victim.txt"
    victim.write_text("HTTP_EVIDENCE_VICTIM", encoding="utf-8")
    victim.chmod(0o644)
    destination = parent / "case_request.txt"
    destination.symlink_to(victim)

    save_http_evidence(
        "GET /fixture HTTP/1.1",
        "HTTP/1.1 200 OK",
        parent,
        "case",
    )

    assert victim.read_text(encoding="utf-8") == "HTTP_EVIDENCE_VICTIM"
    assert stat.S_IMODE(victim.stat().st_mode) == 0o644
    assert destination.is_symlink() is False
    assert destination.read_text(encoding="utf-8") == "GET /fixture HTTP/1.1"
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert stat.S_IMODE(parent.stat().st_mode) == 0o755


def test_process_handoff_closes_fd_and_wipes_on_spawn_exception() -> None:
    bundle = ProtectedCredentialBundle({"password": SECRET})
    inherited_fd = -1
    with pytest.raises(RuntimeError):
        with bundle.open_pipe() as handoff:
            inherited_fd = handoff.pass_fds[0]
            raise RuntimeError("fake spawn failure")
    with pytest.raises(OSError):
        os.fstat(inherited_fd)
    with pytest.raises(RuntimeError):
        with bundle.open_pipe():
            pass


def test_oversized_process_handoff_clears_mutable_source_values() -> None:
    source_values = {"password": "X" * (33 * 1024)}
    with pytest.raises(ValueError):
        ProtectedCredentialBundle(source_values)
    assert source_values == {}


class _does_not_raise:
    def __enter__(self):
        return None

    def __exit__(self, exc_type, exc, tb):
        return False


@pytest.mark.parametrize("protocol", ["ssh", "winrm"])
def test_invalid_transport_identity_fails_without_exact_dual_approval(protocol: str) -> None:
    with pytest.raises(TransportIdentityError):
        enforce_transport_identity(
            protocol=protocol,
            target="127.0.0.1",
            identity_valid=False,
        )


@pytest.mark.parametrize("protocol", ["ssh", "winrm"])
def test_lab_transport_override_requires_matching_approvals_and_audit(protocol: str) -> None:
    reference = CredentialReference.create("fixture")
    credential_approval = CredentialUseApproval(
        approval_id="credential-approval-007",
        provider="fixture",
        target="127.0.0.1",
        credential_reference=reference.value,
    )
    insecure_approval = InsecureTransportApproval(
        approval_id="transport-approval-007",
        protocol=protocol,
        target="127.0.0.1",
        credential_reference=reference.value,
    )
    audit: list[dict[str, object]] = []

    decision = enforce_transport_identity(
        protocol=protocol,
        target="127.0.0.1",
        identity_valid=False,
        credential_reference=reference,
        credential_approval=credential_approval,
        insecure_approval=insecure_approval,
        audit_sink=lambda record: audit.append(record) or True,
    )

    assert decision.lab_override_used is True
    assert decision.audit_recorded is True
    assert len(audit) == 1
    assert SECRET not in json.dumps(audit)

    mismatched = InsecureTransportApproval(
        approval_id="transport-approval-wrong",
        protocol=protocol,
        target="127.0.0.2",
        credential_reference=reference.value,
    )
    with pytest.raises(TransportIdentityError):
        enforce_transport_identity(
            protocol=protocol,
            target="127.0.0.1",
            identity_valid=False,
            credential_reference=reference,
            credential_approval=credential_approval,
            insecure_approval=mismatched,
            audit_sink=lambda record: True,
        )


@pytest.mark.parametrize("export_failure", [False, True])
def test_discovered_credential_cleanup_survives_event_or_export_failure(
    tmp_path: Path,
    export_failure: bool,
) -> None:
    class FakeCredential:
        source = "fixture"

        def to_dict(self):
            return {
                "service": "ssh",
                "username": "operator",
                "host": "127.0.0.1",
            }

        def key(self):
            return "fixture-key"

    class FakeEngine:
        def __init__(self):
            self.wiped = False
            self._creds = [FakeCredential()]

        def __len__(self):
            return len(self._creds)

        def all(self):
            return list(self._creds)

        def export_json(self, path):
            if export_failure:
                raise RuntimeError("fake report serialization failure")
            path.write_text('{"credential_reference":"cred:fixture:reference"}')

        def wipe_all(self):
            self.wiped = True
            self._creds.clear()

    class FailingBus:
        def emit(self, event):
            raise RuntimeError("fake discovered-credential event failure")

    from common.dashboard.event_bus import Event, EventType

    engine = FakeEngine()
    _finalize_credential_engine(engine, tmp_path, FailingBus(), Event, EventType)

    assert engine.wiped is True
    assert engine._creds == []


def test_credential_export_preserves_existing_parent_and_secures_created_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = CredEngine()
    existing_parent = tmp_path / "caller-owned"
    existing_parent.mkdir(mode=0o755)
    existing_parent.chmod(0o755)
    existing_export = existing_parent / "credential-references.json"
    existing_export.write_text("stale", encoding="utf-8")
    existing_export.chmod(0o644)

    engine.export_json(existing_export)

    assert stat.S_IMODE(existing_parent.stat().st_mode) == 0o755
    assert stat.S_IMODE(existing_export.stat().st_mode) == 0o600

    nested_export = tmp_path / "new-parent" / "new-child" / "credential-references.json"
    previous_umask = os.umask(0o022)
    try:
        engine.export_json(nested_export)
    finally:
        os.umask(previous_umask)

    assert stat.S_IMODE(nested_export.parent.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(nested_export.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(nested_export.stat().st_mode) == 0o600

    failed_export = existing_parent / "failed-credential-references.json"
    failed_export.write_text("stale", encoding="utf-8")
    failed_export.chmod(0o644)

    def fail_write(_descriptor: int, _data: bytes) -> int:
        raise OSError("fixture write failure")

    monkeypatch.setattr(cred_engine_module.os, "write", fail_write)

    with pytest.raises(ArtifactBoundaryError, match="artifact write failed") as denied:
        engine.export_json(failed_export)

    assert "fixture write failure" not in str(denied.value)
    assert stat.S_IMODE(existing_parent.stat().st_mode) == 0o755
    assert failed_export.read_text(encoding="utf-8") == "stale"
    assert stat.S_IMODE(failed_export.stat().st_mode) == 0o644
    assert not list(existing_parent.glob(f".{failed_export.name}.*.tmp"))


def test_credential_export_replaces_symlink_without_mutating_victim(
    tmp_path: Path,
) -> None:
    engine = CredEngine()
    parent = tmp_path / "caller-owned"
    parent.mkdir()
    parent.chmod(0o755)
    victim = tmp_path / "victim.txt"
    victim.write_text("CREDENTIAL_EXPORT_SYMLINK_VICTIM", encoding="utf-8")
    victim.chmod(0o644)
    destination = parent / "credential-references.json"
    destination.symlink_to(victim)

    engine.export_json(destination)

    assert victim.read_text(encoding="utf-8") == "CREDENTIAL_EXPORT_SYMLINK_VICTIM"
    assert stat.S_IMODE(victim.stat().st_mode) == 0o644
    assert destination.is_symlink() is False
    assert destination.is_file()
    assert json.loads(destination.read_text(encoding="utf-8")) == []
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert stat.S_IMODE(parent.stat().st_mode) == 0o755


def test_credential_export_rejects_intermediate_parent_symlink(
    tmp_path: Path,
) -> None:
    engine = CredEngine()
    redirected = tmp_path / "redirected"
    redirected.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(redirected, target_is_directory=True)
    destination = alias / "nested" / "credential-references.json"

    with pytest.raises(ArtifactBoundaryError, match="artifact directory"):
        engine.export_json(destination)

    assert list(redirected.iterdir()) == []


def test_credential_export_rejects_parent_swap_after_descriptor_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = CredEngine()
    parent = tmp_path / "credential-parent"
    parent.mkdir(mode=0o755)
    parent.chmod(0o755)
    detached = tmp_path / "credential-parent-detached"
    redirected = tmp_path / "credential-redirected"
    redirected.mkdir(mode=0o755)
    redirected.chmod(0o755)
    destination = parent / "credential-references.json"
    real_write_all = artifact_io_module._write_all
    swapped = False

    def swap_parent_after_write(descriptor: int, payload: bytes) -> None:
        nonlocal swapped
        real_write_all(descriptor, payload)
        if not swapped:
            swapped = True
            parent.rename(detached)
            parent.symlink_to(redirected, target_is_directory=True)

    monkeypatch.setattr(artifact_io_module, "_write_all", swap_parent_after_write)

    with pytest.raises(
        ArtifactBoundaryError,
        match="artifact directory changed during write",
    ):
        engine.export_json(destination)

    assert parent.is_symlink()
    assert list(redirected.iterdir()) == []
    assert list(detached.iterdir()) == []
    assert stat.S_IMODE(redirected.stat().st_mode) == 0o755


def test_credential_export_breaks_hardlink_without_mutating_alias(
    tmp_path: Path,
) -> None:
    engine = CredEngine()
    parent = tmp_path / "caller-owned"
    parent.mkdir(mode=0o755)
    parent.chmod(0o755)
    victim = tmp_path / "credential-hardlink-victim"
    victim.write_text("CREDENTIAL_EXPORT_HARDLINK_VICTIM", encoding="utf-8")
    victim.chmod(0o640)
    victim_before = victim.read_bytes()
    destination = parent / "credential-references.json"
    os.link(victim, destination)

    engine.export_json(destination)

    assert destination.stat().st_ino != victim.stat().st_ino
    assert json.loads(destination.read_text(encoding="utf-8")) == []
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert victim.read_bytes() == victim_before
    assert stat.S_IMODE(victim.stat().st_mode) == 0o640
    assert stat.S_IMODE(parent.stat().st_mode) == 0o755


def test_cred_engine_preserves_unicode_and_clears_owned_buffers_on_duplicates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured_buffers: list[bytearray] = []
    original_buffer_factory = cred_engine_module._owned_plaintext_buffer

    def capture_buffer(value: str) -> bytearray:
        buffer = original_buffer_factory(value)
        captured_buffers.append(buffer)
        return buffer

    monkeypatch.setattr(cred_engine_module, "_owned_plaintext_buffer", capture_buffer)
    password = sys.intern("".join(("CANARY", "_密码_", "🔐")))
    password_alias = password
    original_password = password.encode("utf-8")
    original_hash = hash(password)
    engine = CredEngine()

    first = engine.add("127.0.0.1", "ssh", "operator", password=password)
    duplicate = engine.add(
        "127.0.0.1",
        "ssh",
        "operator",
        password="CANARY_DUPLICATE_PASSWORD",
        nt_hash="CANARY_DUPLICATE_NT_HASH",
        lm_hash="CANARY_DUPLICATE_LM_HASH",
    )

    assert duplicate is first
    assert password_alias is password
    assert password.encode("utf-8") == original_password
    assert hash(password) == original_hash
    assert first.get_password(engine.session_key).encode("utf-8") == original_password
    assert first.get_nt_hash(engine.session_key) == "CANARY_DUPLICATE_NT_HASH"
    assert first.get_lm_hash(engine.session_key) == "CANARY_DUPLICATE_LM_HASH"
    assert len(captured_buffers) == 6
    assert all(buffer == bytearray() for buffer in captured_buffers)


def test_cred_engine_clears_every_owned_buffer_when_encryption_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured_buffers: list[bytearray] = []
    original_buffer_factory = cred_engine_module._owned_plaintext_buffer

    def capture_buffer(value: str) -> bytearray:
        buffer = original_buffer_factory(value)
        captured_buffers.append(buffer)
        return buffer

    def fail_encryption(_value: bytearray, _key: bytes) -> str:
        raise RuntimeError("fixture encryption failure")

    monkeypatch.setattr(cred_engine_module, "_owned_plaintext_buffer", capture_buffer)
    monkeypatch.setattr(cred_engine_module, "_encrypt_field", fail_encryption)

    with pytest.raises(RuntimeError, match="fixture encryption failure"):
        CredEngine().add(
            "127.0.0.1",
            "ssh",
            "operator",
            password="CANARY_PASSWORD",
            nt_hash="CANARY_NT_HASH",
            lm_hash="CANARY_LM_HASH",
        )

    assert len(captured_buffers) == 3
    assert all(buffer == bytearray() for buffer in captured_buffers)


def test_scan_credential_repr_and_explicit_wipe_hide_every_secret_field() -> None:
    secrets = {
        "password": "CANARY_SCAN_PASSWORD",
        "key_path": "/CANARY/PRIVATE/KEY",
        "key_passphrase": "CANARY_KEY_PASSPHRASE",
        "community": "CANARY_COMMUNITY",
        "auth_passphrase": "CANARY_AUTH_PASSPHRASE",
        "priv_passphrase": "CANARY_PRIV_PASSPHRASE",
    }
    credential = ScanCredential(
        transport="ssh",
        username="operator",
        host_pattern="127.0.0.1",
        **secrets,
    )

    rendered = repr(credential)
    assert rendered == "ScanCredential(<redacted>)"
    assert all(secret not in rendered for secret in secrets.values())

    credential.wipe()
    assert all(getattr(credential, field_name) == "" for field_name in secrets)


def test_transport_manager_wipes_credentials_after_close_error() -> None:
    manager = TransportManager()
    credential = ScanCredential(
        transport="ssh",
        username="operator",
        password="CANARY_CLOSE_ERROR_PASSWORD",
        key_passphrase="CANARY_CLOSE_ERROR_KEY",
        host_pattern="127.0.0.1",
    )
    manager.add_credential(credential)
    assert "CANARY_CLOSE_ERROR_PASSWORD" not in repr(manager._creds)
    assert "CANARY_CLOSE_ERROR_KEY" not in repr(manager._creds)
    close_calls: list[str] = []

    async def fail_ssh_close() -> None:
        close_calls.append("ssh")
        raise RuntimeError("fixture close failure")

    async def close_snmp() -> None:
        close_calls.append("snmpv3")

    async def close_winrm() -> None:
        close_calls.append("winrm")

    manager._ssh.close_all = fail_ssh_close  # type: ignore[method-assign]
    manager._snmpv3.close_all = close_snmp  # type: ignore[method-assign]
    manager._winrm.close_all = close_winrm  # type: ignore[method-assign]

    with pytest.raises(RuntimeError, match="fixture close failure"):
        asyncio.run(manager.close_all())

    assert close_calls == ["ssh", "snmpv3", "winrm"]
    assert manager._creds == []
    assert credential.password == ""
    assert credential.key_passphrase == ""


def test_transport_manager_and_pool_clear_on_close_cancellation() -> None:
    manager = TransportManager()
    credential = ScanCredential(
        transport="ssh",
        username="operator",
        password="CANARY_CANCEL_PASSWORD",
        community="CANARY_CANCEL_COMMUNITY",
        host_pattern="127.0.0.1",
    )
    manager.add_credential(credential)
    manager._ssh._sessions["fixture"] = object()
    manager._snmpv3._sessions["fixture"] = object()
    manager._winrm._sessions["fixture"] = object()

    async def cancel_close(_session: object) -> None:
        raise asyncio.CancelledError

    manager._ssh.close = cancel_close  # type: ignore[method-assign]

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(manager.close_all())

    assert manager._ssh._sessions == {}
    assert manager._snmpv3._sessions == {}
    assert manager._winrm._sessions == {}
    assert manager._creds == []
    assert credential.password == ""
    assert credential.community == ""


def test_all_netforge_paramiko_paths_reject_unknown_host_keys() -> None:
    root = Path(__file__).resolve().parents[1]
    paths = [
        root / "netforge/modules/bruteforce/cred_spray.py",
        root / "netforge/modules/bruteforce/hydra_wrap.py",
        root / "netforge/modules/bruteforce/native_brute.py",
        root / "netforge/core/cred_transport.py",
    ]
    for path in paths:
        source = path.read_text(encoding="utf-8")
        assert "paramiko.AutoAddPolicy(" not in source
        assert "paramiko.RejectPolicy(" in source
