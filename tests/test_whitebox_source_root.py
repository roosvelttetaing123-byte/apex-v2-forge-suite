"""Deterministic source-root containment tests for WebForge whitebox modules."""
from __future__ import annotations

import asyncio
import copy
import os
import pickle
import stat
import sys
import traceback
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch

import pytest

from common.action_authorization import (
    AUTHORIZATION_DB_ENV,
    AuthorizationContext,
    ConfirmationMethod,
    OperatorRole,
    SafetyMode,
    consume_authorization,
    issue_authorization,
    open_authorization_session,
)
from common.config import BaseForgeConfig
from common.confirm_gate import ActionConfirmation
from common.db import create_db
from common.scope import Scope
from webforge.core.source_root import (
    SourceRootError,
    canonical_source_root,
    iter_source_files,
    open_source_file,
    require_approved_source_root,
)
from webforge.modules.whitebox.secret_scan import SecretScan
from webforge.modules.whitebox.dep_audit import DepAudit, inventory_dependency_manifests
from webforge import webforge
from webforge.webforge import parse_args


@pytest.fixture(autouse=True)
def _isolated_module_authorization_db(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv(
        AUTHORIZATION_DB_ENV,
        str(tmp_path / "whitebox-authorization.db"),
    )


def _authorized_module_config(
    source_root: object | None,
    module_id: str,
    *,
    attach_envelope: bool = True,
) -> tuple[BaseForgeConfig, str]:
    cfg = BaseForgeConfig(target="https://example.test", mode="whitebox")
    cfg.extra["allowed_scope"] = ["example.test"]
    cfg.extra["excluded_scope"] = []
    if source_root is not None:
        cfg.extra["source_root"] = canonical_source_root(source_root)
    run_id = f"run-{module_id}"
    context = AuthorizationContext(
        tenant_id="tenant-whitebox",
        engagement_id="engagement-whitebox",
        run_id=run_id,
        job_id=f"job-{module_id}",
        operator_id="operator-whitebox",
        operator_role=OperatorRole.OPERATOR,
        action_kind="module.execute",
        engine="webforge",
        module_id=module_id,
        requested_target=cfg.target,
        resolved_target=cfg.target,
        allowed_scope=cfg.extra["allowed_scope"],
        excluded_scope=cfg.extra["excluded_scope"],
        safety_mode=SafetyMode.ACTIVE,
        confirmation_method=ConfirmationMethod.CLI_PROMPT,
        confirmed_by="operator-whitebox",
    )
    session = open_authorization_session()
    try:
        issued = issue_authorization(
            session=session,
            context=context,
            confirmation=ActionConfirmation.create(
                job_id=context.job_id,
                target=cfg.target,
                engine="webforge",
                action="module.execute",
            ),
        )
        assert issued.allowed is True
        consumed = consume_authorization(
            session=session,
            envelope=issued.envelope,
            expected=context,
            boundary="webforge.module",
        )
        assert consumed.allowed is True
    finally:
        session.close()
    if attach_envelope:
        cfg.extra["authorized_module_envelopes"] = {module_id: issued.envelope}
    # These source-root tests exercise traversal and redaction in isolation;
    # they do not construct the canonical module-version / asset graph.  Keep
    # persistence compatibility explicit so production adapters stay strict.
    cfg.extra["allow_legacy_compat"] = True
    return cfg, run_id


def _secret_scan(
    tmp_path: Path,
    source_root: object | None,
    *,
    attach_envelope: bool = True,
) -> SecretScan:
    cfg, run_id = _authorized_module_config(
        source_root,
        "secret_scan",
        attach_envelope=attach_envelope,
    )
    return SecretScan(
        cfg,
        Scope(["example.test"]),
        create_db(tmp_path / "whitebox.db"),
        tmp_path / "results",
        run_id=run_id,
    )


def _dep_audit(tmp_path: Path, source_root: object | None) -> DepAudit:
    cfg, run_id = _authorized_module_config(source_root, "dep_audit")
    return DepAudit(
        cfg,
        Scope(["example.test"]),
        create_db(tmp_path / "dependency-whitebox.db"),
        tmp_path / "results",
        run_id=run_id,
    )


@pytest.mark.parametrize("value", [None, "", ".", "../outside"])
def test_source_root_missing_or_relative_fails_closed(value: object) -> None:
    with pytest.raises(SourceRootError):
        canonical_source_root(value)


def test_malformed_pathlike_fails_closed_without_type_error() -> None:
    class BytesPath:
        def __fspath__(self) -> bytes:
            return b"/tmp/fixture-root"

    with pytest.raises(SourceRootError):
        canonical_source_root(BytesPath())


@pytest.mark.parametrize(
    "value,canary",
    [
        ("/tmp/approved\x00PATH_CANARY", "PATH_CANARY"),
        ("~USER_EXPANSION_CANARY/source", "USER_EXPANSION_CANARY"),
    ],
)
def test_malformed_source_roots_return_only_safe_errors(
    value: object,
    canary: str,
) -> None:
    with pytest.raises(SourceRootError) as caught:
        canonical_source_root(value)

    assert str(caught.value) == "source_root is unavailable"
    assert canary not in str(caught.value)


def test_exploding_pathlike_returns_only_a_safe_error() -> None:
    canary = "PATHLIKE_EXCEPTION_CANARY"

    class ExplodingPath:
        def __fspath__(self) -> str:
            raise RuntimeError(canary)

    with pytest.raises(SourceRootError) as caught:
        canonical_source_root(ExplodingPath())

    assert str(caught.value) == "source_root is unavailable"
    assert canary not in str(caught.value)
    assert caught.value.__cause__ is None
    assert canary not in "".join(traceback.format_exception(caught.value))


def test_generic_root_fstat_and_close_failures_are_normalized_without_masking(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    approved = tmp_path / "approved"
    approved.mkdir()
    fstat_canary = "ROOT_FSTAT_EXCEPTION_CANARY"
    close_canary = "ROOT_CLOSE_EXCEPTION_CANARY"
    real_close = os.close
    opened_descriptors: list[int] = []

    def exploding_fstat(descriptor: int):
        opened_descriptors.append(descriptor)
        raise RuntimeError(fstat_canary)

    def exploding_close(descriptor: int) -> None:
        if descriptor in opened_descriptors:
            raise RuntimeError(close_canary)
        real_close(descriptor)

    with monkeypatch.context() as scoped:
        scoped.setattr("webforge.core.source_root.os.fstat", exploding_fstat)
        scoped.setattr("webforge.core.source_root.os.close", exploding_close)
        with pytest.raises(SourceRootError) as caught:
            canonical_source_root(approved)

    for descriptor in opened_descriptors:
        try:
            real_close(descriptor)
        except OSError:
            pass

    rendered = "".join(traceback.format_exception(caught.value))
    assert str(caught.value) == "source_root is unavailable or unsafe"
    assert caught.value.__cause__ is None
    assert fstat_canary not in rendered
    assert close_canary not in rendered


def test_generic_root_close_failure_prevents_approval_without_disclosure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    approved = tmp_path / "approved"
    approved.mkdir()
    canary = "ROOT_SUCCESS_CLOSE_EXCEPTION_CANARY"
    real_close = os.close
    failed_descriptors: list[int] = []

    def exploding_close(descriptor: int) -> None:
        failed_descriptors.append(descriptor)
        raise RuntimeError(canary)

    with monkeypatch.context() as scoped:
        scoped.setattr("webforge.core.source_root.os.close", exploding_close)
        with pytest.raises(SourceRootError) as caught:
            canonical_source_root(approved)

    for descriptor in failed_descriptors:
        try:
            real_close(descriptor)
        except OSError:
            pass

    rendered = "".join(traceback.format_exception(caught.value))
    assert str(caught.value) == "source_root is unavailable or unsafe"
    assert caught.value.__cause__ is None
    assert canary not in rendered


def test_existing_source_root_error_is_preserved_when_cleanup_also_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    approved = tmp_path / "approved"
    approved.mkdir()
    expected = SourceRootError("source_root identity changed after approval")
    close_canary = "PRESERVED_ERROR_CLOSE_CANARY"
    real_close = os.close
    opened_descriptors: list[int] = []

    def existing_error_fstat(descriptor: int):
        opened_descriptors.append(descriptor)
        raise expected

    def exploding_close(descriptor: int) -> None:
        if descriptor in opened_descriptors:
            raise RuntimeError(close_canary)
        real_close(descriptor)

    with monkeypatch.context() as scoped:
        scoped.setattr("webforge.core.source_root.os.fstat", existing_error_fstat)
        scoped.setattr("webforge.core.source_root.os.close", exploding_close)
        with pytest.raises(SourceRootError) as caught:
            canonical_source_root(approved)

    for descriptor in opened_descriptors:
        try:
            real_close(descriptor)
        except OSError:
            pass

    assert caught.value is expected
    assert close_canary not in "".join(traceback.format_exception(caught.value))


def test_untrusted_identity_property_and_string_strip_are_never_executed(
    tmp_path: Path,
) -> None:
    approved = tmp_path / "approved"
    approved.mkdir()

    class IdentityTrap:
        identity_reads = 0

        @property
        def _approved_identity(self):
            self.identity_reads += 1
            raise RuntimeError("IDENTITY_PROPERTY_CANARY")

        def __fspath__(self) -> str:
            return str(approved)

    class StripTrap(str):
        strip_calls = 0

        def strip(self, *args, **kwargs):
            type(self).strip_calls += 1
            raise RuntimeError("STRIP_OVERRIDE_CANARY")

    trapped_path = IdentityTrap()
    assert canonical_source_root(trapped_path) == approved
    assert trapped_path.identity_reads == 0

    with pytest.raises(SourceRootError) as caught:
        canonical_source_root(StripTrap(str(approved)))
    assert StripTrap.strip_calls == 0
    assert "STRIP_OVERRIDE_CANARY" not in str(caught.value)


def test_alternate_source_keys_do_not_trigger_cwd_scan(tmp_path: Path, monkeypatch) -> None:
    cwd_canary = tmp_path / "cwd-canary.py"
    cwd_canary.write_text('password="CWD_CANARY_PASSWORD"', encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    scanner = _secret_scan(tmp_path, None)
    scanner.config.extra["source_dir"] = str(tmp_path)
    scanner.config.extra["source_path"] = str(tmp_path)

    result = asyncio.run(scanner.run())

    assert result.skipped is True
    assert result.findings == []
    assert "CWD_CANARY_PASSWORD" not in repr(result)


def test_approved_in_root_file_is_scanned_without_secret_echo(tmp_path: Path) -> None:
    root = tmp_path / "approved"
    root.mkdir()
    secret = "CANARY_EXACT_PASSWORD_42"
    (root / "settings.py").write_text(f'password="{secret}"', encoding="utf-8")
    scanner = _secret_scan(tmp_path, str(root), attach_envelope=False)
    approved_root = scanner.config.extra["source_root"]

    findings = asyncio.run(
        scanner._scan_file(
            approved_root / "settings.py",
            approved_root,
            "https://example.test",
            relative_path="settings.py",
        )
    )

    assert findings == 1
    assert len(scanner.findings) == 1
    rendered = repr(scanner.findings[0].to_dict())
    assert "settings.py" in rendered
    assert secret not in rendered


def test_outside_symlinks_and_nested_symlinks_are_not_walked(tmp_path: Path) -> None:
    root = tmp_path / "approved"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    outside_canary = "OUTSIDE_ROOT_CANARY_SECRET"
    (outside / "secret.py").write_text(
        f'password="{outside_canary}"',
        encoding="utf-8",
    )
    (root / "direct-link.py").symlink_to(outside / "secret.py")
    nested = root / "nested"
    nested.mkdir()
    (nested / "outside-dir").symlink_to(outside, target_is_directory=True)

    approved_root = canonical_source_root(root)
    yielded = list(iter_source_files(approved_root, skip_directories=frozenset()))

    assert yielded == []
    assert outside_canary not in repr(yielded)


def test_absolute_outside_file_is_rejected_without_path_or_content_echo(tmp_path: Path) -> None:
    root = tmp_path / "approved"
    outside = tmp_path / "private-location"
    root.mkdir()
    outside.mkdir()
    canary = "OUTSIDE_CONTENT_CANARY"
    outside_file = outside / "secret.txt"
    outside_file.write_text(canary, encoding="utf-8")

    with pytest.raises(SourceRootError) as caught:
        open_source_file(canonical_source_root(root), outside_file, max_bytes=1024)

    rendered = str(caught.value)
    assert canary not in rendered
    assert str(outside_file) not in rendered


def test_symlink_swap_between_walk_and_open_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "approved"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    candidate = root / "input.py"
    candidate.write_text("safe content", encoding="utf-8")
    outside_file = outside / "secret.py"
    outside_file.write_text("SWAP_CANARY_SECRET", encoding="utf-8")
    approved_root = canonical_source_root(root)
    walked = list(iter_source_files(approved_root, skip_directories=frozenset()))
    assert walked[0][0] == candidate

    candidate.unlink()
    candidate.symlink_to(outside_file)

    with pytest.raises(SourceRootError):
        open_source_file(approved_root, candidate, max_bytes=1024)


def test_whole_root_replacement_after_approval_is_rejected(tmp_path: Path) -> None:
    approved = tmp_path / "approved"
    replacement = tmp_path / "replacement"
    approved.mkdir()
    replacement.mkdir()
    (approved / "input.py").write_text("approved", encoding="utf-8")
    outside_canary = "WHOLE_ROOT_REPLACEMENT_CANARY"
    (replacement / "input.py").write_text(outside_canary, encoding="utf-8")

    bound_root = canonical_source_root(approved)
    candidate = bound_root / "input.py"
    original = tmp_path / "approved-original"
    approved.rename(original)
    replacement.rename(approved)

    with pytest.raises(SourceRootError) as opened:
        open_source_file(bound_root, candidate, max_bytes=1024)
    with pytest.raises(SourceRootError) as walked:
        list(iter_source_files(bound_root, skip_directories=frozenset()))

    rendered = f"{opened.value} {walked.value}"
    assert outside_canary not in rendered
    assert str(replacement) not in rendered


def test_open_walk_and_modules_require_the_live_approval_capability(
    tmp_path: Path,
) -> None:
    approved = tmp_path / "approved"
    approved.mkdir()
    candidate = approved / "input.py"
    candidate.write_text("approved", encoding="utf-8")
    bound_root = canonical_source_root(approved)
    stripped_roots = [type(bound_root)(bound_root), Path(bound_root), str(bound_root)]

    with pytest.raises(SourceRootError, match="approval is required"):
        canonical_source_root(stripped_roots[0])
    for stripped_root in stripped_roots:
        with pytest.raises(SourceRootError, match="approval is required"):
            require_approved_source_root(stripped_root)
        with pytest.raises(SourceRootError, match="approval is required"):
            open_source_file(stripped_root, candidate, max_bytes=1024)  # type: ignore[arg-type]
        with pytest.raises(SourceRootError, match="approval is required"):
            list(
                iter_source_files(
                    stripped_root,  # type: ignore[arg-type]
                    skip_directories=frozenset(),
                )
            )

    scanner = _secret_scan(tmp_path, None)
    scanner.config.extra["source_root"] = str(approved)
    result = asyncio.run(scanner.run())
    assert result.skipped is True
    assert result.findings == []
    assert result.skip_reason == "source_root approval is required"


def test_identityless_canonical_capability_fails_closed_at_every_use_boundary(
    tmp_path: Path,
) -> None:
    approved = tmp_path / "approved"
    approved.mkdir()
    candidate = approved / "input.py"
    candidate.write_text("approved", encoding="utf-8")
    bound_root = canonical_source_root(approved)
    setattr(bound_root, "_approved_identity", None)

    with pytest.raises(SourceRootError, match="approval is required"):
        canonical_source_root(bound_root)
    with pytest.raises(SourceRootError, match="approval is required"):
        require_approved_source_root(bound_root)
    with pytest.raises(SourceRootError, match="approval is required"):
        open_source_file(bound_root, candidate, max_bytes=1024)
    with pytest.raises(SourceRootError, match="approval is required"):
        list(iter_source_files(bound_root, skip_directories=frozenset()))


def test_derived_same_root_preserves_approval_on_supported_python_versions(
    tmp_path: Path,
) -> None:
    approved = tmp_path / "approved"
    approved.mkdir()
    bound_root = canonical_source_root(approved)

    derived_same_root = bound_root / "."

    assert require_approved_source_root(derived_same_root) == bound_root


def test_identity_bound_root_copying_preserves_approval_and_pickle_fails_closed(
    tmp_path: Path,
) -> None:
    approved = tmp_path / "approved"
    replacement = tmp_path / "replacement"
    approved.mkdir()
    replacement.mkdir()
    (approved / "input.py").write_text("approved", encoding="utf-8")
    outside_canary = "COPIED_ROOT_REPLACEMENT_CANARY"
    (replacement / "input.py").write_text(outside_canary, encoding="utf-8")

    bound_root = canonical_source_root(approved)
    copied_roots = [copy.copy(bound_root), copy.deepcopy(bound_root)]
    assert all(root is bound_root for root in copied_roots)
    with pytest.raises(TypeError) as pickled:
        pickle.dumps(bound_root)
    assert str(pickled.value) == "identity-bound source_root is not serializable"
    assert str(approved) not in str(pickled.value)

    approved.rename(tmp_path / "approved-original")
    replacement.rename(approved)
    for copied_root in copied_roots:
        with pytest.raises(SourceRootError) as caught:
            open_source_file(
                copied_root,
                copied_root / "input.py",
                max_bytes=1024,
            )
        assert outside_canary not in str(caught.value)


def test_malformed_candidate_pathlike_returns_only_a_safe_error(tmp_path: Path) -> None:
    approved = tmp_path / "approved"
    approved.mkdir()
    canary = "CANDIDATE_PATHLIKE_EXCEPTION_CANARY"

    class ExplodingPath:
        def __fspath__(self) -> str:
            raise RuntimeError(canary)

    with pytest.raises(SourceRootError) as caught:
        open_source_file(
            canonical_source_root(approved),
            ExplodingPath(),  # type: ignore[arg-type]
            max_bytes=1024,
        )

    assert str(caught.value) == "source entry is unavailable or unsafe"
    assert canary not in str(caught.value)
    assert caught.value.__cause__ is None
    assert canary not in "".join(traceback.format_exception(caught.value))


def test_nul_candidate_returns_only_a_safe_error(tmp_path: Path) -> None:
    approved = tmp_path / "approved"
    approved.mkdir()
    bound_root = canonical_source_root(approved)
    candidate = f"{approved}/input.py\x00NUL_CANDIDATE_CANARY"

    with pytest.raises(SourceRootError) as caught:
        open_source_file(bound_root, candidate, max_bytes=1024)  # type: ignore[arg-type]

    rendered = "".join(traceback.format_exception(caught.value))
    assert str(caught.value) == "source entry is unavailable or unsafe"
    assert "NUL_CANDIDATE_CANARY" not in rendered


def test_generic_file_fstat_and_close_failures_are_normalized_without_masking(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    approved = tmp_path / "approved"
    approved.mkdir()
    candidate = approved / "input.py"
    candidate.write_text("approved", encoding="utf-8")
    bound_root = canonical_source_root(approved)
    fstat_canary = "FILE_FSTAT_EXCEPTION_CANARY"
    close_canary = "FILE_CLOSE_EXCEPTION_CANARY"
    real_fstat = os.fstat
    real_close = os.close
    failed_descriptors: list[int] = []

    def exploding_file_fstat(descriptor: int):
        metadata = real_fstat(descriptor)
        if stat.S_ISREG(metadata.st_mode):
            failed_descriptors.append(descriptor)
            raise RuntimeError(fstat_canary)
        return metadata

    def exploding_file_close(descriptor: int) -> None:
        if descriptor in failed_descriptors:
            raise RuntimeError(close_canary)
        real_close(descriptor)

    with monkeypatch.context() as scoped:
        scoped.setattr(
            "webforge.core.source_root.os.fstat",
            exploding_file_fstat,
        )
        scoped.setattr(
            "webforge.core.source_root.os.close",
            exploding_file_close,
        )
        with pytest.raises(SourceRootError) as caught:
            open_source_file(bound_root, candidate, max_bytes=1024)

    for descriptor in failed_descriptors:
        try:
            real_close(descriptor)
        except OSError:
            pass

    rendered = "".join(traceback.format_exception(caught.value))
    assert str(caught.value) == "source entry could not be opened safely"
    assert caught.value.__cause__ is None
    assert fstat_canary not in rendered
    assert close_canary not in rendered


def test_traversal_failure_is_reported_instead_of_silent_partial_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    approved = tmp_path / "approved"
    approved.mkdir()
    (approved / "input.py").write_text("approved", encoding="utf-8")
    scanner = _secret_scan(tmp_path, str(approved))
    canary = "/private/outside/TRAVERSAL_ERROR_CANARY"

    def denied_scandir(path):
        raise PermissionError(canary)

    monkeypatch.setattr("webforge.core.source_root.os.scandir", denied_scandir)
    bound_root = scanner.config.extra["source_root"]
    with pytest.raises(SourceRootError) as caught:
        list(iter_source_files(bound_root, skip_directories=frozenset()))
    assert str(caught.value) == "source directory could not be read safely"
    assert canary not in "".join(traceback.format_exception(caught.value))

    result = asyncio.run(scanner.run())
    assert result.skipped is True
    assert result.findings == []
    assert result.skip_reason == "source directory could not be read safely"


def test_generic_scandir_and_close_failures_are_normalized_without_masking(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    approved = tmp_path / "approved"
    approved.mkdir()
    (approved / "input.py").write_text("approved", encoding="utf-8")
    bound_root = canonical_source_root(approved)
    scandir_canary = "SCANDIR_EXCEPTION_CANARY"
    close_canary = "SCANDIR_CLOSE_EXCEPTION_CANARY"
    real_close = os.close
    walked_descriptors: list[int] = []

    def exploding_scandir(descriptor: int):
        walked_descriptors.append(descriptor)
        raise RuntimeError(scandir_canary)

    def exploding_walk_close(descriptor: int) -> None:
        if descriptor in walked_descriptors:
            raise RuntimeError(close_canary)
        real_close(descriptor)

    with monkeypatch.context() as scoped:
        scoped.setattr(
            "webforge.core.source_root.os.scandir",
            exploding_scandir,
        )
        scoped.setattr(
            "webforge.core.source_root.os.close",
            exploding_walk_close,
        )
        with pytest.raises(SourceRootError) as caught:
            list(iter_source_files(bound_root, skip_directories=frozenset()))

    for descriptor in walked_descriptors:
        try:
            real_close(descriptor)
        except OSError:
            pass

    rendered = "".join(traceback.format_exception(caught.value))
    assert str(caught.value) == "source directory could not be read safely"
    assert caught.value.__cause__ is None
    assert scandir_canary not in rendered
    assert close_canary not in rendered


def test_root_replacement_after_traversal_is_an_explicit_module_skip(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    approved = tmp_path / "approved"
    replacement = tmp_path / "replacement"
    approved.mkdir()
    replacement.mkdir()
    (approved / "input.py").write_text("approved", encoding="utf-8")
    outside_canary = "POST_TRAVERSAL_REPLACEMENT_CANARY"
    (replacement / "input.py").write_text(
        f'password="{outside_canary}"',
        encoding="utf-8",
    )
    scanner = _secret_scan(tmp_path, str(approved))
    real_open = open_source_file
    swapped = False

    def replacing_open(root, candidate, *, max_bytes):
        nonlocal swapped
        if not swapped:
            swapped = True
            approved.rename(tmp_path / "approved-original")
            replacement.rename(approved)
        return real_open(root, candidate, max_bytes=max_bytes)

    monkeypatch.setattr(
        "webforge.modules.whitebox.secret_scan.open_source_file",
        replacing_open,
    )
    result = asyncio.run(scanner.run())

    assert swapped is True
    assert result.skipped is True
    assert result.findings == []
    assert result.skip_reason == "source_root identity changed after approval"
    assert outside_canary not in repr(result)


def test_dependency_root_replacement_after_inventory_is_an_explicit_skip(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    approved = tmp_path / "approved"
    replacement = tmp_path / "replacement"
    approved.mkdir()
    replacement.mkdir()
    (approved / "requirements.txt").write_text("approved==1\n", encoding="utf-8")
    outside_canary = "DEPENDENCY_ROOT_REPLACEMENT_CANARY"
    (replacement / "requirements.txt").write_text(
        outside_canary,
        encoding="utf-8",
    )
    auditor = _dep_audit(tmp_path, str(approved))
    real_open = open_source_file
    swapped = False

    def replacing_open(root, candidate, *, max_bytes):
        nonlocal swapped
        if not swapped:
            swapped = True
            approved.rename(tmp_path / "approved-original")
            replacement.rename(approved)
        return real_open(root, candidate, max_bytes=max_bytes)

    monkeypatch.setattr(
        "webforge.modules.whitebox.dep_audit.open_source_file",
        replacing_open,
    )
    result = asyncio.run(auditor.run())

    assert swapped is True
    assert result.skipped is True
    assert result.findings == []
    assert result.skip_reason == "source_root identity changed after approval"
    assert outside_canary not in repr(result)


@pytest.mark.parametrize(
    ("module_kind", "module_path"),
    [
        ("secret", "webforge.modules.whitebox.secret_scan"),
        ("dependency", "webforge.modules.whitebox.dep_audit"),
    ],
)
def test_unreadable_in_root_content_is_not_reported_as_complete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    module_kind: str,
    module_path: str,
) -> None:
    approved = tmp_path / "approved"
    approved.mkdir()
    (approved / "requirements.txt").write_text("fixture==1\n", encoding="utf-8")
    module = (
        _secret_scan(tmp_path, str(approved))
        if module_kind == "secret"
        else _dep_audit(tmp_path, str(approved))
    )

    def unreadable_open(*args, **kwargs):
        raise SourceRootError("source entry could not be opened safely")

    monkeypatch.setattr(
        f"{module_path}.open_source_file",
        unreadable_open,
    )
    result = asyncio.run(module.run())

    assert result.skipped is True
    assert result.findings == []
    assert result.skip_reason == "source entry could not be opened safely"


def test_root_replacement_during_initial_approval_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    approved = tmp_path / "approved"
    replacement = tmp_path / "replacement"
    approved.mkdir()
    replacement.mkdir()
    (approved / "input.py").write_text("approved", encoding="utf-8")
    (replacement / "input.py").write_text("replacement", encoding="utf-8")

    real_open = os.open
    swapped = False

    def race_open(path, flags, *args, **kwargs):
        nonlocal swapped
        if path == approved and not swapped:
            swapped = True
            approved.rename(tmp_path / "approved-original")
            replacement.rename(approved)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr("webforge.core.source_root.os.open", race_open)
    with pytest.raises(SourceRootError):
        canonical_source_root(approved)
    assert swapped is True


def test_root_disappearance_after_initial_open_is_safely_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    approved = tmp_path / "approved"
    approved.mkdir()

    real_open = os.open
    real_lstat = os.lstat
    root_opened = False

    def tracked_open(path, flags, *args, **kwargs):
        nonlocal root_opened
        descriptor = real_open(path, flags, *args, **kwargs)
        if path == approved:
            root_opened = True
        return descriptor

    def disappearing_lstat(path, *args, **kwargs):
        if path == approved and root_opened:
            raise FileNotFoundError("fixture path disappeared")
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr("webforge.core.source_root.os.open", tracked_open)
    monkeypatch.setattr("webforge.core.source_root.os.lstat", disappearing_lstat)

    with pytest.raises(SourceRootError) as caught:
        canonical_source_root(approved)

    assert str(caught.value) == "source_root identity changed after approval"
    assert str(approved) not in str(caught.value)


def test_engine_carries_root_identity_into_module_configuration(
    tmp_path: Path,
) -> None:
    approved = tmp_path / "approved"
    replacement = tmp_path / "replacement"
    approved.mkdir()
    replacement.mkdir()
    (approved / "input.py").write_text("approved", encoding="utf-8")
    outside_canary = "ENGINE_ROOT_REPLACEMENT_CANARY"
    (replacement / "input.py").write_text(
        f'password="{outside_canary}"',
        encoding="utf-8",
    )
    cfg = BaseForgeConfig(target="https://example.test", mode="whitebox")
    args = Namespace(mode="whitebox", source_root=str(approved))

    assert webforge._validate_scan_source_root(cfg, args) is None
    bound_root = cfg.extra["source_root"]
    assert os.fspath(bound_root) == str(approved.resolve())

    original = tmp_path / "approved-original"
    approved.rename(original)
    replacement.rename(approved)
    scanner = SecretScan(
        cfg,
        Scope(["example.test"]),
        create_db(tmp_path / "engine-root.db"),
        tmp_path / "results",
    )
    result = asyncio.run(scanner.run())

    assert result.skipped is True
    assert result.findings == []
    assert outside_canary not in repr(result)


def test_noncanonical_root_and_symlink_root_are_rejected(tmp_path: Path) -> None:
    root = tmp_path / "approved"
    root.mkdir()
    symlink_root = tmp_path / "alias"
    symlink_root.symlink_to(root, target_is_directory=True)

    with pytest.raises(SourceRootError):
        canonical_source_root(root / ".." / root.name)
    with pytest.raises(SourceRootError):
        canonical_source_root(symlink_root)


def test_open_source_file_reads_regular_file_deterministically(tmp_path: Path) -> None:
    root = tmp_path / "approved"
    root.mkdir()
    candidate = root / "input.txt"
    candidate.write_bytes(b"approved")

    approved_root = canonical_source_root(root)
    assert open_source_file(approved_root, candidate, max_bytes=8) == b"approved"
    with pytest.raises(SourceRootError):
        open_source_file(approved_root, candidate, max_bytes=7)


def test_webforge_cli_rejects_source_alias_and_accepts_only_source_root(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = tmp_path / "approved"
    root.mkdir()
    monkeypatch.setattr(
        sys,
        "argv",
        ["webforge.py", "--target", "https://example.test", "--source", str(root)],
    )
    with pytest.raises(SystemExit):
        parse_args()

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "webforge.py",
            "--target",
            "https://example.test",
            "--mode",
            "whitebox",
            "--source-root",
            str(root),
        ],
    )
    assert parse_args().source_root == str(root)


def test_direct_run_scan_rejects_missing_root_before_execution_side_effects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The programmatic engine boundary must enforce whitebox input too."""
    cfg = BaseForgeConfig(target="https://example.test", mode="whitebox")
    args = Namespace(mode="whitebox", dry_run=False)

    for name in ("_launch_decision", "_consume_engine_authorization", "create_db"):
        monkeypatch.setattr(
            webforge,
            name,
            lambda *items, _name=name, **kwargs: pytest.fail(
                f"{_name} ran before source_root validation"
            ),
        )

    result = asyncio.run(webforge.run_scan(cfg, args, tmp_path))

    assert result["status"] == "failed"
    assert result["errors"] == ["source_root is required for whitebox mode"]
    assert result["findings"] == 0
    assert not (tmp_path / "webforge.db").exists()


def test_direct_run_scan_rejects_invalid_root_before_dry_run_planning(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = BaseForgeConfig(target="https://example.test", mode="whitebox")
    cfg.extra["source_root"] = str(tmp_path / "missing-root")
    args = Namespace(mode="whitebox", dry_run=True)
    monkeypatch.setattr(
        webforge,
        "dry_run_plan",
        lambda *items, **kwargs: pytest.fail("dry-run planning ran before source_root validation"),
    )

    result = asyncio.run(webforge.run_scan(cfg, args, tmp_path))

    assert result["status"] == "failed"
    assert result["errors"] == ["source_root is unavailable"]
    assert not (tmp_path / "dry_run_plan.json").exists()


def test_direct_run_scan_normalizes_malformed_source_root_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    canaries = {
        "PATHLIKE_RUN_SCAN_CANARY",
        "NUL_RUN_SCAN_CANARY",
        "EXPANDUSER_RUN_SCAN_CANARY",
        "STRIP_RUN_SCAN_CANARY",
    }

    class ExplodingPath:
        def __fspath__(self) -> str:
            raise RuntimeError("PATHLIKE_RUN_SCAN_CANARY")

    class StripTrap(str):
        strip_calls = 0

        def strip(self, *args, **kwargs):
            type(self).strip_calls += 1
            raise RuntimeError("STRIP_RUN_SCAN_CANARY")

    for name in ("_launch_decision", "_consume_engine_authorization", "create_db"):
        monkeypatch.setattr(
            webforge,
            name,
            lambda *items, _name=name, **kwargs: pytest.fail(
                f"{_name} ran before source_root validation"
            ),
        )

    values: list[tuple[object, str]] = [
        (ExplodingPath(), "source_root is unavailable"),
        ("/tmp/approved\x00NUL_RUN_SCAN_CANARY", "source_root is unavailable"),
        ("~EXPANDUSER_RUN_SCAN_CANARY/source", "source_root is unavailable"),
        (StripTrap("/tmp/STRIP_RUN_SCAN_CANARY"), "source_root is required"),
    ]
    for value, expected_error in values:
        cfg = BaseForgeConfig(target="https://example.test", mode="whitebox")
        cfg.extra["source_root"] = value
        args = Namespace(mode="whitebox", dry_run=False)

        result = asyncio.run(webforge.run_scan(cfg, args, tmp_path))

        assert result["status"] == "failed"
        assert result["errors"] == [expected_error]
        assert not any(canary in repr(result) for canary in canaries)
    assert StripTrap.strip_calls == 0


def test_generic_fstat_failure_is_normalized_at_engine_boundaries_before_effects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    approved = tmp_path / "approved"
    approved.mkdir()
    canary = "ENGINE_FSTAT_EXCEPTION_CANARY"
    expected_error = "source_root is unavailable or unsafe"

    for name in (
        "_launch_decision",
        "_consume_engine_authorization",
        "create_db",
        "dry_run_plan",
    ):
        monkeypatch.setattr(
            webforge,
            name,
            lambda *items, _name=name, **kwargs: pytest.fail(
                f"{_name} ran before source_root validation"
            ),
        )

    direct_cfg = BaseForgeConfig(target="https://example.test", mode="whitebox")
    direct_cfg.extra["source_root"] = str(approved)
    direct_args = Namespace(mode="whitebox", dry_run=False)
    run_cfg = BaseForgeConfig(target="https://example.test", mode="whitebox")
    run_cfg.extra["source_root"] = str(approved)
    run_args = Namespace(mode="whitebox", dry_run=False)

    def exploding_fstat(descriptor: int):
        del descriptor
        raise RuntimeError(canary)

    with monkeypatch.context() as scoped:
        scoped.setattr("webforge.core.source_root.os.fstat", exploding_fstat)
        validation_error = webforge._validate_scan_source_root(
            direct_cfg,
            direct_args,
        )
        result = asyncio.run(webforge.run_scan(run_cfg, run_args, tmp_path / "results"))

    assert validation_error == expected_error
    assert direct_cfg.extra["source_root"] == str(approved)
    assert result["status"] == "failed"
    assert result["errors"] == [expected_error]
    assert result["findings"] == 0
    assert canary not in repr(result)
    assert not (tmp_path / "results").exists()


def test_engine_source_root_uses_canonical_argument_and_rejects_mismatch(
    tmp_path: Path,
) -> None:
    approved = tmp_path / "approved"
    conflicting = tmp_path / "conflicting"
    approved.mkdir()
    conflicting.mkdir()
    cfg = BaseForgeConfig(target="https://example.test", mode="whitebox")
    args = Namespace(mode="whitebox", source_root=str(approved))

    assert webforge._validate_scan_source_root(cfg, args) is None
    assert os.fspath(cfg.extra["source_root"]) == str(approved.resolve())

    args.source_root = str(conflicting)
    assert webforge._validate_scan_source_root(cfg, args) == "source_root values do not match"
    assert os.fspath(cfg.extra["source_root"]) == str(approved.resolve())


def test_dependency_inventory_spawns_no_tools_or_network(tmp_path: Path) -> None:
    root = tmp_path / "approved"
    root.mkdir()
    (root / "requirements.txt").write_text("fixture==1.0\n", encoding="utf-8")
    with (
        patch("asyncio.create_subprocess_exec") as spawn,
        patch("socket.create_connection") as network,
    ):
        manifests = inventory_dependency_manifests(canonical_source_root(root))

    assert manifests == 1
    spawn.assert_not_called()
    network.assert_not_called()


def test_outside_root_canary_absent_from_module_logs_reports_and_evidence(
    tmp_path: Path,
    caplog,
) -> None:
    from common.reporter import BaseReporter

    root = tmp_path / "approved"
    outside = tmp_path / "private-location"
    root.mkdir()
    outside.mkdir()
    outside_canary = "OUTSIDE_ROOT_REPORT_CANARY_007"
    outside_file = outside / "secret.py"
    outside_file.write_text(f'password="{outside_canary}"', encoding="utf-8")
    (root / "outside.py").symlink_to(outside_file)
    scanner = _secret_scan(tmp_path, str(root))

    with caplog.at_level("DEBUG"):
        result = asyncio.run(scanner.run())
    report_dir = tmp_path / "ordinary-report"
    BaseReporter(
        findings=[finding.to_dict() for finding in result.findings],
        results_dir=report_dir,
        target="https://example.test",
        formats=["json", "csv"],
    ).generate_all()

    rendered = repr(result) + caplog.text
    rendered += "".join(
        path.read_text(encoding="utf-8", errors="replace")
        for path in report_dir.iterdir()
        if path.is_file()
    )
    evidence_dir = tmp_path / "results" / "evidence"
    if evidence_dir.exists():
        rendered += "".join(
            path.read_text(encoding="utf-8", errors="replace")
            for path in evidence_dir.rglob("*")
            if path.is_file()
        )
    assert outside_canary not in rendered
    assert str(outside_file) not in rendered
