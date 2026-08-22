"""Filesystem-boundary regressions for ordinary report artifacts."""
from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import stat
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any, Callable

import pytest

import common.artifact_io as artifact_io_module
import common.evidence as evidence_module
import common.reporter as reporter_module
import common.reporting.report_engine as report_engine_module
from common.artifact_io import ArtifactBoundaryError
from common.reporter import BaseReporter
from common.reporting.delta_report import build_finding_delta
from common.reporting.report_engine import ReportConfig, ReportEngine


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def _assert_private_regular(path: Path) -> None:
    assert path.is_file()
    assert path.is_symlink() is False
    assert _mode(path) == 0o600


def _empty_delta() -> Any:
    return build_finding_delta(
        [],
        [],
        previous_run="fixture-old",
        current_run="fixture-new",
        current_collection_status="success",
        current_coverage_complete=True,
    )


def _write_boundary_fixture(implementation: str, destination: Path) -> None:
    if implementation == "evidence":
        evidence_module._owner_only_write(destination, "evidence replacement")
    elif implementation == "base":
        reporter_module._write_private_text(destination, "base replacement")
    elif implementation == "engine":
        report_engine_module._write_private_text(destination, "engine replacement")
    elif implementation == "delta":
        _empty_delta().write_json(destination)
    else:  # pragma: no cover - test helper contract
        raise AssertionError(f"unknown implementation: {implementation}")


def test_report_constructors_preserve_existing_dirs_and_create_private_dirs(
    tmp_path: Path,
) -> None:
    base_existing = tmp_path / "base-existing"
    base_existing.mkdir(mode=0o755)
    base_existing.chmod(0o755)
    BaseReporter([], base_existing, formats=["json"])
    assert _mode(base_existing) == 0o755

    engine_existing = tmp_path / "engine-existing"
    engine_existing.mkdir(mode=0o755)
    engine_existing.chmod(0o755)
    ReportEngine([], ReportConfig(output_dir=str(engine_existing), formats=[]))
    assert _mode(engine_existing) == 0o755

    base_new = tmp_path / "base-new" / "nested"
    BaseReporter([], base_new, formats=["json"])
    assert _mode(base_new.parent) == 0o700
    assert _mode(base_new) == 0o700

    engine_new = tmp_path / "engine-new" / "nested"
    ReportEngine([], ReportConfig(output_dir=str(engine_new), formats=[]))
    assert _mode(engine_new.parent) == 0o700
    assert _mode(engine_new) == 0o700


def test_report_writers_reject_symlink_output_directories(tmp_path: Path) -> None:
    real_directory = tmp_path / "real-directory"
    real_directory.mkdir(mode=0o755)
    real_directory.chmod(0o755)

    base_alias = tmp_path / "base-alias"
    base_alias.symlink_to(real_directory, target_is_directory=True)
    with pytest.raises(ValueError, match="report directory must be a real directory"):
        BaseReporter([], base_alias, formats=["json"])

    engine_alias = tmp_path / "engine-alias"
    engine_alias.symlink_to(real_directory, target_is_directory=True)
    with pytest.raises(ValueError, match="report directory must be a real directory"):
        ReportEngine([], ReportConfig(output_dir=str(engine_alias), formats=[]))

    delta_alias = tmp_path / "delta-alias"
    delta_alias.symlink_to(real_directory, target_is_directory=True)
    with pytest.raises(ValueError, match="delta report parent must be a real directory"):
        _empty_delta().write_json(delta_alias / "delta.json")

    assert _mode(real_directory) == 0o755
    assert list(real_directory.iterdir()) == []


def test_base_reporter_json_and_csv_replace_symlinks_without_touching_victims(
    tmp_path: Path,
) -> None:
    output_dir = tmp_path / "caller-owned"
    output_dir.mkdir(mode=0o755)
    output_dir.chmod(0o755)
    reporter = BaseReporter([], output_dir, formats=["json", "csv"])

    json_victim = tmp_path / "json-victim"
    json_victim.write_text("JSON_VICTIM", encoding="utf-8")
    json_victim.chmod(0o644)
    json_path = output_dir / "findings.json"
    json_path.symlink_to(json_victim)

    csv_victim = tmp_path / "csv-victim"
    csv_victim.write_text("CSV_VICTIM", encoding="utf-8")
    csv_victim.chmod(0o644)
    csv_path = output_dir / "findings.csv"
    csv_path.symlink_to(csv_victim)

    assert Path(reporter.generate_json()) == json_path
    assert Path(reporter.generate_csv()) == csv_path

    assert json_victim.read_text(encoding="utf-8") == "JSON_VICTIM"
    assert csv_victim.read_text(encoding="utf-8") == "CSV_VICTIM"
    assert _mode(json_victim) == 0o644
    assert _mode(csv_victim) == 0o644
    _assert_private_regular(json_path)
    _assert_private_regular(csv_path)
    assert _mode(output_dir) == 0o755
    assert list(output_dir.glob(".*.tmp")) == []


@pytest.mark.parametrize("implementation", ["evidence", "base", "engine", "delta"])
def test_artifact_writers_break_hardlinks_without_mutating_aliases(
    tmp_path: Path,
    implementation: str,
) -> None:
    output_dir = tmp_path / f"{implementation}-caller-owned"
    output_dir.mkdir(mode=0o755)
    output_dir.chmod(0o755)
    victim = tmp_path / f"{implementation}-hardlink-victim"
    victim.write_bytes(b"HARDLINK_VICTIM")
    victim.chmod(0o640)
    victim_before = victim.read_bytes()
    destination = output_dir / "artifact.json"
    os.link(victim, destination)

    _write_boundary_fixture(implementation, destination)

    assert destination.stat().st_ino != victim.stat().st_ino
    assert _mode(destination) == 0o600
    assert victim.read_bytes() == victim_before
    assert _mode(victim) == 0o640
    assert _mode(output_dir) == 0o755
    assert list(output_dir.glob(".*.tmp")) == []


@pytest.mark.parametrize("implementation", ["evidence", "base", "engine", "delta"])
def test_artifact_writers_reject_intermediate_directory_symlinks(
    tmp_path: Path,
    implementation: str,
) -> None:
    redirected = tmp_path / f"{implementation}-redirected"
    redirected.mkdir(mode=0o755)
    redirected.chmod(0o755)
    alias = tmp_path / f"{implementation}-alias"
    alias.symlink_to(redirected, target_is_directory=True)
    destination = alias / "nested" / "artifact.json"

    with pytest.raises(ValueError) as denied:
        _write_boundary_fixture(implementation, destination)

    assert "directory" in str(denied.value)
    assert str(tmp_path) not in str(denied.value)
    assert list(redirected.iterdir()) == []
    assert _mode(redirected) == 0o755


@pytest.mark.parametrize("implementation", ["evidence", "base", "engine", "delta"])
def test_artifact_writers_reject_world_writable_destination_namespace(
    tmp_path: Path,
    implementation: str,
) -> None:
    destination_dir = tmp_path / f"{implementation}-unmanaged"
    destination_dir.mkdir(mode=0o700)
    destination_dir.chmod(0o777)
    destination = destination_dir / "artifact.json"

    with pytest.raises(
        ArtifactBoundaryError,
        match="artifact directory must be owner-controlled",
    ):
        _write_boundary_fixture(implementation, destination)

    assert list(destination_dir.iterdir()) == []
    assert _mode(destination_dir) == 0o777


@pytest.mark.parametrize("implementation", ["evidence", "base", "engine", "delta"])
def test_artifact_writers_reject_parent_swap_after_descriptor_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    implementation: str,
) -> None:
    parent = tmp_path / f"{implementation}-parent"
    parent.mkdir(mode=0o755)
    parent.chmod(0o755)
    detached = tmp_path / f"{implementation}-parent-detached"
    redirected = tmp_path / f"{implementation}-redirected"
    redirected.mkdir(mode=0o755)
    redirected.chmod(0o755)
    destination = parent / "artifact.json"
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
        _write_boundary_fixture(implementation, destination)

    assert parent.is_symlink()
    assert list(redirected.iterdir()) == []
    assert list(detached.iterdir()) == []
    assert _mode(redirected) == 0o755


@pytest.mark.parametrize("implementation", ["evidence", "base", "engine", "delta"])
@pytest.mark.parametrize("race_kind", ["ancestor", "hardlink"])
def test_artifact_writers_reject_commit_time_namespace_and_alias_races(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    implementation: str,
    race_kind: str,
) -> None:
    parent = tmp_path / f"{implementation}-{race_kind}-parent"
    parent.mkdir(mode=0o755)
    parent.chmod(0o755)
    destination = parent / "artifact.json"
    detached = tmp_path / f"{implementation}-detached"
    redirected = tmp_path / f"{implementation}-redirected"
    alias = parent / "late-alias.json"
    real_replace = os.replace
    real_link = os.link
    raced = False

    def race_after_replace(
        source: str,
        target: str,
        *,
        src_dir_fd: int,
        dst_dir_fd: int,
    ) -> None:
        nonlocal raced
        real_replace(
            source,
            target,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
        )
        if race_kind == "ancestor":
            redirected.mkdir(mode=0o755)
            parent.rename(detached)
            parent.symlink_to(redirected, target_is_directory=True)
        else:
            real_link(
                target,
                alias.name,
                src_dir_fd=dst_dir_fd,
                dst_dir_fd=dst_dir_fd,
                follow_symlinks=False,
            )
        raced = True

    monkeypatch.setattr(artifact_io_module.os, "replace", race_after_replace)

    with pytest.raises(
        ArtifactBoundaryError,
        match="artifact changed during commit",
    ):
        _write_boundary_fixture(implementation, destination)

    assert raced is True
    if race_kind == "ancestor":
        assert parent.is_symlink()
        assert list(detached.iterdir()) == []
        assert list(redirected.iterdir()) == []
    else:
        assert destination.exists() is False
        assert alias.read_bytes() == b""
        assert alias.stat().st_nlink == 1
        assert list(parent.glob(".*.tmp")) == []


@pytest.mark.parametrize("implementation", ["evidence", "base", "engine", "delta"])
def test_artifact_writers_never_change_process_umask(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    implementation: str,
) -> None:
    destination = tmp_path / implementation / "nested" / "artifact.json"

    def reject_umask(_mode: int) -> int:
        raise AssertionError("artifact writer changed process umask")

    with monkeypatch.context() as scoped:
        scoped.setattr(artifact_io_module.os, "umask", reject_umask)
        _write_boundary_fixture(implementation, destination)

    assert _mode(destination.parent.parent) == 0o700
    assert _mode(destination.parent) == 0o700
    assert _mode(destination) == 0o600


def test_immutable_evidence_rejects_hardlink_object_alias(
    tmp_path: Path,
) -> None:
    payload = b"IMMUTABLE_EVIDENCE_FIXTURE"
    digest = hashlib.sha256(payload).hexdigest()
    evidence_ref = f"sha256:{digest}"
    store = tmp_path / "evidence-store"
    store.mkdir(mode=0o700)
    victim = tmp_path / "immutable-hardlink-victim"
    victim.write_bytes(payload)
    victim.chmod(0o400)
    victim_before = victim.read_bytes()
    object_path = store / f"{digest}.evidence"
    os.link(victim, object_path)

    assert evidence_module.immutable_evidence_exists(evidence_ref, store) is False
    with pytest.raises(
        ValueError,
        match="existing evidence object failed content-address validation",
    ):
        evidence_module.persist_immutable_evidence(payload, store)

    assert object_path.stat().st_ino == victim.stat().st_ino
    assert victim.read_bytes() == victim_before
    assert _mode(victim) == 0o400
    assert not list(store.glob(".forge-evidence-*"))


def test_immutable_evidence_rejects_world_writable_store_namespace(
    tmp_path: Path,
) -> None:
    store = tmp_path / "unmanaged-evidence-store"
    store.mkdir(mode=0o700)
    store.chmod(0o777)

    with pytest.raises(
        ArtifactBoundaryError,
        match="artifact directory must be owner-controlled",
    ):
        evidence_module.persist_immutable_evidence(b"fixture", store)

    assert list(store.iterdir()) == []
    assert _mode(store) == 0o777


def test_immutable_evidence_rejects_store_swap_after_descriptor_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = tmp_path / "evidence-store"
    store.mkdir(mode=0o755)
    store.chmod(0o755)
    detached = tmp_path / "evidence-store-detached"
    redirected = tmp_path / "evidence-store-redirected"
    redirected.mkdir(mode=0o755)
    redirected.chmod(0o755)
    real_write_all = evidence_module._write_all
    swapped = False

    def swap_store_after_write(descriptor: int, payload: bytes) -> None:
        nonlocal swapped
        real_write_all(descriptor, payload)
        if not swapped:
            swapped = True
            store.rename(detached)
            store.symlink_to(redirected, target_is_directory=True)

    monkeypatch.setattr(evidence_module, "_write_all", swap_store_after_write)

    with pytest.raises(
        ArtifactBoundaryError,
        match="artifact directory changed during write",
    ):
        evidence_module.persist_immutable_evidence(b"fixture", store)

    assert store.is_symlink()
    assert list(redirected.iterdir()) == []
    assert list(detached.iterdir()) == []
    assert _mode(redirected) == 0o755


@pytest.mark.parametrize("race_kind", ["ancestor", "hardlink"])
def test_immutable_evidence_rejects_commit_time_namespace_and_alias_races(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    race_kind: str,
) -> None:
    payload = b"IMMUTABLE_COMMIT_RACE_FIXTURE_007"
    digest = hashlib.sha256(payload).hexdigest()
    object_name = f"{digest}.evidence"
    store = tmp_path / "evidence-store"
    store.mkdir(mode=0o700)
    detached = tmp_path / "evidence-store-detached"
    redirected = tmp_path / "evidence-store-redirected"
    alias = tmp_path / "late-evidence-alias"
    real_link = os.link
    raced = False

    def race_after_link(
        source: str,
        target: str,
        *,
        src_dir_fd: int,
        dst_dir_fd: int,
        follow_symlinks: bool = True,
    ) -> None:
        nonlocal raced
        real_link(
            source,
            target,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
            follow_symlinks=follow_symlinks,
        )
        if race_kind == "ancestor":
            redirected.mkdir(mode=0o700)
            store.rename(detached)
            store.symlink_to(redirected, target_is_directory=True)
        else:
            real_link(
                object_name,
                alias,
                src_dir_fd=dst_dir_fd,
                follow_symlinks=False,
            )
        raced = True

    monkeypatch.setattr(evidence_module.os, "link", race_after_link)

    with pytest.raises(
        ArtifactBoundaryError,
        match="immutable evidence changed during commit",
    ):
        evidence_module.persist_immutable_evidence(payload, store)

    assert raced is True
    if race_kind == "ancestor":
        assert store.is_symlink()
        assert list(detached.iterdir()) == []
        assert list(redirected.iterdir()) == []
    else:
        assert (store / object_name).exists() is False
        assert alias.read_bytes() == b""
        assert alias.stat().st_nlink == 1
        assert not list(store.glob(".forge-evidence-*"))


def test_existing_immutable_reference_is_rechecked_after_alias_race(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b"EXISTING_IMMUTABLE_REFERENCE_007"
    evidence_ref = evidence_module.persist_immutable_evidence(payload, tmp_path)
    digest = evidence_ref.removeprefix("sha256:")
    object_path = tmp_path / f"{digest}.evidence"
    alias = tmp_path / "existing-reference-late-alias"
    real_validate = evidence_module._immutable_evidence_exists_at
    raced = False

    def validate_then_alias(
        directory_fd: int,
        object_name: str,
        reference: str,
    ) -> bool:
        nonlocal raced
        result = real_validate(directory_fd, object_name, reference)
        if result and not raced:
            os.link(object_path, alias)
            raced = True
        return result

    monkeypatch.setattr(
        evidence_module,
        "_immutable_evidence_exists_at",
        validate_then_alias,
    )

    with pytest.raises(
        ValueError,
        match="existing evidence object failed content-address validation",
    ):
        evidence_module.persist_immutable_evidence(payload, tmp_path)

    assert raced is True
    assert evidence_module.immutable_evidence_exists(evidence_ref, tmp_path) is False
    assert object_path.stat().st_nlink == 2


def test_existing_immutable_write_wipes_late_temporary_alias_before_return(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b"EXISTING_OBJECT_TEMPORARY_ALIAS_007"
    evidence_ref = evidence_module.persist_immutable_evidence(payload, tmp_path)
    alias = tmp_path / "late-temporary-alias"
    real_link = os.link
    raced = False

    def alias_temporary_when_object_exists(
        source: str,
        target: str,
        *,
        src_dir_fd: int,
        dst_dir_fd: int,
        follow_symlinks: bool = True,
    ) -> None:
        nonlocal raced
        try:
            real_link(
                source,
                target,
                src_dir_fd=src_dir_fd,
                dst_dir_fd=dst_dir_fd,
                follow_symlinks=follow_symlinks,
            )
        except FileExistsError:
            real_link(
                source,
                alias,
                src_dir_fd=src_dir_fd,
                follow_symlinks=False,
            )
            raced = True
            raise

    monkeypatch.setattr(evidence_module.os, "link", alias_temporary_when_object_exists)

    assert evidence_module.persist_immutable_evidence(payload, tmp_path) == evidence_ref
    assert raced is True
    assert alias.read_bytes() == b""
    assert alias.stat().st_nlink == 1
    assert not list(tmp_path.glob(".forge-evidence-*"))
    assert evidence_module.immutable_evidence_exists(evidence_ref, tmp_path) is True


def test_report_engine_json_replaces_symlink_without_touching_victim(
    tmp_path: Path,
) -> None:
    output_dir = tmp_path / "caller-owned"
    output_dir.mkdir(mode=0o755)
    output_dir.chmod(0o755)
    victim = tmp_path / "engine-json-victim"
    victim.write_text("ENGINE_JSON_VICTIM", encoding="utf-8")
    victim.chmod(0o644)
    destination = output_dir / "report.json"
    destination.symlink_to(victim)

    engine = ReportEngine(
        [],
        ReportConfig(
            output_dir=str(output_dir),
            formats=["json"],
            include_exec_summary=False,
            include_compliance=False,
        ),
    )
    paths = asyncio.run(engine.generate())

    assert Path(paths["json"]) == destination
    assert victim.read_text(encoding="utf-8") == "ENGINE_JSON_VICTIM"
    assert _mode(victim) == 0o644
    _assert_private_regular(destination)
    assert _mode(output_dir) == 0o755
    assert list(output_dir.glob(".*.tmp")) == []


def test_report_engine_pdf_stages_bytes_before_atomic_symlink_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_dir = tmp_path / "caller-owned"
    output_dir.mkdir(mode=0o755)
    output_dir.chmod(0o755)
    html_path = output_dir / "report.html"
    html_path.write_text("<html>fixture</html>", encoding="utf-8")

    victim = tmp_path / "pdf-victim"
    victim.write_bytes(b"PDF_VICTIM")
    victim.chmod(0o644)
    destination = output_dir / "report.pdf"
    destination.symlink_to(victim)

    class FakeHTML:
        def __init__(self, *, string: str) -> None:
            assert string == "<html>fixture</html>"

        def write_pdf(
            self,
            target: Any,
            *,
            stylesheets: list[Any],
        ) -> None:
            assert stylesheets
            target.write(b"%PDF-1.7\nFIXTURE\n")

    class FakeCSS:
        def __init__(self, *, string: str) -> None:
            assert string

    fake_weasyprint = SimpleNamespace(HTML=FakeHTML, CSS=FakeCSS)
    monkeypatch.setattr(
        report_engine_module.importlib,
        "import_module",
        lambda name: fake_weasyprint if name == "weasyprint" else None,
    )

    engine = ReportEngine([], ReportConfig(output_dir=str(output_dir), formats=[]))
    assert engine._generate_pdf(str(html_path)) == str(destination)

    assert victim.read_bytes() == b"PDF_VICTIM"
    assert _mode(victim) == 0o644
    _assert_private_regular(destination)
    assert destination.read_bytes() == b"%PDF-1.7\nFIXTURE\n"
    assert _mode(output_dir) == 0o755
    assert list(output_dir.glob(".*.tmp")) == []


@pytest.mark.parametrize("alias_kind", ["symlink", "hardlink"])
def test_evidence_previews_and_copy_reject_aliased_source_files(
    tmp_path: Path,
    alias_kind: str,
) -> None:
    victim = tmp_path / "protected-original.bin"
    victim.write_bytes(b"OUTSIDE_EVIDENCE_CANARY_007")
    victim.chmod(0o600)

    screenshot = tmp_path / "shot.png"
    console = tmp_path / "console.html"
    pcap = tmp_path / "capture.pcap"
    for alias in (screenshot, console, pcap):
        if alias_kind == "symlink":
            alias.symlink_to(victim)
        else:
            os.link(victim, alias)

    evidence = evidence_module.Evidence(
        screenshot_path=str(screenshot),
        console_capture_path=str(console),
        pcap_path=str(pcap),
    )
    assert evidence.screenshot_as_base64() is None
    assert evidence.console_capture_as_html() is None
    assert evidence.has_screenshot() is False

    copied = evidence.copy_to(tmp_path / "copied")
    assert copied.screenshot_path is None
    assert copied.console_capture_path is None
    assert copied.pcap_path is None
    assert list((tmp_path / "copied").iterdir()) == []
    assert victim.read_bytes() == b"OUTSIDE_EVIDENCE_CANARY_007"


def test_evidence_read_rejects_intermediate_directory_symlink(
    tmp_path: Path,
) -> None:
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    victim = real_parent / "shot.png"
    victim.write_bytes(b"INTERMEDIATE_EVIDENCE_CANARY_007")
    alias_parent = tmp_path / "alias-parent"
    alias_parent.symlink_to(real_parent, target_is_directory=True)

    evidence = evidence_module.Evidence(
        screenshot_path=str(alias_parent / "shot.png")
    )
    assert evidence.screenshot_as_base64() is None
    copied = evidence.copy_to(tmp_path / "copied")
    assert copied.screenshot_path is None
    assert list((tmp_path / "copied").iterdir()) == []


def test_evidence_read_rejects_leaf_swap_before_consuming_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "shot.png"
    source.write_bytes(b"EXPECTED_SCREENSHOT")
    victim = tmp_path / "outside.bin"
    victim.write_bytes(b"SWAPPED_EVIDENCE_CANARY_007")
    real_open = artifact_io_module.os.open
    swapped = False

    def swap_after_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        nonlocal swapped
        descriptor = real_open(path, flags, *args, **kwargs)
        if path == source.name and kwargs.get("dir_fd") is not None and not swapped:
            swapped = True
            source.unlink()
            source.symlink_to(victim)
        return descriptor

    monkeypatch.setattr(artifact_io_module.os, "open", swap_after_open)
    evidence = evidence_module.Evidence(screenshot_path=str(source))
    assert evidence.screenshot_as_base64() is None
    assert victim.read_bytes() == b"SWAPPED_EVIDENCE_CANARY_007"


def test_evidence_read_discards_bytes_after_late_hardlink_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "shot.png"
    original = b"ORIGINAL_EVIDENCE_BYTES_007"
    injected = b"INJECTED_EVIDENCE_BYTES_007"
    assert len(original) == len(injected)
    source.write_bytes(original)
    source.chmod(0o600)
    outside_alias = tmp_path / "late-outside-alias.png"
    real_read = artifact_io_module.os.read
    raced = False

    def add_alias_and_mutate(descriptor: int, count: int) -> bytes:
        nonlocal raced
        if not raced:
            raced = True
            os.link(source, outside_alias)
            write_descriptor = os.open(outside_alias, os.O_WRONLY | os.O_TRUNC)
            try:
                os.write(write_descriptor, injected)
            finally:
                os.close(write_descriptor)
        return real_read(descriptor, count)

    monkeypatch.setattr(artifact_io_module.os, "read", add_alias_and_mutate)
    evidence = evidence_module.Evidence(screenshot_path=str(source))

    assert evidence.screenshot_as_base64() is None
    assert evidence.has_screenshot() is False
    copied = evidence.copy_to(tmp_path / "copied")
    assert copied.screenshot_path is None
    assert list((tmp_path / "copied").iterdir()) == []
    assert raced is True
    assert source.read_bytes() == injected
    assert source.stat().st_nlink == 2


def test_evidence_read_rejects_parent_swap_before_consuming_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / "evidence-parent"
    parent.mkdir()
    source = parent / "shot.png"
    source.write_bytes(b"EXPECTED_SCREENSHOT")
    detached = tmp_path / "detached-parent"
    redirected = tmp_path / "redirected-parent"
    redirected.mkdir()
    (redirected / "shot.png").write_bytes(b"PARENT_SWAP_CANARY_007")
    real_matches = artifact_io_module.directory_descriptor_matches
    swapped = False

    def swap_before_comparison(descriptor: int, directory: Any) -> bool:
        nonlocal swapped
        if Path(directory) == parent and not swapped:
            swapped = True
            parent.rename(detached)
            parent.symlink_to(redirected, target_is_directory=True)
        return real_matches(descriptor, directory)

    monkeypatch.setattr(
        artifact_io_module,
        "directory_descriptor_matches",
        swap_before_comparison,
    )
    evidence = evidence_module.Evidence(screenshot_path=str(source))
    assert evidence.screenshot_as_base64() is None
    assert (redirected / "shot.png").read_bytes() == b"PARENT_SWAP_CANARY_007"


@pytest.mark.parametrize("alias_kind", ["symlink", "hardlink"])
def test_report_engine_pdf_rejects_aliased_html_source_without_rendering(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    alias_kind: str,
) -> None:
    output_dir = tmp_path / "report"
    output_dir.mkdir()
    victim = tmp_path / "outside.html"
    victim.write_text("<html>OUTSIDE_PDF_CANARY_007</html>", encoding="utf-8")
    html_path = output_dir / "report.html"
    if alias_kind == "symlink":
        html_path.symlink_to(victim)
    else:
        os.link(victim, html_path)
    rendered = False

    class RejectHTML:
        def __init__(self, *, string: str) -> None:
            nonlocal rendered
            rendered = True

    fake_weasyprint = SimpleNamespace(HTML=RejectHTML, CSS=object)
    monkeypatch.setattr(
        report_engine_module.importlib,
        "import_module",
        lambda name: fake_weasyprint if name == "weasyprint" else None,
    )

    engine = ReportEngine([], ReportConfig(output_dir=str(output_dir), formats=[]))
    assert engine._generate_pdf(str(html_path)) is None
    assert rendered is False
    assert not (output_dir / "report.pdf").exists()
    assert victim.read_text(encoding="utf-8") == (
        "<html>OUTSIDE_PDF_CANARY_007</html>"
    )


def test_base_reporter_pdf_replaces_aliased_html_before_rendering(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_dir = tmp_path / "base-report"
    reporter = BaseReporter([], output_dir, formats=[])
    victim = tmp_path / "outside-base.html"
    victim.write_text("<html>BASE_PDF_CANARY_007</html>", encoding="utf-8")
    html_path = output_dir / "report.html"
    html_path.symlink_to(victim)
    rendered: list[str] = []

    def disable_professional(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("professional engine disabled for fixture")

    class FakeHTML:
        def __init__(self, *, string: str) -> None:
            rendered.append(string)

        def write_pdf(self, target: Any) -> None:
            target.write(b"%PDF-1.7\nBASE\n")

    fake_weasyprint = ModuleType("weasyprint")
    fake_weasyprint.HTML = FakeHTML  # type: ignore[attr-defined]
    monkeypatch.setattr(reporter, "_professional_report_config", disable_professional)
    monkeypatch.setitem(sys.modules, "weasyprint", fake_weasyprint)

    assert reporter.generate_pdf() == str(output_dir / "report.pdf")
    assert rendered and "BASE_PDF_CANARY_007" not in rendered[0]
    assert html_path.is_symlink() is False
    assert victim.read_text(encoding="utf-8") == (
        "<html>BASE_PDF_CANARY_007</html>"
    )
    _assert_private_regular(output_dir / "report.pdf")


@pytest.mark.parametrize("implementation", ["base", "engine", "delta"])
@pytest.mark.parametrize("failure_point", ["setup", "write"])
def test_report_write_failures_preserve_prior_output_and_clean_temporaries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    implementation: str,
    failure_point: str,
) -> None:
    output_dir = tmp_path / f"{implementation}-{failure_point}"
    output_dir.mkdir(mode=0o755)
    output_dir.chmod(0o755)
    destination = output_dir / "artifact.json"
    destination.write_bytes(b"PRIOR_COMPLETE_REPORT")
    destination.chmod(0o644)

    write: Callable[[], None]
    if implementation == "base":
        write = lambda: reporter_module._write_private_text(destination, "replacement")
    elif implementation == "engine":
        write = lambda: report_engine_module._write_private_text(destination, "replacement")
    else:
        write = lambda: _empty_delta().write_json(destination)

    if failure_point == "setup":
        def fail_setup(_descriptor: int, _mode: int) -> None:
            raise OSError("fixture setup failure")

        monkeypatch.setattr(artifact_io_module.os, "fchmod", fail_setup)
    else:
        real_write = os.write

        def fail_after_partial_write(descriptor: int, data: Any) -> int:
            real_write(descriptor, bytes(data[:1]))
            raise OSError("fixture write failure")

        monkeypatch.setattr(artifact_io_module.os, "write", fail_after_partial_write)

    with pytest.raises(ArtifactBoundaryError, match="artifact write failed") as denied:
        write()

    assert "fixture" not in str(denied.value)
    assert destination.read_bytes() == b"PRIOR_COMPLETE_REPORT"
    assert _mode(destination) == 0o644
    assert _mode(output_dir) == 0o755
    assert list(output_dir.glob(f".{destination.name}.*.tmp")) == []


def test_failed_artifact_write_wipes_temporary_when_unlink_is_denied(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_dir = tmp_path / "unlink-denied"
    output_dir.mkdir(mode=0o755)
    output_dir.chmod(0o755)
    destination = output_dir / "artifact.json"
    destination.write_bytes(b"PRIOR_COMPLETE_REPORT")
    destination.chmod(0o644)
    real_write = os.write
    real_unlink = os.unlink

    def fail_after_partial_write(descriptor: int, data: Any) -> int:
        real_write(descriptor, bytes(data[:4]))
        raise OSError("CANARY_PARTIAL_ARTIFACT_007")

    def deny_temporary_unlink(
        path: os.PathLike[str] | str,
        *,
        dir_fd: int | None = None,
    ) -> None:
        if Path(path).name.startswith(f".{destination.name}."):
            raise PermissionError("CANARY_UNLINK_DENIED_007")
        real_unlink(path, dir_fd=dir_fd)

    with monkeypatch.context() as scoped:
        scoped.setattr(artifact_io_module.os, "write", fail_after_partial_write)
        scoped.setattr(artifact_io_module.os, "unlink", deny_temporary_unlink)
        with pytest.raises(
            ArtifactBoundaryError,
            match="artifact write failed",
        ) as denied:
            reporter_module._write_private_text(destination, "replacement")

    leftovers = list(output_dir.glob(f".{destination.name}.*.tmp"))
    assert "CANARY" not in str(denied.value)
    assert destination.read_bytes() == b"PRIOR_COMPLETE_REPORT"
    assert _mode(destination) == 0o644
    assert len(leftovers) == 1
    assert leftovers[0].read_bytes() == b""
    assert _mode(leftovers[0]) == 0o600
    leftovers[0].unlink()


def test_delta_report_rejects_post_replace_leaf_swap_without_touching_victim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_dir = tmp_path / "caller-owned"
    output_dir.mkdir(mode=0o755)
    output_dir.chmod(0o755)
    report = _empty_delta()

    victim = tmp_path / "delta-victim"
    victim.write_text("DELTA_VICTIM", encoding="utf-8")
    victim.chmod(0o644)
    destination = output_dir / "delta.json"
    destination.symlink_to(victim)
    report.write_json(destination)

    assert victim.read_text(encoding="utf-8") == "DELTA_VICTIM"
    assert _mode(victim) == 0o644
    _assert_private_regular(destination)
    assert _mode(output_dir) == 0o755

    post_replace_victim = tmp_path / "post-replace-victim"
    post_replace_victim.write_text("POST_REPLACE_VICTIM", encoding="utf-8")
    post_replace_victim.chmod(0o644)
    real_replace = os.replace

    def swap_destination_after_replace(
        source: str,
        target: str,
        *,
        src_dir_fd: int,
        dst_dir_fd: int,
    ) -> None:
        real_replace(
            source,
            target,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
        )
        destination.unlink()
        destination.symlink_to(post_replace_victim)

    monkeypatch.setattr(artifact_io_module.os, "replace", swap_destination_after_replace)
    with pytest.raises(
        ArtifactBoundaryError,
        match="artifact changed during commit",
    ):
        report.write_json(destination)

    assert destination.is_symlink()
    assert post_replace_victim.read_text(encoding="utf-8") == "POST_REPLACE_VICTIM"
    assert _mode(post_replace_victim) == 0o644
    assert _mode(output_dir) == 0o755
    assert list(output_dir.glob(".*.tmp")) == []


def test_report_exception_logs_never_disclose_secret_canaries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    canary = "CANARY_REPORT_EXCEPTION_SECRET_007"

    def fail_with_canary(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError(canary)

    caplog.set_level(logging.DEBUG)
    base = BaseReporter([], tmp_path / "base", formats=["json"])

    from common.reporting.compliance_engine import ComplianceEngine

    with monkeypatch.context() as scoped:
        scoped.setattr(base, "generate_json", fail_with_canary)
        scoped.setattr(
            ComplianceEngine,
            "evaluate_all",
            staticmethod(fail_with_canary),
        )
        base.generate_all()

    with monkeypatch.context() as scoped:
        scoped.setattr(base, "_professional_report_config", fail_with_canary)
        base.generate_html()

    class FailingBasePDF:
        def __init__(self, *, string: str) -> None:
            assert "<html" in string

        def write_pdf(self, _target: Any) -> None:
            raise RuntimeError(canary)

    fake_base_pdf = ModuleType("weasyprint")
    fake_base_pdf.HTML = FailingBasePDF  # type: ignore[attr-defined]
    with monkeypatch.context() as scoped:
        scoped.setattr(base, "_professional_report_config", fail_with_canary)
        scoped.setitem(sys.modules, "weasyprint", fake_base_pdf)
        assert base.generate_pdf() is None

    engine = ReportEngine(
        [],
        ReportConfig(
            output_dir=str(tmp_path / "engine"),
            formats=[],
            include_exec_summary=False,
            include_compliance=True,
        ),
    )
    with monkeypatch.context() as scoped:
        scoped.setattr(
            ComplianceEngine,
            "evaluate_all",
            staticmethod(fail_with_canary),
        )
        asyncio.run(engine.generate())

    import jinja2

    with monkeypatch.context() as scoped:
        scoped.setattr(jinja2.Environment, "from_string", fail_with_canary)
        engine.config.formats = ["html"]
        engine.config.include_compliance = False
        asyncio.run(engine.generate())

    html_path = engine.output_dir / "report.html"
    html_path.write_text("<html>fixture</html>", encoding="utf-8")

    class FailingEnginePDF:
        def __init__(self, *, string: str) -> None:
            assert string == "<html>fixture</html>"

        def write_pdf(self, _target: Any, *, stylesheets: list[Any]) -> None:
            assert stylesheets
            raise RuntimeError(canary)

    class FakeCSS:
        def __init__(self, *, string: str) -> None:
            assert string

    fake_engine_pdf = SimpleNamespace(HTML=FailingEnginePDF, CSS=FakeCSS)
    with monkeypatch.context() as scoped:
        scoped.setattr(
            report_engine_module.importlib,
            "import_module",
            lambda name: fake_engine_pdf if name == "weasyprint" else None,
        )
        assert engine._generate_pdf(str(html_path)) is None

    import common.brain.narrator as narrator_module

    with monkeypatch.context() as scoped:
        scoped.setattr(narrator_module, "ReportNarrator", fail_with_canary)
        asyncio.run(engine._generate_exec_summary())

    rendered = "\n".join(
        record.getMessage()
        for record in caplog.records
        if record.name in {"common.reporter", "forge.reporting.engine"}
    )
    assert canary not in rendered
    assert "Report generation failed for a configured format" in rendered
    assert "Compliance report generation failed" in rendered
    assert "Professional report engine unavailable; using fallback HTML" in rendered
    assert "Professional PDF generation unavailable; using fallback" in rendered
    assert "PDF generation failed" in rendered
    assert "Compliance evaluation failed" in rendered
    assert "HTML template render failed" in rendered
    assert "ForgeBrain narrator unavailable" in rendered


@pytest.mark.parametrize("alias_kind", ["direct", "symlink", "hardlink"])
def test_report_engine_never_embeds_caller_supplied_binary_logo(
    tmp_path: Path,
    alias_kind: str,
) -> None:
    canary = b"OPAQUE_REPORT_LOGO_SECRET_007_X9pQ"
    victim = tmp_path / "protected-original.bin"
    victim.write_bytes(canary)
    victim.chmod(0o600)
    logo = victim
    if alias_kind == "symlink":
        logo = tmp_path / "logo.png"
        logo.symlink_to(victim)
    elif alias_kind == "hardlink":
        logo = tmp_path / "logo.png"
        os.link(victim, logo)

    engine = ReportEngine(
        [],
        ReportConfig(
            output_dir=str(tmp_path / "report"),
            formats=["html"],
            include_exec_summary=False,
            include_compliance=False,
            logo_path=str(logo),
        ),
    )
    paths = asyncio.run(engine.generate())

    assert engine._load_logo() is None
    html = Path(paths["html"]).read_text(encoding="utf-8")
    assert canary.decode("ascii") not in html
    assert "T1BBUVVFX1JFUE9SVF9MT0dPX1NFQ1JFVF8wMDdfWDlwUQ==" not in html
    assert victim.read_bytes() == canary
