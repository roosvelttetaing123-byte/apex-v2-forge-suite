"""Regression coverage for the Task 008 failed supply-review remediations."""

from __future__ import annotations

import asyncio
import base64
import io
import os
import stat
import subprocess
import warnings
import zipfile
from pathlib import Path
from typing import Any, Awaitable, Callable
from unittest.mock import AsyncMock

import pytest
from defusedxml.common import DefusedXmlException

from adforge.modules.enum import gpp_password
from common.dashboard import credential_analysis
from forge_c2.tasks.task_browser_creds import ChromiumExtractor
from forge_c2.tasks import task_download_exec
from netforge.modules.bruteforce import wordlist_mgr
from netforge.modules.post_exploit import lateral_ssh, mimikatz_exec, sam_dump
from scripts import verify_supply_chain


ROOT = Path(__file__).resolve().parents[1]


def _seed_supply_inventory_context(root: Path) -> None:
    for relative in verify_supply_chain._DOCKER_CONTEXT_ROOT_FILES:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"fixture for {relative}\n", encoding="utf-8")
    for relative in verify_supply_chain._DOCKER_CONTEXT_ROOT_DIRECTORIES:
        (root / relative).mkdir(parents=True, exist_ok=True)
    for relative in verify_supply_chain._DOCKER_CONTEXT_CONTROL_FILES:
        (root / relative).write_bytes((ROOT / relative).read_bytes())


def _seed_secret_inventory_context(root: Path) -> None:
    _seed_supply_inventory_context(root)
    for relative in verify_supply_chain._CANDIDATE_ROOT_FILES:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_text(f"fixture for {relative}\n", encoding="utf-8")
    for relative in verify_supply_chain._CANDIDATE_ROOT_DIRECTORIES:
        (root / relative).mkdir(parents=True, exist_ok=True)


def _create_linked_worktree(tmp_path: Path) -> tuple[Path, Path]:
    common = tmp_path / "common-repository"
    linked = tmp_path / "linked-candidate"
    subprocess.run(["git", "init", "-q", str(common)], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(common),
            "-c",
            "user.name=Forge Fixture",
            "-c",
            "user.email=forge-fixture@example.invalid",
            "-c",
            "commit.gpgSign=false",
            "commit",
            "--allow-empty",
            "-qm",
            "linked-worktree fixture",
        ],
        check=True,
    )
    subprocess.run(
        [
            "git",
            "-C",
            str(common),
            "worktree",
            "add",
            "--detach",
            "-q",
            str(linked),
            "HEAD",
        ],
        check=True,
    )
    return common, linked


def _linked_admin_path(root: Path) -> Path:
    marker = (root / ".git").read_text(encoding="utf-8")
    assert marker.startswith("gitdir: ") and marker.endswith("\n")
    return Path(marker.removeprefix("gitdir: ").removesuffix("\n"))


def test_supply_inventory_includes_gitignored_docker_shipped_text(tmp_path: Path) -> None:
    _seed_supply_inventory_context(tmp_path)
    ignored_runtime_asset = tmp_path / "common/dashboard/web/static/js/credentials.js"
    ignored_runtime_asset.parent.mkdir(parents=True)
    ignored_runtime_asset.write_text(
        "const fixture = 'AKIAIOSFODNN7EXAMPLE';\n",
        encoding="utf-8",
    )
    (tmp_path / ".gitignore").write_text("credentials.*\n**\n", encoding="utf-8")

    before = verify_supply_chain.docker_shipped_text_paths(tmp_path)
    (tmp_path / ".gitignore").write_text("**\n", encoding="utf-8")
    after = verify_supply_chain.docker_shipped_text_paths(tmp_path)

    relative = "common/dashboard/web/static/js/credentials.js"
    assert before == after
    assert relative in after
    report = verify_supply_chain.scan_secrets(tmp_path, (relative,))
    assert report["results"][relative]


@pytest.mark.parametrize(
    "extra_pattern",
    (
        "**/*.js",
        "!engagements/**",
        "!tmp/**",
    ),
)
def test_supply_inventory_rejects_broad_dockerignore_drift(
    tmp_path: Path,
    extra_pattern: str,
) -> None:
    _seed_supply_inventory_context(tmp_path)
    dockerignore = tmp_path / ".dockerignore"
    dockerignore.write_text(
        dockerignore.read_text(encoding="utf-8") + extra_pattern + "\n",
        encoding="utf-8",
    )

    with pytest.raises(
        verify_supply_chain.SupplyChainError,
        match="exact fail-closed build-context allowlist",
    ):
        verify_supply_chain.docker_shipped_text_paths(tmp_path)


def test_supply_inventory_rejects_symlinks_in_shipped_source(tmp_path: Path) -> None:
    _seed_supply_inventory_context(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("not part of the context\n", encoding="utf-8")
    (tmp_path / "common/linked-secret.txt").symlink_to(outside)

    with pytest.raises(verify_supply_chain.SupplyChainError, match="must not be a symlink"):
        verify_supply_chain.docker_shipped_text_paths(tmp_path)


def test_supply_inventory_rejects_unreviewed_binary_in_shipped_source(tmp_path: Path) -> None:
    _seed_supply_inventory_context(tmp_path)
    (tmp_path / "common/hidden-utf16-secret.txt").write_bytes(
        "secret = fixture-value\n".encode("utf-16")
    )

    with pytest.raises(verify_supply_chain.SupplyChainError, match="unreviewed binary file"):
        verify_supply_chain.docker_shipped_text_paths(tmp_path)


def test_supply_inventory_rejects_unclassified_top_level_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "unreviewed-secret.txt").write_text("fixture\n", encoding="utf-8")

    with pytest.raises(
        verify_supply_chain.SupplyChainError,
        match="unclassified top-level candidate paths",
    ):
        verify_supply_chain._validate_top_level_classification(tmp_path)

    malformed_root = tmp_path / "malformed"
    malformed_root.mkdir()
    (malformed_root / ".git").write_text("not a git marker\n", encoding="utf-8")
    with pytest.raises(verify_supply_chain.SupplyChainError, match="record syntax"):
        verify_supply_chain._validate_top_level_classification(malformed_root)
    (malformed_root / ".git").write_bytes(b"gitdir: /tmp/unsafe\tpath\n")
    with pytest.raises(verify_supply_chain.SupplyChainError, match="unsafe path"):
        verify_supply_chain._validate_top_level_classification(malformed_root)

    symlink_root = tmp_path / "symlink-marker"
    symlink_root.mkdir()
    (symlink_root / "marker-target").write_text("fixture\n", encoding="utf-8")
    (symlink_root / ".git").symlink_to(symlink_root / "marker-target")
    with pytest.raises(verify_supply_chain.SupplyChainError, match="must not be a symlink"):
        verify_supply_chain._validate_top_level_classification(symlink_root)

    common, linked = _create_linked_worktree(tmp_path / "valid")
    verify_supply_chain._validate_top_level_classification(common)
    verify_supply_chain._validate_top_level_classification(linked)
    admin = _linked_admin_path(linked)

    forged_root = tmp_path / "forged-root"
    forged_root.mkdir()
    (forged_root / ".git").write_bytes((linked / ".git").read_bytes())
    with pytest.raises(verify_supply_chain.SupplyChainError, match="backlink"):
        verify_supply_chain._validate_top_level_classification(forged_root)

    topology_root = tmp_path / "forged-topology"
    topology_root.mkdir()
    fake_admin = common / ".git" / "forged-admin"
    fake_admin.mkdir()
    (fake_admin / "commondir").write_text("..\n", encoding="utf-8")
    (fake_admin / "gitdir").write_text(
        f"{topology_root / '.git'}\n",
        encoding="utf-8",
    )
    (topology_root / ".git").write_text(f"gitdir: {fake_admin}\n", encoding="utf-8")
    with pytest.raises(verify_supply_chain.SupplyChainError, match="topology"):
        verify_supply_chain._validate_top_level_classification(topology_root)

    backlink = admin / "gitdir"
    backlink_content = backlink.read_bytes()
    backlink.write_text(f"{common / '.git'}\n", encoding="utf-8")
    with pytest.raises(verify_supply_chain.SupplyChainError, match="backlink"):
        verify_supply_chain._validate_top_level_classification(linked)
    backlink.write_bytes(backlink_content)

    commondir = admin / "commondir"
    commondir_content = commondir.read_bytes()
    commondir.write_text("..\n", encoding="utf-8")
    with pytest.raises(verify_supply_chain.SupplyChainError, match="administrative parent"):
        verify_supply_chain._validate_top_level_classification(linked)
    commondir.write_bytes(commondir_content)

    hostile = tmp_path / "hostile-git-selection"
    hostile.mkdir()
    monkeypatch.setenv("GIT_DIR", str(common / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(hostile))
    monkeypatch.setenv("GIT_COMMON_DIR", str(hostile))
    monkeypatch.setenv("GIT_INDEX_FILE", str(hostile / "index"))
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.bare")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "true")
    captured_environments: list[dict[str, str]] = []
    captured_commands: list[tuple[str, ...]] = []
    real_run = subprocess.run

    def inspecting_run(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        captured_environments.append(kwargs["env"])
        captured_commands.append(tuple(args[0]))
        return real_run(*args, **kwargs)

    monkeypatch.setattr(verify_supply_chain.subprocess, "run", inspecting_run)
    verify_supply_chain._validate_top_level_classification(linked)
    assert verify_supply_chain._tracked_local_private_paths(common) == ()
    assert verify_supply_chain._tracked_local_private_paths(linked) == ()
    assert captured_environments
    assert all(
        not any(key.upper().startswith("GIT_") for key in environment)
        for environment in captured_environments
    )
    assert any(
        "--is-inside-work-tree" in command and "--is-bare-repository" in command
        for command in captured_commands
    )
    assert any("ls-files" in command for command in captured_commands)

    marker = linked / ".git"

    def drifting_run(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        completed = real_run(*args, **kwargs)
        replacement = marker.with_name(".git.replacement")
        replacement.write_bytes(marker.read_bytes())
        os.replace(replacement, marker)
        return completed

    monkeypatch.setattr(verify_supply_chain.subprocess, "run", drifting_run)
    with pytest.raises(verify_supply_chain.SupplyChainError, match="changed during Git validation"):
        verify_supply_chain._validate_top_level_classification(linked)

    def inventory_drifting_run(
        *args: Any,
        **kwargs: Any,
    ) -> subprocess.CompletedProcess[bytes]:
        completed = real_run(*args, **kwargs)
        if "ls-files" in args[0]:
            replacement = marker.with_name(".git.replacement")
            replacement.write_bytes(marker.read_bytes())
            os.replace(replacement, marker)
        return completed

    monkeypatch.setattr(verify_supply_chain.subprocess, "run", inventory_drifting_run)
    with pytest.raises(verify_supply_chain.SupplyChainError, match="changed during Git validation"):
        verify_supply_chain._tracked_local_private_paths(linked)

    replacement_root = linked.with_name("linked-candidate-prelinked-replacement")
    replacement_root.mkdir()
    os.link(linked / ".git", replacement_root / ".git")
    (replacement_root / "unreviewed-secret.txt").write_text("fixture\n", encoding="utf-8")
    original_root = linked.with_name("linked-candidate-original")
    rejected_root = linked.with_name("linked-candidate-rejected-replacement")
    marker_identity = (linked / ".git").stat().st_dev, (linked / ".git").stat().st_ino
    replacement_marker_identity = (
        (replacement_root / ".git").stat().st_dev,
        (replacement_root / ".git").stat().st_ino,
    )
    assert marker_identity == replacement_marker_identity

    def replacing_root_run(
        *args: Any,
        **kwargs: Any,
    ) -> subprocess.CompletedProcess[bytes]:
        completed = real_run(*args, **kwargs)
        if "--is-inside-work-tree" in args[0]:
            linked.rename(original_root)
            replacement_root.rename(linked)
        return completed

    monkeypatch.setattr(verify_supply_chain.subprocess, "run", replacing_root_run)
    try:
        with pytest.raises(
            verify_supply_chain.SupplyChainError,
            match="candidate root changed during Git validation",
        ):
            verify_supply_chain._validate_top_level_classification(linked)
        assert (linked / "unreviewed-secret.txt").is_file()
    finally:
        if linked.exists() and original_root.exists():
            linked.rename(rejected_root)
            original_root.rename(linked)


def test_supply_inventory_classifies_runtime_database_sidecars(tmp_path: Path) -> None:
    for name in (
        "engagement.db-journal",
        "engagement.db-shm",
        "engagement.db-wal",
        "scan_jobs.db-journal",
        "scan_jobs.db-shm",
        "scan_jobs.db-wal",
    ):
        (tmp_path / name).write_bytes(b"runtime fixture")

    verify_supply_chain._validate_top_level_classification(tmp_path)


def test_supply_inventory_covers_exact_production_docker_text_surface() -> None:
    shipped = verify_supply_chain.docker_shipped_text_paths(ROOT)
    candidate = verify_supply_chain.secret_scan_paths(ROOT)

    assert shipped == tuple(sorted(set(shipped)))
    assert candidate == tuple(sorted(set(candidate)))
    assert set(shipped).issubset(candidate)
    assert "common/dashboard/web/static/js/credentials.js" in shipped
    assert ".env.example" not in shipped
    assert ".env.example" in candidate
    for forbidden in (
        "scan_history.json",
        "engagement.db",
        "common/intel/forge_intel.db",
        "webforge/engagement.db",
    ):
        assert forbidden not in shipped
    assert not any("/__pycache__/" in path or "/results/" in path for path in shipped)


def test_supply_inventory_excludes_machine_local_credentials() -> None:
    shipped = verify_supply_chain.docker_shipped_text_paths(ROOT)
    candidate = verify_supply_chain.secret_scan_paths(ROOT)

    for private_path in (
        "apex-ui/.env.development",
        "common/dashboard/.tls/forge_cert.pem",
        "common/dashboard/.tls/forge_key.pem",
    ):
        assert private_path not in shipped
        assert private_path not in candidate


@pytest.mark.parametrize(
    "relative",
    (
        "common/committed.key",
        "common/dashboard/.tls/committed.pem",
        "apex-ui/.env.development",
    ),
)
def test_supply_inventory_scans_force_tracked_private_paths(
    relative: str,
    tmp_path: Path,
) -> None:
    normal, linked = _create_linked_worktree(tmp_path)
    for candidate_root in (normal, linked):
        _seed_secret_inventory_context(candidate_root)
        private_path = candidate_root / relative
        private_path.parent.mkdir(parents=True, exist_ok=True)
        fixture_value = "AKIA" + "IOSFODNN7EXAMPLE"
        field_name = "aws_" + "access_key_id"
        private_path.write_text(
            f'{field_name} = "{fixture_value}"\n',
            encoding="utf-8",
        )
        untracked = candidate_root / "common/untracked.key"
        untracked_label = "se" + "cret"
        untracked.write_text(
            f'{untracked_label} = "machine-local"\n',
            encoding="utf-8",
        )

        subprocess.run(
            ["git", "-C", str(candidate_root), "add", "-f", "--", relative],
            check=True,
        )

        candidate = verify_supply_chain.secret_scan_paths(candidate_root)

        assert relative in candidate
        assert "common/untracked.key" not in candidate
        report = verify_supply_chain.scan_secrets(candidate_root, (relative,))
        assert report["results"][relative]


@pytest.mark.asyncio
async def test_download_exec_rejects_unmanaged_url_before_execution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    execute = AsyncMock(side_effect=AssertionError("execution boundary reached"))
    monkeypatch.setattr(task_download_exec.DownloadExecEngine, "execute", execute)
    task = task_download_exec.DownloadExecTask(
        task_id="fixture-download",
        url="https://outside.invalid/payload",
    )

    result = await task.execute()

    assert result.status == task_download_exec.TaskStatus.FAILED
    assert result.metadata["reason_code"] == "outbound_policy_unsupported"
    assert "outside.invalid" not in result.error
    execute.assert_not_awaited()


@pytest.mark.asyncio
async def test_download_exec_rejects_malformed_and_oversized_inline_data(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    execute = AsyncMock(side_effect=AssertionError("execution boundary reached"))
    monkeypatch.setattr(task_download_exec.DownloadExecEngine, "execute", execute)

    malformed = task_download_exec.DownloadExecTask(
        task_id="fixture-malformed",
        data="not-valid-base64!!!",
    )
    malformed_result = await malformed.execute()
    assert malformed_result.status == task_download_exec.TaskStatus.FAILED
    assert "Invalid base64" in malformed_result.error

    monkeypatch.setattr(task_download_exec, "MAX_PAYLOAD_BYTES", 4)
    oversized = task_download_exec.DownloadExecTask(
        task_id="fixture-oversized",
        data=base64.b64encode(b"12345").decode("ascii"),
    )
    oversized_result = await oversized.execute()
    assert oversized_result.status == task_download_exec.TaskStatus.FAILED
    assert oversized_result.metadata["reason_code"] == "payload_size_limit"
    execute.assert_not_awaited()


@pytest.mark.asyncio
async def test_lateral_ssh_implant_staging_is_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subprocess_boundary = AsyncMock(
        side_effect=AssertionError("remote subprocess boundary reached")
    )
    monkeypatch.setattr(
        lateral_ssh.asyncio,
        "create_subprocess_shell",
        subprocess_boundary,
    )
    module = lateral_ssh.LateralSSH.__new__(lateral_ssh.LateralSSH)
    target = lateral_ssh.SSHTarget(host="192.0.2.10", username="fixture")

    action = await module._deploy_implant(target, "fixture.bin")

    assert action.status == "failed"
    assert "managed remote staging" in action.error
    assert "/tmp" not in action.output
    subprocess_boundary.assert_not_awaited()


def _zip_with_members(members: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in members.items():
            archive.writestr(name, content)
    return output.getvalue()


@pytest.mark.parametrize(
    ("extractor", "member"),
    (
        (credential_analysis._extract_docx, "word/document.xml"),
        (credential_analysis._extract_xlsx, "xl/workbook.xml"),
    ),
)
def test_office_extractors_reject_dtd_and_entities(
    extractor: Callable[[bytes], list[dict[str, str]]],
    member: str,
) -> None:
    malicious = b'<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///not-read">]><x>&xxe;</x>'
    archive = _zip_with_members({member: malicious})

    with pytest.raises(DefusedXmlException):
        extractor(archive)


def test_office_xml_member_and_cumulative_limits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_bytes = _zip_with_members({"one.xml": b"<x>1234</x>", "two.xml": b"<x>56</x>"})
    monkeypatch.setattr(credential_analysis, "MAX_OFFICE_XML_MEMBER_BYTES", 16)
    monkeypatch.setattr(credential_analysis, "MAX_OFFICE_XML_MEMBERS", 1)

    with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
        budget = credential_analysis._OfficeXmlBudget(remaining_bytes=16)
        assert credential_analysis._read_office_xml(archive, "one.xml", budget) == b"<x>1234</x>"
        with pytest.raises(ValueError, match="too many XML members"):
            credential_analysis._read_office_xml(archive, "two.xml", budget)

    monkeypatch.setattr(credential_analysis, "MAX_OFFICE_XML_MEMBERS", 2)
    with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
        budget = credential_analysis._OfficeXmlBudget(remaining_bytes=13)
        credential_analysis._read_office_xml(archive, "one.xml", budget)
        with pytest.raises(ValueError, match="decompression limit"):
            credential_analysis._read_office_xml(archive, "two.xml", budget)


def test_office_xml_element_and_depth_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(credential_analysis, "MAX_OFFICE_XML_ELEMENTS", 2)
    with pytest.raises(ValueError, match="element limit"):
        credential_analysis._parse_office_xml(b"<a><b/><c/></a>")

    monkeypatch.setattr(credential_analysis, "MAX_OFFICE_XML_ELEMENTS", 10)
    monkeypatch.setattr(credential_analysis, "MAX_OFFICE_XML_DEPTH", 2)
    with pytest.raises(ValueError, match="depth limit"):
        credential_analysis._parse_office_xml(b"<a><b><c/></b></a>")


def test_office_archive_rejects_member_count_and_duplicates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(credential_analysis, "MAX_OFFICE_ARCHIVE_MEMBERS", 1)
    with zipfile.ZipFile(io.BytesIO(_zip_with_members({"one": b"1", "two": b"2"}))) as archive:
        with pytest.raises(ValueError, match="too many members"):
            credential_analysis._validate_office_archive(archive)

    duplicate = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(duplicate, "w") as archive:
            archive.writestr("same.xml", b"<a/>")
            archive.writestr("same.xml", b"<b/>")
    duplicate.seek(0)
    monkeypatch.setattr(credential_analysis, "MAX_OFFICE_ARCHIVE_MEMBERS", 10)
    with zipfile.ZipFile(duplicate) as archive:
        with pytest.raises(ValueError, match="duplicate"):
            credential_analysis._validate_office_archive(archive)


def test_office_relationship_target_is_confined_to_worksheets() -> None:
    assert credential_analysis._xlsx_sheet_path("worksheets/sheet1.xml") == (
        "xl/worksheets/sheet1.xml"
    )
    for target in ("../../secret.xml", "../workbook.xml", "http://example.invalid/sheet.xml"):
        with pytest.raises(ValueError, match="relationship target|outside worksheets"):
            credential_analysis._xlsx_sheet_path(target)


def test_gpp_download_and_parser_resource_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    buffer = gpp_password._BoundedXmlBuffer(limit=4)
    assert buffer.write(b"1234") == 4
    with pytest.raises(ValueError, match="download limit"):
        buffer.write(b"5")

    scanner = gpp_password.GppPassword.__new__(gpp_password.GppPassword)
    entity_xml = b'<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///not-read">]><x>&xxe;</x>'
    assert scanner._parse_gpp_xml(entity_xml, "fixture.xml") == []

    monkeypatch.setattr(gpp_password, "MAX_GPP_XML_BYTES", 4)
    assert scanner._parse_gpp_xml(b"<root/>", "fixture.xml") == []

    monkeypatch.setattr(gpp_password, "MAX_GPP_XML_BYTES", 1024)
    monkeypatch.setattr(gpp_password, "MAX_GPP_XML_ELEMENTS", 2)
    assert scanner._parse_gpp_xml(b"<a><b/><c/></a>", "fixture.xml") == []

    monkeypatch.setattr(gpp_password, "MAX_GPP_XML_ELEMENTS", 10)
    monkeypatch.setattr(gpp_password, "MAX_GPP_XML_DEPTH", 2)
    assert scanner._parse_gpp_xml(b"<a><b><c/></b></a>", "fixture.xml") == []


def test_gpp_result_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gpp_password, "MAX_GPP_RESULTS", 1)
    scanner = gpp_password.GppPassword.__new__(gpp_password.GppPassword)
    xml = (
        b'<Groups><Properties userName="one" cpassword="VPe/o9YRyz2cksnYRbNeqg"/>'
        b'<Properties userName="two" cpassword="VPe/o9YRyz2cksnYRbNeqg"/></Groups>'
    )
    assert len(scanner._parse_gpp_xml(xml, "fixture.xml")) == 1


def test_browser_snapshot_is_private_and_removed(tmp_path: Path) -> None:
    source = tmp_path / "Login Data"
    source.write_bytes(b"sqlite fixture")
    snapshot_path: Path | None = None
    snapshot_parent: Path | None = None

    with ChromiumExtractor._safe_copy(source) as snapshot:
        assert snapshot is not None
        snapshot_path = snapshot
        snapshot_parent = snapshot.parent
        assert snapshot.read_bytes() == source.read_bytes()
        assert stat.S_IMODE(snapshot.stat().st_mode) == 0o600
        assert stat.S_IMODE(snapshot.parent.stat().st_mode) == 0o700

    assert snapshot_path is not None and not snapshot_path.exists()
    assert snapshot_parent is not None and not snapshot_parent.exists()


def test_browser_snapshot_cleanup_on_body_and_copy_failure(tmp_path: Path) -> None:
    source = tmp_path / "Cookies"
    source.write_bytes(b"sqlite fixture")
    snapshot_path: Path | None = None

    with pytest.raises(RuntimeError, match="body failed"):
        with ChromiumExtractor._safe_copy(source) as snapshot:
            assert snapshot is not None
            snapshot_path = snapshot
            raise RuntimeError("body failed")
    assert snapshot_path is not None and not snapshot_path.exists()

    with ChromiumExtractor._safe_copy(tmp_path / "missing") as snapshot:
        assert snapshot is None


def test_wordlist_creation_is_unique_private_and_releasable(tmp_path: Path) -> None:
    first = wordlist_mgr._write_embedded_wordlist(None)
    second = wordlist_mgr._write_embedded_wordlist(None)
    try:
        assert first != second
        assert stat.S_IMODE(first.stat().st_mode) == 0o600
        assert stat.S_IMODE(second.stat().st_mode) == 0o600
        assert wordlist_mgr.release_temporary_wordlist(first)
        assert not first.exists()
        assert not wordlist_mgr.release_temporary_wordlist(first)
    finally:
        wordlist_mgr.release_temporary_wordlist(first)
        wordlist_mgr.release_temporary_wordlist(second)


def test_wordlist_refuses_existing_and_symlink_paths(tmp_path: Path) -> None:
    existing = tmp_path / "existing.txt"
    existing.write_text("preserve\n", encoding="utf-8")
    with pytest.raises(FileExistsError):
        wordlist_mgr._write_embedded_wordlist(existing)
    assert existing.read_text(encoding="utf-8") == "preserve\n"

    target = tmp_path / "target.txt"
    target.write_text("preserve target\n", encoding="utf-8")
    link = tmp_path / "wordlist.txt"
    link.symlink_to(target)
    with pytest.raises(FileExistsError):
        wordlist_mgr._write_embedded_wordlist(link)
    assert target.read_text(encoding="utf-8") == "preserve target\n"


def test_wordlist_chmod_failure_removes_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "wordlist.txt"

    def fail_chmod(_path: Path, _mode: int) -> None:
        raise OSError("chmod failed")

    monkeypatch.setattr(wordlist_mgr.os, "chmod", fail_chmod)
    with pytest.raises(OSError, match="chmod failed"):
        wordlist_mgr._write_embedded_wordlist(destination)
    assert not destination.exists()


class _FakeProcess:
    def __init__(
        self,
        stdout: bytes = b"",
        stderr: bytes = b"",
        *,
        hang: bool = False,
        error: BaseException | None = None,
        returncode: int = 0,
    ) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.error = error
        self.returncode: int | None = None if hang or error is not None else returncode
        self.started = asyncio.Event()
        self.released = asyncio.Event()
        self.killed = False
        self.reaped = False

    async def communicate(self) -> tuple[bytes, bytes]:
        self.started.set()
        if self.error is not None:
            raise self.error
        if self.returncode is None:
            await self.released.wait()
        return self.stdout, self.stderr

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9
        self.released.set()

    async def wait(self) -> int:
        if self.returncode is None:
            await self.released.wait()
        self.reaped = True
        return int(self.returncode or 0)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "communicator",
    (
        sam_dump._communicate_and_reap,
        mimikatz_exec._communicate_and_reap,
        task_download_exec._communicate_and_reap,
    ),
)
async def test_sensitive_subprocess_timeout_kills_and_reaps(
    communicator: Callable[..., Awaitable[tuple[bytes, bytes]]],
) -> None:
    process = _FakeProcess(hang=True)
    with pytest.raises(asyncio.TimeoutError):
        await communicator(process, timeout=0)
    assert process.killed
    assert process.reaped
    assert process.returncode == -9


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "communicator",
    (
        sam_dump._communicate_and_reap,
        mimikatz_exec._communicate_and_reap,
        task_download_exec._communicate_and_reap,
    ),
)
async def test_sensitive_subprocess_cancellation_kills_and_reaps(
    communicator: Callable[..., Awaitable[tuple[bytes, bytes]]],
) -> None:
    process = _FakeProcess(hang=True)
    task = asyncio.create_task(communicator(process, timeout=60))
    await process.started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert process.killed
    assert process.reaped
    assert process.returncode == -9


def test_private_hive_paths_are_operation_unique(monkeypatch: pytest.MonkeyPatch) -> None:
    tokens = iter(("a" * 32, "b" * 32))
    monkeypatch.setattr(sam_dump.secrets, "token_hex", lambda _size: next(tokens))
    first = sam_dump._private_hive_paths("sam", "system")
    second = sam_dump._private_hive_paths("sam", "system")
    assert set(first.values()).isdisjoint(second.values())
    assert first["sam"].name == f"forge_sam_{'a' * 32}.hiv"


@pytest.mark.asyncio
async def test_regsave_timeout_reaps_before_artifact_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = {name: tmp_path / f"{name}.hiv" for name in ("sam", "system", "security")}
    for path in paths.values():
        path.write_bytes(b"sensitive")
    processes: list[_FakeProcess] = []

    async def create_process(*_args: Any, **_kwargs: Any) -> _FakeProcess:
        process = _FakeProcess(error=asyncio.TimeoutError())
        processes.append(process)
        return process

    monkeypatch.setattr(sam_dump, "_private_hive_paths", lambda *_labels: paths)
    monkeypatch.setattr(sam_dump.asyncio, "create_subprocess_exec", create_process)
    module = sam_dump.SAMDump.__new__(sam_dump.SAMDump)
    result = await module._dump_via_regsave("fixture")

    assert result["status"] == "error"
    assert processes and all(process.killed and process.reaped for process in processes)
    assert all(not path.exists() for path in paths.values())


@pytest.mark.asyncio
async def test_regsave_cancellation_reaps_before_artifact_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = {name: tmp_path / f"{name}.hiv" for name in ("sam", "system", "security")}
    for path in paths.values():
        path.write_bytes(b"sensitive")
    process = _FakeProcess(hang=True)

    async def create_process(*_args: Any, **_kwargs: Any) -> _FakeProcess:
        return process

    monkeypatch.setattr(sam_dump, "_private_hive_paths", lambda *_labels: paths)
    monkeypatch.setattr(sam_dump.asyncio, "create_subprocess_exec", create_process)
    module = sam_dump.SAMDump.__new__(sam_dump.SAMDump)
    task = asyncio.create_task(module._dump_via_regsave("fixture"))
    await process.started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert process.killed and process.reaped
    assert all(not path.exists() for path in paths.values())


@pytest.mark.asyncio
async def test_vss_timeout_reaps_before_artifact_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = {name: tmp_path / f"{name}.hiv" for name in ("sam_vss", "system_vss")}
    for path in paths.values():
        path.write_bytes(b"sensitive")
    process = _FakeProcess(error=asyncio.TimeoutError())

    async def create_process(*_args: Any, **_kwargs: Any) -> _FakeProcess:
        return process

    monkeypatch.setattr(sam_dump, "_private_hive_paths", lambda *_labels: paths)
    monkeypatch.setattr(sam_dump.asyncio, "create_subprocess_exec", create_process)
    module = sam_dump.SAMDump.__new__(sam_dump.SAMDump)
    result = await module._dump_via_vss("fixture")

    assert result["status"] == "error"
    assert process.killed and process.reaped
    assert all(not path.exists() for path in paths.values())


@pytest.mark.asyncio
async def test_vss_uses_and_deletes_only_created_shadow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    shadow_id = "{ABCDEF12-1234-5678-90AB-ABCDEF123456}"
    paths = {name: tmp_path / f"{name}.hiv" for name in ("sam_vss", "system_vss")}
    processes = iter(
        (
            _FakeProcess(stdout=f"FORGE_SHADOW_ID={shadow_id}\r\n".encode()),
            _FakeProcess(
                stdout=b"FORGE_SHADOW_DEVICE=\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy7\r\n"
            ),
            _FakeProcess(),
        )
    )
    calls: list[tuple[str, ...]] = []

    async def create_process(*args: str, **_kwargs: Any) -> _FakeProcess:
        calls.append(args)
        return next(processes)

    def copy_file(_source: Path, destination: Path) -> None:
        Path(destination).write_bytes(b"sensitive")

    monkeypatch.setattr(sam_dump, "_private_hive_paths", lambda *_labels: paths)
    monkeypatch.setattr(sam_dump.asyncio, "create_subprocess_exec", create_process)
    monkeypatch.setattr(sam_dump.shutil, "copyfile", copy_file)
    module = sam_dump.SAMDump.__new__(sam_dump.SAMDump)
    module._parse_files = AsyncMock(return_value={"status": "success", "hashes": []})
    result = await module._dump_via_vss("fixture")

    assert result["status"] == "success"
    assert len(calls) == 3
    query_script = base64.b64decode(calls[1][4]).decode("utf-16-le")
    delete_script = base64.b64decode(calls[2][4]).decode("utf-16-le")
    assert shadow_id in query_script
    assert shadow_id in delete_script
    assert all(not path.exists() for path in paths.values())
    assert f"removed:shadow:{shadow_id}" in result["cleanup"]


@pytest.mark.asyncio
async def test_vss_cancellation_deletes_created_shadow_after_reap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    shadow_id = "{ABCDEF12-1234-5678-90AB-ABCDEF123456}"
    paths = {name: tmp_path / f"{name}.hiv" for name in ("sam_vss", "system_vss")}
    for path in paths.values():
        path.write_bytes(b"sensitive")
    query = _FakeProcess(hang=True)
    processes = iter(
        (
            _FakeProcess(stdout=f"FORGE_SHADOW_ID={shadow_id}\r\n".encode()),
            query,
            _FakeProcess(),
        )
    )
    calls: list[tuple[str, ...]] = []

    async def create_process(*args: str, **_kwargs: Any) -> _FakeProcess:
        calls.append(args)
        return next(processes)

    monkeypatch.setattr(sam_dump, "_private_hive_paths", lambda *_labels: paths)
    monkeypatch.setattr(sam_dump.asyncio, "create_subprocess_exec", create_process)
    module = sam_dump.SAMDump.__new__(sam_dump.SAMDump)
    task = asyncio.create_task(module._dump_via_vss("fixture"))
    await query.started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert query.killed and query.reaped
    assert len(calls) == 3
    delete_script = base64.b64decode(calls[2][4]).decode("utf-16-le")
    assert shadow_id in delete_script
    assert all(not path.exists() for path in paths.values())


@pytest.mark.asyncio
async def test_wmic_uses_and_deletes_only_created_shadow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    shadow_id = "{12345678-1234-1234-1234-1234567890AB}"
    paths = {name: tmp_path / f"{name}.hiv" for name in ("sam_wmic", "system_wmic")}
    processes = iter(
        (
            _FakeProcess(stdout=f'ShadowID = "{shadow_id}";\r\n'.encode()),
            _FakeProcess(
                stdout=b"DeviceObject=\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy42\r\n"
            ),
            _FakeProcess(),
        )
    )
    calls: list[tuple[str, ...]] = []

    async def create_process(*args: str, **_kwargs: Any) -> _FakeProcess:
        calls.append(args)
        return next(processes)

    def copy_file(_source: Path, destination: Path) -> None:
        Path(destination).write_bytes(b"sensitive")

    monkeypatch.setattr(sam_dump, "_private_hive_paths", lambda *_labels: paths)
    monkeypatch.setattr(sam_dump.asyncio, "create_subprocess_exec", create_process)
    monkeypatch.setattr(sam_dump.shutil, "copyfile", copy_file)
    module = sam_dump.SAMDump.__new__(sam_dump.SAMDump)
    module._parse_files = AsyncMock(return_value={"status": "success", "hashes": []})
    result = await module._dump_via_wmic("fixture")

    assert result["status"] == "success"
    assert len(calls) == 3
    assert calls[1][3] == f"ID='{shadow_id}'"
    assert calls[2][3] == f"ID='{shadow_id}'"
    assert calls[2][-1] == "delete"
    assert all(not path.exists() for path in paths.values())
    assert f"removed:shadow:{shadow_id}" in result["cleanup"]


@pytest.mark.asyncio
async def test_wmic_cancellation_deletes_created_shadow_after_reap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    shadow_id = "{12345678-1234-1234-1234-1234567890AB}"
    paths = {name: tmp_path / f"{name}.hiv" for name in ("sam_wmic", "system_wmic")}
    for path in paths.values():
        path.write_bytes(b"sensitive")
    query = _FakeProcess(hang=True)
    processes = iter(
        (
            _FakeProcess(stdout=f'ShadowID = "{shadow_id}";\r\n'.encode()),
            query,
            _FakeProcess(),
        )
    )
    calls: list[tuple[str, ...]] = []

    async def create_process(*args: str, **_kwargs: Any) -> _FakeProcess:
        calls.append(args)
        return next(processes)

    monkeypatch.setattr(sam_dump, "_private_hive_paths", lambda *_labels: paths)
    monkeypatch.setattr(sam_dump.asyncio, "create_subprocess_exec", create_process)
    module = sam_dump.SAMDump.__new__(sam_dump.SAMDump)
    task = asyncio.create_task(module._dump_via_wmic("fixture"))
    await query.started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert query.killed and query.reaped
    assert len(calls) == 3
    assert calls[2][3] == f"ID='{shadow_id}'"
    assert calls[2][-1] == "delete"
    assert all(not path.exists() for path in paths.values())


@pytest.mark.asyncio
@pytest.mark.parametrize("failure_stage", ("pid", "dump", "parser"))
async def test_lsass_failure_stages_reap_and_remove_dump(
    failure_stage: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dump_path = tmp_path / f"forge_lsass_{'c' * 32}.dmp"
    dump_path.write_bytes(b"sensitive")
    stage_order = iter(("pid", "dump", "parser"))
    processes: list[_FakeProcess] = []

    async def create_process(*_args: Any, **_kwargs: Any) -> _FakeProcess:
        stage = next(stage_order)
        if stage == "pid":
            process = _FakeProcess(stdout=b"123\n")
        elif stage == "dump":
            process = _FakeProcess()
        else:
            process = _FakeProcess(stdout=b"parsed")
        if stage == failure_stage:
            process = _FakeProcess(error=asyncio.TimeoutError())
        processes.append(process)
        return process

    monkeypatch.setattr(mimikatz_exec.tempfile, "gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr(mimikatz_exec.secrets, "token_hex", lambda _size: "c" * 32)
    monkeypatch.setattr(mimikatz_exec.asyncio, "create_subprocess_exec", create_process)
    module = mimikatz_exec.MimikatzExec.__new__(mimikatz_exec.MimikatzExec)
    await module._lsass_minidump("fixture", "")

    failed = processes[-1]
    assert failed.killed and failed.reaped
    assert not dump_path.exists()


@pytest.mark.asyncio
async def test_lsass_cancellation_reaps_before_dump_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dump_path = tmp_path / f"forge_lsass_{'d' * 32}.dmp"
    dump_path.write_bytes(b"sensitive")
    process = _FakeProcess(hang=True)

    async def create_process(*_args: Any, **_kwargs: Any) -> _FakeProcess:
        return process

    monkeypatch.setattr(mimikatz_exec.tempfile, "gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr(mimikatz_exec.secrets, "token_hex", lambda _size: "d" * 32)
    monkeypatch.setattr(mimikatz_exec.asyncio, "create_subprocess_exec", create_process)
    module = mimikatz_exec.MimikatzExec.__new__(mimikatz_exec.MimikatzExec)
    task = asyncio.create_task(module._lsass_minidump("fixture", ""))
    await process.started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert process.killed and process.reaped
    assert not dump_path.exists()
