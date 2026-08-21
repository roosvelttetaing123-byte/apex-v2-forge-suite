"""Completion-boundary identity tests for WebForge whitebox modules."""
from __future__ import annotations

import asyncio
from pathlib import Path

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
from webforge.core.source_root import canonical_source_root, open_source_file
from webforge.modules.whitebox import dep_audit, secret_scan
from webforge.modules.whitebox.dep_audit import DepAudit
from webforge.modules.whitebox.secret_scan import SecretScan


@pytest.fixture(autouse=True)
def _isolated_module_authorization_db(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv(
        AUTHORIZATION_DB_ENV,
        str(tmp_path / "completion-authorization.db"),
    )


def _module_config(
    source_root: Path,
    module_id: str,
) -> tuple[BaseForgeConfig, str]:
    config = BaseForgeConfig(target="https://example.test", mode="whitebox")
    config.extra["allowed_scope"] = ["example.test"]
    config.extra["excluded_scope"] = []
    config.extra["source_root"] = canonical_source_root(source_root)
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
        requested_target=config.target,
        resolved_target=config.target,
        allowed_scope=config.extra["allowed_scope"],
        excluded_scope=config.extra["excluded_scope"],
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
                target=config.target,
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
    config.extra["authorized_module_envelopes"] = {module_id: issued.envelope}
    return config, run_id


def test_secret_scan_skips_when_root_is_replaced_after_final_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    approved = tmp_path / "approved"
    replacement = tmp_path / "replacement"
    approved.mkdir()
    replacement.mkdir()
    (approved / "input.py").write_text("approved fixture\n", encoding="utf-8")
    outside_canary = "SECRET_SCAN_FINAL_READ_REPLACEMENT_CANARY"
    (replacement / "input.py").write_text(outside_canary, encoding="utf-8")
    config, run_id = _module_config(approved, "secret_scan")
    scanner = SecretScan(
        config,
        Scope(["example.test"]),
        create_db(tmp_path / "secret-scan.db"),
        tmp_path / "results",
        run_id=run_id,
    )
    opened = 0

    def replacing_open(root, candidate, *, max_bytes):
        nonlocal opened
        data = open_source_file(root, candidate, max_bytes=max_bytes)
        opened += 1
        if opened == 1:
            approved.rename(tmp_path / "approved-original")
            replacement.rename(approved)
        return data

    monkeypatch.setattr(secret_scan, "open_source_file", replacing_open)

    result = asyncio.run(scanner.run())

    assert opened == 1
    assert result.skipped is True
    assert result.skip_reason == "source_root identity changed after approval"
    assert result.findings == []
    assert outside_canary not in repr(result)


def test_dependency_audit_skips_when_root_is_replaced_after_final_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    approved = tmp_path / "approved"
    replacement = tmp_path / "replacement"
    approved.mkdir()
    replacement.mkdir()
    outside_canary = "DEPENDENCY_FINAL_READ_REPLACEMENT_CANARY"
    for name, _ in dep_audit._MANIFEST_LIMITS:
        (approved / name).write_text("approved fixture\n", encoding="utf-8")
        (replacement / name).write_text(outside_canary, encoding="utf-8")
    config, run_id = _module_config(approved, "dep_audit")
    auditor = DepAudit(
        config,
        Scope(["example.test"]),
        create_db(tmp_path / "dependency-audit.db"),
        tmp_path / "results",
        run_id=run_id,
    )
    opened = 0

    def replacing_open(root, candidate, *, max_bytes):
        nonlocal opened
        data = open_source_file(root, candidate, max_bytes=max_bytes)
        opened += 1
        if opened == len(dep_audit._MANIFEST_LIMITS):
            approved.rename(tmp_path / "approved-original")
            replacement.rename(approved)
        return data

    monkeypatch.setattr(dep_audit, "open_source_file", replacing_open)

    result = asyncio.run(auditor.run())

    assert opened == len(dep_audit._MANIFEST_LIMITS)
    assert result.skipped is True
    assert result.skip_reason == "source_root identity changed after approval"
    assert result.findings == []
    assert outside_canary not in repr(result)
