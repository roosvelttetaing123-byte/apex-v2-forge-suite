"""Deterministic Task 105 reference vertical-slice contracts.

The fixtures in this file are deliberately local and inert.  Canonical finding,
retest, review, report, export, and migration assertions use the existing
Task 101-104 services.  The one module execution fixture uses a loopback HTTP
server so the real ``ForgeSession``/``PolicyHttpClient`` path is exercised
without contacting an external target.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import http.server
import json
import os
import subprocess
import sys
import threading
import time
from dataclasses import replace
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from common.action_authorization import (
    AUTHORIZATION_DB_ENV,
    ActionAuthorizationEnvelope,
    AuthorizationContext,
    ConfirmationMethod,
    OperatorRole,
    SafetyMode,
    claim_consumed_authorization_execution,
    consume_authorization,
    issue_authorization,
    module_set_binding,
)
from common.base_module import BaseModule
from common.canonical import CanonicalStore
from common.canonical_evidence import (
    CanonicalEvidenceContext,
    CanonicalEvidenceReader,
    CanonicalEvidenceService,
)
from common.config import BaseForgeConfig
from common.confirm_gate import ActionConfirmation
from common.dashboard.auth import Role, issue_identity_token
from common.dashboard.event_bus import EventBus
from common.dashboard.server import DashboardServer
from common.db import ScanJobModel, create_db, open_existing_db
from common.evidence import Evidence
from common.evidence_custody import ArtifactIntegrityError, EvidenceCustodyStore
from common.finding import Finding, Severity
from common.finding_review import (
    FindingReviewConflict,
    FindingReviewFixedProofRequired,
    FindingReviewForbidden,
    FindingReviewNotFound,
    FindingReviewService,
    ReviewStatus,
)
from common.job_state import JobStateService
from common.reporting.canonical_report import (
    CanonicalReportAuthorizationError,
    CanonicalReportNotFound,
    CanonicalReportService,
    CanonicalReportSourceIncomplete,
    report_export_binding,
)
from common.run_finalization import (
    RUN_TRUTH_AUTHORITY_ID_ENV,
    RUN_TRUTH_ISSUER_ID_ENV,
    RUN_TRUTH_POLICY_ID_ENV,
    RUN_TRUTH_POLICY_VERSION_ENV,
    RUN_TRUTH_PRIVATE_KEY_FILE_ENV,
    RUN_TRUTH_PUBLIC_KEY_ENV,
)
from common.run_truth import RunTruthPolicy
from common.retest import (
    HEADER_CSP_CHECK_ID,
    HEADER_CSP_PROOF_POLICY,
    HEADER_CSP_VERIFIER_ID,
    HEADER_CSP_VERIFIER_VERSION,
    HeaderAuditCspVerifier,
    HeaderResponse,
    RetestService,
    RetestStatus,
    classify_csp,
)
from common.schema_migrations import (
    JOB_STATE_SCHEMA_VERSION,
    REFERENCE_SLICE_SCHEMA_VERSION,
    RETEST_SCHEMA_VERSION,
    MigrationError,
    MigrationInterruptedError,
    MigrationManager,
)
from common.scope import Scope
from common.version import VERSION
from webforge.modules.headers.header_audit import HeaderAudit, REQUIRED_HEADERS

from tests.test_real_retest import _active_fixture, _authorization, _run


REFERENCE_SOURCE_SHA256 = (
    "5c2a0887403fbd0959ccd9e2a08cc9b5ac6d355305cb9511478f241509daad84"
)


def _module_context(
    *,
    tenant_id: str,
    engagement_id: str,
    run_id: str,
    job_id: str,
    operator_id: str,
    target: str,
    allowed_scope: list[str],
    module_id: str = "header_audit",
    action_kind: str = "module.execute",
    engine: str = "webforge",
    safety_mode: SafetyMode = SafetyMode.PASSIVE,
) -> AuthorizationContext:
    return AuthorizationContext(
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        run_id=run_id,
        job_id=job_id,
        operator_id=operator_id,
        operator_role=OperatorRole.OPERATOR,
        action_kind=action_kind,
        engine=engine,
        module_id=module_id,
        requested_target=target,
        resolved_target=target,
        allowed_scope=allowed_scope,
        excluded_scope=[],
        scope_policy_version="task105-scope-v1",
        safety_mode=safety_mode,
        confirmation_method=ConfirmationMethod.DASHBOARD,
        confirmed_by=operator_id,
    )


def _consumed_authorization(
    session: Any,
    context: AuthorizationContext,
    *,
    boundary: str,
) -> ActionAuthorizationEnvelope:
    confirmation = ActionConfirmation.create(
        job_id=context.job_id,
        target=context.resolved_target,
        engine=context.engine,
        action=context.action_kind,
    )
    issued = issue_authorization(
        session=session,
        context=context,
        confirmation=confirmation,
    )
    assert issued.allowed
    consumed = consume_authorization(
        session=session,
        envelope=issued.envelope,
        expected=context,
        boundary=boundary,
    )
    assert consumed.allowed
    assert consumed.envelope is not None
    return consumed.envelope


async def _run_header_audit_fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    serve: bool,
) -> tuple[Any, dict[str, Any], list[bytes], str]:
    """Run the real ``HeaderAudit`` against one local response or a refusal."""

    requests: list[bytes] = []

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            requests.append(await asyncio.wait_for(
                reader.readuntil(b"\r\n\r\n"),
                timeout=2.0,
            ))
            body = b"<html>task105-loopback</html>"
            writer.write(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/html\r\n"
                b"X-Content-Type-Options: nosniff\r\n"
                b"X-Frame-Options: DENY\r\n"
                b"Referrer-Policy: strict-origin\r\n"
                b"Permissions-Policy: camera=(), microphone=()\r\n"
                b"Cross-Origin-Opener-Policy: same-origin\r\n"
                b"Cross-Origin-Embedder-Policy: require-corp\r\n"
                b"Cross-Origin-Resource-Policy: same-origin\r\n"
                b"Content-Length: " + str(len(body)).encode("ascii")
                + b"\r\nConnection: close\r\n\r\n" + body
            )
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    listener: asyncio.AbstractServer | None = None
    if serve:
        listener = await asyncio.start_server(handle, "127.0.0.1", 0)
        port = int(listener.sockets[0].getsockname()[1])
    else:
        # Bind and release a loopback port to obtain a deterministic local
        # connection-refused target without touching a service outside pytest.
        closed = await asyncio.start_server(handle, "127.0.0.1", 0)
        port = int(closed.sockets[0].getsockname()[1])
        closed.close()
        await closed.wait_closed()
    target = f"http://127.0.0.1:{port}/account"
    allowed_scope = ["127.0.0.1/32", target]

    auth_path = tmp_path / ("module-auth.db" if serve else "module-failure-auth.db")
    canonical_path = tmp_path / (
        "module-canonical.db" if serve else "module-failure-canonical.db"
    )
    result_root = tmp_path / ("module-results" if serve else "module-failure-results")
    result_root.mkdir(mode=0o700)
    auth = create_db(auth_path)
    context = _module_context(
        tenant_id="tenant-a",
        engagement_id="task105-module-engagement",
        run_id="task105-module-run" if serve else "task105-module-failure-run",
        job_id="task105-module-job" if serve else "task105-module-failure-job",
        operator_id="task105-module-operator",
        target=target,
        allowed_scope=allowed_scope,
    )
    envelope = _consumed_authorization(
        auth,
        context,
        boundary="webforge.module",
    )
    auth.close()
    monkeypatch.setenv(AUTHORIZATION_DB_ENV, str(auth_path))
    canonical = create_db(canonical_path)
    config = BaseForgeConfig(
        target=target,
        engagement=context.engagement_id,
        tester=context.operator_id,
        mode="blackbox",
        extra={
            "allowed_scope": allowed_scope,
            "excluded_scope": [],
            "reference_slice": "header-audit-csp-v1",
            "authorized_module_envelopes": {"header_audit": envelope},
        },
    )
    module = HeaderAudit(
        config,
        Scope([target]),
        canonical,
        result_root,
        run_id=context.run_id,
    )
    try:
        result = await asyncio.wait_for(module.run(), timeout=10.0)
        return canonical, {
            "result": result,
            "module": module,
            "config": config,
            "context": context,
            "envelope": envelope,
            "custody": result_root / "evidence-custody",
        }, requests, target
    finally:
        if listener is not None:
            listener.close()
            await listener.wait_closed()


def _prepare_retest_fixture(
    tmp_path: Path,
    *,
    idempotency_key: str = "task105-report-retest-1",
) -> tuple[dict[str, Any], Any, Any, RetestService]:
    fixture = _active_fixture(tmp_path)

    async def fetch(target: str, *_args: Any) -> HeaderResponse:
        return HeaderResponse(200, {}, target)

    service = RetestService(
        fixture["session"],
        fixture["custody"],
        fixture["jobs"],
        authorization_loader=lambda decision_id: (
            fixture["original_authorization"]
            if decision_id == fixture["original_authorization"].decision_id
            else None
        ),
        outbound_policy_factory=lambda *_args: object(),
        header_verifier=HeaderAuditCspVerifier(fetcher=fetch),
    )
    result = _run(
        service.execute(
            finding_id=fixture["finding_id"],
            tenant_id="tenant-a",
            authorization=fixture["authorization"],
            allowed_scope=("fixture.test",),
            idempotency_key=idempotency_key,
        )
    )
    assert result.verdict is RetestStatus.STILL_VULNERABLE
    fixture["session"].rollback()
    review = FindingReviewService(
        fixture["session"],
        tenant_id="tenant-a",
    ).update(
        fixture["finding_id"],
        expected_version=0,
        actor_operator_id="operator-current",
        actor_role="operator",
        status="in_progress",
        notes="password=TASK105_REVIEW_CANARY",
        ownership="claim",
    )
    fixture["session"].rollback()
    return fixture, result, review, service


def _report_authorization(
    report: Any,
    canonical_session: Any,
    *,
    operator_id: str = "operator-current",
    job_id: str = "task105-export-job",
) -> tuple[ActionAuthorizationEnvelope, Any]:
    auth = Session(bind=canonical_session.get_bind())
    context = _module_context(
        tenant_id=report.tenant_id,
        engagement_id=report.engagement_id,
        run_id=f"{job_id}-run",
        job_id=job_id,
        operator_id=operator_id,
        target=report.target,
        allowed_scope=["fixture.test"],
        module_id=report_export_binding(
            report.report_id,
            report.artifact_sha256,
        ),
        action_kind="report.export",
        engine="forge",
    )
    return _consumed_authorization(
        auth,
        context,
        boundary="dashboard.report.export",
    ), auth


def _register_server_legacy_job(
    server: DashboardServer,
    root: Path,
    envelope: ActionAuthorizationEnvelope,
    *,
    target: str,
) -> None:
    """Register a migration-stable legacy projection after server startup."""

    session = create_db(server._scan_jobs_db_path)
    try:
        session.add(
            ScanJobModel(
                id=envelope.job_id,
                tenant_id=envelope.tenant_id,
                status="completed",
                target=target,
                frameworks=json.dumps([envelope.engine]),
                modules=json.dumps([envelope.module_id]),
                results_dir=str(root),
                logs=json.dumps({}),
                authorization_state="allow",
                authorization_decision_id=envelope.decision_id,
                authorization_action_id=envelope.action_id,
            )
        )
        session.commit()
    finally:
        session.close()


def _dashboard_review_fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[DashboardServer, Any, dict[str, Any], Path]:
    monkeypatch.setenv("FORGE_TENANT_ID", "tenant-a")
    state_root = tmp_path / "dashboard-state"
    state_root.mkdir(mode=0o700)
    state_root.chmod(0o700)
    monkeypatch.setenv("FORGE_DASHBOARD_STATE_DIR", str(state_root))
    server = DashboardServer(event_bus=EventBus(run_id="task105-dashboard"))
    root = server._allocate_scan_results_dir("job-current")
    fixture = _active_fixture(root)
    old_database = fixture["database"]
    fixture["session"].close()
    fixture["jobs"].close()
    database = root / "webforge.db"
    old_database.rename(database)
    fixture["database"] = database
    app = server.create_app()

    # The startup reconciler intentionally demotes old compatibility rows.  A
    # fully bound authorization/consumption/execution lineage keeps this local
    # projection valid for subsequent middleware audit writes.
    auth_session = create_db(server._scan_jobs_db_path)
    target = fixture["target"]
    context = _module_context(
        tenant_id="tenant-a",
        engagement_id="dashboard-engagement",
        run_id="dashboard-run",
        job_id="job-current",
        operator_id="dashboard-owner",
        target=target,
        allowed_scope=["fixture.test"],
        module_id="header_audit",
        action_kind="scan",
        engine="webforge",
    )
    envelope = _consumed_authorization(
        auth_session,
        context,
        boundary="dashboard.launch",
    )
    claimed = claim_consumed_authorization_execution(
        session=auth_session,
        envelope=envelope,
        expected=context,
        boundary="dashboard.launch",
    )
    assert claimed.allowed
    auth_session.close()
    _register_server_legacy_job(server, root, envelope, target=target)
    return server, app, fixture, root


def _migration_table_names(session: Any) -> set[str]:
    return {
        str(row[0])
        for row in session.execute(
            text("SELECT name FROM sqlite_master WHERE type='table'")
        ).all()
    }


def test_task105_uses_unchanged_csp_rule_and_source_digest() -> None:
    csp = next(item for item in REQUIRED_HEADERS if item["name"] == HEADER_CSP_CHECK_ID)
    source = Path(__file__).resolve().parents[1] / "webforge/modules/headers/header_audit.py"
    assert hashlib.sha256(source.read_bytes()).hexdigest() == REFERENCE_SOURCE_SHA256
    assert VERSION == "5.0.0"
    assert csp["severity"].value == "Medium"
    assert csp["cvss"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
    assert csp["references"] == ["CWE-1021", "OWASP A05:2021"]
    assert classify_csp(None) == "csp_missing"
    assert classify_csp("default-src 'self' 'unsafe-inline'") == "csp_weak"
    assert classify_csp("default-src 'self'; object-src 'none'") == "csp_strong"
    assert HEADER_CSP_PROOF_POLICY == "header-audit-csp-proof-v1"
    assert HEADER_CSP_VERIFIER_ID == "webforge.header_audit.csp"
    assert HEADER_CSP_VERIFIER_VERSION == "1.0.0"


def test_dashboard_worker_sqlite_writes_preserve_locks_and_integrity(
    tmp_path: Path,
) -> None:
    """A live Task 103 reader and worker writers must share one safe WAL."""

    database = tmp_path / "cross-process-authority.db"
    jobs = JobStateService(database)
    child = """
import sys
import time
from pathlib import Path
from common.db import open_existing_db, save_audit_log

database = Path(sys.argv[1])
worker = sys.argv[2]
for sequence in range(30):
    for _attempt in range(30):
        session = None
        try:
            session = open_existing_db(database)
            save_audit_log(
                session,
                {
                    "tenant_id": "tenant-cross-process",
                    "action": f"worker.{worker}",
                    "object_id": f"authz-{worker}-{sequence}",
                },
            )
            session.close()
            break
        except Exception:
            if session is not None:
                session.close()
            time.sleep(0.01)
    else:
        raise SystemExit(3)
"""
    environment = {
        **os.environ,
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    processes = [
        subprocess.Popen(  # noqa: S603 - fixed local interpreter/code fixture
            [sys.executable, "-c", child, str(database), str(worker)],
            cwd=Path(__file__).resolve().parents[1],
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for worker in range(2)
    ]
    try:
        deadline = time.monotonic() + 30.0
        while any(process.poll() is None for process in processes):
            assert time.monotonic() < deadline
            assert jobs.list_jobs(tenant_id="tenant-cross-process") == []
            time.sleep(0.002)
        completed = [
            (process.returncode, *process.communicate())
            for process in processes
        ]
        failures = [result for result in completed if result[0] != 0]
        assert failures == []
        session = create_db(database)
        try:
            assert session.execute(text("PRAGMA integrity_check")).scalar_one() == "ok"
            assert session.execute(
                text(
                    "SELECT COUNT(*) FROM audit_logs "
                    "WHERE tenant_id='tenant-cross-process'"
                )
            ).scalar_one() == 60
        finally:
            session.close()
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
        jobs.close()


def test_reference_module_uses_one_get_and_passive_proof(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    canonical, fixture, requests, target = _run(
        _run_header_audit_fixture(tmp_path, monkeypatch, serve=True)
    )
    try:
        result = fixture["result"]
        assert result.skipped is False
        assert result.errors == []
        assert len(result.findings) == 1
        assert len(requests) == 1
        assert requests[0].startswith(
            f"GET /account HTTP/1.1\r\nHost: 127.0.0.1:".encode()
        )
        state = fixture["config"].extra.get("reference_request_state", {})
        assert state == {
            "failure_reason": "",
            "method": "GET",
            "requested_url": target,
            "final_url": target,
            "request_count": 1,
            "response_status": 200,
        }
        csp = next(
            finding
            for finding in result.findings
            if HEADER_CSP_CHECK_ID in finding.title
        )
        assert csp.proof_type == "passive"
        projection = CanonicalEvidenceReader(
            canonical,
            fixture["custody"],
            "tenant-a",
            audit_actor_id="task105-module-operator",
        ).get_finding_projection(csp.id)
        assert projection is not None
        assert projection["proof_type"] == "passive"
        assert projection["evidence"]["state"] == "persisted"
        observation = projection["evidence"]["observations"][0]
        assert observation["route"] == "/account"
        assert observation["proof_type"] == "passive"
        assert observation["check_id"] == HEADER_CSP_CHECK_ID
        assert any(
            artifact["capture_kind"] == "structured_proof"
            for artifact in observation["artifacts"]
        )
    finally:
        canonical.close()


def test_reference_module_transport_failure_is_not_a_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    canonical, fixture, requests, _target = _run(
        _run_header_audit_fixture(tmp_path, monkeypatch, serve=False)
    )
    try:
        result = fixture["result"]
        assert result.findings == []
        assert result.skipped is True
        assert result.skip_reason == "connection_failed"
        assert requests == []
        assert any(error.startswith("reference_slice_transport_") for error in result.errors)
        state = fixture["config"].extra.get("reference_request_state", {})
        assert state["failure_reason"].startswith("reference_slice_transport_")
        assert "request_count" not in state
        assert canonical.execute(
            text("SELECT COUNT(*) FROM canonical_findings")
        ).scalar_one() == 0
    finally:
        canonical.close()


def test_finding_review_cas_history_tenant_redaction(tmp_path: Path) -> None:
    fixture = _active_fixture(tmp_path)
    session = fixture["session"]
    try:
        service = FindingReviewService(session, tenant_id="tenant-a")
        initial = service.get(fixture["finding_id"])
        assert initial.version == 0
        assert initial.status is ReviewStatus.OPEN
        first = service.update(
            fixture["finding_id"],
            expected_version=0,
            actor_operator_id="reviewer-a",
            actor_role="operator",
            status="in_progress",
            notes="password=TASK105_REVIEW_CANARY",
            ownership="claim",
        )
        assert first.version == 1
        assert first.owner_operator_id == "reviewer-a"
        assert first.notes == "password=<redacted>"
        assert "TASK105_REVIEW_CANARY" not in first.notes
        with pytest.raises(FindingReviewFixedProofRequired):
            service.update(
                fixture["finding_id"],
                expected_version=1,
                actor_operator_id="reviewer-a",
                actor_role="operator",
                status="remediated",
            )
        session.rollback()
        with pytest.raises(FindingReviewForbidden):
            service.update(
                fixture["finding_id"],
                expected_version=1,
                actor_operator_id="reviewer-b",
                actor_role="operator",
                ownership="claim",
            )
        session.rollback()
        with pytest.raises(FindingReviewConflict):
            service.update(
                fixture["finding_id"],
                expected_version=0,
                actor_operator_id="reviewer-b",
                actor_role="operator",
                status="remediated",
            )
        duplicate = service.update(
            fixture["finding_id"],
            expected_version=1,
            actor_operator_id="reviewer-a",
            actor_role="operator",
            status="in_progress",
            notes="password=<redacted>",
            ownership="unchanged",
        )
        assert duplicate.duplicate is True
        assert duplicate.version == 1
        with pytest.raises(FindingReviewForbidden):
            service.update(
                fixture["finding_id"],
                expected_version=1,
                actor_operator_id="reviewer-b",
                actor_role="operator",
                ownership="release",
            )
        released = service.update(
            fixture["finding_id"],
            expected_version=1,
            actor_operator_id="reviewer-admin",
            actor_role="admin",
            ownership="release",
        )
        assert released.version == 2
        assert released.owner_operator_id is None
        revisions = service.revisions(fixture["finding_id"])
        assert [int(row["version"]) for row in revisions] == [1, 2]
        assert all("TASK105_REVIEW_CANARY" not in json.dumps(row) for row in revisions)
        with pytest.raises(IntegrityError):
            session.execute(
                text(
                    "UPDATE canonical_finding_review_revisions "
                    "SET notes='mutated' WHERE finding_id=:finding_id"
                ),
                {"finding_id": fixture["finding_id"]},
            )
            session.commit()
        session.rollback()

        tenant_b = FindingReviewService(session, tenant_id="tenant-b")
        with pytest.raises(FindingReviewNotFound):
            tenant_b.get(fixture["finding_id"])
        session.rollback()
        with pytest.raises(FindingReviewNotFound):
            tenant_b.update(
                fixture["finding_id"],
                expected_version=0,
                actor_operator_id="reviewer-b",
                actor_role="operator",
                status="open",
            )
    finally:
        session.close()
        fixture["jobs"].close()


def test_finding_review_concurrent_same_version_has_one_winner(
    tmp_path: Path,
) -> None:
    fixture = _active_fixture(tmp_path)
    main = fixture["session"]
    engine = main.get_bind()
    try:
        main.rollback()
        first = FindingReviewService(main, tenant_id="tenant-a").update(
            fixture["finding_id"],
            expected_version=0,
            actor_operator_id="reviewer-owner",
            actor_role="operator",
            status="in_progress",
            ownership="claim",
        )
        assert first.version == 1
        main.rollback()
        barrier = threading.Barrier(2)
        result_lock = threading.Lock()
        outcomes: list[tuple[str, str]] = []

        def update_as(actor: str) -> None:
            worker = Session(bind=engine)
            try:
                barrier.wait(timeout=5)
                projection = FindingReviewService(
                    worker,
                    tenant_id="tenant-a",
                ).update(
                    fixture["finding_id"],
                    expected_version=1,
                    actor_operator_id=actor,
                    actor_role="operator",
                    notes=f"concurrent note from {actor}",
                )
                outcome = ("success", str(projection.version))
            except FindingReviewConflict as exc:
                outcome = ("conflict", exc.reason_code)
            finally:
                worker.close()
            with result_lock:
                outcomes.append(outcome)

        workers = [
            threading.Thread(target=update_as, args=(actor,))
            for actor in ("reviewer-owner", "reviewer-peer")
        ]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=10)
            assert not worker.is_alive()
        assert sorted(kind for kind, _value in outcomes) == [
            "conflict",
            "success",
        ]
        main.expire_all()
        revisions = FindingReviewService(
            main,
            tenant_id="tenant-a",
        ).revisions(fixture["finding_id"])
        assert [int(row["version"]) for row in revisions] == [1, 2]
    finally:
        main.close()
        fixture["jobs"].close()


def test_dashboard_review_derives_actor_and_enforces_tenant_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server, app, fixture, _root = _dashboard_review_fixture(tmp_path, monkeypatch)
    try:
        token = issue_identity_token(
            "server-reviewer",
            Role.OPERATOR,
            tenant_id="tenant-a",
        )
        tenant_b_token = issue_identity_token(
            "tenant-b-reviewer",
            Role.OPERATOR,
            tenant_id="tenant-b",
        )

        async def scenario() -> tuple[httpx.Response, ...]:
            headers = {"Authorization": f"Bearer {token}"}
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app),
                base_url="http://127.0.0.1",
                headers=headers,
            ) as client, httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app),
                base_url="http://127.0.0.1",
                headers={"Authorization": f"Bearer {tenant_b_token}"},
            ) as foreign:
                forged = await client.patch(
                    f"/api/v1/findings/{fixture['finding_id']}/status",
                    json={
                        "expected_version": 0,
                        "status": "in_progress",
                        "ownership": "claim",
                        "owner_operator_id": "attacker",
                    },
                )
                updated = await client.patch(
                    f"/api/v1/findings/{fixture['finding_id']}/status",
                    json={
                        "expected_version": 0,
                        "status": "in_progress",
                        "ownership": "claim",
                        "notes": "password=TASK105_SERVER_CANARY",
                    },
                )
                stale = await client.patch(
                    f"/api/v1/findings/{fixture['finding_id']}/status",
                    json={
                        "expected_version": 0,
                        "status": "remediated",
                    },
                )
                foreign_response = await foreign.patch(
                    f"/api/v1/findings/{fixture['finding_id']}/status",
                    json={"expected_version": 1, "status": "remediated"},
                )
                refreshed = await client.get("/api/v1/findings")
                return forged, updated, stale, foreign_response, refreshed

        forged, updated, stale, foreign_response, refreshed = _run(scenario())
        assert forged.status_code == 400
        assert forged.json()["detail"]["reason_code"] == (
            "finding_review_identity_is_server_derived"
        )
        assert updated.status_code == 200, updated.text
        review = updated.json()["review"]
        assert review["owner_operator_id"] == "server-reviewer"
        assert review["updated_by_operator_id"] == "server-reviewer"
        assert review["notes"] == "password=<redacted>"
        assert "TASK105_SERVER_CANARY" not in updated.text
        assert stale.status_code == 409
        assert stale.json()["detail"]["reason_code"] == (
            "finding_review_version_conflict"
        )
        assert foreign_response.status_code == 403
        assert foreign_response.json()["detail"]["reason_code"] == (
            "dashboard_tenant_forbidden"
        )
        assert refreshed.status_code == 200
        finding = refreshed.json()["findings"][0]
        assert finding["review_owner_operator_id"] == "server-reviewer"
        assert finding["review_updated_by_operator_id"] == "server-reviewer"
        assert "TASK105_SERVER_CANARY" not in refreshed.text
    finally:
        server.event_bus.stop()
        if server._job_state_service is not None:
            server._job_state_service.close()


def test_report_source_lock_version_and_idempotency(tmp_path: Path) -> None:
    fixture, _result, _review, _retest = _prepare_retest_fixture(tmp_path)
    session = fixture["session"]
    try:
        service = CanonicalReportService(
            session,
            fixture["custody"],
            tenant_id="tenant-a",
        )
        first = _run(
            service.create_html_report(
                fixture["finding_id"],
                operator_id="operator-current",
            )
        )
        duplicate = _run(
            service.create_html_report(
                fixture["finding_id"],
                operator_id="operator-current",
            )
        )
        assert first.version == 1
        assert duplicate.duplicate is True
        assert duplicate.report_id == first.report_id
        assert duplicate.artifact_id == first.artifact_id
        assert duplicate.source_digest == first.source_digest
        assert session.execute(
            text("SELECT COUNT(*) FROM canonical_report_locks")
        ).scalar_one() == 1
        assert session.execute(
            text("SELECT COUNT(*) FROM canonical_report_sources")
        ).scalar_one() == first.source_count
        source = session.execute(
            text(
                "SELECT report_id,ordinal,observation_id,artifact_id,"
                "retest_id,retest_attempt_id,retest_proof_id,review_revision_id "
                "FROM canonical_report_sources WHERE report_id=:report_id "
                "ORDER BY ordinal"
            ),
            {"report_id": first.report_id},
        ).mappings().all()
        assert len(source) == first.source_count
        assert source[-1]["retest_id"] is not None
        assert source[-1]["retest_attempt_id"] is not None
        assert source[-1]["retest_proof_id"] is not None
        assert all(row["review_revision_id"] for row in source)
        rendered = EvidenceCustodyStore(
            fixture["custody"],
            "tenant-a",
        ).read(
            first.artifact_id,
            actor_id="operator-current",
        ).decode("utf-8")
        assert "engagement-original" in rendered
        assert "engagement-current" in rendered
    finally:
        session.close()
        fixture["jobs"].close()


def test_later_review_and_observation_changes_create_new_report_versions(
    tmp_path: Path,
) -> None:
    fixture, _result, _review, retest = _prepare_retest_fixture(tmp_path)
    session = fixture["session"]
    try:
        reports = CanonicalReportService(
            session,
            fixture["custody"],
            tenant_id="tenant-a",
        )
        first = _run(
            reports.create_html_report(
                fixture["finding_id"],
                operator_id="operator-current",
            )
        )
        session.rollback()
        review_two = FindingReviewService(
            session,
            tenant_id="tenant-a",
        ).update(
            fixture["finding_id"],
            expected_version=1,
            actor_operator_id="operator-current",
            actor_role="operator",
            notes="second reviewer note",
        )
        assert review_two.version == 2
        session.rollback()
        second = _run(
            reports.create_html_report(
                fixture["finding_id"],
                operator_id="operator-current",
            )
        )
        assert second.version == 2
        assert second.report_id != first.report_id
        assert second.source_digest != first.source_digest

        retry_authorization = _authorization(
            session,
            tenant_id="tenant-a",
            engagement_id="engagement-later",
            run_id="run-later",
            job_id="job-later",
            operator_id="operator-current",
            module_id=module_set_binding(["header_audit"]),
            target=fixture["target"],
        )
        later = _run(
            retest.execute(
                finding_id=fixture["finding_id"],
                tenant_id="tenant-a",
                authorization=retry_authorization,
                allowed_scope=("fixture.test",),
                idempotency_key="task105-report-retest-later",
            )
        )
        assert later.verdict is RetestStatus.STILL_VULNERABLE
        session.rollback()
        third = _run(
            reports.create_html_report(
                fixture["finding_id"],
                operator_id="operator-current",
            )
        )
        assert third.version == 3
        assert third.report_id != second.report_id
        assert third.source_digest != second.source_digest
    finally:
        session.close()
        fixture["jobs"].close()


def test_report_artifact_tamper_and_immutable_rows_fail_closed(tmp_path: Path) -> None:
    fixture, _result, _review, _retest = _prepare_retest_fixture(tmp_path)
    session = fixture["session"]
    export_auth: Any = None
    export_auth_session: Any = None
    try:
        service = CanonicalReportService(
            session,
            fixture["custody"],
            tenant_id="tenant-a",
        )
        report = _run(
            service.create_html_report(
                fixture["finding_id"],
                operator_id="operator-current",
            )
        )
        manifest = EvidenceCustodyStore(
            fixture["custody"],
            "tenant-a",
        ).get_manifest(report.artifact_id)
        derivative_path = fixture["custody"] / manifest.derivative_relative_path

        immutable_attempts = (
            (
                "UPDATE canonical_finding_review_revisions SET notes='x' "
                "WHERE finding_id=:finding_id",
                {"finding_id": fixture["finding_id"]},
            ),
            (
                "UPDATE canonical_report_sources SET ordinal=99 "
                "WHERE report_id=:report_id",
                {"report_id": report.report_id},
            ),
            (
                "DELETE FROM canonical_report_sources WHERE report_id=:report_id",
                {"report_id": report.report_id},
            ),
            (
                "UPDATE canonical_report_locks SET source_digest='sha256:' || printf('%064d',0) "
                "WHERE report_id=:report_id",
                {"report_id": report.report_id},
            ),
            (
                "DELETE FROM canonical_report_locks WHERE report_id=:report_id",
                {"report_id": report.report_id},
            ),
            (
                "UPDATE canonical_reports SET name='mutated' WHERE id=:report_id",
                {"report_id": report.report_id},
            ),
            (
                "DELETE FROM canonical_reports WHERE id=:report_id",
                {"report_id": report.report_id},
            ),
        )
        for statement, values in immutable_attempts:
            with pytest.raises(IntegrityError):
                session.execute(text(statement), values)
                session.commit()
            session.rollback()

        derivative_path.write_bytes(b"TASK105_REPORT_TAMPER")
        with pytest.raises(CanonicalReportAuthorizationError):
            service.export_html(
                report.report_id,
                operator_id="operator-current",
                authorization=None,  # type: ignore[arg-type]
                request_id="tamper-unauthorized",
            )
        export_auth, export_auth_session = _report_authorization(report, session)
        with pytest.raises(ArtifactIntegrityError):
            service.export_html(
                report.report_id,
                operator_id="operator-current",
                authorization=export_auth,
                request_id="tamper-authorized",
            )
    finally:
        if export_auth_session is not None:
            export_auth_session.close()
        session.close()
        fixture["jobs"].close()


def test_report_orphan_custody_artifact_is_adopted_after_crash_window(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture, _result, _review, _retest = _prepare_retest_fixture(tmp_path)
    session = fixture["session"]
    try:
        service = CanonicalReportService(
            session,
            fixture["custody"],
            tenant_id="tenant-a",
        )
        before = set(fixture["custody"].rglob("manifest.json"))

        def crash_after_custody(*_args: Any, **_kwargs: Any) -> None:
            raise RuntimeError("simulated report-lock crash window")

        with monkeypatch.context() as crash:
            crash.setattr(
                CanonicalStore,
                "persist_artifact_manifest",
                crash_after_custody,
            )
            crash.setattr(
                EvidenceCustodyStore,
                "rollback_artifact",
                lambda *_args, **_kwargs: None,
            )
            with pytest.raises(
                RuntimeError,
                match="simulated report-lock crash window",
            ):
                _run(
                    service.create_html_report(
                        fixture["finding_id"],
                        operator_id="operator-current",
                    )
                )
        session.rollback()
        orphaned = set(fixture["custody"].rglob("manifest.json")) - before
        assert len(orphaned) == 1
        assert session.execute(
            text("SELECT COUNT(*) FROM canonical_report_locks")
        ).scalar_one() == 0
        session.rollback()

        recovered = _run(
            CanonicalReportService(
                session,
                fixture["custody"],
                tenant_id="tenant-a",
            ).create_html_report(
                fixture["finding_id"],
                operator_id="operator-current",
            )
        )
        assert recovered.version == 1
        assert recovered.duplicate is False
        assert session.execute(
            text("SELECT COUNT(*) FROM canonical_report_locks")
        ).scalar_one() == 1
        assert set(fixture["custody"].rglob("manifest.json")) - before == orphaned
    finally:
        session.close()
        fixture["jobs"].close()


def test_authorized_export_receipt_hash_operator_audit_and_idempotency(
    tmp_path: Path,
) -> None:
    fixture, _result, _review, _retest = _prepare_retest_fixture(tmp_path)
    session = fixture["session"]
    auth_session: Any = None
    foreign_auth_session: Any = None
    try:
        service = CanonicalReportService(
            session,
            fixture["custody"],
            tenant_id="tenant-a",
        )
        report = _run(
            service.create_html_report(
                fixture["finding_id"],
                operator_id="operator-current",
            )
        )
        foreign_auth_session = create_db(tmp_path / "foreign-export-auth.db")
        foreign_context = _module_context(
            tenant_id=report.tenant_id,
            engagement_id=report.engagement_id,
            run_id="foreign-export-run",
            job_id="foreign-export-job",
            operator_id="operator-current",
            target=report.target,
            allowed_scope=["fixture.test"],
            module_id=report_export_binding(
                report.report_id,
                report.artifact_sha256,
            ),
            action_kind="report.export",
            engine="forge",
        )
        foreign_authorization = _consumed_authorization(
            foreign_auth_session,
            foreign_context,
            boundary="dashboard.report.export",
        )
        with pytest.raises(CanonicalReportAuthorizationError):
            service.export_html(
                report.report_id,
                operator_id="operator-current",
                authorization=foreign_authorization,
                request_id="foreign-auth-database",
            )
        authorization, auth_session = _report_authorization(report, session)
        with pytest.raises(CanonicalReportAuthorizationError):
            service.export_html(
                report.report_id,
                operator_id="operator-current",
                authorization=replace(authorization, operator_id="other-operator"),
                request_id="export-unauthorized",
            )
        exported = service.export_html(
            report.report_id,
            operator_id="operator-current",
            authorization=authorization,
            request_id="export-request-1",
        )
        repeated = service.export_html(
            report.report_id,
            operator_id="operator-current",
            authorization=authorization,
            request_id="export-request-1",
        )
        receipt = exported.receipt()
        assert receipt["outcome"] == "completed"
        assert receipt["operator_id"] == "operator-current"
        assert receipt["report_id"] == report.report_id
        assert receipt["report_version"] == report.version
        assert receipt["artifact_sha256"] == report.artifact_sha256
        assert receipt["artifact_id"] == report.artifact_id
        assert receipt["authorization_decision_id"] == authorization.decision_id
        assert receipt["authorization_action_id"] == authorization.action_id
        assert hashlib.sha256(exported.content).hexdigest() == report.artifact_sha256.removeprefix(
            "sha256:"
        )
        assert len(exported.content) == report.artifact_size
        assert repeated.duplicate is True
        assert repeated.export_id == exported.export_id
        assert repeated.content == exported.content
        assert session.execute(
            text("SELECT COUNT(*) FROM canonical_export_receipts")
        ).scalar_one() == 1
        stored = session.execute(
            text(
                "SELECT report_id,report_version,report_sha256,operator_id,"
                "authorization_decision_id,authorization_action_id,audit_event_id "
                "FROM canonical_export_receipts WHERE export_id=:export_id"
            ),
            {"export_id": exported.export_id},
        ).mappings().one()
        assert stored["report_id"] == report.report_id
        assert int(stored["report_version"]) == report.version
        assert stored["report_sha256"] == report.artifact_sha256
        assert stored["operator_id"] == "operator-current"
        assert stored["authorization_decision_id"] == authorization.decision_id
        assert stored["authorization_action_id"] == authorization.action_id
        event = session.execute(
            text(
                "SELECT actor_id,event_type,metadata_json FROM canonical_events "
                "WHERE id=:event_id"
            ),
            {"event_id": exported.audit_event_id},
        ).mappings().one()
        assert event["actor_id"] == "operator-current"
        assert event["event_type"] == "report.export.completed"
        assert json.loads(str(event["metadata_json"])) == {
            "format": "html",
            "outcome": "completed",
        }
        for statement in (
            "UPDATE canonical_export_receipts SET format='html' "
            "WHERE export_id=:export_id",
            "DELETE FROM canonical_export_receipts WHERE export_id=:export_id",
            "UPDATE canonical_exports SET status='completed' WHERE id=:export_id",
            "DELETE FROM canonical_exports WHERE id=:export_id",
            "UPDATE canonical_events SET level='warning' WHERE id=:event_id",
            "DELETE FROM canonical_events WHERE id=:event_id",
        ):
            with pytest.raises(IntegrityError):
                session.execute(
                    text(statement),
                    {
                        "export_id": exported.export_id,
                        "event_id": exported.audit_event_id,
                    },
                )
                session.commit()
            session.rollback()
    finally:
        if foreign_auth_session is not None:
            foreign_auth_session.close()
        if auth_session is not None:
            auth_session.close()
        session.close()
        fixture["jobs"].close()


def test_two_tenants_never_share_slice_lineage_workflow_or_artifacts(
    tmp_path: Path,
) -> None:
    database = tmp_path / "two-tenant-reference.db"
    custody_root = tmp_path / "two-tenant-custody"
    session = create_db(database)
    jobs = JobStateService(
        database,
        authorization_checker=lambda *_args: True,
    )
    target = "https://fixture.test/account"
    collected: dict[str, dict[str, Any]] = {}

    async def fetch_missing(target_value: str, *_args: Any) -> HeaderResponse:
        return HeaderResponse(200, {}, target_value)

    try:
        for tenant in ("tenant-isolation-a", "tenant-isolation-b"):
            suffix = tenant.rsplit("-", 1)[-1]
            original = _authorization(
                session,
                tenant_id=tenant,
                engagement_id=f"engagement-original-{suffix}",
                run_id=f"run-original-{suffix}",
                job_id=f"job-original-{suffix}",
                operator_id=f"operator-{suffix}",
                module_id="header_audit",
                target=target,
                consume_boundary="webforge.module",
            )
            job = jobs.create_job(
                tenant_id=tenant,
                job_id=original.job_id,
                engagement_id=original.engagement_id,
                run_id=original.run_id,
                job_kind="webforge",
                target=target,
                authorization_decision_id=original.decision_id,
                authorization_action_id=original.action_id,
                state="queued",
                work_items=("header_audit",),
            )
            attempt = jobs.acquire_lease(
                str(job["id"]),
                f"worker-{suffix}",
                tenant_id=tenant,
                attempt_id=f"attempt-original-{suffix}",
                idempotency_key=f"attempt-key-{suffix}",
            )
            jobs.start_attempt(
                str(attempt["id"]),
                str(attempt["lease_token"]),
                tenant_id=tenant,
                worker_id=f"worker-{suffix}",
            )
            finding = Finding(
                title="Security Header Missing: Content-Security-Policy",
                severity=Severity.MEDIUM,
                target=target,
                url=target,
                module="header_audit",
                description="Tenant-isolated CSP proof.",
                reproduction_steps=["GET /account"],
                remediation="Configure a restrictive CSP.",
                references=["CWE-1021"],
                confidence="HIGH",
                proof_type="passive",
                verification_state="verified",
                maturity="stable",
                evidence=Evidence(
                    request_raw=(
                        "GET /account HTTP/1.1\r\nHost: fixture.test\r\n"
                    ),
                    response_raw="HTTP/1.1 200 OK\r\n",
                    extra={
                        "header": HEADER_CSP_CHECK_ID,
                        "value": None,
                        "issue": "Missing",
                        "route": "/account",
                        "check_id": HEADER_CSP_CHECK_ID,
                    },
                ),
            )
            session.rollback()
            projection = CanonicalEvidenceService(
                session,
                custody_root,
                CanonicalEvidenceContext.from_authorization(
                    original,
                    attempt_id=str(attempt["id"]),
                ),
            ).persist_finding(finding)
            current = _authorization(
                session,
                tenant_id=tenant,
                engagement_id=f"engagement-current-{suffix}",
                run_id=f"run-current-{suffix}",
                job_id=f"job-current-{suffix}",
                operator_id=f"operator-{suffix}",
                module_id=module_set_binding(["header_audit"]),
                target=target,
            )
            retest = _run(
                RetestService(
                    session,
                    custody_root,
                    jobs,
                    authorization_loader=lambda decision_id, original=original: (
                        original
                        if decision_id == original.decision_id
                        else None
                    ),
                    outbound_policy_factory=lambda *_args: object(),
                    header_verifier=HeaderAuditCspVerifier(
                        fetcher=fetch_missing
                    ),
                ).execute(
                    finding_id=str(projection["id"]),
                    tenant_id=tenant,
                    authorization=current,
                    allowed_scope=("fixture.test",),
                    idempotency_key=f"tenant-retest-{suffix}",
                )
            )
            assert retest.verdict is RetestStatus.STILL_VULNERABLE
            session.rollback()
            review = FindingReviewService(
                session,
                tenant_id=tenant,
            ).update(
                str(projection["id"]),
                expected_version=0,
                actor_operator_id=f"operator-{suffix}",
                actor_role="operator",
                status="in_progress",
                notes=f"tenant note {suffix}",
                ownership="claim",
            )
            session.rollback()
            report = _run(
                CanonicalReportService(
                    session,
                    custody_root,
                    tenant_id=tenant,
                ).create_html_report(
                    str(projection["id"]),
                    operator_id=f"operator-{suffix}",
                )
            )
            export_context = _module_context(
                tenant_id=tenant,
                engagement_id=report.engagement_id,
                run_id=f"run-export-{suffix}",
                job_id=f"job-export-{suffix}",
                operator_id=f"operator-{suffix}",
                target=target,
                allowed_scope=["fixture.test"],
                module_id=report_export_binding(
                    report.report_id,
                    report.artifact_sha256,
                ),
                action_kind="report.export",
                engine="forge",
            )
            export_authorization = _consumed_authorization(
                session,
                export_context,
                boundary="dashboard.report.export",
            )
            exported = CanonicalReportService(
                session,
                custody_root,
                tenant_id=tenant,
            ).export_html(
                report.report_id,
                operator_id=f"operator-{suffix}",
                authorization=export_authorization,
                request_id=f"export-request-{suffix}",
            )
            collected[tenant] = {
                "artifact_id": report.artifact_id,
                "attempt_id": str(attempt["id"]),
                "event_id": exported.audit_event_id,
                "export_id": exported.export_id,
                "finding_id": str(projection["id"]),
                "job_id": str(job["id"]),
                "note": review.notes,
                "observation_id": str(
                    projection["evidence"]["observations"][0][
                        "observation_id"
                    ]
                ),
                "report_id": report.report_id,
            }
            session.rollback()

        left = collected["tenant-isolation-a"]
        right = collected["tenant-isolation-b"]
        for field in (
            "artifact_id",
            "attempt_id",
            "event_id",
            "export_id",
            "finding_id",
            "job_id",
            "observation_id",
            "report_id",
        ):
            assert left[field] != right[field]
        assert left["note"] == "tenant note a"
        assert right["note"] == "tenant note b"
        with pytest.raises(FindingReviewNotFound):
            FindingReviewService(
                session,
                tenant_id="tenant-isolation-a",
            ).get(str(right["finding_id"]))
        session.rollback()
        with pytest.raises(CanonicalReportNotFound):
            CanonicalReportService(
                session,
                custody_root,
                tenant_id="tenant-isolation-a",
            ).get_report(str(right["report_id"]))
        session.rollback()
        manifests = list(custody_root.rglob("manifest.json"))
        assert manifests
        tenant_directories = {
            path.relative_to(custody_root).parts[1]
            for path in manifests
        }
        assert len(tenant_directories) == 2
    finally:
        session.close()
        jobs.close()


def test_task105_schema_tables_empty_downgrade_and_reupgrade(tmp_path: Path) -> None:
    session = create_db(tmp_path / "task105-migration-empty.db")
    try:
        manager = MigrationManager(session.get_bind())
        expected = {
            "canonical_finding_review_revisions",
            "canonical_finding_review_current",
            "canonical_report_sources",
            "canonical_report_locks",
            "canonical_export_receipts",
        }
        assert expected <= _migration_table_names(session)
        assert REFERENCE_SLICE_SCHEMA_VERSION in manager.versions
        assert manager.downgrade(target=RETEST_SCHEMA_VERSION) == "forge-canonical-v1"
        assert not expected.intersection(_migration_table_names(session))
        assert manager.upgrade(target=REFERENCE_SLICE_SCHEMA_VERSION) == "forge-canonical-v1"
        assert expected <= _migration_table_names(session)
        for table in expected:
            assert session.execute(text(f"SELECT COUNT(*) FROM {table}")).scalar_one() == 0
        assert manager.journal()[-1]["version"] == REFERENCE_SLICE_SCHEMA_VERSION
        assert manager.journal()[-1]["state"] == "applied"
    finally:
        session.close()


def test_task105_nonempty_downgrade_blocks_and_wrong_lineage_guards(
    tmp_path: Path,
) -> None:
    fixture, _result, _review, _retest = _prepare_retest_fixture(tmp_path)
    session = fixture["session"]
    try:
        report = _run(
            CanonicalReportService(
                session,
                fixture["custody"],
                tenant_id="tenant-a",
            ).create_html_report(
                fixture["finding_id"],
                operator_id="operator-current",
            )
        )
        manager = MigrationManager(session.get_bind())
        with pytest.raises(MigrationError, match="reference-slice downgrade would destroy retained history"):
            manager.downgrade(target=RETEST_SCHEMA_VERSION)
        assert manager.current_version() == "forge-canonical-v1"

        source = session.execute(
            text(
                "SELECT * FROM canonical_report_sources WHERE report_id=:report_id "
                "ORDER BY ordinal LIMIT 1"
            ),
            {"report_id": report.report_id},
        ).mappings().one()
        columns = (
            "tenant_id,report_id,ordinal,schema_version,engagement_id,finding_id,"
            "job_id,observation_id,artifact_id,retest_id,retest_attempt_id,"
            "retest_proof_id,review_revision_id,created_at"
        )
        values = {
            "tenant_id": "tenant-a",
            "report_id": report.report_id,
            "ordinal": 999,
            "schema_version": REFERENCE_SLICE_SCHEMA_VERSION,
            "engagement_id": source["engagement_id"],
            "finding_id": source["finding_id"],
            "job_id": source["job_id"],
            "observation_id": source["observation_id"],
            "artifact_id": source["artifact_id"],
            "retest_id": source["retest_id"],
            "retest_attempt_id": source["retest_attempt_id"],
            "retest_proof_id": source["retest_proof_id"],
            "review_revision_id": "review-revision:wrong-lineage",
            "created_at": source["created_at"],
        }
        with pytest.raises(IntegrityError):
            session.execute(
                text(f"INSERT INTO canonical_report_sources({columns}) VALUES ("
                     + ",".join(f":{column}" for column in columns.split(","))
                     + ")"),
                values,
            )
            session.commit()
        session.rollback()
        with pytest.raises(IntegrityError):
            session.execute(
                text(
                    "INSERT INTO canonical_finding_review_current "
                    "(tenant_id,finding_id,revision_id,schema_version,version,status,"
                    "owner_operator_id,notes,updated_by_operator_id,updated_at) "
                    "VALUES ('tenant-a',:finding_id,'review-revision:wrong-lineage',"
                    ":schema_version,99,'open',NULL,'','operator-current',:created_at)"
                ),
                {
                    "finding_id": fixture["finding_id"],
                    "schema_version": REFERENCE_SLICE_SCHEMA_VERSION,
                    "created_at": source["created_at"],
                },
            )
            session.commit()
        session.rollback()
    finally:
        session.close()
        fixture["jobs"].close()


def test_task105_interrupted_migration_recovers_exact_tables(tmp_path: Path) -> None:
    session = create_db(tmp_path / "task105-migration-interrupted.db")
    try:
        manager = MigrationManager(session.get_bind())
        manager.downgrade(target=RETEST_SCHEMA_VERSION)
        with pytest.raises(MigrationInterruptedError):
            manager.upgrade(target=REFERENCE_SLICE_SCHEMA_VERSION, fail_after=0)
        journal = manager.journal()
        assert journal[-1]["version"] == REFERENCE_SLICE_SCHEMA_VERSION
        assert journal[-1]["state"] == "failed"
        assert "canonical_finding_review_revisions" in _migration_table_names(session)
        assert manager.recover() == "forge-canonical-v1"
        recovered = manager.journal()
        assert recovered[-1]["state"] == "applied"
        assert {
            "canonical_finding_review_revisions",
            "canonical_finding_review_current",
            "canonical_report_sources",
            "canonical_report_locks",
            "canonical_export_receipts",
        } <= _migration_table_names(session)
    finally:
        session.close()


def test_reference_launch_exact_plan_idempotency_and_invalid_scope_no_lease(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FORGE_TENANT_ID", "tenant-launch")
    state_root = tmp_path / "launch-state"
    state_root.mkdir(mode=0o700)
    state_root.chmod(0o700)
    monkeypatch.setenv("FORGE_DASHBOARD_STATE_DIR", str(state_root))
    server = DashboardServer(event_bus=EventBus(run_id="task105-launch"))
    app = server.create_app()
    token = issue_identity_token(
        "launch-operator",
        Role.OPERATOR,
        tenant_id="tenant-launch",
    )
    target = "https://fixture.test/account"
    body = {
        "job_id": "task105-launch-correlation",
        "target": target,
        "scope": ["fixture.test"],
        "exclude": [],
        "mode": "blackbox",
        "modules": ["header_audit"],
        "intensity": 0,
        "schedule": "now",
        "dry_run": True,
        "reference_slice": "header-audit-csp-v1",
    }

    async def scenario() -> tuple[httpx.Response, ...]:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://127.0.0.1",
            headers={"Authorization": f"Bearer {token}"},
        ) as client:
            planned = await client.post("/api/v1/scans/launch", json=body)
            wrong_modules = await client.post(
                "/api/v1/scans/launch",
                json={**body, "modules": ["header_audit", "xss"]},
            )
            wrong_intensity = await client.post(
                "/api/v1/scans/launch",
                json={**body, "intensity": 1},
            )
            invalid_scope = await client.post(
                "/api/v1/scans/launch",
                json={
                    **body,
                    "dry_run": False,
                    "scope": ["other.fixture.test"],
                    "confirmation": ActionConfirmation.create(
                        job_id=body["job_id"],
                        target=target,
                        engine="webforge",
                        action="scan",
                    ).to_dict(),
                },
            )
            missing_approval = await client.post(
                "/api/v1/scans/launch",
                json={**body, "dry_run": False},
            )
            invalid_approval = await client.post(
                "/api/v1/scans/launch",
                json={
                    **body,
                    "dry_run": False,
                    "confirmation": ActionConfirmation.create(
                        job_id=body["job_id"],
                        target="https://other.fixture.test/account",
                        engine="webforge",
                        action="scan",
                    ).to_dict(),
                },
            )
            return (
                planned,
                wrong_modules,
                wrong_intensity,
                invalid_scope,
                missing_approval,
                invalid_approval,
            )

    try:
        (
            planned,
            wrong_modules,
            wrong_intensity,
            invalid_scope,
            missing_approval,
            invalid_approval,
        ) = _run(scenario())
        assert planned.status_code == 200, planned.text
        planned_data = planned.json()
        assert planned_data["status"] == "planned"
        assert planned_data["requested_modules"] == ["header_audit"]
        assert planned_data["actual_modules"] == ["header_audit"]
        assert planned_data["scan_type"] == "web"
        assert planned_data["actions"][0]["decision"]["allowed"] is True
        assert planned_data["actions"][0]["decision"]["normalized_target"] == "fixture.test"
        assert server._reference_slice_job_id(body["job_id"]) == server._reference_slice_job_id(
            body["job_id"]
        )
        assert server._reference_slice_job_id(body["job_id"]) != server._reference_slice_job_id(
            "task105-other-correlation"
        )
        assert wrong_modules.status_code == 400
        assert wrong_modules.json()["detail"]["reason_code"] == (
            "reference_slice_exact_plan_required"
        )
        assert wrong_intensity.status_code == 400
        assert wrong_intensity.json()["detail"]["reason_code"] == (
            "reference_slice_must_be_passive"
        )
        assert invalid_scope.status_code == 403
        assert missing_approval.status_code == 403
        assert invalid_approval.status_code == 403
        assert server._active_scans == {}
        assert server._durable_job_state().list_jobs(tenant_id="tenant-launch") == []
        state = create_db(server._scan_jobs_db_path)
        try:
            assert state.execute(
                text("SELECT COUNT(*) FROM durable_job_state_leases")
            ).scalar_one() == 0
        finally:
            state.close()
    finally:
        if server._job_state_service is not None:
            server._job_state_service.close()
        server.event_bus.stop()


def _live_run_truth_environment(tmp_path: Path) -> dict[str, str]:
    """Create one owner-only Ed25519 run-truth key for a real child process."""

    private_key = Ed25519PrivateKey.generate()
    key_file = tmp_path / "live-run-truth-signing.key"
    key_file.write_bytes(base64.b64encode(private_key.private_bytes_raw()))
    key_file.chmod(0o600)
    public_key = base64.b64encode(
        private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode("ascii")
    return {
        RUN_TRUTH_POLICY_ID_ENV: "forge-run-coverage-v1",
        RUN_TRUTH_POLICY_VERSION_ENV: "1.0",
        RUN_TRUTH_ISSUER_ID_ENV: "task105-live-issuer",
        RUN_TRUTH_PUBLIC_KEY_ENV: public_key,
        RUN_TRUTH_PRIVATE_KEY_FILE_ENV: str(key_file),
        RUN_TRUTH_AUTHORITY_ID_ENV: "task105-live-authority",
    }


class _MissingCspHandler(http.server.BaseHTTPRequestHandler):
    """Local inert HTTP fixture: one HTML response with no CSP header."""

    protocol_version = "HTTP/1.1"
    requests: list[str] = []
    requests_lock = threading.Lock()
    strong_csp = False
    delay_seconds = 0.0

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler hook
        with self.requests_lock:
            self.requests.append(self.path)
        if self.delay_seconds:
            time.sleep(self.delay_seconds)
        body = b"<html><body>task105-live-loopback</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "strict-origin")
        self.send_header(
            "Permissions-Policy",
            "camera=(), microphone=()",
        )
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Embedder-Policy", "require-corp")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        if self.strong_csp:
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; object-src 'none'",
            )
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            return

    def log_message(self, _format: str, *_args: Any) -> None:
        return


def _start_missing_csp_fixture() -> tuple[http.server.ThreadingHTTPServer, threading.Thread]:
    """Start an in-process loopback server and return its owned thread."""

    _MissingCspHandler.requests.clear()
    _MissingCspHandler.strong_csp = False
    _MissingCspHandler.delay_seconds = 0.0
    fixture = http.server.ThreadingHTTPServer(
        ("127.0.0.1", 0),
        _MissingCspHandler,
    )
    fixture.daemon_threads = True
    thread = threading.Thread(
        target=fixture.serve_forever,
        name="task105-loopback-fixture",
        daemon=True,
    )
    thread.start()
    return fixture, thread


def _await_live_terminal_job(
    server: DashboardServer,
    scan_id: str,
    *,
    timeout_seconds: float = 60.0,
) -> dict[str, Any]:
    """Poll Task 103 directly until the child and delivery are truly terminal."""

    terminal_states = {
        "completed",
        "partial",
        "failed",
        "canceled",
        "orphaned",
    }
    deadline = time.monotonic() + timeout_seconds
    last_state = ""
    while time.monotonic() < deadline:
        current = server._durable_job_state().get_job(
            scan_id,
            tenant_id=server.tenant_id,
        )
        if current is not None:
            last_state = str(current.get("state") or "")
            if last_state in terminal_states:
                return current
        time.sleep(0.05)
    raise AssertionError(
        f"live reference job did not reach a terminal state (last={last_state!r})"
    )


def test_live_reference_launch_popen_terminal_lineage_and_api_truth(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exercise the signed subprocess path against one local missing-CSP response."""

    monkeypatch.setenv("FORGE_TENANT_ID", "tenant-live-reference")
    state_root = tmp_path / "live-dashboard-state"
    state_root.mkdir(mode=0o700)
    state_root.chmod(0o700)
    monkeypatch.setenv("FORGE_DASHBOARD_STATE_DIR", str(state_root))
    signer_environment = _live_run_truth_environment(tmp_path)
    for key, value in signer_environment.items():
        monkeypatch.setenv(key, value)
    # The parent-side Task 103 verifier resolves its trust root from the
    # module policy; keep that policy byte-equivalent to the child env key.
    monkeypatch.setattr(
        "common.run_truth.RUN_TRUTH_POLICY",
        RunTruthPolicy(
            policy_id=signer_environment[RUN_TRUTH_POLICY_ID_ENV],
            policy_version=signer_environment[RUN_TRUTH_POLICY_VERSION_ENV],
            issuer_id=signer_environment[RUN_TRUTH_ISSUER_ID_ENV],
            issuer_public_key=signer_environment[RUN_TRUTH_PUBLIC_KEY_ENV],
        ),
    )

    fixture_server, fixture_thread = _start_missing_csp_fixture()
    server: DashboardServer | None = None
    central_session: Any = None
    try:
        port = int(fixture_server.server_address[1])
        target = f"http://127.0.0.1:{port}/account"
        server = DashboardServer(event_bus=EventBus(run_id="task105-live"))
        # The child does not need an HTTP event relay for this ASGI test. An
        # empty URL still exercises the real dashboard launch and Popen path,
        # while keeping all sockets inside the local fixture boundary.
        monkeypatch.setattr(server, "_dashboard_public_url", lambda _request: "")
        app = server.create_app()
        server.event_bus.start()
        token = issue_identity_token(
            "live-operator",
            Role.OPERATOR,
            tenant_id="tenant-live-reference",
        )
        client_job_id = "task105-live-reference"
        confirmation = ActionConfirmation.create(
            job_id=client_job_id,
            target=target,
            engine="webforge",
            action="scan",
        ).to_dict()
        body = {
            "job_id": client_job_id,
            "target": target,
            "scope": ["127.0.0.1/32"],
            "exclude": [],
            "mode": "blackbox",
            "modules": ["header_audit"],
            "intensity": 0,
            "schedule": "now",
            "dry_run": False,
            "reference_slice": "header-audit-csp-v1",
            "timeout": 30,
            "confirmation": confirmation,
        }

        async def launch_twice() -> tuple[httpx.Response, httpx.Response]:
            headers = {"Authorization": f"Bearer {token}"}
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app),
                base_url="http://127.0.0.1",
                headers=headers,
            ) as client:
                first = await client.post("/api/v1/scans/launch", json=body)
                second = await client.post("/api/v1/scans/launch", json=body)
                return first, second

        first, second = _run(launch_twice())
        assert first.status_code == 200, first.text
        assert second.status_code == 200, second.text
        first_data = first.json()
        second_data = second.json()
        scan_id = str(first_data["scan_id"])
        assert first_data["status"] == "launched"
        assert first_data["reference_slice"] == "header-audit-csp-v1"
        assert first_data["requested_modules"] == ["header_audit"]
        assert first_data["actual_modules"] == ["header_audit"]
        assert first_data["duplicate"] is False
        assert second_data["duplicate"] is True
        assert second_data["scan_id"] == scan_id
        assert second_data["client_job_id"] == client_job_id

        # Do not use GET /scans/{id} as the wait condition: a transient read
        # snapshot must never turn a live Task 103 row into legacy orphaned UI.
        terminal = _await_live_terminal_job(server, scan_id)
        assert terminal["state"] == "completed"

        process = server._active_scans[f"{scan_id}_web"]["proc"]
        assert process.poll() == 0
        if process.stdout is not None and not process.stdout.closed:
            process.stdout.close()
        assert len(_MissingCspHandler.requests) == 1
        assert _MissingCspHandler.requests == ["/account"]

        central_session = create_db(server._scan_jobs_db_path)
        job_rows = central_session.execute(
            text(
                "SELECT * FROM durable_job_state_jobs "
                "WHERE tenant_id=:tenant_id AND id=:job_id"
            ),
            {"tenant_id": server.tenant_id, "job_id": scan_id},
        ).mappings().all()
        assert len(job_rows) == 1
        job_row = job_rows[0]
        attempt_rows = central_session.execute(
            text(
                "SELECT * FROM durable_job_state_attempts "
                "WHERE tenant_id=:tenant_id AND job_id=:job_id"
            ),
            {"tenant_id": server.tenant_id, "job_id": scan_id},
        ).mappings().all()
        assert len(attempt_rows) == 1
        attempt = attempt_rows[0]
        attempt_id = str(attempt["id"])
        assert attempt["state"] == "completed"
        assert int(job_row["required_work"]) == 1
        assert int(job_row["completed_work"]) == 1
        assert int(job_row["skipped_work"]) == 0
        assert int(job_row["failed_work"]) == 0

        lease_rows = central_session.execute(
            text(
                "SELECT * FROM durable_job_state_leases "
                "WHERE tenant_id=:tenant_id AND attempt_id=:attempt_id"
            ),
            {"tenant_id": server.tenant_id, "attempt_id": attempt_id},
        ).mappings().all()
        assert len(lease_rows) == 1
        assert lease_rows[0]["revoked_at"] is not None
        work_rows = central_session.execute(
            text(
                "SELECT work_key,state,attempt_id,observation_id "
                "FROM durable_job_state_work_items "
                "WHERE tenant_id=:tenant_id AND job_id=:job_id"
            ),
            {"tenant_id": server.tenant_id, "job_id": scan_id},
        ).mappings().all()
        assert len(work_rows) == 1
        assert dict(work_rows[0])["work_key"] == "webforge"
        assert dict(work_rows[0])["state"] == "completed"

        delivery = central_session.execute(
            text(
                "SELECT * FROM durable_job_state_deliveries "
                "WHERE tenant_id=:tenant_id AND job_id=:job_id "
                "AND attempt_id=:attempt_id"
            ),
            {
                "tenant_id": server.tenant_id,
                "job_id": scan_id,
                "attempt_id": attempt_id,
            },
        ).mappings().all()
        assert len(delivery) == 1
        assert delivery[0]["state"] == "accepted"
        proofs = central_session.execute(
            text(
                "SELECT proof_type,outcome,coverage_identity,result_ref "
                "FROM durable_job_state_terminal_proofs "
                "WHERE tenant_id=:tenant_id AND job_id=:job_id "
                "AND attempt_id=:attempt_id ORDER BY proof_type"
            ),
            {
                "tenant_id": server.tenant_id,
                "job_id": scan_id,
                "attempt_id": attempt_id,
            },
        ).mappings().all()
        assert {str(row["proof_type"]) for row in proofs} == {
            "observation_receipt",
            "run_truth",
        }
        assert all(row["outcome"] == "success" for row in proofs)

        observations = central_session.execute(
            text(
                "SELECT id,job_id,attempt_id,check_id,route,proof_type,status "
                "FROM canonical_observations WHERE tenant_id=:tenant_id "
                "AND job_id=:job_id AND attempt_id=:attempt_id "
                "AND check_id='Content-Security-Policy'"
            ),
            {
                "tenant_id": server.tenant_id,
                "job_id": scan_id,
                "attempt_id": attempt_id,
            },
        ).mappings().all()
        assert len(observations) == 1
        observation = observations[0]
        assert observation["job_id"] == scan_id
        assert observation["attempt_id"] == attempt_id
        assert observation["route"] == "/account"
        assert observation["proof_type"] == "passive"
        assert observation["status"] == "observed"

        finding_rows = central_session.execute(
            text(
                "SELECT f.id,f.title,f.observation_id,f.artifact_id "
                "FROM canonical_findings f WHERE f.tenant_id=:tenant_id "
                "AND f.observation_id=:observation_id"
            ),
            {
                "tenant_id": server.tenant_id,
                "observation_id": str(observation["id"]),
            },
        ).mappings().all()
        assert len(finding_rows) == 1
        finding_id = str(finding_rows[0]["id"])
        assert "Content-Security-Policy" in str(finding_rows[0]["title"])
        artifact_rows = central_session.execute(
            text(
                "SELECT m.metadata_json FROM canonical_artifact_manifests m "
                "JOIN canonical_observation_artifacts oa "
                "ON oa.tenant_id=m.tenant_id AND oa.artifact_id=m.artifact_id "
                "AND oa.observation_id=m.observation_id "
                "WHERE m.tenant_id=:tenant_id AND m.observation_id=:observation_id "
                "ORDER BY oa.sequence"
            ),
            {
                "tenant_id": server.tenant_id,
                "observation_id": str(observation["id"]),
            },
        ).mappings().all()
        assert sorted(
            str(json.loads(str(row["metadata_json"])).get("capture_kind"))
            for row in artifact_rows
        ) == ["request", "response", "structured_proof"]
        assert central_session.execute(
            text("PRAGMA integrity_check")
        ).scalar_one() == "ok"

        async def refresh_api() -> tuple[httpx.Response, httpx.Response]:
            headers = {"Authorization": f"Bearer {token}"}
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app),
                base_url="http://127.0.0.1",
                headers=headers,
            ) as client:
                findings_response = await client.get("/api/v1/findings")
                detail_response = await client.get(f"/api/v1/scans/{scan_id}")
                return findings_response, detail_response

        findings_response, detail_response = _run(refresh_api())
        assert findings_response.status_code == 200, findings_response.text
        assert detail_response.status_code == 200, detail_response.text
        finding_payload = findings_response.json()["findings"]
        assert len(finding_payload) == 1
        assert finding_payload[0]["id"] == finding_id
        detail = detail_response.json()
        assert detail["status"] == "completed"
        assert detail["lifecycle_authority"] == "task103"
        assert detail["findings_count"]["total"] == 1
        assert detail["findings"][0]["id"] == finding_id

        central_session.rollback()
        central_session.close()
        central_session = None
        review_canary = "TASK105_LIVE_REVIEW_SECRET"
        retest_client_job_id = "task105-live-reference-retest"
        retest_confirmation = ActionConfirmation.create(
            job_id=retest_client_job_id,
            target=target,
            engine="webforge",
            action="retest",
        ).to_dict()

        async def finish_operator_workflow() -> tuple[httpx.Response, ...]:
            headers = {"Authorization": f"Bearer {token}"}
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app),
                base_url="http://127.0.0.1",
                headers=headers,
            ) as client:
                review = await client.patch(
                    f"/api/v1/findings/{finding_id}/status",
                    json={
                        "expected_version": 0,
                        "status": "in_progress",
                        "ownership": "claim",
                        "notes": f"password={review_canary}",
                    },
                )
                retest = await client.post(
                    f"/api/v1/findings/{finding_id}/retest",
                    json={
                        "job_id": retest_client_job_id,
                        "scope": ["127.0.0.1/32"],
                        "exclude": [],
                        "dry_run": False,
                        "confirmation": retest_confirmation,
                    },
                )
                report = await client.post(
                    "/api/v1/reports",
                    json={"finding_id": finding_id, "format": "html"},
                )
                denied_export = await client.get(
                    "/api/v1/reports/download",
                    params={"fmt": "html"},
                )
                assert report.status_code == 200, report.text
                report_data = report.json()["report"]
                export_client_job_id = "task105-live-reference-export"
                export_confirmation = ActionConfirmation.create(
                    job_id=export_client_job_id,
                    target=target,
                    engine="forge",
                    action="report.export",
                ).to_dict()
                exported = await client.post(
                    "/api/v1/reports/download",
                    json={
                        "job_id": export_client_job_id,
                        "report_id": report_data["report_id"],
                        "format": "html",
                        "scope": ["127.0.0.1/32"],
                        "exclude": [],
                        "confirmation": export_confirmation,
                    },
                )
                refreshed_findings = await client.get("/api/v1/findings")
                refreshed_reports = await client.get("/api/v1/reports")
                return (
                    review,
                    retest,
                    report,
                    denied_export,
                    exported,
                    refreshed_findings,
                    refreshed_reports,
                )

        (
            review_response,
            retest_response,
            report_response,
            denied_export_response,
            export_response,
            refreshed_findings_response,
            refreshed_reports_response,
        ) = _run(finish_operator_workflow())
        assert review_response.status_code == 200, review_response.text
        review = review_response.json()["review"]
        assert review["version"] == 1
        assert review["status"] == "in_progress"
        assert review["owner_operator_id"] == "live-operator"
        assert review["updated_by_operator_id"] == "live-operator"
        assert review["notes"] == "password=<redacted>"
        assert review_canary not in review_response.text

        assert retest_response.status_code == 200, retest_response.text
        retest = retest_response.json()
        assert retest["state"] == "terminal"
        assert retest["retest_verdict"] == "still_vulnerable"
        assert retest["verdict_authority"] == "canonical_retest_proof"
        assert retest["retest_id"]
        assert retest["retest_attempt_id"]
        assert retest["observation_id"]
        assert retest["artifact_id"]
        assert len(_MissingCspHandler.requests) == 2

        assert report_response.status_code == 200, report_response.text
        report = report_response.json()["report"]
        assert report["status"] == "locked"
        assert report["version"] == 1
        assert report["source_count"] >= 4
        assert report["artifact_sha256"].startswith("sha256:")
        assert denied_export_response.status_code == 403
        assert denied_export_response.json()["reason_code"] == (
            "report_export_action_authorization_required"
        )
        assert export_response.status_code == 200, export_response.text
        exported_html = export_response.content
        assert hashlib.sha256(exported_html).hexdigest() == report[
            "artifact_sha256"
        ].removeprefix("sha256:")
        assert export_response.headers["x-forge-report-id"] == report["report_id"]
        assert export_response.headers["x-forge-report-version"] == "1"
        assert export_response.headers["x-forge-export-id"]
        rendered = exported_html.decode("utf-8")
        assert "Content-Security-Policy" in rendered
        assert finding_id in rendered
        assert review_canary not in rendered

        assert refreshed_findings_response.status_code == 200
        refreshed = refreshed_findings_response.json()["findings"]
        assert len(refreshed) == 1
        assert refreshed[0]["id"] == finding_id
        assert refreshed[0]["review_version"] == 1
        assert refreshed[0]["review_status"] == "in_progress"
        assert refreshed[0]["status"] == "in_progress"
        assert refreshed[0]["retest_verdict"] == "still_vulnerable"
        assert refreshed[0]["retest_id"] == retest["retest_id"]
        assert review_canary not in refreshed_findings_response.text
        assert refreshed_reports_response.status_code == 200
        reports = refreshed_reports_response.json()["reports"]
        assert len(reports) == 1
        assert reports[0]["report_id"] == report["report_id"]
        assert reports[0]["artifact_sha256"] == report["artifact_sha256"]

        central_session = open_existing_db(server._scan_jobs_db_path)
        audit_actions = {
            str(row[0])
            for row in central_session.execute(
                text(
                    "SELECT action FROM audit_logs WHERE tenant_id=:tenant_id"
                ),
                {"tenant_id": server.tenant_id},
            ).all()
        }
        assert {
            "scan.launch",
            "finding.review",
            "finding.retest",
            "report.lock",
            "report.export",
        } <= audit_actions
        assert review_canary not in json.dumps(
            [
                dict(row)
                for row in central_session.execute(
                    text(
                        "SELECT * FROM audit_logs WHERE tenant_id=:tenant_id"
                    ),
                    {"tenant_id": server.tenant_id},
                ).mappings().all()
            ],
            default=str,
        )
        event_history = [
            event.to_json()
            for event in server.event_bus.get_history(limit=10_000)
        ]
        assert event_history
        assert review_canary not in "\n".join(event_history)
        central_session.rollback()
        central_session.close()
        central_session = None

        repeat_client_job_id = "task105-live-reference-repeat"
        repeat_body = {
            **body,
            "job_id": repeat_client_job_id,
            "confirmation": ActionConfirmation.create(
                job_id=repeat_client_job_id,
                target=target,
                engine="webforge",
                action="scan",
            ).to_dict(),
        }

        async def launch_repeat_and_lock_next_version() -> tuple[httpx.Response, ...]:
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app),
                base_url="http://127.0.0.1",
                headers={"Authorization": f"Bearer {token}"},
            ) as client:
                repeated = await client.post(
                    "/api/v1/scans/launch",
                    json=repeat_body,
                )
                return (repeated,)

        (repeat_response,) = _run(launch_repeat_and_lock_next_version())
        assert repeat_response.status_code == 200, repeat_response.text
        repeat_scan_id = str(repeat_response.json()["scan_id"])
        assert _await_live_terminal_job(server, repeat_scan_id)["state"] == (
            "completed"
        )
        assert len(_MissingCspHandler.requests) == 3

        async def lock_second_report() -> tuple[httpx.Response, httpx.Response]:
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app),
                base_url="http://127.0.0.1",
                headers={"Authorization": f"Bearer {token}"},
            ) as client:
                next_report = await client.post(
                    "/api/v1/reports",
                    json={"finding_id": finding_id, "format": "html"},
                )
                findings = await client.get("/api/v1/findings")
                return next_report, findings

        second_report_response, repeat_findings_response = _run(
            lock_second_report()
        )
        assert second_report_response.status_code == 200
        second_report = second_report_response.json()["report"]
        assert second_report["version"] == 2
        assert second_report["report_id"] != report["report_id"]
        assert second_report["source_digest"] != report["source_digest"]
        assert second_report["artifact_sha256"] != report["artifact_sha256"]
        repeated_findings = repeat_findings_response.json()["findings"]
        assert len(repeated_findings) == 1
        assert repeated_findings[0]["id"] == finding_id

        central_session = open_existing_db(server._scan_jobs_db_path)
        assert central_session.execute(
            text(
                "SELECT COUNT(*) FROM canonical_finding_observations "
                "WHERE tenant_id=:tenant_id AND finding_id=:finding_id"
            ),
            {"tenant_id": server.tenant_id, "finding_id": finding_id},
        ).scalar_one() == 2
        first_lock = central_session.execute(
            text(
                "SELECT source_digest,artifact_id,artifact_sha256,artifact_size "
                "FROM canonical_report_locks WHERE tenant_id=:tenant_id "
                "AND report_id=:report_id"
            ),
            {
                "tenant_id": server.tenant_id,
                "report_id": report["report_id"],
            },
        ).mappings().one()
        assert first_lock["source_digest"] == report["source_digest"]
        assert first_lock["artifact_sha256"] == report["artifact_sha256"]
        assert int(first_lock["artifact_size"]) == len(exported_html)
        assert EvidenceCustodyStore(
            server._scan_jobs_db_path.parent / "evidence-custody",
            server.tenant_id,
        ).read(
            str(first_lock["artifact_id"]),
            actor_id="live-operator",
        ) == exported_html
        central_session.rollback()
        central_session.close()
        central_session = None

        _MissingCspHandler.strong_csp = True
        corrected_client_job_id = "task105-live-reference-corrected"
        corrected_body = {
            **body,
            "job_id": corrected_client_job_id,
            "confirmation": ActionConfirmation.create(
                job_id=corrected_client_job_id,
                target=target,
                engine="webforge",
                action="scan",
            ).to_dict(),
        }

        async def launch_corrected() -> httpx.Response:
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app),
                base_url="http://127.0.0.1",
                headers={"Authorization": f"Bearer {token}"},
            ) as client:
                return await client.post(
                    "/api/v1/scans/launch",
                    json=corrected_body,
                )

        corrected_response = _run(launch_corrected())
        assert corrected_response.status_code == 200, corrected_response.text
        corrected_scan_id = str(corrected_response.json()["scan_id"])
        assert corrected_scan_id != scan_id
        assert _await_live_terminal_job(server, corrected_scan_id)["state"] == (
            "completed"
        )
        assert len(_MissingCspHandler.requests) == 4

        fixed_retest_client_job_id = "task105-live-reference-fixed-retest"
        fixed_retest_confirmation = ActionConfirmation.create(
            job_id=fixed_retest_client_job_id,
            target=target,
            engine="webforge",
            action="retest",
        ).to_dict()

        async def verify_corrected_and_remediate() -> tuple[httpx.Response, ...]:
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app),
                base_url="http://127.0.0.1",
                headers={"Authorization": f"Bearer {token}"},
            ) as client:
                corrected_detail = await client.get(
                    f"/api/v1/scans/{corrected_scan_id}"
                )
                fixed_retest = await client.post(
                    f"/api/v1/findings/{finding_id}/retest",
                    json={
                        "job_id": fixed_retest_client_job_id,
                        "scope": ["127.0.0.1/32"],
                        "exclude": [],
                        "dry_run": False,
                        "confirmation": fixed_retest_confirmation,
                    },
                )
                remediated = await client.patch(
                    f"/api/v1/findings/{finding_id}/status",
                    json={
                        "expected_version": 1,
                        "status": "remediated",
                        "ownership": "unchanged",
                        "notes": "Verified against corrected local CSP fixture",
                    },
                )
                refreshed_findings = await client.get("/api/v1/findings")
                return (
                    corrected_detail,
                    fixed_retest,
                    remediated,
                    refreshed_findings,
                )

        (
            corrected_detail_response,
            fixed_retest_response,
            remediated_response,
            corrected_refresh_response,
        ) = _run(verify_corrected_and_remediate())
        assert corrected_detail_response.status_code == 200
        corrected_detail = corrected_detail_response.json()
        assert corrected_detail["status"] == "completed"
        assert corrected_detail["findings_count"]["total"] == 0
        assert corrected_detail["findings"] == []
        assert fixed_retest_response.status_code == 200, fixed_retest_response.text
        fixed_retest = fixed_retest_response.json()
        assert fixed_retest["state"] == "terminal"
        assert fixed_retest["retest_verdict"] == "fixed"
        assert fixed_retest["verdict_authority"] == "canonical_retest_proof"
        assert len(_MissingCspHandler.requests) == 5
        assert remediated_response.status_code == 200, remediated_response.text
        remediated = remediated_response.json()["review"]
        assert remediated["version"] == 2
        assert remediated["status"] == "remediated"
        corrected_findings = corrected_refresh_response.json()["findings"]
        assert len(corrected_findings) == 1
        assert corrected_findings[0]["id"] == finding_id
        assert corrected_findings[0]["status"] == "remediated"
        assert corrected_findings[0]["retest_verdict"] == "fixed"

        central_session = open_existing_db(server._scan_jobs_db_path)
        assert central_session.execute(
            text(
                "SELECT COUNT(*) FROM canonical_observations "
                "WHERE tenant_id=:tenant_id AND job_id=:job_id "
                "AND check_id='Content-Security-Policy'"
            ),
            {
                "tenant_id": server.tenant_id,
                "job_id": corrected_scan_id,
            },
        ).scalar_one() == 0
        assert central_session.execute(
            text(
                "SELECT COUNT(*) FROM canonical_findings "
                "WHERE tenant_id=:tenant_id"
            ),
            {"tenant_id": server.tenant_id},
        ).scalar_one() == 1
    finally:
        if central_session is not None:
            central_session.close()
        if server is not None:
            for info in server._active_scans.values():
                process = info.get("proc")
                if process is None:
                    continue
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=5)
                if process.stdout is not None and not process.stdout.closed:
                    process.stdout.close()
            if server._job_state_service is not None:
                server._job_state_service.close()
            server.event_bus.stop()
        fixture_server.shutdown()
        fixture_server.server_close()
        fixture_thread.join(timeout=5)


@pytest.mark.parametrize("terminal_case", ["timeout", "cancel"])
def test_live_reference_timeout_and_cancel_never_complete_or_claim_fixed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    terminal_case: str,
) -> None:
    """Real blocked requests must end in truthful non-success Task 103 state."""

    tenant_id = f"tenant-live-{terminal_case}"
    monkeypatch.setenv("FORGE_TENANT_ID", tenant_id)
    state_root = tmp_path / f"{terminal_case}-dashboard-state"
    state_root.mkdir(mode=0o700)
    monkeypatch.setenv("FORGE_DASHBOARD_STATE_DIR", str(state_root))
    signer_environment = _live_run_truth_environment(tmp_path)
    for key, value in signer_environment.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(
        "common.run_truth.RUN_TRUTH_POLICY",
        RunTruthPolicy(
            policy_id=signer_environment[RUN_TRUTH_POLICY_ID_ENV],
            policy_version=signer_environment[RUN_TRUTH_POLICY_VERSION_ENV],
            issuer_id=signer_environment[RUN_TRUTH_ISSUER_ID_ENV],
            issuer_public_key=signer_environment[RUN_TRUTH_PUBLIC_KEY_ENV],
        ),
    )
    fixture_server, fixture_thread = _start_missing_csp_fixture()
    _MissingCspHandler.delay_seconds = 8.0 if terminal_case == "timeout" else 30.0
    server: DashboardServer | None = None
    session: Any = None
    try:
        target = (
            f"http://127.0.0.1:{int(fixture_server.server_address[1])}"
            f"/{terminal_case}"
        )
        server = DashboardServer(
            event_bus=EventBus(run_id=f"task105-{terminal_case}")
        )
        monkeypatch.setattr(server, "_dashboard_public_url", lambda _request: "")
        app = server.create_app()
        token = issue_identity_token(
            f"{terminal_case}-operator",
            Role.OPERATOR,
            tenant_id=tenant_id,
        )
        client_job_id = f"task105-live-{terminal_case}"
        body = {
            "job_id": client_job_id,
            "target": target,
            "scope": ["127.0.0.1/32"],
            "exclude": [],
            "mode": "blackbox",
            "modules": ["header_audit"],
            "intensity": 0,
            "schedule": "now",
            "dry_run": False,
            "reference_slice": "header-audit-csp-v1",
            "timeout": 5 if terminal_case == "timeout" else 30,
            "confirmation": ActionConfirmation.create(
                job_id=client_job_id,
                target=target,
                engine="webforge",
                action="scan",
            ).to_dict(),
        }

        async def launch() -> httpx.Response:
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app),
                base_url="http://127.0.0.1",
                headers={"Authorization": f"Bearer {token}"},
            ) as client:
                return await client.post("/api/v1/scans/launch", json=body)

        launched = _run(launch())
        assert launched.status_code == 200, launched.text
        scan_id = str(launched.json()["scan_id"])
        request_deadline = time.monotonic() + 10.0
        while not _MissingCspHandler.requests:
            assert time.monotonic() < request_deadline
            time.sleep(0.02)

        cancel_elapsed = 0.0
        cancel_response: httpx.Response | None = None
        if terminal_case == "cancel":
            started = time.monotonic()

            async def cancel() -> httpx.Response:
                async with httpx.AsyncClient(
                    transport=httpx.ASGITransport(app=app),
                    base_url="http://127.0.0.1",
                    headers={"Authorization": f"Bearer {token}"},
                ) as client:
                    return await client.post(f"/api/v1/scans/{scan_id}/cancel")

            cancel_response = _run(cancel())
            cancel_elapsed = time.monotonic() - started
            assert cancel_response.status_code == 200, cancel_response.text
            assert cancel_elapsed <= 6.0

        terminal = _await_live_terminal_job(
            server,
            scan_id,
            timeout_seconds=20.0,
        )
        expected_state = "canceled" if terminal_case == "cancel" else "failed"
        assert terminal["state"] == expected_state
        assert terminal["state"] not in {"completed", "partial"}
        process = server._active_scans[f"{scan_id}_web"]["proc"]
        process_deadline = time.monotonic() + 6.0
        while process.poll() is None:
            assert time.monotonic() < process_deadline
            time.sleep(0.02)
        assert len(_MissingCspHandler.requests) == 1

        session = open_existing_db(server._scan_jobs_db_path)
        assert session.execute(text("PRAGMA integrity_check")).scalar_one() == "ok"
        assert session.execute(
            text(
                "SELECT COUNT(*) FROM canonical_observations "
                "WHERE tenant_id=:tenant_id AND job_id=:job_id "
                "AND check_id='Content-Security-Policy'"
            ),
            {"tenant_id": tenant_id, "job_id": scan_id},
        ).scalar_one() == 0
        assert session.execute(
            text(
                "SELECT COUNT(*) FROM canonical_findings f "
                "JOIN canonical_finding_observations fo "
                "ON fo.tenant_id=f.tenant_id AND fo.finding_id=f.id "
                "JOIN canonical_observations o "
                "ON o.tenant_id=fo.tenant_id AND o.id=fo.observation_id "
                "WHERE f.tenant_id=:tenant_id AND o.job_id=:job_id"
            ),
            {"tenant_id": tenant_id, "job_id": scan_id},
        ).scalar_one() == 0
        if terminal_case == "timeout":
            delivery = session.execute(
                text(
                    "SELECT state,outcome FROM durable_job_state_deliveries "
                    "WHERE tenant_id=:tenant_id AND job_id=:job_id"
                ),
                {"tenant_id": tenant_id, "job_id": scan_id},
            ).mappings().one()
            assert delivery["state"] == "accepted"
            assert delivery["outcome"] == "failure"
        else:
            assert cancel_response is not None
            assert cancel_response.json()["status"] == "canceled"
    finally:
        if session is not None:
            session.close()
        if server is not None:
            for info in server._active_scans.values():
                process = info.get("proc")
                if process is None:
                    continue
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=5)
                if process.stdout is not None and not process.stdout.closed:
                    process.stdout.close()
            if server._job_state_service is not None:
                server._job_state_service.close()
            server.event_bus.stop()
        fixture_server.shutdown()
        fixture_server.server_close()
        fixture_thread.join(timeout=5)
