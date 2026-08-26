"""Task 102 producer-to-dashboard acceptance workflow.

The helper in this module is intentionally reusable by the canonical integration
tests.  It creates only owner-controlled local SQLite/filesystem state and an
in-process ASGI client; it never opens a target connection.
"""
from __future__ import annotations

import asyncio
import html
import io
import json
import logging
import re
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy import text

from common.action_authorization import (
    AUTHORIZATION_DB_ENV,
    ActionAuthorizationEnvelope,
    AuthorizationContext,
    ConfirmationMethod,
    OperatorRole,
    SafetyMode,
    consume_authorization,
    issue_authorization,
)
from common.base_module import BaseModule, ModuleResult
from common.config import BaseForgeConfig
from common.confirm_gate import ActionConfirmation
from common.dashboard.auth import Role, issue_identity_token
from common.dashboard.event_bus import Event, EventBus, EventType
from common.dashboard.server import DashboardArtifactError, DashboardServer
from common.db import ScanJobModel, create_db
from common.evidence import Evidence
from common.finding import Severity
from common.reporting.report_engine import ReportConfig, ReportEngine
from common.reporter import BaseReporter
from common.scope import Scope


_FORBIDDEN_EVIDENCE_FIELDS = {
    "request_raw",
    "response_raw",
    "screenshot_path",
    "console_capture_path",
    "pcap_path",
    "original_relative_path",
    "derivative_relative_path",
    "original.bin",
}


def _assert_no_raw_or_path_fields(value: Any) -> None:
    if isinstance(value, dict):
        assert not (_FORBIDDEN_EVIDENCE_FIELDS & {str(key) for key in value}), value
        for child in value.values():
            _assert_no_raw_or_path_fields(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _assert_no_raw_or_path_fields(child)


def _assert_no_raw_markers(text: str, marker: str) -> None:
    assert marker not in text
    assert "request_raw" not in text
    assert "response_raw" not in text
    assert "original_relative_path" not in text
    assert "derivative_relative_path" not in text


class _Task102FixtureModule(BaseModule):
    NAME = "task102.e2e.fixture"
    DESCRIPTION = "Deterministic Task 102 local producer fixture"
    PHASE = 1

    async def run(self) -> ModuleResult:
        return self._make_result(time.monotonic())


def _register_scan_job(
    server: DashboardServer,
    result_root: Path,
    authorization: ActionAuthorizationEnvelope,
) -> None:
    """Register the result root through the real durable scan-jobs database."""
    database_path = server._scan_jobs_db_path
    session = create_db(database_path)
    try:
        session.add(
            ScanJobModel(
                id=authorization.job_id,
                tenant_id=authorization.tenant_id,
                status="completed",
                target="https://task102.fixture.invalid",
                frameworks=json.dumps(["forge"]),
                modules=json.dumps([_Task102FixtureModule.NAME]),
                results_dir=str(result_root),
                logs=json.dumps({}),
                authorization_state="allow",
                authorization_decision_id=authorization.decision_id,
                authorization_action_id=authorization.action_id,
            )
        )
        session.commit()
    finally:
        session.close()
    # The dashboard's descriptor-pinned read-only discovery treats a
    # concurrently changing WAL sidecar as an unsafe snapshot.  This fixture
    # has no concurrent writer, so close the SQLAlchemy pool, checkpoint into
    # the durable main file, and use rollback journaling before the live GET.
    if session.bind is not None:
        session.bind.dispose()
    connection = sqlite3.connect(database_path)
    try:
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        connection.execute("PRAGMA journal_mode=DELETE")
    finally:
        connection.close()


async def _api_workflow(
    app: Any,
    token: str,
    finding_id: str,
) -> tuple[dict[str, Any], bytes, bytes]:
    headers = {"Authorization": f"Bearer {token}"}
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://127.0.0.1",
        headers=headers,
    ) as client:
        response = await client.get("/api/v1/findings")
        assert response.status_code == 200, response.text
        api_payload = response.json()
        assert api_payload["total"] == 1
        assert len(api_payload["findings"]) == 1
        assert api_payload["findings"][0]["id"] == finding_id

        first_export = await client.post(
            "/api/v1/findings/export",
            json={"finding_ids": [finding_id]},
        )
        second_export = await client.post(
            "/api/v1/findings/export",
            json={"finding_ids": [finding_id]},
        )
        assert first_export.status_code == 200, first_export.text
        assert second_export.status_code == 200, second_export.text
        assert first_export.content == second_export.content
        return api_payload, first_export.content, second_export.content


def exercise_task102_end_to_end(
    tmp_path: Path,
    monkeypatch: Any,
) -> dict[str, Any]:
    """Exercise Task 102 from ``BaseModule.new_finding`` through all consumers.

    The returned payloads are deliberately ordinary serialized values so cases
    5, 8, and 10 can assert additional policy details without recreating setup.
    """
    tenant_a = "task102-tenant-a"
    tenant_b = "task102-tenant-b"
    state_root = tmp_path / "dashboard-state"
    state_root.mkdir(mode=0o700)
    state_root.chmod(0o700)
    monkeypatch.setenv("FORGE_DASHBOARD_STATE_DIR", str(state_root))
    monkeypatch.setenv("FORGE_TENANT_ID", tenant_a)

    server_a: DashboardServer | None = DashboardServer(
        event_bus=EventBus(run_id="task102-dashboard")
    )
    # Dashboard-launched jobs bind their authorization decision, consumption,
    # and durable job row in the same protected control-plane database.
    authorization_db = server_a._scan_jobs_db_path
    monkeypatch.setenv(AUTHORIZATION_DB_ENV, str(authorization_db))
    result_root = server_a._allocate_scan_results_dir("task102-e2e-job")
    database_path = result_root / "adforge.db"
    session = create_db(database_path)
    event_bus = EventBus(run_id="task102-e2e-run")
    captured_events: list[Event] = []
    persistence_counts: list[int] = []
    event_received = threading.Event()

    raw_marker = f"TASK102_E2E_RAW_CANARY_{uuid.uuid4().hex}"
    log_stream = io.StringIO()
    log_handler = logging.StreamHandler(log_stream)
    log_handler.setFormatter(logging.Formatter("%(levelname)s:%(name)s:%(message)s"))
    module_logger = logging.getLogger(f"forge.{_Task102FixtureModule.NAME}")
    module_logger.addHandler(log_handler)
    module_logger.setLevel(logging.INFO)

    def capture_event(event: Event) -> None:
        if event.event_type is EventType.FINDING_NEW:
            captured_events.append(event)
            check_session = create_db(database_path)
            try:
                persistence_counts.append(
                    int(
                        check_session.execute(
                            text("SELECT COUNT(*) FROM canonical_findings WHERE tenant_id=:tenant_id"),
                            {"tenant_id": tenant_a},
                        ).scalar_one()
                    )
                )
            finally:
                check_session.close()
            event_received.set()

    event_bus.subscribe(EventType.FINDING_NEW, capture_event)
    event_bus.start()
    server_b: DashboardServer | None = None
    try:
        context = AuthorizationContext(
            tenant_id=tenant_a,
            engagement_id="task102-e2e-engagement",
            run_id="task102-e2e-run",
            job_id="task102-e2e-job",
            operator_id="task102-e2e-operator",
            operator_role=OperatorRole.OPERATOR,
            engine="forge",
            module_id=_Task102FixtureModule.NAME,
            action_kind="module.execute",
            scope_policy_version="task102-scope-v1",
            requested_target="https://task102.fixture.invalid/items",
            resolved_target="https://task102.fixture.invalid/items",
            allowed_scope=["https://task102.fixture.invalid/items"],
            excluded_scope=[],
            safety_mode=SafetyMode.ACTIVE,
            confirmation_method=ConfirmationMethod.CLI_PROMPT,
            confirmed_by="task102-e2e-operator",
        )
        authorization_session = create_db(authorization_db)
        try:
            issued = issue_authorization(
                session=authorization_session,
                context=context,
                confirmation=ActionConfirmation.create(
                    job_id=context.job_id,
                    target=context.resolved_target,
                    engine=context.engine,
                    action=context.action_kind,
                ),
            )
            assert issued.allowed
            consumed = consume_authorization(
                session=authorization_session,
                envelope=issued.envelope,
                expected=context,
                boundary="forge.module",
            )
            assert consumed.allowed
        finally:
            authorization_session.close()
        config = BaseForgeConfig(
            target=context.requested_target,
            engagement="task102-e2e-engagement",
            extra={
                "allowed_scope": list(context.allowed_scope),
                "excluded_scope": list(context.excluded_scope),
                "authorized_module_envelopes": {
                    _Task102FixtureModule.NAME: issued.envelope,
                },
            },
        )
        module = _Task102FixtureModule(
            config=config,
            scope=Scope([config.target]),
            db_session=session,
            results_dir=result_root,
            run_id=context.run_id,
            event_bus=event_bus,
        )
        finding = module.new_finding(
            title="Task 102 deterministic persisted observation",
            severity=Severity.HIGH,
            description="Verified derivative-only local fixture.",
            reproduction_steps=["Inspect the persisted local derivative."],
            remediation="Apply the fixture remediation.",
            references=["CWE-000"],
            target=config.target,
            url=f"{config.target}?item=fixture",
            confidence="HIGH",
            proof_type="deterministic_fixture",
            maturity="stable",
            evidence=Evidence(
                request_raw=f"GET /items?item=fixture HTTP/1.1\n\n{raw_marker}",
                response_raw=f"HTTP/1.1 200 OK\n\n{raw_marker}",
                extra={
                    "route": "/items",
                    "parameter": "item",
                    "location": "query",
                    "identity_ref": "principal:task102-e2e",
                    "check_id": "task102.e2e.fixture",
                },
            ),
        )
        assert finding.id
        assert event_received.wait(2.0), "BaseModule finding_new event was not delivered"
        assert persistence_counts == [1], persistence_counts
        assert len(captured_events) == 1

        assert server_a is not None
        _register_scan_job(server_a, result_root, issued.envelope)
        assert server_a._canonical_result_roots() == [result_root]
        rogue_root = tmp_path / "rogue-result-root"
        rogue_root.mkdir(mode=0o700)
        with pytest.raises(
            DashboardArtifactError,
            match="does not match its durable job",
        ):
            server_a._job_bound_canonical_result_root(
                {
                    "scan_id": issued.envelope.job_id,
                    "authorization_state": "allow",
                    "authorization_decision_id": issued.envelope.decision_id,
                    "authorization_action_id": issued.envelope.action_id,
                    "results_dir": str(rogue_root),
                }
            )
        app_a = server_a.create_app()
        token_a = issue_identity_token("task102-viewer-a", Role.VIEWER, tenant_id=tenant_a)
        api_payload, export_bytes, export_repeat = asyncio.run(
            _api_workflow(app_a, token_a, finding.id)
        )
        api_finding = api_payload["findings"][0]
        assert re.fullmatch(r"finding-v[0-9]+:[0-9a-f]{64}", api_finding["dedup_key"])
        evidence = api_finding["evidence"]
        assert evidence["state"] == "persisted"
        artifacts = [
            artifact
            for observation in evidence["observations"]
            for artifact in observation["artifacts"]
        ]
        assert len(artifacts) >= 2
        assert {artifact["capture_kind"] for artifact in artifacts} >= {
            "request",
            "response",
        }
        assert all(artifact["redaction_state"] == "redacted" for artifact in artifacts)
        http_artifacts = [
            artifact for artifact in artifacts
            if artifact["capture_kind"] in {"request", "response"}
        ]
        assert all("<redacted>" in artifact["derivative"] for artifact in http_artifacts)
        _assert_no_raw_or_path_fields(api_payload)
        _assert_no_raw_markers(json.dumps(api_payload, sort_keys=True), raw_marker)
        _assert_no_raw_or_path_fields(json.loads(export_bytes))
        _assert_no_raw_markers(export_bytes.decode("utf-8"), raw_marker)
        assert export_bytes == export_repeat

        event_payload = json.loads(captured_events[0].to_json())
        _assert_no_raw_or_path_fields(event_payload)
        _assert_no_raw_markers(captured_events[0].to_json(), raw_marker)

        operator_token = issue_identity_token(
            "task102-operator-a",
            Role.OPERATOR,
            tenant_id=tenant_a,
        )
        durable_job = server_a._load_scan_job(issued.envelope.job_id)
        assert durable_job is not None
        durable_root = server_a._job_bound_canonical_result_root(durable_job)
        assert server_a._canonical_database_paths(durable_root) == [database_path]
        assert server_a._scan_job_has_canonical_lineage(durable_job)

        async def canonical_deletion_check() -> tuple[httpx.Response, httpx.Response]:
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app_a),
                base_url="http://127.0.0.1",
                headers={"Authorization": f"Bearer {operator_token}"},
            ) as operator_client, httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app_a),
                base_url="http://127.0.0.1",
                headers={"Authorization": f"Bearer {token_a}"},
            ) as viewer_client:
                rejected = await operator_client.delete(
                    f"/api/v1/scans/{issued.envelope.job_id}",
                    params={"purge_artifacts": "true"},
                )
                preserved = await viewer_client.get("/api/v1/findings")
                return rejected, preserved

        rejected_delete, preserved_findings = asyncio.run(
            canonical_deletion_check()
        )
        assert rejected_delete.status_code == 409, rejected_delete.text
        assert preserved_findings.status_code == 200
        assert preserved_findings.json()["findings"][0]["id"] == finding.id

        report_input = json.loads(json.dumps(api_finding))
        base_reporter = BaseReporter(
            [report_input],
            tmp_path / "task102-base-report",
            formats=["json", "html"],
        )
        base_json = Path(base_reporter.generate_json()).read_text(encoding="utf-8")
        base_html = Path(base_reporter.generate_html()).read_text(encoding="utf-8")
        report_config = ReportConfig(
            engagement="Task 102 E2E",
            target="local fixture",
            output_dir=str(tmp_path / "task102-engine-report"),
            formats=["json", "html"],
            include_exec_summary=False,
            include_unverified=True,
        )
        engine_paths = asyncio.run(ReportEngine([report_input], report_config).generate())
        engine_json = Path(engine_paths["json"]).read_text(encoding="utf-8")
        engine_html = Path(engine_paths["html"]).read_text(encoding="utf-8")
        derivative = http_artifacts[0]["derivative"]
        for rendered in (base_json, base_html, engine_json, engine_html):
            assert derivative.splitlines()[0] in rendered or html.escape(
                derivative.splitlines()[0]
            ) in rendered
            _assert_no_raw_markers(rendered, raw_marker)
            _assert_no_raw_or_path_fields(json.loads(rendered) if rendered.startswith("{") else {})

        contract = json.loads(Path("contracts/dashboard-api.json").read_text(encoding="utf-8"))
        routes = contract["routes"]
        assert {"method": "GET", "path": "/api/v1/findings"} in routes
        assert {"method": "POST", "path": "/api/v1/findings/export"} in routes
        ui_source = Path("apex-ui/src/pages/Vulnerabilities.jsx").read_text(encoding="utf-8")
        for consumed in (
            "evidence.state",
            "evidence.observations",
            "artifact.derivative",
            "artifact.capture_kind",
            "verification_state",
            "proof_type",
            "maturity",
        ):
            assert consumed in ui_source
        for field in ("title", "target", "module", "description", "reproduction_steps", "remediation"):
            assert field in api_finding

        monkeypatch.setenv("FORGE_TENANT_ID", tenant_b)
        server_b = DashboardServer(event_bus=EventBus(run_id="task102-tenant-b"))
        app_b = server_b.create_app()
        token_b = issue_identity_token("task102-viewer-b", Role.VIEWER, tenant_id=tenant_b)
        token_wrong = issue_identity_token("task102-wrong-tenant", Role.VIEWER, tenant_id=tenant_b)

        async def tenant_checks() -> tuple[httpx.Response, httpx.Response, httpx.Response]:
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app_a),
                base_url="http://127.0.0.1",
                headers={"Authorization": f"Bearer {token_wrong}"},
            ) as wrong_client, httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app_b),
                base_url="http://127.0.0.1",
                headers={"Authorization": f"Bearer {token_b}"},
            ) as tenant_b_client:
                wrong = await wrong_client.get("/api/v1/findings")
                isolated = await tenant_b_client.get("/api/v1/findings")
                blocked_export = await tenant_b_client.post(
                    "/api/v1/findings/export",
                    json={"finding_ids": [finding.id]},
                )
                return wrong, isolated, blocked_export

        wrong_response, isolated_response, blocked_export_response = asyncio.run(tenant_checks())
        assert wrong_response.status_code == 403
        assert isolated_response.status_code == 200
        assert isolated_response.json() == {"findings": [], "total": 0}
        assert blocked_export_response.status_code in {400, 409}
        _assert_no_raw_markers(log_stream.getvalue(), raw_marker)
        return {
            "finding_id": finding.id,
            "api": api_payload,
            "export": export_bytes.decode("utf-8"),
            "export_repeat": export_repeat.decode("utf-8"),
            "event": event_payload,
            "reports": {
                "base_json": base_json,
                "base_html": base_html,
                "engine_json": engine_json,
                "engine_html": engine_html,
            },
            "logs": log_stream.getvalue(),
            "raw_marker": raw_marker,
        }
    finally:
        module_logger.removeHandler(log_handler)
        log_handler.close()
        session.close()
        event_bus.stop()
        if server_a is not None:
            server_a.event_bus.stop()
        if server_b is not None:
            server_b.event_bus.stop()


def test_task102_end_to_end_helper_covers_live_dashboard_and_reports(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    result = exercise_task102_end_to_end(tmp_path, monkeypatch)
    assert result["finding_id"]
    assert result["api"]["total"] == 1
    assert result["export"] == result["export_repeat"]
    assert result["api"]["findings"][0]["evidence"]["state"] == "persisted"
