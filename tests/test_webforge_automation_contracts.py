from __future__ import annotations

import asyncio
import json
import os
import stat
from argparse import Namespace
from pathlib import Path
from types import SimpleNamespace

import pytest

import forge
from common.config import BaseForgeConfig
from common.target_manager import TargetManager
from webforge import webforge


def _webforge_args(**overrides) -> Namespace:
    defaults = {
        "target": "https://app.example.test",
        "mode": "blackbox",
        "engagement": "pytest",
        "tester": "contract-tests",
        "config": None,
        "output": None,
        "report_format": "json",
        "rate": 10.0,
        "workers": 2,
        "proxy": None,
        "username": None,
        "password": None,
        "token": None,
        "cookie": None,
        "session": None,
        "sso": False,
        "source": None,
        "modules": "sqli_scanner",
        "skip_modules": None,
        "jwt_token": None,
        "scope": ["example.test"],
        "exclude": [],
        "dry_run": True,
        "resume": None,
        "auto_confirm": False,
        "browser": None,
        "browser_render": False,
        "login_url": None,
        "login_script": None,
        "auth_type": None,
        "header_name": "Authorization",
        "auth_state": None,
        "api_schema": None,
        "graphql_schema_url": None,
        "no_screenshot": True,
        "list_modules": False,
        "profile": None,
        "list_profiles": False,
        "verbose": False,
        "quiet": True,
        "collab_domain": None,
        "dashboard_url": None,
        "control_file": None,
    }
    defaults.update(overrides)
    return Namespace(**defaults)


def test_webforge_dry_run_plan_persists_planned_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    phase = SimpleNamespace(number=1, name="Injection", modules=["sqli_scanner", "xss_scanner"])
    monkeypatch.setattr(webforge, "get_phases", lambda *args, **kwargs: [phase])

    cfg = BaseForgeConfig(
        target="https://app.example.test",
        engagement="pytest",
        tester="contract-tests",
        mode="blackbox",
        dry_run=True,
    )
    args = _webforge_args(modules="sqli_scanner,xss_scanner")

    async def exercise() -> dict[str, object]:
        return await webforge.dry_run_plan(cfg, args, tmp_path)

    summary = asyncio.run(exercise())
    plan_path = Path(summary["plan_path"])
    persisted = json.loads(plan_path.read_text(encoding="utf-8"))

    assert summary["status"] == "completed"
    assert summary["dry_run"] is True
    assert summary["authorized"] is False
    assert summary["findings"] == 0
    assert summary["plan"]["status"] == "planned"
    assert persisted["dry_run"] is True
    assert persisted["authorized"] is False
    assert persisted["target"] == "app.example.test"
    assert persisted["results_dir"] == str(tmp_path)
    assert persisted["module_count"] == 2
    assert persisted["phases"] == [
        {"number": 1, "name": "Injection", "modules": ["sqli_scanner", "xss_scanner"]}
    ]


def test_webforge_dry_run_does_not_instantiate_or_run_module_classes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    class ForbiddenModule:
        def __init__(self, *args, **kwargs) -> None:
            calls.append("__init__")
            raise AssertionError("dry-run must not instantiate scanner modules")

        async def run(self) -> None:
            calls.append("run")
            raise AssertionError("dry-run must not run scanner modules")

    class NoopReporter:
        def __init__(self, **kwargs) -> None:
            self.kwargs = kwargs

        def generate_all(self) -> dict[str, Path]:
            return {}

    phase = SimpleNamespace(number=1, name="Injection", modules=["sqli_scanner"])
    monkeypatch.setattr(webforge, "get_phases", lambda *args, **kwargs: [phase])
    monkeypatch.setattr(webforge, "load_module_class", lambda name: ForbiddenModule)
    monkeypatch.setattr(webforge, "BaseReporter", NoopReporter)
    monkeypatch.setattr(webforge, "_get_eng_bus", lambda: None)

    cfg = BaseForgeConfig(
        target="https://app.example.test",
        engagement="pytest",
        tester="contract-tests",
        mode="blackbox",
        dry_run=True,
    )
    args = _webforge_args()

    async def exercise() -> dict[str, object]:
        return await webforge.run_scan(cfg, args, tmp_path)

    summary = asyncio.run(exercise())

    assert summary["findings"] == 0
    assert calls == []


def test_setup_results_dir_honors_explicit_output_and_avoids_collisions(tmp_path: Path) -> None:
    first = webforge.setup_results_dir(
        "https://app.example.test",
        "pytest",
        None,
        output_dir=tmp_path,
    )
    second = webforge.setup_results_dir(
        "https://app.example.test",
        "pytest",
        None,
        output_dir=tmp_path,
    )

    assert first.parent == tmp_path
    assert second.parent == tmp_path
    assert first != second
    assert first.exists()
    assert second.exists()
    assert (first / "evidence" / "screenshots").is_dir()
    assert (first / "evidence" / "http").is_dir()
    assert stat.S_IMODE(first.stat().st_mode) == 0o700
    assert stat.S_IMODE(second.stat().st_mode) == 0o700


def test_webforge_dry_run_omits_target_secrets_and_uses_private_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    canaries = (
        "CANARY_USERINFO_007",
        "CANARY_QUERY_007",
        "CANARY_ENGAGEMENT_007",
    )
    target = (
        "https://operator:CANARY_USERINFO_007@app.example.test/private/path"
        "?opaque=CANARY_QUERY_007&token=CANARY_QUERY_007"
    )
    engagement = "../../CANARY_ENGAGEMENT_007?segment=value"
    output = tmp_path / "open-umask" / "nested"
    phase = SimpleNamespace(number=1, name="Injection", modules=["sqli_scanner"])
    monkeypatch.setattr(webforge, "get_phases", lambda *args, **kwargs: [phase])

    cfg = BaseForgeConfig(
        target=target,
        engagement=engagement,
        tester="contract-tests",
        mode="blackbox",
        dry_run=True,
    )
    args = _webforge_args(target=target, engagement=engagement)

    previous_umask = os.umask(0o002)
    try:
        results_dir = webforge.setup_results_dir(
            target,
            engagement,
            None,
            output_dir=str(output),
        )
        summary = asyncio.run(webforge.dry_run_plan(cfg, args, results_dir))
    finally:
        os.umask(previous_umask)

    plan_path = Path(summary["plan_path"])
    persisted = plan_path.read_text(encoding="utf-8")
    rendered = repr(summary) + persisted + capsys.readouterr().out
    for canary in canaries:
        assert canary not in rendered
        assert canary not in str(results_dir)
    assert summary["plan"]["target"] == "<invalid-target>"
    assert "@" not in results_dir.name
    assert "?" not in results_dir.name
    assert stat.S_IMODE((tmp_path / "open-umask").stat().st_mode) == 0o700
    assert stat.S_IMODE(output.stat().st_mode) == 0o700
    assert stat.S_IMODE(results_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE((results_dir / "evidence").stat().st_mode) == 0o700
    assert stat.S_IMODE((results_dir / "evidence" / "screenshots").stat().st_mode) == 0o700
    assert stat.S_IMODE((results_dir / "evidence" / "http").stat().st_mode) == 0o700
    assert stat.S_IMODE(plan_path.stat().st_mode) == 0o600


def test_multi_target_dry_run_progress_uses_safe_targets_and_atomic_mode(
    tmp_path: Path,
) -> None:
    secret = "CANARY_MULTI_TARGET_007"
    raw_target = f"https://operator:{secret}@app.example.test/path?opaque={secret}"
    results_dir = tmp_path / "multi" / "progress"
    manager = TargetManager(
        max_parallel=1,
        results_dir=results_dir,
        defer_results_setup=True,
        safe_target_persistence=True,
    )
    assert manager.add_target(raw_target)

    async def planned(_entry) -> dict[str, object]:
        manager.enable_progress_persistence()
        return {"status": "completed", "findings": 0, "errors": []}

    previous_umask = os.umask(0o002)
    try:
        summary = asyncio.run(manager.run_all(planned))
    finally:
        os.umask(previous_umask)

    progress_path = results_dir / "target_progress.json"
    rendered = repr(summary) + progress_path.read_text(encoding="utf-8")
    assert secret not in rendered
    assert raw_target not in rendered
    assert summary["targets"][0]["target"] == "<invalid-target>"
    assert stat.S_IMODE((tmp_path / "multi").stat().st_mode) == 0o700
    assert stat.S_IMODE(results_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE(progress_path.stat().st_mode) == 0o600


def test_top_level_web_parser_accepts_targets_and_parallel(tmp_path: Path) -> None:
    targets_file = tmp_path / "targets.txt"
    targets_file.write_text("https://one.example.test\nhttps://two.example.test\n", encoding="utf-8")

    parser = forge.build_parser()
    args = parser.parse_args(
        [
            "web",
            "--targets",
            str(targets_file),
            "--parallel",
            "7",
            "--output-dir",
            str(tmp_path / "out"),
        ]
    )

    assert args.command == "web"
    assert args.targets == str(targets_file)
    assert args.parallel == 7
    assert forge._validate_common_scan_inputs(args) == [
        "https://one.example.test",
        "https://two.example.test",
    ]
    framework_args = forge._build_framework_args(args, "web")
    assert framework_args == [
        "--targets",
        str(targets_file),
        "--parallel",
        "7",
        "--output",
        str(tmp_path / "out"),
    ]


def test_run_for_target_can_be_exercised_by_target_manager_without_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[tuple[str, float, int, bool]] = []
    setup_calls: list[tuple[str, str, str | None, str | None]] = []

    async def fake_run_scan(
        cfg: BaseForgeConfig,
        args: Namespace,
        results_dir: Path,
        event_bus=None,
        scan_control=None,
    ) -> dict[str, object]:
        seen.append((cfg.target, cfg.rate.requests_per_second, cfg.workers, cfg.dry_run))
        assert args.target == cfg.target
        assert results_dir.is_dir()
        return {"findings": 1, "errors": [], "duration": 0.01}

    def fake_setup_results_dir(
        target: str,
        engagement: str,
        resume: str | None,
        output_dir: str | None = None,
    ) -> Path:
        setup_calls.append((target, engagement, resume, output_dir))
        base = Path(output_dir) if output_dir else tmp_path / "default-results"
        path = base / target.replace("https://", "")
        path.mkdir(parents=True, exist_ok=True)
        return path

    monkeypatch.setattr(webforge, "run_scan", fake_run_scan)
    monkeypatch.setattr(webforge, "prepare_browser_context", lambda *args, **kwargs: None)
    monkeypatch.setattr(webforge, "prepare_api_schema_context", lambda *args, **kwargs: None)
    monkeypatch.setattr(webforge, "setup_results_dir", fake_setup_results_dir)

    base_args = _webforge_args(
        config=str(tmp_path / "missing-webforge.yaml"),
        modules=None,
        rate=4.5,
        workers=3,
        output=str(tmp_path),
    )

    mgr = TargetManager(max_parallel=2, results_dir=tmp_path / "manager")
    assert mgr.add_target("https://one.example.test", options={"rate": 2.0})
    assert mgr.add_target("https://two.example.test")

    async def exercise() -> dict[str, object]:
        return await mgr.run_all(lambda entry: webforge.run_for_target(entry, base_args))

    summary = asyncio.run(exercise())

    assert summary["states"]["completed"] == 2
    assert summary["total_findings"] == 2
    assert setup_calls == [
        ("https://one.example.test", "pytest", None, str(tmp_path)),
        ("https://two.example.test", "pytest", None, str(tmp_path)),
    ]
    assert seen == [
        ("https://one.example.test", 2.0, 3, True),
        ("https://two.example.test", 4.5, 3, True),
    ]
