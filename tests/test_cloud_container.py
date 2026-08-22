"""Tests for Sprint 1 — Cloud & Container Attack Modules.

Validates:
  - All 6 modules follow BaseModule interface
  - Modules import cleanly
  - Class attributes match spec
  - Instantiation works with standard fixtures
  - Module-specific logic (parsers, classifiers, validators)
  - Attack chains are registered

FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import asyncio
import importlib
import time
from pathlib import Path
from typing import Any

import pytest

from common.config import BaseForgeConfig
from common.scope import Scope
from common.db import create_db


# ── Helpers ──────────────────────────────────────────────────────────

def _make_module(cls: type, tmp_path: Path, target: str = "https://example.com") -> Any:
    """Instantiate a module with standard test fixtures."""
    cfg = BaseForgeConfig(target=target)
    scope = Scope([target.replace("https://", "").replace("http://", "")])
    session = create_db(tmp_path / "test.db")
    mod = cls(cfg, scope, session, tmp_path)
    return mod, session


# ══════════════════════════════════════════════════════════════════════
# IMPORT TESTS
# ══════════════════════════════════════════════════════════════════════

class TestCloudContainerImports:
    """Verify all cloud/ modules import without errors."""

    def test_import_cloud_api_scanner(self) -> None:
        from cloud.cloud_api_scanner import CloudApiScanner
        assert CloudApiScanner.NAME == "cloud_api_scanner"

    def test_import_cloud_iam_chaining(self) -> None:
        from cloud.cloud_iam_chaining import CloudIamChaining
        assert CloudIamChaining.NAME == "cloud_iam_chaining"

    def test_import_container_escape(self) -> None:
        from cloud.container_escape import ContainerEscape
        assert ContainerEscape.NAME == "container_escape"

    def test_import_k8s_attack(self) -> None:
        from cloud.k8s_attack import K8sAttack
        assert K8sAttack.NAME == "k8s_attack"

    def test_import_tf_state_poisoner(self) -> None:
        from cloud.tf_state_poisoner import TfStatePoisoner
        assert TfStatePoisoner.NAME == "tf_state_poisoner"

    def test_import_serverless_inject(self) -> None:
        from cloud.serverless_inject import ServerlessInject
        assert ServerlessInject.NAME == "serverless_inject"


# ══════════════════════════════════════════════════════════════════════
# BASE MODULE INTERFACE TESTS
# ══════════════════════════════════════════════════════════════════════

class TestCloudModuleInterface:
    """Verify all cloud modules follow the BaseModule interface."""

    @pytest.mark.parametrize("class_name,module_path", [
        ("CloudApiScanner", "cloud.cloud_api_scanner"),
        ("CloudIamChaining", "cloud.cloud_iam_chaining"),
        ("ContainerEscape", "cloud.container_escape"),
        ("K8sAttack", "cloud.k8s_attack"),
        ("TfStatePoisoner", "cloud.tf_state_poisoner"),
        ("ServerlessInject", "cloud.serverless_inject"),
    ])
    def test_has_required_attrs(self, class_name: str, module_path: str, tmp_path: Path) -> None:
        mod = importlib.import_module(module_path)
        cls = getattr(mod, class_name)

        # Check class attributes
        assert hasattr(cls, "NAME"), f"{class_name} missing NAME"
        assert hasattr(cls, "DESCRIPTION"), f"{class_name} missing DESCRIPTION"
        assert hasattr(cls, "PHASE"), f"{class_name} missing PHASE"
        assert hasattr(cls, "TAGS"), f"{class_name} missing TAGS"
        assert isinstance(cls.TAGS, list), f"{class_name}.TAGS should be a list"
        assert len(cls.NAME) > 0, f"{class_name}.NAME is empty"
        assert len(cls.DESCRIPTION) > 0, f"{class_name}.DESCRIPTION is empty"

        # Check instantiation
        instance, session = _make_module(cls, tmp_path)
        assert hasattr(instance, "run"), f"{class_name} missing run()"
        assert asyncio.iscoroutinefunction(instance.run), f"{class_name}.run() must be async"
        assert hasattr(instance, "new_finding"), f"{class_name} missing new_finding()"
        assert hasattr(instance, "check_scope"), f"{class_name} missing check_scope()"
        assert hasattr(instance, "rate_limit"), f"{class_name} missing rate_limit()"
        session.close()

    @pytest.mark.parametrize("class_name,module_path", [
        ("CloudApiScanner", "cloud.cloud_api_scanner"),
        ("CloudIamChaining", "cloud.cloud_iam_chaining"),
        ("ContainerEscape", "cloud.container_escape"),
        ("K8sAttack", "cloud.k8s_attack"),
        ("TfStatePoisoner", "cloud.tf_state_poisoner"),
        ("ServerlessInject", "cloud.serverless_inject"),
    ])
    def test_run_returns_module_result(self, class_name: str, module_path: str, tmp_path: Path) -> None:
        """Verify run() returns a proper ModuleResult (no network needed for basic return)."""
        from common.base_module import ModuleResult

        mod = importlib.import_module(module_path)
        cls = getattr(mod, class_name)
        instance, session = _make_module(cls, tmp_path)
        result = asyncio.run(instance.run())
        assert isinstance(result, ModuleResult), f"{class_name}.run() didn't return ModuleResult"
        assert result.module_name == cls.NAME
        session.close()


# ══════════════════════════════════════════════════════════════════════
# CLOUD API SCANNER TESTS
# ══════════════════════════════════════════════════════════════════════

class TestCloudApiScannerLogic:
    """Test CloudApiScanner-specific logic."""

    def test_severity_classification(self, tmp_path: Path) -> None:
        from cloud.cloud_api_scanner import CloudApiScanner, Severity

        mod, session = _make_module(CloudApiScanner, tmp_path, "http://169.254.169.254")
        assert mod._classify_severity("/creds", "AccessKeyId=AKIA1234567890ABCDEF") == Severity.CRITICAL
        assert mod._classify_severity("/latest/meta-data/iam/security-credentials/", "roles") == Severity.HIGH
        assert mod._classify_severity("/latest/meta-data/hostname", "ip-10-0-0-1") == Severity.MEDIUM
        session.close()

    def test_header_string_formatting(self) -> None:
        from cloud.cloud_api_scanner import CloudApiScanner

        assert "Metadata-Flavor" in CloudApiScanner._header_string({"Metadata-Flavor": "Google"})
        assert CloudApiScanner._header_string(None) == ""
        assert CloudApiScanner._header_string({}) == ""


# ══════════════════════════════════════════════════════════════════════
# IAM CHAINING TESTS
# ══════════════════════════════════════════════════════════════════════

class TestIamChainingLogic:
    """Test CloudIamChaining-specific logic."""

    def test_escalation_path_dataclass(self) -> None:
        from cloud.cloud_iam_chaining import EscalationPath

        path = EscalationPath(
            provider="AWS", action="iam:PassRole",
            description="test", severity="High",
        )
        assert path.provider == "AWS"
        assert path.source_role == ""
        assert path.evidence == {}

    def test_no_creds_no_findings(self, tmp_path: Path) -> None:
        from cloud.cloud_iam_chaining import CloudIamChaining

        mod, session = _make_module(CloudIamChaining, tmp_path)
        result = asyncio.run(mod.run())
        assert result.findings == []
        session.close()


# ══════════════════════════════════════════════════════════════════════
# CONTAINER ESCAPE TESTS
# ══════════════════════════════════════════════════════════════════════

class TestContainerEscapeLogic:
    """Test ContainerEscape-specific logic."""

    def test_detect_container_env_returns_bool(self, tmp_path: Path) -> None:
        from cloud.container_escape import ContainerEscape

        mod, session = _make_module(ContainerEscape, tmp_path, "10.0.0.1")
        result = mod._detect_container_env()
        assert isinstance(result, bool)
        session.close()

    def test_escape_checks_completeness(self) -> None:
        from cloud.container_escape import _ESCAPE_CHECKS

        assert len(_ESCAPE_CHECKS) >= 8
        check_ids = [c["id"] for c in _ESCAPE_CHECKS]
        assert "privileged_container" in check_ids
        assert "docker_socket" in check_ids
        assert "cgroup_release_agent" in check_ids
        assert "proc_root_traversal" in check_ids


# ══════════════════════════════════════════════════════════════════════
# K8S ATTACK TESTS
# ══════════════════════════════════════════════════════════════════════

class TestK8sAttackLogic:
    """Test K8sAttack-specific logic."""

    def test_kubelet_paths_coverage(self) -> None:
        from cloud.k8s_attack import _KUBELET_PATHS

        paths = [p[0] for p in _KUBELET_PATHS]
        assert "/pods" in paths
        assert "/healthz" in paths

    def test_k8s_api_paths_coverage(self) -> None:
        from cloud.k8s_attack import _K8S_API_PATHS

        paths = [p[0] for p in _K8S_API_PATHS]
        assert "/api/v1/secrets" in paths
        assert "/api/v1/namespaces" in paths
        assert "/version" in paths


# ══════════════════════════════════════════════════════════════════════
# TF STATE POISONER TESTS
# ══════════════════════════════════════════════════════════════════════

class TestTfStatePoisonerLogic:
    """Test TfStatePoisoner-specific logic."""

    def test_valid_tfstate_detection(self, tmp_path: Path) -> None:
        from cloud.tf_state_poisoner import TfStatePoisoner

        mod, session = _make_module(TfStatePoisoner, tmp_path)
        assert mod._is_valid_tfstate('{"version": 4, "resources": []}') is True
        assert mod._is_valid_tfstate('{"version": 3, "modules": []}') is True
        assert mod._is_valid_tfstate("<html>404</html>") is False
        assert mod._is_valid_tfstate("{}") is False
        assert mod._is_valid_tfstate("not json at all") is False
        session.close()

    def test_secret_extraction(self, tmp_path: Path) -> None:
        from cloud.tf_state_poisoner import TfStatePoisoner

        mod, session = _make_module(TfStatePoisoner, tmp_path)
        body = '{"password": "SuperSecretPass123", "token": "ghp_abcdefghijklmnopqrstuvwxyz1234567890"}'
        secrets = mod._extract_secrets(body)
        assert len(secrets) >= 1
        types = [s["type"] for s in secrets]
        assert any("Password" in t or "Secret" in t or "Token" in t for t in types)
        session.close()

    def test_resource_extraction(self, tmp_path: Path) -> None:
        from cloud.tf_state_poisoner import TfStatePoisoner

        mod, session = _make_module(TfStatePoisoner, tmp_path)
        body = '{"version": 4, "resources": [{"type": "aws_instance", "name": "web"}, {"type": "aws_s3_bucket", "name": "data"}]}'
        resources = mod._extract_resources(body)
        assert len(resources) == 2
        assert resources[0]["type"] == "aws_instance"
        session.close()


# ══════════════════════════════════════════════════════════════════════
# SERVERLESS INJECT TESTS
# ══════════════════════════════════════════════════════════════════════

class TestServerlessInjectLogic:
    """Test ServerlessInject-specific logic."""

    def test_api_gateway_detection(self, tmp_path: Path) -> None:
        from cloud.serverless_inject import ServerlessInject

        mod, session = _make_module(ServerlessInject, tmp_path)
        assert mod._is_api_gateway_response(
            '{"message": "Missing Authentication Token"}',
            {"x-amzn-requestid": "abc123"},
        ) is True
        assert mod._is_api_gateway_response(
            "<html>Normal</html>", {"content-type": "text/html"},
        ) is False
        session.close()

    def test_env_extraction_from_response(self, tmp_path: Path) -> None:
        from cloud.serverless_inject import ServerlessInject

        mod, session = _make_module(ServerlessInject, tmp_path)
        body = "Error: AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENG"
        env_vars = mod._extract_env_from_response(body)
        assert len(env_vars) >= 2
        names = [v["name"] for v in env_vars]
        assert "AWS Access Key" in names
        assert "AWS Secret Key" in names
        session.close()

    def test_injection_payloads_structure(self) -> None:
        from cloud.serverless_inject import _LAMBDA_INJECTION_PAYLOADS

        assert len(_LAMBDA_INJECTION_PAYLOADS) >= 3
        for p in _LAMBDA_INJECTION_PAYLOADS:
            assert "name" in p
            assert "payload" in p
            assert "indicators" in p
            assert isinstance(p["indicators"], list)


# ══════════════════════════════════════════════════════════════════════
# ATTACK CHAIN INTEGRATION TESTS
# ══════════════════════════════════════════════════════════════════════

class TestCloudAttackChains:
    """Verify Sprint 1 attack chains are registered."""

    def test_cloud_chains_exist(self) -> None:
        from common.attack_chains import _CHAIN_DEFINITIONS

        chain_ids = [c.chain_id for c in _CHAIN_DEFINITIONS]
        assert "ssrf_to_cloud_metadata" in chain_ids
        assert "container_escape_to_host" in chain_ids
        assert "k8s_pod_to_cluster_admin" in chain_ids

    def test_cloud_chains_have_correct_modules(self) -> None:
        from common.attack_chains import _CHAIN_DEFINITIONS

        chain_map = {c.chain_id: c for c in _CHAIN_DEFINITIONS}

        ssrf_chain = chain_map.get("ssrf_to_cloud_metadata")
        assert ssrf_chain is not None
        assert ssrf_chain.next_module == "cloud_api_scanner"

        escape_chain = chain_map.get("container_escape_to_host")
        assert escape_chain is not None
        assert escape_chain.next_module == "cloud_api_scanner"

        k8s_chain = chain_map.get("k8s_pod_to_cluster_admin")
        assert k8s_chain is not None
        assert k8s_chain.next_module == "k8s_attack"

    def test_chain_engine_registers_all(self) -> None:
        from common.attack_chains import ChainEngine, _CHAIN_DEFINITIONS

        engine = ChainEngine(auto_trigger=False)
        engine.register_all()
        # Should register without error — count includes Sprint 0 + Sprint 1
        assert len(_CHAIN_DEFINITIONS) >= 18  # 15 from Sprint 0 + 3 from Sprint 1
