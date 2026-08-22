"""Deterministic Task 008 tests for container, install, and version surfaces."""

from __future__ import annotations

import asyncio
import copy
import json
import os
import re
import subprocess
import sys
import types
from pathlib import Path

import pytest
import yaml

from common.dashboard.auth import _get_users
from common.dashboard.server import DashboardServer
from common.reporting.report_engine import ReportConfig, ReportEngine
from common.intel.nuclei_sync import NUCLEI_SYNC_USER_AGENT
from common.intel.technique_learner import TECHNIQUE_LEARNER_USER_AGENT
from common.version import PRODUCT_LABEL, PRODUCT_USER_AGENT, VERSION
from scripts import generate_build_manifest as build_manifest_module
from scripts import verify_container_runtime


ROOT = Path(__file__).resolve().parents[1]
PINNED_PYTHON = (
    "python:3.13.9-slim-bookworm@"
    "sha256:b685a4fa58bb19d1814d78a1ec0f0208f351452724f78b20212c984d6e124a34"
)
PINNED_NODE = (
    "node:20.19.5-bookworm-slim@"
    "sha256:9e70124bd00f47dd023e349cd587132ae61892acc0e47ed641416c3e18f401c3"
)
PINNED_NPM = "10.8.2"
_SCAN_JOBS_PATH = DashboardServer._scan_jobs_db_path.fget


def _read(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


def _manifest_command(*extra: str) -> list[str]:
    return [
        sys.executable,
        "scripts/generate_build_manifest.py",
        "--image-ref",
        f"forge-suite:{VERSION}",
        "--python-image",
        PINNED_PYTHON,
        "--node-image",
        PINNED_NODE,
        "--npm-version",
        PINNED_NPM,
        "--vcs-ref",
        "0123456789abcdef",
        *extra,
    ]


_EXPECTED_WRITABLE_MOUNTS = {
    "forge-dashboard": {
        "/opt/forge-suite/results",
        "/opt/forge-suite/webforge/results",
        "/opt/forge-suite/netforge/results",
        "/opt/forge-suite/adforge/results",
        "/opt/forge-suite/aiforge/results",
        "/opt/forge-suite/data",
        "/opt/forge-suite/state",
    },
    "forge-c2": {"/opt/forge-suite/c2_data"},
    "forge-scan": {
        "/opt/forge-suite/results",
        "/opt/forge-suite/webforge/results",
        "/opt/forge-suite/netforge/results",
        "/opt/forge-suite/adforge/results",
        "/opt/forge-suite/aiforge/results",
        "/opt/forge-suite/data",
        "/opt/forge-suite/state",
    },
}
_EXPECTED_CAPABILITIES = {
    "forge-dashboard": None,
    "forge-c2": ["NET_BIND_SERVICE"],
    "forge-scan": ["NET_RAW"],
}


def _volume_destination(volume: object) -> tuple[str, bool]:
    if isinstance(volume, str):
        parts = volume.split(":")
        return parts[1], len(parts) < 3 or parts[2] != "ro"
    if not isinstance(volume, dict) or not isinstance(volume.get("target"), str):
        raise ValueError("volume entry is malformed")
    return volume["target"], not bool(volume.get("read_only"))


def _validate_compose_runtime_policy(document: object) -> None:
    if not isinstance(document, dict) or not isinstance(document.get("services"), dict):
        raise ValueError("Compose services are missing")
    services = document["services"]
    if set(services) != set(_EXPECTED_WRITABLE_MOUNTS):
        raise ValueError("Compose service set changed")
    for name, expected_writable in _EXPECTED_WRITABLE_MOUNTS.items():
        service = services[name]
        if not isinstance(service, dict):
            raise ValueError(f"{name}: service is malformed")
        if service.get("user") != "10001:10001":
            raise ValueError(f"{name}: numeric runtime user is required")
        if service.get("read_only") is not True:
            raise ValueError(f"{name}: read-only root filesystem is required")
        if service.get("init") is not True:
            raise ValueError(f"{name}: init is required")
        if service.get("cap_drop") != ["ALL"]:
            raise ValueError(f"{name}: every ambient capability must be dropped")
        if service.get("cap_add") != _EXPECTED_CAPABILITIES[name]:
            raise ValueError(f"{name}: capability allowlist changed")
        if service.get("security_opt") != ["no-new-privileges:true"]:
            raise ValueError(f"{name}: no-new-privileges is required")
        if service.get("logging") != {
            "driver": "json-file",
            "options": {"max-size": "10m", "max-file": "3"},
        }:
            raise ValueError(f"{name}: bounded logging policy changed")
        if service.get("privileged") not in (None, False) or service.get("devices"):
            raise ValueError(f"{name}: privileged/device access is forbidden")
        if not isinstance(service.get("pids_limit"), int) or service["pids_limit"] <= 0:
            raise ValueError(f"{name}: positive PID limit is required")
        if not isinstance(service.get("cpus"), (int, float)) or service["cpus"] <= 0:
            raise ValueError(f"{name}: positive CPU limit is required")
        memory = service.get("mem_limit")
        if not isinstance(memory, str) or memory in {"", "0", "0b"}:
            raise ValueError(f"{name}: positive memory limit is required")

        writable: set[str] = set()
        read_only: set[str] = set()
        for volume in service.get("volumes", []):
            destination, is_writable = _volume_destination(volume)
            if destination == "/var/run/docker.sock":
                raise ValueError(f"{name}: Docker socket mount is forbidden")
            (writable if is_writable else read_only).add(destination)
        if writable != expected_writable:
            raise ValueError(f"{name}: writable mount allowlist changed")
        if name == "forge-dashboard" and read_only != {
            "/run/secrets/forge-dashboard-tls-cert.pem",
            "/run/secrets/forge-dashboard-tls-key.pem",
        }:
            raise ValueError("forge-dashboard: TLS bind mounts must be read-only")

        tmpfs_targets = {str(entry).split(":", 1)[0] for entry in service.get("tmpfs", [])}
        if tmpfs_targets != {"/tmp", "/home/forge"}:
            raise ValueError(f"{name}: tmpfs allowlist changed")


def test_container_uses_immutable_inputs_and_locked_builds() -> None:
    dockerfile = _read("Dockerfile")
    assert f"ARG PYTHON_IMAGE={PINNED_PYTHON}" in dockerfile
    assert f"ARG NODE_IMAGE={PINNED_NODE}" in dockerfile
    assert "FROM ${NODE_IMAGE} AS frontend-builder" in dockerfile
    assert "FROM ${PYTHON_IMAGE} AS python-base" in dockerfile
    assert "FROM python-base AS python-builder" in dockerfile
    assert "FROM python-base AS runtime" in dockerfile
    assert "groupadd --gid 10001 forge" in dockerfile
    assert "--uid 10001" in dockerfile
    assert "--gid 10001" in dockerfile
    assert "snapshot.debian.org/archive/debian/20251117T000000Z" in dockerfile
    assert "snapshot.debian.org/archive/debian-security/20251117T000000Z" in dockerfile
    for package_pin in (
        "gcc=4:12.2.0-3",
        "libffi-dev=3.4.4-1",
        "libssl-dev=3.0.17-1~deb12u3",
        "chromium=142.0.7444.162-1~deb12u1",
        "curl=7.88.1-10+deb12u14",
        "dnsutils=1:9.18.41-1~deb12u1",
        "hydra=9.4-1",
        "iputils-ping=3:20221126-1+deb12u1",
        "netcat-openbsd=1.219-1",
        "nmap=7.93+dfsg1-1",
        "smbclient=2:4.17.12+dfsg-0+deb12u2",
    ):
        assert package_pin in dockerfile
    assert "npm ci --ignore-scripts --no-audit --no-fund" in dockerfile
    assert 'test "$(node --version)" = "v20.19.5"' in dockerfile
    assert f'test "$(npm --version)" = "{PINNED_NPM}"' in dockerfile
    assert "npm install --global" not in dockerfile
    assert "npm run typecheck" in dockerfile
    assert "COPY requirements.lock" in dockerfile
    assert "--require-hashes" in dockerfile
    assert "requirements.txt" not in dockerfile
    assert "HEALTHCHECK NONE" in dockerfile
    assert "curl -fsk" not in dockerfile
    assert "COPY apex-ui/ ./" not in dockerfile
    assert "COPY --chown=0:0 . ." not in dockerfile
    assert dockerfile.count("COPY --chown=0:0") == 12
    for source in (
        "common",
        "webforge",
        "netforge",
        "adforge",
        "aiforge",
        "forge_c2",
        "forge_collab",
        "forge_payload",
        "cloud",
        "leak_intel",
    ):
        assert f"COPY --chown=0:0 {source} ./{source}" in dockerfile
    assert "chown -R forge:forge /opt/forge-suite" not in dockerfile
    assert "install -d -o forge -g forge -m 0700" in dockerfile
    assert "ln -s /opt/forge-suite/data/cve_cache.db netforge/data/cve_cache.db" in dockerfile
    for variable in (
        "FORGE_AUTHORIZATION_DB=/opt/forge-suite/state/authorization.db",
        "FORGE_DASHBOARD_STATE_DIR=/opt/forge-suite/state",
        "FORGE_ENGAGEMENT_DB=/opt/forge-suite/state/engagement.db",
        "FORGE_INTEL_BACKUP_DIR=/opt/forge-suite/data/backups",
    ):
        assert variable in dockerfile

    lowered = dockerfile.lower()
    assert "releases/latest" not in lowered
    assert "projectdiscovery" not in lowered
    assert "nuclei.zip" not in lowered
    assert 'org.forge.optional.nuclei="operator-provided-not-bundled"' in dockerfile
    assert "FORGE_DASHBOARD_PASSWORD=" not in dockerfile
    assert "FORGE_C2_ADMIN_PW=" not in dockerfile


def test_compose_is_profile_independent_fail_closed_and_least_privileged() -> None:
    compose = _read("docker-compose.yml")
    document = yaml.safe_load(compose)
    _validate_compose_runtime_policy(document)
    assert "${FORGE_VERSION:?Set FORGE_VERSION from the VERSION file}" in compose
    assert "${FORGE_DASHBOARD_PASSWORD_HASH:?" not in compose
    assert "${FORGE_DASHBOARD_TLS_CERT_FILE:?" not in compose
    assert "${FORGE_DASHBOARD_TLS_KEY_FILE:?" not in compose
    assert 'FORGE_DASHBOARD_PASSWORD_HASH: "${FORGE_DASHBOARD_PASSWORD_HASH-}"' in compose
    assert "${FORGE_DASHBOARD_TLS_CERT_FILE:-/dev/null}" in compose
    assert "${FORGE_DASHBOARD_TLS_KEY_FILE:-/dev/null}" in compose
    assert "FORGE_DASHBOARD_PASSWORD_HASH is required for forge-dashboard" in compose
    assert "FORGE_DASHBOARD_TLS_CERT_FILE must name a non-empty certificate" in compose
    assert "FORGE_DASHBOARD_TLS_KEY_FILE must name a non-empty private key" in compose
    assert "FORGE_DASHBOARD_TLS_CERT: /run/secrets/forge-dashboard-tls-cert.pem" in compose
    assert "FORGE_DASHBOARD_TLS_KEY: /run/secrets/forge-dashboard-tls-key.pem" in compose
    assert 'FORGE_DASHBOARD_PUBLIC_HOST: "${FORGE_DASHBOARD_PUBLIC_HOST:-localhost}"' in compose
    assert "\nsecrets:" not in compose
    assert 'profiles: ["local-lab-c2"]' in compose
    assert 'test -n "$${FORGE_C2_ADMIN_PW:-}"' in compose
    assert "FORGE_C2_ADMIN_PW is required" in compose
    c2_service = compose.split("  forge-c2:", 1)[1].split("  forge-scan:", 1)[0]
    assert 'restart: "no"' in c2_service
    assert "restart: unless-stopped" not in c2_service
    assert "forge-c2-data:/opt/forge-suite/c2_data" in c2_service
    dashboard_service = compose.split("  forge-dashboard:", 1)[1].split("  forge-c2:", 1)[0]
    assert 'restart: "no"' in dashboard_service
    assert "--cacert" in dashboard_service
    assert document["services"]["forge-dashboard"]["healthcheck"]["test"] == (
        verify_container_runtime.HEALTHCHECK
    )
    assert "cap_add" not in document["services"]["forge-dashboard"]
    assert document["services"]["forge-scan"]["cap_add"] == ["NET_RAW"]
    assert "-k" not in document["services"]["forge-dashboard"]["healthcheck"]["test"]
    assert "https://localhost:1337/api/v1/health" in dashboard_service
    assert "forge2026" not in compose.lower()
    assert "changeme" not in compose.lower()


def test_compose_policy_rejects_seeded_privilege_and_write_expansion() -> None:
    baseline = yaml.safe_load(_read("docker-compose.yml"))
    mutations = {
        "writable root": lambda service: service.__setitem__("read_only", False),
        "ambient capabilities": lambda service: service.__setitem__("cap_drop", []),
        "SYS_ADMIN": lambda service: service.__setitem__("cap_add", ["SYS_ADMIN"]),
        "privilege escalation": lambda service: service.__setitem__("security_opt", []),
        "unbounded processes": lambda service: service.__setitem__("pids_limit", 0),
        "unbounded memory": lambda service: service.__setitem__("mem_limit", "0"),
        "Docker socket": lambda service: service["volumes"].append(
            "/var/run/docker.sock:/var/run/docker.sock"
        ),
    }
    for label, mutate in mutations.items():
        seeded = copy.deepcopy(baseline)
        mutate(seeded["services"]["forge-dashboard"])
        with pytest.raises(ValueError) as error:
            _validate_compose_runtime_policy(seeded)
        assert str(error.value), label


def _dashboard_runtime_inspection() -> list[dict[str, object]]:
    mounts = [
        {
            "Type": "volume",
            "Name": f"forge-ci-{index}",
            "Source": f"/var/lib/docker/volumes/forge-ci-{index}/_data",
            "Destination": destination,
            "RW": True,
        }
        for index, destination in enumerate(sorted(verify_container_runtime.WRITABLE_VOLUMES))
    ]
    mounts.extend(
        {
            "Type": "bind",
            "Source": f"/tmp/operator/{Path(destination).name}",
            "Destination": destination,
            "RW": False,
        }
        for destination in sorted(verify_container_runtime.READ_ONLY_BINDS)
    )
    return [
        {
            "State": {"Running": True, "Health": {"Status": "healthy"}},
            "Config": {
                "User": "10001:10001",
                "Healthcheck": {"Test": verify_container_runtime.HEALTHCHECK},
                "Env": [
                    "FORGE_DASHBOARD_PASSWORD_HASH=scrypt:fixture",
                    "FORGE_DASHBOARD_TLS_CERT=/run/secrets/forge-dashboard-tls-cert.pem",
                    "FORGE_DASHBOARD_TLS_KEY=/run/secrets/forge-dashboard-tls-key.pem",
                    f"FORGE_VERSION={VERSION}",
                ],
            },
            "HostConfig": {
                "ReadonlyRootfs": True,
                "Privileged": False,
                "Init": True,
                "CapDrop": ["ALL"],
                "CapAdd": None,
                "SecurityOpt": ["no-new-privileges:true"],
                "Devices": [],
                "DeviceRequests": [],
                "NetworkMode": "forge-ci_default",
                "PidsLimit": 512,
                "Memory": 2 * 1024**3,
                "NanoCpus": 2 * 10**9,
                "ShmSize": 512 * 1024**2,
                "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
                "LogConfig": {
                    "Type": "json-file",
                    "Config": {"max-file": "3", "max-size": "10m"},
                },
                "PortBindings": {"1337/tcp": [{"HostIp": "127.0.0.1", "HostPort": "1337"}]},
                "Tmpfs": {
                    "/tmp": "rw,noexec,nosuid,nodev,size=64m,uid=10001,gid=10001,mode=1777",
                    "/home/forge": "rw,nosuid,nodev,size=256m,uid=10001,gid=10001,mode=0700",
                },
            },
            "Mounts": mounts,
        }
    ]


def test_live_dashboard_runtime_validator_fails_closed() -> None:
    baseline = _dashboard_runtime_inspection()
    assert verify_container_runtime.validate_dashboard_inspection(baseline) == {
        "containers": 1,
        "persistent_volumes": 7,
        "read_only_binds": 2,
        "tmpfs_mounts": 2,
    }

    mutations = {
        "root writable": lambda record: record["HostConfig"].__setitem__("ReadonlyRootfs", False),
        "extra capability": lambda record: record["HostConfig"].__setitem__(
            "CapAdd", ["CAP_NET_RAW"]
        ),
        "untrusted health": lambda record: record["Config"]["Healthcheck"].__setitem__(
            "Test", ["CMD", "curl", "-k", "https://localhost:1337/api/v1/health"]
        ),
        "Docker socket": lambda record: record["Mounts"].append(
            {
                "Type": "bind",
                "Source": "/var/run/docker.sock",
                "Destination": "/var/run/docker.sock",
                "RW": True,
            }
        ),
    }
    for label, mutate in mutations.items():
        seeded = copy.deepcopy(baseline)
        mutate(seeded[0])
        with pytest.raises(verify_container_runtime.RuntimeValidationError) as error:
            verify_container_runtime.validate_dashboard_inspection(seeded)
        assert str(error.value), label


def test_ci_exercises_the_hardened_compose_runtime_and_sanitizes_evidence() -> None:
    workflow = yaml.safe_load(_read(".github/workflows/ci.yml"))
    steps = workflow["jobs"]["container-sbom"]["steps"]
    by_name = {step["name"]: step for step in steps}
    interpolation = by_name["Validate secure Compose interpolation"]["run"]
    runtime = by_name["Prove authenticated TLS startup and health"]["run"]

    assert "--profile local-lab-c2 config forge-c2" in interpolation
    assert "--profile scan config forge-scan" in interpolation
    assert "env -u FORGE_VERSION" in interpolation
    assert (
        "docker compose --project-name forge-ci up --detach --no-build forge-dashboard" in runtime
    )
    assert "docker run -d" not in runtime
    assert "chmod 0444 build/container/dashboard-cert.pem" in runtime
    assert "chmod 0400 build/container/dashboard-key.pem" in runtime
    assert "sudo chown 10001:10001" in runtime
    assert "curl --fail --silent --show-error --cacert" in runtime
    assert "https://127.0.0.1:1337/api/v1/health" in runtime
    assert 'test "${protected_status}" = "401"' in runtime
    assert "scripts/verify_container_runtime.py" in runtime
    assert "--sanitized-output build/container/runtime-inspect.json" in runtime
    assert "rm -f build/container/runtime-inspect.raw.json" in runtime


def test_install_is_noninteractive_hash_locked_and_offline_safe() -> None:
    installer = _read("install.sh")
    assert os.access(ROOT / "install.sh", os.X_OK)
    assert 'EXPECTED_PYTHON_VERSION="3.13.9"' in installer
    assert 'EXPECTED_NODE_VERSION="20.19.5"' in installer
    assert 'EXPECTED_NPM_VERSION="10.8.2"' in installer
    assert "--require-hashes" in installer
    assert "requirements.lock" in installer
    assert '"${npm_bin}" ci --ignore-scripts --no-audit --no-fund' in installer
    assert '"${npm_bin}" run typecheck' in installer
    assert '"${npm_bin}" run build' in installer
    assert "requirements.txt" not in installer
    assert "pip install --upgrade" not in installer
    assert not re.search(r"(?m)^\s*read\s", installer)
    assert "8.8.8.8" not in installer
    assert "1.1.1.1" not in installer
    assert not re.search(r"(?m)^\s*(curl|wget)\b", installer)
    assert not re.search(r"(?m)^\s*cp\s+.*\.env", installer)
    assert "operator-provided binary detected" in installer
    assert "no .env file was written" in installer


def test_secret_examples_are_blank_and_docker_context_is_clean() -> None:
    values: dict[str, str] = {}
    env_example = _read(".env.example")
    for line in env_example.splitlines():
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            values[key] = value

    for key in (
        "ANTHROPIC_API_KEY",
        "FORGE_C2_ADMIN_PW",
        "FORGE_DASHBOARD_PASSWORD_HASH",
        "FORGE_DASHBOARD_TLS_CERT_FILE",
        "FORGE_DASHBOARD_TLS_KEY_FILE",
        "FORGE_GITHUB_TOKEN",
        "FORGE_JIRA_TOKEN",
        "FORGE_NVD_API_KEY",
        "FORGE_SLACK_WEBHOOK",
        "FORGE_TEAMS_WEBHOOK",
    ):
        assert values[key] == ""
    assert "sk-ant-" not in env_example
    assert "forge2026" not in env_example.lower()
    assert "changeme" not in env_example.lower()

    dockerignore = _read(".dockerignore")
    effective_patterns = [
        line for line in dockerignore.splitlines() if line and not line.startswith("#")
    ]
    assert effective_patterns[0] == "**"
    for pattern in (
        "!VERSION",
        "!requirements.lock",
        "!common/**",
        "!apex-ui/src/**",
        "**/node_modules/",
        "**/results/",
        "common/intel/forge_intel.db",
        "webforge/engagement.db",
    ):
        assert pattern in effective_patterns
    assert "!.env.example" not in effective_patterns


def test_dashboard_auth_has_no_implicit_user(monkeypatch) -> None:
    monkeypatch.delenv("FORGE_DASHBOARD_PASSWORD", raising=False)
    monkeypatch.delenv("FORGE_DASHBOARD_PASSWORD_HASH", raising=False)
    assert _get_users() == {}


def test_dashboard_direct_start_fails_without_credentials(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.delenv("FORGE_DASHBOARD_PASSWORD", raising=False)
    monkeypatch.delenv("FORGE_DASHBOARD_PASSWORD_HASH", raising=False)
    state_root = tmp_path / "dashboard-state"
    monkeypatch.setenv("FORGE_DASHBOARD_STATE_DIR", str(state_root))
    server = DashboardServer(host="127.0.0.1")
    assert server._history_path == state_root / "scan_history.json"
    assert _SCAN_JOBS_PATH is not None
    assert _SCAN_JOBS_PATH(server) == state_root / "scan_history.db"
    assert server._scan_logs_dir == state_root / "dashboard_scans"
    assert server._control_dir == state_root / "dashboard_controls"

    with pytest.raises(RuntimeError, match="dashboard credentials are required"):
        asyncio.run(server.start())


def test_dashboard_direct_start_accepts_operator_credentials(monkeypatch) -> None:
    monkeypatch.setenv("FORGE_DASHBOARD_PASSWORD", "fixture-operator-secret")
    monkeypatch.delenv("FORGE_DASHBOARD_PASSWORD_HASH", raising=False)
    served: list[bool] = []

    class _Server:
        def __init__(self, _config: object) -> None:
            pass

        async def serve(self) -> None:
            served.append(True)

    fake_uvicorn = types.SimpleNamespace(
        Config=lambda **kwargs: kwargs,
        Server=_Server,
    )
    monkeypatch.setitem(sys.modules, "uvicorn", fake_uvicorn)

    server = DashboardServer(host="127.0.0.1")
    monkeypatch.setattr(server, "create_app", lambda: object())
    monkeypatch.setattr(server, "_create_ssl_context", lambda: None)
    monkeypatch.setattr(server.event_bus, "async_subscribe", lambda *_args: None)
    monkeypatch.setattr(server.event_bus, "start", lambda **_kwargs: None)

    asyncio.run(server.start())
    assert served == [True]


def test_canonical_version_reaches_server_and_reports(tmp_path: Path) -> None:
    assert (
        subprocess.run(
            ["make", "-s", "version"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        == VERSION
    )

    package = json.loads(_read("apex-ui/package.json"))
    assert package["version"] == VERSION
    assert package["engines"] == {"node": "20.19.5", "npm": PINNED_NPM}
    assert package["packageManager"] == f"npm@{PINNED_NPM}"
    vite_config = _read("apex-ui/vite.config.js")
    assert "../VERSION" in vite_config
    assert "__FORGE_VERSION__" in vite_config
    app_source = _read("apex-ui/src/App.jsx")
    assert "FORGE_UI_VERSION = __FORGE_VERSION__" in app_source
    assert "FORGE v{FORGE_UI_VERSION}" in app_source
    assert PRODUCT_USER_AGENT == f"Forge-Suite/{VERSION}"
    assert TECHNIQUE_LEARNER_USER_AGENT == (
        f"{PRODUCT_USER_AGENT} IntelPipeline (TechniqueLearner)"
    )
    assert NUCLEI_SYNC_USER_AGENT == f"{PRODUCT_USER_AGENT} IntelPipeline (NucleiSync)"
    brain_source = _read("common/brain/brain.py")
    assert "from common.version import PRODUCT_LABEL" in brain_source
    assert "for {PRODUCT_LABEL} —" in brain_source

    server = _read("common/dashboard/server.py")
    assert '(("GET", "/api/v1/health")' not in server  # guard a malformed tuple
    assert '("GET", "/api/v1/health"): ("public_bootstrap", None)' in server
    assert '@app.get("/api/v1/health")' in server
    health_route = server.split('@app.get("/api/v1/health")', 1)[1].split(
        '@app.get("/api/v1/tools")', 1
    )[0]
    assert '"version": VERSION' in health_route
    assert '"auth_required": True' in health_route
    assert '"sso"' not in health_route
    assert "get_sso_config" not in health_route
    for sensitive_field in ("issuer", "authorization_url", "token_url", "redirect_uri"):
        assert sensitive_field not in health_route

    config = ReportConfig(
        formats=["html", "json"],
        output_dir=str(tmp_path),
        include_exec_summary=False,
        include_remediation_roadmap=False,
        include_mitre_appendix=False,
        include_compliance=False,
    )
    paths = asyncio.run(ReportEngine([], config).generate())
    assert PRODUCT_LABEL in Path(paths["html"]).read_text(encoding="utf-8")
    report_json = json.loads(Path(paths["json"]).read_text(encoding="utf-8"))
    assert report_json["product"] == PRODUCT_LABEL
    assert report_json["product_version"] == VERSION


def test_build_manifest_is_deterministic_and_rejects_unpinned_images() -> None:
    env = dict(os.environ)
    env.pop("SOURCE_DATE_EPOCH", None)
    first = subprocess.run(
        _manifest_command(),
        cwd=ROOT,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    second = subprocess.run(
        _manifest_command(),
        cwd=ROOT,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    assert first.stdout == second.stdout
    manifest = json.loads(first.stdout)
    assert manifest["product"]["version"] == VERSION
    assert manifest["product"]["packages"]["frontend"] == {
        "name": "apex-ui",
        "version": VERSION,
        "node": "20.19.5",
        "npm": PINNED_NPM,
        "package_manager": f"npm@{PINNED_NPM}",
    }
    assert manifest["source"]["created_at"] is None
    assert manifest["container"]["base_images"] == {
        "node": PINNED_NODE,
        "python": PINNED_PYTHON,
    }
    assert manifest["container"]["javascript_toolchain"] == {
        "node": "20.19.5",
        "npm": PINNED_NPM,
        "provenance": "bundled-in-immutable-node-base-image",
    }
    assert manifest["container"]["runtime_identity"] == {
        "user": "forge",
        "uid": 10001,
        "gid": 10001,
    }
    assert manifest["container"]["operating_system_packages"]["debian_snapshot"] == (
        "20251117T000000Z"
    )
    assert manifest["container"]["operating_system_packages"]["direct_packages"]["nmap"] == (
        "7.93+dfsg1-1"
    )
    assert manifest["container"]["operating_system_packages"]["direct_packages"]["smbclient"] == (
        "2:4.17.12+dfsg-0+deb12u2"
    )
    assert manifest["container"]["optional_components"]["nuclei"]["status"] == "omitted"
    assert "scripts/generate_build_manifest.py" in {record["path"] for record in manifest["inputs"]}

    command = _manifest_command()
    command[command.index(PINNED_PYTHON)] = "python:3.13.9-slim-bookworm"
    rejected = subprocess.run(
        command,
        cwd=ROOT,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    assert rejected.returncode != 0
    assert "exact tag and sha256 digest" in rejected.stderr


def test_build_manifest_rejects_frontend_package_version_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    frontend_dir = tmp_path / "apex-ui"
    frontend_dir.mkdir()
    (frontend_dir / "package.json").write_text(
        json.dumps(
            {
                "name": "apex-ui",
                "version": "0.0.0",
                "packageManager": f"npm@{PINNED_NPM}",
                "engines": {"node": "20.19.5", "npm": PINNED_NPM},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(build_manifest_module, "ROOT", tmp_path)
    with pytest.raises(ValueError, match="must match VERSION"):
        build_manifest_module._frontend_package(VERSION, PINNED_NPM)
