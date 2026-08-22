#!/usr/bin/env python3
"""Fail closed unless a live dashboard container matches the reviewed policy."""

from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path
from typing import Any


class RuntimeValidationError(RuntimeError):
    """Raised when runtime evidence expands the reviewed container boundary."""


WRITABLE_VOLUMES = frozenset(
    {
        "/opt/forge-suite/results",
        "/opt/forge-suite/webforge/results",
        "/opt/forge-suite/netforge/results",
        "/opt/forge-suite/adforge/results",
        "/opt/forge-suite/aiforge/results",
        "/opt/forge-suite/data",
        "/opt/forge-suite/state",
    }
)
READ_ONLY_BINDS = frozenset(
    {
        "/run/secrets/forge-dashboard-tls-cert.pem",
        "/run/secrets/forge-dashboard-tls-key.pem",
    }
)
TMPFS_TARGETS = frozenset({"/tmp", "/home/forge"})
HEALTHCHECK = [
    "CMD",
    "curl",
    "--fail",
    "--silent",
    "--show-error",
    "--cacert",
    "/run/secrets/forge-dashboard-tls-cert.pem",
    "https://localhost:1337/api/v1/health",
]


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RuntimeValidationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _mapping(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RuntimeValidationError(f"{label} must be an object")
    return value


def _list(value: object, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise RuntimeValidationError(f"{label} must be an array")
    return value


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeValidationError(message)


def _validate_host_config(host: dict[str, Any]) -> None:
    _require(host.get("ReadonlyRootfs") is True, "root filesystem is not read-only")
    _require(host.get("Privileged") is False, "privileged runtime is forbidden")
    _require(host.get("Init") is True, "container init is required")
    _require(host.get("CapDrop") == ["ALL"], "ambient capability drop changed")
    _require(
        host.get("CapAdd") in (None, []),
        "dashboard must not add Linux capabilities",
    )
    _require(
        host.get("SecurityOpt") == ["no-new-privileges:true"],
        "no-new-privileges policy changed",
    )
    _require(not host.get("Devices"), "device access is forbidden")
    _require(not host.get("DeviceRequests"), "device requests are forbidden")
    _require(host.get("NetworkMode") != "host", "host networking is forbidden")
    _require(host.get("PidsLimit") == 512, "PID limit changed")
    _require(host.get("Memory") == 2 * 1024**3, "memory limit changed")
    _require(host.get("NanoCpus") == 2 * 10**9, "CPU limit changed")
    _require(host.get("ShmSize") == 512 * 1024**2, "shared-memory limit changed")

    restart = _mapping(host.get("RestartPolicy"), "HostConfig.RestartPolicy")
    _require(restart == {"Name": "no", "MaximumRetryCount": 0}, "restart policy changed")
    logging = _mapping(host.get("LogConfig"), "HostConfig.LogConfig")
    _require(
        logging == {"Type": "json-file", "Config": {"max-file": "3", "max-size": "10m"}},
        "bounded logging policy changed",
    )
    _require(
        host.get("PortBindings") == {"1337/tcp": [{"HostIp": "127.0.0.1", "HostPort": "1337"}]},
        "dashboard port binding changed",
    )

    tmpfs = _mapping(host.get("Tmpfs"), "HostConfig.Tmpfs")
    _require(set(tmpfs) == TMPFS_TARGETS, "tmpfs destination allowlist changed")
    for destination, required_options in {
        "/tmp": {
            "rw",
            "noexec",
            "nosuid",
            "nodev",
            "size=64m",
            "uid=10001",
            "gid=10001",
            "mode=1777",
        },
        "/home/forge": {
            "rw",
            "nosuid",
            "nodev",
            "size=256m",
            "uid=10001",
            "gid=10001",
            "mode=0700",
        },
    }.items():
        options = tmpfs.get(destination)
        _require(isinstance(options, str), f"{destination} tmpfs options are missing")
        _require(
            set(options.split(",")) == required_options, f"{destination} tmpfs options changed"
        )


def _validate_mounts(raw_mounts: object) -> None:
    mounts = _list(raw_mounts, "Mounts")
    by_destination: dict[str, dict[str, Any]] = {}
    for index, raw_mount in enumerate(mounts):
        mount = _mapping(raw_mount, f"Mounts[{index}]")
        destination = mount.get("Destination")
        _require(isinstance(destination, str) and destination, "mount destination is missing")
        _require(destination not in by_destination, f"duplicate mount destination: {destination}")
        _require(destination != "/var/run/docker.sock", "Docker socket mount is forbidden")
        by_destination[destination] = mount

    allowed = WRITABLE_VOLUMES | READ_ONLY_BINDS | TMPFS_TARGETS
    _require(set(by_destination).issubset(allowed), "unexpected runtime mount is present")
    _require(WRITABLE_VOLUMES.issubset(by_destination), "required writable volume is missing")
    _require(READ_ONLY_BINDS.issubset(by_destination), "required TLS bind is missing")

    for destination in WRITABLE_VOLUMES:
        mount = by_destination[destination]
        _require(mount.get("Type") == "volume", f"{destination} must be a named volume")
        _require(mount.get("RW") is True, f"{destination} must be writable")
        _require(bool(mount.get("Name")), f"{destination} volume identity is missing")
    for destination in READ_ONLY_BINDS:
        mount = by_destination[destination]
        source = mount.get("Source")
        _require(mount.get("Type") == "bind", f"{destination} must be a bind mount")
        _require(mount.get("RW") is False, f"{destination} must be read-only")
        _require(
            isinstance(source, str) and Path(source).is_absolute() and source != "/dev/null",
            f"{destination} source must be an operator-owned absolute file",
        )
    for destination in TMPFS_TARGETS & set(by_destination):
        mount = by_destination[destination]
        _require(mount.get("Type") == "tmpfs", f"{destination} must be tmpfs")
        _require(mount.get("RW") is True, f"{destination} tmpfs must be writable")


def _validate_config(config: dict[str, Any]) -> None:
    _require(config.get("User") == "10001:10001", "numeric runtime user changed")
    _require(config.get("Healthcheck", {}).get("Test") == HEALTHCHECK, "TLS healthcheck changed")
    environment = _list(config.get("Env"), "Config.Env")
    values: dict[str, str] = {}
    for raw in environment:
        _require(isinstance(raw, str) and "=" in raw, "malformed environment entry")
        key, value = raw.split("=", 1)
        _require(key not in values, f"duplicate environment variable: {key}")
        values[key] = value
    _require("FORGE_DASHBOARD_PASSWORD" not in values, "plaintext dashboard password is forbidden")
    _require(bool(values.get("FORGE_DASHBOARD_PASSWORD_HASH")), "dashboard verifier is missing")
    _require(
        values.get("FORGE_DASHBOARD_TLS_CERT") == "/run/secrets/forge-dashboard-tls-cert.pem",
        "dashboard certificate path changed",
    )
    _require(
        values.get("FORGE_DASHBOARD_TLS_KEY") == "/run/secrets/forge-dashboard-tls-key.pem",
        "dashboard private-key path changed",
    )


def validate_dashboard_inspection(document: object) -> dict[str, int]:
    records = _list(document, "inspection document")
    _require(len(records) == 1, "inspection must contain exactly one container")
    record = _mapping(records[0], "inspection record")
    state = _mapping(record.get("State"), "State")
    _require(state.get("Running") is True, "dashboard container is not running")
    health = _mapping(state.get("Health"), "State.Health")
    _require(health.get("Status") == "healthy", "dashboard container is not healthy")
    _validate_config(_mapping(record.get("Config"), "Config"))
    _validate_host_config(_mapping(record.get("HostConfig"), "HostConfig"))
    _validate_mounts(record.get("Mounts"))
    return {
        "containers": 1,
        "persistent_volumes": len(WRITABLE_VOLUMES),
        "read_only_binds": len(READ_ONLY_BINDS),
        "tmpfs_mounts": len(TMPFS_TARGETS),
    }


def sanitized_inspection(document: object) -> list[dict[str, Any]]:
    """Return replayable inspect evidence without the authentication verifier."""
    records = copy.deepcopy(_list(document, "inspection document"))
    _require(len(records) == 1, "inspection must contain exactly one container")
    record = _mapping(records[0], "inspection record")
    config = _mapping(record.get("Config"), "Config")
    environment = _list(config.get("Env"), "Config.Env")
    redacted = False
    for index, raw in enumerate(environment):
        if isinstance(raw, str) and raw.startswith("FORGE_DASHBOARD_PASSWORD_HASH="):
            environment[index] = "FORGE_DASHBOARD_PASSWORD_HASH=<redacted-after-validation>"
            redacted = True
    _require(redacted, "dashboard verifier was not available for redaction")
    return records


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inspect", required=True, type=Path)
    parser.add_argument("--sanitized-output", type=Path)
    args = parser.parse_args(argv)
    try:
        document = json.loads(
            args.inspect.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_object,
        )
        counts = validate_dashboard_inspection(document)
        if args.sanitized_output is not None:
            args.sanitized_output.parent.mkdir(parents=True, exist_ok=True)
            args.sanitized_output.write_text(
                json.dumps(sanitized_inspection(document), indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
    except (OSError, json.JSONDecodeError, RuntimeValidationError) as exc:
        print(f"FAIL container-runtime: {exc}", file=sys.stderr)
        return 1
    print("PASS container-runtime " + " ".join(f"{key}={value}" for key, value in counts.items()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
