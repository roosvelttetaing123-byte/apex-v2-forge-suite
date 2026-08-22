#!/usr/bin/env python3
"""Generate deterministic release/build metadata from reviewed inputs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
INPUT_PATHS = (
    "VERSION",
    "requirements.lock",
    "apex-ui/package.json",
    "apex-ui/package-lock.json",
    "Dockerfile",
    "docker-compose.yml",
    ".dockerignore",
    "install.sh",
    "Makefile",
    "scripts/generate_build_manifest.py",
)
SEMVER_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
PINNED_IMAGE_RE = re.compile(r"^[^\s@:]+(?:/[^\s@:]+)*:[^\s@]+@sha256:[0-9a-f]{64}$")
SAFE_REVISION_RE = re.compile(r"^[A-Za-z0-9._/-]+$")


def _read_version() -> str:
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    if not SEMVER_RE.fullmatch(version):
        raise ValueError("VERSION must contain one semantic version")
    return version


def _file_record(relative_path: str) -> dict[str, Any]:
    path = ROOT / relative_path
    if not path.is_file():
        raise ValueError(f"required build input is missing: {relative_path}")
    content = path.read_bytes()
    return {
        "path": relative_path,
        "sha256": hashlib.sha256(content).hexdigest(),
        "size": len(content),
    }


def _validate_pinned_image(label: str, reference: str) -> str:
    if not PINNED_IMAGE_RE.fullmatch(reference):
        raise ValueError(f"{label} must include an exact tag and sha256 digest")
    return reference


def _frontend_package(version: str, npm_version: str) -> dict[str, str]:
    package_path = ROOT / "apex-ui" / "package.json"
    try:
        package = json.loads(package_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("apex-ui/package.json must be readable JSON") from exc
    expected = {
        "name": "apex-ui",
        "version": version,
        "node": "20.19.5",
        "npm": npm_version,
        "package_manager": f"npm@{npm_version}",
    }
    observed = {
        "name": package.get("name"),
        "version": package.get("version"),
        "node": (package.get("engines") or {}).get("node"),
        "npm": (package.get("engines") or {}).get("npm"),
        "package_manager": package.get("packageManager"),
    }
    if observed != expected:
        raise ValueError(
            "apex-ui/package.json identity/toolchain must match VERSION and the "
            "qualified Node/npm tuple"
        )
    return expected


def _container_os_inputs() -> dict[str, Any]:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    snapshots = sorted(set(re.findall(
        r"snapshot\.debian\.org/archive/(?:debian|debian-security)/(\d{8}T\d{6}Z)",
        dockerfile,
    )))
    if len(snapshots) != 1:
        raise ValueError("Dockerfile must use one Debian snapshot date")
    package_pairs = re.findall(
        r"^\s{8}([a-z0-9][a-z0-9+.-]*)=([^\s\\]+)(?:\s*\\)?$",
        dockerfile,
        flags=re.MULTILINE,
    )
    if not package_pairs:
        raise ValueError("Dockerfile must pin direct Debian package versions")
    return {
        "debian_snapshot": snapshots[0],
        "direct_packages": dict(sorted(package_pairs)),
    }


def _created_at(source_date_epoch: str | None) -> str | None:
    if source_date_epoch is None or source_date_epoch == "":
        return None
    try:
        epoch = int(source_date_epoch)
    except ValueError as exc:
        raise ValueError("SOURCE_DATE_EPOCH must be a non-negative integer") from exc
    if epoch < 0:
        raise ValueError("SOURCE_DATE_EPOCH must be a non-negative integer")
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat().replace("+00:00", "Z")


def build_manifest(args: argparse.Namespace) -> dict[str, Any]:
    version = _read_version()
    python_image = _validate_pinned_image("python image", args.python_image)
    node_image = _validate_pinned_image("node image", args.node_image)
    if not SEMVER_RE.fullmatch(args.npm_version):
        raise ValueError("npm version must be exact")
    frontend_package = _frontend_package(version, args.npm_version)

    image_digest = args.image_digest.strip() or None
    if image_digest is not None and not DIGEST_RE.fullmatch(image_digest):
        raise ValueError("image digest must be empty or sha256:<64 lowercase hex characters>")
    if not args.image_ref.strip():
        raise ValueError("image reference must not be empty")
    if not SAFE_REVISION_RE.fullmatch(args.vcs_ref):
        raise ValueError("VCS revision contains unsupported characters")

    return {
        "schema_version": 1,
        "product": {
            "name": "Forge Suite",
            "version": version,
            "packages": {
                "frontend": frontend_package,
            },
        },
        "source": {
            "revision": args.vcs_ref,
            "created_at": _created_at(args.source_date_epoch),
        },
        "container": {
            "image": {
                "reference": args.image_ref,
                "digest": image_digest,
            },
            "base_images": {
                "node": node_image,
                "python": python_image,
            },
            "javascript_toolchain": {
                "node": "20.19.5",
                "npm": args.npm_version,
                "provenance": "bundled-in-immutable-node-base-image",
            },
            "runtime_identity": {
                "user": "forge",
                "uid": 10001,
                "gid": 10001,
            },
            "operating_system_packages": _container_os_inputs(),
            "optional_components": {
                "nuclei": {
                    "status": "omitted",
                    "provisioning": "operator-provided, pinned, and verified",
                },
            },
        },
        "inputs": [_file_record(path) for path in INPUT_PATHS],
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="-", help="output JSON path, or - for stdout")
    parser.add_argument("--image-ref", required=True)
    parser.add_argument("--image-digest", default="")
    parser.add_argument("--python-image", required=True)
    parser.add_argument("--node-image", required=True)
    parser.add_argument("--npm-version", default="10.8.2")
    parser.add_argument("--vcs-ref", default="unknown")
    parser.add_argument(
        "--source-date-epoch",
        default=os.environ.get("SOURCE_DATE_EPOCH"),
        help="optional reproducible build timestamp (defaults to SOURCE_DATE_EPOCH)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        manifest = build_manifest(args)
        rendered = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
        if args.output == "-":
            sys.stdout.write(rendered)
            return 0

        output_path = Path(args.output).resolve()
        input_paths = {(ROOT / path).resolve() for path in INPUT_PATHS}
        if output_path in input_paths:
            raise ValueError("output path must not overwrite a build input")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered, encoding="utf-8")
        return 0
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
