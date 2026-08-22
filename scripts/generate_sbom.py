#!/usr/bin/env python3
"""Generate a deterministic CycloneDX SBOM for Python, Node, and the image."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
import uuid
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import quote

try:
    from scripts.check_dependency_locks import parse_lock
except ModuleNotFoundError:
    from check_dependency_locks import parse_lock


ROOT = Path(__file__).resolve().parents[1]
SEMVER_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
IMAGE_RE = re.compile(r"^([^\s@]+)@sha256:([0-9a-f]{64})$")
BASE_IMAGE_RE = re.compile(
    r"^ARG (PYTHON_IMAGE|NODE_IMAGE)=([^\s@]+)@sha256:([0-9a-f]{64})$",
    re.MULTILINE,
)
APT_PIN_RE = re.compile(
    r"^\s{8}([a-z0-9][a-z0-9+.-]*)=([^\s\\]+)(?:\s*\\)?$",
    re.MULTILINE,
)
DOCKER_STAGE_RE = re.compile(
    r"^FROM\s+\S+(?:\s+AS\s+([a-z0-9_.-]+))?\s*$",
    re.IGNORECASE | re.MULTILINE,
)


class SbomGenerationError(RuntimeError):
    """Raised when SBOM source inputs are incomplete or ambiguous."""


def _properties(ecosystem: str, **values: str) -> list[dict[str, str]]:
    properties = [{"name": "forge:ecosystem", "value": ecosystem}]
    properties.extend(
        {"name": f"forge:{key.replace('_', '-')}", "value": value}
        for key, value in sorted(values.items())
    )
    return properties


def _pypi_components(root: Path) -> list[dict[str, Any]]:
    components = []
    for requirement in parse_lock(root / "requirements.lock").values():
        components.append(
            {
                "type": "library",
                "bom-ref": f"pkg:pypi/{requirement.name}@{quote(requirement.version, safe='')}",
                "name": requirement.name,
                "version": requirement.version,
                "purl": f"pkg:pypi/{requirement.name}@{quote(requirement.version, safe='')}",
                "scope": "required",
                "properties": _properties(
                    "python",
                    lock="requirements.lock",
                    artifact_sha256=",".join(requirement.hashes),
                ),
            }
        )
    return components


def _npm_name(package_path: str) -> str:
    marker = "node_modules/"
    if marker not in package_path:
        raise SbomGenerationError(f"unexpected package-lock path: {package_path}")
    return package_path.rsplit(marker, 1)[1]


def _npm_components(root: Path) -> list[dict[str, Any]]:
    lock = json.loads((root / "apex-ui/package-lock.json").read_text(encoding="utf-8"))
    if lock.get("lockfileVersion") != 3 or not isinstance(lock.get("packages"), dict):
        raise SbomGenerationError("apex-ui/package-lock.json must use lockfileVersion 3")
    components: dict[str, dict[str, Any]] = {}
    for package_path, record in sorted(lock["packages"].items()):
        if not package_path:
            continue
        name = _npm_name(package_path)
        version = record.get("version")
        if not isinstance(version, str) or not version:
            raise SbomGenerationError(f"npm lock entry lacks a version: {package_path}")
        encoded_name = quote(name, safe="/")
        purl = f"pkg:npm/{encoded_name}@{quote(version, safe='')}"
        component: dict[str, Any] = {
            "type": "library",
            "bom-ref": purl,
            "name": name,
            "version": version,
            "purl": purl,
            "scope": "optional" if record.get("optional") else "required",
            "properties": _properties(
                "node",
                lock="apex-ui/package-lock.json",
                development=str(bool(record.get("dev"))).lower(),
            ),
        }
        integrity = record.get("integrity")
        if isinstance(integrity, str) and integrity.startswith("sha512-"):
            try:
                digest = base64.b64decode(integrity[7:], validate=True).hex()
            except ValueError as exc:
                raise SbomGenerationError(f"invalid npm integrity for {package_path}") from exc
            component["hashes"] = [{"alg": "SHA-512", "content": digest}]
        existing = components.get(purl)
        if existing is not None and existing != component:
            raise SbomGenerationError(f"conflicting npm lock records for {purl}")
        components[purl] = component
    return list(components.values())


def _base_image_components(root: Path) -> list[dict[str, Any]]:
    dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")
    matches = BASE_IMAGE_RE.findall(dockerfile)
    if {match[0] for match in matches} != {"PYTHON_IMAGE", "NODE_IMAGE"}:
        raise SbomGenerationError("Dockerfile must declare the two reviewed digest-pinned base images")
    components = []
    for variable, tagged, digest in sorted(matches):
        repository, tag = tagged.rsplit(":", 1)
        name = repository.rsplit("/", 1)[-1]
        purl = (
            f"pkg:oci/{quote(name, safe='')}@sha256:{digest}"
            f"?repository_url={quote(repository, safe='')}&tag={quote(tag, safe='')}"
        )
        components.append(
            {
                "type": "container",
                "bom-ref": purl,
                "name": repository,
                "version": tag,
                "purl": purl,
                "hashes": [{"alg": "SHA-256", "content": digest}],
                "properties": _properties("base-image", docker_arg=variable),
            }
        )
    return components


def _docker_stage(dockerfile: str, stage: str) -> str:
    """Return one named Docker stage without including later stages."""
    matches = list(DOCKER_STAGE_RE.finditer(dockerfile))
    for index, match in enumerate(matches):
        if (match.group(1) or "").lower() != stage.lower():
            continue
        end = matches[index + 1].start() if index + 1 < len(matches) else len(dockerfile)
        return dockerfile[match.end():end]
    raise SbomGenerationError(f"Dockerfile does not declare stage {stage!r}")


def _declared_debian_packages(
    root: Path,
    stage: str | None = None,
) -> list[tuple[str, str, str]]:
    dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")
    source = _docker_stage(dockerfile, stage) if stage is not None else dockerfile
    packages = [(name, version, "unknown") for name, version in APT_PIN_RE.findall(source)]
    if not packages:
        scope = f" in stage {stage!r}" if stage is not None else ""
        raise SbomGenerationError(f"Dockerfile contains no exact Debian package pins{scope}")
    return sorted(set(packages))


def _container_packages(path: Path | None, root: Path) -> tuple[list[tuple[str, str, str]], str]:
    if path is None:
        return _declared_debian_packages(root), "declared-direct"
    packages: list[tuple[str, str, str]] = []
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw_line.strip():
            continue
        fields = raw_line.split("\t")
        if len(fields) not in (2, 3, 4):
            raise SbomGenerationError(
                f"container package inventory line {line_number} must have 2-4 tab fields"
            )
        name, version = fields[:2]
        architecture = fields[2] if len(fields) >= 3 else "unknown"
        status = fields[3] if len(fields) == 4 else "ii"
        if not name or not version or not status.startswith("ii"):
            raise SbomGenerationError(f"invalid installed package row at line {line_number}")
        packages.append((name, version, architecture or "unknown"))
    if not packages:
        raise SbomGenerationError("container package inventory is empty")
    return sorted(set(packages)), "image-dpkg-query"


def _debian_components(
    packages: list[tuple[str, str, str]],
    inventory_source: str,
) -> list[dict[str, Any]]:
    components = []
    for name, version, architecture in packages:
        qualifiers = "distro=debian-12"
        if architecture != "unknown":
            qualifiers = f"arch={quote(architecture, safe='')}&{qualifiers}"
        purl = f"pkg:deb/debian/{quote(name, safe='')}@{quote(version, safe='')}?{qualifiers}"
        components.append(
            {
                "type": "operating-system",
                "bom-ref": purl,
                "name": name,
                "version": version,
                "purl": purl,
                "properties": _properties(
                    "debian",
                    architecture=architecture,
                    inventory_source=inventory_source,
                ),
            }
        )
    return components


def build_sbom(
    root: Path,
    container_packages: Path | None = None,
    image_ref: str = "",
) -> dict[str, Any]:
    version = (root / "VERSION").read_text(encoding="utf-8").strip()
    if not SEMVER_RE.fullmatch(version):
        raise SbomGenerationError("VERSION must contain one semantic version")
    packages, inventory_source = _container_packages(container_packages, root)
    components = (
        _pypi_components(root)
        + _npm_components(root)
        + _base_image_components(root)
        + _debian_components(packages, inventory_source)
    )
    if image_ref:
        match = IMAGE_RE.fullmatch(image_ref)
        if match is None:
            raise SbomGenerationError("--image-ref must be a tag/name plus @sha256 digest")
        tagged, digest = match.groups()
        name, tag = tagged.rsplit(":", 1)
        purl = (
            f"pkg:oci/{quote(name.rsplit('/', 1)[-1], safe='')}@sha256:{digest}"
            f"?repository_url={quote(name, safe='')}&tag={quote(tag, safe='')}"
        )
        components.append(
            {
                "type": "container",
                "bom-ref": purl,
                "name": name,
                "version": tag,
                "purl": purl,
                "hashes": [{"alg": "SHA-256", "content": digest}],
                "properties": _properties(
                    "container-image",
                    inventory_source=inventory_source,
                    nuclei="omitted",
                ),
            }
        )
    components.sort(key=lambda component: component["bom-ref"])
    refs = [component["bom-ref"] for component in components]
    if len(refs) != len(set(refs)):
        raise SbomGenerationError("component identities are not unique")
    identity_seed = "\n".join(
        [version, image_ref, inventory_source]
        + [hashlib.sha256((root / path).read_bytes()).hexdigest() for path in (
            "requirements.lock",
            "apex-ui/package-lock.json",
            "Dockerfile",
        )]
        + refs
    )
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, identity_seed)}",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": f"pkg:generic/forge-suite@{version}",
                "name": "forge-suite",
                "version": version,
                "purl": f"pkg:generic/forge-suite@{version}",
                "properties": _properties(
                    "product",
                    nuclei="omitted",
                    container_inventory_source=inventory_source,
                ),
            },
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "forge-sbom-generator",
                        "version": "1",
                    }
                ]
            },
        },
        "components": components,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path, default=Path("build/forge-sbom.cdx.json"))
    parser.add_argument("--container-packages", type=Path)
    parser.add_argument("--image-ref", default="")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    output = args.output if args.output.is_absolute() else root / args.output
    inventory = args.container_packages
    if inventory is not None and not inventory.is_absolute():
        inventory = root / inventory
    try:
        document = build_sbom(root, inventory, args.image_ref)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except (OSError, json.JSONDecodeError, SbomGenerationError) as exc:
        print(f"FAIL sbom-generation: {exc}", file=sys.stderr)
        return 1
    counts = Counter(
        next(
            prop["value"]
            for prop in component.get("properties", [])
            if prop.get("name") == "forge:ecosystem"
        )
        for component in document["components"]
    )
    print(
        f"PASS sbom-generation output={output} components={len(document['components'])} "
        + " ".join(f"{name}={count}" for name, count in sorted(counts.items()))
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
