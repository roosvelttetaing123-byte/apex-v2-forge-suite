#!/usr/bin/env python3
"""Validate Forge's combined CycloneDX SBOM against every reviewed lock input."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

try:
    from scripts.check_dependency_locks import parse_lock
    from scripts.generate_sbom import _declared_debian_packages, _npm_name
except ModuleNotFoundError:
    from check_dependency_locks import parse_lock
    from generate_sbom import _declared_debian_packages, _npm_name


ROOT = Path(__file__).resolve().parents[1]
HEX_RE = re.compile(r"^[0-9a-f]+$")


class SbomValidationError(RuntimeError):
    """Raised when an SBOM omits or misidentifies a shipped component."""


def _property_map(component: dict[str, Any]) -> dict[str, str]:
    properties = component.get("properties", [])
    if not isinstance(properties, list):
        raise SbomValidationError(f"component {component.get('bom-ref')} properties are invalid")
    mapped: dict[str, str] = {}
    for prop in properties:
        if not isinstance(prop, dict) or not isinstance(prop.get("name"), str):
            raise SbomValidationError(f"component {component.get('bom-ref')} has an invalid property")
        name = prop["name"]
        value = prop.get("value")
        if not isinstance(value, str) or name in mapped:
            raise SbomValidationError(f"component {component.get('bom-ref')} has duplicate/invalid {name}")
        mapped[name] = value
    return mapped


def _validate_hashes(component: dict[str, Any]) -> None:
    expected_lengths = {"SHA-256": 64, "SHA-512": 128}
    for item in component.get("hashes", []):
        if not isinstance(item, dict):
            raise SbomValidationError("component hash must be an object")
        algorithm = item.get("alg")
        content = item.get("content")
        if (
            algorithm not in expected_lengths
            or not isinstance(content, str)
            or len(content) != expected_lengths[algorithm]
            or not HEX_RE.fullmatch(content)
        ):
            raise SbomValidationError(
                f"component {component.get('bom-ref')} contains a malformed {algorithm} hash"
            )


def validate_document(
    document: dict[str, Any],
    root: Path = ROOT,
    require_container_inventory: bool = False,
) -> dict[str, int]:
    if document.get("bomFormat") != "CycloneDX" or document.get("specVersion") != "1.6":
        raise SbomValidationError("SBOM must be CycloneDX 1.6")
    if document.get("version") != 1 or not str(document.get("serialNumber", "")).startswith("urn:uuid:"):
        raise SbomValidationError("SBOM document identity is missing or invalid")
    version = (root / "VERSION").read_text(encoding="utf-8").strip()
    metadata_component = (document.get("metadata") or {}).get("component")
    if not isinstance(metadata_component, dict):
        raise SbomValidationError("SBOM metadata component is missing")
    if metadata_component.get("name") != "forge-suite" or metadata_component.get("version") != version:
        raise SbomValidationError("SBOM product identity differs from VERSION")
    product_properties = _property_map(metadata_component)
    if product_properties.get("forge:nuclei") != "omitted":
        raise SbomValidationError("SBOM must record that Nuclei is omitted")

    components = document.get("components")
    if not isinstance(components, list) or not components:
        raise SbomValidationError("SBOM components are missing")
    refs: set[str] = set()
    by_ecosystem: dict[str, list[dict[str, Any]]] = {}
    for component in components:
        if not isinstance(component, dict):
            raise SbomValidationError("SBOM component must be an object")
        reference = component.get("bom-ref")
        if not isinstance(reference, str) or not reference or reference in refs:
            raise SbomValidationError(f"duplicate or missing bom-ref: {reference!r}")
        refs.add(reference)
        if component.get("purl") != reference:
            raise SbomValidationError(f"component {reference} does not use its purl as bom-ref")
        if not isinstance(component.get("name"), str) or not isinstance(component.get("version"), str):
            raise SbomValidationError(f"component {reference} lacks name/version")
        _validate_hashes(component)
        ecosystem = _property_map(component).get("forge:ecosystem")
        if not ecosystem:
            raise SbomValidationError(f"component {reference} lacks forge:ecosystem")
        by_ecosystem.setdefault(ecosystem, []).append(component)

    required_ecosystems = {"python", "node", "base-image", "debian"}
    missing = required_ecosystems - set(by_ecosystem)
    if missing:
        raise SbomValidationError(f"SBOM is missing ecosystems: {sorted(missing)}")

    observed_python = {
        (component["name"], component["version"])
        for component in by_ecosystem["python"]
    }
    expected_python = {
        (requirement.name, requirement.version)
        for requirement in parse_lock(root / "requirements.lock").values()
    }
    if observed_python != expected_python:
        raise SbomValidationError(
            f"Python SBOM/lock drift: missing={len(expected_python - observed_python)} "
            f"extra={len(observed_python - expected_python)}"
        )

    npm_lock = json.loads((root / "apex-ui/package-lock.json").read_text(encoding="utf-8"))
    expected_node = {
        (_npm_name(package_path), record["version"])
        for package_path, record in npm_lock["packages"].items()
        if package_path
    }
    observed_node = {
        (component["name"], component["version"])
        for component in by_ecosystem["node"]
    }
    if observed_node != expected_node:
        raise SbomValidationError(
            f"Node SBOM/lock drift: missing={len(expected_node - observed_node)} "
            f"extra={len(observed_node - expected_node)}"
        )

    base_images = by_ecosystem["base-image"]
    if len(base_images) != 2 or any(not component.get("hashes") for component in base_images):
        raise SbomValidationError("SBOM must contain both digest-pinned base images")
    # A built-image inventory represents only the final runtime stage. Builder
    # packages remain visible in the deterministic static SBOM, but correctly
    # do not appear in dpkg-query output from the shipped image.
    expected_stage = "runtime" if require_container_inventory else None
    expected_debian = {
        (name, package_version)
        for name, package_version, _ in _declared_debian_packages(
            root,
            stage=expected_stage,
        )
    }
    observed_debian = {
        (component["name"], component["version"])
        for component in by_ecosystem["debian"]
    }
    if not expected_debian <= observed_debian:
        raise SbomValidationError("SBOM omits a direct Dockerfile Debian package pin")

    inventory_source = product_properties.get("forge:container-inventory-source")
    if require_container_inventory:
        if inventory_source != "image-dpkg-query":
            raise SbomValidationError("SBOM was not generated from the built image package inventory")
        image_components = by_ecosystem.get("container-image", [])
        if len(image_components) != 1 or not image_components[0].get("hashes"):
            raise SbomValidationError("built-image SBOM requires one digest-identified container image")
        if any(
            _property_map(component).get("forge:inventory-source") != "image-dpkg-query"
            for component in by_ecosystem["debian"]
        ):
            raise SbomValidationError("Debian components do not come from the built image")
    elif inventory_source not in {"declared-direct", "image-dpkg-query"}:
        raise SbomValidationError("SBOM container inventory provenance is invalid")

    return {ecosystem: len(items) for ecosystem, items in sorted(by_ecosystem.items())}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--input", type=Path, default=Path("build/forge-sbom.cdx.json"))
    parser.add_argument("--require-container-inventory", action="store_true")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    input_path = args.input if args.input.is_absolute() else root / args.input
    try:
        document = json.loads(input_path.read_text(encoding="utf-8"))
        counts = validate_document(document, root, args.require_container_inventory)
    except (OSError, json.JSONDecodeError, SbomValidationError) as exc:
        print(f"FAIL sbom-verification: {exc}", file=sys.stderr)
        return 1
    print(
        f"PASS sbom-verification input={input_path} "
        + " ".join(f"{name}={count}" for name, count in counts.items())
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
