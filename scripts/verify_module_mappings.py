#!/usr/bin/env python3
"""Verify engine registries and classify every unregistered module file."""

from __future__ import annotations

import ast
import importlib
import sys
import tomllib
from collections import Counter
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


class MappingValidationError(RuntimeError):
    """Raised when a registry cannot be audited as a literal mapping."""


def _module_path(path: str) -> str:
    return Path(*path.split(".")).with_suffix(".py").as_posix()


def _files(root: Path, engine: str) -> set[str]:
    return {
        path.relative_to(root).as_posix()
        for path in (root / engine / "modules").rglob("*.py")
    }


def _literal_mapping_groups(source: str, mapping_name: str) -> tuple[list[list[str]], bool]:
    module = ast.parse(source)
    candidate: ast.AST | None = None
    update_nodes: list[ast.Dict] = []
    for node in module.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == mapping_name
            for target in node.targets
        ):
            candidate = node.value
        elif (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == mapping_name
        ):
            candidate = node.value
        elif (
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Attribute)
            and isinstance(node.value.func.value, ast.Name)
            and node.value.func.value.id == mapping_name
            and node.value.func.attr == "update"
        ):
            if (
                len(node.value.args) != 1
                or node.value.keywords
                or not isinstance(node.value.args[0], ast.Dict)
            ):
                raise MappingValidationError(
                    f"{mapping_name}.update must receive one literal dictionary"
                )
            update_nodes.append(node.value.args[0])
    derived = isinstance(candidate, ast.DictComp)
    if not isinstance(candidate, (ast.Dict, ast.DictComp)):
        raise MappingValidationError(
            f"{mapping_name} must be a top-level dict literal or audited comprehension"
        )
    if derived:
        comprehension = candidate
        if (
            len(comprehension.generators) != 1
            or not isinstance(comprehension.key, ast.Name)
            or not isinstance(comprehension.generators[0].target, ast.Name)
            or comprehension.key.id != comprehension.generators[0].target.id
            or not isinstance(comprehension.generators[0].iter, ast.Name)
            or comprehension.generators[0].iter.id != "MODULE_MAP"
        ):
            raise MappingValidationError(
                f"{mapping_name} comprehension must derive keys directly from MODULE_MAP"
            )
        dict_nodes = update_nodes
    else:
        dict_nodes = [candidate, *update_nodes]
    groups: list[list[str]] = []
    for dictionary in dict_nodes:
        keys: list[str] = []
        for key in dictionary.keys:
            if not isinstance(key, ast.Constant) or not isinstance(key.value, str):
                raise MappingValidationError(f"{mapping_name} keys must be string literals")
            keys.append(key.value)
        groups.append(keys)
    return groups, derived


def literal_mapping_keys(source: str, mapping_name: str) -> list[str]:
    """Return literal keys without collapsing duplicates as Python dicts do."""

    groups, _derived = _literal_mapping_groups(source, mapping_name)
    return [key for group in groups for key in group]


def duplicate_literal_keys(source: str, mapping_name: str) -> list[str]:
    counts = Counter(literal_mapping_keys(source, mapping_name))
    return sorted(key for key, count in counts.items() if count > 1)


def validate_repository(root: Path = ROOT) -> dict[str, int]:
    from adforge import adforge
    from aiforge import aiforge
    from netforge import netforge
    from webforge import webforge

    engines: list[
        tuple[
            str,
            str,
            Path,
            dict[str, str],
            dict[str, str],
            Callable[[str], Any],
        ]
    ] = [
        (
            "webforge",
            "webforge",
            root / "webforge/webforge.py",
            webforge.MODULE_MAP,
            webforge.CLASS_NAME_MAP,
            webforge.load_module_class,
        ),
        (
            "netforge",
            "netforge",
            root / "netforge/netforge.py",
            netforge.MODULE_MAP,
            netforge.CLASS_NAME_MAP,
            netforge.load_module,
        ),
        (
            "adforge",
            "adforge",
            root / "adforge/adforge.py",
            adforge.MODULE_MAP,
            adforge.CLASS_NAME_MAP,
            adforge.load_module,
        ),
        (
            "aiforge",
            "aiforge",
            root / "aiforge/aiforge.py",
            aiforge.MODULE_MAP,
            aiforge.CLASS_NAME_MAP,
            aiforge.load_module_class,
        ),
    ]
    classification_path = root / "config/module-classification.toml"
    classification_document = tomllib.loads(classification_path.read_text(encoding="utf-8"))
    if classification_document.get("schema_version") != 1:
        raise MappingValidationError("module classification schema_version must be 1")
    classified = classification_document.get("unregistered")
    if not isinstance(classified, dict):
        raise MappingValidationError("module classification requires [unregistered]")

    failures: list[str] = []
    registered_paths: set[str] = set()
    all_module_files: set[str] = set()
    total = 0

    for label, package_root, source_path, mapping, class_names, loader in engines:
        source = source_path.read_text(encoding="utf-8")
        for mapping_name, runtime_mapping in (
            ("MODULE_MAP", mapping),
            ("CLASS_NAME_MAP", class_names),
        ):
            try:
                literal_groups, derived = _literal_mapping_groups(source, mapping_name)
            except (SyntaxError, MappingValidationError) as exc:
                failures.append(f"{label}: {exc}")
                continue
            for literal_keys in literal_groups:
                duplicates = sorted(
                    key for key, count in Counter(literal_keys).items() if count > 1
                )
                failures.extend(
                    f"{label}: duplicate {mapping_name} ID {module_id!r}"
                    for module_id in duplicates
                )
            literal_key_set = {key for group in literal_groups for key in group}
            if not derived and not any(
                isinstance(node, ast.Expr)
                and isinstance(node.value, ast.Call)
                and isinstance(node.value.func, ast.Attribute)
                and isinstance(node.value.func.value, ast.Name)
                and node.value.func.value.id == mapping_name
                for node in ast.parse(source).body
            ) and literal_key_set != set(runtime_mapping):
                failures.append(f"{label}: runtime {mapping_name} differs from literal source")

        if set(mapping) != set(class_names):
            failures.append(f"{label}: class map keys differ from registry keys")
        duplicate_paths = sorted(
            path for path, count in Counter(mapping.values()).items() if count > 1
        )
        failures.extend(f"{label}: duplicate registered implementation {path}" for path in duplicate_paths)

        engine_registered: set[str] = set()
        for module_id, import_path in sorted(mapping.items()):
            total += 1
            path = _module_path(import_path)
            engine_registered.add(path)
            registered_paths.add(path)
            if not (root / path).is_file():
                failures.append(f"{label}:{module_id}: missing {path}")
                continue
            try:
                module = importlib.import_module(import_path)
                expected = class_names[module_id]
                loaded = loader(module_id)
                declared = getattr(module, expected, None)
            except Exception as exc:
                failures.append(f"{label}:{module_id}: {type(exc).__name__}: {exc}")
                continue
            if declared is None or loaded is not declared:
                failures.append(f"{label}:{module_id}: expected class {expected}")

        engine_files = _files(root, package_root)
        all_module_files.update(engine_files)
        unregistered = engine_files - engine_registered
        missing_classification = unregistered - set(classified)
        failures.extend(
            f"{label}: unclassified {path}" for path in sorted(missing_classification)
        )

    stale = set(classified) - all_module_files
    failures.extend(f"stale classification: {path}" for path in sorted(stale))
    overlap = set(classified) & registered_paths
    failures.extend(f"registered path must not be classified unregistered: {path}" for path in sorted(overlap))
    failures.extend(
        f"classification reason is empty: {path}"
        for path, reason in sorted(classified.items())
        if not isinstance(reason, str) or not reason.strip()
    )

    if failures:
        raise MappingValidationError("\n".join(failures))
    return {
        "registered": total,
        "unique_paths": len(registered_paths),
        "classified_unregistered": len(classified),
    }


def main() -> int:
    try:
        counts = validate_repository()
    except (OSError, tomllib.TOMLDecodeError, MappingValidationError) as exc:
        print(f"FAIL module-mappings:\n{exc}", file=sys.stderr)
        return 1
    print("PASS module-mappings " + " ".join(f"{key}={value}" for key, value in counts.items()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
