from __future__ import annotations

import importlib
from pathlib import Path


def test_all_common_python_modules_import() -> None:
    """Every common/ module should at least import cleanly."""
    root = Path(__file__).resolve().parents[1]
    failures: dict[str, str] = {}
    for path in sorted((root / "common").rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        rel = path.relative_to(root).with_suffix("")
        module = ".".join(rel.parts)
        try:
            importlib.import_module(module)
        except Exception as exc:
            failures[module] = f"{type(exc).__name__}: {exc}"

    assert failures == {}
