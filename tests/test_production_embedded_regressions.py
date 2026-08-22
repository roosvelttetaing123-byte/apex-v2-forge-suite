"""Collect every genuine regression historically embedded in product modules.

The aliases below let normal ``pytest tests/`` discovery execute the existing
``Test*`` classes without copying or weakening their assertions.  The
inventory command records the exact source node and its deterministic alias.
"""

from __future__ import annotations

import importlib

from scripts.inventory_production_tests import inventory, validate_policy


_REGRESSIONS, _FAILURES = inventory()
_FAILURES.extend(validate_policy(_REGRESSIONS))
if _FAILURES:
    raise RuntimeError("invalid production regression inventory:\n" + "\n".join(_FAILURES))

_CLASSES: dict[tuple[str, str], str] = {}
for _regression in _REGRESSIONS:
    _key = (_regression.path, _regression.class_name)
    if _key in _CLASSES:
        continue
    _module_name = _regression.path.removesuffix(".py").replace("/", ".")
    _module = importlib.import_module(_module_name)
    _class = getattr(_module, _regression.class_name)
    if not isinstance(_class, type):
        raise TypeError(f"{_regression.source_node_id}: owner is not a class")
    _CLASSES[_key] = _regression.collector_class
    globals()[_regression.collector_class] = _class


def test_production_regression_inventory_is_fully_collected() -> None:
    """Keep the inventory floor and zero-exception policy visible in pytest."""
    assert len(_REGRESSIONS) >= 1444
    assert len(_CLASSES) >= 381
    assert not _FAILURES
