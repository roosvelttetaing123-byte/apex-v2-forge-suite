"""
Forge C2 — Registry Operations Task
========================================
Full Windows registry CRUD operations with cross-platform emulation.

Operations:
    • query   — Read a registry value or enumerate subkeys
    • read    — Alias for query (single value)
    • write   — Create or modify a registry value
    • delete  — Delete a key or value
    • search  — Search registry for pattern matches

Supports:
    • All standard hives: HKLM, HKCU, HKCR, HKU, HKCC
    • All value types: REG_SZ, REG_DWORD, REG_QWORD, REG_BINARY,
                       REG_EXPAND_SZ, REG_MULTI_SZ
    • Recursive enumeration and search
    • Windows: native winreg module
    • Linux/macOS: emulation mode with structured output

MITRE ATT&CK: T1012 — Query Registry
FOR AUTHORIZED RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import asyncio
import json
import logging
import platform
import time
from dataclasses import dataclass, field
from typing import Any

from forge_c2.tasks.base_task import (
    BaseTask, TaskResult, TaskStatus, register_task,
)

log = logging.getLogger("forge.c2.tasks.registry")


# ══════════════════════════════════════════════════════════════════════
#  HIVE MAPPING
# ══════════════════════════════════════════════════════════════════════

HIVE_MAP: dict[str, int] = {}
HIVE_NAMES: dict[str, str] = {
    "HKLM": "HKEY_LOCAL_MACHINE",
    "HKCU": "HKEY_CURRENT_USER",
    "HKCR": "HKEY_CLASSES_ROOT",
    "HKU": "HKEY_USERS",
    "HKCC": "HKEY_CURRENT_CONFIG",
    "HKEY_LOCAL_MACHINE": "HKEY_LOCAL_MACHINE",
    "HKEY_CURRENT_USER": "HKEY_CURRENT_USER",
    "HKEY_CLASSES_ROOT": "HKEY_CLASSES_ROOT",
    "HKEY_USERS": "HKEY_USERS",
    "HKEY_CURRENT_CONFIG": "HKEY_CURRENT_CONFIG",
}

# Value type mapping
REG_TYPE_MAP = {
    "REG_SZ": 1,
    "REG_EXPAND_SZ": 2,
    "REG_BINARY": 3,
    "REG_DWORD": 4,
    "REG_MULTI_SZ": 7,
    "REG_QWORD": 11,
}

REG_TYPE_NAMES = {v: k for k, v in REG_TYPE_MAP.items()}


def _parse_key_path(full_path: str) -> tuple[str, str]:
    """Parse 'HKLM\\SOFTWARE\\Microsoft' into (hive, subkey)."""
    parts = full_path.replace("/", "\\").split("\\", 1)
    hive = parts[0].upper()
    subkey = parts[1] if len(parts) > 1 else ""

    # Resolve short names
    hive = HIVE_NAMES.get(hive, hive)

    return hive, subkey


# ══════════════════════════════════════════════════════════════════════
#  REGISTRY ENGINE
# ══════════════════════════════════════════════════════════════════════

@dataclass
class RegistryValue:
    """A single registry value."""
    name: str
    data: Any
    value_type: str
    key_path: str = ""

    def to_dict(self) -> dict[str, Any]:
        data_repr = self.data
        if isinstance(data_repr, bytes):
            data_repr = data_repr.hex()
        return {
            "name": self.name,
            "data": data_repr,
            "type": self.value_type,
            "key": self.key_path,
        }


@dataclass
class RegistryQueryResult:
    """Result of a registry query operation."""
    key_path: str
    values: list[RegistryValue] = field(default_factory=list)
    subkeys: list[str] = field(default_factory=list)
    success: bool = True
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key_path,
            "values": [v.to_dict() for v in self.values],
            "subkeys": self.subkeys,
            "success": self.success,
            "error": self.error,
        }


class RegistryEngine:
    """Cross-platform registry operations engine."""

    def __init__(self) -> None:
        self._is_windows = platform.system() == "Windows"

    def query(self, key_path: str, value_name: str = "") -> RegistryQueryResult:
        """Query registry key — enumerate values and subkeys."""
        if self._is_windows:
            return self._query_windows(key_path, value_name)
        return self._query_emulation(key_path, value_name)

    def write(
        self,
        key_path: str,
        value_name: str,
        value_data: Any,
        value_type: str = "REG_SZ",
    ) -> RegistryQueryResult:
        """Write a registry value."""
        if self._is_windows:
            return self._write_windows(key_path, value_name, value_data, value_type)
        return self._write_emulation(key_path, value_name, value_data, value_type)

    def delete(
        self,
        key_path: str,
        value_name: str = "",
        delete_key: bool = False,
    ) -> RegistryQueryResult:
        """Delete a registry value or key."""
        if self._is_windows:
            return self._delete_windows(key_path, value_name, delete_key)
        return self._delete_emulation(key_path, value_name, delete_key)

    def search(
        self,
        root_path: str,
        pattern: str,
        max_depth: int = 5,
        max_results: int = 50,
    ) -> list[RegistryValue]:
        """Search registry for values matching a pattern."""
        if self._is_windows:
            return self._search_windows(root_path, pattern, max_depth, max_results)
        return self._search_emulation(root_path, pattern)

    # ── Windows implementations ────────────────────────────────────

    def _query_windows(self, key_path: str, value_name: str) -> RegistryQueryResult:
        try:
            import winreg

            hive_name, subkey = _parse_key_path(key_path)
            hive = getattr(winreg, hive_name)

            with winreg.OpenKey(hive, subkey) as key:
                result = RegistryQueryResult(key_path=key_path)

                if value_name:
                    # Read specific value
                    data, reg_type = winreg.QueryValueEx(key, value_name)
                    result.values.append(RegistryValue(
                        name=value_name,
                        data=data,
                        value_type=REG_TYPE_NAMES.get(reg_type, f"TYPE_{reg_type}"),
                        key_path=key_path,
                    ))
                else:
                    # Enumerate all values
                    i = 0
                    while True:
                        try:
                            name, data, reg_type = winreg.EnumValue(key, i)
                            result.values.append(RegistryValue(
                                name=name or "(Default)",
                                data=data,
                                value_type=REG_TYPE_NAMES.get(reg_type, f"TYPE_{reg_type}"),
                                key_path=key_path,
                            ))
                            i += 1
                        except OSError:
                            break

                    # Enumerate subkeys
                    i = 0
                    while True:
                        try:
                            subkey_name = winreg.EnumKey(key, i)
                            result.subkeys.append(subkey_name)
                            i += 1
                        except OSError:
                            break

                return result

        except FileNotFoundError:
            return RegistryQueryResult(
                key_path=key_path, success=False,
                error=f"Registry key not found: {key_path}",
            )
        except PermissionError:
            return RegistryQueryResult(
                key_path=key_path, success=False,
                error=f"Access denied: {key_path}",
            )
        except Exception as exc:
            return RegistryQueryResult(
                key_path=key_path, success=False, error=str(exc),
            )

    def _write_windows(
        self, key_path: str, value_name: str, value_data: Any, value_type: str,
    ) -> RegistryQueryResult:
        try:
            import winreg

            hive_name, subkey = _parse_key_path(key_path)
            hive = getattr(winreg, hive_name)
            reg_type = REG_TYPE_MAP.get(value_type, 1)

            with winreg.CreateKeyEx(hive, subkey, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, value_name, 0, reg_type, value_data)

            return RegistryQueryResult(
                key_path=key_path, success=True,
                values=[RegistryValue(
                    name=value_name, data=value_data,
                    value_type=value_type, key_path=key_path,
                )],
            )

        except Exception as exc:
            return RegistryQueryResult(
                key_path=key_path, success=False, error=str(exc),
            )

    def _delete_windows(
        self, key_path: str, value_name: str, delete_key: bool,
    ) -> RegistryQueryResult:
        try:
            import winreg

            hive_name, subkey = _parse_key_path(key_path)
            hive = getattr(winreg, hive_name)

            if delete_key:
                winreg.DeleteKey(hive, subkey)
            else:
                with winreg.OpenKey(hive, subkey, 0, winreg.KEY_SET_VALUE) as key:
                    winreg.DeleteValue(key, value_name)

            return RegistryQueryResult(key_path=key_path, success=True)

        except Exception as exc:
            return RegistryQueryResult(
                key_path=key_path, success=False, error=str(exc),
            )

    def _search_windows(
        self, root_path: str, pattern: str,
        max_depth: int, max_results: int,
    ) -> list[RegistryValue]:
        import winreg
        import re

        results: list[RegistryValue] = []
        hive_name, subkey = _parse_key_path(root_path)
        hive = getattr(winreg, hive_name)

        regex = re.compile(pattern, re.IGNORECASE)

        def _search_recursive(current_key: str, depth: int) -> None:
            if depth > max_depth or len(results) >= max_results:
                return

            try:
                with winreg.OpenKey(hive, current_key) as key:
                    # Check values
                    i = 0
                    while True:
                        try:
                            name, data, reg_type = winreg.EnumValue(key, i)
                            data_str = str(data) if not isinstance(data, bytes) else data.hex()
                            if regex.search(name) or regex.search(data_str):
                                results.append(RegistryValue(
                                    name=name,
                                    data=data,
                                    value_type=REG_TYPE_NAMES.get(reg_type, ""),
                                    key_path=f"{hive_name}\\{current_key}",
                                ))
                            i += 1
                        except OSError:
                            break

                    # Recurse subkeys
                    i = 0
                    while True:
                        try:
                            sub = winreg.EnumKey(key, i)
                            child = f"{current_key}\\{sub}" if current_key else sub
                            _search_recursive(child, depth + 1)
                            i += 1
                        except OSError:
                            break

            except (PermissionError, OSError):
                pass

        _search_recursive(subkey, 0)
        return results

    # ── Emulation implementations ──────────────────────────────────

    def _query_emulation(self, key_path: str, value_name: str) -> RegistryQueryResult:
        # Return realistic-looking emulated data
        emulated_data: dict[str, list[RegistryValue]] = {
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion": [
                RegistryValue("ProductName", "Windows 10 Pro", "REG_SZ"),
                RegistryValue("CurrentBuild", "19045", "REG_SZ"),
                RegistryValue("EditionID", "Professional", "REG_SZ"),
                RegistryValue("InstallDate", 1640000000, "REG_DWORD"),
            ],
            "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services": [
                RegistryValue("(Default)", "", "REG_SZ"),
            ],
        }

        hive, subkey = _parse_key_path(key_path)
        full_path = f"{hive}\\{subkey}" if subkey else hive

        if full_path in emulated_data:
            values = emulated_data[full_path]
            if value_name:
                values = [v for v in values if v.name == value_name]
        else:
            values = [RegistryValue("(Default)", "", "REG_SZ")]

        return RegistryQueryResult(
            key_path=key_path,
            values=values,
            subkeys=["SubKey1", "SubKey2"] if not value_name else [],
        )

    def _write_emulation(
        self, key_path: str, value_name: str, value_data: Any, value_type: str,
    ) -> RegistryQueryResult:
        log.info(
            "[EMULATION] Registry write: %s\\%s = %s (%s)",
            key_path, value_name, value_data, value_type,
        )
        return RegistryQueryResult(
            key_path=key_path, success=True,
            values=[RegistryValue(value_name, value_data, value_type, key_path)],
        )

    def _delete_emulation(
        self, key_path: str, value_name: str, delete_key: bool,
    ) -> RegistryQueryResult:
        target = key_path if delete_key else f"{key_path}\\{value_name}"
        log.info("[EMULATION] Registry delete: %s", target)
        return RegistryQueryResult(key_path=key_path, success=True)

    def _search_emulation(
        self, root_path: str, pattern: str,
    ) -> list[RegistryValue]:
        log.info("[EMULATION] Registry search: %s in %s", pattern, root_path)
        return [
            RegistryValue(
                name="ExampleMatch",
                data=f"[contains '{pattern}']",
                value_type="REG_SZ",
                key_path=f"{root_path}\\ExampleKey",
            ),
        ]


# ══════════════════════════════════════════════════════════════════════
#  TASK CLASS
# ══════════════════════════════════════════════════════════════════════

@register_task
class RegistryTask(BaseTask):
    """Windows registry CRUD operations.

    Args (via kwargs):
        operation:    "query", "read", "write", "delete", "search"
        key_path:     Full registry path (e.g. "HKLM\\SOFTWARE\\Microsoft")
        value_name:   Name of specific value (optional for query)
        value_data:   Data to write (for write operation)
        value_type:   Registry type: REG_SZ, REG_DWORD, etc. (default REG_SZ)
        delete_key:   If True, delete the entire key (for delete operation)
        search_pattern: Regex pattern (for search operation)
        max_depth:    Max recursion depth for search (default 5)
        output_format: "text" or "json" (default "text")

    MITRE ATT&CK: T1012 — Query Registry
    """

    TASK_TYPE = "registry"
    DESCRIPTION = "Registry CRUD: read/write/query/delete keys"
    OPSEC_RISK = "medium"
    MITRE_ID = "T1012"

    async def execute(self) -> TaskResult:
        operation = self.args.get("operation", "query").lower()
        key_path = self.args.get("key_path", "")
        value_name = self.args.get("value_name", "")
        value_data = self.args.get("value_data", "")
        value_type = self.args.get("value_type", "REG_SZ")
        delete_key = self.args.get("delete_key", False)
        search_pattern = self.args.get("search_pattern", "")
        max_depth = self.args.get("max_depth", 5)
        output_format = self.args.get("output_format", "text")

        start = time.time()

        if not key_path and operation != "search":
            return TaskResult(
                task_id=self.task_id,
                status=TaskStatus.FAILED,
                error="No registry key path specified.",
                started_at=start,
                completed_at=time.time(),
            )

        engine = RegistryEngine()

        try:
            if operation in ("query", "read"):
                result = await asyncio.get_event_loop().run_in_executor(
                    None, engine.query, key_path, value_name,
                )
                if not result.success:
                    return TaskResult(
                        task_id=self.task_id,
                        status=TaskStatus.FAILED,
                        error=result.error,
                        started_at=start,
                        completed_at=time.time(),
                    )

                if output_format == "json":
                    output = json.dumps(result.to_dict(), indent=2, default=str)
                else:
                    output = self._format_query_result(result)

            elif operation == "write":
                if not value_name:
                    return TaskResult(
                        task_id=self.task_id,
                        status=TaskStatus.FAILED,
                        error="No value_name specified for write.",
                        started_at=start,
                        completed_at=time.time(),
                    )

                result = await asyncio.get_event_loop().run_in_executor(
                    None, engine.write, key_path, value_name, value_data, value_type,
                )

                if not result.success:
                    return TaskResult(
                        task_id=self.task_id,
                        status=TaskStatus.FAILED,
                        error=result.error,
                        started_at=start,
                        completed_at=time.time(),
                    )

                output = f"Written: {key_path}\\{value_name} = {value_data} ({value_type})"

            elif operation == "delete":
                result = await asyncio.get_event_loop().run_in_executor(
                    None, engine.delete, key_path, value_name, delete_key,
                )

                if not result.success:
                    return TaskResult(
                        task_id=self.task_id,
                        status=TaskStatus.FAILED,
                        error=result.error,
                        started_at=start,
                        completed_at=time.time(),
                    )

                target = key_path if delete_key else f"{key_path}\\{value_name}"
                output = f"Deleted: {target}"

            elif operation == "search":
                if not search_pattern:
                    return TaskResult(
                        task_id=self.task_id,
                        status=TaskStatus.FAILED,
                        error="No search_pattern specified.",
                        started_at=start,
                        completed_at=time.time(),
                    )

                matches = await asyncio.get_event_loop().run_in_executor(
                    None, engine.search, key_path, search_pattern, max_depth, 50,
                )

                if output_format == "json":
                    output = json.dumps(
                        [m.to_dict() for m in matches], indent=2, default=str,
                    )
                else:
                    lines = [f"Search results for '{search_pattern}' ({len(matches)} matches):\n"]
                    for m in matches:
                        lines.append(f"  {m.key_path}\\{m.name} = {m.data} ({m.value_type})")
                    output = "\n".join(lines)

            else:
                return TaskResult(
                    task_id=self.task_id,
                    status=TaskStatus.FAILED,
                    error=f"Unknown operation: {operation}. Use query/write/delete/search.",
                    started_at=start,
                    completed_at=time.time(),
                )

            return TaskResult(
                task_id=self.task_id,
                status=TaskStatus.COMPLETED,
                output=output,
                started_at=start,
                completed_at=time.time(),
                metadata={
                    "operation": operation,
                    "key_path": key_path,
                    "mitre": self.MITRE_ID,
                },
            )

        except Exception as exc:
            return TaskResult(
                task_id=self.task_id,
                status=TaskStatus.FAILED,
                error=str(exc),
                started_at=start,
                completed_at=time.time(),
            )

    @staticmethod
    def _format_query_result(result: RegistryQueryResult) -> str:
        """Format registry query result as readable text."""
        lines = [f"Registry Key: {result.key_path}\n"]

        if result.values:
            lines.append("Values:")
            for v in result.values:
                data_repr = v.data
                if isinstance(data_repr, bytes):
                    data_repr = f"(hex) {data_repr.hex()}"
                lines.append(f"  {v.name:30s} {v.value_type:16s} {data_repr}")

        if result.subkeys:
            lines.append(f"\nSubkeys ({len(result.subkeys)}):")
            for sk in result.subkeys:
                lines.append(f"  {sk}")

        return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════
#  UNIT TESTS
# ══════════════════════════════════════════════════════════════════════

class TestRegistryTask:
    """Tests for registry task."""

    def test_encode(self) -> None:
        task = RegistryTask(task_id="r1", operation="query",
                            key_path="HKLM\\SOFTWARE")
        encoded = task.encode()
        assert encoded["type"] == "registry"

    def test_decode(self) -> None:
        data = {"task_id": "r2", "type": "registry",
                "args": {"operation": "query", "key_path": "HKCU\\Software"}}
        task = RegistryTask.decode(data)
        assert task.args["operation"] == "query"

    def test_no_key_path(self) -> None:
        import asyncio
        task = RegistryTask(task_id="r3", operation="query")
        result = asyncio.get_event_loop().run_until_complete(task.execute())
        assert result.status == TaskStatus.FAILED

    def test_invalid_operation(self) -> None:
        import asyncio
        task = RegistryTask(task_id="r4", operation="bogus",
                            key_path="HKLM\\SOFTWARE")
        result = asyncio.get_event_loop().run_until_complete(task.execute())
        assert result.status == TaskStatus.FAILED

    def test_parse_key_path(self) -> None:
        hive, subkey = _parse_key_path("HKLM\\SOFTWARE\\Microsoft")
        assert hive == "HKEY_LOCAL_MACHINE"
        assert subkey == "SOFTWARE\\Microsoft"

    def test_parse_key_short_name(self) -> None:
        hive, _ = _parse_key_path("HKCU\\Software")
        assert hive == "HKEY_CURRENT_USER"

    def test_emulation_query(self) -> None:
        engine = RegistryEngine()
        if platform.system() != "Windows":
            result = engine.query("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion")
            assert result.success
            assert len(result.values) > 0

    def test_value_to_dict(self) -> None:
        v = RegistryValue(name="Test", data="value", value_type="REG_SZ")
        d = v.to_dict()
        assert d["name"] == "Test"
        assert d["data"] == "value"
