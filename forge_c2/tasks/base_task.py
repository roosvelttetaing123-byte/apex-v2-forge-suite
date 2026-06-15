"""
Forge C2 — Task Base
========================
Abstract base for all C2 tasks (shell, download, upload, screenshot, etc.).

Every task implements encode() (server → beacon) and execute() (beacon-side).
This is the code that actually runs on the target.

FOR AUTHORIZED RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import abc
import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

log = logging.getLogger("forge.c2.tasks")


class TaskStatus(str, Enum):
    """Task execution status."""
    PENDING    = "pending"
    RUNNING    = "running"
    COMPLETED  = "completed"
    FAILED     = "failed"
    TIMEOUT    = "timeout"
    CANCELLED  = "cancelled"


@dataclass
class TaskResult:
    """Result of a task execution."""
    task_id:      str = ""
    status:       TaskStatus = TaskStatus.COMPLETED
    output:       str = ""
    data:         bytes = b""             # Binary data (file contents, screenshot, etc.)
    error:        str = ""
    started_at:   float = field(default_factory=time.time)
    completed_at: float = field(default_factory=time.time)
    metadata:     dict[str, Any] = field(default_factory=dict)

    @property
    def duration(self) -> float:
        return self.completed_at - self.started_at

    @property
    def success(self) -> bool:
        return self.status == TaskStatus.COMPLETED

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "status": self.status.value,
            "output": self.output,
            "error": self.error,
            "duration": round(self.duration, 3),
            "has_data": len(self.data) > 0,
            "data_size": len(self.data),
            "metadata": self.metadata,
        }

    def to_json(self) -> bytes:
        return json.dumps(self.to_dict(), default=str).encode()


class BaseTask(abc.ABC):
    """Abstract base class for C2 tasks.

    Lifecycle:
        1. Server creates task with args
        2. encode() serializes for transport to beacon
        3. Beacon receives, deserializes with decode()
        4. execute() runs on target
        5. Result sent back through transport

    Every task type (shell, download, upload, etc.) extends this.
    """

    # Subclasses set these
    TASK_TYPE: str = "base"
    DESCRIPTION: str = "Base task"
    OPSEC_RISK: str = "low"        # low, medium, high, critical

    def __init__(self, task_id: str = "", **kwargs: Any) -> None:
        self.task_id = task_id
        self.args = kwargs
        self.timeout: float = kwargs.get("timeout", 300.0)  # 5 min default

    def encode(self) -> dict[str, Any]:
        """Serialize task for transport to beacon.

        Returns a JSON-serializable dict that the beacon can
        deserialize and execute.
        """
        return {
            "task_id": self.task_id,
            "type": self.TASK_TYPE,
            "args": self.args,
            "timeout": self.timeout,
        }

    @classmethod
    def decode(cls, data: dict[str, Any]) -> "BaseTask":
        """Deserialize a task from transport data."""
        return cls(
            task_id=data.get("task_id", ""),
            **data.get("args", {}),
        )

    @abc.abstractmethod
    async def execute(self) -> TaskResult:
        """Execute the task on the target (beacon-side).

        Returns TaskResult with output/data.
        """
        ...

    def to_dict(self) -> dict[str, Any]:
        return self.encode()

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} id={self.task_id} args={self.args}>"


# ══════════════════════════════════════════════════════════════════════
#  TASK REGISTRY — maps type strings to task classes
# ══════════════════════════════════════════════════════════════════════

_TASK_REGISTRY: dict[str, type[BaseTask]] = {}


def register_task(cls: type[BaseTask]) -> type[BaseTask]:
    """Decorator: register a task type in the global registry."""
    _TASK_REGISTRY[cls.TASK_TYPE] = cls
    return cls


def get_task_class(task_type: str) -> type[BaseTask] | None:
    """Look up a task class by type string."""
    return _TASK_REGISTRY.get(task_type)


def create_task(task_type: str, task_id: str = "", **kwargs: Any) -> BaseTask | None:
    """Factory: create a task instance by type string."""
    cls = get_task_class(task_type)
    if not cls:
        log.warning("Unknown task type: %s", task_type)
        return None
    return cls(task_id=task_id, **kwargs)


def list_task_types() -> list[dict[str, str]]:
    """List all registered task types."""
    return [
        {"type": cls.TASK_TYPE, "description": cls.DESCRIPTION, "risk": cls.OPSEC_RISK}
        for cls in _TASK_REGISTRY.values()
    ]


# ══════════════════════════════════════════════════════════════════════
#  UNIT TESTS
# ══════════════════════════════════════════════════════════════════════

class TestTaskResult:
    """Tests for TaskResult."""

    def test_to_dict(self) -> None:
        r = TaskResult(task_id="t1", output="hello", status=TaskStatus.COMPLETED)
        d = r.to_dict()
        assert d["task_id"] == "t1"
        assert d["output"] == "hello"
        assert d["status"] == "completed"

    def test_success(self) -> None:
        r = TaskResult(status=TaskStatus.COMPLETED)
        assert r.success is True
        r2 = TaskResult(status=TaskStatus.FAILED)
        assert r2.success is False

    def test_to_json(self) -> None:
        r = TaskResult(task_id="t2")
        j = json.loads(r.to_json())
        assert j["task_id"] == "t2"
