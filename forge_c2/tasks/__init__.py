"""Forge C2 — Tasks package.

Exports all task classes and the task registry::

    from forge_c2.tasks import ShellTask, DownloadTask, UploadTask
    from forge_c2.tasks import create_task, list_task_types
"""
from __future__ import annotations

from forge_c2.tasks.base_task import (
    BaseTask,
    TaskResult,
    TaskStatus,
    register_task,
    get_task_class,
    create_task,
    list_task_types,
)

# Import all task modules to trigger @register_task decorators
from forge_c2.tasks.task_shell import ShellTask
from forge_c2.tasks.task_file import DownloadTask, UploadTask
from forge_c2.tasks.task_screenshot import ScreenshotTask
from forge_c2.tasks.task_socks import SocksTask, HashDumpTask

__all__ = [
    # Base
    "BaseTask",
    "TaskResult",
    "TaskStatus",
    "register_task",
    "get_task_class",
    "create_task",
    "list_task_types",
    # Tasks
    "ShellTask",
    "DownloadTask",
    "UploadTask",
    "ScreenshotTask",
    "SocksTask",
    "HashDumpTask",
]
