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

# ── Sprint 3: C2 Task Expansion (12 new tasks) ────────────────────
from forge_c2.tasks.task_assembly import AssemblyTask
from forge_c2.tasks.task_keylogger import KeyloggerTask
from forge_c2.tasks.task_browser_creds import BrowserCredsTask
from forge_c2.tasks.task_clipboard import ClipboardTask
from forge_c2.tasks.task_mimikatz import MimikatzTask
from forge_c2.tasks.task_registry import RegistryTask
from forge_c2.tasks.task_service import ServiceTask
from forge_c2.tasks.task_wmi import WMITask
from forge_c2.tasks.task_inject import InjectTask
from forge_c2.tasks.task_token import TokenTask
from forge_c2.tasks.task_portscan import PortScanTask
from forge_c2.tasks.task_download_exec import DownloadExecTask

__all__ = [
    # Base
    "BaseTask",
    "TaskResult",
    "TaskStatus",
    "register_task",
    "get_task_class",
    "create_task",
    "list_task_types",
    # Original Tasks
    "ShellTask",
    "DownloadTask",
    "UploadTask",
    "ScreenshotTask",
    "SocksTask",
    "HashDumpTask",
    # Sprint 3 Tasks
    "AssemblyTask",
    "KeyloggerTask",
    "BrowserCredsTask",
    "ClipboardTask",
    "MimikatzTask",
    "RegistryTask",
    "ServiceTask",
    "WMITask",
    "InjectTask",
    "TokenTask",
    "PortScanTask",
    "DownloadExecTask",
]
