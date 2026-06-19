"""Shared Rich-based logger for all forge-suite frameworks."""
from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme

_THEME = Theme({
    "info":     "cyan",
    "warning":  "yellow",
    "error":    "bold red",
    "critical": "bold white on red",
    "success":  "bold green",
    "finding":  "bold magenta",
    "phase":    "bold cyan",
})

console = Console(theme=_THEME, highlight=True)
quiet_console = Console(quiet=True)


class JsonlFileHandler(logging.Handler):
    """Writes every log record as a JSON line to a file for audit trail."""

    def __init__(self, path: Path, module_name: str = "") -> None:
        super().__init__()
        self.path = path
        self.module_name = module_name
        path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = path.open("a", encoding="utf-8")

    def emit(self, record: logging.LogRecord) -> None:
        entry: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "module": getattr(record, "forge_module", self.module_name),
            "event": record.getMessage(),
            "target": getattr(record, "target", ""),
            "detail": getattr(record, "detail", {}),
            "operator_confirmed": getattr(record, "operator_confirmed", None),
        }
        try:
            self._fh.write(json.dumps(entry, default=str) + "\n")
            self._fh.flush()
        except Exception:
            pass

    def close(self) -> None:
        self._fh.close()
        super().close()


def get_logger(
    name: str,
    log_file: Path | None = None,
    quiet: bool = False,
    verbose: bool = False,
) -> logging.Logger:
    """Return a configured logger with Rich console + optional JSONL file output."""
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    if not quiet:
        rich_handler = RichHandler(
            console=console,
            show_time=True,
            show_path=False,
            markup=True,
            rich_tracebacks=True,
            tracebacks_show_locals=False,
        )
        rich_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
        logger.addHandler(rich_handler)

    if log_file:
        file_handler = JsonlFileHandler(log_file, module_name=name)
        file_handler.setLevel(logging.DEBUG)
        logger.addHandler(file_handler)

    return logger


def phase_banner(number: int, total: int, name: str) -> None:
    """Print a phase separator banner to the Rich console."""
    console.print(f"\n[phase]{'═' * 60}[/phase]")
    console.print(f"[phase]  PHASE {number}/{total}: {name.upper()}[/phase]")
    console.print(f"[phase]{'═' * 60}[/phase]\n")


def finding_banner(title: str, severity: str) -> None:
    """Print a finding alert to the Rich console."""
    color = {
        "Critical": "bold white on red",
        "High":     "bold red",
        "Medium":   "bold yellow",
        "Low":      "yellow",
        "Informational": "cyan",
    }.get(severity, "white")
    console.print(f"[{color}]  [FINDING] {severity.upper()}: {title}[/{color}]")


class TestLogger:
    """Unit tests for logger module."""

    def test_get_logger_returns_logger(self) -> None:
        lg = get_logger("test.logger")
        assert isinstance(lg, logging.Logger)

    def test_get_logger_idempotent(self) -> None:
        lg1 = get_logger("test.idem")
        lg2 = get_logger("test.idem")
        assert lg1 is lg2

    def test_jsonl_handler_writes(self, tmp_path: Path) -> None:
        p = tmp_path / "test.log"
        lg = get_logger("test.jsonl", log_file=p, quiet=True)
        lg.info("hello")
        lines = p.read_text().strip().split("\n")
        assert len(lines) >= 1
        entry = json.loads(lines[0])
        assert entry["event"] == "hello"


if __name__ == "__main__":
    lg = get_logger("demo", verbose=True)
    phase_banner(1, 12, "Reconnaissance")
    lg.info("Logger working correctly")
    finding_banner("SQL Injection", "High")
