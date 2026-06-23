"""Evidence collection dataclass and helpers."""
from __future__ import annotations

import base64
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Evidence:
    """Full evidence bundle attached to every finding."""
    request_raw:          str | None = None   # Raw HTTP request
    response_raw:         str | None = None   # Raw HTTP response
    screenshot_path:      str | None = None   # PNG screenshot path
    console_capture_path: str | None = None   # Rich HTML console export path
    pcap_path:            str | None = None   # PCAP file path
    extra:                dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize evidence for events, storage, and reports."""
        return {
            "request_raw": self.request_raw,
            "response_raw": self.response_raw,
            "screenshot_path": self.screenshot_path,
            "console_capture_path": self.console_capture_path,
            "pcap_path": self.pcap_path,
            "extra": self.extra,
        }

    def screenshot_as_base64(self) -> str | None:
        """Return screenshot as base64 data URI for HTML embedding."""
        if not self.screenshot_path:
            return None
        p = Path(self.screenshot_path)
        if not p.exists():
            return None
        data = base64.b64encode(p.read_bytes()).decode()
        return f"data:image/png;base64,{data}"

    def console_capture_as_html(self) -> str | None:
        """Return Rich console capture HTML content."""
        if not self.console_capture_path:
            return None
        p = Path(self.console_capture_path)
        if not p.exists():
            return None
        return p.read_text(encoding="utf-8")

    def has_screenshot(self) -> bool:
        """Return True if a screenshot file exists."""
        return bool(self.screenshot_path and Path(self.screenshot_path).exists())

    def copy_to(self, dest_dir: Path) -> "Evidence":
        """Copy all evidence files to dest_dir and return updated Evidence."""
        dest_dir.mkdir(parents=True, exist_ok=True)
        new = Evidence(
            request_raw=self.request_raw,
            response_raw=self.response_raw,
            extra=dict(self.extra),
        )
        if self.screenshot_path and Path(self.screenshot_path).exists():
            dst = dest_dir / Path(self.screenshot_path).name
            shutil.copy2(self.screenshot_path, dst)
            new.screenshot_path = str(dst)
        if self.console_capture_path and Path(self.console_capture_path).exists():
            dst = dest_dir / Path(self.console_capture_path).name
            shutil.copy2(self.console_capture_path, dst)
            new.console_capture_path = str(dst)
        if self.pcap_path and Path(self.pcap_path).exists():
            dst = dest_dir / Path(self.pcap_path).name
            shutil.copy2(self.pcap_path, dst)
            new.pcap_path = str(dst)
        return new


def save_http_evidence(
    request: str,
    response: str,
    evidence_dir: Path,
    finding_id: str,
) -> Evidence:
    """Save HTTP request/response as text files and return Evidence."""
    evidence_dir.mkdir(parents=True, exist_ok=True)
    req_path = evidence_dir / f"{finding_id}_request.txt"
    resp_path = evidence_dir / f"{finding_id}_response.txt"
    req_path.write_text(request, encoding="utf-8")
    resp_path.write_text(response, encoding="utf-8")
    return Evidence(request_raw=request, response_raw=response)


class TestEvidence:
    """Unit tests for evidence module."""

    def test_evidence_creation(self) -> None:
        e = Evidence(request_raw="GET / HTTP/1.1", response_raw="HTTP/1.1 200 OK")
        assert e.request_raw == "GET / HTTP/1.1"
        assert not e.has_screenshot()

    def test_base64_no_path(self) -> None:
        e = Evidence()
        assert e.screenshot_as_base64() is None

    def test_copy_to(self, tmp_path: Path) -> None:
        src = tmp_path / "src"
        src.mkdir()
        ss = src / "shot.png"
        ss.write_bytes(b"PNG")
        e = Evidence(screenshot_path=str(ss))
        dst = tmp_path / "dst"
        new_e = e.copy_to(dst)
        assert new_e.has_screenshot()
        assert Path(new_e.screenshot_path).parent == dst
