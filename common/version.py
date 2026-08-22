"""Canonical Forge Suite release identity."""

from __future__ import annotations

from pathlib import Path


_VERSION_FILE = Path(__file__).resolve().parents[1] / "VERSION"
VERSION = _VERSION_FILE.read_text(encoding="ascii").strip()

if not VERSION or any(not part.isdigit() for part in VERSION.split(".")):
    raise RuntimeError(f"invalid release version in {_VERSION_FILE}")

PRODUCT_NAME = "Forge Suite"
PRODUCT_LABEL = f"{PRODUCT_NAME} v{VERSION} APEX"
PRODUCT_USER_AGENT = f"Forge-Suite/{VERSION}"
