"""Forge C2 — Implant Builder package.

Exports all implant builders and helpers::

    from forge_c2.implant import ImplantBuilder, ImplantConfig
    from forge_c2.implant import WindowsImplant, LinuxImplant
    from forge_c2.implant import StagerFactory
"""
from __future__ import annotations

from forge_c2.implant.implant_config import (
    ImplantConfig,
    ImplantArch,
    ImplantFormat,
    ImplantOS,
    ObfuscationLevel,
    SleepTechnique,
)
from forge_c2.implant.implant_builder import ImplantBuilder
from forge_c2.implant.implant_windows import WindowsImplant
from forge_c2.implant.implant_linux import LinuxImplant
from forge_c2.implant.stager_factory import StagerFactory, StagerType

__all__ = [
    "ImplantConfig",
    "ImplantArch",
    "ImplantFormat",
    "ImplantOS",
    "ObfuscationLevel",
    "SleepTechnique",
    "ImplantBuilder",
    "WindowsImplant",
    "LinuxImplant",
    "StagerFactory",
    "StagerType",
]
