"""Forge C2 — BOF (Beacon Object File) Framework.

Provides in-memory COFF object file loading and execution for post-exploitation.
"""
from forge_c2.bof.bof_loader import BOFLoader, BOFResult
from forge_c2.bof.bof_api import BeaconAPI

__all__ = ["BOFLoader", "BOFResult", "BeaconAPI"]
