"""Forge Payload — Standalone payload generation framework.

Generates encoded shellcode payloads in multiple formats (PE, ELF, DLL, PS1, HTA)
independent of the C2 framework.  Use forge_c2/ for C2 beacon generation.

FOR AUTHORIZED PENETRATION TESTING ONLY.
"""

from forge_payload.payload_factory import PayloadFactory, PayloadArtifact

__all__ = ["PayloadFactory", "PayloadArtifact"]
__version__ = "5.0.0"
