"""Forge C2 — Malleable C2 Profiles.

Profile management and parsing for customizable beacon communications.
"""
from forge_c2.profiles.profile_parser import (
    MalleableProfile,
    ProfileParser,
    load_profile,
    list_profiles,
    get_builtin_profile,
    BUILTIN_PROFILES,
)

__all__ = [
    "MalleableProfile",
    "ProfileParser",
    "load_profile",
    "list_profiles",
    "get_builtin_profile",
    "BUILTIN_PROFILES",
]
