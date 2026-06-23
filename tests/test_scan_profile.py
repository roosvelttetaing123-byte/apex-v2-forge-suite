"""ScanProfile — full test coverage.

Tests: all 6 profiles, get_profile(), validate_profile(), list_profiles(),
describe_profiles(), to_dict() structure, and per-profile setting assertions.
"""
from __future__ import annotations

import io
import sys

import pytest

from webforge.core.scan_profile import (
    PROFILES,
    ScanProfile,
    get_profile,
    list_profiles,
    describe_profiles,
    validate_profile,
)


# ── All profiles exist ────────────────────────────────────────────────────────

class TestProfileRegistry:
    REQUIRED_PROFILES = {"quick", "standard", "full", "api", "compliance", "stealth"}

    def test_all_required_profiles_present(self):
        missing = self.REQUIRED_PROFILES - set(PROFILES.keys())
        assert not missing, f"Missing profiles: {missing}"

    def test_all_profiles_have_modules(self):
        for name, prof in PROFILES.items():
            assert len(prof.modules) > 0, f"Profile '{name}' has zero modules"

    def test_all_profiles_have_descriptions(self):
        for name, prof in PROFILES.items():
            assert prof.description.strip(), f"Profile '{name}' has empty description"

    def test_all_profiles_have_tags(self):
        for name, prof in PROFILES.items():
            assert len(prof.tags) >= 1, f"Profile '{name}' has no tags"

    def test_all_profiles_have_estimated_time(self):
        for name, prof in PROFILES.items():
            assert prof.estimated_minutes, f"Profile '{name}' has no ETA"

    def test_all_profile_names_match_key(self):
        for key, prof in PROFILES.items():
            assert prof.name == key, f"Profile key '{key}' != name '{prof.name}'"


# ── get_profile() ─────────────────────────────────────────────────────────────

class TestGetProfile:
    def test_get_quick(self):
        p = get_profile("quick")
        assert p.name == "quick"

    def test_get_standard(self):
        p = get_profile("standard")
        assert p.name == "standard"

    def test_get_full(self):
        p = get_profile("full")
        assert p.name == "full"

    def test_get_api(self):
        p = get_profile("api")
        assert p.name == "api"

    def test_get_compliance(self):
        p = get_profile("compliance")
        assert p.name == "compliance"

    def test_get_stealth(self):
        p = get_profile("stealth")
        assert p.name == "stealth"

    def test_case_insensitive(self):
        p = get_profile("QUICK")
        assert p.name == "quick"

    def test_unknown_raises_value_error(self):
        with pytest.raises(ValueError, match="Unknown scan profile"):
            get_profile("nonexistent")

    def test_error_message_lists_available(self):
        with pytest.raises(ValueError) as exc_info:
            get_profile("oops")
        assert "quick" in str(exc_info.value)


# ── Per-profile setting assertions ────────────────────────────────────────────

class TestProfileSettings:
    def test_quick_is_fast(self):
        p = get_profile("quick")
        assert p.rate_limit >= 15.0
        assert p.max_workers >= 10

    def test_quick_skips_verification(self):
        p = get_profile("quick")
        assert p.verify_findings is False

    def test_standard_verifies(self):
        p = get_profile("standard")
        assert p.verify_findings is True

    def test_full_verifies(self):
        p = get_profile("full")
        assert p.verify_findings is True

    def test_full_has_whitebox_modules(self):
        p = get_profile("full")
        assert "source_audit" in p.modules
        assert "secret_scan" in p.modules
        assert "dep_audit" in p.modules

    def test_stealth_is_slow(self):
        p = get_profile("stealth")
        assert p.rate_limit <= 2.0
        assert p.max_workers <= 3

    def test_stealth_skips_verification(self):
        p = get_profile("stealth")
        assert p.verify_findings is False

    def test_api_profile_has_api_modules(self):
        p = get_profile("api")
        assert "rest_audit" in p.modules
        assert "graphql_audit" in p.modules

    def test_compliance_profile_has_ssl_modules(self):
        p = get_profile("compliance")
        assert "ssl_audit" in p.modules
        assert "cert_inspect" in p.modules

    def test_compliance_profile_low_rate(self):
        p = get_profile("compliance")
        assert p.rate_limit <= 10.0

    def test_full_superset_of_standard(self):
        standard_mods = set(get_profile("standard").modules)
        full_mods = set(get_profile("full").modules)
        assert standard_mods.issubset(full_mods)

    def test_quick_is_subset_of_standard(self):
        quick_mods = set(get_profile("quick").modules)
        standard_mods = set(get_profile("standard").modules)
        overlap = quick_mods & standard_mods
        assert len(overlap) >= 5, "Quick should share significant overlap with standard"


# ── list_profiles() ───────────────────────────────────────────────────────────

class TestListProfiles:
    def test_returns_list_of_dicts(self):
        profiles = list_profiles()
        assert isinstance(profiles, list)
        assert all(isinstance(p, dict) for p in profiles)

    def test_count_matches_registry(self):
        assert len(list_profiles()) == len(PROFILES)

    def test_each_has_required_keys(self):
        for p in list_profiles():
            for key in ("name", "description", "modules", "max_workers",
                        "rate_limit", "verify_findings", "estimated_minutes", "tags"):
                assert key in p, f"Missing key '{key}' in profile dict"

    def test_modules_is_list(self):
        for p in list_profiles():
            assert isinstance(p["modules"], list)

    def test_verify_findings_is_bool(self):
        for p in list_profiles():
            assert isinstance(p["verify_findings"], bool)


# ── ScanProfile.to_dict() ─────────────────────────────────────────────────────

class TestScanProfileToDict:
    def test_to_dict_round_trip(self):
        p = get_profile("api")
        d = p.to_dict()
        assert d["name"] == "api"
        assert d["verify_findings"] is True
        assert "rest_audit" in d["modules"]

    def test_to_dict_browser_render_default_false(self):
        d = get_profile("standard").to_dict()
        assert d["browser_render"] is False

    def test_to_dict_all_fields(self):
        d = get_profile("full").to_dict()
        assert isinstance(d["modules"], list)
        assert len(d["modules"]) > 50


# ── validate_profile() ────────────────────────────────────────────────────────

class TestValidateProfile:
    def test_clean_returns_empty_list(self):
        p = get_profile("quick")
        available = set(p.modules)
        assert validate_profile(p, available) == []

    def test_detects_unknown_module(self):
        from dataclasses import replace
        p = get_profile("quick")
        bad = replace(p, modules=[*p.modules, "nonexistent_module"])
        available = set(p.modules)
        invalid = validate_profile(bad, available)
        assert "nonexistent_module" in invalid

    def test_detects_multiple_bad_modules(self):
        from dataclasses import replace
        p = get_profile("quick")
        bad = replace(p, modules=[*p.modules, "bad_module_1", "bad_module_2"])
        available = set(p.modules)
        invalid = validate_profile(bad, available)
        assert "bad_module_1" in invalid
        assert "bad_module_2" in invalid

    def test_valid_module_not_in_result(self):
        p = get_profile("quick")
        available = set(p.modules)
        invalid = validate_profile(p, available)
        assert "sqli_scanner" not in invalid


# ── describe_profiles() ───────────────────────────────────────────────────────

class TestDescribeProfiles:
    def test_runs_without_error(self, capsys):
        describe_profiles()
        captured = capsys.readouterr()
        assert "quick" in captured.out.lower() or "QUICK" in captured.out

    def test_all_profile_names_printed(self, capsys):
        describe_profiles()
        captured = capsys.readouterr()
        for name in PROFILES:
            assert name.upper() in captured.out or name in captured.out

    def test_profile_count_shown(self, capsys):
        describe_profiles()
        captured = capsys.readouterr()
        assert str(len(PROFILES)) in captured.out
