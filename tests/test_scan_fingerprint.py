from __future__ import annotations

import json

import pytest

from common.scan_fingerprint import (
    RatePolicy,
    RateSignal,
    ScanFingerprintStore,
    build_scan_fingerprint,
    service_key,
    stable_json_hash,
)


def test_stable_json_hash_ignores_mapping_and_set_order() -> None:
    left = {
        "banners": {"ssh": "OpenSSH_9.2", "http": "nginx"},
        "ports": {443, 22, 80},
    }
    right = {
        "ports": {80, 443, 22},
        "banners": {"http": "nginx", "ssh": "OpenSSH_9.2"},
    }

    assert stable_json_hash(left) == stable_json_hash(right)


def test_build_scan_fingerprint_normalizes_identity() -> None:
    fingerprint = build_scan_fingerprint(
        "HTTPS://Example.COM:443/login",
        "HTTPS",
        port="443",
        protocol="TCP",
        attributes={"headers": {"Server": "nginx"}, "paths": ["/login"]},
    )

    assert fingerprint.key == "example.com|tcp|443|https"
    assert fingerprint.host == "example.com"
    assert fingerprint.service == "https"
    assert fingerprint.port == 443
    assert fingerprint.protocol == "tcp"


def test_service_key_handles_bare_host_port() -> None:
    assert service_key("Example.com:8443", "HTTPS", None, "TCP") == "example.com|tcp|-|https"


def test_store_plans_only_new_or_changed_targets(tmp_path) -> None:
    state_file = tmp_path / "scan-fingerprints.json"
    store = ScanFingerprintStore(state_file)

    original = build_scan_fingerprint(
        "app.example.test",
        "https",
        port=443,
        attributes={"status": 200, "title": "Portal", "server": "nginx"},
    )
    store.record_scan(original, scanned_at="2026-06-30T12:00:00Z")
    store.save()

    unchanged = build_scan_fingerprint(
        "APP.EXAMPLE.TEST",
        "HTTPS",
        port="443",
        attributes={"server": "nginx", "title": "Portal", "status": 200},
    )
    changed = build_scan_fingerprint(
        "app.example.test",
        "https",
        port=443,
        attributes={"status": 200, "title": "Admin Portal", "server": "nginx"},
    )
    new_target = build_scan_fingerprint(
        "api.example.test",
        "https",
        port=443,
        attributes={"status": 200, "title": "API"},
    )

    reloaded = ScanFingerprintStore(state_file)
    plan = reloaded.plan_rescan([unchanged, changed, new_target])

    assert [decision.reason for decision in plan.decisions] == ["unchanged", "changed", "new"]
    assert plan.unchanged_keys == [unchanged.key]
    assert plan.changed_keys == [changed.key, new_target.key]
    assert plan.targets_to_scan == [changed, new_target]


def test_record_scan_preserves_first_seen_and_increments_scan_count(tmp_path) -> None:
    state_file = tmp_path / "scan-fingerprints.json"
    target = build_scan_fingerprint(
        "db.example.test",
        "postgres",
        port=5432,
        attributes={"banner": "PostgreSQL 15"},
    )

    store = ScanFingerprintStore(state_file)
    first = store.record_scan(target, scanned_at="2026-06-30T12:00:00Z")
    second = store.record_scan(target, scanned_at="2026-06-30T13:00:00Z")
    store.save()

    assert first["scan_count"] == 1
    assert second["scan_count"] == 2
    assert second["first_scanned_at"] == "2026-06-30T12:00:00Z"
    assert second["last_scanned_at"] == "2026-06-30T13:00:00Z"

    raw = json.loads(state_file.read_text(encoding="utf-8"))
    assert raw["targets"][target.key]["scan_count"] == 2
    assert not list(tmp_path.glob("*.tmp"))


def test_rate_adapter_reduces_on_negative_signals_and_persists(tmp_path) -> None:
    state_file = tmp_path / "scan-fingerprints.json"
    target = build_scan_fingerprint("api.example.test", "https", port=443)
    policy = RatePolicy(initial_rate=20.0, min_rate=1.0, recovery_successes=2)

    store = ScanFingerprintStore(state_file)
    timeout = store.adapt_rate(
        target,
        RateSignal.TIMEOUT,
        policy=policy,
        updated_at="2026-06-30T12:00:00Z",
    )
    dropped = store.adapt_rate(
        target,
        "connection_reset",
        policy=policy,
        updated_at="2026-06-30T12:01:00Z",
    )
    limited = store.adapt_rate(
        target,
        "429",
        policy=policy,
        updated_at="2026-06-30T12:02:00Z",
    )
    store.save()

    assert timeout.current_rate == 10.0
    assert timeout.action == "backoff_timeout"
    assert dropped.current_rate == 5.0
    assert dropped.action == "backoff_connection_drop"
    assert limited.current_rate == 1.25
    assert limited.action == "backoff_rate_limit"

    reloaded = ScanFingerprintStore(state_file)
    assert reloaded.current_rate(target) == 1.25
    assert reloaded.rate_state(target)["backoff_streak"] == 3


def test_rate_adapter_recovers_cautiously_after_success_streak(tmp_path) -> None:
    state_file = tmp_path / "scan-fingerprints.json"
    target = build_scan_fingerprint("web.example.test", "https", port=443)
    policy = RatePolicy(
        initial_rate=10.0,
        min_rate=1.0,
        recovery_factor=1.2,
        recovery_successes=3,
    )
    store = ScanFingerprintStore(state_file)

    store.adapt_rate(target, "rate_limit", policy=policy)
    success_1 = store.adapt_rate(target, "success", policy=policy)
    success_2 = store.adapt_rate(target, "success", policy=policy)
    success_3 = store.adapt_rate(target, "success", policy=policy)

    assert success_1.current_rate == 2.5
    assert success_1.action == "hold"
    assert success_1.success_streak == 1
    assert success_2.current_rate == 2.5
    assert success_2.success_streak == 2
    assert success_3.current_rate == 3.0
    assert success_3.action == "recover"
    assert success_3.success_streak == 0


def test_rate_adapter_never_exceeds_max_rate(tmp_path) -> None:
    state_file = tmp_path / "scan-fingerprints.json"
    target = build_scan_fingerprint("web.example.test", "https", port=443)
    policy = RatePolicy(
        initial_rate=10.0,
        min_rate=1.0,
        max_rate=10.0,
        recovery_factor=2.0,
        recovery_successes=1,
    )
    store = ScanFingerprintStore(state_file)

    store.adapt_rate(target, "timeout", policy=policy)
    for _ in range(10):
        result = store.adapt_rate(target, "success", policy=policy)

    assert result.current_rate == 10.0


def test_invalid_rate_signal_is_rejected(tmp_path) -> None:
    target = build_scan_fingerprint("web.example.test", "https", port=443)
    store = ScanFingerprintStore(tmp_path / "scan-fingerprints.json")

    with pytest.raises(ValueError, match="Unsupported rate signal"):
        store.adapt_rate(target, "server_on_fire")
