from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from common.confirm_gate import (
    LAUNCH_ACTION_ENV,
    LAUNCH_CONFIRMATIONS_ENV,
    LAUNCH_JOB_ID_ENV,
    ActionConfirmation,
    confirm,
    decide_action,
    encode_launch_confirmations,
    load_launch_confirmations,
    load_launch_expectation,
    select_launch_confirmation,
    set_auto_confirm,
)
from common.scope import Scope, ScopeReason, decide_scope


LAB_URL = "http://127.0.0.1:8080/fixture"
LAB_SCOPE = ["127.0.0.1/32"]
NOW = datetime(2026, 7, 19, 18, 0, tzinfo=timezone.utc)


@pytest.mark.parametrize("allowed", [None, [], [""], [" ", "\t"]])
def test_missing_effective_scope_denies(allowed: list[str] | None) -> None:
    decision = decide_scope(LAB_URL, allowed)

    assert decision.allowed is False
    assert decision.reason_code == ScopeReason.MISSING_SCOPE.value


@pytest.mark.parametrize(
    ("target", "allowed"),
    [
        ("https://app.example.test/login", ["example.test"]),
        ("api.example.test", ["https://example.test/root"]),
        ("10.20.30.40", ["10.20.30.0/24"]),
        ("10.20.30.0/25", ["10.20.30.0/24"]),
        ("2001:db8::10", ["2001:db8::/64"]),
        ("https://[2001:db8::10]/", ["2001:db8::/64"]),
    ],
)
def test_scope_normalization_allows_deterministic_matches(
    target: str,
    allowed: list[str],
) -> None:
    assert decide_scope(target, allowed).allowed is True


def test_exclusion_overrides_broader_allow() -> None:
    decision = decide_scope(
        "10.20.30.40",
        ["10.20.30.0/24"],
        excluded=["10.20.30.40/32"],
    )

    assert decision.allowed is False
    assert decision.reason_code == ScopeReason.EXCLUDED.value


def test_candidate_cidr_is_denied_when_it_contains_one_excluded_ip() -> None:
    decision = decide_scope(
        "10.20.30.0/24",
        ["10.20.0.0/16"],
        excluded=["10.20.30.40/32"],
    )

    assert decision.allowed is False
    assert decision.reason_code == ScopeReason.EXCLUDED.value


def test_ipv4_mapped_ipv6_honors_ipv4_exclusion() -> None:
    decision = decide_scope(
        "::ffff:127.0.0.1",
        ["::/0"],
        excluded=["127.0.0.0/8"],
    )

    assert decision.allowed is False
    assert decision.reason_code == ScopeReason.EXCLUDED.value


def test_ipv6_supernet_containing_mapped_ipv4_honors_ipv4_exclusion() -> None:
    decision = decide_scope(
        "::/0",
        ["::/0"],
        excluded=["127.0.0.0/8"],
    )

    assert decision.allowed is False
    assert decision.reason_code == ScopeReason.EXCLUDED.value


def test_ipv4_candidate_honors_broad_ipv6_exclusion_containing_mapped_range() -> None:
    decision = decide_scope(
        "127.0.0.1",
        ["127.0.0.0/8"],
        excluded=["::/0"],
    )

    assert decision.allowed is False
    assert decision.reason_code == ScopeReason.EXCLUDED.value


def test_domain_scope_never_authorizes_resolved_ip() -> None:
    decision = decide_scope("192.0.2.25", ["app.example.test"])

    assert decision.allowed is False
    assert decision.reason_code == ScopeReason.TARGET_MISMATCH.value


@pytest.mark.parametrize(
    "target",
    [
        r"https://evil.test\@allowed.test/path",
        "https://operator:password@allowed.test/path",
    ],
)
def test_ambiguous_or_userinfo_url_is_rejected(target: str) -> None:
    decision = decide_scope(target, ["allowed.test"])

    assert decision.allowed is False
    assert decision.reason_code == ScopeReason.MALFORMED_TARGET.value


@pytest.mark.parametrize(
    "target",
    [
        "@allowed.test",
        "[[127.0.0.1]]",
        "]::1[",
        "example.test?token=one",
        "example.test#fragment",
    ],
)
def test_malformed_bare_authority_is_rejected(target: str) -> None:
    decision = decide_scope(target, ["allowed.test", "example.test", "127.0.0.0/8", "::1/128"])

    assert decision.allowed is False
    assert decision.reason_code == ScopeReason.MALFORMED_TARGET.value


def test_strict_bare_authority_still_allows_valid_bracketed_ipv6_port() -> None:
    assert decide_scope("[::1]:8443", ["::1/128"]).allowed is True


@pytest.mark.parametrize(
    "target",
    ["2130706433", "0177.0.0.1", "0x7f000001", "127.1", "010.0.0.1", "999.999.999.999"],
)
def test_ambiguous_ipv4_forms_are_not_treated_as_domains(target: str) -> None:
    decision = decide_scope(target, ["allowed.test"])

    assert decision.allowed is False
    assert decision.reason_code == ScopeReason.MALFORMED_TARGET.value


def test_broader_candidate_cidr_is_not_authorized_by_narrow_scope() -> None:
    decision = decide_scope("10.20.0.0/16", ["10.20.30.0/24"])

    assert decision.allowed is False
    assert decision.reason_code == ScopeReason.TARGET_MISMATCH.value


@pytest.mark.parametrize(
    "allowed",
    [
        ["10.20.30.1/999"],
        ["https://"],
        ["example.test", "10.20.30.1/999"],
        ["*"],
    ],
)
def test_malformed_or_ambiguous_scope_denies(allowed: list[str]) -> None:
    decision = decide_scope("example.test", allowed)

    assert decision.allowed is False
    assert decision.reason_code == ScopeReason.MALFORMED_SCOPE.value


def test_blank_exclusion_is_not_silently_discarded() -> None:
    decision = decide_scope("example.test", ["example.test"], excluded=[" "])

    assert decision.allowed is False
    assert decision.reason_code == ScopeReason.MALFORMED_SCOPE.value


def test_non_string_scope_or_target_data_fails_closed() -> None:
    malformed_scope = decide_scope("example.test", [None])  # type: ignore[list-item]
    malformed_target = decide_scope(None, ["example.test"])  # type: ignore[arg-type]

    assert malformed_scope.reason_code == ScopeReason.MALFORMED_SCOPE.value
    assert malformed_target.reason_code == ScopeReason.MALFORMED_TARGET.value


def _confirmation(**overrides: object) -> ActionConfirmation:
    values: dict[str, object] = {
        "job_id": "job-lab-001",
        "target": LAB_URL,
        "engine": "webforge",
        "action": "scan",
        "issued_at": NOW,
    }
    values.update(overrides)
    return ActionConfirmation.create(**values)


def _decision(
    confirmation: ActionConfirmation | dict[str, object] | None,
    **overrides: object,
):
    values: dict[str, object] = {
        "target": LAB_URL,
        "allowed_scope": LAB_SCOPE,
        "excluded_scope": [],
        "confirmation": confirmation,
        "job_id": "job-lab-001",
        "engine": "webforge",
        "action": "scan",
        "now": NOW,
    }
    values.update(overrides)
    return decide_action(**values)


def test_exact_confirmation_allows_matching_local_lab_action() -> None:
    decision = _decision(_confirmation())

    assert decision.allowed is True
    assert decision.reason_code == ScopeReason.ALLOWED.value


@pytest.mark.parametrize(
    ("confirmed_target", "requested_target"),
    [
        ("example.test:443", "example.test:8443"),
        ("127.0.0.1:443", "127.0.0.1:8443"),
        ("[2001:db8::1]:443", "[2001:db8::1]:8443"),
    ],
)
def test_bare_target_port_changes_invalidate_confirmation(
    confirmed_target: str,
    requested_target: str,
) -> None:
    confirmation = ActionConfirmation.create(
        job_id="job-lab-001",
        target=confirmed_target,
        engine="webforge",
        action="scan",
        issued_at=NOW,
    )
    decision = decide_action(
        target=requested_target,
        allowed_scope=[requested_target],
        excluded_scope=[],
        confirmation=confirmation,
        job_id="job-lab-001",
        engine="webforge",
        action="scan",
        now=NOW,
    )

    assert decision.allowed is False
    assert decision.reason_code == ScopeReason.TARGET_MISMATCH.value


def test_missing_confirmation_denies_active_action() -> None:
    decision = _decision(None)

    assert decision.allowed is False
    assert decision.reason_code == ScopeReason.MISSING_CONFIRMATION.value


@pytest.mark.parametrize(
    ("confirmation", "reason"),
    [
        (_confirmation(job_id="job-other"), ScopeReason.JOB_MISMATCH),
        (_confirmation(target="http://127.0.0.2:8080/fixture"), ScopeReason.TARGET_MISMATCH),
        (_confirmation(engine="netforge"), ScopeReason.ENGINE_MISMATCH),
        (_confirmation(action="web_to_network"), ScopeReason.ACTION_MISMATCH),
        (
            _confirmation(issued_at=NOW - timedelta(minutes=10)),
            ScopeReason.STALE_CONFIRMATION,
        ),
    ],
)
def test_mismatched_or_stale_confirmation_denies(
    confirmation: ActionConfirmation,
    reason: ScopeReason,
) -> None:
    decision = _decision(confirmation)

    assert decision.allowed is False
    assert decision.reason_code == reason.value


def test_changed_dns_answer_invalidates_network_escalation_confirmation() -> None:
    confirmation = ActionConfirmation.create(
        job_id="job-lab-001",
        target="192.0.2.10",
        engine="netforge",
        action="web_to_network",
        issued_at=NOW,
    )
    decision = decide_action(
        target="192.0.2.11",
        allowed_scope=["192.0.2.10/32", "192.0.2.11/32"],
        excluded_scope=[],
        confirmation=confirmation,
        job_id="job-lab-001",
        engine="netforge",
        action="web_to_network",
        now=NOW,
    )

    assert decision.allowed is False
    assert decision.reason_code == ScopeReason.TARGET_MISMATCH.value


def test_mutated_confirmation_digest_is_rejected_as_invalid() -> None:
    forged = _confirmation().to_dict()
    forged["job_id"] = "job-forged"

    decision = _decision(forged)

    assert decision.allowed is False
    assert decision.reason_code == ScopeReason.INVALID_CONFIRMATION.value


def test_direct_confirmation_instances_receive_full_shape_validation() -> None:
    wrong_schema = replace(_confirmation(), schema_version="not-forge")
    non_boolean = replace(_confirmation(), confirmed="yes")  # type: ignore[arg-type]

    assert _decision(wrong_schema).reason_code == ScopeReason.INVALID_CONFIRMATION.value
    assert _decision(non_boolean).reason_code == ScopeReason.INVALID_CONFIRMATION.value
    with pytest.raises(ValueError, match="boolean"):
        ActionConfirmation.create(
            job_id="job-lab-001",
            target=LAB_URL,
            engine="webforge",
            action="scan",
            issued_at=NOW,
            confirmed="yes",  # type: ignore[arg-type]
        )


def test_falsey_malformed_issued_at_is_not_replaced_with_current_time() -> None:
    with pytest.raises(ValueError, match="datetime"):
        ActionConfirmation.create(
            job_id="job-lab-001",
            target=LAB_URL,
            engine="webforge",
            action="scan",
            issued_at=False,  # type: ignore[arg-type]
        )


def test_confirmation_max_age_cannot_exceed_short_lived_contract() -> None:
    old = _confirmation(issued_at=NOW - timedelta(days=365))

    decision = _decision(old, max_age_seconds=10**100)

    assert decision.allowed is False
    assert decision.reason_code == ScopeReason.INVALID_CONFIRMATION.value


def test_trusted_parent_launch_context_round_trips_exact_confirmation() -> None:
    confirmation = _confirmation()
    environ = {LAUNCH_CONFIRMATIONS_ENV: encode_launch_confirmations([confirmation])}

    loaded = load_launch_confirmations(environ)
    selected = select_launch_confirmation(
        loaded,
        target=LAB_URL,
        engine="webforge",
        action="scan",
    )

    assert selected == confirmation


def test_launch_expectation_requires_canonical_independent_job_and_action() -> None:
    environ = {
        LAUNCH_JOB_ID_ENV: "job-lab-001",
        LAUNCH_ACTION_ENV: "scan",
    }

    assert load_launch_expectation(environ) == ("job-lab-001", "scan")
    assert load_launch_expectation({LAUNCH_JOB_ID_ENV: "job-lab-001"}) is None
    assert load_launch_expectation({**environ, LAUNCH_ACTION_ENV: " Scan "}) is None


def test_launch_context_selection_requires_exact_target_and_job() -> None:
    first = _confirmation(job_id="job-one")
    second = _confirmation(job_id="job-two")

    assert select_launch_confirmation(
        [first],
        target="http://127.0.0.2:8080/fixture",
        engine="webforge",
        action="scan",
    ) is None
    assert select_launch_confirmation(
        [first, second],
        target=LAB_URL,
        engine="webforge",
        action="scan",
    ) is None
    assert select_launch_confirmation(
        [first, second],
        target=LAB_URL,
        engine="webforge",
        action="scan",
        job_id="job-two",
    ) == second


def test_explicit_empty_launch_environment_does_not_use_ambient_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        LAUNCH_CONFIRMATIONS_ENV,
        encode_launch_confirmations([_confirmation()]),
    )

    assert load_launch_confirmations({}) == []


@pytest.mark.parametrize("raw", ["not-json", "[]", '{"schema_version":"wrong"}'])
def test_malformed_launch_context_fails_closed(raw: str) -> None:
    assert load_launch_confirmations({LAUNCH_CONFIRMATIONS_ENV: raw}) == []


def test_dry_run_scope_match_is_explicitly_not_action_authorization() -> None:
    decision = decide_action(
        target=LAB_URL,
        allowed_scope=LAB_SCOPE,
        excluded_scope=[],
        confirmation=None,
        job_id="job-lab-001",
        engine="webforge",
        action="scan",
        now=NOW,
        require_confirmation=False,
    )

    assert decision.allowed is True
    assert decision.reason_code == ScopeReason.SCOPE_MATCHED.value
    assert "no action was authorized" in decision.reason.lower()


def test_non_boolean_confirmation_requirement_fails_closed() -> None:
    decision = _decision(None, require_confirmation=0)

    assert decision.allowed is False
    assert decision.reason_code == ScopeReason.INVALID_CONFIRMATION.value


def test_non_boolean_auto_confirm_cannot_enable_legacy_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    set_auto_confirm(False)
    with pytest.raises(ValueError, match="boolean"):
        set_auto_confirm("false")  # type: ignore[arg-type]
    monkeypatch.setattr("builtins.input", lambda _prompt: "no")

    assert confirm("test", "local fixture", LAB_URL, "none") is False


def test_confirmation_serialization_and_logs_do_not_expose_target_secrets(
    caplog: pytest.LogCaptureFixture,
) -> None:
    password = "CANARY_PASSWORD_002"
    token = "CANARY_TOKEN_002"
    target = f"https://127.0.0.1/path?password={password}&token={token}"
    record = ActionConfirmation.create(
        job_id="job-lab-001",
        target=target,
        engine="webforge",
        action="scan",
        issued_at=NOW,
    )

    serialized = str(record.to_dict())
    assert password not in serialized
    assert token not in serialized

    set_auto_confirm(True)
    try:
        assert confirm("test", f"scan token={token}", target, f"risk {password}") is True
    finally:
        set_auto_confirm(False)
    assert password not in caplog.text
    assert token not in caplog.text


def test_scope_denial_logging_does_not_echo_url_secrets(caplog: pytest.LogCaptureFixture) -> None:
    canary_password = "CANARY_PASSWORD_001"
    canary_token = "CANARY_TOKEN_001"
    target = f"https://operator:{canary_password}@outside.test/path?token={canary_token}"

    assert Scope([], strict=False).check(target) is False
    rendered = caplog.text
    assert canary_password not in rendered
    assert canary_token not in rendered

    serialized = decide_scope(target, ["inside.test"]).to_dict()
    assert canary_password not in str(serialized)
    assert canary_token not in str(serialized)


def test_serialized_denial_does_not_disclose_exclusion_policy() -> None:
    decision = decide_scope(
        "127.0.0.0/8",
        ["127.0.0.0/8"],
        excluded=["127.0.0.1/32"],
    )

    assert decision.reason_code == ScopeReason.EXCLUDED.value
    assert "matched_scope" not in decision.to_dict()
    assert "127.0.0.1/32" not in str(decision.to_dict())
