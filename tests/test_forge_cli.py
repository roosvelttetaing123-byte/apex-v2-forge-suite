from __future__ import annotations

import argparse

import pytest

import forge


def test_port_accepts_valid_range() -> None:
    assert forge._port("1") == 1
    assert forge._port("65535") == 65535


def test_port_rejects_invalid_range() -> None:
    with pytest.raises(argparse.ArgumentTypeError):
        forge._port("0")
    with pytest.raises(argparse.ArgumentTypeError):
        forge._port("65536")


def test_target_file_ignores_comments_and_blanks(tmp_path) -> None:
    target_file = tmp_path / "targets.txt"
    target_file.write_text("\n# comment\nhttps://example.com\n10.0.0.1\n", encoding="utf-8")

    assert forge._read_targets_file(str(target_file)) == ["https://example.com", "10.0.0.1"]


def test_scan_input_requires_one_target_source(tmp_path) -> None:
    target_file = tmp_path / "targets.txt"
    target_file.write_text("https://example.com\n", encoding="utf-8")
    args = argparse.Namespace(
        target="https://example.com",
        targets=str(target_file),
        resume=None,
        parallel=3,
    )

    with pytest.raises(ValueError, match="only one"):
        forge._validate_common_scan_inputs(args)


def test_scan_input_rejects_empty_target_file(tmp_path) -> None:
    target_file = tmp_path / "targets.txt"
    target_file.write_text("\n# no targets\n", encoding="utf-8")
    args = argparse.Namespace(target=None, targets=str(target_file), resume=None, parallel=3)

    with pytest.raises(ValueError, match="no usable targets"):
        forge._validate_common_scan_inputs(args)


def test_scan_input_rejects_bad_url_scheme() -> None:
    args = argparse.Namespace(target="ftp://example.com", targets=None, resume=None, parallel=3)

    with pytest.raises(ValueError, match="unsupported URL scheme"):
        forge._validate_common_scan_inputs(args)


def test_high_risk_requires_flag_and_environment(monkeypatch) -> None:
    args = argparse.Namespace(red_team=True)

    monkeypatch.delenv("FORGE_ENABLE_HIGH_RISK", raising=False)
    assert forge._is_high_risk_enabled(args) is False

    monkeypatch.setenv("FORGE_ENABLE_HIGH_RISK", "1")
    assert forge._is_high_risk_enabled(args) is True


def test_payload_evasion_defaults_are_disabled() -> None:
    parser = forge.build_parser()
    args = parser.parse_args([
        "payload",
        "--red-team",
        "--lhost",
        "127.0.0.1",
    ])

    assert args.sandbox_detect is False
    assert args.amsi_bypass is False
    assert args.etw_bypass is False


def test_dashboard_no_auth_requires_loopback() -> None:
    assert forge._launch_web_dashboard(host="0.0.0.0", port=1337, auth=False) == 1


def test_kill_date_validation() -> None:
    forge._validate_kill_date("2026-06-23")

    with pytest.raises(ValueError, match="YYYY-MM-DD"):
        forge._validate_kill_date("06/23/2026")
