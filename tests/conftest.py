from __future__ import annotations

import ipaddress
import hashlib
import re
import socket
import tomllib
from pathlib import Path
from typing import Any, Iterable

import pytest


ROOT = Path(__file__).resolve().parents[1]
_FORGE_SKIPPED_NODE_IDS: set[str] = set()
_FORGE_COLLECTION_SKIPS: set[str] = set()
_FORGE_DESELECTED_NODE_IDS: set[str] = set()
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _qualification_policy() -> dict[str, Any]:
    document = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return document["tool"]["forge"]["qualification"]


def pytest_addoption(parser: pytest.Parser) -> None:
    group = parser.getgroup("forge qualification")
    group.addoption(
        "--forge-qualification",
        action="store_true",
        default=False,
        help="enforce the complete Forge collection, node digest, and reviewed skip set",
    )


def pytest_configure() -> None:
    _FORGE_SKIPPED_NODE_IDS.clear()
    _FORGE_COLLECTION_SKIPS.clear()
    _FORGE_DESELECTED_NODE_IDS.clear()


def pytest_runtest_logreport(report: pytest.TestReport) -> None:
    if report.skipped:
        _FORGE_SKIPPED_NODE_IDS.add(report.nodeid)


def pytest_collectreport(report: pytest.CollectReport) -> None:
    if report.skipped:
        _FORGE_COLLECTION_SKIPS.add(report.nodeid)


def pytest_deselected(items: list[pytest.Item]) -> None:
    _FORGE_DESELECTED_NODE_IDS.update(item.nodeid for item in items)


def _collection_nodes_sha256(node_ids: Iterable[str]) -> str:
    """Hash the sorted, NUL-delimited collection identity.

    A trailing NUL makes concatenation unambiguous and keeps the digest contract
    independent of pytest's collection order.
    """

    ordered = sorted(node_ids)
    payload = b"".join(node_id.encode("utf-8") + b"\0" for node_id in ordered)
    return hashlib.sha256(payload).hexdigest()


def _has_focused_selection(config: pytest.Config) -> bool:
    option = config.option
    return bool(
        getattr(option, "keyword", "")
        or getattr(option, "markexpr", "")
        or getattr(option, "lf", False)
        or getattr(option, "failedfirst", False)
        or getattr(option, "newfirst", False)
        or getattr(option, "ignore", None)
        or getattr(option, "ignore_glob", None)
        or getattr(option, "deselect", None)
    )


def _is_canonical_full_tests_invocation(config: pytest.Config) -> bool:
    """Recognize the ordinary unfiltered ``pytest tests/`` entry point."""

    if _has_focused_selection(config) or len(config.args) != 1:
        return False
    try:
        selected = Path(config.args[0]).resolve()
    except (OSError, TypeError, ValueError):
        return False
    return selected == (ROOT / "tests").resolve()


def _qualification_requested(config: pytest.Config) -> bool:
    return bool(config.getoption("--forge-qualification")) or _is_canonical_full_tests_invocation(
        config
    )


def _qualification_failures(
    *,
    node_ids: Iterable[str],
    skipped_node_ids: set[str],
    deselected_node_ids: set[str],
    collectonly: bool,
    policy: dict[str, Any],
) -> list[str]:
    collected = tuple(node_ids)
    collected_set = set(collected)
    reviewed_skips = set(policy["allowed_skip_node_ids"])
    failures: list[str] = []

    if len(collected_set) != len(collected):
        failures.append("full qualification collected duplicate node IDs")

    minimum = int(policy["expected_collection_minimum"])
    if len(collected) < minimum:
        failures.append(
            f"full qualification collection is below floor: minimum={minimum} actual={len(collected)}"
        )

    if deselected_node_ids:
        failures.append(
            "full qualification deselected nodes: " + ", ".join(sorted(deselected_node_ids))
        )

    observed_digest = _collection_nodes_sha256(collected)
    expected_digest = policy.get("expected_collection_sha256")
    if not isinstance(expected_digest, str) or not _SHA256_RE.fullmatch(expected_digest):
        failures.append(
            "expected_collection_sha256 is not a finalized lowercase SHA-256 digest: "
            f"actual={observed_digest}"
        )
    else:
        if observed_digest != expected_digest:
            failures.append(
                "full qualification collection digest changed: "
                f"expected={expected_digest} actual={observed_digest}"
            )

    missing_reviewed_nodes = reviewed_skips - collected_set
    if missing_reviewed_nodes:
        failures.append(
            "reviewed skip nodes are absent from collection: "
            + ", ".join(sorted(missing_reviewed_nodes))
        )

    if not collectonly and skipped_node_ids != reviewed_skips:
        missing = sorted(reviewed_skips - skipped_node_ids)
        unexpected = sorted(skipped_node_ids - reviewed_skips)
        failures.append(
            "full qualification skip set changed: "
            f"missing={missing} unexpected={unexpected}"
        )
    return failures


def pytest_sessionfinish(session: pytest.Session) -> None:
    policy = _qualification_policy()
    allowed_node_ids = set(policy["allowed_skip_node_ids"])
    all_skips = _FORGE_SKIPPED_NODE_IDS | _FORGE_COLLECTION_SKIPS
    unexpected = sorted(all_skips - allowed_node_ids)
    failures: list[str] = []
    if unexpected:
        failures.append("unexpected skipped nodes: " + ", ".join(unexpected))
    if _qualification_requested(session.config):
        failures.extend(
            _qualification_failures(
                node_ids=(item.nodeid for item in session.items),
                skipped_node_ids=all_skips,
                deselected_node_ids=_FORGE_DESELECTED_NODE_IDS,
                collectonly=bool(session.config.option.collectonly),
                policy=policy,
            )
        )
    if failures:
        reporter = session.config.pluginmanager.get_plugin("terminalreporter")
        if reporter is not None:
            reporter.write_sep("=", "FORGE SKIP POLICY FAILURE", red=True)
            for failure in failures:
                reporter.write_line(failure, red=True)
        if session.exitstatus in {pytest.ExitCode.OK, pytest.ExitCode.NO_TESTS_COLLECTED}:
            session.exitstatus = pytest.ExitCode.TESTS_FAILED


@pytest.fixture(autouse=True)
def _isolate_dashboard_database(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Keep dashboard mutation/audit state private to each test.

    Tests must not read or mutate the developer's repository-level
    ``scan_jobs.db``.  A per-test database also prevents parallel or failed
    runs from corrupting later authorization and audit assertions.
    """
    from common.dashboard.server import DashboardServer

    database_path = tmp_path / "dashboard-scan-jobs.db"
    monkeypatch.setattr(
        DashboardServer,
        "_scan_jobs_db_path",
        property(lambda _server: database_path),
    )


def _assert_loopback_address(address: Any) -> None:
    if isinstance(address, str):
        # AF_UNIX filesystem/abstract socket.
        return
    if not isinstance(address, tuple) or not address:
        raise AssertionError(f"unsupported socket address in test: {address!r}")
    host = str(address[0]).split("%", 1)[0]
    if host.lower() == "localhost":
        return
    try:
        parsed = ipaddress.ip_address(host)
    except ValueError as exc:
        raise AssertionError(
            f"test attempted DNS/network access for non-loopback host: {host}"
        ) from exc
    if not parsed.is_loopback:
        raise AssertionError(
            f"test attempted a non-loopback socket: {address!r}"
        )


@pytest.fixture(autouse=True)
def _block_non_loopback_test_sockets(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail in-process non-loopback sockets and libc-backed DNS lookups.

    Subprocesses are outside Python monkeypatch isolation and must use their
    own deterministic fixtures; this guard does not claim to sandbox them.
    """
    original_connect = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex
    original_sendto = socket.socket.sendto
    original_sendmsg = getattr(socket.socket, "sendmsg", None)
    original_getaddrinfo = socket.getaddrinfo
    original_gethostbyname = socket.gethostbyname
    original_gethostbyname_ex = socket.gethostbyname_ex
    original_gethostbyaddr = socket.gethostbyaddr
    original_getnameinfo = socket.getnameinfo

    def guarded_connect(sock: socket.socket, address: Any) -> Any:
        _assert_loopback_address(address)
        return original_connect(sock, address)

    def guarded_connect_ex(sock: socket.socket, address: Any) -> Any:
        _assert_loopback_address(address)
        return original_connect_ex(sock, address)

    def guarded_sendto(sock: socket.socket, data: bytes, *args: Any) -> Any:
        if not args:
            raise AssertionError("sendto called without a destination")
        _assert_loopback_address(args[-1])
        return original_sendto(sock, data, *args)

    def guarded_sendmsg(sock: socket.socket, buffers: Any, *args: Any) -> Any:
        if len(args) >= 3:
            _assert_loopback_address(args[2])
        if original_sendmsg is None:
            raise AssertionError("sendmsg is unavailable on this platform")
        return original_sendmsg(sock, buffers, *args)

    def guarded_getaddrinfo(host: Any, *args: Any, **kwargs: Any) -> Any:
        if host is not None:
            _assert_loopback_address((host, 0))
        return original_getaddrinfo(host, *args, **kwargs)

    def guarded_gethostbyname(host: Any) -> Any:
        _assert_loopback_address((host, 0))
        return original_gethostbyname(host)

    def guarded_gethostbyname_ex(host: Any) -> Any:
        _assert_loopback_address((host, 0))
        return original_gethostbyname_ex(host)

    def guarded_gethostbyaddr(host: Any) -> Any:
        _assert_loopback_address((host, 0))
        return original_gethostbyaddr(host)

    def guarded_getnameinfo(sockaddr: Any, flags: int) -> Any:
        _assert_loopback_address(sockaddr)
        return original_getnameinfo(sockaddr, flags)

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", guarded_connect_ex)
    monkeypatch.setattr(socket.socket, "sendto", guarded_sendto)
    if original_sendmsg is not None:
        monkeypatch.setattr(socket.socket, "sendmsg", guarded_sendmsg)
    monkeypatch.setattr(socket, "getaddrinfo", guarded_getaddrinfo)
    monkeypatch.setattr(socket, "gethostbyname", guarded_gethostbyname)
    monkeypatch.setattr(socket, "gethostbyname_ex", guarded_gethostbyname_ex)
    monkeypatch.setattr(socket, "gethostbyaddr", guarded_gethostbyaddr)
    monkeypatch.setattr(socket, "getnameinfo", guarded_getnameinfo)
