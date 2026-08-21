#!/usr/bin/env python3
"""Generate the dashboard API contract from the backend route policy."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
from typing import Any


DEFAULT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_SOURCE = Path("common/dashboard/server.py")
CONTRACT_OUTPUT = Path("contracts/dashboard-api.json")
TYPESCRIPT_OUTPUT = Path("apex-ui/src/generated/dashboard-api.ts")

# These aliases are the stable names consumed by the existing dashboard UI.
# Every alias must match a route mechanically extracted from the backend.
ENDPOINT_ALIASES: dict[str, tuple[str, str]] = {
    "actionConfirmations": ("POST", "/api/v1/action-confirmations"),
    "authLogin": ("POST", "/api/v1/auth/login"),
    "authSsoConfig": ("GET", "/api/v1/auth/sso/config"),
    "authSsoExchange": ("POST", "/api/v1/auth/sso/exchange"),
    "authSsoStart": ("GET", "/api/v1/auth/sso/start"),
    "authTest": ("POST", "/api/v1/auth/test"),
    "deleteScan": ("DELETE", "/api/v1/scans/{scan_id}"),
    "deleteScanTemplate": ("DELETE", "/api/v1/scan/templates/{template_id}"),
    "health": ("GET", "/api/v1/health"),
    "launchScan": ("POST", "/api/v1/scans/launch"),
    "pauseScan": ("POST", "/api/v1/control/pause"),
    "retestFinding": ("POST", "/api/v1/findings/{finding_id}/retest"),
    "resumeScan": ("POST", "/api/v1/control/resume"),
    "scanDetail": ("GET", "/api/v1/scans/{scan_id}"),
    "scanHistory": ("GET", "/api/v1/scans/history"),
    "scanLogs": ("GET", "/api/v1/scans/{scan_id}/logs"),
    "scanTemplates": ("GET", "/api/v1/scan/templates"),
    "saveScanTemplate": ("POST", "/api/v1/scan/templates"),
    "startScan": ("POST", "/api/v1/scans/start"),
    "stopScan": ("POST", "/api/v1/scans/stop"),
    "websocket": ("WS", "/ws/dashboard"),
}


class ContractGenerationError(RuntimeError):
    """Raised when backend route truth cannot be extracted deterministically."""


def _string_pair(node: ast.AST) -> tuple[str, str] | None:
    if not isinstance(node, ast.Tuple) or len(node.elts) != 2:
        return None
    method_node, path_node = node.elts
    if not (
        isinstance(method_node, ast.Constant)
        and isinstance(method_node.value, str)
        and isinstance(path_node, ast.Constant)
        and isinstance(path_node.value, str)
    ):
        return None
    return method_node.value, path_node.value


def extract_backend_routes(source: str) -> list[tuple[str, str]]:
    """Extract and reconcile API policy rows with actual route decorators."""

    try:
        module = ast.parse(source, filename=BACKEND_SOURCE.as_posix())
    except SyntaxError as exc:
        raise ContractGenerationError(f"backend source is not valid Python: {exc}") from exc

    policy: ast.Dict | None = None
    for node in module.body:
        value: ast.AST | None = None
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "DASHBOARD_API_ROUTE_POLICY"
            for target in node.targets
        ):
            value = node.value
        elif (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == "DASHBOARD_API_ROUTE_POLICY"
        ):
            value = node.value
        if value is not None:
            if not isinstance(value, ast.Dict):
                raise ContractGenerationError("DASHBOARD_API_ROUTE_POLICY must be a dict literal")
            policy = value
            break

    if policy is None:
        raise ContractGenerationError("DASHBOARD_API_ROUTE_POLICY was not found")

    policy_routes: set[tuple[str, str]] = set()
    for key in policy.keys:
        if key is None:
            raise ContractGenerationError("dictionary expansion is not allowed in route policy")
        route = _string_pair(key)
        if route is None:
            raise ContractGenerationError("route policy keys must be literal (method, path) pairs")
        method, path = route
        policy_routes.add((method.upper(), path))

    decorated_http_routes: list[tuple[str, str]] = []
    websocket_routes: list[tuple[str, str]] = []
    http_decorators = {"delete", "get", "patch", "post", "put"}
    for node in ast.walk(module):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            if not (
                isinstance(decorator, ast.Call)
                and isinstance(decorator.func, ast.Attribute)
                and decorator.func.attr in http_decorators | {"websocket"}
                and decorator.args
                and isinstance(decorator.args[0], ast.Constant)
                and isinstance(decorator.args[0].value, str)
            ):
                continue
            path = decorator.args[0].value
            if decorator.func.attr == "websocket":
                websocket_routes.append(("WS", path))
            elif path.startswith("/api/"):
                decorated_http_routes.append((decorator.func.attr.upper(), path))

    duplicate_decorators = sorted(
        route for route in set(decorated_http_routes + websocket_routes)
        if (decorated_http_routes + websocket_routes).count(route) > 1
    )
    if duplicate_decorators:
        rendered = ", ".join(f"{method} {path}" for method, path in duplicate_decorators)
        raise ContractGenerationError(f"duplicate backend route decorators: {rendered}")

    decorated_http_set = set(decorated_http_routes)
    missing_policy = sorted(decorated_http_set - policy_routes)
    stale_policy = sorted(policy_routes - decorated_http_set)
    if missing_policy or stale_policy:
        details: list[str] = []
        if missing_policy:
            details.append(
                "unclassified decorators="
                + ",".join(f"{method} {path}" for method, path in missing_policy)
            )
        if stale_policy:
            details.append(
                "undecorated policy rows="
                + ",".join(f"{method} {path}" for method, path in stale_policy)
            )
        raise ContractGenerationError(
            "route policy does not match decorated API routes: " + "; ".join(details)
        )

    routes = decorated_http_set | set(websocket_routes)

    if not routes:
        raise ContractGenerationError("backend route extraction produced no routes")
    return sorted(routes, key=lambda route: (route[1], route[0]))


def build_contract(root: Path) -> dict[str, Any]:
    backend_path = root / BACKEND_SOURCE
    if not backend_path.is_file():
        raise ContractGenerationError(f"backend source does not exist: {backend_path}")
    backend_raw = backend_path.read_bytes()
    backend_text = backend_raw.decode("utf-8")
    routes = extract_backend_routes(backend_text)
    route_set = set(routes)

    endpoints: dict[str, dict[str, str]] = {}
    for name, route in sorted(ENDPOINT_ALIASES.items()):
        if route not in route_set:
            method, path = route
            raise ContractGenerationError(
                f"required endpoint {name!r} is missing from backend truth: {method} {path}"
            )
        endpoints[name] = {"method": route[0], "path": route[1]}

    return {
        "backend_source": BACKEND_SOURCE.as_posix(),
        "backend_source_sha256": hashlib.sha256(backend_raw).hexdigest(),
        "endpoints": endpoints,
        "routes": [{"method": method, "path": path} for method, path in routes],
        "schema_version": "forge-dashboard-api-v1",
    }


def render_contract(contract: dict[str, Any]) -> str:
    return json.dumps(contract, indent=2, sort_keys=True) + "\n"


def render_typescript(contract: dict[str, Any], contract_text: str) -> str:
    lines = [
        "// Generated by scripts/generate_frontend_contracts.py. Do not edit.",
        f"// backend-source-sha256: {contract['backend_source_sha256']}",
        f"// contract-sha256: {hashlib.sha256(contract_text.encode('utf-8')).hexdigest()}",
        f"export const DASHBOARD_API_SCHEMA = {json.dumps(contract['schema_version'])} as const;",
        f"export const DASHBOARD_API_BACKEND_SOURCE = {json.dumps(contract['backend_source'])} as const;",
        f"export const DASHBOARD_API_BACKEND_SHA256 = {json.dumps(contract['backend_source_sha256'])} as const;",
        "export const DASHBOARD_API = {",
    ]
    for name, endpoint in contract["endpoints"].items():
        lines.append(
            f"  {name}: {{ method: {json.dumps(endpoint['method'])}, path: {json.dumps(endpoint['path'])} }},"
        )
    lines.extend(["} as const;", "export const DASHBOARD_API_ROUTES = ["])
    for route in contract["routes"]:
        lines.append(
            f"  {{ method: {json.dumps(route['method'])}, path: {json.dumps(route['path'])} }},"
        )
    lines.extend(
        [
            "] as const;",
            "export type DashboardEndpoint = keyof typeof DASHBOARD_API;",
            "export type DashboardRoute = (typeof DASHBOARD_API_ROUTES)[number];",
            "",
        ]
    )
    return "\n".join(lines)


def _check_output(path: Path, expected: str, root: Path) -> bool:
    actual = path.read_text(encoding="utf-8") if path.is_file() else ""
    if actual == expected:
        return True
    try:
        display_path = path.relative_to(root)
    except ValueError:
        display_path = path
    print(f"stale generated contract: {display_path}")
    return False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument(
        "--root",
        type=Path,
        default=DEFAULT_ROOT,
        help="repository root (used by deterministic negative-fixture tests)",
    )
    args = parser.parse_args()
    root = args.root.resolve()

    try:
        contract = build_contract(root)
    except (ContractGenerationError, UnicodeDecodeError) as exc:
        print(f"contract generation failed: {exc}")
        return 2

    contract_text = render_contract(contract)
    typescript_text = render_typescript(contract, contract_text)
    contract_path = root / CONTRACT_OUTPUT
    typescript_path = root / TYPESCRIPT_OUTPUT

    if args.check:
        current = _check_output(contract_path, contract_text, root)
        current &= _check_output(typescript_path, typescript_text, root)
        if not current:
            return 1
        print(
            "PASS contracts="
            f"{CONTRACT_OUTPUT.as_posix()},{TYPESCRIPT_OUTPUT.as_posix()} "
            f"routes={len(contract['routes'])}"
        )
        return 0

    contract_path.parent.mkdir(parents=True, exist_ok=True)
    typescript_path.parent.mkdir(parents=True, exist_ok=True)
    contract_path.write_text(contract_text, encoding="utf-8")
    typescript_path.write_text(typescript_text, encoding="utf-8")
    print(
        "generated contracts="
        f"{CONTRACT_OUTPUT.as_posix()},{TYPESCRIPT_OUTPUT.as_posix()} "
        f"routes={len(contract['routes'])}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
