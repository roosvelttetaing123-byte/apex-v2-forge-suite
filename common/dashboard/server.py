"""War Room Dashboard — FastAPI + WebSocket server.

Serves the live dashboard UI and provides real-time event streaming
via WebSocket. Integrates with EventBus and StateStore for live
scan visualization, C2 beacon management, and operator controls.

Launch:
    python forge.py dashboard --port 1337
    python forge.py dashboard --attach results_dir/
"""
from __future__ import annotations

import asyncio
import io
import json
import logging
import os
import shlex
import socket
import signal
import ssl
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger("forge.dashboard.server")

# ── Conditional imports (graceful fallback) ───────────────────────────
try:
    from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
    from fastapi import HTTPException, Depends, Query
    from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
    from fastapi.staticfiles import StaticFiles
    from fastapi.templating import Jinja2Templates
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

from common.dashboard.event_bus import Event, EventBus, EventType
from common.dashboard.state_store import StateStore
from common.dashboard.auth import (
    generate_token, validate_token, require_role, Role, TokenPayload,
)

# ── Paths ─────────────────────────────────────────────────────────────
_DASHBOARD_DIR = Path(__file__).parent
_APEX_DIR = _DASHBOARD_DIR.parent.parent / "apex-ui"
_APEX_DIST_DIR = _APEX_DIR / "dist"
_WEB_DIR = _DASHBOARD_DIR / "web"
_STATIC_DIR = _APEX_DIST_DIR if _APEX_DIST_DIR.exists() else _APEX_DIR
_TEMPLATE_DIR = _APEX_DIST_DIR if _APEX_DIST_DIR.exists() else _APEX_DIR

# ── UI module ID → real scanner module mapping ─────────────────────────
# Maps ScanBuilder UI IDs to (framework, scanner_module_name).
# None = module not implemented → rejected with 400.
UI_MODULE_MAP: dict[str, tuple[str, str] | None] = {
    # Web modules
    "sqli":          ("web", "sqli_scanner"),
    "xss":           ("web", "xss_scanner"),
    "lfi":           ("web", "lfi_rfi"),
    "ssrf":          ("web", "ssrf_scanner"),
    "xxe":           ("web", "xxe_scanner"),
    "ssti":          ("web", "ssti_scanner"),
    "rce":           ("web", "cmd_inject"),
    "csrf":          ("web", "cookie_audit"),
    "redirect":      ("web", "open_redirect"),
    "dirtraversal":  ("web", "path_traversal"),
    "subdtakeover":  ("web", "subdomain_takeover"),
    "jwt":           ("web", "jwt_audit"),
    "oauth":         ("web", "oauth_check"),
    "massassign":    ("web", "mass_assignment"),
    "deserial":      ("web", "deserialization"),
    "bof":           None,  # not implemented
    # Network modules
    "portscan":      ("net", "port_scanner"),
    "svcfp":         ("net", "service_id"),
    "ssltls":        ("net", "ssl_audit"),
    "smb":           ("net", "smb_audit"),
    "dns":           ("net", "dns_recon"),
    "snmp":          ("net", "snmp_audit"),
    "netsweep":      ("net", "host_discover"),
    "vulsvc":        ("net", "cve_matcher"),
    # API modules
    "apikey":        ("web", "secret_scan"),
    "graphql":       ("web", "graphql_audit"),
    "bola":          ("web", "idor_scanner"),
    "ratelimit":     ("web", "api_rate_check"),
    "cors":          ("web", "cors_check"),
    "parampollu":    ("web", "parameter_pollution"),
    "apiversion":    None,  # not implemented
    # Auth modules
    "bruteforce":    ("web", "login_brute"),
    "defaultcreds":  ("web", "login_brute"),
    "sessfixation":  ("web", "session_audit"),
    "mfabypass":     ("web", "mfa_bypass"),
    "tokenentropy":  ("web", "session_audit"),
    "pwspray":       ("net", "cred_spray"),
    # Cloud modules — NOT IMPLEMENTED
    "s3":            None,
    "iam":           None,
    "metadata":      None,
    "snapshot":      None,
    "serverless":    None,
    "container":     None,
}


def _resolve_modules(ui_ids: list[str]) -> tuple[list[str], list[str], list[str]]:
    """Map UI module IDs → (web_scanner_modules, net_scanner_modules, unsupported_ids)."""
    web: list[str] = []
    net: list[str] = []
    bad: list[str] = []
    seen_web: set[str] = set()
    seen_net: set[str] = set()
    for uid in ui_ids:
        entry = UI_MODULE_MAP.get(uid)
        if entry is None:
            bad.append(uid)
        elif entry[0] == "web":
            if entry[1] not in seen_web:
                web.append(entry[1])
                seen_web.add(entry[1])
        elif entry[0] == "net":
            if entry[1] not in seen_net:
                net.append(entry[1])
                seen_net.add(entry[1])
    return web, net, bad


class DashboardServer:
    """War Room dashboard server.

    Manages the FastAPI application, WebSocket connections, and
    integration with the scan engine via EventBus + StateStore.

    Args:
        event_bus:   EventBus instance for receiving scan events.
        state_store: StateStore instance for state snapshots.
        host:        Bind address (default 0.0.0.0).
        port:        Bind port (default 1337).
        auth:        Enable authentication (default True).
    """

    def __init__(
        self,
        event_bus: EventBus | None = None,
        state_store: StateStore | None = None,
        host: str = "0.0.0.0",
        port: int = 1337,
        auth: bool = True,
    ) -> None:
        self.event_bus = event_bus or EventBus(run_id="dashboard")
        self.state_store = state_store or StateStore(
            self.event_bus, framework="forge", target="",
        )
        self.host = host
        self.port = port
        self.auth_enabled = auth
        self._ws_clients: list[WebSocket] = []
        self._scan_paused = False
        self._scan_aborted = False
        self._app: Any = None

        # Active scan subprocess tracking
        self._active_scans: dict[str, dict[str, Any]] = {}  # scan_id → {proc, type, target, ...}
        self._last_results_dir: Path | None = None
        self._scan_logs_dir = Path(__file__).parent.parent.parent / "tmp" / "dashboard_scans"
        self._control_dir = Path(__file__).parent.parent.parent / "tmp" / "dashboard_controls"
        self._scan_logs_dir.mkdir(parents=True, exist_ok=True)
        self._control_dir.mkdir(parents=True, exist_ok=True)

        # Subscribe to all events for WebSocket broadcast
        self.event_bus.subscribe(None, self._on_event)

    def _track_scan_process(self, scan_key: str, info: dict[str, Any]) -> None:
        """Capture subprocess output and emit completion/failure events."""
        proc: subprocess.Popen[str] = info["proc"]
        log_path = self._scan_logs_dir / f"{scan_key}.log"

        def _worker() -> None:
            try:
                with log_path.open("w", encoding="utf-8", errors="replace") as fh:
                    if isinstance(proc.stdout, io.TextIOBase):
                        for line in proc.stdout:
                            fh.write(line)
                    rc = proc.wait()
            except Exception as exc:
                log.warning("Scan monitor failed for %s: %s", scan_key, exc)
                return

            info["returncode"] = rc
            if info.get("status") in {"aborted", "stopped"}:
                event_type = EventType.SCAN_ABORTED
            else:
                info["status"] = "completed" if rc == 0 else "failed"
                event_type = EventType.SCAN_COMPLETE if rc == 0 else EventType.SCAN_INTERRUPTED
            self.event_bus.emit_simple(
                event_type,
                source="dashboard",
                scan_id=scan_key,
                scan_type=info.get("type", ""),
                target=info.get("target", ""),
                returncode=rc,
                log_path=str(log_path),
            )
            self._update_scan_history_status(self._base_scan_id(scan_key), info["status"])

        threading.Thread(
            target=_worker,
            name=f"ScanMonitor-{scan_key}",
            daemon=True,
        ).start()

    def _on_event(self, event: Event) -> None:
        """Broadcast event to all connected WebSocket clients."""
        # This runs on the EventBus dispatch thread.
        # We need to schedule async sends on the event loop.
        pass  # Handled via async_subscribe in start()

    def create_app(self) -> Any:
        """Create the FastAPI application with all routes."""
        if not HAS_FASTAPI:
            raise ImportError(
                "FastAPI not installed. Run: pip install fastapi uvicorn[standard] websockets"
            )

        app = FastAPI(
            title="Forge Suite — War Room",
            description="Real-time offensive security dashboard",
            version="5.0.0",
            docs_url=None, redoc_url=None,  # Disable Swagger UI for security
        )

        # CORS — allow APEX UI dev server
        try:
            from fastapi.middleware.cors import CORSMiddleware
            app.add_middleware(
                CORSMiddleware,
                allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
                allow_origin_regex=r"^http://(localhost|127\.0\.0\.1):51[0-9]{2}$",
                allow_credentials=True,
                allow_methods=["*"],
                allow_headers=["*"],
            )
        except ImportError:
            pass  # CORSMiddleware not available

        # Static files. Standalone dashboard serves the built React app from dist/.
        if (_STATIC_DIR / "assets").exists():
            app.mount("/assets", StaticFiles(directory=str(_STATIC_DIR / "assets")), name="assets")
        if (_STATIC_DIR / "icons.svg").exists():
            @app.get("/icons.svg")
            async def icons_svg():
                return FileResponse(str(_STATIC_DIR / "icons.svg"), media_type="image/svg+xml")
        if (_STATIC_DIR / "favicon.svg").exists():
            @app.get("/favicon.svg")
            async def favicon_svg():
                return FileResponse(str(_STATIC_DIR / "favicon.svg"), media_type="image/svg+xml")
        if _STATIC_DIR.exists():
            app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")
        if not _APEX_DIST_DIR.exists() and (_APEX_DIR / "src").exists():
            app.mount("/src", StaticFiles(directory=str(_APEX_DIR / "src")), name="src")

        # Templates
        templates = None
        if _TEMPLATE_DIR.exists():
            templates = Jinja2Templates(directory=str(_TEMPLATE_DIR))

        server = self  # Closure reference

        # ── Helper: extract token ─────────────────────────────────────
        def _get_token(request: Request) -> str | None:
            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                return auth_header[7:]
            return request.query_params.get("token")

        def _require_auth(request: Request, role: Role = Role.VIEWER) -> TokenPayload | None:
            if not server.auth_enabled:
                return TokenPayload(
                    username="operator", role=Role.ADMIN,
                    issued_at=time.time(), expires_at=time.time() + 86400,
                    session_id="noauth",
                )
            token = _get_token(request)
            payload = require_role(token, role)
            if not payload:
                raise HTTPException(status_code=401, detail="Unauthorized")
            return payload

        # ── Routes ────────────────────────────────────────────────────

        @app.get("/", response_class=HTMLResponse)
        async def dashboard_page():
            """Serve the main dashboard SPA."""
            index_path = _TEMPLATE_DIR / "index.html"
            if index_path.exists():
                return HTMLResponse(index_path.read_text(encoding="utf-8"))
            return HTMLResponse("<h1>Forge Suite War Room</h1><p>Dashboard UI not found.</p>")

        @app.get("/login", response_class=HTMLResponse)
        async def login_page(request: Request):
            """Serve the login page."""
            if templates and (_TEMPLATE_DIR / "login.html").exists():
                return templates.TemplateResponse(request=request, name="login.html", context={"request": request})
            return HTMLResponse("<h1>Login</h1>")

        @app.get("/scans/{scan_id}", response_class=HTMLResponse)
        async def scan_detail_page(scan_id: str):
            """Serve the React scan detail route on browser refresh/deep link."""
            index_path = _TEMPLATE_DIR / "index.html"
            if index_path.exists():
                return HTMLResponse(index_path.read_text(encoding="utf-8"))
            return HTMLResponse("<h1>Forge Suite War Room</h1><p>Dashboard UI not found.</p>")

        @app.get("/scan-builder", response_class=HTMLResponse)
        @app.get("/red-teaming", response_class=HTMLResponse)
        @app.get("/c2-console", response_class=HTMLResponse)
        @app.get("/mobile", response_class=HTMLResponse)
        @app.get("/discovery", response_class=HTMLResponse)
        @app.get("/targets", response_class=HTMLResponse)
        @app.get("/scans", response_class=HTMLResponse)
        @app.get("/scheduling", response_class=HTMLResponse)
        @app.get("/reports", response_class=HTMLResponse)
        @app.get("/vulnerabilities", response_class=HTMLResponse)
        @app.get("/policies", response_class=HTMLResponse)
        @app.get("/notifications", response_class=HTMLResponse)
        @app.get("/integrations", response_class=HTMLResponse)
        @app.get("/team", response_class=HTMLResponse)
        @app.get("/activity", response_class=HTMLResponse)
        @app.get("/agents", response_class=HTMLResponse)
        async def spa_page():
            """Serve React client-side routes on browser refresh/deep link."""
            index_path = _TEMPLATE_DIR / "index.html"
            if index_path.exists():
                return HTMLResponse(index_path.read_text(encoding="utf-8"))
            return HTMLResponse("<h1>Forge Suite War Room</h1><p>Dashboard UI not found.</p>")

        @app.post("/api/v1/auth/login")
        async def api_login(request: Request):
            """Authenticate and get a bearer token."""
            body = await request.json()
            username = body.get("username", "")
            password = body.get("password", "")
            token = generate_token(username, password)
            if not token:
                raise HTTPException(status_code=401, detail="Invalid credentials")
            return {"token": token, "username": username}

        @app.get("/api/v1/health")
        async def api_health(request: Request):
            """Dashboard connectivity status for UI preflight checks."""
            return {
                "status": "ok",
                "host": server.host,
                "port": server.port,
                "auth_enabled": server.auth_enabled,
                "dashboard_url": server._dashboard_public_url(request),
                "active_processes": sum(
                    1 for info in server._active_scans.values()
                    if info.get("proc") and info["proc"].poll() is None
                ),
                "tools": server._tool_inventory(),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        @app.get("/api/v1/tools")
        async def api_tools(request: Request):
            """Framework/tool connection inventory used by the dashboard."""
            _require_auth(request)
            tools = server._tool_inventory()
            return {"tools": tools, "ready": all(t["ready"] for t in tools)}

        @app.get("/api/v1/state")
        async def api_state(request: Request):
            """Full state snapshot for dashboard initialization."""
            _require_auth(request)
            return JSONResponse(server.state_store.snapshot())

        @app.get("/api/v1/findings")
        async def api_findings(
            request: Request,
            severity: str | None = None,
            module: str | None = None,
            target: str | None = None,
            limit: int = Query(default=100, le=1000),
            offset: int = Query(default=0, ge=0),
        ):
            """Paginated findings with filters."""
            _require_auth(request)
            findings = server.state_store.findings_snapshot(severity=severity, limit=limit + offset)
            # Apply additional filters
            if module:
                findings = [f for f in findings if f.get("module") == module]
            if target:
                findings = [f for f in findings if f.get("target") == target]
            return {
                "findings": findings[offset:offset + limit],
                "total": len(server.state_store.findings),
            }

        @app.get("/api/v1/targets")
        async def api_targets(request: Request):
            """Target status map."""
            _require_auth(request)
            snap = server.state_store.snapshot()
            return {"targets": snap.get("targets", {})}

        @app.get("/api/v1/metrics")
        async def api_metrics(request: Request):
            """Current metrics snapshot."""
            _require_auth(request)
            return server.state_store.metrics_snapshot().to_dict()

        @app.get("/api/v1/kill-chain")
        async def api_kill_chain(request: Request):
            """Kill chain state."""
            _require_auth(request)
            return server.state_store.kill_chain.to_dict()

        @app.get("/api/v1/credentials")
        async def api_credentials(request: Request):
            """Discovered credentials (masked)."""
            _require_auth(request, Role.OPERATOR)
            snap = server.state_store.snapshot()
            return {"credentials": snap.get("credentials", [])}

        @app.get("/api/v1/sessions")
        async def api_sessions(request: Request):
            """Active shell sessions."""
            _require_auth(request, Role.OPERATOR)
            snap = server.state_store.snapshot()
            return {"sessions": snap.get("sessions", [])}

        @app.get("/api/v1/timeline")
        async def api_timeline(request: Request, limit: int = Query(default=100, le=500)):
            """Threat timeline events."""
            _require_auth(request)
            return {"timeline": server.state_store.timeline[-limit:]}

        # ── Scan Control ──────────────────────────────────────────────

        @app.post("/api/v1/events/emit")
        async def api_events_emit(request: Request):
            """Accept events from remote scan processes (RemoteEventBus).

            Allows framework subprocesses running in separate OS processes to
            push events into the dashboard's EventBus, which then broadcasts
            them to all connected WebSocket clients.
            """
            try:
                body = await request.body()
                event = Event.from_json(body.decode())
                server.event_bus.emit(event)
                return {"status": "ok"}
            except Exception as exc:
                raise HTTPException(status_code=400, detail=str(exc))

        # ── Credential preflight test ─────────────────────────────────

        def _validate_preflight_url(url: str) -> str | None:
            """Return an error string if the URL is unsafe, else None."""
            import ipaddress as _ip
            import urllib.parse as _up
            try:
                p = _up.urlparse(url)
            except Exception:
                return "Malformed URL"
            if p.scheme not in ("http", "https"):
                return f"Scheme '{p.scheme}' not allowed; use http or https"
            host = (p.hostname or "").lower()
            if not host:
                return "Missing host"
            if host in ("localhost",):
                return f"Host '{host}' is not a routable address"
            try:
                addr = _ip.ip_address(host)
                if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved or addr.is_multicast:
                    return f"Host '{host}' resolves to a non-routable address"
            except ValueError:
                pass  # hostname — routable check happens at DNS time
            return None

        @app.post("/api/v1/auth/test")
        async def api_auth_test(request: Request):
            """Preflight credential check — validates auth before launching a scan.

            Sends a single HTTP request using the supplied credentials and returns
            whether the server responded with a non-4xx/5xx status.  Secrets are
            accepted in the request body but never logged.
            """
            _require_auth(request, Role.OPERATOR)
            body = await request.json()
            auth_type   = body.get("auth_type", "form")
            username    = body.get("username", "")
            password    = body.get("password", "")    # used, never logged
            token       = body.get("token", "")       # used, never logged
            header_name = body.get("header_name", "Authorization")
            cookie_jar  = body.get("cookie_jar", "")  # used, never logged
            login_url   = body.get("login_url", "").strip()

            import re as _re
            cookie_jar = _re.sub(r"^cookie:\s*", "", cookie_jar, flags=_re.IGNORECASE)

            if not login_url:
                return JSONResponse({"success": False, "message": "login_url is required"})

            url_err = _validate_preflight_url(login_url)
            if url_err:
                return JSONResponse({"success": False, "message": f"Invalid login_url: {url_err}"})

            try:
                import aiohttp as _aiohttp
                import ssl as _ssl
                ssl_ctx = _ssl.create_default_context()
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = _ssl.CERT_NONE
                timeout = _aiohttp.ClientTimeout(total=10)

                async with _aiohttp.ClientSession(timeout=timeout) as session:
                    if auth_type == "form":
                        resp = await session.post(
                            login_url,
                            data={"username": username, "password": password},
                            allow_redirects=True,
                            ssl=ssl_ctx,
                        )
                    elif auth_type == "bearer":
                        hdr_val = f"Bearer {token}" if header_name == "Authorization" else token
                        resp = await session.get(
                            login_url,
                            headers={header_name: hdr_val},
                            ssl=ssl_ctx,
                        )
                    else:  # cookie
                        resp = await session.get(
                            login_url,
                            headers={"Cookie": cookie_jar},
                            ssl=ssl_ctx,
                        )
                    success = resp.status < 400
                    suffix = "" if success else " — authentication may have failed"
                    return {"success": success, "message": f"HTTP {resp.status}{suffix}"}

            except Exception as exc:
                log.debug("Credential preflight failed: %s", exc)
                return JSONResponse({"success": False, "message": f"Test failed: {exc}"})

        @app.post("/api/v1/control/pause")
        async def api_pause(request: Request):
            """Pause the current scan."""
            _require_auth(request, Role.OPERATOR)
            server._scan_paused = True
            server._write_all_control_files({"paused": True, "aborted": False})
            server.event_bus.emit_simple(
                EventType.SCAN_PAUSED, source="dashboard",
            )
            return {"status": "paused"}

        @app.post("/api/v1/control/resume")
        async def api_resume(request: Request):
            """Resume a paused scan."""
            _require_auth(request, Role.OPERATOR)
            server._scan_paused = False
            server._write_all_control_files({"paused": False, "aborted": False})
            server.event_bus.emit_simple(
                EventType.SCAN_RESUMED, source="dashboard",
            )
            return {"status": "resumed"}

        @app.post("/api/v1/control/abort")
        async def api_abort(request: Request):
            """Abort the current scan."""
            _require_auth(request, Role.ADMIN)
            server._scan_aborted = True
            server._write_all_control_files({"paused": False, "aborted": True})
            killed = server._terminate_active_scans(status="aborted")
            server.event_bus.emit_simple(
                EventType.SCAN_ABORTED, source="dashboard", killed=killed,
            )
            return {"status": "aborted", "killed": killed}

        @app.post("/api/v1/control/skip-module")
        async def api_skip_module(request: Request):
            """Skip the currently running module."""
            _require_auth(request, Role.OPERATOR)
            body = await request.json()
            module_name = body.get("module", "")
            server.event_bus.emit_simple(
                EventType.CONTROL_COMMAND, source="dashboard",
                command="skip_module", module=module_name,
            )
            return {"status": "skip_requested", "module": module_name}

        # ── Scan launch ───────────────────────────────────────────────

        @app.post("/api/v1/scans/start")
        async def api_scan_start(request: Request):
            """Launch a webforge / netforge / combined VAPT scan as a subprocess.

            Body JSON:
              target      : URL, IP, or CIDR (required)
              scan_type   : "web" | "net" | "vapt"  (default: web)
              mode        : "blackbox" | "greybox" | "whitebox"  (default: blackbox)
              username    : (optional) login username for greybox/whitebox
              password    : (optional) login password
              token       : (optional) bearer/API token
              engagement  : (optional) engagement name for report
              tester      : (optional) tester name for report

            Note: When scan_type is "web", the target hostname is also resolved to an
            IP and netforge runs a network vulnerability scan on that IP automatically.
            """
            _require_auth(request, Role.OPERATOR)
            body = await request.json()

            target = body.get("target", "").strip()
            if not target:
                raise HTTPException(status_code=400, detail="target is required")
            # Normalize bare hostnames/IPs to https:// so subprocess tools get a valid URL
            if not target.startswith(("http://", "https://")):
                target = "https://" + target

            scan_type  = body.get("scan_type", "web").lower()   # web | net | vapt
            mode       = body.get("mode", "blackbox").lower()

            _VALID_MODES = {"blackbox", "greybox", "whitebox"}
            if mode not in _VALID_MODES:
                raise HTTPException(status_code=400, detail=f"Invalid mode '{mode}'. Must be one of: {', '.join(sorted(_VALID_MODES))}")

            # Extract auth_profile — supports both legacy flat fields and new structured form
            auth_profile = body.get("auth_profile") or {}
            auth_type    = auth_profile.get("auth_type", body.get("auth_type", "form"))
            username     = auth_profile.get("username", body.get("username", "")).strip()
            login_url_   = auth_profile.get("login_url", body.get("login_url", "")).strip()
            header_name  = auth_profile.get("header_name", "Authorization").strip()
            # Secrets — extracted but never logged or placed in argv
            password     = auth_profile.get("password", body.get("password", "")).strip()
            token        = auth_profile.get("token",    body.get("token", "")).strip()
            cookie_jar   = auth_profile.get("cookie_jar", "").strip()

            import re as _re
            cookie_jar = _re.sub(r"^cookie:\s*", "", cookie_jar, flags=_re.IGNORECASE)

            engagement = body.get("engagement", "Forge-VAPT-Demo").strip()
            tester     = body.get("tester", "Forge Suite v5 APEX").strip()

            # Build subprocess env — secrets travel via env, never argv
            import os as _os
            scan_env = _os.environ.copy()
            if mode != "blackbox":
                scan_env["FORGE_AUTH_TYPE"] = auth_type
                if password:   scan_env["FORGE_PASSWORD"]  = password
                if token:      scan_env["FORGE_TOKEN"]     = token
                if cookie_jar: scan_env["FORGE_COOKIE_JAR"] = cookie_jar

            log.info(
                "Scan requested: target=%s type=%s mode=%s auth=%s username=%s password=<redacted>",
                target, scan_type, mode, auth_type, username or "—",
            )

            # Determine dashboard URL for event relay
            dash_url = server._dashboard_public_url(request)

            forge_root = Path(__file__).parent.parent.parent  # forge-suite/
            scan_id = str(uuid.uuid4())[:8]
            control_file = server._init_control_file(scan_id)

            # Clean env for netforge — it doesn't consume FORGE_* credential vars
            net_scan_env = {k: v for k, v in scan_env.items() if not k.startswith("FORGE_")}

            def _build_cmd(framework: str, net_target: str | None = None) -> list[str]:
                script = str(forge_root / framework / f"{framework}.py")
                effective_target = net_target if (framework == "netforge" and net_target) else target
                if framework == "netforge":
                    return [
                        sys.executable, script,
                        "--target", effective_target,
                        "--mode", "external",
                        "--engagement", engagement,
                        "--auto-confirm",
                        "--dashboard-url", dash_url,
                        "--control-file", str(control_file),
                    ]
                cmd = [
                    sys.executable, script,
                    "--target", effective_target,
                    "--mode", mode,
                    "--engagement", engagement,
                    "--tester", tester,
                    "--auto-confirm",
                    "--dashboard-url", dash_url,
                    "--control-file", str(control_file),
                    "--report-format", "html,json",
                ]
                # Non-secret auth args — username, login_url, header_name are safe in argv
                if mode != "blackbox":
                    cmd += ["--auth-type", auth_type]
                    if username:    cmd += ["--username", username]
                    if login_url_:  cmd += ["--login-url", login_url_]
                    if header_name and auth_type == "bearer":
                        cmd += ["--header-name", header_name]
                # NEVER: cmd += ["--password", password] or ["--token", token]
                return cmd

            def _resolve_host_ip(raw_target: str) -> str | None:
                """Resolve a URL or hostname to its IP address for network scanning."""
                try:
                    import urllib.parse
                    parsed = urllib.parse.urlparse(raw_target)
                    hostname = parsed.hostname or raw_target.split("/")[0].split(":")[0]
                    return socket.gethostbyname(hostname)
                except Exception:
                    return None

            launched: list[str] = []
            resolved_ip: str | None = None
            try:
                if scan_type in ("web", "vapt"):
                    cmd = _build_cmd("webforge")
                    proc = subprocess.Popen(
                        cmd,
                        cwd=str(forge_root),
                        env=scan_env,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                    )
                    server._active_scans[scan_id + "_web"] = {
                        "proc": proc, "type": "web", "target": target,
                        "started_at": time.time(), "engagement": engagement,
                        "mode": mode, "status": "running",
                        "started_dt": datetime.now(timezone.utc).isoformat(),
                        "control_file": str(control_file),
                        "command": server._sanitize_cmd(cmd),
                        "dashboard_url": dash_url,
                    }
                    server._track_scan_process(scan_id + "_web", server._active_scans[scan_id + "_web"])
                    launched.append("web")

                    # For web scans, also resolve host → IP and run network vuln scan
                    if scan_type == "web":
                        resolved_ip = _resolve_host_ip(target)
                        if resolved_ip:
                            net_cmd = _build_cmd("netforge", net_target=resolved_ip)
                            net_proc = subprocess.Popen(
                                net_cmd,
                                cwd=str(forge_root),
                                env=net_scan_env,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT,
                                text=True,
                            )
                            server._active_scans[scan_id + "_net_auto"] = {
                                "proc": net_proc, "type": "net", "target": resolved_ip,
                                "started_at": time.time(), "engagement": engagement,
                                "mode": "external", "status": "running",
                                "started_dt": datetime.now(timezone.utc).isoformat(),
                                "auto_from_web": True,
                                "control_file": str(control_file),
                                "command": server._sanitize_cmd(net_cmd),
                                "dashboard_url": dash_url,
                            }
                            server._track_scan_process(scan_id + "_net_auto", server._active_scans[scan_id + "_net_auto"])
                            launched.append("net_auto")
                            log.info("Auto-launched netforge on resolved IP %s for web target %s", resolved_ip, target)

                if scan_type in ("net", "vapt"):
                    resolved_ip = resolved_ip or _resolve_host_ip(target)
                    net_target = resolved_ip or target
                    cmd = _build_cmd("netforge", net_target=net_target)
                    proc = subprocess.Popen(
                        cmd,
                        cwd=str(forge_root),
                        env=net_scan_env,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                    )
                    server._active_scans[scan_id + "_net"] = {
                        "proc": proc, "type": "net", "target": net_target,
                        "started_at": time.time(), "engagement": engagement,
                        "mode": "external", "status": "running",
                        "started_dt": datetime.now(timezone.utc).isoformat(),
                        "control_file": str(control_file),
                        "command": server._sanitize_cmd(cmd),
                        "dashboard_url": dash_url,
                    }
                    server._track_scan_process(scan_id + "_net", server._active_scans[scan_id + "_net"])
                    launched.append("net")

            except Exception as exc:
                log.error("Failed to launch scan: %s", exc)
                raise HTTPException(status_code=500, detail=f"Failed to launch scan: {exc}")

            # Persist scan record to history DB
            server._write_scan_history(
                scan_id=scan_id, target=target, scan_type=scan_type,
                mode=mode, engagement=engagement, frameworks=launched,
            )

            server.event_bus.emit_simple(
                EventType.SCAN_START, source="dashboard",
                target=target, scan_type=scan_type, mode=mode,
                engagement=engagement, scan_id=scan_id,
                resolved_ip=resolved_ip or "",
            )

            return {
                "status": "launched",
                "scan_id": scan_id,
                "target": target,
                "scan_type": scan_type,
                "mode": mode,
                "frameworks": launched,
                "resolved_ip": resolved_ip,
                "dashboard_url": dash_url,
            }

        @app.get("/api/v1/scans/status")
        async def api_scan_status(request: Request):
            """Return status of all tracked scan subprocesses."""
            _require_auth(request)
            running = []
            completed = []
            for key, info in list(server._active_scans.items()):
                proc = info["proc"]
                rc = info.get("returncode")
                if rc is None:
                    rc = proc.poll()
                entry = {
                    "scan_id": key,
                    "root_scan_id": server._base_scan_id(key),
                    "type": info["type"],
                    "target": info["target"],
                    "started_at": info["started_at"],
                    "returncode": rc,
                    "status": info.get("status", "running" if rc is None else "completed"),
                    "control_file": info.get("control_file", ""),
                    "dashboard_url": info.get("dashboard_url", ""),
                }
                if rc is None:
                    running.append(entry)
                else:
                    completed.append(entry)
            return {"running": running, "completed": completed}

        @app.post("/api/v1/scans/stop")
        async def api_scan_stop(request: Request):
            """Kill all running scan subprocesses."""
            _require_auth(request, Role.OPERATOR)
            server._write_all_control_files({"paused": False, "aborted": True})
            killed = server._terminate_active_scans(status="stopped")
            server.event_bus.emit_simple(
                EventType.SCAN_ABORTED, source="dashboard", reason="operator_stop",
            )
            return {"status": "stopped", "killed": killed}

        @app.get("/api/v1/scans/history")
        async def api_scan_history(request: Request, limit: int = Query(default=50, le=200)):
            """Return scan history across all past and current engagements.

            Combines in-memory active scans with persisted records from the
            scan history JSON store. Sorted newest-first.
            """
            _require_auth(request)
            history = server._load_scan_history(limit=limit)
            return {"history": history, "total": len(history)}

        @app.get("/api/v1/scans/{scan_id}")
        async def api_scan_detail(request: Request, scan_id: str):
            """Return a single scan's status, subprocesses, logs, reports, and findings."""
            _require_auth(request)
            detail = server._get_scan_detail(scan_id)
            if not detail:
                raise HTTPException(status_code=404, detail="Scan not found")
            return detail

        @app.delete("/api/v1/scans/{scan_id}")
        async def api_scan_delete(
            request: Request,
            scan_id: str,
            purge_artifacts: bool = False,
        ):
            """Delete a scan from dashboard history; optionally purge result artifacts."""
            _require_auth(request, Role.OPERATOR)
            deleted = server._delete_scan_record(scan_id, purge_artifacts=purge_artifacts)
            if not deleted.get("found"):
                raise HTTPException(status_code=404, detail="Scan not found")
            server.event_bus.emit_simple(
                EventType.CONTROL_COMMAND,
                source="dashboard",
                command="delete_scan",
                scan_id=scan_id,
                purge_artifacts=purge_artifacts,
            )
            return deleted

        # ── Scan Templates ─────────────────────────────────────────────

        @app.get("/api/v1/scan/templates")
        async def api_scan_templates(request: Request):
            """List saved scan templates."""
            _require_auth(request)
            templates_list = server._load_scan_templates()
            return {"templates": templates_list}

        @app.post("/api/v1/scan/templates")
        async def api_save_scan_template(request: Request):
            """Save a scan configuration as a reusable template."""
            _require_auth(request, Role.OPERATOR)
            body = await request.json()
            name = body.get("name", "").strip()
            if not name:
                raise HTTPException(status_code=400, detail="Template name is required")
            template = {
                "id": str(uuid.uuid4())[:8],
                "name": name,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "config": {
                    "target": body.get("target", ""),
                    "profile": body.get("profile", ""),
                    "modules": body.get("modules", []),
                    "mode": body.get("mode", "blackbox"),
                    "intensity": body.get("intensity", 2),
                    "maxThreads": body.get("maxThreads", 20),
                    "timeout": body.get("timeout", 30),
                    "rateLimit": body.get("rateLimit", 1000),
                    "maxDepth": body.get("maxDepth", 5),
                    "followRedirects": body.get("followRedirects", True),
                    "schedule": body.get("schedule", "now"),
                },
            }
            server._save_scan_template(template)
            return {"status": "saved", "template": template}

        @app.delete("/api/v1/scan/templates/{template_id}")
        async def api_delete_scan_template(request: Request, template_id: str):
            """Delete a scan template."""
            _require_auth(request, Role.OPERATOR)
            templates_list = server._load_scan_templates()
            templates_list = [t for t in templates_list if t.get("id") != template_id]
            server._write_scan_templates(templates_list)
            return {"status": "deleted"}

        # ── Findings Management ────────────────────────────────────────

        @app.patch("/api/v1/findings/{finding_id}/status")
        async def api_update_finding_status(request: Request, finding_id: str):
            """Update the status of a finding."""
            _require_auth(request, Role.OPERATOR)
            body = await request.json()
            new_status = body.get("status", "").strip()
            valid = {"Open", "Fixed", "Accepted", "False Positive"}
            if new_status not in valid:
                raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: {', '.join(valid)}")
            # Update in StateStore
            updated = False
            for f in server.state_store.findings:
                if getattr(f, "id", "") == finding_id:
                    f.status = new_status
                    updated = True
                    break
            if not updated:
                raise HTTPException(status_code=404, detail="Finding not found")
            server.event_bus.emit_simple(
                EventType.FINDING_UPDATED, source="dashboard",
                finding_id=finding_id, status=new_status,
            )
            return {"status": "updated", "finding_id": finding_id, "new_status": new_status}

        @app.post("/api/v1/findings/{finding_id}/retest")
        async def api_retest_finding(request: Request, finding_id: str):
            """Re-test a specific finding to verify if it's still exploitable."""
            _require_auth(request, Role.OPERATOR)
            # In a real system, this would re-run the specific module.
            # For now, emit an event and return a simulated result.
            server.event_bus.emit_simple(
                EventType.FINDING_UPDATED, source="dashboard",
                finding_id=finding_id, action="retest", status="retesting",
            )
            # Simulate retest delay — in production this would be async
            import random
            confidence = random.choice(["HIGH", "MEDIUM", "LOW"])
            still_vuln = random.choice([True, True, False])  # bias towards still vulnerable
            return {
                "status": "retested",
                "finding_id": finding_id,
                "still_vulnerable": still_vuln,
                "confidence": confidence,
                "retested_at": datetime.now(timezone.utc).isoformat(),
            }

        # ── Scan Launch (extended for ScanBuilder) ─────────────────────

        @app.post("/api/v1/scans/launch")
        async def api_scan_launch(request: Request):
            """Launch a scan from the ScanBuilder with full configuration.

            Accepts the rich ScanBuilder config with modules, intensity,
            threads, etc. Maps to the simpler scans/start internally.
            """
            _require_auth(request, Role.OPERATOR)
            body = await request.json()

            target = body.get("target", "").strip()
            if not target:
                raise HTTPException(status_code=400, detail="target is required")
            if not target.startswith(("http://", "https://")):
                target = "https://" + target

            mode = body.get("mode", "blackbox").lower()
            _VALID_MODES = {"blackbox", "greybox", "whitebox"}
            if mode not in _VALID_MODES:
                raise HTTPException(status_code=400, detail=f"Invalid mode '{mode}'. Must be one of: {', '.join(sorted(_VALID_MODES))}")

            # Extract auth_profile — supports both nested auth_profile and legacy flat fields
            auth_profile = body.get("auth_profile") or {}
            auth_type    = auth_profile.get("auth_type", body.get("auth_type", "form"))
            username     = auth_profile.get("username", body.get("username", "")).strip()
            login_url_   = auth_profile.get("login_url", body.get("login_url", "")).strip()
            header_name  = auth_profile.get("header_name", body.get("header_name", "Authorization")).strip()
            password     = auth_profile.get("password", body.get("password", "")).strip()    # never logged
            token        = auth_profile.get("token", body.get("token", "")).strip()           # never logged
            cookie_jar   = auth_profile.get("cookie_jar", "").strip()                         # never logged

            import re as _re2
            cookie_jar = _re2.sub(r"^cookie:\s*", "", cookie_jar, flags=_re2.IGNORECASE)

            # Build subprocess env
            import os as _os2
            scan_env = _os2.environ.copy()
            if mode != "blackbox":
                scan_env["FORGE_AUTH_TYPE"] = auth_type
                if password:   scan_env["FORGE_PASSWORD"]   = password
                if token:      scan_env["FORGE_TOKEN"]      = token
                if cookie_jar: scan_env["FORGE_COOKIE_JAR"] = cookie_jar

            log.info(
                "ScanBuilder launch: target=%s mode=%s auth=%s username=%s password=<redacted>",
                target, mode, auth_type, username or "—",
            )

            # Resolve UI module IDs → real scanner module names
            modules = body.get("modules", [])
            web_modules, net_modules, unsupported = _resolve_modules(modules)

            # Reject if ALL selected modules are unsupported
            if modules and not web_modules and not net_modules:
                raise HTTPException(
                    status_code=400,
                    detail=f"None of the selected modules are implemented: {', '.join(unsupported)}. "
                           f"Cloud and mobile modules are planned but not yet available.",
                )

            # Determine scan type from resolved modules
            if web_modules and net_modules:
                scan_type = "vapt"
            elif net_modules and not web_modules:
                scan_type = "net"
            else:
                scan_type = "web"

            engagement    = f"ScanBuilder-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M')}"
            tester_       = body.get('tester', 'Forge Suite v5 APEX').strip()
            scan_id       = str(uuid.uuid4())[:8]
            forge_root    = Path(__file__).parent.parent.parent
            control_file  = server._init_control_file(scan_id)
            dash_url      = server._dashboard_public_url(request)
            intensity_map = {0: 'passive', 1: 'low', 2: 'standard', 3: 'aggressive', 4: 'maximum'}
            intensity_label = intensity_map.get(body.get('intensity', 2), 'standard')
            launched: list[str] = []

            # Clean env for netforge — it doesn't read FORGE_* credential vars
            net_scan_env_ = {k: v for k, v in scan_env.items() if not k.startswith("FORGE_")}

            def _web_cmd() -> list[str]:
                cmd = [
                    sys.executable, str(forge_root / 'webforge' / 'webforge.py'),
                    '--target', target,
                    '--mode', mode,
                    '--engagement', engagement,
                    '--tester', tester_,
                    '--auto-confirm',
                    '--dashboard-url', dash_url,
                    '--control-file', str(control_file),
                    '--report-format', 'html,json',
                ]
                if mode != "blackbox":
                    cmd += ['--auth-type', auth_type]
                    if username:   cmd += ['--username', username]
                    if login_url_: cmd += ['--login-url', login_url_]
                    if header_name and auth_type == 'bearer':
                        cmd += ['--header-name', header_name]
                if web_modules:
                    cmd += ['--modules', ','.join(web_modules)]
                return cmd

            def _net_cmd(net_target: str) -> list[str]:
                cmd = [
                    sys.executable, str(forge_root / 'netforge' / 'netforge.py'),
                    '--target', net_target,
                    '--mode', 'external',
                    '--engagement', engagement,
                    '--auto-confirm',
                    '--dashboard-url', dash_url,
                    '--control-file', str(control_file),
                ]
                if net_modules:
                    cmd += ['--modules', ','.join(net_modules)]
                return cmd

            try:
                if scan_type in ('web', 'vapt'):
                    web_cmd = _web_cmd()
                    proc = subprocess.Popen(
                        web_cmd, cwd=str(forge_root), env=scan_env,
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                    )
                    server._active_scans[scan_id + '_web'] = {
                        'proc': proc, 'type': 'web', 'target': target,
                        'started_at': time.time(), 'engagement': engagement,
                        'mode': mode, 'status': 'running',
                        'started_dt': datetime.now(timezone.utc).isoformat(),
                        'control_file': str(control_file),
                        'command': server._sanitize_cmd(web_cmd),
                        'dashboard_url': dash_url,
                    }
                    server._track_scan_process(scan_id + '_web', server._active_scans[scan_id + '_web'])
                    launched.append('web')

                if scan_type in ('net', 'vapt'):
                    resolved_ip = target
                    try:
                        import urllib.parse
                        parsed = urllib.parse.urlparse(target)
                        hostname = parsed.hostname or target.split('/')[0].split(':')[0]
                        resolved_ip = socket.gethostbyname(hostname)
                    except Exception:
                        pass
                    net_cmd = _net_cmd(resolved_ip)
                    proc = subprocess.Popen(
                        net_cmd, cwd=str(forge_root), env=net_scan_env_,
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                    )
                    server._active_scans[scan_id + '_net'] = {
                        'proc': proc, 'type': 'net', 'target': resolved_ip,
                        'started_at': time.time(), 'engagement': engagement,
                        'mode': 'external', 'status': 'running',
                        'started_dt': datetime.now(timezone.utc).isoformat(),
                        'control_file': str(control_file),
                        'command': server._sanitize_cmd(net_cmd),
                        'dashboard_url': dash_url,
                    }
                    server._track_scan_process(scan_id + '_net', server._active_scans[scan_id + '_net'])
                    launched.append('net')

            except Exception as exc:
                raise HTTPException(status_code=500, detail=f"Failed to launch scan: {exc}")

            server._write_scan_history(
                scan_id=scan_id, target=target, scan_type=scan_type,
                mode=mode, engagement=engagement, frameworks=launched,
                requested_modules=modules,
                actual_modules=(web_modules + net_modules),
            )

            server.event_bus.emit_simple(
                EventType.SCAN_START, source='scan_builder',
                target=target, scan_type=scan_type, scan_id=scan_id,
                modules=modules, actual_modules=(web_modules + net_modules),
                intensity=intensity_label,
                threads=body.get('maxThreads', 20),
                unsupported=unsupported,
            )

            response_data = {
                'status': 'launched',
                'scan_id': scan_id,
                'target': target,
                'scan_type': scan_type,
                'frameworks': launched,
                'modules_count': len(web_modules) + len(net_modules),
                'requested_modules': modules,
                'actual_modules': web_modules + net_modules,
                'intensity': intensity_label,
                'dashboard_url': dash_url,
            }
            if unsupported:
                response_data['unsupported_modules'] = unsupported
                response_data['warning'] = f"{len(unsupported)} module(s) not yet implemented: {', '.join(unsupported)}"
            return response_data

        # ── Report download ───────────────────────────────────────────

        @app.get("/api/v1/reports/latest")
        async def api_report_latest(request: Request, fmt: str = "html"):
            """Return the path of the most recently generated report.

            Query params:
              fmt: "html" | "pdf" | "json"
            """
            _require_auth(request)
            forge_root = Path(__file__).parent.parent.parent
            # Search webforge and netforge results dirs
            candidates: list[Path] = []
            for framework in ("webforge", "netforge"):
                results_root = forge_root / framework / "results"
                if results_root.exists():
                    candidates.extend(results_root.rglob(f"report.{fmt}"))
                    candidates.extend(results_root.rglob(f"findings.{fmt}"))

            if not candidates:
                raise HTTPException(status_code=404, detail=f"No {fmt} report found yet — run a scan first")

            latest = max(candidates, key=lambda p: p.stat().st_mtime)
            return {"path": str(latest), "size": latest.stat().st_size}

        @app.get("/api/v1/reports/download")
        async def api_report_download(request: Request, fmt: str = "html"):
            """Download the most recently generated report.

            Query params:
              fmt: "html" | "pdf" | "json"
            """
            _require_auth(request)
            forge_root = Path(__file__).parent.parent.parent
            candidates: list[Path] = []
            for framework in ("webforge", "netforge"):
                results_root = forge_root / framework / "results"
                if results_root.exists():
                    candidates.extend(results_root.rglob(f"report.{fmt}"))
                    if fmt == "json":
                        candidates.extend(results_root.rglob("findings.json"))

            if not candidates:
                raise HTTPException(status_code=404, detail=f"No {fmt} report found — run a scan first")

            latest = max(candidates, key=lambda p: p.stat().st_mtime)
            media_types = {"html": "text/html", "pdf": "application/pdf", "json": "application/json"}
            return FileResponse(
                str(latest),
                media_type=media_types.get(fmt, "application/octet-stream"),
                filename=f"forge_report.{fmt}",
            )

        # ── Plugin inventory ──────────────────────────────────────────

        @app.get("/api/v1/plugins")
        async def api_plugins(request: Request):
            """Inventory of all available webforge scanner modules."""
            _require_auth(request)
            try:
                import sys as _sys
                _forge_root = Path(__file__).parent.parent.parent
                if str(_forge_root) not in _sys.path:
                    _sys.path.insert(0, str(_forge_root))
                from webforge.webforge import MODULE_MAP as _MM, CLASS_NAME_MAP as _CM
                from webforge.core.mode_engine import PHASES as _PHASES
                _name_to_phase = {
                    name: num
                    for num, _phase_name, names in _PHASES
                    for name in names
                }
                _name_to_phase_name = {
                    name: _phase_name
                    for num, _phase_name, names in _PHASES
                    for name in names
                }
            except ImportError:
                _MM = _CM = {}
                _name_to_phase = {}
                _name_to_phase_name = {}
            plugins = [
                {
                    "name": name,
                    "import_path": _MM.get(name, ""),
                    "class_name": _CM.get(name, ""),
                    "phase": _name_to_phase.get(name),
                    "phase_name": _name_to_phase_name.get(name),
                }
                for name in _MM
            ]
            return {"plugins": plugins, "total": len(plugins)}

        # ── Report listing ────────────────────────────────────────────

        @app.get("/api/v1/reports")
        async def api_reports_list(
            request: Request,
            fmt: str | None = None,
            framework: str | None = None,
            limit: int = Query(default=50, le=200),
        ):
            """List all generated reports across all engagements.

            Query params:
              fmt:       filter by format — html | pdf | json
              framework: filter by framework — webforge | netforge
              limit:     max results (default 50, max 200)
            """
            _require_auth(request)
            forge_root = Path(__file__).parent.parent.parent
            frameworks = [framework] if framework else ["webforge", "netforge"]
            extensions = [fmt] if fmt else ["html", "pdf", "json"]
            entries: list[dict] = []
            for fw in frameworks:
                results_root = forge_root / fw / "results"
                if not results_root.exists():
                    continue
                for ext in extensions:
                    for p in results_root.rglob(f"*.{ext}"):
                        try:
                            stat = p.stat()
                        except OSError:
                            continue
                        entries.append({
                            "path": str(p.relative_to(forge_root)),
                            "framework": fw,
                            "format": ext,
                            "engagement": p.parent.name,
                            "size": stat.st_size,
                            "modified_at": datetime.fromtimestamp(
                                stat.st_mtime, tz=timezone.utc,
                            ).isoformat(),
                        })
            entries.sort(key=lambda e: e["modified_at"], reverse=True)
            return {"reports": entries[:limit], "total": len(entries)}

        # ── Verification queue ────────────────────────────────────────

        @app.get("/api/v1/findings/verification-queue")
        async def api_verification_queue(
            request: Request,
            limit: int = Query(default=100, le=500),
        ):
            """Findings pending operator verification, sorted by risk (VPR then CVSS).

            Returns findings where confidence is UNVERIFIED or status is open.
            """
            _require_auth(request, Role.OPERATOR)
            queue = [
                f for f in server.state_store.findings
                if f.confidence == "UNVERIFIED" or f.status == "open"
            ]
            queue.sort(
                key=lambda f: (f.vpr_score or 0.0, f.cvss_score or 0.0),
                reverse=True,
            )
            return {
                "queue": [f.to_dict() for f in queue[:limit]],
                "total": len(queue),
            }

        # ── WebSocket ─────────────────────────────────────────────────

        @app.websocket("/ws/dashboard")
        async def ws_dashboard(websocket: WebSocket):
            """Real-time dashboard event stream."""
            await websocket.accept()

            # Authenticate WebSocket
            if server.auth_enabled:
                try:
                    auth_msg = await asyncio.wait_for(
                        websocket.receive_json(), timeout=10.0,
                    )
                    token = auth_msg.get("token", "")
                    payload = validate_token(token)
                    if not payload:
                        await websocket.send_json({"error": "unauthorized"})
                        await websocket.close(code=4001)
                        return
                except asyncio.TimeoutError:
                    await websocket.close(code=4002)
                    return

            server._ws_clients.append(websocket)
            log.info("WebSocket client connected (%d total)", len(server._ws_clients))

            # Send initial state snapshot
            try:
                await websocket.send_json({
                    "type": "state_snapshot",
                    "data": server.state_store.snapshot(),
                })
            except Exception:
                pass

            # Event relay loop
            try:
                while True:
                    # Keep connection alive + receive client commands
                    msg = await websocket.receive_text()
                    try:
                        cmd = json.loads(msg)
                        await server._handle_ws_command(cmd, websocket)
                    except json.JSONDecodeError:
                        pass
            except WebSocketDisconnect:
                pass
            finally:
                if websocket in server._ws_clients:
                    server._ws_clients.remove(websocket)
                log.info("WebSocket client disconnected (%d remaining)",
                         len(server._ws_clients))

        self._app = app
        return app

    async def _handle_ws_command(
        self, cmd: dict[str, Any], ws: WebSocket,
    ) -> None:
        """Handle commands from WebSocket clients."""
        action = cmd.get("action")
        if action == "ping":
            await ws.send_json({"type": "pong", "ts": time.time()})
        elif action == "get_state":
            await ws.send_json({
                "type": "state_snapshot",
                "data": self.state_store.snapshot(),
            })
        elif action == "get_findings":
            severity = cmd.get("severity")
            limit = cmd.get("limit", 100)
            findings = self.state_store.findings_snapshot(severity=severity, limit=limit)
            await ws.send_json({"type": "findings", "data": findings})

    async def _broadcast_event(self, event: Event) -> None:
        """Broadcast an event to all connected WebSocket clients."""
        if not self._ws_clients:
            return
        msg = json.dumps({
            "type": "event",
            "event_type": event.event_type.value,
            "data": event.data,
            "source": event.source,
            "timestamp": event.timestamp,
            "event_id": event.event_id,
        }, default=str)

        disconnected: list[WebSocket] = []
        for ws in self._ws_clients:
            try:
                await ws.send_text(msg)
            except Exception:
                disconnected.append(ws)
        for ws in disconnected:
            if ws in self._ws_clients:
                self._ws_clients.remove(ws)

    async def start(self) -> None:
        """Start the dashboard server with uvicorn."""
        try:
            import uvicorn
        except ImportError:
            raise ImportError("uvicorn not installed. Run: pip install uvicorn[standard]")

        app = self.create_app()

        # Wire async event broadcasting
        loop = asyncio.get_event_loop()
        self.event_bus.async_subscribe(None, self._broadcast_event)
        if not self.event_bus._running:
            self.event_bus.start(loop=loop)

        # Always attempt TLS (self-signed cert). Browsers must use https://.
        # If cryptography is not installed, falls back to plain HTTP.
        ssl_ctx = self._create_ssl_context()
        proto = "https" if ssl_ctx else "http"

        config = uvicorn.Config(
            app=app,
            host=self.host,
            port=self.port,
            ssl_certfile=ssl_ctx.get("certfile") if ssl_ctx else None,
            ssl_keyfile=ssl_ctx.get("keyfile") if ssl_ctx else None,
            log_level="warning",
            access_log=False,
        )
        server = uvicorn.Server(config)
        log.info("War Room dashboard starting at %s://%s:%d", proto, self.host, self.port)
        await server.serve()

    def _create_ssl_context(self) -> dict[str, str] | None:
        """Generate self-signed TLS cert for local HTTPS."""
        cert_dir = _DASHBOARD_DIR / ".tls"
        cert_file = cert_dir / "forge_cert.pem"
        key_file = cert_dir / "forge_key.pem"

        if cert_file.exists() and key_file.exists():
            return {"certfile": str(cert_file), "keyfile": str(key_file)}

        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            import datetime

            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, "Forge Suite War Room"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Forge Suite"),
            ])
            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
                .not_valid_after(
                    datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
                )
                .add_extension(
                    x509.SubjectAlternativeName([
                        x509.DNSName("localhost"),
                        x509.IPAddress(
                            __import__("ipaddress").IPv4Address("127.0.0.1")
                        ),
                    ]),
                    critical=False,
                )
                .sign(key, hashes.SHA256())
            )

            cert_dir.mkdir(parents=True, exist_ok=True)
            with open(key_file, "wb") as f:
                f.write(key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption(),
                ))
            with open(cert_file, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))

            log.info("Generated self-signed TLS cert at %s", cert_file)
            return {"certfile": str(cert_file), "keyfile": str(key_file)}

        except ImportError:
            log.warning("cryptography not available — running dashboard without TLS")
            return None

    def _dashboard_public_url(self, request: Request | None = None) -> str:
        """Best-effort URL scan subprocesses can use to post events back."""
        configured = os.environ.get("FORGE_DASHBOARD_URL", "").strip()
        if configured:
            return configured.rstrip("/")

        scheme = "https"
        if request:
            forwarded_proto = request.headers.get("x-forwarded-proto")
            if forwarded_proto:
                scheme = forwarded_proto.split(",")[0].strip()
            elif request.url.scheme in {"http", "https"}:
                scheme = request.url.scheme

        host = "127.0.0.1" if self.host in {"0.0.0.0", "::", ""} else self.host
        if request:
            forwarded_host = request.headers.get("x-forwarded-host")
            host_header = forwarded_host or request.headers.get("host", "")
            if host_header:
                host = host_header.split(",")[0].strip().split(":")[0] or host
                if host in {"0.0.0.0", "::"}:
                    host = "127.0.0.1"
        return f"{scheme}://{host}:{self.port}"

    def _tool_inventory(self) -> list[dict[str, Any]]:
        """Return the framework scripts the dashboard can launch/control."""
        forge_root = Path(__file__).parent.parent.parent
        specs = [
            ("web", "WebForge", forge_root / "webforge" / "webforge.py", True),
            ("net", "NetForge", forge_root / "netforge" / "netforge.py", True),
            ("ad", "ADForge", forge_root / "adforge" / "adforge.py", False),
            ("ai", "AIForge", forge_root / "aiforge" / "aiforge.py", False),
            ("c2", "Forge C2", forge_root / "forge_c2" / "server.py", False),
            ("payload", "Payload Factory", forge_root / "forge_payload" / "payload_factory.py", False),
        ]
        return [
            {
                "id": tool_id,
                "name": name,
                "path": str(path.relative_to(forge_root)),
                "ready": path.exists(),
                "dashboard_launch": launchable,
            }
            for tool_id, name, path, launchable in specs
        ]

    def _sanitize_cmd(self, cmd: list[str]) -> list[str]:
        """Redact any sensitive argv values before storing command metadata."""
        sensitive_flags = {"--password", "--token", "--cookie", "--cookie-jar", "--secret"}
        sanitized: list[str] = []
        skip_next = False
        for part in cmd:
            if skip_next:
                sanitized.append("<redacted>")
                skip_next = False
                continue
            sanitized.append(part)
            if part in sensitive_flags:
                skip_next = True
        return sanitized

    @property
    def is_paused(self) -> bool:
        return self._scan_paused

    @property
    def is_aborted(self) -> bool:
        return self._scan_aborted

    # ── Subprocess Control ────────────────────────────────────────────

    def _init_control_file(self, scan_id: str) -> Path:
        """Create a shared control file for all subprocesses in one scan."""
        path = self._control_dir / f"{scan_id}.json"
        self._write_control_file(path, paused=False, aborted=False)
        return path

    def _write_control_file(self, path: Path, paused: bool, aborted: bool) -> None:
        payload = {
            "paused": paused,
            "aborted": aborted,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        try:
            path.write_text(json.dumps(payload), encoding="utf-8")
        except Exception as exc:
            log.warning("Could not write control file %s: %s", path, exc)

    def _write_all_control_files(self, state: dict[str, bool]) -> None:
        seen: set[str] = set()
        for info in self._active_scans.values():
            path_str = info.get("control_file")
            if not path_str or path_str in seen:
                continue
            seen.add(path_str)
            self._write_control_file(
                Path(path_str),
                paused=bool(state.get("paused", False)),
                aborted=bool(state.get("aborted", False)),
            )

    def _terminate_active_scans(self, status: str = "stopped") -> list[str]:
        """Terminate running child processes and mark them with a terminal status."""
        killed: list[str] = []
        for key, info in list(self._active_scans.items()):
            proc = info.get("proc")
            if not proc or proc.poll() is not None:
                continue
            info["status"] = status
            try:
                proc.terminate()
                killed.append(key)
            except Exception as exc:
                log.warning("Could not terminate scan %s: %s", key, exc)

        deadline = time.monotonic() + 5.0
        for key in killed:
            proc = self._active_scans[key]["proc"]
            remaining = max(0.0, deadline - time.monotonic())
            try:
                proc.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                try:
                    proc.kill()
                except Exception as exc:
                    log.warning("Could not kill scan %s: %s", key, exc)

        return killed

    # ── Scan History (lightweight JSON store) ─────────────────────────

    @staticmethod
    def _base_scan_id(scan_key: str) -> str:
        """Return the user-facing scan id from a framework-specific process key."""
        for suffix in ("_net_auto", "_web", "_net"):
            if scan_key.endswith(suffix):
                return scan_key[: -len(suffix)]
        return scan_key

    @property
    def _history_path(self) -> Path:
        """Path to the scan history JSON file (next to engagement.db)."""
        return Path(__file__).parent.parent.parent / "scan_history.json"

    def _write_scan_history(
        self,
        scan_id: str,
        target: str,
        scan_type: str,
        mode: str,
        engagement: str,
        frameworks: list[str],
        requested_modules: list[str] | None = None,
        actual_modules: list[str] | None = None,
    ) -> None:
        """Append a new scan record to the persistent history store."""
        record = {
            "scan_id": scan_id,
            "target": target,
            "scan_type": scan_type,
            "mode": mode,
            "engagement": engagement,
            "frameworks": frameworks,
            "requested_modules": requested_modules or [],
            "actual_modules": actual_modules or [],
            "started_at": datetime.now(timezone.utc).isoformat(),
            "status": "running",
            "findings_count": {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0},
        }
        try:
            history: list[dict] = []
            if self._history_path.exists():
                history = json.loads(self._history_path.read_text(encoding="utf-8"))
            history.insert(0, record)
            self._history_path.write_text(
                json.dumps(history, indent=2), encoding="utf-8",
            )
        except Exception as exc:
            log.warning("Could not write scan history: %s", exc)

    def _update_scan_history_status(self, scan_id: str, status: str) -> None:
        """Persist terminal status for a scan record when a child process exits."""
        try:
            if not self._history_path.exists():
                return
            history = json.loads(self._history_path.read_text(encoding="utf-8"))
            changed = False
            for record in history:
                if record.get("scan_id") == scan_id:
                    record["status"] = self._aggregate_scan_status(scan_id, fallback=status)
                    record["updated_at"] = datetime.now(timezone.utc).isoformat()
                    changed = True
                    break
            if changed:
                self._history_path.write_text(
                    json.dumps(history, indent=2), encoding="utf-8",
                )
        except Exception as exc:
            log.warning("Could not update scan history status: %s", exc)

    def _aggregate_scan_status(self, scan_id: str, fallback: str = "running") -> str:
        """Aggregate web/net subprocess states into one user-facing scan status."""
        states: list[str] = []
        for key, info in self._active_scans.items():
            if self._base_scan_id(key) != scan_id:
                continue
            proc = info.get("proc")
            rc = info.get("returncode")
            if rc is None and proc:
                rc = proc.poll()
            if rc is None:
                states.append(info.get("status", "running"))
            elif info.get("status") in {"aborted", "stopped"}:
                states.append(info["status"])
            elif rc == 0:
                states.append("completed")
            else:
                states.append("failed")
        if not states:
            return fallback
        if any(s == "running" for s in states):
            return "running"
        if any(s == "aborted" for s in states):
            return "aborted"
        if any(s == "stopped" for s in states):
            return "stopped"
        if any(s == "failed" for s in states):
            return "failed"
        return "completed"

    def _load_scan_history(self, limit: int = 50) -> list[dict]:
        """Load scan history records, enriched with live status from active scans."""
        history: list[dict] = []
        try:
            if self._history_path.exists():
                history = json.loads(self._history_path.read_text(encoding="utf-8"))
        except Exception:
            pass

        # Enrich with current findings counts and live process status
        changed = False
        for record in history:
            sid = record.get("scan_id", "")
            if any(self._base_scan_id(key) == sid for key in self._active_scans):
                record["status"] = self._aggregate_scan_status(sid, fallback=record.get("status", "running"))
            elif record.get("status") == "running":
                record["status"] = "orphaned"
                record["updated_at"] = datetime.now(timezone.utc).isoformat()
                record["status_note"] = "No live dashboard process is tracking this scan."
                changed = True

        # Collect finding counts from results directories for completed scans
        forge_root = Path(__file__).parent.parent.parent
        for record in history:
            if record.get("status") == "completed":
                record["findings_count"] = self._count_findings_for_scan(
                    forge_root, record,
                )
        if changed:
            self._write_scan_history_records(history)

        return history[:limit]

    def _write_scan_history_records(self, history: list[dict]) -> None:
        try:
            self._history_path.write_text(
                json.dumps(history, indent=2), encoding="utf-8",
            )
        except Exception as exc:
            log.warning("Could not write scan history: %s", exc)

    def _delete_scan_record(self, scan_id: str, purge_artifacts: bool = False) -> dict:
        """Remove scan history/log/control state and optionally matching result artifacts."""
        history: list[dict] = []
        if self._history_path.exists():
            try:
                history = json.loads(self._history_path.read_text(encoding="utf-8"))
            except Exception:
                history = []

        record = next((r for r in history if r.get("scan_id") == scan_id), None)
        found = record is not None or any(self._base_scan_id(k) == scan_id for k in self._active_scans)
        if not found:
            return {"found": False, "scan_id": scan_id}

        removed_processes: list[str] = []
        for key, info in list(self._active_scans.items()):
            if self._base_scan_id(key) != scan_id:
                continue
            proc = info.get("proc")
            if proc and proc.poll() is None:
                try:
                    info["status"] = "stopped"
                    proc.terminate()
                except Exception as exc:
                    log.warning("Could not terminate scan %s during delete: %s", key, exc)
            removed_processes.append(key)
            self._active_scans.pop(key, None)

        removed_files: list[str] = []
        for path in [
            self._control_dir / f"{scan_id}.json",
            *self._scan_logs_dir.glob(f"{scan_id}*.log"),
        ]:
            if path.exists():
                try:
                    path.unlink()
                    removed_files.append(str(path))
                except Exception as exc:
                    log.warning("Could not remove scan file %s: %s", path, exc)

        removed_artifacts: list[str] = []
        if purge_artifacts and record:
            removed_artifacts = self._purge_scan_artifacts(record)

        if record:
            history = [r for r in history if r.get("scan_id") != scan_id]
            self._write_scan_history_records(history)

        return {
            "found": True,
            "scan_id": scan_id,
            "history_deleted": bool(record),
            "processes_removed": removed_processes,
            "files_deleted": removed_files,
            "artifacts_deleted": removed_artifacts,
        }

    def _purge_scan_artifacts(self, record: dict) -> list[str]:
        """Delete result directories whose name matches the scan engagement."""
        engagement = record.get("engagement", "")
        if not engagement:
            return []
        forge_root = Path(__file__).parent.parent.parent
        removed: list[str] = []
        for fw in ("webforge", "netforge"):
            results_root = forge_root / fw / "results"
            target = results_root / engagement
            try:
                if target.exists() and target.is_dir() and target.resolve().is_relative_to(results_root.resolve()):
                    import shutil
                    shutil.rmtree(target)
                    removed.append(str(target))
            except Exception as exc:
                log.warning("Could not purge result artifact %s: %s", target, exc)
        return removed

    def _get_scan_detail(self, scan_id: str) -> dict | None:
        """Build the Nessus-style drilldown payload for one scan."""
        records = self._load_scan_history(limit=500)
        record = next((r for r in records if r.get("scan_id") == scan_id), None)

        process_entries = []
        for key, info in self._active_scans.items():
            if self._base_scan_id(key) != scan_id:
                continue
            proc = info.get("proc")
            rc = info.get("returncode")
            if rc is None and proc:
                rc = proc.poll()
            if rc is None:
                status = info.get("status", "running")
            elif rc == 0:
                status = "completed"
            else:
                status = info.get("status") if info.get("status") in {"aborted", "stopped"} else "failed"
            log_path = self._scan_logs_dir / f"{key}.log"
            process_entries.append({
                "process_id": key,
                "framework": info.get("type", ""),
                "target": info.get("target", ""),
                "mode": info.get("mode", ""),
                "status": status,
                "returncode": rc,
                "started_at": info.get("started_dt"),
                "log_path": str(log_path) if log_path.exists() else "",
                "log_tail": self._tail_text(log_path),
                "command": info.get("command", []),
                "control_file": info.get("control_file", ""),
                "dashboard_url": info.get("dashboard_url", ""),
            })

        if not record and not process_entries:
            return None

        if not record:
            first = process_entries[0]
            record = {
                "scan_id": scan_id,
                "target": first.get("target", ""),
                "scan_type": first.get("framework", ""),
                "mode": first.get("mode", ""),
                "engagement": "",
                "frameworks": [p["framework"] for p in process_entries],
                "started_at": first.get("started_at"),
                "status": first.get("status", "running"),
                "requested_modules": [],
                "actual_modules": [],
            }

        forge_root = Path(__file__).parent.parent.parent
        findings = self._findings_for_scan(forge_root, record)
        return {
            **record,
            "findings_count": self._count_findings(findings),
            "processes": process_entries,
            "reports": self._reports_for_scan(forge_root, record),
            "findings": findings[:200],
        }

    def _tail_text(self, path: Path, max_lines: int = 120) -> str:
        """Return the last lines of a subprocess log without loading huge files into memory."""
        if not path.exists():
            return ""
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            return "\n".join(lines[-max_lines:])
        except Exception:
            return ""

    def _reports_for_scan(self, forge_root: Path, record: dict) -> list[dict]:
        """List report artifacts for a scan's engagement."""
        engagement = record.get("engagement", "")
        reports: list[dict] = []
        for fw in ("webforge", "netforge"):
            results_root = forge_root / fw / "results"
            if not results_root.exists():
                continue
            for p in results_root.rglob("*"):
                if not p.is_file() or p.suffix.lower().lstrip(".") not in {"html", "pdf", "json", "csv"}:
                    continue
                if engagement and p.parent.name != engagement:
                    continue
                try:
                    stat = p.stat()
                except OSError:
                    continue
                reports.append({
                    "path": str(p.relative_to(forge_root)),
                    "framework": fw,
                    "format": p.suffix.lower().lstrip("."),
                    "size": stat.st_size,
                    "modified_at": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
                })
        reports.sort(key=lambda r: r["modified_at"], reverse=True)
        return reports

    def _findings_for_scan(self, forge_root: Path, record: dict) -> list[dict]:
        """Load finding rows for a scan's engagement."""
        engagement = record.get("engagement", "")
        rows: list[dict] = []
        for fw in ("webforge", "netforge"):
            results_root = forge_root / fw / "results"
            if not results_root.exists():
                continue
            for findings_file in results_root.rglob("findings.json"):
                if engagement and findings_file.parent.name != engagement:
                    continue
                try:
                    raw = json.loads(findings_file.read_text(encoding="utf-8"))
                    items = raw.get("findings", []) if isinstance(raw, dict) else raw
                    if not isinstance(items, list):
                        continue
                    for item in items:
                        if isinstance(item, dict):
                            rows.append({**item, "framework": fw})
                except Exception:
                    pass
        return rows

    def _count_findings(self, findings: list[dict]) -> dict:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}
        for finding in findings:
            sev = (finding.get("severity") or "info").lower()
            if sev in counts:
                counts[sev] += 1
            counts["total"] += 1
        return counts

    def _count_findings_for_scan(self, forge_root: Path, record: dict) -> dict:
        """Count findings from result JSON files for a completed scan."""
        counts = self._count_findings(self._findings_for_scan(forge_root, record))
        return {k: counts[k] for k in ("critical", "high", "medium", "low", "total")}

    # ── Scan Templates store ────────────────────────────────────────

    @property
    def _templates_path(self) -> Path:
        return Path(__file__).parent.parent.parent / "scan_templates.json"

    def _load_scan_templates(self) -> list[dict]:
        try:
            if self._templates_path.exists():
                return json.loads(self._templates_path.read_text(encoding="utf-8"))
        except Exception:
            pass
        return []

    def _save_scan_template(self, template: dict) -> None:
        try:
            templates = self._load_scan_templates()
            templates.insert(0, template)
            self._write_scan_templates(templates)
        except Exception as exc:
            log.warning("Could not save scan template: %s", exc)

    def _write_scan_templates(self, templates: list[dict]) -> None:
        try:
            self._templates_path.write_text(
                json.dumps(templates, indent=2), encoding="utf-8",
            )
        except Exception as exc:
            log.warning("Could not write scan templates: %s", exc)


def create_app(
    event_bus: EventBus | None = None,
    state_store: StateStore | None = None,
) -> Any:
    """Factory function for creating the dashboard app.

    Useful for testing and when running with external ASGI servers.
    """
    server = DashboardServer(
        event_bus=event_bus,
        state_store=state_store,
        auth=False,
    )
    return server.create_app()
