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
import json
import logging
import os
import ssl
import time
import uuid
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
    import jinja2 as _jinja2
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
_WEB_DIR = _DASHBOARD_DIR / "web"
_STATIC_DIR = _WEB_DIR / "static"
_TEMPLATE_DIR = _WEB_DIR / "templates"


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

        # Subscribe to all events for WebSocket broadcast
        self.event_bus.subscribe(None, self._on_event)

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

        # Static files
        if _STATIC_DIR.exists():
            app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

        # Templates
        templates = None
        if _TEMPLATE_DIR.exists():
            _jinja_env = _jinja2.Environment(
                loader=_jinja2.FileSystemLoader(str(_TEMPLATE_DIR)),
                autoescape=True,
                cache_size=0,
            )
            templates = Jinja2Templates(env=_jinja_env)

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
        async def dashboard_page(request: Request):
            """Serve the main dashboard SPA."""
            if templates and (_TEMPLATE_DIR / "index.html").exists():
                return templates.TemplateResponse(request, "index.html", {
                    "auth_enabled": server.auth_enabled,
                })
            return HTMLResponse("<h1>Forge Suite War Room</h1><p>Dashboard UI not found.</p>")

        @app.get("/login", response_class=HTMLResponse)
        async def login_page(request: Request):
            """Serve the login page."""
            if templates and (_TEMPLATE_DIR / "login.html").exists():
                return templates.TemplateResponse(request, "login.html", {})
            return HTMLResponse("<h1>Login</h1>")

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

        @app.post("/api/v1/control/pause")
        async def api_pause(request: Request):
            """Pause the current scan."""
            _require_auth(request, Role.OPERATOR)
            server._scan_paused = True
            server.event_bus.emit_simple(
                EventType.SCAN_PAUSED, source="dashboard",
            )
            return {"status": "paused"}

        @app.post("/api/v1/control/resume")
        async def api_resume(request: Request):
            """Resume a paused scan."""
            _require_auth(request, Role.OPERATOR)
            server._scan_paused = False
            server.event_bus.emit_simple(
                EventType.SCAN_RESUMED, source="dashboard",
            )
            return {"status": "resumed"}

        @app.post("/api/v1/control/abort")
        async def api_abort(request: Request):
            """Abort the current scan."""
            _require_auth(request, Role.ADMIN)
            server._scan_aborted = True
            server.event_bus.emit_simple(
                EventType.SCAN_ABORTED, source="dashboard",
            )
            return {"status": "aborted"}

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

        # ── Event ingestion (for out-of-process scanners) ─────────────

        @app.post("/api/v1/events/ingest")
        async def api_ingest_event(request: Request):
            """Accept scan events from subprocess scanners and emit on the bus."""
            body = await request.json()
            etype = body.get("event_type", "")
            source = body.get("source", "scanner")
            data = {k: v for k, v in body.items() if k not in ("event_type", "source")}
            try:
                server.event_bus.emit(Event(
                    event_type=EventType(etype),
                    data=data,
                    source=source,
                ))
            except (ValueError, KeyError):
                pass
            # Give the StateStore thread a moment to process, then push snapshot
            await asyncio.sleep(0.05)
            await server._push_state_snapshot()
            return {"status": "ok"}

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

    async def _push_state_snapshot(self) -> None:
        """Push a full state snapshot to all connected WebSocket clients."""
        if not self._ws_clients:
            return
        msg = {"type": "state_snapshot", "data": self.state_store.snapshot()}
        disconnected: list[WebSocket] = []
        for ws in self._ws_clients:
            try:
                await ws.send_json(msg)
            except Exception:
                disconnected.append(ws)
        for ws in disconnected:
            if ws in self._ws_clients:
                self._ws_clients.remove(ws)

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

        # Generate self-signed TLS cert for HTTPS
        ssl_ctx = self._create_ssl_context()

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
        log.info("War Room dashboard starting at https://%s:%d", self.host, self.port)
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

    @property
    def is_paused(self) -> bool:
        return self._scan_paused

    @property
    def is_aborted(self) -> bool:
        return self._scan_aborted


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
