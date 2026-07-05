---
name: run-forge
description: >
  Run, start, build, launch, test, smoke-test, or verify Forge Suite v5 APEX.
  Covers the forge.py CLI launcher, intel pipeline, dashboard web server,
  framework imports, and the smoke driver. Use when the user asks to run,
  test, demo, or troubleshoot Forge Suite.
---

# Run Forge Suite v5 APEX

Forge Suite is a CLI tool with an optional FastAPI/WebSocket dashboard and a
React UI. The primary interaction paths:

1. **Smoke driver** — `python3 .claude/skills/run-forge-suite/smoke.py` (runs everything, exit 0 = pass)
2. **CLI one-liners** — `python3 forge.py <cmd>`
3. **Dashboard API** — start server, POST /api/v1/auth/login, then hit REST endpoints
4. **React UI** — `cd apex-ui && npm run dev` (port 5173)

All commands run from `forge-suite/`. Paths are relative to that root.

---

## Prerequisites

```bash
pip install rich fastapi "uvicorn[standard]" websockets pyjwt cryptography \
            pydantic pyyaml jinja2 aiohttp requests networkx python-dateutil
```

Python 3.10+ required. All packages are pure-Python.

---

## Smoke Test (Preferred Agent Path)

```bash
python3 .claude/skills/run-forge-suite/smoke.py
```

The driver exercises:
- CLI help (banner + subcommand listing)
- `intel status` and `intel search`
- All four framework imports (netforge, webforge, adforge, aiforge)
- Dashboard API: start server → login → /api/v1/state, /findings, /metrics, /kill-chain

Flags:
```
--dashboard-port PORT   Port for the test dashboard (default: 19337)
--skip-dashboard        Skip dashboard API tests (faster, no port needed)
```

Exit 0 = all checks passed. Exit 1 = at least one failed (printed at bottom).

---

## CLI Commands

```bash
# Main help
python3 forge.py --help

# Intel pipeline status
python3 forge.py intel status

# Intel search (empty until synced)
python3 forge.py intel search "Apache 2.4"

# Scan framework help
python3 forge.py net --target 127.0.0.1   # launches netforge
python3 forge.py web --target http://example.com
python3 forge.py ad --target dc.corp.local
python3 forge.py ai --target http://llm-api.example.com

# Dashboard
python3 forge.py dashboard --port 1337
```

---

## Dashboard Server

The dashboard starts a self-signed HTTPS server. Default credentials: `operator / forge2026`.

```bash
# Start (blocks — run in background or separate terminal)
python3 forge.py dashboard --port 1337

# Login and get token
TOKEN=$(curl -sk -X POST https://127.0.0.1:1337/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"operator","password":"forge2026"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

# Query state
curl -sk https://127.0.0.1:1337/api/v1/state -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

# Query metrics
curl -sk https://127.0.0.1:1337/api/v1/metrics -H "Authorization: Bearer $TOKEN"

# List available endpoints
curl -sk https://127.0.0.1:1337/openapi.json | python3 -c "import sys,json; [print(k) for k in json.load(sys.stdin)['paths']]"
```

### API Routes (all require Bearer token)

```
GET  /api/v1/state          Full scan state snapshot
GET  /api/v1/findings       Findings list (?page=1&limit=20)
GET  /api/v1/targets        Active targets
GET  /api/v1/metrics        Throughput / module / finding counters
GET  /api/v1/kill-chain     Kill chain phase progress
GET  /api/v1/credentials    Captured credentials
GET  /api/v1/sessions       Active sessions
GET  /api/v1/timeline       Event timeline
POST /api/v1/control/pause  Pause running scan
POST /api/v1/control/resume Resume paused scan
POST /api/v1/control/abort  Abort scan
POST /api/v1/scans/launch   Launch scan (ScanBuilder config)
GET  /api/v1/scans/history  Scan history
GET  /api/v1/c2/bofs        List available BOFs
POST /api/v1/c2/bofs/{name}/execute  Execute BOF locally
GET  /api/v1/c2/profiles    List malleable C2 profiles
GET  /api/v1/c2/profiles/{name}  Profile detail
WS   /ws/dashboard          Real-time events
```

### Dashboard Env Vars

| Variable | Default | Description |
|---|---|---|
| `FORGE_DASHBOARD_PASSWORD` | `forge2026` | Operator password |

---

## Direct Invocation (Library-Level Testing)

For PRs touching internals — test without launching full scans:

```python
import os, sys
sys.path.insert(0, "/home/kali/Desktop/Forge-alpha/forge-suite")

# Intel engine
from common.intel.intel_engine import IntelEngine
e = IntelEngine()
print(e.status())

# State store / event bus
from common.dashboard.event_bus import EventBus
from common.dashboard.state_store import StateStore
bus = EventBus(run_id="test")
store = StateStore(bus, framework="forge", target="http://example.com")
print(store.snapshot()["scan_status"])  # → "initializing"

# Framework orchestrators (do NOT call run_scan — that hits live targets)
from netforge.netforge import run_scan  # import OK; don't call without --target
from webforge.webforge import run_scan
from adforge.adforge import run_scan
from aiforge.aiforge import run_scan
```

---

## Gotchas & Troubleshooting

### Known Issues
- **Dashboard root `/` returns HTTP 500** — Jinja2 template bug (`TypeError: unhashable
  type: 'dict'`). The REST API (`/api/v1/*`) works fine. Use `/openapi.json` to verify
  the server is up (no auth required, returns 200).
- **`forge.py c2 server` won't start** — imports `C2Server` but actual class is
  `TeamServer`. Prints "C2 server module not yet available" and exits 1. Known placeholder.
- **Intel DB starts empty** — `intel status` shows 0 records. Expected on fresh install.
  Run `intel sync --all` to populate (requires network access).
- **Scan frameworks require a live target** — Never point at a target you don't own.

### Common Errors

| Error | Fix |
|---|---|
| `ModuleNotFoundError: No module named 'rich'` | `pip install rich fastapi "uvicorn[standard]" websockets pyjwt cryptography pydantic pyyaml jinja2 aiohttp requests networkx python-dateutil` |
| Dashboard `/openapi.json` connection refused | Server needs ~5-8s to start. Smoke driver polls every 0.5s for 12s. |
| `curl: (60) SSL certificate problem` | Dashboard uses self-signed cert. Use `curl -sk` or `--insecure`. |
| `{"detail":"Unauthorized"}` from API | Missing `Authorization: Bearer <token>` header, or token expired (8h TTL). Re-login. |
