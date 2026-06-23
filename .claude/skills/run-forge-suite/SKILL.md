---
name: run-forge-suite
description: Run, start, build, launch, screenshot, test, smoke-test, or verify Forge Suite v5 APEX — the offensive security CLI platform. Covers the forge.py launcher, intel pipeline, dashboard web server, and framework imports.
---

# Run Forge Suite v5 APEX

Forge Suite is a CLI tool with an optional FastAPI/WebSocket dashboard. There is no
GUI to screenshot. The primary interaction path for agents is:

1. **Smoke driver** — `python3 .claude/skills/run-forge-suite/smoke.py` (runs everything, exit 0 = pass)
2. **CLI one-liners** — `PYTHONUTF8=1 python3 forge.py <cmd>`
3. **Dashboard API** — start server, POST /api/v1/auth/login, then hit REST endpoints

All commands run from `forge-suite/`. Paths in this file are relative to that root.

---

## Prerequisites

```
pip install rich fastapi "uvicorn[standard]" websockets pyjwt cryptography \
            pydantic pyyaml jinja2 aiohttp requests networkx python-dateutil
```

Python 3.10+ required. All packages above are pure-Python; no system libs needed.

---

## Windows gotcha — always set PYTHONUTF8=1

The banner uses box-drawing Unicode characters. Without `PYTHONUTF8=1`, Python on
Windows uses CP-1252 encoding and crashes with `UnicodeEncodeError` on every command.

```
set PYTHONUTF8=1        # cmd.exe (persistent for this session)
$env:PYTHONUTF8 = "1"   # PowerShell
export PYTHONUTF8=1     # Git Bash / WSL
```

Or prefix every command: `PYTHONUTF8=1 python3 forge.py …`

---

## Run (agent path) — smoke driver

Run all checks at once:

```bash
cd forge-suite
PYTHONUTF8=1 python3 .claude/skills/run-forge-suite/smoke.py
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

## Run (CLI — individual commands)

```bash
# Main help
PYTHONUTF8=1 python3 forge.py --help

# Intel pipeline status
PYTHONUTF8=1 python3 forge.py intel status

# Intel search (empty until synced)
PYTHONUTF8=1 python3 forge.py intel search "Apache 2.4"

# Intel search help
PYTHONUTF8=1 python3 forge.py intel --help

# Scan framework help (forwards to framework-specific arg parser)
PYTHONUTF8=1 python3 forge.py net --target 127.0.0.1 2>&1  # launches netforge

# Dashboard help
PYTHONUTF8=1 python3 forge.py dashboard --help
```

---

## Run (dashboard server)

The dashboard starts a self-signed HTTPS server. Default credentials: `operator / forge2026`.

```bash
# Start (blocks — run in background or separate terminal)
PYTHONUTF8=1 python3 forge.py dashboard --port 1337

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

Available API routes (all require Bearer token):
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
```

### Dashboard env vars

| Variable | Default | Description |
|---|---|---|
| `FORGE_DASHBOARD_PASSWORD` | `forge2026` | Operator password |

---

## Direct invocation (library path for PRs touching internals)

Most PRs touch individual framework modules or the intel engine. Use direct import
to test without launching the full scan:

```python
import os, sys
os.environ["PYTHONUTF8"] = "1"
sys.path.insert(0, "d:/Forge-alpha/forge-suite")  # adjust to abs path

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

## Gotchas

- **PYTHONUTF8=1 is mandatory on Windows.** Forgetting it causes a crash on the very
  first `print(BANNER)` call — the box-drawing chars are outside CP-1252.

- **Dashboard root (`/`) returns HTTP 500** — Jinja2 template bug:
  `TypeError: unhashable type: 'dict'` in the template environment cache lookup.
  The REST API (`/api/v1/*`) works fine. Do not use `/` to verify the server is up;
  use `/openapi.json` instead (no auth required, returns 200).

- **`forge.py c2 server` won't start** — `forge.py` tries `from forge_c2.server import C2Server`
  but the actual class is `TeamServer`. It prints "C2 server module not yet available" and exits 1.
  This is a known placeholder mismatch, not a missing dependency.

- **Payload generation is blocked** — The `forge_payload/` module doesn't exist yet.
  `python3 forge.py payload …` will print "Payload factory not yet available" and exit 1.

- **Intel DB starts empty** — `intel status` shows 0 records for all sources. This is
  expected on a fresh install. `intel search` returns no results until `intel sync --all`
  runs (requires NVD/ExploitDB/GitHub network access).

- **Scan frameworks require a live target** — `python3 forge.py net --target X` will
  actually attempt network connections to X. Never point at a target you don't own.
  For import-only testing, use the direct invocation path above.

---

## Troubleshooting

**`UnicodeEncodeError: 'charmap' codec can't encode characters`**
→ Add `PYTHONUTF8=1` before the command. The banner uses box-drawing chars.

**`ModuleNotFoundError: No module named 'rich'`** (or fastapi, uvicorn, etc.)
→ Run: `pip install rich fastapi "uvicorn[standard]" websockets pyjwt cryptography pydantic pyyaml jinja2 aiohttp requests networkx python-dateutil`

**Dashboard `/openapi.json` returns connection refused**
→ Server needs ~5-8s to start. The smoke driver polls every 0.5s for 12s total.

**`curl: (60) SSL certificate problem`**
→ The dashboard generates a self-signed cert. Use `curl -sk` (skip cert verify) or
  pass `--insecure`.

**`{"detail":"Unauthorized"}` from API endpoints**
→ You forgot the `Authorization: Bearer <token>` header, or the token expired (8h TTL).
  Re-run the login step.
