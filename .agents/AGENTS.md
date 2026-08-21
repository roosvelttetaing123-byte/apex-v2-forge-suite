# Forge Suite v5 APEX — Workspace Rules

## Identity

You are ForgeMaster when working on this codebase. Forge Suite v5 APEX is an enterprise
offensive security platform competing with Cobalt Strike, Nessus, Acunetix, Burp Suite
Enterprise, and Core Impact. 11/25 pillars complete. 498+ files, 135K+ lines.

## Architecture Rules

- `forge.py` is the unified CLI entry point — never create competing launchers
- All frameworks (NetForge, WebForge, ADForge, AIForge) use the same orchestrator
  pattern: `run_scan()` → `run_for_target()` with EventBus + ScanControl
- Shared code lives in `common/` — never duplicate into framework dirs
- Dashboard is FastAPI + WebSocket at `common/dashboard/`
- Intel pipeline is `common/intel/` with SQLite + FTS5
- C2 framework lives in `forge_c2/` — server, beacons, listeners, BOF engine, malleable profiles
- Payload generation lives in `forge_payload/` — 12 formats, 11 stagers, 5 encoders
- OOB callback server lives in `forge_collab/`

## Directory Layout

```
forge-suite/
├── forge.py                  # Unified CLI (subcommands: scan, dashboard, c2, intel, payload)
├── apex-ui/                  # React UI (17 pages, Vite, port 5173)
├── common/                   # Shared: brain, dashboard, intel, reporting, FP reducer
├── webforge/                 # Web app pentesting (12 phases)
├── netforge/                 # Network pentesting (14 phases, 102 YAML checks)
├── adforge/                  # AD attacks (14 phases)
├── aiforge/                  # AI/LLM red team (8 phases)
├── forge_c2/                 # C2 framework (BOF engine, malleable profiles)
├── forge_payload/            # Payload generation
├── forge_collab/             # OOB callback server
├── skill.md                  # AI coding reference (legacy — see .agents/ skills)
├── ROADMAP.md                # ALL remaining tasks (single source of truth)
└── HANDOFF.md                # Current state, architecture, how to run
```

## Module Pattern (MANDATORY for new modules)

Every module extends `BaseModule` and MUST include:

```python
class ClassName(BaseModule):
    NAME        = "module_name"
    DESCRIPTION = "What it does"
    PHASE       = N
    TAGS        = ["tag", "cwe-XXX"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target.rstrip("/")
        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")
        await self.rate_limit()
        # ... module logic ...
        return self._make_result(start)
```

Non-negotiable safety calls:
- `self.check_scope(target)` at the start of `run()`
- `await self.rate_limit()` before every outbound request
- `self.confirm_action(action, target, risk)` before active exploitation
- `ask_internet_permission()` before online resource use

## Key Code Patterns

```python
await self.rate_limit()                           # Before every request
self.check_scope(url)                             # Scope check
self.confirm_action(action, target, risk)          # Before exploitation
opsec = get_opsec(); await opsec.jitter()          # OpSec jitter
cred_engine.add(host, svc, user, pw)               # Feed creds
attack_chain.ingest_finding(finding.to_dict())      # Feed chain
```

## Do NOT Rebuild (check before creating)

These modules already exist — search the codebase first:

- **ADForge**: ADCS ESC1-14, ACL abuse, delegation, GPO abuse, BloodHound, DCSync,
  Golden/Silver tickets, Zerologon, PetitPotam, NoPac, Kerberoast, AS-REP roast,
  NTLM relay, Pass-the-Hash/Ticket
- **NetForge**: 145 modules + 102 YAML checks across Kubernetes, Docker, MongoDB,
  MySQL, MSSQL, Redis, SNMP, VoIP, ICS/SCADA, IPMI, Printer, NFS, VNC, Telnet,
  TFTP, SSH, RDP, SMB, FTP, Elastic, cloud metadata
- **C2**: Full beacon crypto (AES-256-GCM, RSA-4096, HMAC-SHA256), implant builder
  (12 formats), stagers (11 types), HTTP/DNS/TCP listeners, malleable profiles,
  BOF engine with 10 builtins
- **WebForge**: 100 modules across recon, headers, injection, file, auth, access-control,
  API, advanced web, whitebox, reporting

## Project Docs — Two Files Only

- `ROADMAP.md` — ALL remaining tasks, sprint-organized. Single source of truth.
- `HANDOFF.md` — Current state, architecture, how to run. One file.
- Do NOT create new tracking/status docs. Update these two.

## Running & Testing

- **Smoke test**: `python3 .claude/skills/run-forge-suite/smoke.py`
- **CLI help**: `python3 forge.py --help`
- **Dashboard backend**: `python3 forge.py dashboard --port 1337`
- **Dashboard UI**: `cd apex-ui && npm run dev` (port 5173)
- **Dashboard creds**: `operator / forge2026`
- **Intel status**: `python3 forge.py intel status`

### Known Gotchas
- Dashboard root `/` returns HTTP 500 (Jinja2 template bug) — use `/openapi.json` to verify
- `forge.py c2 server` has a known import mismatch (`TeamServer` vs `C2Server`)
- Never run scans against targets you don't own
- Intel DB starts empty until `intel sync --all` is run

## FP/FN Methodology

All detection modules must use 3-layer false positive reduction:

1. **Baseline** — N clean requests → median response time + size
2. **Probe** — Inject payload → compare delta
3. **Confirm** — Re-probe with variant → require 2/2 match

Confidence levels:
- **HIGH**: 2/2 confirmed probes → default report
- **MEDIUM**: 1/2 or marginal → report, flagged
- **LOW**: Single probe, weak signal → "Needs Verification" only
- **UNVERIFIED**: No secondary verification → `--verbose` only

## Coding Conventions

- Python 3.10+, async-first
- Use `rich` for CLI output
- Type hints on public APIs
- Docstrings on classes and public methods
- Red Team modules require `--red-team` flag
- Exploit modules require operator confirmation
- AIForge DoS/destructive gates cannot be bypassed with `--auto-confirm`
- Graceful degradation — every enhancement must have a fallback if API/dependency missing
