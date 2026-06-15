# Forge Suite v5 APEX — Enterprise Offensive Security Platform
# =============================================================
#
#   ██████╗ ██████╗ ██████╗  ██████╗ ███████╗    ███████╗██╗   ██╗██╗████████╗███████╗
#   ██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝    ██╔════╝██║   ██║██║╚══██╔══╝██╔════╝
#   █████╗  ██║   ██║██████╔╝██║  ███╗█████╗      ███████╗██║   ██║██║   ██║   █████╗
#   ██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝      ╚════██║██║   ██║██║   ██║   ██╔══╝
#   ██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗    ███████║╚██████╔╝██║   ██║   ███████╗
#   ╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝    ╚══════╝ ╚═════╝ ╚═╝   ╚═╝   ╚══════╝
#
#   v5.0.0 APEX — Enterprise Offensive Security Platform
#
# Quick Start:
#   chmod +x install.sh && ./install.sh
#   python3 forge.py --help

## What Is This?

An enterprise-grade offensive security platform with **4 specialized frameworks**, a **C2 framework**, **live war room dashboard**, **intelligence pipeline**, and **multi-target orchestration** — in one unified suite.

### Frameworks

| Framework | What It Does | Entry Point |
|-----------|-------------|-------------|
| **NetForge** | Network pentest + Red Team (11 phases, 50+ modules) | `python3 forge.py net --target 10.0.0.0/24` |
| **WebForge** | Web application security (12 phases, 70+ modules) | `python3 forge.py web --target https://example.com` |
| **ADForge**  | Active Directory attack & audit (14 phases, 85+ modules) | `python3 forge.py ad --target dc.domain.local` |
| **AIForge**  | LLM/AI red teaming (8 phases, 30+ modules) | `python3 forge.py ai --target https://api.example.com` |

### Platform Capabilities

| Capability | Description |
|------------|-------------|
| **C2 Framework** | Beacon-based C2 with HTTP/DNS/TCP/SMB transports, 12 implant formats, 11 stager types |
| **War Room Dashboard** | Real-time WebSocket dashboard + Rich terminal TUI |
| **Multi-Target Engine** | Bulk scanning from file, parallel execution, pause/resume/abort |
| **Post-Exploitation** | Credential harvesting, lateral movement (5 methods), persistence (4 methods), rootkit engine |
| **Intel Pipeline** | Auto-sync NVD CVEs, ExploitDB, Nuclei templates, MITRE ATT&CK |
| **Evasion Engine** | AMSI bypass (6 techniques), ETW blinding (5 techniques), process hollowing |

## Quick Start

### Option 1: Native Install (Kali / Ubuntu)

```bash
# Install
chmod +x install.sh
./install.sh

# Scan
python3 forge.py net --target 10.0.0.0/24 --mode internal
python3 forge.py web --target https://example.com --dashboard
python3 forge.py ad  --dc 10.0.0.1 --domain CORP.LOCAL --mode auth
python3 forge.py ai  --target https://api.openai.com/v1/chat/completions
```

### Option 2: Docker

```bash
# Build image
docker build -t forge-suite:5.0.0 .

# Dashboard + C2 (docker compose)
docker compose up -d

# One-shot scan
docker run -it --rm -v ./results:/opt/forge-suite/results forge-suite:5.0.0 \
  forge.py net --target 10.0.0.0/24 --mode internal
```

### Option 3: Make

```bash
make install        # Install dependencies
make dashboard      # Launch web dashboard
make c2             # Start C2 team server
make docker-up      # docker compose up
make help           # Show all targets
```

## Dashboard

```bash
# Web dashboard (HTTPS on port 1337)
python3 forge.py dashboard
# Default login: operator / forge2026

# Terminal TUI dashboard
python3 forge.py dashboard --tui

# Dashboard alongside scan
python3 forge.py web --target https://example.com --dashboard
```

## C2 Framework

```bash
# Start team server
python3 forge.py c2 server --port 8443

# Connect as operator
python3 forge.py c2 connect --server team.local:8443

# Generate implants via forge_c2/implant/ (12 formats: EXE, DLL, PS1, HTA, VBA, C#, ELF, SO, bash...)
```

## Intelligence Pipeline

```bash
# Sync all sources (NVD + ExploitDB + Nuclei + ATT&CK)
python3 forge.py intel sync --all

# Search local intel
python3 forge.py intel search "Apache 2.4"
python3 forge.py intel search --cve CVE-2024-1234

# Check sync status
python3 forge.py intel status
```

## Multi-Target Scanning

```bash
# Scan from file (one target per line)
python3 forge.py web --targets targets.txt --parallel 5

# Scheduled scan
python3 forge.py net --targets hosts.txt --schedule daily:02:00

# Continuous monitoring
python3 forge.py web --target https://example.com --continuous --interval 12h
```

## Red Team Mode (NetForge)

```bash
# Standard VAPT scan
python3 forge.py net --target 10.0.0.0/24 --mode internal

# Red Team with stealth
python3 forge.py net --target 10.0.0.0/24 --red-team --opsec stealth --attacker-ip 192.168.1.100

# Aggressive Red Team (fast, loud)
python3 forge.py net --target 10.0.0.0/24 --red-team --opsec aggressive
```

### OpSec Profiles
- `--opsec stealth` — 2-15s jitter, 3 threads, decoy traffic, log encryption
- `--opsec normal` — 0.5-3s jitter, 10 threads (default)
- `--opsec aggressive` — 0-0.1s jitter, 50 threads (loud)

## Hardware Requirements

| Tier | CPU | RAM | Disk | Notes |
|------|-----|-----|------|-------|
| **Minimum** | 4 cores | 8 GB | 20 GB | Single target scans |
| **Recommended** | 8+ cores | 16+ GB | 100 GB SSD | Multi-target, dashboard, C2 |
| **C2 Server** | 2+ cores | 4 GB | 10 GB | Dedicated, stable IP/domain |
| **Full Intel DB** | — | — | +500 MB | NVD + ExploitDB + Nuclei + ATT&CK |

**Supported OS:** Kali Linux, Ubuntu 22.04+, Debian 12+, Parrot OS, any Linux with Python 3.10+

## Directory Structure

```
forge-suite/
├── forge.py                 ← Unified v5 launcher (all subcommands)
├── install.sh               ← Full dependency installer
├── requirements.txt         ← Python dependencies
├── Dockerfile               ← Multi-stage Docker build
├── docker-compose.yml       ← Dashboard + C2 + Scan services
├── Makefile                 ← 15 make targets
│
├── netforge/                ← Network pentest + Red Team (11 phases)
│   ├── netforge.py          ← Orchestrator (EventBus + ScanControl)
│   ├── core/                ← OpSec, sessions, credentials, attack chain
│   └── modules/
│       ├── discovery/       ← Host/port/OS/service detection
│       ├── external/        ← DNS, SSL, SMTP, firewall
│       ├── internal/        ← ARP, DHCP, VLAN, LLMNR
│       ├── services/        ← SMB, SSH, RDP, Redis, etc.
│       ├── vuln/            ← CVE matching, nuclei, exploits
│       ├── bruteforce/      ← Native brute force, cred spray
│       ├── exploit/         ← Heartbleed, EternalBlue, BlueKeep, Zerologon
│       ├── post_exploit/    ← Pivot, loot, SAM/NTDS, mimikatz, lateral movement, persistence
│       ├── rootkit/         ← Userland hooking, kernel BYOVD/DKOM, process hollowing, AMSI/ETW bypass
│       └── reporting/       ← HTML, PDF, JSON, CSV reports
│
├── webforge/                ← Web application testing (12 phases, 70+ modules)
├── adforge/                 ← Active Directory (14 phases, 85+ modules)
├── aiforge/                 ← AI/LLM red teaming (8 phases, 30+ modules)
│
├── forge_c2/                ← C2 Framework
│   ├── server.py            ← Team server (operators, listeners, task router)
│   ├── beacon/              ← Beacon crypto (AES-256-GCM) + core lifecycle
│   ├── transport/           ← HTTP/DNS/TCP/SMB transports + malleable profiles
│   ├── listeners/           ← HTTP/DNS/TCP listeners
│   ├── tasks/               ← Shell, file transfer, screenshot, SOCKS5, hashdump
│   └── implant/             ← Builder (12 formats), stager factory (11 types), evasion generator
│
└── common/                  ← Shared infrastructure
    ├── base_module.py       ← Module base class
    ├── target_manager.py    ← Multi-target orchestration
    ├── engagement_scheduler.py ← Scan scheduling
    ├── dashboard/           ← War Room dashboard (web + TUI)
    │   ├── server.py        ← FastAPI + WebSocket backend
    │   ├── event_bus.py     ← 25+ event types
    │   ├── auth.py          ← JWT authentication
    │   ├── web/             ← SPA frontend (HTML, CSS, JS)
    │   └── tui/             ← Rich terminal TUI
    └── intel/               ← Intelligence pipeline
        ├── intel_engine.py  ← Coordinator + FTS5 search
        ├── cve_sync.py      ← NVD API v2
        ├── exploit_db_sync.py ← ExploitDB mirror
        ├── nuclei_sync.py   ← Nuclei template sync
        ├── technique_learner.py ← MITRE ATT&CK STIX 2.1
        └── offline_db.py    ← Export/import/snapshot manager
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `FORGE_DASHBOARD_PASSWORD` | `forge2026` | Dashboard auth password |
| `FORGE_C2_ADMIN_PW` | *(required)* | C2 team server admin password |
| `FORGE_NVD_API_KEY` | *(optional)* | NVD API key (higher rate limits) |
| `FORGE_GITHUB_TOKEN` | *(optional)* | GitHub API token (Nuclei sync) |
| `FORGE_INTEL_DB` | `data/intel.db` | Intel database path |
| `FORGE_ATTACK_BUNDLE_PATH` | *(auto-download)* | Local ATT&CK STIX bundle |
| `FORGE_NUCLEI_TEMPLATES_DIR` | *(auto-download)* | Local Nuclei templates dir |
| `FORGE_EXPLOITDB_CSV_PATH` | *(auto-download)* | Local ExploitDB CSV |

## Legal

**FOR AUTHORIZED PENETRATION TESTING AND RED TEAM ENGAGEMENTS ONLY.**
Unauthorized use is illegal under CFAA and equivalent laws worldwide.
