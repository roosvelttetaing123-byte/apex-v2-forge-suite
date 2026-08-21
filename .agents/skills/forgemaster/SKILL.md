---
name: forgemaster
description: >
  Activates ForgeMaster context for building Forge Suite v5 APEX — the enterprise
  offensive security platform. Use for: module development, framework architecture,
  C2/beacon work, payload generation, evasion techniques, vulnerability scanner
  building, pentest methodology, FP/FN tuning, dashboard development, intel pipeline,
  reporting, compliance mapping, VPR scoring, or any offensive security tool engineering.
---

# ForgeMaster — Forge Suite v5 APEX Development Skill

## Platform Overview

Forge Suite v5 APEX is a 25-pillar enterprise offensive security platform:

| Framework | Purpose | Phases |
|-----------|---------|--------|
| NetForge | Network pentesting + red team | 14 phases, 145 modules, 102 YAML checks |
| WebForge | Web app pentesting | 12 phases, 100 modules |
| ADForge | Active Directory attacks | 14 phases, 98 modules |
| AIForge | AI/LLM red teaming | 8 phases, 39 modules |

Cross-cutting systems: Forge C2, Dashboard, Intel Pipeline, Post-Exploit, Payload Gen, OOB Server.

### Current Status: 11/25 Pillars Complete

Completed: C2, Dashboard, Multi-Target, Post-Exploit, Intel, Payload, NetForge VAPT,
Packaging, FP/FN, OOB Server, BOF+Malleable (Sprint 1)

In progress: ForgeBrain (9G pending), Chains (wiring pending)

See `ROADMAP.md` for the full remaining task list.

---

## Build Priority Tiers

| Tier | Pillars | Goal |
|------|---------|------|
| 1 | 9 (ForgeBrain), 10 (FP/FN), 17 (OOB) | Intelligence & accuracy |
| 2 | 15 (Dashboard UX), 20 (Reporting) | Product feel |
| 3 | 16 (Headless browser), 19 (Credentialed scanning), 11 (CVEs) | Coverage |
| 4 | 18 (Advanced C2), 22 (Payload delivery), 6 (Payload gen) | C2 parity |
| 5 | 12 (Cross-framework chains), 21 (Integrations), 23 (Cloud) | Chaining |
| 6 | 13 (Hardening), 25 (Distributed), 14 (Observability), 24 (Quality) | Enterprise |

---

## v5 Orchestrator Pattern (All 4 Frameworks)

```python
def _get_event_bus(event_bus=None):
    if event_bus is None: return None, None, None
    from common.dashboard.event_bus import Event, EventType
    return event_bus, Event, EventType

def _emit(bus, Event, EventType, etype, source="framework", **data):
    if bus is None: return
    bus.emit(Event(event_type=EventType(etype), data=data, source=source))

class ScanControl:
    def __init__(self):
        self._paused = asyncio.Event()
        self._paused.set()
        self._aborted = False
    async def wait_if_paused(self): await self._paused.wait()

async def run_scan(cfg, args, results_dir, event_bus=None, scan_control=None): ...
async def run_for_target(target_entry, base_args, event_bus=None, scan_control=None): ...
```

---

## Evasion Reference

### AV/EDR Bypass
- Direct syscalls (Hell's Gate, Halo's Gate)
- ETW patching (EtwEventWrite → xor eax,eax; ret)
- AMSI patching (AmsiScanBuffer → E_INVALIDARG)
- DLL unhooking (remap clean ntdll from disk)
- Sleep masking (Ekko, StackOPs with EC2 encryption)
- Signed binary abuse (msbuild, regsvr32, rundll32, installutil)
- Fileless via reflective DLL loading

### Network Evasion
- Domain fronting (CDN SNI spoofing)
- DNS tunneling (base32 in TXT records)
- JA3/S randomization
- Jitter: 15-45% randomized sleep

### Log Evasion
- Clear PowerShell history
- wevtutil Windows event log deletion
- Disable Defender real-time monitoring
- Selective /var/log/* deletion on Linux

---

## C2 Beacon Patterns

### Transports
- HTTP/S — Mimics Office 365, random UA per beacon
- DNS — TXT base32 queries, subdomain exfiltration
- TCP — Length-prefixed binary, auto-reconnect
- SMB — Named pipe (internal lateral)
- ICMP — Data in echo request payloads (placeholder)

### Beacon Config
- Jitter: 15-45%
- Sleep: 30s-5m configurable
- Kill date support
- C2 failover: round-robin 3+ endpoints

### Implant Formats (12)
EXE, DLL, ServiceEXE, shellcode, PowerShell, HTA, VBA, C#, ELF, SO, bash, raw

### Stager Types (11)
HTTP_PS, HTTP_CMD, CERTUTIL, BITSADMIN, MSHTA, REGSVR32, PYTHON, CURL_BASH, DNS_TXT

---

## ForgeBrain AI Model Routing

| Task | Model |
|------|-------|
| Heavy reasoning / attack planning | claude-opus-4-8 |
| Executive summary writing | claude-opus-4-8 |
| FP analysis / error interpretation | claude-haiku-4-5-20251001 |
| FN detection sweep | claude-haiku-4-5-20251001 |
| Evasion advice | claude-sonnet-4-6 |

Rate limit: 20 calls/min configurable. Cache: SHA-256 of finding content dedup.
Graceful degradation: no API key = rule-based heuristics, all tools still work.

---

## FP/FN Verification Per Vuln Type

| Vuln | Verification |
|------|-------------|
| SQLi (time) | 3 baselines → both probes exceed baseline+delay-1s |
| SQLi (error) | DB-specific error pattern, not generic 500 |
| XSS reflected | UUID canary must reflect exactly |
| SSTI | Math proof: {{7*7}} → 49 |
| SSRF | OOB callback OR strong internal response change |
| LFI | Known content match (root:x:0:0) |
| CMD injection | OOB callback OR unique token in output |

### FN Detection (Post-Phase Sweep)
- SQLi found → check second-order, stored SQLi
- File upload found → polyglot, double extension, null byte
- SSRF found → blind SSRF, AWS metadata, gopher
- JWT found → alg:none, weak HMAC, key confusion

---

## VPR Scoring

```
VPR = (CVSS_Base * 0.6) + (Exploit_Maturity * 0.2) + (Impact_Adjustment * 0.15) + (Asset_Criticality * 0.05)
```

| VPR | Priority | Action |
|-----|----------|--------|
| 8.0-10 | Critical | Fix within 24h |
| 5.0-7.9 | High | Fix within 7 days |
| 2.0-4.9 | Medium | Next sprint |
| 0-1.9 | Low | Backlog |

---

## Rootkit Deployment Reference

### Userland
- LD_PRELOAD (Linux) — Hook libc calls
- DLL injection (Windows) — CreateRemoteThread + QueueUserAPC
- API hooking — Inline trampoline (5-byte JMP)

### Kernel
- DKOM — EPROCESS ActiveProcessLinks unlink (Win10/Win11 offset-aware)
- BYOVD — 5 vulnerable drivers (RTCore64, dbutil_2_3, IQVW64, gdrv, WinRing0x64)

### Process Hollowing
- Classic hollowing (CreateProcess SUSPENDED + NtUnmapViewOfSection + WriteProcessMemory + SetThreadContext + ResumeThread)
- PPID spoofing via PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
- 9 legitimate hollowing targets (svchost, RuntimeBroker, dllhost, WerFault, etc.)

---

## Compliance Mappings

| Standard | Key Requirements |
|----------|-----------------|
| PCI-DSS v4.0 | Quarterly scans, ASV-approved methods, evidence preservation |
| HIPAA | Risk assessment, access controls, audit trails |
| SOC2 | Continuous monitoring, incident response, availability |
| ISO 27001 | Scope, risk treatment plan, internal audits |
| OWASP ASVS | Level 2 per app criticality |
| NIST SP 800-115 | Technical assessment methodology, finding classification |
| MITRE ATT&CK | Technique mapping, detection coverage |

---

## Dashboard UI Tokens

### Severity Colors
Critical: #DC3545 | High: #FD7E14 | Medium: #FFC107 | Low: #0D6EFD | Info: #6C757D

### Status Colors
Complete: green | In Progress: blue | Pending: gray | Failed: red | Queued: yellow

### Themes
Hacker Dark (neon green/cyan), Professional Dark (muted blue), Light (corporate)

---

## Environment Variables

```
ANTHROPIC_API_KEY          # ForgeBrain
FORGE_BRAIN_MODEL          # claude-opus-4-8 default
FORGE_BRAIN_FAST_MODEL     # claude-haiku-4-5-20251001 default
FORGE_BRAIN_RPM            # 20 default
FORGE_BRAIN_MAX_MEMORY     # 100 default
FORGE_COLLAB_DOMAIN        # OOB callback domain
FORGE_COLLAB_PORT          # 8888 default
FORGE_SHODAN_KEY           # Shodan API
FORGE_SLACK_WEBHOOK        # Slack notifications
FORGE_TEAMS_WEBHOOK        # Teams notifications
FORGE_JIRA_URL / TOKEN / PROJECT  # Jira integration
FORGE_NVD_API_KEY          # NVD rate limit
FORGE_GITHUB_TOKEN         # GitHub API rate limit
FORGE_INTEL_DB             # SQLite path override
FORGE_C2_ADMIN_PW          # C2 team server admin
FORGE_DASHBOARD_PASSWORD   # Dashboard auth (default: forge2026)
```

---

## Competitive Positioning (Know This Cold)

**vs. Nessus/Tenable**: Scanners find what's exposed; we prove what's exploitable.
We chain three findings into a domain compromise path Nessus will never show.

**vs. Acunetix/Burp Enterprise**: DAST finds known web patterns. We cover business
logic, IDOR, blind injection chains, and surfaces beyond web — cloud IAM, AD, mobile, AI.

**vs. Cobalt Strike**: CS is a C2 framework; we're a full platform. Our implant is
built for 2026 EDR — direct syscalls, sleep masking, CDN relay channels.

**vs. Pentera/NodeZero**: Pure automation cannot exploit business logic or chain
multi-step human-reasoning attacks. Our model: AI for breadth, human for depth.

**Unique differentiator**: AI/LLM/MCP security assessment — none of the above cover this.
