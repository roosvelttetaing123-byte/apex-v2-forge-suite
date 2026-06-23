# FORGE-SUITE v5 APEX — Handoff
# Updated: 2026-06-21 | 11/25 Pillars Done | DA-1/2/3 UI Wiring Done

---

## STATUS

| # | Pillar | Status |
|---|--------|--------|
| 1 | C2 Framework | ✅ |
| 2 | Live War Room Dashboard | ✅ |
| 3 | Multi-Target Engine | ✅ |
| 4 | Post-Exploit + Rootkit | ✅ |
| 5 | Intel Pipeline | ✅ |
| 6 | Payload Generation | ✅ |
| 7 | Advanced Modules (legacy) | ❌ |
| 8 | Packaging | ✅ |
| 9 | ForgeBrain (AI) | 🟡 9G remaining: brain verdict panel in War Room |
| 10 | FP/FN Reduction | 🟡 Engine done, scanner retrofit pending |
| 11 | Modern CVE Coverage | ❌ |
| 12 | Cross-Framework Chains | ✅ (engine+chains done, wiring to AutonomousEngine pending) |
| 13 | Architecture Hardening | ❌ |
| 14 | Observability | ❌ |
| 15 | Dashboard UX | 🟡 DA-1/2/3 done, per-page polish pending |
| 16 | Headless Browser + Auth | ❌ |
| 17A | ForgeCollab OOB Server | ✅ |
| 17B | Module OOB Wiring | 🟡 ssrf+xxe done; sqli/Log4Shell/cmdi/xss remain |
| 18-25 | (Various) | ❌ |

---

## WHAT WAS BUILT THIS SESSION (2026-06-21)

### DA-1: ScanBuilder → Backend Launch
- `ScanBuilder.jsx`: "Launch Scan" → `POST /api/v1/scans/launch` with full config (target, profile, modules[], intensity, threads, timeout, rateLimit, maxDepth, followRedirects, schedule)
- On success: toast + navigate to `/` (Automated Scans) after 1.5s
- On error: red error banner with dismiss
- "Save Template" → modal → `POST /api/v1/scan/templates`; loads saved templates on mount via `GET /api/v1/scan/templates`
- `server.py`: Added `POST /api/v1/scans/launch`, `GET/POST /api/v1/scan/templates`, `DELETE /api/v1/scan/templates/{id}`, CORS middleware for dev server

### DA-2: Automated Scans — Live WebSocket Feed
- `AutomatedScans.jsx` was already fully wired (WebSocket subscriptions for scan_start/complete/failed, finding_new, brain_verdict, module_progress). No seeded demo data.
- Added: notification beep via Web Audio API on scan_complete (double beep) and scan_failed/aborted (single low beep)
- Added: `scan_failed` as explicit event handler

### DA-3: Vulnerabilities — Finding Detail Slide-Out
- `Vulnerabilities.jsx`: Complete rewrite with:
  - 40%-width animated slide-out panel on row click (`slideInRight` CSS animation)
  - Panel: severity/CVSS/VPR/confidence score boxes, description, repro steps, evidence, remediation, metadata
  - Inline status editor: 4 buttons (Open/Fixed/Accepted/False Positive) → `PATCH /api/v1/findings/{id}/status` with optimistic UI
  - Re-test button → `POST /api/v1/findings/{id}/retest` with spinner animation
  - Escape key + outside-click closes panel
  - Checkbox per row → bulk ops bar (Change Status dropdown, Export JSON, Clear Selection)
  - Live `FINDING_NEW` / `FINDING_UPDATED` WebSocket subscriptions
  - Fetches findings from `GET /api/v1/findings` on mount, falls back to rich seed data
- `server.py`: Added `PATCH /api/v1/findings/{id}/status`, `POST /api/v1/findings/{id}/retest`

### CSS Additions (index.css)
- Added `@keyframes slideIn`, `slideInRight`, `spin`, `fadeIn` — used by toast, slide-out panel, loading spinners

---

## ARCHITECTURE (unchanged — see skill.md for full details)

```
forge-suite/
├── forge.py                     # Unified launcher
├── apex-ui/                     # React UI (17 pages, Vite, port 5173)
│   └── src/pages/               # ScanBuilder, AutomatedScans, Vulnerabilities all now wired
├── common/dashboard/server.py   # FastAPI + WebSocket (port 1337) — now has CORS, templates, findings mgmt
├── common/dashboard/event_bus.py # 25+ EventTypes
├── common/brain/                # ForgeBrain AI
└── [netforge|webforge|adforge|aiforge|forge_c2|forge_collab|forge_payload]
```

### Key Backend APIs (server.py)
| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/v1/scans/start` | Launch scan (simple) |
| POST | `/api/v1/scans/launch` | Launch scan (ScanBuilder full config) |
| GET | `/api/v1/scans/history` | Scan history |
| GET/POST | `/api/v1/scan/templates` | Scan templates CRUD |
| DELETE | `/api/v1/scan/templates/{id}` | Delete template |
| GET | `/api/v1/findings` | Paginated findings |
| PATCH | `/api/v1/findings/{id}/status` | Update finding status |
| POST | `/api/v1/findings/{id}/retest` | Re-test a finding |
| POST | `/api/v1/control/pause` | Pause scan |
| POST | `/api/v1/control/resume` | Resume scan |
| POST | `/api/v1/scans/stop` | Stop all scans |
| WS | `/ws/dashboard` | Real-time events |

---

## NEXT PRIORITY — Pick from task_p1_critical.md

### Remaining P1 tasks (in order):
1. **9G**: Brain verdict panel in War Room dashboard — subscribe to BRAIN_VERDICT WS event, render verdict chips
2. **10B**: Scanner retrofit — integrate FPReducer into sqli/xss/ssti/lfi/cmdi scanners
3. **12 wiring**: Wire ChainEngine into AutonomousEngine.run_engagement() + EngagementBus.publish()
4. **16A-D**: Headless browser engine (Playwright), login recorder, API schema import, scan profiles
5. **17B remaining**: blind_sqli, Log4Shell, blind_xss, blind_cmdi OOB wiring

### P2 tasks (task_p2_important.md):
- Pillar 15F per-page feature completions
- Pillar 20 Reporting

### P3 tasks (task_p3_nicetohave.md):
- Command palette, skeleton screens, ScanBuilder enhancements

---

## DO NOT TOUCH
- `index.css` design tokens (vars are stable)
- `Sidebar.jsx` routes
- `Card.jsx` / `Button.jsx` / `Badge.jsx` base components
- `useWebSocket.js` hook (exponential backoff working)

---

## HOW TO RUN
```bash
cd forge-suite/apex-ui && npm run dev   # UI at http://localhost:5173
python forge.py dashboard              # Backend at https://localhost:1337
```

## KEY ENV VARS
```
ANTHROPIC_API_KEY, FORGE_BRAIN_MODEL=claude-opus-4-8, FORGE_COLLAB_DOMAIN
FORGE_DASHBOARD_PASSWORD, FORGE_C2_ADMIN_PW
```
