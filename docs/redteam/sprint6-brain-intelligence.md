# Sprint 6 — Brain Intelligence Upgrades

## Goal
Make the autonomous planner think like a red teamer, not a module sequencer.

## Files to Modify
- `common/brain/planner.py` — attack planning upgrades
- `common/brain/autonomous.py` — engagement intelligence
- `common/brain/brain.py` — core brain upgrades

## Features to Build

### 1. Attack Graph Model
Build real-time graph: nodes = assets/states, edges = attack techniques.
- Use NetworkX (in-memory, no external DB needed)
- Node types: `host`, `credential`, `service`, `domain_object`, `cloud_resource`
- Edge types: each attack technique with `P(success)` weight
- Query: shortest path from current position to objective
- Update graph as findings come in

### 2. Defensive Awareness
When scan detects EDR/AV (Defender, CrowdStrike, SentinelOne, Carbon Black):
- Auto-adjust `opsec_level` to STEALTH
- Select evasion techniques matching detected product
- Modify scan timing (slow down, add jitter)
- Avoid known-detected techniques for that EDR
- Store EDR detection in `EngagementState`

### 3. Objective-Driven Planning
Set engagement goal (e.g., "reach Domain Admin", "exfil customer DB", "access CEO mailbox").
- Planner works backward from objective to current position
- Identifies required chain of techniques
- Prioritizes actions that advance toward objective
- Reports progress as % toward goal

### 4. Detection Risk Scoring
For each action, estimate P(detection):
- Map technique → known EDR detections
- Show operator risk/reward matrix before execution
- Accumulate "noise score" across engagement
- Alert when noise budget exceeded

### 5. Threat Model Matching
Pre-built APT emulation profiles:
- APT29 (Cozy Bear): phishing → stolen creds → lateral via WMI
- FIN7: spear-phish → backdoor → POS targeting
- APT28 (Fancy Bear): credential harvesting → OAuth abuse
- Operator selects profile → planner auto-selects matching TTPs

### 6. Leak-Driven Prioritization
If OSINT finds leaked creds, re-prioritize:
- Move credential testing to top of action queue
- Deprioritize scanning that could alert defenders
- Fast-path: leak → test → access → establish persistence

## Acceptance Criteria

- [ ] Attack graph builds from scan findings
- [ ] Shortest-path query returns valid technique chain
- [ ] EDR detection triggers automatic opsec adjustment
- [ ] Objective progress reported as percentage
- [ ] At least 3 APT profiles available
