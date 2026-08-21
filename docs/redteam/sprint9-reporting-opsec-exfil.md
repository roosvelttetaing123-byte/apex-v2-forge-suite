# Sprint 9 — Reporting, Opsec & Exfiltration

## Goal
Professional reporting, operational security engine, and exfiltration pipeline.

## Reporting (`common/reporting/` upgrade)

1. **`report_generator.py`** — Automated pentest report:
   - Word (.docx) and PDF output
   - Sections: Executive summary, methodology, findings (CVSS scored), remediation, appendices
   - Auto-embed screenshots, request/response evidence, attack chain diagrams
   - Template-driven (customizable per client)

2. **`timeline_viewer.py`** — Attack timeline:
   - Chronological event log: discovery → exploit → lateral → objective
   - Export as HTML interactive timeline
   - Client debrief format

3. **`loot_dashboard.py`** — Centralized loot view:
   - All creds, sessions, screenshots, files in one place
   - Searchable, filterable by target/engagement/type

4. **`evidence_locker.py`** — Auto-capture per finding:
   - Screenshot, command output, PCAP snippet, request/response
   - Link evidence to finding ID

5. **`executive_summary.py`** — Auto-generate narrative:
   - "From initial access to Domain Admin in 47 minutes via 3 hops"
   - Path visualization with time annotations

## Opsec Engine (`forge_suite/opsec/`)

1. **`noise_budget.py`** — Track total SIEM events generated per engagement. Alert operator at configurable threshold.
2. **`timing_controller.py`** — Randomized intervals: uniform, gaussian, poisson distributions. Anti-pattern-matching.
3. **`cleanup_manager.py`** — Auto-remove: created accounts, persistence mechanisms, registry keys, dropped files, event log entries.
4. **`rollback.py`** — Full engagement rollback: clean everything and vanish on detection.

## Exfiltration Pipeline (`forge_suite/exfil/`)

1. **`smart_exfil.py`** — Rate-limited, encrypted, chunked exfil via DNS/HTTP/Cloud API.
2. **`data_staging.py`** — Auto-compress + encrypt loot before exfil.
3. **`exfil_tunnel.py`** — Multi-hop relay: victim → staging host → C2 → external drop.
4. **`cover_tracks.py`** — Selectively wipe traces after exfil complete.

## Acceptance Criteria

- [ ] Report generator produces Word doc with findings, evidence, remediation
- [ ] Timeline shows chronological attack path
- [ ] Noise budget alerts at threshold
- [ ] Cleanup manager removes all persistence artifacts
- [ ] Smart exfil transfers data without triggering DLP
