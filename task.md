# Forge Suite v5 APEX — Task Index

## Instructions (DO THIS, NO QUESTIONS, NO SUMMARIES)

1. **Read `skill.md`** — Learn codebase patterns. Do NOT summarize it back.
2. **Read `HANDOFF.md`** — Learn current state. Do NOT summarize it back.
3. **Open the highest-priority task file that still has uncompleted tasks** (`task_p1_critical.md` → `task_p2_important.md` → `task_p3_nicetohave.md`).
4. **Pick the next 3 uncompleted `[ ]` tasks and BUILD THEM.** No asking which ones. No listing options. Just start coding.
5. **After building, mark each completed task `[x]`** in the priority file.
6. **Update `HANDOFF.md`** with what was built and what's next.
7. **Do NOT output a summary table, do NOT ask "want me to start?", do NOT waste tokens on fluff.** Just work.

## Completed Pillars (archived — all done ✅)
- Pillar 1: C2 Framework
- Pillar 2: Live War Room Dashboard
- Pillar 3: Multi-Target Engine
- Pillar 4: Post-Exploit + Rootkit
- Pillar 5: Intel Pipeline
- Pillar 8: Packaging

## Active Task Files

| File | Priority | Pillars |
|------|----------|---------|
| `task_p1_critical.md` | 🔴 CRITICAL | 9, 10, 12, 16, 17 |
| `task_p2_important.md` | 🟡 IMPORTANT | 6, 7, 11, 13, 15, 18, 20, 22 |
| `task_p3_nicetohave.md` | 🟢 NICE-TO-HAVE | 14, 19, 21, 23, 24, 25 |

---

## APEX Dashboard UI — Next Builds
# All 17 pages exist and render. DA-1/DA-2/DA-3 live-data wiring DONE (2026-06-21).
# See `HANDOFF_DASHBOARD.md` for full page-by-page status.

| Priority | Where | What |
|----------|-------|------|
| 🟡 P2 | `task_p2_important.md` → **Pillar 15F** | Per-page feature completions (Discovery graph, C2 live, Reports export, etc.) |
| 🟢 P3 | `task_p3_nicetohave.md` → **DP-1, DP-2, DP-3** | Command palette, skeleton screens, ScanBuilder enhancements |

**ScanBuilder rebuilt 2026-06-21** — fully interactive with 37 modules across 5 tabs, severity filters, live counts, working intensity slider, schedule toggle, follow-redirects toggle. Backend wiring (DA-1) DONE — launches scans, saves templates.
