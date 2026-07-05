# Sprint 3 — C2 Task Expansion

## Goal
Add 12 new beacon tasks to `forge_c2/tasks/`.

## Base Pattern
Follow existing `forge_c2/tasks/base_task.py` interface. Each task needs:
- `task_type` string
- `execute(beacon, params)` method
- `validate(params)` method
- Registration in `forge_c2/tasks/__init__.py`

## New Tasks

| File | task_type | Description | MITRE |
|------|-----------|-------------|-------|
| `task_assembly.py` | `execute_assembly` | Load .NET assembly in-memory, execute, capture output | T1218 |
| `task_keylogger.py` | `keylogger` | Keyboard capture (start/stop/dump) | T1056.001 |
| `task_browser_creds.py` | `browser_creds` | Extract Chrome/Firefox/Edge saved passwords + cookies | T1555.003 |
| `task_clipboard.py` | `clipboard` | Clipboard monitoring, capture on interval | T1115 |
| `task_mimikatz.py` | `mimikatz` | In-memory Mimikatz via BOF or reflective DLL | T1003.001 |
| `task_registry.py` | `registry` | Registry CRUD: read/write/query/delete keys | T1012 |
| `task_service.py` | `service` | Service create/modify/delete/query | T1543.003 |
| `task_wmi.py` | `wmi` | WMI query/exec for enum and lateral | T1047 |
| `task_inject.py` | `inject` | Shellcode injection into target PID | T1055 |
| `task_token.py` | `token` | Token impersonation, steal, make_token, rev2self | T1134 |
| `task_portscan.py` | `portscan` | Beacon-side TCP port scan (internal recon) | T1046 |
| `task_download_exec.py` | `download_exec` | Download file from C2 and execute | T1105 |

## Operator Shell Integration
Each task needs a command registered in `forge_c2/operator_shell.py`.

## Dashboard API
Each task needs endpoints in `forge_c2/server.py`:
- `POST /api/v1/c2/beacons/{id}/tasks/{task_type}`
- Task output via existing task output endpoint

## Acceptance Criteria

- [ ] All 12 tasks registered and callable from operator shell
- [ ] Each task validates params before execution
- [ ] Task output streams to dashboard via existing WebSocket
- [ ] High-risk tasks (inject, mimikatz) gated behind engagement authorization
