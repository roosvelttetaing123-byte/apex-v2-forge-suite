# Forge Suite v5 APEX — Build Tasks

## Pillar 2: Live War Room Dashboard — COMPLETE ✅
- [x] Update EventBus with new event types (C2, multi-target, controls)
- [x] Create dashboard auth (`common/dashboard/auth.py`)
- [x] Create dashboard backend (`common/dashboard/server.py`)
- [x] Create dashboard frontend HTML (`common/dashboard/web/templates/index.html`)
- [x] Create theme CSS (`common/dashboard/web/static/css/themes.css`)
- [x] Create component CSS (`common/dashboard/web/static/css/components.css`)
- [x] Create dashboard layout CSS (`common/dashboard/web/static/css/dashboard.css`)
- [x] Create WebSocket client JS (`common/dashboard/web/static/js/websocket.js`)
- [x] Create charts JS (`common/dashboard/web/static/js/charts.js`)
- [x] Create notifications JS (`common/dashboard/web/static/js/notifications.js`)
- [x] Create kill chain JS (`common/dashboard/web/static/js/kill_chain.js`)
- [x] Create findings JS (`common/dashboard/web/static/js/findings.js`)
- [x] Create targets JS (`common/dashboard/web/static/js/targets.js`)
- [x] Create modules JS (`common/dashboard/web/static/js/modules.js`)
- [x] Create timeline JS (`common/dashboard/web/static/js/timeline.js`)
- [x] Create credentials JS (`common/dashboard/web/static/js/credentials.js`)
- [x] Create sessions JS (`common/dashboard/web/static/js/sessions.js`)
- [x] Create C2 panel JS (`common/dashboard/web/static/js/c2_panel.js`)
- [x] Create controls JS (`common/dashboard/web/static/js/controls.js`)
- [x] Create app.js main wiring (`common/dashboard/web/static/js/app.js`)
- [x] Create TUI war room (`common/dashboard/tui/war_room_tui.py`)

## Pillar 3: Multi-Target Engine — COMPLETE ✅
- [x] Create target manager (`common/target_manager.py`)
- [x] Create engagement scheduler (`common/engagement_scheduler.py`)
- [x] Rewrite forge.py with v5 subcommands + multi-target + dashboard
- [x] Wire EventBus + multi-target + pause/resume into `netforge/netforge.py`
- [x] Wire EventBus + multi-target + pause/resume into `webforge/webforge.py`
- [x] Wire EventBus + multi-target + pause/resume into `adforge/adforge.py`
- [x] Wire EventBus + multi-target + pause/resume into `aiforge/aiforge.py`

## Pillar 1: C2 Framework — 100% COMPLETE ✅
- [x] Create C2 package (`forge_c2/__init__.py`)
- [x] Create beacon crypto (`forge_c2/beacon/beacon_crypto.py`)
- [x] Create beacon core + registry (`forge_c2/beacon/beacon_core.py`)
- [x] Create C2 team server (`forge_c2/server.py`) — OperatorManager (RBAC), ListenerManager (HTTP/TCP/DNS/SMB), TaskRouter, TeamServer w/ operator JSON-over-TCP API, beacon protocol handlers, dead-check loop, state persistence
- [x] Create operator shell (`forge_c2/operator_shell.py`)
- [x] Create transport base + HTTP/DNS/TCP/SMB (`forge_c2/transport/`) — BaseTransport ABC, MalleableProfile system (5 profiles: default/amazon/microsoft/slack/paranoid), HTTPTransport (domain fronting, proxy chaining, SSL), DNSTransport (TXT/A record encoding, raw UDP fallback), TCPTransport (length-prefixed binary framing), SMBTransport (named pipe skeleton), TransportStats tracking
- [x] Create listeners (`forge_c2/listeners/`) — HTTPListener (refactored from server.py, malleable profile routing, rate limiting, body transforms, beacon callbacks), DNSListener (query parsing, TXT record C2), TCPListener (binary protocol handler)
- [x] Create C2 tasks (`forge_c2/tasks/`) — BaseTask ABC with registry/factory pattern, ShellTask (cmd/powershell/bash, timeout, hidden window), DownloadTask (file read + SHA256 hash), UploadTask (base64 decode + write), ScreenshotTask (Windows ctypes BitBlt + PowerShell fallback, macOS screencapture, Linux import/scrot), SocksTask (full SOCKS5 RFC 1928/1929, auth, IPv4/IPv6/domain, bidirectional relay), HashDumpTask (SAM/NTDS/LSASS/shadow dump methods)
- [x] Create implant builder (`forge_c2/implant/`) — ImplantConfig (12 output formats, 6 sleep techniques, 5 obfuscation levels, 10+ evasion flags), ImplantBuilder orchestrator with StringEncryptor (XOR + stack strings + C/Python codegen) and EvasionGenerator (anti-debug, anti-VM, AMSI bypass, ETW bypass, ntdll unhooking), WindowsImplant (8 formats: EXE/DLL/ServiceEXE/shellcode/PowerShell/HTA/VBA/C#, each with full beacon loop + WinHTTP transport + encrypted config + evasion), LinuxImplant (4 formats: ELF/SO/shellcode/bash, with libcurl transport + daemonize + ptrace anti-debug + DMI anti-VM), StagerFactory (11 stager types: HTTP PS/CMD cradles, certutil/bitsadmin/mshta/regsvr32 LOLBins, Python, curl|bash, DNS TXT pull, each with one-liner output)

## Pillar 5: Intel Pipeline — 100% COMPLETE ✅
- [x] Create intel engine (`common/intel/intel_engine.py`) — IntelEngine coordinator (sync orchestration, FTS5 search, SQLite storage, bulk upsert, CVE/product lookup, EventBus integration, offline mode, CLI status reporting)
- [x] Create CVE sync (`common/intel/cve_sync.py`) — NVD API v2 paginated client (CVSS v3.1/v3.0/v2.0 extraction, CPE product parsing, exploit-availability flagging, rate limiting, incremental sync via lastModStartDate, bulk upsert batching)
- [x] Create Exploit-DB sync (`common/intel/exploit_db_sync.py`) — GitLab CSV mirror (streaming parser, type/platform normalization, CVE cross-referencing, severity heuristics, incremental date filtering, batch upsert)
- [x] Create Nuclei sync (`common/intel/nuclei_sync.py`) — GitHub API + local directory modes (recursive tree traversal, YAML mini-parser, template classification by directory, severity inference, CVE cross-referencing, path-based metadata extraction)
- [x] Create technique learner (`common/intel/technique_learner.py`) — MITRE ATT&CK STIX 2.1 bundle parser (attack-pattern/tactic/relationship/mitigation indexing, kill chain phase mapping, severity heuristics by tactic, software/group cross-referencing, sub-technique support, incremental sync via modified date)
- [x] Create offline DB manager (`common/intel/offline_db.py`) — Database lifecycle manager (gzip JSON export/import with merge/replace modes, point-in-time snapshots with rotation, integrity verification with SHA-256/FTS health, VACUUM compaction, stale record pruning, IntelEngine sync contract for automated maintenance)

## Pillar 4: Post-Exploit + Rootkit — 100% COMPLETE ✅
- [x] Rewrite pivot_finder.py (active SOCKS deployment, subnet topology, pivot chains, proxychains gen)
- [x] Rewrite loot_parse.py (SAM/SYSTEM/NTDS hive parsing, shadow, LSASS, DPAPI, cloud creds, SSH keys)
- [x] Create new post-exploit modules (sam_dump, ntds_dump, mimikatz_exec, token_steal)
- [x] Create lateral movement modules (lateral_smb, lateral_wmi, lateral_winrm, lateral_psexec, lateral_ssh)
- [x] Create persistence modules (persist_schtask, persist_registry, persist_service, persist_cron)
- [x] Create rootkit base + userland + kernel modules (rootkit_base, userland_rootkit, kernel_rootkit, process_hollow)
- [x] Create evasion modules (amsi_bypass, etw_blind)

## Pillar 6: Payload Generation — 100% COMPLETE ✅
- [x] Create payload factory (`forge_payload/payload_factory.py`) — PayloadFactory + PayloadArtifact, 14 payload types
- [x] Create shellcode templates (`forge_payload/shellcode/`) — x64 (Windows PEB walk + Linux raw syscall), x86 (int 0x80), arm64 (svc #0)
- [x] Create encoders (`forge_payload/encoders/`) — XOR (rolling/chained + C/PS1 decoder stubs), AES-256-CBC (BCrypt/OpenSSL + .NET), Polymorphic (XOR→ROL→ADD, random var names, junk code)
- [x] Create format builders (`forge_payload/formats/`) — PE (VirtualAlloc loader), ELF (mmap exec), DLL (DllMain thread), PS1 (AllocHGlobal+CreateThread), HTA + VBA (Office macros)
- [x] Create stagers (`forge_payload/stagers/`) — HTTP (IWR/WebClient/certutil/bitsadmin/python/curl/WinHTTP), DNS (TXT 200-char chunks + PS1/bash/python), SMB (named pipe 4-byte protocol)
- [x] Create evasion modules (`forge_payload/evasion/`) — StringObfuscator (XOR/stack/rot C + concat/base64/charcode PS1), SandboxDetect (cores/RAM/uptime/disk/tools/registry + C/PS1/bash blocks)

## Pillar 7: Advanced Modules — 100% COMPLETE ✅
- [x] Log4Shell exploit (`netforge/modules/exploit/log4shell.py`) — CVE-2021-44228, 14-header JNDI fuzzing + 8 WAF-bypass variants
- [x] ProxyShell exploit (`netforge/modules/exploit/proxyshell.py`) — CVE-2021-34473/34523/31207, Exchange auth bypass + file write chain
- [x] ProxyLogon exploit (`netforge/modules/exploit/proxylogon.py`) — CVE-2021-26855/27065, SSRF via X-BEResource cookie + file write
- [x] Spring4Shell exploit (`netforge/modules/exploit/spring4shell.py`) — CVE-2022-22965, class loader data binding + AccessLogValve JSP shell
- [x] PrintNightmare exploit (`netforge/modules/exploit/printnightmare.py`) — CVE-2021-34527, spoolss pipe probe + impacket chain
- [x] SMBGhost exploit (`netforge/modules/exploit/smbghost.py`) — CVE-2020-0796, raw SMBv3 compression negotiate probe
- [x] CitrixBleed exploit (`netforge/modules/exploit/citrix_bleed.py`) — CVE-2023-4966, NSC_AAAC oversized cookie memory leak
- [x] MOVEit RCE exploit (`netforge/modules/exploit/moveit_rce.py`) — CVE-2023-34362, boolean + time-based SQLi + ASPX shell upload
- [x] Confluence RCE exploit (`netforge/modules/exploit/confluence_rce.py`) — CVE-2022-26134/CVE-2023-22515/CVE-2023-22527
- [x] Kerberos audit (`netforge/modules/services/kerberos_audit.py`) — AS-REP roasting, Kerberoasting, delegation, krbtgt age, LDAP anon
- [x] WinRM audit (`netforge/modules/services/winrm_audit.py`) — 5985/5986 auth methods, Basic cleartext, CredSSP, TLS, cred spray
- [x] MQTT audit (`netforge/modules/services/mqtt_audit.py`) — 1883/8883 anonymous auth, wildcard subscribe, $SYS enum, publish ACL
- [x] OPC-UA audit (`netforge/modules/services/opcua_audit.py`) — 4840/4843 SecurityMode=None, anonymous session, node browsing, raw TCP probe

## Pillar 8: Packaging — 100% COMPLETE ✅
- [x] Update requirements.txt (added fastapi, uvicorn, websockets, pyjwt, Pillow, pytest-asyncio)
- [x] Update install.sh (venv, import verification, expanded tool checks, intel seeding, Docker detection, quick-start guide)
- [x] Create Dockerfile (multi-stage build, python:3.12-slim, nmap/hydra/nuclei/chromium, non-root user, healthcheck)
- [x] Create docker-compose.yml (dashboard + C2 + scan services, named volumes, env vars)
- [x] Create .dockerignore
- [x] Update Makefile (15 targets: install/test/lint/intel-sync/dashboard/c2/docker/clean/help)
- [x] Update HANDOFF.md (Pillar 8 documented, quick start updated, header updated)
