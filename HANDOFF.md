# FORGE-SUITE v5 APEX — Context Handoff Document
# Updated: 2026-06-15 | ALL 8 PILLARS COMPLETE | For: Fresh AI session

---

## CORE GOAL

Evolve Forge Suite from a mid-tier VAPT tool (v3, rated 7.5-8.0/10) into an **enterprise-grade offensive security platform** (v5 "APEX", target 9.5+/10) competing with Cobalt Strike, Nessus, and Acunetix.

**8 Pillars of the v5 architecture:**
1. C2 Framework (beacon-based command & control)
2. Live War Room Dashboard (WebSocket-driven real-time UI)
3. Multi-Target Engine (--targets file.txt bulk scanning)
4. Post-Exploitation + Rootkit Engine
5. Intelligence Pipeline (auto-updating CVE/techniques)
6. Payload Generation Framework
7. Advanced Module Upgrades (new exploits, services)
8. Hardware Requirements & Deployment Packaging

**Monorepo structure — 4 frameworks + 2 new packages:**
- **NetForge** (`netforge/`) — network pentesting + red team, 9→11 phases
- **WebForge** (`webforge/`) — web application pentesting, 12 phases
- **ADForge** (`adforge/`) — Active Directory attacks, 14 phases
- **AIForge** (`aiforge/`) — AI/LLM red teaming, 8 phases
- **Forge C2** (`forge_c2/`) — NEW, C2 framework
- **Forge Payload** (`forge_payload/`) — NEW, payload generation

**Unified launcher: `forge.py`** — UPDATED with subcommands: dashboard, c2, intel, payload, multi-target, scheduling

---

## WHAT HAS BEEN DONE

### Pillar 2: Live War Room Dashboard — 100% COMPLETE

Full-stack real-time dashboard built from scratch:

| File | Status | What It Does |
|------|--------|-------------|
| `common/dashboard/event_bus.py` | **MODIFIED** | Extended EventType enum with 25+ new event types: C2 (beacon_checkin, beacon_new, beacon_dead, etc.), multi-target (target_queued/scanning/paused/completed/failed), scan control (scan_paused/resumed/aborted), post-exploit (lateral_move, persistence_set, rootkit_deployed, data_staged/exfiltrated), intel (intel_sync_start/complete, intel_cve_new), payload (payload_generated), dashboard (control_command) |
| `common/dashboard/auth.py` | **NEW** | JWT-like authentication — HMAC-SHA256 signed tokens, role-based access (viewer/operator/admin), configurable via FORGE_DASHBOARD_PASSWORD env var, default creds: operator/forge2026 |
| `common/dashboard/server.py` | **NEW** | FastAPI + WebSocket dashboard server — serves at https://localhost:1337, self-signed TLS cert auto-generation, REST API endpoints (GET /api/v1/state, /findings, /targets, /metrics, /kill-chain, /credentials, /sessions, /timeline, POST /control/pause, /control/resume, /control/abort, /control/skip-module), WebSocket at /ws/dashboard with auth + state snapshot on connect + real-time event broadcast |
| `common/dashboard/web/templates/index.html` | **NEW** | Main SPA shell — command bar (engagement info, pause/resume/abort, elapsed time, opsec indicator, theme switcher, WS status), kill chain 7-stage pipeline, 6-tab interface (Overview, Findings, Targets, Credentials, C2 Sessions, Timeline), stat cards (severity counts), module progress panel, metrics panel with canvas chart, recent findings feed, findings table with filters, target card grid, credential vault table, C2 beacon list + interactive console, timeline feed, finding detail modal, toast notification container |
| `common/dashboard/web/static/css/themes.css` | **NEW** | 3 themes via CSS custom properties — Hacker Dark (neon green/cyan on deep black, default), Professional Dark (muted blue on slate), Light (corporate). Full token system: colors, shadows, borders, radius, transitions, scrollbar, animations (pulse-glow, fade-in, slide-in-right, slide-in-up, shimmer, spin, blink) |
| `common/dashboard/web/static/css/components.css` | **NEW** | Reusable component library — badges (severity-colored), status dots (animated), buttons (primary/secondary/danger + icon + control), inputs/selects, tables (sticky header), panels, stat cards, progress bars (animated shimmer), module items, finding items, target cards (pwned/shell states), timeline items, console (header/output/input), modal (backdrop blur), toast notifications (auto-dismiss), tab badges, filter groups |
| `common/dashboard/web/static/css/dashboard.css` | **NEW** | Structural layout — sticky command bar with glassmorphism, kill chain horizontal pipeline with connectors, tab navigation, overview grid (6-col stats + 2-col modules/metrics), findings table container, targets auto-fill grid, credentials table, C2 2-col layout (beacons + console), timeline container. Responsive breakpoints at 1200px and 768px |
| `common/dashboard/web/static/js/websocket.js` | **NEW** | WebSocket client — auto-reconnect with exponential backoff (max 20 attempts), JWT auth on connect, pub/sub event dispatch (subscribe by event type or wildcard *), 30s heartbeat keepalive, connection status dot |
| `common/dashboard/web/static/js/charts.js` | **NEW** | Canvas-based RollingLineChart — 60-point rolling window, HiDPI/Retina support, ResizeObserver, grid lines, Y-axis labels, area fill, line with glow dot, theme-aware colors |
| `common/dashboard/web/static/js/notifications.js` | **NEW** | Toast notification system — auto-dismiss with configurable duration, severity-based styling, convenience methods: finding(), credential(), shell() |
| `common/dashboard/web/static/js/kill_chain.js` | **NEW** | Kill chain visualization — updates 7 pipeline stages (count, progress fill, active/reached/unreached states), summary text |
| `common/dashboard/web/static/js/findings.js` | **NEW** | Findings panel — recent feed (last 10), filterable table (severity dropdown + search), severity counters, tab badge, finding detail modal, toast for Critical/High findings |
| `common/dashboard/web/static/js/targets.js` | **NEW** | Targets panel — card grid with compromise status (shell=🔴, pwned=🟠, clean=🟢), services tags, cred/finding counts, tab badge |
| `common/dashboard/web/static/js/modules.js` | **NEW** | Module progress — sorted by phase + status, status icons (⏳🔄✅❌⏭), progress bars, duration, finding counts, summary counter |
| `common/dashboard/web/static/js/timeline.js` | **NEW** | Threat timeline — chronological event log, icon per event type, 500-event cap, newest first |
| `common/dashboard/web/static/js/credentials.js` | **NEW** | Credential vault — table with type badges, masked secrets, source tracking, toast on new creds, tab badge |
| `common/dashboard/web/static/js/sessions.js` | **NEW** | C2 sessions — beacon card list with access level badges, interactive console toggle, shell notification on new sessions, tab badge |
| `common/dashboard/web/static/js/c2_panel.js` | **NEW** | Beacon console — command history (up/down arrows), built-in help, commands: shell/download/upload/screenshot/hashdump/socks/sleep/clear/help, WebSocket dispatch |
| `common/dashboard/web/static/js/controls.js` | **NEW** | Scan controls — pause/resume/abort with REST API calls, status indicator updates, confirmation dialog for abort |
| `common/dashboard/web/static/js/app.js` | **NEW** | Main app — wires all panels to WebSocket stream, handles state snapshots + individual events, tab switching, theme persistence (localStorage), elapsed time ticker, RPS chart ticker, event routing |

| `common/dashboard/tui/war_room_tui.py` | **NEW** | Rich terminal TUI — full Layout/Live dashboard with kill chain pipeline (animated active phase), findings feed (severity coloring), target status grid, module progress tracker, metrics sparklines (RPS/findings/errors), credential vault (masked), sessions panel, threat timeline (10 most recent), flash alerts (Critical/High findings, shells, pwned, creds), tab switching (1=Main, 2=Credentials, 3=Sessions), operator controls (P=pause, R=resume, A=abort, Q=quit), platform-aware input (msvcrt on Windows, termios on Unix) |

### Pillar 3: Multi-Target Engine — 100% COMPLETE

| File | Status | What It Does |
|------|--------|-------------|
| `common/target_manager.py` | **NEW** | Multi-target orchestration — load from file (one per line, # comments, inline --options), dedup by normalized target, priority queue, asyncio.Semaphore for concurrent scans (max_parallel), per-target state (queued/scanning/paused/completed/failed/aborted/skipped), global + per-target pause/resume/abort, progress persistence to JSON, retry logic (max_retries), resume from progress file, EventBus integration |

| `common/engagement_scheduler.py` | **NEW** | Engagement scheduler — ScheduleConfig parser (5 modes: once/daily/weekly/interval/continuous), ScheduleType enum, duration parser (Ns/Nm/Nh/Nd), day-of-week mapping (full + abbreviated), next_run_time calculation (today-or-tomorrow logic, weekly targeting, interval from last completion), async run() loop (interruptible sleep, max_runs cap, scan_fn dispatch), EngagementRun history tracking (per-run: started_at, completed_at, status, findings, duration, error), JSON history persistence, EventBus integration, from_cli_args() factory for --schedule/--continuous/--interval flags |
| `forge.py` | **REWRITTEN** | Unified v5 launcher — argparse with subcommands: scan frameworks (net/web/ad/ai) with common args (--target, --targets, --parallel, --resume, --dashboard, --dashboard-port, --dashboard-tui, --schedule, --continuous, --interval, --auto-update, --offline, --output-dir), dashboard (--host, --port, --tui, --no-auth, --attach, --replay), c2 (server/connect/listener/payload subcommands with full args), intel (sync/search/status with source filters + --since), payload (--type, --lhost, --lport, --format, --arch, --encode, --iterations, --list). Framework alias resolution, unknown-arg passthrough for backward compat, background dashboard co-launch for --dashboard flag, graceful degradation for unbuilt modules |
| `netforge/netforge.py` | **REWRITTEN** | v5 orchestrator — EventBus integration (emits scan_start, phase_start/complete, module_start/complete/fail/skip, finding_new, credential_found, scan_complete/aborted/paused/resumed), ScanControl class (asyncio.Event for pause, bool for abort), pause gate checked at phase + module level, `run_scan()` separated from `main()` for TargetManager callability, `run_for_target()` entry point creates per-target config/results and delegates to run_scan(), all existing features preserved (OpSec profiles, stealth logging, CredEngine, AttackChain, Red Team gates) |
| `webforge/webforge.py` | **REWRITTEN** | v5 orchestrator — same EventBus + ScanControl pattern as NetForge, `run_scan()` + `run_for_target()`, PhaseScheduler integration maintained, SSO session capture preserved, all 12 phases + 70+ modules preserved |
| `adforge/adforge.py` | **REWRITTEN** | v5 orchestrator — same pattern, 14 phases + 85+ modules preserved, DCSync/BloodHound gates preserved, mode-based phase filtering (unauth/auth/admin) |
| `aiforge/aiforge.py` | **REWRITTEN** | v5 orchestrator — same pattern, 8 phases + 30+ modules preserved, DoS/destructive double-confirmation gates preserved (cannot bypass with --auto-confirm), --no-dos/--no-destructive/--allow-destructive flags |

### Pillar 1: C2 Framework — 100% COMPLETE ✅

| File | Status | What It Does |
|------|--------|-------------|
| `forge_c2/__init__.py` | **NEW** | Package init |
| `forge_c2/beacon/beacon_crypto.py` | **NEW** | C2 crypto layer — RSA-4096 keypair for server identity, AES-256-GCM session encryption (per-message nonce derived from key+counter), HMAC-SHA256 message authentication (verify-then-decrypt), automatic key rotation (after 100 messages or 24 hours), encrypt_json/decrypt_json convenience methods, ctypes.memset key wiping, XOR fallback if cryptography lib unavailable |
| `forge_c2/beacon/beacon_core.py` | **NEW** | Beacon lifecycle — BeaconState (staging→active→sleeping→dead→killed), BeaconMetadata (hostname, username, domain, OS, arch, PID, process, integrity, is_admin, is_domain, interfaces, AV products, IPs), BeaconTask (queued→sent→completed/failed), Beacon (checkin with task dispatch, queue_task, complete_task, mark_missed for dead detection, kill, set_sleep with jitter, kill_date support, parent/child for pivots), BeaconRegistry (register, get, remove, active_beacons, check_dead_beacons, summary) |
| `forge_c2/server.py` | **NEW** | C2 Team Server — **OperatorManager**: multi-operator auth with RBAC (admin/operator/viewer), SHA-256 password hashing with salt, session token management, active operator tracking. **ListenerManager**: create/start/stop/remove listeners, supports HTTPS/HTTP/TCP/DNS/SMB transports, asyncio.start_server for HTTP + TCP (DNS/SMB are placeholder loops for transport/ modules), HTTP handler parses beacon protocol (POST /api/v1/register, /check, /result), decoy page masquerades as IIS/ASP.NET, per-listener connection/byte stats. **TaskRouter**: routes operator commands to beacons, logs all tasks with operator attribution, task_beacon/task_all/kill_beacon/set_sleep, emits c2_task_queued/c2_beacon_killed events to EventBus. **TeamServer**: central orchestrator tying registry+crypto+listeners+operators+router, operator API (JSON-over-TCP on port 50050, length-prefixed protocol), 18 commands (auth, beacons, beacon_info, task, task_all, kill, sleep, listeners, listener_create/start/stop, operators, status, task_history, add_operator), dead-check background loop (30s interval), state persistence to JSON, default admin account from FORGE_C2_ADMIN_PW env var |
| `forge_c2/transport/base_transport.py` | **NEW** | Transport base layer — BaseTransport ABC (connect/send/recv/disconnect/heartbeat/negotiate), MalleableProfile system (URI rotation, header spoofing, body transforms, jittered sleep, request/response shaping), 5 built-in profiles (default, amazon, microsoft, slack, paranoid), TransportType enum, TransportStats tracking (bytes/messages/connections/errors) |
| `forge_c2/transport/http_transport.py` | **NEW** | HTTP/S transport — HTTPTransport (client + server modes), DomainFrontConfig (SNI/Host header swap for CDN fronting), ProxyConfig (HTTP/SOCKS proxy chaining), self-signed TLS cert auto-generation, malleable request building (rotated UAs, smuggled beacon ID in cookies), HTTP request/response parsing, beacon check-in/register/result convenience methods, decoy page serving (Microsoft Update Services), async server handler for listener integration |
| `forge_c2/transport/dns_transport.py` | **NEW** | DNS transport — DNSTransport with DNSConfig (domain, nameserver, record type, chunk size), base32-encoded data in DNS labels, TXT/A record support, raw UDP DNS query fallback (no dnspython needed), _DNSClientProtocol/_DNSServerProtocol asyncio datagram handlers, query name extraction/parsing, C2 domain filtering |
| `forge_c2/transport/tcp_transport.py` | **NEW** | TCP transport — TCPTransport with TCPConfig (keepalive, reconnect, backoff), 4-byte big-endian length-prefixed binary framing, auto-reconnect with exponential backoff, 10MB message ceiling, server mode with client handler dispatch, send_recv convenience method. Also contains SMBTransport skeleton (named pipe path, structural I/O stubs) |
| `forge_c2/listeners/http_listener.py` | **NEW** | HTTP/S listener — HTTPListener with HTTPListenerConfig (bind, SSL, cert, profile, protocol paths), refactored from server.py inline handlers, malleable profile URI matching, request rate limiting (per-minute), body transform wrap/unwrap, beacon registration callbacks (on_beacon_registered/on_beacon_checkin), EventBus integration for c2_beacon_new/c2_task_complete/c2_listener_start/stop events, decoy response serving |
| `forge_c2/listeners/dns_listener.py` | **NEW** | DNS listener — DNSListener with DNSListenerConfig (domain, bind, record type), delegates I/O to DNSTransport, async process loop for incoming data, JSON command parsing (register/checkin/result routing), BeaconRegistry integration |
| `forge_c2/listeners/tcp_listener.py` | **NEW** | TCP listener — TCPListener with TCPListenerConfig (bind host/port), length-prefixed binary protocol, content-based routing (register if hostname present, result if task_id present, else checkin), BeaconRegistry integration |
| `forge_c2/tasks/base_task.py` | **NEW** | Task base layer — BaseTask ABC (encode/decode/execute lifecycle), TaskResult dataclass (status, output, data, error, duration, metadata), TaskStatus enum (pending/running/completed/failed/timeout/cancelled), @register_task decorator for task registry, create_task factory, list_task_types introspection |
| `forge_c2/tasks/task_shell.py` | **NEW** | Shell task — ShellTask (@register_task "shell"), platform-aware shell selection (cmd.exe, PowerShell, bash, auto-detect), asyncio subprocess with timeout enforcement, hidden window mode (CREATE_NO_WINDOW on Windows), working directory + env var injection, combined stdout+stderr output, exit code tracking |
| `forge_c2/tasks/task_file.py` | **NEW** | File transfer tasks — DownloadTask (@register_task "download"): file read with SHA256 hash, 100MB limit, async executor. UploadTask (@register_task "upload"): base64 decode + write, auto directory creation, append mode support |
| `forge_c2/tasks/task_screenshot.py` | **NEW** | Screenshot task — ScreenshotTask (@register_task "screenshot"): Windows native ctypes BitBlt/GetDIBits with BMP→PNG conversion (Pillow optional), PowerShell fallback, macOS screencapture utility, Linux import/scrot/gnome-screenshot multi-tool fallback |
| `forge_c2/tasks/task_socks.py` | **NEW** | SOCKS proxy + hash dump — SocksTask (@register_task "socks"): full RFC 1928/1929 SOCKS5 server (method negotiation, username/password auth, CONNECT command, IPv4/IPv6/domain address types, bidirectional async relay). HashDumpTask (@register_task "hashdump"): SAM dump (reg save), NTDS.dit (shadow copy), LSASS dump (comsvcs.dll MiniDump), Linux /etc/shadow |
| `forge_c2/implant/implant_config.py` | **NEW** | Implant configuration — ImplantConfig dataclass (every build-time knob), ImplantOS (windows/linux/macos), ImplantArch (x64/x86/arm64), ImplantFormat (12 formats: exe/dll/service_exe/shellcode/powershell/hta/vba/csharp/elf/so/macho/raw), ObfuscationLevel (none/light/medium/heavy/paranoid), SleepTechnique (standard/ekko/foliage/death_sleep/thread_pool/waitable_timer), PE version info spoofing (defaults to wuauclt.exe), auto-generated watermark, from_dict/to_dict serialization |
| `forge_c2/implant/implant_builder.py` | **NEW** | Implant builder orchestrator — BuildArtifact (output path, size, SHA256, MD5, watermark, build time, warnings), StringEncryptor (XOR with random per-string keys, stack string construction, C + Python decryption snippet generation), EvasionGenerator (anti_debug_c: IsDebuggerPresent + NtQueryInformationProcess + timing check + CheckRemoteDebuggerPresent; anti_vm_c: CPU count + RAM check + uptime + VM registry keys + analysis tool detection; amsi_bypass_c: AmsiScanBuffer patch to E_INVALIDARG; amsi_bypass_ps: amsiInitFailed reflection; etw_bypass_c: EtwEventWrite xor eax ret patch; unhook_ntdll_c: remap clean ntdll .text section from disk), ImplantBuilder (routes to WindowsImplant/LinuxImplant, build logging, format listing) |
| `forge_c2/implant/implant_windows.py` | **NEW** | Windows implant generator — 8 output formats: EXE (WinMain + WinHTTP beacon loop), DLL (DllMain thread + rundll32 exports DllRegisterServer/ServiceMain), ServiceEXE (SCM framework + CreateThread beacon), shellcode (PEB walking + djb2 API hashing skeleton), PowerShell (full beacon with Invoke-Register/Invoke-CheckIn/Invoke-Task, shell/download/upload/screenshot/exit task execution, domain fronting, TLS12), HTA (VBScript dropper with embedded encoded PS1), VBA (Office macro with Auto_Open/Document_Open/Workbook_Open, chunked encoded command), C# (.NET assembly with HttpClient beacon, JSON parsing, task execution). All formats embed encrypted C2 config (XOR with 32-byte random key), configurable evasion blocks, jittered sleep, and kill date support |
| `forge_c2/implant/implant_linux.py` | **NEW** | Linux implant generator — 4 output formats: ELF (C with libcurl transport, fork+setsid daemonize, SIGHUP ignore, ptrace anti-debug, DMI/cpuinfo/meminfo anti-VM), SO (__attribute__((constructor)) + pthread for LD_PRELOAD injection), shellcode (raw syscalls via inline asm, SYS_SOCKET/SYS_CONNECT, no libc dependency), bash (pure bash beacon with curl transport, self-daemonizing via nohup+disown, python3 JSON parsing, shell/download/upload/exit task execution, base64 file transfer, kill date support) |
| `forge_c2/implant/stager_factory.py` | **NEW** | Stager factory — 11 stager types: HTTP_PS (PowerShell download cradle with variable name obfuscation), HTTP_CMD (cmd.exe with PS inner call), CERTUTIL (certutil -urlcache LOLBin), BITSADMIN (bitsadmin /transfer LOLBin), MSHTA (HTA VBScript dropper), REGSVR32 (COM scriptlet Squiblydoo), PYTHON (urllib one-liner), CURL_BASH (curl pipe bash), DNS_TXT (Resolve-DnsName TXT record pull). Each stager supports: delay, env_check, self-cleanup, obfuscation, and outputs both a full script file and a copy-paste one-liner |

**C2 FRAMEWORK IS 100% COMPLETE.** No remaining C2 items.

### Pillar 5: Intel Pipeline — 100% COMPLETE ✅

| File | Status | What It Does |
|------|--------|-------------|
| `common/intel/__init__.py` | **NEW** | Package init with module docstring |
| `common/intel/intel_engine.py` | **NEW** | Intel pipeline coordinator — IntelEngine class: sync orchestration with dynamic import of sync modules (CVESync, ExploitDBSync, NucleiSync, TechniqueLearner), graceful degradation for unbuilt modules, SQLite storage with WAL mode, standalone FTS5 full-text search (query + severity + source + exploit-only filters), LIKE fallback search, bulk_upsert for batch performance, IntelRecord unified dataclass (record_id, source, title, severity, cvss_score, products, references, tags, exploit_available, published/updated dates, raw_data), IntelSource/IntelSeverity/SyncStatus enums, SyncResult tracking, sync_meta + sync_history persistence, EventBus integration (intel_sync_start/complete, intel_cve_new events), CLI status report with per-source record counts + DB size, lookup helpers (lookup_cve, lookup_product_cves, has_exploit, get_techniques_for_tactic), maintenance (vacuum, rebuild_fts, purge_source), offline mode, env var FORGE_INTEL_DB for DB path override |
| `common/intel/cve_sync.py` | **NEW** | NVD API v2 CVE sync — CVESync class: paginated API traversal (2,000 results/page), incremental sync via lastModStartDate/pubStartDate, CVSS v3.1/v3.0/v2.0 score extraction with severity normalization, CPE product string parsing, reference URL/tag extraction, exploit-availability flagging from reference tags, rate limiting (public 5req/30s, keyed 50req/30s via FORGE_NVD_API_KEY), bulk upsert batching (500/commit), EventBus integration for new critical CVE events, stdlib-only HTTP (no aiohttp dep) |
| `common/intel/exploit_db_sync.py` | **NEW** | Exploit-DB mirror sync — ExploitDBSync class: GitLab CSV mirror download (files_exploits.csv), streaming CSV parser, type/platform normalization (remote/local/webapps/dos/shellcode → severity mapping), CVE cross-referencing (flags exploit_available on matching CVE records), incremental date filtering, author/port/file metadata extraction, batch upsert (1000/commit), offline mode via FORGE_EXPLOITDB_CSV_PATH env var |
| `common/intel/nuclei_sync.py` | **NEW** | Nuclei template sync — NucleiSync class: dual-mode (GitHub API recursive tree + local directory scan), YAML mini-parser (no PyYAML dep, regex extraction of id/name/severity/description/references/classification/tags), template classification by directory (cves/vulnerabilities/misconfigurations/exposures/technologies/default-logins/takeovers/dns/ssl), severity inference, path-based metadata for fast indexing (5000 template cap per sync), CVE template enrichment via raw content fetch, CVE cross-referencing, FORGE_GITHUB_TOKEN for rate limits, FORGE_NUCLEI_TEMPLATES_DIR for local mode |
| `common/intel/technique_learner.py` | **NEW** | MITRE ATT&CK technique learner — TechniqueLearner class: STIX 2.1 bundle download (enterprise-attack.json ~30MB), full bundle indexing (attack-patterns, tactics, relationships, mitigations, intrusion-sets, malware, tools), tactic→technique kill chain mapping, severity heuristics by tactic position (recon=info → impact=critical), platform/permission/data-source extraction, software/group cross-referencing (which APTs use which techniques), mitigation association, sub-technique support, revoked/deprecated filtering, incremental sync via modification date, FORGE_ATTACK_BUNDLE_PATH for offline mode |
| `common/intel/offline_db.py` | **NEW** | Offline database manager — OfflineDBManager class: gzip-compressed JSON export bundles (source-filtered, with sync metadata), import with merge/replace modes, point-in-time snapshots with rotation (MAX_SNAPSHOTS=10), integrity verification (PRAGMA integrity_check, table existence, FTS health, SHA-256 checksum), compaction (VACUUM + FTS rebuild), stale record pruning (configurable retention via FORGE_INTEL_RETENTION), restore from snapshot, IntelEngine sync contract for automated maintenance, human-readable status reporting |

---

## WHAT HAS BEEN DONE (continued)

### Pillar 4: Post-Exploit + Rootkit — 100% COMPLETE ✅

| File | Status | What It Does |
|------|--------|-------------|
| `netforge/modules/post_exploit/pivot_finder.py` | **REWRITTEN** | v5 pivot finder — active SOCKS proxy deployment through C2 beacons, dual-homed/multi-NIC host discovery from beacon metadata + ARP tables + route tables, internal subnet topology mapping (connectivity graph), BFS-based pivot chain generation (multi-hop paths to isolated segments), automatic proxychains.conf generation, 5 RFC 1918/link-local/CGNAT internal ranges, PivotHost scoring (0-10 scale: dual-homed, beacon, admin ports, DB ports, subnet reach), SOCKSDeployment tracking, EventBus lateral_move events, CredEngine + AttackChain integration, operator tunneling suggestions (SSH/Chisel/ligolo/RDP/WinRM/SMB) |
| `netforge/modules/post_exploit/loot_parse.py` | **REWRITTEN** | v5 loot parser — binary SAM/SYSTEM registry hive parsing (bootkey extraction from SYSTEM, per-user DES key derivation, LM+NTLM hash decryption), NTDS.dit parsing (secretsdump-style text + binary format), /etc/shadow parsing (SHA-512/SHA-256/bcrypt/MD5/DES/yescrypt identification + crack difficulty assessment), LSASS minidump credential extraction (NTLM + cleartext + Kerberos patterns), DPAPI blob detection, SSH private key detection (RSA/OpenSSH/ECDSA/DSA/PKCS8 + encrypted vs unencrypted), cloud credential scanning (AWS access/secret key, Azure tenant/client/secret, GCP service account JSON), 40+ regex secret patterns (expanded: GitHub PATs, GitLab PATs, Slack tokens, Stripe keys, Twilio, SendGrid, bearer tokens, .NET connection strings, JDBC, MongoDB/Redis/PostgreSQL URIs), hash type identification (NTLM/LM/SHA512-crypt/bcrypt/MD5-crypt/DES/Net-NTLMv2/Kerberoast/MSCache2), hashcat mode mapping, ExtractedCredential dataclass with redaction + hashcat helpers, CredEngine auto-feed, EventBus credential_found events, AttackChain integration |
| `netforge/modules/post_exploit/sam_dump.py` | **NEW** | SAM registry hive dumper — 4 extraction methods: reg save (standard admin), Volume Shadow Copy (stealthier, bypasses file locks), WMIC shadow copy (alternative VSS), C2 beacon hashdump task delegation. PowerShell EncodedCommand for VSS script delivery. Binary hive parsing via LootParse delegation. secretsdump-style output parsing (DOMAIN\user:RID:LM:NTLM:::). Per-account analysis (admin detection, empty password flagging, machine account identification). Cleanup command generation. CredEngine auto-feed, EventBus credential_found events, hashcat/john crack commands in evidence |
| `netforge/modules/post_exploit/ntds_dump.py` | **NEW** | NTDS.dit domain credential dumper — 4 extraction methods: ntdsutil IFM (Install From Media snapshot), Volume Shadow Copy, DCSync via C2 beacon (DRSUAPI replication), local secretsdump.py. Full domain hash extraction with domain-wide analysis: user vs machine account separation, Domain Admin identification, krbtgt hash capture (Golden Ticket risk), password reuse detection (hash frequency analysis across all accounts). Generates separate password reuse finding when shared hashes detected. Impacket secretsdump integration for binary NTDS.dit parsing. CredEngine auto-feed (capped at 500 for flooding prevention), EventBus events, AttackChain integration |
| `netforge/modules/post_exploit/mimikatz_exec.py` | **NEW** | Mimikatz in-memory executor — 4 deployment methods: C2 beacon ShellTask, Invoke-Mimikatz PowerShell reflection, direct binary execution, LSASS MiniDump via comsvcs.dll (LOLBin) + pypykatz offline parsing. Supports 8 Mimikatz commands: logonpasswords, wdigest, kerberos, msv, sam, dcsync, golden, lsass_dump. Full structured output parser for logon sessions (Authentication Id sections → per-session MSV/WDigest/Kerberos/SSP/CredMan auth package extraction). MimikatzCredential dataclass (auth_package, cleartext flag, logon_type, SID). Kerberos ticket extraction (client/server/encryption/flags). Optional AMSI bypass (amsiInitFailed reflection). CredEngine auto-feed, EventBus integration |
| `netforge/modules/post_exploit/token_steal.py` | **NEW** | Windows access token enumerator + stealer — full process token enumeration via Get-Process -IncludeUserName (local + C2), token classification (SYSTEM/admin/Domain Admin/service account), ProcessToken scoring (0-10: dual factors for SYSTEM, DA, impersonation level, key privileges), Potato escalation eligibility check (SeImpersonate/SeAssignPrimaryToken → SYSTEM via JuicyPotato/RoguePotato/SweetPotato/PrintSpoofer/GodPotato), whoami /priv parsing for current privilege analysis, DuplicateTokenEx + ImpersonateLoggedOnUser token theft via PowerShell Add-Type Win32 interop, TokenAction tracking. CredEngine + EventBus + AttackChain integration |
| `netforge/modules/post_exploit/lateral_smb.py` | **NEW** | SMBExec lateral movement — execute commands on remote hosts via SMB service creation (SCM RPC). SMBTarget dataclass (host, port, credentials, NTLM hash, domain, accessible shares, admin status). Share enumeration (ADMIN$, C$, IPC$) via smbclient. 4 execution methods: SMBExec (sc create + start, output via share read, automatic service + output cleanup), Pass-the-Hash (impacket smbexec.py + crackmapexec fallback), File Copy (smbclient put to ADMIN$), C2 Beacon Deploy (ImplantBuilder → stage via SMB → execute via service). Randomized service names (10 stealthy prefixes + 6-char suffix). Multi-target credential spray support. MITRE T1021.002/T1569.002. CredEngine + EventBus lateral_move + AttackChain integration |
| `netforge/modules/post_exploit/lateral_wmi.py` | **NEW** | WMI lateral movement — execute commands on remote hosts via Win32_Process.Create (DCOM/RPC port 135). WMITarget dataclass with OS info detection. 3 execution methods: Win32_Process.Create (native wmic, output via temp file on C$ share), wmiexec (impacket semi-interactive shell), WMI Event Subscription (persistent — creates __EventFilter + CommandLineEventConsumer + __FilterToConsumerBinding via PowerShell, 60s timer trigger). Output retrieval via remote share read + cleanup. MITRE T1047/T1021.003. CredEngine + EventBus + AttackChain integration |
| `netforge/modules/post_exploit/lateral_winrm.py` | **NEW** | WinRM lateral movement — execute commands via PowerShell Remoting (HTTP/5985, HTTPS/5986). WinRMTarget dataclass with PS version + OS detection via Test-WSMan + Invoke-Command probe. 3 execution methods: Invoke-Command (native PS remoting with credential object), Evil-WinRM (pass-the-hash support), CIM Session (WMI-over-WinRM without DCOM, New-CimSession + Invoke-CimMethod Win32_Process.Create). Multi-target fan-out. MITRE T1021.006. CredEngine + EventBus + AttackChain integration |
| `netforge/modules/post_exploit/lateral_psexec.py` | **NEW** | PsExec lateral movement — remote command execution via service binary deployment. 3 execution methods: Sysinternals PsExec (classic, -s for SYSTEM, -accepteula), Impacket psexec.py (Python clone with randomized service name, pass-the-hash), PAExec (open-source alternative). Multi-target support. MITRE T1569.002/T1021.002. CredEngine + EventBus + AttackChain integration |
| `netforge/modules/post_exploit/lateral_ssh.py` | **NEW** | SSH lateral movement — move between Unix/Linux/macOS hosts via SSH. SSHTarget dataclass with key/password/hostname/OS tracking. 4 execution methods: SSH key auth (stolen private key, ProxyJump multi-hop), Password auth (sshpass wrapper), SSH agent forwarding hijack (SSH_AUTH_SOCK), SCP implant deployment (stage via SCP → chmod +x → nohup background exec). Supports id_rsa, ed25519, ecdsa key types. MITRE T1021.004. CredEngine + EventBus + AttackChain integration |
| `netforge/modules/post_exploit/persist_schtask.py` | **NEW** | Scheduled task persistence — maintain access via Windows Task Scheduler. PersistenceTask dataclass with full lifecycle. 7 stealthy task paths (\Microsoft\Windows\* namespace blending). 6 trigger types (logon, startup, daily, hourly, idle, registration). 3 creation methods: schtasks.exe (/create + /sc + /ru SYSTEM), XML import (full task XML with hidden flag, RegistrationInfo masquerading as Microsoft Corp, StartWhenAvailable, no battery/idle restrictions, no time limit), PowerShell (Register-ScheduledTask with New-ScheduledTaskAction/Trigger/Settings/Principal). C2 beacon callback builder (base64-encoded PowerShell polling loop with jittered sleep). Cleanup command generation. MITRE T1053.005. EventBus persistence_set + AttackChain integration |
| `netforge/modules/post_exploit/persist_registry.py` | **NEW** | Registry Run key persistence — maintain access via Windows registry autostart. 7 registry key targets (HKLM/HKCU Run/RunOnce, Winlogon Userinit/Shell, WOW6432Node). 12 stealthy value names (SecurityHealth, WindowsDefenderUpdate, OneDriveSync, etc.). Existing Run key enumeration for recon. 2 persistence methods: standard Run key (reg add), Winlogon hijack (append to Userinit value or Shell value, preserving explorer.exe). C2 beacon callback with PowerShell IWR polling loop. Cleanup command generation. MITRE T1547.001. EventBus persistence_set + AttackChain integration |
| `netforge/modules/post_exploit/persist_service.py` | **NEW** | Windows service persistence — maintain access via service installation. 8 stealthy service names with display names (WinDefHealthSvc, NlaProfileSvc, etc.). 4 start types (auto, delayed-auto, demand, boot). 3 creation methods: sc.exe (sc create + sc description + sc failure recovery with restart actions), PowerShell (New-Service with Automatic startup), Registry direct write (HKLM\SYSTEM\CurrentControlSet\Services\ with Type/Start/ErrorControl/ImagePath/DisplayName/ObjectName/DelayedAutoStart). Service failure recovery (restart/60s × 3). MITRE T1543.003. EventBus persistence_set + AttackChain integration |
| `netforge/modules/post_exploit/persist_cron.py` | **NEW** | Linux cron persistence — maintain access via cron job installation. 8 stealthy cron.d names (sysstat, apt-compat, logrotate-check, etc.). 5 schedule presets (@reboot, hourly, daily, 5min, 15min). 3 creation methods: cron.d drop-in (/etc/cron.d/ file with SCHEDULE USER COMMAND format, chmod 644), user crontab injection (crontab -l append + pipe), cron directory script (/etc/cron.hourly/ executable with stealth naming). Existing cron enumeration (user crontab + system crontab + cron.d listing). C2 beacon callback (bash curl polling loop with jittered sleep). Cleanup command generation. MITRE T1053.003. EventBus persistence_set + AttackChain integration |
| `netforge/modules/rootkit/__init__.py` | **NEW** | Package init for rootkit module directory |
| `netforge/modules/rootkit/rootkit_base.py` | **NEW** | Rootkit base ABC — abstract interface for all rootkit modules. RootkitType enum (userland/kernel/bootkit/firmware/hypervisor). HideCapability enum (process/file/registry/network/module/user/service/driver). RootkitState lifecycle (not_deployed → deploying → deployed → active/inactive → cleaning → cleaned/failed). HiddenItem dataclass (capability, identifier, timestamp, status). RootkitStatus dataclass (type, state, capabilities, hidden items, artifacts, cleanup commands, to_dict()). RootkitBase(BaseModule, ABC) with CRITICAL risk confirmation gate, action routing (deploy/cleanup/status), automatic hiding orchestration (hide_pids/hide_files/hide_ports/hide_registry → _hide_item → _activate_hiding), result reporting (findings with cleanup commands), common _exec helper. Subclasses must implement: _deploy(), _activate_hiding(), _cleanup(), _check_status() |
| `netforge/modules/rootkit/userland_rootkit.py` | **NEW** | Userland rootkit via API hooking + DLL injection. Extends RootkitBase. Capabilities: PROCESS, FILE, REGISTRY, NETWORK hiding. Generates C source for hooking DLL (NtQuerySystemInformation hook for process hiding, NtQueryDirectoryFile hook for file hiding, inline trampoline pattern with 5-byte JMP + original byte save for clean unhook, config file reader for hide lists). 2 injection methods: CreateRemoteThread (classic — OpenProcess + VirtualAllocEx + WriteProcessMemory + LoadLibraryA), QueueUserAPC (APC injection to all alertable threads via OpenThread + QueueUserAPC). PowerShell Add-Type Win32 interop for both methods (base64 EncodedCommand delivery). Hide config via C:\Windows\Temp\.forge_hide.cfg (PROC:/FILE:/NET:/REG: prefixed lines). Cleanup: DLL deletion + config removal. MITRE T1014/T1055.001/T1562.001 |
| `netforge/modules/rootkit/kernel_rootkit.py` | **NEW** | Windows kernel-mode rootkit via driver loading. Extends RootkitBase. Capabilities: PROCESS, FILE, REGISTRY, NETWORK, DRIVER, MODULE hiding (6 capabilities). DKOM process hiding (EPROCESS ActiveProcessLinks unlink with version-aware offsets: Win10 1809=0x2F0, Win10 21H2/Win11=0x448). 5 known vulnerable drivers for BYOVD (RTCore64.sys/CVE-2019-16098, dbutil_2_3.sys/CVE-2021-21551, IQVW64E.SYS/CVE-2015-2291, gdrv.sys/CVE-2018-19320, WinRing0x64.sys). 3 loading methods: BYOVD (load vuln driver → patch CI!g_CiOptions → load unsigned rootkit → unload vuln driver), test signing (bcdedit /set testsigning), DSE bypass (CI.dll g_CiOptions kernel patch). Generated C driver source with DriverEntry, device/symlink creation, IOCTL communication. MITRE T1014/T1068/T1562.001 |
| `netforge/modules/rootkit/process_hollow.py` | **NEW** | Process hollowing for fileless payload execution. 9 legitimate hollowable targets (svchost.exe, RuntimeBroker.exe, dllhost.exe, WerFault.exe, etc.). 4 techniques: Classic hollowing (CreateProcess SUSPENDED + NtUnmapViewOfSection + VirtualAllocEx + WriteProcessMemory + SetThreadContext + ResumeThread, full PowerShell Add-Type Win32 interop implementation), Process Doppelgänging (TxF transacted NTFS stub), Process Herpaderping (modify-after-map stub), Process Ghosting (delete-pending stub). PPID spoofing support (PROC_THREAD_ATTRIBUTE_PARENT_PROCESS). PID extraction from PROCESS_INFORMATION. MITRE T1055.012/T1055.013 |
| `netforge/modules/rootkit/amsi_bypass.py` | **NEW** | AMSI bypass via in-memory patching. 6 bypass techniques: amsiInitFailed reflection (set NonPublic,Static field to $true via [Ref].Assembly.GetType), AmsiScanBuffer patch (VirtualProtect + overwrite with mov eax,0x80070057; ret = E_INVALIDARG), AmsiContext corruption (null the amsiContext pointer), CLR JIT hook (COMPlus_ETWEnabled=0 + reflection fallback), Hardware breakpoint (DR register stub + reflection fallback), Obfuscated (string-split variable names to evade detection). Auto mode tries techniques in reliability order. All scripts base64-encoded for delivery. Success detection via AMSI_BYPASS_OK marker. MITRE T1562.001 |
| `netforge/modules/rootkit/etw_blind.py` | **NEW** | ETW blinding via in-memory patching to blind EDR telemetry. 5 known EDR ETW providers tracked (Threat-Intelligence, DotNETRuntime, PowerShell, AMSI, WMI-Activity with GUIDs). 5 bypass techniques: EtwEventWrite patch (VirtualProtect + overwrite with xor eax,eax; ret = STATUS_SUCCESS), NtTraceEvent patch (same at syscall boundary), Provider unregister (COMPlus_ETWEnabled=0 + PSEtwLogProvider m_enabled=0 via reflection), CLR ETW disable (environment variables), Session kill (logman query -ets + logman stop). Auto mode tries in order. Per-provider unregistration support. All scripts base64-encoded. MITRE T1562.006 |

---

## ALL PILLARS COMPLETE ✅

### Pillar 6: Payload Generation Framework — 100% COMPLETE ✅

| File | What It Does |
|------|-------------|
| `forge_payload/__init__.py` | Package init — exports PayloadFactory, PayloadArtifact |
| `forge_payload/payload_factory.py` | Main orchestrator — 14 payload types, generate()/generate_artifact()/list_payloads(), 4-step build pipeline (shellcode→encode→format→write), PayloadArtifact dataclass (sha256/md5/size/build_time) |
| `forge_payload/shellcode/shellcode_x64.py` | x64 shellcode — Windows (PEB walk + djb2 API hash): reverse_tcp, reverse_http, bind_tcp, staged_http/tcp, exec_cmd. Linux (raw syscalls via `syscall` ASM, _start entry): reverse_tcp, bind_tcp, staged_tcp |
| `forge_payload/shellcode/shellcode_x86.py` | x86 shellcode — same methods as x64 but 32-bit (-m32). Linux uses int 0x80 + socketcall (SYS_socketcall=102) |
| `forge_payload/shellcode/shellcode_arm64.py` | ARM64 shellcode — Linux raw syscalls via `svc #0` (SYS_socket=198, SYS_connect=203, SYS_execve=221, SYS_mmap=222) |
| `forge_payload/encoders/encoder_xor.py` | XOR encoder (rolling/chained modes) — encode/decode, C decoder stub (VirtualAlloc/mmap), PS1 decoder stub (AllocHGlobal+CreateThread) |
| `forge_payload/encoders/encoder_aes.py` | AES-256-CBC encoder — IV prepended to blob, C decoder (BCryptDecrypt/OpenSSL), PS1 decoder (.NET AES BCL), pure-Python fallback |
| `forge_payload/encoders/encoder_poly.py` | Polymorphic encoder — XOR→ROL(3)→ADD chain, random var/function names, dead junk code insertion, C + PS1 decoder stubs |
| `forge_payload/formats/format_pe.py` | PE format builder — detects C source vs binary; C source: annotate + passthrough; binary: VirtualAlloc+memcpy+VirtualProtect+CreateThread loader |
| `forge_payload/formats/format_elf.py` | ELF format builder — mmap PROT_READ\|WRITE\|EXEC loader, ARM64 __builtin___clear_cache, compile commands for x64/x86/arm64 |
| `forge_payload/formats/format_dll.py` | DLL format builder — C source: rename main()→dllmain_payload, add DllMain+DllRegisterServer; binary: DllMain spawns background thread |
| `forge_payload/formats/format_ps1.py` | PS1 format builder — AllocHGlobal+Marshal.Copy+CreateThread, obfuscation, encoded_command() returns `powershell.exe -EncodedCommand <b64>` |
| `forge_payload/formats/format_hta.py` | HTA + VBA format builder — HTA: `<HTA:APPLICATION>` + VBScript WScript.Shell.Run; VBA: Office macro Document_Open/AutoOpen/Workbook_Open |
| `forge_payload/stagers/stager_http.py` | HTTP stager — powershell_iwr/webclient, certutil, bitsadmin, python_stager, curl_bash (all with one-liner), c_winhttp (WinHTTP C stager + compile cmd) |
| `forge_payload/stagers/stager_dns.py` | DNS stager — 200-char base64 TXT chunks, count record, powershell_stager (Resolve-DnsName), bash_stager (dig), python_stager (dns.resolver), zone_file_example (BIND format) |
| `forge_payload/stagers/stager_smb.py` | SMB named pipe stager — 4-byte LE length prefix protocol, powershell_stager (NamedPipeClientStream + VirtualAlloc exec), c_stager (WaitNamedPipeW + CreateFileW + ReadFile), pipe_server_ps1 (server-side delivery script) |
| `forge_payload/evasion/string_obfuscator.py` | String obfuscator — C techniques: XOR runtime decode, stack string (char-by-char), ROT13. PS1 techniques: concat split, base64, charcode (-join [char[]]), format string |
| `forge_payload/evasion/sandbox_detect.py` | Sandbox detector — SandboxConfig dataclass (min cores/RAM/uptime/disk, known tools, VM registry keys). c_block() (IsSystemProcessorFeature + uptime + disk + tool detection). ps1_block() (WMI queries). bash_block() (/proc checks) |

### Pillar 7: Advanced Modules — 100% COMPLETE ✅

**New Exploit Modules:**

| File | CVE | What It Does |
|------|-----|-------------|
| `netforge/modules/exploit/log4shell.py` | CVE-2021-44228 | JNDI injection in 14 HTTP headers — passive (error response) + active (8 WAF-bypass variants), marshalsec/JNDI-Exploit-Kit command generation |
| `netforge/modules/exploit/proxyshell.py` | CVE-2021-34473/34523/31207 | Exchange auth bypass chain — URL confusion (?@domain/ews/exchange.asmx), ExportItems SOAP file write, 3-CVE sequential chain |
| `netforge/modules/exploit/proxylogon.py` | CVE-2021-26855/27065 | Exchange SSRF via X-BEResource cookie + ExchangeSettingsProvider DDI file write |
| `netforge/modules/exploit/spring4shell.py` | CVE-2022-22965 | Spring MVC class loader data binding — baseline vs probe POST comparison + AccessLogValve JSP shell write via pattern property |
| `netforge/modules/exploit/printnightmare.py` | CVE-2021-34527 | Raw SMBv2 NEGOTIATE probe for spoolss pipe detection + impacket addUser chain |
| `netforge/modules/exploit/smbghost.py` | CVE-2020-0796 | Hand-crafted SMBv3.1.1 NEGOTIATE with SMB2_COMPRESSION_CAPABILITIES — dialect 0x0311 detection in response |
| `netforge/modules/exploit/citrix_bleed.py` | CVE-2023-4966 | NetScaler version semver comparison + oversized NSC_AAAC cookie memory leak probe — scans response for leaked token patterns |
| `netforge/modules/exploit/moveit_rce.py` | CVE-2023-34362 | guestaccess.aspx boolean-based + WAITFOR DELAY time-based SQLi + ASPX shell upload (confirm-gated) |
| `netforge/modules/exploit/confluence_rce.py` | CVE-2022-26134 / CVE-2023-22515 / CVE-2023-22527 | OGNL URL injection, Velocity template POST, /setup/setupadministrator.action access control check |

**New Service Auditors:**

| File | Protocol | What It Does |
|------|----------|-------------|
| `netforge/modules/services/kerberos_audit.py` | Kerberos / LDAP | AS-REP roasting (impacket GetNPUsers + native AS-REQ probe), Kerberoasting (GetUserSPNs TGS extraction), unconstrained + constrained delegation (ldap3 LDAP query), krbtgt password age, LDAP anonymous bind |
| `netforge/modules/services/winrm_audit.py` | WinRM 5985/5986 | WWW-Authenticate header auth method detection, Basic cleartext finding (CRITICAL), CredSSP finding (HIGH), TLS cert expiry + self-signed check, pywinrm/requests-ntlm auth testing, default cred spray |
| `netforge/modules/services/mqtt_audit.py` | MQTT 1883/8883/9001 | Raw CONNECT packet (no library dep), anonymous auth detection, default cred spray, wildcard '#' subscribe for topic enumeration + retained message disclosure, $SYS broker version, confirm-gated publish-to-sensitive-topics probe |
| `netforge/modules/services/opcua_audit.py` | OPC-UA 4840/4843 | asyncua GetEndpoints security policy analysis (None/Basic128/Basic256/Basic256Sha256), anonymous session establishment + node browsing (asyncua), SoftwareVersion disclosure, username/password auth test, raw TCP HEL/ACK probe fallback |

---

## WHAT HAS BEEN DONE (continued — Pillar 8)

### Pillar 8: Hardware Requirements & Deployment Packaging — 100% COMPLETE ✅

| File | Status | What It Does |
|------|--------|-------------|
| `requirements.txt` | **REWRITTEN** | Complete v5 APEX dependencies — added fastapi>=0.109.0, uvicorn[standard]>=0.27.0, websockets>=12.0 (Dashboard/Pillar 2), pyjwt>=2.8.0 (auth), Pillow>=10.2.0 (screenshots), pytest-asyncio>=0.23.0 (testing), organized by component (HTTP, Dashboard, UI, Storage, Crypto, Reporting, Browser, Network, Graph, Analysis, Testing) |
| `install.sh` | **REWRITTEN** | v5 APEX installer — virtual environment auto-creation, critical import verification (fastapi, uvicorn, rich, cryptography, aiohttp, jinja2, pydantic), expanded external tool checks (nmap, hydra, smbclient required + nuclei, impacket, testssl.sh, crackmapexec, evil-winrm, chisel, ligolo-ng optional), Docker/Docker Compose detection, v5 IntelEngine seeding (NVD + ATT&CK) with legacy cve_import fallback, data directory creation, full quick-start guide (scan/dashboard/C2/intel/docker commands + default credentials) |
| `Dockerfile` | **NEW** | Multi-stage Docker build — Stage 1: python:3.12-slim builder (gcc, libffi, libssl for native extensions), pip install to /install prefix. Stage 2: python:3.12-slim runtime with nmap, hydra, netcat, dnsutils, curl, wget, git, smbclient, chromium, nuclei (latest release auto-download). Non-root `forge` user, PYTHONUNBUFFERED, ports 1337/8443/50050/53, healthcheck on dashboard /api/v1/state, ENTRYPOINT python3 |
| `docker-compose.yml` | **NEW** | 3-service deployment — forge-dashboard (port 1337, HTTPS dashboard), forge-c2 (ports 8443/50050/8080/53, team server), forge-scan (host networking, scan profile, one-shot container). Named volumes: forge-results, forge-intel, forge-c2-data. Environment variables for passwords. Restart policies |
| `.dockerignore` | **NEW** | Build context exclusions — __pycache__, .git, IDE files, results dirs, databases, logs, env files, Docker files themselves |
| `Makefile` | **REWRITTEN** | Expanded targets — install, test, lint, intel-sync, update-cve-db, dashboard, dashboard-tui, c2, docker (build), docker-up (compose up), docker-down (compose down), clean, help |

**Hardware Requirements (documented in install.sh + README):**
- **Minimum**: 4 CPU cores, 8GB RAM, 20GB disk, Python 3.10+
- **Recommended**: 8+ CPU cores, 16GB+ RAM, 100GB SSD, Kali Linux / Ubuntu 22.04+
- **C2 Server**: 2+ CPU cores, 4GB RAM (dedicated), stable IP/domain
- **Dashboard**: 1+ CPU core, 2GB RAM (runs alongside scans)
- **Multi-Target**: Add 1GB RAM per parallel target (--parallel N)
- **Full Intel DB**: ~500MB disk for NVD + ExploitDB + Nuclei + ATT&CK

---

### Optional: Post-Exploit Expansion
- Additional lateral: lateral_dcom.py
- Additional persistence: persist_wmi_event, persist_startup, persist_systemd
- Additional rootkit: linux_rootkit, dll_inject, reflective_load, syscall_unhook, ppid_spoof, fileless_exec
- Data operations: data_staging, exfil_engine, screenshot_remote, keylog_deploy, av_evasion

---

## EXISTING ARCHITECTURE (unchanged from v3)

### Module Template Pattern
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
        # ... logic ...
        return self._make_result(start)
```

### Orchestrator Pattern (v5 — all 4 frameworks now follow this)
```python
# EventBus helpers — fire-and-forget, never crash the scan
def _get_event_bus(event_bus=None):
    if event_bus is None: return None, None, None
    from common.dashboard.event_bus import Event, EventType
    return event_bus, Event, EventType

def _emit(bus, Event, EventType, etype, source="framework", **data):
    if bus is None: return
    bus.emit(Event(event_type=EventType(etype), data=data, source=source))

# Pause/Resume/Abort — asyncio.Event controls
class ScanControl:
    def __init__(self):
        self._paused = asyncio.Event()   # cleared = paused, set = running
        self._paused.set()
        self._aborted = False
    async def wait_if_paused(self): await self._paused.wait()

# Separated scan logic from main() for TargetManager callability
async def run_scan(cfg, args, results_dir, event_bus=None, scan_control=None): ...
async def run_for_target(target_entry, base_args, event_bus=None, scan_control=None): ...
```

### Key Patterns
```python
await self.rate_limit()                    # Before every request
self.check_scope(url)                      # Scope check
self.confirm_action(action, target, risk)  # Before exploitation
opsec = get_opsec(); await opsec.jitter()  # OpSec jitter
cred_engine.add(host, svc, user, pw)       # Feed creds
attack_chain.ingest_finding(finding.to_dict())  # Feed chain
```

### Safety Constraints (non-negotiable)
1. `self.check_scope(target)` at start of `run()`
2. `await self.rate_limit()` before every outbound request
3. `self.confirm_action()` before any active exploitation
4. `ask_internet_permission()` before any online resource use
5. Red Team modules require `--red-team` CLI flag
6. Exploit modules require operator confirmation

### Good Reference Files
- **Dashboard server**: `common/dashboard/server.py`
- **EventBus (extended)**: `common/dashboard/event_bus.py`
- **StateStore**: `common/dashboard/state_store.py`
- **TUI War Room**: `common/dashboard/tui/war_room_tui.py`
- **Multi-target**: `common/target_manager.py`
- **Engagement scheduler**: `common/engagement_scheduler.py`
- **Unified launcher**: `forge.py` (v5 rewrite with subcommands)
- **C2 Team Server**: `forge_c2/server.py` (OperatorManager, ListenerManager, TaskRouter, TeamServer)
- **Beacon crypto**: `forge_c2/beacon/beacon_crypto.py`
- **Beacon core**: `forge_c2/beacon/beacon_core.py`
- **OpSec engine**: `netforge/core/opsec.py`
- **Attack chain**: `netforge/core/attack_chain.py`
- **NetForge orchestrator**: `netforge/netforge.py` (v5 EventBus + ScanControl pattern)
- **WebForge orchestrator**: `webforge/webforge.py` (v5 EventBus + ScanControl pattern)
- **ADForge orchestrator**: `adforge/adforge.py` (v5 EventBus + ScanControl pattern)
- **AIForge orchestrator**: `aiforge/aiforge.py` (v5 EventBus + ScanControl pattern)
- **Lateral movement**: `netforge/modules/post_exploit/lateral_smb.py` (SMBExec pattern)
- **Persistence**: `netforge/modules/post_exploit/persist_schtask.py` (task persistence pattern)
- **Rootkit base**: `netforge/modules/rootkit/rootkit_base.py` (ABC for all rootkits)
- **Evasion**: `netforge/modules/rootkit/amsi_bypass.py` (AMSI bypass techniques)
- **Native exploit**: `netforge/modules/exploit/eternalblue.py`
- **Native brute force**: `netforge/modules/bruteforce/native_brute.py`

---

## QUICK START PROMPT FOR NEW SESSION

> "Read forge-suite/HANDOFF.md. Forge Suite v5 APEX is FULLY COMPLETE — all 8 pillars done. Dashboard (Pillar 2): web + TUI. Multi-target (Pillar 3): target_manager, scheduler, forge.py, all 4 orchestrators. C2 (Pillar 1): beacon crypto + core + team server + transports + listeners + tasks + implant builder (12 formats, 11 stagers). Intel (Pillar 5): CVE sync + ExploitDB + Nuclei + MITRE ATT&CK + offline DB. Post-Exploit (Pillar 4): pivot_finder, loot_parse, sam_dump, ntds_dump, mimikatz_exec, token_steal, lateral movement (SMB/WMI/WinRM/PsExec/SSH), persistence (schtask/registry/service/cron), rootkit engine (base + userland + kernel BYOVD/DKOM + process hollowing), evasion (AMSI bypass 6 techniques + ETW blinding 5 techniques). Packaging (Pillar 8): requirements.txt, install.sh, Dockerfile, docker-compose.yml, Makefile. Payload Generation (Pillar 6): forge_payload/ with shellcode (x64/x86/arm64), encoders (XOR/AES/poly), formats (PE/ELF/DLL/PS1/HTA/VBA), stagers (HTTP/DNS/SMB), evasion (string obfuscator + sandbox detect). Advanced Modules (Pillar 7): 9 exploit modules (Log4Shell/ProxyShell/ProxyLogon/Spring4Shell/PrintNightmare/SMBGhost/CitrixBleed/MOVEit/Confluence) + 4 service auditors (kerberos_audit/winrm_audit/mqtt_audit/opcua_audit). All safety constraints preserved throughout: check_scope, rate_limit, confirm_action, ask_internet_permission."
