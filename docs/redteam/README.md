# Red Team Roadmap — Agent Task Index

Read ONLY the file you need. Do NOT load all files.

## Sprint Order

| Sprint | File | Summary |
|--------|------|---------|
| 0 | `sprint0-leak-intel.md` | Leak Intelligence Engine — OSINT scanners + credential testing |
| 1 | `sprint1-cloud-container.md` | Cloud API, IAM chaining, container escape, K8s attacks |
| 2 | `sprint2-chain-engine-v2.md` | Multi-hop chains, state machine, scoring, 24 new chains |
| 3 | `sprint3-c2-tasks.md` | 12 new C2 tasks (assembly, keylogger, inject, etc.) |
| 4 | `sprint4-evasion.md` | Implant evasion: sleep mask, syscalls, unhooking, spoofing |
| 5 | `sprint5-cicd-supply-chain.md` | CI/CD pipeline attacks + dependency confusion |
| 6 | `sprint6-brain-intelligence.md` | Attack graphs, EDR awareness, objective planning |
| 7 | `sprint7-macos.md` | macOS implant + TCC bypass + PKG/DMG delivery |
| 8 | `sprint8-transport-delivery.md` | DoH, WebSocket, Slack C2 + HTA/VBA/MSI/DLL delivery |
| 9 | `sprint9-reporting-opsec-exfil.md` | Reports, opsec engine, exfil pipeline |
| 10 | `sprint10-integrations-edge.md` | REST API, SIEM, Jira, IPv6, OT/ICS |
| 11 | `sprint11-scanner-depth.md` | GraphQL, advanced SSRF, gRPC, coerce, responder |

## Current Inventory (reference only)

- 10 attack chains in `common/attack_chains.py`
- C2 tasks: shell, file, screenshot, bof, socks in `forge_c2/tasks/`
- Transports: HTTP, TCP, DNS in `forge_c2/transport/`
- Listeners: HTTP, TCP, DNS in `forge_c2/listeners/`
- Evasion: BYOVD, sandbox_detect, string_obfuscate in `forge_payload/evasion/`
- Encoders: XOR, RC4, AES, UUID, polymorphic in `forge_payload/encoders/`
- Delivery: ISO, LNK, ZIP in `forge_payload/delivery/`
- Process injection: 5 emulation-only techniques in `forge_c2/emulation.py`
