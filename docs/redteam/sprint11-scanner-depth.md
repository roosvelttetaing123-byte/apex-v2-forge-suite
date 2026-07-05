# Sprint 11 — Scanner Offensive Depth

## Goal
Fill remaining web and network scanner gaps. Lowest priority — existing scanners are solid.

## Web Modules (`webforge/modules/`)

| File | Location | Description |
|------|----------|-------------|
| `graphql_scanner.py` | `injection/` | Full GraphQL audit: introspection leak, batching abuse, injection via variables, DoS via deep nesting |
| `cors_exploit.py` | `advanced/` | CORS exploitation: origin reflection, null origin, subdomain wildcard, credential theft |
| `ssrf_advanced.py` | `injection/` | DNS rebinding, IPv6 bypass, redirect chains, protocol smuggling (gopher://, dict://) |
| `websocket_inject.py` | `advanced/` | WebSocket message injection, cross-site WebSocket hijacking |
| `http2_smuggling.py` | `advanced/` | HTTP/2-specific smuggling: h2c upgrade, CRLF in pseudo-headers, desync via content-length |
| `grpc_audit.py` | `api/` | gRPC service reflection, method enumeration, message fuzzing |
| `path_traversal_advanced.py` | `injection/` | Null byte, double encoding, unicode normalization, ..%c0%af bypasses |
| `prototype_pollution_exploit.py` | `advanced/` | PP → RCE chains: __proto__ → constructor → process.mainModule |

## Network Modules (`netforge/modules/`)

| File | Location | Description |
|------|----------|-------------|
| `coerce_attacks.py` | `exploit/` | Unified coerce: PetitPotam + PrinterBug + DFSCoerce + ShadowCoerce with auto-relay to NTLM relay module |
| `responder_emulation.py` | `internal/` | LLMNR/NBT-NS/MDNS poisoning detection + emulation |
| `ipv6_attacks.py` | `internal/` | IPv6 MITM via SLAAC, DHCPv6 spoofing, RA flooding |
| `wifi_audit.py` | `external/` | 802.11 deauth detection, WPA handshake capture, evil twin (requires wireless adapter) |
| `snmp_exploit.py` | `exploit/` | SNMP community brute + config extraction + device RCE |

## Acceptance Criteria

- [ ] graphql_scanner detects introspection + injection in test fixture
- [ ] ssrf_advanced demonstrates DNS rebinding technique
- [ ] coerce_attacks unifies existing PetitPotam/PrinterBug modules
- [ ] All modules follow base_module interface
