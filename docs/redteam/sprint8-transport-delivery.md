# Sprint 8 — Transport & Delivery Expansion

## Goal
Add 6 C2 channels + 6 delivery builders.

## New C2 Transports (`forge_c2/transport/`)

Follow `forge_c2/transport/base_transport.py` interface.

| File | Transport | Stealth |
|------|-----------|---------|
| `doh_transport.py` | DNS-over-HTTPS via Cloudflare/Google DoH endpoints | HIGH |
| `websocket_transport.py` | Persistent WebSocket connection, blends with web traffic | HIGH |
| `slack_transport.py` | Slack API as C2 channel (bot token + channel messages) | HIGH |
| `teams_transport.py` | Teams API as C2 channel | HIGH |
| `icmp_transport.py` | ICMP echo request/reply tunnel | MEDIUM |
| `smb_pipe_transport.py` | Real SMB named pipe relay (upgrade from emulation-only) | HIGH |

Each transport needs:
- `send(data)` and `recv()` methods
- Encryption layer (already in base_transport)
- Jitter/sleep support
- Corresponding listener in `forge_c2/listeners/`

## New Delivery Builders (`forge_payload/delivery/`)

| File | Mechanism |
|------|-----------|
| `hta_builder.py` | HTML Application (.hta) with embedded payload |
| `vba_builder.py` | Office VBA macro generation (Word/Excel) |
| `msi_builder.py` | Windows Installer (.msi) payload |
| `dll_sideload_builder.py` | DLL for sideloading via legitimate apps (OneDrive, Teams, etc.) |
| `onenote_builder.py` | .one file with embedded script |
| `chm_builder.py` | Compiled HTML Help (.chm) with payload |

## Acceptance Criteria

- [ ] Each transport sends/receives data with encryption
- [ ] DoH transport resolves through real DoH endpoint
- [ ] Slack transport uses bot API for send/recv
- [ ] Each delivery builder produces valid payload file
- [ ] Transports registered in listener registry
