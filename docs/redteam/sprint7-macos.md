# Sprint 7 — macOS Implant

## Goal
macOS persistent agent with TCC bypass and keychain extraction.

## New Directory
`forge_c2/implant/macos/`

## Modules to Build

1. **`implant_macos.py`** — macOS persistent agent:
   - LaunchAgent/LaunchDaemon persistence
   - Login item persistence
   - Cron persistence
   - Heartbeat + sleep/jitter
   - Same task interface as Windows/Linux implants

2. **`tcc_bypass.py`** — Transparency, Consent, and Control bypass:
   - FDA (Full Disk Access) abuse via trusted apps
   - Accessibility API injection
   - Automation permission abuse
   - Camera/mic access via TCC.db manipulation

3. **`keychain_extract.py`** — macOS Keychain extraction:
   - Dump login keychain passwords
   - Extract saved WiFi passwords
   - Extract browser passwords via Security framework
   - Certificate/key extraction

4. **`pkg_builder.py`** — macOS delivery:
   - PKG installer payload (preinstall/postinstall scripts)
   - DMG with disguised payload
   - Code-signing avoidance (unsigned + Gatekeeper bypass)

## Integration
- Register macOS as platform in `forge_c2/implant/implant_builder.py`
- Add macOS compile target to `forge_c2/implant/stager_factory.py`
- Cross-platform task dispatch in `forge_c2/tasks/base_task.py`

## Acceptance Criteria

- [ ] macOS implant checks in with C2 server
- [ ] At least 2 persistence mechanisms work
- [ ] Keychain extraction returns credentials
- [ ] PKG builder produces installable payload
- [ ] Tasks (shell, file, screenshot) work on macOS
