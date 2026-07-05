# Sprint 4 — Implant Evasion Layer

## Goal
Add 9 evasion techniques to `forge_payload/evasion/`.

## Modules to Build

### P0 (Critical)

1. **`sleep_mask.py`** — Encrypt beacon memory region during sleep intervals. On wake, decrypt and resume. Defeats memory scanners that scan during beacon sleep.

2. **`indirect_syscalls.py`** — Generate syscall stubs that jump directly to ntdll syscall instructions, bypassing EDR userland hooks. Need syscall number resolution per OS version.

### P1 (High)

3. **`stack_spoof.py`** — During sleep, replace thread call stack with legitimate-looking frames (e.g., kernel32!WaitForSingleObject chain). Defeats stack-walking EDR detections.

4. **`pe_stomp.py`** — After loading beacon into memory, overwrite the PE header with zeros or garbage. Breaks forensic tools that scan for MZ/PE signatures.

5. **`unhook.py`** — Read clean ntdll.dll from disk (`\KnownDlls\ntdll.dll` or `C:\Windows\System32\ntdll.dll`), remap .text section over hooked copy. Restores original syscall stubs.

6. **`ppid_spoof.py`** — Create processes with spoofed parent PID using `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`. Makes beacon-spawned processes appear to come from legitimate parents (explorer.exe, svchost.exe).

7. **`etw_patch.py`** — Patch `EtwEventWrite` in ntdll to return immediately (`ret`). Blinds ETW consumers. Note: `netforge/modules/rootkit/etw_blind.py` exists — this is the implant-side equivalent.

### P2 (Medium)

8. **`timestomp.py`** — Modify file creation/modification/access times to match surrounding files. Anti-forensics for dropped files.

9. **`module_overload.py`** — Load beacon shellcode into memory space of a legitimately loaded DLL (e.g., amsi.dll). Beacon runs from a "known good" module address range.

## Integration Points
- `forge_payload/payload_factory.py` — Add evasion selection to payload generation
- `forge_c2/implant/implant_config.py` — Add evasion config options
- `forge_c2/implant/implant_windows.py` — Wire evasion into Windows implant

## Acceptance Criteria

- [ ] Each technique has standalone unit test verifying byte patterns
- [ ] sleep_mask encrypts/decrypts beacon memory region correctly
- [ ] indirect_syscalls resolves syscall numbers for Win10/11/Server2019+
- [ ] Evasion techniques selectable in implant config
- [ ] Payload factory applies selected evasion at build time
