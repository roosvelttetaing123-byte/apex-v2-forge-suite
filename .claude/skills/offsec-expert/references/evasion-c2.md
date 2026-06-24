# EDR Evasion + C2 + Tradecraft Reference

## EDR Landscape (2026)

Tier 1 (hardest): CrowdStrike Falcon, SentinelOne Singularity, Microsoft Defender for Endpoint (MDE)
Tier 2: Carbon Black, Cortex XDR, Cybereason, Elastic Security
Tier 3: Sophos Intercept X, Trend Micro Vision One, ESET Inspect

Key detection mechanisms to defeat:
- Userland API hooking (DLL injection into process)
- Kernel callbacks (PsSetCreateProcessNotifyRoutine, etc.)
- ETW (Event Tracing for Windows) telemetry
- Memory scanning (PE header detection, RWX regions, unbacked memory)
- Behavioral analytics (process tree anomalies, parent-child relationships)
- Network telemetry (JA3/JA4 fingerprinting, beacon pattern detection)

---

## Syscall Strategies (T1106, T1055)

### Direct Syscalls
Bypass userland hooks by calling NT syscalls directly without going through ntdll.dll.

```c
// SysWhispers3 / HellsGate / Tartarus Gate patterns
// Dynamically resolve syscall numbers at runtime
// Avoid static syscall stubs (detected by some EDRs via signature scanning)
```

Tools: SysWhispers3, HellsGate, RecycledGate, TartarusGate

### Indirect Syscalls
Use legitimate `syscall` instruction from ntdll.dll itself (return-oriented to ntdll syscall gadget) — defeats EDRs that check syscall origin address.

### API Unhooking
```c
// Overwrite hooked ntdll functions with clean copy from disk
// 1. Map fresh ntdll from \KnownDlls\ or disk
// 2. Copy .text section over hooked in-memory version
// AV/EDR hook check: compare first bytes of NtOpenProcess vs known-good
```

---

## Sleep Masking (T1027)

Modern EDRs scan process memory during sleep. Mask beacon memory while sleeping:

Techniques:
- **Ekko** — ROP-based sleep with memory encryption via NtContinue
- **Foliage** — Stack spoofing + sleep masking
- **Cronos** — Timer-based async sleep masking
- **RIPPL** — Memory remapping during sleep
- **Gargoyle** (concept) — RWX → RX flip + timer callback

Goal: During sleep, beacon shellcode region is either encrypted or remapped as non-executable.

---

## Process Injection (T1055)

| Technique | API | Detection Risk |
|-----------|-----|----------------|
| Classic injection | VirtualAllocEx + WriteProcessMemory + CreateRemoteThread | High — monitored API sequence |
| APC injection | QueueUserAPC into alertable thread | Medium |
| Process Hollowing | CreateProcess(SUSPENDED) + unmap + remap | High — CreateProcess(SUSPENDED) flagged |
| Module Stomping | Overwrite legitimate DLL in remote process | Low-Medium — no new allocations |
| Thread Hijacking | SuspendThread + GetContext + SetContext + ResumeThread | Medium |
| Phantom DLL Hollowing | Map non-present DLL section + inject | Low |
| PPID Spoofing | Set parent PID to explorer.exe via PROC_THREAD_ATTRIBUTE | Medium — legitimate parent breaks behavioral chain |

---

## BYOVD (Bring Your Own Vulnerable Driver) (T1014)

Load a signed but vulnerable kernel driver → exploit it for kernel-level code execution → terminate EDR process/disable protection.

Common BYOVD drivers (verify current LOLDrivers.io list):
- **RTCore64.sys** (MSI Afterburner) — IOCTL for arbitrary kernel R/W
- **gdrv.sys** (Gigabyte) — kernel R/W
- **DBUtil_2_3.sys** (Dell) — mapped to many BYOVD campaigns

Process:
1. Load driver with `sc create` or `NtLoadDriver`
2. Open device handle
3. Send IOCTL for arbitrary memory read/write
4. Patch EDR kernel callback table or terminate EDR process from kernel

OPSEC: BYOVD is loud — `sc create` + new driver load generates Event ID 7045. Use LOLDrivers that are already present on target or load via DKOM.

---

## C2 Framework Selection (2026)

| Framework | EDR Evasion | Maturity | License | Notes |
|-----------|-------------|----------|---------|-------|
| Cobalt Strike 4.x | Medium (requires customization) | Highest | Commercial | Most detected — watermarks in default beacon |
| Sliver | Medium-High | High | Open Source | Go-based, active development, mTLS/WireGuard |
| Havoc | High | Medium | Open Source | Modern sleep masking built-in, demon implant |
| BRC4 | High | Medium | Commercial | Designed for EDR evasion from ground up |
| Mythic | Low (framework) | High | Open Source | Modular — evasion depends on agent choice |
| Nighthawk | Very High | Low | Commercial | Most expensive, best default evasion |
| Outflank C2 | High | Medium | Commercial | Dutch red team tool, OPSEC-focused |

### Malleable C2 / Traffic Blending
- Use legitimate-looking JA3/JA4 fingerprints (mimic Chrome, Edge)
- Domain fronting via CDN (Cloudflare Workers, Azure CDN, AWS CloudFront)
- Telegram/Discord bot API as C2 channel — encrypted, allowed in most corps
- DNS over HTTPS (DoH) as C2 transport

---

## Payload Delivery (T1027, T1566)

### Container Formats by Detection Rate (lower = better)
- .lnk with PowerShell/COM abuse — Medium (heavily signatured)
- .iso / .vhd mounts (bypasses Mark-of-the-Web) — Low-Medium
- HTML Smuggling (Base64 blob in JS, auto-download) — Low
- OneNote .one with embedded EXE — Medium (now flagged by MDE)
- Macro-less XLL (Excel add-in) — Medium
- MSIX/APPX installer (signed) — Low (if signed with valid cert)

### Obfuscation
- **LLVM obfuscator** — control flow flattening, bogus control flow, string encryption
- **Donut** — shellcode from .NET/EXE, supports AMSI/ETW bypass
- **Garble** — Go binary obfuscation (for Go-based implants)

---

## AMSI / ETW Bypass

AMSI (Antimalware Scan Interface) — patches `AmsiScanBuffer` return value:
```powershell
# Classic (heavily signatured — encode/split):
[Ref].Assembly.GetType('System.Management.Automation.Am'+'siUtils').GetField('am'+'siInitFailed','NonPublic,Static').SetValue($null,$true)
```

ETW bypass — patch `EtwEventWrite` in ntdll to return immediately:
```c
// Write 0xC3 (RET) to EtwEventWrite — kills all ETW telemetry from this process
```

---

## OPSEC Notes
- Never run default Cobalt Strike profiles — unique JA3 and beacon metadata is trivially fingerprinted
- Avoid `cmd.exe` as parent — use `svchost`, `explorer`, or injected process instead
- PowerShell Script Block Logging (Event 4104) captures all PS regardless of obfuscation
- AMSI bypasses are caught by behavioral heuristics even when signature evades — chain with ETW patch
- Sleep jitter ±30% minimum — fixed-interval beacons are caught by network ML within hours
