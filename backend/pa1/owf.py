"""
PA#1 - One-Way Function (OWF) Implementation
=============================================
Two constructions:
  1. DLP-based OWF:  f(x) = g^x mod p   (discrete log problem)
  2. AES-based OWF:  f(k) = AES_k(0^128) XOR k  (built from scratch, no pycrypto)

Restriction: only os.urandom and built-in int operations are used.
No external crypto libraries (hashlib, hmac, Crypto, etc.).
"""

import os

# ---------------------------------------------------------------------------
# Shared safe prime p and generator g for DLP-based OWF
# Using a well-known 256-bit safe prime (p = 2q+1 where q is also prime)
# ---------------------------------------------------------------------------
DLP_P = int(
    "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1"
    "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD"
    "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245"
    "E485B576 625E7EC6 F44C42E9 A63A3620 FFFFFFFF FFFFFFFF".replace(" ", ""),
    16,
)
DLP_G = 2  # primitive root mod p


def owf_dlp(x: int) -> int:
    """
    DLP-based OWF: f(x) = g^x mod p
    One-way under the discrete logarithm assumption.
    Input:  x  — any non-negative integer (used as exponent)
    Output: g^x mod p  (integer in [1, p-1])
    """
    if not isinstance(x, int) or x < 0:
        raise ValueError("x must be a non-negative integer")
    return pow(DLP_G, x, DLP_P)


# ---------------------------------------------------------------------------
# AES-128 built from scratch (SubBytes/ShiftRows/MixColumns/AddRoundKey)
# Only built-in int and bit operations — no external libraries.
# ---------------------------------------------------------------------------

# AES S-box (standard FIPS 197 values, pre-computed as a constant)
_AES_SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]

# AES Rcon table (first 10 round constants)
_AES_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]


def _xtime(a: int) -> int:
    """Multiply by 2 in GF(2^8)."""
    return ((a << 1) ^ 0x1b) & 0xff if (a & 0x80) else (a << 1) & 0xff


def _gmul(a: int, b: int) -> int:
    """Multiply two bytes in GF(2^8)."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xff
        if hi:
            a ^= 0x1b
        b >>= 1
    return p


def _sub_bytes(state: list) -> list:
    return [_AES_SBOX[b] for b in state]


def _shift_rows(state: list) -> list:
    # state is 16 bytes in column-major order (AES standard)
    # convert to row-major for shifting
    s = state[:]
    # row 0: no shift
    # row 1: left rotate by 1
    s[1], s[5], s[9], s[13] = state[5], state[9], state[13], state[1]
    # row 2: left rotate by 2
    s[2], s[6], s[10], s[14] = state[10], state[14], state[2], state[6]
    # row 3: left rotate by 3
    s[3], s[7], s[11], s[15] = state[15], state[3], state[7], state[11]
    return s


def _mix_columns(state: list) -> list:
    result = [0] * 16
    for c in range(4):
        a = [state[c * 4 + r] for r in range(4)]
        result[c * 4 + 0] = _gmul(a[0], 2) ^ _gmul(a[1], 3) ^ a[2] ^ a[3]
        result[c * 4 + 1] = a[0] ^ _gmul(a[1], 2) ^ _gmul(a[2], 3) ^ a[3]
        result[c * 4 + 2] = a[0] ^ a[1] ^ _gmul(a[2], 2) ^ _gmul(a[3], 3)
        result[c * 4 + 3] = _gmul(a[0], 3) ^ a[1] ^ a[2] ^ _gmul(a[3], 2)
    return result


def _add_round_key(state: list, round_key: list) -> list:
    return [state[i] ^ round_key[i] for i in range(16)]


def _key_expansion(key_bytes: bytes) -> list:
    """Expand 128-bit key into 11 round keys (each 16 bytes)."""
    w = list(key_bytes)  # 16 bytes = 4 words × 4 bytes
    for i in range(4, 44):
        temp = w[(i - 1) * 4: i * 4]
        if i % 4 == 0:
            # RotWord + SubWord + Rcon
            temp = temp[1:] + temp[:1]  # RotWord
            temp = [_AES_SBOX[b] for b in temp]  # SubWord
            temp[0] ^= _AES_RCON[i // 4 - 1]
        new_word = [w[(i - 4) * 4 + j] ^ temp[j] for j in range(4)]
        w.extend(new_word)
    # Group into 11 round keys
    return [w[i * 16: (i + 1) * 16] for i in range(11)]


def _aes128_encrypt_block(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt a single 128-bit block using AES-128."""
    if len(plaintext) != 16 or len(key) != 16:
        raise ValueError("AES-128 requires 16-byte key and 16-byte plaintext")
    round_keys = _key_expansion(key)
    # state in column-major: col0=[s0,s1,s2,s3], col1=[s4,s5,s6,s7], ...
    state = list(plaintext)
    state = _add_round_key(state, round_keys[0])
    for rnd in range(1, 10):
        state = _sub_bytes(state)
        state = _shift_rows(state)
        state = _mix_columns(state)
        state = _add_round_key(state, round_keys[rnd])
    # Final round (no MixColumns)
    state = _sub_bytes(state)
    state = _shift_rows(state)
    state = _add_round_key(state, round_keys[10])
    return bytes(state)


def owf_aes(k: bytes) -> bytes:
    """
    AES-based OWF: f(k) = AES_k(0^128) XOR k
    One-way assuming AES is a pseudorandom permutation.
    Input:  k  — 16-byte key
    Output: 16-byte value
    """
    if len(k) != 16:
        raise ValueError("AES-OWF requires a 16-byte key")
    zero_block = b'\x00' * 16
    aes_out = _aes128_encrypt_block(zero_block, k)
    return bytes(a ^ b for a, b in zip(aes_out, k))


def owf(x, mode: str = "dlp"):
    """
    Unified OWF interface.
    mode='dlp'  -> DLP-based OWF (x is int)
    mode='aes'  -> AES-based OWF (x is 16-byte key)
    """
    if mode == "dlp":
        return owf_dlp(x)
    elif mode == "aes":
        return owf_aes(x)
    else:
        raise ValueError(f"Unknown OWF mode: {mode}")
