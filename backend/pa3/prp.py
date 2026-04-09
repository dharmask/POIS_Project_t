"""
PA#3 — Pseudorandom Permutation (PRP) + AES Modes of Operation
==============================================================

PRP Definition:
  A PRP F_k: {0,1}^n -> {0,1}^n is a keyed permutation that is:
    1. Efficiently computable and efficiently invertible
    2. Pseudorandom: no PPT adversary can distinguish F_k from a truly random permutation

  AES-128 is our concrete PRP construction.

PRP ↔ PRF Switching Lemma:
  For any q-query adversary A:
    |Adv_PRF(A) - Adv_PRP(A)| ≤ q(q-1) / 2^{n+1}
  For AES (n=128), this is negligible for any polynomial q.

Modes of Operation:
  ECB — Electronic Codebook: c_i = E_k(m_i)
        INSECURE: identical plaintext blocks produce identical ciphertext blocks.

  CBC — Cipher Block Chaining: c_i = E_k(m_i ⊕ c_{i-1}), c_0 = IV
        CPA-secure with a uniformly random IV. Sequential encryption.

  CTR — Counter Mode: c_i = m_i ⊕ E_k(nonce ‖ counter_i)
        CPA-secure, fully parallelizable, no padding needed.

Padding Oracle Attack:
  If a server reveals whether CBC decryption yields valid PKCS#7 padding,
  an adversary recovers any ciphertext byte-by-byte with ≤ 256 queries per byte.
  This shows CBC is CPA-secure but NOT CCA-secure.

No external libraries — only os.urandom and built-in int operations.
"""

import os

from backend.pa1.owf import _aes128_encrypt_block, _key_expansion


# ---------------------------------------------------------------------------
# AES Inverse helpers
# ---------------------------------------------------------------------------

_AES_INV_SBOX = [
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d,
]


def _gmul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1: p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xff
        if hi: a ^= 0x1b
        b >>= 1
    return p


def _inv_sub_bytes(state):
    return [_AES_INV_SBOX[b] for b in state]


def _inv_shift_rows(state):
    s = state[:]
    s[1],  s[5],  s[9],  s[13] = state[13], state[1],  state[5],  state[9]
    s[2],  s[6],  s[10], s[14] = state[10], state[14], state[2],  state[6]
    s[3],  s[7],  s[11], s[15] = state[7],  state[11], state[15], state[3]
    return s


def _inv_mix_columns(state):
    r = [0]*16
    for c in range(4):
        a = [state[c*4+i] for i in range(4)]
        r[c*4+0] = _gmul(a[0],14)^_gmul(a[1],11)^_gmul(a[2],13)^_gmul(a[3], 9)
        r[c*4+1] = _gmul(a[0], 9)^_gmul(a[1],14)^_gmul(a[2],11)^_gmul(a[3],13)
        r[c*4+2] = _gmul(a[0],13)^_gmul(a[1], 9)^_gmul(a[2],14)^_gmul(a[3],11)
        r[c*4+3] = _gmul(a[0],11)^_gmul(a[1],13)^_gmul(a[2], 9)^_gmul(a[3],14)
    return r


def _add_round_key(state, rk):
    return [state[i]^rk[i] for i in range(16)]


def _aes128_decrypt_block(ct: bytes, key: bytes) -> bytes:
    if len(ct) != 16 or len(key) != 16:
        raise ValueError("AES-128 requires 16-byte key and block")
    rks = _key_expansion(key)
    state = list(ct)
    state = _add_round_key(state, rks[10])
    for rnd in range(9, 0, -1):
        state = _inv_shift_rows(state)
        state = _inv_sub_bytes(state)
        state = _add_round_key(state, rks[rnd])
        state = _inv_mix_columns(state)
    state = _inv_shift_rows(state)
    state = _inv_sub_bytes(state)
    state = _add_round_key(state, rks[0])
    return bytes(state)


# ---------------------------------------------------------------------------
# PKCS#7 Padding
# ---------------------------------------------------------------------------

def pkcs7_pad(data: bytes, bs: int = 16) -> bytes:
    pad_len = bs - (len(data) % bs)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes, bs: int = 16) -> bytes:
    if not data or len(data) % bs != 0:
        raise ValueError("Invalid ciphertext length")
    pad_len = data[-1]
    if pad_len == 0 or pad_len > bs:
        raise ValueError("Invalid PKCS#7 padding")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid PKCS#7 padding")
    return data[:-pad_len]


# ---------------------------------------------------------------------------
# PRP: AES as a keyed permutation — forward + inverse
# ---------------------------------------------------------------------------

class PRP_AES:
    """AES-128 as a Pseudorandom Permutation. Demonstrates bijectivity."""

    def __init__(self, key: bytes):
        if len(key) != 16:
            raise ValueError("PRP key must be 16 bytes")
        self.key = key

    def forward(self, x: bytes) -> bytes:
        """F_k(x) = AES_k(x)"""
        return _aes128_encrypt_block(x, self.key)

    def inverse(self, y: bytes) -> bytes:
        """F_k^{-1}(y) = AES_k^{-1}(y)"""
        return _aes128_decrypt_block(y, self.key)

    def verify_bijection(self, x: bytes) -> bool:
        return self.inverse(self.forward(x)) == x


# ---------------------------------------------------------------------------
# ECB Mode  (INSECURE — for demonstration of pattern leakage)
# ---------------------------------------------------------------------------

def ecb_encrypt(plaintext: bytes, key: bytes) -> bytes:
    padded = pkcs7_pad(plaintext)
    return b"".join(_aes128_encrypt_block(padded[i:i+16], key)
                    for i in range(0, len(padded), 16))


def ecb_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    if len(ciphertext) % 16 != 0:
        raise ValueError("Ciphertext length must be multiple of 16")
    plain = b"".join(_aes128_decrypt_block(ciphertext[i:i+16], key)
                     for i in range(0, len(ciphertext), 16))
    return pkcs7_unpad(plain)


def ecb_pattern_demo(key: bytes) -> dict:
    """Encrypt a message with two identical blocks — shows ECB leaks patterns."""
    block_a = b"YELLOW SUBMARINE"
    block_b = b"YELLOW SUBMARINE"
    block_c = b"TOP SECRET DATA!"
    msg = block_a + block_b + block_c
    ct = ecb_encrypt(msg, key)
    blocks = [ct[i:i+16].hex() for i in range(0, len(ct), 16)]
    return {
        "plaintext_blocks": [block_a.hex(), block_b.hex(), block_c.hex()],
        "ciphertext_blocks": blocks,
        "identical_blocks_leaked": blocks[0] == blocks[1],
        "insight": "Blocks 0 and 1 encrypt to the same ciphertext — ECB is not CPA-secure!",
    }


# ---------------------------------------------------------------------------
# CBC Mode  (CPA-secure with random IV)
# ---------------------------------------------------------------------------

def cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes = None) -> tuple:
    if iv is None:
        iv = os.urandom(16)
    padded = pkcs7_pad(plaintext)
    prev, blocks = iv, []
    for i in range(0, len(padded), 16):
        block = bytes(a^b for a,b in zip(padded[i:i+16], prev))
        enc = _aes128_encrypt_block(block, key)
        blocks.append(enc)
        prev = enc
    return iv, b"".join(blocks)


def cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    if len(ciphertext) % 16 != 0 or len(iv) != 16:
        raise ValueError("Invalid ciphertext or IV")
    prev, blocks = iv, []
    for i in range(0, len(ciphertext), 16):
        dec = _aes128_decrypt_block(ciphertext[i:i+16], key)
        blocks.append(bytes(a^b for a,b in zip(dec, prev)))
        prev = ciphertext[i:i+16]
    return pkcs7_unpad(b"".join(blocks))


# ---------------------------------------------------------------------------
# CTR Mode  (CPA-secure, no padding, parallelizable)
# ---------------------------------------------------------------------------

def ctr_crypt(data: bytes, key: bytes, nonce: bytes = None) -> tuple:
    """Encrypt or decrypt (same operation). Returns (nonce, result)."""
    if nonce is None:
        nonce = os.urandom(8)
    result = []
    for i in range(0, len(data), 16):
        ctr_block = nonce + (i // 16).to_bytes(8, 'big')
        ks = _aes128_encrypt_block(ctr_block, key)
        chunk = data[i:i+16]
        result.append(bytes(a^b for a,b in zip(chunk, ks)))
    return nonce, b"".join(result)


# ---------------------------------------------------------------------------
# Padding Oracle Attack on CBC
# ---------------------------------------------------------------------------

def padding_oracle_attack(target_ct: bytes, prev_block: bytes, key: bytes) -> dict:
    """
    Recover plaintext from a single CBC ciphertext block using a padding oracle.
    The oracle reveals only whether decryption has valid PKCS#7 padding.
    Recovers all 16 bytes with at most 256*16 = 4096 oracle queries.
    """
    def oracle(modified_prev: bytes, ct_block: bytes) -> bool:
        dec = _aes128_decrypt_block(ct_block, key)
        candidate = bytes(a^b for a,b in zip(dec, modified_prev))
        try:
            pkcs7_unpad(candidate)
            return True
        except ValueError:
            return False

    intermediate = [0] * 16
    steps = []

    for byte_pos in range(15, -1, -1):
        pad_byte = 16 - byte_pos
        crafted = [0] * 16
        # Fix already-recovered bytes to produce valid padding suffix
        for j in range(byte_pos + 1, 16):
            crafted[j] = intermediate[j] ^ pad_byte

        found = False
        for guess in range(256):
            crafted[byte_pos] = guess
            if oracle(bytes(crafted), target_ct):
                # Verify not a false positive (only for pad_byte=1)
                if byte_pos > 0:
                    crafted[byte_pos - 1] ^= 1
                    if not oracle(bytes(crafted), target_ct):
                        crafted[byte_pos - 1] ^= 1
                        continue
                    crafted[byte_pos - 1] ^= 1
                intermediate[byte_pos] = guess ^ pad_byte
                pt_byte = intermediate[byte_pos] ^ prev_block[byte_pos]
                steps.append({
                    "byte_index": byte_pos,
                    "guesses_tried": guess + 1,
                    "pad_byte": pad_byte,
                    "intermediate_hex": hex(intermediate[byte_pos]),
                    "plaintext_byte_hex": hex(pt_byte),
                    "plaintext_byte_chr": chr(pt_byte) if 32 <= pt_byte < 127 else ".",
                })
                found = True
                break

        if not found:
            steps.append({"byte_index": byte_pos, "error": "not found"})

    recovered = bytes(intermediate[i] ^ prev_block[i] for i in range(16))
    return {
        "recovered_hex": recovered.hex(),
        "recovered_ascii": recovered.decode("utf-8", errors="replace"),
        "total_oracle_queries": sum(s.get("guesses_tried", 0) for s in steps),
        "steps": steps,
    }


# ---------------------------------------------------------------------------
# PRP–PRF Switching Lemma bound
# ---------------------------------------------------------------------------

def switching_lemma(n_queries: int, block_bits: int = 128) -> dict:
    bound = (n_queries * (n_queries - 1)) / (2 ** (block_bits + 1))
    return {
        "n_queries": n_queries,
        "block_bits": block_bits,
        "bound": bound,
        "bound_sci": f"{bound:.3e}",
        "negligible": bound < 1e-10,
        "formula": "|Adv_PRF - Adv_PRP| ≤ q(q-1) / 2^{n+1}",
    }
