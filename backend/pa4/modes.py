"""
PA#4 - Modes of operation built from the existing PRP/PRF stack.

Implements:
  - CBC
  - OFB
  - CTR

And explicit attack demos:
  - CBC IV reuse
  - OFB keystream reuse
  - CPA malleability on stream-style encryption
"""

from __future__ import annotations

import os

from backend.pa3.prp import PRP_AES


BLOCK_BYTES = 16
NONCE_BYTES = 8


def _coerce_key(key: bytes) -> bytes:
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("key must be bytes")
    key_bytes = bytes(key)
    if len(key_bytes) != BLOCK_BYTES:
        raise ValueError("key must be exactly 16 bytes")
    return key_bytes


def _xor_bytes(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def pkcs7_pad(data: bytes, block_size: int = BLOCK_BYTES) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes, block_size: int = BLOCK_BYTES) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("invalid padded data length")
    pad_len = data[-1]
    if pad_len == 0 or pad_len > block_size:
        raise ValueError("invalid PKCS#7 padding")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("invalid PKCS#7 padding")
    return data[:-pad_len]


def cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes | None = None) -> tuple[bytes, bytes]:
    key_bytes = _coerce_key(key)
    iv_bytes = os.urandom(BLOCK_BYTES) if iv is None else bytes(iv)
    if len(iv_bytes) != BLOCK_BYTES:
        raise ValueError("iv must be 16 bytes")
    prp = PRP_AES(key_bytes)

    padded = pkcs7_pad(plaintext)
    prev = iv_bytes
    blocks = []
    for offset in range(0, len(padded), BLOCK_BYTES):
        block = padded[offset:offset + BLOCK_BYTES]
        chained = _xor_bytes(block, prev)
        enc = prp.forward(chained)
        blocks.append(enc)
        prev = enc
    return iv_bytes, b"".join(blocks)


def cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    key_bytes = _coerce_key(key)
    iv_bytes = bytes(iv)
    if len(iv_bytes) != BLOCK_BYTES or len(ciphertext) % BLOCK_BYTES != 0:
        raise ValueError("invalid ciphertext or iv length")
    prp = PRP_AES(key_bytes)

    prev = iv_bytes
    blocks = []
    for offset in range(0, len(ciphertext), BLOCK_BYTES):
        ct_block = ciphertext[offset:offset + BLOCK_BYTES]
        plain_block = _xor_bytes(prp.inverse(ct_block), prev)
        blocks.append(plain_block)
        prev = ct_block
    return pkcs7_unpad(b"".join(blocks))


def ofb_crypt(data: bytes, key: bytes, iv: bytes | None = None) -> tuple[bytes, bytes]:
    key_bytes = _coerce_key(key)
    iv_bytes = os.urandom(BLOCK_BYTES) if iv is None else bytes(iv)
    if len(iv_bytes) != BLOCK_BYTES:
        raise ValueError("iv must be 16 bytes")
    prp = PRP_AES(key_bytes)

    feedback = iv_bytes
    out = bytearray()
    for offset in range(0, len(data), BLOCK_BYTES):
        feedback = prp.forward(feedback)
        chunk = data[offset:offset + BLOCK_BYTES]
        out.extend(_xor_bytes(chunk, feedback[:len(chunk)]))
    return iv_bytes, bytes(out)


def ctr_crypt(data: bytes, key: bytes, nonce: bytes | None = None) -> tuple[bytes, bytes]:
    key_bytes = _coerce_key(key)
    nonce_bytes = os.urandom(NONCE_BYTES) if nonce is None else bytes(nonce)
    if len(nonce_bytes) != NONCE_BYTES:
        raise ValueError("nonce must be 8 bytes")
    prp = PRP_AES(key_bytes)

    out = bytearray()
    for counter, offset in enumerate(range(0, len(data), BLOCK_BYTES)):
        counter_block = nonce_bytes + counter.to_bytes(BLOCK_BYTES - NONCE_BYTES, "big")
        keystream = prp.forward(counter_block)
        chunk = data[offset:offset + BLOCK_BYTES]
        out.extend(_xor_bytes(chunk, keystream[:len(chunk)]))
    return nonce_bytes, bytes(out)


def cbc_iv_reuse_demo(key: bytes | None = None) -> dict:
    key_bytes = os.urandom(BLOCK_BYTES) if key is None else _coerce_key(key)
    reused_iv = os.urandom(BLOCK_BYTES)
    m1 = b"shared-prefix-AAA" + b"unique block one"
    m2 = b"shared-prefix-AAA" + b"unique block two"
    iv1, c1 = cbc_encrypt(m1, key_bytes, reused_iv)
    iv2, c2 = cbc_encrypt(m2, key_bytes, reused_iv)
    return {
        "iv_hex": reused_iv.hex(),
        "ciphertext1_hex": c1.hex(),
        "ciphertext2_hex": c2.hex(),
        "first_blocks_equal": c1[:BLOCK_BYTES] == c2[:BLOCK_BYTES],
        "insight": "Reusing the CBC IV leaks whether the first plaintext blocks are equal.",
    }


def ofb_keystream_reuse_demo(key: bytes | None = None) -> dict:
    key_bytes = os.urandom(BLOCK_BYTES) if key is None else _coerce_key(key)
    reused_iv = os.urandom(BLOCK_BYTES)
    m1 = b"attack at dawn!!"
    m2 = b"defend at dusk!!"
    _, c1 = ofb_crypt(m1, key_bytes, reused_iv)
    _, c2 = ofb_crypt(m2, key_bytes, reused_iv)
    xor_ct = _xor_bytes(c1, c2)
    xor_pt = _xor_bytes(m1, m2)
    return {
        "iv_hex": reused_iv.hex(),
        "ciphertext1_hex": c1.hex(),
        "ciphertext2_hex": c2.hex(),
        "xor_ciphertexts_hex": xor_ct.hex(),
        "xor_plaintexts_hex": xor_pt.hex(),
        "keystream_reuse_detected": xor_ct == xor_pt,
        "insight": "OFB nonce/IV reuse reuses the same keystream, so C1 xor C2 = M1 xor M2.",
    }


def cpa_malleability_demo(key: bytes | None = None) -> dict:
    key_bytes = os.urandom(BLOCK_BYTES) if key is None else _coerce_key(key)
    message = b"pay=1000&to=bob"
    nonce, ciphertext = ctr_crypt(message, key_bytes)
    tampered = bytearray(ciphertext)
    amount_marker = b"1000"
    amount_offset = message.find(amount_marker)
    if amount_offset < 0:
        raise ValueError("demo message must contain the amount marker '1000'")
    index = amount_offset
    delta = ord("1") ^ ord("9")
    tampered[index] ^= delta
    _, recovered = ctr_crypt(bytes(tampered), key_bytes, nonce)
    return {
        "nonce_hex": nonce.hex(),
        "original_message": message.decode(),
        "original_ciphertext_hex": ciphertext.hex(),
        "tampered_ciphertext_hex": bytes(tampered).hex(),
        "tampered_plaintext": recovered.decode("utf-8", errors="replace"),
        "malleability_observed": recovered != message and recovered.startswith(b"pay=9000"),
        "insight": "CTR/OFB style encryption is CPA-secure but malleable: flipping ciphertext bits flips plaintext bits.",
    }
