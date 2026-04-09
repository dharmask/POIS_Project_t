"""
PA#5 - MACs from the PA#2 PRF and PA#4 style chaining.

Implements:
  - PRF-MAC
  - CBC-MAC
  - EUF-CMA demo
"""

from __future__ import annotations

import hmac
import os

from backend.pa2.prf import PRF_AES


BLOCK_BYTES = 16


def _coerce_key(key: bytes) -> bytes:
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("key must be bytes")
    key_bytes = bytes(key)
    if len(key_bytes) != BLOCK_BYTES:
        raise ValueError("key must be exactly 16 bytes")
    return key_bytes


def _xor_bytes(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def _pad_block(message: bytes) -> bytes:
    if len(message) > BLOCK_BYTES:
        raise ValueError("PRF-MAC messages must fit in one block")
    return message.ljust(BLOCK_BYTES, b"\x00")


def _iter_cbc_mac_blocks(message: bytes) -> list[bytes]:
    length_prefix = len(message).to_bytes(BLOCK_BYTES, "big")
    payload = message
    pad_len = (-len(payload)) % BLOCK_BYTES
    if pad_len:
        payload += b"\x00" * pad_len
    return [length_prefix] + [payload[i:i + BLOCK_BYTES] for i in range(0, len(payload), BLOCK_BYTES)]


def mac_prf(key: bytes, message: bytes, *, prf=None) -> bytes:
    prf_impl = prf if prf is not None else PRF_AES()
    key_bytes = _coerce_key(key)
    return prf_impl.evaluate(key_bytes, _pad_block(message))


def vrfy_prf(key: bytes, message: bytes, tag: bytes, *, prf=None) -> bool:
    return hmac.compare_digest(mac_prf(key, message, prf=prf), bytes(tag))


def cbc_mac(key: bytes, message: bytes, *, prf=None) -> bytes:
    """
    Variable-length CBC-MAC with a 16-byte length prefix.

    This differs intentionally from the PA#4 CBC-MAC demo, which uses PKCS#7
    padding to illustrate the vanilla chaining construction.
    """
    prf_impl = prf if prf is not None else PRF_AES()
    key_bytes = _coerce_key(key)
    state = b"\x00" * BLOCK_BYTES
    for block in _iter_cbc_mac_blocks(message):
        state = prf_impl.evaluate(key_bytes, _xor_bytes(block, state))
    return state


def vrfy_cbc_mac(key: bytes, message: bytes, tag: bytes, *, prf=None) -> bool:
    return hmac.compare_digest(cbc_mac(key, message, prf=prf), bytes(tag))


def euf_cma_game(mac_mode: str = "prf", n_queries: int = 10) -> dict:
    """
    Simulate a simple EUF-CMA game.

    The adversary gets oracle access, then tries a replay-style forgery on a
    fresh message. Secure MACs should reject.
    """
    if mac_mode not in {"prf", "cbc"}:
        raise ValueError("mac_mode must be 'prf' or 'cbc'")
    if n_queries <= 0:
        raise ValueError("n_queries must be positive")

    key = os.urandom(BLOCK_BYTES)

    def tag(msg: bytes) -> bytes:
        return mac_prf(key, msg) if mac_mode == "prf" else cbc_mac(key, msg)

    queries = []
    seen_messages = []
    for i in range(n_queries):
        msg = f"message_{i:02d}".encode()
        seen_messages.append(msg)
        queries.append({"message": msg.decode(), "tag_hex": tag(msg).hex()})

    forged_message = b"fresh_forgery"
    replayed_tag = bytes.fromhex(queries[0]["tag_hex"])
    success = forged_message not in seen_messages and tag(forged_message) == replayed_tag

    return {
        "mac_mode": mac_mode,
        "n_queries": n_queries,
        "queries": queries[:5],
        "forgery_attempt": {
            "message": forged_message.decode(),
            "replayed_tag_hex": replayed_tag.hex(),
            "correct_tag_hex": tag(forged_message).hex(),
            "success": success,
        },
        "verdict": "secure" if not success else "forged",
        "note": "Replay does not forge a tag for a fresh message under a secure MAC.",
    }
