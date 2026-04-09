"""
PA#3 - CPA-secure symmetric encryption from a PRF.

Construction:
  Enc_k(m):
    1. sample a fresh random nonce r
    2. derive keystream blocks F_k(r || ctr_i)
    3. output c = r || (m xor keystream)

  Dec_k(c):
    1. parse r from the ciphertext prefix
    2. regenerate the same PRF keystream
    3. xor to recover the message

This is the standard PRF-based randomized encryption construction.
"""

from __future__ import annotations

import os

from backend.pa2.prf import PRF_AES, PRF_GGM


KEY_BYTES = 16
BLOCK_BYTES = 16
NONCE_BYTES = 8
COUNTER_BYTES = BLOCK_BYTES - NONCE_BYTES


def _coerce_key(key: bytes) -> bytes:
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("key must be bytes")
    key_bytes = bytes(key)
    if len(key_bytes) != KEY_BYTES:
        raise ValueError("key must be exactly 16 bytes")
    return key_bytes


def _coerce_message(message) -> bytes:
    if isinstance(message, str):
        return message.encode()
    if isinstance(message, (bytes, bytearray)):
        return bytes(message)
    raise TypeError("message must be bytes or str")


def _xor_bytes(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def _counter_block(nonce: bytes, counter: int) -> bytes:
    if len(nonce) != NONCE_BYTES:
        raise ValueError("nonce must be 8 bytes")
    if counter < 0 or counter >= (1 << (8 * COUNTER_BYTES)):
        raise ValueError("counter is out of range")
    return nonce + counter.to_bytes(COUNTER_BYTES, "big")


class PRFCPAEncryption:
    """Randomized CPA-secure encryption built from a PRF."""

    def __init__(self, prf=None):
        self.prf = prf if prf is not None else PRF_AES()

    def _keystream(self, key: bytes, nonce: bytes, n_bytes: int) -> bytes:
        blocks = bytearray()
        counter = 0
        while len(blocks) < n_bytes:
            blocks.extend(self.prf.evaluate(key, _counter_block(nonce, counter)))
            counter += 1
        return bytes(blocks[:n_bytes])

    def encrypt(self, key: bytes, message, nonce: bytes | None = None) -> bytes:
        key_bytes = _coerce_key(key)
        msg = _coerce_message(message)
        nonce_bytes = os.urandom(NONCE_BYTES) if nonce is None else bytes(nonce)
        if len(nonce_bytes) != NONCE_BYTES:
            raise ValueError("nonce must be 8 bytes")
        keystream = self._keystream(key_bytes, nonce_bytes, len(msg))
        return nonce_bytes + _xor_bytes(msg, keystream)

    def decrypt(self, key: bytes, ciphertext: bytes) -> bytes:
        key_bytes = _coerce_key(key)
        if not isinstance(ciphertext, (bytes, bytearray)):
            raise TypeError("ciphertext must be bytes")
        ct = bytes(ciphertext)
        if len(ct) < NONCE_BYTES:
            raise ValueError("ciphertext is too short")
        nonce, body = ct[:NONCE_BYTES], ct[NONCE_BYTES:]
        keystream = self._keystream(key_bytes, nonce, len(body))
        return _xor_bytes(body, keystream)


class BrokenDeterministicPRFEncryption(PRFCPAEncryption):
    """
    Intentionally insecure variant that reuses a fixed nonce for every
    encryption, making the scheme deterministic and distinguishable.
    """

    def __init__(self, prf=None, *, fixed_nonce: bytes = b"\x00" * NONCE_BYTES):
        super().__init__(prf=prf)
        if len(fixed_nonce) != NONCE_BYTES:
            raise ValueError("fixed_nonce must be 8 bytes")
        self.fixed_nonce = fixed_nonce

    def encrypt(self, key: bytes, message, nonce: bytes | None = None) -> bytes:
        nonce_bytes = self.fixed_nonce if nonce is None else nonce
        return super().encrypt(key, message, nonce=nonce_bytes)


def Enc(k: bytes, m, *, scheme: str = "secure", prf_mode: str = "aes") -> bytes:
    """Requested reusable encryption API."""
    scheme_impl = build_scheme(scheme=scheme, prf_mode=prf_mode)
    return scheme_impl.encrypt(k, m)


def Dec(k: bytes, c: bytes, *, scheme: str = "secure", prf_mode: str = "aes") -> bytes:
    """Requested reusable decryption API."""
    scheme_impl = build_scheme(scheme=scheme, prf_mode=prf_mode)
    return scheme_impl.decrypt(k, c)


def build_scheme(*, scheme: str = "secure", prf_mode: str = "aes"):
    if prf_mode not in {"aes", "ggm"}:
        raise ValueError(f"Unknown PRF mode: {prf_mode}")
    prf = PRF_AES() if prf_mode == "aes" else PRF_GGM(input_bits=BLOCK_BYTES * 8)
    # The GGM-backed option uses a full 128-bit input domain, so each
    # keystream block performs a 128-level tree traversal. That is useful for
    # reduction demos but intentionally much slower than the AES plug-in PRF.
    if scheme == "secure":
        return PRFCPAEncryption(prf=prf)
    if scheme == "broken":
        return BrokenDeterministicPRFEncryption(prf=prf)
    raise ValueError(f"Unknown encryption scheme: {scheme}")


def cpa_game(*, scheme: str = "secure", trials: int = 200, prf_mode: str = "aes") -> dict:
    """
    Simulate the IND-CPA left-right game using a replay adversary.

    The adversary first queries encryptions of m0 and m1, then compares the
    challenge ciphertext against those references. This wins against the
    broken deterministic construction and falls back to random guessing
    against the randomized construction.
    """
    if trials <= 0:
        raise ValueError("trials must be positive")

    wins = 0
    transcripts = []

    for trial in range(trials):
        key = os.urandom(KEY_BYTES)
        scheme_impl = build_scheme(scheme=scheme, prf_mode=prf_mode)
        m0 = b"A" * 32
        m1 = b"B" * 32

        ref0 = scheme_impl.encrypt(key, m0)
        ref1 = scheme_impl.encrypt(key, m1)

        challenge_bit = int.from_bytes(os.urandom(1), "big") & 1
        challenge = scheme_impl.encrypt(key, m1 if challenge_bit else m0)

        if challenge == ref0:
            guess = 0
        elif challenge == ref1:
            guess = 1
        else:
            # Against the randomized scheme the replay adversary gets no match,
            # so it falls back to a fixed guess and wins with probability 1/2.
            guess = 0

        win = guess == challenge_bit
        wins += int(win)

        if trial < 5:
            transcripts.append(
                {
                    "trial": trial,
                    "challenge_bit": challenge_bit,
                    "reference0_hex": ref0.hex(),
                    "reference1_hex": ref1.hex(),
                    "challenge_hex": challenge.hex(),
                    "guess": guess,
                    "win": win,
                }
            )

    success_rate = wins / trials
    advantage = abs(success_rate - 0.5)
    return {
        "scheme": scheme,
        "prf_mode": prf_mode,
        "trials": trials,
        "wins": wins,
        "success_rate": success_rate,
        "advantage": advantage,
        "verdict": "broken" if advantage > 0.25 else "looks_cpa_secure",
        "adversary": "reference-ciphertext replay distinguisher",
        "transcripts": transcripts,
    }
