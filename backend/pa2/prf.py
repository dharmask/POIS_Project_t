"""
PA#2 - Pseudorandom Functions from the existing PA#1 PRG.

This module keeps the reductions explicit and reusable:
  - PRG -> PRF via the GGM tree construction
  - PRF -> PRG via G_k(s) = F_k(s||0) || F_k(s||1)
  - AES plug-in PRF using the scratch AES block cipher from PA#1

No external crypto libraries are used.
"""

from __future__ import annotations

import os

from backend.pa1.owf import _aes128_encrypt_block
from backend.pa1.prg import PRG_AES


BLOCK_BYTES = 16
BLOCK_BITS = BLOCK_BYTES * 8
DOUBLE_BLOCK_BYTES = 2 * BLOCK_BYTES
DEFAULT_AES_PRG_R = bytes.fromhex("c0ffeec0ffeec0ffeec0ffeec0ffee11")


def _int_to_fixed_bytes(value: int, length: int) -> bytes:
    if value < 0:
        raise ValueError("value must be non-negative")
    if value >= (1 << (8 * length)):
        raise ValueError(f"value does not fit in {length} bytes")
    return value.to_bytes(length, "big")


def _coerce_key(key: bytes) -> bytes:
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("key must be bytes")
    key_bytes = bytes(key)
    if len(key_bytes) != BLOCK_BYTES:
        raise ValueError("key must be exactly 16 bytes")
    return key_bytes


def _coerce_domain_value(x, input_bits: int) -> int:
    if input_bits <= 0:
        raise ValueError("input_bits must be positive")
    if isinstance(x, (bytes, bytearray)):
        x_int = int.from_bytes(bytes(x), "big")
    else:
        x_int = int(x)
    if x_int < 0:
        raise ValueError("domain inputs must be non-negative")
    if x_int >= (1 << input_bits):
        raise ValueError(f"input must fit in {input_bits} bits")
    return x_int


def _coerce_block_input(x) -> bytes:
    if isinstance(x, (bytes, bytearray)):
        block = bytes(x)
        if len(block) > BLOCK_BYTES:
            raise ValueError("AES PRF input must fit in 16 bytes")
        return block.rjust(BLOCK_BYTES, b"\x00")
    return _int_to_fixed_bytes(int(x), BLOCK_BYTES)


def _bits_msb_first(x_int: int, input_bits: int) -> list[int]:
    return [(x_int >> shift) & 1 for shift in range(input_bits - 1, -1, -1)]


def _doubling_prg(seed: bytes, *, r: bytes = DEFAULT_AES_PRG_R) -> tuple[bytes, bytes]:
    """
    Concrete doubling PRG used by GGM.

    The implementation is built strictly from PA#1's AES PRG by asking for
    256 output bits and splitting them into two 128-bit halves.

    Note: the PA#1 AES PRG expects a fixed public parameter ``r``. For this
    course project we thread that same pedagogical constant through the GGM
    tree as well. This keeps the reduction stack explicit and deterministic for
    demos, but it should not be mistaken for a deployment-ready construction.
    """
    seed_bytes = _coerce_key(seed)
    prg = PRG_AES(output_bits=2 * BLOCK_BITS, r=r)
    prg.seed(seed_bytes)
    expanded = prg.generate_bytes(DOUBLE_BLOCK_BYTES)
    return expanded[:BLOCK_BYTES], expanded[BLOCK_BYTES:]


class PRF_GGM:
    """PRF from PRG via the Goldreich-Goldwasser-Micali tree construction."""

    def __init__(self, input_bits: int = BLOCK_BITS, *, prg_r: bytes = DEFAULT_AES_PRG_R):
        self.input_bits = input_bits
        self.prg_r = prg_r

    def expand_seed(self, seed: bytes) -> tuple[bytes, bytes]:
        return _doubling_prg(seed, r=self.prg_r)

    def evaluate(self, k: bytes, x) -> bytes:
        key = _coerce_key(k)
        x_int = _coerce_domain_value(x, self.input_bits)

        state = key
        for bit in _bits_msb_first(x_int, self.input_bits):
            left, right = self.expand_seed(state)
            state = right if bit else left
        return state

    def __call__(self, k: bytes, x) -> bytes:
        return self.evaluate(k, x)


class PRF_AES:
    """Drop-in PRF plug-in: F_k(x) = AES_k(x)."""

    def evaluate(self, k: bytes, x) -> bytes:
        key = _coerce_key(k)
        block = _coerce_block_input(x)
        return _aes128_encrypt_block(block, key)

    def __call__(self, k: bytes, x) -> bytes:
        return self.evaluate(k, x)


def PRF(k: bytes, x, *, mode: str = "ggm", input_bits: int = BLOCK_BITS) -> bytes:
    """
    Convenience API requested by later assignments.

    mode='ggm' uses the PRG->PRF reduction.
    mode='aes' uses the AES plug-in PRF.
    """
    if mode == "ggm":
        return PRF_GGM(input_bits=input_bits).evaluate(k, x)
    if mode == "aes":
        return PRF_AES().evaluate(k, x)
    raise ValueError(f"Unknown PRF mode: {mode}")


def prg_from_prf_once(k: bytes, s=0, *, prf=None, input_bits: int = BLOCK_BITS) -> bytes:
    """
    Strict PRF -> PRG reduction:
      G_k(s) = F_k(s||0) || F_k(s||1)

    When ``input_bits`` is small (for example the UI's 8-bit demo setting), the
    state space is intentionally tiny and the stream will cycle quickly.
    """
    if input_bits < 2:
        raise ValueError("input_bits must be at least 2")
    prf_impl = prf if prf is not None else PRF_GGM(input_bits=input_bits)
    key = _coerce_key(k)
    seed_int = _coerce_domain_value(s, input_bits - 1)
    x0 = seed_int << 1
    x1 = x0 | 1
    return prf_impl.evaluate(key, x0) + prf_impl.evaluate(key, x1)


class PRG_from_PRF:
    """
    Stream wrapper over the strict reduction above.

    Each refill uses the textbook reduction on the current seed and then
    increments the seed modulo 2^(input_bits-1) to support longer outputs.
    """

    def __init__(self, prf=None, input_bits: int = BLOCK_BITS):
        if input_bits < 2:
            raise ValueError("input_bits must be at least 2")
        self._prf = prf if prf is not None else PRF_GGM(input_bits=input_bits)
        self.input_bits = input_bits
        self._key: bytes | None = None
        self._seed: int = 0
        self._buffer = bytearray()

    def seed(self, k: bytes, s=0):
        self._key = _coerce_key(k)
        self._seed = _coerce_domain_value(s, self.input_bits - 1)
        self._buffer.clear()

    def _require_seeded(self):
        if self._key is None:
            raise RuntimeError("call seed() before requesting output")

    def _expand(self):
        self._require_seeded()
        self._buffer.extend(
            prg_from_prf_once(
                self._key,
                self._seed,
                prf=self._prf,
                input_bits=self.input_bits,
            )
        )
        modulus = 1 << (self.input_bits - 1)
        self._seed = (self._seed + 1) % modulus

    def generate_bytes(self, n_bytes: int) -> bytes:
        if n_bytes < 0:
            raise ValueError("n_bytes must be non-negative")
        while len(self._buffer) < n_bytes:
            self._expand()
        chunk = bytes(self._buffer[:n_bytes])
        del self._buffer[:n_bytes]
        return chunk

    def next_bits(self, n: int) -> int:
        if n < 0:
            raise ValueError("n must be non-negative")
        n_bytes = (n + 7) // 8
        chunk = self.generate_bytes(n_bytes)
        value = int.from_bytes(chunk, "big")
        excess_bits = (8 * n_bytes) - n
        if excess_bits:
            value >>= excess_bits
        return value & ((1 << n) - 1) if n else 0


def distinguishing_game(
    n_queries: int = 32,
    input_bits: int = 8,
    *,
    prf=None,
    trials: int = 64,
) -> dict:
    """
    Compare a real PRF oracle with a truly random function oracle using a very
    lightweight output-bias sanity check.

    This is intentionally a toy classroom experiment, not a serious PRF
    distinguisher or proof-oriented adversary.
    """
    if n_queries <= 0:
        raise ValueError("n_queries must be positive")
    if trials <= 0:
        raise ValueError("trials must be positive")

    prf_impl = prf if prf is not None else PRF_AES()
    domain = [i % (1 << input_bits) for i in range(n_queries)]

    def sample_real_world() -> list[int]:
        key = os.urandom(BLOCK_BYTES)
        return [prf_impl.evaluate(key, x)[-1] & 1 for x in domain]

    def sample_random_world() -> list[int]:
        table = {}
        outputs = []
        for x in domain:
            if x not in table:
                table[x] = os.urandom(BLOCK_BYTES)
            outputs.append(table[x][-1] & 1)
        return outputs

    def zeros_ratio(bits: list[int]) -> float:
        return bits.count(0) / len(bits)

    real_ratios = [zeros_ratio(sample_real_world()) for _ in range(trials)]
    random_ratios = [zeros_ratio(sample_random_world()) for _ in range(trials)]

    real_mean = sum(real_ratios) / trials
    random_mean = sum(random_ratios) / trials
    statistical_distance = abs(real_mean - random_mean)

    return {
        "n_queries": n_queries,
        "trials": trials,
        "input_bits": input_bits,
        "real_zero_ratio": real_mean,
        "random_zero_ratio": random_mean,
        "statistical_distance": statistical_distance,
        "verdict": "indistinguishable" if statistical_distance < 0.10 else "distinguishable",
        "note": (
            "This demo only measures a simple bit-balance heuristic, so it is a "
            "pedagogical sanity check rather than a real PRF attack."
        ),
    }
