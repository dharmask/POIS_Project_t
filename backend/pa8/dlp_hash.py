"""
PA#8 - DLP-based collision-resistant hash function.

Builds a Merkle-Damgard hash from the PA#7 framework using the compression
function

    Compress(x, y) = g^x * h_hat^y mod p

over a prime-order subgroup of Z_p* where p = 2q + 1 and q is prime.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from typing import Callable

from backend.pa1.owf import DLP_P
from backend.pa5.pubkey import _is_probable_prime, _mod_inverse
from backend.pa7.merkle_damgard import MerkleDamgard


FULL_H_HAT = int(
    "6d1ca524d28913d467412bd6e5a08f169de3a623d449b0ea4a9d0f44a69ef3ba"
    "9a6c33ae2c1e04d679a94dfdbdafbcd6b12155669cbd076346f023e106a53b75"
    "de2ba98d1599760fd2cd2c5ec6aa8f859042384a96c70b950acc0b7fa37a2182",
    16,
)


@dataclass(frozen=True, slots=True)
class DLPHashParams:
    name: str
    p: int
    q: int
    g: int
    h_hat: int
    group_bytes: int
    block_bytes: int
    demo_alpha: int | None = None

    @property
    def q_bytes(self) -> int:
        return max(1, (self.q.bit_length() + 7) // 8)


def mod_exp(base: int, exp: int, mod: int) -> int:
    return pow(base, exp, mod)


def mod_inv(value: int, mod: int) -> int:
    return _mod_inverse(value, mod)


def int_to_bytes(value: int, length: int | None = None) -> bytes:
    if value < 0:
        raise ValueError("value must be non-negative")
    if length is None:
        length = max(1, (value.bit_length() + 7) // 8)
    return value.to_bytes(length, "big")


def bytes_to_int(data: bytes) -> int:
    return int.from_bytes(bytes(data), "big")


def bytes_to_zq(data: bytes, q: int) -> int:
    return bytes_to_int(data) % q


def random_zq(q: int) -> int:
    if q <= 2:
        raise ValueError("q must be greater than 2")
    nbytes = max(1, (q.bit_length() + 7) // 8)
    while True:
        candidate = int.from_bytes(os.urandom(nbytes), "big") % q
        if candidate != 0:
            return candidate


def find_subgroup_generator(p: int, q: int) -> int:
    if p != 2 * q + 1:
        raise ValueError("expected a safe prime p = 2q + 1")
    for candidate in range(2, min(p - 1, 512)):
        g = mod_exp(candidate, 2, p)
        if g != 1 and mod_exp(g, q, p) == 1:
            return g
    raise ValueError("could not find subgroup generator")


def generate_safe_prime_subgroup(q_bits: int = 128) -> DLPHashParams:
    if q_bits < 8:
        raise ValueError("q_bits must be at least 8")

    q_bytes = (q_bits + 7) // 8
    while True:
        q = int.from_bytes(os.urandom(q_bytes), "big")
        q |= (1 << (q_bits - 1)) | 1
        if not _is_probable_prime(q):
            continue
        p = 2 * q + 1
        if not _is_probable_prime(p):
            continue
        g = find_subgroup_generator(p, q)
        alpha = random_zq(q)
        h_hat = mod_exp(g, alpha, p)
        group_bytes = max(1, (p.bit_length() + 7) // 8)
        return DLPHashParams(
            name=f"generated-{q_bits}-bit-subgroup",
            p=p,
            q=q,
            g=g,
            h_hat=h_hat,
            group_bytes=group_bytes,
            block_bytes=group_bytes,
            demo_alpha=None,
        )


FULL_PARAMS = DLPHashParams(
    name="full-safe-prime",
    p=DLP_P,
    q=(DLP_P - 1) // 2,
    g=4,
    h_hat=FULL_H_HAT,
    group_bytes=max(1, (DLP_P.bit_length() + 7) // 8),
    block_bytes=max(1, (DLP_P.bit_length() + 7) // 8),
)


TOY_PARAMS = DLPHashParams(
    name="toy-safe-prime",
    p=32843,
    q=16421,
    g=4,
    h_hat=0x37B,
    group_bytes=2,
    block_bytes=2,
    demo_alpha=1337,
)


def compress_pair(x: int, y: int, params: DLPHashParams = FULL_PARAMS) -> int:
    x_q = x % params.q
    y_q = y % params.q
    gx = mod_exp(params.g, x_q, params.p)
    hy = mod_exp(params.h_hat, y_q, params.p)
    return (gx * hy) % params.p


def compress_bytes(
    chaining_value: bytes,
    block: bytes,
    params: DLPHashParams = FULL_PARAMS,
) -> bytes:
    x = bytes_to_zq(chaining_value, params.q)
    y = bytes_to_zq(block, params.q)
    return int_to_bytes(compress_pair(x, y, params), params.group_bytes)


def truncate_digest(digest: bytes, output_bits: int | None) -> bytes:
    data = bytes(digest)
    if output_bits is None:
        return data
    if output_bits <= 0:
        raise ValueError("output_bits must be positive")
    full = bytes_to_int(data)
    mask = (1 << output_bits) - 1
    truncated = full & mask
    out_len = max(1, (output_bits + 7) // 8)
    return int_to_bytes(truncated, out_len)


class DLPHash:
    def __init__(self, params: DLPHashParams = FULL_PARAMS):
        self.params = params
        self.iv = bytes(self.params.group_bytes)

    def merkle_damgard(self) -> MerkleDamgard:
        return MerkleDamgard(
            compress=lambda cv, block: compress_bytes(cv, block, self.params),
            iv=self.iv,
            block_size=self.params.block_bytes,
            output_size=self.params.group_bytes,
        )

    def hash_bytes(self, message: bytes, output_bits: int | None = None) -> bytes:
        digest = self.merkle_damgard().hash(bytes(message))
        return truncate_digest(digest, output_bits)

    def hash_hex(self, message: bytes, output_bits: int | None = None) -> str:
        return self.hash_bytes(message, output_bits).hex()

    def hash_truncated(self, message: bytes, output_bits: int) -> bytes:
        return self.hash_bytes(message, output_bits)

    def trace(self, message: bytes, output_bits: int | None = None) -> dict:
        md = self.merkle_damgard()
        result = md.trace(bytes(message))
        enriched_steps = []
        for step in result["steps"]:
            chaining_bytes = bytes.fromhex(step["chaining_in_hex"])
            block_bytes = bytes.fromhex(step["block_hex"])
            chaining_zq = bytes_to_zq(chaining_bytes, self.params.q)
            block_zq = bytes_to_zq(block_bytes, self.params.q)
            enriched_steps.append(
                {
                    **step,
                    "chaining_value_zq": str(chaining_zq),
                    "block_value_zq": str(block_zq),
                    "compression_formula": (
                        f"g^{chaining_zq} * h_hat^{block_zq} mod p"
                    ),
                }
            )

        full_digest = bytes.fromhex(result["digest_hex"])
        digest = truncate_digest(full_digest, output_bits)
        return {
            **result,
            "parameter_set": self.params.name,
            "group_bits": self.params.p.bit_length(),
            "q_bits": self.params.q.bit_length(),
            "p_hex": hex(self.params.p),
            "q_hex": hex(self.params.q),
            "g_hex": hex(self.params.g),
            "h_hat_hex": hex(self.params.h_hat),
            "full_digest_hex": full_digest.hex(),
            "digest_hex": digest.hex(),
            "output_bits": output_bits or len(full_digest) * 8,
            "steps": enriched_steps,
        }


def hash_bytes(message: bytes, output_bits: int | None = None, params: DLPHashParams = FULL_PARAMS) -> bytes:
    return DLPHash(params).hash_bytes(message, output_bits)


def hash_hex(message: bytes, output_bits: int | None = None, params: DLPHashParams = FULL_PARAMS) -> str:
    return DLPHash(params).hash_hex(message, output_bits)


def hash_truncated(message: bytes, bits: int, params: DLPHashParams = FULL_PARAMS) -> bytes:
    return DLPHash(params).hash_truncated(message, bits)


def recover_alpha_from_collision(
    x: int,
    y: int,
    x_prime: int,
    y_prime: int,
    q: int,
) -> int:
    denominator = (y_prime - y) % q
    if denominator == 0:
        raise ValueError("cannot recover alpha when y == y_prime mod q")
    numerator = (x - x_prime) % q
    return (numerator * mod_inv(denominator, q)) % q


def compression_collision_reduction_demo(
    params: DLPHashParams = TOY_PARAMS,
    max_attempts: int = 5000,
    pair_factory: Callable[[int], tuple[int, int]] | None = None,
) -> dict:
    seen: dict[int, tuple[int, int]] = {}
    for attempt in range(max_attempts):
        if pair_factory is None:
            x = random_zq(params.q)
            y = random_zq(params.q)
        else:
            x, y = pair_factory(attempt)
            x %= params.q
            y %= params.q

        output = compress_pair(x, y, params)
        previous = seen.get(output)
        if previous is not None and previous != (x, y):
            prev_x, prev_y = previous
            if (prev_y - y) % params.q != 0:
                recovered_alpha = recover_alpha_from_collision(prev_x, prev_y, x, y, params.q)
                expected = params.demo_alpha
                return {
                    "attempts": attempt + 1,
                    "collision_found": True,
                    "pair1": {"x": prev_x, "y": prev_y},
                    "pair2": {"x": x, "y": y},
                    "compression_output_hex": hex(output),
                    "recovered_alpha": recovered_alpha,
                    "expected_alpha": expected,
                    "recovery_matches": expected is None or recovered_alpha == expected,
                }
        seen[output] = (x, y)

    raise ValueError("failed to find a compression collision in the allotted attempts")


def birthday_collision_demo(
    bits: int = 16,
    params: DLPHashParams = TOY_PARAMS,
    max_attempts: int = 200000,
    message_bytes: int = 8,
    message_factory: Callable[[int], bytes] | None = None,
) -> dict:
    if bits <= 0:
        raise ValueError("bits must be positive")
    hasher = DLPHash(params)
    seen: dict[str, bytes] = {}

    for attempt in range(max_attempts):
        if message_factory is None:
            candidate = os.urandom(message_bytes)
        else:
            candidate = bytes(message_factory(attempt))
        digest = hasher.hash_truncated(candidate, bits)
        digest_hex = digest.hex()
        previous = seen.get(digest_hex)
        if previous is not None and previous != candidate:
            reduction_demo = compression_collision_reduction_demo(params)
            return {
                "bits": bits,
                "attempts": attempt + 1,
                "message1_hex": previous.hex(),
                "message2_hex": candidate.hex(),
                "truncated_digest_hex": digest_hex,
                "full_digest1_hex": hasher.hash_hex(previous),
                "full_digest2_hex": hasher.hash_hex(candidate),
                "expected_birthday_work": 2 ** (bits / 2),
                "parameter_set": params.name,
                "compression_reduction_demo": reduction_demo,
            }
        seen[digest_hex] = candidate

    raise ValueError("no collision found within the allotted attempts")
