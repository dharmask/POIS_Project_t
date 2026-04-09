"""
PA#9 - Birthday attack and collision-finding experiments.

Implements both the standard hash-table birthday attack and a space-efficient
Floyd cycle-finding variant over n-bit truncated hash outputs.
"""

from __future__ import annotations

import math
import os
import statistics
from typing import Callable, Literal

from backend.pa8.dlp_hash import DLPHash, FULL_PARAMS


HashKind = Literal["toy", "dlp"]
AttackKind = Literal["naive", "floyd"]


def _mask(n_bits: int) -> int:
    if n_bits <= 0:
        raise ValueError("n_bits must be positive")
    return (1 << n_bits) - 1


def _byte_length(n_bits: int) -> int:
    return max(1, (n_bits + 7) // 8)


def _int_to_bytes(value: int, n_bits: int) -> bytes:
    return (value & _mask(n_bits)).to_bytes(_byte_length(n_bits), "big")


def _truncate_to_int(value: bytes | int | str, n_bits: int) -> int:
    if isinstance(value, bytes):
        integer = int.from_bytes(value, "big")
    elif isinstance(value, str):
        integer = int(value, 16)
    else:
        integer = int(value)
    return integer & _mask(n_bits)


def _hash_hex(value: int, n_bits: int) -> str:
    return _int_to_bytes(value, n_bits).hex()


def birthday_collision_probability(queries: int, n_bits: int) -> float:
    if queries <= 0:
        return 0.0
    exponent = -(queries * (queries - 1)) / float(2 ** (n_bits + 1))
    return 1.0 - math.exp(exponent)


def weak_toy_hash(message: bytes, output_bits: int) -> bytes:
    """
    A deliberately weak toy hash with a tiny internal state.

    This is not intended to be secure; it simply gives a deterministic n-bit
    digest that is cheap enough for repeated collision experiments.
    """

    mask = _mask(output_bits)
    state = 0x9E3779B1 & mask
    if state == 0:
        state = 1

    rotate = min(5, max(1, output_bits - 1))
    for index, byte in enumerate(message, start=1):
        state = (state * 257 + byte + 17 * index) & mask
        mixed = ((state << rotate) | (state >> max(1, output_bits - rotate))) & mask
        state ^= mixed
        state ^= (byte * 131) & mask
        state &= mask

    state ^= (len(message) * 0x45D9F3B) & mask
    return _int_to_bytes(state, output_bits)


def _select_hash(hash_kind: HashKind, n_bits: int) -> tuple[Callable[[bytes], bytes], int, str]:
    if hash_kind == "toy":
        return (
            lambda message: weak_toy_hash(message, n_bits),
            max(4, _byte_length(n_bits)),
            "Deliberately weak toy hash",
        )

    hasher = DLPHash(FULL_PARAMS)
    return (
        lambda message: hasher.hash_truncated(message, n_bits),
        max(2, _byte_length(n_bits)),
        "PA8 DLP hash truncated to n bits",
    )


def birthday_attack(
    hash_fn: Callable[[bytes], bytes | int | str],
    n_bits: int,
    num_trials: int | None = None,
    *,
    max_attempts: int | None = None,
    message_bytes: int | None = None,
    message_factory: Callable[[int], bytes] | None = None,
) -> dict:
    """
    Standard birthday attack using a dictionary of seen digests.

    `num_trials` is accepted as an alias for `max_attempts` to match common
    assignment wording.
    """

    if max_attempts is None:
        max_attempts = num_trials
    if max_attempts is None:
        max_attempts = max(32, int(8 * math.ceil(2 ** (n_bits / 2))))
    if message_bytes is None:
        message_bytes = max(4, _byte_length(n_bits))

    seen: dict[int, bytes] = {}
    evaluations = 0

    for attempt in range(max_attempts):
        candidate = (
            os.urandom(message_bytes)
            if message_factory is None
            else bytes(message_factory(attempt))
        )
        digest_int = _truncate_to_int(hash_fn(candidate), n_bits)
        evaluations += 1

        previous = seen.get(digest_int)
        if previous is not None and previous != candidate:
            expected = 2 ** (n_bits / 2)
            return {
                "algorithm": "naive",
                "space_complexity": "O(k)",
                "n_bits": n_bits,
                "evaluations": evaluations,
                "expected_work": expected,
                "ratio_to_birthday_bound": evaluations / expected,
                "input1_hex": previous.hex(),
                "input2_hex": candidate.hex(),
                "collision_digest_hex": _hash_hex(digest_int, n_bits),
            }

        seen[digest_int] = candidate

    raise ValueError("no collision found within the allotted attempts")


def floyd_cycle_collision_attack(
    hash_fn: Callable[[bytes], bytes | int | str],
    n_bits: int,
    *,
    seed: int | None = None,
    max_restarts: int = 24,
) -> dict:
    """
    Space-efficient collision search using Floyd's tortoise-and-hare method.

    We iterate the map f(x) = H(x) on n-bit states and extract two distinct
    predecessors that land on the same output.
    """

    message_bytes = _byte_length(n_bits)
    if seed is None:
        seed = int.from_bytes(os.urandom(message_bytes), "big") & _mask(n_bits)

    def base_state_fn(state: int) -> int:
        return _truncate_to_int(hash_fn(_int_to_bytes(state, n_bits)), n_bits)

    expected = 2 ** (n_bits / 2)
    total_evaluations = 0

    for restart in range(max_restarts):
        start = (seed + restart * 0x9E3779B1) & _mask(n_bits)
        evaluations = 0

        def step(state: int) -> int:
            nonlocal evaluations
            evaluations += 1
            return base_state_fn(state)

        def advance(state: int, steps: int) -> int:
            current = state
            for _ in range(steps):
                current = step(current)
            return current

        tortoise = step(start)
        hare = step(step(start))

        while tortoise != hare:
            tortoise = step(tortoise)
            hare = step(step(hare))

        mu = 0
        tortoise = start
        while tortoise != hare:
            tortoise = step(tortoise)
            hare = step(hare)
            mu += 1

        lam = 1
        hare = step(tortoise)
        while tortoise != hare:
            hare = step(hare)
            lam += 1

        if mu == 0:
            total_evaluations += evaluations
            continue

        entry = advance(start, mu)
        predecessor_a = advance(start, mu - 1)
        predecessor_b = entry if lam == 1 else advance(entry, lam - 1)
        output_a = step(predecessor_a)
        output_b = step(predecessor_b)

        total_evaluations += evaluations
        if predecessor_a == predecessor_b or output_a != output_b:
            continue

        return {
            "algorithm": "floyd",
            "space_complexity": "O(1)",
            "n_bits": n_bits,
            "evaluations": total_evaluations,
            "expected_work": expected,
            "ratio_to_birthday_bound": total_evaluations / expected,
            "input1_hex": _int_to_bytes(predecessor_a, n_bits).hex(),
            "input2_hex": _int_to_bytes(predecessor_b, n_bits).hex(),
            "collision_digest_hex": _hash_hex(output_a, n_bits),
            "cycle_entry_hex": _int_to_bytes(entry, n_bits).hex(),
            "mu": mu,
            "lambda": lam,
            "restarts": restart,
        }

    raise ValueError("failed to extract a collision with Floyd cycle finding")


def run_collision_attack(
    hash_kind: HashKind = "toy",
    algorithm: AttackKind = "naive",
    n_bits: int = 16,
) -> dict:
    hash_fn, message_bytes, description = _select_hash(hash_kind, n_bits)
    if algorithm == "naive":
        result = birthday_attack(hash_fn, n_bits, message_bytes=message_bytes)
    else:
        result = floyd_cycle_collision_attack(hash_fn, n_bits)

    return {
        **result,
        "hash_kind": hash_kind,
        "hash_description": description,
    }


def compare_algorithms_on_toy_hash(
    n_values: tuple[int, ...] = (8, 12, 16),
    trials: int = 24,
) -> dict:
    hash_kind: HashKind = "toy"
    results = []

    for n_bits in n_values:
        hash_fn, message_bytes, description = _select_hash(hash_kind, n_bits)
        naive_counts = []
        floyd_counts = []

        for _ in range(trials):
            naive_counts.append(
                birthday_attack(hash_fn, n_bits, message_bytes=message_bytes)["evaluations"]
            )
            floyd_counts.append(
                floyd_cycle_collision_attack(hash_fn, n_bits)["evaluations"]
            )

        expected = 2 ** (n_bits / 2)
        results.append(
            {
                "n_bits": n_bits,
                "expected_work": expected,
                "naive": _summary_from_counts(naive_counts, expected),
                "floyd": _summary_from_counts(floyd_counts, expected),
                "hash_description": description,
            }
        )

    return {
        "hash_kind": hash_kind,
        "trials": trials,
        "results": results,
    }


def empirical_birthday_curve(
    n_values: tuple[int, ...] = (8, 10, 12, 14, 16),
    trials: int = 100,
) -> dict:
    hash_fn_cache: dict[int, tuple[Callable[[bytes], bytes], int, str]] = {}
    curves = []

    for n_bits in n_values:
        if n_bits not in hash_fn_cache:
            hash_fn_cache[n_bits] = _select_hash("toy", n_bits)
        hash_fn, message_bytes, description = hash_fn_cache[n_bits]

        counts = [
            birthday_attack(hash_fn, n_bits, message_bytes=message_bytes)["evaluations"]
            for _ in range(trials)
        ]
        expected = 2 ** (n_bits / 2)
        max_queries = max(counts) + 8
        empirical_points = []
        theoretical_points = []

        sorted_counts = sorted(counts)
        cursor = 0
        for queries in range(1, max_queries + 1):
            while cursor < len(sorted_counts) and sorted_counts[cursor] <= queries:
                cursor += 1
            empirical_points.append(
                {
                    "queries": queries,
                    "probability": cursor / trials,
                }
            )
            theoretical_points.append(
                {
                    "queries": queries,
                    "probability": birthday_collision_probability(queries, n_bits),
                }
            )

        curves.append(
            {
                "n_bits": n_bits,
                "expected_work": expected,
                "trial_counts": counts,
                "summary": _summary_from_counts(counts, expected),
                "empirical_curve": empirical_points,
                "theoretical_curve": theoretical_points,
                "hash_description": description,
            }
        )

    return {
        "hash_kind": "toy",
        "trials": trials,
        "curves": curves,
    }


def build_live_demo(n_bits: int = 12) -> dict:
    result = run_collision_attack("toy", "naive", n_bits)
    expected = result["expected_work"]
    limit = max(result["evaluations"] + 12, int(math.ceil(expected * 3)))
    theory_points = [
        {
            "queries": queries,
            "probability": birthday_collision_probability(queries, n_bits),
        }
        for queries in range(1, limit + 1)
    ]
    return {
        **result,
        "chart_limit": limit,
        "expected_marker": expected,
        "theoretical_curve": theory_points,
    }


def modern_hash_context(hash_rate_per_second: int = 10**9) -> dict:
    if hash_rate_per_second <= 0:
        raise ValueError("hash_rate_per_second must be positive")

    results = []
    for algorithm, n_bits in (("MD5", 128), ("SHA-1", 160)):
        work = 2 ** (n_bits / 2)
        seconds = work / hash_rate_per_second
        years = seconds / (60 * 60 * 24 * 365.25)
        results.append(
            {
                "algorithm": algorithm,
                "output_bits": n_bits,
                "birthday_work": work,
                "birthday_work_sci": f"{work:.3e}",
                "seconds_at_rate": seconds,
                "seconds_at_rate_sci": f"{seconds:.3e}",
                "years_at_rate": years,
                "years_at_rate_sci": f"{years:.3e}",
            }
        )

    return {
        "hash_rate_per_second": hash_rate_per_second,
        "results": results,
    }


def _summary_from_counts(counts: list[int], expected: float) -> dict:
    return {
        "min": min(counts),
        "max": max(counts),
        "mean": statistics.fmean(counts),
        "median": statistics.median(counts),
        "ratio_mean_to_bound": statistics.fmean(counts) / expected,
    }
