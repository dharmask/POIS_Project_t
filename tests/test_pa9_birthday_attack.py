"""
Tests for PA#9 - Birthday attack.
"""

from backend.pa9.birthday_attack import (
    birthday_attack,
    birthday_collision_probability,
    build_live_demo,
    compare_algorithms_on_toy_hash,
    empirical_birthday_curve,
    floyd_cycle_collision_attack,
    modern_hash_context,
    run_collision_attack,
    weak_toy_hash,
)


class TestToyHash:
    def test_toy_hash_is_deterministic(self):
        message = b"birthday"
        assert weak_toy_hash(message, 12) == weak_toy_hash(message, 12)


class TestBirthdayAttack:
    def test_naive_attack_finds_collision_on_toy_hash(self):
        result = birthday_attack(
            lambda message: weak_toy_hash(message, 8),
            8,
            max_attempts=400,
            message_bytes=2,
            message_factory=lambda i: i.to_bytes(2, "big"),
        )
        assert result["input1_hex"] != result["input2_hex"]
        assert result["collision_digest_hex"] != ""
        assert result["evaluations"] <= 400

    def test_floyd_attack_finds_collision_on_toy_hash(self):
        result = floyd_cycle_collision_attack(
            lambda message: weak_toy_hash(message, 8),
            8,
            seed=7,
        )
        assert result["input1_hex"] != result["input2_hex"]
        assert result["collision_digest_hex"] != ""
        assert result["mu"] > 0

    def test_dlp_truncated_attack_runs_end_to_end(self):
        result = run_collision_attack("dlp", "naive", 8)
        assert result["hash_kind"] == "dlp"
        assert result["input1_hex"] != result["input2_hex"]
        assert result["collision_digest_hex"] != ""


class TestExperimentHelpers:
    def test_probability_curve_is_monotone(self):
        p16 = birthday_collision_probability(16, 8)
        p32 = birthday_collision_probability(32, 8)
        assert 0 <= p16 < p32 < 1

    def test_compare_algorithms_returns_both_strategies(self):
        result = compare_algorithms_on_toy_hash((8,), trials=4)
        row = result["results"][0]
        assert row["n_bits"] == 8
        assert row["naive"]["mean"] > 0
        assert row["floyd"]["mean"] > 0

    def test_empirical_curve_returns_trials_and_points(self):
        result = empirical_birthday_curve((8,), trials=6)
        curve = result["curves"][0]
        assert len(curve["trial_counts"]) == 6
        assert len(curve["empirical_curve"]) == len(curve["theoretical_curve"])
        assert curve["empirical_curve"][-1]["probability"] >= curve["empirical_curve"][0]["probability"]

    def test_live_demo_includes_chart_and_collision(self):
        result = build_live_demo(8)
        assert result["evaluations"] > 0
        assert result["expected_marker"] == 16.0
        assert len(result["theoretical_curve"]) == result["chart_limit"]

    def test_modern_hash_context_scales_with_output_bits(self):
        result = modern_hash_context()
        md5, sha1 = result["results"]
        assert md5["algorithm"] == "MD5"
        assert sha1["algorithm"] == "SHA-1"
        assert sha1["birthday_work"] > md5["birthday_work"]
