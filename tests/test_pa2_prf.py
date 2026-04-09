"""
Tests for PA#2 - PRF and the PRG<->PRF reductions.
"""

import os

import pytest

from backend.pa2.prf import (
    PRF,
    PRF_AES,
    PRF_GGM,
    PRG_from_PRF,
    _doubling_prg,
    distinguishing_game,
    prg_from_prf_once,
)


class TestDoublingPRG:
    def test_output_lengths(self):
        left, right = _doubling_prg(os.urandom(16))
        assert len(left) == 16
        assert len(right) == 16

    def test_is_deterministic_for_fixed_seed(self):
        seed = bytes(range(16))
        assert _doubling_prg(seed) == _doubling_prg(seed)

    def test_left_and_right_halves_differ(self):
        left, right = _doubling_prg(os.urandom(16))
        assert left != right


class TestPRFGGM:
    def setup_method(self):
        self.prf = PRF_GGM(input_bits=8)
        self.key = os.urandom(16)

    def test_output_length(self):
        assert len(self.prf.evaluate(self.key, 42)) == 16

    def test_is_deterministic(self):
        assert self.prf.evaluate(self.key, 42) == self.prf.evaluate(self.key, 42)

    def test_distinguishes_small_domain_inputs(self):
        outputs = {self.prf.evaluate(self.key, x) for x in range(16)}
        assert len(outputs) == 16

    def test_accepts_bytes_inputs(self):
        assert self.prf.evaluate(self.key, b"\x2a") == self.prf.evaluate(self.key, 42)

    def test_rejects_out_of_range_input(self):
        with pytest.raises(ValueError):
            self.prf.evaluate(self.key, 1 << 8)


class TestPRFAES:
    def setup_method(self):
        self.prf = PRF_AES()
        self.key = os.urandom(16)

    def test_output_length(self):
        assert len(self.prf.evaluate(self.key, 0)) == 16

    def test_is_deterministic(self):
        assert self.prf.evaluate(self.key, 9) == self.prf.evaluate(self.key, 9)

    def test_accepts_bytes_and_ints(self):
        assert self.prf.evaluate(self.key, 255) == self.prf.evaluate(self.key, b"\xff")


class TestPRFConvenienceAPI:
    def test_ggm_mode_matches_class(self):
        key = os.urandom(16)
        x = 17
        assert PRF(key, x, mode="ggm", input_bits=8) == PRF_GGM(input_bits=8).evaluate(key, x)

    def test_aes_mode_matches_class(self):
        key = os.urandom(16)
        x = 1234
        assert PRF(key, x, mode="aes") == PRF_AES().evaluate(key, x)


class TestPRGFromPRFReduction:
    def test_one_step_reduction_matches_definition(self):
        key = os.urandom(16)
        prf = PRF_GGM(input_bits=8)
        seed = 0b1010101
        reduced = prg_from_prf_once(key, seed, prf=prf, input_bits=8)
        expected = prf.evaluate(key, seed << 1) + prf.evaluate(key, (seed << 1) | 1)
        assert reduced == expected

    def test_stream_wrapper_is_deterministic(self):
        key = os.urandom(16)
        prg1 = PRG_from_PRF(input_bits=8)
        prg2 = PRG_from_PRF(input_bits=8)
        prg1.seed(key, 5)
        prg2.seed(key, 5)
        assert prg1.generate_bytes(48) == prg2.generate_bytes(48)

    def test_requires_seed(self):
        prg = PRG_from_PRF(input_bits=8)
        with pytest.raises(RuntimeError):
            prg.generate_bytes(1)

    def test_next_bits_returns_integer(self):
        key = os.urandom(16)
        prg = PRG_from_PRF(input_bits=8)
        prg.seed(key, 3)
        assert isinstance(prg.next_bits(17), int)

    def test_next_bits_masks_to_requested_width(self):
        key = os.urandom(16)
        prg = PRG_from_PRF(input_bits=8)
        prg.seed(key, 7)
        value = prg.next_bits(13)
        assert 0 <= value < (1 << 13)


class TestDistinguishingGame:
    def test_result_shape(self):
        result = distinguishing_game(n_queries=10, input_bits=4, trials=12)
        assert "real_zero_ratio" in result
        assert "random_zero_ratio" in result
        assert "statistical_distance" in result
        assert result["verdict"] in {"indistinguishable", "distinguishable"}

    def test_distance_is_bounded(self):
        result = distinguishing_game(n_queries=40, input_bits=8, trials=20)
        assert 0.0 <= result["statistical_distance"] <= 1.0
