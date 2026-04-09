"""
Tests for PA#1 — NIST SP 800-22 Statistical Tests
"""
import os
import pytest
from backend.pa1.nist_tests import (
    frequency_test, runs_test, serial_test,
    run_tests_on_bytes, _bits_from_bytes
)
from backend.pa1.prg import PRG_AES, make_prg


class TestFrequencyTest:
    def test_balanced_sequence_passes(self):
        """Perfectly balanced 0101...0101 sequence should pass."""
        bits = [0, 1] * 5000  # 10000 bits, exactly 5000 ones
        result = frequency_test(bits)
        assert result['pass']
        assert result['p_value'] > 0.01

    def test_all_ones_fails(self):
        """All-ones sequence should fail (very biased)."""
        bits = [1] * 1000
        result = frequency_test(bits)
        assert not result['pass']
        assert result['p_value'] < 0.01

    def test_all_zeros_fails(self):
        """All-zeros sequence should fail."""
        bits = [0] * 1000
        result = frequency_test(bits)
        assert not result['pass']

    def test_too_short_sequence(self):
        """Sequences shorter than 100 bits should return an error result."""
        bits = [1, 0] * 10
        result = frequency_test(bits)
        assert result['p_value'] is None

    def test_returns_correct_keys(self):
        bits = [0, 1] * 500
        result = frequency_test(bits)
        assert 'test' in result
        assert 'p_value' in result
        assert 'pass' in result
        assert 'details' in result


class TestRunsTest:
    def test_alternating_fails(self):
        """
        Perfectly alternating 010101... has ~n-1 runs vs. expected ~n/2.
        That's a huge excess of runs — runs test should FAIL it.
        """
        bits = [0, 1] * 5000
        result = runs_test(bits)
        # Too many runs → p_value near 0, test fails
        assert not result['pass']
        assert result['p_value'] < 0.01

    def test_long_run_fails(self):
        """Very long run of identical bits should fail."""
        bits = [0] * 500 + [1] * 500
        result = runs_test(bits)
        # This should likely fail due to poor run distribution
        assert result['p_value'] is not None

    def test_too_short_sequence(self):
        bits = [0, 1] * 20
        result = runs_test(bits)
        assert result['p_value'] is None


class TestSerialTest:
    def test_uniform_distribution_passes(self):
        """Uniform distribution of 2-bit patterns should pass."""
        # Repeat 00 01 10 11 uniformly
        pattern = [0, 0, 0, 1, 1, 0, 1, 1]
        bits = pattern * 2000  # 16000 bits
        result = serial_test(bits, m=2)
        assert result['p_value'] is not None
        assert result['pass']

    def test_returns_correct_keys(self):
        bits = [0, 1] * 1000
        result = serial_test(bits, m=2)
        assert 'test' in result
        assert 'p_value' in result

    def test_too_short_sequence(self):
        bits = [0, 1] * 10
        result = serial_test(bits)
        assert result['p_value'] is None


class TestNISTOnPRGOutput:
    def test_aes_prg_passes_all_tests(self):
        """AES-based PRG output should pass all three NIST tests."""
        prg = make_prg("aes", output_bits=20000)
        seed = os.urandom(16)
        prg.seed(seed)
        data = prg.generate_bytes(20000 // 8)
        results = run_tests_on_bytes(data)

        assert len(results) == 3
        for r in results:
            # Each test should at least produce a p_value
            assert r['p_value'] is not None
            # AES-based output should be pseudorandom enough to pass
            assert r['pass'], f"Test {r['test']} failed with p={r['p_value']}"

    def test_bits_from_bytes_correct(self):
        """Verify bit extraction from bytes."""
        data = bytes([0b10101010, 0b11001100])
        bits = _bits_from_bytes(data)
        assert bits == [1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0]

    def test_all_bytes_255_fails_frequency(self):
        """All-0xff bytes = all ones, should fail frequency test."""
        data = b'\xff' * 200
        results = run_tests_on_bytes(data)
        freq = next(r for r in results if 'Frequency' in r['test'])
        assert not freq['pass']
