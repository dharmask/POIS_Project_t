"""
Tests for PA#1 — One-Way Function (OWF)
"""
import pytest
from backend.pa1.owf import owf_dlp, owf_aes, DLP_P, _aes128_encrypt_block


class TestDLPOWF:
    def test_output_in_range(self):
        """g^x mod p must be in [1, p-1]."""
        for x in [0, 1, 2, 100, 12345, 2**31]:
            result = owf_dlp(x)
            assert 1 <= result < DLP_P

    def test_deterministic(self):
        """Same input always gives same output."""
        assert owf_dlp(42) == owf_dlp(42)
        assert owf_dlp(0) == owf_dlp(0)

    def test_different_inputs_different_outputs(self):
        """Different inputs should almost certainly give different outputs."""
        outputs = {owf_dlp(i) for i in range(20)}
        assert len(outputs) == 20  # no collisions in small range

    def test_identity_element(self):
        """g^0 mod p == 1."""
        assert owf_dlp(0) == 1

    def test_invalid_input(self):
        with pytest.raises((ValueError, TypeError)):
            owf_dlp(-1)

    def test_large_exponent(self):
        """Large exponent should still work correctly."""
        x = 2 ** 255
        result = owf_dlp(x)
        assert 1 <= result < DLP_P

    def test_multiplicative_property(self):
        """g^(a+b) mod p == (g^a * g^b) mod p."""
        a, b = 17, 23
        lhs = owf_dlp(a + b)
        rhs = (owf_dlp(a) * owf_dlp(b)) % DLP_P
        assert lhs == rhs


class TestAESOWF:
    def test_output_length(self):
        """AES OWF output is always 16 bytes."""
        key = bytes(range(16))
        assert len(owf_aes(key)) == 16

    def test_deterministic(self):
        """Same key gives same output."""
        key = bytes(range(16))
        assert owf_aes(key) == owf_aes(key)

    def test_different_keys_different_outputs(self):
        """Different keys should give different outputs."""
        keys = [bytes([i] * 16) for i in range(16)]
        outputs = {owf_aes(k) for k in keys}
        assert len(outputs) == 16

    def test_not_identity(self):
        """f(k) != k (it's not an identity function)."""
        key = bytes(range(16))
        assert owf_aes(key) != key

    def test_zero_key(self):
        """Zero key should still produce valid 16-byte output."""
        key = b'\x00' * 16
        result = owf_aes(key)
        assert len(result) == 16
        assert result != key

    def test_invalid_key_length(self):
        with pytest.raises(ValueError):
            owf_aes(b'\x00' * 15)
        with pytest.raises(ValueError):
            owf_aes(b'\x00' * 17)


class TestAES128:
    """Unit tests for our scratch AES-128 implementation."""

    # FIPS 197 Appendix B test vector
    FIPS_KEY       = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    FIPS_PLAINTEXT = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
    FIPS_CIPHERTEXT= bytes.fromhex("3925841d02dc09fbdc118597196a0b32")

    def test_fips_vector(self):
        """Check against FIPS 197 Appendix B known-answer test."""
        ct = _aes128_encrypt_block(self.FIPS_PLAINTEXT, self.FIPS_KEY)
        assert ct == self.FIPS_CIPHERTEXT

    def test_all_zeros(self):
        """AES(0^128, 0^128) should equal well-known constant."""
        # NIST known answer: AES(key=0, pt=0) = 66e94bd4ef8a2c3b884cfa59ca342b2e
        key = b'\x00' * 16
        pt  = b'\x00' * 16
        ct = _aes128_encrypt_block(pt, key)
        assert ct == bytes.fromhex("66e94bd4ef8a2c3b884cfa59ca342b2e")

    def test_output_length(self):
        ct = _aes128_encrypt_block(b'\x01' * 16, b'\x02' * 16)
        assert len(ct) == 16
