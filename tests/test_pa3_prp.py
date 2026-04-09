"""
Tests for PA#3 — Pseudorandom Permutation (PRP) + AES Modes of Operation
"""
import os
import pytest
from backend.pa3.prp import (
    PRP_AES,
    _aes128_decrypt_block,
    pkcs7_pad, pkcs7_unpad,
    ecb_encrypt, ecb_decrypt, ecb_pattern_demo,
    cbc_encrypt, cbc_decrypt,
    ctr_crypt,
    padding_oracle_attack,
    switching_lemma,
)
from backend.pa1.owf import _aes128_encrypt_block


# ---------------------------------------------------------------------------
# AES Decryption
# ---------------------------------------------------------------------------

class TestAESDecrypt:
    def test_decrypt_inverts_encrypt(self):
        key = os.urandom(16)
        pt = os.urandom(16)
        ct = _aes128_encrypt_block(pt, key)
        assert _aes128_decrypt_block(ct, key) == pt

    def test_decrypt_known_vector(self):
        """NIST zero-key / zero-plaintext: encrypt then decrypt round-trip."""
        key = b'\x00' * 16
        pt = b'\x00' * 16
        ct = _aes128_encrypt_block(pt, key)
        assert _aes128_decrypt_block(ct, key) == pt

    def test_decrypt_invalid_lengths(self):
        with pytest.raises(ValueError):
            _aes128_decrypt_block(b'\x00' * 15, b'\x00' * 16)
        with pytest.raises(ValueError):
            _aes128_decrypt_block(b'\x00' * 16, b'\x00' * 15)

    def test_multiple_round_trips(self):
        for _ in range(5):
            key, pt = os.urandom(16), os.urandom(16)
            assert _aes128_decrypt_block(_aes128_encrypt_block(pt, key), key) == pt


# ---------------------------------------------------------------------------
# PKCS#7 Padding
# ---------------------------------------------------------------------------

class TestPKCS7:
    def test_pad_full_block(self):
        data = b'\xaa' * 16
        padded = pkcs7_pad(data)
        assert len(padded) == 32
        assert padded[16:] == bytes([16] * 16)

    def test_pad_partial(self):
        data = b'\xbb' * 10
        padded = pkcs7_pad(data)
        assert len(padded) == 16
        assert padded[10:] == bytes([6] * 6)

    def test_pad_empty(self):
        padded = pkcs7_pad(b'')
        assert len(padded) == 16
        assert padded == bytes([16] * 16)

    def test_unpad_roundtrip(self):
        for n in range(1, 33):
            data = os.urandom(n)
            assert pkcs7_unpad(pkcs7_pad(data)) == data

    def test_unpad_full_block_padding(self):
        padded = (b'\x10' * 16) + (b'\x10' * 16)
        assert pkcs7_unpad(padded) == b'\x10' * 16

    def test_unpad_invalid_length(self):
        with pytest.raises(ValueError):
            pkcs7_unpad(b'\x00' * 15)

    def test_unpad_invalid_padding_byte(self):
        bad = b'\x00' * 15 + b'\x00'
        with pytest.raises(ValueError):
            pkcs7_unpad(bad)

    def test_unpad_inconsistent_padding(self):
        bad = b'\x00' * 14 + bytes([2, 3])
        with pytest.raises(ValueError):
            pkcs7_unpad(bad)


# ---------------------------------------------------------------------------
# PRP_AES class
# ---------------------------------------------------------------------------

class TestPRPAES:
    def setup_method(self):
        self.key = os.urandom(16)
        self.prp = PRP_AES(self.key)

    def test_forward_returns_16_bytes(self):
        assert len(self.prp.forward(os.urandom(16))) == 16

    def test_inverse_returns_16_bytes(self):
        ct = self.prp.forward(os.urandom(16))
        assert len(self.prp.inverse(ct)) == 16

    def test_bijection(self):
        pt = os.urandom(16)
        assert self.prp.verify_bijection(pt) is True

    def test_inverse_of_forward(self):
        pt = os.urandom(16)
        assert self.prp.inverse(self.prp.forward(pt)) == pt

    def test_forward_of_inverse(self):
        ct = os.urandom(16)
        assert self.prp.forward(self.prp.inverse(ct)) == ct

    def test_deterministic(self):
        pt = b'\xcc' * 16
        assert self.prp.forward(pt) == self.prp.forward(pt)

    def test_different_keys_different_outputs(self):
        pt = b'\xdd' * 16
        prp2 = PRP_AES(os.urandom(16))
        assert self.prp.forward(pt) != prp2.forward(pt)

    def test_invalid_key_length(self):
        with pytest.raises(ValueError):
            PRP_AES(b'\x00' * 15)


# ---------------------------------------------------------------------------
# ECB Mode
# ---------------------------------------------------------------------------

class TestECB:
    def setup_method(self):
        self.key = os.urandom(16)

    def test_encrypt_decrypt_roundtrip(self):
        pt = b"Hello ECB World!"
        assert ecb_decrypt(ecb_encrypt(pt, self.key), self.key) == pt

    def test_variable_lengths(self):
        for n in [1, 15, 16, 17, 31, 32, 48]:
            pt = os.urandom(n)
            assert ecb_decrypt(ecb_encrypt(pt, self.key), self.key) == pt

    def test_identical_blocks_produce_identical_ciphertext(self):
        block = b"YELLOW SUBMARINE"
        ct = ecb_encrypt(block + block, self.key)
        assert ct[:16] == ct[16:32]

    def test_pattern_demo(self):
        result = ecb_pattern_demo(self.key)
        assert result["identical_blocks_leaked"] is True
        assert len(result["ciphertext_blocks"]) == 4

    def test_decrypt_invalid_length(self):
        with pytest.raises(ValueError):
            ecb_decrypt(b'\x00' * 15, self.key)


# ---------------------------------------------------------------------------
# CBC Mode
# ---------------------------------------------------------------------------

class TestCBC:
    def setup_method(self):
        self.key = os.urandom(16)

    def test_encrypt_decrypt_roundtrip(self):
        pt = b"Hello CBC World!"
        iv, ct = cbc_encrypt(pt, self.key)
        assert cbc_decrypt(ct, self.key, iv) == pt

    def test_variable_lengths(self):
        for n in [1, 15, 16, 17, 31, 32, 64]:
            pt = os.urandom(n)
            iv, ct = cbc_encrypt(pt, self.key)
            assert cbc_decrypt(ct, self.key, iv) == pt

    def test_random_iv_each_time(self):
        pt = b"same plaintext!!"
        iv1, ct1 = cbc_encrypt(pt, self.key)
        iv2, ct2 = cbc_encrypt(pt, self.key)
        assert iv1 != iv2 or ct1 != ct2

    def test_identical_blocks_do_not_leak(self):
        block = b"YELLOW SUBMARINE"
        iv, ct = cbc_encrypt(block + block, self.key)
        assert ct[:16] != ct[16:32]

    def test_explicit_iv(self):
        iv = b'\x00' * 16
        pt = b"deterministic iv"
        iv_out, ct = cbc_encrypt(pt, self.key, iv)
        assert iv_out == iv
        assert cbc_decrypt(ct, self.key, iv_out) == pt

    def test_invalid_ct_length(self):
        with pytest.raises(ValueError):
            cbc_decrypt(b'\x00' * 15, self.key, b'\x00' * 16)


# ---------------------------------------------------------------------------
# CTR Mode
# ---------------------------------------------------------------------------

class TestCTR:
    def setup_method(self):
        self.key = os.urandom(16)

    def test_encrypt_decrypt_roundtrip(self):
        pt = b"Hello CTR World!"
        nonce, ct = ctr_crypt(pt, self.key)
        _, recovered = ctr_crypt(ct, self.key, nonce)
        assert recovered == pt

    def test_variable_lengths(self):
        for n in [1, 15, 16, 17, 31, 32, 100]:
            pt = os.urandom(n)
            nonce, ct = ctr_crypt(pt, self.key)
            _, recovered = ctr_crypt(ct, self.key, nonce)
            assert recovered == pt

    def test_no_padding_needed(self):
        pt = os.urandom(7)
        nonce, ct = ctr_crypt(pt, self.key)
        assert len(ct) == len(pt)

    def test_ctr_is_xor_stream(self):
        pt = b"stream cipher!"
        nonce, ct = ctr_crypt(pt, self.key)
        _, recovered = ctr_crypt(ct, self.key, nonce)
        assert recovered == pt


# ---------------------------------------------------------------------------
# Padding Oracle Attack
# ---------------------------------------------------------------------------

class TestPaddingOracle:
    def test_recovers_plaintext(self):
        key = os.urandom(16)
        pt = b"Secret message!!"
        assert len(pt) == 16
        iv, ct = cbc_encrypt(pt, key)
        result = padding_oracle_attack(ct[:16], iv, key)
        recovered = bytes.fromhex(result["recovered_hex"])
        assert recovered == pt

    def test_result_structure(self):
        key = os.urandom(16)
        pt = b"0123456789abcdef"
        iv, ct = cbc_encrypt(pt, key)
        result = padding_oracle_attack(ct[:16], iv, key)
        assert "recovered_hex" in result
        assert "total_oracle_queries" in result
        assert "steps" in result
        assert len(result["steps"]) == 16

    def test_oracle_query_count_bounded(self):
        key = os.urandom(16)
        pt = b"AAAAAAAAAAAAAAAA"
        iv, ct = cbc_encrypt(pt, key)
        result = padding_oracle_attack(ct[:16], iv, key)
        assert result["total_oracle_queries"] <= 4096


# ---------------------------------------------------------------------------
# Switching Lemma
# ---------------------------------------------------------------------------

class TestSwitchingLemma:
    def test_small_queries(self):
        r = switching_lemma(10)
        assert r["negligible"] is True
        assert r["bound"] < 1e-10

    def test_formula_present(self):
        r = switching_lemma(100)
        assert "q(q-1)" in r["formula"]

    def test_large_queries_still_negligible(self):
        r = switching_lemma(2**20, block_bits=128)
        assert r["negligible"] is True
