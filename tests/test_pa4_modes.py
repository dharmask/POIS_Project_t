"""
Tests for PA#4 - CBC, OFB, CTR modes and their attacks.
"""

import os

from backend.pa4.modes import (
    cbc_decrypt,
    cbc_encrypt,
    cbc_iv_reuse_demo,
    cpa_malleability_demo,
    ctr_crypt,
    ofb_keystream_reuse_demo,
    ofb_crypt,
)


class TestCBCMode:
    def setup_method(self):
        self.key = os.urandom(16)

    def test_roundtrip(self):
        iv, ct = cbc_encrypt(b"hello cbc mode", self.key)
        assert cbc_decrypt(ct, self.key, iv) == b"hello cbc mode"

    def test_variable_lengths(self):
        for n in [1, 15, 16, 17, 31, 32, 64]:
            msg = os.urandom(n)
            iv, ct = cbc_encrypt(msg, self.key)
            assert cbc_decrypt(ct, self.key, iv) == msg


class TestOFBMode:
    def setup_method(self):
        self.key = os.urandom(16)

    def test_roundtrip(self):
        iv, ct = ofb_crypt(b"hello ofb mode", self.key)
        _, pt = ofb_crypt(ct, self.key, iv)
        assert pt == b"hello ofb mode"

    def test_preserves_length(self):
        data = os.urandom(37)
        _, ct = ofb_crypt(data, self.key)
        assert len(ct) == len(data)


class TestCTRMode:
    def setup_method(self):
        self.key = os.urandom(16)

    def test_roundtrip(self):
        nonce, ct = ctr_crypt(b"hello ctr mode", self.key)
        _, pt = ctr_crypt(ct, self.key, nonce)
        assert pt == b"hello ctr mode"

    def test_preserves_length(self):
        data = os.urandom(55)
        _, ct = ctr_crypt(data, self.key)
        assert len(ct) == len(data)


class TestModeAttacks:
    def test_cbc_iv_reuse_leaks_first_block_equality(self):
        result = cbc_iv_reuse_demo()
        assert result["first_blocks_equal"] is True

    def test_ofb_keystream_reuse_leaks_xor(self):
        result = ofb_keystream_reuse_demo()
        assert result["keystream_reuse_detected"] is True

    def test_ctr_malleability_demo(self):
        result = cpa_malleability_demo()
        assert result["malleability_observed"] is True
