"""
Tests for PA#4 — Message Authentication Codes (PRF-MAC, CBC-MAC, HMAC-AES)
"""
import os
import pytest
import hmac as stdlib_hmac
from backend.pa4.mac import (
    mac_prf, vrfy_prf,
    cbc_mac, vrfy_cbc_mac,
    hmac_aes, vrfy_hmac_aes,
    _aes_hash, _davies_meyer,
    length_extension_demo, euf_cma_game,
)


# ---------------------------------------------------------------------------
# Davies-Meyer / AES Hash
# ---------------------------------------------------------------------------

class TestDaviesMeyer:
    def test_output_length(self):
        cv = b'\x00' * 16
        block = os.urandom(16)
        assert len(_davies_meyer(cv, block)) == 16

    def test_deterministic(self):
        cv = b'\x11' * 16
        block = b'\x22' * 16
        assert _davies_meyer(cv, block) == _davies_meyer(cv, block)

    def test_different_blocks_different_output(self):
        cv = b'\x00' * 16
        assert _davies_meyer(cv, b'\x01' * 16) != _davies_meyer(cv, b'\x02' * 16)


class TestAESHash:
    def test_output_length(self):
        assert len(_aes_hash(b"hello")) == 16

    def test_deterministic(self):
        assert _aes_hash(b"test") == _aes_hash(b"test")

    def test_different_inputs(self):
        assert _aes_hash(b"abc") != _aes_hash(b"xyz")

    def test_empty_input(self):
        h = _aes_hash(b"")
        assert len(h) == 16

    def test_long_input(self):
        h = _aes_hash(b"A" * 1000)
        assert len(h) == 16


# ---------------------------------------------------------------------------
# PRF-MAC (fixed-length, 16-byte messages)
# ---------------------------------------------------------------------------

class TestPRFMAC:
    def setup_method(self):
        self.key = os.urandom(16)

    def test_tag_length(self):
        tag = mac_prf(self.key, b'\x00' * 16)
        assert len(tag) == 16

    def test_deterministic(self):
        msg = b'\xab' * 16
        assert mac_prf(self.key, msg) == mac_prf(self.key, msg)

    def test_verify_correct(self):
        msg = b'\xcd' * 16
        tag = mac_prf(self.key, msg)
        assert vrfy_prf(self.key, msg, tag) is True

    def test_verify_wrong_tag(self):
        msg = b'\xef' * 16
        tag = mac_prf(self.key, msg)
        bad_tag = bytes(b ^ 1 for b in tag)
        assert vrfy_prf(self.key, msg, bad_tag) is False

    def test_verify_accepts_bytearray_tag(self):
        msg = b'\x01' * 16
        tag = mac_prf(self.key, msg)
        assert vrfy_prf(self.key, msg, bytearray(tag)) is True

    def test_different_keys(self):
        msg = b'\x00' * 16
        k2 = os.urandom(16)
        assert mac_prf(self.key, msg) != mac_prf(k2, msg)

    def test_different_messages(self):
        assert mac_prf(self.key, b'\x00' * 16) != mac_prf(self.key, b'\x01' * 16)

    def test_invalid_key_length(self):
        with pytest.raises(ValueError):
            mac_prf(b'\x00' * 15, b'\x00' * 16)

    def test_invalid_message_length(self):
        with pytest.raises(ValueError):
            mac_prf(self.key, b'\x00' * 15)


# ---------------------------------------------------------------------------
# CBC-MAC (variable-length)
# ---------------------------------------------------------------------------

class TestCBCMAC:
    def setup_method(self):
        self.key = os.urandom(16)

    def test_tag_length(self):
        assert len(cbc_mac(self.key, b"hello")) == 16

    def test_deterministic(self):
        msg = b"test message"
        assert cbc_mac(self.key, msg) == cbc_mac(self.key, msg)

    def test_verify_correct(self):
        msg = b"authenticate me"
        tag = cbc_mac(self.key, msg)
        assert vrfy_cbc_mac(self.key, msg, tag) is True

    def test_verify_wrong_tag(self):
        msg = b"authenticate me"
        tag = cbc_mac(self.key, msg)
        bad = bytes(b ^ 0xff for b in tag)
        assert vrfy_cbc_mac(self.key, msg, bad) is False

    def test_variable_lengths(self):
        for n in [1, 15, 16, 17, 32, 100]:
            msg = os.urandom(n)
            tag = cbc_mac(self.key, msg)
            assert len(tag) == 16
            assert vrfy_cbc_mac(self.key, msg, tag) is True

    def test_different_messages(self):
        assert cbc_mac(self.key, b"msg1") != cbc_mac(self.key, b"msg2")

    def test_empty_message_raises(self):
        with pytest.raises(ValueError):
            cbc_mac(self.key, b"")

    def test_invalid_key(self):
        with pytest.raises(ValueError):
            cbc_mac(b'\x00' * 8, b"hello")


# ---------------------------------------------------------------------------
# HMAC-AES
# ---------------------------------------------------------------------------

class TestHMACAES:
    def setup_method(self):
        self.key = os.urandom(16)

    def test_tag_length(self):
        assert len(hmac_aes(self.key, b"hello")) == 16

    def test_deterministic(self):
        msg = b"deterministic"
        assert hmac_aes(self.key, msg) == hmac_aes(self.key, msg)

    def test_verify_correct(self):
        msg = b"verify me"
        tag = hmac_aes(self.key, msg)
        assert vrfy_hmac_aes(self.key, msg, tag) is True

    def test_verify_wrong_tag(self):
        msg = b"verify me"
        tag = hmac_aes(self.key, msg)
        bad = bytes(b ^ 1 for b in tag)
        assert vrfy_hmac_aes(self.key, msg, bad) is False

    def test_matches_compare_digest_behavior(self):
        msg = b"compare-digest"
        tag = hmac_aes(self.key, msg)
        assert vrfy_hmac_aes(self.key, msg, tag) is stdlib_hmac.compare_digest(tag, tag)

    def test_different_keys(self):
        msg = b"same message"
        k2 = os.urandom(16)
        assert hmac_aes(self.key, msg) != hmac_aes(k2, msg)

    def test_different_messages(self):
        assert hmac_aes(self.key, b"a") != hmac_aes(self.key, b"b")

    def test_empty_message(self):
        tag = hmac_aes(self.key, b"")
        assert len(tag) == 16

    def test_long_key(self):
        long_key = os.urandom(32)
        tag = hmac_aes(long_key, b"test")
        assert len(tag) == 16

    def test_short_key_padded(self):
        short_key = b'\xaa' * 8
        tag = hmac_aes(short_key, b"test")
        assert len(tag) == 16


# ---------------------------------------------------------------------------
# Length-Extension Attack Demo
# ---------------------------------------------------------------------------

class TestLengthExtension:
    def test_attack_succeeds(self):
        key = os.urandom(16)
        msg = b"user=alice&role=user"
        result = length_extension_demo(key, msg)
        assert result["attack_succeeded"] is True

    def test_hmac_immune(self):
        key = os.urandom(16)
        result = length_extension_demo(key, b"data")
        assert result["hmac_immune"] is True

    def test_result_structure(self):
        key = os.urandom(16)
        result = length_extension_demo(key, b"hello")
        assert "original_tag" in result
        assert "attacker_forged_tag" in result
        assert "server_expected_tag" in result
        assert "extension" in result


# ---------------------------------------------------------------------------
# EUF-CMA Security Game
# ---------------------------------------------------------------------------

class TestEUFCMA:
    def test_hmac_secure(self):
        result = euf_cma_game("hmac", n_queries=10)
        assert result["forgery_attempt"]["success"] is False

    def test_cbc_secure(self):
        result = euf_cma_game("cbc", n_queries=10)
        assert result["forgery_attempt"]["success"] is False

    def test_prf_secure(self):
        result = euf_cma_game("prf", n_queries=10)
        assert result["forgery_attempt"]["success"] is False

    def test_result_structure(self):
        result = euf_cma_game("hmac", n_queries=5)
        assert "mac_mode" in result
        assert "queries" in result
        assert "forgery_attempt" in result
        assert "verdict" in result
