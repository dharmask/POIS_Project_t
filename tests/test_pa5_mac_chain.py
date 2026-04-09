"""
Tests for PA#5 - PRF-MAC, CBC-MAC, and EUF-CMA.
"""

import os

import pytest

from backend.pa5.mac import cbc_mac, euf_cma_game, mac_prf, vrfy_cbc_mac, vrfy_prf


class TestPRFMAC:
    def setup_method(self):
        self.key = os.urandom(16)

    def test_tag_length(self):
        assert len(mac_prf(self.key, b"hi")) == 16

    def test_verify_roundtrip(self):
        msg = b"auth message"
        tag = mac_prf(self.key, msg)
        assert vrfy_prf(self.key, msg, tag) is True

    def test_wrong_tag_rejected(self):
        msg = b"auth message"
        tag = mac_prf(self.key, msg)
        bad = bytes([tag[0] ^ 1]) + tag[1:]
        assert vrfy_prf(self.key, msg, bad) is False

    def test_rejects_multi_block_input(self):
        with pytest.raises(ValueError):
            mac_prf(self.key, b"a" * 17)


class TestCBCMAC:
    def setup_method(self):
        self.key = os.urandom(16)

    def test_tag_length(self):
        assert len(cbc_mac(self.key, b"hello")) == 16

    def test_verify_roundtrip(self):
        msg = b"variable length message"
        tag = cbc_mac(self.key, msg)
        assert vrfy_cbc_mac(self.key, msg, tag) is True

    def test_length_prefix_changes_tag(self):
        assert cbc_mac(self.key, b"a") != cbc_mac(self.key, b"a\x00")


class TestEUFCMA:
    def test_prf_mac_secure(self):
        result = euf_cma_game("prf", 10)
        assert result["forgery_attempt"]["success"] is False

    def test_cbc_mac_secure(self):
        result = euf_cma_game("cbc", 10)
        assert result["forgery_attempt"]["success"] is False
