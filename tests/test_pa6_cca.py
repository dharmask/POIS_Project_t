"""
Tests for PA#6 - Encrypt-then-MAC and CCA protection.
"""

import os

import pytest

from backend.pa6.cca import CCAError, CCAEtMScheme, cca2_game, decrypt_then_verify_failure_demo, etm_decrypt, etm_encrypt


class TestEncryptThenMAC:
    def setup_method(self):
        self.key = os.urandom(16)
        self.scheme = CCAEtMScheme()

    def test_roundtrip(self):
        bundle = self.scheme.encrypt(self.key, b"protected message")
        assert self.scheme.decrypt(self.key, bundle) == b"protected message"

    def test_module_level_api_roundtrip(self):
        bundle = etm_encrypt(self.key, b"module api")
        assert etm_decrypt(self.key, bundle) == b"module api"

    def test_tampering_is_rejected(self):
        bundle = bytearray(self.scheme.encrypt(self.key, b"reject tampering"))
        bundle[3] ^= 0x40
        with pytest.raises(CCAError):
            self.scheme.decrypt(self.key, bytes(bundle))

    def test_empty_message_roundtrip(self):
        bundle = self.scheme.encrypt(self.key, b"")
        assert self.scheme.decrypt(self.key, bundle) == b""

    def test_wrong_key_rejected(self):
        bundle = self.scheme.encrypt(self.key, b"wrong key")
        with pytest.raises(CCAError):
            self.scheme.decrypt(os.urandom(16), bundle)

    def test_too_short_bundle_rejected(self):
        with pytest.raises(CCAError):
            self.scheme.decrypt(self.key, b"\x00" * 8)


class TestCCADemos:
    def test_protection_demo(self):
        result = decrypt_then_verify_failure_demo()
        assert result["etm_rejected"] is True
        assert result["bare_tampered_plaintext"] != "wire funds tomorrow"
        assert result["tampered_byte_index"] == 8

    def test_cca2_game(self):
        result = cca2_game(40)
        assert result["cca_protected"] is True
        assert result["tamper_rejection_rate"] == 1.0
        assert result["experiment"] == "tamper_rejection_demo"
