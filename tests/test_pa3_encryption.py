"""
Tests for PA#3 - CPA-secure encryption from a PRF.
"""

import os

from backend.pa3.encryption import (
    BrokenDeterministicPRFEncryption,
    Dec,
    Enc,
    PRFCPAEncryption,
    build_scheme,
    cpa_game,
)


class TestPRFCPAEncryption:
    def setup_method(self):
        self.key = os.urandom(16)
        self.scheme = PRFCPAEncryption()

    def test_encrypt_decrypt_roundtrip(self):
        message = b"hello from pa3"
        ciphertext = self.scheme.encrypt(self.key, message)
        assert self.scheme.decrypt(self.key, ciphertext) == message

    def test_randomized_encryption_changes_ciphertext(self):
        message = b"same plaintext"
        c1 = self.scheme.encrypt(self.key, message)
        c2 = self.scheme.encrypt(self.key, message)
        assert c1 != c2

    def test_module_level_api_roundtrip(self):
        message = b"module level api"
        ciphertext = Enc(self.key, message)
        assert Dec(self.key, ciphertext) == message


class TestBrokenDeterministicVariant:
    def setup_method(self):
        self.key = os.urandom(16)
        self.scheme = BrokenDeterministicPRFEncryption()

    def test_still_decrypts_correctly(self):
        message = b"deterministic but correct"
        ciphertext = self.scheme.encrypt(self.key, message)
        assert self.scheme.decrypt(self.key, ciphertext) == message

    def test_same_message_same_ciphertext(self):
        message = b"chosen plaintext"
        assert self.scheme.encrypt(self.key, message) == self.scheme.encrypt(self.key, message)

    def test_different_messages_different_ciphertexts(self):
        assert self.scheme.encrypt(self.key, b"a" * 16) != self.scheme.encrypt(self.key, b"b" * 16)


class TestSchemeFactory:
    def test_secure_factory(self):
        assert isinstance(build_scheme(scheme="secure"), PRFCPAEncryption)

    def test_broken_factory(self):
        assert isinstance(build_scheme(scheme="broken"), BrokenDeterministicPRFEncryption)


class TestCPAGame:
    def test_secure_scheme_has_low_advantage(self):
        result = cpa_game(scheme="secure", trials=200)
        assert result["advantage"] < 0.2
        assert result["verdict"] == "looks_cpa_secure"

    def test_broken_scheme_is_distinguishable(self):
        result = cpa_game(scheme="broken", trials=50)
        assert result["advantage"] > 0.4
        assert result["verdict"] == "broken"
