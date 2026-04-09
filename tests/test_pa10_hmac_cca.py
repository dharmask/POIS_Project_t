"""
Tests for PA#10 - HMAC over the PA#8 DLP hash and Encrypt-then-HMAC.
"""

import os

import pytest

from backend.api.main import (
    PA10DecryptRequest,
    PA10EncryptRequest,
    PA10HMACRequest,
    pa10_decrypt,
    pa10_encrypt,
    pa10_hmac,
)
from backend.pa10.hmac_cca import (
    HMACCCAError,
    HMACDLP,
    HMACEtMScheme,
    cca2_hmac_game,
    decrypt_then_hmac_demo,
    etm_hmac_decrypt,
    etm_hmac_encrypt,
)


class TestHMACDLP:
    def setup_method(self):
        self.key = os.urandom(16)
        self.hmac = HMACDLP()

    def test_tag_is_deterministic(self):
        tag1 = self.hmac.tag(self.key, b"same message")
        tag2 = self.hmac.tag(self.key, b"same message")
        assert tag1 == tag2

    def test_verify_accepts_valid_tag(self):
        tag = self.hmac.tag(self.key, b"verify me")
        assert self.hmac.verify(self.key, b"verify me", tag) is True

    def test_verify_rejects_modified_message(self):
        tag = self.hmac.tag(self.key, b"original")
        assert self.hmac.verify(self.key, b"modified", tag) is False

    def test_trace_returns_inner_and_outer_hashes(self):
        trace = self.hmac.trace(self.key, b"trace me")
        assert trace["inner_trace"]["digest_hex"] != ""
        assert trace["outer_trace"]["digest_hex"] == trace["tag_hex"]
        assert trace["tag_bits"] == self.hmac.output_bytes * 8


class TestEncryptThenHMAC:
    def setup_method(self):
        self.key = os.urandom(16)
        self.scheme = HMACEtMScheme()

    def test_roundtrip(self):
        bundle = self.scheme.encrypt(self.key, b"protected message")
        assert self.scheme.decrypt(self.key, bundle) == b"protected message"

    def test_module_level_api_roundtrip(self):
        bundle = etm_hmac_encrypt(self.key, b"module api")
        assert etm_hmac_decrypt(self.key, bundle) == b"module api"

    def test_tampering_is_rejected(self):
        bundle = bytearray(self.scheme.encrypt(self.key, b"reject tampering"))
        bundle[4] ^= 0x10
        with pytest.raises(HMACCCAError):
            self.scheme.decrypt(self.key, bytes(bundle))

    def test_wrong_key_is_rejected(self):
        bundle = self.scheme.encrypt(self.key, b"wrong key")
        with pytest.raises(HMACCCAError):
            self.scheme.decrypt(os.urandom(16), bundle)

    def test_too_short_bundle_is_rejected(self):
        with pytest.raises(HMACCCAError):
            self.scheme.decrypt(self.key, b"\x00" * 8)


class TestPA10Demos:
    def test_protection_demo(self):
        result = decrypt_then_hmac_demo()
        assert result["etm_rejected"] is True
        assert result["bare_tampered_plaintext"] != "release assignment ten"
        assert result["tampered_byte_index"] == 6

    def test_cca2_game(self):
        result = cca2_hmac_game(30)
        assert result["cca_protected"] is True
        assert result["tamper_rejection_rate"] == 1.0
        assert result["experiment"] == "encrypt_then_hmac_demo"


class TestPA10API:
    def test_hmac_endpoint_compute_and_verify(self):
        req = PA10HMACRequest(
            key_hex="00112233445566778899aabbccddeeff",
            message="api smoke test",
        )
        data = pa10_hmac(req)
        assert data["tag_hex"] != ""

        verify_data = pa10_hmac(
            PA10HMACRequest(
                key_hex="00112233445566778899aabbccddeeff",
                message="api smoke test",
                tag_hex=data["tag_hex"],
            )
        )
        assert verify_data["verified"] is True

    def test_encrypt_then_decrypt_endpoints_roundtrip(self):
        key_hex = "8899aabbccddeeff0011223344556677"
        encrypt_data = pa10_encrypt(
            PA10EncryptRequest(key_hex=key_hex, message="end to end")
        )
        bundle = encrypt_data["ciphertext_hex"]

        decrypt_data = pa10_decrypt(
            PA10DecryptRequest(key_hex=key_hex, ciphertext_hex=bundle)
        )
        assert decrypt_data["message_text"] == "end to end"
