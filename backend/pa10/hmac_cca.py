"""
PA#10 - HMAC using the PA#8 DLP hash plus HMAC-based CCA-secure encryption.

This assignment replaces the earlier AES-flavoured HMAC demo with a proper
construction layered on top of the PA#8 collision-resistant hash. We then use
that HMAC inside an Encrypt-then-MAC composition to obtain tamper rejection.
"""

from __future__ import annotations

import hmac
import os

from backend.pa3.encryption import Dec, Enc
from backend.pa8.dlp_hash import DLPHash, FULL_PARAMS


MASTER_KEY_BYTES = 16
NONCE_BYTES = 8
_KDF_ENC_LABEL = b"PA10-ENC\x00"
_KDF_MAC_LABEL = b"PA10-MAC\x00"


def _xor_bytes(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def _coerce_master_key(key: bytes) -> bytes:
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("master key must be bytes")
    key_bytes = bytes(key)
    if len(key_bytes) != MASTER_KEY_BYTES:
        raise ValueError("master key must be exactly 16 bytes")
    return key_bytes


class HMACDLP:
    """
    HMAC built from the PA#8 DLP-based Merkle-Damgard hash.

    We keep the standard HMAC structure:
      H((k xor opad) || H((k xor ipad) || m))

    but instantiate H with the PA#8 hash rather than SHA-256.
    """

    def __init__(self, *, block_size: int | None = None):
        self.hash = DLPHash(FULL_PARAMS)
        self.block_size = block_size or FULL_PARAMS.block_bytes
        self.output_bytes = FULL_PARAMS.group_bytes
        self.ipad = bytes([0x36] * self.block_size)
        self.opad = bytes([0x5C] * self.block_size)

    def _normalize_key(self, key: bytes) -> bytes:
        key_bytes = bytes(key)
        if len(key_bytes) > self.block_size:
            key_bytes = self.hash.hash_bytes(key_bytes)
        return key_bytes.ljust(self.block_size, b"\x00")

    def tag(self, key: bytes, message: bytes) -> bytes:
        key_block = self._normalize_key(bytes(key))
        inner = self.hash.hash_bytes(_xor_bytes(key_block, self.ipad) + bytes(message))
        return self.hash.hash_bytes(_xor_bytes(key_block, self.opad) + inner)

    def verify(self, key: bytes, message: bytes, tag: bytes) -> bool:
        return hmac.compare_digest(self.tag(key, message), bytes(tag))

    def trace(self, key: bytes, message: bytes) -> dict:
        key_block = self._normalize_key(bytes(key))
        inner_input = _xor_bytes(key_block, self.ipad) + bytes(message)
        inner_trace = self.hash.trace(inner_input)
        inner_digest = bytes.fromhex(inner_trace["digest_hex"])

        outer_input = _xor_bytes(key_block, self.opad) + inner_digest
        outer_trace = self.hash.trace(outer_input)

        return {
            "block_size": self.block_size,
            "key_hex": bytes(key).hex(),
            "normalized_key_hex": key_block.hex(),
            "ipad_hex": self.ipad.hex(),
            "opad_hex": self.opad.hex(),
            "inner_pad_hex": _xor_bytes(key_block, self.ipad).hex(),
            "outer_pad_hex": _xor_bytes(key_block, self.opad).hex(),
            "message_hex": bytes(message).hex(),
            "inner_trace": inner_trace,
            "outer_trace": outer_trace,
            "tag_hex": outer_trace["digest_hex"],
            "tag_bits": len(bytes.fromhex(outer_trace["digest_hex"])) * 8,
            "description": "HMAC over the PA#8 DLP hash using standard ipad/opad domain separation.",
        }


def _derive_subkeys(master_key: bytes) -> tuple[bytes, bytes]:
    """
    Derive independent encryption and MAC keys via domain-separated PA#8 hashes.

    The encryption layer needs a 16-byte key for PA#3. The HMAC key can be the
    full digest, which is then normalized by HMACDLP.
    """
    key = _coerce_master_key(master_key)
    base_hash = DLPHash(FULL_PARAMS)
    enc_material = base_hash.hash_bytes(_KDF_ENC_LABEL + key)
    mac_material = base_hash.hash_bytes(_KDF_MAC_LABEL + key)
    return enc_material[:MASTER_KEY_BYTES], mac_material


class HMACCCAError(ValueError):
    pass


class HMACEtMScheme:
    def __init__(self, *, enc_scheme: str = "secure", prf_mode: str = "aes"):
        self.enc_scheme = enc_scheme
        self.prf_mode = prf_mode
        self.hmac = HMACDLP()

    def encrypt(self, master_key: bytes, message) -> bytes:
        key = _coerce_master_key(master_key)
        plaintext = message.encode() if isinstance(message, str) else bytes(message)
        enc_key, mac_key = _derive_subkeys(key)
        ciphertext = Enc(enc_key, plaintext, scheme=self.enc_scheme, prf_mode=self.prf_mode)
        tag = self.hmac.tag(mac_key, ciphertext)
        return ciphertext + tag

    def decrypt(self, master_key: bytes, bundle: bytes) -> bytes:
        key = _coerce_master_key(master_key)
        if not isinstance(bundle, (bytes, bytearray)):
            raise TypeError("ciphertext bundle must be bytes")
        data = bytes(bundle)
        tag_bytes = self.hmac.output_bytes
        min_len = NONCE_BYTES + tag_bytes
        if len(data) < min_len:
            raise HMACCCAError("ciphertext bundle is too short")
        ciphertext, tag = data[:-tag_bytes], data[-tag_bytes:]
        enc_key, mac_key = _derive_subkeys(key)
        if not self.hmac.verify(mac_key, ciphertext, tag):
            raise HMACCCAError("HMAC verification failed")
        return Dec(enc_key, ciphertext, scheme=self.enc_scheme, prf_mode=self.prf_mode)


def etm_hmac_encrypt(master_key: bytes, message, *, prf_mode: str = "aes") -> bytes:
    return HMACEtMScheme(prf_mode=prf_mode).encrypt(master_key, message)


def etm_hmac_decrypt(master_key: bytes, bundle: bytes, *, prf_mode: str = "aes") -> bytes:
    return HMACEtMScheme(prf_mode=prf_mode).decrypt(master_key, bundle)


def decrypt_then_hmac_demo() -> dict:
    key = os.urandom(MASTER_KEY_BYTES)
    message = b"release assignment ten"
    scheme = HMACEtMScheme()
    protected = scheme.encrypt(key, message)
    tampered = bytearray(protected)
    tampered[6] ^= 0x20

    bare_enc_key, _ = _derive_subkeys(key)
    bare_ciphertext = Enc(bare_enc_key, message)
    bare_tampered = bytearray(bare_ciphertext)
    bare_tampered[6] ^= 0x20
    bare_plaintext = Dec(bare_enc_key, bytes(bare_tampered))

    rejected = False
    try:
        scheme.decrypt(key, bytes(tampered))
    except HMACCCAError:
        rejected = True

    return {
        "bare_ciphertext_hex": bare_ciphertext.hex(),
        "bare_tampered_plaintext": bare_plaintext.decode("utf-8", errors="replace"),
        "etm_ciphertext_hex": protected.hex(),
        "tampered_bundle_hex": bytes(tampered).hex(),
        "tampered_byte_index": 6,
        "tampered_region": "ciphertext body before the appended HMAC tag",
        "etm_rejected": rejected,
        "insight": "Encrypt-then-HMAC rejects tampering before decryption, unlike bare CPA encryption.",
    }


def cca2_hmac_game(trials: int = 100) -> dict:
    if trials <= 0:
        raise ValueError("trials must be positive")

    wins = 0
    transcripts = []
    scheme = HMACEtMScheme()

    for trial in range(trials):
        key = os.urandom(MASTER_KEY_BYTES)
        m0 = b"grade=71"
        m1 = b"grade=99"
        challenge_bit = int.from_bytes(os.urandom(1), "big") & 1
        challenge = scheme.encrypt(key, m1 if challenge_bit else m0)
        tampered = bytearray(challenge)
        tampered[5] ^= 0x80

        rejected = False
        try:
            scheme.decrypt(key, bytes(tampered))
        except HMACCCAError:
            rejected = True

        wins += int(rejected)
        if trial < 5:
            transcripts.append(
                {
                    "trial": trial,
                    "challenge_bit": challenge_bit,
                    "challenge_hex": challenge.hex(),
                    "tampered_hex": bytes(tampered).hex(),
                    "tamper_rejected": rejected,
                }
            )

    success_rate = wins / trials
    return {
        "trials": trials,
        "tamper_rejection_rate": success_rate,
        "cca_protected": success_rate == 1.0,
        "verdict": "secure" if success_rate == 1.0 else "warning",
        "experiment": "encrypt_then_hmac_demo",
        "transcripts": transcripts,
    }
