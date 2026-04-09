"""
PA#6 - CCA-secure encryption via Encrypt-then-MAC.

Composition:
  ciphertext = Enc_{k_enc}(m)
  tag        = Mac_{k_mac}(ciphertext)
  output     = ciphertext || tag
"""

from __future__ import annotations

import os

from backend.pa2.prf import PRF_AES
from backend.pa3.encryption import Dec, Enc
from backend.pa5.mac import cbc_mac, vrfy_cbc_mac


MASTER_KEY_BYTES = 16
TAG_BYTES = 16


class CCAError(ValueError):
    pass


def _coerce_master_key(key: bytes) -> bytes:
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("master key must be bytes")
    key_bytes = bytes(key)
    if len(key_bytes) != MASTER_KEY_BYTES:
        raise ValueError("master key must be exactly 16 bytes")
    return key_bytes


def _derive_subkeys(master_key: bytes) -> tuple[bytes, bytes]:
    prf = PRF_AES()
    enc_key = prf.evaluate(master_key, 0)
    mac_key = prf.evaluate(master_key, 1)
    return enc_key, mac_key


class CCAEtMScheme:
    def __init__(self, *, enc_scheme: str = "secure", prf_mode: str = "aes"):
        self.enc_scheme = enc_scheme
        self.prf_mode = prf_mode

    def encrypt(self, master_key: bytes, message) -> bytes:
        key = _coerce_master_key(master_key)
        enc_key, mac_key = _derive_subkeys(key)
        ciphertext = Enc(enc_key, message, scheme=self.enc_scheme, prf_mode=self.prf_mode)
        tag = cbc_mac(mac_key, ciphertext)
        return ciphertext + tag

    def decrypt(self, master_key: bytes, bundle: bytes) -> bytes:
        key = _coerce_master_key(master_key)
        if not isinstance(bundle, (bytes, bytearray)):
            raise TypeError("ciphertext bundle must be bytes")
        data = bytes(bundle)
        if len(data) < TAG_BYTES:
            raise CCAError("ciphertext bundle is too short")
        ciphertext, tag = data[:-TAG_BYTES], data[-TAG_BYTES:]
        enc_key, mac_key = _derive_subkeys(key)
        if not vrfy_cbc_mac(mac_key, ciphertext, tag):
            raise CCAError("MAC verification failed")
        return Dec(enc_key, ciphertext, scheme=self.enc_scheme, prf_mode=self.prf_mode)


def etm_encrypt(master_key: bytes, message, *, prf_mode: str = "aes") -> bytes:
    return CCAEtMScheme(prf_mode=prf_mode).encrypt(master_key, message)


def etm_decrypt(master_key: bytes, bundle: bytes, *, prf_mode: str = "aes") -> bytes:
    return CCAEtMScheme(prf_mode=prf_mode).decrypt(master_key, bundle)


def decrypt_then_verify_failure_demo() -> dict:
    """
    Compare bare CPA encryption with Encrypt-then-MAC under tampering.
    """
    key = os.urandom(MASTER_KEY_BYTES)
    message = b"wire funds tomorrow"
    etm = CCAEtMScheme()
    protected = etm.encrypt(key, message)
    tampered = bytearray(protected)
    tampered[8] ^= 0x01

    bare_key, _ = _derive_subkeys(key)
    bare_ciphertext = Enc(bare_key, message)
    bare_tampered = bytearray(bare_ciphertext)
    bare_tampered[8] ^= 0x01

    bare_plaintext = Dec(bare_key, bytes(bare_tampered))

    rejected = False
    try:
        etm.decrypt(key, bytes(tampered))
    except CCAError:
        rejected = True

    return {
        "bare_ciphertext_hex": bare_ciphertext.hex(),
        "bare_tampered_plaintext": bare_plaintext.decode("utf-8", errors="replace"),
        "etm_ciphertext_hex": protected.hex(),
        "tampered_bundle_hex": bytes(tampered).hex(),
        "tampered_byte_index": 8,
        "tampered_region": "first byte of encrypted body after the 8-byte nonce",
        "etm_rejected": rejected,
        "insight": "Bare CPA encryption is malleable; Encrypt-then-MAC rejects tampering before decryption.",
    }


def cca2_game(trials: int = 100) -> dict:
    """
    Tamper-rejection experiment against Encrypt-then-MAC.

    This is not a full IND-CCA2 game with a general decryption oracle. Instead,
    it measures the narrower property that tampering with a challenge ciphertext
    is rejected before decryption.
    """
    if trials <= 0:
        raise ValueError("trials must be positive")

    wins = 0
    transcripts = []
    scheme = CCAEtMScheme()

    for trial in range(trials):
        key = os.urandom(MASTER_KEY_BYTES)
        m0 = b"transfer=0001"
        m1 = b"transfer=9999"
        b = int.from_bytes(os.urandom(1), "big") & 1
        challenge = scheme.encrypt(key, m1 if b else m0)
        tampered = bytearray(challenge)
        tampered[5] ^= 0x80

        rejected = False
        try:
            scheme.decrypt(key, bytes(tampered))
        except CCAError:
            rejected = True

        wins += int(rejected)
        if trial < 5:
            transcripts.append(
                {
                    "trial": trial,
                    "challenge_bit": b,
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
        "experiment": "tamper_rejection_demo",
        "transcripts": transcripts,
    }
