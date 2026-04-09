"""
Tests for PA#5 — Public-Key Cryptography (RSA + Diffie-Hellman)
"""
import os
import pytest
from backend.pa5.pubkey import (
    _mod_exp, _mod_inverse, _is_probable_prime, _generate_prime,
    rsa_keygen, rsa_encrypt, rsa_decrypt, rsa_sign, rsa_verify,
    rsa_cpa_demo,
    dh_keygen, dh_shared_secret, dh_exchange_demo,
    dh_mitm_demo, authenticated_dh_demo, _hash_to_rsa_message,
    DH_P, DH_G,
)


# ---------------------------------------------------------------------------
# Number-theory helpers
# ---------------------------------------------------------------------------

class TestNumberTheory:
    def test_mod_exp_basic(self):
        assert _mod_exp(2, 10, 1000) == 24
        assert _mod_exp(3, 0, 100) == 1
        assert _mod_exp(5, 1, 100) == 5

    def test_mod_inverse(self):
        assert (_mod_inverse(3, 7) * 3) % 7 == 1
        assert (_mod_inverse(17, 43) * 17) % 43 == 1

    def test_mod_inverse_no_inverse(self):
        with pytest.raises(ValueError):
            _mod_inverse(2, 4)

    def test_is_probable_prime(self):
        assert _is_probable_prime(2) is True
        assert _is_probable_prime(3) is True
        assert _is_probable_prime(17) is True
        assert _is_probable_prime(97) is True
        assert _is_probable_prime(4) is False
        assert _is_probable_prime(15) is False
        assert _is_probable_prime(1) is False
        assert _is_probable_prime(0) is False

    def test_generate_prime(self):
        p = _generate_prime(64)
        assert p.bit_length() == 64
        assert _is_probable_prime(p)

    def test_generate_prime_128(self):
        p = _generate_prime(128)
        assert p.bit_length() == 128
        assert _is_probable_prime(p)


# ---------------------------------------------------------------------------
# RSA Key Generation
# ---------------------------------------------------------------------------

class TestRSAKeygen:
    def test_keygen_structure(self):
        keys = rsa_keygen(256)
        assert "public" in keys
        assert "private" in keys
        assert "n" in keys["public"]
        assert "e" in keys["public"]
        assert "d" in keys["private"]
        assert "p" in keys
        assert "q" in keys

    def test_p_q_are_prime(self):
        keys = rsa_keygen(256)
        assert _is_probable_prime(keys["p"])
        assert _is_probable_prime(keys["q"])

    def test_n_equals_p_times_q(self):
        keys = rsa_keygen(256)
        assert keys["public"]["n"] == keys["p"] * keys["q"]

    def test_e_d_inverse(self):
        keys = rsa_keygen(256)
        phi = keys["phi"]
        e, d = keys["public"]["e"], keys["private"]["d"]
        assert (e * d) % phi == 1

    def test_default_e(self):
        keys = rsa_keygen(256)
        assert keys["public"]["e"] == 65537 or keys["public"]["e"] >= 3


# ---------------------------------------------------------------------------
# RSA Encrypt / Decrypt
# ---------------------------------------------------------------------------

class TestRSACrypt:
    def setup_method(self):
        self.keys = rsa_keygen(512)
        self.n = self.keys["public"]["n"]
        self.e = self.keys["public"]["e"]
        self.d = self.keys["private"]["d"]

    def test_encrypt_decrypt_roundtrip(self):
        m = 42
        c = rsa_encrypt(m, self.n, self.e)
        assert rsa_decrypt(c, self.n, self.d) == m

    def test_encrypt_decrypt_large_message(self):
        m = int.from_bytes(b"Hello RSA World!", 'big')
        if m >= self.n:
            m = m % self.n
        c = rsa_encrypt(m, self.n, self.e)
        assert rsa_decrypt(c, self.n, self.d) == m

    def test_encrypt_zero(self):
        c = rsa_encrypt(0, self.n, self.e)
        assert rsa_decrypt(c, self.n, self.d) == 0

    def test_encrypt_one(self):
        c = rsa_encrypt(1, self.n, self.e)
        assert rsa_decrypt(c, self.n, self.d) == 1

    def test_message_too_large(self):
        with pytest.raises(ValueError):
            rsa_encrypt(self.n, self.n, self.e)

    def test_negative_message(self):
        with pytest.raises(ValueError):
            rsa_encrypt(-1, self.n, self.e)

    def test_deterministic(self):
        m = 12345
        c1 = rsa_encrypt(m, self.n, self.e)
        c2 = rsa_encrypt(m, self.n, self.e)
        assert c1 == c2  # textbook RSA is deterministic


# ---------------------------------------------------------------------------
# RSA Sign / Verify
# ---------------------------------------------------------------------------

class TestRSASign:
    def setup_method(self):
        self.keys = rsa_keygen(512)
        self.n = self.keys["public"]["n"]
        self.e = self.keys["public"]["e"]
        self.d = self.keys["private"]["d"]

    def test_sign_verify(self):
        m = 999
        sig = rsa_sign(m, self.n, self.d)
        assert rsa_verify(m, sig, self.n, self.e) is True

    def test_verify_wrong_message(self):
        m = 999
        sig = rsa_sign(m, self.n, self.d)
        assert rsa_verify(1000, sig, self.n, self.e) is False

    def test_verify_wrong_signature(self):
        m = 42
        sig = rsa_sign(m, self.n, self.d)
        assert rsa_verify(m, sig + 1, self.n, self.e) is False

    def test_sign_message_too_large(self):
        with pytest.raises(ValueError):
            rsa_sign(self.n, self.n, self.d)


# ---------------------------------------------------------------------------
# RSA CPA-insecurity Demo
# ---------------------------------------------------------------------------

class TestRSACPA:
    def test_cpa_demo_deterministic(self):
        result = rsa_cpa_demo(256)
        assert result["identical"] is True

    def test_cpa_demo_insight(self):
        result = rsa_cpa_demo(256)
        assert "deterministic" in result["insight"].lower() or "CPA" in result["insight"]


# ---------------------------------------------------------------------------
# Diffie-Hellman
# ---------------------------------------------------------------------------

class TestDiffieHellman:
    def test_dh_keygen_structure(self):
        kp = dh_keygen()
        assert "private" in kp
        assert "public" in kp
        assert kp["p"] == DH_P
        assert kp["g"] == DH_G

    def test_dh_public_key_in_group(self):
        kp = dh_keygen()
        assert 1 < kp["public"] < DH_P

    def test_dh_shared_secret_matches(self):
        alice = dh_keygen()
        bob = dh_keygen()
        s1 = dh_shared_secret(alice["private"], bob["public"])
        s2 = dh_shared_secret(bob["private"], alice["public"])
        assert s1 == s2

    def test_dh_exchange_demo(self):
        result = dh_exchange_demo()
        assert result["secrets_match"] is True

    def test_dh_different_sessions(self):
        a1 = dh_keygen()
        a2 = dh_keygen()
        assert a1["public"] != a2["public"]  # overwhelmingly likely


# ---------------------------------------------------------------------------
# MITM Demo
# ---------------------------------------------------------------------------

class TestDHMITM:
    def test_mitm_attack(self):
        result = dh_mitm_demo()
        assert result["alice_mallory_match"] is True
        assert result["bob_mallory_match"] is True
        assert result["alice_bob_compromised"] is True


# ---------------------------------------------------------------------------
# Authenticated DH
# ---------------------------------------------------------------------------

class TestAuthenticatedDH:
    def test_authenticated_dh(self):
        result = authenticated_dh_demo(256)
        assert result["alice_signature_valid"] is True
        assert result["shared_secret_match"] is True

    def test_hash_to_rsa_message_lands_in_modulus(self):
        keys = rsa_keygen(256)
        mapped = _hash_to_rsa_message(dh_keygen()["public"], keys["public"]["n"])
        assert 0 <= mapped < keys["public"]["n"]

    def test_authenticated_dh_exposes_signed_digest(self):
        result = authenticated_dh_demo(256)
        assert "signed_digest_hex" in result
