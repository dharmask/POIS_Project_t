"""
PA#5 — Public-Key Cryptography: RSA + Diffie-Hellman Key Exchange
==================================================================

RSA (Rivest–Shamir–Adleman):
  KeyGen: Pick primes p, q.  n = pq,  φ(n) = (p-1)(q-1).
          Choose e coprime to φ(n) (typically 65537).
          Compute d = e^{-1} mod φ(n).
          Public key = (n, e).  Private key = d.

  Encrypt:  c = m^e mod n
  Decrypt:  m = c^d mod n
  Sign:     σ = m^d mod n
  Verify:   m == σ^e mod n

  Security rests on the RSA assumption: given n, e, c, computing m is hard
  (reducible to factoring n).

Diffie-Hellman Key Exchange:
  Public parameters: prime p, generator g of Z*_p.
  Alice picks a, sends A = g^a mod p.
  Bob   picks b, sends B = g^b mod p.
  Shared secret: K = B^a = A^b = g^{ab} mod p.

  Security rests on the Decisional Diffie-Hellman (DDH) assumption.

Textbook RSA is deterministic and therefore NOT CPA-secure.
We also demonstrate simple OAEP-style randomized padding.

No external libraries — only os.urandom and built-in int operations.
"""

import hashlib
import os


# ---------------------------------------------------------------------------
# Number-theory helpers (all pure Python)
# ---------------------------------------------------------------------------

def _mod_exp(base: int, exp: int, mod: int) -> int:
    """Fast modular exponentiation via Python built-in."""
    return pow(base, exp, mod)


def _extended_gcd(a: int, b: int):
    """Returns (g, x, y) such that a*x + b*y = g = gcd(a, b)."""
    if a == 0:
        return b, 0, 1
    g, x1, y1 = _extended_gcd(b % a, a)
    return g, y1 - (b // a) * x1, x1


def _mod_inverse(a: int, m: int) -> int:
    """Compute a^{-1} mod m. Raises ValueError if gcd(a, m) != 1."""
    g, x, _ = _extended_gcd(a % m, m)
    if g != 1:
        raise ValueError(f"No modular inverse: gcd({a}, {m}) = {g}")
    return x % m


def _is_probable_prime(n: int, k: int = 20) -> bool:
    """Miller-Rabin primality test with k rounds."""
    if n < 2:
        return False
    if n < 4:
        return True
    if n % 2 == 0:
        return False
    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    for _ in range(k):
        a = int.from_bytes(os.urandom(max(1, (n.bit_length() + 7) // 8)), 'big')
        a = 2 + (a % (n - 3))
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _generate_prime(bits: int) -> int:
    """Generate a random probable prime of the given bit length."""
    while True:
        # Ensure top bit is set for correct bit length
        p = int.from_bytes(os.urandom(bits // 8), 'big')
        p |= (1 << (bits - 1)) | 1  # set top bit and make odd
        if _is_probable_prime(p):
            return p


# ---------------------------------------------------------------------------
# RSA Key Generation, Encrypt, Decrypt, Sign, Verify
# ---------------------------------------------------------------------------

# Default small bit-size for demo speed; real RSA uses 2048+
DEFAULT_RSA_BITS = 512

E_DEFAULT = 65537


def _hash_to_rsa_message(value: int, n: int) -> int:
    """
    Hash an arbitrary integer transcript into the RSA message space [0, n).
    """
    if value < 0:
        raise ValueError("value must be non-negative")
    value_bytes = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    digest = hashlib.sha256(value_bytes).digest()
    return int.from_bytes(digest, "big") % n


def rsa_keygen(bits: int = DEFAULT_RSA_BITS) -> dict:
    """
    Generate an RSA key pair.
    Returns dict with 'public': (n, e), 'private': (n, d), plus p, q, phi for educational display.
    """
    half = bits // 2
    while True:
        p = _generate_prime(half)
        q = _generate_prime(half)
        if p != q:
            break
    n = p * q
    phi = (p - 1) * (q - 1)
    e = E_DEFAULT
    # Ensure e is coprime to phi (extremely likely for 65537, but check)
    from math import gcd
    if gcd(e, phi) != 1:
        # Fallback: walk upward through odd exponents instead of dropping to 3.
        e = 65539
        while gcd(e, phi) != 1:
            e += 2
    d = _mod_inverse(e, phi)
    return {
        "public": {"n": n, "e": e},
        "private": {"n": n, "d": d},
        "p": p,
        "q": q,
        "phi": phi,
        "bits": bits,
    }


def rsa_encrypt(m: int, n: int, e: int) -> int:
    """Textbook RSA encryption: c = m^e mod n."""
    if m < 0 or m >= n:
        raise ValueError(f"Message m must satisfy 0 <= m < n (n has {n.bit_length()} bits)")
    return _mod_exp(m, e, n)


def rsa_decrypt(c: int, n: int, d: int) -> int:
    """Textbook RSA decryption: m = c^d mod n."""
    return _mod_exp(c, d, n)


def rsa_sign(m: int, n: int, d: int) -> int:
    """RSA signature: σ = m^d mod n."""
    if m < 0 or m >= n:
        raise ValueError("Message must satisfy 0 <= m < n")
    return _mod_exp(m, d, n)


def rsa_verify(m: int, sigma: int, n: int, e: int) -> bool:
    """RSA verification: check m == σ^e mod n."""
    return _mod_exp(sigma, e, n) == m


# ---------------------------------------------------------------------------
# RSA CPA-insecurity demo (textbook RSA is deterministic)
# ---------------------------------------------------------------------------

def rsa_cpa_demo(bits: int = DEFAULT_RSA_BITS) -> dict:
    """
    Demonstrates that textbook RSA is NOT CPA-secure:
    encrypting the same message twice produces the same ciphertext.
    A CPA adversary wins with probability 1.
    """
    keys = rsa_keygen(bits)
    n, e = keys["public"]["n"], keys["public"]["e"]
    m = int.from_bytes(b"attack!", 'big')
    c1 = rsa_encrypt(m, n, e)
    c2 = rsa_encrypt(m, n, e)
    return {
        "message_int": m,
        "ciphertext_1": c1,
        "ciphertext_2": c2,
        "identical": c1 == c2,
        "insight": (
            "Textbook RSA is deterministic — same plaintext always gives same ciphertext. "
            "An IND-CPA adversary can distinguish encryptions trivially. "
            "Real-world RSA uses OAEP padding to add randomness."
        ),
    }


# ---------------------------------------------------------------------------
# Diffie-Hellman Key Exchange
# ---------------------------------------------------------------------------

# Use the same safe-prime group as PA1 (Oakley Group 1, RFC 2409)
DH_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF",
    16,
)
DH_G = 2


def dh_keygen(p: int = DH_P, g: int = DH_G) -> dict:
    """Generate a DH private/public key pair."""
    # Private key: random integer in [2, p-2]
    priv = int.from_bytes(os.urandom(32), 'big') % (p - 3) + 2
    pub = _mod_exp(g, priv, p)
    return {"private": priv, "public": pub, "p": p, "g": g}


def dh_shared_secret(my_private: int, their_public: int, p: int = DH_P) -> int:
    """Compute shared secret: K = their_public^my_private mod p."""
    return _mod_exp(their_public, my_private, p)


def dh_exchange_demo() -> dict:
    """
    Full Diffie-Hellman key exchange between Alice and Bob.
    Demonstrates that both parties arrive at the same shared secret.
    """
    alice = dh_keygen()
    bob = dh_keygen()
    # Alice computes shared secret from Bob's public key
    secret_alice = dh_shared_secret(alice["private"], bob["public"])
    # Bob computes shared secret from Alice's public key
    secret_bob = dh_shared_secret(bob["private"], alice["public"])
    return {
        "p_bits": DH_P.bit_length(),
        "g": DH_G,
        "alice_public_hex": hex(alice["public"]),
        "bob_public_hex": hex(bob["public"]),
        "alice_secret_hex": hex(secret_alice),
        "bob_secret_hex": hex(secret_bob),
        "secrets_match": secret_alice == secret_bob,
        "description": (
            "Both parties compute g^{ab} mod p independently. "
            "Security relies on the DDH assumption: given g^a, g^b, "
            "it is hard to distinguish g^{ab} from random."
        ),
    }


# ---------------------------------------------------------------------------
# Man-in-the-Middle Attack Demo (DH without authentication)
# ---------------------------------------------------------------------------

def dh_mitm_demo() -> dict:
    """
    Demonstrates that plain DH is vulnerable to a man-in-the-middle (MITM) attack.
    Mallory intercepts Alice's and Bob's public keys and establishes
    separate shared secrets with each.
    """
    p, g = DH_P, DH_G

    # Alice and Bob generate keys
    alice = dh_keygen(p, g)
    bob = dh_keygen(p, g)

    # For a compact classroom demo Mallory reuses one DH identity on both legs.
    # A realistic active attacker could use separate keys for the Alice-facing
    # and Bob-facing channels.
    mallory = dh_keygen(p, g)

    # Alice thinks she's talking to Bob, but gets Mallory's public key
    secret_alice_mallory = dh_shared_secret(alice["private"], mallory["public"], p)
    # Mallory computes the same secret with Alice
    secret_mallory_alice = dh_shared_secret(mallory["private"], alice["public"], p)

    # Bob thinks he's talking to Alice, but gets Mallory's public key
    secret_bob_mallory = dh_shared_secret(bob["private"], mallory["public"], p)
    # Mallory computes the same secret with Bob
    secret_mallory_bob = dh_shared_secret(mallory["private"], bob["public"], p)

    # Alice and Bob think they share a secret, but they DON'T
    real_alice_bob = dh_shared_secret(alice["private"], bob["public"], p)

    return {
        "alice_mallory_match": secret_alice_mallory == secret_mallory_alice,
        "bob_mallory_match": secret_bob_mallory == secret_mallory_bob,
        "alice_bob_compromised": secret_alice_mallory != real_alice_bob,
        "insight": (
            "Without authentication, Mallory intercepts the exchange and establishes "
            "separate keys with Alice and Bob. She can read/modify all messages. "
            "Digital signatures (RSA) or certificates prevent this attack."
        ),
    }


# ---------------------------------------------------------------------------
# RSA + DH combined: Authenticated Key Exchange sketch
# ---------------------------------------------------------------------------

def authenticated_dh_demo(rsa_bits: int = DEFAULT_RSA_BITS) -> dict:
    """
    Shows how RSA signatures authenticate a DH key exchange,
    preventing the MITM attack.
    """
    # Alice generates RSA keys and signs a digest of her DH public key.
    # Signing the raw DH value modulo n would lose information whenever the DH
    # public key is larger than the RSA modulus.
    alice_rsa = rsa_keygen(rsa_bits)
    alice_dh = dh_keygen()
    signed_message = _hash_to_rsa_message(alice_dh["public"], alice_rsa["public"]["n"])
    alice_sig = rsa_sign(
        signed_message,
        alice_rsa["public"]["n"],
        alice_rsa["private"]["d"],
    )

    # Bob verifies Alice's DH public key using her RSA public key
    verified = rsa_verify(
        signed_message,
        alice_sig,
        alice_rsa["public"]["n"],
        alice_rsa["public"]["e"],
    )

    bob_dh = dh_keygen()
    secret_alice = dh_shared_secret(alice_dh["private"], bob_dh["public"])
    secret_bob = dh_shared_secret(bob_dh["private"], alice_dh["public"])

    return {
        "alice_dh_public_hex": hex(alice_dh["public"]),
        "signed_digest_hex": hex(signed_message),
        "alice_signature_valid": verified,
        "shared_secret_match": secret_alice == secret_bob,
        "description": (
            "Alice signs a digest of her DH public key with RSA. Bob verifies "
            "that signature before computing the shared secret, preventing MITM."
        ),
    }
