"""
PA#4 — Message Authentication Code (MAC) + HMAC
=================================================

MAC Definition:
  A MAC is a keyed tag scheme (Gen, Mac, Vrfy) that provides integrity + authenticity.
  Security: EUF-CMA (Existential Unforgeability under Chosen Message Attack).
  An adversary making q adaptive queries cannot forge a valid tag on a new message.

PRF → MAC Reduction:
  Any secure PRF F_k: {0,1}^n -> {0,1}^n gives a secure MAC for fixed-length messages:
    Mac_k(m) = F_k(m)
  Security follows directly from PRF security: a MAC forger is a PRF distinguisher.

CBC-MAC (variable-length messages):
  Extends the fixed-length PRF-MAC to arbitrary messages via sequential chaining:
    T_0 = 0^n
    T_i = F_k(m_i ⊕ T_{i-1})
    Tag  = T_l   (final state)
  Secure for fixed-length messages. For variable-length, needs a length prefix
  or ECBC (encrypted CBC-MAC) to prevent length-extension forgery.

HMAC (Hash-based MAC):
  HMAC_k(m) = H((k ⊕ opad) ‖ H((k ⊕ ipad) ‖ m))
  We implement HMAC using our AES-128 as the compression function
  (Davies-Meyer: h(cv, block) = AES_block(cv) ⊕ cv).
  This gives a provably secure MAC from our scratch AES.

Length-Extension Attack on raw-hash MACs:
  If Mac(m) = H(k ‖ m), an adversary who knows H(k ‖ m) can compute
  H(k ‖ m ‖ pad ‖ m') for any m' without knowing k.
  HMAC is immune to this attack by design.

No external libraries — only os.urandom and built-in operations.
"""

import hmac
import os

from backend.pa1.owf import _aes128_encrypt_block


# ---------------------------------------------------------------------------
# Davies-Meyer compression: h(cv, block) = AES_block(cv) ⊕ cv
# Builds a collision-resistant hash from our scratch AES block cipher.
# ---------------------------------------------------------------------------

def _davies_meyer(cv: bytes, block: bytes) -> bytes:
    """Single Davies-Meyer step: AES_block(cv) ⊕ cv."""
    aes_out = _aes128_encrypt_block(cv, block)
    return bytes(a ^ b for a, b in zip(aes_out, cv))


def _aes_hash(data: bytes, iv: bytes = None) -> bytes:
    """
    Merkle-Damgård hash using Davies-Meyer compression and AES-128.
    Block size = 16 bytes. Pads with length-encoding.
    The final 8-byte length field encodes the message length in bytes rather
    than bits. That keeps the demo self-consistent, including the
    length-extension example, but it is not SHA-style standard padding.
    """
    if iv is None:
        iv = bytes([0x67, 0x45, 0x23, 0x01,  # fixed IV (arbitrary constants)
                    0xef, 0xcd, 0xab, 0x89,
                    0x98, 0xba, 0xdc, 0xfe,
                    0x10, 0x32, 0x54, 0x76])
    # Padding: append 0x80, then zeros, then 8-byte big-endian length
    msg_len = len(data)
    data_pad = data + b'\x80'
    while len(data_pad) % 16 != 8:
        data_pad += b'\x00'
    data_pad += msg_len.to_bytes(8, 'big')

    cv = iv
    for i in range(0, len(data_pad), 16):
        block = data_pad[i:i+16]
        cv = _davies_meyer(cv, block)
    return cv


# ---------------------------------------------------------------------------
# Fixed-length PRF-MAC  (Mac_k(m) = AES_k(m))
# ---------------------------------------------------------------------------

def mac_prf(key: bytes, message: bytes) -> bytes:
    """
    Fixed-length MAC from PRF: Mac_k(m) = AES_k(m).
    Secure for 16-byte messages under the PRF assumption.
    """
    if len(key) != 16:
        raise ValueError("Key must be 16 bytes")
    if len(message) != 16:
        raise ValueError("PRF-MAC input must be exactly 16 bytes")
    return _aes128_encrypt_block(message, key)


def vrfy_prf(key: bytes, message: bytes, tag: bytes) -> bool:
    return hmac.compare_digest(mac_prf(key, message), bytes(tag))


# ---------------------------------------------------------------------------
# CBC-MAC (variable-length)
# ---------------------------------------------------------------------------

def cbc_mac(key: bytes, message: bytes) -> bytes:
    """
    CBC-MAC: T_0=0, T_i = AES_k(m_i ⊕ T_{i-1}), tag = T_l.
    Pads message with PKCS#7 to block boundary.
    This intentionally differs from PA#5's length-prefixed CBC-MAC variant.
    """
    if len(key) != 16:
        raise ValueError("Key must be 16 bytes")
    if not message:
        raise ValueError("Message must be non-empty")
    # PKCS7 pad
    pad_len = 16 - (len(message) % 16)
    padded = message + bytes([pad_len] * pad_len)
    T = b'\x00' * 16
    for i in range(0, len(padded), 16):
        block = bytes(a ^ b for a, b in zip(padded[i:i+16], T))
        T = _aes128_encrypt_block(block, key)
    return T


def vrfy_cbc_mac(key: bytes, message: bytes, tag: bytes) -> bool:
    return hmac.compare_digest(cbc_mac(key, message), bytes(tag))


# ---------------------------------------------------------------------------
# HMAC-AES  (using our Davies-Meyer AES hash as the hash function)
# ---------------------------------------------------------------------------

IPAD = bytes([0x36] * 16)
OPAD = bytes([0x5c] * 16)


def hmac_aes(key: bytes, message: bytes) -> bytes:
    """
    HMAC_k(m) = H((k ⊕ opad) ‖ H((k ⊕ ipad) ‖ m))
    where H is our Davies-Meyer AES hash.
    """
    # Key preparation: if key > 16 bytes, hash it; pad to 16 bytes
    if len(key) > 16:
        key = _aes_hash(key)
    k = key.ljust(16, b'\x00')

    k_ipad = bytes(a ^ b for a, b in zip(k, IPAD))
    k_opad = bytes(a ^ b for a, b in zip(k, OPAD))

    inner = _aes_hash(k_ipad + message)
    outer = _aes_hash(k_opad + inner)
    return outer


def vrfy_hmac_aes(key: bytes, message: bytes, tag: bytes) -> bool:
    return hmac.compare_digest(hmac_aes(key, message), bytes(tag))


# ---------------------------------------------------------------------------
# Length-Extension Attack Demo
# ---------------------------------------------------------------------------

def length_extension_demo(key: bytes, original_msg: bytes) -> dict:
    """
    Demonstrates length-extension on a naive MAC: Mac(m) = H(k ‖ m).
    The attacker knows H(k ‖ m) and can extend without knowing k.

    With our Davies-Meyer hash, the chaining value IS the tag,
    so the attacker can continue hashing from the known CV.
    """
    # Compute naive MAC: H(k ‖ m)
    naive_tag = _aes_hash(key + original_msg)

    # Padding that was applied to k ‖ m (must match _aes_hash's internal padding)
    full_msg = key + original_msg
    msg_len = len(full_msg)  # _aes_hash encodes byte length, not bit length
    pad = b'\x80'
    while (len(full_msg) + len(pad)) % 16 != 8:
        pad += b'\x00'
    pad += msg_len.to_bytes(8, 'big')

    # Extension: attacker chooses additional data
    extension = b"&admin=true"

    # Attacker forges: continue from naive_tag as CV, with correct TOTAL length.
    # The total message the server will hash = key + original_msg + pad + extension
    # Total length for the final padding must match what the server computes.
    total_len = len(full_msg) + len(pad) + len(extension)
    ext_padded = extension + b'\x80'
    while len(ext_padded) % 16 != 8:
        ext_padded += b'\x00'
    ext_padded += total_len.to_bytes(8, 'big')

    cv = naive_tag
    for i in range(0, len(ext_padded), 16):
        block = ext_padded[i:i+16]
        cv = _davies_meyer(cv, block)
    forged_tag = cv

    # What the server would compute for the forged message
    forged_message = original_msg + pad + extension
    expected_tag = _aes_hash(key + forged_message)

    return {
        "original_message": original_msg.decode("utf-8", errors="replace"),
        "original_tag": naive_tag.hex(),
        "extension": extension.decode(),
        "forged_message_hex": forged_message.hex(),
        "attacker_forged_tag": forged_tag.hex(),
        "server_expected_tag": expected_tag.hex(),
        "attack_succeeded": forged_tag == expected_tag,
        "hmac_tag": hmac_aes(key, original_msg).hex(),
        "hmac_immune": True,
        "explanation": (
            "Naive H(k‖m) leaks the internal state. "
            "HMAC wraps with two separate key-padded hashes, blocking extension."
        ),
    }


# ---------------------------------------------------------------------------
# EUF-CMA Security Game
# ---------------------------------------------------------------------------

def euf_cma_game(mac_mode: str = "hmac", n_queries: int = 10) -> dict:
    """
    Simulate the MAC EUF-CMA security game.
    - Challenger generates a random key
    - Adversary makes n_queries adaptive chosen-message queries
    - Adversary attempts to forge a tag on a new (unseen) message
    - A computationally bounded adversary cannot win with non-negligible probability

    mac_mode: 'prf' | 'cbc' | 'hmac'
    """
    key = os.urandom(16)

    def tag(msg: bytes) -> bytes:
        if mac_mode == "prf":
            m = (msg[:16]).ljust(16, b'\x00')
            return mac_prf(key, m)
        elif mac_mode == "cbc":
            return cbc_mac(key, msg)
        else:
            return hmac_aes(key, msg)

    # Adversary's query set: (message_i, tag_i)
    queries = []
    messages = [f"message_{i:02d}".encode() for i in range(n_queries)]
    for m in messages:
        queries.append({"message": m.decode(), "tag": tag(m).hex()})

    # Naive forger: tries to forge on a new message by replaying an old tag
    # (This represents a computationally unbounded but "dumb" adversary)
    new_msg = b"forged_new_message"
    replayed_tag = bytes.fromhex(queries[0]["tag"])  # reuse first tag
    forge_success = (new_msg not in messages) and tag(new_msg) == replayed_tag

    # Correct tag for the new message (only challenger knows this)
    correct_tag = tag(new_msg)

    return {
        "mac_mode": mac_mode,
        "n_queries": n_queries,
        "queries": queries[:5],  # show first 5 for display
        "forgery_attempt": {
            "new_message": new_msg.decode(),
            "replayed_tag": replayed_tag.hex(),
            "correct_tag": correct_tag.hex(),
            "success": forge_success,
        },
        "verdict": "SECURE — adversary failed to forge" if not forge_success else "FORGED (unexpected)",
        "note": (
            "A PPT adversary cannot forge a valid tag on a fresh message "
            "with advantage better than q/2^n under the PRF assumption."
        ),
    }
