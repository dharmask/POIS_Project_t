"""
PA#1 - Pseudorandom Generator (PRG) Implementation
====================================================
Construction: HILL hard-core bit construction from OWF.

  Given OWF f: {0,1}^n -> {0,1}^n, define PRG G of length l+1:
    G(x_0) = b(x_0) || b(x_1) || ... || b(x_l)
  where:
    x_{i+1} = f(x_i)          (iterate the OWF)
    b(x_i)  = inner product of x_i with a fixed random vector r  (mod 2)
              = Goldreich-Levin hard-core bit

The output length l can be set at construction time.

Bidirectional reduction included:
  - OWF => PRG: standard HILL/GL construction above
  - PRG => OWF: given a PRG G, define f(s) = G(s)
                This is one-way because if you could invert f you could
                recover the seed and break pseudorandomness.

Only os.urandom and built-in int operations used.
"""

import os
from .owf import owf_dlp, owf_aes, DLP_P


# ---------------------------------------------------------------------------
# Goldreich-Levin hard-core bit
# ---------------------------------------------------------------------------

def _int_to_bits(x: int, n_bits: int) -> list:
    """Convert integer x to a list of n_bits bits (MSB first)."""
    return [(x >> (n_bits - 1 - i)) & 1 for i in range(n_bits)]


def _gl_hard_core_bit(x: int, r: int, n_bits: int) -> int:
    """
    Goldreich-Levin hard-core bit: b(x) = <x, r> mod 2
    = popcount(x AND r) mod 2
    """
    return bin(x & r).count('1') % 2


# ---------------------------------------------------------------------------
# PRG state class
# ---------------------------------------------------------------------------

class PRG_DLP:
    """
    PRG built from DLP-based OWF using the GL hard-core bit.
    Stretches n bits to (n + output_bits) bits.

    Interface:
      seed(s: int)          -- set internal seed
      next_bits(n: int)     -- generate n pseudorandom bits as an integer
    """

    def __init__(self, output_bits: int = 256, r: int = None):
        """
        output_bits: number of bits to generate per seed (stretch length)
        r:           GL projection vector; if None, a fresh random one is used
        """
        self.output_bits = output_bits
        # GL vector r: same bit-width as DLP_P
        self.n_bits = DLP_P.bit_length()
        if r is None:
            r_bytes = os.urandom(self.n_bits // 8 + 1)
            self._r = int.from_bytes(r_bytes, 'big') % DLP_P
        else:
            self._r = r
        self._state: int = None

    def seed(self, s: int):
        """Set the seed/state."""
        if not isinstance(s, int) or s < 0:
            raise ValueError("Seed must be a non-negative integer")
        self._state = s % DLP_P

    def _next_bit(self) -> int:
        """Advance state via OWF and return one hard-core bit."""
        if self._state is None:
            raise RuntimeError("Call seed() first")
        bit = _gl_hard_core_bit(self._state, self._r, self.n_bits)
        self._state = owf_dlp(self._state)
        return bit

    def next_bits(self, n: int) -> int:
        """
        Generate n pseudorandom bits.
        Returns an integer whose binary representation is the bit-string.
        """
        result = 0
        for _ in range(n):
            result = (result << 1) | self._next_bit()
        return result

    def generate_bytes(self, n_bytes: int) -> bytes:
        """Generate n_bytes of pseudorandom bytes."""
        total_bits = n_bytes * 8
        val = self.next_bits(total_bits)
        return val.to_bytes(n_bytes, 'big')


class PRG_AES:
    """
    PRG built from AES-based OWF using the GL hard-core bit.
    Operates on 128-bit (16-byte) seeds.

    Interface:
      seed(s: bytes)         -- set 16-byte seed
      next_bits(n: int)      -- generate n pseudorandom bits as int
    """

    def __init__(self, output_bits: int = 256, r: bytes = None):
        self.output_bits = output_bits
        self.n_bits = 128
        if r is None:
            self._r = int.from_bytes(os.urandom(16), 'big')
        else:
            self._r = int.from_bytes(r, 'big') if isinstance(r, bytes) else r
        self._state: bytes = None

    def seed(self, s: bytes):
        if isinstance(s, int):
            s = s.to_bytes(16, 'big')
        if len(s) != 16:
            raise ValueError("AES-PRG seed must be 16 bytes")
        self._state = s

    def _next_bit(self) -> int:
        if self._state is None:
            raise RuntimeError("Call seed() first")
        state_int = int.from_bytes(self._state, 'big')
        bit = _gl_hard_core_bit(state_int, self._r, self.n_bits)
        self._state = owf_aes(self._state)
        return bit

    def next_bits(self, n: int) -> int:
        result = 0
        for _ in range(n):
            result = (result << 1) | self._next_bit()
        return result

    def generate_bytes(self, n_bytes: int) -> bytes:
        total_bits = n_bytes * 8
        val = self.next_bits(total_bits)
        return val.to_bytes(n_bytes, 'big')


# ---------------------------------------------------------------------------
# PRG => OWF reduction
# ---------------------------------------------------------------------------

class OWF_from_PRG:
    """
    Reduction: OWF built from a PRG.
    Given PRG G, define
        f_G(s) = G(s)

    This is one-way: if there existed an efficient inverter A for f_G,
    we could recover the seed from the PRG output and break pseudorandomness.
    """

    def __init__(self, prg: PRG_DLP | PRG_AES):
        self._prg = prg

    def compute(self, seed_value) -> int:
        """
        Compute f_G(seed_value) = G(seed_value).
        Returns the full PRG output as an integer.
        """
        self._prg.seed(seed_value)
        return self._prg.next_bits(self._prg.output_bits)


# ---------------------------------------------------------------------------
# Convenience factory
# ---------------------------------------------------------------------------

def make_prg(mode: str = "dlp", output_bits: int = 256, r=None) -> PRG_DLP | PRG_AES:
    """
    Factory for creating a PRG.
    mode: 'dlp' or 'aes'
    output_bits: number of bits to output per seed
    r: optional fixed GL projection vector
    """
    if mode == "dlp":
        return PRG_DLP(output_bits=output_bits, r=r)
    elif mode == "aes":
        return PRG_AES(output_bits=output_bits, r=r)
    else:
        raise ValueError(f"Unknown PRG mode: {mode}")


def PRG(seed_value, mode: str = "aes", output_bits: int = 256, r=None, *, as_int: bool = False):
    """
    Convenience API for later assignments.

    Returns PRG(seed_value) using the existing PA#1 implementation.
    By default the output is returned as bytes; set as_int=True to receive
    the exact output bitstring as an integer.
    """
    prg = make_prg(mode=mode, output_bits=output_bits, r=r)
    prg.seed(seed_value)
    if as_int:
        return prg.next_bits(output_bits)
    return prg.generate_bytes((output_bits + 7) // 8)
