"""
PA#1 - NIST SP 800-22 Statistical Tests (subset)
==================================================
Implemented tests:
  1. Frequency (Monobit) Test  — Section 2.1
  2. Runs Test                 — Section 2.3
  3. Serial Test (overlapping) — Section 2.11 (m=2)

All tests return a dict with:
  {'test': name, 'p_value': float, 'pass': bool, 'details': dict}

A test passes if p_value >= 0.01 (NIST threshold).
"""

import math


def _bits_from_int(x: int, n: int) -> list:
    """Extract n bits from integer x (MSB first)."""
    return [(x >> (n - 1 - i)) & 1 for i in range(n)]


def _bits_from_bytes(data: bytes) -> list:
    """Convert bytes to list of bits."""
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


# ---------------------------------------------------------------------------
# 1. Frequency (Monobit) Test
# ---------------------------------------------------------------------------

def frequency_test(bits: list) -> dict:
    """
    NIST SP 800-22 Section 2.1 — Frequency (Monobit) Test.
    Tests whether the number of 1s equals the number of 0s.
    """
    n = len(bits)
    if n < 100:
        return {'test': 'Frequency', 'p_value': None,
                'pass': False, 'details': {'error': 'Need >= 100 bits'}}

    # S_n = sum of (+1 for 1-bit, -1 for 0-bit)
    s_n = sum(1 if b == 1 else -1 for b in bits)
    s_obs = abs(s_n) / math.sqrt(n)
    # p-value = erfc(s_obs / sqrt(2))
    p_value = math.erfc(s_obs / math.sqrt(2))

    return {
        'test': 'Frequency (Monobit)',
        'p_value': p_value,
        'pass': p_value >= 0.01,
        'details': {
            'n': n,
            's_n': s_n,
            's_obs': s_obs,
            'ones_count': bits.count(1),
            'zeros_count': bits.count(0),
        }
    }


# ---------------------------------------------------------------------------
# 2. Runs Test
# ---------------------------------------------------------------------------

def runs_test(bits: list) -> dict:
    """
    NIST SP 800-22 Section 2.3 — Runs Test.
    Tests whether oscillation between 0s and 1s is as expected for random.
    """
    n = len(bits)
    if n < 100:
        return {'test': 'Runs', 'p_value': None,
                'pass': False, 'details': {'error': 'Need >= 100 bits'}}

    # Pre-test: proportion of ones
    pi = bits.count(1) / n
    tau = 2.0 / math.sqrt(n)
    if abs(pi - 0.5) >= tau:
        p_value = 0.0
        return {
            'test': 'Runs',
            'p_value': p_value,
            'pass': False,
            'details': {
                'n': n,
                'pi': pi,
                'tau': tau,
                'note': 'Pre-test failed: proportion of ones too far from 0.5'
            }
        }

    # Count runs
    v_obs = 1 + sum(1 for i in range(1, n) if bits[i] != bits[i - 1])

    # Compute p-value
    numerator = abs(v_obs - 2 * n * pi * (1 - pi))
    denominator = 2 * math.sqrt(2 * n) * pi * (1 - pi)
    p_value = math.erfc(numerator / denominator)

    return {
        'test': 'Runs',
        'p_value': p_value,
        'pass': p_value >= 0.01,
        'details': {
            'n': n,
            'pi': pi,
            'v_obs': v_obs,
            'v_expected': 2 * n * pi * (1 - pi),
        }
    }


# ---------------------------------------------------------------------------
# 3. Serial Test (m=2, overlapping)
# ---------------------------------------------------------------------------

def _count_patterns(bits: list, m: int) -> dict:
    """Count frequency of all m-bit patterns in cyclic sequence."""
    n = len(bits)
    counts = {}
    for i in range(n):
        pattern = tuple(bits[(i + j) % n] for j in range(m))
        counts[pattern] = counts.get(pattern, 0) + 1
    return counts


def serial_test(bits: list, m: int = 2) -> dict:
    """
    NIST SP 800-22 Section 2.11 — Serial Test.
    Tests the uniformity of m-bit patterns in the sequence.
    Uses m=2 by default (tests 2-bit patterns: 00, 01, 10, 11).
    """
    n = len(bits)
    if n < 100:
        return {'test': 'Serial', 'p_value': None,
                'pass': False, 'details': {'error': 'Need >= 100 bits'}}

    def psi_sq(m_val):
        if m_val <= 0:
            return 0.0
        counts = _count_patterns(bits, m_val)
        total = sum(counts.values())
        s = sum(c * c for c in counts.values())
        return (2 ** m_val / n) * s - n

    psi_sq_m = psi_sq(m)
    psi_sq_m1 = psi_sq(m - 1)
    psi_sq_m2 = psi_sq(m - 2)

    delta1 = psi_sq_m - psi_sq_m1
    delta2 = psi_sq_m - 2 * psi_sq_m1 + psi_sq_m2

    def _igamc(a, x):
        """Regularized upper incomplete gamma function approximation."""
        return _regularized_gamma_upper(a, x)

    p_value1 = _igamc(2 ** (m - 2), delta1 / 2)
    p_value2 = _igamc(2 ** (m - 3), delta2 / 2) if m >= 2 else 1.0

    # Use the minimum as the conservative p-value
    p_value = min(p_value1, p_value2) if m >= 2 else p_value1

    return {
        'test': f'Serial (m={m})',
        'p_value': p_value,
        'pass': p_value >= 0.01,
        'details': {
            'n': n,
            'm': m,
            'psi_sq_m': psi_sq_m,
            'delta1': delta1,
            'delta2': delta2,
            'p_value1': p_value1,
            'p_value2': p_value2,
        }
    }


def _regularized_gamma_upper(a: float, x: float) -> float:
    """
    Regularized upper incomplete gamma Q(a, x) = 1 - P(a, x).
    Uses continued fraction expansion for x > a+1, series for x <= a+1.
    Pure Python, no scipy.
    """
    if x < 0:
        raise ValueError("x must be >= 0")
    if x == 0:
        return 1.0
    if a <= 0:
        raise ValueError("a must be > 0")

    if x <= a + 1.0:
        # Series expansion for lower incomplete gamma
        p = _lower_gamma_series(a, x)
        return 1.0 - p
    else:
        # Continued fraction for upper incomplete gamma
        return _upper_gamma_cf(a, x)


def _lower_gamma_series(a: float, x: float) -> float:
    """Regularized lower incomplete gamma P(a,x) via series."""
    if x < 0:
        return 0.0
    ap = a
    delt = s = 1.0 / a
    for _ in range(300):
        ap += 1.0
        delt *= x / ap
        s += delt
        if abs(delt) < abs(s) * 1e-12:
            break
    return s * math.exp(-x + a * math.log(x) - math.lgamma(a))


def _upper_gamma_cf(a: float, x: float) -> float:
    """Regularized upper incomplete gamma Q(a,x) via Lentz continued fraction."""
    FPMIN = 1e-300
    EPS = 1e-12
    b = x + 1.0 - a
    c = 1.0 / FPMIN
    d = 1.0 / b
    h = d
    for i in range(1, 300):
        an = -i * (i - a)
        b += 2.0
        d = an * d + b
        if abs(d) < FPMIN:
            d = FPMIN
        c = b + an / c
        if abs(c) < FPMIN:
            c = FPMIN
        d = 1.0 / d
        delt = d * c
        h *= delt
        if abs(delt - 1.0) < EPS:
            break
    return math.exp(-x + a * math.log(x) - math.lgamma(a)) * h


# ---------------------------------------------------------------------------
# Run all tests on PRG output
# ---------------------------------------------------------------------------

def run_all_tests(prg, seed_value, n_bits: int = 20000) -> list:
    """
    Run all three NIST tests on n_bits of PRG output.
    Returns a list of test result dicts.
    """
    prg.seed(seed_value)
    value = prg.next_bits(n_bits)
    bits = _bits_from_int(value, n_bits)

    return [
        frequency_test(bits),
        runs_test(bits),
        serial_test(bits, m=2),
    ]


def run_tests_on_bytes(data: bytes) -> list:
    """Run all three NIST tests on a bytes object."""
    bits = _bits_from_bytes(data)
    return [
        frequency_test(bits),
        runs_test(bits),
        serial_test(bits, m=2),
    ]
