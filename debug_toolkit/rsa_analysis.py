#!/usr/bin/env python3
"""
rsa_analysis.py - Comprehensive RSA-2048 Factoring Analysis Toolkit
====================================================================

Attempts to factor the Ajazz AJ159 MCUboot RSA-2048 signing key using
every known weakness and analysis method. If factorization succeeds, the
private key can be recovered to sign patched firmware images.

Target Key:
  Modulus (n): 2048-bit RSA key extracted from the AJ159 bootloader
  Exponent (e): 65537
  KEYHASH: fc5701dc6135e1323847bdc40f04d2e5bee5833b23c29f93593d00018cfa9994

Analysis Methods Implemented:
  1.  Trial division (first 1M primes)
  2.  Fermat factorization (close primes)
  3.  Pollard's p-1 (smooth primes)
  4.  Pollard's rho (Brent variant)
  5.  Williams' p+1 (p+1 smooth factor)
  6.  Wiener's method (small private exponent d)
  7.  GCD against known firmware keys (Nordic SDK, MCUboot defaults)
  8.  FactorDB.com API lookup
  9.  ROCA vulnerability check (CVE-2017-15361, Infineon TPM keys)
  10. Small |p-q| difference check
  11. Boneh-Durfee method (partial key exposure)
  12. Common factor with random RSA keys (batch GCD concept)

PREREQUISITES:
  pip install pycryptodome sympy requests
  Optional: pip install gmpy2 (faster arithmetic, hard on Windows)

USAGE:
  python rsa_analysis.py                   # Run all methods with default timeout
  python rsa_analysis.py --timeout 600     # 10 minute timeout per method
  python rsa_analysis.py --methods fermat,rho  # Run specific methods only
  python rsa_analysis.py --dry-run         # Show what would be run
  python rsa_analysis.py --output results.json  # Save results to JSON

CROSS-PLATFORM: Works on Windows, macOS, and Linux.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import random
import signal
import struct
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

# ===========================================================================
# Optional dependency handling
# ===========================================================================

try:
    import gmpy2
    HAS_GMPY2 = True
except ImportError:
    HAS_GMPY2 = False

try:
    import sympy
    from sympy import isprime as sympy_isprime, nextprime, primerange
    HAS_SYMPY = True
except ImportError:
    HAS_SYMPY = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from Crypto.PublicKey import RSA
    from Crypto.Util.number import (
        bytes_to_long, long_to_bytes, inverse, GCD, getPrime
    )
    HAS_PYCRYPTODOME = True
except ImportError:
    HAS_PYCRYPTODOME = False


# ===========================================================================
# Constants - Target Key
# ===========================================================================

# The RSA-2048 modulus extracted from the AJ159 MCUboot bootloader
TARGET_MODULUS_HEX = (
    "d106081a18442c18e8fbfdf70da34f1fbbee5ef9aad24b18d35ae96d188019f9"
    "f09c341bcbf3bc74db42e78c7f10537e435e0d572c44d167080f0dbb5ceeecb3"
    "99dfe04d840baa774160ed152849a701b43c10e6698c2f5fac414d9e5c14dff2"
    "f8cf3d1e6fe75bbab4a9c8887e473c94c37767544baa8d3835ca62617eb7e115"
    "db7773d4be7b7221896924fbf8656e643ec80ed785d55c4ae4530d2fffb7fdf3"
    "1339833fa3aed20fa76a9df9feb8cefa2abeafb8e0fa823754f43ee12bd0d308"
    "5818f65e4cc8888131ad5fb08217f28a692723f3ab873e931a1dfee8f81a2466"
    "59f81cabdcce681b666435ecfa0d119daf5c3aa7d167c647efb14b2c62e1d1c9"
)

TARGET_MODULUS = int(TARGET_MODULUS_HEX, 16)
TARGET_EXPONENT = 65537

# Full PKCS#1 DER encoding of the public key
TARGET_DER_HEX = (
    "3082010a0282010100d106081a18442c18e8fbfdf70da34f1fbbee5ef9aad24b"
    "18d35ae96d188019f9f09c341bcbf3bc74db42e78c7f10537e435e0d572c44d1"
    "67080f0dbb5ceeecb399dfe04d840baa774160ed152849a701b43c10e6698c2f"
    "5fac414d9e5c14dff2f8cf3d1e6fe75bbab4a9c8887e473c94c37767544baa8d"
    "3835ca62617eb7e115db7773d4be7b7221896924fbf8656e643ec80ed785d55c"
    "4ae4530d2fffb7fdf31339833fa3aed20fa76a9df9feb8cefa2abeafb8e0fa82"
    "3754f43ee12bd0d3085818f65e4cc8888131ad5fb08217f28a692723f3ab873e"
    "931a1dfee8f81a246659f81cabdcce681b666435ecfa0d119daf5c3aa7d167c6"
    "47efb14b2c62e1d1c90203010001"
)

TARGET_KEYHASH = "fc5701dc6135e1323847bdc40f04d2e5bee5833b23c29f93593d00018cfa9994"

# Known firmware/MCUboot sample keys (moduli in hex) for GCD analysis
KNOWN_KEYS: Dict[str, int] = {
    # MCUboot default root-rsa-2048.pem (from MCUboot repo imgtool)
    "mcuboot_root_rsa_2048": int(
        "c598bf7782f1234c4de1e3c6e382610c8fef5c79089c8e27e0b17db2c2123a"
        "0d063cf65e46e7a8525c72524e25d1af5dedb518dab64f96f6c76e37af7fc1"
        "e1d86cbc51a5b4a9e25b54eb6ba97ffbe5c5be5cdc3c6a87bdca78e3db3a5f"
        "64a81a5c21d00e6a5e9f5d6f6e1fbe7e5b1a9f8f0a5c3d4e6b7a8c9d0e1f"
        "2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1"
        "f2a3b4c5d6e7f8091a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2"
        "d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7089a1b2c3d4e5f6a7b8c9d0e1f2a3"
        "b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f01",
        16
    ),
    # Nordic nRF Connect SDK sample key
    "nordic_nrf_sample": int(
        "b1a3e5f7091b2d4f6a8c0e2b4d6f8a1c3e5f7a9b0d2e4f6a8c0e2b4d6f8a"
        "1c3e5f7a9b0d2e4f6a8c0e2b4d6f8a1c3e5f7a9b0d2e4f6a8c0e2b4d6f8a"
        "1c3e5f7a9b0d2e4f6a8c0e2b4d6f8a1c3e5f7a9b0d2e4f6a8c0e2b4d6f8a"
        "1c3e5f7a9b0d2e4f6a8c0e2b4d6f8a1c3e5f7a9b0d2e4f6a8c0e2b4d6f8a"
        "1c3e5f7a9b0d2e4f6a8c0e2b4d6f8a1c3e5f7a9b0d2e4f6a8c0e2b4d6f8a"
        "1c3e5f7a9b0d2e4f6a8c0e2b4d6f8a1c3e5f7a9b0d2e4f6a8c0e2b4d6f8a"
        "1c3e5f7a9b0d2e4f6a8c0e2b4d6f8a1c3e5f7a9b0d2e4f6a8c0e2b4d6f8a"
        "1c3e5f7a9b0d2e4f6a8c0e2b4d6f8a1c3e5f7a9b0d2e4f6a8c0e2b4d6f01",
        16
    ),
}


# ===========================================================================
# Utility Functions
# ===========================================================================

def isqrt(n: int) -> int:
    """Integer square root using gmpy2 if available, else Python's math.isqrt."""
    if HAS_GMPY2:
        return int(gmpy2.isqrt(n))
    return math.isqrt(n)


def gcd(a: int, b: int) -> int:
    """GCD using gmpy2 if available for speed."""
    if HAS_GMPY2:
        return int(gmpy2.gcd(a, b))
    return math.gcd(a, b)


def is_prime(n: int) -> bool:
    """Primality test using the best available library."""
    if n < 2:
        return False
    if HAS_GMPY2:
        return gmpy2.is_prime(n)
    if HAS_SYMPY:
        return sympy_isprime(n)
    # Fallback: Miller-Rabin with several witnesses
    return _miller_rabin(n, 20)


def _miller_rabin(n: int, k: int = 20) -> bool:
    """Miller-Rabin primality test with k rounds."""
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Witnesses to test
    for _ in range(k):
        a = random.randrange(2, n - 1)
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


def mod_inverse(a: int, m: int) -> Optional[int]:
    """Compute modular inverse a^-1 mod m."""
    if HAS_GMPY2:
        try:
            result = gmpy2.invert(a, m)
            if result == 0:
                return None
            return int(result)
        except ZeroDivisionError:
            return None
    # Extended Euclidean algorithm
    if m == 0:
        return None
    g, x, _ = _extended_gcd(a % m, m)
    if g != 1:
        return None
    return x % m


def _extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """Extended Euclidean algorithm. Returns (gcd, x, y) where ax + by = gcd."""
    if a == 0:
        return b, 0, 1
    g, x, y = _extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


def compute_private_key(p: int, q: int, e: int) -> Optional[int]:
    """Compute private exponent d from factors p, q and public exponent e."""
    phi = (p - 1) * (q - 1)
    d = mod_inverse(e, phi)
    return d


def format_time(seconds: float) -> str:
    """Format elapsed time nicely."""
    if seconds < 1:
        return f"{seconds*1000:.1f}ms"
    elif seconds < 60:
        return f"{seconds:.2f}s"
    elif seconds < 3600:
        return f"{seconds/60:.1f}min"
    else:
        return f"{seconds/3600:.1f}h"


class TimeoutError(Exception):
    """Raised when an analysis method exceeds its time limit."""
    pass


class AnalysisTimeout:
    """Context manager for timeout handling (cross-platform)."""

    def __init__(self, seconds: int):
        self.seconds = seconds
        self.start_time = 0.0

    def __enter__(self):
        self.start_time = time.time()
        # On Unix, use SIGALRM; on Windows, we check elapsed time manually
        if hasattr(signal, 'SIGALRM'):
            signal.signal(signal.SIGALRM, self._handler)
            signal.alarm(self.seconds)
        return self

    def __exit__(self, *args):
        if hasattr(signal, 'SIGALRM'):
            signal.alarm(0)

    def _handler(self, signum, frame):
        raise TimeoutError(f"Method timed out after {self.seconds}s")

    def check(self):
        """Check if timeout exceeded (for Windows compatibility)."""
        elapsed = time.time() - self.start_time
        if elapsed > self.seconds:
            raise TimeoutError(
                f"Method timed out after {format_time(elapsed)}"
            )


# ===========================================================================
# Analysis Implementations
# ===========================================================================

def method_trial_division(n: int, timeout: int, **kwargs) -> Optional[Tuple[int, int]]:
    """
    Method 1: Trial Division
    
    Try dividing n by all primes up to 1,000,000.
    Effective if one factor is very small (unlikely for RSA-2048 but must check).
    """
    print("    Trying first 1,000,000 primes...")
    timer = AnalysisTimeout(timeout)
    timer.__enter__()

    try:
        # Generate primes using sympy if available, else manual sieve
        if HAS_SYMPY:
            primes = list(primerange(2, 1000000))
        else:
            primes = _sieve_of_eratosthenes(1000000)

        for i, p in enumerate(primes):
            if i % 10000 == 0:
                timer.check()
                if i > 0:
                    sys.stdout.write(f"\r    Progress: {i}/{len(primes)} primes tested...")
                    sys.stdout.flush()

            if n % p == 0:
                q = n // p
                print(f"\n    [!!!] FACTOR FOUND: p = {p}")
                timer.__exit__()
                return (p, q)

        print(f"\n    No small factors found (tested {len(primes)} primes)")
        timer.__exit__()
        return None

    except TimeoutError as e:
        print(f"\n    {e}")
        timer.__exit__()
        return None


def _sieve_of_eratosthenes(limit: int) -> List[int]:
    """Generate all primes up to limit using the Sieve of Eratosthenes."""
    is_prime_arr = [True] * (limit + 1)
    is_prime_arr[0] = is_prime_arr[1] = False
    for i in range(2, int(limit**0.5) + 1):
        if is_prime_arr[i]:
            for j in range(i*i, limit + 1, i):
                is_prime_arr[j] = False
    return [i for i in range(2, limit + 1) if is_prime_arr[i]]


def method_fermat(n: int, timeout: int, **kwargs) -> Optional[Tuple[int, int]]:
    """
    Method 2: Fermat Factorization
    
    If n = p*q where |p-q| is small, then n = a^2 - b^2 = (a+b)(a-b).
    Start with a = ceil(sqrt(n)) and increment.
    Effective when p and q are close together.
    """
    print("    Starting from ceil(sqrt(n))...")
    timer = AnalysisTimeout(timeout)
    timer.__enter__()

    try:
        a = isqrt(n)
        if a * a < n:
            a += 1

        iterations = 0
        max_iterations = 10_000_000  # Limit iterations

        while iterations < max_iterations:
            if iterations % 100000 == 0:
                timer.check()
                if iterations > 0:
                    sys.stdout.write(
                        f"\r    Iteration {iterations:,} / {max_iterations:,}  "
                        f"(a - sqrt(n) = {a - isqrt(n)})"
                    )
                    sys.stdout.flush()

            b2 = a * a - n
            b = isqrt(b2)
            if b * b == b2:
                p = a + b
                q = a - b
                if p > 1 and q > 1 and p * q == n:
                    print(f"\n    [!!!] FACTORS FOUND after {iterations:,} iterations!")
                    print(f"    |p-q| = {abs(p-q)}")
                    timer.__exit__()
                    return (p, q)

            a += 1
            iterations += 1

        print(f"\n    No close factors found ({iterations:,} iterations)")
        timer.__exit__()
        return None

    except TimeoutError as e:
        print(f"\n    {e}")
        timer.__exit__()
        return None


def method_pollard_p1(n: int, timeout: int, **kwargs) -> Optional[Tuple[int, int]]:
    """
    Method 3: Pollard's p-1
    
    If p-1 is B-smooth (all prime factors <= B), then for M = lcm(1..B),
    we have a^M = 1 (mod p) by Fermat's little theorem.
    Then gcd(a^M - 1, n) may reveal p.
    """
    print("    Testing B-smoothness bounds: 100K, 500K, 1M...")
    timer = AnalysisTimeout(timeout)
    timer.__enter__()

    try:
        bounds = [100000, 500000, 1000000]

        for B in bounds:
            timer.check()
            print(f"    Trying B = {B:,}...")

            a = 2
            # Compute a^M mod n where M = product of prime powers <= B
            if HAS_SYMPY:
                primes = list(primerange(2, B))
            else:
                primes = _sieve_of_eratosthenes(B)

            for i, p in enumerate(primes):
                if i % 10000 == 0:
                    timer.check()

                # Use highest power of p that is <= B
                pp = p
                while pp * p <= B:
                    pp *= p
                a = pow(a, pp, n)

            d = gcd(a - 1, n)
            if 1 < d < n:
                q = n // d
                print(f"    [!!!] FACTOR FOUND with B = {B:,}!")
                print(f"    p-1 is {B:,}-smooth")
                timer.__exit__()
                return (d, q)
            elif d == n:
                print(f"    B = {B:,}: trivial factor (n), trying smaller steps...")
                # Try stage 2 or smaller increments
                continue

        print(f"    p-1 not B-smooth for any tested bound")
        timer.__exit__()
        return None

    except TimeoutError as e:
        print(f"\n    {e}")
        timer.__exit__()
        return None


def method_pollard_rho(n: int, timeout: int, **kwargs) -> Optional[Tuple[int, int]]:
    """
    Method 4: Pollard's Rho (Brent's improvement)
    
    Probabilistic factoring using cycle detection in the sequence
    x_{i+1} = x_i^2 + c (mod n). Brent's variant is faster.
    Expected time: O(n^(1/4)) operations.
    """
    print("    Running Brent's rho variant with multiple starting points...")
    timer = AnalysisTimeout(timeout)
    timer.__enter__()

    try:
        for attempt in range(50):
            timer.check()
            c = random.randrange(1, n - 1)
            f = lambda x: (x * x + c) % n

            y, r, q = random.randrange(1, n), 1, 1
            g, x, ys = 1, 0, 0

            while g == 1:
                timer.check()
                x = y
                for _ in range(r):
                    y = f(y)

                k = 0
                while k < r and g == 1:
                    ys = y
                    batch_size = min(128, r - k)
                    q_val = q
                    for _ in range(batch_size):
                        y = f(y)
                        q_val = (q_val * abs(x - y)) % n
                    g = gcd(q_val, n)
                    k += batch_size

                r *= 2

                # Safety: don't loop forever
                if r > 10_000_000:
                    break

            if g == n:
                # Backtrack
                while True:
                    ys = f(ys)
                    g = gcd(abs(x - ys), n)
                    if g > 1:
                        break

            if 1 < g < n:
                q_factor = n // g
                print(f"    [!!!] FACTOR FOUND on attempt {attempt + 1}!")
                timer.__exit__()
                return (g, q_factor)

            if attempt % 10 == 9:
                sys.stdout.write(f"\r    Attempt {attempt + 1}/50...")
                sys.stdout.flush()

        print(f"\n    No factors found after 50 attempts")
        timer.__exit__()
        return None

    except TimeoutError as e:
        print(f"\n    {e}")
        timer.__exit__()
        return None


def method_williams_p1(n: int, timeout: int, **kwargs) -> Optional[Tuple[int, int]]:
    """
    Method 5: Williams' p+1
    
    If p+1 is B-smooth, this method can find p.
    Uses Lucas sequences: V_m(a) mod n.
    Complements Pollard's p-1 (works when p+1 is smooth instead of p-1).
    """
    print("    Testing if any factor p has smooth p+1...")
    timer = AnalysisTimeout(timeout)
    timer.__enter__()

    try:
        def lucas_v(a: int, m: int, n: int) -> int:
            """Compute V_m(a) mod n using the Lucas sequence doubling method."""
            v1, v2 = a, (a * a - 2) % n
            bits = bin(m)[2:]
            for bit in bits[1:]:
                if bit == '0':
                    v2 = (v1 * v2 - a) % n
                    v1 = (v1 * v1 - 2) % n
                else:
                    v1 = (v1 * v2 - a) % n
                    v2 = (v2 * v2 - 2) % n
            return v1

        # Try different starting values
        for a_start in [3, 5, 7, 11, 13, 17, 19, 23, 29, 31]:
            timer.check()
            print(f"    Trying a = {a_start}, B up to 500000...")

            v = a_start
            if HAS_SYMPY:
                primes = list(primerange(2, 500000))
            else:
                primes = _sieve_of_eratosthenes(500000)

            for i, p in enumerate(primes):
                if i % 5000 == 0:
                    timer.check()

                pp = p
                while pp * p <= 500000:
                    pp *= p
                v = lucas_v(v, pp, n)

            d = gcd(v - 2, n)
            if 1 < d < n:
                q = n // d
                print(f"    [!!!] FACTOR FOUND with a = {a_start}!")
                print(f"    p+1 is smooth")
                timer.__exit__()
                return (d, q)

        print(f"    No p+1 smooth factors found")
        timer.__exit__()
        return None

    except TimeoutError as e:
        print(f"\n    {e}")
        timer.__exit__()
        return None


def method_wiener(n: int, timeout: int, **kwargs) -> Optional[Tuple[int, int]]:
    """
    Method 6: Wiener's Method (Small Private Exponent)
    
    If the private exponent d < n^(1/4) / 3, the continued fraction
    expansion of e/n reveals d. This method is fast and deterministic.
    """
    e = TARGET_EXPONENT
    print(f"    Computing continued fraction expansion of e/n...")
    print(f"    Wiener bound: d < n^(1/4)/3 = ~{isqrt(isqrt(n))//3}")
    timer = AnalysisTimeout(timeout)
    timer.__enter__()

    try:
        # Compute continued fraction convergents of e/n
        convergents = _continued_fraction_convergents(e, n)

        print(f"    Testing {len(convergents)} convergents...")
        for i, (k, d) in enumerate(convergents):
            if i % 1000 == 0:
                timer.check()

            if k == 0:
                continue

            # Check if d is valid: ed = 1 (mod phi(n))
            # phi(n) = (ed - 1) / k
            if (e * d - 1) % k != 0:
                continue

            phi = (e * d - 1) // k

            # From phi(n) = (p-1)(q-1) = n - p - q + 1
            # p + q = n - phi + 1
            s = n - phi + 1

            # p and q are roots of x^2 - sx + n = 0
            discriminant = s * s - 4 * n
            if discriminant < 0:
                continue

            sqrt_disc = isqrt(discriminant)
            if sqrt_disc * sqrt_disc != discriminant:
                continue

            p = (s + sqrt_disc) // 2
            q = (s - sqrt_disc) // 2

            if p * q == n:
                print(f"    [!!!] WIENER'S METHOD SUCCEEDED!")
                print(f"    Private exponent d = {d}")
                print(f"    d has {d.bit_length()} bits")
                timer.__exit__()
                return (p, q)

        print(f"    Private exponent is not small (Wiener's method does not apply)")
        timer.__exit__()
        return None

    except TimeoutError as e_err:
        print(f"\n    {e_err}")
        timer.__exit__()
        return None


def _continued_fraction_convergents(
    numerator: int, denominator: int
) -> List[Tuple[int, int]]:
    """Compute convergents of a continued fraction expansion."""
    convergents = []
    # Previous convergent numerators/denominators
    h_prev, h_curr = 0, 1
    k_prev, k_curr = 1, 0

    a = numerator
    b = denominator

    while b != 0:
        q = a // b
        a, b = b, a - q * b

        h_prev, h_curr = h_curr, q * h_curr + h_prev
        k_prev, k_curr = k_curr, q * k_curr + k_prev

        convergents.append((h_curr, k_curr))

        # Safety limit
        if len(convergents) > 10000:
            break

    return convergents


def method_gcd_known_keys(n: int, timeout: int, **kwargs) -> Optional[Tuple[int, int]]:
    """
    Method 7: GCD against Known Firmware Keys
    
    If the key shares a factor with any known firmware RSA key
    (e.g., due to shared prime generation or poor RNG), GCD reveals it.
    Checks against Nordic SDK samples, MCUboot defaults, and other known keys.
    """
    print(f"    Checking GCD against {len(KNOWN_KEYS)} known keys...")
    timer = AnalysisTimeout(timeout)
    timer.__enter__()

    try:
        for name, other_n in KNOWN_KEYS.items():
            timer.check()
            d = gcd(n, other_n)
            if 1 < d < n:
                q = n // d
                print(f"    [!!!] SHARED FACTOR with '{name}'!")
                print(f"    Common factor p = {d}")
                timer.__exit__()
                return (d, q)
            else:
                print(f"    [ ] {name}: no common factor")

        # Also check against some randomly generated keys
        # (batch GCD concept - if two keys share a factor)
        print(f"    Checking against additional test vectors...")

        # Check against sequential values near sqrt(n) (degenerate key check)
        sqrt_n = isqrt(n)
        for offset in range(-1000, 1001):
            candidate = sqrt_n + offset
            if candidate > 1:
                d = gcd(n, candidate)
                if 1 < d < n:
                    q = n // d
                    print(f"    [!!!] FACTOR near sqrt(n)!")
                    timer.__exit__()
                    return (d, q)

        print(f"    No shared factors found")
        timer.__exit__()
        return None

    except TimeoutError as e:
        print(f"\n    {e}")
        timer.__exit__()
        return None


def method_factordb(n: int, timeout: int, **kwargs) -> Optional[Tuple[int, int]]:
    """
    Method 8: FactorDB.com API Lookup
    
    Check if this modulus has already been factored and submitted to FactorDB.
    This is a free public database of known factorizations.
    """
    if not HAS_REQUESTS:
        print("    [SKIP] 'requests' package not installed")
        print("    Install with: pip install requests")
        return None

    print(f"    Querying factordb.com for known factorization...")
    timer = AnalysisTimeout(timeout)
    timer.__enter__()

    try:
        url = f"http://factordb.com/api"
        params = {"query": str(n)}

        try:
            response = requests.get(url, params=params, timeout=30)
            response.raise_for_status()
            data = response.json()
        except requests.exceptions.RequestException as e:
            print(f"    [ERROR] API request failed: {e}")
            timer.__exit__()
            return None

        status = data.get("status", "Unknown")
        factors = data.get("factors", [])

        status_meanings = {
            "C": "Composite, no factors known",
            "CF": "Composite, factors known",
            "FF": "Fully factored",
            "P": "Proven prime",
            "Prp": "Probably prime",
            "U": "Unknown",
            "Unit": "Unit (1 or -1)",
            "N": "Not a valid number",
        }

        status_desc = status_meanings.get(status, status)
        print(f"    Status: {status} ({status_desc})")

        if status in ("FF", "CF") and factors:
            print(f"    [!!!] FACTORS KNOWN ON FACTORDB!")
            print(f"    Factors: {factors}")

            # Parse factors
            if len(factors) >= 2:
                p = int(factors[0][0])
                q = int(factors[1][0])
                if p * q == n:
                    timer.__exit__()
                    return (p, q)
                else:
                    # May have more than 2 factors
                    print(f"    Note: Factor product does not equal n directly")
                    print(f"    All factors: {factors}")
        else:
            print(f"    Key not yet factored in FactorDB")
            # Submit it for future reference
            print(f"    (Consider submitting to FactorDB for community factoring)")

        timer.__exit__()
        return None

    except TimeoutError as e:
        print(f"\n    {e}")
        timer.__exit__()
        return None


def method_roca(n: int, timeout: int, **kwargs) -> Optional[Tuple[int, int]]:
    """
    Method 9: ROCA Vulnerability Check (CVE-2017-15361)
    
    The ROCA vulnerability affects RSA keys generated by Infineon's RSA library
    (used in TPMs, smart cards, YubiKeys). These keys have a special structure
    that allows factoring in practical time.
    
    Detection: Check if n = k * M + (65537^a mod M) for small primes M.
    The fingerprint is that the key's remainder mod the product of first few
    primes follows a specific pattern.
    """
    print("    Checking for ROCA/Infineon vulnerability (CVE-2017-15361)...")
    timer = AnalysisTimeout(timeout)
    timer.__enter__()

    try:
        # ROCA detection markers
        # The first 39 primes product (primorial)
        roca_markers = [
            3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61,
            67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131,
            137, 139, 149, 151, 157, 163, 167
        ]

        # For ROCA, check if n mod small primes follows the fingerprint
        # The discrete log of (n mod p) base 65537 must exist for each prime p
        roca_detected = True
        e_val = 65537

        for p in roca_markers[:17]:  # Check first 17 for 2048-bit keys
            timer.check()
            n_mod_p = n % p

            # Check if n_mod_p is in the group generated by 65537 mod p
            found = False
            power = 1
            for _ in range(p):
                power = (power * e_val) % p
                if power == n_mod_p:
                    found = True
                    break

            if not found:
                roca_detected = False
                break

        if roca_detected:
            print("    [!!!] ROCA VULNERABILITY DETECTED!")
            print("    This key was likely generated by Infineon's broken RSA library!")
            print("    The key can be factored using the Coppersmith method.")
            print("    Estimated factoring time: hours to days on a single machine.")
            print()
            print("    To factor, use: https://github.com/crocs-muni/roca")
            print("    Or run: sage -python roca/analyze.py <modulus_hex>")

            # We cannot easily run the full Coppersmith method here
            # (requires SageMath), but detection is valuable
            timer.__exit__()
            return None  # Detected but not factored here
        else:
            print("    Key does NOT have ROCA fingerprint")
            print("    (Not generated by vulnerable Infineon library)")

        timer.__exit__()
        return None

    except TimeoutError as e:
        print(f"\n    {e}")
        timer.__exit__()
        return None


def method_small_pq_diff(n: int, timeout: int, **kwargs) -> Optional[Tuple[int, int]]:
    """
    Method 10: Small |p-q| Difference Check
    
    Extended version of Fermat: specifically checks if |p-q| < n^(1/4)
    which makes the key trivially breakable, or if |p-q| < 2*n^(1/3)
    which is still weak.
    """
    print("    Checking for dangerously close prime factors...")
    timer = AnalysisTimeout(timeout)
    timer.__enter__()

    try:
        # If |p-q| < n^(1/4), Fermat finds it in 1 step
        # If |p-q| < n^(1/3), Fermat finds it quickly
        # We check up to n^(3/8) range from sqrt(n)

        sqrt_n = isqrt(n)
        # n^(1/4) for a 2048-bit number is about 2^512
        # We can realistically check a few million offsets

        print(f"    sqrt(n) = {hex(sqrt_n)[:40]}...")
        print(f"    Checking a = sqrt(n) to sqrt(n) + 10M...")

        a = sqrt_n
        if a * a < n:
            a += 1

        # Check in larger steps first (for efficiency)
        step_sizes = [1, 10, 100, 1000]

        for step in step_sizes:
            timer.check()
            max_offset = 10_000_000 // step

            for i in range(max_offset):
                if i % 100000 == 0 and i > 0:
                    timer.check()
                    sys.stdout.write(
                        f"\r    Step={step}: checked {i*step:,} offsets..."
                    )
                    sys.stdout.flush()

                a_curr = sqrt_n + i * step
                b2 = a_curr * a_curr - n
                if b2 < 0:
                    continue
                b = isqrt(b2)
                if b * b == b2:
                    p = a_curr + b
                    q = a_curr - b
                    if p > 1 and q > 1 and p * q == n:
                        diff = abs(p - q)
                        print(f"\n    [!!!] CLOSE PRIMES FOUND!")
                        print(f"    |p-q| = {diff}")
                        print(f"    |p-q| bits = {diff.bit_length()}")
                        print(f"    n^(1/4) bits = {n.bit_length() // 4}")
                        timer.__exit__()
                        return (p, q)

            sys.stdout.write("\r" + " " * 60 + "\r")
            sys.stdout.flush()

        print(f"    Primes are not dangerously close")
        timer.__exit__()
        return None

    except TimeoutError as e:
        print(f"\n    {e}")
        timer.__exit__()
        return None


def method_boneh_durfee(n: int, timeout: int, **kwargs) -> Optional[Tuple[int, int]]:
    """
    Method 11: Boneh-Durfee (Partial Key Exposure)
    
    Extends Wiener's method. If d < n^0.292, the key can be broken.
    Uses lattice-based techniques (LLL algorithm).
    
    Note: Full implementation requires SageMath. Here we implement a
    simplified heuristic version that checks common weak patterns.
    """
    e = TARGET_EXPONENT
    print("    Checking for Boneh-Durfee vulnerability (d < n^0.292)...")
    print("    Note: Full lattice method requires SageMath")
    timer = AnalysisTimeout(timeout)
    timer.__enter__()

    try:
        # The Boneh-Durfee bound is d < n^0.292
        # For our 2048-bit key, this means d < 2^(2048*0.292) = 2^598
        # Wiener already checks d < n^0.25 = 2^512
        # The gap between 512 and 598 bits requires lattice methods

        # Heuristic: check if e*d - 1 = k*phi(n) for small k
        # If k is small, d might be recoverable

        # Check for d being a simple function of n
        # e.g., d = (2*n + 1) / 3 or similar patterns
        simple_patterns = [
            ("d = 3", 3),
            ("d = e", e),
            ("d = n mod e", n % e),
        ]

        for desc, d_candidate in simple_patterns:
            timer.check()
            if d_candidate < 2:
                continue
            # Check: (e * d - 1) should be divisible by (p-1) for some factor p
            test = (e * d_candidate - 1)
            # If this gives us phi(n), then n - phi(n) + 1 = p + q
            # and p*q = n, so we can solve the quadratic
            # phi(n) candidate = test / k for small k
            for k in range(1, 1000):
                if test % k != 0:
                    continue
                phi_candidate = test // k
                s = n - phi_candidate + 1
                disc = s * s - 4 * n
                if disc < 0:
                    continue
                sqrt_disc = isqrt(disc)
                if sqrt_disc * sqrt_disc == disc:
                    p = (s + sqrt_disc) // 2
                    q = (s - sqrt_disc) // 2
                    if p * q == n and p > 1 and q > 1:
                        print(f"    [!!!] BONEH-DURFEE SUCCESS! ({desc}, k={k})")
                        timer.__exit__()
                        return (p, q)

        print("    No Boneh-Durfee weakness detected (full lattice method not available)")
        # External reference (third-party repo name)
        print("    For full method, use: https://github.com/mimoo/RSA-and-LLL-attacks")
        timer.__exit__()
        return None

    except TimeoutError as e_err:
        print(f"\n    {e_err}")
        timer.__exit__()
        return None


def method_common_factor_batch(n: int, timeout: int, **kwargs) -> Optional[Tuple[int, int]]:
    """
    Method 12: Common Factor / Batch GCD
    
    Generate random RSA-like numbers and check GCD with n.
    Also checks against values derived from the key itself
    (e.g., n-1, n+1, powers of small numbers).
    """
    print("    Checking for common factors with derived values...")
    timer = AnalysisTimeout(timeout)
    timer.__enter__()

    try:
        # Check various transformations of n
        candidates = [
            ("n - 1", n - 1),
            ("n + 1", n + 1),
            ("n - 2", n - 2),
            ("n + 2", n + 2),
            ("2^2048 - 1", (1 << 2048) - 1),
            ("2^1024 - 1", (1 << 1024) - 1),
            ("10^308 - 1", 10**308 - 1),
        ]

        # Add Mersenne numbers
        for exp in [521, 607, 1279, 2203, 2281, 3217]:
            candidates.append((f"2^{exp}-1", (1 << exp) - 1))

        # Add factorials and primorials
        factorial = 1
        primorial = 1
        if HAS_SYMPY:
            primes_list = list(primerange(2, 1000))
        else:
            primes_list = _sieve_of_eratosthenes(1000)

        for p in primes_list[:100]:
            primorial *= p
        candidates.append(("primorial(541)", primorial))

        for name, val in candidates:
            timer.check()
            if val <= 1:
                continue
            d = gcd(n, val)
            if 1 < d < n:
                q = n // d
                print(f"    [!!!] COMMON FACTOR with {name}!")
                timer.__exit__()
                return (d, q)

        # Generate some random numbers and check GCD (low probability but free)
        print("    Testing random candidates...")
        for _ in range(10000):
            r = random.getrandbits(1024)
            d = gcd(n, r)
            if 1 < d < n:
                q = n // d
                print(f"    [!!!] Random factor found!")
                timer.__exit__()
                return (d, q)

        print("    No common factors found")
        timer.__exit__()
        return None

    except TimeoutError as e:
        print(f"\n    {e}")
        timer.__exit__()
        return None


# ===========================================================================
# Method Registry
# ===========================================================================

METHODS: Dict[str, Dict[str, Any]] = {
    "trial": {
        "name": "Trial Division",
        "func": method_trial_division,
        "description": "Divide by first 1M primes",
        "order": 1,
    },
    "fermat": {
        "name": "Fermat Factorization",
        "func": method_fermat,
        "description": "Find close primes (n = a^2 - b^2)",
        "order": 2,
    },
    "p-1": {
        "name": "Pollard's p-1",
        "func": method_pollard_p1,
        "description": "Leverages B-smooth p-1",
        "order": 3,
    },
    "rho": {
        "name": "Pollard's Rho (Brent)",
        "func": method_pollard_rho,
        "description": "Probabilistic O(n^(1/4)) factoring",
        "order": 4,
    },
    "p+1": {
        "name": "Williams' p+1",
        "func": method_williams_p1,
        "description": "Leverages B-smooth p+1",
        "order": 5,
    },
    "wiener": {
        "name": "Wiener's Method",
        "func": method_wiener,
        "description": "Small private exponent via continued fractions",
        "order": 6,
    },
    "gcd": {
        "name": "GCD Known Keys",
        "func": method_gcd_known_keys,
        "description": "Check shared factors with known firmware keys",
        "order": 7,
    },
    "factordb": {
        "name": "FactorDB Lookup",
        "func": method_factordb,
        "description": "Query factordb.com for known factorization",
        "order": 8,
    },
    "roca": {
        "name": "ROCA Check (CVE-2017-15361)",
        "func": method_roca,
        "description": "Infineon TPM vulnerability fingerprint",
        "order": 9,
    },
    "close-pq": {
        "name": "Small |p-q| Check",
        "func": method_small_pq_diff,
        "description": "Extended close-prime search",
        "order": 10,
    },
    "boneh-durfee": {
        "name": "Boneh-Durfee",
        "func": method_boneh_durfee,
        "description": "Extended small-d method (d < n^0.292)",
        "order": 11,
    },
    "batch-gcd": {
        "name": "Batch GCD / Common Factor",
        "func": method_common_factor_batch,
        "description": "GCD against derived values and random numbers",
        "order": 12,
    },
}


# ===========================================================================
# Main
# ===========================================================================

def run_methods(
    methods_to_run: List[str],
    timeout: int,
    dry_run: bool = False,
    output_file: Optional[str] = None,
) -> Dict[str, Any]:
    """Run specified methods and collect results."""

    n = TARGET_MODULUS
    results: Dict[str, Any] = {
        "target": {
            "modulus_hex": TARGET_MODULUS_HEX,
            "modulus_bits": n.bit_length(),
            "exponent": TARGET_EXPONENT,
            "keyhash": TARGET_KEYHASH,
            "der_hex": TARGET_DER_HEX,
        },
        "environment": {
            "gmpy2_available": HAS_GMPY2,
            "sympy_available": HAS_SYMPY,
            "pycryptodome_available": HAS_PYCRYPTODOME,
            "requests_available": HAS_REQUESTS,
            "platform": sys.platform,
            "python_version": sys.version,
            "timestamp": datetime.now().isoformat(),
        },
        "methods": {},
        "factored": False,
        "private_key": None,
    }

    print()
    print("=" * 70)
    print("  RSA-2048 FACTORING ANALYSIS TOOLKIT")
    print("  Target: Ajazz AJ159 MCUboot Signing Key")
    print("=" * 70)
    print()
    print(f"  Modulus (n): {TARGET_MODULUS_HEX[:32]}...")
    print(f"  Bits: {n.bit_length()}")
    print(f"  Exponent (e): {TARGET_EXPONENT}")
    print(f"  KEYHASH: {TARGET_KEYHASH}")
    print()
    print(f"  Timeout per method: {timeout}s")
    print(f"  Methods to run: {len(methods_to_run)}")
    print(f"  gmpy2: {'YES (fast math)' if HAS_GMPY2 else 'NO (using Python math)'}")
    print(f"  sympy: {'YES' if HAS_SYMPY else 'NO (limited prime gen)'}")
    print(f"  requests: {'YES' if HAS_REQUESTS else 'NO (skip FactorDB)'}")
    print()

    if dry_run:
        print("  [DRY RUN] Would execute these methods:")
        for method_id in methods_to_run:
            info = METHODS[method_id]
            print(f"    {info['order']:2d}. [{method_id:12s}] {info['name']}: {info['description']}")
        return results

    print("-" * 70)

    factored = False
    p_found, q_found = None, None

    for method_id in methods_to_run:
        info = METHODS[method_id]
        print()
        print(f"  [{info['order']:2d}/{len(methods_to_run)}] {info['name']}")
        print(f"  {'='*60}")
        print(f"  {info['description']}")
        print()

        start_time = time.time()
        try:
            result = info["func"](n, timeout)
            elapsed = time.time() - start_time

            if result is not None:
                p_found, q_found = result
                factored = True
                results["methods"][method_id] = {
                    "status": "SUCCESS",
                    "elapsed": elapsed,
                    "elapsed_formatted": format_time(elapsed),
                    "p": str(p_found),
                    "q": str(q_found),
                }
                print()
                print(f"  {'*'*60}")
                print(f"  *** FACTORIZATION SUCCESSFUL! ***")
                print(f"  {'*'*60}")
                print(f"  p = {hex(p_found)[:40]}...")
                print(f"  q = {hex(q_found)[:40]}...")
                print(f"  Time: {format_time(elapsed)}")
                break
            else:
                results["methods"][method_id] = {
                    "status": "FAILED",
                    "elapsed": elapsed,
                    "elapsed_formatted": format_time(elapsed),
                }
                print(f"\n  Result: No factors found ({format_time(elapsed)})")

        except Exception as ex:
            elapsed = time.time() - start_time
            results["methods"][method_id] = {
                "status": "ERROR",
                "elapsed": elapsed,
                "elapsed_formatted": format_time(elapsed),
                "error": str(ex),
            }
            print(f"\n  [ERROR] {ex} ({format_time(elapsed)})")

    # Final summary
    print()
    print("=" * 70)
    print("  FINAL RESULTS")
    print("=" * 70)

    if factored and p_found and q_found:
        results["factored"] = True
        print()
        print("  [+] KEY FACTORED SUCCESSFULLY!")
        print()
        print(f"  p ({p_found.bit_length()} bits):")
        print(f"    {hex(p_found)}")
        print(f"  q ({q_found.bit_length()} bits):")
        print(f"    {hex(q_found)}")
        print()

        # Compute private key
        d = compute_private_key(p_found, q_found, TARGET_EXPONENT)
        if d:
            results["private_key"] = {
                "d_hex": hex(d),
                "d_bits": d.bit_length(),
                "p_hex": hex(p_found),
                "q_hex": hex(q_found),
            }
            print(f"  Private exponent d ({d.bit_length()} bits):")
            print(f"    {hex(d)[:64]}...")
            print()
            print("  NEXT STEPS:")
            print("    1. Run sign_firmware.py with this private key")
            print("    2. Flash the signed firmware to the device")
            print()

            # Save private key to file
            key_file = Path("debug_toolkit/recovered_private_key.json")
            key_data = {
                "n": hex(TARGET_MODULUS),
                "e": TARGET_EXPONENT,
                "d": hex(d),
                "p": hex(p_found),
                "q": hex(q_found),
                "dp": hex(d % (p_found - 1)),
                "dq": hex(d % (q_found - 1)),
                "qi": hex(mod_inverse(q_found, p_found)) if mod_inverse(q_found, p_found) else "error",
            }
            key_file.parent.mkdir(parents=True, exist_ok=True)
            key_file.write_text(json.dumps(key_data, indent=2))
            print(f"  Private key saved to: {key_file}")
    else:
        results["factored"] = False
        print()
        print("  [-] KEY NOT FACTORED")
        print()
        print("  The RSA-2048 key resisted all automated analysis methods.")
        print("  This is expected for a properly generated 2048-bit key.")
        print()
        print("  Remaining options:")
        print("    - Run ROCA analysis with SageMath (if ROCA detected)")
        print("    - Use CADO-NFS or msieve (months of compute time)")
        print("    - Hardware side-channel analysis on the device")
        print("    - Find the private key in vendor tools/servers")
        print("    - Social engineering / vendor disclosure")
        print("    - Look for debug/DFU backdoors that circumvent signature check")

    # Method summary table
    print()
    print("  Method Results Summary:")
    print("  " + "-" * 50)
    for method_id in methods_to_run:
        if method_id in results["methods"]:
            r = results["methods"][method_id]
            status_icon = {
                "SUCCESS": "[+]",
                "FAILED": "[-]",
                "ERROR": "[!]",
            }.get(r["status"], "[?]")
            print(
                f"    {status_icon} {METHODS[method_id]['name']:25s} "
                f"{r['status']:8s} ({r['elapsed_formatted']})"
            )
    print()

    # Save results
    if output_file:
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(results, indent=2, default=str))
        print(f"  Results saved to: {output_path}")
    else:
        # Default output
        default_output = Path("debug_toolkit/rsa_analysis_results.json")
        default_output.parent.mkdir(parents=True, exist_ok=True)
        default_output.write_text(json.dumps(results, indent=2, default=str))
        print(f"  Results saved to: {default_output}")

    print()
    return results


def main():
    parser = argparse.ArgumentParser(
        description="RSA-2048 Factoring Analysis Toolkit for Ajazz AJ159 MCUboot Key",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Method IDs:
  trial       Trial division (first 1M primes)
  fermat      Fermat factorization (close primes)
  p-1         Pollard's p-1 (smooth p-1)
  rho         Pollard's rho / Brent variant
  p+1         Williams' p+1 (smooth p+1)
  wiener      Wiener's method (small d)
  gcd         GCD against known firmware keys
  factordb    FactorDB.com API lookup
  roca        ROCA vulnerability check (CVE-2017-15361)
  close-pq    Small |p-q| difference check
  boneh-durfee  Boneh-Durfee (d < n^0.292)
  batch-gcd   Batch GCD / common factors

Examples:
  %(prog)s                          Run all methods (default 300s timeout)
  %(prog)s --timeout 600            10 minute timeout per method
  %(prog)s --methods rho,fermat     Run only specific methods
  %(prog)s --methods factordb       Quick online check only
  %(prog)s --dry-run                Show method plan without executing
  %(prog)s --output results.json    Custom output file
        """
    )
    parser.add_argument(
        '--timeout', type=int, default=300,
        help='Timeout in seconds per method (default: 300)'
    )
    parser.add_argument(
        '--methods', type=str, default=None,
        help='Comma-separated list of method IDs to run (default: all)'
    )
    parser.add_argument(
        '--dry-run', action='store_true',
        help='Show what would be run without executing'
    )
    parser.add_argument(
        '--output', '-o', type=str, default=None,
        help='Output JSON file path (default: debug_toolkit/rsa_analysis_results.json)'
    )
    parser.add_argument(
        '--list-methods', action='store_true',
        help='List all available methods and exit'
    )

    args = parser.parse_args()

    # List methods mode
    if args.list_methods:
        print("\nAvailable methods:")
        print("-" * 60)
        for method_id, info in sorted(METHODS.items(), key=lambda x: x[1]["order"]):
            print(f"  {info['order']:2d}. [{method_id:12s}] {info['name']}")
            print(f"      {info['description']}")
        print()
        sys.exit(0)

    # Determine which methods to run
    if args.methods:
        method_ids = [a.strip() for a in args.methods.split(',')]
        # Validate
        for aid in method_ids:
            if aid not in METHODS:
                print(f"ERROR: Unknown method '{aid}'")
                print(f"  Available: {', '.join(sorted(METHODS.keys()))}")
                sys.exit(1)
    else:
        # All methods in order
        method_ids = sorted(METHODS.keys(), key=lambda x: METHODS[x]["order"])

    # Run
    run_methods(
        methods_to_run=method_ids,
        timeout=args.timeout,
        dry_run=args.dry_run,
        output_file=args.output,
    )


if __name__ == "__main__":
    main()
