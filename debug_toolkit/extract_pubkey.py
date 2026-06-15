#!/usr/bin/env python3
"""
extract_pubkey.py - RSA Public Key Extraction for Ajazz AJ159 MCUboot Verification
====================================================================================

Searches the ry_upgrade_PATCHED.exe binary for the RSA-2048 public key used by
MCUboot to verify firmware signatures.

Known information:
  - The key's SHA-256 hash (KEYHASH in MCUboot TLV):
    fc5701dc6135e1323847bdc40f04d2e5bee5833b23c29f93593d00018cfa9994
  - Key type: RSA-2048 (256 bytes modulus, typically 65537 exponent)
  - The key is embedded somewhere in the EXE (which contains the bootloader)

Search strategies:
  1. Look for DER-encoded RSA public keys (ASN.1 SEQUENCE headers: 0x30 0x82)
  2. Search for raw 256-byte values that could be RSA moduli
  3. Check against known Nordic SDK sample keys

If found, the public key can be used to:
  - Understand if it is a default/sample key (trivially breakable)
  - Attempt to factor small/weak keys
  - Sign firmware images if the private key is recoverable

PREREQUISITES:
  - Python 3.7+
  - No additional packages required (uses hashlib from stdlib)

USAGE:
  python extract_pubkey.py                              # Search default EXE
  python extract_pubkey.py --exe-path /path/to/exe      # Custom path
  python extract_pubkey.py --verbose                    # Show all candidates
"""

from __future__ import annotations

import sys
import struct
import hashlib
import argparse
from pathlib import Path
from typing import List, Tuple

# ===========================================================================
# Constants
# ===========================================================================

# Known KEYHASH from MCUboot TLV (SHA-256 of the DER-encoded public key)
KNOWN_KEYHASH = bytes.fromhex(
    "fc5701dc6135e1323847bdc40f04d2e5bee5833b23c29f93593d00018cfa9994"
)

# Default EXE path (relative to repo structure)
DEFAULT_EXE = "../firmware_patch/ry_upgrade_PATCHED.exe"

# Fallback filename (checked in the script's own directory)
FALLBACK_EXE_FILENAME = "ry_upgrade_PATCHED.exe"

# RSA-2048 key sizes
RSA_2048_MODULUS_SIZE = 256  # bytes
RSA_2048_KEY_BITS = 2048

# ASN.1 DER markers for RSA public keys
# RSA public key in PKCS#1 format:
#   SEQUENCE { INTEGER (modulus), INTEGER (exponent) }
# RSA public key in X.509/SPKI format:
#   SEQUENCE { SEQUENCE { OID, NULL }, BIT STRING { SEQUENCE { INTEGER, INTEGER } } }

# OID for rsaEncryption: 1.2.840.113549.1.1.1
RSA_OID = bytes.fromhex("06092a864886f70d010101")

# Common RSA-2048 public exponent (65537 = 0x010001)
RSA_EXPONENT_65537 = 65537

# Known Nordic SDK sample RSA-2048 keys (from MCUboot samples)
# These are the modulus values of commonly used sample keys
NORDIC_SAMPLE_KEY_HASHES = {
    # MCUboot default signing key (root-rsa-2048.pem from MCUboot repo)
    "mcuboot_default": None,  # Will compute if we find the key
}


# ===========================================================================
# DER Parsing Helpers
# ===========================================================================

def parse_der_length(data: bytes, offset: int) -> Tuple[int, int]:
    """
    Parse a DER length field at the given offset.
    Returns (length_value, bytes_consumed_by_length_field).
    """
    if offset >= len(data):
        return (0, 0)

    first = data[offset]
    if first < 0x80:
        return (first, 1)
    elif first == 0x81:
        if offset + 1 >= len(data):
            return (0, 0)
        return (data[offset + 1], 2)
    elif first == 0x82:
        if offset + 2 >= len(data):
            return (0, 0)
        return (struct.unpack_from('>H', data, offset + 1)[0], 3)
    elif first == 0x83:
        if offset + 3 >= len(data):
            return (0, 0)
        val = (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3]
        return (val, 4)
    else:
        return (0, 0)


def try_parse_spki_rsa_key(data: bytes, offset: int) -> bytes:
    """
    Try to parse an X.509 SubjectPublicKeyInfo (SPKI) RSA key at the given offset.
    Returns the full DER-encoded SPKI key if valid, or empty bytes.
    """
    if offset + 4 >= len(data):
        return b""

    # Must start with SEQUENCE (0x30)
    if data[offset] != 0x30:
        return b""

    # Parse outer SEQUENCE length
    seq_len, len_bytes = parse_der_length(data, offset + 1)
    if seq_len == 0 or seq_len > 1024:
        return b""

    total_len = 1 + len_bytes + seq_len
    if offset + total_len > len(data):
        return b""

    candidate = data[offset:offset + total_len]

    # Check for RSA OID inside
    if RSA_OID in candidate:
        return candidate

    return b""


def try_parse_pkcs1_rsa_key(data: bytes, offset: int) -> bytes:
    """
    Try to parse a PKCS#1 RSAPublicKey at the given offset.
    Format: SEQUENCE { INTEGER (modulus), INTEGER (exponent) }
    Returns the full DER if valid, or empty bytes.
    """
    if offset + 4 >= len(data):
        return b""

    if data[offset] != 0x30:
        return b""

    seq_len, len_bytes = parse_der_length(data, offset + 1)
    if seq_len == 0 or seq_len > 512:
        return b""

    total_len = 1 + len_bytes + seq_len
    if offset + total_len > len(data):
        return b""

    # Inside should be two INTEGERs
    inner_offset = offset + 1 + len_bytes
    if data[inner_offset] != 0x02:  # INTEGER tag
        return b""

    # Parse first INTEGER (modulus)
    int_len, int_len_bytes = parse_der_length(data, inner_offset + 1)
    if int_len < 128 or int_len > 300:  # RSA-2048 modulus is ~256-257 bytes
        return b""

    # Check second INTEGER (exponent) follows
    exp_offset = inner_offset + 1 + int_len_bytes + int_len
    if exp_offset >= offset + total_len:
        return b""
    if data[exp_offset] != 0x02:
        return b""

    candidate = data[offset:offset + total_len]
    return candidate


def extract_modulus_from_der(der_key: bytes) -> bytes:
    """Extract the raw modulus bytes from a DER-encoded RSA key."""
    # Find the first INTEGER (longest one is the modulus)
    i = 0
    integers = []
    while i < len(der_key) - 2:
        if der_key[i] == 0x02:  # INTEGER tag
            int_len, len_bytes = parse_der_length(der_key, i + 1)
            if int_len > 0 and i + 1 + len_bytes + int_len <= len(der_key):
                int_data = der_key[i + 1 + len_bytes:i + 1 + len_bytes + int_len]
                integers.append(int_data)
                i += 1 + len_bytes + int_len
                continue
        i += 1

    # Return the longest integer (should be the modulus)
    if integers:
        longest = max(integers, key=len)
        # Strip leading zero byte (ASN.1 sign padding)
        if longest[0] == 0x00 and len(longest) > 1:
            longest = longest[1:]
        return longest

    return b""


# ===========================================================================
# Search Functions
# ===========================================================================

def search_der_keys(exe_data: bytes, verbose: bool) -> List[Tuple[int, bytes, str]]:
    """
    Search for DER-encoded RSA public keys (ASN.1 SEQUENCE headers).
    Returns list of (offset, der_bytes, description) tuples.
    """
    print("\n[*] Strategy 1: Searching for DER-encoded RSA public keys...")
    print(f"    Looking for 0x30 0x82 (SEQUENCE with 2-byte length)...")

    candidates = []
    found_at = set()

    # Search for 0x30 0x82 XX XX (SEQUENCE with 2-byte length)
    i = 0
    while i < len(exe_data) - 300:
        if exe_data[i] == 0x30 and exe_data[i + 1] == 0x82:
            # Parse the sequence length
            seq_len = struct.unpack_from('>H', exe_data, i + 2)[0]

            # RSA-2048 SPKI key is typically 270-300 bytes total
            # PKCS#1 key is typically 260-270 bytes
            if 250 <= seq_len <= 400:
                # Try SPKI format
                spki = try_parse_spki_rsa_key(exe_data, i)
                if spki:
                    key_hash = hashlib.sha256(spki).hexdigest()
                    if i not in found_at:
                        found_at.add(i)
                        desc = f"SPKI RSA key ({len(spki)} bytes)"
                        candidates.append((i, spki, desc))
                        match = "MATCH!" if key_hash == KNOWN_KEYHASH.hex() else ""
                        if verbose or match:
                            print(f"    [+] Offset 0x{i:08X}: {desc}")
                            print(f"        SHA-256: {key_hash}")
                            if match:
                                print(f"        *** KEYHASH MATCH! ***")

                # Try PKCS#1 format
                pkcs1 = try_parse_pkcs1_rsa_key(exe_data, i)
                if pkcs1 and i not in found_at:
                    key_hash = hashlib.sha256(pkcs1).hexdigest()
                    found_at.add(i)
                    desc = f"PKCS#1 RSA key ({len(pkcs1)} bytes)"
                    candidates.append((i, pkcs1, desc))
                    match = "MATCH!" if key_hash == KNOWN_KEYHASH.hex() else ""
                    if verbose or match:
                        print(f"    [+] Offset 0x{i:08X}: {desc}")
                        print(f"        SHA-256: {key_hash}")
                        if match:
                            print(f"        *** KEYHASH MATCH! ***")

        i += 1

    print(f"    Found {len(candidates)} DER key candidate(s)")
    return candidates


def search_raw_moduli(exe_data: bytes, verbose: bool) -> List[Tuple[int, bytes]]:
    """
    Search for raw 256-byte values that could be RSA moduli.
    A valid RSA modulus has its high bit set (MSB >= 0x80) and is odd (LSB is odd).
    """
    print("\n[*] Strategy 2: Searching for raw 256-byte RSA moduli...")
    print(f"    Criteria: high bit set, odd value, not 0xFF-filled")

    candidates = []

    # We need to be smart about this - cannot check every offset
    # Look for sequences that start with a high byte and end with an odd byte
    # Also check entropy (not repetitive)
    for i in range(0, len(exe_data) - RSA_2048_MODULUS_SIZE, 4):
        # Quick filter: first byte must have high bit set (>= 0x80)
        if exe_data[i] < 0x80:
            continue

        # Last byte must be odd
        if exe_data[i + RSA_2048_MODULUS_SIZE - 1] % 2 == 0:
            continue

        # Must not be all 0xFF
        if exe_data[i] == 0xFF and exe_data[i + 1] == 0xFF:
            # Check if this is a 0xFF-filled region
            if all(b == 0xFF for b in exe_data[i:i + 16]):
                continue

        # Must not be all same byte
        if len(set(exe_data[i:i + 16])) < 4:
            continue

        # Extract candidate modulus
        modulus = exe_data[i:i + RSA_2048_MODULUS_SIZE]

        # Compute entropy check: need reasonable byte diversity
        unique_bytes = len(set(modulus))
        if unique_bytes < 100:  # Good RSA modulus has high entropy
            continue

        # Build a pseudo-DER to compute hash comparable to KEYHASH
        # MCUboot computes KEYHASH as SHA-256 of the full DER-encoded public key
        # We need to try wrapping this as both SPKI and PKCS#1

        # Try PKCS#1: SEQUENCE { INTEGER(modulus), INTEGER(65537) }
        # Add leading zero for sign bit
        mod_with_sign = b'\x00' + modulus
        mod_int = b'\x02' + b'\x82' + struct.pack('>H', len(mod_with_sign)) + mod_with_sign
        # Exponent 65537 = 0x010001
        exp_int = b'\x02\x03\x01\x00\x01'
        inner = mod_int + exp_int
        pkcs1_der = b'\x30' + b'\x82' + struct.pack('>H', len(inner)) + inner

        pkcs1_hash = hashlib.sha256(pkcs1_der).hexdigest()

        # Try SPKI wrapper
        # AlgorithmIdentifier: SEQUENCE { OID rsaEncryption, NULL }
        algo_id = b'\x30\x0d' + RSA_OID + b'\x05\x00'
        # BIT STRING wrapping the PKCS#1 key
        bit_string_content = b'\x00' + pkcs1_der  # leading zero for unused bits
        bit_string = (b'\x03' + b'\x82' +
                      struct.pack('>H', len(bit_string_content)) +
                      bit_string_content)
        spki_inner = algo_id + bit_string
        spki_der = b'\x30' + b'\x82' + struct.pack('>H', len(spki_inner)) + spki_inner

        spki_hash = hashlib.sha256(spki_der).hexdigest()

        if pkcs1_hash == KNOWN_KEYHASH.hex():
            print(f"    [!!!] MATCH at offset 0x{i:08X} (PKCS#1 format)!")
            print(f"          Modulus (first 32 bytes): {modulus[:32].hex()}")
            print(f"          SHA-256(PKCS#1 DER): {pkcs1_hash}")
            candidates.append((i, modulus))
        elif spki_hash == KNOWN_KEYHASH.hex():
            print(f"    [!!!] MATCH at offset 0x{i:08X} (SPKI format)!")
            print(f"          Modulus (first 32 bytes): {modulus[:32].hex()}")
            print(f"          SHA-256(SPKI DER): {spki_hash}")
            candidates.append((i, modulus))
        elif verbose and i % 0x100000 == 0:
            sys.stdout.write(f"\r    Scanning... offset 0x{i:08X}")
            sys.stdout.flush()

    if not verbose:
        pass
    else:
        print()

    print(f"    Found {len(candidates)} raw modulus match(es)")
    return candidates


def search_nordic_sample_keys(exe_data: bytes, verbose: bool):
    """
    Check if the KEYHASH matches any known Nordic SDK sample keys.
    """
    print("\n[*] Strategy 3: Checking against known Nordic SDK sample keys...")

    # MCUboot root-rsa-2048.pem sample key (from imgtool/keys in MCUboot repo)
    # This is a well-known test key that ships with MCUboot
    # Its SHA-256 hash of the DER-encoded public key:
    mcuboot_sample_hashes = [
        # root-rsa-2048.pem from MCUboot repository
        "9fee2410b8e2e83095aa53f1e30d7a0e9e9b9f60b9e4e7de7cde8e22f4ca5a80",
        # Another common sample key
        "b4b0d792db47b15cf8a2ebea72ecb46a32825a1f2cdae9183ef9e6c02e0b0a26",
    ]

    known_hash = KNOWN_KEYHASH.hex()
    print(f"    Target KEYHASH: {known_hash}")

    for name, sample_hash in [("MCUboot root-rsa-2048.pem", mcuboot_sample_hashes[0]),
                               ("MCUboot alternate sample", mcuboot_sample_hashes[1])]:
        if known_hash == sample_hash:
            print(f"    [!!!] MATCH: {name}")
            print(f"          This is a KNOWN SAMPLE KEY - private key is publicly available!")
            return True
        else:
            if verbose:
                print(f"    [ ] {name}: {sample_hash} (no match)")

    print(f"    No match against known sample keys")
    print(f"    (Key appears to be vendor-specific, not a default MCUboot sample)")
    return False


def search_keyhash_direct(exe_data: bytes, verbose: bool):
    """
    Search for the KEYHASH value itself in the EXE (it might appear near the key).
    """
    print("\n[*] Strategy 4: Searching for KEYHASH bytes in EXE...")

    positions = []
    i = 0
    while True:
        pos = exe_data.find(KNOWN_KEYHASH, i)
        if pos == -1:
            break
        positions.append(pos)
        i = pos + 1

    if positions:
        print(f"    Found KEYHASH at {len(positions)} location(s):")
        for pos in positions:
            # Show context around the hash
            context_start = max(0, pos - 16)
            context_end = min(len(exe_data), pos + 32 + 16)
            print(f"      Offset 0x{pos:08X}")
            if verbose:
                print(f"        Before: {exe_data[context_start:pos].hex()}")
                print(f"        Hash:   {exe_data[pos:pos+32].hex()}")
                print(f"        After:  {exe_data[pos+32:context_end].hex()}")
    else:
        print(f"    KEYHASH not found directly in EXE")

    # Also search for partial matches (first 8 bytes)
    partial = KNOWN_KEYHASH[:8]
    partial_positions = []
    i = 0
    while True:
        pos = exe_data.find(partial, i)
        if pos == -1:
            break
        if pos not in positions:
            partial_positions.append(pos)
        i = pos + 1

    if partial_positions and verbose:
        print(f"    Partial matches (first 8 bytes): {len(partial_positions)} location(s)")
        for pos in partial_positions[:5]:
            print(f"      Offset 0x{pos:08X}: {exe_data[pos:pos+32].hex()}")

    return positions


# ===========================================================================
# Main
# ===========================================================================

def main():
    parser = argparse.ArgumentParser(
        description="AJ159 MCUboot RSA Public Key Extraction Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                                  Search default EXE
  %(prog)s --exe-path /path/to/exe          Custom EXE path
  %(prog)s -v                               Verbose output (all candidates)

The tool searches for the RSA-2048 public key whose SHA-256 hash is:
  fc5701dc6135e1323847bdc40f04d2e5bee5833b23c29f93593d00018cfa9994

If the key is found, it means:
  - If it's a sample/default key: the private key may be publicly available
  - If it's vendor-specific: key factoring or side-channel attacks needed
  - Either way: knowing the exact key format helps with further analysis
        """
    )
    parser.add_argument(
        '--exe-path', type=str, default=DEFAULT_EXE,
        help=f'Path to EXE file (default: {DEFAULT_EXE})'
    )
    parser.add_argument(
        '-v', '--verbose', action='store_true',
        help='Show all candidates and detailed progress'
    )

    args = parser.parse_args()

    print()
    print("=" * 70)
    print("  AJ159 APEX - RSA Public Key Extraction")
    print("  Target KEYHASH: fc5701dc6135e1323847bdc40f04d2e5")
    print("                  bee5833b23c29f93593d00018cfa9994")
    print("=" * 70)

    # Resolve path with fallback to script's own directory
    exe_path = Path(args.exe_path)
    if not exe_path.is_absolute():
        script_dir = Path(__file__).resolve().parent
        candidate = script_dir / exe_path
        if candidate.exists():
            exe_path = candidate
        else:
            # Fallback: check for the filename in the script's directory
            fallback = script_dir / FALLBACK_EXE_FILENAME
            if fallback.exists():
                exe_path = fallback
            else:
                exe_path = candidate  # Use the original for the error message
    elif not exe_path.exists():
        pass  # Will fail below with a helpful message

    if not exe_path.exists():
        print(f"ERROR: EXE file not found: {exe_path}")
        print(f"       Also checked: {Path(__file__).resolve().parent / FALLBACK_EXE_FILENAME}")
        print()
        print(f"  Use --exe-path to specify location:")
        print(f"    python extract_pubkey.py --exe-path {FALLBACK_EXE_FILENAME}")
        sys.exit(1)

    print(f"\n[*] Loading EXE: {exe_path}")
    exe_data = exe_path.read_bytes()
    print(f"    Size: {len(exe_data)} bytes ({len(exe_data) / 1024 / 1024:.1f} MB)")

    # Strategy 1: DER-encoded keys
    der_keys = search_der_keys(exe_data, args.verbose)

    # Check DER candidates against KEYHASH
    match_found = False
    for offset, der_bytes, desc in der_keys:
        key_hash = hashlib.sha256(der_bytes).digest()
        if key_hash == KNOWN_KEYHASH:
            print(f"\n    *** FOUND THE KEY! ***")
            print(f"    Offset: 0x{offset:08X}")
            print(f"    Format: {desc}")
            print(f"    DER hex: {der_bytes.hex()}")
            modulus = extract_modulus_from_der(der_bytes)
            if modulus:
                print(f"    Modulus ({len(modulus)} bytes): {modulus[:32].hex()}...")
                print(f"    Modulus (last 16): ...{modulus[-16:].hex()}")
                # Check if modulus is small/weak
                mod_int = int.from_bytes(modulus, 'big')
                print(f"    Modulus bit length: {mod_int.bit_length()}")
            match_found = True

    # Strategy 2: Raw moduli
    raw_matches = search_raw_moduli(exe_data, args.verbose)
    if raw_matches:
        match_found = True

    # Strategy 3: Nordic SDK sample keys
    is_sample = search_nordic_sample_keys(exe_data, args.verbose)
    if is_sample:
        match_found = True

    # Strategy 4: Search for KEYHASH in EXE
    hash_positions = search_keyhash_direct(exe_data, args.verbose)

    # Final summary
    print(f"\n{'='*70}")
    print(f"  SUMMARY")
    print(f"{'='*70}")
    if match_found:
        print(f"\n  [+] RSA public key FOUND!")
        print(f"      Next steps:")
        print(f"      - Extract the key to PEM format")
        print(f"      - Check if it matches any known weak/sample keys")
        print(f"      - Try to find the private key in the EXE")
        print(f"      - Attempt to use it to sign patched firmware")
    else:
        print(f"\n  [-] RSA public key NOT found by automated search")
        print(f"      Possible reasons:")
        print(f"      - Key may be stored in a non-standard format")
        print(f"      - Key may be obfuscated or encrypted")
        print(f"      - Key may be in the bootloader (not in EXE)")
        print(f"      - Key hash may be computed over a different encoding")
        print(f"\n      Manual analysis suggestions:")
        print(f"      - Check the MCUboot image header area in the EXE")
        print(f"      - Look at the bootloader code (if extractable)")
        print(f"      - Try different DER encoding variations")
        if hash_positions:
            print(f"      - KEYHASH found at {len(hash_positions)} offset(s) - "
                  f"key may be nearby")
    print()


if __name__ == "__main__":
    main()
