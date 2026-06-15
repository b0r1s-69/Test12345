#!/usr/bin/env python3
"""
sign_firmware.py - MCUboot Firmware Image Signing Tool
=======================================================

Signs a patched firmware image for the Ajazz AJ159 using a recovered RSA-2048
private key. Produces a properly signed MCUboot image that can be flashed.

If the RSA key has been factored (using rsa_attack.py), this tool takes the
recovered private key and signs the patched firmware binary with the correct
MCUboot image format (TLV with RSA-2048 PKCS#1 v1.5 signature).

MCUboot Image Format:
  - Image header (32 bytes)
  - Firmware payload
  - Protected TLV area (optional)
  - TLV area containing:
    - KEYHASH (0x01): SHA-256 of the public key DER
    - SHA256 (0x10): SHA-256 of header + payload
    - RSA2048 (0x20): RSA-PKCS#1 v1.5 signature (256 bytes)

PREREQUISITES:
  pip install pycryptodome

USAGE:
  python sign_firmware.py --key recovered_private_key.json --firmware mouse_app_fw_PATCHED.bin
  python sign_firmware.py --key private.pem --firmware firmware.bin --output signed.bin
  python sign_firmware.py --help

CROSS-PLATFORM: Works on Windows, macOS, and Linux.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path
from typing import Optional, Tuple

# ===========================================================================
# Optional dependency handling
# ===========================================================================

try:
    from Crypto.PublicKey import RSA
    from Crypto.Signature import pkcs1_15
    from Crypto.Hash import SHA256
    from Crypto.Util.number import bytes_to_long, long_to_bytes, inverse
    HAS_PYCRYPTODOME = True
except ImportError:
    HAS_PYCRYPTODOME = False


# ===========================================================================
# Constants
# ===========================================================================

# MCUboot image header magic
IMAGE_MAGIC = 0x96F3B83D

# MCUboot TLV types
TLV_INFO_MAGIC = 0x6907
TLV_PROT_INFO_MAGIC = 0x6908

# TLV type IDs (MCUboot standard)
TLV_KEYHASH = 0x01      # Key hash (SHA-256 of public key DER)
TLV_SHA256 = 0x10       # Image hash (SHA-256 of header + payload)
TLV_RSA2048 = 0x20      # RSA-2048 signature (PKCS#1 v1.5)
TLV_RSA3072 = 0x23      # RSA-3072 signature
TLV_ECDSA256 = 0x22     # ECDSA-P256 signature
TLV_ED25519 = 0x24      # Ed25519 signature

# Target key parameters
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

TARGET_EXPONENT = 65537

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

# MCUboot image header size
MCUBOOT_HEADER_SIZE = 32


# ===========================================================================
# MCUboot Image Structures
# ===========================================================================

class MCUbootHeader:
    """MCUboot image header (32 bytes)."""

    FORMAT = '<IIHH IHHI'  # magic, load_addr, hdr_size, prot_tlv_size,
                           # img_size, flags, ver_major|minor, ver_rev, ver_build

    def __init__(self, data: bytes):
        if len(data) < 32:
            raise ValueError(f"Header too short: {len(data)} bytes (need 32)")

        (
            self.magic,
            self.load_addr,
            self.hdr_size,
            self.prot_tlv_size,
            self.img_size,
            self.flags,
            ver_word,
            self.ver_build,
        ) = struct.unpack_from(self.FORMAT, data)

        # Parse version
        self.ver_major = (ver_word >> 0) & 0xFF
        self.ver_minor = (ver_word >> 8) & 0xFF
        self.ver_revision = (ver_word >> 16) & 0xFFFF

    @property
    def is_valid(self) -> bool:
        return self.magic == IMAGE_MAGIC

    def __str__(self) -> str:
        return (
            f"MCUboot Header:\n"
            f"  Magic: 0x{self.magic:08X} "
            f"({'VALID' if self.is_valid else 'INVALID'})\n"
            f"  Load addr: 0x{self.load_addr:08X}\n"
            f"  Header size: {self.hdr_size}\n"
            f"  Protected TLV size: {self.prot_tlv_size}\n"
            f"  Image size: {self.img_size}\n"
            f"  Flags: 0x{self.flags:08X}\n"
            f"  Version: {self.ver_major}.{self.ver_minor}."
            f"{self.ver_revision}+{self.ver_build}"
        )


class TLVEntry:
    """A single TLV entry."""

    def __init__(self, tlv_type: int, data: bytes):
        self.type = tlv_type
        self.data = data

    @property
    def type_name(self) -> str:
        names = {
            TLV_KEYHASH: "KEYHASH",
            TLV_SHA256: "SHA256",
            TLV_RSA2048: "RSA2048_SIG",
            TLV_RSA3072: "RSA3072_SIG",
            TLV_ECDSA256: "ECDSA256_SIG",
            TLV_ED25519: "ED25519_SIG",
        }
        return names.get(self.type, f"UNKNOWN(0x{self.type:04X})")

    def to_bytes(self) -> bytes:
        """Serialize TLV entry to bytes (type:2, pad:2, len:2, pad:2, data)."""
        # MCUboot TLV format: type (2 bytes) + length (2 bytes) + data
        return struct.pack('<HH', self.type, len(self.data)) + self.data


def parse_tlvs(data: bytes) -> list:
    """Parse TLV area from binary data."""
    tlvs = []
    offset = 0

    # Check for TLV info header
    if len(data) < 4:
        return tlvs

    magic, total_len = struct.unpack_from('<HH', data, 0)
    if magic not in (TLV_INFO_MAGIC, TLV_PROT_INFO_MAGIC):
        return tlvs

    offset = 4
    end = min(total_len, len(data))

    while offset + 4 <= end:
        tlv_type, tlv_len = struct.unpack_from('<HH', data, offset)
        offset += 4

        if offset + tlv_len > end:
            break

        tlv_data = data[offset:offset + tlv_len]
        tlvs.append(TLVEntry(tlv_type, tlv_data))
        offset += tlv_len

    return tlvs


# ===========================================================================
# Key Loading
# ===========================================================================

def load_private_key_json(path: Path) -> Optional[RSA.RsaKey]:
    """Load private key from JSON format (output of rsa_attack.py)."""
    if not HAS_PYCRYPTODOME:
        print("ERROR: pycryptodome required. Install with: pip install pycryptodome")
        return None

    data = json.loads(path.read_text())

    n = int(data["n"], 16) if isinstance(data["n"], str) else data["n"]
    e = int(data["e"]) if isinstance(data["e"], (str, int)) else data["e"]
    d = int(data["d"], 16) if isinstance(data["d"], str) else data["d"]
    p = int(data["p"], 16) if isinstance(data["p"], str) else data["p"]
    q = int(data["q"], 16) if isinstance(data["q"], str) else data["q"]

    # Construct RSA key
    key = RSA.construct((n, e, d, p, q))
    return key


def load_private_key_pem(path: Path) -> Optional[RSA.RsaKey]:
    """Load private key from PEM file."""
    if not HAS_PYCRYPTODOME:
        print("ERROR: pycryptodome required. Install with: pip install pycryptodome")
        return None

    pem_data = path.read_bytes()
    key = RSA.import_key(pem_data)

    if not key.has_private():
        print("ERROR: PEM file does not contain a private key")
        return None

    return key


def load_private_key(path: Path) -> Optional[RSA.RsaKey]:
    """Load private key from either JSON or PEM format."""
    suffix = path.suffix.lower()

    if suffix == '.json':
        return load_private_key_json(path)
    elif suffix in ('.pem', '.key'):
        return load_private_key_pem(path)
    else:
        # Try JSON first, then PEM
        try:
            return load_private_key_json(path)
        except (json.JSONDecodeError, KeyError):
            return load_private_key_pem(path)


# ===========================================================================
# Signing
# ===========================================================================

def compute_image_hash(header: bytes, payload: bytes) -> bytes:
    """
    Compute the MCUboot image hash (SHA-256 of header + payload).
    This is the value that gets signed.
    """
    h = hashlib.sha256()
    h.update(header)
    h.update(payload)
    return h.digest()


def sign_hash_rsa2048(image_hash: bytes, private_key: RSA.RsaKey) -> bytes:
    """
    Sign the image hash using RSA-2048 PKCS#1 v1.5.
    Returns 256-byte signature.
    """
    h = SHA256.new(image_hash)

    # MCUboot uses raw PKCS#1 v1.5 signature over the SHA-256 hash
    # But the hash is already computed, so we sign the raw hash
    # Actually, MCUboot signs SHA256(header + payload) using PKCS1_v1_5
    # The signature is: RSASSA-PKCS1-v1_5-SIGN(SHA-256(header||payload))

    # pycryptodome's pkcs1_15 expects to hash the message itself,
    # but we already have the hash. We need to sign the pre-computed hash.
    # Use the SHA256 hash object initialized with the image content hash

    # Actually for MCUboot, the signature is over the TLV SHA256 hash value
    # Re-create the hash object from the digest
    signer = pkcs1_15.new(private_key)

    # Create a hash object that "contains" our pre-computed hash
    # MCUboot computes: sig = RSA_sign(SHA256(header || payload || protected_tlv))
    # We sign the hash directly
    hash_obj = SHA256.new(image_hash)
    signature = signer.sign(hash_obj)

    return signature


def sign_raw_pkcs1v15(message_hash: bytes, private_key: RSA.RsaKey) -> bytes:
    """
    Create PKCS#1 v1.5 signature manually for maximum compatibility.
    This matches exactly what MCUboot expects.
    """
    # PKCS#1 v1.5 signature padding for SHA-256:
    # 0x00 0x01 [0xFF padding] 0x00 [DigestInfo] [hash]
    # DigestInfo for SHA-256: 30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20
    digest_info = bytes.fromhex(
        "3031300d060960864801650304020105000420"
    )

    # Key size in bytes
    k = (private_key.size_in_bits() + 7) // 8  # 256 for RSA-2048

    # T = DigestInfo || Hash
    t = digest_info + message_hash

    # PS = 0xFF * (k - len(T) - 3)
    ps_len = k - len(t) - 3
    if ps_len < 8:
        raise ValueError("Key too short for this hash")
    ps = b'\xFF' * ps_len

    # EM = 0x00 || 0x01 || PS || 0x00 || T
    em = b'\x00\x01' + ps + b'\x00' + t

    # Convert to integer and sign: signature = em^d mod n
    em_int = int.from_bytes(em, byteorder='big')
    n = private_key.n
    d = private_key.d
    sig_int = pow(em_int, d, n)

    # Convert back to bytes
    signature = sig_int.to_bytes(k, byteorder='big')
    return signature


def build_signed_image(
    firmware_data: bytes,
    private_key: RSA.RsaKey,
    verbose: bool = False,
) -> Optional[bytes]:
    """
    Build a properly signed MCUboot image.
    
    If the firmware already has a header, re-signs it.
    If not, creates a minimal header and signs the image.
    """
    # Check if firmware already has MCUboot header
    has_header = False
    if len(firmware_data) >= 32:
        magic = struct.unpack_from('<I', firmware_data, 0)[0]
        if magic == IMAGE_MAGIC:
            has_header = True

    if has_header:
        print("  [*] Firmware has MCUboot header, re-signing...")
        header = MCUbootHeader(firmware_data[:32])
        if verbose:
            print(f"  {header}")

        # Extract header + payload (what gets hashed/signed)
        hdr_bytes = firmware_data[:header.hdr_size]
        payload = firmware_data[header.hdr_size:header.hdr_size + header.img_size]

        # Check for protected TLV
        prot_tlv_data = b""
        if header.prot_tlv_size > 0:
            prot_offset = header.hdr_size + header.img_size
            prot_tlv_data = firmware_data[prot_offset:prot_offset + header.prot_tlv_size]

        # Compute hash of header + payload + protected TLV
        hash_input = hdr_bytes + payload
        if prot_tlv_data:
            hash_input += prot_tlv_data
        image_hash = hashlib.sha256(hash_input).digest()

    else:
        print("  [*] Firmware has no MCUboot header, creating one...")
        # Create a minimal MCUboot header
        payload = firmware_data
        hdr_size = 32  # Minimum header
        img_size = len(payload)

        # Build header
        # Format: magic, load_addr, hdr_size, prot_tlv_size, img_size, flags, ver, build_num
        hdr_bytes = struct.pack(
            '<IIHH IHHI',
            IMAGE_MAGIC,       # magic
            0x00000000,        # load_addr (device-specific, 0 is common)
            hdr_size,          # hdr_size
            0,                 # prot_tlv_size
            img_size,          # img_size
            0,                 # flags
            0x00010000,        # version 1.0.0
            0,                 # build_num
        )
        # Pad header to hdr_size
        hdr_bytes = hdr_bytes.ljust(hdr_size, b'\x00')

        prot_tlv_data = b""
        image_hash = hashlib.sha256(hdr_bytes + payload).digest()

    print(f"  [*] Image hash (SHA-256): {image_hash.hex()}")

    # Sign the image hash
    print("  [*] Signing with RSA-2048 PKCS#1 v1.5...")
    try:
        signature = sign_raw_pkcs1v15(image_hash, private_key)
    except Exception as e:
        print(f"  [ERROR] Signing failed: {e}")
        return None

    print(f"  [*] Signature ({len(signature)} bytes): {signature[:16].hex()}...")

    # Verify signature
    print("  [*] Verifying signature...")
    n = private_key.n
    e_val = private_key.e
    sig_int = int.from_bytes(signature, byteorder='big')
    recovered = pow(sig_int, e_val, n)
    recovered_bytes = recovered.to_bytes(256, byteorder='big')
    if recovered_bytes[:2] == b'\x00\x01' and image_hash in recovered_bytes:
        print("  [+] Signature verification PASSED")
    else:
        print("  [!] WARNING: Signature verification may have issues")
        if verbose:
            print(f"      Recovered: {recovered_bytes[:20].hex()}...")

    # Build KEYHASH
    keyhash = bytes.fromhex(TARGET_KEYHASH)

    # Build TLV area
    # TLV info header: magic (2) + total_len (2)
    tlv_entries = b""

    # TLV_KEYHASH entry
    tlv_entries += struct.pack('<HH', TLV_KEYHASH, len(keyhash)) + keyhash

    # TLV_SHA256 entry
    tlv_entries += struct.pack('<HH', TLV_SHA256, len(image_hash)) + image_hash

    # TLV_RSA2048 entry
    tlv_entries += struct.pack('<HH', TLV_RSA2048, len(signature)) + signature

    # TLV info header
    tlv_total_len = 4 + len(tlv_entries)  # header + entries
    tlv_header = struct.pack('<HH', TLV_INFO_MAGIC, tlv_total_len)

    # Assemble final image
    signed_image = hdr_bytes + payload + prot_tlv_data + tlv_header + tlv_entries

    print(f"  [+] Signed image size: {len(signed_image)} bytes")
    print(f"      Header: {len(hdr_bytes)} bytes")
    print(f"      Payload: {len(payload)} bytes")
    if prot_tlv_data:
        print(f"      Protected TLV: {len(prot_tlv_data)} bytes")
    print(f"      TLV area: {tlv_total_len} bytes")

    return signed_image


# ===========================================================================
# Main
# ===========================================================================

def main():
    parser = argparse.ArgumentParser(
        description="MCUboot Firmware Image Signing Tool for Ajazz AJ159",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
This tool signs firmware images for the Ajazz AJ159 mouse using a recovered
RSA-2048 private key. The key must first be factored using rsa_attack.py.

Key formats supported:
  - JSON (output of rsa_attack.py): {"n": "0x...", "e": 65537, "d": "0x...", ...}
  - PEM (standard RSA private key file)

Examples:
  %(prog)s --key recovered_private_key.json --firmware mouse_app_fw_PATCHED.bin
  %(prog)s --key private.pem --firmware firmware.bin --output signed_fw.bin
  %(prog)s --key key.json --firmware fw.bin --verify-only

MCUboot Image Format:
  The signed image contains:
  1. Header (32+ bytes): magic, version, image size
  2. Payload: the firmware binary
  3. TLV area: KEYHASH + SHA256 hash + RSA-2048 signature
        """
    )
    parser.add_argument(
        '--key', '-k', type=str, required=False,
        help='Path to private key file (JSON or PEM format)'
    )
    parser.add_argument(
        '--firmware', '-f', type=str, required=False,
        help='Path to firmware binary to sign'
    )
    parser.add_argument(
        '--output', '-o', type=str, default=None,
        help='Output path for signed firmware (default: <firmware>_signed.bin)'
    )
    parser.add_argument(
        '--verify-only', action='store_true',
        help='Only verify an existing signature (do not sign)'
    )
    parser.add_argument(
        '--verbose', '-v', action='store_true',
        help='Verbose output'
    )
    parser.add_argument(
        '--info', action='store_true',
        help='Show MCUboot image info without signing'
    )

    args = parser.parse_args()

    print()
    print("=" * 70)
    print("  MCUboot Firmware Signing Tool")
    print("  Target: Ajazz AJ159 APEX")
    print("=" * 70)
    print()

    # Check dependencies
    if not HAS_PYCRYPTODOME:
        print("ERROR: pycryptodome is required.")
        print("  Install with: pip install pycryptodome")
        print()
        sys.exit(1)

    # Info mode: just show image details
    if args.info:
        if not args.firmware:
            print("ERROR: --firmware required with --info")
            sys.exit(1)

        fw_path = Path(args.firmware)
        if not fw_path.exists():
            print(f"ERROR: Firmware file not found: {fw_path}")
            sys.exit(1)

        fw_data = fw_path.read_bytes()
        print(f"  File: {fw_path}")
        print(f"  Size: {len(fw_data)} bytes")
        print()

        if len(fw_data) >= 32:
            magic = struct.unpack_from('<I', fw_data, 0)[0]
            if magic == IMAGE_MAGIC:
                header = MCUbootHeader(fw_data[:32])
                print(f"  {header}")
                print()

                # Parse TLVs
                tlv_offset = header.hdr_size + header.img_size
                if header.prot_tlv_size > 0:
                    tlv_offset += header.prot_tlv_size

                if tlv_offset < len(fw_data):
                    tlv_data = fw_data[tlv_offset:]
                    tlvs = parse_tlvs(tlv_data)
                    if tlvs:
                        print("  TLV Entries:")
                        for tlv in tlvs:
                            print(f"    {tlv.type_name} ({len(tlv.data)} bytes): "
                                  f"{tlv.data[:16].hex()}...")
                    else:
                        print("  No TLV entries found")
            else:
                print(f"  No MCUboot header (magic: 0x{magic:08X})")
        print()
        sys.exit(0)

    # Verify mode
    if args.verify_only:
        if not args.firmware:
            print("ERROR: --firmware required with --verify-only")
            sys.exit(1)
        print("  [*] Verify-only mode")
        print("  (Full verification requires the public key, checking structure only)")
        fw_path = Path(args.firmware)
        fw_data = fw_path.read_bytes()

        if len(fw_data) < 32:
            print("  ERROR: File too small for MCUboot image")
            sys.exit(1)

        magic = struct.unpack_from('<I', fw_data, 0)[0]
        if magic != IMAGE_MAGIC:
            print(f"  ERROR: Invalid MCUboot magic (0x{magic:08X})")
            sys.exit(1)

        header = MCUbootHeader(fw_data[:32])
        print(f"  {header}")

        # Find and check signature TLV
        tlv_offset = header.hdr_size + header.img_size + header.prot_tlv_size
        if tlv_offset < len(fw_data):
            tlv_data = fw_data[tlv_offset:]
            tlvs = parse_tlvs(tlv_data)
            sig_found = False
            for tlv in tlvs:
                if tlv.type == TLV_RSA2048:
                    sig_found = True
                    print(f"\n  RSA-2048 signature found ({len(tlv.data)} bytes)")
                    print(f"  First 16 bytes: {tlv.data[:16].hex()}")

                    # Verify using public key
                    n = int(TARGET_MODULUS_HEX, 16)
                    e_val = TARGET_EXPONENT
                    sig_int = int.from_bytes(tlv.data, 'big')
                    recovered = pow(sig_int, e_val, n)
                    recovered_bytes = recovered.to_bytes(256, 'big')

                    if recovered_bytes[:2] == b'\x00\x01':
                        print("  Signature structure: VALID (PKCS#1 v1.5 format)")
                    else:
                        print("  Signature structure: INVALID or different format")

            if not sig_found:
                print("\n  No RSA-2048 signature TLV found")
        print()
        sys.exit(0)

    # Sign mode - need both key and firmware
    if not args.key:
        print("ERROR: --key is required for signing")
        print("  Use recovered_private_key.json from rsa_attack.py")
        print("  Or provide a PEM private key file")
        print()
        parser.print_help()
        sys.exit(1)

    if not args.firmware:
        print("ERROR: --firmware is required for signing")
        print()
        parser.print_help()
        sys.exit(1)

    # Load private key
    key_path = Path(args.key)
    if not key_path.exists():
        print(f"ERROR: Key file not found: {key_path}")
        print()
        print("  Run rsa_attack.py first to factor the key.")
        print("  If successful, it saves: debug_toolkit/recovered_private_key.json")
        sys.exit(1)

    print(f"  [*] Loading private key from: {key_path}")
    private_key = load_private_key(key_path)
    if private_key is None:
        print("  ERROR: Failed to load private key")
        sys.exit(1)

    print(f"  [+] Key loaded: {private_key.size_in_bits()}-bit RSA")

    # Verify key matches target
    if private_key.n != int(TARGET_MODULUS_HEX, 16):
        print("  [!] WARNING: Key modulus does not match target!")
        print("      The signed firmware may not be accepted by the bootloader.")
        if not args.verbose:
            print("      Use --verbose to continue anyway")
            sys.exit(1)

    # Load firmware
    fw_path = Path(args.firmware)
    if not fw_path.exists():
        print(f"  ERROR: Firmware file not found: {fw_path}")
        sys.exit(1)

    print(f"  [*] Loading firmware: {fw_path}")
    fw_data = fw_path.read_bytes()
    print(f"  [+] Firmware size: {len(fw_data)} bytes")

    # Sign the firmware
    print()
    signed_image = build_signed_image(fw_data, private_key, verbose=args.verbose)
    if signed_image is None:
        print("\n  ERROR: Signing failed!")
        sys.exit(1)

    # Determine output path
    if args.output:
        output_path = Path(args.output)
    else:
        output_path = fw_path.with_name(fw_path.stem + "_signed" + fw_path.suffix)

    # Write signed image
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(signed_image)

    print()
    print(f"  [+] Signed firmware written to: {output_path}")
    print(f"      Size: {len(signed_image)} bytes")
    print()
    print("  NEXT STEPS:")
    print(f"    1. Flash {output_path.name} to the device")
    print("    2. Use the vendor's DFU tool or custom flasher")
    print("    3. The bootloader should accept the new signature")
    print()


if __name__ == "__main__":
    main()
