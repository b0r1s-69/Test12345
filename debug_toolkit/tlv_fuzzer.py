#!/usr/bin/env python3
"""
tlv_fuzzer.py - MCUboot TLV Malformation Experiments for Ajazz AJ159 APEX Mouse
=================================================================================

Builds malformed firmware images with different MCUboot TLV configurations to
test edge cases in the bootloader's signature verification. The goal is to find
a TLV configuration that bypasses RSA-2048 signature checking.

MCUboot image structure:
  [Header: 512 bytes] [Code: 108608 bytes] [TLV: variable]

TLV format:
  - 4-byte header: uint16 magic (0x6907), uint16 total_length (includes header)
  - Followed by entries: uint16 type + uint16 length + data

TLV types:
  0x0010 - SHA256 hash (32 bytes, covers header+code)
  0x0001 - KEYHASH (32 bytes, SHA-256 of the signing public key DER)
  0x0020 - RSA2048 signature (256 bytes)

The complete blob sent to the device:
  [App MCUboot image padded to 128KB with 0xFF] + [BLE image from EXE]
  Total: 131072 + 170420 = 301492 bytes

PREREQUISITES:
  - Python 3.7+
  - pip install hidapi (only needed for --flash mode)
  - Mouse in boot mode (PID 0x4025) for flashing

USAGE:
  python tlv_fuzzer.py --dry-run                   # Build all variants, show info
  python tlv_fuzzer.py --dry-run --variant 1       # Build specific variant only
  python tlv_fuzzer.py --flash --variant 1         # Flash variant 1 to device
  python tlv_fuzzer.py --flash --variant all       # Flash all variants (with prompts)
  python tlv_fuzzer.py --save-dir ./output         # Save built images to directory
"""

from __future__ import annotations

import sys
import time
import math
import struct
import hashlib
import argparse
from pathlib import Path
from typing import Optional, Tuple

# ===========================================================================
# Constants
# ===========================================================================

# Device identifiers (boot mode)
BOOT_VID = 0x3151
BOOT_PID = 0x4025
BOOT_USAGE_PAGE = 0xFF01
BOOT_INTERFACE = 0

REPORT_ID = 0x00
REPORT_SIZE = 64

CMD_TX_PREFIX = 0xBA
CMD_RX_PREFIX = 0xAB
CMD_GET_BOOT_ID = 0xFF
CMD_INIT_TRANSFER = 0xC0
CMD_COMPLETE = 0xC2

# MCUboot image constants
MCUBOOT_MAGIC = 0x96F3B83D
LOAD_ADDR = 0x00010000
HDR_SIZE = 512
IMG_SIZE = 108608  # patched app code size
FLAGS = 0x20
VERSION_MAJOR = 1
VERSION_MINOR = 0
VERSION_REVISION = 0
VERSION_BUILD = 76824442

# TLV constants
TLV_INFO_MAGIC = 0x6907
TLV_TYPE_SHA256 = 0x0010
TLV_TYPE_KEYHASH = 0x0001
TLV_TYPE_RSA2048 = 0x0020

# Known KEYHASH
KNOWN_KEYHASH = bytes.fromhex(
    "fc5701dc6135e1323847bdc40f04d2e5bee5833b23c29f93593d00018cfa9994"
)

# Blob layout
APP_PAD_SIZE = 131072  # 128KB
BLE_IMG_EXE_OFFSET = 0x011C291F
BLE_IMG_SIZE = 170420
EXPECTED_TOTAL = 301492

# Default paths (relative to repo structure)
DEFAULT_FW_PATH = "../firmware_patch/mouse_app_fw_PATCHED.bin"
DEFAULT_EXE_PATH = "../firmware_patch/ry_upgrade_PATCHED.exe"

# Fallback filenames (checked in the script's own directory)
FALLBACK_FW_FILENAME = "mouse_app_fw_PATCHED.bin"
FALLBACK_EXE_FILENAME = "ry_upgrade_PATCHED.exe"


# ===========================================================================
# Path Resolution Helpers
# ===========================================================================

def resolve_firmware_path(user_path: str) -> Path:
    """
    Resolve the firmware .bin path with fallback logic:
      1. If absolute and exists, use it directly
      2. Try relative to the script's directory
      3. Fallback: check script's directory for the known filename
      4. If nothing works, print helpful error and exit
    """
    script_dir = Path(__file__).resolve().parent
    p = Path(user_path)

    # Absolute path provided
    if p.is_absolute():
        if p.exists():
            return p
    else:
        # Try relative to script directory (handles repo-relative defaults)
        candidate = script_dir / p
        if candidate.exists():
            return candidate

    # Fallback: look for the filename in the script's own directory
    fallback = script_dir / FALLBACK_FW_FILENAME
    if fallback.exists():
        return fallback

    # Nothing found - print helpful error
    print(f"ERROR: Firmware file not found at: {p}")
    print(f"       Also checked: {fallback}")
    print()
    print(f"  Use --fw-path to specify location:")
    print(f"    python tlv_fuzzer.py --fw-path {FALLBACK_FW_FILENAME} "
          f"--exe-path {FALLBACK_EXE_FILENAME} --flash --variant all")
    sys.exit(1)


def resolve_exe_path(user_path: str) -> Path:
    """
    Resolve the EXE path with fallback logic:
      1. If absolute and exists, use it directly
      2. Try relative to the script's directory
      3. Fallback: check script's directory for the known filename
      4. If nothing works, print helpful error and exit
    """
    script_dir = Path(__file__).resolve().parent
    p = Path(user_path)

    # Absolute path provided
    if p.is_absolute():
        if p.exists():
            return p
    else:
        # Try relative to script directory (handles repo-relative defaults)
        candidate = script_dir / p
        if candidate.exists():
            return candidate

    # Fallback: look for the filename in the script's own directory
    fallback = script_dir / FALLBACK_EXE_FILENAME
    if fallback.exists():
        return fallback

    # Nothing found - print helpful error
    print(f"ERROR: EXE file not found at: {p}")
    print(f"       Also checked: {fallback}")
    print()
    print(f"  Use --exe-path to specify location:")
    print(f"    python tlv_fuzzer.py --fw-path {FALLBACK_FW_FILENAME} "
          f"--exe-path {FALLBACK_EXE_FILENAME} --flash --variant all")
    sys.exit(1)


# ===========================================================================
# MCUboot Image Builder
# ===========================================================================

def build_mcuboot_header() -> bytes:
    """Build the 512-byte MCUboot image header."""
    header = bytearray(HDR_SIZE)

    # Magic (offset 0, uint32 LE)
    struct.pack_into('<I', header, 0, MCUBOOT_MAGIC)
    # Load address (offset 4, uint32 LE)
    struct.pack_into('<I', header, 4, LOAD_ADDR)
    # Header size (offset 8, uint16 LE)
    struct.pack_into('<H', header, 8, HDR_SIZE)
    # Protected TLV size (offset 10, uint16 LE)
    struct.pack_into('<H', header, 10, 0)
    # Image size (offset 12, uint32 LE)
    struct.pack_into('<I', header, 12, IMG_SIZE)
    # Flags (offset 16, uint32 LE)
    struct.pack_into('<I', header, 16, FLAGS)
    # Version: major (byte@20), minor (byte@21), revision (uint16@22), build (uint32@24)
    header[20] = VERSION_MAJOR
    header[21] = VERSION_MINOR
    struct.pack_into('<H', header, 22, VERSION_REVISION)
    struct.pack_into('<I', header, 24, VERSION_BUILD)

    return bytes(header)


def build_tlv_entry(tlv_type: int, data: bytes) -> bytes:
    """Build a single TLV entry: uint16 type + uint16 length + data."""
    entry = struct.pack('<HH', tlv_type, len(data)) + data
    return entry


def build_tlv_section(entries: list) -> bytes:
    """
    Build a complete TLV section with header and entries.
    Header: uint16 magic (0x6907) + uint16 total_length (includes 4-byte header).
    """
    body = b""
    for tlv_type, data in entries:
        body += build_tlv_entry(tlv_type, data)

    total_length = 4 + len(body)  # 4-byte header + entries
    header = struct.pack('<HH', TLV_INFO_MAGIC, total_length)
    return header + body


def compute_image_sha256(header: bytes, code: bytes) -> bytes:
    """Compute SHA-256 over header + code (what MCUboot validates)."""
    h = hashlib.sha256()
    h.update(header)
    h.update(code)
    return h.digest()


# ===========================================================================
# TLV Variants
# ===========================================================================

class TLVVariant:
    """Represents a TLV malformation variant."""

    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description

    def build_tlv(self, sha256_hash: bytes) -> bytes:
        """Build the TLV bytes for this variant. Override in subclasses."""
        raise NotImplementedError


class EmptyTLV(TLVVariant):
    """Variant 1: Just the 4-byte TLV header with total_length=4, no entries."""

    def __init__(self):
        super().__init__(
            "EMPTY_TLV",
            "4-byte TLV header only (magic=0x6907, total_len=4, no entries)"
        )

    def build_tlv(self, sha256_hash: bytes) -> bytes:
        return struct.pack('<HH', TLV_INFO_MAGIC, 4)


class SHA256Only(TLVVariant):
    """Variant 2: TLV with only SHA256 entry, no KEYHASH or RSA."""

    def __init__(self):
        super().__init__(
            "SHA256_ONLY",
            "TLV with SHA256 entry only (no KEYHASH, no RSA signature)"
        )

    def build_tlv(self, sha256_hash: bytes) -> bytes:
        entries = [(TLV_TYPE_SHA256, sha256_hash)]
        return build_tlv_section(entries)


class ZeroLengthTLV(TLVVariant):
    """Variant 3: TLV header with total_length=0."""

    def __init__(self):
        super().__init__(
            "ZERO_LENGTH_TLV",
            "TLV header with total_length=0 (may cause underflow/wrap)"
        )

    def build_tlv(self, sha256_hash: bytes) -> bytes:
        return struct.pack('<HH', TLV_INFO_MAGIC, 0)


class NoTLVMagic(TLVVariant):
    """Variant 4: Replace TLV magic 0x6907 with 0x0000."""

    def __init__(self):
        super().__init__(
            "NO_TLV_MAGIC",
            "TLV header with magic=0x0000 (may skip TLV processing entirely)"
        )

    def build_tlv(self, sha256_hash: bytes) -> bytes:
        # Include valid entries in case bootloader still parses
        entries_body = build_tlv_entry(TLV_TYPE_SHA256, sha256_hash)
        total_length = 4 + len(entries_body)
        header = struct.pack('<HH', 0x0000, total_length)
        return header + entries_body


class WrongTLVMagic(TLVVariant):
    """Variant 5: Replace TLV magic 0x6907 with 0xFFFF."""

    def __init__(self):
        super().__init__(
            "WRONG_TLV_MAGIC",
            "TLV header with magic=0xFFFF (may skip TLV processing)"
        )

    def build_tlv(self, sha256_hash: bytes) -> bytes:
        entries_body = build_tlv_entry(TLV_TYPE_SHA256, sha256_hash)
        total_length = 4 + len(entries_body)
        header = struct.pack('<HH', 0xFFFF, total_length)
        return header + entries_body


class SHA256KeyhashNoRSA(TLVVariant):
    """Variant 6: SHA256 + KEYHASH but no RSA signature."""

    def __init__(self):
        super().__init__(
            "SHA256_KEYHASH_NO_RSA",
            "SHA256 + correct KEYHASH, but no RSA entry (tests if RSA is optional)"
        )

    def build_tlv(self, sha256_hash: bytes) -> bytes:
        entries = [
            (TLV_TYPE_SHA256, sha256_hash),
            (TLV_TYPE_KEYHASH, KNOWN_KEYHASH),
        ]
        return build_tlv_section(entries)


class DuplicateSHA256(TLVVariant):
    """Variant 7: Two SHA256 entries (second one all zeros)."""

    def __init__(self):
        super().__init__(
            "DUPLICATE_SHA256",
            "Two SHA256 entries: correct one + all-zeros one (parser confusion)"
        )

    def build_tlv(self, sha256_hash: bytes) -> bytes:
        entries = [
            (TLV_TYPE_SHA256, sha256_hash),
            (TLV_TYPE_SHA256, bytes(32)),  # All zeros
        ]
        return build_tlv_section(entries)


class NullRSA(TLVVariant):
    """Variant 8: SHA256 + KEYHASH + RSA with all zeros."""

    def __init__(self):
        super().__init__(
            "NULL_RSA",
            "SHA256 + KEYHASH + RSA entry with 256 zero bytes (null signature)"
        )

    def build_tlv(self, sha256_hash: bytes) -> bytes:
        entries = [
            (TLV_TYPE_SHA256, sha256_hash),
            (TLV_TYPE_KEYHASH, KNOWN_KEYHASH),
            (TLV_TYPE_RSA2048, bytes(256)),  # All zeros
        ]
        return build_tlv_section(entries)


class OriginalTLVPatchedSHA(TLVVariant):
    """Variant 9: Original KEYHASH + RSA but updated SHA256 for patched code."""

    def __init__(self, original_rsa: bytes = None):
        super().__init__(
            "ORIGINAL_TLV_WITH_PATCHED_SHA",
            "Original KEYHASH + original RSA signature, but SHA256 updated for patched code"
        )
        self.original_rsa = original_rsa or bytes(256)

    def build_tlv(self, sha256_hash: bytes) -> bytes:
        entries = [
            (TLV_TYPE_SHA256, sha256_hash),
            (TLV_TYPE_KEYHASH, KNOWN_KEYHASH),
            (TLV_TYPE_RSA2048, self.original_rsa),
        ]
        return build_tlv_section(entries)


# ===========================================================================
# Firmware Building
# ===========================================================================

def read_patched_code(fw_path: Path) -> bytes:
    """Read the patched app firmware code (108608 bytes)."""
    if not fw_path.exists():
        sys.exit(f"ERROR: Firmware file not found: {fw_path}")

    data = fw_path.read_bytes()
    if len(data) == IMG_SIZE:
        # Raw code only
        return data
    elif len(data) > IMG_SIZE:
        # Might be full MCUboot image (header + code + TLV)
        magic = struct.unpack_from('<I', data, 0)[0]
        if magic == MCUBOOT_MAGIC:
            hdr_size = struct.unpack_from('<H', data, 8)[0]
            img_size = struct.unpack_from('<I', data, 12)[0]
            if img_size == IMG_SIZE:
                print(f"    Extracted code from MCUboot image (skipped {hdr_size}-byte header)")
                return data[hdr_size:hdr_size + img_size]
        # Just use first IMG_SIZE bytes
        print(f"    WARNING: File is {len(data)} bytes, using first {IMG_SIZE}")
        return data[:IMG_SIZE]
    else:
        sys.exit(f"ERROR: Firmware file too small ({len(data)} bytes, need {IMG_SIZE})")


def read_ble_image(exe_path: Path) -> bytes:
    """Read the BLE controller image from the EXE at known offset."""
    if not exe_path.exists():
        sys.exit(f"ERROR: EXE file not found: {exe_path}")

    exe_data = exe_path.read_bytes()
    if len(exe_data) < BLE_IMG_EXE_OFFSET + BLE_IMG_SIZE:
        sys.exit(f"ERROR: EXE file too small for BLE image at offset 0x{BLE_IMG_EXE_OFFSET:X}")

    magic = struct.unpack_from('<I', exe_data, BLE_IMG_EXE_OFFSET)[0]
    if magic != MCUBOOT_MAGIC:
        sys.exit(
            f"ERROR: MCUboot magic not found at EXE offset 0x{BLE_IMG_EXE_OFFSET:X}\n"
            f"Found: 0x{magic:08X}, expected: 0x{MCUBOOT_MAGIC:08X}"
        )

    return exe_data[BLE_IMG_EXE_OFFSET:BLE_IMG_EXE_OFFSET + BLE_IMG_SIZE]


def extract_original_rsa(exe_path: Path) -> bytes:
    """
    Extract the original RSA signature from the app image in the EXE.
    The app image starts at 0x011A291F in the EXE.
    """
    APP_IMG_EXE_OFFSET = 0x011A291F

    exe_data = exe_path.read_bytes()
    if len(exe_data) < APP_IMG_EXE_OFFSET + HDR_SIZE + IMG_SIZE + 336:
        print("    WARNING: Cannot extract original RSA (EXE too small)")
        return bytes(256)

    magic = struct.unpack_from('<I', exe_data, APP_IMG_EXE_OFFSET)[0]
    if magic != MCUBOOT_MAGIC:
        print(f"    WARNING: MCUboot magic not found at app offset 0x{APP_IMG_EXE_OFFSET:X}")
        return bytes(256)

    # TLV starts after header + code
    tlv_offset = APP_IMG_EXE_OFFSET + HDR_SIZE + IMG_SIZE

    # Parse TLV header
    tlv_magic = struct.unpack_from('<H', exe_data, tlv_offset)[0]
    tlv_total = struct.unpack_from('<H', exe_data, tlv_offset + 2)[0]

    if tlv_magic != TLV_INFO_MAGIC:
        print(f"    WARNING: TLV magic mismatch: 0x{tlv_magic:04X}")
        return bytes(256)

    # Scan TLV entries for RSA2048
    pos = tlv_offset + 4
    end = tlv_offset + tlv_total
    while pos + 4 <= end:
        entry_type = struct.unpack_from('<H', exe_data, pos)[0]
        entry_len = struct.unpack_from('<H', exe_data, pos + 2)[0]
        if entry_type == TLV_TYPE_RSA2048 and entry_len == 256:
            rsa_data = exe_data[pos + 4:pos + 4 + 256]
            print(f"    Extracted original RSA signature from EXE offset 0x{pos+4:X}")
            return rsa_data
        pos += 4 + entry_len

    print("    WARNING: RSA2048 entry not found in original TLV")
    return bytes(256)


def build_complete_blob(code: bytes, tlv_bytes: bytes, ble_image: bytes) -> bytes:
    """
    Build the complete firmware blob:
      [Header(512) + Code(108608) + TLV(variable)] padded to 128KB + BLE image
    """
    header = build_mcuboot_header()
    app_image = header + code + tlv_bytes

    # Pad to 128KB with 0xFF
    if len(app_image) > APP_PAD_SIZE:
        sys.exit(f"ERROR: App image ({len(app_image)} bytes) exceeds 128KB")

    app_padded = app_image + bytes([0xFF] * (APP_PAD_SIZE - len(app_image)))

    # Concatenate with BLE image
    blob = app_padded + ble_image
    return blob


# ===========================================================================
# Flash Protocol (mirrors aj159_flasher.py)
# ===========================================================================

def require_hid():
    """Import and return the hid module."""
    try:
        import hid
        return hid
    except ImportError:
        sys.exit(
            "ERROR: The 'hidapi' package is required for --flash mode.\n"
            "Install with: pip install hidapi"
        )


def open_boot_device(hid_module):
    """Open boot-mode device."""
    devices = hid_module.enumerate(BOOT_VID, BOOT_PID)
    dev_info = None
    for d in devices:
        if (d.get('usage_page') == BOOT_USAGE_PAGE and
                d.get('interface_number') == BOOT_INTERFACE):
            dev_info = d
            break
    if not dev_info and devices:
        for d in devices:
            up = d.get('usage_page', 0)
            if up >= 0xFF00:
                dev_info = d
                break
    if not dev_info:
        sys.exit(
            f"ERROR: Boot device not found (VID={BOOT_VID:#06x} PID={BOOT_PID:#06x})\n"
            "Is the mouse in boot mode?"
        )

    h = hid_module.device()
    h.open_path(dev_info['path'])
    print(f"    Opened boot device: VID={dev_info['vendor_id']:#06x} "
          f"PID={dev_info['product_id']:#06x}")
    return h


def send_cmd(device, payload: bytes) -> None:
    """Send a 64-byte command."""
    assert len(payload) == REPORT_SIZE
    device.send_feature_report(bytes([REPORT_ID]) + payload)


def read_resp(device) -> bytes:
    """Read a 64-byte response."""
    resp = device.get_feature_report(REPORT_ID, REPORT_SIZE + 1)
    return bytes(resp[1:]) if resp else b""


def flash_blob(device, blob: bytes) -> Tuple[bool, str]:
    """
    Flash a firmware blob using the boot protocol.
    Returns (success, message).
    """
    chunk_count = math.ceil(len(blob) / REPORT_SIZE)
    checksum = sum(blob) & 0xFFFFFFFF

    # Step 1: BA FF (get boot ID)
    payload = bytearray(REPORT_SIZE)
    payload[0] = CMD_TX_PREFIX
    payload[1] = CMD_GET_BOOT_ID
    payload[7] = 0x46
    send_cmd(device, bytes(payload))
    time.sleep(0.05)
    resp = read_resp(device)
    if resp[0] != CMD_RX_PREFIX or resp[1] != CMD_GET_BOOT_ID:
        return False, f"BA FF failed: got {resp[:4].hex()}"
    print(f"      BA FF OK: device_id=0x{struct.unpack_from('<H', resp, 2)[0]:04X}")

    # Step 2: BA C0 (init transfer)
    data = struct.pack('<HI', chunk_count, len(blob))
    payload = bytearray(REPORT_SIZE)
    payload[0] = CMD_TX_PREFIX
    payload[1] = CMD_INIT_TRANSFER
    payload[2:2 + len(data)] = data
    send_cmd(device, bytes(payload))
    time.sleep(0.05)
    resp = read_resp(device)
    if resp[0] != CMD_RX_PREFIX or resp[1] != CMD_INIT_TRANSFER:
        return False, f"BA C0 failed: got {resp[:4].hex()}"
    print(f"      BA C0 OK: {chunk_count} chunks, {len(blob)} bytes")

    # Step 3: Stream data
    for i in range(chunk_count):
        offset = i * REPORT_SIZE
        chunk = blob[offset:offset + REPORT_SIZE]
        if len(chunk) < REPORT_SIZE:
            chunk = chunk + bytes(REPORT_SIZE - len(chunk))
        device.send_feature_report(bytes([REPORT_ID]) + chunk)

        if (i + 1) % 500 == 0 or i == chunk_count - 1:
            pct = (i + 1) * 100 // chunk_count
            sys.stdout.write(f"\r      Streaming: {pct}% ({i+1}/{chunk_count})")
            sys.stdout.flush()

    print()

    # Step 4: BA C2 (complete)
    data = struct.pack('<HII', chunk_count, checksum, len(blob))
    payload = bytearray(REPORT_SIZE)
    payload[0] = CMD_TX_PREFIX
    payload[1] = CMD_COMPLETE
    payload[2:2 + len(data)] = data
    send_cmd(device, bytes(payload))
    time.sleep(0.1)
    resp = read_resp(device)

    if resp[0] != CMD_RX_PREFIX or resp[1] != CMD_COMPLETE:
        return False, f"BA C2 rejected: got {resp[:8].hex()} (signature verification likely failed)"

    # Check the 48-byte crypto response data
    crypto_data = resp[2:50]
    print(f"      BA C2 OK: crypto_data={crypto_data[:16].hex()}...")

    return True, "Transfer accepted by bootloader!"


# ===========================================================================
# Main Logic
# ===========================================================================

ALL_VARIANTS = [
    EmptyTLV,
    SHA256Only,
    ZeroLengthTLV,
    NoTLVMagic,
    WrongTLVMagic,
    SHA256KeyhashNoRSA,
    DuplicateSHA256,
    NullRSA,
    OriginalTLVPatchedSHA,
]


def main():
    parser = argparse.ArgumentParser(
        description="AJ159 MCUboot TLV Malformation Fuzzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Variants:
  1. EMPTY_TLV              - 4-byte header only, no entries
  2. SHA256_ONLY            - SHA256 hash, no key or signature
  3. ZERO_LENGTH_TLV        - Header with total_length=0 (underflow test)
  4. NO_TLV_MAGIC           - Magic replaced with 0x0000
  5. WRONG_TLV_MAGIC        - Magic replaced with 0xFFFF
  6. SHA256_KEYHASH_NO_RSA  - Hash + key, no signature
  7. DUPLICATE_SHA256       - Two SHA256 entries (confusion test)
  8. NULL_RSA               - Hash + key + all-zero RSA signature
  9. ORIGINAL_TLV_PATCHED_SHA - Original RSA sig with new SHA256

Examples:
  %(prog)s --dry-run                   Build all variants, show info
  %(prog)s --dry-run --variant 2       Build variant 2 only
  %(prog)s --flash --variant 1         Flash variant 1 to device
  %(prog)s --save-dir ./output         Save all variant images to disk
        """
    )
    parser.add_argument(
        '--dry-run', action='store_true',
        help='Build images and show info, do not flash (default behavior)'
    )
    parser.add_argument(
        '--flash', action='store_true',
        help='Actually flash the variant to the device'
    )
    parser.add_argument(
        '--variant', type=str, default='all',
        help='Variant number (1-9) or "all" (default: all)'
    )
    parser.add_argument(
        '--fw-path', type=str, default=DEFAULT_FW_PATH,
        help=f'Path to patched firmware .bin (default: {DEFAULT_FW_PATH})'
    )
    parser.add_argument(
        '--exe-path', type=str, default=DEFAULT_EXE_PATH,
        help=f'Path to EXE with BLE image (default: {DEFAULT_EXE_PATH})'
    )
    parser.add_argument(
        '--save-dir', type=str, default=None,
        help='Save built variant images to this directory'
    )

    args = parser.parse_args()

    # If neither --dry-run nor --flash, default to dry-run
    if not args.flash:
        args.dry_run = True

    print()
    print("=" * 70)
    print("  AJ159 APEX - MCUboot TLV Malformation Fuzzer")
    print("  Testing signature verification bypass via TLV manipulation")
    print("=" * 70)

    # Resolve paths (with fallback to script's own directory)
    fw_path = resolve_firmware_path(args.fw_path)
    exe_path = resolve_exe_path(args.exe_path)

    # Read inputs
    print(f"\n[*] Loading firmware components...")
    print(f"    Firmware: {fw_path}")
    code = read_patched_code(fw_path)
    print(f"    Code size: {len(code)} bytes")

    print(f"    EXE: {exe_path}")
    ble_image = read_ble_image(exe_path)
    print(f"    BLE image: {len(ble_image)} bytes")

    # Extract original RSA for variant 9
    print(f"\n[*] Extracting original RSA signature from EXE...")
    original_rsa = extract_original_rsa(exe_path)

    # Compute SHA-256 of header + code
    header = build_mcuboot_header()
    sha256_hash = compute_image_sha256(header, code)
    print(f"\n[*] Image SHA-256 (header+code): {sha256_hash.hex()}")

    # Determine which variants to build
    if args.variant.lower() == 'all':
        variant_indices = list(range(len(ALL_VARIANTS)))
    else:
        try:
            idx = int(args.variant) - 1
            if idx < 0 or idx >= len(ALL_VARIANTS):
                sys.exit(f"ERROR: Variant must be 1-{len(ALL_VARIANTS)}")
            variant_indices = [idx]
        except ValueError:
            sys.exit(f"ERROR: --variant must be a number (1-{len(ALL_VARIANTS)}) or 'all'")

    # Create save directory if requested
    save_dir = None
    if args.save_dir:
        save_dir = Path(args.save_dir)
        save_dir.mkdir(parents=True, exist_ok=True)
        print(f"\n[*] Saving images to: {save_dir}")

    # Build and optionally flash each variant
    print(f"\n{'='*70}")
    results = []

    for idx in variant_indices:
        variant_class = ALL_VARIANTS[idx]

        # Special handling for variant 9 (needs original RSA)
        if variant_class == OriginalTLVPatchedSHA:
            variant = variant_class(original_rsa=original_rsa)
        else:
            variant = variant_class()

        variant_num = idx + 1
        print(f"\n  Variant {variant_num}: {variant.name}")
        print(f"  Description: {variant.description}")
        print(f"  {'-'*60}")

        # Build TLV
        tlv_bytes = variant.build_tlv(sha256_hash)
        print(f"    TLV size: {len(tlv_bytes)} bytes")
        print(f"    TLV hex: {tlv_bytes[:32].hex()}" +
              ("..." if len(tlv_bytes) > 32 else ""))

        # Build complete blob
        blob = build_complete_blob(code, tlv_bytes, ble_image)
        checksum = sum(blob) & 0xFFFFFFFF
        chunk_count = math.ceil(len(blob) / REPORT_SIZE)

        print(f"    App image size: {HDR_SIZE + IMG_SIZE + len(tlv_bytes)} bytes")
        print(f"    Total blob: {len(blob)} bytes ({chunk_count} chunks)")
        print(f"    Checksum: 0x{checksum:08X}")

        # Save if requested
        if save_dir:
            filename = f"variant_{variant_num}_{variant.name.lower()}.bin"
            (save_dir / filename).write_bytes(blob)
            print(f"    Saved: {save_dir / filename}")

        # Flash if requested
        if args.flash:
            print(f"\n    [FLASH] Attempting to flash variant {variant_num}...")
            hid = require_hid()
            device = open_boot_device(hid)
            try:
                success, msg = flash_blob(device, blob)
                results.append((variant_num, variant.name, success, msg))
                if success:
                    print(f"    [!!!] SUCCESS: {msg}")
                    print(f"    [!!!] MCUboot ACCEPTED the image!")
                    print(f"    [!!!] The signature check may be bypassed!")
                else:
                    print(f"    [---] REJECTED: {msg}")
            except Exception as e:
                results.append((variant_num, variant.name, False, str(e)))
                print(f"    [ERR] Error: {e}")
            finally:
                device.close()

            # Wait for device to settle between variants
            if len(variant_indices) > 1:
                print(f"    Waiting 3 seconds for device to settle...")
                time.sleep(3)
        else:
            results.append((variant_num, variant.name, None, "dry-run"))

    # Final summary
    print(f"\n{'='*70}")
    print(f"  RESULTS SUMMARY")
    print(f"{'='*70}\n")

    for num, name, success, msg in results:
        if success is None:
            status = "DRY-RUN"
        elif success:
            status = "ACCEPTED"
        else:
            status = "REJECTED"
        print(f"    {num}. {name:35s} [{status:8s}] {msg}")

    if args.flash:
        accepted = [r for r in results if r[2] is True]
        if accepted:
            print(f"\n  [!!!] {len(accepted)} variant(s) ACCEPTED by bootloader!")
            print(f"        This may indicate a bypass of RSA signature verification.")
        else:
            print(f"\n  [-] All variants rejected. RSA verification appears enforced.")

    if args.dry_run and not args.flash:
        print(f"\n  This was a dry run. Use --flash to actually send to device.")
        print(f"  Make sure the mouse is in boot mode (PID 0x4025) first.")

    print()


if __name__ == "__main__":
    main()
