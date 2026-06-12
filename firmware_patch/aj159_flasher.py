#!/usr/bin/env python3
"""
aj159_flasher.py - Ajazz AJ159 APEX Mouse Firmware Flasher
===========================================================

Complete firmware flasher implementing the boot protocol decoded from USB capture.

PROTOCOL SUMMARY (from mouse_capture2.pcap analysis):
  - Transport: HID Feature Reports, Report ID 0x00, 64 bytes, control endpoint
  - Boot device: VID 0x3151, PID 0x4025, usage_page 0xFF01, interface 0
  - Normal device: VID 0x3151, PID 0x4026, usage_page 0xFF01/0xFFFF, interface 2
  - Commands: BA XX for TX (host->device), AB XX for RX (device->host response)
  - Data streaming: raw 64-byte SET_REPORT blocks with no framing
  - Checksum: simple sum of all data bytes mod 2^32 (NOT CRC32)

FIRMWARE BLOB LAYOUT (matching official tool):
  - App image: padded to 128KB (131072 bytes)
  - BLE controller image: 170420 bytes
  - Total: 301492 bytes = 4711 chunks of 64 bytes

PREREQUISITES:
  - Python 3.7+
  - pip install hidapi
  - Mouse in boot mode (PID 0x4025) OR use --enter-boot from normal mode
  - Windows: run as Administrator if device access fails
  - Linux: run as root or configure udev rules

SAFETY WARNING:
  The patched firmware has a correct SHA256 in the MCUboot TLV but a stale RSA
  signature. If the bootloader validates RSA, it may reject the image. However,
  the mouse will remain in boot mode and can be re-flashed with the original
  firmware -- it will NOT be bricked.

USAGE:
  python aj159_flasher.py                    # Flash with default files
  python aj159_flasher.py --dry-run          # Build blob, show info, don't flash
  python aj159_flasher.py --enter-boot       # Just enter boot mode
  python aj159_flasher.py --fw-path alt.bin  # Use alternative firmware file
"""

from __future__ import annotations

import sys
import time
import struct
import argparse
import math
from pathlib import Path
from typing import Optional

# ===========================================================================
# Constants
# ===========================================================================

# Device identifiers
BOOT_VID = 0x3151
BOOT_PID = 0x4025
BOOT_USAGE_PAGE = 0xFF01
BOOT_INTERFACE = 0

NORMAL_VID = 0x3151
NORMAL_PID = 0x4026
NORMAL_USAGE_PAGE = 0xFF01  # or 0xFFFF
NORMAL_INTERFACE = 2

# Protocol constants
REPORT_ID = 0x00
REPORT_SIZE = 64  # 64 bytes payload per feature report

# Command prefixes
CMD_TX_PREFIX = 0xBA  # Host -> Device
CMD_RX_PREFIX = 0xAB  # Device -> Host (response)

# Command IDs
CMD_GET_BOOT_ID = 0xFF
CMD_INIT_TRANSFER = 0xC0
CMD_COMPLETE = 0xC2

# MCUboot magic
MCUBOOT_MAGIC = 0x96F3B83D

# Image layout
APP_PAD_SIZE = 131072  # 128KB aligned
APP_IMG_EXE_OFFSET = 0x011A291F   # App MCUboot image offset in EXE
BLE_IMG_EXE_OFFSET = 0x011C291F   # BLE MCUboot image offset in EXE
BLE_IMG_SIZE = 170420             # 512 + 169572 + 336 bytes
EXPECTED_TOTAL = 301492           # 131072 + 170420

# Enter-boot command (from normal mode)
ENTER_BOOT_CMD = bytes([0x7F, 0x55, 0xAA, 0x55, 0xAA, 0x00, 0x00, 0x82]) + bytes(56)


# ===========================================================================
# HID Helpers
# ===========================================================================

def require_hid():
    """Import and return the hid module, or exit with install instructions."""
    try:
        import hid
        return hid
    except ImportError:
        sys.exit(
            "ERROR: The 'hidapi' package is required.\n"
            "Install with:\n"
            "    pip install hidapi\n"
            "\n"
            "On Linux you may also need: sudo apt install libhidapi-dev\n"
            "On Windows: hidapi wheels include the DLL, no extra install needed."
        )


def send_command(device, payload: bytes) -> None:
    """
    Send a 64-byte command via HID feature report.

    hidapi convention: prepend report ID (0x00) to the 64-byte payload.
    send_feature_report(bytes([0x00]) + 64_bytes)
    """
    assert len(payload) == REPORT_SIZE, f"Payload must be {REPORT_SIZE} bytes, got {len(payload)}"
    packet = bytes([REPORT_ID]) + payload
    result = device.send_feature_report(packet)
    if result < 0:
        raise IOError(f"send_feature_report failed (returned {result})")


def read_response(device, timeout_ms: int = 2000) -> bytes:
    """
    Read a 64-byte response via HID feature report.

    hidapi convention: get_feature_report(report_id, size)
    Returns bytes of length 65: [report_id] + 64 data bytes.
    We strip the report ID and return just the 64-byte payload.
    """
    resp = device.get_feature_report(REPORT_ID, REPORT_SIZE + 1)
    if not resp:
        raise IOError("get_feature_report returned empty response")
    # resp is 65 bytes: [0x00] + 64 data bytes
    return bytes(resp[1:])


def build_command(cmd_id: int, data: bytes = b"") -> bytes:
    """
    Build a 64-byte TX command packet.
    Format: [BA <cmd_id> <data...> <zero padding to 64 bytes>]
    """
    payload = bytearray(REPORT_SIZE)
    payload[0] = CMD_TX_PREFIX
    payload[1] = cmd_id
    if data:
        payload[2:2 + len(data)] = data
    return bytes(payload)


# ===========================================================================
# Device Discovery
# ===========================================================================

def find_device(hid_module, vid: int, pid: int, usage_page: int,
                interface: int) -> Optional[dict]:
    """Find a HID device matching VID, PID, usage_page, and interface."""
    devices = hid_module.enumerate(vid, pid)
    if not devices:
        return None

    # Prefer exact match on usage_page and interface
    for d in devices:
        if (d.get('usage_page') == usage_page and
                d.get('interface_number') == interface):
            return d

    # Fall back: match just usage page (vendor-defined)
    for d in devices:
        up = d.get('usage_page', 0)
        if up >= 0xFF00:
            return d

    # Last resort: first device
    return devices[0] if devices else None


def open_device(hid_module, vid: int, pid: int, usage_page: int,
                interface: int, label: str = "device"):
    """Open a HID device. Returns device handle."""
    dev_info = find_device(hid_module, vid, pid, usage_page, interface)
    if not dev_info:
        print(f"\nERROR: {label} not found (VID={vid:#06x} PID={pid:#06x})")
        print("\nScanning all HID devices...")
        all_devs = hid_module.enumerate()
        found = False
        for d in all_devs:
            if d['vendor_id'] == vid:
                found = True
                print(f"  VID:{d['vendor_id']:#06x} PID:{d['product_id']:#06x} "
                      f"iface={d.get('interface_number')} "
                      f"usage_page={d.get('usage_page', 0):#06x} "
                      f"product={d.get('product_string', '')!r}")
        if not found:
            print(f"  No devices found with VID {vid:#06x}")
        sys.exit(1)

    print(f"  Found {label}: VID={dev_info['vendor_id']:#06x} "
          f"PID={dev_info['product_id']:#06x} "
          f"iface={dev_info.get('interface_number')} "
          f"usage_page={dev_info.get('usage_page', 0):#06x}")

    h = hid_module.device()
    try:
        h.open_path(dev_info['path'])
    except Exception as e:
        sys.exit(
            f"ERROR: Cannot open {label}: {e}\n\n"
            "Possible fixes:\n"
            "  - Windows: Run as Administrator\n"
            "  - Windows: Close ry_upgrade.exe or any other software using the mouse\n"
            "  - Linux: Run with sudo, or install udev rules\n"
            "  - macOS: Grant Input Monitoring permission to Terminal"
        )

    return h


# ===========================================================================
# Firmware Blob Building
# ===========================================================================

def read_app_image(fw_path: str, exe_path: str) -> bytes:
    """
    Read the full MCUboot app image.

    Strategy:
      1. If fw_path exists and is 109456 bytes (full MCUboot image), use it directly
      2. Otherwise, extract from the EXE at offset 0x011A291F
      3. If fw_path is the raw code (108608 bytes), extract full image from EXE
         which already contains the patched code
    """
    fw_file = Path(fw_path)

    if fw_file.exists():
        data = fw_file.read_bytes()
        if len(data) == 109456:
            # Full MCUboot image (header + code + TLV)
            magic = struct.unpack_from('<I', data, 0)[0]
            if magic == MCUBOOT_MAGIC:
                print(f"  App image: {fw_path} ({len(data)} bytes, full MCUboot image)")
                return data
            else:
                print(f"  WARNING: {fw_path} is 109456 bytes but lacks MCUboot magic")

    # Extract from EXE
    exe_file = Path(exe_path)
    if not exe_file.exists():
        sys.exit(f"ERROR: EXE file not found: {exe_path}")

    exe_data = exe_file.read_bytes()
    if len(exe_data) < APP_IMG_EXE_OFFSET + 109456:
        sys.exit(f"ERROR: EXE file too small to contain app image at offset {APP_IMG_EXE_OFFSET:#x}")

    # Verify MCUboot magic
    magic = struct.unpack_from('<I', exe_data, APP_IMG_EXE_OFFSET)[0]
    if magic != MCUBOOT_MAGIC:
        sys.exit(f"ERROR: MCUboot magic not found at EXE offset {APP_IMG_EXE_OFFSET:#x}")

    # Read header to get image size
    img_size = struct.unpack_from('<I', exe_data, APP_IMG_EXE_OFFSET + 12)[0]
    hdr_size = struct.unpack_from('<H', exe_data, APP_IMG_EXE_OFFSET + 8)[0]
    total_size = hdr_size + img_size + 336  # header + code + TLV

    app_image = exe_data[APP_IMG_EXE_OFFSET:APP_IMG_EXE_OFFSET + total_size]
    print(f"  App image: extracted from {exe_path} at offset {APP_IMG_EXE_OFFSET:#x}")
    print(f"    Header: {hdr_size} bytes, Code: {img_size} bytes, TLV: 336 bytes")
    print(f"    Total: {len(app_image)} bytes")

    return app_image


def read_ble_image(exe_path: str) -> bytes:
    """
    Read the BLE controller MCUboot image from the EXE.

    Located at offset 0x011C291F, size 170420 bytes (512 + 169572 + 336).
    """
    exe_file = Path(exe_path)
    if not exe_file.exists():
        sys.exit(f"ERROR: EXE file not found: {exe_path}")

    exe_data = exe_file.read_bytes()
    if len(exe_data) < BLE_IMG_EXE_OFFSET + BLE_IMG_SIZE:
        sys.exit(f"ERROR: EXE file too small to contain BLE image at offset {BLE_IMG_EXE_OFFSET:#x}")

    # Verify MCUboot magic
    magic = struct.unpack_from('<I', exe_data, BLE_IMG_EXE_OFFSET)[0]
    if magic != MCUBOOT_MAGIC:
        sys.exit(
            f"ERROR: MCUboot magic (0x{MCUBOOT_MAGIC:08X}) not found at "
            f"EXE offset {BLE_IMG_EXE_OFFSET:#x}\n"
            f"Found: 0x{struct.unpack_from('<I', exe_data, BLE_IMG_EXE_OFFSET)[0]:08X}"
        )

    # Read header fields for verification
    img_size = struct.unpack_from('<I', exe_data, BLE_IMG_EXE_OFFSET + 12)[0]
    hdr_size = struct.unpack_from('<H', exe_data, BLE_IMG_EXE_OFFSET + 8)[0]
    total_size = hdr_size + img_size + 336

    if total_size != BLE_IMG_SIZE:
        print(f"  WARNING: BLE image size mismatch: expected {BLE_IMG_SIZE}, got {total_size}")
        print(f"  Using actual size from header: {total_size}")

    ble_image = exe_data[BLE_IMG_EXE_OFFSET:BLE_IMG_EXE_OFFSET + total_size]
    print(f"  BLE image: extracted from {exe_path} at offset {BLE_IMG_EXE_OFFSET:#x}")
    print(f"    Header: {hdr_size} bytes, Code: {img_size} bytes, TLV: 336 bytes")
    print(f"    Total: {len(ble_image)} bytes")

    return ble_image


def build_firmware_blob(fw_path: str, exe_path: str) -> bytes:
    """
    Build the complete firmware blob matching what the official tool sends.

    Layout:
      - App image padded to 128KB (131072 bytes) with 0xFF
      - BLE controller image (170420 bytes)
      - Total: 301492 bytes
    """
    print("\n[*] Building firmware blob...")
    print()

    # Read app image
    app_image = read_app_image(fw_path, exe_path)

    # Read BLE image
    ble_image = read_ble_image(exe_path)

    # Pad app image to 128KB with 0xFF
    if len(app_image) > APP_PAD_SIZE:
        sys.exit(f"ERROR: App image ({len(app_image)} bytes) exceeds 128KB pad size")

    app_padded = app_image + bytes([0xFF] * (APP_PAD_SIZE - len(app_image)))
    print(f"\n  App padded: {len(app_image)} -> {len(app_padded)} bytes (0xFF fill)")

    # Concatenate
    blob = app_padded + ble_image
    total = len(blob)
    chunk_count = math.ceil(total / REPORT_SIZE)

    # Compute checksum (simple sum of all bytes mod 2^32)
    checksum = sum(blob) & 0xFFFFFFFF

    print(f"\n  Final blob: {total} bytes ({chunk_count} chunks of {REPORT_SIZE} bytes)")
    print(f"  Checksum: 0x{checksum:08X} (sum of all bytes mod 2^32)")

    if total != EXPECTED_TOTAL:
        print(f"  NOTE: Expected {EXPECTED_TOTAL} bytes, got {total} bytes")
        print(f"  (This may be fine if using a different firmware version)")

    return blob


# ===========================================================================
# Flash Protocol
# ===========================================================================

def cmd_get_boot_id(device) -> bytes:
    """
    Step 1: Send BA FF to get boot ID and confirm communication.

    TX: [BA FF 00 00 00 00 00 46] + 56 zero bytes = 64 bytes
    RX: [AB FF <device_id_le16> ...]
    """
    print("\n[*] Step 1: Get Boot ID (BA FF)...")

    # Build the exact packet from the capture
    payload = bytearray(REPORT_SIZE)
    payload[0] = CMD_TX_PREFIX  # BA
    payload[1] = CMD_GET_BOOT_ID  # FF
    payload[2] = 0x00
    payload[3] = 0x00
    payload[4] = 0x00
    payload[5] = 0x00
    payload[6] = 0x00
    payload[7] = 0x46  # 0x46 seen in capture
    # Rest is zeros

    send_command(device, bytes(payload))
    time.sleep(0.05)
    resp = read_response(device)

    # Verify response
    if resp[0] != CMD_RX_PREFIX or resp[1] != CMD_GET_BOOT_ID:
        print(f"  ERROR: Unexpected response: {resp[:8].hex()}")
        print(f"  Expected: AB FF ...")
        sys.exit(1)

    device_id = struct.unpack_from('<H', resp, 2)[0]
    print(f"  Response: {resp[:8].hex()}")
    print(f"  Device ID: 0x{device_id:04X}")
    print(f"  Communication confirmed!")

    return resp


def cmd_init_transfer(device, blob: bytes) -> bytes:
    """
    Step 2: Send BA C0 to initialize the transfer.

    TX: [BA C0 <chunk_count_LE16> <total_size_LE32>] + 56 zero bytes
    RX: [AB C0 ...]
    """
    total_size = len(blob)
    chunk_count = math.ceil(total_size / REPORT_SIZE)

    print(f"\n[*] Step 2: Init Transfer (BA C0)...")
    print(f"  Chunks: {chunk_count}")
    print(f"  Total size: {total_size} bytes")

    # Build command
    data = struct.pack('<HI', chunk_count, total_size)
    payload = build_command(CMD_INIT_TRANSFER, data)

    send_command(device, payload)
    time.sleep(0.05)
    resp = read_response(device)

    # Verify response
    if resp[0] != CMD_RX_PREFIX or resp[1] != CMD_INIT_TRANSFER:
        print(f"  ERROR: Unexpected response: {resp[:8].hex()}")
        print(f"  Expected: AB C0 ...")
        sys.exit(1)

    print(f"  Response: {resp[:8].hex()}")
    print(f"  Transfer initialized!")

    return resp


def stream_firmware(device, blob: bytes) -> None:
    """
    Step 3: Stream firmware data as raw 64-byte feature reports.

    Each chunk is sent as send_feature_report(bytes([0x00]) + 64_bytes).
    No per-chunk response needed (USB ACK is sufficient).
    """
    total_size = len(blob)
    chunk_count = math.ceil(total_size / REPORT_SIZE)

    print(f"\n[*] Step 3: Streaming firmware ({chunk_count} chunks)...")
    print()

    start_time = time.time()
    last_progress = 0

    for i in range(chunk_count):
        offset = i * REPORT_SIZE
        chunk = blob[offset:offset + REPORT_SIZE]

        # Pad last chunk with zeros if needed
        if len(chunk) < REPORT_SIZE:
            chunk = chunk + bytes(REPORT_SIZE - len(chunk))

        # Send raw chunk as feature report (no BA prefix, just raw data)
        packet = bytes([REPORT_ID]) + chunk
        result = device.send_feature_report(packet)
        if result < 0:
            print(f"\n  ERROR: send_feature_report failed at chunk {i}/{chunk_count}")
            sys.exit(1)

        # Progress bar
        progress = int((i + 1) / chunk_count * 100)
        if progress != last_progress or i == chunk_count - 1:
            last_progress = progress
            elapsed = time.time() - start_time
            speed = ((i + 1) * REPORT_SIZE) / elapsed / 1024 if elapsed > 0 else 0
            bar_width = 40
            filled = int(bar_width * (i + 1) / chunk_count)
            bar = "#" * filled + "-" * (bar_width - filled)
            sys.stdout.write(
                f"\r  [{bar}] {progress:3d}% "
                f"({i+1}/{chunk_count} chunks, {speed:.1f} KB/s)"
            )
            sys.stdout.flush()

    elapsed = time.time() - start_time
    print(f"\n\n  Transfer complete in {elapsed:.1f} seconds")
    print(f"  Average speed: {total_size / elapsed / 1024:.1f} KB/s")


def cmd_complete_transfer(device, blob: bytes) -> bytes:
    """
    Step 4: Send BA C2 to complete the transfer.

    TX: [BA C2 <chunk_count_LE16> <checksum_LE32> <total_size_LE32>] + 50 zero bytes
    RX: [AB C2 ...]

    Checksum = sum of ALL bytes in the blob, mod 2^32
    """
    total_size = len(blob)
    chunk_count = math.ceil(total_size / REPORT_SIZE)
    checksum = sum(blob) & 0xFFFFFFFF

    print(f"\n[*] Step 4: Complete Transfer (BA C2)...")
    print(f"  Chunk count: {chunk_count}")
    print(f"  Checksum: 0x{checksum:08X}")
    print(f"  Total size: {total_size}")

    # Build command: BA C2 <chunk_count_LE16> <checksum_LE32> <total_size_LE32>
    data = struct.pack('<HII', chunk_count, checksum, total_size)

    payload = bytearray(REPORT_SIZE)
    payload[0] = CMD_TX_PREFIX  # BA
    payload[1] = CMD_COMPLETE   # C2
    payload[2:2 + len(data)] = data

    send_command(device, bytes(payload))
    time.sleep(0.1)
    resp = read_response(device)

    # Verify response
    if resp[0] != CMD_RX_PREFIX or resp[1] != CMD_COMPLETE:
        print(f"  ERROR: Unexpected response: {resp[:8].hex()}")
        print(f"  Expected: AB C2 ...")
        print(f"  The device may have rejected the firmware (RSA signature mismatch).")
        print(f"  The mouse should still be in boot mode - try flashing again.")
        sys.exit(1)

    print(f"  Response: {resp[:8].hex()}")
    print(f"  Transfer verified by device!")

    return resp


# ===========================================================================
# Enter Boot Mode
# ===========================================================================

def enter_boot_mode(hid_module) -> None:
    """
    Send the enter-boot command to the mouse in normal mode.

    Normal mode: VID 0x3151, PID 0x4026, interface 2
    Command: [0x00] + [7F 55 AA 55 AA 00 00 82] + 56 zeros

    After sending, wait ~3 seconds for the device to re-enumerate as PID 0x4025.
    """
    print("\n[*] Entering boot mode...")
    print(f"  Looking for normal-mode device (PID {NORMAL_PID:#06x})...")

    # Try both known usage pages for normal mode
    dev_info = find_device(hid_module, NORMAL_VID, NORMAL_PID,
                           NORMAL_USAGE_PAGE, NORMAL_INTERFACE)
    if not dev_info:
        # Try alternate usage page 0xFFFF
        dev_info = find_device(hid_module, NORMAL_VID, NORMAL_PID,
                               0xFFFF, NORMAL_INTERFACE)
    if not dev_info:
        # Try any vendor-page device with this VID/PID
        devices = hid_module.enumerate(NORMAL_VID, NORMAL_PID)
        for d in devices:
            up = d.get('usage_page', 0)
            if up >= 0xFF00:
                dev_info = d
                break

    if not dev_info:
        print(f"\n  ERROR: Normal-mode device not found (PID {NORMAL_PID:#06x})")
        print(f"  Is the mouse connected and powered on?")
        print(f"  If already in boot mode (PID {BOOT_PID:#06x}), no need to enter boot.")
        sys.exit(1)

    print(f"  Found: VID={dev_info['vendor_id']:#06x} "
          f"PID={dev_info['product_id']:#06x} "
          f"iface={dev_info.get('interface_number')} "
          f"usage_page={dev_info.get('usage_page', 0):#06x}")

    h = hid_module.device()
    try:
        h.open_path(dev_info['path'])
    except Exception as e:
        sys.exit(
            f"ERROR: Cannot open normal-mode device: {e}\n"
            "  - Windows: Close any mouse config software, run as Administrator\n"
            "  - Linux: Run with sudo or install udev rules"
        )

    # Send enter-boot command
    print(f"  Sending enter-boot command...")
    packet = bytes([REPORT_ID]) + ENTER_BOOT_CMD
    result = h.send_feature_report(packet)
    h.close()

    if result < 0:
        sys.exit("ERROR: Failed to send enter-boot command")

    print(f"  Command sent! Waiting for device to re-enumerate...")
    print(f"  (Device will disconnect and reappear as PID {BOOT_PID:#06x})")

    # Wait for re-enumeration
    for i in range(30):  # Wait up to ~6 seconds
        time.sleep(0.2)
        sys.stdout.write(f"\r  Waiting... {(i+1)*0.2:.1f}s")
        sys.stdout.flush()
        boot_dev = find_device(hid_module, BOOT_VID, BOOT_PID,
                               BOOT_USAGE_PAGE, BOOT_INTERFACE)
        if boot_dev:
            print(f"\n  Boot device detected! (PID {BOOT_PID:#06x})")
            return

    print(f"\n  WARNING: Boot device not detected after timeout.")
    print(f"  The device may need more time. Try running the flasher again.")
    sys.exit(1)


# ===========================================================================
# Main
# ===========================================================================

def print_banner():
    """Print the flasher banner."""
    print()
    print("=" * 60)
    print("  AJ159 APEX Firmware Flasher")
    print("  Protocol: HID Feature Reports (BA/AB command framing)")
    print("=" * 60)


def print_safety_warning():
    """Print the safety/RSA warning."""
    print()
    print("-" * 60)
    print("  SAFETY NOTE:")
    print("  The patched firmware has a valid SHA256 hash in MCUboot TLV")
    print("  but the RSA signature is stale (from original firmware).")
    print()
    print("  If the bootloader validates RSA: the image may be rejected,")
    print("  but the mouse will remain in boot mode (NOT bricked).")
    print("  You can always re-flash with the original firmware.")
    print("-" * 60)
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Ajazz AJ159 APEX Mouse Firmware Flasher",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                      Flash with default firmware files
  %(prog)s --dry-run            Build blob and show info without flashing
  %(prog)s --enter-boot         Enter boot mode without flashing
  %(prog)s --fw-path my_fw.bin  Use a custom firmware file
        """
    )
    parser.add_argument(
        '--dry-run', action='store_true',
        help='Build firmware blob and show info, but do not flash'
    )
    parser.add_argument(
        '--enter-boot', action='store_true',
        help='Enter boot mode from normal mode (PID 0x4026 -> 0x4025)'
    )
    parser.add_argument(
        '--fw-path', type=str, default=None,
        help='Path to firmware .bin file (default: mouse_app_fw_PATCHED.bin)'
    )
    parser.add_argument(
        '--exe-path', type=str, default=None,
        help='Path to EXE containing BLE image (default: ry_upgrade_PATCHED.exe)'
    )

    args = parser.parse_args()

    # Resolve paths relative to script directory
    script_dir = Path(__file__).parent
    fw_path = args.fw_path or str(script_dir / "mouse_app_fw_PATCHED.bin")
    exe_path = args.exe_path or str(script_dir / "ry_upgrade_PATCHED.exe")

    print_banner()

    # Handle --enter-boot mode (requires hidapi)
    if args.enter_boot:
        hid = require_hid()
        enter_boot_mode(hid)
        print("\n[+] Boot mode entry complete.")
        print("    Run this script again (without --enter-boot) to flash.")
        return

    # Build the firmware blob (pure file I/O, no hidapi needed)
    blob = build_firmware_blob(fw_path, exe_path)

    if args.dry_run:
        print("\n" + "=" * 60)
        print("  DRY RUN - No flash operation performed")
        print("=" * 60)
        chunk_count = math.ceil(len(blob) / REPORT_SIZE)
        checksum = sum(blob) & 0xFFFFFFFF
        print(f"\n  Blob size: {len(blob)} bytes")
        print(f"  Chunks: {chunk_count}")
        print(f"  Checksum: 0x{checksum:08X}")
        print(f"\n  BA C0 would send: chunk_count={chunk_count} total_size={len(blob)}")
        print(f"  BA C2 would send: chunk_count={chunk_count} "
              f"checksum=0x{checksum:08X} total_size={len(blob)}")
        print(f"\n  To flash for real, run without --dry-run")
        return

    # Import hidapi for actual flashing
    hid = require_hid()

    print_safety_warning()

    # Open boot device
    print("[*] Opening boot device...")
    device = open_device(hid, BOOT_VID, BOOT_PID, BOOT_USAGE_PAGE,
                         BOOT_INTERFACE, "boot device")

    try:
        # Step 1: Get boot ID
        cmd_get_boot_id(device)

        # Step 2: Init transfer
        cmd_init_transfer(device, blob)

        # Step 3: Stream firmware
        stream_firmware(device, blob)

        # Step 4: Complete transfer
        cmd_complete_transfer(device, blob)

        # Done!
        print("\n" + "=" * 60)
        print("  FLASH COMPLETE!")
        print("=" * 60)
        print()
        print("  The device will now reboot and validate the firmware.")
        print("  This may take a few seconds.")
        print()
        print("  If MCUboot accepts the image:")
        print("    -> Mouse will boot normally with the patched firmware")
        print()
        print("  If MCUboot rejects the image (RSA mismatch):")
        print("    -> Mouse will stay in boot mode (PID 0x4025)")
        print("    -> Re-flash with original firmware to recover")
        print()

    except KeyboardInterrupt:
        print("\n\n  Interrupted! The device may be in an inconsistent state.")
        print("  If the mouse is unresponsive, power cycle it.")
        print("  It should return to boot mode for re-flashing.")
    except Exception as e:
        print(f"\n\n  ERROR: {e}")
        print("  The device may still be in boot mode.")
        print("  Try running the flasher again.")
        raise
    finally:
        device.close()


if __name__ == "__main__":
    main()
