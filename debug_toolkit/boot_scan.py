#!/usr/bin/env python3
"""
boot_scan.py - Bootloader Command Scanner for Ajazz AJ159 APEX Mouse
======================================================================

Sends all 256 possible BA XX command IDs to the mouse in boot mode and logs
all responses. This helps discover undocumented bootloader commands that might
provide alternative paths past MCUboot RSA-2048 signature verification.

Known commands:
  BA FF - Get boot ID (byte[7]=0x46 selects mode, response has device ID 0x06DB)
  BA C0 - Init transfer (requires specific parameters, SKIPPED)
  BA C2 - Complete transfer (requires specific parameters, SKIPPED)

PREREQUISITES:
  - Python 3.7+
  - pip install hidapi
  - Mouse in boot mode (PID 0x4025)
  - Windows: run as Administrator
  - Linux: run as root or configure udev rules

USAGE:
  python boot_scan.py                  # Scan all command IDs
  python boot_scan.py --sweep-baff     # Also sweep BA FF mode bytes
  python boot_scan.py --timeout 100    # Custom read timeout (ms)
  python boot_scan.py --skip-known     # Skip BA C0 and BA C2 (default)
"""

from __future__ import annotations

import sys
import time
import argparse
from typing import Optional

# ===========================================================================
# Constants
# ===========================================================================

BOOT_VID = 0x3151
BOOT_PID = 0x4025
BOOT_USAGE_PAGE = 0xFF01
BOOT_INTERFACE = 0

REPORT_ID = 0x00
REPORT_SIZE = 64

CMD_TX_PREFIX = 0xBA
CMD_RX_PREFIX = 0xAB

# Commands to skip by default (they require specific parameters)
SKIP_COMMANDS = {0xC0, 0xC2}


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


def find_boot_device(hid_module) -> Optional[dict]:
    """Find the boot-mode device."""
    devices = hid_module.enumerate(BOOT_VID, BOOT_PID)
    if not devices:
        return None

    for d in devices:
        if (d.get('usage_page') == BOOT_USAGE_PAGE and
                d.get('interface_number') == BOOT_INTERFACE):
            return d

    # Fallback: any vendor-page device
    for d in devices:
        up = d.get('usage_page', 0)
        if up >= 0xFF00:
            return d

    return devices[0] if devices else None


def open_boot_device(hid_module):
    """Open the boot-mode HID device."""
    dev_info = find_boot_device(hid_module)
    if not dev_info:
        print(f"\nERROR: Boot device not found (VID={BOOT_VID:#06x} PID={BOOT_PID:#06x})")
        print("\nIs the mouse in boot mode? To enter boot mode:")
        print("  1. Use aj159_flasher.py --enter-boot")
        print("  2. Or hold side buttons while plugging in USB")
        print("\nScanning for any Compx devices...")
        all_devs = hid_module.enumerate()
        for d in all_devs:
            if d['vendor_id'] == BOOT_VID:
                print(f"  VID:{d['vendor_id']:#06x} PID:{d['product_id']:#06x} "
                      f"iface={d.get('interface_number')} "
                      f"usage_page={d.get('usage_page', 0):#06x}")
        sys.exit(1)

    print(f"[*] Found boot device: VID={dev_info['vendor_id']:#06x} "
          f"PID={dev_info['product_id']:#06x} "
          f"iface={dev_info.get('interface_number')} "
          f"usage_page={dev_info.get('usage_page', 0):#06x}")

    h = hid_module.device()
    try:
        h.open_path(dev_info['path'])
    except Exception as e:
        sys.exit(
            f"ERROR: Cannot open boot device: {e}\n\n"
            "Possible fixes:\n"
            "  - Windows: Run as Administrator\n"
            "  - Windows: Close ry_upgrade.exe or other software\n"
            "  - Linux: Run with sudo, or install udev rules\n"
            "  - macOS: Grant Input Monitoring permission"
        )

    return h


def send_command(device, payload: bytes) -> None:
    """Send a 64-byte command via HID feature report."""
    assert len(payload) == REPORT_SIZE
    packet = bytes([REPORT_ID]) + payload
    result = device.send_feature_report(packet)
    if result < 0:
        raise IOError(f"send_feature_report failed (returned {result})")


def read_response(device, timeout_ms: int = 200) -> Optional[bytes]:
    """
    Read a 64-byte response via HID feature report.
    Returns None if the response appears to be stale (echo of sent data).
    """
    try:
        resp = device.get_feature_report(REPORT_ID, REPORT_SIZE + 1)
        if not resp or len(resp) < 2:
            return None
        return bytes(resp[1:])
    except Exception:
        return None


# ===========================================================================
# Scan Logic
# ===========================================================================

def scan_commands(device, timeout_ms: int, skip_known: bool, verbose: bool):
    """
    Send BA XX for all 256 possible command IDs and log responses.
    """
    print(f"\n{'='*70}")
    print(f"  BOOTLOADER COMMAND SCAN")
    print(f"  Sending BA XX for XX = 0x00..0xFF")
    if skip_known:
        print(f"  Skipping: BA C0, BA C2 (require parameters)")
    print(f"  Timeout: {timeout_ms} ms per command")
    print(f"{'='*70}\n")

    results = {
        'responded': [],    # Commands that got a valid AB XX response
        'echo': [],         # Commands where response was just echo of sent data
        'no_response': [],  # Commands with no meaningful response
        'error': [],        # Commands that caused an error
        'skipped': [],      # Commands skipped
    }

    # First, read the current state to establish a baseline
    baseline = read_response(device, timeout_ms)
    if baseline:
        print(f"[*] Baseline read (current feature report state):")
        print(f"    {baseline[:16].hex()}")
        print()

    for cmd_id in range(256):
        if skip_known and cmd_id in SKIP_COMMANDS:
            results['skipped'].append(cmd_id)
            if verbose:
                print(f"  [SKIP] BA {cmd_id:02X} (requires parameters)")
            continue

        # Build command: BA <cmd_id> + 62 zero bytes
        payload = bytearray(REPORT_SIZE)
        payload[0] = CMD_TX_PREFIX
        payload[1] = cmd_id

        try:
            send_command(device, bytes(payload))
            time.sleep(timeout_ms / 1000.0)
            resp = read_response(device, timeout_ms)

            if resp is None:
                results['no_response'].append(cmd_id)
                if verbose:
                    print(f"  [----] BA {cmd_id:02X} -> no response")
                continue

            # Check if it is a proper AB XX response
            if resp[0] == CMD_RX_PREFIX and resp[1] == cmd_id:
                results['responded'].append((cmd_id, resp))
                resp_hex = resp[:16].hex()
                print(f"  [RESP] BA {cmd_id:02X} -> AB {cmd_id:02X} | {resp_hex}...")
                if verbose:
                    print(f"         Full: {resp.hex()}")
            elif resp[0] == CMD_RX_PREFIX:
                # Response with different command ID (interesting!)
                results['responded'].append((cmd_id, resp))
                resp_hex = resp[:16].hex()
                print(f"  [!!!!] BA {cmd_id:02X} -> AB {resp[1]:02X} (DIFFERENT CMD!) | {resp_hex}...")
                if verbose:
                    print(f"         Full: {resp.hex()}")
            elif resp == bytes(payload):
                # Echo of what we sent (device just mirrors feature report)
                results['echo'].append(cmd_id)
                if verbose:
                    print(f"  [ECHO] BA {cmd_id:02X} -> echo of sent data")
            else:
                # Some other response
                results['responded'].append((cmd_id, resp))
                resp_hex = resp[:16].hex()
                print(f"  [????] BA {cmd_id:02X} -> {resp_hex}...")
                if verbose:
                    print(f"         Full: {resp.hex()}")

        except IOError as e:
            results['error'].append((cmd_id, str(e)))
            print(f"  [ERR!] BA {cmd_id:02X} -> {e}")
        except Exception as e:
            results['error'].append((cmd_id, str(e)))
            print(f"  [ERR!] BA {cmd_id:02X} -> {e}")

    # Summary
    print(f"\n{'='*70}")
    print(f"  SUMMARY")
    print(f"{'='*70}")
    print(f"  Responded (AB XX): {len(results['responded'])}")
    print(f"  Echo only:         {len(results['echo'])}")
    print(f"  No response:       {len(results['no_response'])}")
    print(f"  Errors:            {len(results['error'])}")
    print(f"  Skipped:           {len(results['skipped'])}")

    if results['responded']:
        print(f"\n  Commands with valid responses:")
        for cmd_id, resp in results['responded']:
            print(f"    BA {cmd_id:02X} -> {resp[:8].hex()}")

    return results


def sweep_baff_mode_byte(device, timeout_ms: int, verbose: bool):
    """
    For BA FF, sweep byte[7] (the mode byte) from 0x00 to 0xFF.
    The known working value is 0x46. Others might unlock different behaviors.
    """
    print(f"\n{'='*70}")
    print(f"  BA FF MODE BYTE SWEEP (byte[7] = 0x00..0xFF)")
    print(f"  Known working: byte[7] = 0x46 (returns device ID 0x06DB)")
    print(f"{'='*70}\n")

    unique_responses = {}

    for mode in range(256):
        payload = bytearray(REPORT_SIZE)
        payload[0] = CMD_TX_PREFIX
        payload[1] = 0xFF
        payload[7] = mode

        try:
            send_command(device, bytes(payload))
            time.sleep(timeout_ms / 1000.0)
            resp = read_response(device, timeout_ms)

            if resp is None:
                if verbose:
                    print(f"  mode=0x{mode:02X}: no response")
                continue

            # Categorize by unique response content
            resp_key = resp[:16].hex()
            if resp_key not in unique_responses:
                unique_responses[resp_key] = []
                print(f"  [NEW!] mode=0x{mode:02X}: {resp_key}")
                if verbose:
                    print(f"         Full: {resp.hex()}")
            unique_responses[resp_key].append(mode)

        except Exception as e:
            print(f"  [ERR!] mode=0x{mode:02X}: {e}")

    # Summary
    print(f"\n  Unique response patterns: {len(unique_responses)}")
    for pattern, modes in unique_responses.items():
        if len(modes) <= 10:
            mode_list = ", ".join(f"0x{m:02X}" for m in modes)
        else:
            mode_list = (", ".join(f"0x{m:02X}" for m in modes[:5]) +
                         f" ... ({len(modes)} total)")
        print(f"    {pattern}")
        print(f"      Modes: {mode_list}")

    return unique_responses


# ===========================================================================
# Main
# ===========================================================================

def main():
    parser = argparse.ArgumentParser(
        description="AJ159 Bootloader Command Scanner Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          Scan all BA XX commands
  %(prog)s --sweep-baff             Also sweep BA FF mode byte
  %(prog)s --timeout 200            Use 200ms read timeout
  %(prog)s --no-skip                Don't skip BA C0/BA C2 (risky!)
  %(prog)s -v                       Verbose output (show all responses)

Known boot commands:
  BA FF  - Get boot ID (mode byte 0x46 at offset 7)
  BA C0  - Init transfer (chunk_count LE16 at [2:4], size LE32 at [4:8])
  BA C2  - Complete transfer (chunk_count, checksum, size)
        """
    )
    parser.add_argument(
        '--timeout', type=int, default=50,
        help='Read timeout in ms after each command (default: 50)'
    )
    parser.add_argument(
        '--sweep-baff', action='store_true',
        help='Also sweep the BA FF mode byte (byte[7]) from 0x00 to 0xFF'
    )
    parser.add_argument(
        '--no-skip', action='store_true',
        help='Do NOT skip BA C0 and BA C2 (may confuse device state!)'
    )
    parser.add_argument(
        '-v', '--verbose', action='store_true',
        help='Show all responses including echoes and empty'
    )

    args = parser.parse_args()

    print()
    print("=" * 70)
    print("  AJ159 APEX - Bootloader Command Scanner")
    print("  Target: VID 0x3151, PID 0x4025 (boot mode)")
    print("  Protocol: HID Feature Reports, 64 bytes, no report ID")
    print("=" * 70)

    hid = require_hid()
    device = open_boot_device(hid)

    try:
        # Phase 1: Scan all BA XX commands
        results = scan_commands(
            device,
            timeout_ms=args.timeout,
            skip_known=not args.no_skip,
            verbose=args.verbose
        )

        # Phase 2: Sweep BA FF mode byte
        if args.sweep_baff:
            sweep_baff_mode_byte(device, timeout_ms=args.timeout, verbose=args.verbose)

        print(f"\n{'='*70}")
        print(f"  DONE")
        print(f"{'='*70}")
        print()
        print("  Next steps:")
        print("  - Any BA XX that returns AB XX (other than FF) is an undocumented command")
        print("  - Look for commands that might:")
        print("    * Disable signature checking")
        print("    * Read/write flash directly")
        print("    * Enter a debug/JTAG mode")
        print("    * Return version/config info")
        print()

    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user.")
    except Exception as e:
        print(f"\n[!] Error: {e}")
        raise
    finally:
        device.close()
        print("[*] Device closed.")


if __name__ == "__main__":
    main()
