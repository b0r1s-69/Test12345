#!/usr/bin/env python3
"""
probe_reports.py - Undocumented HID Report ID Probe for Ajazz AJ159 APEX Mouse
================================================================================

Probes the mouse in NORMAL mode on the vendor HID interface for undocumented
report IDs. This can reveal hidden functionality that might be useful for
firmware manipulation or debug access.

Targets:
  - VID 0x3151, PID 0x4026 (normal mode)
  - usage_page 0xFFFF, interface 2 (vendor-specific)

Actions:
  - GET_FEATURE for report IDs 0x00 through 0xFF
  - SET_FEATURE with 64 zero bytes for specific undocumented report IDs
    (0x13, 0x14, 0x15, 0x16, 0x17, 0x18) identified from firmware analysis

PREREQUISITES:
  - Python 3.7+
  - pip install hidapi
  - Mouse in normal mode (PID 0x4026), plugged in via USB or 2.4G receiver
  - Windows: run as Administrator
  - Linux: run as root or configure udev rules

USAGE:
  python probe_reports.py                    # Probe all report IDs
  python probe_reports.py --set-feature      # Also try SET_FEATURE on undocumented IDs
  python probe_reports.py --range 0x00 0x20  # Probe specific range only
"""

from __future__ import annotations

import sys
import time
import argparse
from typing import Optional

# ===========================================================================
# Constants
# ===========================================================================

NORMAL_VID = 0x3151
NORMAL_PID = 0x4026
NORMAL_USAGE_PAGE = 0xFFFF
NORMAL_INTERFACE = 2

REPORT_SIZE = 64

# Undocumented report IDs found during firmware reverse engineering
UNDOCUMENTED_REPORT_IDS = [0x13, 0x14, 0x15, 0x16, 0x17, 0x18]

# Known report IDs (from aj159_debug.py protocol analysis)
KNOWN_REPORT_IDS = {
    0x04: "DPI configuration (56 bytes)",
    0x05: "Preferences/RGB/sleep (15 bytes)",
    0x06: "Polling rate (9 bytes)",
}


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


def find_normal_device(hid_module) -> Optional[dict]:
    """Find the normal-mode device on the vendor interface."""
    devices = hid_module.enumerate(NORMAL_VID, NORMAL_PID)
    if not devices:
        return None

    # Prefer exact match: usage_page=0xFFFF, interface=2
    for d in devices:
        if (d.get('usage_page') == NORMAL_USAGE_PAGE and
                d.get('interface_number') == NORMAL_INTERFACE):
            return d

    # Fallback: any vendor-page device on interface 2
    for d in devices:
        if d.get('interface_number') == NORMAL_INTERFACE:
            return d

    # Fallback: any vendor usage page
    for d in devices:
        up = d.get('usage_page', 0)
        if up >= 0xFF00:
            return d

    return devices[0] if devices else None


def open_normal_device(hid_module):
    """Open the normal-mode HID device on the vendor interface."""
    dev_info = find_normal_device(hid_module)
    if not dev_info:
        print(f"\nERROR: Normal-mode device not found (VID={NORMAL_VID:#06x} PID={NORMAL_PID:#06x})")
        print("\nIs the mouse connected in normal mode?")
        print("If it is in boot mode (PID 0x4025), power cycle it first.")
        print("\nScanning for Compx devices...")
        all_devs = hid_module.enumerate()
        for d in all_devs:
            if d['vendor_id'] == NORMAL_VID:
                print(f"  VID:{d['vendor_id']:#06x} PID:{d['product_id']:#06x} "
                      f"iface={d.get('interface_number')} "
                      f"usage_page={d.get('usage_page', 0):#06x}")
        sys.exit(1)

    print(f"[*] Found normal device: VID={dev_info['vendor_id']:#06x} "
          f"PID={dev_info['product_id']:#06x} "
          f"iface={dev_info.get('interface_number')} "
          f"usage_page={dev_info.get('usage_page', 0):#06x}")

    h = hid_module.device()
    try:
        h.open_path(dev_info['path'])
    except Exception as e:
        sys.exit(
            f"ERROR: Cannot open device: {e}\n\n"
            "Possible fixes:\n"
            "  - Windows: Run as Administrator\n"
            "  - Windows: Close mouse config software (ry_upgrade.exe, etc.)\n"
            "  - Linux: Run with sudo, or install udev rules\n"
            "  - macOS: Grant Input Monitoring permission"
        )

    return h


# ===========================================================================
# Probe Logic
# ===========================================================================

def probe_get_feature(device, first: int, last: int, verbose: bool):
    """
    Try GET_FEATURE for a range of report IDs.
    Log which ones return data vs which fail.
    """
    print(f"\n{'='*70}")
    print(f"  GET_FEATURE PROBE (Report IDs 0x{first:02X} to 0x{last:02X})")
    print(f"{'='*70}\n")

    results = {
        'data': [],      # Report IDs that returned non-zero data
        'empty': [],     # Report IDs that returned all zeros
        'error': [],     # Report IDs that raised an error
    }

    for rid in range(first, last + 1):
        try:
            # Request feature report with given ID
            data = device.get_feature_report(rid, REPORT_SIZE + 1)

            if data is None or len(data) == 0:
                results['error'].append((rid, "empty response"))
                if verbose:
                    print(f"  report 0x{rid:02X}: <empty>")
                continue

            # Strip report ID byte (first byte)
            payload = bytes(data[1:]) if len(data) > 1 else bytes(data)

            # Check if data is all zeros
            if not any(payload):
                results['empty'].append(rid)
                if verbose:
                    print(f"  report 0x{rid:02X}: all zeros ({len(payload)} bytes)")
                continue

            # Non-zero data found!
            results['data'].append((rid, payload))
            known = KNOWN_REPORT_IDS.get(rid, "")
            tag = f"  [{known}]" if known else ""
            hex_str = " ".join(f"{b:02x}" for b in payload[:REPORT_SIZE])
            print(f"  [DATA] report 0x{rid:02X} ({len(payload)} bytes){tag}:")
            print(f"         {hex_str}")

        except Exception as e:
            results['error'].append((rid, str(e)))
            if verbose:
                print(f"  report 0x{rid:02X}: <error: {e}>")

    # Summary
    print(f"\n  Results:")
    print(f"    Reports with data:    {len(results['data'])}")
    print(f"    Reports all zeros:    {len(results['empty'])}")
    print(f"    Reports with errors:  {len(results['error'])}")

    if results['data']:
        print(f"\n  Report IDs with data: "
              + ", ".join(f"0x{rid:02X}" for rid, _ in results['data']))

    return results


def probe_set_feature(device, report_ids: list, verbose: bool):
    """
    Try SET_FEATURE with 64 zero bytes for specific report IDs.
    These are the undocumented ones from firmware analysis.
    """
    print(f"\n{'='*70}")
    print(f"  SET_FEATURE PROBE (Undocumented Report IDs)")
    print(f"  Target IDs: {', '.join(f'0x{rid:02X}' for rid in report_ids)}")
    print(f"{'='*70}\n")

    print("  WARNING: SET_FEATURE writes data to the device. This is potentially")
    print("  dangerous but we are sending all-zeros which is typically benign.")
    print()

    for rid in report_ids:
        print(f"  --- Report ID 0x{rid:02X} ---")

        # Read current value first
        try:
            before = device.get_feature_report(rid, REPORT_SIZE + 1)
            if before and len(before) > 1:
                before_payload = bytes(before[1:])
                if any(before_payload):
                    print(f"    BEFORE: {' '.join(f'{b:02x}' for b in before_payload[:32])}...")
                else:
                    print(f"    BEFORE: all zeros")
            else:
                print(f"    BEFORE: <could not read>")
        except Exception as e:
            print(f"    BEFORE: <error: {e}>")
            before_payload = None

        # Try SET_FEATURE with zeros
        try:
            payload = bytes([rid]) + bytes(REPORT_SIZE)
            result = device.send_feature_report(payload)
            if result < 0:
                print(f"    SET:    FAILED (returned {result})")
            else:
                print(f"    SET:    OK (sent {result} bytes of zeros)")
        except Exception as e:
            print(f"    SET:    ERROR: {e}")
            continue

        # Small delay then read back
        time.sleep(0.05)

        # Read after
        try:
            after = device.get_feature_report(rid, REPORT_SIZE + 1)
            if after and len(after) > 1:
                after_payload = bytes(after[1:])
                if any(after_payload):
                    print(f"    AFTER:  {' '.join(f'{b:02x}' for b in after_payload[:32])}...")
                else:
                    print(f"    AFTER:  all zeros")

                # Compare
                if before_payload and after_payload != before_payload:
                    print(f"    [!] RESPONSE CHANGED after SET_FEATURE!")
            else:
                print(f"    AFTER:  <could not read>")
        except Exception as e:
            print(f"    AFTER:  <error: {e}>")

        print()


# ===========================================================================
# Main
# ===========================================================================

def main():
    parser = argparse.ArgumentParser(
        description="AJ159 Undocumented HID Report ID Probe",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          Probe GET_FEATURE for all report IDs
  %(prog)s --set-feature            Also try SET_FEATURE on undocumented IDs
  %(prog)s --range 0x00 0x20        Only probe IDs 0x00 to 0x20
  %(prog)s -v                       Verbose (show empty/error reports too)

Undocumented Report IDs (from firmware analysis):
  0x13, 0x14, 0x15, 0x16, 0x17, 0x18

Known Report IDs:
  0x04 - DPI configuration
  0x05 - Preferences/RGB/sleep
  0x06 - Polling rate
        """
    )
    parser.add_argument(
        '--set-feature', action='store_true',
        help='Also try SET_FEATURE with zeros on undocumented report IDs'
    )
    parser.add_argument(
        '--range', type=lambda x: int(x, 0), nargs=2, default=[0x00, 0xFF],
        metavar=('FIRST', 'LAST'),
        help='Range of report IDs to probe (default: 0x00 to 0xFF)'
    )
    parser.add_argument(
        '-v', '--verbose', action='store_true',
        help='Show all results including empty/error reports'
    )

    args = parser.parse_args()

    print()
    print("=" * 70)
    print("  AJ159 APEX - Undocumented HID Report ID Probe")
    print("  Target: VID 0x3151, PID 0x4026 (normal mode)")
    print("  Interface: 2, usage_page: 0xFFFF (vendor-specific)")
    print("=" * 70)

    hid = require_hid()
    device = open_normal_device(hid)

    try:
        # Phase 1: GET_FEATURE probe across all report IDs
        get_results = probe_get_feature(
            device,
            first=args.range[0],
            last=args.range[1],
            verbose=args.verbose
        )

        # Phase 2: SET_FEATURE on undocumented report IDs
        if args.set_feature:
            probe_set_feature(device, UNDOCUMENTED_REPORT_IDS, args.verbose)

        print(f"\n{'='*70}")
        print(f"  DONE")
        print(f"{'='*70}")
        print()
        print("  Analysis tips:")
        print("  - Reports with non-zero data may contain configuration/state")
        print("  - SET_FEATURE responses that change indicate writable registers")
        print("  - Look for patterns that might indicate:")
        print("    * Debug mode enable/disable flags")
        print("    * Firmware version or build info")
        print("    * Memory read/write primitives")
        print("    * Boot mode trigger sequences")
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
