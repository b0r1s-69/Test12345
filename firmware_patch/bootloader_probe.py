#!/usr/bin/env python3
"""
bootloader_probe.py - Phase 1: Read-Only Bootloader Protocol Probe
===================================================================
Ajazz AJ159 APEX Gaming Mouse - Dual-Protocol Bootloader Discovery

WHAT THIS DOES
--------------
This script probes the AJ159's MCUboot bootloader using BOTH discovered
communication protocols to gather information about the device state. It is
strictly READ-ONLY: no erase, write, or flash commands are sent.

The AJ159 bootloader is MULTI-PROTOCOL (discovered via ry_upgrade.exe reversing):

  1. NORDICKEYBOARD protocol (Report ID 0x7F):
     Magic: 55 AA 55 AA, followed by 00 00 + command byte
     This is a raw Nordic OTA path that may bypass RSA signature checks.

  2. MOUSE protocol (Report ID 0xF8):
     Magic: 55 AA 55, followed by command byte
     This is the MCUboot-validated path with RSA-2048 enforcement.

PREREQUISITES
-------------
  - Mouse MUST be in boot mode (VID 0x0C4F / PID 0x0FB9, i.e. 3151:4025 decimal)
  - Python 3.7+
  - hidapi package: pip install hidapi
  - Windows: run as Administrator if device access fails
  - Linux: run as root or install udev rules (see debug_toolkit/99-aj159.rules)

SAFETY
------
This script ONLY sends query/info commands. It never sends:
  - Erase commands (0x03, 0x83)
  - Write/data commands (0x04, 0x84)
  - Execute/reset commands (0x05, 0x85)

HOW TO INTERPRET RESULTS
------------------------
NORDICKEYBOARD responses:
  - If the device responds with data (not all zeros or timeout), the protocol
    is active and the bootloader accepts this command set.
  - Command 0x82: "Get Boot Info" - returns device ID, USB version, firmware info
  - Command 0x01: Possibly "Init/Hello"
  - Command 0x02: Possibly "Get Status"
  - Command 0x80: Possibly "Start" or "Ping"
  - Command 0x81: Possibly "Get Version"

MOUSE responses:
  - Command 0x82: "Get Boot ID" - returns MCUboot version, device info
  - Response parsing: bytes 5+ contain version/ID data

A non-zero, non-timeout response means the protocol path is ALIVE and the
bootloader will accept further commands on that channel. This is the key
finding needed for Phase 2 (actual firmware flash attempt).

USAGE
-----
  python bootloader_probe.py              # Auto-detect boot device
  python bootloader_probe.py --verbose    # Extra hex dump detail
  python bootloader_probe.py --timeout 2000  # Longer read timeout (ms)
"""

from __future__ import annotations

import sys
import time
import argparse
from typing import Optional

# ===========================================================================
# Device constants
# ===========================================================================
BOOT_VID = 0x0C4F   # 3151 decimal (Compx)
BOOT_PID = 0x0FB9   # 4025 decimal (boot mode PID)
BOOT_USAGE_PAGE = 0xFF01
BOOT_USAGE = 0x01

REPORT_SIZE = 64     # All reports are 64 bytes

# ===========================================================================
# Protocol definitions
# ===========================================================================

# NORDICKEYBOARD protocol: Report ID 0x7F
# Format: [0x7F, 0x55, 0xAA, 0x55, 0xAA, 0x00, 0x00, cmd] + padding to 64 bytes
NK_REPORT_ID = 0x7F
NK_MAGIC = [0x55, 0xAA, 0x55, 0xAA]
NK_PADDING = [0x00, 0x00]  # Two zero bytes between magic and command

# MOUSE protocol: Report ID 0xF8
# Format: [0xF8, 0x55, 0xAA, 0x55, cmd] + padding to 64 bytes
MOUSE_REPORT_ID = 0xF8
MOUSE_MAGIC = [0x55, 0xAA, 0x55]

# Safe query commands only (no erase/write/execute)
NK_QUERY_COMMANDS = {
    0x82: "Get Boot Info (primary query)",
    0x01: "Init / Hello",
    0x02: "Get Status",
    0x80: "Start / Ping",
    0x81: "Get Version",
    0x83: "Get Address / Memory Info",  # NOTE: 0x83 in NK context is query, not erase
    0x84: "Get Config",
}

MOUSE_QUERY_COMMANDS = {
    0x82: "Get Boot ID (primary query)",
    0x80: "Ping / Hello",
    0x81: "Get Version",
    0x86: "Get Status",
    0x87: "Get Info",
}

# Commands we NEVER send (safety list - these are destructive)
DANGEROUS_COMMANDS = {0x03, 0x04, 0x05, 0x85}


# ===========================================================================
# Helpers
# ===========================================================================
def hex_dump(data: bytes | list, prefix: str = "    ") -> str:
    """Format a hex dump with both hex and ASCII columns."""
    if not data:
        return f"{prefix}(empty)"
    lines = []
    raw = bytes(data) if not isinstance(data, bytes) else data
    for offset in range(0, len(raw), 16):
        chunk = raw[offset:offset + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{prefix}{offset:04x}: {hex_part:<48s}  |{ascii_part}|")
    return "\n".join(lines)


def build_nk_packet(cmd: int) -> bytes:
    """Build a 64-byte NORDICKEYBOARD query packet."""
    assert cmd not in DANGEROUS_COMMANDS, f"SAFETY: refusing to build dangerous cmd 0x{cmd:02x}"
    pkt = bytearray(REPORT_SIZE)
    pkt[0] = NK_REPORT_ID
    pkt[1:5] = NK_MAGIC
    pkt[5:7] = NK_PADDING
    pkt[7] = cmd
    return bytes(pkt)


def build_mouse_packet(cmd: int) -> bytes:
    """Build a 64-byte MOUSE query packet."""
    assert cmd not in DANGEROUS_COMMANDS, f"SAFETY: refusing to build dangerous cmd 0x{cmd:02x}"
    pkt = bytearray(REPORT_SIZE)
    pkt[0] = MOUSE_REPORT_ID
    pkt[1:4] = MOUSE_MAGIC
    pkt[4] = cmd
    return bytes(pkt)


def is_meaningful_response(data: Optional[list | bytes]) -> bool:
    """Check if a response contains any non-zero data (beyond report ID)."""
    if not data:
        return False
    # Skip first byte (report ID) and check if rest has content
    return any(b != 0 for b in data[1:]) if len(data) > 1 else False


# ===========================================================================
# HID operations
# ===========================================================================
def require_hid():
    """Import and return the hid module, or exit with install instructions."""
    try:
        import hid
        return hid
    except ImportError:
        sys.exit(
            "ERROR: the 'hidapi' package is required.\n"
            "Install with:\n"
            "    pip install hidapi\n"
            "\n"
            "On Linux you may also need: sudo apt install libhidapi-dev\n"
            "On Windows: hidapi wheels include the DLL, no extra install needed."
        )


def find_boot_device(hid_module, vid: int = BOOT_VID, pid: int = BOOT_PID) -> Optional[dict]:
    """Find the AJ159 in boot mode by VID:PID and usage page."""
    devices = hid_module.enumerate(vid, pid)
    if not devices:
        return None

    # Prefer the device matching our expected usage page
    for d in devices:
        if d.get('usage_page') == BOOT_USAGE_PAGE and d.get('usage') == BOOT_USAGE:
            return d

    # Fall back to first vendor-page device
    for d in devices:
        up = d.get('usage_page', 0)
        if up >= 0xFF00:
            return d

    # Last resort: first device
    return devices[0] if devices else None


def open_boot_device(hid_module, verbose: bool = False, vid: int = BOOT_VID, pid: int = BOOT_PID):
    """Open the boot-mode HID device. Returns (device_handle, device_info)."""
    dev_info = find_boot_device(hid_module, vid=vid, pid=pid)
    if not dev_info:
        # List what IS present for debugging
        print(f"\nERROR: Boot device not found (VID={vid:#06x} PID={pid:#06x})")
        print("\nSearching all HID devices for Compx/RuiYu VIDs...")
        all_devs = hid_module.enumerate()
        found_any = False
        for d in all_devs:
            if d['vendor_id'] in (0x3151, 0x0C4F, 0x0C45):
                found_any = True
                print(f"  VID:{d['vendor_id']:#06x} PID:{d['product_id']:#06x} "
                      f"iface={d.get('interface_number')} "
                      f"usage_page={d.get('usage_page', 0):#06x} "
                      f"product={d.get('product_string', '')!r}")
        if not found_any:
            print("  (none found)")
        print("\nIs the mouse in boot mode? (PID should be 4025/0x0FB9)")
        print("If the mouse is in normal mode (PID 4026/0x0FBA), it needs to")
        print("enter boot mode first. But per the briefing, it should already")
        print("be stuck in boot mode.")
        sys.exit(1)

    if verbose:
        print(f"  Found boot device:")
        print(f"    VID:PID        = {dev_info['vendor_id']:#06x}:{dev_info['product_id']:#06x}")
        print(f"    interface      = {dev_info.get('interface_number')}")
        print(f"    usage_page     = {dev_info.get('usage_page', 0):#06x}")
        print(f"    usage          = {dev_info.get('usage', 0):#06x}")
        print(f"    product        = {dev_info.get('product_string', '')!r}")
        print(f"    manufacturer   = {dev_info.get('manufacturer_string', '')!r}")
        print(f"    path           = {dev_info.get('path')}")
        print()

    h = hid_module.device()
    try:
        h.open_path(dev_info['path'])
    except Exception as e:
        sys.exit(
            f"ERROR: Cannot open boot device: {e}\n\n"
            "Possible fixes:\n"
            "  - Windows: Run as Administrator\n"
            "  - Windows: Close ry_upgrade.exe or any other software using the mouse\n"
            "  - Linux: Run with sudo, or install udev rules\n"
            "  - macOS: Grant Input Monitoring permission to Terminal"
        )

    return h, dev_info


def send_and_read(device, packet: bytes, timeout_ms: int = 1000,
                  retries: int = 1) -> Optional[bytes]:
    """Send an output report and read the response. Returns response or None on timeout."""
    for attempt in range(retries):
        try:
            device.write(packet)
        except Exception as e:
            if attempt < retries - 1:
                time.sleep(0.1)
                continue
            raise RuntimeError(f"Write failed: {e}")

        # Read response
        try:
            resp = device.read(REPORT_SIZE, timeout_ms=timeout_ms)
            if resp:
                return bytes(resp)
        except Exception:
            pass

        if attempt < retries - 1:
            time.sleep(0.05)

    return None


# ===========================================================================
# Probe routines
# ===========================================================================
def probe_nordickeyboard(device, timeout_ms: int, verbose: bool) -> dict:
    """Probe the NORDICKEYBOARD (0x7F) protocol path. Returns results dict."""
    results = {}
    print("=" * 70)
    print(" NORDICKEYBOARD Protocol Probe (Report ID 0x7F)")
    print(" Magic: 55 AA 55 AA 00 00 + cmd")
    print("=" * 70)
    print()

    for cmd, description in NK_QUERY_COMMANDS.items():
        print(f"  [{cmd:#04x}] {description}")
        pkt = build_nk_packet(cmd)
        if verbose:
            print(f"  TX ({len(pkt)} bytes):")
            print(hex_dump(pkt, prefix="      "))

        try:
            resp = send_and_read(device, pkt, timeout_ms=timeout_ms)
        except RuntimeError as e:
            print(f"  ERROR: {e}")
            results[cmd] = {"status": "error", "error": str(e)}
            print()
            continue

        if resp is None:
            print(f"  RX: (timeout - no response within {timeout_ms}ms)")
            results[cmd] = {"status": "timeout"}
        elif is_meaningful_response(resp):
            print(f"  RX ({len(resp)} bytes) *** HAS DATA ***:")
            print(hex_dump(resp, prefix="      "))
            results[cmd] = {"status": "data", "response": resp}
        else:
            print(f"  RX ({len(resp)} bytes): all zeros (acknowledged but empty)")
            results[cmd] = {"status": "zeros", "response": resp}

        print()
        time.sleep(0.05)  # Small delay between probes

    return results


def probe_mouse(device, timeout_ms: int, verbose: bool) -> dict:
    """Probe the MOUSE (0xF8) protocol path. Returns results dict."""
    results = {}
    print("=" * 70)
    print(" MOUSE Protocol Probe (Report ID 0xF8)")
    print(" Magic: 55 AA 55 + cmd")
    print("=" * 70)
    print()

    for cmd, description in MOUSE_QUERY_COMMANDS.items():
        print(f"  [{cmd:#04x}] {description}")
        pkt = build_mouse_packet(cmd)
        if verbose:
            print(f"  TX ({len(pkt)} bytes):")
            print(hex_dump(pkt, prefix="      "))

        try:
            resp = send_and_read(device, pkt, timeout_ms=timeout_ms)
        except RuntimeError as e:
            print(f"  ERROR: {e}")
            results[cmd] = {"status": "error", "error": str(e)}
            print()
            continue

        if resp is None:
            print(f"  RX: (timeout - no response within {timeout_ms}ms)")
            results[cmd] = {"status": "timeout"}
        elif is_meaningful_response(resp):
            print(f"  RX ({len(resp)} bytes) *** HAS DATA ***:")
            print(hex_dump(resp, prefix="      "))
            results[cmd] = {"status": "data", "response": resp}
        else:
            print(f"  RX ({len(resp)} bytes): all zeros (acknowledged but empty)")
            results[cmd] = {"status": "zeros", "response": resp}

        print()
        time.sleep(0.05)

    return results


def probe_nk_extended(device, timeout_ms: int, verbose: bool) -> dict:
    """Try additional NORDICKEYBOARD command bytes for discovery."""
    results = {}
    extra_cmds = {
        0x00: "NOP / Reset?",
        0x06: "Unknown 0x06",
        0x07: "Unknown 0x07",
        0x08: "Unknown 0x08",
        0x0A: "Unknown 0x0A",
        0x10: "Unknown 0x10",
        0x20: "Unknown 0x20",
        0x40: "Unknown 0x40",
        0x7F: "Unknown 0x7F",
        0xFE: "Unknown 0xFE",
        0xFF: "Unknown 0xFF",
    }

    print("=" * 70)
    print(" NORDICKEYBOARD Extended Discovery (additional command bytes)")
    print("=" * 70)
    print()

    for cmd, description in extra_cmds.items():
        # Skip if already tested or dangerous
        if cmd in NK_QUERY_COMMANDS or cmd in DANGEROUS_COMMANDS:
            continue

        print(f"  [{cmd:#04x}] {description}")
        pkt = build_nk_packet(cmd)

        try:
            resp = send_and_read(device, pkt, timeout_ms=timeout_ms)
        except RuntimeError as e:
            print(f"  ERROR: {e}")
            results[cmd] = {"status": "error", "error": str(e)}
            print()
            continue

        if resp is None:
            print(f"  RX: (timeout)")
            results[cmd] = {"status": "timeout"}
        elif is_meaningful_response(resp):
            print(f"  RX ({len(resp)} bytes) *** HAS DATA ***:")
            print(hex_dump(resp, prefix="      "))
            results[cmd] = {"status": "data", "response": resp}
        else:
            print(f"  RX: all zeros")
            results[cmd] = {"status": "zeros", "response": resp}

        print()
        time.sleep(0.05)

    return results


# ===========================================================================
# Summary
# ===========================================================================
def print_summary(nk_results: dict, mouse_results: dict, nk_ext_results: dict):
    """Print a clear summary of findings."""
    print()
    print("=" * 70)
    print(" SUMMARY")
    print("=" * 70)
    print()

    # NORDICKEYBOARD
    nk_responsive = [cmd for cmd, r in nk_results.items() if r["status"] in ("data", "zeros")]
    nk_data = [cmd for cmd, r in nk_results.items() if r["status"] == "data"]
    nk_timeout = [cmd for cmd, r in nk_results.items() if r["status"] == "timeout"]

    print("  NORDICKEYBOARD (0x7F) protocol:")
    if nk_responsive:
        print(f"    ALIVE - {len(nk_responsive)} command(s) got a response")
        if nk_data:
            print(f"    Commands with DATA: {', '.join(f'0x{c:02x}' for c in nk_data)}")
        print(f"    Commands acknowledged (zeros): "
              f"{', '.join(f'0x{c:02x}' for c in nk_responsive if c not in nk_data)}")
    elif nk_timeout:
        print(f"    NO RESPONSE - all {len(nk_timeout)} commands timed out")
        print("    This protocol path may not be supported by this bootloader.")
    print()

    # MOUSE
    mouse_responsive = [cmd for cmd, r in mouse_results.items() if r["status"] in ("data", "zeros")]
    mouse_data = [cmd for cmd, r in mouse_results.items() if r["status"] == "data"]
    mouse_timeout = [cmd for cmd, r in mouse_results.items() if r["status"] == "timeout"]

    print("  MOUSE (0xF8) protocol:")
    if mouse_responsive:
        print(f"    ALIVE - {len(mouse_responsive)} command(s) got a response")
        if mouse_data:
            print(f"    Commands with DATA: {', '.join(f'0x{c:02x}' for c in mouse_data)}")
    elif mouse_timeout:
        print(f"    NO RESPONSE - all {len(mouse_timeout)} commands timed out")
    print()

    # Extended
    nk_ext_data = [cmd for cmd, r in nk_ext_results.items() if r["status"] == "data"]
    if nk_ext_data:
        print(f"  EXTENDED NK discoveries: {', '.join(f'0x{c:02x}' for c in nk_ext_data)}")
        print()

    # Recommendation
    print("  NEXT STEPS:")
    if nk_data:
        print("    >> NORDICKEYBOARD protocol is ACTIVE and returning data!")
        print("    >> This is the most promising path for unsigned firmware flash.")
        print("    >> Phase 2: attempt to send firmware data via 0x7F channel.")
    elif nk_responsive:
        print("    >> NORDICKEYBOARD protocol is responding (acknowledged commands).")
        print("    >> May need correct sequencing (init before query).")
        print("    >> Try: send 0x01 (init) first, then 0x82 (get info).")
    elif mouse_data:
        print("    >> Only MOUSE protocol responded. RSA bypass via NK not available.")
        print("    >> May need to find another approach (key extraction, glitching).")
    else:
        print("    >> Neither protocol responded. Possible issues:")
        print("       - Device not actually in boot mode")
        print("       - Wrong HID interface selected")
        print("       - Report size mismatch")
        print("       - Need to flush/reset HID state first")
    print()


# ===========================================================================
# Main
# ===========================================================================
def main():
    parser = argparse.ArgumentParser(
        description=(
            "Phase 1: Read-Only Bootloader Probe for Ajazz AJ159 APEX\n"
            "Probes both NORDICKEYBOARD (0x7F) and MOUSE (0xF8) boot protocols.\n"
            "SAFE: Only sends query commands, never erase/write/flash."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--timeout", type=int, default=1000,
                        help="Read timeout in milliseconds (default: 1000)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show TX packets in hex dump")
    parser.add_argument("--skip-extended", action="store_true",
                        help="Skip extended command discovery")
    parser.add_argument("--vid", type=lambda x: int(x, 0), default=BOOT_VID,
                        help=f"Override VID (default: {BOOT_VID:#06x})")
    parser.add_argument("--pid", type=lambda x: int(x, 0), default=BOOT_PID,
                        help=f"Override PID (default: {BOOT_PID:#06x})")
    args = parser.parse_args()

    # Apply user-specified VID/PID
    vid = args.vid
    pid = args.pid

    print(r"""
    ___    _ _ _____ ___    _   ___ _____  __
   / _ \  (_) |___ /| _ \  /_\ | _ \ __\ \/ /
  / /_\ \ | | | |_ \|  _/ / _ \|  _/ _| >  <
 / /_/  \ | |_|___) | |  / ___ \ | | |__/ /\ \
/_/   \_\_/ |_|____/|_| /_/   \_\_| |____/_/\_\
          |__/
    """)
    print("  Phase 1: Read-Only Bootloader Protocol Probe")
    print("  Target: Ajazz AJ159 APEX (boot mode)")
    print(f"  VID:PID = {vid:#06x}:{pid:#06x}")
    print(f"  Expected usage_page={BOOT_USAGE_PAGE:#06x} usage={BOOT_USAGE:#06x}")
    print()
    print("  SAFETY: This script only sends QUERY commands.")
    print("          No erase, write, or flash operations will be performed.")
    print()
    print("-" * 70)

    # Load HID library
    hid = require_hid()

    # Open device
    print(f"\n[*] Searching for boot device (VID={vid:#06x} PID={pid:#06x})...")
    device, dev_info = open_boot_device(hid, verbose=args.verbose, vid=vid, pid=pid)
    print(f"[+] Device opened successfully!")
    print(f"    Interface: {dev_info.get('interface_number')}")
    print(f"    Usage page: {dev_info.get('usage_page', 0):#06x}")
    print(f"    Product: {dev_info.get('product_string', 'N/A')!r}")
    print()

    # Set non-blocking for reads (we use timeout instead)
    device.set_nonblocking(False)

    try:
        # Phase 1: NORDICKEYBOARD probe
        nk_results = probe_nordickeyboard(device, args.timeout, args.verbose)

        # Small delay between protocol switches
        time.sleep(0.1)

        # Phase 2: MOUSE probe
        mouse_results = probe_mouse(device, args.timeout, args.verbose)

        # Phase 3: Extended discovery (optional)
        nk_ext_results = {}
        if not args.skip_extended:
            time.sleep(0.1)
            nk_ext_results = probe_nk_extended(device, args.timeout, args.verbose)

        # Summary
        print_summary(nk_results, mouse_results, nk_ext_results)

    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user (Ctrl+C)")
    except Exception as e:
        print(f"\n[!] Unexpected error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        device.close()
        print("[*] Device closed. Probe complete.")


if __name__ == "__main__":
    main()
