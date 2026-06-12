#!/usr/bin/env python3
"""
bootloader_probe.py - Phase 1: Multi-Transport Bootloader Protocol Probe
=========================================================================
Ajazz AJ159 APEX Gaming Mouse - Exhaustive HID Communication Discovery

WHAT THIS DOES
--------------
This script probes the AJ159's bootloader using EVERY possible HID
communication pattern to find where the device sends its responses.

KEY DISCOVERY (from prior attempts):
  - send_feature_report() SUCCEEDS (returns 65) = device IS receiving data
  - get_feature_report() returns all zeros = response is NOT on control pipe
  - hid_write + hid_read both timeout = not using output/input reports directly

HYPOTHESIS: The device uses a HYBRID transport:
  - SEND: via feature reports (SET_REPORT on control endpoint)
  - RECEIVE: via interrupt IN endpoint (device.read())

This is common in HID bootloaders where the host sends commands via control
transfers but the device pushes responses as input reports on the interrupt pipe.

TRANSPORT VARIANTS TESTED
--------------------------
1. HYBRID: send_feature_report() + device.read() [MOST LIKELY]
2. READ-FIRST: device.read() before sending anything (check buffered data)
3. FEATURE-ONLY: send_feature_report() + get_feature_report() (already failed)
4. OUTPUT+INPUT: hid_write() + device.read() (already failed, retry anyway)
5. REPORT ID 0x00: Some devices use no report ID or report ID 0
6. REPORT IDs 0x01, 0x02, 0x03: Common default report IDs
7. RAW MINIMAL: Just [report_id, 0x00...] to check if ANY read comes back

PROTOCOLS TESTED (for each transport):
  - NORDICKEYBOARD (Report ID 0x7F): Magic 55 AA 55 AA 00 00 + cmd
  - MOUSE (Report ID 0xF8): Magic 55 AA 55 + cmd

PREREQUISITES
-------------
  - Mouse MUST be in boot mode (VID 0x3151 / PID 0x4025)
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
BOOT_VID = 0x3151   # 12625 decimal - Ajazz/RuiYu VID
BOOT_PID = 0x4025   # 16421 decimal - boot mode PID
BOOT_USAGE_PAGE = 0xFF01
BOOT_USAGE = 0x01

REPORT_SIZE = 64     # Data payload is 64 bytes; feature reports are 65 (report_id + 64)

# ===========================================================================
# Protocol definitions
# ===========================================================================

# NORDICKEYBOARD protocol: Report ID 0x7F
NK_REPORT_ID = 0x7F
NK_MAGIC = [0x55, 0xAA, 0x55, 0xAA]
NK_PADDING = [0x00, 0x00]

# MOUSE protocol: Report ID 0xF8
MOUSE_REPORT_ID = 0xF8
MOUSE_MAGIC = [0x55, 0xAA, 0x55]

# Safe query commands only
NK_QUERY_COMMANDS = {
    0x82: "Get Boot Info (primary query)",
    0x01: "Init / Hello",
    0x02: "Get Status",
    0x80: "Start / Ping",
    0x81: "Get Version",
}

MOUSE_QUERY_COMMANDS = {
    0x82: "Get Boot ID (primary query)",
    0x80: "Ping / Hello",
    0x81: "Get Version",
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


def build_nk_packet(cmd: int, report_id: int = NK_REPORT_ID) -> bytes:
    """
    Build a 65-byte NORDICKEYBOARD query packet.
    Format: [report_id] [55 AA 55 AA 00 00 cmd] [zeros to pad to 65 total]
    """
    assert cmd not in DANGEROUS_COMMANDS, f"SAFETY: refusing to build dangerous cmd 0x{cmd:02x}"
    pkt = bytearray(REPORT_SIZE + 1)  # 65 bytes total
    pkt[0] = report_id
    pkt[1:5] = NK_MAGIC
    pkt[5:7] = NK_PADDING
    pkt[7] = cmd
    return bytes(pkt)


def build_mouse_packet(cmd: int, report_id: int = MOUSE_REPORT_ID) -> bytes:
    """
    Build a 65-byte MOUSE query packet.
    Format: [report_id] [55 AA 55 cmd] [zeros to pad to 65 total]
    """
    assert cmd not in DANGEROUS_COMMANDS, f"SAFETY: refusing to build dangerous cmd 0x{cmd:02x}"
    pkt = bytearray(REPORT_SIZE + 1)  # 65 bytes total
    pkt[0] = report_id
    pkt[1:4] = MOUSE_MAGIC
    pkt[4] = cmd
    return bytes(pkt)


def build_raw_packet(report_id: int, payload: list = None) -> bytes:
    """Build a 65-byte packet with just a report ID and optional payload."""
    pkt = bytearray(REPORT_SIZE + 1)
    pkt[0] = report_id
    if payload:
        for i, b in enumerate(payload[:REPORT_SIZE]):
            pkt[1 + i] = b
    return bytes(pkt)


def is_meaningful_response(data: Optional[list | bytes]) -> bool:
    """Check if a response contains any non-zero data."""
    if not data:
        return False
    raw = bytes(data) if not isinstance(data, bytes) else data
    # Check all bytes (including first, which might be report ID)
    return any(b != 0 for b in raw)


def is_meaningful_response_skip_first(data: Optional[list | bytes]) -> bool:
    """Check if a response contains any non-zero data beyond the first byte."""
    if not data:
        return False
    raw = bytes(data) if not isinstance(data, bytes) else data
    return any(b != 0 for b in raw[1:]) if len(raw) > 1 else False


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
        print(f"\nERROR: Boot device not found (VID={vid:#06x} PID={pid:#06x})")
        print("\nSearching all HID devices for Compx/RuiYu VIDs...")
        all_devs = hid_module.enumerate()
        found_any = False
        for d in all_devs:
            if d['vendor_id'] in (0x3151, 0x0C4F, 0x0C45, 3151):
                found_any = True
                print(f"  VID:{d['vendor_id']:#06x} PID:{d['product_id']:#06x} "
                      f"iface={d.get('interface_number')} "
                      f"usage_page={d.get('usage_page', 0):#06x} "
                      f"product={d.get('product_string', '')!r}")
        if not found_any:
            print("  (none found)")
        print("\nIs the mouse in boot mode? (PID should be 0x4025)")
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


# ===========================================================================
# Transport methods
# ===========================================================================

def transport_hybrid_feature_send_interrupt_read(device, packet: bytes,
                                                  timeout_ms: int = 1000,
                                                  verbose: bool = False) -> Optional[bytes]:
    """
    HYBRID transport: send via feature report, read via interrupt IN.

    This is the MOST LIKELY correct pattern for this bootloader:
      - Host sends command via SET_REPORT (control endpoint) = send_feature_report()
      - Device responds via interrupt IN endpoint = device.read()

    Many HID bootloaders work this way because:
      - The control endpoint (feature reports) is reliable for host->device
      - The interrupt pipe is efficient for device->host async responses
    """
    try:
        bytes_sent = device.send_feature_report(packet)
        if verbose:
            print(f"        send_feature_report returned: {bytes_sent}")
    except Exception as e:
        if verbose:
            print(f"        send_feature_report FAILED: {e}")
        return None

    # Give device time to process and queue response
    time.sleep(0.02)

    # Read from interrupt IN endpoint
    try:
        resp = device.read(REPORT_SIZE + 1, timeout_ms=timeout_ms)
        if resp:
            return bytes(resp)
    except Exception as e:
        if verbose:
            print(f"        device.read() error: {e}")

    return None


def transport_feature_only(device, packet: bytes, report_id: int,
                           timeout_ms: int = 1000,
                           verbose: bool = False) -> Optional[bytes]:
    """
    FEATURE-ONLY transport: send and receive via feature reports.
    (Already confirmed: send succeeds, get returns zeros. Kept for completeness.)
    """
    try:
        device.send_feature_report(packet)
    except Exception as e:
        if verbose:
            print(f"        send_feature_report FAILED: {e}")
        return None

    time.sleep(0.01)

    # Try get_feature_report with same and alternate report IDs
    for rid in [report_id, 0x7F, 0xF8, 0x01, 0x02, 0x00]:
        try:
            resp = device.get_feature_report(rid, REPORT_SIZE + 1)
            if resp and is_meaningful_response_skip_first(bytes(resp)):
                if verbose:
                    print(f"        get_feature_report(0x{rid:02x}) has data!")
                return bytes(resp)
        except Exception:
            pass

    return None


def transport_output_input(device, packet: bytes,
                           timeout_ms: int = 1000,
                           verbose: bool = False) -> Optional[bytes]:
    """
    OUTPUT/INPUT transport: send via hid_write, read via hid_read.
    (Previously timed out, but retrying with different packet formats.)
    """
    try:
        device.write(packet)
    except Exception as e:
        if verbose:
            print(f"        hid_write FAILED: {e}")
        return None

    time.sleep(0.02)

    try:
        resp = device.read(REPORT_SIZE + 1, timeout_ms=timeout_ms)
        if resp:
            return bytes(resp)
    except Exception as e:
        if verbose:
            print(f"        device.read() error: {e}")

    return None


def transport_read_only(device, timeout_ms: int = 1000,
                        verbose: bool = False) -> Optional[bytes]:
    """
    READ-FIRST: just read without sending anything.
    The device might have buffered data waiting from a previous send,
    or it might spontaneously send status reports.
    """
    try:
        resp = device.read(REPORT_SIZE + 1, timeout_ms=timeout_ms)
        if resp:
            return bytes(resp)
    except Exception as e:
        if verbose:
            print(f"        device.read() error: {e}")

    return None


# ===========================================================================
# Probe routines
# ===========================================================================

def probe_read_first(device, timeout_ms: int, verbose: bool) -> list:
    """
    VARIANT 1: Try reading FIRST before sending anything.
    The device might have buffered data from prior send_feature_report calls,
    or it might send periodic status reports on its own.
    """
    results = []
    print("=" * 70)
    print(" VARIANT 1: READ-FIRST (check for buffered/spontaneous data)")
    print(" Method: device.read() without sending anything first")
    print("=" * 70)
    print()

    # Try multiple reads in case there are multiple buffered reports
    for i in range(5):
        print(f"  Read attempt {i+1}/5 (timeout={timeout_ms}ms)...")
        resp = transport_read_only(device, timeout_ms=min(timeout_ms, 500),
                                   verbose=verbose)
        if resp and is_meaningful_response(resp):
            print(f"  *** GOT DATA *** ({len(resp)} bytes):")
            print(hex_dump(resp, prefix="      "))
            results.append({"attempt": i+1, "data": resp})
        else:
            print(f"  (no data)")
            # If first read is empty, subsequent ones likely are too
            if i == 0:
                # Do one more with longer timeout
                resp2 = transport_read_only(device, timeout_ms=timeout_ms,
                                            verbose=verbose)
                if resp2 and is_meaningful_response(resp2):
                    print(f"  *** GOT DATA on retry *** ({len(resp2)} bytes):")
                    print(hex_dump(resp2, prefix="      "))
                    results.append({"attempt": i+1, "data": resp2})
                break
        time.sleep(0.01)

    if not results:
        print("  Result: No buffered data found.")
    print()
    return results


def probe_hybrid(device, timeout_ms: int, verbose: bool) -> dict:
    """
    VARIANT 2 (MOST LIKELY): HYBRID transport.
    Send via send_feature_report(), receive via device.read().

    This is the expected pattern for bootloaders that:
      - Accept commands on the control endpoint (feature reports)
      - Send responses on the interrupt IN endpoint (input reports)
    """
    results = {}
    print("=" * 70)
    print(" VARIANT 2: HYBRID (send_feature_report + device.read)")
    print(" This is the MOST LIKELY correct transport pattern.")
    print(" send_feature_report() already confirmed working (returned 65).")
    print(" Hypothesis: response comes back on interrupt IN pipe.")
    print("=" * 70)
    print()

    # --- NORDICKEYBOARD protocol ---
    print("  --- NORDICKEYBOARD (Report ID 0x7F) ---")
    print()
    for cmd, description in NK_QUERY_COMMANDS.items():
        label = f"NK_0x{cmd:02x}"
        print(f"  [{cmd:#04x}] {description}")
        pkt = build_nk_packet(cmd)
        if verbose:
            print(f"  TX ({len(pkt)} bytes):")
            print(hex_dump(pkt, prefix="      "))

        resp = transport_hybrid_feature_send_interrupt_read(
            device, pkt, timeout_ms=timeout_ms, verbose=verbose)

        if resp and is_meaningful_response(resp):
            print(f"  *** RESPONSE *** ({len(resp)} bytes):")
            print(hex_dump(resp, prefix="      "))
            results[label] = {"status": "data", "response": resp, "cmd": cmd,
                              "protocol": "NK", "transport": "hybrid"}
        else:
            print(f"  (no response on interrupt read)")
            results[label] = {"status": "timeout", "cmd": cmd, "protocol": "NK"}
        print()
        time.sleep(0.05)

    # --- MOUSE protocol ---
    print("  --- MOUSE (Report ID 0xF8) ---")
    print()
    for cmd, description in MOUSE_QUERY_COMMANDS.items():
        label = f"MOUSE_0x{cmd:02x}"
        print(f"  [{cmd:#04x}] {description}")
        pkt = build_mouse_packet(cmd)
        if verbose:
            print(f"  TX ({len(pkt)} bytes):")
            print(hex_dump(pkt, prefix="      "))

        resp = transport_hybrid_feature_send_interrupt_read(
            device, pkt, timeout_ms=timeout_ms, verbose=verbose)

        if resp and is_meaningful_response(resp):
            print(f"  *** RESPONSE *** ({len(resp)} bytes):")
            print(hex_dump(resp, prefix="      "))
            results[label] = {"status": "data", "response": resp, "cmd": cmd,
                              "protocol": "MOUSE", "transport": "hybrid"}
        else:
            print(f"  (no response on interrupt read)")
            results[label] = {"status": "timeout", "cmd": cmd, "protocol": "MOUSE"}
        print()
        time.sleep(0.05)

    return results


def probe_alternate_report_ids(device, timeout_ms: int, verbose: bool) -> dict:
    """
    VARIANT 3: Try report IDs 0x00, 0x01, 0x02, 0x03.
    Some devices use report ID 0 (no report ID in descriptor) or common defaults.
    Test with both hybrid and feature-only transport.
    """
    results = {}
    print("=" * 70)
    print(" VARIANT 3: ALTERNATE REPORT IDs (0x00, 0x01, 0x02, 0x03)")
    print(" Some bootloaders use report ID 0 or standard low IDs.")
    print(" Testing both HYBRID and FEATURE-ONLY transport for each.")
    print("=" * 70)
    print()

    alt_report_ids = [0x00, 0x01, 0x02, 0x03]
    cmd = 0x82  # Primary query command

    for rid in alt_report_ids:
        print(f"  --- Report ID 0x{rid:02X} ---")
        print()

        # Test with NK magic
        label = f"RID{rid:#04x}_NK"
        print(f"    [NK magic + cmd 0x82] via report ID 0x{rid:02x}")
        pkt = build_nk_packet(cmd, report_id=rid)
        if verbose:
            print(f"    TX: {' '.join(f'{b:02x}' for b in pkt[:16])}...")

        # Hybrid first
        resp = transport_hybrid_feature_send_interrupt_read(
            device, pkt, timeout_ms=timeout_ms, verbose=verbose)
        if resp and is_meaningful_response(resp):
            print(f"    *** HYBRID RESPONSE *** ({len(resp)} bytes):")
            print(hex_dump(resp, prefix="        "))
            results[label + "_hybrid"] = {"status": "data", "response": resp}
        else:
            print(f"    (hybrid: no response)")
            results[label + "_hybrid"] = {"status": "timeout"}

        # Feature only
        resp2 = transport_feature_only(
            device, pkt, report_id=rid, timeout_ms=timeout_ms, verbose=verbose)
        if resp2 and is_meaningful_response_skip_first(resp2):
            print(f"    *** FEATURE RESPONSE *** ({len(resp2)} bytes):")
            print(hex_dump(resp2, prefix="        "))
            results[label + "_feature"] = {"status": "data", "response": resp2}
        else:
            print(f"    (feature: no response)")
            results[label + "_feature"] = {"status": "timeout"}
        print()

        # Test with MOUSE magic
        label = f"RID{rid:#04x}_MOUSE"
        print(f"    [MOUSE magic + cmd 0x82] via report ID 0x{rid:02x}")
        pkt = build_mouse_packet(cmd, report_id=rid)

        # Hybrid
        resp = transport_hybrid_feature_send_interrupt_read(
            device, pkt, timeout_ms=timeout_ms, verbose=verbose)
        if resp and is_meaningful_response(resp):
            print(f"    *** HYBRID RESPONSE *** ({len(resp)} bytes):")
            print(hex_dump(resp, prefix="        "))
            results[label + "_hybrid"] = {"status": "data", "response": resp}
        else:
            print(f"    (hybrid: no response)")
            results[label + "_hybrid"] = {"status": "timeout"}

        # Feature only
        resp2 = transport_feature_only(
            device, pkt, report_id=rid, timeout_ms=timeout_ms, verbose=verbose)
        if resp2 and is_meaningful_response_skip_first(resp2):
            print(f"    *** FEATURE RESPONSE *** ({len(resp2)} bytes):")
            print(hex_dump(resp2, prefix="        "))
            results[label + "_feature"] = {"status": "data", "response": resp2}
        else:
            print(f"    (feature: no response)")
            results[label + "_feature"] = {"status": "timeout"}
        print()

        # Test with NO magic (raw zeros after report ID)
        label = f"RID{rid:#04x}_RAW"
        print(f"    [RAW: just report ID + zeros] via report ID 0x{rid:02x}")
        pkt = build_raw_packet(rid)

        resp = transport_hybrid_feature_send_interrupt_read(
            device, pkt, timeout_ms=timeout_ms, verbose=verbose)
        if resp and is_meaningful_response(resp):
            print(f"    *** HYBRID RESPONSE *** ({len(resp)} bytes):")
            print(hex_dump(resp, prefix="        "))
            results[label + "_hybrid"] = {"status": "data", "response": resp}
        else:
            print(f"    (hybrid: no response)")
            results[label + "_hybrid"] = {"status": "timeout"}

        resp2 = transport_feature_only(
            device, pkt, report_id=rid, timeout_ms=timeout_ms, verbose=verbose)
        if resp2 and is_meaningful_response_skip_first(resp2):
            print(f"    *** FEATURE RESPONSE *** ({len(resp2)} bytes):")
            print(hex_dump(resp2, prefix="        "))
            results[label + "_feature"] = {"status": "data", "response": resp2}
        else:
            print(f"    (feature: no response)")
            results[label + "_feature"] = {"status": "timeout"}
        print()

        time.sleep(0.05)

    return results


def probe_raw_minimal(device, timeout_ms: int, verbose: bool) -> dict:
    """
    VARIANT 4: Send minimal/raw packets without protocol magic.
    Just report_id + zeros, or report_id + single command byte.
    The goal is to see if ANY read comes back regardless of content.
    """
    results = {}
    print("=" * 70)
    print(" VARIANT 4: RAW MINIMAL (no magic, just see if device talks back)")
    print(" Send simple packets and check if any response appears.")
    print("=" * 70)
    print()

    test_cases = [
        # (description, report_id, payload)
        ("0x7F + all zeros", 0x7F, []),
        ("0x7F + single 0x01", 0x7F, [0x01]),
        ("0x7F + single 0x82", 0x7F, [0x82]),
        ("0xF8 + all zeros", 0xF8, []),
        ("0xF8 + single 0x01", 0xF8, [0x01]),
        ("0xF8 + single 0x82", 0xF8, [0x82]),
        ("0x00 + all zeros", 0x00, []),
        ("0x01 + all zeros", 0x01, []),
        ("0x02 + all zeros", 0x02, []),
        ("0x7F + 0xFF fill", 0x7F, [0xFF] * 64),
    ]

    for desc, rid, payload in test_cases:
        label = f"RAW_{desc}"
        print(f"  [{desc}]")
        pkt = build_raw_packet(rid, payload)

        # Try hybrid (most likely)
        resp = transport_hybrid_feature_send_interrupt_read(
            device, pkt, timeout_ms=min(timeout_ms, 500), verbose=verbose)
        if resp and is_meaningful_response(resp):
            print(f"    *** HYBRID RESPONSE *** ({len(resp)} bytes):")
            print(hex_dump(resp, prefix="        "))
            results[label] = {"status": "data", "response": resp, "transport": "hybrid"}
        else:
            # Try output/input as last resort
            resp2 = transport_output_input(
                device, pkt, timeout_ms=min(timeout_ms, 300), verbose=verbose)
            if resp2 and is_meaningful_response(resp2):
                print(f"    *** OUTPUT/INPUT RESPONSE *** ({len(resp2)} bytes):")
                print(hex_dump(resp2, prefix="        "))
                results[label] = {"status": "data", "response": resp2,
                                  "transport": "output_input"}
            else:
                print(f"    (no response)")
                results[label] = {"status": "timeout"}
        print()
        time.sleep(0.03)

    return results


def probe_output_input_retry(device, timeout_ms: int, verbose: bool) -> dict:
    """
    VARIANT 5: Retry OUTPUT/INPUT with the main protocol packets.
    Previously failed but worth retrying since the device state may have changed
    after receiving our feature report sends.
    """
    results = {}
    print("=" * 70)
    print(" VARIANT 5: OUTPUT/INPUT RETRY (hid_write + device.read)")
    print(" Previously timed out, but device state may have changed.")
    print("=" * 70)
    print()

    # Try NK primary query
    print("  [NK 0x82 via hid_write]")
    pkt = build_nk_packet(0x82)
    resp = transport_output_input(device, pkt, timeout_ms=timeout_ms, verbose=verbose)
    if resp and is_meaningful_response(resp):
        print(f"  *** RESPONSE *** ({len(resp)} bytes):")
        print(hex_dump(resp, prefix="      "))
        results["NK_0x82_output"] = {"status": "data", "response": resp}
    else:
        print(f"  (no response)")
        results["NK_0x82_output"] = {"status": "timeout"}
    print()

    # Try MOUSE primary query
    print("  [MOUSE 0x82 via hid_write]")
    pkt = build_mouse_packet(0x82)
    resp = transport_output_input(device, pkt, timeout_ms=timeout_ms, verbose=verbose)
    if resp and is_meaningful_response(resp):
        print(f"  *** RESPONSE *** ({len(resp)} bytes):")
        print(hex_dump(resp, prefix="      "))
        results["MOUSE_0x82_output"] = {"status": "data", "response": resp}
    else:
        print(f"  (no response)")
        results["MOUSE_0x82_output"] = {"status": "timeout"}
    print()

    # Try with 64-byte packet (no report ID prefix) in case device expects raw
    print("  [NK 0x82 as 64-byte raw (no report ID byte)]")
    raw_pkt = bytearray(64)
    raw_pkt[0:4] = NK_MAGIC
    raw_pkt[4:6] = NK_PADDING
    raw_pkt[6] = 0x82
    try:
        device.write(bytes(raw_pkt))
        time.sleep(0.02)
        resp = device.read(REPORT_SIZE + 1, timeout_ms=timeout_ms)
        if resp and is_meaningful_response(bytes(resp)):
            print(f"  *** RESPONSE *** ({len(resp)} bytes):")
            print(hex_dump(bytes(resp), prefix="      "))
            results["NK_0x82_raw64"] = {"status": "data", "response": bytes(resp)}
        else:
            print(f"  (no response)")
            results["NK_0x82_raw64"] = {"status": "timeout"}
    except Exception as e:
        print(f"  (error: {e})")
        results["NK_0x82_raw64"] = {"status": "error", "error": str(e)}
    print()

    return results


def probe_feature_report_ids(device, timeout_ms: int, verbose: bool) -> dict:
    """
    VARIANT 6: Try get_feature_report with various report IDs.
    Even without sending first, some devices have feature reports with static data.
    Also try after sending via the confirmed-working send_feature_report.
    """
    results = {}
    print("=" * 70)
    print(" VARIANT 6: FEATURE REPORT ID SCAN")
    print(" Try get_feature_report() with IDs 0x00-0x03, 0x7F, 0xF8")
    print(" Both cold (no prior send) and warm (after send_feature_report)")
    print("=" * 70)
    print()

    scan_ids = [0x00, 0x01, 0x02, 0x03, 0x7F, 0xF8]

    # Cold read (no prior send)
    print("  --- Cold reads (get_feature_report without prior send) ---")
    print()
    for rid in scan_ids:
        label = f"COLD_feature_0x{rid:02x}"
        try:
            resp = device.get_feature_report(rid, REPORT_SIZE + 1)
            if resp and is_meaningful_response_skip_first(bytes(resp)):
                print(f"  Report ID 0x{rid:02x}: *** HAS DATA *** ({len(resp)} bytes)")
                print(hex_dump(bytes(resp), prefix="      "))
                results[label] = {"status": "data", "response": bytes(resp)}
            else:
                print(f"  Report ID 0x{rid:02x}: (zeros or empty)")
                results[label] = {"status": "zeros"}
        except Exception as e:
            print(f"  Report ID 0x{rid:02x}: error - {e}")
            results[label] = {"status": "error", "error": str(e)}
    print()

    # Warm read (send NK 0x82 first, then try reading various IDs)
    print("  --- Warm reads (after sending NK 0x82 via feature report) ---")
    print()
    pkt = build_nk_packet(0x82)
    try:
        device.send_feature_report(pkt)
        time.sleep(0.05)
    except Exception as e:
        print(f"  (send failed: {e})")
        return results

    for rid in scan_ids:
        label = f"WARM_feature_0x{rid:02x}"
        try:
            resp = device.get_feature_report(rid, REPORT_SIZE + 1)
            if resp and is_meaningful_response_skip_first(bytes(resp)):
                print(f"  Report ID 0x{rid:02x}: *** HAS DATA *** ({len(resp)} bytes)")
                print(hex_dump(bytes(resp), prefix="      "))
                results[label] = {"status": "data", "response": bytes(resp)}
            else:
                print(f"  Report ID 0x{rid:02x}: (zeros or empty)")
                results[label] = {"status": "zeros"}
        except Exception as e:
            print(f"  Report ID 0x{rid:02x}: error - {e}")
            results[label] = {"status": "error", "error": str(e)}
    print()

    # Also try interrupt read after the warm send
    print("  --- Interrupt read after warm send ---")
    resp = transport_read_only(device, timeout_ms=timeout_ms, verbose=verbose)
    if resp and is_meaningful_response(resp):
        print(f"  *** INTERRUPT DATA *** ({len(resp)} bytes):")
        print(hex_dump(resp, prefix="      "))
        results["WARM_interrupt"] = {"status": "data", "response": resp}
    else:
        print(f"  (no interrupt data)")
        results["WARM_interrupt"] = {"status": "timeout"}
    print()

    return results


# ===========================================================================
# Summary
# ===========================================================================
def print_summary(all_results: dict):
    """Print a clear summary of all findings across all transport variants."""
    print()
    print("=" * 70)
    print(" FINAL SUMMARY - ALL TRANSPORT VARIANTS")
    print("=" * 70)
    print()

    # Collect all responses that had actual data
    successes = []
    for variant_name, variant_results in all_results.items():
        if isinstance(variant_results, list):
            # read-first results
            for item in variant_results:
                successes.append((variant_name, "read_first", item.get("data")))
        elif isinstance(variant_results, dict):
            for key, result in variant_results.items():
                if isinstance(result, dict) and result.get("status") == "data":
                    successes.append((variant_name, key, result.get("response")))

    if successes:
        print(f"  *** {len(successes)} SUCCESSFUL RESPONSE(S) FOUND ***")
        print()
        for variant, key, data in successes:
            print(f"  VARIANT: {variant}")
            print(f"  KEY:     {key}")
            if data:
                print(f"  DATA ({len(data)} bytes):")
                print(hex_dump(data, prefix="      "))
            print()
        print("  CONCLUSION: The device IS responding! Use the transport variant")
        print("  that produced data for Phase 2 firmware operations.")
    else:
        print("  NO RESPONSES received from ANY transport variant.")
        print()
        print("  Possible explanations:")
        print("    1. Device requires a specific INIT SEQUENCE before it responds")
        print("       (e.g., a timing-sensitive handshake or specific byte pattern)")
        print("    2. Device is in a deeper sleep/error state than expected")
        print("    3. The HID descriptor defines different report sizes")
        print("    4. Response uses a completely different mechanism (raw USB bulk?)")
        print("    5. Device firmware is corrupted and bootloader is non-functional")
        print()
        print("  NEXT STEPS:")
        print("    - Try running with --timeout 5000 (longer wait)")
        print("    - USB packet capture (Wireshark + USBPcap) to see what the")
        print("      device actually sends on the wire after our commands")
        print("    - Try the ry_upgrade.exe tool under Wireshark to capture the")
        print("      exact transport it uses successfully")
    print()


# ===========================================================================
# Main
# ===========================================================================
def main():
    parser = argparse.ArgumentParser(
        description=(
            "Phase 1: Multi-Transport Bootloader Probe for Ajazz AJ159 APEX\n"
            "Tests ALL possible HID communication patterns to find device responses.\n"
            "SAFE: Only sends query commands, never erase/write/flash."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--timeout", type=int, default=1000,
                        help="Read timeout in milliseconds (default: 1000)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show detailed TX/RX info")
    parser.add_argument("--vid", type=lambda x: int(x, 0), default=BOOT_VID,
                        help=f"Override VID (default: {BOOT_VID:#06x})")
    parser.add_argument("--pid", type=lambda x: int(x, 0), default=BOOT_PID,
                        help=f"Override PID (default: {BOOT_PID:#06x})")
    parser.add_argument("--skip-slow", action="store_true",
                        help="Skip slower probe variants (feature scan, output/input retry)")
    args = parser.parse_args()

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
    print("  Phase 1: MULTI-TRANSPORT Bootloader Protocol Probe")
    print("  Target: Ajazz AJ159 APEX (boot mode)")
    print(f"  VID:PID = {vid:#06x}:{pid:#06x}")
    print(f"  Expected usage_page={BOOT_USAGE_PAGE:#06x} usage={BOOT_USAGE:#06x}")
    print(f"  Timeout: {args.timeout}ms per read attempt")
    print()
    print("  KEY DISCOVERY: send_feature_report() SUCCEEDS (returns 65)")
    print("  The device IS receiving our commands. We need to find WHERE")
    print("  it sends the response (interrupt pipe? different report ID?)")
    print()
    print("  SAFETY: This script only sends QUERY commands.")
    print("          No erase, write, or flash operations will be performed.")
    print()
    print("  TRANSPORT VARIANTS TO TEST:")
    print("    1. READ-FIRST (check for buffered data)")
    print("    2. HYBRID: send_feature_report + device.read [MOST LIKELY]")
    print("    3. ALTERNATE REPORT IDs (0x00, 0x01, 0x02, 0x03)")
    print("    4. RAW MINIMAL (no magic, just poke and listen)")
    print("    5. OUTPUT/INPUT RETRY (hid_write + device.read)")
    print("    6. FEATURE REPORT ID SCAN (get_feature_report with various IDs)")
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

    # Use blocking mode with timeouts for reads
    device.set_nonblocking(False)

    all_results = {}

    try:
        # === VARIANT 1: Read first (buffered data check) ===
        read_first_results = probe_read_first(device, args.timeout, args.verbose)
        all_results["READ_FIRST"] = read_first_results

        time.sleep(0.1)

        # === VARIANT 2: HYBRID (most likely correct) ===
        hybrid_results = probe_hybrid(device, args.timeout, args.verbose)
        all_results["HYBRID"] = hybrid_results

        time.sleep(0.1)

        # === VARIANT 3: Alternate report IDs ===
        alt_id_results = probe_alternate_report_ids(device, args.timeout, args.verbose)
        all_results["ALT_REPORT_IDS"] = alt_id_results

        time.sleep(0.1)

        # === VARIANT 4: Raw minimal ===
        raw_results = probe_raw_minimal(device, args.timeout, args.verbose)
        all_results["RAW_MINIMAL"] = raw_results

        if not args.skip_slow:
            time.sleep(0.1)

            # === VARIANT 5: Output/Input retry ===
            oi_results = probe_output_input_retry(device, args.timeout, args.verbose)
            all_results["OUTPUT_INPUT"] = oi_results

            time.sleep(0.1)

            # === VARIANT 6: Feature report ID scan ===
            feat_results = probe_feature_report_ids(device, args.timeout, args.verbose)
            all_results["FEATURE_SCAN"] = feat_results

        # === Final Summary ===
        print_summary(all_results)

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
