#!/usr/bin/env python3
"""
hid_fuzzer.py - Smart HID SET_REPORT Fuzzer for Ajazz AJ159 APEX Mouse
========================================================================

A comprehensive HID fuzzer targeting buffer overflow exploitation in the
AJ159 firmware. The SET_REPORT handler at 0x1C1A8 allocates only 60 bytes
on the stack (SUB SP, #0x3C) but receives 64-byte feature reports, creating
a potential stack buffer overflow of 4 bytes into saved registers.

Additionally, 5 dangerous memcpy sites copy varying lengths to stack buffers:
  - 0x12DD4: copies 70 bytes (10-byte overflow potential)
  - 0x14A7A: copies 94 bytes (34-byte overflow)
  - 0x1677A: copies 64 bytes (4-byte overflow, matches report size)
  - 0x1E4F0: copies 115 bytes (55-byte overflow)
  - 0x1EC4C: copies 115 bytes (55-byte overflow)

Architecture: ARM Cortex-M4F (nRF52840), Zephyr RTOS
  - No stack canaries
  - No ASLR (fixed flash addresses)
  - No XN by default (stack is executable)
  - Little-endian, Thumb mode

Target: VID 0x3151, PID 0x4026 (normal mode), Interface 2
Reports: 64-byte Feature Reports via SET_REPORT control endpoint

SAFETY: MCUboot swap design ensures device ALWAYS recovers from failed flash.
Worst case: watchdog reset -> reboot to boot mode (PID 0x4025) or normal mode.

PREREQUISITES:
  - Python 3.7+
  - pip install hidapi
  - Mouse in normal mode (PID 0x4026), plugged in via USB
  - Linux: run as root or configure udev rules (99-aj159.rules)

USAGE:
  python hid_fuzzer.py --strategy all                   # Run all strategies
  python hid_fuzzer.py --strategy overflow              # Only stack overflow test
  python hid_fuzzer.py --strategy sweep                 # Report ID sweep
  python hid_fuzzer.py --strategy vendor                # Vendor ID fuzzing
  python hid_fuzzer.py --strategy boundary              # Parameter boundary test
  python hid_fuzzer.py --strategy rapidfire             # Race condition test
  python hid_fuzzer.py --strategy overflow --delay 100  # Custom inter-packet delay
  python hid_fuzzer.py --start-id 0x13 --end-id 0x18   # Limit ID range
  python hid_fuzzer.py --log crash_log.json             # Save results to file
"""

from __future__ import annotations

import sys
import json
import time
import struct
import argparse
from datetime import datetime
from typing import Optional, List, Dict, Tuple, Any

# ===========================================================================
# Constants
# ===========================================================================

NORMAL_VID = 0x3151
NORMAL_PID = 0x4026
BOOT_PID = 0x4025
NORMAL_USAGE_PAGE = 0xFFFF
NORMAL_INTERFACE = 2

REPORT_SIZE = 64
REPORT_ID = 0x00

# Stack frame analysis (from 0x1C1A8: PUSH {R0-R7, LR}; SUB SP, #0x3C)
STACK_FRAME_SIZE = 0x3C  # 60 bytes allocated on stack
OVERFLOW_START = 60      # Bytes 60-63 overflow into saved registers
SAVED_REGS_SIZE = 36     # 9 registers * 4 bytes (R0-R7 + LR)

# Dangerous memcpy sites from firmware analysis
DANGEROUS_MEMCPY = {
    0x12DD4: {'size': 70, 'overflow': 10, 'desc': '70-byte copy to stack buffer'},
    0x14A7A: {'size': 94, 'overflow': 34, 'desc': '94-byte copy to stack buffer'},
    0x1677A: {'size': 64, 'overflow': 4, 'desc': '64-byte copy (matches report size)'},
    0x1E4F0: {'size': 115, 'overflow': 55, 'desc': '115-byte copy to stack buffer'},
    0x1EC4C: {'size': 115, 'overflow': 55, 'desc': '115-byte copy to stack buffer'},
}

# Known report IDs
KNOWN_IDS = [0x04, 0x05, 0x06, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18]
VENDOR_IDS = [0x13, 0x14, 0x15, 0x16, 0x17, 0x18]

# Fuzzing strategies
STRATEGIES = ['overflow', 'sweep', 'vendor', 'boundary', 'rapidfire']


# ===========================================================================
# De Bruijn Sequence Generator
# ===========================================================================

def de_bruijn(k: int, n: int) -> List[int]:
    """
    Generate a De Bruijn sequence for alphabet size k, subsequence length n.
    Used to identify exact overflow offsets in crash analysis.

    For k=256, n=4: generates a sequence where every 4-byte subsequence is unique.
    This lets us identify the exact offset that overwrites a register by examining
    the register value after a crash.
    """
    alphabet = list(range(k))
    a = [0] * (k * n)
    sequence = []

    def db(t, p):
        if t > n:
            if n % p == 0:
                sequence.extend(a[1:p + 1])
        else:
            a[t] = a[t - p]
            db(t + 1, p)
            for j in range(a[t - p] + 1, k):
                a[t] = j
                db(t + 1, t)

    db(1, 1)
    return sequence


def generate_pattern(length: int) -> bytes:
    """
    Generate a cyclic pattern (simplified De Bruijn) for identifying crash offsets.
    Uses a 3-character alphabet cycling to create unique 4-byte sequences.

    Pattern format: Aa0Aa1Aa2...Ba0Ba1...
    Each 4-byte window is unique, allowing crash register analysis.
    """
    pattern = bytearray()
    # Use uppercase + lowercase + digit cycling for readability
    upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    lower = 'abcdefghijklmnopqrstuvwxyz'
    digits = '0123456789'

    for u in upper:
        for l in lower:
            for d in digits:
                pattern.extend([ord(u), ord(l), ord(d), ord(d)])
                if len(pattern) >= length:
                    return bytes(pattern[:length])

    # If we need more, extend with raw bytes
    while len(pattern) < length:
        idx = len(pattern)
        pattern.append(idx & 0xFF)

    return bytes(pattern[:length])


def find_pattern_offset(pattern: bytes, value: int) -> int:
    """
    Find the offset of a 4-byte value within a cyclic pattern.
    Used after a crash to identify which pattern bytes overwrote a register.

    Args:
        pattern: The full pattern that was sent
        value: The 32-bit register value found after crash (little-endian)

    Returns:
        Offset in the pattern, or -1 if not found
    """
    needle = struct.pack('<I', value)
    idx = pattern.find(needle)
    return idx


# ===========================================================================
# HID Helpers
# ===========================================================================

def require_hid():
    """Import and return the hid module."""
    try:
        import hid
        return hid
    except ImportError:
        sys.exit(
            "ERROR: The 'hidapi' package is required.\n"
            "Install with: pip install hidapi\n"
            "\n"
            "On Linux you may also need: sudo apt install libhidapi-dev"
        )


def find_device(hid_module, vid: int, pid: int) -> Optional[dict]:
    """Find device by VID/PID on the vendor interface."""
    devices = hid_module.enumerate(vid, pid)
    if not devices:
        return None

    for d in devices:
        if (d.get('usage_page') == NORMAL_USAGE_PAGE and
                d.get('interface_number') == NORMAL_INTERFACE):
            return d

    for d in devices:
        if d.get('interface_number') == NORMAL_INTERFACE:
            return d

    for d in devices:
        up = d.get('usage_page', 0)
        if up >= 0xFF00:
            return d

    return devices[0] if devices else None


def open_device(hid_module):
    """Open normal-mode device."""
    dev_info = find_device(hid_module, NORMAL_VID, NORMAL_PID)
    if not dev_info:
        print(f"\nERROR: Device not found (VID={NORMAL_VID:#06x} PID={NORMAL_PID:#06x})")
        print("Is the mouse in normal mode? If in boot mode (PID 0x4025), power cycle it.")
        sys.exit(1)

    print(f"[*] Opened: VID={dev_info['vendor_id']:#06x} "
          f"PID={dev_info['product_id']:#06x} "
          f"iface={dev_info.get('interface_number')}")

    h = hid_module.device()
    try:
        h.open_path(dev_info['path'])
    except Exception as e:
        sys.exit(f"ERROR: Cannot open device: {e}\n"
                 "  Linux: Run with sudo or install udev rules")
    return h


def check_device_alive(device) -> bool:
    """Quick check if device responds to GET_REPORT."""
    try:
        resp = device.get_feature_report(0x04, REPORT_SIZE + 1)
        return resp is not None and len(resp) > 0
    except Exception:
        return False


def wait_for_device(hid_module, timeout_s: float = 10.0) -> Optional[str]:
    """
    Wait for device to re-enumerate after a crash.
    Returns 'normal' if PID 0x4026 appears, 'boot' if PID 0x4025 appears,
    or None if timeout.
    """
    start = time.time()
    while time.time() - start < timeout_s:
        # Check normal mode
        if find_device(hid_module, NORMAL_VID, NORMAL_PID):
            return 'normal'
        # Check boot mode
        if find_device(hid_module, NORMAL_VID, BOOT_PID):
            return 'boot'
        time.sleep(0.5)
    return None


# ===========================================================================
# Fuzzing Strategies
# ===========================================================================

class FuzzResult:
    """Result of a single fuzz attempt."""

    def __init__(self, strategy: str, report_id: int, payload: bytes):
        self.strategy = strategy
        self.report_id = report_id
        self.payload = payload
        self.sent_ok = False
        self.response = None
        self.device_alive = True
        self.crash_type = None  # 'soft', 'hard', 'hang'
        self.timestamp = datetime.now().isoformat()
        self.notes = ''

    def to_dict(self) -> Dict[str, Any]:
        return {
            'strategy': self.strategy,
            'report_id': self.report_id,
            'report_id_hex': f'0x{self.report_id:02X}',
            'payload_hex': self.payload.hex(),
            'payload_len': len(self.payload),
            'sent_ok': self.sent_ok,
            'response_hex': self.response.hex() if self.response else None,
            'device_alive': self.device_alive,
            'crash_type': self.crash_type,
            'timestamp': self.timestamp,
            'notes': self.notes,
        }


def send_fuzz_payload(device, report_id: int, payload: bytes,
                      strategy: str) -> FuzzResult:
    """Send a fuzz payload and check for crash."""
    result = FuzzResult(strategy, report_id, payload)

    # Build the full send buffer: [0x00 report ID prefix] + [64-byte payload]
    send_buf = bytes([REPORT_ID]) + payload
    assert len(send_buf) == REPORT_SIZE + 1

    try:
        n = device.send_feature_report(send_buf)
        result.sent_ok = n > 0
    except Exception as e:
        result.sent_ok = False
        result.notes = f"send error: {e}"
        # Send failure might indicate crash already
        result.device_alive = False
        return result

    # Brief pause for processing
    time.sleep(0.01)

    # Check if device is still alive
    result.device_alive = check_device_alive(device)

    if result.device_alive:
        # Try to read response
        try:
            resp = device.get_feature_report(report_id, REPORT_SIZE + 1)
            if resp and len(resp) > 1:
                result.response = bytes(resp[1:])
        except Exception:
            pass
    else:
        result.crash_type = 'detected'

    return result


def strategy_overflow(device, delay_ms: float, start_id: int,
                      end_id: int, verbose: bool) -> List[FuzzResult]:
    """
    STRATEGY 1 - Length overflow targeting saved registers.

    The SET_REPORT handler at 0x1C1A8:
      PUSH {R0-R7, LR}    ; saves 9 regs = 36 bytes to stack
      SUB SP, #0x3C        ; allocates 60 bytes (0x3C) local storage

    Stack layout (high to low):
      [caller frame]
      [saved LR]           <- offset 60+32 = 92 from SP (after SUB)
      [saved R7..R0]       <- offset 60+0..60+28
      [local buf: 60 bytes] <- SP points here

    When 64 bytes are written to the local buffer:
      bytes 0-59:  fill the local buffer
      bytes 60-63: overflow into saved R0 (first PUSH register)

    This strategy crafts the overflow bytes (60-63) with various values
    to test register corruption.
    """
    results = []
    pattern = generate_pattern(REPORT_SIZE)

    print(f"\n  [STRATEGY 1] Stack overflow - targeting bytes 60-63")
    print(f"  Stack frame: 60 bytes (SUB SP, #0x3C)")
    print(f"  Overflow target: saved R0 at SP+60")
    print(f"  Testing report IDs: 0x{start_id:02X} to 0x{end_id:02X}")
    print()

    # Test cases for the overflow bytes
    overflow_patterns = [
        (b'\x41\x41\x41\x41', "AAAA (detect in register dump)"),
        (b'\x00\x00\x00\x00', "NULL (test null deref)"),
        (b'\xFF\xFF\xFF\xFF', "0xFFFFFFFF (invalid address)"),
        (b'\x00\x00\x01\x20', "0x20010000 (RAM start, LE)"),
        (b'\x00\x80\x01\x20', "0x20018000 (RAM mid)"),
        (b'\x00\x00\x00\x10', "0x10000000 (Flash start)"),
        (b'\xFE\xFF\xFF\x7F', "0x7FFFFFFE (max positive)"),
        # De Bruijn pattern for exact offset identification
        (pattern[60:64], f"Pattern bytes 60-63: {pattern[60:64].hex()}"),
    ]

    target_ids = [i for i in KNOWN_IDS if start_id <= i <= end_id]

    for rid in target_ids:
        for overflow_bytes, desc in overflow_patterns:
            # Build payload: valid structure in bytes 0-59, overflow in 60-63
            payload = bytearray(REPORT_SIZE)
            payload[0] = rid
            payload[1] = REPORT_SIZE
            payload[2] = 0x01  # Valid sub-command

            # Fill body with pattern for offset identification
            for i in range(3, OVERFLOW_START):
                payload[i] = pattern[i]

            # The critical overflow bytes
            payload[OVERFLOW_START:OVERFLOW_START + 4] = overflow_bytes

            result = send_fuzz_payload(device, rid, bytes(payload), 'overflow')
            result.notes = f"overflow={desc}"
            results.append(result)

            if verbose:
                status = "ALIVE" if result.device_alive else "CRASH!"
                print(f"    ID=0x{rid:02X} overflow={overflow_bytes.hex()} "
                      f"-> {status}")

            if not result.device_alive:
                print(f"\n    [!!!] CRASH with overflow bytes: {desc}")
                print(f"         Report ID: 0x{rid:02X}")
                print(f"         Payload: {bytes(payload).hex()}")
                return results

            time.sleep(delay_ms / 1000.0)

    return results


def strategy_sweep(device, delay_ms: float, start_id: int,
                   end_id: int, verbose: bool) -> List[FuzzResult]:
    """
    STRATEGY 2 - Report ID sweep with De Bruijn pattern.

    Sends each report ID (0x00-0xEF or specified range) with a full
    64-byte De Bruijn pattern. This tests all possible dispatch paths
    and allows crash offset identification from register values.
    """
    results = []
    pattern = generate_pattern(REPORT_SIZE)

    print(f"\n  [STRATEGY 2] Report ID sweep with De Bruijn pattern")
    print(f"  Range: 0x{start_id:02X} to 0x{end_id:02X}")
    print(f"  Pattern: {pattern[:8].hex()}... (cyclic, unique 4-byte windows)")
    print()

    # Limit sweep to valid range (report_id <= 0xEF per validation gate)
    actual_end = min(end_id, 0xEF)
    total = actual_end - start_id + 1
    crashes = 0

    for idx, rid in enumerate(range(start_id, actual_end + 1)):
        # Build payload with report ID as first byte, rest is pattern
        payload = bytearray(REPORT_SIZE)
        payload[0] = rid
        payload[1:] = pattern[1:REPORT_SIZE]

        result = send_fuzz_payload(device, rid, bytes(payload), 'sweep')
        results.append(result)

        if verbose and (idx % 16 == 0 or not result.device_alive):
            status = "ALIVE" if result.device_alive else "CRASH!"
            print(f"    ID=0x{rid:02X} ({idx+1}/{total}) -> {status}")

        if not result.device_alive:
            crashes += 1
            print(f"\n    [!!!] CRASH at report ID 0x{rid:02X}")
            print(f"         De Bruijn pattern sent - check crash registers")
            print(f"         Use find_pattern_offset() to identify overflow offset")
            return results

        time.sleep(delay_ms / 1000.0)

    print(f"    Sweep complete: {total} IDs tested, {crashes} crashes")
    return results


def strategy_vendor(device, delay_ms: float, start_id: int,
                    end_id: int, verbose: bool) -> List[FuzzResult]:
    """
    STRATEGY 3 - Vendor report ID fuzzing (0x13-0x18).

    These IDs use the least-tested code paths. The firmware has special
    dispatch at 0x17E1E for IDs 0x13 and 0x17 (indirect function call
    through pointer chain). Other vendor IDs (0x14-0x16, 0x18) may have
    similarly interesting behavior.

    Tests:
      - All 0xFF (max values in every field)
      - All 0x00 (null/zero in every field)
      - Incrementing bytes (position detection)
      - Max values in specific field positions
      - Mixed patterns targeting validation boundaries
    """
    results = []

    vendor_ids = [i for i in VENDOR_IDS if start_id <= i <= end_id]

    print(f"\n  [STRATEGY 3] Vendor report ID fuzzing")
    print(f"  Target IDs: {', '.join(f'0x{i:02X}' for i in vendor_ids)}")
    print(f"  Special dispatch (0x13, 0x17): indirect call at 0x17E2C")
    print()

    # Payload patterns to test
    payload_generators = [
        ('all_ff', lambda rid: bytes([rid]) + bytes([0xFF] * 63)),
        ('all_00', lambda rid: bytes([rid]) + bytes([0x00] * 63)),
        ('incrementing', lambda rid: bytes([rid]) + bytes(range(1, 64))),
        ('decrementing', lambda rid: bytes([rid]) + bytes(range(63, 0, -1))),
        ('alternating', lambda rid: bytes([rid]) + bytes([0xAA, 0x55] * 31 + [0xAA])),
        ('max_fields', lambda rid: bytes([rid, 0xFF, 0x03, 0x01] +
                                         [0xFF] * 24 + [0x04, 0x00, 0x00, 0x00] +
                                         [0x0F] + [0xFF] * 31)),
        ('trigger_deferred', lambda rid: bytes([rid, 0x40, 0x01] + [0xCC] * 61)),
        ('ptr_overwrite', lambda rid: bytes([rid] + [0x00] * 59 +
                                            [0x00, 0x00, 0x02, 0x20])),
    ]

    for rid in vendor_ids:
        special = " [SPECIAL DISPATCH]" if rid in [0x13, 0x17] else ""
        if verbose:
            print(f"    --- Report ID 0x{rid:02X}{special} ---")

        for pattern_name, generator in payload_generators:
            payload = generator(rid)
            # Ensure exactly 64 bytes
            if len(payload) < REPORT_SIZE:
                payload = payload + bytes(REPORT_SIZE - len(payload))
            elif len(payload) > REPORT_SIZE:
                payload = payload[:REPORT_SIZE]

            result = send_fuzz_payload(device, rid, payload, 'vendor')
            result.notes = f"pattern={pattern_name}"
            results.append(result)

            if verbose:
                status = "OK" if result.device_alive else "CRASH!"
                print(f"      {pattern_name:20s} -> {status}")

            if not result.device_alive:
                print(f"\n    [!!!] CRASH with pattern '{pattern_name}' "
                      f"on ID 0x{rid:02X}{special}")
                print(f"         Payload: {payload.hex()}")
                return results

            time.sleep(delay_ms / 1000.0)

        if verbose:
            print()

    return results


def strategy_boundary(device, delay_ms: float, start_id: int,
                      end_id: int, verbose: bool) -> List[FuzzResult]:
    """
    STRATEGY 4 - Parameter boundary testing.

    The validation gate at 0x1C1A8 checks specific payload fields:
      - sp+0x64 (byte offset ~4): must be <= 3
      - sp+0x68 (byte offset ~8): must be <= 1
      - sp+0x80 (byte offset ~28): must be between 1 and 4
      - sp+0x84 (byte offset ~32): must be <= 0xF

    This strategy passes validation with maximum valid values to reach
    the deepest code paths, then tests one-off boundary violations.
    """
    results = []

    target_ids = [i for i in KNOWN_IDS if start_id <= i <= end_id]

    print(f"\n  [STRATEGY 4] Parameter boundary testing")
    print(f"  Validation gate checks (firmware at 0x1C1A8):")
    print(f"    sp+0x64 <= 3  |  sp+0x68 <= 1  |  sp+0x80: 1-4  |  sp+0x84 <= 0xF")
    print(f"  Testing both valid-max and boundary-violation payloads")
    print()

    # Approximate byte offsets for validation fields
    # (stack frame mapping: sp+0x3C is start of buffer after SUB SP, #0x3C)
    # sp+0x64 = buffer_start + 0x28 = byte 40
    # sp+0x68 = buffer_start + 0x2C = byte 44
    # sp+0x80 = buffer_start + 0x44 = byte 56 (actually beyond 60-byte frame!)
    # sp+0x84 = buffer_start + 0x48 = byte 60 (overflow region!)
    # NOTE: Offsets are approximate - the exact mapping depends on compiler layout

    # We try multiple possible offset interpretations
    field_offset_candidates = [
        # Interpretation 1: direct offset from buffer start
        {'sp_64': 4, 'sp_68': 8, 'sp_80': 28, 'sp_84': 32},
        # Interpretation 2: relative to payload after report_id
        {'sp_64': 5, 'sp_68': 9, 'sp_80': 29, 'sp_84': 33},
        # Interpretation 3: accounting for stack frame layout
        {'sp_64': 40, 'sp_68': 44, 'sp_80': 56, 'sp_84': 60},
    ]

    boundary_tests = [
        # (field_name, valid_value, invalid_values, description)
        ('sp_64', 3, [4, 5, 0xFF, 128], 'sp+0x64 boundary (max valid=3)'),
        ('sp_68', 1, [2, 3, 0xFF, 128], 'sp+0x68 boundary (max valid=1)'),
        ('sp_80', 4, [0, 5, 6, 0xFF], 'sp+0x80 boundary (valid=1-4)'),
        ('sp_84', 0xF, [0x10, 0x11, 0xFF, 0x80], 'sp+0x84 boundary (max valid=0xF)'),
    ]

    for interp_idx, offsets in enumerate(field_offset_candidates):
        if verbose:
            print(f"    --- Offset interpretation {interp_idx + 1} ---")

        for rid in target_ids:
            # First: payload with ALL fields at maximum valid values
            payload = bytearray(REPORT_SIZE)
            payload[0] = rid
            payload[1] = REPORT_SIZE
            payload[2] = 0x01

            # Set all validation fields to max valid
            for field_name, valid_val, _, _ in boundary_tests:
                offset = offsets[field_name]
                if offset < REPORT_SIZE:
                    payload[offset] = valid_val

            result = send_fuzz_payload(device, rid, bytes(payload), 'boundary')
            result.notes = f"interp={interp_idx} all_max_valid"
            results.append(result)

            if not result.device_alive:
                print(f"    [!!!] CRASH with max-valid payload, ID=0x{rid:02X}")
                return results

            # Then test each boundary violation individually
            for field_name, valid_val, invalid_vals, desc in boundary_tests:
                offset = offsets[field_name]
                if offset >= REPORT_SIZE:
                    continue

                for invalid_val in invalid_vals:
                    test_payload = bytearray(payload)  # Start from valid base
                    test_payload[offset] = invalid_val

                    result = send_fuzz_payload(device, rid, bytes(test_payload),
                                              'boundary')
                    result.notes = (f"interp={interp_idx} "
                                    f"{field_name}={invalid_val:#x} (valid={valid_val})")
                    results.append(result)

                    if verbose:
                        status = "OK" if result.device_alive else "CRASH!"
                        print(f"      ID=0x{rid:02X} {field_name}="
                              f"{invalid_val:#04x} -> {status}")

                    if not result.device_alive:
                        print(f"\n    [!!!] CRASH on boundary violation!")
                        print(f"         Field: {desc}")
                        print(f"         Value: {invalid_val:#x} "
                              f"(valid max: {valid_val})")
                        print(f"         Offset in payload: byte {offset}")
                        return results

                    time.sleep(delay_ms / 1000.0)

    return results


def strategy_rapidfire(device, delay_ms: float, start_id: int,
                       end_id: int, verbose: bool) -> List[FuzzResult]:
    """
    STRATEGY 5 - Rapid-fire sending (race condition / queue overflow).

    Sends reports faster than the deferred handler can process them.
    The common handler at 0x21D44 sets bit 6 of a control register to
    trigger deferred processing. If we send faster than processing,
    we may overflow a processing queue or trigger a race condition.

    Specifically targets:
      - Queue overflow: fill pending report queue
      - Race condition: new SET_REPORT while deferred handler is mid-process
      - State corruption: interleave different report IDs rapidly
    """
    results = []

    target_ids = [i for i in KNOWN_IDS if start_id <= i <= end_id]

    print(f"\n  [STRATEGY 5] Rapid-fire sending (race condition test)")
    print(f"  Sending reports with NO delay between packets")
    print(f"  Targets: queue overflow, race conditions, state corruption")
    print()

    # Test 1: Burst same ID (queue overflow)
    print(f"    Test 1: Burst same ID (50 packets, no delay)")
    for rid in target_ids[:3]:  # Test first 3 IDs
        payload = bytearray(REPORT_SIZE)
        payload[0] = rid
        payload[1] = REPORT_SIZE
        payload[2] = 0x01

        burst_count = 50
        for i in range(burst_count):
            # Vary a byte so each packet is slightly different
            payload[3] = i & 0xFF
            result = send_fuzz_payload(device, rid, bytes(payload), 'rapidfire')
            result.notes = f"burst_same_id={rid:#x} packet={i}"
            results.append(result)

            if not result.device_alive:
                print(f"      [!!!] CRASH after {i+1} rapid packets to ID 0x{rid:02X}")
                return results
            # NO delay - that is the point

        if verbose:
            print(f"      ID=0x{rid:02X}: {burst_count} packets sent, device alive")

    # Test 2: Interleave different IDs (state corruption)
    print(f"    Test 2: Rapid interleave of different IDs")
    interleave_count = 100
    for i in range(interleave_count):
        rid = target_ids[i % len(target_ids)]
        payload = bytearray(REPORT_SIZE)
        payload[0] = rid
        payload[1] = REPORT_SIZE
        payload[2] = 0x01
        payload[3] = i & 0xFF

        result = send_fuzz_payload(device, rid, bytes(payload), 'rapidfire')
        result.notes = f"interleave packet={i} id={rid:#x}"
        results.append(result)

        if not result.device_alive:
            print(f"      [!!!] CRASH after {i+1} interleaved packets "
                  f"(last ID: 0x{rid:02X})")
            return results

    if verbose:
        print(f"      {interleave_count} interleaved packets sent, device alive")

    # Test 3: Alternating SET/GET without pauses
    print(f"    Test 3: Rapid SET+GET alternation (timing attack)")
    for rid in target_ids[:3]:
        payload = bytearray(REPORT_SIZE)
        payload[0] = rid
        payload[1] = REPORT_SIZE
        payload[2] = 0x01

        for i in range(30):
            try:
                device.send_feature_report(bytes([REPORT_ID]) + bytes(payload))
                device.get_feature_report(rid, REPORT_SIZE + 1)
            except Exception:
                pass

            payload[3] = (i + 1) & 0xFF

        alive = check_device_alive(device)
        if not alive:
            print(f"      [!!!] CRASH during rapid SET+GET on ID 0x{rid:02X}")
            result = FuzzResult('rapidfire', rid, bytes(payload))
            result.device_alive = False
            result.crash_type = 'detected'
            result.notes = "rapid SET+GET alternation"
            results.append(result)
            return results

        if verbose:
            print(f"      ID=0x{rid:02X}: rapid SET+GET OK")

    return results


# ===========================================================================
# Main
# ===========================================================================

def main():
    parser = argparse.ArgumentParser(
        description="AJ159 APEX - Smart HID SET_REPORT Fuzzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Fuzzing strategies:
  overflow   - Stack buffer overflow (bytes 60-63 into saved registers)
  sweep      - Report ID sweep with De Bruijn pattern (offset detection)
  vendor     - Vendor-specific ID fuzzing (0x13-0x18, special dispatch)
  boundary   - Validation gate boundary testing (max/invalid field values)
  rapidfire  - Race condition / queue overflow (no inter-packet delay)
  all        - Run all strategies in sequence

Firmware vulnerability summary:
  - SET_REPORT handler: 60-byte stack buffer for 64-byte input
  - 5 dangerous memcpy sites with 4-55 byte overflow potential
  - No stack canaries, no ASLR, executable stack
  - ARM Cortex-M4F Thumb mode, little-endian

SAFETY: MCUboot swap design means device ALWAYS recovers.
  - Soft crash: watchdog reset -> normal mode (PID 0x4026)
  - Hard crash: -> boot mode (PID 0x4025)
  - Recovery: unplug/replug USB cable

Examples:
  %(prog)s --strategy overflow                    # Test stack overflow
  %(prog)s --strategy all --delay 50              # All strategies, 50ms delay
  %(prog)s --strategy vendor --start-id 0x13      # Vendor IDs from 0x13
  %(prog)s --strategy sweep --log fuzz.json       # Sweep with JSON logging
        """
    )
    parser.add_argument(
        '--strategy', type=str, default='all',
        choices=STRATEGIES + ['all'],
        help='Fuzzing strategy to use (default: all)'
    )
    parser.add_argument(
        '--delay', type=float, default=20.0,
        help='Delay in ms between fuzz packets (default: 20, 0 for rapidfire)'
    )
    parser.add_argument(
        '--start-id', type=lambda x: int(x, 0), default=0x00,
        help='Starting report ID for sweep (default: 0x00)'
    )
    parser.add_argument(
        '--end-id', type=lambda x: int(x, 0), default=0xEF,
        help='Ending report ID for sweep (default: 0xEF, max valid per gate)'
    )
    parser.add_argument(
        '--log', type=str, default=None,
        help='Save fuzz results to JSON log file'
    )
    parser.add_argument(
        '-v', '--verbose', action='store_true',
        help='Verbose output for each fuzz attempt'
    )
    parser.add_argument(
        '--dry-run', action='store_true',
        help='Show what would be sent without actually connecting'
    )

    args = parser.parse_args()

    print()
    print("=" * 70)
    print("  AJ159 APEX - Smart HID SET_REPORT Fuzzer")
    print("  Target: VID 0x3151, PID 0x4026 (normal mode), Interface 2")
    print("=" * 70)
    print()
    print("  WARNING: This tool intentionally sends malformed data to trigger")
    print("  crashes. The MCUboot swap design ensures the device always recovers.")
    print("  If the mouse stops responding: unplug/replug USB to reset.")
    print()
    print(f"  Strategy: {args.strategy}")
    print(f"  Delay: {args.delay}ms between packets")
    print(f"  ID range: 0x{args.start_id:02X} - 0x{args.end_id:02X}")
    print()

    if args.dry_run:
        print("  [DRY RUN] Showing sample payloads without connecting:")
        print()
        pattern = generate_pattern(REPORT_SIZE)
        print(f"  De Bruijn pattern (64 bytes):")
        print(f"    {pattern.hex()}")
        print(f"  Overflow bytes (60-63): {pattern[60:64].hex()}")
        print()
        print("  Stack frame layout at 0x1C1A8:")
        print("    PUSH {R0-R7, LR}  -> 36 bytes saved")
        print("    SUB SP, #0x3C     -> 60 bytes local")
        print("    Buffer: SP+0 to SP+59")
        print("    Overflow: SP+60 -> saved R0")
        print("    Overflow: SP+64 -> saved R1")
        print("    ...")
        print("    Overflow: SP+92 -> saved LR (return address!)")
        print()
        print(f"  Dangerous memcpy sites:")
        for addr, info in DANGEROUS_MEMCPY.items():
            print(f"    0x{addr:05X}: {info['desc']} "
                  f"(overflow: {info['overflow']} bytes)")
        return

    # Connect to device
    hid = require_hid()
    device = open_device(hid)

    all_results = []
    crash_found = False
    crash_payload = None

    try:
        strategies_to_run = STRATEGIES if args.strategy == 'all' else [args.strategy]

        for strategy_name in strategies_to_run:
            print(f"\n{'='*70}")

            strategy_func = {
                'overflow': strategy_overflow,
                'sweep': strategy_sweep,
                'vendor': strategy_vendor,
                'boundary': strategy_boundary,
                'rapidfire': strategy_rapidfire,
            }[strategy_name]

            results = strategy_func(
                device, args.delay, args.start_id, args.end_id, args.verbose
            )
            all_results.extend(results)

            # Check if any crash was found
            crashed = [r for r in results if not r.device_alive]
            if crashed:
                crash_found = True
                crash_payload = crashed[-1]
                print(f"\n  [!!!] CRASH DETECTED in strategy '{strategy_name}'!")
                print(f"        Report ID: 0x{crash_payload.report_id:02X}")
                print(f"        Payload: {crash_payload.payload.hex()}")
                print(f"        Notes: {crash_payload.notes}")
                print()
                print(f"  Waiting for device to re-enumerate...")

                # Wait for recovery
                device.close()
                recovery = wait_for_device(hid, timeout_s=15.0)
                if recovery == 'normal':
                    print(f"  Device recovered to NORMAL mode (soft crash)")
                    crash_payload.crash_type = 'soft'
                    device = open_device(hid)
                elif recovery == 'boot':
                    print(f"  Device entered BOOT mode (hard crash/watchdog)!")
                    crash_payload.crash_type = 'hard'
                    print(f"  [!!!] This is exploitable - device rebooted!")
                    break
                else:
                    print(f"  Device did not re-enumerate (hang)")
                    crash_payload.crash_type = 'hang'
                    break

        # Final summary
        print(f"\n{'='*70}")
        print(f"  FUZZING SUMMARY")
        print(f"{'='*70}\n")

        total = len(all_results)
        sent_ok = sum(1 for r in all_results if r.sent_ok)
        crashes = [r for r in all_results if not r.device_alive]

        print(f"  Total payloads attempted: {total}")
        print(f"  Successfully sent: {sent_ok}")
        print(f"  Crashes detected: {len(crashes)}")

        if crashes:
            print(f"\n  CRASH DETAILS:")
            for i, c in enumerate(crashes):
                print(f"    {i+1}. Strategy: {c.strategy}")
                print(f"       Report ID: 0x{c.report_id:02X}")
                print(f"       Crash type: {c.crash_type or 'unknown'}")
                print(f"       Notes: {c.notes}")
                print(f"       Payload: {c.payload[:32].hex()}...")
                print()

            print(f"  NEXT STEPS:")
            print(f"    1. Run crash_analyzer.py --replay-log {args.log or 'fuzz_log.json'}")
            print(f"    2. Narrow down exact crash byte with binary search")
            print(f"    3. If offset is in bytes 60-63: direct register control")
            print(f"    4. Build shellcode payload for code execution")
        else:
            print(f"\n  No crashes detected. The device may:")
            print(f"    - Properly validate all inputs (unlikely given analysis)")
            print(f"    - Silently discard invalid payloads")
            print(f"    - Only crash on specific payload structures")
            print(f"\n  Recommendations:")
            print(f"    - Try with --delay 0 for more aggressive timing")
            print(f"    - Focus on --strategy vendor for untested paths")
            print(f"    - Try larger ID ranges with --start-id 0x00 --end-id 0xEF")

    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user.")
    except Exception as e:
        print(f"\n[!] Unexpected error: {e}")
        raise
    finally:
        try:
            device.close()
        except Exception:
            pass
        print("\n[*] Device closed.")

    # Save log
    if args.log:
        log_data = {
            'timestamp': datetime.now().isoformat(),
            'config': {
                'strategy': args.strategy,
                'delay_ms': args.delay,
                'start_id': f'0x{args.start_id:02X}',
                'end_id': f'0x{args.end_id:02X}',
            },
            'summary': {
                'total_payloads': len(all_results),
                'crashes': len([r for r in all_results if not r.device_alive]),
                'crash_found': crash_found,
            },
            'results': [r.to_dict() for r in all_results],
        }

        with open(args.log, 'w') as f:
            json.dump(log_data, f, indent=2)
        print(f"[*] Results saved to: {args.log}")


if __name__ == "__main__":
    main()
