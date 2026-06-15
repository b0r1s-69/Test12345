#!/usr/bin/env python3
"""
hid_deferred_probe.py - Deferred Processing Path Probe for Ajazz AJ159 APEX Mouse
===================================================================================

Systematically probes the deferred processing path in the AJ159 firmware.
The SET_REPORT handler at 0x1C1A8 validates incoming reports, then the config
dispatch at 0x17DDC routes them by report ID. A deferred handler at 0x21D44
sets bit 6 of a control register, triggering actual processing later.

This script sends structured payloads for each known report ID, passes the
firmware validation gate, and monitors responses to map which code paths
actually process data beyond the initial dispatch.

Key firmware structures:
  - SET_REPORT handler: 0x1C1A8 (PUSH {R0-R7, LR}; SUB SP, #0x3C)
  - Config dispatch: 0x17DDC (routes by report ID)
  - Special dispatch for 0x13 and 0x17: 0x17E1E-0x17E2C (indirect call)
  - Common handler: 0x21D44 (sets bit 6 flag for deferred processing)
  - Validation gate checks:
      report_id <= 0xEF
      sp+0x64 <= 3
      sp+0x68 <= 1
      sp+0x80 between 1-4
      sp+0x84 <= 0xF

Target: VID 0x3151, PID 0x4026 (normal mode), Interface 2, usage_page 0xFFFF
Reports: 64-byte Feature Reports via SET_REPORT/GET_REPORT on control endpoint

SAFETY: The MCUboot swap design means the device ALWAYS recovers from crashes.
If the mouse stops responding, unplug/replug or wait for watchdog reset. It will
reboot to either normal mode (PID 0x4026) or boot mode (PID 0x4025).

PREREQUISITES:
  - Python 3.7+
  - pip install hidapi
  - Mouse in normal mode (PID 0x4026), plugged in via USB
  - Linux: run as root or configure udev rules (99-aj159.rules)

USAGE:
  python hid_deferred_probe.py                      # Probe all known report IDs
  python hid_deferred_probe.py --ids 0x13 0x17      # Probe specific IDs only
  python hid_deferred_probe.py --deep               # Extended probing with payload variants
  python hid_deferred_probe.py --timing             # Measure deferred processing timing
  python hid_deferred_probe.py --output report.json # Save results to JSON
"""

from __future__ import annotations

import sys
import json
import time
import struct
import argparse
from datetime import datetime
from typing import Optional, List, Dict, Any

# ===========================================================================
# Constants
# ===========================================================================

NORMAL_VID = 0x3151
NORMAL_PID = 0x4026
NORMAL_USAGE_PAGE = 0xFFFF
NORMAL_INTERFACE = 2

REPORT_SIZE = 64  # 64-byte feature reports
REPORT_ID = 0x00  # Implicit report ID

# Known report IDs from firmware dispatch at 0x17DDC
KNOWN_REPORT_IDS = [0x04, 0x05, 0x06, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18]

# IDs with special dispatch path at 0x17E1E-0x17E2C (indirect function call)
SPECIAL_DISPATCH_IDS = [0x13, 0x17]

# Firmware addresses (for reference in output)
FW_ADDRESSES = {
    'set_report_handler': 0x1C1A8,
    'config_dispatch': 0x17DDC,
    'special_dispatch': 0x17E1E,
    'indirect_call': 0x17E2C,
    'common_handler': 0x21D44,
}

# Validation gate field offsets and bounds
# These correspond to fields within the 64-byte report payload
VALIDATION_FIELDS = {
    'report_id': {'max': 0xEF, 'desc': 'Report ID must be <= 0xEF'},
    'sp_0x64': {'max': 3, 'desc': 'Field at stack offset 0x64 must be <= 3'},
    'sp_0x68': {'max': 1, 'desc': 'Field at stack offset 0x68 must be <= 1'},
    'sp_0x80': {'min': 1, 'max': 4, 'desc': 'Field at stack offset 0x80 must be 1-4'},
    'sp_0x84': {'max': 0xF, 'desc': 'Field at stack offset 0x84 must be <= 0xF'},
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
            "Install with: pip install hidapi\n"
            "\n"
            "On Linux you may also need: sudo apt install libhidapi-dev"
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

    # Fallback: interface 2
    for d in devices:
        if d.get('interface_number') == NORMAL_INTERFACE:
            return d

    # Fallback: any vendor usage page
    for d in devices:
        up = d.get('usage_page', 0)
        if up >= 0xFF00:
            return d

    return devices[0] if devices else None


def open_device(hid_module):
    """Open the normal-mode HID device."""
    dev_info = find_normal_device(hid_module)
    if not dev_info:
        print(f"\nERROR: Device not found (VID={NORMAL_VID:#06x} PID={NORMAL_PID:#06x})")
        print("Is the mouse connected in normal mode?")
        print("If in boot mode (PID 0x4025), power cycle it first.")
        sys.exit(1)

    print(f"[*] Found device: VID={dev_info['vendor_id']:#06x} "
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
            "  - Linux: Run with sudo, or install udev rules (99-aj159.rules)\n"
            "  - Close any mouse config software first"
        )

    return h


def is_device_alive(device) -> bool:
    """Check if device is still responsive via GET_REPORT."""
    try:
        resp = device.get_feature_report(0x04, REPORT_SIZE + 1)
        return resp is not None and len(resp) > 0
    except Exception:
        return False


# ===========================================================================
# Payload Construction
# ===========================================================================

def build_valid_payload(report_id: int, variant: int = 0) -> bytes:
    """
    Build a 64-byte payload that passes the firmware validation gate.

    The payload structure (mapped to stack frame at 0x1C1A8):
      byte[0]  = report_id (command byte, routed at 0x17DDC)
      byte[1]  = length/size field (often mirrors report length)
      byte[2]  = sub-command or mode selector
      byte[3:] = payload data

    Validation gate constraints (from firmware analysis):
      - report_id (byte 0) <= 0xEF
      - Various stack offset checks depend on payload structure

    variant controls which payload pattern to use:
      0 = minimal (all zeros after report_id)
      1 = standard (matches known protocol structure)
      2 = maximum valid values (boundary testing)
      3 = incremental pattern (for state change detection)
    """
    buf = bytearray(REPORT_SIZE)
    buf[0] = report_id

    if variant == 0:
        # Minimal: just the report ID, rest zeros
        # This should pass validation and reach the dispatcher
        buf[1] = REPORT_SIZE  # length field
        buf[2] = 0x01  # sub-command: typically 0x01 for "read/query"

    elif variant == 1:
        # Standard: mimic observed protocol patterns
        buf[1] = REPORT_SIZE
        buf[2] = 0x01
        # Set fields that pass validation gate bounds
        # sp+0x80 area (approx byte offset 28-32 in payload)
        buf[28] = 0x01  # Must be 1-4
        buf[32] = 0x01  # Must be <= 0xF

    elif variant == 2:
        # Maximum valid: push all validation fields to their limits
        buf[1] = REPORT_SIZE
        buf[2] = 0x03  # max for sp+0x64 field (<= 3)
        buf[3] = 0x01  # max for sp+0x68 field (<= 1)
        buf[28] = 0x04  # max for sp+0x80 field (1-4)
        buf[32] = 0x0F  # max for sp+0x84 field (<= 0xF)
        # Fill remaining with recognizable pattern
        for i in range(4, 28):
            buf[i] = i & 0xFF
        for i in range(33, REPORT_SIZE):
            buf[i] = (i * 7) & 0xFF

    elif variant == 3:
        # Incremental: each byte is its position (for detecting which bytes matter)
        buf[1] = REPORT_SIZE
        buf[2] = 0x01
        for i in range(3, REPORT_SIZE):
            buf[i] = i & 0xFF

    return bytes(buf)


def build_deferred_trigger_payload(report_id: int, fill_byte: int = 0xAA) -> bytes:
    """
    Build a payload specifically targeting the deferred processing path.

    For report IDs 0x13 and 0x17, the firmware takes a special path at
    0x17E1E that performs an indirect function call:
      ldr r0, [pc]        ; load pointer to object
      ldr r0, [r0, #0x24] ; load vtable/function table pointer
      ldr r0, [r0, #0x1c] ; load specific function pointer
      blx r0              ; call the handler

    We want to pass validation and reach this indirect call to understand
    what the deferred handler does with the payload data.
    """
    buf = bytearray(REPORT_SIZE)
    buf[0] = report_id
    buf[1] = REPORT_SIZE
    buf[2] = 0x01  # Valid sub-command
    # Fill with recognizable pattern for memory analysis
    for i in range(3, REPORT_SIZE):
        buf[i] = fill_byte

    return bytes(buf)


# ===========================================================================
# Probe Logic
# ===========================================================================

def probe_single_id(device, report_id: int, delay_ms: float = 50.0,
                    verbose: bool = False) -> Dict[str, Any]:
    """
    Probe a single report ID:
      1. GET_REPORT to read current state
      2. SET_REPORT with structured payload
      3. GET_REPORT again to detect state changes
      4. Measure timing for deferred processing detection

    Returns a dict with probe results.
    """
    result = {
        'report_id': report_id,
        'report_id_hex': f'0x{report_id:02X}',
        'is_special_dispatch': report_id in SPECIAL_DISPATCH_IDS,
        'before': None,
        'after': None,
        'state_changed': False,
        'set_success': False,
        'get_before_success': False,
        'get_after_success': False,
        'timing_ms': 0.0,
        'error': None,
    }

    # Step 1: GET_REPORT (read current state)
    try:
        before = device.get_feature_report(report_id, REPORT_SIZE + 1)
        if before and len(before) > 1:
            result['before'] = bytes(before[1:]).hex()
            result['get_before_success'] = True
            if verbose:
                payload_bytes = bytes(before[1:])
                if any(payload_bytes):
                    print(f"    GET before: {payload_bytes[:16].hex()}...")
                else:
                    print(f"    GET before: all zeros")
        else:
            result['before'] = None
            if verbose:
                print(f"    GET before: empty response")
    except Exception as e:
        result['error'] = f"GET before failed: {e}"
        if verbose:
            print(f"    GET before: ERROR - {e}")

    # Step 2: SET_REPORT with valid payload
    payload = build_valid_payload(report_id, variant=1)
    try:
        t_start = time.perf_counter()
        # send_feature_report expects: [report_id_byte] + [64 bytes payload]
        # For implicit report ID 0x00, we prepend 0x00
        send_buf = bytes([REPORT_ID]) + payload
        n = device.send_feature_report(send_buf)
        t_set = time.perf_counter()

        if n > 0:
            result['set_success'] = True
            if verbose:
                print(f"    SET: OK ({n} bytes sent)")
        else:
            result['set_success'] = False
            if verbose:
                print(f"    SET: returned {n}")
    except Exception as e:
        result['error'] = f"SET failed: {e}"
        if verbose:
            print(f"    SET: ERROR - {e}")
        return result

    # Wait for deferred processing
    time.sleep(delay_ms / 1000.0)

    # Step 3: GET_REPORT (check for state changes)
    try:
        t_get_start = time.perf_counter()
        after = device.get_feature_report(report_id, REPORT_SIZE + 1)
        t_get_end = time.perf_counter()

        result['timing_ms'] = (t_get_end - t_start) * 1000.0

        if after and len(after) > 1:
            result['after'] = bytes(after[1:]).hex()
            result['get_after_success'] = True

            # Compare before/after
            if result['before'] is not None:
                result['state_changed'] = (result['before'] != result['after'])

            if verbose:
                payload_bytes = bytes(after[1:])
                if any(payload_bytes):
                    print(f"    GET after:  {payload_bytes[:16].hex()}...")
                else:
                    print(f"    GET after:  all zeros")
                if result['state_changed']:
                    print(f"    [!] STATE CHANGED after SET_REPORT!")
        else:
            result['after'] = None
            if verbose:
                print(f"    GET after: empty response")
    except Exception as e:
        result['error'] = f"GET after failed: {e}"
        if verbose:
            print(f"    GET after: ERROR - {e}")

    return result


def probe_with_variants(device, report_id: int, delay_ms: float = 50.0,
                        verbose: bool = False) -> List[Dict[str, Any]]:
    """
    Probe a report ID with multiple payload variants to map behavior.
    Returns a list of results, one per variant.
    """
    results = []
    variant_names = ['minimal', 'standard', 'max_valid', 'incremental']

    for variant_idx, variant_name in enumerate(variant_names):
        if verbose:
            print(f"\n    Variant {variant_idx}: {variant_name}")

        payload = build_valid_payload(report_id, variant=variant_idx)
        result = {
            'variant': variant_name,
            'variant_idx': variant_idx,
            'payload_hex': payload.hex(),
            'set_success': False,
            'response': None,
            'state_changed': False,
            'timing_ms': 0.0,
            'error': None,
        }

        # Read before
        try:
            before = device.get_feature_report(report_id, REPORT_SIZE + 1)
            before_data = bytes(before[1:]) if before and len(before) > 1 else None
        except Exception:
            before_data = None

        # Send
        try:
            t_start = time.perf_counter()
            send_buf = bytes([REPORT_ID]) + payload
            n = device.send_feature_report(send_buf)
            result['set_success'] = n > 0
        except Exception as e:
            result['error'] = str(e)
            results.append(result)
            continue

        time.sleep(delay_ms / 1000.0)

        # Read after
        try:
            after = device.get_feature_report(report_id, REPORT_SIZE + 1)
            t_end = time.perf_counter()
            result['timing_ms'] = (t_end - t_start) * 1000.0

            if after and len(after) > 1:
                after_data = bytes(after[1:])
                result['response'] = after_data.hex()
                if before_data is not None:
                    result['state_changed'] = (after_data != before_data)
        except Exception as e:
            result['error'] = f"GET failed: {e}"

        results.append(result)

        # Brief pause between variants
        time.sleep(0.02)

    return results


def probe_deferred_timing(device, report_id: int, iterations: int = 10,
                          verbose: bool = False) -> Dict[str, Any]:
    """
    Measure timing characteristics of deferred processing.

    Sends SET_REPORT, then immediately tries GET_REPORT at increasing
    intervals to detect when deferred processing completes.
    """
    delays_ms = [1, 2, 5, 10, 20, 50, 100, 200, 500]
    timing_results = []

    payload = build_deferred_trigger_payload(report_id)
    send_buf = bytes([REPORT_ID]) + payload

    for delay in delays_ms:
        responses_differ = 0

        for _ in range(iterations):
            try:
                # Read baseline
                baseline = device.get_feature_report(report_id, REPORT_SIZE + 1)
                baseline_data = bytes(baseline[1:]) if baseline and len(baseline) > 1 else b''

                # Send
                device.send_feature_report(send_buf)

                # Wait specified delay
                time.sleep(delay / 1000.0)

                # Read response
                after = device.get_feature_report(report_id, REPORT_SIZE + 1)
                after_data = bytes(after[1:]) if after and len(after) > 1 else b''

                if after_data != baseline_data:
                    responses_differ += 1

            except Exception:
                pass

            time.sleep(0.01)

        change_rate = responses_differ / iterations
        timing_results.append({
            'delay_ms': delay,
            'change_rate': change_rate,
            'changes_detected': responses_differ,
            'iterations': iterations,
        })

        if verbose:
            print(f"    delay={delay:4d}ms: {responses_differ}/{iterations} "
                  f"state changes ({change_rate:.0%})")

    return {
        'report_id': report_id,
        'report_id_hex': f'0x{report_id:02X}',
        'timing_profile': timing_results,
    }


# ===========================================================================
# Main
# ===========================================================================

def main():
    parser = argparse.ArgumentParser(
        description="AJ159 APEX - Deferred Processing Path Probe",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Probes the firmware's deferred processing path by sending structured
SET_REPORT payloads and monitoring for state changes via GET_REPORT.

WARNING: This tool sends data to the mouse firmware. The MCUboot swap
design means the device always recovers from crashes (worst case: unplug
and replug, device reboots to boot mode PID 0x4025 or normal mode).

Firmware addresses (from reverse engineering):
  SET_REPORT handler:  0x1C1A8
  Config dispatch:     0x17DDC
  Special dispatch:    0x17E1E (report IDs 0x13, 0x17)
  Indirect call:       0x17E2C (ldr r0,[pc]; ldr r0,[r0,#0x24]; blx r0)
  Common handler:      0x21D44 (sets bit 6 for deferred processing)

Examples:
  %(prog)s                           Probe all known report IDs
  %(prog)s --ids 0x13 0x17           Probe only special-dispatch IDs
  %(prog)s --deep                    Try all payload variants per ID
  %(prog)s --timing                  Measure deferred processing timing
  %(prog)s --output results.json     Save results to JSON file
        """
    )
    parser.add_argument(
        '--ids', type=lambda x: int(x, 0), nargs='+', default=None,
        metavar='ID',
        help='Specific report IDs to probe (default: all known IDs)'
    )
    parser.add_argument(
        '--deep', action='store_true',
        help='Extended probing with multiple payload variants per report ID'
    )
    parser.add_argument(
        '--timing', action='store_true',
        help='Measure deferred processing timing characteristics'
    )
    parser.add_argument(
        '--delay', type=float, default=50.0,
        help='Delay in ms between SET and GET (default: 50)'
    )
    parser.add_argument(
        '--iterations', type=int, default=10,
        help='Iterations per timing measurement (default: 10)'
    )
    parser.add_argument(
        '--output', '-o', type=str, default=None,
        help='Save results to JSON file'
    )
    parser.add_argument(
        '-v', '--verbose', action='store_true',
        help='Verbose output showing all probe details'
    )

    args = parser.parse_args()

    target_ids = args.ids if args.ids else KNOWN_REPORT_IDS

    print()
    print("=" * 70)
    print("  AJ159 APEX - Deferred Processing Path Probe")
    print("  Target: VID 0x3151, PID 0x4026 (normal mode)")
    print("  Interface: 2, usage_page: 0xFFFF (vendor-specific)")
    print("=" * 70)
    print()
    print("  WARNING: This tool sends SET_REPORT commands to the mouse firmware.")
    print("  If the device crashes, unplug/replug to recover (MCUboot safe).")
    print()
    print(f"  Report IDs to probe: {', '.join(f'0x{i:02X}' for i in target_ids)}")
    print(f"  Special dispatch IDs: {', '.join(f'0x{i:02X}' for i in SPECIAL_DISPATCH_IDS)}")
    print(f"  Mode: {'deep (all variants)' if args.deep else 'standard'}"
          f"{' + timing' if args.timing else ''}")
    print()

    # Open device
    hid = require_hid()
    device = open_device(hid)

    all_results = {
        'timestamp': datetime.now().isoformat(),
        'device': {
            'vid': f'0x{NORMAL_VID:04X}',
            'pid': f'0x{NORMAL_PID:04X}',
            'interface': NORMAL_INTERFACE,
        },
        'firmware_addresses': {k: f'0x{v:05X}' for k, v in FW_ADDRESSES.items()},
        'probe_results': [],
        'variant_results': [],
        'timing_results': [],
        'summary': {},
    }

    try:
        # Phase 1: Basic probe of each report ID
        print(f"\n{'='*70}")
        print(f"  PHASE 1: Basic Probe (SET + GET for each report ID)")
        print(f"{'='*70}\n")

        for rid in target_ids:
            special_tag = " [SPECIAL DISPATCH]" if rid in SPECIAL_DISPATCH_IDS else ""
            print(f"  --- Report ID 0x{rid:02X}{special_tag} ---")

            result = probe_single_id(device, rid, delay_ms=args.delay,
                                     verbose=args.verbose)
            all_results['probe_results'].append(result)

            # Summary line
            status_parts = []
            if result['get_before_success']:
                status_parts.append("GET:OK")
            else:
                status_parts.append("GET:FAIL")
            if result['set_success']:
                status_parts.append("SET:OK")
            else:
                status_parts.append("SET:FAIL")
            if result['state_changed']:
                status_parts.append("CHANGED")
            if result['error']:
                status_parts.append(f"ERR:{result['error'][:40]}")

            print(f"    Result: {' | '.join(status_parts)}")
            print(f"    Timing: {result['timing_ms']:.1f}ms")
            print()

            # Check device is still alive
            if not is_device_alive(device):
                print("    [!!!] DEVICE NOT RESPONDING - possible crash!")
                print("    Waiting for recovery...")
                time.sleep(3)
                if not is_device_alive(device):
                    print("    Device did not recover. Exiting.")
                    all_results['summary']['crash_at_id'] = f'0x{rid:02X}'
                    break

        # Phase 2: Deep probing (if requested)
        if args.deep:
            print(f"\n{'='*70}")
            print(f"  PHASE 2: Deep Probe (multiple payload variants)")
            print(f"{'='*70}\n")

            for rid in target_ids:
                special_tag = " [SPECIAL]" if rid in SPECIAL_DISPATCH_IDS else ""
                print(f"  --- Report ID 0x{rid:02X}{special_tag} ---")

                variants = probe_with_variants(device, rid, delay_ms=args.delay,
                                               verbose=args.verbose)
                all_results['variant_results'].append({
                    'report_id': rid,
                    'report_id_hex': f'0x{rid:02X}',
                    'variants': variants,
                })

                # Summary
                changes = sum(1 for v in variants if v['state_changed'])
                successes = sum(1 for v in variants if v['set_success'])
                print(f"    {successes}/4 SET succeeded, {changes}/4 caused state changes")
                print()

                if not is_device_alive(device):
                    print("    [!!!] DEVICE CRASH detected during deep probe!")
                    all_results['summary']['crash_at_deep_id'] = f'0x{rid:02X}'
                    break

        # Phase 3: Timing analysis (if requested)
        if args.timing:
            print(f"\n{'='*70}")
            print(f"  PHASE 3: Timing Analysis (deferred processing detection)")
            print(f"{'='*70}\n")

            for rid in target_ids:
                special_tag = " [SPECIAL]" if rid in SPECIAL_DISPATCH_IDS else ""
                print(f"  --- Report ID 0x{rid:02X}{special_tag} ---")

                timing = probe_deferred_timing(device, rid,
                                               iterations=args.iterations,
                                               verbose=args.verbose)
                all_results['timing_results'].append(timing)
                print()

                if not is_device_alive(device):
                    print("    [!!!] DEVICE CRASH during timing analysis!")
                    break

        # Final summary
        print(f"\n{'='*70}")
        print(f"  SUMMARY")
        print(f"{'='*70}\n")

        responsive_ids = [r for r in all_results['probe_results']
                          if r['get_before_success']]
        changed_ids = [r for r in all_results['probe_results']
                       if r['state_changed']]
        set_ok_ids = [r for r in all_results['probe_results']
                      if r['set_success']]

        print(f"  Report IDs responding to GET_REPORT: "
              f"{len(responsive_ids)}/{len(target_ids)}")
        if responsive_ids:
            print(f"    IDs: {', '.join(r['report_id_hex'] for r in responsive_ids)}")

        print(f"  Report IDs accepting SET_REPORT: "
              f"{len(set_ok_ids)}/{len(target_ids)}")
        if set_ok_ids:
            print(f"    IDs: {', '.join(r['report_id_hex'] for r in set_ok_ids)}")

        print(f"  Report IDs with state changes: "
              f"{len(changed_ids)}/{len(target_ids)}")
        if changed_ids:
            print(f"    IDs: {', '.join(r['report_id_hex'] for r in changed_ids)}")
            print(f"    [!] These IDs trigger deferred processing that modifies state!")

        all_results['summary'].update({
            'total_probed': len(target_ids),
            'responsive_to_get': len(responsive_ids),
            'accepting_set': len(set_ok_ids),
            'state_changes': len(changed_ids),
            'changed_ids': [r['report_id_hex'] for r in changed_ids],
        })

        print()
        print("  Next steps:")
        print("  - IDs with state changes are candidates for deeper exploitation")
        print("  - Use hid_fuzzer.py to test boundary conditions on responsive IDs")
        print("  - IDs 0x13/0x17 (special dispatch) may have exploitable indirect calls")
        print()

    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user.")
    except Exception as e:
        print(f"\n[!] Unexpected error: {e}")
        raise
    finally:
        device.close()
        print("[*] Device closed.")

    # Save results
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(all_results, f, indent=2)
        print(f"[*] Results saved to: {args.output}")


if __name__ == "__main__":
    main()
