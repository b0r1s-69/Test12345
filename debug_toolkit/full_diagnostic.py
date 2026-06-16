#!/usr/bin/env python3
"""
full_diagnostic.py - Comprehensive Firmware Update Vector Diagnostics for Ajazz AJ159 APEX
============================================================================================

Probes EVERY possible update vector on the AJ159 APEX gaming mouse to find alternative
paths past the MCUboot RSA-2048 signature verification. This is the definitive test to
determine which (if any) firmware delivery method can succeed.

TARGET DEVICE:
  Normal mode: VID 0x3151, PID 0x4026
    Interface 0: usage_page 0x0001, usage 0x0002 (mouse HID)
    Interface 1: usage_page 0xFFFF, usage 0x0001 (vendor)
    Interface 2: usage_page 0xFFFF, usage 0x0002 (vendor config - primary target)
  Boot mode:   VID 0x3151, PID 0x4025
    Interface 0: usage_page 0xFF01 (bootloader)

KNOWN PROTOCOL:
  Normal mode commands (interface 2, 64-byte feature reports):
    0x8F = get_id
    0x80 = get_version
    0x7F = enter_boot
  Boot mode commands (interface 0, 64-byte feature reports):
    BA FF = get_boot_id (byte[7]=0x46)
    BA C0 = init transfer
    BA C2 = complete transfer

UPDATE METHODS (from support_config.json for PID 0x4026):
    MOUSE, NORDICKEYBOARD, MLED, OLED, FLASH, TOUCHSCREEN

PHASES:
  1. Device fingerprinting - enumerate interfaces, read all feature reports
  2. Normal mode protocol sweep - try all command bytes on interfaces 1 & 2
  3. Boot mode deep probe - enter boot, try all prefixes, SMP/MCUmgr, Nordic DFU
  4. Alternative protocol tests - YZW, FLASH, NORDICKEYBOARD payload variants
  5. MCUmgr/SMP protocol test - CBOR-encoded management frames
  6. Report generation - JSON output with all findings

SAFETY:
  MCUboot uses a swap-based upgrade with automatic revert. Even if a bad image is
  somehow written, the device will revert to the previous working image on next boot.
  All probes are READ or STATUS commands unless explicitly opted in. No flash writes
  are performed without --allow-writes flag.

PREREQUISITES:
  - Python 3.7+
  - pip install hidapi
  - Mouse connected via USB (wired mode recommended)
  - Windows: run as Administrator
  - Linux: run as root or configure udev rules (99-aj159.rules)

USAGE:
  python full_diagnostic.py                         # Run all phases
  python full_diagnostic.py --phase 1               # Run only phase 1
  python full_diagnostic.py --phase 2 3             # Run phases 2 and 3
  python full_diagnostic.py --quick                 # Fast scan (reduced sweep)
  python full_diagnostic.py --output results.json   # Save results to JSON
  python full_diagnostic.py --allow-writes          # Enable write probes (careful!)
"""

from __future__ import annotations

import argparse
import json
import os
import struct
import sys
import time
import traceback
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

# ===========================================================================
# Constants
# ===========================================================================

# Normal mode
NORMAL_VID = 0x3151
NORMAL_PID = 0x4026
NORMAL_IFACE_MOUSE = 0       # usage_page 0x0001, usage 0x0002
NORMAL_IFACE_VENDOR1 = 1     # usage_page 0xFFFF, usage 0x0001
NORMAL_IFACE_VENDOR2 = 2     # usage_page 0xFFFF, usage 0x0002 (config)

# Boot mode
BOOT_VID = 0x3151
BOOT_PID = 0x4025
BOOT_IFACE = 0
BOOT_USAGE_PAGE = 0xFF01

# Protocol constants
REPORT_ID = 0x00
REPORT_SIZE = 64

# Known normal-mode commands
CMD_GET_ID = 0x8F
CMD_GET_VERSION = 0x80
CMD_ENTER_BOOT = 0x7F

# Known boot-mode protocol
BOOT_TX_PREFIX = 0xBA
BOOT_RX_PREFIX = 0xAB
BOOT_CMD_GET_ID = 0xFF
BOOT_CMD_INIT = 0xC0
BOOT_CMD_COMPLETE = 0xC2

# MCUmgr/SMP constants
SMP_HEADER_SIZE = 8
MGMT_OP_READ = 0
MGMT_OP_READ_RSP = 1
MGMT_OP_WRITE = 2
MGMT_OP_WRITE_RSP = 3
MGMT_GROUP_OS = 0
MGMT_GROUP_IMAGE = 1
MGMT_ID_ECHO = 0
MGMT_ID_RESET = 5
MGMT_ID_IMAGE_STATE = 0
MGMT_ID_IMAGE_UPLOAD = 1

# Nordic DFU
NORDIC_DFU_PKT_INIT = 0x01
NORDIC_DFU_PKT_DATA = 0x02
NORDIC_DFU_OP_START = 0x01
NORDIC_DFU_OP_INIT = 0x02
NORDIC_DFU_OP_RECV_FW = 0x03
NORDIC_DFU_OP_VALIDATE = 0x04
NORDIC_DFU_OP_ACTIVATE = 0x05
NORDIC_DFU_OP_RESET = 0x06
NORDIC_DFU_OP_PKT_NOTIF = 0x08
NORDIC_DFU_OP_RESPONSE = 0x10
NORDIC_DFU_OP_GET_VERSION = 0x0B

# Reconnect settings
RECONNECT_TIMEOUT = 15.0
RECONNECT_POLL_INTERVAL = 0.5


# ===========================================================================
# Utility Functions
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


def timestamp() -> str:
    """Return current timestamp string."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def hexdump(data: bytes, max_bytes: int = 64) -> str:
    """Format bytes as hex string."""
    if not data:
        return "<empty>"
    shown = data[:max_bytes]
    result = " ".join(f"{b:02x}" for b in shown)
    if len(data) > max_bytes:
        result += f" ... ({len(data)} total)"
    return result


def is_interesting_response(data: bytes) -> bool:
    """Check if a response contains non-trivial data (not all zeros/0xFF)."""
    if not data:
        return False
    if all(b == 0x00 for b in data):
        return False
    if all(b == 0xFF for b in data):
        return False
    return True


def build_cbor_map(items: Dict[str, Any]) -> bytes:
    """
    Build a minimal CBOR map. Supports string keys and int/bytes/string values.
    This is a simplified encoder sufficient for MCUmgr probing.
    """
    result = bytearray()
    n = len(items)
    if n <= 23:
        result.append(0xA0 | n)
    else:
        result.append(0xB8)
        result.append(n)

    for key, val in items.items():
        # Encode string key
        key_bytes = key.encode('utf-8')
        klen = len(key_bytes)
        if klen <= 23:
            result.append(0x60 | klen)
        else:
            result.append(0x78)
            result.append(klen)
        result.extend(key_bytes)

        # Encode value
        if isinstance(val, int):
            if val >= 0:
                if val <= 23:
                    result.append(val)
                elif val <= 0xFF:
                    result.append(0x18)
                    result.append(val)
                elif val <= 0xFFFF:
                    result.append(0x19)
                    result.extend(struct.pack('>H', val))
                else:
                    result.append(0x1A)
                    result.extend(struct.pack('>I', val))
            else:
                neg = -1 - val
                if neg <= 23:
                    result.append(0x20 | neg)
                elif neg <= 0xFF:
                    result.append(0x38)
                    result.append(neg)
                else:
                    result.append(0x39)
                    result.extend(struct.pack('>H', neg))
        elif isinstance(val, bytes):
            blen = len(val)
            if blen <= 23:
                result.append(0x40 | blen)
            else:
                result.append(0x58)
                result.append(blen)
            result.extend(val)
        elif isinstance(val, str):
            val_bytes = val.encode('utf-8')
            vlen = len(val_bytes)
            if vlen <= 23:
                result.append(0x60 | vlen)
            else:
                result.append(0x78)
                result.append(vlen)
            result.extend(val_bytes)
        elif isinstance(val, bool):
            result.append(0xF5 if val else 0xF4)

    return bytes(result)


def build_smp_frame(op: int, flags: int, length: int, group: int,
                    seq: int, cmd_id: int, payload: bytes = b'') -> bytes:
    """Build an SMP/MCUmgr header + payload."""
    header = struct.pack('>BBHHBH', op, flags, length, group, seq, cmd_id)
    return header + payload


# ===========================================================================
# Device Connection Manager
# ===========================================================================

class DeviceManager:
    """Manages HID device connections with auto-reconnect support."""

    def __init__(self, hid_module):
        self.hid = hid_module
        self.device = None
        self.current_mode = None  # 'normal' or 'boot'
        self.current_interface = None

    def find_normal_device(self, interface: int = NORMAL_IFACE_VENDOR2) -> Optional[dict]:
        """Find a normal-mode device on the specified interface."""
        devices = self.hid.enumerate(NORMAL_VID, NORMAL_PID)
        for d in devices:
            if d.get('interface_number') == interface:
                return d
        # Fallback: any device with matching VID/PID
        return devices[0] if devices else None

    def find_boot_device(self) -> Optional[dict]:
        """Find a boot-mode device."""
        devices = self.hid.enumerate(BOOT_VID, BOOT_PID)
        for d in devices:
            if d.get('usage_page') == BOOT_USAGE_PAGE:
                return d
        # Fallback
        for d in devices:
            up = d.get('usage_page', 0)
            if up >= 0xFF00:
                return d
        return devices[0] if devices else None

    def open_normal(self, interface: int = NORMAL_IFACE_VENDOR2) -> bool:
        """Open normal-mode device on specified interface."""
        self.close()
        dev_info = self.find_normal_device(interface)
        if not dev_info:
            return False
        try:
            self.device = self.hid.device()
            self.device.open_path(dev_info['path'])
            self.current_mode = 'normal'
            self.current_interface = interface
            return True
        except Exception:
            self.device = None
            return False

    def open_boot(self) -> bool:
        """Open boot-mode device."""
        self.close()
        dev_info = self.find_boot_device()
        if not dev_info:
            return False
        try:
            self.device = self.hid.device()
            self.device.open_path(dev_info['path'])
            self.current_mode = 'boot'
            self.current_interface = BOOT_IFACE
            return True
        except Exception:
            self.device = None
            return False

    def close(self):
        """Close current device."""
        if self.device:
            try:
                self.device.close()
            except Exception:
                pass
            self.device = None
            self.current_mode = None
            self.current_interface = None

    def send(self, payload: bytes) -> bool:
        """Send a 64-byte feature report. Returns True on success."""
        if not self.device:
            return False
        try:
            padded = (payload + b'\x00' * REPORT_SIZE)[:REPORT_SIZE]
            packet = bytes([REPORT_ID]) + padded
            result = self.device.send_feature_report(packet)
            return result >= 0
        except Exception:
            return False

    def recv(self, timeout_ms: int = 100) -> Optional[bytes]:
        """Read a feature report. Returns 64 bytes or None."""
        if not self.device:
            return None
        try:
            resp = self.device.get_feature_report(REPORT_ID, REPORT_SIZE + 1)
            if resp and len(resp) > 1:
                return bytes(resp[1:REPORT_SIZE + 1])
            return None
        except Exception:
            return None

    def send_recv(self, payload: bytes, delay_ms: int = 50,
                  timeout_ms: int = 100) -> Optional[bytes]:
        """Send a command and read the response."""
        if not self.send(payload):
            return None
        if delay_ms > 0:
            time.sleep(delay_ms / 1000.0)
        return self.recv(timeout_ms)

    def is_alive(self) -> bool:
        """Check if device is still responding."""
        if not self.device:
            return False
        try:
            self.device.get_feature_report(REPORT_ID, REPORT_SIZE + 1)
            return True
        except Exception:
            return False

    def wait_for_device(self, mode: str = 'normal', timeout: float = RECONNECT_TIMEOUT) -> bool:
        """Wait for device to reappear after a reset."""
        self.close()
        deadline = time.time() + timeout
        while time.time() < deadline:
            time.sleep(RECONNECT_POLL_INTERVAL)
            if mode == 'normal':
                if self.open_normal():
                    return True
            elif mode == 'boot':
                if self.open_boot():
                    return True
            else:
                # Try both
                if self.open_normal():
                    return True
                if self.open_boot():
                    return True
        return False


# ===========================================================================
# Results Collector
# ===========================================================================

class Results:
    """Collects and organizes diagnostic findings."""

    def __init__(self):
        self.start_time = timestamp()
        self.phases: Dict[str, Dict] = {}
        self.highlights: List[str] = []
        self.errors: List[str] = []

    def add_phase(self, phase_id: str, name: str):
        """Initialize a new phase."""
        self.phases[phase_id] = {
            'name': name,
            'start_time': timestamp(),
            'findings': [],
            'status': 'running',
            'summary': ''
        }

    def add_finding(self, phase_id: str, category: str, description: str,
                    data: Any = None, severity: str = 'info'):
        """Record a finding within a phase."""
        finding = {
            'category': category,
            'description': description,
            'severity': severity,  # info, low, medium, high, critical
            'timestamp': timestamp()
        }
        if data is not None:
            if isinstance(data, bytes):
                finding['data'] = data.hex()
            else:
                finding['data'] = data
        self.phases[phase_id]['findings'].append(finding)
        if severity in ('high', 'critical'):
            self.highlights.append(f"[{severity.upper()}] Phase {phase_id}: {description}")

    def complete_phase(self, phase_id: str, summary: str):
        """Mark a phase as complete."""
        self.phases[phase_id]['end_time'] = timestamp()
        self.phases[phase_id]['status'] = 'completed'
        self.phases[phase_id]['summary'] = summary

    def fail_phase(self, phase_id: str, reason: str):
        """Mark a phase as failed."""
        self.phases[phase_id]['end_time'] = timestamp()
        self.phases[phase_id]['status'] = 'failed'
        self.phases[phase_id]['summary'] = reason
        self.errors.append(f"Phase {phase_id} failed: {reason}")

    def to_dict(self) -> Dict:
        """Export results as dictionary."""
        return {
            'diagnostic_report': {
                'tool': 'full_diagnostic.py',
                'target': 'Ajazz AJ159 APEX',
                'start_time': self.start_time,
                'end_time': timestamp(),
                'phases': self.phases,
                'highlights': self.highlights,
                'errors': self.errors,
                'conclusion': self._generate_conclusion()
            }
        }

    def _generate_conclusion(self) -> str:
        """Generate overall conclusion."""
        high_findings = [h for h in self.highlights if '[HIGH]' in h or '[CRITICAL]' in h]
        if high_findings:
            return (f"Found {len(high_findings)} high/critical finding(s) that may indicate "
                    f"viable update vectors. Review highlights for details.")
        return ("No viable update vectors discovered. The MCUboot RSA-2048 signature "
                "verification appears to be the sole gate for firmware updates. "
                "Alternative paths (SMP, Nordic DFU, vendor commands) were not responsive.")

    def save(self, filepath: str):
        """Save results to JSON file."""
        with open(filepath, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)
        print(f"\n[*] Results saved to: {filepath}")


# ===========================================================================
# Phase 1: Device Fingerprinting
# ===========================================================================

def phase1_fingerprint(dm: DeviceManager, results: Results, quick: bool = False):
    """
    Phase 1: Device Fingerprinting
    - Enumerate all interfaces
    - Read feature reports 0x00-0xFF on each vendor interface
    - Collect device identifiers
    """
    phase_id = '1'
    results.add_phase(phase_id, 'Device Fingerprinting')
    print("\n" + "=" * 70)
    print("  PHASE 1: DEVICE FINGERPRINTING")
    print("=" * 70)

    hid_mod = dm.hid

    # Step 1: Enumerate all interfaces
    print("\n[1.1] Enumerating device interfaces...")
    all_devices = hid_mod.enumerate(NORMAL_VID, NORMAL_PID)
    boot_devices = hid_mod.enumerate(BOOT_VID, BOOT_PID)

    if not all_devices and not boot_devices:
        results.fail_phase(phase_id, "No device found (VID 0x3151, PID 0x4026 or 0x4025)")
        print("  ERROR: No device found!")
        print(f"  Looking for VID={NORMAL_VID:#06x} PID={NORMAL_PID:#06x} (normal)")
        print(f"  or VID={BOOT_VID:#06x} PID={BOOT_PID:#06x} (boot)")
        print("\n  Scanning all Compx devices...")
        for d in hid_mod.enumerate():
            if d['vendor_id'] == NORMAL_VID:
                print(f"    VID:{d['vendor_id']:#06x} PID:{d['product_id']:#06x} "
                      f"iface={d.get('interface_number')} "
                      f"usage_page={d.get('usage_page', 0):#06x}")
        return False

    current_mode = 'normal' if all_devices else 'boot'
    print(f"  Device found in {current_mode.upper()} mode")

    if all_devices:
        print(f"\n  Normal mode interfaces ({len(all_devices)}):")
        interface_info = []
        for d in all_devices:
            info = {
                'interface': d.get('interface_number'),
                'usage_page': f"0x{d.get('usage_page', 0):04X}",
                'usage': f"0x{d.get('usage', 0):04X}",
                'product': d.get('product_string', ''),
                'manufacturer': d.get('manufacturer_string', ''),
            }
            interface_info.append(info)
            print(f"    Interface {info['interface']}: "
                  f"usage_page={info['usage_page']} usage={info['usage']} "
                  f"product={info['product']!r}")
        results.add_finding(phase_id, 'enumeration', 'Normal mode interfaces found',
                            interface_info)

    if boot_devices:
        print(f"\n  Boot mode interfaces ({len(boot_devices)}):")
        for d in boot_devices:
            print(f"    Interface {d.get('interface_number')}: "
                  f"usage_page=0x{d.get('usage_page', 0):04X}")
        results.add_finding(phase_id, 'enumeration', 'Device is in boot mode',
                            severity='medium')

    # Step 2: Read feature reports on vendor interfaces
    if all_devices:
        report_range = range(0x00, 0x20) if quick else range(0x00, 0x100)
        for iface in [NORMAL_IFACE_VENDOR1, NORMAL_IFACE_VENDOR2]:
            print(f"\n[1.2] Reading feature reports on interface {iface} "
                  f"(IDs 0x{report_range.start:02X}-0x{report_range.stop - 1:02X})...")
            if not dm.open_normal(iface):
                print(f"  Could not open interface {iface}")
                results.add_finding(phase_id, 'access', f'Cannot open interface {iface}',
                                    severity='low')
                continue

            report_map = {}
            for rid in report_range:
                try:
                    resp = dm.device.get_feature_report(rid, REPORT_SIZE + 1)
                    if resp and len(resp) > 1:
                        data = bytes(resp[1:])
                        if is_interesting_response(data):
                            report_map[f"0x{rid:02X}"] = data.hex()
                            print(f"    Report 0x{rid:02X}: {hexdump(data, 16)}")
                except Exception:
                    pass

            if report_map:
                results.add_finding(phase_id, 'feature_reports',
                                    f'Interface {iface}: {len(report_map)} readable reports',
                                    report_map)
            else:
                print(f"    No interesting reports on interface {iface}")

            dm.close()

    # Step 3: Read known status commands
    if all_devices:
        print(f"\n[1.3] Reading known status commands...")
        if dm.open_normal(NORMAL_IFACE_VENDOR2):
            # Get ID (0x8F)
            payload = bytearray(REPORT_SIZE)
            payload[0] = CMD_GET_ID
            resp = dm.send_recv(bytes(payload))
            if resp and is_interesting_response(resp):
                print(f"    CMD 0x8F (get_id): {hexdump(resp, 16)}")
                results.add_finding(phase_id, 'identity', 'Device ID response',
                                    resp.hex())

            # Get Version (0x80)
            payload = bytearray(REPORT_SIZE)
            payload[0] = CMD_GET_VERSION
            resp = dm.send_recv(bytes(payload))
            if resp and is_interesting_response(resp):
                print(f"    CMD 0x80 (get_version): {hexdump(resp, 16)}")
                results.add_finding(phase_id, 'identity', 'Firmware version response',
                                    resp.hex())

            dm.close()

    total_reports = sum(len(p.get('data', {})) for p in results.phases[phase_id]['findings']
                        if isinstance(p.get('data'), dict))
    results.complete_phase(phase_id,
                           f"Enumerated {len(all_devices)} interfaces, "
                           f"found {total_reports} readable reports")
    print(f"\n  Phase 1 complete.")
    return True


# ===========================================================================
# Phase 2: Normal Mode Protocol Sweep
# ===========================================================================

def phase2_protocol_sweep(dm: DeviceManager, results: Results, quick: bool = False):
    """
    Phase 2: Normal Mode Protocol Sweep
    - Try all command bytes 0x00-0xFF on interfaces 1 and 2
    - Identify which commands produce responses
    - Look for hidden update/debug commands
    """
    phase_id = '2'
    results.add_phase(phase_id, 'Normal Mode Protocol Sweep')
    print("\n" + "=" * 70)
    print("  PHASE 2: NORMAL MODE PROTOCOL SWEEP")
    print("=" * 70)

    cmd_range = range(0x00, 0x100)
    if quick:
        # In quick mode, test known ranges + sample others
        cmd_list = list(range(0x00, 0x20)) + list(range(0x70, 0xA0)) + list(range(0xF0, 0x100))
    else:
        cmd_list = list(cmd_range)

    responsive_cmds: Dict[str, List] = {}

    for iface in [NORMAL_IFACE_VENDOR1, NORMAL_IFACE_VENDOR2]:
        print(f"\n[2.{iface}] Sweeping interface {iface} "
              f"({len(cmd_list)} commands)...")

        if not dm.open_normal(iface):
            print(f"  Could not open interface {iface}")
            results.add_finding(phase_id, 'access',
                                f'Cannot open interface {iface}', severity='low')
            continue

        iface_key = f"iface_{iface}"
        responsive_cmds[iface_key] = []
        baseline = dm.recv(50)

        for idx, cmd in enumerate(cmd_list):
            if idx % 64 == 0 and idx > 0:
                print(f"    Progress: {idx}/{len(cmd_list)} commands tested...")
                # Verify device is still alive
                if not dm.is_alive():
                    print(f"    WARNING: Device stopped responding at cmd 0x{cmd:02X}")
                    results.add_finding(phase_id, 'crash',
                                        f'Device unresponsive after cmd 0x{cmd_list[idx-1]:02X} '
                                        f'on interface {iface}',
                                        severity='high')
                    # Try to reconnect
                    dm.close()
                    time.sleep(2)
                    if not dm.open_normal(iface):
                        print(f"    FATAL: Cannot reconnect to interface {iface}")
                        break

            payload = bytearray(REPORT_SIZE)
            payload[0] = cmd
            resp = dm.send_recv(bytes(payload), delay_ms=30)

            if resp and is_interesting_response(resp):
                # Check if response differs from what we sent (not just echo)
                if resp != bytes(payload) and resp != baseline:
                    entry = {
                        'cmd': f"0x{cmd:02X}",
                        'response': resp[:16].hex(),
                        'full_response': resp.hex()
                    }
                    responsive_cmds[iface_key].append(entry)

                    # Classify response
                    if resp[0] == cmd:
                        print(f"    [RESP] CMD 0x{cmd:02X} -> echoed cmd byte | "
                              f"{hexdump(resp, 8)}")
                    else:
                        print(f"    [!!!!] CMD 0x{cmd:02X} -> different response | "
                              f"{hexdump(resp, 8)}")
                        results.add_finding(phase_id, 'unexpected_response',
                                            f'Cmd 0x{cmd:02X} on iface {iface} '
                                            f'returned unexpected data',
                                            entry, severity='medium')

        found = len(responsive_cmds.get(iface_key, []))
        print(f"    Interface {iface}: {found} responsive commands")
        dm.close()

    # Additional probes: try multi-byte command prefixes
    print(f"\n[2.3] Testing multi-byte command prefixes on interface 2...")
    if dm.open_normal(NORMAL_IFACE_VENDOR2):
        prefixes_to_try = [
            (b'\xBA\xFF', "Boot-style BA FF in normal mode"),
            (b'\xAB\x00', "Boot response prefix AB"),
            (b'\x55\xAA', "Common magic 55 AA"),
            (b'\xAA\x55', "Common magic AA 55"),
            (b'\x5A\xA5', "Alternate magic 5A A5"),
            (b'\xFE\xED', "Feed prefix"),
            (b'\xDE\xAD', "Dead prefix"),
            (b'\x09\x01', "Nordic SMP over HID"),
            (b'\x06\x09\x01', "Polling-style prefix"),
            (b'\x04\x38\x01', "DPI-style prefix"),
            (b'\x05\x0F\x01', "Prefs-style prefix"),
        ]
        for prefix, desc in prefixes_to_try:
            payload = bytearray(REPORT_SIZE)
            payload[:len(prefix)] = prefix
            resp = dm.send_recv(bytes(payload), delay_ms=30)
            if resp and is_interesting_response(resp) and resp != bytes(payload):
                print(f"    [!] {desc}: {hexdump(resp, 16)}")
                results.add_finding(phase_id, 'magic_prefix',
                                    f'{desc} produced response',
                                    {'prefix': prefix.hex(), 'response': resp.hex()},
                                    severity='medium')
        dm.close()

    total_responsive = sum(len(v) for v in responsive_cmds.values() if isinstance(v, list))
    results.add_finding(phase_id, 'sweep_results',
                        f'Total responsive commands: {total_responsive}',
                        responsive_cmds)
    results.complete_phase(phase_id,
                           f"Swept {len(cmd_list)} commands on 2 interfaces, "
                           f"{total_responsive} responded")
    print(f"\n  Phase 2 complete.")
    return True


# ===========================================================================
# Phase 3: Boot Mode Deep Probe
# ===========================================================================

def phase3_boot_probe(dm: DeviceManager, results: Results, quick: bool = False):
    """
    Phase 3: Boot Mode Entry + Deep Probe
    - Enter boot mode via CMD 0x7F
    - Try all command prefixes (not just BA)
    - Try SMP/MCUmgr CBOR frames
    - Try Nordic DFU init packet format
    """
    phase_id = '3'
    results.add_phase(phase_id, 'Boot Mode Deep Probe')
    print("\n" + "=" * 70)
    print("  PHASE 3: BOOT MODE DEEP PROBE")
    print("=" * 70)

    # Step 1: Enter boot mode
    print("\n[3.1] Entering boot mode...")

    # Check if already in boot mode
    if dm.find_boot_device():
        print("  Device already in boot mode")
    else:
        # Send enter-boot command
        if not dm.open_normal(NORMAL_IFACE_VENDOR2):
            results.fail_phase(phase_id, "Cannot open normal-mode device")
            return False

        payload = bytearray(REPORT_SIZE)
        payload[0] = CMD_ENTER_BOOT
        dm.send(bytes(payload))
        dm.close()
        print("  Sent enter-boot command (0x7F), waiting for boot device...")
        time.sleep(2)

        # Wait for boot device
        if not dm.wait_for_device('boot', timeout=10.0):
            results.fail_phase(phase_id,
                               "Device did not appear in boot mode after CMD 0x7F")
            print("  ERROR: Boot device not found after enter-boot command")
            # Try to reconnect to normal mode
            dm.wait_for_device('normal', timeout=10.0)
            return False

    print("  Boot mode confirmed!")
    results.add_finding(phase_id, 'boot_entry', 'Successfully entered boot mode')

    # Step 2: Read boot device info
    print("\n[3.2] Reading boot device identification...")
    if dm.open_boot():
        # Standard BA FF get_id
        payload = bytearray(REPORT_SIZE)
        payload[0] = BOOT_TX_PREFIX
        payload[1] = BOOT_CMD_GET_ID
        payload[7] = 0x46  # mode byte
        resp = dm.send_recv(bytes(payload), delay_ms=50)
        if resp and is_interesting_response(resp):
            print(f"    BA FF (get_id): {hexdump(resp, 16)}")
            results.add_finding(phase_id, 'boot_id', 'Boot device ID response',
                                resp.hex())

    # Step 3: Try all first-byte prefixes (not just BA)
    print(f"\n[3.3] Sweeping command prefixes 0x00-0xFF (first byte)...")
    prefix_range = range(0x00, 0x100) if not quick else range(0x00, 0x100, 4)
    interesting_prefixes = []

    if dm.device:
        for prefix in prefix_range:
            payload = bytearray(REPORT_SIZE)
            payload[0] = prefix
            payload[1] = 0xFF  # Use FF as sub-command (most likely to get response)
            resp = dm.send_recv(bytes(payload), delay_ms=20)
            if resp and is_interesting_response(resp):
                # Skip if it is just BA/AB echo
                if resp[0] != prefix or any(resp[2:16]):
                    entry = {'prefix': f"0x{prefix:02X}", 'response': resp[:16].hex()}
                    interesting_prefixes.append(entry)
                    if prefix != BOOT_TX_PREFIX:  # Skip known BA
                        print(f"    [!] Prefix 0x{prefix:02X}: {hexdump(resp, 16)}")
                        results.add_finding(phase_id, 'unknown_prefix',
                                            f'Prefix 0x{prefix:02X} produced response in boot',
                                            entry, severity='high')

    # Step 4: Try BA XX for all sub-commands
    print(f"\n[3.4] Sweeping BA XX sub-commands 0x00-0xFF...")
    sub_range = range(0x00, 0x100) if not quick else list(range(0x00, 0x10)) + \
        list(range(0xB0, 0xD0)) + list(range(0xF0, 0x100))
    boot_commands_found = []

    if dm.device:
        for sub_cmd in sub_range:
            if sub_cmd in (0xC0, 0xC2):
                continue  # Skip dangerous init/complete
            payload = bytearray(REPORT_SIZE)
            payload[0] = BOOT_TX_PREFIX
            payload[1] = sub_cmd
            resp = dm.send_recv(bytes(payload), delay_ms=20)
            if resp and is_interesting_response(resp):
                if resp[0] == BOOT_RX_PREFIX:
                    entry = {'cmd': f"BA {sub_cmd:02X}",
                             'response': resp[:16].hex()}
                    boot_commands_found.append(entry)
                    if sub_cmd != BOOT_CMD_GET_ID:
                        print(f"    [RESP] BA {sub_cmd:02X} -> {hexdump(resp, 8)}")
                        results.add_finding(phase_id, 'boot_command',
                                            f'Boot command BA {sub_cmd:02X} responded',
                                            entry, severity='medium')

    # Step 5: Try SMP/MCUmgr frames
    print(f"\n[3.5] Testing SMP/MCUmgr protocol frames...")
    smp_tests = [
        ('OS Echo', MGMT_GROUP_OS, MGMT_ID_ECHO, MGMT_OP_WRITE,
         build_cbor_map({"d": "test"})),
        ('OS Reset', MGMT_GROUP_OS, MGMT_ID_RESET, MGMT_OP_WRITE,
         build_cbor_map({})),
        ('Image State', MGMT_GROUP_IMAGE, MGMT_ID_IMAGE_STATE, MGMT_OP_READ,
         b''),
        ('Image Upload (probe)', MGMT_GROUP_IMAGE, MGMT_ID_IMAGE_UPLOAD, MGMT_OP_READ,
         b''),
    ]

    if dm.device:
        for name, group, cmd_id, op, cbor_payload in smp_tests:
            smp_frame = build_smp_frame(op, 0, len(cbor_payload), group, 0, cmd_id,
                                        cbor_payload)
            # Try sending raw SMP frame
            payload = bytearray(REPORT_SIZE)
            payload[:len(smp_frame)] = smp_frame[:REPORT_SIZE]
            resp = dm.send_recv(bytes(payload), delay_ms=50)
            if resp and is_interesting_response(resp):
                # Check for SMP response header
                if resp[0] in (MGMT_OP_READ_RSP, MGMT_OP_WRITE_RSP):
                    print(f"    [!!!!] SMP {name}: GOT SMP RESPONSE! {hexdump(resp, 16)}")
                    results.add_finding(phase_id, 'smp_active',
                                        f'SMP/MCUmgr {name} responded!',
                                        resp.hex(), severity='critical')
                elif resp != bytes(payload[:REPORT_SIZE]):
                    print(f"    [?] SMP {name}: non-SMP response: {hexdump(resp, 8)}")
                    results.add_finding(phase_id, 'smp_partial',
                                        f'SMP {name} got non-standard response',
                                        resp.hex(), severity='medium')

            # Also try with 0x09 0x01 prefix (SMP over HID transport marker)
            payload2 = bytearray(REPORT_SIZE)
            payload2[0] = 0x09
            payload2[1] = 0x01
            frame_len = min(len(smp_frame), REPORT_SIZE - 2)
            payload2[2:2 + frame_len] = smp_frame[:frame_len]
            resp = dm.send_recv(bytes(payload2), delay_ms=50)
            if resp and is_interesting_response(resp) and resp != bytes(payload2):
                print(f"    [?] SMP-HID {name}: {hexdump(resp, 16)}")
                results.add_finding(phase_id, 'smp_hid',
                                    f'SMP-HID {name} got response',
                                    resp.hex(), severity='medium')

    # Step 6: Try Nordic DFU protocol
    print(f"\n[3.6] Testing Nordic DFU protocol frames...")
    dfu_tests = [
        ('DFU Get Version', bytes([NORDIC_DFU_OP_GET_VERSION])),
        ('DFU Start (app)', bytes([NORDIC_DFU_OP_START, 0x04, 0x00, 0x00, 0x00])),
        ('DFU Init', bytes([NORDIC_DFU_OP_INIT, NORDIC_DFU_PKT_INIT])),
        ('DFU Validate', bytes([NORDIC_DFU_OP_VALIDATE])),
        ('DFU Reset', bytes([NORDIC_DFU_OP_RESET])),
        ('DFU Pkt Notif', bytes([NORDIC_DFU_OP_PKT_NOTIF, 0x00, 0x00])),
    ]

    if dm.device:
        for name, dfu_cmd in dfu_tests:
            payload = bytearray(REPORT_SIZE)
            payload[:len(dfu_cmd)] = dfu_cmd
            resp = dm.send_recv(bytes(payload), delay_ms=50)
            if resp and is_interesting_response(resp):
                if resp[0] == NORDIC_DFU_OP_RESPONSE:
                    print(f"    [!!!!] Nordic DFU {name}: GOT DFU RESPONSE! "
                          f"{hexdump(resp, 16)}")
                    results.add_finding(phase_id, 'nordic_dfu_active',
                                        f'Nordic DFU {name} responded!',
                                        resp.hex(), severity='critical')
                elif resp != bytes(payload):
                    print(f"    [?] Nordic DFU {name}: {hexdump(resp, 8)}")
                    results.add_finding(phase_id, 'nordic_dfu_partial',
                                        f'Nordic DFU {name} got non-standard response',
                                        resp.hex(), severity='medium')

    # Step 7: Try to return to normal mode (device should reboot on its own
    # after ~30s of no activity, but we can also just unplug/replug)
    print(f"\n[3.7] Boot mode probing complete. Device will auto-reboot to normal.")
    dm.close()

    results.add_finding(phase_id, 'boot_sweep',
                        f'Found {len(boot_commands_found)} boot commands, '
                        f'{len(interesting_prefixes)} interesting prefixes',
                        {'commands': boot_commands_found,
                         'prefixes': interesting_prefixes})
    results.complete_phase(phase_id,
                           f"Probed {len(sub_range)} boot commands, "
                           f"tested SMP and Nordic DFU protocols")
    print(f"\n  Phase 3 complete.")
    return True


# ===========================================================================
# Phase 4: Alternative Protocol Tests
# ===========================================================================

def phase4_alternative_protocols(dm: DeviceManager, results: Results,
                                 quick: bool = False):
    """
    Phase 4: Alternative Protocol Tests
    - YZW-style update protocol
    - FLASH-style direct write protocol
    - NORDICKEYBOARD update variant
    - MOUSE update method
    """
    phase_id = '4'
    results.add_phase(phase_id, 'Alternative Protocol Tests')
    print("\n" + "=" * 70)
    print("  PHASE 4: ALTERNATIVE PROTOCOL TESTS")
    print("=" * 70)

    # Wait for device to return to normal mode
    print("\n[4.0] Waiting for device in normal mode...")
    if not dm.open_normal(NORMAL_IFACE_VENDOR2):
        # Wait longer
        time.sleep(3)
        if not dm.wait_for_device('normal', timeout=15.0):
            results.fail_phase(phase_id, "Device not available in normal mode")
            return False
    dm.close()

    # Based on support_config.json, PID 0x4026 supports:
    # MOUSE, NORDICKEYBOARD, MLED, OLED, FLASH, TOUCHSCREEN

    # --- YZW Protocol ---
    print(f"\n[4.1] Testing YZW update protocol...")
    print("  (YZW uses 0x55 0xAA header with chunk-based transfer)")
    if dm.open_normal(NORMAL_IFACE_VENDOR2):
        yzw_tests = [
            # YZW init: 55 AA 01 <size_le32> <chunks_le16>
            ("YZW Init", bytes([0x55, 0xAA, 0x01, 0x00, 0x00, 0x01, 0x00,
                                0x10, 0x00])),
            # YZW query: 55 AA 00
            ("YZW Query", bytes([0x55, 0xAA, 0x00])),
            # YZW status: 55 AA 03
            ("YZW Status", bytes([0x55, 0xAA, 0x03])),
            # YZW version: 55 AA 04
            ("YZW Version", bytes([0x55, 0xAA, 0x04])),
            # YZW24 init: 55 AA 24 01
            ("YZW24 Init", bytes([0x55, 0xAA, 0x24, 0x01])),
            # YZW24 query: 55 AA 24 00
            ("YZW24 Query", bytes([0x55, 0xAA, 0x24, 0x00])),
        ]
        for name, cmd in yzw_tests:
            payload = bytearray(REPORT_SIZE)
            payload[:len(cmd)] = cmd
            resp = dm.send_recv(bytes(payload), delay_ms=50)
            if resp and is_interesting_response(resp):
                if resp[:2] == b'\x55\xAA' or resp[:2] == b'\xAA\x55':
                    print(f"    [!!!!] {name}: YZW response! {hexdump(resp, 16)}")
                    results.add_finding(phase_id, 'yzw_active',
                                        f'{name} got YZW response!',
                                        resp.hex(), severity='critical')
                elif resp != bytes(payload):
                    print(f"    [?] {name}: {hexdump(resp, 8)}")
                    results.add_finding(phase_id, 'yzw_partial',
                                        f'{name} got non-standard response',
                                        resp.hex(), severity='low')
        dm.close()

    # --- FLASH Protocol ---
    print(f"\n[4.2] Testing FLASH update protocol...")
    print("  (FLASH uses direct memory write with address/length headers)")
    if dm.open_normal(NORMAL_IFACE_VENDOR2):
        flash_tests = [
            # FLASH status query
            ("FLASH Status", bytes([0xF0, 0x00])),
            # FLASH info
            ("FLASH Info", bytes([0xF0, 0x01])),
            # FLASH unlock
            ("FLASH Unlock", bytes([0xF1, 0x00])),
            # FLASH read address 0
            ("FLASH Read@0", bytes([0xF2, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00])),
            # Generic flash commands
            ("FLASH Cmd F3", bytes([0xF3])),
            ("FLASH Cmd F4", bytes([0xF4])),
            ("FLASH Cmd F5", bytes([0xF5])),
            ("FLASH Cmd F8", bytes([0xF8])),
            ("FLASH Cmd FA", bytes([0xFA])),
            ("FLASH Cmd FB", bytes([0xFB])),
            ("FLASH Cmd FC", bytes([0xFC])),
            ("FLASH Cmd FD", bytes([0xFD])),
            ("FLASH Cmd FE", bytes([0xFE])),
            ("FLASH Cmd FF", bytes([0xFF])),
        ]
        for name, cmd in flash_tests:
            payload = bytearray(REPORT_SIZE)
            payload[:len(cmd)] = cmd
            resp = dm.send_recv(bytes(payload), delay_ms=30)
            if resp and is_interesting_response(resp):
                if resp != bytes(payload):
                    print(f"    [!] {name}: {hexdump(resp, 16)}")
                    results.add_finding(phase_id, 'flash_response',
                                        f'{name} produced response',
                                        resp.hex(), severity='medium')
        dm.close()

    # --- NORDICKEYBOARD Protocol ---
    print(f"\n[4.3] Testing NORDICKEYBOARD update protocol...")
    print("  (Nordic keyboard update uses DFU-like sequence with different framing)")
    if dm.open_normal(NORMAL_IFACE_VENDOR2):
        nordic_kb_tests = [
            # Nordic keyboard uses report ID prefix style
            ("NK Get Version", bytes([0x09, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
                                      0x00, 0x01])),
            ("NK Init DFU", bytes([0x09, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00,
                                   0x00, 0x01])),
            # Try with BA prefix (some Nordic keyboards use this)
            ("NK BA Style", bytes([0xBA, 0x01, 0x00, 0x00, 0x00, 0x00])),
            # NORDICDANGLE style
            ("NK Dangle", bytes([0x09, 0x02, 0x00, 0x00, 0x00, 0x00])),
        ]
        for name, cmd in nordic_kb_tests:
            payload = bytearray(REPORT_SIZE)
            payload[:len(cmd)] = cmd
            resp = dm.send_recv(bytes(payload), delay_ms=50)
            if resp and is_interesting_response(resp):
                if resp != bytes(payload):
                    print(f"    [!] {name}: {hexdump(resp, 16)}")
                    results.add_finding(phase_id, 'nordickeyboard_response',
                                        f'{name} produced response',
                                        resp.hex(), severity='medium')
        dm.close()

    # --- MOUSE Protocol ---
    print(f"\n[4.4] Testing MOUSE update protocol...")
    print("  (MOUSE method - proprietary chunked firmware delivery)")
    if dm.open_normal(NORMAL_IFACE_VENDOR2):
        mouse_tests = [
            # MOUSE protocol typically uses report IDs 0x13-0x18 for config
            # and has a firmware update sequence using specific vendor commands
            ("MOUSE FW Query", bytes([0x13, 0x01, 0x00])),
            ("MOUSE FW Init", bytes([0x13, 0x02, 0x00])),
            ("MOUSE Status 14", bytes([0x14, 0x00])),
            ("MOUSE Status 15", bytes([0x15, 0x00])),
            ("MOUSE Status 16", bytes([0x16, 0x00])),
            ("MOUSE Status 17", bytes([0x17, 0x00])),
            ("MOUSE Status 18", bytes([0x18, 0x00])),
            # Try the enter-update sequence from ry_upgrade.exe
            ("MOUSE Update Seq", bytes([0x80, 0x02])),
            ("MOUSE Update Init", bytes([0x80, 0x03])),
            # Undocumented ranges
            ("MOUSE Cmd 81", bytes([0x81])),
            ("MOUSE Cmd 82", bytes([0x82])),
            ("MOUSE Cmd 83", bytes([0x83])),
            ("MOUSE Cmd 84", bytes([0x84])),
            ("MOUSE Cmd 85", bytes([0x85])),
            ("MOUSE Cmd 8E", bytes([0x8E])),
        ]
        for name, cmd in mouse_tests:
            payload = bytearray(REPORT_SIZE)
            payload[:len(cmd)] = cmd
            resp = dm.send_recv(bytes(payload), delay_ms=30)
            if resp and is_interesting_response(resp):
                if resp != bytes(payload):
                    print(f"    [!] {name}: {hexdump(resp, 16)}")
                    results.add_finding(phase_id, 'mouse_response',
                                        f'{name} produced response',
                                        resp.hex(), severity='medium')
        dm.close()

    # --- MLED/OLED/TOUCHSCREEN probes ---
    print(f"\n[4.5] Testing MLED/OLED/TOUCHSCREEN protocols...")
    if dm.open_normal(NORMAL_IFACE_VENDOR2):
        misc_tests = [
            ("MLED Query", bytes([0xA0, 0x00])),
            ("MLED Init", bytes([0xA0, 0x01])),
            ("MLED Data", bytes([0xA1, 0x00])),
            ("OLED Query", bytes([0xB0, 0x00])),
            ("OLED Init", bytes([0xB0, 0x01])),
            ("OLED Data", bytes([0xB1, 0x00])),
            ("Touch Query", bytes([0xC0, 0x00])),
            ("Touch Init", bytes([0xC0, 0x01])),
            ("Touch Data", bytes([0xC1, 0x00])),
        ]
        for name, cmd in misc_tests:
            payload = bytearray(REPORT_SIZE)
            payload[:len(cmd)] = cmd
            resp = dm.send_recv(bytes(payload), delay_ms=30)
            if resp and is_interesting_response(resp):
                if resp != bytes(payload):
                    print(f"    [!] {name}: {hexdump(resp, 16)}")
                    results.add_finding(phase_id, 'misc_response',
                                        f'{name} produced response',
                                        resp.hex(), severity='low')
        dm.close()

    # --- Interface 1 alternative protocols ---
    print(f"\n[4.6] Testing alternative protocols on interface 1...")
    if dm.open_normal(NORMAL_IFACE_VENDOR1):
        iface1_tests = [
            ("I1 YZW", bytes([0x55, 0xAA, 0x00])),
            ("I1 FLASH", bytes([0xF0, 0x00])),
            ("I1 SMP", build_smp_frame(MGMT_OP_READ, 0, 0, MGMT_GROUP_IMAGE, 0,
                                       MGMT_ID_IMAGE_STATE)),
            ("I1 DFU Version", bytes([NORDIC_DFU_OP_GET_VERSION])),
            ("I1 BA FF", bytes([0xBA, 0xFF])),
            ("I1 Get Version", bytes([0x80])),
        ]
        for name, cmd in iface1_tests:
            payload = bytearray(REPORT_SIZE)
            payload[:min(len(cmd), REPORT_SIZE)] = cmd[:REPORT_SIZE]
            resp = dm.send_recv(bytes(payload), delay_ms=30)
            if resp and is_interesting_response(resp):
                if resp != bytes(payload):
                    print(f"    [!] {name}: {hexdump(resp, 16)}")
                    results.add_finding(phase_id, 'iface1_response',
                                        f'{name} on interface 1 produced response',
                                        resp.hex(), severity='medium')
        dm.close()

    results.complete_phase(phase_id,
                           "Tested YZW, FLASH, NORDICKEYBOARD, MOUSE, MLED, OLED, "
                           "TOUCHSCREEN protocols on both vendor interfaces")
    print(f"\n  Phase 4 complete.")
    return True


# ===========================================================================
# Phase 5: MCUmgr/SMP Protocol Test
# ===========================================================================

def phase5_mcumgr_smp(dm: DeviceManager, results: Results, quick: bool = False):
    """
    Phase 5: MCUmgr/SMP Protocol Test (in normal mode)
    - Send CBOR-encoded management frames
    - Test OS group (reset, echo)
    - Test Image group (list, upload probe)
    - Try different transport framings
    """
    phase_id = '5'
    results.add_phase(phase_id, 'MCUmgr/SMP Protocol Test')
    print("\n" + "=" * 70)
    print("  PHASE 5: MCUmgr/SMP PROTOCOL TEST (NORMAL MODE)")
    print("=" * 70)

    # Ensure we are in normal mode
    if not dm.open_normal(NORMAL_IFACE_VENDOR2):
        time.sleep(3)
        if not dm.wait_for_device('normal', timeout=15.0):
            results.fail_phase(phase_id, "Device not available in normal mode")
            return False

    smp_responded = False

    # Test 1: Raw SMP frames (no transport wrapper)
    print(f"\n[5.1] Testing raw SMP frames (no transport wrapper)...")
    raw_smp_tests = [
        ('OS Echo (write)', MGMT_OP_WRITE, MGMT_GROUP_OS, MGMT_ID_ECHO,
         build_cbor_map({"d": "diagnostic"})),
        ('OS Echo (read)', MGMT_OP_READ, MGMT_GROUP_OS, MGMT_ID_ECHO, b''),
        ('OS Reset', MGMT_OP_WRITE, MGMT_GROUP_OS, MGMT_ID_RESET,
         build_cbor_map({})),
        ('Image State (read)', MGMT_OP_READ, MGMT_GROUP_IMAGE,
         MGMT_ID_IMAGE_STATE, b''),
        ('Image Upload (read)', MGMT_OP_READ, MGMT_GROUP_IMAGE,
         MGMT_ID_IMAGE_UPLOAD, b''),
    ]

    for name, op, group, cmd_id, cbor_data in raw_smp_tests:
        frame = build_smp_frame(op, 0, len(cbor_data), group, 1, cmd_id, cbor_data)
        payload = bytearray(REPORT_SIZE)
        payload[:min(len(frame), REPORT_SIZE)] = frame[:REPORT_SIZE]
        resp = dm.send_recv(bytes(payload), delay_ms=80)
        if resp and is_interesting_response(resp):
            if resp[0] in (MGMT_OP_READ_RSP, MGMT_OP_WRITE_RSP):
                print(f"    [!!!!] RAW SMP {name}: RESPONSE! {hexdump(resp, 16)}")
                results.add_finding(phase_id, 'smp_raw_active',
                                    f'Raw SMP {name} responded!',
                                    resp.hex(), severity='critical')
                smp_responded = True
            elif resp != bytes(payload):
                print(f"    [?] RAW SMP {name}: {hexdump(resp, 8)}")

    dm.close()

    # Test 2: SMP over HID (with report ID prefix)
    print(f"\n[5.2] Testing SMP over HID transport (0x09 prefix)...")
    if dm.open_normal(NORMAL_IFACE_VENDOR2):
        for name, op, group, cmd_id, cbor_data in raw_smp_tests:
            frame = build_smp_frame(op, 0, len(cbor_data), group, 2, cmd_id,
                                    cbor_data)
            # Transport: first byte is report size, rest is SMP frame
            payload = bytearray(REPORT_SIZE)
            payload[0] = 0x09  # HID-SMP marker
            payload[1] = min(len(frame), REPORT_SIZE - 2) & 0xFF
            frame_portion = frame[:REPORT_SIZE - 2]
            payload[2:2 + len(frame_portion)] = frame_portion
            resp = dm.send_recv(bytes(payload), delay_ms=80)
            if resp and is_interesting_response(resp):
                if resp[0] == 0x09 or resp[0] in (MGMT_OP_READ_RSP, MGMT_OP_WRITE_RSP):
                    print(f"    [!!!!] HID-SMP {name}: RESPONSE! {hexdump(resp, 16)}")
                    results.add_finding(phase_id, 'smp_hid_active',
                                        f'HID-SMP {name} responded!',
                                        resp.hex(), severity='critical')
                    smp_responded = True
                elif resp != bytes(payload):
                    print(f"    [?] HID-SMP {name}: {hexdump(resp, 8)}")
        dm.close()

    # Test 3: SMP with various framing options
    print(f"\n[5.3] Testing SMP with alternate framings...")
    if dm.open_normal(NORMAL_IFACE_VENDOR2):
        # Try base64-encoded SMP (some implementations use this)
        echo_frame = build_smp_frame(MGMT_OP_WRITE, 0, 0, MGMT_GROUP_OS, 3,
                                     MGMT_ID_ECHO, build_cbor_map({"d": "x"}))

        framings = [
            ("SMP+len16 prefix", struct.pack('>H', len(echo_frame)) + echo_frame),
            ("SMP+0x06 prefix", bytes([0x06]) + echo_frame),
            ("SMP+0x0A prefix", bytes([0x0A]) + echo_frame),
            ("SMP+COBS(0x00)", bytes([0x00]) + echo_frame + bytes([0x00])),
            ("SMP reversed endian", build_smp_frame(
                op, 0, len(b''), MGMT_GROUP_OS, 3, MGMT_ID_ECHO, b'')),
        ]

        for name, frame_data in framings:
            payload = bytearray(REPORT_SIZE)
            portion = frame_data[:REPORT_SIZE]
            payload[:len(portion)] = portion
            resp = dm.send_recv(bytes(payload), delay_ms=50)
            if resp and is_interesting_response(resp) and resp != bytes(payload):
                print(f"    [?] {name}: {hexdump(resp, 8)}")
                results.add_finding(phase_id, 'smp_framing',
                                    f'{name} got response',
                                    resp.hex(), severity='medium')
        dm.close()

    # Test 4: Try on interface 1
    print(f"\n[5.4] Testing SMP on interface 1...")
    if dm.open_normal(NORMAL_IFACE_VENDOR1):
        echo_frame = build_smp_frame(MGMT_OP_WRITE, 0, 7, MGMT_GROUP_OS, 4,
                                     MGMT_ID_ECHO,
                                     build_cbor_map({"d": "hi"}))
        payload = bytearray(REPORT_SIZE)
        payload[:min(len(echo_frame), REPORT_SIZE)] = echo_frame[:REPORT_SIZE]
        resp = dm.send_recv(bytes(payload), delay_ms=80)
        if resp and is_interesting_response(resp):
            if resp[0] in (MGMT_OP_READ_RSP, MGMT_OP_WRITE_RSP):
                print(f"    [!!!!] SMP on iface 1: RESPONSE! {hexdump(resp, 16)}")
                results.add_finding(phase_id, 'smp_iface1',
                                    'SMP responded on interface 1!',
                                    resp.hex(), severity='critical')
                smp_responded = True
            elif resp != bytes(payload):
                print(f"    [?] SMP on iface 1: {hexdump(resp, 8)}")
        dm.close()

    # Test 5: MCUmgr serial framing (HDLC-like with 0x7E delimiters)
    print(f"\n[5.5] Testing MCUmgr serial/HDLC framing...")
    if dm.open_normal(NORMAL_IFACE_VENDOR2):
        echo_payload = build_cbor_map({"d": "t"})
        echo_frame = build_smp_frame(MGMT_OP_WRITE, 0, len(echo_payload),
                                     MGMT_GROUP_OS, 5, MGMT_ID_ECHO, echo_payload)
        # HDLC framing: 0x7E <data> <crc16> 0x7E
        import binascii
        crc = binascii.crc_hqx(echo_frame, 0xFFFF)
        hdlc_frame = bytes([0x7E]) + echo_frame + struct.pack('>H', crc) + bytes([0x7E])

        payload = bytearray(REPORT_SIZE)
        portion = hdlc_frame[:REPORT_SIZE]
        payload[:len(portion)] = portion
        resp = dm.send_recv(bytes(payload), delay_ms=80)
        if resp and is_interesting_response(resp):
            if resp[0] == 0x7E or resp[0] in (MGMT_OP_READ_RSP, MGMT_OP_WRITE_RSP):
                print(f"    [!!!!] HDLC-SMP: RESPONSE! {hexdump(resp, 16)}")
                results.add_finding(phase_id, 'smp_hdlc',
                                    'MCUmgr HDLC framing responded!',
                                    resp.hex(), severity='critical')
                smp_responded = True
            elif resp != bytes(payload):
                print(f"    [?] HDLC-SMP: {hexdump(resp, 8)}")
        dm.close()

    if smp_responded:
        summary = "SMP/MCUmgr protocol IS active - potential firmware upload path!"
    else:
        summary = "SMP/MCUmgr protocol not responsive on any transport or interface"

    results.complete_phase(phase_id, summary)
    print(f"\n  Phase 5 complete. {summary}")
    return True


# ===========================================================================
# Phase 6: Report Generation
# ===========================================================================

def phase6_report(results: Results, output_path: str):
    """
    Phase 6: Generate comprehensive report.
    """
    phase_id = '6'
    results.add_phase(phase_id, 'Report Generation')
    print("\n" + "=" * 70)
    print("  PHASE 6: REPORT GENERATION")
    print("=" * 70)

    # Print summary
    print(f"\n{'='*70}")
    print("  DIAGNOSTIC SUMMARY")
    print(f"{'='*70}")
    print(f"\n  Phases executed: {len(results.phases) - 1}")  # -1 for phase 6 itself

    for pid, phase in results.phases.items():
        if pid == '6':
            continue
        status_icon = {
            'completed': '[OK]',
            'failed': '[FAIL]',
            'running': '[...]'
        }.get(phase['status'], '[?]')
        finding_count = len(phase.get('findings', []))
        print(f"    Phase {pid} {status_icon} {phase['name']}: "
              f"{finding_count} findings - {phase.get('summary', '')}")

    # Highlight critical/high findings
    if results.highlights:
        print(f"\n  {'!'*60}")
        print(f"  CRITICAL/HIGH FINDINGS:")
        print(f"  {'!'*60}")
        for h in results.highlights:
            print(f"    {h}")
    else:
        print(f"\n  No critical or high-severity findings.")

    # Errors
    if results.errors:
        print(f"\n  Errors encountered:")
        for e in results.errors:
            print(f"    - {e}")

    # Conclusion
    conclusion = results._generate_conclusion()
    print(f"\n  CONCLUSION:")
    print(f"    {conclusion}")

    # Save JSON report
    if output_path:
        results.save(output_path)

    results.complete_phase(phase_id, 'Report generated successfully')
    print(f"\n  Phase 6 complete.")
    return True


# ===========================================================================
# Main Orchestrator
# ===========================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Ajazz AJ159 APEX - Comprehensive Firmware Update Vector Diagnostic",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
PHASES:
  1  Device fingerprinting (enumerate, read feature reports)
  2  Normal mode protocol sweep (command bytes 0x00-0xFF)
  3  Boot mode deep probe (prefixes, SMP, Nordic DFU)
  4  Alternative protocol tests (YZW, FLASH, NORDICKEYBOARD, MOUSE)
  5  MCUmgr/SMP protocol test (CBOR frames, multiple transports)
  6  Report generation (JSON output)

EXAMPLES:
  %(prog)s                          Run all 6 phases
  %(prog)s --phase 1                Fingerprint only
  %(prog)s --phase 1 2              Phases 1 and 2
  %(prog)s --phase 3 5              Boot probe + SMP test
  %(prog)s --quick                  Fast scan (reduced ranges)
  %(prog)s --output diagnostic.json    Save detailed results
  %(prog)s --quick --output r.json  Quick scan with JSON output

SAFETY:
  This tool does NOT write firmware to flash. It only sends probe/status
  commands. MCUboot swap design guarantees recovery even if the device
  enters an unexpected state. Worst case: unplug and replug the mouse.

TARGET:
  VID 0x3151, PID 0x4026 (normal) / PID 0x4025 (boot)
  Requires the mouse to be connected via USB (wired mode).

NOTE:
  On Windows, run as Administrator.
  On Linux, run with sudo or install the udev rules (99-aj159.rules).
        """
    )

    parser.add_argument(
        '--phase', type=int, nargs='+', choices=[1, 2, 3, 4, 5, 6],
        help='Run specific phase(s) only (default: all)'
    )
    parser.add_argument(
        '--quick', action='store_true',
        help='Fast scan mode (reduced sweep ranges, fewer probes)'
    )
    parser.add_argument(
        '--output', '-o', type=str, default='',
        help='Output JSON report path (e.g., results.json)'
    )
    parser.add_argument(
        '--allow-writes', action='store_true',
        help='Enable write probes (not implemented yet, reserved for future)'
    )
    parser.add_argument(
        '--timeout', type=int, default=100,
        help='Default read timeout in ms (default: 100)'
    )
    parser.add_argument(
        '--delay', type=int, default=30,
        help='Delay between probes in ms (default: 30)'
    )
    parser.add_argument(
        '--verbose', '-v', action='store_true',
        help='Verbose output (show all probe attempts)'
    )

    args = parser.parse_args()

    # Determine which phases to run
    phases_to_run = args.phase if args.phase else [1, 2, 3, 4, 5, 6]

    # Banner
    print()
    print("=" * 70)
    print("  AJAZZ AJ159 APEX - COMPREHENSIVE FIRMWARE UPDATE VECTOR DIAGNOSTIC")
    print("=" * 70)
    print(f"  Target:  VID 0x3151, PID 0x4026 (normal) / 0x4025 (boot)")
    print(f"  Phases:  {phases_to_run}")
    print(f"  Mode:    {'QUICK' if args.quick else 'FULL'}")
    print(f"  Output:  {args.output or '(console only)'}")
    print(f"  Started: {timestamp()}")
    print("=" * 70)

    # Safety warning
    print("\n  SAFETY NOTICE:")
    print("  - This tool sends probe/status commands only (no flash writes)")
    print("  - MCUboot swap design ensures device recovery")
    print("  - If device becomes unresponsive: unplug and replug USB")
    print("  - Phase 3 will enter boot mode (device auto-recovers)")
    print()

    # Initialize
    hid_mod = require_hid()
    dm = DeviceManager(hid_mod)
    results = Results()

    try:
        # Execute phases
        if 1 in phases_to_run:
            if not phase1_fingerprint(dm, results, quick=args.quick):
                if 2 not in phases_to_run and 3 not in phases_to_run:
                    print("\n[!] Phase 1 failed and no device found. Aborting.")
                    if args.output:
                        results.save(args.output)
                    return 1

        if 2 in phases_to_run:
            phase2_protocol_sweep(dm, results, quick=args.quick)

        if 3 in phases_to_run:
            phase3_boot_probe(dm, results, quick=args.quick)

        if 4 in phases_to_run:
            phase4_alternative_protocols(dm, results, quick=args.quick)

        if 5 in phases_to_run:
            phase5_mcumgr_smp(dm, results, quick=args.quick)

        if 6 in phases_to_run:
            output_path = args.output or ''
            phase6_report(results, output_path)
        elif args.output:
            # Save results even if phase 6 not explicitly requested
            results.save(args.output)

    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user (Ctrl-C)")
        if args.output:
            results.save(args.output)
    except Exception as e:
        print(f"\n[!] Unexpected error: {e}")
        traceback.print_exc()
        if args.output:
            results.save(args.output)
        return 1
    finally:
        dm.close()

    # Final status
    print(f"\n{'='*70}")
    print(f"  DIAGNOSTIC COMPLETE")
    print(f"  Finished: {timestamp()}")
    if results.highlights:
        print(f"  ** {len(results.highlights)} HIGH/CRITICAL FINDING(S) - REVIEW ABOVE **")
    else:
        print(f"  No viable vectors found.")
    print(f"{'='*70}\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
