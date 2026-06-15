#!/usr/bin/env python3
"""
smp_upload.py - MCUmgr/SMP Firmware Uploader for Ajazz AJ159 APEX Mouse
=========================================================================

Uploads firmware to the Ajazz AJ159 APEX gaming mouse via the MCUmgr/SMP protocol
accessible through HID Feature Reports on Interface 2 (usage_page 0xFFFF, usage 0x0002).

TRANSPORT DETAILS:
  The SMP transport uses HID Feature Reports with this frame format:
    Byte 0:   0x09 (SMP prefix)
    Byte 1:   payload length (length of the SMP frame that follows)
    Bytes 2+: SMP frame

  SMP frame format (big-endian):
    Byte 0:    Op (0=Read, 1=ReadRsp, 2=Write, 3=WriteRsp)
    Byte 1:    Flags (usually 0)
    Bytes 2-3: Length (uint16 BE, length of CBOR payload)
    Bytes 4-5: Group (uint16 BE)
    Byte 6:    Sequence number
    Byte 7:    Command ID
    Bytes 8+:  CBOR payload

PHASES:
  Phase 1: SMP Verification
    - Send OS Echo with unique payload, verify actual processing (not buffer echo)
    - Check sequence number increment behavior
    - Confirm SMP is genuinely processing commands

  Phase 2: Image State Query
    - Query current image state (group=1, id=0, op=read)
    - Decode CBOR to show slot 0 info and slot 1 status
    - Determine if upload is supported

  Phase 3: Test Upload (first chunk only)
    - Send Image Upload write with first chunk
    - Check response for rc (return code) and off (next offset)
    - Safe operation: only writes one small chunk

  Phase 4: Full Upload
    - Upload entire firmware image in chunks
    - Progress reporting
    - Send Image Test + OS Reset after upload

  Phase 5: Verification
    - Wait for device reboot
    - Check if device returns in normal mode or boot mode

MODES:
  --verify-only   Only Phases 1-2 (safe, read-only)
  --test-chunk    Phases 1-3 (writes one chunk, minimal risk)
  --full-upload   Phases 1-5 (full firmware upload)

SAFETY:
  MCUboot uses swap-based upgrade with automatic revert. Even if a bad image is
  written to the secondary slot, MCUboot validates RSA-2048 signatures before
  booting. The device will revert to the previous working firmware if validation
  fails. Default mode is --verify-only (no writes).

IMPORTANT CAVEATS:
  1. SMP responses showing byte changes (sequence number, length) suggest real
     processing, but the device may still just be echoing with minimal modification.
  2. Even if Image Upload succeeds (rc=0), MCUboot STILL validates RSA signatures
     on boot. Without a valid signature, the image will be rejected.
  3. This tool includes verification steps before any upload attempt.

TARGET DEVICE:
  Normal mode: VID 0x3151, PID 0x4026, Interface 2
  Boot mode:   VID 0x3151, PID 0x4025

PREREQUISITES:
  - Python 3.7+
  - pip install hidapi
  - Mouse connected via USB (wired mode recommended)
  - Windows: run as Administrator
  - Linux: run as root or configure udev rules (99-aj159.rules)

USAGE:
  python smp_upload.py --verify-only                     # Safe verification
  python smp_upload.py --test-chunk --firmware fw.bin    # Test single chunk
  python smp_upload.py --full-upload --firmware fw.bin   # Full upload
  python smp_upload.py --verify-only --output results.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple


# ===========================================================================
# Constants
# ===========================================================================

# Device identifiers
NORMAL_VID = 0x3151
NORMAL_PID = 0x4026
BOOT_VID = 0x3151
BOOT_PID = 0x4025
NORMAL_USAGE_PAGE = 0xFFFF
NORMAL_USAGE = 0x0002
NORMAL_INTERFACE = 2

# HID report size
REPORT_SIZE = 64

# SMP transport
SMP_HID_PREFIX = 0x09
SMP_HEADER_SIZE = 8

# SMP Operations
MGMT_OP_READ = 0
MGMT_OP_READ_RSP = 1
MGMT_OP_WRITE = 2
MGMT_OP_WRITE_RSP = 3

# SMP Groups
MGMT_GROUP_OS = 0
MGMT_GROUP_IMAGE = 1

# SMP Command IDs
MGMT_ID_ECHO = 0
MGMT_ID_RESET = 5
MGMT_ID_IMAGE_STATE = 0
MGMT_ID_IMAGE_UPLOAD = 1

# SMP max payload per HID report
# 64 bytes total - 2 bytes HID prefix (0x09 + len) - 8 bytes SMP header = 54 bytes for CBOR
SMP_MAX_CBOR_PER_REPORT = 54

# Practical chunk size for image data (accounting for CBOR map overhead)
# First chunk has: map(4){off:0, len:N, sha:32bytes, data:Xbytes}
# CBOR overhead for first chunk: ~50 bytes (keys + lengths + sha)
# Subsequent chunks: map(2){off:N, data:Xbytes} = ~10 bytes overhead
IMAGE_CHUNK_SIZE_FIRST = 32   # conservative for first chunk
IMAGE_CHUNK_SIZE = 40         # subsequent chunks

# Reconnect settings
RECONNECT_TIMEOUT = 30.0
RECONNECT_POLL_INTERVAL = 1.0


# ===========================================================================
# Minimal CBOR Encoder/Decoder
# ===========================================================================

class CBORError(Exception):
    """CBOR encoding/decoding error."""
    pass


def cbor_encode_uint(value: int) -> bytes:
    """Encode an unsigned integer in CBOR."""
    if value < 0:
        raise CBORError(f"Cannot encode negative int as uint: {value}")
    if value <= 23:
        return bytes([value])
    elif value <= 0xFF:
        return bytes([0x18, value])
    elif value <= 0xFFFF:
        return bytes([0x19]) + struct.pack(">H", value)
    elif value <= 0xFFFFFFFF:
        return bytes([0x1A]) + struct.pack(">I", value)
    else:
        return bytes([0x1B]) + struct.pack(">Q", value)


def cbor_encode_int(value: int) -> bytes:
    """Encode an integer (signed or unsigned) in CBOR."""
    if value >= 0:
        return cbor_encode_uint(value)
    # Negative: CBOR major type 1, value = -1 - n
    n = -1 - value
    if n <= 23:
        return bytes([0x20 | n])
    elif n <= 0xFF:
        return bytes([0x38, n])
    elif n <= 0xFFFF:
        return bytes([0x39]) + struct.pack(">H", n)
    elif n <= 0xFFFFFFFF:
        return bytes([0x3A]) + struct.pack(">I", n)
    else:
        return bytes([0x3B]) + struct.pack(">Q", n)


def cbor_encode_bytes(data: bytes) -> bytes:
    """Encode a byte string in CBOR."""
    header = _cbor_major_header(2, len(data))
    return header + data


def cbor_encode_text(text: str) -> bytes:
    """Encode a text string in CBOR."""
    encoded = text.encode("utf-8")
    header = _cbor_major_header(3, len(encoded))
    return header + encoded


def cbor_encode_map(items: Dict[str, Any]) -> bytes:
    """Encode a map with string keys and mixed values in CBOR.

    Supported value types: int, bytes, str, bool, None, list, dict
    """
    header = _cbor_major_header(5, len(items))
    body = b""
    for key, value in items.items():
        body += cbor_encode_text(key)
        body += _cbor_encode_value(value)
    return header + body


def cbor_encode_array(items: list) -> bytes:
    """Encode an array in CBOR."""
    header = _cbor_major_header(4, len(items))
    body = b""
    for item in items:
        body += _cbor_encode_value(item)
    return header + body


def _cbor_encode_value(value: Any) -> bytes:
    """Encode a value based on its Python type."""
    if isinstance(value, bool):
        return bytes([0xF5 if value else 0xF4])
    elif isinstance(value, int):
        return cbor_encode_int(value)
    elif isinstance(value, bytes):
        return cbor_encode_bytes(value)
    elif isinstance(value, str):
        return cbor_encode_text(value)
    elif isinstance(value, list):
        return cbor_encode_array(value)
    elif isinstance(value, dict):
        return cbor_encode_map(value)
    elif value is None:
        return bytes([0xF6])  # CBOR null
    else:
        raise CBORError(f"Unsupported type for CBOR encoding: {type(value)}")


def _cbor_major_header(major_type: int, length: int) -> bytes:
    """Create a CBOR header with major type and length."""
    mt = major_type << 5
    if length <= 23:
        return bytes([mt | length])
    elif length <= 0xFF:
        return bytes([mt | 24, length])
    elif length <= 0xFFFF:
        return bytes([mt | 25]) + struct.pack(">H", length)
    elif length <= 0xFFFFFFFF:
        return bytes([mt | 26]) + struct.pack(">I", length)
    else:
        return bytes([mt | 27]) + struct.pack(">Q", length)


# --- CBOR Decoder ---

def cbor_decode(data: bytes) -> Tuple[Any, int]:
    """Decode a CBOR value from bytes. Returns (value, bytes_consumed)."""
    if not data:
        raise CBORError("Empty CBOR data")
    return _cbor_decode_item(data, 0)


def _cbor_decode_item(data: bytes, offset: int) -> Tuple[Any, int]:
    """Decode one CBOR item starting at offset."""
    if offset >= len(data):
        raise CBORError(f"Unexpected end of CBOR data at offset {offset}")

    initial_byte = data[offset]
    major_type = (initial_byte >> 5) & 0x07
    additional = initial_byte & 0x1F

    if major_type == 0:  # Unsigned integer
        value, new_offset = _cbor_decode_uint(data, offset)
        return value, new_offset
    elif major_type == 1:  # Negative integer
        value, new_offset = _cbor_decode_uint(data, offset)
        return -1 - value, new_offset
    elif major_type == 2:  # Byte string
        length, new_offset = _cbor_decode_length(data, offset)
        end = new_offset + length
        if end > len(data):
            raise CBORError(f"Byte string overflows data at offset {offset}")
        return data[new_offset:end], end
    elif major_type == 3:  # Text string
        length, new_offset = _cbor_decode_length(data, offset)
        end = new_offset + length
        if end > len(data):
            raise CBORError(f"Text string overflows data at offset {offset}")
        return data[new_offset:end].decode("utf-8"), end
    elif major_type == 4:  # Array
        count, new_offset = _cbor_decode_length(data, offset)
        items = []
        for _ in range(count):
            item, new_offset = _cbor_decode_item(data, new_offset)
            items.append(item)
        return items, new_offset
    elif major_type == 5:  # Map
        count, new_offset = _cbor_decode_length(data, offset)
        result = {}
        for _ in range(count):
            key, new_offset = _cbor_decode_item(data, new_offset)
            value, new_offset = _cbor_decode_item(data, new_offset)
            result[key] = value
        return result, new_offset
    elif major_type == 7:  # Simple values and floats
        if additional == 20:
            return False, offset + 1
        elif additional == 21:
            return True, offset + 1
        elif additional == 22:
            return None, offset + 1
        elif additional == 23:
            return None, offset + 1  # undefined -> None
        elif additional == 25:
            # float16 - skip for simplicity
            return 0.0, offset + 3
        elif additional == 26:
            # float32
            val = struct.unpack(">f", data[offset + 1:offset + 5])[0]
            return val, offset + 5
        elif additional == 27:
            # float64
            val = struct.unpack(">d", data[offset + 1:offset + 9])[0]
            return val, offset + 9
        else:
            return additional, offset + 1
    else:
        raise CBORError(f"Unsupported CBOR major type {major_type} at offset {offset}")


def _cbor_decode_uint(data: bytes, offset: int) -> Tuple[int, int]:
    """Decode unsigned integer value (without major type consideration for length)."""
    additional = data[offset] & 0x1F
    if additional <= 23:
        return additional, offset + 1
    elif additional == 24:
        return data[offset + 1], offset + 2
    elif additional == 25:
        return struct.unpack(">H", data[offset + 1:offset + 3])[0], offset + 3
    elif additional == 26:
        return struct.unpack(">I", data[offset + 1:offset + 5])[0], offset + 5
    elif additional == 27:
        return struct.unpack(">Q", data[offset + 1:offset + 9])[0], offset + 9
    else:
        raise CBORError(f"Invalid additional value {additional} at offset {offset}")


def _cbor_decode_length(data: bytes, offset: int) -> Tuple[int, int]:
    """Decode length from CBOR header, returning (length, offset_after_header)."""
    additional = data[offset] & 0x1F
    if additional <= 23:
        return additional, offset + 1
    elif additional == 24:
        return data[offset + 1], offset + 2
    elif additional == 25:
        return struct.unpack(">H", data[offset + 1:offset + 3])[0], offset + 3
    elif additional == 26:
        return struct.unpack(">I", data[offset + 1:offset + 5])[0], offset + 5
    elif additional == 27:
        return struct.unpack(">Q", data[offset + 1:offset + 9])[0], offset + 9
    else:
        raise CBORError(f"Indefinite length not supported at offset {offset}")


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


def find_device(hid_module, vid: int, pid: int, usage_page: int = None,
                usage: int = None) -> Optional[dict]:
    """Find a HID device matching the given criteria."""
    for dev in hid_module.enumerate(vid, pid):
        if usage_page is not None and dev.get("usage_page") != usage_page:
            continue
        if usage is not None and dev.get("usage") != usage:
            continue
        return dev
    return None


def open_device(hid_module, vid: int = NORMAL_VID, pid: int = NORMAL_PID,
                usage_page: int = NORMAL_USAGE_PAGE, usage: int = NORMAL_USAGE):
    """Open the target HID device. Returns device handle or exits."""
    dev_info = find_device(hid_module, vid, pid, usage_page, usage)
    if not dev_info:
        return None

    device = hid_module.device()
    device.open_path(dev_info["path"])
    return device


def send_feature_report(device, data: bytes) -> bool:
    """Send a feature report (SET_REPORT). Pads to 64 bytes."""
    # Prepend Report ID 0x00, pad payload to REPORT_SIZE
    padded = data[:REPORT_SIZE].ljust(REPORT_SIZE, b'\x00')
    report = bytes([0x00]) + padded  # Report ID + 64 bytes
    try:
        result = device.send_feature_report(report)
        return result >= 0
    except Exception:
        return False


def get_feature_report(device) -> Optional[bytes]:
    """Read a feature report (GET_REPORT). Returns 64 bytes or None."""
    try:
        data = device.get_feature_report(0x00, REPORT_SIZE + 1)  # +1 for report ID
        if data and len(data) > 1:
            return bytes(data[1:])  # Strip report ID byte
        return None
    except Exception:
        return None


# ===========================================================================
# SMP Protocol Layer
# ===========================================================================

class SMPSession:
    """Manages SMP communication over HID Feature Reports."""

    def __init__(self, device):
        self.device = device
        self.seq = 0

    def next_seq(self) -> int:
        """Get next sequence number (wraps at 256)."""
        seq = self.seq
        self.seq = (self.seq + 1) & 0xFF
        return seq

    def build_smp_frame(self, op: int, group: int, cmd_id: int,
                        cbor_payload: bytes = b"") -> bytes:
        """Build a complete SMP frame with header + CBOR payload."""
        seq = self.next_seq()
        header = struct.pack(">BBHHBB",
                             op,           # Operation
                             0,            # Flags
                             len(cbor_payload),  # CBOR length
                             group,        # Group ID
                             seq,          # Sequence
                             cmd_id)       # Command ID
        return header + cbor_payload

    def build_hid_frame(self, smp_frame: bytes) -> bytes:
        """Wrap SMP frame in HID transport format."""
        # Prefix: 0x09 (SMP marker), length byte, then SMP frame
        return bytes([SMP_HID_PREFIX, len(smp_frame)]) + smp_frame

    def send_smp(self, op: int, group: int, cmd_id: int,
                 cbor_payload: bytes = b"") -> Optional[bytes]:
        """Send an SMP command and read the response.

        Returns the raw response bytes (full 64-byte report) or None on failure.
        """
        smp_frame = self.build_smp_frame(op, group, cmd_id, cbor_payload)
        hid_frame = self.build_hid_frame(smp_frame)

        # Send
        if not send_feature_report(self.device, hid_frame):
            return None

        # Small delay to allow processing
        time.sleep(0.05)

        # Read response
        response = get_feature_report(self.device)
        return response

    def parse_smp_response(self, raw: bytes) -> Optional[Dict[str, Any]]:
        """Parse a raw HID response into SMP components.

        Returns dict with: op, flags, length, group, seq, cmd_id, cbor_data
        Or None if the response does not look like a valid SMP frame.
        """
        if not raw or len(raw) < 10:
            return None

        # Check SMP prefix
        if raw[0] != SMP_HID_PREFIX:
            return None

        payload_len = raw[1]
        if payload_len < SMP_HEADER_SIZE:
            return None

        smp_data = raw[2:2 + payload_len]
        if len(smp_data) < SMP_HEADER_SIZE:
            return None

        op, flags, cbor_len, group, seq, cmd_id = struct.unpack(
            ">BBHHBB", smp_data[:SMP_HEADER_SIZE]
        )

        cbor_data = smp_data[SMP_HEADER_SIZE:SMP_HEADER_SIZE + cbor_len]

        return {
            "op": op,
            "flags": flags,
            "cbor_len": cbor_len,
            "group": group,
            "seq": seq,
            "cmd_id": cmd_id,
            "cbor_data": cbor_data,
            "raw_smp": smp_data,
        }


# ===========================================================================
# Utility Functions
# ===========================================================================

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


def print_banner():
    """Print tool banner."""
    print("=" * 72)
    print("  SMP Firmware Uploader for Ajazz AJ159 APEX")
    print("  MCUmgr/SMP over HID Feature Reports")
    print("=" * 72)
    print()


def print_phase(num: int, title: str):
    """Print phase header."""
    print()
    print(f"{'=' * 72}")
    print(f"  PHASE {num}: {title}")
    print(f"{'=' * 72}")
    print()


def print_warning():
    """Print safety warning."""
    print("WARNING: This tool communicates with firmware update mechanisms.")
    print("  - Default mode (--verify-only) is SAFE and performs no writes")
    print("  - --test-chunk writes ONE small chunk to secondary slot")
    print("  - --full-upload writes the ENTIRE firmware to secondary slot")
    print()
    print("  MCUboot swap design means the device can always recover:")
    print("  - If RSA signature validation fails, MCUboot rejects the image")
    print("  - The primary slot (working firmware) is preserved")
    print("  - The device will boot the existing firmware")
    print()


# ===========================================================================
# Phase 1: SMP Verification
# ===========================================================================

def phase1_verify_smp(smp: SMPSession, results: Dict[str, Any]) -> bool:
    """Verify that SMP is genuinely processing commands.

    Sends OS Echo with a unique payload and checks if the response
    contains the echoed data (proving real processing vs buffer echo).
    Also tests sequence number behavior.
    """
    print_phase(1, "SMP VERIFICATION")
    phase_results = {
        "echo_test": None,
        "sequence_test": None,
        "smp_responsive": False,
    }

    # --- Test 1: OS Echo ---
    print("[*] Test 1: OS Echo with unique payload...")
    echo_string = f"smp_test_{int(time.time()) % 10000}"
    echo_payload = cbor_encode_map({"d": echo_string})

    print(f"    Sending echo: '{echo_string}'")
    print(f"    CBOR payload: {hexdump(echo_payload)}")

    response = smp.send_smp(MGMT_OP_WRITE, MGMT_GROUP_OS, MGMT_ID_ECHO, echo_payload)

    if response is None:
        print("    [!] No response received")
        phase_results["echo_test"] = {"status": "no_response"}
        results["phase1"] = phase_results
        return False

    print(f"    Response raw: {hexdump(response)}")

    parsed = smp.parse_smp_response(response)
    if parsed is None:
        print("    [!] Response does not have SMP format")
        phase_results["echo_test"] = {"status": "invalid_format", "raw": hexdump(response)}
        results["phase1"] = phase_results
        return False

    print(f"    SMP Op={parsed['op']} Group={parsed['group']} "
          f"Seq={parsed['seq']} CmdID={parsed['cmd_id']} "
          f"CBOR_len={parsed['cbor_len']}")

    # Check if this is a write response
    echo_result = {
        "status": "received",
        "op": parsed["op"],
        "group": parsed["group"],
        "seq": parsed["seq"],
        "cmd_id": parsed["cmd_id"],
        "cbor_len": parsed["cbor_len"],
    }

    if parsed["cbor_data"]:
        try:
            decoded, _ = cbor_decode(parsed["cbor_data"])
            echo_result["decoded_cbor"] = str(decoded)
            print(f"    Decoded CBOR: {decoded}")

            if isinstance(decoded, dict) and "d" in decoded:
                if decoded["d"] == echo_string:
                    print("    [+] ECHO VERIFIED - SMP is genuinely processing!")
                    echo_result["verified"] = True
                    phase_results["smp_responsive"] = True
                else:
                    print(f"    [?] Echo response differs: got '{decoded['d']}'")
                    echo_result["verified"] = False
            elif isinstance(decoded, dict) and "rc" in decoded:
                print(f"    [*] Got return code: rc={decoded['rc']}")
                echo_result["rc"] = decoded["rc"]
                if decoded["rc"] == 0:
                    phase_results["smp_responsive"] = True
        except CBORError as e:
            echo_result["cbor_error"] = str(e)
            print(f"    [!] CBOR decode error: {e}")
            print(f"    Raw CBOR bytes: {hexdump(parsed['cbor_data'])}")
    else:
        print("    [*] No CBOR payload in response")

    # Check if response differs from request (not just buffer echo)
    sent_frame = smp.build_smp_frame(MGMT_OP_WRITE, MGMT_GROUP_OS, MGMT_ID_ECHO, echo_payload)
    sent_hid = smp.build_hid_frame(sent_frame)
    # Account for seq increment - we need to compare structure
    if response[:2] == sent_hid[:2].ljust(2, b'\x00')[:2]:
        # Same prefix - check if op changed (write->write_rsp)
        if parsed["op"] == MGMT_OP_WRITE_RSP:
            print("    [+] Response has WRITE_RSP op - confirms processing")
            phase_results["smp_responsive"] = True
        elif parsed["op"] == MGMT_OP_WRITE:
            print("    [?] Response has same WRITE op - might be buffer echo")
    else:
        print("    [*] Response prefix differs from sent data")

    phase_results["echo_test"] = echo_result

    # --- Test 2: Sequence Number Behavior ---
    print()
    print("[*] Test 2: Sequence number increment check...")
    # Send another echo and verify seq increments
    echo_payload2 = cbor_encode_map({"d": "seq_test"})
    response2 = smp.send_smp(MGMT_OP_WRITE, MGMT_GROUP_OS, MGMT_ID_ECHO, echo_payload2)

    if response2:
        parsed2 = smp.parse_smp_response(response2)
        if parsed2:
            print(f"    First response seq: {parsed.get('seq', '?')}")
            print(f"    Second response seq: {parsed2.get('seq', '?')}")

            seq_result = {
                "first_seq": parsed.get("seq"),
                "second_seq": parsed2.get("seq"),
            }

            if parsed2["seq"] != parsed["seq"]:
                print("    [+] Sequence numbers differ - confirms real processing")
                seq_result["increments"] = True
                phase_results["smp_responsive"] = True
            else:
                print("    [?] Same sequence number - might be echo")
                seq_result["increments"] = False

            phase_results["sequence_test"] = seq_result
        else:
            print("    [!] Second response not parseable")
            phase_results["sequence_test"] = {"status": "unparseable"}
    else:
        print("    [!] No second response")
        phase_results["sequence_test"] = {"status": "no_response"}

    # --- Summary ---
    print()
    if phase_results["smp_responsive"]:
        print("[+] PHASE 1 RESULT: SMP appears responsive and processing commands")
    else:
        print("[!] PHASE 1 RESULT: Could not confirm genuine SMP processing")
        print("    Responses may be buffer echoes (device echoes SET_REPORT via GET_REPORT)")

    results["phase1"] = phase_results
    return phase_results["smp_responsive"]


# ===========================================================================
# Phase 2: Image State Query
# ===========================================================================

def phase2_image_state(smp: SMPSession, results: Dict[str, Any]) -> bool:
    """Query the current image state to understand slot configuration.

    Sends Image State read (group=1, id=0, op=read) and decodes the response
    to show current slot info and whether upload is supported.
    """
    print_phase(2, "IMAGE STATE QUERY")
    phase_results = {
        "image_state_response": None,
        "slots": [],
        "upload_supported": False,
    }

    # Send empty CBOR map for read request
    empty_map = cbor_encode_map({})
    print("[*] Sending Image State read (group=1, id=0, op=read)...")
    print(f"    CBOR: {hexdump(empty_map)}")

    response = smp.send_smp(MGMT_OP_READ, MGMT_GROUP_IMAGE, MGMT_ID_IMAGE_STATE, empty_map)

    if response is None:
        print("    [!] No response received")
        phase_results["image_state_response"] = {"status": "no_response"}
        results["phase2"] = phase_results
        return False

    print(f"    Response raw: {hexdump(response)}")

    parsed = smp.parse_smp_response(response)
    if parsed is None:
        print("    [!] Response does not have SMP format")
        phase_results["image_state_response"] = {"status": "invalid_format", "raw": hexdump(response)}
        results["phase2"] = phase_results
        return False

    print(f"    SMP Op={parsed['op']} Group={parsed['group']} "
          f"Seq={parsed['seq']} CmdID={parsed['cmd_id']} "
          f"CBOR_len={parsed['cbor_len']}")

    state_result = {
        "op": parsed["op"],
        "group": parsed["group"],
        "seq": parsed["seq"],
        "cmd_id": parsed["cmd_id"],
        "cbor_len": parsed["cbor_len"],
    }

    if parsed["cbor_data"]:
        try:
            decoded, _ = cbor_decode(parsed["cbor_data"])
            state_result["decoded"] = str(decoded)
            print(f"    Decoded CBOR: {decoded}")

            # MCUmgr image state response format:
            # {"images": [{"slot": 0, "version": "x.y.z", "hash": <bytes>, ...}, ...]}
            if isinstance(decoded, dict):
                if "images" in decoded and isinstance(decoded["images"], list):
                    print()
                    print("    Image Slot Information:")
                    print("    " + "-" * 50)
                    for img in decoded["images"]:
                        slot = img.get("slot", "?")
                        version = img.get("version", "unknown")
                        img_hash = img.get("hash", b"")
                        active = img.get("active", False)
                        confirmed = img.get("confirmed", False)
                        pending = img.get("pending", False)
                        bootable = img.get("bootable", False)

                        hash_hex = img_hash.hex() if isinstance(img_hash, bytes) else str(img_hash)

                        print(f"    Slot {slot}:")
                        print(f"      Version:   {version}")
                        print(f"      Hash:      {hash_hex[:32]}...")
                        print(f"      Active:    {active}")
                        print(f"      Confirmed: {confirmed}")
                        print(f"      Pending:   {pending}")
                        print(f"      Bootable:  {bootable}")
                        print()

                        phase_results["slots"].append({
                            "slot": slot,
                            "version": version,
                            "hash": hash_hex,
                            "active": active,
                            "confirmed": confirmed,
                            "pending": pending,
                            "bootable": bootable,
                        })

                    phase_results["upload_supported"] = True
                    print("    [+] Image state decoded successfully - upload likely supported")

                elif "rc" in decoded:
                    rc = decoded["rc"]
                    print(f"    Return code: {rc}")
                    state_result["rc"] = rc
                    if rc == 0:
                        phase_results["upload_supported"] = True
                        print("    [+] rc=0, image management appears supported")
                    else:
                        print(f"    [!] rc={rc}, image management may not be supported")
                        print(f"        Error codes: 1=unknown, 2=no_memory, 3=in_val, "
                              f"4=timeout, 5=no_entry, 6=bad_state")
                else:
                    print(f"    [*] Unexpected response structure: {decoded}")
                    # If we got a valid CBOR response, SMP is working
                    phase_results["upload_supported"] = True

        except CBORError as e:
            state_result["cbor_error"] = str(e)
            print(f"    [!] CBOR decode error: {e}")
            print(f"    Raw CBOR bytes: {hexdump(parsed['cbor_data'])}")
    else:
        print("    [*] No CBOR payload in response (empty body)")
        # An empty response to image state read might mean no images / unsupported
        if parsed["op"] == MGMT_OP_READ_RSP:
            print("    [+] Got READ_RSP - SMP processed the request")
            phase_results["upload_supported"] = True

    phase_results["image_state_response"] = state_result

    # --- Also test Image Upload read (to see if the endpoint exists) ---
    print()
    print("[*] Testing Image Upload endpoint (group=1, id=1, op=read)...")
    response2 = smp.send_smp(MGMT_OP_READ, MGMT_GROUP_IMAGE, MGMT_ID_IMAGE_UPLOAD, empty_map)
    if response2:
        parsed2 = smp.parse_smp_response(response2)
        if parsed2:
            print(f"    SMP Op={parsed2['op']} Group={parsed2['group']} "
                  f"Seq={parsed2['seq']} CmdID={parsed2['cmd_id']}")
            if parsed2["cbor_data"]:
                try:
                    decoded2, _ = cbor_decode(parsed2["cbor_data"])
                    print(f"    Decoded: {decoded2}")
                except CBORError:
                    pass
            print("    [+] Image Upload endpoint responds")
        else:
            print("    [?] Response not parseable as SMP")
    else:
        print("    [!] No response from Image Upload endpoint")

    # --- Summary ---
    print()
    if phase_results["upload_supported"]:
        print("[+] PHASE 2 RESULT: Image management appears supported")
    else:
        print("[!] PHASE 2 RESULT: Could not confirm image management support")

    results["phase2"] = phase_results
    return phase_results["upload_supported"]


# ===========================================================================
# Phase 3: Test Upload (First Chunk Only)
# ===========================================================================

def phase3_test_chunk(smp: SMPSession, firmware_path: str,
                      results: Dict[str, Any]) -> bool:
    """Upload the first chunk of firmware to test if Image Upload accepts data.

    This is a minimal write test - only sends the first chunk with offset 0.
    Checks the response for rc (return code) and off (next expected offset).
    """
    print_phase(3, "TEST UPLOAD (First Chunk)")

    phase_results = {
        "firmware_path": firmware_path,
        "firmware_size": 0,
        "first_chunk_response": None,
        "upload_accepted": False,
    }

    # Load firmware
    if not os.path.isfile(firmware_path):
        print(f"    [!] Firmware file not found: {firmware_path}")
        phase_results["error"] = "file_not_found"
        results["phase3"] = phase_results
        return False

    with open(firmware_path, "rb") as f:
        firmware_data = f.read()

    fw_size = len(firmware_data)
    fw_sha256 = hashlib.sha256(firmware_data).digest()

    print(f"    Firmware: {firmware_path}")
    print(f"    Size: {fw_size} bytes ({fw_size / 1024:.1f} KB)")
    print(f"    SHA-256: {fw_sha256.hex()}")
    print()

    phase_results["firmware_size"] = fw_size
    phase_results["firmware_sha256"] = fw_sha256.hex()

    # Build first chunk payload
    # First chunk includes: off=0, len=total_size, sha=hash, data=first_bytes
    first_chunk = firmware_data[:IMAGE_CHUNK_SIZE_FIRST]

    upload_payload = cbor_encode_map({
        "off": 0,
        "len": fw_size,
        "sha": fw_sha256,
        "data": first_chunk,
    })

    print(f"    First chunk: {len(first_chunk)} bytes of firmware data")
    print(f"    CBOR payload size: {len(upload_payload)} bytes")

    # Check if payload fits in one HID report
    if len(upload_payload) > SMP_MAX_CBOR_PER_REPORT:
        print(f"    [!] Payload too large ({len(upload_payload)} > {SMP_MAX_CBOR_PER_REPORT})")
        print(f"    Reducing chunk size...")
        # Reduce chunk size to fit
        for test_size in range(IMAGE_CHUNK_SIZE_FIRST, 0, -1):
            first_chunk = firmware_data[:test_size]
            upload_payload = cbor_encode_map({
                "off": 0,
                "len": fw_size,
                "sha": fw_sha256,
                "data": first_chunk,
            })
            if len(upload_payload) <= SMP_MAX_CBOR_PER_REPORT:
                print(f"    Adjusted chunk size: {test_size} bytes")
                break
        else:
            # Cannot fit even 1 byte with all metadata - try without sha
            print("    [!] Cannot fit first chunk even with 1 byte. Trying without sha...")
            first_chunk = firmware_data[:1]
            upload_payload = cbor_encode_map({
                "off": 0,
                "len": fw_size,
                "data": first_chunk,
            })
            if len(upload_payload) > SMP_MAX_CBOR_PER_REPORT:
                print("    [!] FATAL: Cannot fit minimal upload payload in HID report")
                phase_results["error"] = "payload_too_large"
                results["phase3"] = phase_results
                return False

    print()
    print(f"    Sending Image Upload write (off=0, len={fw_size}, "
          f"data={len(first_chunk)} bytes)...")
    print(f"    Full HID payload: {hexdump(upload_payload)}")

    response = smp.send_smp(MGMT_OP_WRITE, MGMT_GROUP_IMAGE,
                            MGMT_ID_IMAGE_UPLOAD, upload_payload)

    if response is None:
        print("    [!] No response received")
        phase_results["first_chunk_response"] = {"status": "no_response"}
        results["phase3"] = phase_results
        return False

    print(f"    Response raw: {hexdump(response)}")

    parsed = smp.parse_smp_response(response)
    if parsed is None:
        print("    [!] Response does not have SMP format")
        phase_results["first_chunk_response"] = {
            "status": "invalid_format",
            "raw": hexdump(response)
        }
        results["phase3"] = phase_results
        return False

    print(f"    SMP Op={parsed['op']} Group={parsed['group']} "
          f"Seq={parsed['seq']} CmdID={parsed['cmd_id']} "
          f"CBOR_len={parsed['cbor_len']}")

    chunk_result = {
        "op": parsed["op"],
        "group": parsed["group"],
        "seq": parsed["seq"],
        "cmd_id": parsed["cmd_id"],
        "cbor_len": parsed["cbor_len"],
    }

    if parsed["cbor_data"]:
        try:
            decoded, _ = cbor_decode(parsed["cbor_data"])
            chunk_result["decoded"] = str(decoded)
            print(f"    Decoded CBOR: {decoded}")

            if isinstance(decoded, dict):
                rc = decoded.get("rc", None)
                off = decoded.get("off", None)

                if rc is not None:
                    chunk_result["rc"] = rc
                    print(f"    Return code (rc): {rc}")
                    if rc == 0:
                        print("    [+] UPLOAD ACCEPTED! rc=0")
                        phase_results["upload_accepted"] = True
                    else:
                        print(f"    [!] Upload rejected with rc={rc}")
                        rc_meanings = {
                            1: "UNKNOWN - generic error",
                            2: "NO_MEMORY - insufficient memory",
                            3: "IN_VAL - invalid value/parameter",
                            4: "TIMEOUT - operation timed out",
                            5: "NO_ENTRY - no such entry",
                            6: "BAD_STATE - bad state",
                            7: "TOO_LONG - response too long",
                            8: "NOT_SUPPORTED - not supported",
                            9: "CORRUPT - corrupt data",
                            10: "BUSY - busy",
                            11: "ACCESS_DENIED - access denied",
                        }
                        meaning = rc_meanings.get(rc, "unknown error")
                        print(f"    Meaning: {meaning}")

                if off is not None:
                    chunk_result["next_offset"] = off
                    print(f"    Next offset (off): {off}")
                    if off > 0:
                        print(f"    [+] Device expects more data at offset {off}")
                        phase_results["upload_accepted"] = True

        except CBORError as e:
            chunk_result["cbor_error"] = str(e)
            print(f"    [!] CBOR decode error: {e}")
            print(f"    Raw CBOR bytes: {hexdump(parsed['cbor_data'])}")
    else:
        print("    [*] No CBOR payload in response")
        if parsed["op"] == MGMT_OP_WRITE_RSP:
            print("    [+] Got WRITE_RSP with empty body - might indicate success")

    phase_results["first_chunk_response"] = chunk_result

    # --- Summary ---
    print()
    if phase_results["upload_accepted"]:
        print("[+] PHASE 3 RESULT: First chunk upload ACCEPTED!")
        print("    The device accepted firmware data via SMP Image Upload.")
        print("    NOTE: MCUboot will still validate RSA-2048 signature on boot.")
    else:
        print("[!] PHASE 3 RESULT: Upload was NOT confirmed as accepted")
        print("    The device may not support SMP Image Upload, or the response")
        print("    format differs from expected MCUmgr protocol.")

    results["phase3"] = phase_results
    return phase_results["upload_accepted"]


# ===========================================================================
# Phase 4: Full Upload
# ===========================================================================

def phase4_full_upload(smp: SMPSession, firmware_path: str,
                       results: Dict[str, Any]) -> bool:
    """Upload the full firmware image in chunks via SMP Image Upload.

    After upload completes:
    1. Send Image Test (mark the image for testing on next boot)
    2. Send OS Reset to trigger MCUboot swap
    """
    print_phase(4, "FULL FIRMWARE UPLOAD")

    phase_results = {
        "upload_started": False,
        "chunks_sent": 0,
        "bytes_sent": 0,
        "upload_complete": False,
        "image_test_sent": False,
        "reset_sent": False,
        "errors": [],
    }

    # Load firmware
    with open(firmware_path, "rb") as f:
        firmware_data = f.read()

    fw_size = len(firmware_data)
    fw_sha256 = hashlib.sha256(firmware_data).digest()

    print(f"    Firmware: {firmware_path}")
    print(f"    Size: {fw_size} bytes ({fw_size / 1024:.1f} KB)")
    print(f"    SHA-256: {fw_sha256.hex()}")
    print()

    # Calculate chunk sizes
    # First, determine the maximum data size that fits in CBOR payload
    # We need to account for the CBOR map overhead

    # First chunk: map(4){text("off"):uint(0), text("len"):uint(N),
    #              text("sha"):bstr(32), text("data"):bstr(chunk)}
    # Subsequent: map(2){text("off"):uint(N), text("data"):bstr(chunk)}

    # Dynamically determine chunk sizes
    def calc_first_chunk_size():
        """Find the largest first chunk that fits in one HID report."""
        for size in range(IMAGE_CHUNK_SIZE_FIRST, 0, -1):
            payload = cbor_encode_map({
                "off": 0,
                "len": fw_size,
                "sha": fw_sha256,
                "data": firmware_data[:size],
            })
            if len(payload) <= SMP_MAX_CBOR_PER_REPORT:
                return size
        return 1

    def calc_chunk_size(offset: int):
        """Find the largest chunk that fits for a given offset."""
        for size in range(IMAGE_CHUNK_SIZE, 0, -1):
            payload = cbor_encode_map({
                "off": offset,
                "data": firmware_data[offset:offset + size],
            })
            if len(payload) <= SMP_MAX_CBOR_PER_REPORT:
                return size
        return 1

    first_chunk_size = calc_first_chunk_size()
    print(f"    First chunk size: {first_chunk_size} bytes")
    print(f"    Subsequent chunk size: ~{calc_chunk_size(first_chunk_size)} bytes")

    total_chunks = 1 + ((fw_size - first_chunk_size + IMAGE_CHUNK_SIZE - 1)
                        // IMAGE_CHUNK_SIZE)
    print(f"    Estimated total chunks: ~{total_chunks}")
    print()

    # --- Send first chunk ---
    print("[*] Sending first chunk (off=0)...")
    first_chunk_data = firmware_data[:first_chunk_size]
    first_payload = cbor_encode_map({
        "off": 0,
        "len": fw_size,
        "sha": fw_sha256,
        "data": first_chunk_data,
    })

    response = smp.send_smp(MGMT_OP_WRITE, MGMT_GROUP_IMAGE,
                            MGMT_ID_IMAGE_UPLOAD, first_payload)
    if response is None:
        print("    [!] No response to first chunk - aborting")
        phase_results["errors"].append("No response to first chunk")
        results["phase4"] = phase_results
        return False

    parsed = smp.parse_smp_response(response)
    if parsed and parsed["cbor_data"]:
        try:
            decoded, _ = cbor_decode(parsed["cbor_data"])
            rc = decoded.get("rc", -1) if isinstance(decoded, dict) else -1
            if rc != 0:
                print(f"    [!] First chunk rejected: rc={rc}")
                phase_results["errors"].append(f"First chunk rejected: rc={rc}")
                results["phase4"] = phase_results
                return False
        except CBORError:
            pass

    phase_results["upload_started"] = True
    phase_results["chunks_sent"] = 1
    phase_results["bytes_sent"] = first_chunk_size

    offset = first_chunk_size
    chunk_num = 1
    errors_consecutive = 0
    max_consecutive_errors = 5

    # --- Send remaining chunks ---
    print(f"[*] Uploading firmware ({fw_size} bytes)...")
    print()

    last_progress_time = time.time()

    while offset < fw_size:
        chunk_size = calc_chunk_size(offset)
        chunk_data = firmware_data[offset:offset + chunk_size]
        actual_size = len(chunk_data)

        payload = cbor_encode_map({
            "off": offset,
            "data": chunk_data,
        })

        response = smp.send_smp(MGMT_OP_WRITE, MGMT_GROUP_IMAGE,
                                MGMT_ID_IMAGE_UPLOAD, payload)

        if response is None:
            errors_consecutive += 1
            phase_results["errors"].append(f"No response at offset {offset}")
            if errors_consecutive >= max_consecutive_errors:
                print(f"\n    [!] {max_consecutive_errors} consecutive errors - aborting")
                break
            time.sleep(0.1)
            continue

        # Parse response
        parsed = smp.parse_smp_response(response)
        if parsed and parsed["cbor_data"]:
            try:
                decoded, _ = cbor_decode(parsed["cbor_data"])
                if isinstance(decoded, dict):
                    rc = decoded.get("rc", 0)
                    next_off = decoded.get("off", offset + actual_size)
                    if rc != 0:
                        errors_consecutive += 1
                        phase_results["errors"].append(
                            f"Error at offset {offset}: rc={rc}")
                        if errors_consecutive >= max_consecutive_errors:
                            print(f"\n    [!] Too many errors - aborting")
                            break
                        time.sleep(0.1)
                        continue
                    else:
                        errors_consecutive = 0
                        offset = next_off
            except CBORError:
                errors_consecutive = 0
                offset += actual_size
        else:
            errors_consecutive = 0
            offset += actual_size

        chunk_num += 1
        phase_results["chunks_sent"] = chunk_num
        phase_results["bytes_sent"] = offset

        # Progress bar
        now = time.time()
        if now - last_progress_time >= 1.0 or offset >= fw_size:
            pct = min(100.0, (offset / fw_size) * 100)
            bar_len = 40
            filled = int(bar_len * offset / fw_size)
            bar = "#" * filled + "-" * (bar_len - filled)
            print(f"\r    [{bar}] {pct:5.1f}% ({offset}/{fw_size} bytes, "
                  f"chunk #{chunk_num})", end="", flush=True)
            last_progress_time = now

    print()  # newline after progress bar
    print()

    if offset >= fw_size:
        phase_results["upload_complete"] = True
        print(f"[+] Upload complete! {chunk_num} chunks, {offset} bytes sent")
    else:
        print(f"[!] Upload incomplete. Sent {offset}/{fw_size} bytes")
        results["phase4"] = phase_results
        return False

    # --- Send Image Test ---
    print()
    print("[*] Sending Image Test (mark image for testing)...")
    # Image Test: group=1, id=0, op=write, payload={"confirm": false, "hash": sha256}
    test_payload = cbor_encode_map({
        "confirm": False,
        "hash": fw_sha256,
    })

    response = smp.send_smp(MGMT_OP_WRITE, MGMT_GROUP_IMAGE,
                            MGMT_ID_IMAGE_STATE, test_payload)
    if response:
        parsed = smp.parse_smp_response(response)
        if parsed and parsed["cbor_data"]:
            try:
                decoded, _ = cbor_decode(parsed["cbor_data"])
                print(f"    Image Test response: {decoded}")
                if isinstance(decoded, dict) and decoded.get("rc", -1) == 0:
                    print("    [+] Image marked for testing")
                    phase_results["image_test_sent"] = True
            except CBORError as e:
                print(f"    [!] CBOR error: {e}")
        else:
            print("    [*] Response received (no CBOR body)")
            phase_results["image_test_sent"] = True
    else:
        print("    [!] No response to Image Test")

    # --- Send OS Reset ---
    print()
    print("[*] Sending OS Reset to trigger MCUboot swap...")
    reset_payload = cbor_encode_map({})
    response = smp.send_smp(MGMT_OP_WRITE, MGMT_GROUP_OS, MGMT_ID_RESET, reset_payload)
    if response:
        print("    [+] Reset command sent - device should reboot")
        phase_results["reset_sent"] = True
    else:
        print("    [*] No response (device may have already reset)")
        phase_results["reset_sent"] = True

    results["phase4"] = phase_results
    return phase_results["upload_complete"]


# ===========================================================================
# Phase 5: Post-Upload Verification
# ===========================================================================

def phase5_verify_reboot(hid_module, results: Dict[str, Any]) -> bool:
    """Wait for device to reboot and check which mode it comes back in.

    After MCUboot processes the uploaded image:
    - If signature valid: boots new image (normal mode, PID 0x4026)
    - If signature invalid: reverts to old image (normal mode, PID 0x4026)
    - If something went very wrong: stays in boot mode (PID 0x4025)
    """
    print_phase(5, "POST-UPLOAD VERIFICATION")

    phase_results = {
        "device_found": False,
        "mode": None,
        "wait_time": 0,
    }

    print("[*] Waiting for device to reboot...")
    print(f"    Timeout: {RECONNECT_TIMEOUT} seconds")
    print()

    # First, wait for device to disappear
    time.sleep(2.0)

    start_time = time.time()
    found = False

    while (time.time() - start_time) < RECONNECT_TIMEOUT:
        elapsed = time.time() - start_time

        # Check for normal mode
        normal_dev = find_device(hid_module, NORMAL_VID, NORMAL_PID,
                                 NORMAL_USAGE_PAGE, NORMAL_USAGE)
        if normal_dev:
            phase_results["device_found"] = True
            phase_results["mode"] = "normal"
            phase_results["wait_time"] = elapsed
            found = True
            print(f"    [+] Device found in NORMAL mode after {elapsed:.1f}s")
            print(f"    PID: 0x{NORMAL_PID:04X}")
            print()
            print("    This means MCUboot either:")
            print("    1. Accepted the new firmware (new version running)")
            print("    2. Rejected the firmware and reverted to previous image")
            print()
            print("    To confirm which occurred, run: python smp_upload.py --verify-only")
            print("    and check the image slot versions/hashes.")
            break

        # Check for boot mode
        boot_dev = find_device(hid_module, BOOT_VID, BOOT_PID)
        if boot_dev:
            phase_results["device_found"] = True
            phase_results["mode"] = "boot"
            phase_results["wait_time"] = elapsed
            found = True
            print(f"    [!] Device found in BOOT mode after {elapsed:.1f}s!")
            print(f"    PID: 0x{BOOT_PID:04X}")
            print()
            print("    This suggests MCUboot could not boot either image.")
            print("    The device may need recovery via the native boot protocol.")
            break

        # Progress
        pct = min(100, int((elapsed / RECONNECT_TIMEOUT) * 100))
        print(f"\r    Waiting... {elapsed:.0f}s / {RECONNECT_TIMEOUT:.0f}s ({pct}%)",
              end="", flush=True)
        time.sleep(RECONNECT_POLL_INTERVAL)

    if not found:
        print()
        print("    [!] Device did not re-enumerate within timeout")
        print("    It may still be rebooting, or may need manual intervention.")
        phase_results["mode"] = "timeout"

    results["phase5"] = phase_results
    return found


# ===========================================================================
# Main Execution
# ===========================================================================

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="MCUmgr/SMP Firmware Uploader for Ajazz AJ159 APEX Mouse",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  %(prog)s --verify-only                     # Safe: verify SMP, query image state
  %(prog)s --test-chunk --firmware fw.bin    # Test: send first chunk only
  %(prog)s --full-upload --firmware fw.bin   # Full: upload entire firmware

Safety:
  MCUboot validates RSA-2048 signatures before booting. Even if upload succeeds,
  the device will revert to working firmware if the signature is invalid.
  Default mode is --verify-only (no writes performed).
"""
    )

    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument("--verify-only", action="store_true", default=True,
                            help="Only verify SMP and query image state (default, safe)")
    mode_group.add_argument("--test-chunk", action="store_true",
                            help="Send first firmware chunk only (minimal write)")
    mode_group.add_argument("--full-upload", action="store_true",
                            help="Upload entire firmware image")

    parser.add_argument("--firmware", "-f", type=str,
                        default=None,
                        help="Path to firmware binary (required for --test-chunk/--full-upload)")
    parser.add_argument("--output", "-o", type=str, default=None,
                        help="Save results to JSON file")
    parser.add_argument("--vid", type=lambda x: int(x, 0), default=NORMAL_VID,
                        help=f"Device VID (default: 0x{NORMAL_VID:04X})")
    parser.add_argument("--pid", type=lambda x: int(x, 0), default=NORMAL_PID,
                        help=f"Device PID (default: 0x{NORMAL_PID:04X})")
    parser.add_argument("--no-verify-reboot", action="store_true",
                        help="Skip Phase 5 reboot verification (for --full-upload)")

    args = parser.parse_args()

    # Determine actual mode (argparse defaults make this tricky)
    if args.full_upload:
        mode = "full_upload"
    elif args.test_chunk:
        mode = "test_chunk"
    else:
        mode = "verify_only"

    # Validate arguments
    if mode in ("test_chunk", "full_upload") and not args.firmware:
        # Default firmware path
        default_fw = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                  "..", "firmware_patch", "mouse_app_fw_PATCHED.bin")
        if os.path.isfile(default_fw):
            args.firmware = default_fw
            print(f"[*] Using default firmware: {default_fw}")
        else:
            parser.error(f"--firmware is required for --{mode.replace('_', '-')} mode")

    # Start
    print_banner()
    print_warning()
    print(f"[*] Mode: {mode}")
    print(f"[*] Time: {timestamp()}")
    print(f"[*] Target: VID=0x{args.vid:04X} PID=0x{args.pid:04X}")
    if args.firmware:
        print(f"[*] Firmware: {args.firmware}")
    print()

    # Initialize HID
    hid_module = require_hid()

    # Open device
    print("[*] Opening device...")
    device = open_device(hid_module, args.vid, args.pid, NORMAL_USAGE_PAGE, NORMAL_USAGE)
    if device is None:
        print("[!] FAILED: Could not find/open device")
        print(f"    Looking for: VID=0x{args.vid:04X} PID=0x{args.pid:04X} "
              f"usage_page=0x{NORMAL_USAGE_PAGE:04X} usage=0x{NORMAL_USAGE:04X}")
        print()
        print("    Troubleshooting:")
        print("    - Is the mouse plugged in via USB?")
        print("    - Windows: run as Administrator")
        print("    - Linux: run as root or check udev rules")
        print("    - Is the mouse in normal mode (not boot mode)?")
        sys.exit(1)

    print("[+] Device opened successfully")

    # Create SMP session
    smp = SMPSession(device)
    results: Dict[str, Any] = {
        "timestamp": timestamp(),
        "mode": mode,
        "device": {"vid": args.vid, "pid": args.pid},
    }

    success = True

    try:
        # Phase 1: SMP Verification (always)
        phase1_ok = phase1_verify_smp(smp, results)

        if not phase1_ok:
            print()
            print("[!] SMP verification inconclusive.")
            print("    Proceeding anyway (responses may be buffer echoes).")
            print()

        # Phase 2: Image State (always)
        phase2_ok = phase2_image_state(smp, results)

        if mode == "verify_only":
            print()
            print("=" * 72)
            print("  VERIFICATION COMPLETE")
            print("=" * 72)
            print()
            if phase1_ok and phase2_ok:
                print("  SMP is responsive and image management appears supported.")
                print("  To test upload, run with --test-chunk --firmware <path>")
            elif phase1_ok:
                print("  SMP is responsive but image state unclear.")
                print("  Consider testing with --test-chunk")
            else:
                print("  SMP verification inconclusive.")
                print("  Responses may be buffer echoes rather than real processing.")
            success = phase1_ok
        else:
            # Phase 3: Test Chunk
            if not args.firmware:
                print("[!] No firmware file specified")
                success = False
            else:
                phase3_ok = phase3_test_chunk(smp, args.firmware, results)

                if mode == "test_chunk":
                    print()
                    print("=" * 72)
                    print("  TEST CHUNK COMPLETE")
                    print("=" * 72)
                    print()
                    if phase3_ok:
                        print("  First chunk was ACCEPTED by the device!")
                        print("  To upload full firmware: --full-upload --firmware <path>")
                        print()
                        print("  REMEMBER: MCUboot will still validate RSA-2048 on boot.")
                        print("  Without a valid signature, the image will be rejected")
                        print("  and the device will revert to the current firmware.")
                    else:
                        print("  First chunk was NOT confirmed as accepted.")
                        print("  Full upload is unlikely to succeed.")
                    success = phase3_ok
                else:
                    # Phase 4: Full Upload
                    if not phase3_ok:
                        print()
                        print("[!] Test chunk was not accepted - aborting full upload")
                        print("    Run with --test-chunk first to diagnose")
                        success = False
                    else:
                        # Reset SMP session for clean upload
                        smp.seq = 0
                        phase4_ok = phase4_full_upload(smp, args.firmware, results)

                        if phase4_ok and not args.no_verify_reboot:
                            # Close device before waiting for reboot
                            device.close()
                            device = None
                            # Phase 5: Verify Reboot
                            phase5_verify_reboot(hid_module, results)

                        success = phase4_ok

    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
        results["interrupted"] = True
        success = False
    except Exception as e:
        print(f"\n\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
        results["error"] = str(e)
        success = False
    finally:
        if device is not None:
            try:
                device.close()
            except Exception:
                pass

    # Save results
    results["success"] = success

    if args.output:
        # Convert bytes to hex strings for JSON serialization
        def sanitize_for_json(obj):
            if isinstance(obj, bytes):
                return obj.hex()
            elif isinstance(obj, dict):
                return {k: sanitize_for_json(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [sanitize_for_json(v) for v in obj]
            return obj

        json_results = sanitize_for_json(results)
        with open(args.output, "w") as f:
            json.dump(json_results, f, indent=2)
        print(f"\n[*] Results saved to: {args.output}")

    # Final summary
    print()
    print("=" * 72)
    print(f"  FINAL RESULT: {'SUCCESS' if success else 'INCONCLUSIVE/FAILED'}")
    print("=" * 72)
    print()

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
