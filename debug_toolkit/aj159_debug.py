#!/usr/bin/env python3
"""
aj159_debug.py - Diagnostic / debug toolkit for the Ajazz AJ159 (APEX/PRO/P) and
                 sibling "Compx / RuiYu" platform gaming mice (Attack Shark X11, etc.).

WHAT THIS IS
------------
A read-first USB-HID debugging tool you run LOCALLY on the machine where the mouse
(or its 2.4 GHz / 8K receiver) is plugged in. It can:
  * enumerate and identify the mouse's HID interfaces (list / info)
  * stream raw input reports for reverse engineering (monitor)
  * read battery level on the wireless interface (battery)
  * probe readable feature reports (probe)
  * set polling rate, DPI stages and debounce/RGB via the reverse-engineered
    vendor protocol (set-polling / set-dpi / set-prefs)
  * validate the protocol encoders against known-good vectors WITHOUT hardware
    (selftest)

The config write protocol was reverse-engineered by the community
(attack-shark-x11-driver, MIT). It targets USB interface 2 with HID feature
reports. The AJ159 family shares this RuiYu/Compx platform, but report layouts
can differ between revisions -- ALWAYS run `selftest`, then `monitor` and
`probe` to confirm on YOUR unit before trusting the writes.

SAFETY
------
* This tool does NOT flash firmware. Firmware updates must be done with the
  official RuiYu "ry_upgrade.exe" on Windows (blind flashing bricks devices).
* Writes are throttled (default 300 ms between packets); sending config packets
  too fast can hang this firmware. Recovery: switch the mouse to Bluetooth for a
  few seconds, then back to 2.4 GHz/wired.
* Writing config is opt-in (you must pass the relevant subcommand/flags).

DEPENDENCIES
------------
    pip install hidapi          # required (cross-platform: Win/macOS/Linux)
    pip install pyusb           # optional, only for `descriptor` on Linux

Run `python3 aj159_debug.py --help` for the command list.
"""

from __future__ import annotations

import argparse
import sys
import time

# ----------------------------------------------------------------------------
# Known vendor/product IDs for this mouse family.
# The AJ159 is not individually named in the OEM whitelist; in NORMAL operating
# mode these mice commonly enumerate under one of the VIDs below. In BOOT/DFU
# mode they switch to a bootloader VID (e.g. 0c45 SONiX, 0461 Primax).
# Use `list` to discover the exact VID:PID of YOUR unit, then pass --vid/--pid.
# ----------------------------------------------------------------------------
KNOWN_VENDORS = {
    0x1D57: "Attack Shark / generic 2.4G HID (X11 etc.)",
    0x3151: "Compx (common Ajazz/VGN/Attack Shark normal mode)",
    0x006F: "RuiYu OEM platform",
    0x25A7: "Areson / OEM 2.4G",
    0x25AA: "OEM 2.4G receiver",
    0x342D: "OEM mouse platform",
    0x347A: "OEM mouse platform",
    0x374A: "OEM mouse platform",
    0x3794: "OEM mouse platform",
    0x2717: "Xiaomi/OEM",
    0x0738: "Mad Catz/OEM",
    0x117F: "OEM",
    0x331A: "OEM",
    0x05AC: "Apple VID (used by some dongles)",
}
BOOT_VENDORS = {
    0x0C45: "SONiX bootloader (DFU)",
    0x0461: "Primax bootloader (DFU)",
    0x3151: "Compx bootloader",
    0x25AA: "OEM bootloader",
    0x25A7: "OEM bootloader",
}

# Default config interface for the X11/AJ159 platform.
CONFIG_INTERFACE = 2
INTERRUPT_BATTERY_PREFIX = bytes([0x03, 0x55, 0x40, 0x01])

# ----------------------------------------------------------------------------
# DPI step map (DPI value -> sensor code byte), ported verbatim from
# attack-shark-x11-driver/src/tables/dpi-map.ts (MIT). Supported 50..22000.
# ----------------------------------------------------------------------------
DPI_STEP_MAP = {
    50: 0x01, 100: 0x02, 150: 0x03, 200: 0x04, 250: 0x05, 300: 0x06, 350: 0x08,
    400: 0x09, 450: 0x0a, 500: 0x0b, 550: 0x0c, 600: 0x0e, 650: 0x0f, 700: 0x10,
    750: 0x11, 800: 0x12, 850: 0x13, 900: 0x15, 950: 0x16, 1000: 0x17, 1050: 0x18,
    1100: 0x19, 1150: 0x1b, 1200: 0x1c, 1250: 0x1d, 1300: 0x1e, 1350: 0x1f,
    1400: 0x20, 1450: 0x22, 1500: 0x23, 1550: 0x24, 1600: 0x25, 1650: 0x26,
    1700: 0x27, 1750: 0x29, 1800: 0x2a, 1850: 0x2b, 1900: 0x2c, 1950: 0x2d,
    2000: 0x2f, 2050: 0x30, 2100: 0x31, 2150: 0x32, 2200: 0x33, 2250: 0x34,
    2300: 0x36, 2350: 0x37, 2400: 0x38, 2450: 0x39, 2500: 0x3a, 2550: 0x3b,
    2600: 0x3d, 2650: 0x3e, 2700: 0x3f, 2750: 0x40, 2800: 0x41, 2850: 0x43,
    2900: 0x44, 2950: 0x45, 3000: 0x46, 3050: 0x47, 3100: 0x48, 3150: 0x4a,
    3200: 0x4b, 3250: 0x4c, 3300: 0x4d, 3350: 0x4e, 3400: 0x4f, 3450: 0x51,
    3500: 0x52, 3550: 0x53, 3600: 0x54, 3650: 0x55, 3700: 0x57, 3750: 0x58,
    3800: 0x59, 3850: 0x5a, 3900: 0x5b, 3950: 0x5c, 4000: 0x5e, 4050: 0x5f,
    4100: 0x60, 4150: 0x61, 4200: 0x62, 4250: 0x63, 4300: 0x65, 4350: 0x66,
    4400: 0x67, 4450: 0x68, 4500: 0x69, 4550: 0x6b, 4600: 0x6c, 4650: 0x6d,
    4700: 0x6e, 4750: 0x6f, 4800: 0x70, 4850: 0x72, 4900: 0x73, 4950: 0x74,
    5000: 0x75, 5050: 0x76, 5100: 0x77, 5150: 0x79, 5200: 0x7a, 5250: 0x7b,
    5300: 0x7c, 5350: 0x7d, 5400: 0x7f, 5450: 0x80, 5500: 0x81, 5550: 0x82,
    5600: 0x83, 5650: 0x84, 5700: 0x86, 5750: 0x87, 5800: 0x88, 5850: 0x89,
    5900: 0x8a, 5950: 0x8b, 6000: 0x8d, 6050: 0x8e, 6100: 0x8f, 6150: 0x90,
    6200: 0x91, 6250: 0x93, 6300: 0x94, 6350: 0x95, 6400: 0x96, 6450: 0x97,
    6500: 0x98, 6550: 0x9a, 6600: 0x9b, 6650: 0x9c, 6700: 0x9d, 6750: 0x9e,
    6800: 0x9f, 6850: 0xa1, 6900: 0xa2, 6950: 0xa3, 7000: 0xa4, 7050: 0xa5,
    7100: 0xa7, 7150: 0xa8, 7200: 0xa9, 7250: 0xaa, 7300: 0xab, 7350: 0xac,
    7400: 0xae, 7450: 0xaf, 7500: 0xb0, 7550: 0xb1, 7600: 0xb2, 7650: 0xb3,
    7700: 0xb5, 7750: 0xb6, 7800: 0xb7, 7850: 0xb8, 7900: 0xb9, 7950: 0xbb,
    8000: 0xbc, 8050: 0xbd, 8100: 0xbe, 8150: 0xbf, 8200: 0xc0, 8250: 0xc2,
    8300: 0xc3, 8350: 0xc4, 8400: 0xc5, 8450: 0xc6, 8500: 0xc7, 8550: 0xc9,
    8600: 0xca, 8650: 0xcb, 8700: 0xcc, 8750: 0xcd, 8800: 0xcf, 8850: 0xd0,
    8900: 0xd1, 8950: 0xd2, 9000: 0xd3, 9050: 0xd4, 9100: 0xd6, 9150: 0xd7,
    9200: 0xd8, 9250: 0xd9, 9300: 0xda, 9350: 0xdb, 9400: 0xdd, 9450: 0xde,
    9500: 0xdf, 9550: 0xe0, 9600: 0xe1, 9650: 0xe3, 9700: 0xe4, 9750: 0xe5,
    9800: 0xe6, 9850: 0xe7, 9900: 0xe8, 9950: 0xea, 10000: 0xeb,
    10100: 0x76, 10200: 0x77, 10300: 0x79, 10400: 0x7a, 10500: 0x7b, 10600: 0x7c,
    10700: 0x7d, 10800: 0x7f, 10900: 0x80, 11000: 0x81, 11100: 0x82, 11200: 0x83,
    11300: 0x84, 11400: 0x86, 11500: 0x87, 11600: 0x88, 11700: 0x89, 11800: 0x8a,
    11900: 0x8b, 12000: 0x8d, 12100: 0x8e, 12200: 0x8f, 12300: 0x90, 12400: 0x91,
    12500: 0x93, 12600: 0x94, 12700: 0x95, 12800: 0x96, 12900: 0x97, 13000: 0x98,
    13100: 0x9a, 13200: 0x9b, 13300: 0x9c, 13400: 0x9d, 13500: 0x9e, 13600: 0x9f,
    13700: 0xa1, 13800: 0xa2, 13900: 0xa3, 14000: 0xa4, 14100: 0xa5, 14200: 0xa7,
    14300: 0xa8, 14400: 0xa9, 14500: 0xaa, 14600: 0xab, 14700: 0xac, 14800: 0xae,
    14900: 0xaf, 15000: 0xb0, 15100: 0xb1, 15200: 0xb2, 15300: 0xb3, 15400: 0xb5,
    15500: 0xb6, 15600: 0xb7, 15700: 0xb8, 15800: 0xb9, 15900: 0xbb, 16000: 0xbc,
    16100: 0xbd, 16200: 0xbe, 16300: 0xbf, 16400: 0xc0, 16500: 0xc2, 16600: 0xc3,
    16700: 0xc4, 16800: 0xc5, 16900: 0xc6, 17000: 0xc7, 17100: 0xc9, 17200: 0xca,
    17300: 0xcb, 17400: 0xcc, 17500: 0xcd, 17600: 0xcf, 17700: 0xd0, 17800: 0xd1,
    17900: 0xd2, 18000: 0xd3, 18100: 0xd4, 18200: 0xd6, 18300: 0xd7, 18400: 0xd8,
    18500: 0xd9, 18600: 0xda, 18700: 0xdb, 18800: 0xdd, 18900: 0xde, 19000: 0xdf,
    19100: 0xe0, 19200: 0xe1, 19300: 0xe3, 19400: 0xe4, 19500: 0xe5, 19600: 0xe6,
    19700: 0xe7, 19800: 0xe8, 19900: 0xea, 20000: 0xeb, 20100: 0xeb, 20200: 0x76,
    20300: 0x76, 20400: 0x77, 20500: 0x77, 20600: 0x79, 20700: 0x79, 20800: 0x7a,
    20900: 0x7a, 21000: 0x7b, 21100: 0x7b, 21200: 0x7c, 21300: 0x7c, 21400: 0x7d,
    21500: 0x7d, 21600: 0x7f, 21700: 0x7f, 21800: 0x80, 21900: 0x80, 22000: 0x81,
}


# ============================================================================
# Protocol builders (ports of attack-shark-x11-driver, MIT)
# ============================================================================
def encode_dpi(dpi: int) -> int:
    keys = sorted(DPI_STEP_MAP)
    for k in keys:
        if k >= dpi:
            return DPI_STEP_MAP[k]
    raise ValueError(f"Unsupported DPI: {dpi} (max {keys[-1]})")


def build_polling_report(rate_hz: int) -> bytes:
    """Report 0x06 / wValue 0x0306, 9 bytes."""
    rate_map = {125: 0x08, 250: 0x04, 500: 0x02, 1000: 0x01}
    if rate_hz not in rate_map:
        raise ValueError(f"Unsupported polling rate: {rate_hz} (use 125/250/500/1000)")
    code = rate_map[rate_hz]
    buf = bytearray(9)
    buf[0] = 0x06
    buf[1] = 0x09
    buf[2] = 0x01
    buf[3] = code
    buf[4] = 0xFF - code
    return bytes(buf)


# Fixed constant bytes [25..49] of the DPI report (from DpiBuilder).
_DPI_FIXED_25_49 = [
    0xFF, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0x00,
    0x00, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0x40, 0x00, 0xFF, 0xFF, 0xFF, 0x02,
]


def build_dpi_report(stages, active_stage: int, angle_snap: bool = False,
                     ripple_control: bool = True, wired: bool = False) -> bytes:
    """Report 0x04 / wValue 0x0304, 56 bytes (52 in wired mode)."""
    if len(stages) != 6:
        raise ValueError("Need exactly 6 DPI stage values, e.g. 800 1600 2400 3200 5000 22000")
    if not (1 <= active_stage <= 6):
        raise ValueError("active stage must be 1..6")

    buf = bytearray(56)
    buf[0], buf[1], buf[2] = 0x04, 0x38, 0x01
    buf[3] = 0x01 if angle_snap else 0x00
    buf[4] = 0x01 if ripple_control else 0x00
    buf[5] = 0x3F

    # stage codes
    for i, dpi in enumerate(stages):
        buf[8 + i] = encode_dpi(dpi)

    # stage mask (bit set if dpi > 12000)
    bit_values = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20]
    mask = 0
    for i, dpi in enumerate(stages):
        if dpi > 12000:
            mask |= bit_values[i]
    buf[6] = mask
    buf[7] = mask

    # high-stage flags (bytes 16..21)
    for i, dpi in enumerate(stages):
        buf[16 + i] = 0x01 if ((10100 <= dpi <= 12000) or (20100 <= dpi <= 22000)) else 0x00

    buf[24] = active_stage
    for j, v in enumerate(_DPI_FIXED_25_49):
        buf[25 + j] = v

    checksum = sum(buf[3:50]) & 0xFFFF
    buf[50] = (checksum >> 8) & 0xFF
    buf[51] = checksum & 0xFF
    # 52..55 stay 0x00 (wireless padding)
    return bytes(buf[:52]) if wired else bytes(buf)


LIGHT_MODES = {
    "off": 0x00, "static": 0x10, "breathing": 0x20, "neon": 0x30,
    "colorbreathing": 0x40, "staticdpi": 0x50, "breathingdpi": 0x60,
}


def build_prefs_report(light_mode="off", rgb=(0, 255, 0), led_speed=3,
                       sleep_min=0.5, deep_sleep_min=10, key_response_ms=8,
                       wired: bool = False) -> bytes:
    """Report 0x05 / wValue 0x0305, 15 bytes (13 in wired mode)."""
    if light_mode not in LIGHT_MODES:
        raise ValueError(f"light_mode must be one of {list(LIGHT_MODES)}")
    if not (1 <= led_speed <= 5):
        raise ValueError("led_speed must be 1..5")
    if not (0.5 <= sleep_min <= 30):
        raise ValueError("sleep_min must be 0.5..30")
    if not (1 <= deep_sleep_min <= 60):
        raise ValueError("deep_sleep_min must be 1..60")
    if key_response_ms < 4 or key_response_ms > 50 or key_response_ms % 2 != 0:
        raise ValueError("key_response_ms must be even, 4..50")

    r, g, b = rgb
    buf = bytearray(15)
    buf[0], buf[1], buf[2] = 0x05, 0x0F, 0x01
    buf[3] = LIGHT_MODES[light_mode]
    # index4: high nibble = deep-sleep bucket, low nibble = inverted led speed
    bucket = (deep_sleep_min - 1) // 16
    hw_speed = 6 - led_speed
    buf[4] = ((bucket << 4) | (hw_speed & 0x0F)) & 0xFF
    buf[5] = (0x08 + deep_sleep_min * 0x10) & 0xFF
    buf[6], buf[7], buf[8] = r & 0xFF, g & 0xFF, b & 0xFF
    buf[9] = round(sleep_min * 2)
    buf[10] = (key_response_ms - 4) // 2 + 0x02
    # index11: count of channels >= 0x64 (+1 if BreathingDpi)
    count = sum(1 for c in (r, g, b) if c >= 0x64)
    buf[11] = (count + 1) if light_mode == "breathingdpi" else count
    buf[12] = sum(buf[3:11]) & 0xFF
    return bytes(buf[:13]) if wired else bytes(buf)


# ============================================================================
# HID helpers
# ============================================================================
def _require_hid():
    try:
        import hid  # noqa
        return hid
    except Exception:
        sys.exit("ERROR: the 'hidapi' module is required. Install with:\n"
                 "    pip install hidapi\n"
                 "(On Linux you may also need the libhidapi system package.)")


def _fmt_vid(vid: int) -> str:
    tag = KNOWN_VENDORS.get(vid) or BOOT_VENDORS.get(vid)
    return f"{vid:#06x}" + (f"  <{tag}>" if tag else "")


def cmd_list(args):
    hid = _require_hid()
    devs = hid.enumerate()
    if not devs:
        print("No HID devices found. (On Linux, try sudo or install the udev rule.)")
        return
    # group by (vid, pid)
    print(f"{'VID:PID':14} {'iface':5} {'usage_pg':9} {'usage':6}  product / path")
    print("-" * 90)
    interesting = []
    for d in sorted(devs, key=lambda x: (x['vendor_id'], x['product_id'], x.get('interface_number', -1))):
        vid, pid = d['vendor_id'], d['product_id']
        mark = " *" if (vid in KNOWN_VENDORS or vid in BOOT_VENDORS) else "  "
        prod = (d.get('product_string') or '').strip()
        line = (f"{vid:#06x}:{pid:04x} "
                f"{str(d.get('interface_number')):>5} "
                f"{d.get('usage_page', 0):#06x}  "
                f"{d.get('usage', 0):#06x} {mark} {prod}")
        print(line)
        if mark == " *":
            interesting.append(d)
    print("\n* = VID belongs to a known mouse/receiver/bootloader family.")
    if interesting:
        print("\nLikely target(s):")
        seen = set()
        for d in interesting:
            key = (d['vendor_id'], d['product_id'])
            if key in seen:
                continue
            seen.add(key)
            print(f"  {_fmt_vid(d['vendor_id'])}  PID {d['product_id']:#06x}")
        print("\nPick one and pass:  --vid 0xXXXX --pid 0xYYYY")
        print("Then run:  info / monitor / battery / probe")
    else:
        print("\nNo known-family device matched. Use `monitor` after identifying the mouse,")
        print("or capture USB traffic (see README) to find its VID:PID.")


def _open_target(args, prefer_interface=CONFIG_INTERFACE):
    """Open the HID path matching --vid/--pid, preferring the config interface
    (interface 2) or a vendor-defined usage page (0xff00-0xffff)."""
    hid = _require_hid()
    if args.vid is None or args.pid is None:
        sys.exit("ERROR: please specify --vid and --pid (run `list` first).")
    candidates = [d for d in hid.enumerate(args.vid, args.pid)]
    if not candidates:
        sys.exit(f"ERROR: no device with VID {args.vid:#06x} PID {args.pid:#06x} found.")

    chosen = None
    if args.path:
        for d in candidates:
            if d.get('path') == args.path.encode() or str(d.get('path')) == args.path:
                chosen = d
                break
    if chosen is None:
        # prefer requested interface
        for d in candidates:
            if d.get('interface_number') == prefer_interface:
                chosen = d
                break
    if chosen is None:
        # prefer a vendor usage page
        for d in candidates:
            up = d.get('usage_page', 0)
            if 0xFF00 <= up <= 0xFFFF:
                chosen = d
                break
    if chosen is None:
        chosen = candidates[0]

    h = hid.device()
    try:
        h.open_path(chosen['path'])
    except Exception as e:
        sys.exit(f"ERROR: could not open device path {chosen.get('path')}: {e}\n"
                 "(Linux: needs udev rule or sudo; close other software using the mouse.)")
    return h, chosen, candidates


def cmd_info(args):
    h, chosen, candidates = _open_target(args)
    try:
        print("Selected interface:")
        print(f"  VID:PID          {chosen['vendor_id']:#06x}:{chosen['product_id']:04x}")
        print(f"  manufacturer     {h.get_manufacturer_string()!r}")
        print(f"  product          {h.get_product_string()!r}")
        try:
            print(f"  serial           {h.get_serial_number_string()!r}")
        except Exception:
            pass
        print(f"  interface_number {chosen.get('interface_number')}")
        print(f"  usage_page       {chosen.get('usage_page'):#06x}")
        print(f"  usage            {chosen.get('usage'):#06x}")
        print(f"  release/bcd      {chosen.get('release_number')}")
        print(f"  path             {chosen.get('path')}")
        print(f"\nAll {len(candidates)} interface(s) for this VID:PID:")
        for d in candidates:
            print(f"  iface={d.get('interface_number')!s:>3}  "
                  f"usage_page={d.get('usage_page'):#06x}  usage={d.get('usage'):#06x}  "
                  f"path={d.get('path')}")
    finally:
        h.close()


def cmd_monitor(args):
    h, chosen, _ = _open_target(args, prefer_interface=args.interface)
    print(f"Monitoring input reports on iface {chosen.get('interface_number')} "
          f"(usage_page {chosen.get('usage_page'):#06x}). Ctrl-C to stop.\n"
          "Move/click the mouse, change DPI, dock/undock to elicit reports.")
    h.set_nonblocking(False)
    try:
        while True:
            data = h.read(64, timeout_ms=args.timeout)
            if data:
                hexs = " ".join(f"{b:02x}" for b in data)
                tag = ""
                if bytes(data[:4]) == INTERRUPT_BATTERY_PREFIX:
                    tag = f"   <-- BATTERY {data[4]}%"
                print(f"[{time.strftime('%H:%M:%S')}] ({len(data):2d}) {hexs}{tag}")
    except KeyboardInterrupt:
        print("\nstopped.")
    finally:
        h.close()


def cmd_battery(args):
    h, chosen, _ = _open_target(args, prefer_interface=args.interface)
    print(f"Listening for battery report (03 55 40 01 xx) on iface "
          f"{chosen.get('interface_number')} for up to {args.wait}s ...")
    print("NOTE: battery is reported only in WIRELESS (2.4G/BT) mode, not wired.")
    h.set_nonblocking(False)
    deadline = time.time() + args.wait
    try:
        while time.time() < deadline:
            data = h.read(64, timeout_ms=500)
            if data and bytes(data[:4]) == INTERRUPT_BATTERY_PREFIX and len(data) >= 5:
                print(f"Battery: {data[4]}%")
                return
        print("No battery report received within the timeout.")
        print("Try: wireless mode, move the mouse, or use --interface to pick another interface.")
    except KeyboardInterrupt:
        pass
    finally:
        h.close()


def cmd_probe(args):
    """Read feature reports across report IDs (safe, read-only) to fingerprint
    the device and aid reverse engineering."""
    h, chosen, _ = _open_target(args)
    print(f"Reading feature reports on iface {chosen.get('interface_number')} "
          f"(report IDs {args.first}..{args.last}). Read-only.\n")
    found = 0
    for rid in range(args.first, args.last + 1):
        try:
            data = h.get_feature_report(rid, args.length)
        except Exception as e:
            print(f"  report {rid:#04x}: <error: {e}>")
            continue
        if data and any(data[1:]):
            found += 1
            hexs = " ".join(f"{b:02x}" for b in data)
            print(f"  report {rid:#04x}: {hexs}")
    if not found:
        print("  (no non-empty feature reports returned)")
    h.close()


def _send_feature(args, payload: bytes, label: str):
    h, chosen, _ = _open_target(args)
    iface = chosen.get('interface_number')
    if iface != CONFIG_INTERFACE:
        print(f"WARNING: selected interface is {iface}, expected {CONFIG_INTERFACE}. "
              "Use --path to force the config interface if this fails.")
    print(f"{label}\n  -> feature report ({len(payload)} bytes): "
          + " ".join(f"{b:02x}" for b in payload))
    if not args.yes:
        ans = input("Send this to the device? [y/N] ").strip().lower()
        if ans != "y":
            print("aborted.")
            h.close()
            return
    try:
        n = h.send_feature_report(payload)
        print(f"  sent ({n} bytes). Waiting {args.delay} ms ...")
        time.sleep(args.delay / 1000.0)
        print("  done.")
    except Exception as e:
        print(f"  ERROR sending feature report: {e}")
    finally:
        h.close()


def cmd_set_polling(args):
    payload = build_polling_report(args.rate)
    _send_feature(args, payload, f"Set polling rate -> {args.rate} Hz")


def cmd_set_dpi(args):
    payload = build_dpi_report(args.stages, args.active, angle_snap=args.angle_snap,
                               ripple_control=not args.no_ripple, wired=args.wired)
    _send_feature(args, payload,
                  f"Set DPI stages {args.stages}, active={args.active}, "
                  f"angle_snap={args.angle_snap}, ripple={not args.no_ripple}")


def cmd_set_prefs(args):
    payload = build_prefs_report(light_mode=args.light, rgb=tuple(args.rgb),
                                 led_speed=args.led_speed, sleep_min=args.sleep,
                                 deep_sleep_min=args.deep_sleep,
                                 key_response_ms=args.debounce, wired=args.wired)
    _send_feature(args, payload,
                  f"Set prefs light={args.light} rgb={tuple(args.rgb)} "
                  f"led_speed={args.led_speed} debounce={args.debounce}ms")


def cmd_selftest(args):
    """Validate the encoders against known-good vectors (no hardware needed)."""
    ok = True

    def check(name, got, expect):
        nonlocal ok
        good = got == expect
        ok = ok and good
        print(f"  [{'PASS' if good else 'FAIL'}] {name}")
        if not good:
            print(f"        got:    {got.hex()}")
            print(f"        expect: {expect.hex()}")

    print("Polling rate vectors:")
    check("1000Hz", build_polling_report(1000), bytes.fromhex("060901 01 fe 0000 0000".replace(" ", "")))
    check("125Hz",  build_polling_report(125),  bytes.fromhex("060901 08 f7 0000 0000".replace(" ", "")))
    check("500Hz",  build_polling_report(500),  bytes.fromhex("060901 02 fd 0000 0000".replace(" ", "")))

    print("DPI encoder values:")
    enc_ok = all([
        encode_dpi(800) == 0x12, encode_dpi(1600) == 0x25, encode_dpi(2400) == 0x38,
        encode_dpi(3200) == 0x4b, encode_dpi(5000) == 0x75, encode_dpi(22000) == 0x81,
    ])
    ok = ok and enc_ok
    print(f"  [{'PASS' if enc_ok else 'FAIL'}] 800/1600/2400/3200/5000/22000 -> 12 25 38 4b 75 81")

    print("DPI report (default [800,1600,2400,3200,5000,22000], stage2):")
    dpi = build_dpi_report([800, 1600, 2400, 3200, 5000, 22000], 2)
    cks = (dpi[50] << 8) | dpi[51]
    cks_ok = cks == 0x0F68
    ok = ok and cks_ok
    print(f"  [{'PASS' if cks_ok else 'FAIL'}] checksum == 0x0f68 (got {cks:#06x})")
    fields_ok = (dpi[0:3] == bytes([0x04, 0x38, 0x01]) and dpi[6] == 0x20
                 and dpi[8:14] == bytes([0x12, 0x25, 0x38, 0x4b, 0x75, 0x81])
                 and dpi[21] == 0x01 and dpi[24] == 0x02 and len(dpi) == 56)
    ok = ok and fields_ok
    print(f"  [{'PASS' if fields_ok else 'FAIL'}] header/mask/stages/highflag/active/length")

    print("Prefs report (defaults, wired 13 bytes):")
    prefs = build_prefs_report(wired=True)
    prefs_ok = prefs == bytes.fromhex("050f0100 03 a8 00ff00 01 04 01 af")
    ok = ok and prefs_ok
    print(f"  [{'PASS' if prefs_ok else 'FAIL'}] == 05 0f 01 00 03 a8 00 ff 00 01 04 01 af")
    if not prefs_ok:
        print(f"        got: {prefs.hex()}")

    print("\nRESULT:", "ALL PASS - encoders match reference vectors." if ok
          else "FAILURES present - do not trust writes until fixed.")
    sys.exit(0 if ok else 1)


# ============================================================================
# CLI
# ============================================================================
def build_parser():
    p = argparse.ArgumentParser(
        description="Ajazz AJ159 (APEX/PRO/P) & Compx/RuiYu-platform mouse HID debug toolkit.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Typical flow:\n"
               "  python3 aj159_debug.py selftest\n"
               "  python3 aj159_debug.py list\n"
               "  python3 aj159_debug.py info    --vid 0x3151 --pid 0x4012\n"
               "  python3 aj159_debug.py monitor --vid 0x3151 --pid 0x4012\n"
               "  python3 aj159_debug.py battery --vid 0x3151 --pid 0x4012\n"
               "  python3 aj159_debug.py set-polling --vid 0x3151 --pid 0x4012 --rate 1000\n")

    def add_target(sp):
        sp.add_argument("--vid", type=lambda x: int(x, 0), help="vendor id, e.g. 0x3151")
        sp.add_argument("--pid", type=lambda x: int(x, 0), help="product id, e.g. 0x4012")
        sp.add_argument("--path", help="exact hidapi device path (overrides interface pick)")

    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("selftest", help="validate protocol encoders (no hardware)").set_defaults(func=cmd_selftest)
    sub.add_parser("list", help="enumerate HID devices and flag known families").set_defaults(func=cmd_list)

    sp = sub.add_parser("info", help="show details for --vid/--pid")
    add_target(sp); sp.set_defaults(func=cmd_info)

    sp = sub.add_parser("monitor", help="stream raw input reports")
    add_target(sp)
    sp.add_argument("--interface", type=int, default=CONFIG_INTERFACE, help="interface to open (default 2)")
    sp.add_argument("--timeout", type=int, default=2000, help="read timeout ms (default 2000)")
    sp.set_defaults(func=cmd_monitor)

    sp = sub.add_parser("battery", help="read battery (wireless mode only)")
    add_target(sp)
    sp.add_argument("--interface", type=int, default=CONFIG_INTERFACE, help="interface to open (default 2)")
    sp.add_argument("--wait", type=int, default=10, help="seconds to wait (default 10)")
    sp.set_defaults(func=cmd_battery)

    sp = sub.add_parser("probe", help="read feature reports (read-only fingerprint)")
    add_target(sp)
    sp.add_argument("--first", type=lambda x: int(x, 0), default=0x01)
    sp.add_argument("--last", type=lambda x: int(x, 0), default=0x0A)
    sp.add_argument("--length", type=int, default=64, help="feature report length to request")
    sp.set_defaults(func=cmd_probe)

    sp = sub.add_parser("set-polling", help="set polling rate (125/250/500/1000)")
    add_target(sp)
    sp.add_argument("--rate", type=int, required=True, choices=[125, 250, 500, 1000])
    sp.add_argument("--delay", type=int, default=300, help="ms to wait after send (default 300)")
    sp.add_argument("-y", "--yes", action="store_true", help="skip confirmation")
    sp.set_defaults(func=cmd_set_polling)

    sp = sub.add_parser("set-dpi", help="set 6 DPI stages + active stage")
    add_target(sp)
    sp.add_argument("--stages", type=int, nargs=6, required=True,
                    metavar=("S1", "S2", "S3", "S4", "S5", "S6"),
                    help="six DPI values 50..22000, e.g. 800 1600 2400 3200 5000 22000")
    sp.add_argument("--active", type=int, default=1, choices=range(1, 7), help="active stage 1..6")
    sp.add_argument("--angle-snap", action="store_true")
    sp.add_argument("--no-ripple", action="store_true", help="disable ripple control")
    sp.add_argument("--wired", action="store_true", help="build 52-byte wired variant")
    sp.add_argument("--delay", type=int, default=300)
    sp.add_argument("-y", "--yes", action="store_true")
    sp.set_defaults(func=cmd_set_dpi)

    sp = sub.add_parser("set-prefs", help="set RGB/sleep/debounce")
    add_target(sp)
    sp.add_argument("--light", default="off", choices=list(LIGHT_MODES))
    sp.add_argument("--rgb", type=int, nargs=3, default=[0, 255, 0], metavar=("R", "G", "B"))
    sp.add_argument("--led-speed", type=int, default=3, choices=range(1, 6))
    sp.add_argument("--sleep", type=float, default=0.5, help="sleep minutes 0.5..30")
    sp.add_argument("--deep-sleep", type=int, default=10, help="deep sleep minutes 1..60")
    sp.add_argument("--debounce", type=int, default=8, help="click debounce ms (even, 4..50)")
    sp.add_argument("--wired", action="store_true")
    sp.add_argument("--delay", type=int, default=300)
    sp.add_argument("-y", "--yes", action="store_true")
    sp.set_defaults(func=cmd_set_prefs)

    return p


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
