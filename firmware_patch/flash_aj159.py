#!/usr/bin/env python3
"""
flash_aj159.py - Python HID flasher for the Ajazz AJ159 APEX mouse.

Attempts to flash firmware using the RuiYu (RY) upgrade protocol over USB HID.
This is a reverse-engineering / debugging tool. Use at your own risk.

REQUIREMENTS:
    python -m pip install hidapi

USAGE:
    python flash_aj159.py --help       Show this help
    python flash_aj159.py --probe      Probe the device (read-only, safe)
    python flash_aj159.py --flash FILE Flash the given firmware file

The mouse must be connected via USB cable (wired mode).
Close all other mouse software before running this tool.

PROTOCOL OVERVIEW (reverse-engineered from ry_upgrade.exe):
    1. Open vendor HID interface (iface 1, usage_page 0xFFFF, usage 0x01)
    2. Send "Enter Boot" command
    3. Wait for device to re-enumerate as VID 3151 PID 4025
    4. Open boot HID interface (usage_page 0xFF01, usage 0x01)
    5. Send "Get Boot ID" / "Get Version"
    6. Stream firmware data in 52-byte chunks
    7. Send reboot command
"""

from __future__ import annotations
import os
import sys
import time
import struct

# ============================================================================
# Constants
# ============================================================================

# Normal mode device
NORMAL_VID = 0x3151
NORMAL_PID = 0x4026

# Vendor interface for "enter boot" command (interface 1)
VENDOR_IFACE_NUM = 1
VENDOR_USAGE_PAGE = 0xFFFF
VENDOR_USAGE = 0x0001

# Config interface (interface 2) - used for normal config and also upgrade
CONFIG_IFACE_NUM = 2
CONFIG_USAGE_PAGE = 0xFFFF
CONFIG_USAGE = 0x0002

# Boot mode device
BOOT_VID = 0x3151
BOOT_PID = 0x4025
BOOT_USAGE_PAGE = 0xFF01
BOOT_USAGE = 0x0001

# Timing
ENUM_WAIT_SECONDS = 10
CHUNK_DELAY_MS = 50
INTER_CMD_DELAY_MS = 200

# Protocol bytes (best guesses based on RY tool reverse engineering)
# The RY protocol uses feature reports or output reports on the vendor interface.
# Common command IDs found in the binary:
CMD_ENTER_BOOT = 0x01
CMD_GET_VERSION = 0x02
CMD_GET_BOOT_ID = 0x03
CMD_GET_ADDRESS = 0x04
CMD_UPGRADE_START = 0x05
CMD_UPGRADE_DATA = 0x06
CMD_BOOT_UPGRADE = 0x07
CMD_REBOOT = 0x08

# Chunk size for firmware data transfer (HID report minus header)
DATA_CHUNK_SIZE = 52
REPORT_SIZE = 64


# ============================================================================
# HID helpers
# ============================================================================

def require_hid():
    """Import and return the hid module, or exit with install instructions."""
    try:
        import hid
        return hid
    except ImportError:
        print("ERROR: The 'hidapi' module is required.")
        print("")
        print("Install it with:")
        print("    python -m pip install hidapi")
        print("")
        print("On Linux you may also need: sudo apt install libhidapi-dev")
        sys.exit(1)


def find_device(hid_mod, vid, pid, usage_page=None, usage=None, iface=None):
    """Find a HID device matching the given criteria. Returns device info dict or None."""
    devices = hid_mod.enumerate(vid, pid)
    for d in devices:
        if usage_page is not None and d.get("usage_page", 0) != usage_page:
            continue
        if usage is not None and d.get("usage", 0) != usage:
            continue
        if iface is not None and d.get("interface_number", -1) != iface:
            continue
        return d
    return None


def find_any_device(hid_mod, vid, pid):
    """Find any HID interface for the given VID:PID. Returns list of device info dicts."""
    return hid_mod.enumerate(vid, pid)


def open_device(hid_mod, dev_info):
    """Open a HID device from its info dict. Returns the device handle."""
    h = hid_mod.device()
    path = dev_info.get("path")
    if path:
        h.open_path(path)
    else:
        h.open(dev_info["vendor_id"], dev_info["product_id"])
    return h


def hex_dump(data, prefix="  "):
    """Format bytes as a hex string for display."""
    if not data:
        return prefix + "(empty)"
    hex_str = " ".join("%02x" % b for b in data)
    ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
    return prefix + hex_str + "  |" + ascii_str + "|"


# ============================================================================
# Probe mode - safe read-only exploration
# ============================================================================

def do_probe():
    """Probe the device interfaces, read feature reports, and display findings."""
    hid_mod = require_hid()

    print("=" * 70)
    print("AJ159 APEX Flash Tool - PROBE MODE (read-only, safe)")
    print("=" * 70)
    print("")

    # Step 1: Find normal mode device
    print("[1] Searching for mouse in normal mode...")
    print("    VID: 0x%04x  PID: 0x%04x" % (NORMAL_VID, NORMAL_PID))
    print("")

    all_devs = find_any_device(hid_mod, NORMAL_VID, NORMAL_PID)
    if not all_devs:
        print("    ERROR: Mouse not found!")
        print("    Make sure the mouse is connected via USB cable.")
        print("    Close any other mouse software (Ajazz driver, etc).")
        print("")
        print("    Listing ALL HID devices with VID 0x3151:")
        all_3151 = hid_mod.enumerate(NORMAL_VID, 0)
        if not all_3151:
            all_3151 = hid_mod.enumerate(NORMAL_VID)
        if all_3151:
            for d in all_3151:
                print("      PID=0x%04x iface=%s usage_page=0x%04x usage=0x%04x  %s" % (
                    d.get("product_id", 0),
                    str(d.get("interface_number", "?")),
                    d.get("usage_page", 0),
                    d.get("usage", 0),
                    d.get("product_string", ""),
                ))
        else:
            print("      (none found)")
        return False

    print("    Found %d interface(s):" % len(all_devs))
    for d in all_devs:
        print("      iface=%s  usage_page=0x%04x  usage=0x%04x  product=%s" % (
            str(d.get("interface_number", "?")),
            d.get("usage_page", 0),
            d.get("usage", 0),
            d.get("product_string", ""),
        ))
    print("")

    # Step 2: Probe vendor interface (iface 1)
    print("[2] Probing vendor interface (iface 1, usage_page=0xFFFF, usage=0x01)...")
    vendor_dev = find_device(hid_mod, NORMAL_VID, NORMAL_PID,
                             usage_page=VENDOR_USAGE_PAGE, usage=VENDOR_USAGE,
                             iface=VENDOR_IFACE_NUM)
    if not vendor_dev:
        # Try without interface number constraint
        vendor_dev = find_device(hid_mod, NORMAL_VID, NORMAL_PID,
                                 usage_page=VENDOR_USAGE_PAGE, usage=VENDOR_USAGE)
    if not vendor_dev:
        # Try any vendor usage page on iface 1
        vendor_dev = find_device(hid_mod, NORMAL_VID, NORMAL_PID, iface=VENDOR_IFACE_NUM)

    if vendor_dev:
        print("    Found: iface=%s usage_page=0x%04x usage=0x%04x" % (
            str(vendor_dev.get("interface_number", "?")),
            vendor_dev.get("usage_page", 0),
            vendor_dev.get("usage", 0),
        ))
        try:
            h = open_device(hid_mod, vendor_dev)
            print("    Opened successfully.")
            print("")
            print("    Reading feature reports (IDs 0x00 - 0x0F):")
            for rid in range(0x00, 0x10):
                try:
                    data = h.get_feature_report(rid, REPORT_SIZE)
                    if data and any(b != 0 for b in data[1:]):
                        print("      Report 0x%02x: %s" % (rid, " ".join("%02x" % b for b in data)))
                except Exception:
                    pass
            print("")
            print("    Trying to read input reports (5 second timeout)...")
            h.set_nonblocking(True)
            deadline = time.time() + 5.0
            got_any = False
            while time.time() < deadline:
                data = h.read(REPORT_SIZE)
                if data:
                    got_any = True
                    print("      IN: %s" % " ".join("%02x" % b for b in data))
                else:
                    time.sleep(0.05)
            if not got_any:
                print("      (no input reports received)")
            h.close()
        except Exception as e:
            print("    ERROR opening: %s" % str(e))
    else:
        print("    NOT FOUND - vendor interface not available")
        print("    (This interface is needed for Enter Boot command)")
    print("")

    # Step 3: Probe config interface (iface 2)
    print("[3] Probing config interface (iface 2, usage_page=0xFFFF, usage=0x02)...")
    config_dev = find_device(hid_mod, NORMAL_VID, NORMAL_PID,
                             usage_page=CONFIG_USAGE_PAGE, usage=CONFIG_USAGE,
                             iface=CONFIG_IFACE_NUM)
    if not config_dev:
        config_dev = find_device(hid_mod, NORMAL_VID, NORMAL_PID,
                                 usage_page=CONFIG_USAGE_PAGE, usage=CONFIG_USAGE)
    if not config_dev:
        config_dev = find_device(hid_mod, NORMAL_VID, NORMAL_PID, iface=CONFIG_IFACE_NUM)

    if config_dev:
        print("    Found: iface=%s usage_page=0x%04x usage=0x%04x" % (
            str(config_dev.get("interface_number", "?")),
            config_dev.get("usage_page", 0),
            config_dev.get("usage", 0),
        ))
        try:
            h = open_device(hid_mod, config_dev)
            print("    Opened successfully.")
            print("")
            print("    Reading feature reports (IDs 0x00 - 0x0F):")
            for rid in range(0x00, 0x10):
                try:
                    data = h.get_feature_report(rid, REPORT_SIZE)
                    if data and any(b != 0 for b in data[1:]):
                        print("      Report 0x%02x: %s" % (rid, " ".join("%02x" % b for b in data)))
                except Exception:
                    pass
            print("")

            # Try reading version info via known report patterns
            print("    Trying known version query patterns:")
            version_patterns = [
                ([0x07, 0x00, 0x00, 0x00], "Report 0x07 (possible version)"),
                ([0x08, 0x00, 0x00, 0x00], "Report 0x08"),
                ([0x09, 0x00, 0x00, 0x00], "Report 0x09"),
                ([0x0A, 0x00, 0x00, 0x00], "Report 0x0A"),
            ]
            for pattern, label in version_patterns:
                try:
                    buf = pattern + [0] * (REPORT_SIZE - len(pattern))
                    data = h.get_feature_report(pattern[0], REPORT_SIZE)
                    if data and any(b != 0 for b in data[1:]):
                        print("      %s: %s" % (label, " ".join("%02x" % b for b in data[:16])))
                except Exception:
                    pass
            h.close()
        except Exception as e:
            print("    ERROR opening: %s" % str(e))
    else:
        print("    NOT FOUND - config interface not available")
    print("")

    # Step 4: Check for boot mode device
    print("[4] Checking for device already in boot mode...")
    print("    VID: 0x%04x  PID: 0x%04x" % (BOOT_VID, BOOT_PID))
    boot_devs = find_any_device(hid_mod, BOOT_VID, BOOT_PID)
    if boot_devs:
        print("    FOUND! Device is in boot mode:")
        for d in boot_devs:
            print("      iface=%s  usage_page=0x%04x  usage=0x%04x" % (
                str(d.get("interface_number", "?")),
                d.get("usage_page", 0),
                d.get("usage", 0),
            ))
        # Try to open and read boot ID
        boot_dev = find_device(hid_mod, BOOT_VID, BOOT_PID,
                               usage_page=BOOT_USAGE_PAGE, usage=BOOT_USAGE)
        if not boot_dev and boot_devs:
            boot_dev = boot_devs[0]
        if boot_dev:
            try:
                h = open_device(hid_mod, boot_dev)
                print("")
                print("    Reading boot mode feature reports:")
                for rid in range(0x00, 0x10):
                    try:
                        data = h.get_feature_report(rid, REPORT_SIZE)
                        if data and any(b != 0 for b in data[1:]):
                            print("      Report 0x%02x: %s" % (rid, " ".join("%02x" % b for b in data)))
                    except Exception:
                        pass
                h.close()
            except Exception as e:
                print("    ERROR opening boot device: %s" % str(e))
    else:
        print("    Not in boot mode (normal - mouse is running normally)")
    print("")

    print("=" * 70)
    print("Probe complete. Review the output above to understand the device state.")
    print("=" * 70)
    return True


# ============================================================================
# Flash mode - attempt firmware upgrade
# ============================================================================

def wait_for_device(hid_mod, vid, pid, timeout_sec, label="device"):
    """Poll for a device to appear. Returns device info list or empty list."""
    print("    Waiting up to %d seconds for %s (VID=0x%04x PID=0x%04x)..." % (
        timeout_sec, label, vid, pid))
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        devs = find_any_device(hid_mod, vid, pid)
        if devs:
            return devs
        time.sleep(0.5)
        sys.stdout.write(".")
        sys.stdout.flush()
    print("")
    return []


def wait_for_device_gone(hid_mod, vid, pid, timeout_sec):
    """Wait for a device to disappear (indicating reboot). Returns True if gone."""
    print("    Waiting for device to disconnect (reboot to bootloader)...")
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        devs = find_any_device(hid_mod, vid, pid)
        if not devs:
            return True
        time.sleep(0.3)
        sys.stdout.write(".")
        sys.stdout.flush()
    print("")
    return False


def build_enter_boot_report(report_id, cmd_byte, sub_byte):
    """Build a feature report to send an enter-boot command."""
    buf = bytearray(REPORT_SIZE)
    buf[0] = report_id
    buf[1] = cmd_byte
    buf[2] = sub_byte
    return bytes(buf)


def try_enter_boot(hid_mod):
    """Try various methods to put the mouse into boot mode. Returns True if successful."""
    print("")
    print("[STEP 2] Sending Enter Boot command...")
    print("")

    # Strategy: Try the vendor interface first (iface 1), then config interface (iface 2)
    # The RY tool uses the vendor interface for "enter boot"

    interfaces_to_try = []

    # Try vendor interface (iface 1)
    vendor_dev = find_device(hid_mod, NORMAL_VID, NORMAL_PID,
                             usage_page=VENDOR_USAGE_PAGE, usage=VENDOR_USAGE,
                             iface=VENDOR_IFACE_NUM)
    if not vendor_dev:
        vendor_dev = find_device(hid_mod, NORMAL_VID, NORMAL_PID,
                                 usage_page=VENDOR_USAGE_PAGE, usage=VENDOR_USAGE)
    if not vendor_dev:
        vendor_dev = find_device(hid_mod, NORMAL_VID, NORMAL_PID, iface=VENDOR_IFACE_NUM)
    if vendor_dev:
        interfaces_to_try.append(("vendor (iface 1)", vendor_dev))

    # Also try config interface (iface 2)
    config_dev = find_device(hid_mod, NORMAL_VID, NORMAL_PID,
                             usage_page=CONFIG_USAGE_PAGE, usage=CONFIG_USAGE,
                             iface=CONFIG_IFACE_NUM)
    if not config_dev:
        config_dev = find_device(hid_mod, NORMAL_VID, NORMAL_PID,
                                 usage_page=CONFIG_USAGE_PAGE, usage=CONFIG_USAGE)
    if not config_dev:
        config_dev = find_device(hid_mod, NORMAL_VID, NORMAL_PID, iface=CONFIG_IFACE_NUM)
    if config_dev:
        interfaces_to_try.append(("config (iface 2)", config_dev))

    if not interfaces_to_try:
        print("    ERROR: No suitable interface found on the mouse!")
        print("    Make sure the mouse is connected via USB and no other software is using it.")
        return False

    # Known "enter boot" byte patterns to try (from RY protocol analysis)
    # Format: (report_id, cmd_byte, sub_byte, description)
    enter_boot_patterns = [
        (0x07, 0x01, 0x01, "report 0x07: cmd=0x01 sub=0x01"),
        (0x07, 0x01, 0x00, "report 0x07: cmd=0x01 sub=0x00"),
        (0x07, 0x00, 0x01, "report 0x07: cmd=0x00 sub=0x01"),
        (0x00, 0x07, 0x01, "report 0x00: cmd=0x07 sub=0x01"),
        (0x00, 0x01, 0x01, "report 0x00: cmd=0x01 sub=0x01"),
        (0x09, 0x01, 0x01, "report 0x09: cmd=0x01 sub=0x01"),
        (0x0A, 0x01, 0x01, "report 0x0A: cmd=0x01 sub=0x01"),
    ]

    for iface_label, dev_info in interfaces_to_try:
        print("    Trying interface: %s" % iface_label)
        print("      iface=%s usage_page=0x%04x usage=0x%04x" % (
            str(dev_info.get("interface_number", "?")),
            dev_info.get("usage_page", 0),
            dev_info.get("usage", 0),
        ))

        try:
            h = open_device(hid_mod, dev_info)
        except Exception as e:
            print("      ERROR opening: %s" % str(e))
            print("      Skipping this interface.")
            print("")
            continue

        for report_id, cmd_byte, sub_byte, desc in enter_boot_patterns:
            payload = build_enter_boot_report(report_id, cmd_byte, sub_byte)
            print("      Trying: %s" % desc)
            print("        Sending: %s" % " ".join("%02x" % b for b in payload[:8]))

            try:
                # Try as feature report first
                n = h.send_feature_report(payload)
                print("        Sent as feature report (%d bytes)" % n)
            except Exception as e1:
                # Try as output report
                try:
                    n = h.write(payload)
                    print("        Sent as output report (%d bytes)" % n)
                except Exception as e2:
                    print("        Failed: feature=%s, output=%s" % (str(e1), str(e2)))
                    continue

            # Brief delay then check if device rebooted
            time.sleep(0.5)

            # Check if normal mode device disappeared
            check = find_any_device(hid_mod, NORMAL_VID, NORMAL_PID)
            if not check:
                print("        Device disconnected! Likely rebooting to bootloader.")
                h.close()
                return True

            # Check if boot mode device appeared
            boot_check = find_any_device(hid_mod, BOOT_VID, BOOT_PID)
            if boot_check:
                print("        Boot mode device appeared!")
                h.close()
                return True

        # Also try: write a raw "enter boot" string as some tools do
        print("      Trying raw 'Enter Boot' ASCII command...")
        try:
            raw_cmd = bytearray(REPORT_SIZE)
            raw_cmd[0] = 0x00  # report ID
            enter_str = b"Enter Boot"
            for i in range(len(enter_str)):
                raw_cmd[1 + i] = enter_str[i]
            h.write(bytes(raw_cmd))
            print("        Sent 'Enter Boot' as output report")
            time.sleep(0.5)
            check = find_any_device(hid_mod, NORMAL_VID, NORMAL_PID)
            if not check:
                print("        Device disconnected!")
                h.close()
                return True
            boot_check = find_any_device(hid_mod, BOOT_VID, BOOT_PID)
            if boot_check:
                print("        Boot mode device appeared!")
                h.close()
                return True
        except Exception as e:
            print("        Failed: %s" % str(e))

        h.close()
        print("")

    return False


def do_flash(firmware_path):
    """Attempt to flash firmware to the mouse."""
    hid_mod = require_hid()

    print("=" * 70)
    print("AJ159 APEX Flash Tool - FLASH MODE")
    print("=" * 70)
    print("")

    # Validate firmware file
    if not os.path.isfile(firmware_path):
        print("ERROR: Firmware file not found: %s" % firmware_path)
        return False

    fw_size = os.path.getsize(firmware_path)
    print("Firmware file: %s" % firmware_path)
    print("Firmware size: %d bytes" % fw_size)

    if fw_size == 0:
        print("ERROR: Firmware file is empty!")
        return False

    if fw_size > 256 * 1024:
        print("ERROR: Firmware file seems too large (>256KB). Are you sure this is correct?")
        return False

    # Read the firmware
    with open(firmware_path, "rb") as f:
        fw_data = f.read()

    # Check for MCUboot header magic
    if len(fw_data) >= 4:
        magic = struct.unpack("<I", fw_data[:4])[0]
        if magic == 0x96F3B83D:
            print("MCUboot header: VALID (magic 0x96F3B83D)")
        else:
            print("MCUboot header: NOT FOUND (first 4 bytes: %s)" % " ".join("%02x" % b for b in fw_data[:4]))
            print("WARNING: This may not be a valid MCUboot image.")
            print("         Expected the full image (header + app + TLV).")
    print("")

    # Confirmation
    print("!" * 70)
    print("WARNING: You are about to flash firmware to your mouse.")
    print("         If something goes wrong, the mouse may stop working.")
    print("         Make sure you have the ORIGINAL firmware as backup.")
    print("!" * 70)
    print("")
    print("Type YES to continue, or anything else to abort:")
    try:
        answer = input("> ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\nAborted.")
        return False

    if answer != "YES":
        print("Aborted. (You must type YES in capital letters)")
        return False

    print("")

    # Step 1: Check if already in boot mode
    print("[STEP 1] Checking device state...")
    boot_devs = find_any_device(hid_mod, BOOT_VID, BOOT_PID)
    if boot_devs:
        print("    Device is ALREADY in boot mode! Skipping enter-boot step.")
        already_in_boot = True
    else:
        # Check normal mode device exists
        normal_devs = find_any_device(hid_mod, NORMAL_VID, NORMAL_PID)
        if not normal_devs:
            print("    ERROR: Mouse not found in normal mode OR boot mode!")
            print("    Connect the mouse via USB and try again.")
            return False
        print("    Mouse found in normal mode (%d interfaces)" % len(normal_devs))
        already_in_boot = False

    # Step 2: Enter boot mode (if not already there)
    if not already_in_boot:
        success = try_enter_boot(hid_mod)
        if not success:
            print("")
            print("    Could not trigger bootloader entry with any known pattern.")
            print("")
            print("    ALTERNATIVES:")
            print("    1. Try holding mouse buttons while plugging in USB")
            print("       (hold left+right, or hold the button under the mouse)")
            print("    2. Run --probe to see what the device responds to")
            print("    3. The enter-boot command pattern may be different for your unit")
            print("")
            print("    If the device IS now in boot mode (PID changed to 0x4025),")
            print("    run this script again and it will detect it automatically.")
            return False

        # Wait for boot mode device to appear
        print("")
        print("[STEP 3] Waiting for boot mode device...")
        time.sleep(2)  # Give the device time to reboot
        boot_devs = wait_for_device(hid_mod, BOOT_VID, BOOT_PID,
                                    ENUM_WAIT_SECONDS, "boot mode device")
        if not boot_devs:
            print("")
            print("    ERROR: Boot mode device did not appear within %d seconds." % ENUM_WAIT_SECONDS)
            print("    The mouse may have rebooted back to normal mode.")
            print("    Try running the script again.")
            return False
        print("")
        print("    Boot mode device found!")
    else:
        print("")

    # Step 3/4: Open boot mode device
    step_num = 4 if not already_in_boot else 2
    print("[STEP %d] Opening boot mode device..." % step_num)
    boot_dev = find_device(hid_mod, BOOT_VID, BOOT_PID,
                           usage_page=BOOT_USAGE_PAGE, usage=BOOT_USAGE)
    if not boot_dev:
        # Try any interface
        boot_devs_list = find_any_device(hid_mod, BOOT_VID, BOOT_PID)
        if boot_devs_list:
            boot_dev = boot_devs_list[0]
        else:
            print("    ERROR: Cannot find boot mode device!")
            return False

    print("    iface=%s usage_page=0x%04x usage=0x%04x" % (
        str(boot_dev.get("interface_number", "?")),
        boot_dev.get("usage_page", 0),
        boot_dev.get("usage", 0),
    ))

    try:
        h = open_device(hid_mod, boot_dev)
    except Exception as e:
        print("    ERROR: Cannot open boot device: %s" % str(e))
        return False

    print("    Opened successfully.")
    print("")

    # Step: Get Boot ID
    step_num += 1
    print("[STEP %d] Querying boot ID..." % step_num)
    boot_id_patterns = [
        (0x07, 0x03, 0x00, "Get Boot ID (0x07, 0x03)"),
        (0x07, 0x02, 0x00, "Get Version (0x07, 0x02)"),
        (0x00, 0x03, 0x00, "Get Boot ID (0x00, 0x03)"),
        (0x01, 0x03, 0x00, "Get Boot ID (0x01, 0x03)"),
    ]

    got_response = False
    for report_id, cmd, sub, desc in boot_id_patterns:
        buf = bytearray(REPORT_SIZE)
        buf[0] = report_id
        buf[1] = cmd
        buf[2] = sub
        print("    Trying: %s" % desc)
        try:
            h.send_feature_report(bytes(buf))
            time.sleep(0.1)
            resp = h.get_feature_report(report_id, REPORT_SIZE)
            if resp and any(b != 0 for b in resp[1:]):
                print("    Response: %s" % " ".join("%02x" % b for b in resp[:16]))
                got_response = True
                break
        except Exception as e:
            try:
                h.write(bytes(buf))
                time.sleep(0.1)
                h.set_nonblocking(True)
                resp = h.read(REPORT_SIZE)
                h.set_nonblocking(False)
                if resp:
                    print("    Response: %s" % " ".join("%02x" % b for b in resp[:16]))
                    got_response = True
                    break
            except Exception:
                pass

    if not got_response:
        print("    WARNING: No response to boot ID query.")
        print("    The protocol commands may be different than expected.")
        print("    Proceeding anyway (the device IS in boot mode)...")
    print("")

    # Step: Get flash address
    step_num += 1
    print("[STEP %d] Querying flash address..." % step_num)
    addr_patterns = [
        (0x07, 0x04, 0x00, "Get Address (0x07, 0x04)"),
        (0x00, 0x04, 0x00, "Get Address (0x00, 0x04)"),
    ]
    flash_addr = 0x10000  # Default for Nordic MCUboot slot

    for report_id, cmd, sub, desc in addr_patterns:
        buf = bytearray(REPORT_SIZE)
        buf[0] = report_id
        buf[1] = cmd
        buf[2] = sub
        try:
            h.send_feature_report(bytes(buf))
            time.sleep(0.1)
            resp = h.get_feature_report(report_id, REPORT_SIZE)
            if resp and any(b != 0 for b in resp[1:]):
                print("    %s response: %s" % (desc, " ".join("%02x" % b for b in resp[:16])))
                # Try to parse address from response
                if len(resp) >= 6:
                    maybe_addr = struct.unpack("<I", bytes(resp[2:6]))[0]
                    if 0x1000 <= maybe_addr <= 0x100000:
                        flash_addr = maybe_addr
                        print("    Flash address: 0x%08x" % flash_addr)
                break
        except Exception:
            pass

    print("    Using flash address: 0x%08x" % flash_addr)
    print("")

    # Step: Stream firmware data
    step_num += 1
    total_chunks = (len(fw_data) + DATA_CHUNK_SIZE - 1) // DATA_CHUNK_SIZE
    print("[STEP %d] Streaming firmware (%d bytes in %d chunks of %d bytes)..." % (
        step_num, len(fw_data), total_chunks, DATA_CHUNK_SIZE))
    print("")

    # Send upgrade start command
    print("    Sending upgrade start command...")
    start_buf = bytearray(REPORT_SIZE)
    start_buf[0] = 0x07  # report ID
    start_buf[1] = CMD_UPGRADE_START
    start_buf[2] = 0x00
    # Pack firmware size
    struct.pack_into("<I", start_buf, 3, len(fw_data))
    # Pack flash address
    struct.pack_into("<I", start_buf, 7, flash_addr)
    try:
        h.send_feature_report(bytes(start_buf))
        time.sleep(INTER_CMD_DELAY_MS / 1000.0)
    except Exception as e:
        try:
            h.write(bytes(start_buf))
            time.sleep(INTER_CMD_DELAY_MS / 1000.0)
        except Exception as e2:
            print("    WARNING: Could not send start command: %s / %s" % (str(e), str(e2)))

    # Stream data chunks
    errors = 0
    for chunk_idx in range(total_chunks):
        offset = chunk_idx * DATA_CHUNK_SIZE
        chunk = fw_data[offset:offset + DATA_CHUNK_SIZE]

        # Build data report
        data_buf = bytearray(REPORT_SIZE)
        data_buf[0] = 0x07  # report ID (or 0x00 depending on protocol)
        data_buf[1] = CMD_UPGRADE_DATA
        # Chunk index (2 bytes LE)
        struct.pack_into("<H", data_buf, 2, chunk_idx)
        # Data offset in firmware
        struct.pack_into("<I", data_buf, 4, offset)
        # Chunk length
        data_buf[8] = len(chunk)
        # Copy chunk data
        for i in range(len(chunk)):
            data_buf[9 + i] = chunk[i]

        try:
            h.send_feature_report(bytes(data_buf))
        except Exception:
            try:
                h.write(bytes(data_buf))
            except Exception as e:
                errors += 1
                if errors <= 3:
                    print("    ERROR at chunk %d: %s" % (chunk_idx, str(e)))
                if errors > 10:
                    print("    Too many errors, aborting!")
                    h.close()
                    return False

        # Progress display
        if chunk_idx % 50 == 0 or chunk_idx == total_chunks - 1:
            pct = int((chunk_idx + 1) * 100 / total_chunks)
            bar_len = 40
            filled = int(bar_len * pct / 100)
            bar = "#" * filled + "-" * (bar_len - filled)
            sys.stdout.write("\r    [%s] %3d%% (%d/%d)" % (bar, pct, chunk_idx + 1, total_chunks))
            sys.stdout.flush()

        # Small delay between chunks
        if CHUNK_DELAY_MS > 0:
            time.sleep(CHUNK_DELAY_MS / 1000.0)

    print("")
    if errors > 0:
        print("    Completed with %d errors." % errors)
    else:
        print("    All chunks sent successfully.")
    print("")

    # Step: Send reboot / finalize command
    step_num += 1
    print("[STEP %d] Sending reboot command..." % step_num)
    reboot_buf = bytearray(REPORT_SIZE)
    reboot_buf[0] = 0x07  # report ID
    reboot_buf[1] = CMD_BOOT_UPGRADE  # or CMD_REBOOT
    reboot_buf[2] = 0x00
    try:
        h.send_feature_report(bytes(reboot_buf))
    except Exception:
        try:
            h.write(bytes(reboot_buf))
        except Exception as e:
            print("    WARNING: Reboot command may have failed: %s" % str(e))
            print("    (This is normal if the device already rebooted)")

    h.close()
    print("    Reboot command sent.")
    print("")

    # Wait for normal mode device to come back
    print("    Waiting for mouse to reboot to normal mode...")
    time.sleep(3)
    normal_devs = wait_for_device(hid_mod, NORMAL_VID, NORMAL_PID, 15, "mouse")
    if normal_devs:
        print("")
        print("    Mouse is back in normal mode!")
        print("")
        print("=" * 70)
        print("FLASH COMPLETE")
        print("")
        print("The firmware has been sent to the mouse. If the bootloader accepted")
        print("it, the new firmware is now running. Test the macro fix:")
        print("  1. Assign a macro to LMB")
        print("  2. Hold RMB, then press LMB")
        print("  3. RMB should stay held (not release)")
        print("")
        print("If the mouse is unresponsive or the fix did not work, the bootloader")
        print("may have rejected the image. Reflash with the original firmware using")
        print("ry_upgrade.exe from the official firmware ZIP.")
        print("=" * 70)
    else:
        print("")
        print("    Mouse did not reappear in normal mode within 15 seconds.")
        print("    Try unplugging and replugging the USB cable.")
        print("    If the mouse is unresponsive, hold left+right buttons while")
        print("    plugging in to force bootloader mode, then reflash original firmware.")

    return True


# ============================================================================
# Main
# ============================================================================

def show_help():
    """Show usage information."""
    print("")
    print("=" * 70)
    print("AJ159 APEX Mouse Firmware Flash Tool")
    print("=" * 70)
    print("")
    print("REQUIREMENTS:")
    print("    python -m pip install hidapi")
    print("")
    print("USAGE:")
    print("    python flash_aj159.py --help       Show this help")
    print("    python flash_aj159.py --probe      Probe device (safe, read-only)")
    print("    python flash_aj159.py --flash FILE Flash firmware file to mouse")
    print("")
    print("IMPORTANT:")
    print("    - Connect the mouse via USB cable (wired mode)")
    print("    - Close all other mouse software first")
    print("    - Keep the original firmware ZIP as backup")
    print("    - The mouse will reboot during flashing")
    print("")
    print("PROBE MODE (--probe):")
    print("    Reads device information without writing anything.")
    print("    Use this first to verify the script can see your mouse.")
    print("")
    print("FLASH MODE (--flash):")
    print("    Attempts the full upgrade flow:")
    print("    1. Sends 'Enter Boot' to put mouse in bootloader mode")
    print("    2. Streams firmware data to the bootloader")
    print("    3. Sends reboot command")
    print("    You will be asked for confirmation before any writes.")
    print("")
    print("EXAMPLE:")
    print("    python flash_aj159.py --probe")
    print("    python flash_aj159.py --flash aj159_apex_patched_full.bin")
    print("")
    print("If the official ry_upgrade.exe does not detect your mouse on Windows 11,")
    print("this tool attempts to talk the same protocol directly via Python/hidapi.")
    print("=" * 70)
    print("")


def main():
    """Main entry point - parse command line arguments and dispatch."""
    if len(sys.argv) < 2:
        show_help()
        sys.exit(0)

    arg = sys.argv[1].lower().strip()

    if arg == "--help" or arg == "-h" or arg == "help" or arg == "/?":
        show_help()
        sys.exit(0)

    elif arg == "--probe" or arg == "probe":
        do_probe()

    elif arg == "--flash" or arg == "flash":
        if len(sys.argv) < 3:
            print("ERROR: --flash requires a firmware file path.")
            print("")
            print("Usage: python flash_aj159.py --flash <firmware_file>")
            print("")
            print("Example: python flash_aj159.py --flash aj159_apex_patched_full.bin")
            sys.exit(1)
        firmware_file = sys.argv[2]
        success = do_flash(firmware_file)
        if not success:
            sys.exit(1)

    else:
        print("ERROR: Unknown argument: %s" % arg)
        print("")
        show_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
