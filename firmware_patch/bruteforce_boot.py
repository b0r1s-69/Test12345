import hid
import time
import sys

VID = 0x3151
PID = 0x4026
BOOT_PID = 0x4025

print("=" * 60)
print("AJ159 APEX - Brute Force Boot Mode Entry")
print("=" * 60)
print("")
print("This script tries EVERY possible command byte combination")
print("on the vendor HID interface to find the enter-boot command.")
print("")
print("ALSO TRY PHYSICAL METHOD:")
print("  1. Unplug USB cable")
print("  2. Hold LMB + RMB + Scroll Click (all 3 at once)")
print("  3. While holding all 3, plug USB cable back in")
print("  4. Keep holding for 5 seconds, then release")
print("  5. Run: python scan_mouse.py")
print("     (look for PID 0x4025 instead of 0x4026)")
print("")
print("If the physical method worked, skip this script and run:")
print("  python flash_aj159.py --flash aj159_apex_patched_full.bin")
print("")
print("-" * 60)
print("")

# Check if already in boot mode
boot_devs = hid.enumerate(VID, BOOT_PID)
if boot_devs:
    print("DEVICE ALREADY IN BOOT MODE! (PID 0x4025)")
    print("Run: python flash_aj159.py --flash aj159_apex_patched_full.bin")
    input("Press Enter to close...")
    sys.exit(0)

# Find interfaces
vendor_path = None
config_path = None
for d in hid.enumerate(VID, PID):
    if d["usage_page"] == 0xFFFF and d["usage"] == 0x01:
        vendor_path = d["path"]
    if d["usage_page"] == 0xFFFF and d["usage"] == 0x02:
        config_path = d["path"]

if not vendor_path and not config_path:
    print("ERROR: Mouse not found!")
    print("Connect via USB cable in wired mode.")
    input("Press Enter...")
    sys.exit(1)

def try_patterns_on_interface(path, iface_name):
    print("Testing on: %s" % iface_name)
    print("")

    first_bytes = [0x0F, 0x07, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
                   0x55, 0xAA, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                   0x08, 0x10, 0x11, 0x12, 0x13, 0x20, 0x30, 0x40,
                   0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0,
                   0xD0, 0xE0, 0xF0, 0xFE, 0xFF, 0x00]

    second_bytes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                    0x0A, 0x0B, 0x0F, 0x10, 0x11, 0x55, 0xAA, 0xFF,
                    0x00, 0x80, 0xFE]

    total = len(first_bytes) * len(second_bytes)
    count = 0

    for b1 in first_bytes:
        for b2 in second_bytes:
            count += 1
            payload = [b1, b2, 0x01, 0x00] + [0x00] * 60

            sys.stdout.write("\r  [%d/%d] Trying: %02x %02x ...    " % (count, total, b1, b2))
            sys.stdout.flush()

            try:
                h = hid.device()
                h.open_path(path)
                h.write(bytes(payload))
                h.close()
            except Exception:
                try:
                    h.close()
                except Exception:
                    pass
                continue

            time.sleep(0.3)
            normal = hid.enumerate(VID, PID)
            if not normal:
                print("")
                print("")
                print("  *** DEVICE DISAPPEARED after: %02x %02x ***" % (b1, b2))
                print("  Waiting 5 seconds for boot mode device...")
                time.sleep(5)
                boot = hid.enumerate(VID, BOOT_PID)
                if boot:
                    print("")
                    print("  !!! SUCCESS !!! Boot mode device found!")
                    print("  Command that worked: %02x %02x 01 00" % (b1, b2))
                    return True
                else:
                    all_3151 = hid.enumerate(VID)
                    if all_3151:
                        print("  Device reappeared with PID(s):")
                        for d in all_3151:
                            print("    PID=0x%04x" % d["product_id"])
                        if all_3151[0]["product_id"] != PID:
                            print("  !!! POSSIBLE BOOT MODE !!!")
                            print("  Command: %02x %02x 01 00" % (b1, b2))
                            return True
                    else:
                        print("  Device still gone!")
                        print("  Command that caused reboot: %02x %02x 01 00" % (b1, b2))
                        print("  Unplug and replug USB to recover.")
                        return True

    print("")
    print("  No pattern triggered reboot on %s." % iface_name)
    print("")
    return False

if vendor_path:
    result = try_patterns_on_interface(vendor_path, "VENDOR (iface 1)")
    if result:
        input("Press Enter to close...")
        sys.exit(0)

if config_path:
    print("")
    result = try_patterns_on_interface(config_path, "CONFIG (iface 2)")
    if result:
        input("Press Enter to close...")
        sys.exit(0)

print("")
print("=" * 60)
print("No command triggered boot mode.")
print("")
print("TRY PHYSICAL COMBOS (unplug first, hold buttons, plug in):")
print("  - LMB + RMB + Scroll Click")
print("  - Scroll Click only")
print("  - Left + Right only")
print("  - DPI button (under mouse or top)")
print("  - Forward button")
print("  - Back button")
print("")
print("After each try, run: python scan_mouse.py")
print("Look for PID 0x4025 or any different PID than 0x4026")
print("=" * 60)
input("Press Enter to close...")
