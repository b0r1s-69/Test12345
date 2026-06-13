import hid
import time
import sys

VID = 0x3151
PID = 0x4026
BOOT_PID = 0x4025

print("=" * 60)
print("AJ159 APEX - Enter Boot Mode (one pattern at a time)")
print("=" * 60)
print("")
print("This will try ONE command, then wait 3 seconds to see")
print("if the mouse reboots into bootloader mode.")
print("")

# Find vendor interface
vendor_path = None
for d in hid.enumerate(VID, PID):
    if d["usage_page"] == 0xFFFF and d["usage"] == 0x01:
        vendor_path = d["path"]
        break

if not vendor_path:
    print("ERROR: Mouse vendor interface not found!")
    print("Make sure mouse is connected via USB cable.")
    input("Press Enter...")
    sys.exit(1)

# All patterns to try (one per run)
patterns = [
    ("0x0F 0x04 0x00 0x01", [0x0F, 0x04, 0x00, 0x01]),
    ("0x0F 0x04 0x01 0x00", [0x0F, 0x04, 0x01, 0x00]),
    ("0x0F 0x01 0x01 0x00", [0x0F, 0x01, 0x01, 0x00]),
    ("0x07 0x01 0x01 0x00", [0x07, 0x01, 0x01, 0x00]),
    ("0x07 0x01 0x00 0x00", [0x07, 0x01, 0x00, 0x00]),
    ("0x55 0xAA 0x01 0x00", [0x55, 0xAA, 0x01, 0x00]),
    ("0xAA 0x55 0x01 0x00", [0xAA, 0x55, 0x01, 0x00]),
    ("0x0F 0x07 0x01 0x00", [0x0F, 0x07, 0x01, 0x00]),
    ("0x0F 0x02 0x01 0x00", [0x0F, 0x02, 0x01, 0x00]),
    ("0x0F 0x05 0x01 0x00", [0x0F, 0x05, 0x01, 0x00]),
    ("0x0F 0x06 0x01 0x00", [0x0F, 0x06, 0x01, 0x00]),
    ("0x0F 0x08 0x01 0x00", [0x0F, 0x08, 0x01, 0x00]),
    ("0x0F 0x0A 0x01 0x00", [0x0F, 0x0A, 0x01, 0x00]),
]

# Check which pattern to try
if len(sys.argv) > 1:
    try:
        idx = int(sys.argv[1])
    except ValueError:
        idx = 0
else:
    idx = 0

if idx >= len(patterns):
    print("All patterns tried. None triggered boot mode.")
    input("Press Enter...")
    sys.exit(0)

desc, data = patterns[idx]
payload = data + [0x00] * (64 - len(data))

print("Pattern %d/%d: %s" % (idx + 1, len(patterns), desc))
print("Payload: %s" % " ".join("%02x" % b for b in payload[:8]))
print("")
print("Sending...")

h = hid.device()
h.open_path(vendor_path)

try:
    h.write(bytes(payload))
    print("Sent OK.")
except Exception as e:
    print("Write error: %s" % str(e))
    h.close()
    print("")
    print("Try next: python enter_boot.py %d" % (idx + 1))
    input("Press Enter...")
    sys.exit(1)

h.close()

print("")
print("Waiting 3 seconds for reboot...")
time.sleep(3)

# Check if mouse changed
normal = hid.enumerate(VID, PID)
boot = hid.enumerate(VID, BOOT_PID)

if boot:
    print("")
    print("!!! SUCCESS !!! Device is now in BOOT MODE (PID 0x4025)")
    print("Boot interfaces found: %d" % len(boot))
    for d in boot:
        print("  iface=%s usage_page=0x%04x usage=0x%04x" % (
            str(d.get("interface_number", "?")),
            d.get("usage_page", 0),
            d.get("usage", 0)))
    print("")
    print("The pattern that worked: %s" % desc)
    print("")
    print("NOW RUN: python flash_aj159.py --flash aj159_apex_patched_full.bin")
elif not normal:
    print("")
    print("Mouse DISAPPEARED! It may be rebooting...")
    print("Wait 5 more seconds...")
    time.sleep(5)
    boot = hid.enumerate(VID, BOOT_PID)
    normal = hid.enumerate(VID, PID)
    if boot:
        print("SUCCESS! Device appeared in BOOT MODE!")
        print("NOW RUN: python flash_aj159.py --flash aj159_apex_patched_full.bin")
    elif normal:
        print("Mouse came back in normal mode. Pattern did not work.")
        print("Try next: python enter_boot.py %d" % (idx + 1))
    else:
        print("Mouse still missing. Unplug and replug USB cable.")
        print("If it comes back normal, try: python enter_boot.py %d" % (idx + 1))
else:
    print("Mouse still in normal mode. Pattern did not trigger reboot.")
    print("")
    print("Try next: python enter_boot.py %d" % (idx + 1))

print("")
input("Press Enter to close...")
