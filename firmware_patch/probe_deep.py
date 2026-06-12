import hid
import time
import sys

VID = 0x3151
PID = 0x4026

print("=" * 60)
print("AJ159 APEX - Deep Protocol Probe")
print("=" * 60)
print("")

# Find vendor interface (usage_page=0xFFFF, usage=0x01)
vendor_path = None
config_path = None
for d in hid.enumerate(VID, PID):
    if d["usage_page"] == 0xFFFF and d["usage"] == 0x01:
        vendor_path = d["path"]
    if d["usage_page"] == 0xFFFF and d["usage"] == 0x02:
        config_path = d["path"]

if not vendor_path:
    print("ERROR: Vendor interface not found!")
    input("Press Enter...")
    sys.exit(1)

if not config_path:
    print("ERROR: Config interface not found!")
    input("Press Enter...")
    sys.exit(1)

print("[1] VENDOR INTERFACE (iface 1, usage 0xFFFF:0x01)")
print("    Testing write -> read protocol")
print("")

h = hid.device()
h.open_path(vendor_path)
h.set_nonblocking(True)

patterns = [
    ("All zeros (64)", [0x00] * 64),
    ("0x07 0x00", [0x07, 0x00, 0x00, 0x00] + [0x00] * 60),
    ("0x07 0x01", [0x07, 0x01, 0x00, 0x00] + [0x00] * 60),
    ("0x07 0x02", [0x07, 0x02, 0x00, 0x00] + [0x00] * 60),
    ("0x07 0x03", [0x07, 0x03, 0x00, 0x00] + [0x00] * 60),
    ("0x07 0x04", [0x07, 0x04, 0x00, 0x00] + [0x00] * 60),
    ("0x0F 0x01", [0x0F, 0x01, 0x00, 0x00] + [0x00] * 60),
    ("0x0F 0x04 0x00 0x01", [0x0F, 0x04, 0x00, 0x01] + [0x00] * 60),
    ("0x09 0x01", [0x09, 0x01, 0x00, 0x00] + [0x00] * 60),
    ("0x0A 0x01", [0x0A, 0x01, 0x00, 0x00] + [0x00] * 60),
    ("0x55 0xAA", [0x55, 0xAA, 0x01, 0x00] + [0x00] * 60),
    ("0xAA 0x55", [0xAA, 0x55, 0x01, 0x00] + [0x00] * 60),
    ("0x00 0x07 0x01", [0x00, 0x07, 0x01, 0x00] + [0x00] * 60),
    ("0x00 0x0F 0x01", [0x00, 0x0F, 0x01, 0x00] + [0x00] * 60),
]

print("    Sending and checking for responses:")
print("")
any_response = False
for desc, data in patterns:
    try:
        n = h.write(bytes(data))
        time.sleep(0.15)
        resp = h.read(64)
        if resp:
            any_response = True
            hex_resp = " ".join("%02x" % b for b in resp[:20])
            print("  > %-25s REPLY: %s" % (desc, hex_resp))
    except Exception as e:
        print("  > %-25s ERROR: %s" % (desc, str(e)))

if not any_response:
    print("  (No responses on vendor interface via write/read)")
print("")
h.close()

print("[2] CONFIG INTERFACE (iface 2, usage 0xFFFF:0x02)")
print("    Testing write -> read protocol")
print("")

h2 = hid.device()
h2.open_path(config_path)
h2.set_nonblocking(True)

config_patterns = [
    ("0x0F 0x01", [0x0F, 0x01, 0x00, 0x00] + [0x00] * 60),
    ("0x0F 0x04 0x00 0x01", [0x0F, 0x04, 0x00, 0x01] + [0x00] * 60),
    ("0x0F 0x04 0x01 0x00", [0x0F, 0x04, 0x01, 0x00] + [0x00] * 60),
    ("0x07 0x02", [0x07, 0x02, 0x00, 0x00] + [0x00] * 60),
    ("0x07 0x03", [0x07, 0x03, 0x00, 0x00] + [0x00] * 60),
    ("All zeros", [0x00] * 64),
    ("0x04 0x38 0x01", [0x04, 0x38, 0x01, 0x00] + [0x00] * 60),
    ("0x06 0x09 0x01", [0x06, 0x09, 0x01, 0x00] + [0x00] * 60),
]

any_response2 = False
for desc, data in config_patterns:
    try:
        n = h2.write(bytes(data))
        time.sleep(0.15)
        resp = h2.read(64)
        if resp:
            any_response2 = True
            hex_resp = " ".join("%02x" % b for b in resp[:24])
            print("  > %-25s REPLY: %s" % (desc, hex_resp))
    except Exception as e:
        print("  > %-25s ERROR: %s" % (desc, str(e)))

if not any_response2:
    print("  (No responses on config interface via write/read)")

print("")
print("[3] FEATURE REPORTS on config interface")
print("")
any_feature = False
for rid in range(0x01, 0x10):
    try:
        resp = h2.get_feature_report(rid, 64)
        if resp and any(b != 0 for b in resp[1:]):
            any_feature = True
            hex_resp = " ".join("%02x" % b for b in resp[:20])
            print("  Feature 0x%02x: %s" % (rid, hex_resp))
    except Exception:
        pass

if not any_feature:
    print("  (No feature reports returned data)")

print("")
print("[4] FEATURE REPORTS on vendor interface")
print("")
h3 = hid.device()
h3.open_path(vendor_path)
any_feature2 = False
for rid in range(0x01, 0x10):
    try:
        resp = h3.get_feature_report(rid, 64)
        if resp and any(b != 0 for b in resp[1:]):
            any_feature2 = True
            hex_resp = " ".join("%02x" % b for b in resp[:20])
            print("  Feature 0x%02x: %s" % (rid, hex_resp))
    except Exception:
        pass

if not any_feature2:
    print("  (No feature reports returned data)")
h3.close()

h2.close()
print("")
print("=" * 60)
print("Done. Share this output.")
print("=" * 60)
input("Press Enter to close...")
