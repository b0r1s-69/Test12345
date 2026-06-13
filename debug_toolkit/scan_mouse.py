import hid

print("Scanning for AJ159 APEX (VID 3151)...")
devs = [d for d in hid.enumerate() if d["vendor_id"] == 0x3151]
print("Found " + str(len(devs)) + " interfaces:")
print("")

for d in devs:
    print("  PID=" + hex(d["product_id"]) + " iface=" + str(d["interface_number"]) + " usage_page=" + hex(d["usage_page"]) + " usage=" + hex(d["usage"]))
    print("    product: " + str(d["product_string"]))
    print("    path: " + str(d["path"]))
    print("")

if not devs:
    print("ERROR: Mouse not found! Is it plugged in via USB cable in wired mode?")
    print("")
    print("Checking ALL HID devices...")
    all_devs = hid.enumerate()
    print("Total HID devices: " + str(len(all_devs)))
    for d in all_devs:
        if d["vendor_id"] not in (0, 0x046D):
            print("  VID=" + hex(d["vendor_id"]) + " PID=" + hex(d["product_id"]) + " iface=" + str(d["interface_number"]) + " - " + str(d["product_string"]))

input("")
input("Press Enter to close...")
