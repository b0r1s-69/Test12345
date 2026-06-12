#!/usr/bin/env python3
"""
AJ159 APEX Firmware Patcher - Macro Button OR-Merge Fix
=========================================================
Patches the mouse_app_fw.bin (extracted from the MCUboot image inside ry_upgrade.exe)
to fix the macro playback button-byte overwrite bug.

THE BUG: When a macro fires, it overwrites the HID report's buttons byte without
OR-merging the physical button state. This causes held buttons (like RMB) to "release"
during macro playback.

THE FIX: Redirect the macro button write through a trampoline that OR-merges
the macro buttons with the current physical button state before writing to the report.

USAGE:
  python3 patch_macro_fix.py mouse_app_fw.bin mouse_app_fw_PATCHED.bin

SAFETY: This patches the APPLICATION firmware only (loaded at 0x10000). It does NOT
touch the bootloader, BLE controller, or radio firmware. The patched image must be
re-embedded in ry_upgrade.exe (or flashed via SWD) to take effect.
"""
import sys, struct, hashlib

EXPECTED_SHA256 = "1c0c5fdd02ce92ed521729a00218f0f86920211455b1d51fe9a4455a7a3d8262"
EXPECTED_SIZE = 108608

# Patch definitions: (file_offset, original_bytes, patched_bytes)
PATCHES = [
    # Bug site: redirect to trampoline
    (0x14616, bytes.fromhex("417921708079607000e0"),
              bytes.fromhex("01f08efc02e000bf00bf")),
    # Code cave: OR-merge trampoline
    (0x15f36, bytes.fromhex("000000000000000000000000000000000000"),
              bytes.fromhex("417922781143217081796278114361707047")),
]

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input.bin> <output.bin>")
        sys.exit(1)
    
    data = bytearray(open(sys.argv[1], 'rb').read())
    
    # Verify input
    if len(data) != EXPECTED_SIZE:
        print(f"ERROR: Expected {EXPECTED_SIZE} bytes, got {len(data)}")
        sys.exit(1)
    
    sha = hashlib.sha256(data).hexdigest()
    if sha != EXPECTED_SHA256:
        print(f"WARNING: SHA256 mismatch!")
        print(f"  Expected: {EXPECTED_SHA256}")
        print(f"  Got:      {sha}")
        print("  This may be a different firmware version. Patch may not work correctly.")
        ans = input("  Continue anyway? [y/N] ").strip().lower()
        if ans != 'y':
            sys.exit(1)
    else:
        print("Input verified: mouse_app_fw.bin MV302 (SHA256 match)")
    
    # Apply patches
    for off, orig, patch in PATCHES:
        current = bytes(data[off:off+len(orig)])
        if current == patch:
            print(f"  Patch at {off:#06x}: already applied (skipping)")
            continue
        if current != orig:
            print(f"  ERROR at {off:#06x}: unexpected bytes!")
            print(f"    Expected: {orig.hex()}")
            print(f"    Found:    {current.hex()}")
            sys.exit(1)
        data[off:off+len(patch)] = patch
        print(f"  Patched {off:#06x}: {len(patch)} bytes")
    
    with open(sys.argv[2], 'wb') as f:
        f.write(data)
    
    new_sha = hashlib.sha256(data).hexdigest()
    print(f"\nOutput: {sys.argv[2]}")
    print(f"  SHA256: {new_sha}")
    print("\nPatch applied successfully!")
    print("\nNEXT STEPS:")
    print("  1. Re-embed the patched .bin into the MCUboot image (restore header)")
    print("  2. Replace the firmware blob in ry_upgrade.exe OR flash via SWD")
    print("  3. Test: hold RMB, fire LMB macro - RMB should stay held")

if __name__ == "__main__":
    main()
