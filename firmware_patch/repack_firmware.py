#!/usr/bin/env python3
"""
Repackage the patched firmware into an MCUboot image and embed it back
into ry_upgrade.exe for flashing via the standard upgrade tool.

WARNING: Modifying firmware carries risk of bricking. Have a backup plan
(SWD/JTAG access or a known-good ry_upgrade.exe).
"""
import sys, struct, hashlib

def main():
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <original_ry_upgrade.exe> <patched_fw.bin> <output_ry_upgrade.exe>")
        sys.exit(1)
    
    exe_data = bytearray(open(sys.argv[1], 'rb').read())
    fw_data = open(sys.argv[2], 'rb').read()
    
    # The MCUboot image header for the mouse app is at EXE offset 0x11A291F
    # Image data starts at 0x11A291F + 512 = 0x11A2B1F
    HEADER_OFFSET = 0x11A291F
    HDR_SIZE = 512
    IMG_OFFSET = HEADER_OFFSET + HDR_SIZE
    
    # Verify the header is still valid
    magic = struct.unpack_from('<I', exe_data, HEADER_OFFSET)[0]
    if magic != 0x96f3b83d:
        print(f"ERROR: MCUboot magic not found at expected offset!")
        sys.exit(1)
    
    orig_img_size = struct.unpack_from('<I', exe_data, HEADER_OFFSET+12)[0]
    if len(fw_data) != orig_img_size:
        print(f"ERROR: Patched firmware size ({len(fw_data)}) != original ({orig_img_size})")
        sys.exit(1)
    
    # Replace the image data
    exe_data[IMG_OFFSET:IMG_OFFSET+len(fw_data)] = fw_data
    
    with open(sys.argv[3], 'wb') as f:
        f.write(exe_data)
    
    print(f"Re-packed: {sys.argv[3]}")
    print(f"  Header at: {HEADER_OFFSET:#x}")
    print(f"  Image at:  {IMG_OFFSET:#x}")
    print(f"  Image size: {len(fw_data)} bytes")
    print(f"  SHA256: {hashlib.sha256(exe_data).hexdigest()}")
    print("\nIMPORTANT: MCUboot may verify image signature/hash.")
    print("If the upgrade tool rejects the image, you may need to:")
    print("  - Recalculate the MCUboot TLV (trailer) hash")
    print("  - Or flash via SWD (bypassing signature check)")

if __name__ == "__main__":
    main()
