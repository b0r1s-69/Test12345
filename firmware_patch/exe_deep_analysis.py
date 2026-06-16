#!/usr/bin/env python3
"""
AJ159 APEX ry_upgrade.exe Deep Analysis Tool
==============================================
Reverse-engineers the RuiYu OEM firmware updater to find:
  - All embedded firmware blobs (MCUboot images)
  - RSA key material (public keys, key hashes)
  - Update methods and their security levels
  - DFU protocol constants and strings
  - Debug/factory mode indicators
  - Signature bypass possibilities
  - Device-to-method mapping

USAGE:
  python3 exe_deep_analysis.py [path/to/ry_upgrade_PATCHED.exe]

OUTPUT:
  firmware_patch/EXE_DEEP_ANALYSIS_REPORT.md
"""
import sys
import os
import struct
import hashlib
import re
from collections import defaultdict, OrderedDict
from pathlib import Path

try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False
    print("[!] pefile not available, using manual PE parsing")

# ===========================================================================
# Configuration
# ===========================================================================

MCUBOOT_MAGIC = 0x96F3B83D
MCUBOOT_MAGIC_BYTES = struct.pack('<I', MCUBOOT_MAGIC)  # 3D B8 F3 96

# Known offsets from prior analysis
KNOWN_RSA_KEY_OFFSET = 0x0119B47F     # 270 bytes PKCS#1 DER
KNOWN_APP_IMAGE_OFFSET = 0x011A291F   # App MCUboot image
KNOWN_BLE_IMAGE_OFFSET = 0x011C291F   # BLE MCUboot image
KNOWN_KEYHASH_1 = 0x011BD38B
KNOWN_KEYHASH_2 = 0x011EC1AF

# MCUboot TLV types (newer MCUboot versions)
TLV_TYPES = {
    0x0001: "KEYHASH (SHA-256 of public key)",
    0x0010: "SHA256 (image hash)",
    0x0020: "RSA2048 (RSA-2048 signature)",
    0x0021: "ECDSA224 (deprecated)",
    0x0022: "ECDSA256 (ECDSA-P256 signature)",
    0x0023: "RSA3072 (RSA-3072 signature)",
    0x0030: "DEPENDENCY",
    0x0050: "SEC_CNT (security counter)",
    0x0060: "BOOT_RECORD",
    # Protected TLV types
    0x0002: "SHA256 (protected)",
    0x0003: "RSA2048_PSS",
    0x0004: "ED25519",
}

# MCUboot header structure
MCUBOOT_HDR_SIZE = 32
MCUBOOT_HDR_FORMAT = '<IIHH IHHI'  # magic, load_addr, hdr_size, pad_hdr_size, img_size, flags, ver_major|minor, ver_rev, ver_build

# RSA PKCS#1 DER markers
RSA_DER_HEADER = bytes([0x30, 0x82])  # SEQUENCE tag + 2-byte length
RSA_KEY_MARKERS = [
    bytes.fromhex("3082010a0282010100"),  # RSA-2048 public key (SubjectPublicKeyInfo)
    bytes.fromhex("30820122300d06092a"),  # RSA-2048 PKCS#8 wrapped
    bytes.fromhex("3082010902820100"),    # RSA-2048 alternate encoding
]

# DFU-related search strings
DFU_STRINGS = [
    b"dfu", b"DFU", b"nordic", b"Nordic", b"NORDIC",
    b"nrf", b"NRF", b"nRF",
    b"smp", b"SMP", b"mcuboot", b"MCUboot", b"MCUBOOT",
    b"bootloader", b"Bootloader", b"BOOTLOADER",
    b"firmware", b"Firmware", b"FIRMWARE",
    b"upgrade", b"Upgrade", b"UPGRADE",
    b"flash", b"Flash", b"FLASH",
    b"signature", b"Signature",
    b"verify", b"Verify",
    b"slot", b"Slot",
    b"swap", b"Swap",
    b"image", b"Image",
    b"init_packet", b"init packet",
    b"dat_file", b"zip_file",
    b"manifest",
]

# Update method strings
METHOD_STRINGS = [
    b"MOUSE", b"NORDICKEYBOARD", b"FLASH", b"YZW", b"YZW24",
    b"BK100", b"KEYBOARD", b"DONGLE", b"RECEIVER",
    b"Nordic", b"NRF52", b"nrf52",
    b"mouse_method", b"keyboard_method", b"flash_method",
]

# Debug/factory mode strings
DEBUG_STRINGS = [
    b"debug", b"Debug", b"DEBUG",
    b"test", b"Test", b"TEST",
    b"factory", b"Factory", b"FACTORY",
    b"force", b"Force", b"FORCE",
    b"bypass", b"Bypass", b"BYPASS",
    b"skip_verify", b"skip_sign", b"no_sign",
    b"unsigned", b"UNSIGNED",
    b"dev_mode", b"development",
    b"unlock", b"Unlock",
    b"backdoor", b"Backdoor",
    b"override", b"Override",
    b"insecure", b"Insecure",
    b"raw_write", b"raw_flash",
    b"direct_write", b"direct_flash",
]

# VID/PID patterns (little-endian 16-bit)
KNOWN_VID = 0x3151
KNOWN_PID_NORMAL = 0x4026
KNOWN_PID_BOOT = 0x4025


# ===========================================================================
# Helper functions
# ===========================================================================

def find_all_occurrences(data, pattern):
    """Find all occurrences of a byte pattern in data."""
    results = []
    pos = 0
    while True:
        idx = data.find(pattern, pos)
        if idx == -1:
            break
        results.append(idx)
        pos = idx + 1
    return results


def extract_string_at(data, offset, max_len=256):
    """Extract a null-terminated or printable string at offset."""
    result = bytearray()
    for i in range(max_len):
        if offset + i >= len(data):
            break
        b = data[offset + i]
        if b == 0:
            break
        if 32 <= b < 127:
            result.append(b)
        else:
            break
    return result.decode('ascii', errors='replace')


def extract_utf16_string_at(data, offset, max_len=512):
    """Extract a null-terminated UTF-16LE string at offset."""
    result = bytearray()
    for i in range(0, max_len, 2):
        if offset + i + 1 >= len(data):
            break
        lo = data[offset + i]
        hi = data[offset + i + 1]
        if lo == 0 and hi == 0:
            break
        result.append(lo)
        result.append(hi)
    try:
        return result.decode('utf-16-le')
    except (UnicodeDecodeError, ValueError):
        return ""


def parse_mcuboot_header(data, offset):
    """Parse MCUboot image header at offset."""
    if offset + 32 > len(data):
        return None
    
    magic = struct.unpack_from('<I', data, offset)[0]
    if magic != MCUBOOT_MAGIC:
        return None
    
    hdr = {}
    hdr['magic'] = magic
    hdr['load_addr'] = struct.unpack_from('<I', data, offset + 4)[0]
    hdr['hdr_size'] = struct.unpack_from('<H', data, offset + 8)[0]
    hdr['protect_tlv_size'] = struct.unpack_from('<H', data, offset + 10)[0]
    hdr['img_size'] = struct.unpack_from('<I', data, offset + 12)[0]
    hdr['flags'] = struct.unpack_from('<I', data, offset + 16)[0]
    
    # Version
    ver_major = data[offset + 20]
    ver_minor = data[offset + 21]
    ver_rev = struct.unpack_from('<H', data, offset + 22)[0]
    ver_build = struct.unpack_from('<I', data, offset + 24)[0]
    hdr['version'] = f"{ver_major}.{ver_minor}.{ver_rev}+{ver_build}"
    
    return hdr


def parse_mcuboot_tlvs(data, offset, hdr):
    """Parse MCUboot TLV area following the image."""
    tlvs = []
    tlv_start = offset + hdr['hdr_size'] + hdr['img_size']
    
    if tlv_start + 4 > len(data):
        return tlvs
    
    # TLV info header: magic (2 bytes) + tlv_tot (2 bytes)
    tlv_magic = struct.unpack_from('<H', data, tlv_start)[0]
    tlv_tot = struct.unpack_from('<H', data, tlv_start + 2)[0]
    
    if tlv_magic != 0x6907:  # TLV_INFO_MAGIC
        # Try alternate magic
        if tlv_magic != 0x6908:  # TLV_PROT_INFO_MAGIC
            return tlvs
    
    pos = tlv_start + 4
    end = tlv_start + 4 + tlv_tot
    
    while pos + 4 <= end and pos + 4 <= len(data):
        tlv_type = struct.unpack_from('<H', data, pos)[0]
        tlv_len = struct.unpack_from('<H', data, pos + 2)[0]
        
        if pos + 4 + tlv_len > len(data):
            break
        
        tlv_data = data[pos + 4:pos + 4 + tlv_len]
        tlv_name = TLV_TYPES.get(tlv_type, f"UNKNOWN(0x{tlv_type:04x})")
        
        tlvs.append({
            'offset': pos,
            'type': tlv_type,
            'name': tlv_name,
            'length': tlv_len,
            'data': tlv_data,
        })
        
        pos += 4 + tlv_len
    
    return tlvs


def compute_sha256(data):
    """Compute SHA-256 hash."""
    return hashlib.sha256(data).hexdigest()


# ===========================================================================
# Analysis Sections
# ===========================================================================

def analyze_pe_structure(data, report):
    """Section 1: Parse PE structure."""
    report.append("## Section 1: PE Structure Analysis")
    report.append("")
    
    if HAS_PEFILE:
        try:
            pe = pefile.PE(data=data)
            
            report.append(f"- **Machine**: {hex(pe.FILE_HEADER.Machine)}")
            report.append(f"- **Number of sections**: {pe.FILE_HEADER.NumberOfSections}")
            report.append(f"- **Timestamp**: {pe.FILE_HEADER.TimeDateStamp}")
            report.append(f"- **Characteristics**: {hex(pe.FILE_HEADER.Characteristics)}")
            report.append(f"- **Image base**: {hex(pe.OPTIONAL_HEADER.ImageBase)}")
            report.append(f"- **Entry point**: {hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}")
            report.append(f"- **Subsystem**: {pe.OPTIONAL_HEADER.Subsystem}")
            report.append("")
            
            # Sections
            report.append("### Sections:")
            report.append("")
            report.append("| Name | VirtualAddr | VirtualSize | RawOffset | RawSize | Characteristics |")
            report.append("|------|-------------|-------------|-----------|---------|-----------------|")
            for section in pe.sections:
                name = section.Name.decode('ascii', errors='replace').rstrip('\x00')
                name = ''.join(c if 32 <= ord(c) < 127 else '.' for c in name)
                report.append(f"| {name} | {hex(section.VirtualAddress)} | {section.Misc_VirtualSize} | {hex(section.PointerToRawData)} | {section.SizeOfRawData} | {hex(section.Characteristics)} |")
            report.append("")
            
            # Imports
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                report.append("### Import DLLs:")
                report.append("")
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('ascii', errors='replace')
                    # Sanitize
                    dll_name = ''.join(c if 32 <= ord(c) < 127 else '.' for c in dll_name)
                    num_funcs = len(entry.imports)
                    report.append(f"- **{dll_name}** ({num_funcs} functions)")
                report.append("")
            
            # Resources
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                report.append("### Resources:")
                report.append("")
                for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    if hasattr(entry, 'name') and entry.name:
                        report.append(f"- Type: {entry.name}")
                    else:
                        report.append(f"- Type ID: {entry.id}")
                report.append("")
            
            return pe
        except Exception as e:
            report.append(f"pefile parsing error: {e}")
            report.append("")
    else:
        # Manual PE parsing
        report.append("### Manual PE Parsing (pefile not available)")
        report.append("")
        
        # DOS header
        if data[:2] != b'MZ':
            report.append("ERROR: Not a valid PE file (no MZ signature)")
            return None
        
        pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
        if data[pe_offset:pe_offset+4] != b'PE\x00\x00':
            report.append("ERROR: Invalid PE signature")
            return None
        
        # COFF header
        machine = struct.unpack_from('<H', data, pe_offset + 4)[0]
        num_sections = struct.unpack_from('<H', data, pe_offset + 6)[0]
        
        report.append(f"- PE offset: {pe_offset:#x}")
        report.append(f"- Machine: {machine:#x}")
        report.append(f"- Sections: {num_sections}")
        report.append("")
    
    return None


def analyze_mcuboot_images(data, report):
    """Section 2: Find ALL MCUboot image magic values."""
    report.append("## Section 2: Embedded MCUboot Images")
    report.append("")
    report.append(f"Searching for MCUboot magic (0x{MCUBOOT_MAGIC:08X} / {MCUBOOT_MAGIC_BYTES.hex()})...")
    report.append("")
    
    magic_offsets = find_all_occurrences(data, MCUBOOT_MAGIC_BYTES)
    
    report.append(f"### Found {len(magic_offsets)} MCUboot magic occurrences:")
    report.append("")
    
    images = []
    for offset in magic_offsets:
        hdr = parse_mcuboot_header(data, offset)
        if hdr:
            images.append((offset, hdr))
            report.append(f"#### Image at offset {offset:#010x}:")
            report.append("")
            report.append(f"- Magic: {hdr['magic']:#010x}")
            report.append(f"- Load address: {hdr['load_addr']:#010x}")
            report.append(f"- Header size: {hdr['hdr_size']}")
            report.append(f"- Image size: {hdr['img_size']} bytes ({hdr['img_size']/1024:.1f} KB)")
            report.append(f"- Flags: {hdr['flags']:#010x}")
            report.append(f"- Version: {hdr['version']}")
            report.append("")
            
            # Compute SHA-256 of the image
            img_start = offset + hdr['hdr_size']
            img_end = img_start + hdr['img_size']
            if img_end <= len(data):
                img_hash = compute_sha256(data[img_start:img_end])
                report.append(f"- Image SHA-256: `{img_hash}`")
                report.append("")
            
            # Parse TLVs
            tlvs = parse_mcuboot_tlvs(data, offset, hdr)
            if tlvs:
                report.append(f"  **TLVs ({len(tlvs)} entries):**")
                report.append("")
                for tlv in tlvs:
                    report.append(f"  - Type: {tlv['name']} (len={tlv['length']})")
                    if tlv['type'] == 0x0001:  # KEYHASH
                        report.append(f"    Hash: `{tlv['data'].hex()}`")
                    elif tlv['type'] in (0x0010, 0x0002):  # SHA256
                        report.append(f"    Hash: `{tlv['data'].hex()}`")
                    elif tlv['type'] in (0x0020, 0x0003):  # RSA2048
                        report.append(f"    Signature: `{tlv['data'][:16].hex()}...` ({tlv['length']} bytes)")
                report.append("")
            
            # Check known offsets
            if offset == KNOWN_APP_IMAGE_OFFSET:
                report.append("  **>>> This is the KNOWN APP IMAGE <<<**")
                report.append("")
            elif offset == KNOWN_BLE_IMAGE_OFFSET:
                report.append("  **>>> This is the KNOWN BLE IMAGE <<<**")
                report.append("")
        else:
            report.append(f"- Magic at {offset:#010x} - NOT a valid MCUboot header (may be data/coincidence)")
            report.append("")
    
    # Compare key hashes across images
    if len(images) >= 2:
        report.append("### Key Hash Comparison Across Images:")
        report.append("")
        report.append("If different images use different key hashes, some may use weaker keys!")
        report.append("")
        
        key_hashes = set()
        for offset, hdr in images:
            tlvs = parse_mcuboot_tlvs(data, offset, hdr)
            for tlv in tlvs:
                if tlv['type'] == 0x0001:
                    key_hashes.add(tlv['data'].hex())
        
        report.append(f"Unique key hashes found: {len(key_hashes)}")
        for kh in key_hashes:
            report.append(f"- `{kh}`")
        report.append("")
        
        if len(key_hashes) == 1:
            report.append("All images use the SAME key - no weaker-key bypass possible.")
        elif len(key_hashes) > 1:
            report.append("!!! DIFFERENT KEYS DETECTED !!! Some images may use weaker verification!")
        report.append("")
    
    return images


def analyze_rsa_keys(data, report):
    """Section 3: Search for ALL RSA key material."""
    report.append("## Section 3: RSA Key Material Search")
    report.append("")
    
    # Search for known RSA key at expected offset
    report.append("### Known RSA Key Location:")
    report.append("")
    if KNOWN_RSA_KEY_OFFSET + 270 <= len(data):
        key_data = data[KNOWN_RSA_KEY_OFFSET:KNOWN_RSA_KEY_OFFSET + 270]
        report.append(f"- Offset: {KNOWN_RSA_KEY_OFFSET:#010x}")
        report.append(f"- First 32 bytes: `{key_data[:32].hex()}`")
        report.append(f"- SHA-256 of key: `{compute_sha256(key_data)}`")
        report.append("")
    
    # Search for RSA key DER markers throughout the binary
    report.append("### Searching for RSA key DER structures:")
    report.append("")
    
    key_locations = []
    for marker in RSA_KEY_MARKERS:
        occurrences = find_all_occurrences(data, marker)
        for offset in occurrences:
            key_locations.append((offset, marker.hex()))
    
    # Also search for generic ASN.1 SEQUENCE markers that could be keys
    # RSA-2048 keys are typically 270 bytes (SubjectPublicKeyInfo) or 256 bytes (raw modulus)
    seq_offsets = find_all_occurrences(data, RSA_DER_HEADER)
    for offset in seq_offsets:
        if offset + 4 > len(data):
            continue
        # Check if length field suggests a key-sized structure
        length = struct.unpack_from('>H', data, offset + 2)[0]
        if 256 <= length <= 300:  # Key-sized ASN.1 structures
            key_locations.append((offset, f"30 82 {length:04x} (len={length})"))
    
    # Deduplicate
    seen = set()
    unique_keys = []
    for offset, marker in sorted(key_locations):
        if offset not in seen:
            seen.add(offset)
            unique_keys.append((offset, marker))
    
    if unique_keys:
        report.append(f"Found {len(unique_keys)} potential RSA key structures:")
        report.append("")
        report.append("| Offset | Marker | First 16 bytes |")
        report.append("|--------|--------|----------------|")
        for offset, marker in unique_keys[:30]:
            first_bytes = data[offset:offset+16].hex()
            report.append(f"| {offset:#010x} | {marker[:20]} | {first_bytes} |")
        report.append("")
    
    # Search for known KEYHASH values
    report.append("### KEYHASH Occurrences:")
    report.append("")
    
    # Extract keyhash from known offset
    if KNOWN_KEYHASH_1 + 32 <= len(data):
        keyhash_1 = data[KNOWN_KEYHASH_1:KNOWN_KEYHASH_1 + 32]
        report.append(f"- KEYHASH at {KNOWN_KEYHASH_1:#x}: `{keyhash_1.hex()}`")
        
        # Search for this hash elsewhere
        other_occurrences = find_all_occurrences(data, keyhash_1)
        report.append(f"  Found at {len(other_occurrences)} locations: {[f'{o:#x}' for o in other_occurrences]}")
        report.append("")
    
    if KNOWN_KEYHASH_2 + 32 <= len(data):
        keyhash_2 = data[KNOWN_KEYHASH_2:KNOWN_KEYHASH_2 + 32]
        report.append(f"- KEYHASH at {KNOWN_KEYHASH_2:#x}: `{keyhash_2.hex()}`")
        
        other_occurrences = find_all_occurrences(data, keyhash_2)
        report.append(f"  Found at {len(other_occurrences)} locations: {[f'{o:#x}' for o in other_occurrences]}")
        report.append("")
    
    # Check if any private key material exists (very unlikely but worth checking)
    report.append("### Private Key Search:")
    report.append("")
    
    # Private keys have specific ASN.1 markers
    private_markers = [
        b"-----BEGIN RSA PRIVATE",
        b"-----BEGIN PRIVATE",
        bytes.fromhex("3082025c02010002818100"),  # RSA-1024 private
        bytes.fromhex("308204a30201000282010100"),  # RSA-2048 private
    ]
    
    found_private = False
    for marker in private_markers:
        occurrences = find_all_occurrences(data, marker)
        if occurrences:
            found_private = True
            report.append(f"!!! PRIVATE KEY FOUND at offsets: {[f'{o:#x}' for o in occurrences]}")
    
    if not found_private:
        report.append("No private key material found (expected - vendor would not embed private keys).")
    report.append("")


def analyze_dfu_strings(data, report):
    """Section 4: Search for DFU-related strings."""
    report.append("## Section 4: DFU and Firmware Update Strings")
    report.append("")
    
    # Search for each DFU string
    all_findings = defaultdict(list)
    
    for search_term in DFU_STRINGS:
        occurrences = find_all_occurrences(data, search_term)
        for offset in occurrences:
            # Extract context
            start = max(0, offset - 20)
            end = min(len(data), offset + len(search_term) + 60)
            context = data[start:end]
            # Filter to printable
            printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in context)
            all_findings[search_term.decode('ascii', errors='replace')].append((offset, printable))
    
    # Report findings grouped by category
    report.append("### DFU/Update String Occurrences:")
    report.append("")
    
    for term, locations in sorted(all_findings.items(), key=lambda x: -len(x[1])):
        report.append(f"#### `{term}` - {len(locations)} occurrences")
        report.append("")
        for offset, context in locations[:10]:
            report.append(f"- {offset:#010x}: `{context[:80]}`")
        if len(locations) > 10:
            report.append(f"  ... and {len(locations) - 10} more")
        report.append("")


def analyze_method_strings(data, report):
    """Section 5: Search for update method strings."""
    report.append("## Section 5: Update Method Strings")
    report.append("")
    report.append("The updater supports multiple methods: MOUSE, NORDICKEYBOARD, FLASH, YZW, etc.")
    report.append("Each may have different security characteristics.")
    report.append("")
    
    for search_term in METHOD_STRINGS:
        occurrences = find_all_occurrences(data, search_term)
        if occurrences:
            report.append(f"### `{search_term.decode()}` - {len(occurrences)} occurrences")
            report.append("")
            for offset in occurrences[:15]:
                # Extract context
                start = max(0, offset - 10)
                end = min(len(data), offset + len(search_term) + 80)
                context_bytes = data[start:end]
                printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in context_bytes)
                report.append(f"- {offset:#010x}: `{printable[:100]}`")
            report.append("")


def analyze_debug_strings(data, report):
    """Section 6: Search for debug/factory mode indicators."""
    report.append("## Section 6: Debug/Factory/Bypass Mode Search")
    report.append("")
    report.append("Searching for any strings that indicate hidden modes, bypass mechanisms,")
    report.append("or test/factory functionality that might skip signature verification.")
    report.append("")
    
    found_any = False
    for search_term in DEBUG_STRINGS:
        occurrences = find_all_occurrences(data, search_term)
        if occurrences:
            found_any = True
            report.append(f"### `{search_term.decode()}` - {len(occurrences)} occurrences")
            report.append("")
            for offset in occurrences[:10]:
                start = max(0, offset - 10)
                end = min(len(data), offset + len(search_term) + 60)
                context_bytes = data[start:end]
                printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in context_bytes)
                report.append(f"- {offset:#010x}: `{printable[:100]}`")
            report.append("")
    
    if not found_any:
        report.append("No debug/factory/bypass mode strings found.")
        report.append("")


def analyze_vid_pid(data, report):
    """Section 7: Search for VID/PID references and device mapping."""
    report.append("## Section 7: VID/PID and Device Mapping")
    report.append("")
    
    # Search for our known VID/PID
    vid_bytes = struct.pack('<H', KNOWN_VID)
    pid_normal_bytes = struct.pack('<H', KNOWN_PID_NORMAL)
    pid_boot_bytes = struct.pack('<H', KNOWN_PID_BOOT)
    
    vid_offsets = find_all_occurrences(data, vid_bytes)
    pid_normal_offsets = find_all_occurrences(data, pid_normal_bytes)
    pid_boot_offsets = find_all_occurrences(data, pid_boot_bytes)
    
    report.append(f"### Known Device IDs:")
    report.append("")
    report.append(f"- VID 0x{KNOWN_VID:04X}: found at {len(vid_offsets)} locations")
    report.append(f"- PID 0x{KNOWN_PID_NORMAL:04X} (normal): found at {len(pid_normal_offsets)} locations")
    report.append(f"- PID 0x{KNOWN_PID_BOOT:04X} (boot): found at {len(pid_boot_offsets)} locations")
    report.append("")
    
    # Look for paired VID/PID (VID followed closely by PID)
    report.append("### VID/PID Pairs (VID within 16 bytes of PID):")
    report.append("")
    
    pairs_found = []
    for vid_off in vid_offsets:
        for pid_off in pid_normal_offsets + pid_boot_offsets:
            if abs(vid_off - pid_off) <= 16:
                pid_val = KNOWN_PID_NORMAL if pid_off in pid_normal_offsets else KNOWN_PID_BOOT
                pairs_found.append((vid_off, pid_off, pid_val))
    
    for vid_off, pid_off, pid_val in pairs_found[:20]:
        # Extract surrounding context
        start = min(vid_off, pid_off) - 4
        end = max(vid_off, pid_off) + 8
        context = data[max(0, start):min(len(data), end)].hex()
        report.append(f"- VID@{vid_off:#x}, PID 0x{pid_val:04X}@{pid_off:#x}: `{context}`")
    report.append("")
    
    # Search for other common USB VIDs that might share firmware infrastructure
    common_vids = [0x1532, 0x046D, 0x1038, 0x1B1C, 0x258A, 0x320F, 0x3151, 0x0D8C]
    report.append("### Other USB VIDs found in binary:")
    report.append("")
    for vid in common_vids:
        if vid == KNOWN_VID:
            continue
        vid_bytes_search = struct.pack('<H', vid)
        occurrences = find_all_occurrences(data, vid_bytes_search)
        # Filter to reasonable locations (not in code sections typically)
        if occurrences and len(occurrences) < 100:
            report.append(f"- VID 0x{vid:04X}: {len(occurrences)} occurrences")
    report.append("")


def analyze_support_config(data, report):
    """Section 8: Extract and analyze support_config.json content."""
    report.append("## Section 8: Embedded Configuration Data")
    report.append("")
    
    # Search for JSON-like structures
    json_markers = [b'"vid"', b'"pid"', b'"method"', b'"name"', b'"chip"',
                    b'support_config', b'"devices"', b'"upgrade_method"']
    
    report.append("### JSON/Config Markers:")
    report.append("")
    
    for marker in json_markers:
        occurrences = find_all_occurrences(data, marker)
        if occurrences:
            report.append(f"- `{marker.decode()}`: {len(occurrences)} occurrences")
            for offset in occurrences[:5]:
                # Try to extract surrounding JSON
                start = max(0, offset - 20)
                end = min(len(data), offset + 200)
                context = data[start:end]
                printable = ''.join(chr(b) if 32 <= b < 127 else '' for b in context)
                report.append(f"  - {offset:#x}: `{printable[:120]}`")
            report.append("")
    
    # Try to find the full support_config JSON blob
    report.append("### Searching for embedded JSON configuration blob:")
    report.append("")
    
    # Look for a large JSON structure
    json_starts = find_all_occurrences(data, b'{"')
    large_json = []
    for start in json_starts:
        # Try to find matching close brace
        depth = 0
        pos = start
        max_search = min(start + 100000, len(data))
        while pos < max_search:
            if data[pos:pos+1] == b'{':
                depth += 1
            elif data[pos:pos+1] == b'}':
                depth -= 1
                if depth == 0:
                    json_text = data[start:pos+1]
                    if len(json_text) > 500:  # Only interested in large JSON blobs
                        # Sanitize to ASCII-only for display
                        preview = ''.join(chr(b) if 32 <= b < 127 else '.' for b in json_text[:200])
                        large_json.append((start, len(json_text), preview))
                    break
            pos += 1
    
    if large_json:
        report.append(f"Found {len(large_json)} large JSON blobs (>500 bytes):")
        report.append("")
        for offset, size, preview in sorted(large_json, key=lambda x: -x[1])[:10]:
            # Sanitize preview to only ASCII printable
            safe_preview = ''.join(c if 32 <= ord(c) < 127 else '.' for c in preview)
            report.append(f"- Offset {offset:#x}, size {size} bytes:")
            report.append(f"  `{safe_preview[:150]}...`")
            report.append("")
    else:
        report.append("No large JSON blobs found directly in binary.")
        report.append("Configuration may be in a resource section or compressed.")
        report.append("")


def analyze_unsigned_images(data, images, report):
    """Section 9: Check if any embedded images are unsigned or use different keys."""
    report.append("## Section 9: Image Signature Analysis")
    report.append("")
    report.append("Checking each embedded MCUboot image for signature presence and key usage.")
    report.append("")
    
    if not images:
        report.append("No MCUboot images found to analyze.")
        report.append("")
        return
    
    all_keyhashes = {}
    unsigned_images = []
    
    for offset, hdr in images:
        report.append(f"### Image at {offset:#x} (v{hdr['version']}, {hdr['img_size']} bytes):")
        report.append("")
        
        tlvs = parse_mcuboot_tlvs(data, offset, hdr)
        
        has_signature = False
        has_hash = False
        keyhash = None
        sig_type = None
        
        for tlv in tlvs:
            if tlv['type'] == 0x0001:  # KEYHASH
                keyhash = tlv['data'].hex()
                report.append(f"  - KEYHASH: `{keyhash}`")
            elif tlv['type'] in (0x0010, 0x0002):  # SHA256
                has_hash = True
                report.append(f"  - SHA256: `{tlv['data'].hex()}`")
            elif tlv['type'] in (0x0020, 0x0003, 0x0022, 0x0023, 0x0004):  # Signatures
                has_signature = True
                sig_type = TLV_TYPES.get(tlv['type'], f"SIG_TYPE_{tlv['type']:#x}")
                report.append(f"  - Signature: {sig_type} ({tlv['length']} bytes)")
            else:
                report.append(f"  - TLV type {tlv['type']:#06x}: {tlv['length']} bytes")
        
        if not has_signature:
            unsigned_images.append(offset)
            report.append("  - **!!! NO SIGNATURE - IMAGE IS UNSIGNED !!!**")
        
        if keyhash:
            all_keyhashes.setdefault(keyhash, []).append(offset)
        
        report.append("")
    
    # Summary
    report.append("### Summary:")
    report.append("")
    report.append(f"- Total images: {len(images)}")
    report.append(f"- Unsigned images: {len(unsigned_images)}")
    report.append(f"- Unique key hashes: {len(all_keyhashes)}")
    report.append("")
    
    if unsigned_images:
        report.append("**CRITICAL: Unsigned images found! These bypass signature verification!**")
        report.append("")
    
    if len(all_keyhashes) > 1:
        report.append("**IMPORTANT: Multiple key hashes detected! Different signing keys in use!**")
        report.append("")
        for kh, offsets in all_keyhashes.items():
            report.append(f"- Key `{kh[:32]}...` used by images at: {[f'{o:#x}' for o in offsets]}")
        report.append("")


def analyze_nordickeyboard_path(data, report):
    """Section 10: Analyze the NORDICKEYBOARD update method."""
    report.append("## Section 10: NORDICKEYBOARD Method Analysis")
    report.append("")
    report.append("The NORDICKEYBOARD method is used for some devices. Understanding what it does")
    report.append("differently from MOUSE method could reveal alternative update paths.")
    report.append("")
    
    # Search for NORDICKEYBOARD-related code/strings
    nk_occurrences = find_all_occurrences(data, b"NORDICKEYBOARD")
    
    if nk_occurrences:
        report.append(f"### Found {len(nk_occurrences)} occurrences of 'NORDICKEYBOARD':")
        report.append("")
        for offset in nk_occurrences:
            start = max(0, offset - 40)
            end = min(len(data), offset + 100)
            context = data[start:end]
            printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in context)
            report.append(f"- {offset:#010x}: `{printable[:120]}`")
        report.append("")
    
    # Search for related method dispatch
    # Rust strings are typically UTF-8 with length prefix or null-terminated
    mouse_method_refs = find_all_occurrences(data, b"MOUSE")
    flash_method_refs = find_all_occurrences(data, b"FLASH")
    
    report.append("### Method string comparison:")
    report.append("")
    report.append(f"- MOUSE: {len(mouse_method_refs)} occurrences")
    report.append(f"- NORDICKEYBOARD: {len(nk_occurrences)} occurrences")
    report.append(f"- FLASH: {len(flash_method_refs)} occurrences")
    report.append("")
    
    # Look for "enter_boot" or boot-related sequences near NORDICKEYBOARD refs
    boot_strings = [b"enter_boot", b"enter boot", b"boot_mode", b"bootloader_mode",
                    b"reset_to_boot", b"dfu_mode"]
    
    report.append("### Boot-entry related strings:")
    report.append("")
    for s in boot_strings:
        occs = find_all_occurrences(data, s)
        if occs:
            report.append(f"- `{s.decode()}`: found at {[f'{o:#x}' for o in occs[:5]]}")
    report.append("")


def analyze_protocol_constants(data, report):
    """Section 11: Search for protocol-specific constants."""
    report.append("## Section 11: Protocol Constants and Packet Structures")
    report.append("")
    report.append("Looking for HID report structures, packet formats, and protocol commands")
    report.append("that the updater uses to communicate with the device.")
    report.append("")
    
    # Search for HID report-related byte patterns
    # The mouse uses 64-byte feature reports with report ID 0x00
    # Look for patterns that suggest packet building
    
    # Search for common protocol magic bytes
    protocol_patterns = [
        (b"\x7f\x00\x00\x00", "Enter-boot command (0x7F)"),
        (b"\xba", "BA prefix (bootloader acknowledge?)"),
        (b"\x00\x40\x00\x00", "64-byte size reference"),
        (b"\x00\x01\x00\x00\x10\x00", "Load address 0x10000"),
    ]
    
    report.append("### Protocol Magic Patterns:")
    report.append("")
    for pattern, desc in protocol_patterns:
        occurrences = find_all_occurrences(data, pattern)
        # Filter to likely data sections (high offsets in EXE)
        filtered = [o for o in occurrences if o > 0x1000]
        if filtered and len(filtered) < 200:
            report.append(f"- {desc} (`{pattern.hex()}`): {len(filtered)} occurrences")
            for offset in filtered[:5]:
                report.append(f"  - {offset:#010x}")
    report.append("")
    
    # Look for command byte sequences used in the USB protocol
    report.append("### USB HID Report Building Patterns:")
    report.append("")
    
    # Search for Rust string patterns related to HID
    hid_strings = [b"hid", b"HID", b"report", b"Report",
                   b"feature_report", b"set_report", b"get_report",
                   b"SET_REPORT", b"GET_REPORT", b"FEATURE",
                   b"interface", b"Interface",
                   b"endpoint", b"Endpoint",
                   b"transfer", b"Transfer"]
    
    for s in hid_strings:
        occs = find_all_occurrences(data, s)
        if occs and len(occs) < 50:
            report.append(f"- `{s.decode()}`: {len(occs)} occurrences")
    report.append("")


def analyze_rust_strings(data, report):
    """Section 12: Extract interesting Rust-specific strings."""
    report.append("## Section 12: Rust Application Strings Analysis")
    report.append("")
    report.append("Extracting strings that reveal the application's internal structure.")
    report.append("")
    
    # Rust panic strings reveal internal module structure
    panic_marker = b"panicked at"
    panic_locations = find_all_occurrences(data, panic_marker)
    
    report.append(f"### Rust panic messages ({len(panic_locations)} found):")
    report.append("")
    
    panic_messages = set()
    for offset in panic_locations[:50]:
        # Panic messages are usually nearby
        start = max(0, offset - 50)
        end = min(len(data), offset + 200)
        context = data[start:end]
        # Extract printable string
        text = ''.join(chr(b) if 32 <= b < 127 else '\n' for b in context)
        lines = [l.strip() for l in text.split('\n') if len(l.strip()) > 10]
        for line in lines:
            if 'panicked' in line or '.rs' in line or '\\src\\' in line or '/src/' in line:
                panic_messages.add(line[:120])
    
    for msg in sorted(panic_messages)[:30]:
        report.append(f"- `{msg}`")
    report.append("")
    
    # Rust source file paths reveal module structure
    rs_file_marker = b".rs"
    rs_locations = find_all_occurrences(data, rs_file_marker)
    
    source_files = set()
    for offset in rs_locations:
        # Look for path-like string around .rs
        start = max(0, offset - 80)
        context = data[start:offset + 3]
        text = ''.join(chr(b) if 32 <= b < 127 else '\x00' for b in context)
        # Find the last path-like segment
        parts = text.split('\x00')
        for part in parts:
            if '.rs' in part and len(part) > 5:
                # Clean up to just the file path
                clean = part.strip()
                if '\\' in clean or '/' in clean:
                    source_files.add(clean[-80:])
    
    report.append(f"### Rust source file references ({len(source_files)} unique):")
    report.append("")
    for sf in sorted(source_files)[:40]:
        report.append(f"- `{sf}`")
    report.append("")
    
    # Look for interesting error messages
    error_strings = [b"Error", b"error", b"Failed", b"failed", b"Invalid", b"invalid",
                     b"timeout", b"Timeout", b"retry", b"Retry"]
    
    report.append("### Error/failure messages (sample):")
    report.append("")
    
    error_messages = set()
    for marker in error_strings:
        for offset in find_all_occurrences(data, marker)[:20]:
            start = max(0, offset - 10)
            end = min(len(data), offset + 80)
            context = data[start:end]
            text = ''.join(chr(b) if 32 <= b < 127 else '' for b in context)
            if len(text) > 15:
                error_messages.add(text[:100])
    
    for msg in sorted(error_messages)[:30]:
        report.append(f"- `{msg}`")
    report.append("")


def analyze_signature_verification(data, report):
    """Section 13: Look for signature verification logic patterns."""
    report.append("## Section 13: Signature Verification Analysis")
    report.append("")
    report.append("Looking for patterns that suggest where/how signature verification happens.")
    report.append("This could reveal bypass opportunities in the host-side tool.")
    report.append("")
    
    # Search for crypto-library related strings
    crypto_strings = [
        b"rsa", b"RSA", b"sha256", b"SHA256", b"sha-256",
        b"verify", b"Verify", b"VERIFY",
        b"signature", b"Signature", b"SIGNATURE",
        b"digest", b"Digest",
        b"public_key", b"PublicKey", b"public key",
        b"pkcs", b"PKCS",
        b"asn1", b"ASN1",
        b"mbedtls", b"openssl", b"ring",  # Common Rust crypto libs
        b"crypto", b"Crypto",
    ]
    
    report.append("### Cryptography-related strings:")
    report.append("")
    for s in crypto_strings:
        occs = find_all_occurrences(data, s)
        if occs and len(occs) < 100:
            report.append(f"- `{s.decode()}`: {len(occs)} occurrences")
            if len(occs) <= 5:
                for offset in occs:
                    start = max(0, offset - 20)
                    end = min(len(data), offset + 60)
                    ctx = data[start:end]
                    text = ''.join(chr(b) if 32 <= b < 127 else '.' for b in ctx)
                    report.append(f"  - {offset:#x}: `{text[:80]}`")
    report.append("")
    
    # Look for the "image ok" / "image valid" / "signature valid" type strings
    validation_strings = [
        b"image ok", b"image valid", b"valid image",
        b"signature ok", b"signature valid", b"valid signature",
        b"verification pass", b"verify pass", b"verify ok",
        b"image_ok", b"sig_ok", b"verified",
        b"mcuboot_verify", b"boot_verify",
    ]
    
    report.append("### Validation result strings:")
    report.append("")
    for s in validation_strings:
        occs = find_all_occurrences(data, s)
        if occs:
            report.append(f"- `{s.decode()}`: {len(occs)} at {[f'{o:#x}' for o in occs[:5]]}")
    report.append("")


def generate_exe_conclusions(data, images, report):
    """Section 14: Conclusions from EXE analysis."""
    report.append("## Section 14: Conclusions and Analysis Paths")
    report.append("")
    report.append("### Summary of Findings:")
    report.append("")
    report.append(f"- EXE size: {len(data):,} bytes")
    report.append(f"- MCUboot images found: {len(images)}")
    report.append(f"- Known RSA key at offset: {KNOWN_RSA_KEY_OFFSET:#x}")
    report.append("")
    report.append("### Potential Analysis Strategies:")
    report.append("")
    report.append("1. **Method Substitution**: If NORDICKEYBOARD or FLASH methods have different")
    report.append("   security requirements, force the updater to use an alternative method")
    report.append("   for our device")
    report.append("")
    report.append("2. **Configuration Manipulation**: Modify the embedded support_config.json")
    report.append("   to change the device's assigned update method")
    report.append("")
    report.append("3. **Image Replacement in EXE**: Since we can patch the EXE, we could replace")
    report.append("   an embedded firmware image with our patched version. If the EXE does not")
    report.append("   re-verify signatures before flashing, this works.")
    report.append("")
    report.append("4. **Protocol Replay**: Capture the exact USB protocol the EXE uses during")
    report.append("   a legitimate update and replay it with modified firmware data")
    report.append("")
    report.append("5. **Key Hash Mismatch**: If multiple key hashes exist, there might be a")
    report.append("   fallback verification path that accepts different signatures")
    report.append("")
    report.append("6. **Rust Binary Patching**: Patch the EXE's signature verification routine")
    report.append("   to always return success (NOP out the check)")
    report.append("")
    report.append("### Critical Question:")
    report.append("")
    report.append("Does the EXE verify signatures BEFORE sending data to the device,")
    report.append("or does the DEVICE verify signatures after receiving the data?")
    report.append("")
    report.append("If verification is DEVICE-SIDE (MCUboot), then patching the EXE alone")
    report.append("will not help - we need to bypass MCUboot on the device itself.")
    report.append("")
    report.append("If verification is EXE-SIDE (host tool), then simply patching the")
    report.append("verification function in the EXE would allow flashing any image.")
    report.append("")
    report.append("The answer is likely BOTH - the EXE probably validates before sending,")
    report.append("AND MCUboot validates after receiving. The device-side validation is")
    report.append("the hard barrier that cannot be bypassed without the signing key.")
    report.append("")


# ===========================================================================
# Main
# ===========================================================================

def main():
    """Run the EXE deep analysis."""
    script_dir = Path(__file__).parent.resolve()
    
    if len(sys.argv) > 1:
        exe_path = Path(sys.argv[1])
    else:
        exe_path = script_dir / "ry_upgrade_PATCHED.exe"
    
    output_path = script_dir / "EXE_DEEP_ANALYSIS_REPORT.md"
    
    print("=" * 70)
    print("  AJ159 APEX ry_upgrade.exe Deep Analysis")
    print("=" * 70)
    print()
    
    # Load EXE
    if not exe_path.exists():
        print(f"ERROR: EXE file not found: {exe_path}")
        sys.exit(1)
    
    data = exe_path.read_bytes()
    print(f"[+] Loaded EXE: {exe_path} ({len(data):,} bytes)")
    print()
    
    # Build report
    report = []
    report.append("# AJ159 APEX ry_upgrade.exe Deep Analysis Report")
    report.append("")
    report.append("Generated by `exe_deep_analysis.py`")
    report.append("")
    report.append(f"Target: `{exe_path.name}` ({len(data):,} bytes)")
    report.append("")
    report.append("This analysis reverse-engineers the RuiYu OEM firmware updater to find")
    report.append("alternative paths for flashing modified firmware.")
    report.append("")
    report.append("---")
    report.append("")
    
    # Section 1: PE structure
    print("[1/14] Parsing PE structure...")
    pe = analyze_pe_structure(data, report)
    
    # Section 2: MCUboot images
    print("[2/14] Searching for MCUboot images...")
    images = analyze_mcuboot_images(data, report)
    
    # Section 3: RSA keys
    print("[3/14] Searching for RSA key material...")
    analyze_rsa_keys(data, report)
    
    # Section 4: DFU strings
    print("[4/14] Searching for DFU-related strings...")
    analyze_dfu_strings(data, report)
    
    # Section 5: Method strings
    print("[5/14] Searching for update method strings...")
    analyze_method_strings(data, report)
    
    # Section 6: Debug strings
    print("[6/14] Searching for debug/factory mode strings...")
    analyze_debug_strings(data, report)
    
    # Section 7: VID/PID
    print("[7/14] Analyzing VID/PID references...")
    analyze_vid_pid(data, report)
    
    # Section 8: Configuration
    print("[8/14] Searching for embedded configuration...")
    analyze_support_config(data, report)
    
    # Section 9: Unsigned images
    print("[9/14] Analyzing image signatures...")
    analyze_unsigned_images(data, images, report)
    
    # Section 10: NORDICKEYBOARD
    print("[10/14] Analyzing NORDICKEYBOARD method...")
    analyze_nordickeyboard_path(data, report)
    
    # Section 11: Protocol constants
    print("[11/14] Searching for protocol constants...")
    analyze_protocol_constants(data, report)
    
    # Section 12: Rust strings
    print("[12/14] Extracting Rust application strings...")
    analyze_rust_strings(data, report)
    
    # Section 13: Signature verification
    print("[13/14] Analyzing signature verification patterns...")
    analyze_signature_verification(data, report)
    
    # Section 14: Conclusions
    print("[14/14] Generating conclusions...")
    generate_exe_conclusions(data, images, report)
    
    # Write report
    report_text = '\n'.join(report)
    output_path.write_text(report_text)
    
    print()
    print("=" * 70)
    print(f"[+] Report written to: {output_path}")
    print(f"[+] Report size: {len(report_text):,} bytes, {len(report)} lines")
    print("=" * 70)


if __name__ == '__main__':
    main()
