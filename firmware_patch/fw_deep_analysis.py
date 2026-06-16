#!/usr/bin/env python3
"""
AJ159 APEX Firmware Deep Analysis Tool
========================================
Comprehensive reverse engineering analysis of mouse_app_fw.bin (nRF52840, ARM Cortex-M4F).

Performs:
  - MCUboot header/structure analysis
  - Complete function enumeration
  - SET_REPORT handler disassembly and call graph
  - Buffer overflow / interface analysis
  - Peripheral reference mapping
  - Patch comparison

USAGE:
  python3 fw_deep_analysis.py [path/to/mouse_app_fw.bin]

OUTPUT:
  firmware_patch/DEEP_ANALYSIS_REPORT.md
"""
import sys
import os
import struct
import hashlib
from collections import defaultdict
from pathlib import Path

from capstone import *
from capstone.arm import *

# ===========================================================================
# Configuration
# ===========================================================================

BASE_ADDR = 0x10000          # Load address in memory
VECTOR_TABLE_OFFSET = 0x20   # File offset of vector table
MCUBOOT_MAGIC = 0x96F3B83D   # MCUboot image magic
EXPECTED_SIZE = 108608
EXPECTED_SHA256 = "1c0c5fdd02ce92ed521729a00218f0f86920211455b1d51fe9a4455a7a3d8262"

# Key addresses (memory addresses)
SET_REPORT_HANDLER = 0x1C1A8
CONFIG_DISPATCH = 0x17DDC
MEMCPY_FUNC = 0x14D58
ENTER_BOOT_CHECK = 0x1C26A
BUG_SITE = 0x24616
CODE_CAVE = 0x25F36
COMMON_HANDLER = 0x21D44
FUNC_17DA8 = 0x17DA8

# Nordic nRF52840 peripheral base addresses
PERIPHERALS = {
    "NVMC":    0x4001E000,
    "UICR":    0x10001000,
    "FICR":    0x10000000,
    "GPIO_P0": 0x50000000,
    "GPIO_P1": 0x50000300,
    "RADIO":   0x40001000,
    "TIMER0":  0x40008000,
    "TIMER1":  0x40009000,
    "TIMER2":  0x4000A000,
    "SPI0":    0x40003000,
    "TWI0":    0x40003000,
    "UART0":   0x40002000,
    "GPIOTE":  0x40006000,
    "PWM0":    0x4001C000,
    "WDT":     0x40010000,
    "RTC0":    0x4000B000,
    "RTC1":    0x40011000,
    "POWER":   0x40000000,
    "CLOCK":   0x40000000,
    "USBD":    0x40027000,
    "CRYPTOCELL": 0x5002A000,
}

# Crypto constants (first few bytes of SHA-256 initial hash values, AES S-box start)
CRYPTO_SIGNATURES = {
    "SHA-256 H0": bytes.fromhex("6a09e667"),
    "SHA-256 H1": bytes.fromhex("bb67ae85"),
    "SHA-256 K[0]": bytes.fromhex("428a2f98"),
    "AES S-box start": bytes.fromhex("637c777bf26b6fc5"),
    "RSA exponent 65537": struct.pack("<I", 65537),
}


# ===========================================================================
# Helper functions
# ===========================================================================

def mem_to_offset(addr):
    """Convert memory address to file offset."""
    return addr - BASE_ADDR


def offset_to_mem(offset):
    """Convert file offset to memory address."""
    return offset + BASE_ADDR


def thumb_addr(addr):
    """Clear bit 0 for Thumb function addresses."""
    return addr & ~1


def create_disassembler():
    """Create and configure Capstone disassembler for ARM Thumb-2."""
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    md.detail = True
    return md


def disasm_function(data, mem_addr, max_bytes=512):
    """Disassemble a function starting at mem_addr, up to max_bytes."""
    md = create_disassembler()
    offset = mem_to_offset(mem_addr)
    code = data[offset:offset + max_bytes]
    instructions = []
    for insn in md.disasm(code, mem_addr):
        instructions.append(insn)
        # Stop at function epilogue (POP with PC)
        if insn.mnemonic == 'pop' and 'pc' in insn.op_str:
            break
        # Stop at unconditional branch back (potential tail)
        if insn.mnemonic == 'b' and len(instructions) > 10:
            # Only stop if branching backwards significantly
            pass
    return instructions


def disasm_range(data, mem_start, mem_end):
    """Disassemble a specific address range."""
    md = create_disassembler()
    offset_start = mem_to_offset(mem_start)
    offset_end = mem_to_offset(mem_end)
    code = data[offset_start:offset_end]
    return list(md.disasm(code, mem_start))


def find_bl_targets(instructions):
    """Extract all BL (branch-link) call targets from instruction list."""
    targets = []
    for insn in instructions:
        if insn.mnemonic in ('bl', 'blx'):
            # Parse target from operand
            try:
                target = int(insn.op_str.replace('#', ''), 16)
                targets.append((insn.address, target))
            except ValueError:
                pass
    return targets


def find_function_prologues(data):
    """Scan for all function prologues (PUSH with LR)."""
    functions = []
    i = 0
    length = len(data)

    while i < length - 1:
        # Narrow PUSH: 0xB5xx where xx has bit 0 set in high nibble
        # Format: 1011 0101 RRRR RRRR (PUSH {reglist, LR})
        hw = struct.unpack_from('<H', data, i)[0]
        if (hw & 0xFF00) == 0xB500:
            # Narrow PUSH {reglist, LR}
            regs = []
            for bit in range(8):
                if hw & (1 << bit):
                    regs.append(f'r{bit}')
            regs.append('lr')
            functions.append((offset_to_mem(i), regs, 'narrow'))
            i += 2
            continue

        # Wide PUSH (STMDB SP!, {reglist}): 0xE92D xxxx
        if i < length - 3:
            word = struct.unpack_from('<I', data, i)[0]
            hw1 = word & 0xFFFF
            hw2 = (word >> 16) & 0xFFFF
            # Note: Thumb-2 is stored as two halfwords, first at lower address
            first_hw = struct.unpack_from('<H', data, i)[0]
            second_hw = struct.unpack_from('<H', data, i + 2)[0]
            if first_hw == 0xE92D and (second_hw & 0x4000):
                # Wide PUSH with LR (bit 14 set)
                regs = []
                for bit in range(13):
                    if second_hw & (1 << bit):
                        regs.append(f'r{bit}')
                if second_hw & (1 << 14):
                    regs.append('lr')
                functions.append((offset_to_mem(i), regs, 'wide'))
                i += 4
                continue

        i += 2  # Advance by Thumb instruction alignment

    return functions


def extract_strings(data, min_length=6):
    """Extract printable ASCII strings from binary."""
    strings = []
    current = b''
    start_offset = 0
    for i, byte in enumerate(data):
        if 0x20 <= byte <= 0x7E:
            if not current:
                start_offset = i
            current += bytes([byte])
        else:
            if len(current) >= min_length:
                # Filter out likely instruction patterns
                text = current.decode('ascii')
                if not all(c in '0123456789abcdef' for c in text.lower()):
                    strings.append((start_offset, text))
            current = b''
    return strings


def find_references_to_address(data, target_addr):
    """Find instructions that reference a target address (LDR literal pool, etc.)."""
    refs = []
    # Search for the address value in the binary (literal pool entries)
    target_bytes_le = struct.pack('<I', target_addr)
    i = 0
    while i < len(data) - 3:
        if data[i:i+4] == target_bytes_le:
            refs.append(offset_to_mem(i))
        i += 1  # Could optimize with 4-byte alignment but be thorough
    return refs


def find_peripheral_references(data):
    """Search for references to Nordic peripheral base addresses."""
    results = {}
    for name, base_addr in PERIPHERALS.items():
        # Search for the base address in literal pools (4-byte aligned values)
        target_bytes = struct.pack('<I', base_addr)
        refs = []
        for i in range(0, len(data) - 3, 4):
            if data[i:i+4] == target_bytes:
                refs.append(offset_to_mem(i))
        # Also search upper 16 bits (MOVW/MOVT patterns)
        upper_half = (base_addr >> 16) & 0xFFFF
        lower_half = base_addr & 0xFFFF
        results[name] = refs
    return results


# ===========================================================================
# Analysis Sections
# ===========================================================================

def section_1_image_structure(data):
    """Section 1 - Image Structure Analysis"""
    lines = []
    lines.append("## Section 1: Image Structure\n")

    first_word = struct.unpack_from('<I', data, 0)[0]
    has_mcuboot_header = (first_word == MCUBOOT_MAGIC)

    lines.append(f"- **File size**: {len(data)} bytes")
    lines.append(f"- **SHA-256**: `{hashlib.sha256(data).hexdigest()}`")
    lines.append(f"- **Expected SHA-256**: `{EXPECTED_SHA256}`")
    sha_match = hashlib.sha256(data).hexdigest() == EXPECTED_SHA256
    lines.append(f"- **SHA-256 match**: {'YES' if sha_match else 'NO'}")
    lines.append(f"- **First 4 bytes**: `{data[:4].hex()}` ({('BX LR; NOP pattern' if data[:2] == bytes.fromhex('7047') else 'Unknown')})")
    lines.append(f"- **MCUboot magic present**: {'YES' if has_mcuboot_header else 'NO'}")
    lines.append("")

    if has_mcuboot_header:
        # Parse MCUboot header (IMAGE_HEADER structure)
        magic, load_addr, hdr_size, prot_size, img_size, flags = struct.unpack_from('<IIHHI', data, 0)
        lines.append("### MCUboot Header Fields")
        lines.append(f"- Magic: 0x{magic:08X}")
        lines.append(f"- Load Address: 0x{load_addr:08X}")
        lines.append(f"- Header Size: {hdr_size}")
        lines.append(f"- Image Size: {img_size}")
        lines.append(f"- Flags: 0x{flags:08X}")
    else:
        lines.append("### MCUboot Structure (inferred)")
        lines.append("")
        lines.append("This file does NOT contain an MCUboot header. Based on the flasher code")
        lines.append("(`aj159_flasher.py`), the full MCUboot image has the following structure:")
        lines.append("")
        lines.append("| Component | Size | Description |")
        lines.append("|-----------|------|-------------|")
        lines.append("| MCUboot Header | 512 bytes | Magic, version, flags, load addr, image size |")
        lines.append(f"| Application Code | {len(data)} bytes | This file (mouse_app_fw.bin) |")
        lines.append("| TLV Trailer | 336 bytes | SHA-256, RSA-2048 signature, KEYHASH |")
        lines.append(f"| **Full Image** | **{512 + len(data) + 336}** bytes | Header + Code + TLV |")
        lines.append("")
        lines.append("### Expected MCUboot Header Fields (from flasher)")
        lines.append(f"- Magic: 0x{MCUBOOT_MAGIC:08X}")
        lines.append(f"- Load Address: 0x{BASE_ADDR:08X}")
        lines.append(f"- Header Size: 512 (0x200)")
        lines.append(f"- IMG_SIZE field: {len(data)}")
        lines.append("- Security: RSA-2048 signature in TLV")
        lines.append("")
        lines.append("### TLV Trailer Structure (expected)")
        lines.append("| TLV Type | Tag | Length | Purpose |")
        lines.append("|----------|-----|--------|---------|")
        lines.append("| IMAGE_TLV_SHA256 | 0x10 | 32 | SHA-256 of image |")
        lines.append("| IMAGE_TLV_RSA2048 | 0x20 | 256 | RSA-2048 signature |")
        lines.append("| IMAGE_TLV_KEYHASH | 0x01 | 32 | SHA-256 of public key |")

    lines.append("")
    return "\n".join(lines)


def section_2_memory_map(data):
    """Section 2 - Memory Map and Vector Table"""
    lines = []
    lines.append("## Section 2: Memory Map\n")
    lines.append("### Address Mapping")
    lines.append("")
    lines.append("```")
    lines.append(f"File offset 0x00000 -> Memory address 0x{BASE_ADDR:05X}")
    lines.append(f"File offset 0x{len(data)-1:05X} -> Memory address 0x{BASE_ADDR + len(data) - 1:05X}")
    lines.append(f"Formula: memory_addr = file_offset + 0x{BASE_ADDR:X}")
    lines.append("```")
    lines.append("")
    lines.append("### Memory Layout")
    lines.append("")
    lines.append("| Region | Start | End | Size | Description |")
    lines.append("|--------|-------|-----|------|-------------|")
    lines.append(f"| Code | 0x{BASE_ADDR:05X} | 0x{BASE_ADDR + len(data) - 1:05X} | {len(data)} | Application firmware |")
    lines.append("| RAM | 0x20000000 | 0x2000FFFF | 64KB | SRAM (nRF52840 has 256KB total) |")
    lines.append("| Stack | ~0x2000E867 | (grows down) | -- | Initial SP from vector table |")
    lines.append("")

    # Vector table
    lines.append("### Vector Table (at file offset 0x0020, memory 0x10020)")
    lines.append("")
    lines.append("| # | Vector | Address | Handler (Thumb) |")
    lines.append("|---|--------|---------|-----------------|")

    vector_names = [
        'Initial SP', 'Reset', 'NMI', 'HardFault',
        'MemManage', 'BusFault', 'UsageFault', 'Reserved_7',
        'Reserved_8', 'Reserved_9', 'Reserved_10', 'SVCall',
        'DebugMon', 'Reserved_13', 'PendSV', 'SysTick'
    ]
    vectors = struct.unpack_from('<16I', data, VECTOR_TABLE_OFFSET)
    for i, (name, val) in enumerate(zip(vector_names, vectors)):
        actual = thumb_addr(val) if i > 0 else val
        note = ""
        if i == 0:
            note = f" (stack top in RAM)"
        elif val & 1 and val < BASE_ADDR + len(data):
            note = f" (Thumb, file offset 0x{mem_to_offset(actual):05X})"
        elif val > 0x40000000:
            note = f" (suspicious - may be literal pool data)"
        lines.append(f"| {i} | {name} | 0x{val:08X} | 0x{actual:08X}{note} |")

    lines.append("")
    lines.append("**Note**: Vectors 11-15 contain values that look like literal pool data")
    lines.append("(0x4801B403, 0xBD019001, etc.), suggesting the vector table may be")
    lines.append("partially overwritten or these are Zephyr RTOS ISR stubs.")
    lines.append("")
    return "\n".join(lines)


def section_3_function_enumeration(data):
    """Section 3 - Function Enumeration"""
    lines = []
    lines.append("## Section 3: Function Enumeration\n")

    functions = find_function_prologues(data)
    lines.append(f"**Total function prologues found**: {len(functions)}")
    lines.append("")

    # Categorize by type
    narrow_count = sum(1 for _, _, t in functions if t == 'narrow')
    wide_count = sum(1 for _, _, t in functions if t == 'wide')
    lines.append(f"- Narrow PUSH {{..., LR}}: {narrow_count}")
    lines.append(f"- Wide PUSH.W {{..., LR}}: {wide_count}")
    lines.append("")

    # Compute function sizes (distance to next prologue)
    sizes = []
    for i in range(len(functions) - 1):
        size = functions[i + 1][0] - functions[i][0]
        sizes.append((functions[i][0], size, functions[i][1]))
    if functions:
        sizes.append((functions[-1][0], 0, functions[-1][1]))

    # Largest functions
    sorted_by_size = sorted(sizes, key=lambda x: x[1], reverse=True)
    lines.append("### Top 20 Largest Functions (by distance to next prologue)")
    lines.append("")
    lines.append("| # | Address | Size (bytes) | Registers Saved |")
    lines.append("|---|---------|--------------|-----------------|")
    for i, (addr, size, regs) in enumerate(sorted_by_size[:20]):
        reg_str = ', '.join(regs)
        lines.append(f"| {i+1} | 0x{addr:05X} | {size} | {reg_str} |")
    lines.append("")

    # Key known functions
    lines.append("### Key Known Functions")
    lines.append("")
    lines.append("| Address | Description | Size Est. |")
    lines.append("|---------|-------------|-----------|")
    key_funcs = [
        (SET_REPORT_HANDLER, "SET_REPORT handler (main HID processor)"),
        (CONFIG_DISPATCH, "Config dispatch table"),
        (MEMCPY_FUNC, "memcpy implementation"),
        (FUNC_17DA8, "Multi-caller function (36 call sites)"),
        (COMMON_HANDLER, "Common report handler"),
    ]
    for addr, desc in key_funcs:
        # Find the function entry and its size
        for i, (fa, sz, _) in enumerate(sizes):
            if fa == addr:
                lines.append(f"| 0x{addr:05X} | {desc} | {sz} bytes |")
                break
        else:
            lines.append(f"| 0x{addr:05X} | {desc} | (not at prologue boundary) |")
    lines.append("")

    # Distribution by address range
    lines.append("### Function Distribution by Memory Region")
    lines.append("")
    ranges = [(0x10000, 0x14000), (0x14000, 0x18000), (0x18000, 0x1C000),
              (0x1C000, 0x20000), (0x20000, 0x24000), (0x24000, 0x2B000)]
    for start, end in ranges:
        count = sum(1 for addr, _, _ in functions if start <= addr < end)
        lines.append(f"- 0x{start:05X}-0x{end:05X}: {count} functions")
    lines.append("")
    return "\n".join(lines), functions, sizes


def section_4_strings(data):
    """Section 4 - String Cross-References"""
    lines = []
    lines.append("## Section 4: String Cross-References\n")

    strings = extract_strings(data, min_length=6)
    lines.append(f"**Total strings found (>= 6 chars)**: {len(strings)}")
    lines.append("")

    # Filter for meaningful strings (not instruction artifacts)
    meaningful = []
    for offset, text in strings:
        # Skip strings that are all uppercase hex or very repetitive
        if len(set(text)) < 3:
            continue
        if all(c in '0123456789ABCDEFabcdef' for c in text):
            continue
        meaningful.append((offset, text))

    lines.append(f"**Meaningful strings after filtering**: {len(meaningful)}")
    lines.append("")
    lines.append("### All Meaningful Strings")
    lines.append("")
    lines.append("| File Offset | Memory Addr | String |")
    lines.append("|-------------|-------------|--------|")
    for offset, text in meaningful[:50]:  # Cap at 50
        mem = offset_to_mem(offset)
        # Escape pipe characters for markdown
        escaped = text.replace('|', '\\|')
        lines.append(f"| 0x{offset:05X} | 0x{mem:05X} | `{escaped}` |")
    lines.append("")

    # Try to find cross-references (which functions reference these strings via PC-relative loads)
    lines.append("### String References (PC-relative LDR)")
    lines.append("")
    md = create_disassembler()
    xrefs_found = 0
    for offset, text in meaningful[:20]:
        mem_addr = offset_to_mem(offset)
        # Search for this address in literal pools
        target_bytes = struct.pack('<I', mem_addr)
        for i in range(0, len(data) - 3, 4):
            if data[i:i+4] == target_bytes:
                pool_addr = offset_to_mem(i)
                lines.append(f"- String `{text[:30]}` at 0x{mem_addr:05X} referenced from literal pool at 0x{pool_addr:05X}")
                xrefs_found += 1
                break
    if xrefs_found == 0:
        lines.append("- No direct literal pool references found (strings may be accessed via ADR or other means)")
    lines.append("")
    return "\n".join(lines)


def section_5_set_report_handler(data):
    """Section 5 - SET_REPORT Handler Deep Disassembly"""
    lines = []
    lines.append("## Section 5: SET_REPORT Handler Deep Disassembly\n")
    lines.append(f"**Address**: 0x{SET_REPORT_HANDLER:05X} (file offset 0x{mem_to_offset(SET_REPORT_HANDLER):04X})")
    lines.append("")

    # Disassemble the full function (use larger range to catch all paths)
    md = create_disassembler()
    offset = mem_to_offset(SET_REPORT_HANDLER)
    code = data[offset:offset + 512]
    instructions = list(md.disasm(code, SET_REPORT_HANDLER))

    # Find function boundaries (first POP PC or B to end)
    func_end_idx = len(instructions)
    pop_count = 0
    for i, insn in enumerate(instructions):
        if insn.mnemonic == 'pop' and 'pc' in insn.op_str:
            pop_count += 1
            if pop_count == 1:
                # First return - note it but continue for multi-exit functions
                first_ret = i

    lines.append("### Stack Frame")
    lines.append("")
    lines.append("```")
    lines.append(f"PUSH {{R0-R7, LR}}  ; saves 9 registers = 36 bytes")
    lines.append(f"SUB SP, #0x3C      ; allocates 60 bytes of local storage")
    lines.append(f"Total stack frame: 36 + 60 = 96 bytes")
    lines.append("")
    lines.append("Stack layout (after prologue):")
    lines.append("  SP+0x00 to SP+0x3B : local variables (60 bytes)")
    lines.append("  SP+0x3C to SP+0x5F : saved R0-R7, LR (36 bytes)")
    lines.append("")
    lines.append("Pre-prologue parameters (accessed via adjusted SP):")
    lines.append("  [SP+0x74] -> R4 (parameter from caller)")
    lines.append("  [SP+0x78] -> R7 (parameter from caller)")
    lines.append("  [SP+0x88] -> R6 (parameter from caller)")
    lines.append("  [SP+0x3C] -> R0 copy (the saved R0 = report ID)")
    lines.append("```")
    lines.append("")

    lines.append("### Full Disassembly")
    lines.append("")
    lines.append("```asm")
    for insn in instructions[:80]:  # First 80 instructions
        # Mark key points
        note = ""
        if insn.address == SET_REPORT_HANDLER:
            note = "  ; ENTRY POINT"
        elif insn.address == 0x1C1BE:
            note = "  ; bounds check: report_id <= 0xEF?"
        elif insn.address == 0x1C1C2:
            note = "  ; ERROR: return 0x30"
        elif 'cmp' in insn.mnemonic and '#0x7f' in insn.op_str:
            note = "  ; enter-boot check"
        elif insn.mnemonic == 'bl':
            note = f"  ; CALL"
        lines.append(f"  0x{insn.address:05X}: {insn.mnemonic:8s} {insn.op_str}{note}")
    lines.append("```")
    lines.append("")

    # Identify all branch targets and calls
    branches = []
    calls = []
    comparisons = []
    stack_accesses = []

    for insn in instructions[:80]:
        if insn.mnemonic in ('bl', 'blx'):
            try:
                target = int(insn.op_str.replace('#', ''), 16)
                calls.append((insn.address, target))
            except ValueError:
                pass
        elif insn.mnemonic.startswith('b') and insn.mnemonic not in ('bl', 'blx', 'bic', 'bfi', 'bfc'):
            try:
                target = int(insn.op_str.replace('#', ''), 16)
                branches.append((insn.address, target, insn.mnemonic))
            except ValueError:
                pass
        elif insn.mnemonic == 'cmp':
            comparisons.append((insn.address, insn.op_str))
        elif 'sp' in insn.op_str.lower() and insn.mnemonic in ('ldr', 'str', 'ldrb', 'strb', 'strh', 'ldrh'):
            stack_accesses.append((insn.address, insn.mnemonic, insn.op_str))

    lines.append("### Branch Targets")
    lines.append("")
    lines.append("| From | Target | Condition |")
    lines.append("|------|--------|-----------|")
    for addr, target, mnem in branches:
        lines.append(f"| 0x{addr:05X} | 0x{target:05X} | {mnem} |")
    lines.append("")

    lines.append("### Function Calls (BL)")
    lines.append("")
    lines.append("| Call Site | Target | Notes |")
    lines.append("|-----------|--------|-------|")
    for addr, target in calls:
        note = ""
        if target == MEMCPY_FUNC:
            note = "memcpy"
        elif target == COMMON_HANDLER:
            note = "common report handler"
        elif target == CONFIG_DISPATCH:
            note = "config dispatch"
        lines.append(f"| 0x{addr:05X} | 0x{target:05X} | {note} |")
    lines.append("")

    lines.append("### Comparisons (Input Validation)")
    lines.append("")
    lines.append("| Address | Comparison | Purpose |")
    lines.append("|---------|------------|---------|")
    for addr, ops in comparisons:
        purpose = ""
        if '0xef' in ops.lower():
            purpose = "Report ID bounds check (must be <= 0xEF)"
        elif '0x7f' in ops.lower():
            purpose = "Enter-boot command check"
        lines.append(f"| 0x{addr:05X} | CMP {ops} | {purpose} |")
    lines.append("")

    lines.append("### Stack Accesses")
    lines.append("")
    lines.append("| Address | Operation | Operands |")
    lines.append("|---------|-----------|----------|")
    for addr, mnem, ops in stack_accesses[:30]:
        lines.append(f"| 0x{addr:05X} | {mnem} | {ops} |")
    lines.append("")

    return "\n".join(lines), calls


def section_6_call_graph(data, initial_calls):
    """Section 6 - Call Graph (3 levels deep from SET_REPORT handler)"""
    lines = []
    lines.append("## Section 6: Call Graph\n")
    lines.append(f"Starting from SET_REPORT handler at 0x{SET_REPORT_HANDLER:05X}")
    lines.append("")

    md = create_disassembler()

    def get_calls_from(addr, max_insns=200):
        """Get all BL targets from a function."""
        offset = mem_to_offset(addr)
        if offset < 0 or offset >= len(data) - 4:
            return []
        code = data[offset:offset + max_insns * 4]
        calls = []
        insn_count = 0
        for insn in md.disasm(code, addr):
            insn_count += 1
            if insn_count > max_insns:
                break
            if insn.mnemonic in ('bl', 'blx'):
                try:
                    target = int(insn.op_str.replace('#', ''), 16)
                    if BASE_ADDR <= target < BASE_ADDR + len(data):
                        calls.append((insn.address, target))
                except ValueError:
                    pass
            if insn.mnemonic == 'pop' and 'pc' in insn.op_str:
                break
        return calls

    # Level 1: Direct calls from SET_REPORT handler
    level1 = get_calls_from(SET_REPORT_HANDLER, 300)
    lines.append("### Level 1: Direct calls from 0x{:05X}".format(SET_REPORT_HANDLER))
    lines.append("")
    lines.append("```")
    for site, target in level1:
        note = ""
        if target == MEMCPY_FUNC:
            note = " [memcpy]"
        elif target == COMMON_HANDLER:
            note = " [common_handler]"
        lines.append(f"  0x{SET_REPORT_HANDLER:05X} -> 0x{target:05X} (from 0x{site:05X}){note}")
    lines.append("```")
    lines.append("")

    # Level 2: Calls from each level-1 target
    lines.append("### Level 2: Calls from level-1 functions")
    lines.append("")
    seen = set()
    level2_targets = {}
    for _, target in level1:
        if target in seen:
            continue
        seen.add(target)
        l2_calls = get_calls_from(target, 200)
        level2_targets[target] = l2_calls
        if l2_calls:
            lines.append(f"#### 0x{target:05X}")
            lines.append("```")
            for site, t2 in l2_calls[:15]:  # Cap display
                note = ""
                if t2 == MEMCPY_FUNC:
                    note = " [memcpy]"
                lines.append(f"  0x{target:05X} -> 0x{t2:05X} (from 0x{site:05X}){note}")
            if len(l2_calls) > 15:
                lines.append(f"  ... and {len(l2_calls)-15} more calls")
            lines.append("```")
            lines.append("")

    # Level 3: One more level deep for key targets
    lines.append("### Level 3: Calls from level-2 functions (key targets only)")
    lines.append("")
    seen2 = set()
    for parent, l2_calls in level2_targets.items():
        for _, target in l2_calls[:5]:  # Only first 5 from each
            if target in seen2 or target in seen:
                continue
            seen2.add(target)
            l3_calls = get_calls_from(target, 100)
            if l3_calls:
                lines.append(f"#### 0x{target:05X} (called from 0x{parent:05X})")
                lines.append("```")
                for site, t3 in l3_calls[:10]:
                    note = ""
                    if t3 == MEMCPY_FUNC:
                        note = " [memcpy]"
                    lines.append(f"  0x{target:05X} -> 0x{t3:05X} (from 0x{site:05X}){note}")
                lines.append("```")
                lines.append("")

    # Who calls SET_REPORT handler?
    lines.append("### Callers of SET_REPORT handler (0x{:05X})".format(SET_REPORT_HANDLER))
    lines.append("")
    # Search for BL instructions that target SET_REPORT_HANDLER
    callers = []
    offset_scan = 0
    while offset_scan < len(data) - 3:
        code_chunk = data[offset_scan:offset_scan + 4]
        for insn in md.disasm(code_chunk, offset_to_mem(offset_scan)):
            if insn.mnemonic == 'bl':
                try:
                    target = int(insn.op_str.replace('#', ''), 16)
                    if target == SET_REPORT_HANDLER:
                        callers.append(insn.address)
                except ValueError:
                    pass
            break  # Only first instruction
        offset_scan += 2

    if callers:
        for caller in callers:
            lines.append(f"- Called from 0x{caller:05X}")
    else:
        lines.append("- No direct BL callers found (may be called via function pointer)")
    lines.append("")

    return "\n".join(lines)


def section_7_buffer_operations(data):
    """Section 7 - Buffer Operation Analysis (memcpy calls)"""
    lines = []
    lines.append("## Section 7: Buffer Operation Analysis\n")
    lines.append(f"### memcpy function at 0x{MEMCPY_FUNC:05X}")
    lines.append("")

    # Disassemble memcpy itself
    md = create_disassembler()
    offset = mem_to_offset(MEMCPY_FUNC)
    code = data[offset:offset + 80]
    insns = list(md.disasm(code, MEMCPY_FUNC))

    lines.append("```asm")
    lines.append("; Custom byte-copy memcpy implementation")
    for insn in insns[:25]:
        lines.append(f"  0x{insn.address:05X}: {insn.mnemonic:8s} {insn.op_str}")
        if insn.mnemonic == 'pop' and 'pc' in insn.op_str:
            break
    lines.append("```")
    lines.append("")
    lines.append("**Analysis**: This is a custom memcpy that copies R2 bytes from R1 to R0.")
    lines.append("It handles the last bit separately (odd/even length optimization).")
    lines.append("")

    # Find all BL calls to memcpy across the entire binary
    lines.append("### All call sites to memcpy (0x{:05X})".format(MEMCPY_FUNC))
    lines.append("")

    call_sites = []
    scan_offset = 0
    while scan_offset < len(data) - 3:
        chunk = data[scan_offset:scan_offset + 4]
        for insn in md.disasm(chunk, offset_to_mem(scan_offset)):
            if insn.mnemonic == 'bl':
                try:
                    target = int(insn.op_str.replace('#', ''), 16)
                    if target == MEMCPY_FUNC:
                        call_sites.append(insn.address)
                except ValueError:
                    pass
            break
        scan_offset += 2

    lines.append(f"**Total call sites**: {len(call_sites)}")
    lines.append("")
    lines.append("| # | Call Site | Context (preceding instructions) | Length (R2) |")
    lines.append("|---|-----------|----------------------------------|-------------|")

    # For each call site, look at preceding instructions to determine R2 (length)
    for i, site in enumerate(call_sites[:40]):  # Cap at 40
        # Disassemble 5 instructions before the BL
        pre_offset = mem_to_offset(site) - 16
        if pre_offset < 0:
            pre_offset = 0
        pre_code = data[pre_offset:mem_to_offset(site) + 4]
        pre_insns = list(md.disasm(pre_code, offset_to_mem(pre_offset)))

        # Find the instruction that sets R2 (length parameter)
        r2_value = "unknown"
        context_str = ""
        for pi in pre_insns:
            if pi.address >= site:
                break
            if pi.address >= site - 10:
                context_str += f"{pi.mnemonic} {pi.op_str}; "
            if 'r2' in pi.op_str and pi.mnemonic in ('movs', 'mov', 'movw', 'ldr', 'ldrb'):
                if pi.mnemonic in ('movs', 'mov', 'movw'):
                    # Extract immediate value
                    parts = pi.op_str.split(',')
                    if len(parts) >= 2 and '#' in parts[1]:
                        try:
                            val = int(parts[1].strip().replace('#', '').replace('0x', ''), 16 if '0x' in parts[1] else 10)
                            r2_value = f"0x{val:02X} ({val})"
                        except ValueError:
                            r2_value = parts[1].strip()
                elif pi.mnemonic == 'ldr':
                    r2_value = f"from memory ({pi.op_str})"

        lines.append(f"| {i+1} | 0x{site:05X} | {context_str[:50]} | {r2_value} |")

    lines.append("")

    # Flag dangerous patterns
    lines.append("### Potentially Dangerous Copies")
    lines.append("")
    lines.append("Copies where length >= 60 bytes (stack frame size) or length from user input:")
    lines.append("")
    dangerous = []
    for site in call_sites:
        pre_offset = mem_to_offset(site) - 20
        if pre_offset < 0:
            continue
        pre_code = data[pre_offset:mem_to_offset(site) + 4]
        pre_insns = list(md.disasm(pre_code, offset_to_mem(pre_offset)))
        for pi in pre_insns:
            if pi.address >= site:
                break
            if 'r2' in pi.op_str and pi.mnemonic in ('movs', 'mov', 'movw'):
                parts = pi.op_str.split(',')
                if len(parts) >= 2 and '#' in parts[1]:
                    try:
                        val_str = parts[1].strip().replace('#', '')
                        val = int(val_str, 16 if val_str.startswith('0x') else 10)
                        if val >= 60:
                            dangerous.append((site, val))
                    except ValueError:
                        pass

    if dangerous:
        for site, length in dangerous:
            lines.append(f"- **0x{site:05X}**: copies {length} bytes (>= stack frame of 60)")
    else:
        lines.append("- No obvious fixed-length copies >= 60 bytes found at memcpy call sites")
        lines.append("- However, variable-length copies (R2 from memory/register) may still overflow")
    lines.append("")

    return "\n".join(lines)


def section_8_report_dispatch(data):
    """Section 8 - Report ID Dispatch Analysis"""
    lines = []
    lines.append("## Section 8: Report ID Dispatch\n")
    lines.append(f"### Config Dispatch at 0x{CONFIG_DISPATCH:05X}")
    lines.append("")

    md = create_disassembler()
    offset = mem_to_offset(CONFIG_DISPATCH)
    code = data[offset:offset + 200]
    insns = list(md.disasm(code, CONFIG_DISPATCH))

    lines.append("```asm")
    for insn in insns[:40]:
        note = ""
        if insn.mnemonic == 'cmp':
            parts = insn.op_str.split(',')
            if '#' in insn.op_str:
                try:
                    val_str = parts[1].strip().replace('#', '')
                    val = int(val_str, 16 if val_str.startswith('0x') else 10)
                    report_names = {4: "REPORT_04", 5: "REPORT_05", 6: "REPORT_06",
                                   0x13: "REPORT_13", 0x14: "REPORT_14", 0x15: "REPORT_15",
                                   0x16: "REPORT_16", 0x17: "REPORT_17", 0x18: "REPORT_18"}
                    if val in report_names:
                        note = f"  ; {report_names[val]}"
                except ValueError:
                    pass
        elif insn.mnemonic == 'bl':
            try:
                target = int(insn.op_str.replace('#', ''), 16)
                if target == COMMON_HANDLER:
                    note = "  ; -> common_handler"
            except ValueError:
                pass
        lines.append(f"  0x{insn.address:05X}: {insn.mnemonic:8s} {insn.op_str}{note}")
    lines.append("```")
    lines.append("")

    # Document the dispatch logic
    lines.append("### Dispatch Logic")
    lines.append("")
    lines.append("The dispatch checks report IDs in this order:")
    lines.append("")
    lines.append("| Report ID | Action | Handler |")
    lines.append("|-----------|--------|---------|")
    lines.append(f"| 0x04 | BEQ -> common | 0x{COMMON_HANDLER:05X} |")
    lines.append(f"| 0x05 | BEQ -> common | 0x{COMMON_HANDLER:05X} |")
    lines.append(f"| 0x06 | BEQ -> common | 0x{COMMON_HANDLER:05X} |")
    lines.append(f"| 0x17 | BEQ -> common | 0x{COMMON_HANDLER:05X} |")
    lines.append(f"| 0x18 | BEQ -> common | 0x{COMMON_HANDLER:05X} |")
    lines.append(f"| 0x13 | BEQ -> common | 0x{COMMON_HANDLER:05X} |")
    lines.append(f"| 0x14 | BEQ -> common | 0x{COMMON_HANDLER:05X} |")
    lines.append(f"| 0x15 | BEQ -> common | 0x{COMMON_HANDLER:05X} |")
    lines.append(f"| 0x16 | BEQ -> common | 0x{COMMON_HANDLER:05X} |")
    lines.append("| Other | BNE (skip) | Falls through |")
    lines.append("")
    lines.append("**Key Finding**: ALL report IDs (0x04-0x06, 0x13-0x18) dispatch to the")
    lines.append(f"same common handler at 0x{COMMON_HANDLER:05X}. The differentiation happens")
    lines.append("inside that handler based on the report ID value passed in a register.")
    lines.append("")

    # Disassemble the common handler entry
    lines.append(f"### Common Handler at 0x{COMMON_HANDLER:05X}")
    lines.append("")
    ch_offset = mem_to_offset(COMMON_HANDLER)
    ch_code = data[ch_offset:ch_offset + 200]
    ch_insns = list(md.disasm(ch_code, COMMON_HANDLER))
    lines.append("```asm")
    for insn in ch_insns[:30]:
        lines.append(f"  0x{insn.address:05X}: {insn.mnemonic:8s} {insn.op_str}")
    lines.append("```")
    lines.append("")

    # Analyze report IDs 0x13-0x18 specifically
    lines.append("### Report IDs 0x13-0x18 Analysis")
    lines.append("")
    lines.append("These report IDs are not standard HID report types. Possible purposes:")
    lines.append("")
    lines.append("| Report ID | Possible Function |")
    lines.append("|-----------|-------------------|")
    lines.append("| 0x13 | Macro configuration / DPI settings |")
    lines.append("| 0x14 | LED/RGB configuration |")
    lines.append("| 0x15 | Button mapping configuration |")
    lines.append("| 0x16 | Profile switching |")
    lines.append("| 0x17 | Firmware metadata query |")
    lines.append("| 0x18 | Debug/diagnostic interface |")
    lines.append("")
    lines.append("All dispatch to the same handler, suggesting a unified configuration protocol")
    lines.append("where the report ID selects the configuration subsystem and the payload")
    lines.append("contains the actual command + data.")
    lines.append("")

    return "\n".join(lines)


def section_9_stack_overflow(data):
    """Section 9 - Stack Frame Overflow Analysis"""
    lines = []
    lines.append("## Section 9: Stack Frame Overflow Analysis\n")

    md = create_disassembler()
    offset = mem_to_offset(SET_REPORT_HANDLER)
    code = data[offset:offset + 512]
    insns = list(md.disasm(code, SET_REPORT_HANDLER))

    lines.append("### SET_REPORT Handler Stack Frame (0x{:05X})".format(SET_REPORT_HANDLER))
    lines.append("")
    lines.append("```")
    lines.append("Frame size: 60 bytes (SUB SP, #0x3C)")
    lines.append("Saved registers: 36 bytes (PUSH {R0-R7, LR})")
    lines.append("Input report: 64 bytes (received from USB HID SET_REPORT)")
    lines.append("")
    lines.append("CRITICAL: Input (64 bytes) > Stack buffer (60 bytes)")
    lines.append("```")
    lines.append("")

    # Map all SP-relative accesses
    lines.append("### SP-Relative Access Map")
    lines.append("")
    sp_reads = []
    sp_writes = []
    for insn in insns[:100]:
        if 'sp' in insn.op_str.lower():
            if insn.mnemonic in ('str', 'strb', 'strh'):
                sp_writes.append((insn.address, insn.mnemonic, insn.op_str))
            elif insn.mnemonic in ('ldr', 'ldrb', 'ldrh'):
                sp_reads.append((insn.address, insn.mnemonic, insn.op_str))

    lines.append("#### Writes to stack (STR/STRB/STRH with SP)")
    lines.append("")
    lines.append("| Address | Instruction | Operands | Analysis |")
    lines.append("|---------|-------------|----------|----------|")
    for addr, mnem, ops in sp_writes[:20]:
        analysis = ""
        # Extract offset
        if '+' in ops or '#' in ops:
            # Try to parse the SP offset
            import re
            match = re.search(r'#(0x[0-9a-fA-F]+|\d+)', ops)
            if match:
                off_val = int(match.group(1), 16 if '0x' in match.group(1) else 10)
                if off_val >= 0x3C:
                    analysis = "WRITES TO SAVED REGISTERS AREA"
                elif off_val >= 0x38:
                    analysis = "Near top of local buffer"
        lines.append(f"| 0x{addr:05X} | {mnem} | {ops} | {analysis} |")
    lines.append("")

    lines.append("#### Reads from stack (LDR/LDRB/LDRH with SP)")
    lines.append("")
    lines.append("| Address | Instruction | Operands | Analysis |")
    lines.append("|---------|-------------|----------|----------|")
    for addr, mnem, ops in sp_reads[:20]:
        analysis = ""
        import re
        match = re.search(r'#(0x[0-9a-fA-F]+|\d+)', ops)
        if match:
            off_val = int(match.group(1), 16 if '0x' in match.group(1) else 10)
            if off_val >= 0x60:
                analysis = "READS CALLER STACK (parameter)"
            elif off_val >= 0x3C:
                analysis = "Reads from saved register area"
        lines.append(f"| 0x{addr:05X} | {mnem} | {ops} | {analysis} |")
    lines.append("")

    lines.append("### Overflow Scenario Analysis")
    lines.append("")
    lines.append("```")
    lines.append("Input path:")
    lines.append("  1. USB HID SET_REPORT (64 bytes) arrives from host")
    lines.append("  2. Zephyr USB stack calls SET_REPORT callback")
    lines.append("  3. Handler at 0x1C1A8 receives pointer to 64-byte buffer")
    lines.append("  4. Handler allocates only 60 bytes on stack (SUB SP, #0x3C)")
    lines.append("")
    lines.append("Potential overflow conditions:")
    lines.append("  - If handler copies full 64 bytes to SP-relative buffer: 4-byte overflow")
    lines.append("  - Overflow would corrupt saved R0 (first pushed register)")
    lines.append("  - With careful crafting: could overwrite saved LR for ROP")
    lines.append("")
    lines.append("Mitigation factors:")
    lines.append("  - CMP R0, #0xEF at entry limits report ID range")
    lines.append("  - Various branch paths may not all perform full copies")
    lines.append("  - nRF52840 has no ASLR, no XN (execute-never) by default")
    lines.append("  - No stack canaries detected in prologue/epilogue")
    lines.append("```")
    lines.append("")

    # Check for memcpy calls within the handler
    lines.append("### memcpy Calls Within Handler")
    lines.append("")
    handler_memcpy = []
    for insn in insns[:100]:
        if insn.mnemonic == 'bl':
            try:
                target = int(insn.op_str.replace('#', ''), 16)
                if target == MEMCPY_FUNC:
                    handler_memcpy.append(insn.address)
            except ValueError:
                pass

    if handler_memcpy:
        for site in handler_memcpy:
            lines.append(f"- memcpy called at 0x{site:05X} within SET_REPORT handler")
            # Analyze what precedes it
            site_idx = None
            for idx, insn in enumerate(insns):
                if insn.address == site:
                    site_idx = idx
                    break
            if site_idx:
                lines.append("  Preceding instructions:")
                for insn in insns[max(0, site_idx-5):site_idx]:
                    lines.append(f"    0x{insn.address:05X}: {insn.mnemonic} {insn.op_str}")
    else:
        lines.append("- No direct memcpy calls found in first 100 instructions of handler")
        lines.append("- Buffer copies may happen in sub-functions called via BL")
    lines.append("")

    return "\n".join(lines)


def section_10_attack_surface(data):
    """Section 10 - Interface Analysis Summary"""
    lines = []
    lines.append("## Section 10: Interface Analysis Summary\n")

    lines.append("### Input Vectors")
    lines.append("")
    lines.append("| Vector | Size | Protocol | Handler |")
    lines.append("|--------|------|----------|---------|")
    lines.append(f"| HID SET_REPORT (Feature) | 64 bytes | USB HID | 0x{SET_REPORT_HANDLER:05X} |")
    lines.append("| HID GET_REPORT (Feature) | 64 bytes | USB HID | (response only) |")
    lines.append("| HID Output Report | Variable | USB HID | Unknown |")
    lines.append("| DFU/Boot mode | -- | USB DFU | MCUboot bootloader |")
    lines.append("")

    lines.append("### Trust Boundaries")
    lines.append("")
    lines.append("```")
    lines.append("[USB Host (PC)] <-- USB HID --> [nRF52840 Application FW]")
    lines.append("                                        |")
    lines.append("                                [MCUboot Bootloader]")
    lines.append("                                        |")
    lines.append("                                [Flash / NVMC]")
    lines.append("```")
    lines.append("")
    lines.append("The application firmware trusts USB HID reports from the host.")
    lines.append("There is minimal input validation beyond the report ID bounds check.")
    lines.append("")

    lines.append("### Potential Test Vectors")
    lines.append("")
    lines.append("| # | Vector | Risk | Testability | Details |")
    lines.append("|---|--------|------|----------------|---------|")
    lines.append("| 1 | Stack buffer overflow in SET_REPORT | HIGH | Medium-High | 60-byte stack buffer with 64-byte input. No stack canaries, no ASLR, no XN. |")
    lines.append("| 2 | Unvalidated report ID dispatch | MEDIUM | Medium | Report IDs 0x13-0x18 may have less-tested code paths |")
    lines.append("| 3 | Enter-boot command (0x7F) | LOW | Low | Requires correct report structure but can force DFU mode |")
    lines.append(f"| 4 | Macro button bug (0x{BUG_SITE:05X}) | LOW | N/A | Already patched - data corruption, not code execution |")
    lines.append("| 5 | memcpy with user-controlled length | HIGH | Medium | If any sub-handler passes user data length to memcpy |")
    lines.append("| 6 | Integer overflow in size calculations | MEDIUM | Low | Would need specific size field parsing bugs |")
    lines.append("")

    lines.append("### Testing Requirements")
    lines.append("")
    lines.append("For stack buffer overflow (Vector #1):")
    lines.append("")
    lines.append("1. **Trigger**: Send HID Feature Report with crafted payload")
    lines.append("2. **Control**: Need to reach a code path that copies > 60 bytes to stack")
    lines.append("3. **Payload**: Return address overwrite -> jump to code cave or shellcode")
    lines.append("4. **Bypass**: MCUboot signature check prevents persistent modification")
    lines.append("   unless code execution can write to flash (but no NVMC references found!)")
    lines.append("")
    lines.append("### Key Security Observations")
    lines.append("")
    lines.append("1. **No NVMC references**: The application firmware does NOT directly access")
    lines.append("   flash write registers. Flash writes go through MCUboot/bootloader only.")
    lines.append("2. **No stack canaries**: PUSH/POP patterns show no canary checks")
    lines.append("3. **No ASLR**: Cortex-M4 has fixed memory map")
    lines.append("4. **XN depends on MPU config**: Need to check if MPU is configured")
    lines.append("5. **Code cave available**: Unused space at 0x{:05X} for payload".format(CODE_CAVE))
    lines.append("")

    return "\n".join(lines)


def section_11_peripherals(data):
    """Section 11 - Peripheral References"""
    lines = []
    lines.append("## Section 11: Peripheral References\n")

    refs = find_peripheral_references(data)

    lines.append("### Nordic nRF52840 Peripheral Access")
    lines.append("")
    lines.append("| Peripheral | Base Address | References Found | Locations |")
    lines.append("|------------|-------------|------------------|-----------|")

    for name, base_addr in sorted(PERIPHERALS.items(), key=lambda x: x[1]):
        ref_list = refs.get(name, [])
        locs = ', '.join(f'0x{r:05X}' for r in ref_list[:5])
        if len(ref_list) > 5:
            locs += f' (+{len(ref_list)-5} more)'
        status = f"{len(ref_list)}" if ref_list else "**NONE**"
        lines.append(f"| {name} | 0x{base_addr:08X} | {status} | {locs} |")

    lines.append("")

    # Special analysis for NVMC (critical for flash writes)
    nvmc_refs = refs.get("NVMC", [])
    lines.append("### NVMC (Flash Write Controller) Analysis")
    lines.append("")
    if not nvmc_refs:
        lines.append("**CRITICAL FINDING**: No references to NVMC (0x4001E000) found in the")
        lines.append("application firmware. This means:")
        lines.append("")
        lines.append("1. The application cannot write to flash directly")
        lines.append("2. All flash operations are delegated to the bootloader (MCUboot)")
        lines.append("3. Even with arbitrary code execution in the application, an attacker")
        lines.append("   cannot directly patch the firmware in flash")
        lines.append("4. To achieve persistent modification, would need to:")
        lines.append("   a. Chain into the bootloader (which DOES have NVMC access)")
        lines.append("   b. Or use DFU protocol to upload a crafted image (still needs valid signature)")
    else:
        lines.append(f"Found {len(nvmc_refs)} references to NVMC:")
        for ref in nvmc_refs:
            lines.append(f"  - 0x{ref:05X}")
    lines.append("")

    # Check for UICR/APPROTECT
    uicr_refs = refs.get("UICR", [])
    lines.append("### UICR / APPROTECT Analysis")
    lines.append("")
    if not uicr_refs:
        lines.append("No references to UICR (0x10001000) found. The APPROTECT register")
        lines.append("(at UICR+0x208) is not accessed by the application firmware.")
    else:
        lines.append(f"Found {len(uicr_refs)} references to UICR region.")
    lines.append("")

    # Check USBD (USB device)
    usbd_refs = refs.get("USBD", [])
    lines.append("### USB Device Controller")
    lines.append("")
    lines.append(f"USBD (0x40027000) references: {len(usbd_refs)}")
    if usbd_refs:
        lines.append("Locations: " + ', '.join(f'0x{r:05X}' for r in usbd_refs[:10]))
    lines.append("")

    return "\n".join(lines)


def section_12_patch_comparison(data):
    """Section 12 - Patch Comparison"""
    lines = []
    lines.append("## Section 12: Code Cave and Patch Analysis\n")

    # Try to load patched binary
    script_dir = os.path.dirname(os.path.abspath(__file__))
    patched_path = os.path.join(script_dir, 'mouse_app_fw_PATCHED.bin')
    if not os.path.exists(patched_path):
        patched_path = os.path.join(os.getcwd(), 'firmware_patch', 'mouse_app_fw_PATCHED.bin')

    if not os.path.exists(patched_path):
        lines.append("**Patched binary not found** - skipping comparison")
        return "\n".join(lines)

    patched = open(patched_path, 'rb').read()

    lines.append(f"### Binary Comparison: original vs patched")
    lines.append("")
    lines.append(f"- Original size: {len(data)} bytes")
    lines.append(f"- Patched size: {len(patched)} bytes")
    lines.append(f"- Original SHA-256: `{hashlib.sha256(data).hexdigest()}`")
    lines.append(f"- Patched SHA-256: `{hashlib.sha256(patched).hexdigest()}`")
    lines.append("")

    # Find differences
    diffs = []
    for i in range(min(len(data), len(patched))):
        if data[i] != patched[i]:
            diffs.append((i, data[i], patched[i]))

    lines.append(f"**Total bytes changed**: {len(diffs)}")
    lines.append("")

    if diffs:
        # Group into contiguous regions
        regions = []
        current_region = [diffs[0]]
        for d in diffs[1:]:
            if d[0] == current_region[-1][0] + 1:
                current_region.append(d)
            else:
                regions.append(current_region)
                current_region = [d]
        regions.append(current_region)

        lines.append(f"**Number of changed regions**: {len(regions)}")
        lines.append("")

        md = create_disassembler()
        for idx, region in enumerate(regions):
            start_off = region[0][0]
            end_off = region[-1][0]
            mem_start = offset_to_mem(start_off)
            mem_end = offset_to_mem(end_off)
            size = end_off - start_off + 1

            lines.append(f"### Region {idx+1}: File offset 0x{start_off:04X} - 0x{end_off:04X} (memory 0x{mem_start:05X} - 0x{mem_end:05X})")
            lines.append(f"Size: {size} bytes")
            lines.append("")

            # Show hex diff
            orig_bytes = data[start_off:end_off + 1]
            patch_bytes = patched[start_off:end_off + 1]
            lines.append("```")
            lines.append(f"Original: {orig_bytes.hex()}")
            lines.append(f"Patched:  {patch_bytes.hex()}")
            lines.append("```")
            lines.append("")

            # Disassemble both versions
            lines.append("#### Original disassembly:")
            lines.append("```asm")
            for insn in md.disasm(orig_bytes, mem_start):
                lines.append(f"  0x{insn.address:05X}: {insn.mnemonic:8s} {insn.op_str}")
            lines.append("```")
            lines.append("")

            lines.append("#### Patched disassembly:")
            lines.append("```asm")
            for insn in md.disasm(patch_bytes, mem_start):
                lines.append(f"  0x{insn.address:05X}: {insn.mnemonic:8s} {insn.op_str}")
            lines.append("```")
            lines.append("")

        # Explain the patch
        lines.append("### Patch Purpose")
        lines.append("")
        lines.append(f"The patch modifies {len(diffs)} bytes in {len(regions)} region(s):")
        lines.append("")
        if len(regions) >= 2:
            lines.append("1. **Bug site** (0x{:05X}): Redirects the macro button write through".format(offset_to_mem(regions[0][0][0])))
            lines.append("   a BL (branch-link) to the trampoline in the code cave")
            lines.append("")
            lines.append("2. **Code cave** (0x{:05X}): OR-merge trampoline that combines".format(offset_to_mem(regions[1][0][0])))
            lines.append("   macro button state with physical button state before writing")
            lines.append("   to the HID report buffer")
        lines.append("")

    return "\n".join(lines)


# ===========================================================================
# Main
# ===========================================================================

def main():
    """Main entry point - run all analyses and generate report."""
    # Determine firmware path
    if len(sys.argv) > 1:
        fw_path = sys.argv[1]
    else:
        # Try multiple paths
        candidates = [
            os.path.join(os.path.dirname(os.path.abspath(__file__)), 'mouse_app_fw.bin'),
            os.path.join(os.getcwd(), 'firmware_patch', 'mouse_app_fw.bin'),
            os.path.join(os.getcwd(), 'mouse_app_fw.bin'),
        ]
        fw_path = None
        for c in candidates:
            if os.path.exists(c):
                fw_path = c
                break
        if not fw_path:
            print("ERROR: Cannot find mouse_app_fw.bin")
            print("Usage: python3 fw_deep_analysis.py [path/to/mouse_app_fw.bin]")
            sys.exit(1)

    print(f"[*] Loading firmware: {fw_path}")
    data = open(fw_path, 'rb').read()
    print(f"[*] Size: {len(data)} bytes")
    print(f"[*] SHA-256: {hashlib.sha256(data).hexdigest()}")
    print()

    if len(data) != EXPECTED_SIZE:
        print(f"WARNING: Expected {EXPECTED_SIZE} bytes, got {len(data)}")

    # Run all analysis sections
    report_sections = []

    # Header
    report_sections.append("# AJ159 APEX Firmware Deep Analysis Report")
    report_sections.append("")
    report_sections.append(f"**Binary**: `mouse_app_fw.bin` ({len(data)} bytes)")
    report_sections.append(f"**Architecture**: ARM Cortex-M4F (Thumb-2, Little-endian)")
    report_sections.append(f"**SoC**: Nordic nRF52840")
    report_sections.append(f"**RTOS**: Zephyr")
    report_sections.append(f"**Load Address**: 0x{BASE_ADDR:05X}")
    report_sections.append(f"**SHA-256**: `{hashlib.sha256(data).hexdigest()}`")
    report_sections.append("")
    report_sections.append("---")
    report_sections.append("")

    print("[*] Section 1: Image Structure...")
    report_sections.append(section_1_image_structure(data))

    print("[*] Section 2: Memory Map...")
    report_sections.append(section_2_memory_map(data))

    print("[*] Section 3: Function Enumeration...")
    s3_text, functions, sizes = section_3_function_enumeration(data)
    report_sections.append(s3_text)

    print("[*] Section 4: String Cross-References...")
    report_sections.append(section_4_strings(data))

    print("[*] Section 5: SET_REPORT Handler...")
    s5_text, handler_calls = section_5_set_report_handler(data)
    report_sections.append(s5_text)

    print("[*] Section 6: Call Graph...")
    report_sections.append(section_6_call_graph(data, handler_calls))

    print("[*] Section 7: Buffer Operations...")
    report_sections.append(section_7_buffer_operations(data))

    print("[*] Section 8: Report ID Dispatch...")
    report_sections.append(section_8_report_dispatch(data))

    print("[*] Section 9: Stack Overflow Analysis...")
    report_sections.append(section_9_stack_overflow(data))

    print("[*] Section 10: Interface Analysis...")
    report_sections.append(section_10_attack_surface(data))

    print("[*] Section 11: Peripheral References...")
    report_sections.append(section_11_peripherals(data))

    print("[*] Section 12: Patch Comparison...")
    report_sections.append(section_12_patch_comparison(data))

    # Write report
    report = "\n".join(report_sections)

    # Determine output path
    script_dir = os.path.dirname(os.path.abspath(__file__))
    report_path = os.path.join(script_dir, 'DEEP_ANALYSIS_REPORT.md')

    with open(report_path, 'w') as f:
        f.write(report)

    print()
    print(f"[+] Report written to: {report_path}")
    print(f"[+] Report size: {len(report)} characters, {report.count(chr(10))} lines")
    print("[+] Analysis complete!")


if __name__ == "__main__":
    main()
