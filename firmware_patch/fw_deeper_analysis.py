#!/usr/bin/env python3
"""
AJ159 APEX Firmware DEEPER Analysis Tool
==========================================
Goes beyond the initial analysis to find unexplored paths for firmware flashing.

Focuses on:
  - Full SET_REPORT handler disassembly (all 336 bytes)
  - Post-validation path tracing (0x1C246 onwards)
  - Caller context analysis (0x19AB4)
  - Largest function analysis (flash write ops?)
  - MOVW/MOVT peripheral address construction
  - Indirect call mapping (bypasses static analysis)
  - Zephyr flash driver API patterns
  - SPI flash access patterns (MCUboot secondary slot)
  - Patch-target address range references

USAGE:
  python3 fw_deeper_analysis.py [path/to/mouse_app_fw.bin]

OUTPUT:
  firmware_patch/FW_DEEPER_ANALYSIS_REPORT.md
"""
import sys
import os
import struct
from collections import defaultdict
from pathlib import Path

from capstone import *
from capstone.arm import *

# ===========================================================================
# Configuration
# ===========================================================================

BASE_ADDR = 0x10000          # Load address in memory
EXPECTED_SIZE = 108608

# Key addresses (memory addresses)
SET_REPORT_HANDLER = 0x1C1A8   # Full handler (336 bytes)
SET_REPORT_CALLER = 0x19AB4    # Only caller of SET_REPORT handler
VALIDATED_PATH = 0x1C246       # Where validated path continues (ADD R1, SP, #4)
CONFIG_DISPATCH = 0x17DDC
MEMCPY_FUNC = 0x14D58
INDIRECT_CALL = 0x17E2C       # Indirect call for report IDs 0x13 and 0x17
LARGEST_FUNC = 0x262D0        # 6480 bytes - may contain flash operations
MAIN_LOOP = 0x192C0           # 3208 bytes - main processing loop
COMMON_HANDLER = 0x21D44
FUNC_17DA8 = 0x17DA8          # Called from 36 locations

# Sizes for key functions
LARGEST_FUNC_SIZE = 6480
MAIN_LOOP_SIZE = 3208
SET_REPORT_SIZE = 336

# nRF52840 peripheral addresses for MOVW/MOVT detection
PERIPHERAL_ADDRS = {
    0x4001E000: "NVMC_BASE",
    0x4001E504: "NVMC_CONFIG",
    0x4001E508: "NVMC_ERASEPAGE",
    0x4001E50C: "NVMC_ERASEALL",
    0x4001E514: "NVMC_ERASEUICR",
    0x10001000: "UICR_BASE",
    0x10000000: "FICR_BASE",
    0x50000000: "GPIO_P0",
    0x50000300: "GPIO_P1",
    0x40001000: "RADIO",
    0x40027000: "USBD",
    0x40003000: "SPI0/TWI0",
    0x40004000: "SPI1/TWI1",
    0x40023000: "SPI2",
    0x4002F000: "QSPI",
    0x40000000: "POWER/CLOCK",
}

# Address ranges of interest (our patch targets)
PATCH_RANGE_START = 0x24000
PATCH_RANGE_END = 0x25FFF

# SPI flash-related constants
SPI_COMMANDS = {
    0x9F: "JEDEC_ID",
    0x06: "WRITE_ENABLE",
    0x04: "WRITE_DISABLE",
    0x02: "PAGE_PROGRAM",
    0x03: "READ_DATA",
    0x0B: "FAST_READ",
    0x20: "SECTOR_ERASE_4K",
    0xD8: "BLOCK_ERASE_64K",
    0xC7: "CHIP_ERASE",
    0x05: "READ_STATUS_REG1",
    0x35: "READ_STATUS_REG2",
    0x01: "WRITE_STATUS_REG",
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


def create_disassembler(skipdata=False):
    """Create and configure Capstone disassembler for ARM Thumb-2."""
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    md.detail = True
    if skipdata:
        md.skipdata = True
    return md


def disasm_range(data, mem_start, size):
    """Disassemble a specific address range given start and size.
    Uses skipdata to handle embedded data/literal pools."""
    md = create_disassembler(skipdata=True)
    offset = mem_to_offset(mem_start)
    code = data[offset:offset + size]
    return list(md.disasm(code, mem_start))


def disasm_range_code_only(data, mem_start, size):
    """Disassemble a range, returning only real instructions (no .byte data)."""
    insns = disasm_range(data, mem_start, size)
    return [i for i in insns if not i.mnemonic.startswith('.')]


def disasm_at(data, mem_addr, max_bytes=256):
    """Disassemble starting at address, up to max_bytes."""
    md = create_disassembler(skipdata=True)
    offset = mem_to_offset(mem_addr)
    if offset < 0 or offset >= len(data):
        return []
    code = data[offset:offset + max_bytes]
    return [i for i in md.disasm(code, mem_addr) if not i.mnemonic.startswith('.')]


def find_bl_targets(instructions):
    """Extract all BL/BLX call targets from instruction list."""
    targets = []
    for insn in instructions:
        if insn.mnemonic in ('bl', 'blx'):
            try:
                target = int(insn.op_str.replace('#', ''), 16)
                targets.append((insn.address, target))
            except ValueError:
                # Register-based BLX
                targets.append((insn.address, insn.op_str))
    return targets


def find_indirect_calls(instructions):
    """Find all indirect calls (BLX Rn, BX Rn where Rn != LR)."""
    indirect = []
    for insn in instructions:
        if insn.mnemonic == 'blx' and not insn.op_str.startswith('#'):
            indirect.append((insn.address, 'blx', insn.op_str))
        elif insn.mnemonic == 'bx' and insn.op_str != 'lr':
            indirect.append((insn.address, 'bx', insn.op_str))
    return indirect


def decode_movw_movt_pairs(instructions):
    """Find MOVW/MOVT pairs that construct 32-bit constants."""
    pairs = {}  # reg -> (movw_addr, movw_val, movt_addr, movt_val, full_val)
    pending_movw = {}  # reg -> (addr, val)
    
    for insn in instructions:
        if insn.mnemonic == 'movw':
            parts = insn.op_str.split(',')
            if len(parts) == 2:
                reg = parts[0].strip()
                try:
                    val = int(parts[1].strip().replace('#', ''), 0)
                    pending_movw[reg] = (insn.address, val)
                except ValueError:
                    pass
        elif insn.mnemonic == 'movt':
            parts = insn.op_str.split(',')
            if len(parts) == 2:
                reg = parts[0].strip()
                try:
                    val = int(parts[1].strip().replace('#', ''), 0)
                    if reg in pending_movw:
                        movw_addr, movw_val = pending_movw[reg]
                        full_val = (val << 16) | movw_val
                        key = f"{reg}_{insn.address:#x}"
                        pairs[key] = (movw_addr, movw_val, insn.address, val, full_val)
                except ValueError:
                    pass
    return pairs


def find_function_prologues(data):
    """Scan for all function prologues (PUSH with LR)."""
    functions = []
    i = 0
    length = len(data)
    
    while i < length - 1:
        hw = struct.unpack_from('<H', data, i)[0]
        # Narrow PUSH {reglist, LR}: 1011 0101 RRRR RRRR
        if (hw & 0xFF00) == 0xB500:
            regs = []
            for bit in range(8):
                if hw & (1 << bit):
                    regs.append(f'r{bit}')
            regs.append('lr')
            functions.append((offset_to_mem(i), regs))
            i += 2
            continue
        
        # Wide PUSH (STMDB SP!, {reglist}): E92D xxxx
        if i < length - 3:
            first_hw = struct.unpack_from('<H', data, i)[0]
            second_hw = struct.unpack_from('<H', data, i + 2)[0]
            if first_hw == 0xE92D and (second_hw & 0x4000):  # bit 14 = LR
                regs = []
                for bit in range(13):
                    if second_hw & (1 << bit):
                        regs.append(f'r{bit}')
                regs.append('lr')
                functions.append((offset_to_mem(i), regs))
                i += 4
                continue
        
        i += 2
    
    return functions


def scan_for_literal_pool_refs(data, target_addr, search_range=None):
    """Find LDR Rn, [PC, #offset] that loads a value matching target_addr."""
    results = []
    if search_range:
        start_off, end_off = search_range
    else:
        start_off, end_off = 0, len(data)
    
    # Search for the target value in the binary (literal pool entries)
    target_bytes_le = struct.pack('<I', target_addr)
    pos = start_off
    while pos < end_off - 3:
        idx = data.find(target_bytes_le, pos, end_off)
        if idx == -1:
            break
        # Check if this is word-aligned (literal pools are usually aligned)
        if idx % 4 == 0:
            results.append(offset_to_mem(idx))
        pos = idx + 1
    
    return results


# ===========================================================================
# Analysis Sections
# ===========================================================================

def analyze_set_report_full(data, report):
    """Section 1: Full SET_REPORT handler disassembly (all 336 bytes)."""
    report.append("## Section 1: Full SET_REPORT Handler (0x1C1A8, 336 bytes)")
    report.append("")
    report.append("Complete disassembly of the HID SET_REPORT handler including all branch paths.")
    report.append("")
    
    insns = disasm_range(data, SET_REPORT_HANDLER, SET_REPORT_SIZE)
    
    report.append("```asm")
    branches = []
    calls = []
    for insn in insns:
        line = f"  {insn.address:#010x}: {insn.mnemonic:8s} {insn.op_str}"
        report.append(line)
        
        if insn.mnemonic.startswith('b') and insn.mnemonic not in ('bx', 'blx', 'bl', 'bic', 'bfc', 'bfi'):
            try:
                target = int(insn.op_str.replace('#', ''), 16)
                branches.append((insn.address, insn.mnemonic, target))
            except ValueError:
                pass
        if insn.mnemonic in ('bl', 'blx'):
            try:
                target = int(insn.op_str.replace('#', ''), 16)
                calls.append((insn.address, target))
            except ValueError:
                calls.append((insn.address, insn.op_str))
    report.append("```")
    report.append("")
    
    # Summarize branches
    report.append("### Branch Targets within Handler")
    report.append("")
    report.append("| From | Condition | Target | Direction |")
    report.append("|------|-----------|--------|-----------|")
    for addr, cond, target in branches:
        direction = "forward" if target > addr else "backward"
        in_handler = "IN-HANDLER" if SET_REPORT_HANDLER <= target < SET_REPORT_HANDLER + SET_REPORT_SIZE else "OUT"
        report.append(f"| {addr:#x} | {cond} | {target:#x} | {direction} ({in_handler}) |")
    report.append("")
    
    # Summarize calls
    report.append("### Function Calls from Handler")
    report.append("")
    report.append("| Call Site | Target | Notes |")
    report.append("|----------|--------|-------|")
    for addr, target in calls:
        if isinstance(target, int):
            notes = ""
            if target == MEMCPY_FUNC:
                notes = "memcpy"
            elif target == CONFIG_DISPATCH:
                notes = "config_dispatch"
            elif target == COMMON_HANDLER:
                notes = "common_handler"
            report.append(f"| {addr:#x} | {target:#x} | {notes} |")
        else:
            report.append(f"| {addr:#x} | {target} | indirect call |")
    report.append("")
    
    return insns


def analyze_validated_path(data, report):
    """Section 2: Post-validation path (0x1C246 onwards)."""
    report.append("## Section 2: Post-Validation Path (0x1C246 onwards)")
    report.append("")
    report.append("After the validation gate passes, execution continues here.")
    report.append("This is where validated HID data gets processed.")
    report.append("")
    
    # Disassemble 256 bytes from the validated path
    insns = disasm_at(data, VALIDATED_PATH, max_bytes=256)
    
    report.append("```asm")
    for insn in insns:
        line = f"  {insn.address:#010x}: {insn.mnemonic:8s} {insn.op_str}"
        report.append(line)
    report.append("```")
    report.append("")
    
    # Look for what functions are called from this path
    bl_targets = find_bl_targets(insns)
    if bl_targets:
        report.append("### Functions called from validated path:")
        report.append("")
        for addr, target in bl_targets:
            if isinstance(target, int):
                report.append(f"- {addr:#x} calls {target:#x}")
            else:
                report.append(f"- {addr:#x} calls {target} (indirect)")
        report.append("")
    
    # Check for indirect calls
    indirect = find_indirect_calls(insns)
    if indirect:
        report.append("### INDIRECT calls from validated path (bypass static analysis):")
        report.append("")
        for addr, mnem, reg in indirect:
            report.append(f"- {addr:#x}: {mnem} {reg}")
        report.append("")
    
    return insns


def analyze_caller_context(data, report):
    """Section 3: Caller at 0x19AB4 - understand parameter passing."""
    report.append("## Section 3: Caller Context (0x19AB4)")
    report.append("")
    report.append("The SET_REPORT handler at 0x1C1A8 has only ONE caller: 0x19AB4.")
    report.append("Understanding how parameters are passed reveals what data reaches the handler.")
    report.append("")
    
    # Disassemble a generous range around the call site
    # Start 128 bytes before to see setup, 128 bytes after
    start_addr = SET_REPORT_CALLER - 128
    insns = disasm_at(data, start_addr, max_bytes=384)
    
    # Find the BL to SET_REPORT_HANDLER
    call_idx = None
    for i, insn in enumerate(insns):
        if insn.mnemonic == 'bl':
            try:
                target = int(insn.op_str.replace('#', ''), 16)
                if target == SET_REPORT_HANDLER:
                    call_idx = i
                    break
            except ValueError:
                pass
    
    report.append("### Disassembly around the call site:")
    report.append("")
    report.append("```asm")
    # Show 30 instructions before and 10 after the call
    if call_idx is not None:
        start_show = max(0, call_idx - 30)
        end_show = min(len(insns), call_idx + 10)
        for i in range(start_show, end_show):
            insn = insns[i]
            marker = " <<< CALL TO SET_REPORT" if i == call_idx else ""
            line = f"  {insn.address:#010x}: {insn.mnemonic:8s} {insn.op_str}{marker}"
            report.append(line)
    else:
        # Just show everything
        for insn in insns[:60]:
            line = f"  {insn.address:#010x}: {insn.mnemonic:8s} {insn.op_str}"
            report.append(line)
    report.append("```")
    report.append("")
    
    # Analyze parameter registers
    report.append("### Parameter Analysis")
    report.append("")
    report.append("ARM calling convention: R0-R3 are arguments, R0 is return value.")
    report.append("Look for MOV/LDR to R0-R3 immediately before the BL.")
    report.append("")
    
    if call_idx is not None:
        # Look at instructions before the call for R0-R3 setup
        for i in range(max(0, call_idx - 10), call_idx):
            insn = insns[i]
            for reg in ['r0', 'r1', 'r2', 'r3']:
                if reg in insn.op_str.split(',')[0].strip().lower():
                    report.append(f"- {insn.address:#x}: {insn.mnemonic} {insn.op_str} (sets {reg})")
    report.append("")


def analyze_largest_function(data, report):
    """Section 4: Largest function at 0x262D0 (6480 bytes) - look for flash ops."""
    report.append("## Section 4: Largest Function Analysis (0x262D0, 6480 bytes)")
    report.append("")
    report.append("This is the largest function in the binary. Analyzing for:")
    report.append("- Flash write operations (NVMC access)")
    report.append("- MOVW/MOVT pairs constructing peripheral addresses")
    report.append("- Indirect calls that could reach flash drivers")
    report.append("")
    
    insns = disasm_range_code_only(data, LARGEST_FUNC, LARGEST_FUNC_SIZE)
    
    # Find MOVW/MOVT pairs
    pairs = decode_movw_movt_pairs(insns)
    
    peripheral_refs = []
    other_interesting = []
    
    for key, (movw_addr, movw_val, movt_addr, movt_val, full_val) in pairs.items():
        # Check if it matches a known peripheral
        matched = False
        for paddr, pname in PERIPHERAL_ADDRS.items():
            if full_val == paddr or (full_val & 0xFFFFF000) == (paddr & 0xFFFFF000):
                peripheral_refs.append((movw_addr, full_val, pname))
                matched = True
                break
        if not matched and full_val >= 0x40000000:
            other_interesting.append((movw_addr, full_val))
    
    if peripheral_refs:
        report.append("### PERIPHERAL REFERENCES FOUND via MOVW/MOVT:")
        report.append("")
        report.append("| Address | Value | Peripheral |")
        report.append("|---------|-------|-----------|")
        for addr, val, name in peripheral_refs:
            report.append(f"| {addr:#x} | {val:#010x} | {name} |")
        report.append("")
    else:
        report.append("### No peripheral references via MOVW/MOVT in this function.")
        report.append("")
    
    if other_interesting:
        report.append("### Other high-address constants constructed:")
        report.append("")
        for addr, val in other_interesting[:20]:
            report.append(f"- {addr:#x}: constructs {val:#010x}")
        report.append("")
    
    # Find indirect calls
    indirect = find_indirect_calls(insns)
    if indirect:
        report.append("### Indirect Calls in Largest Function:")
        report.append("")
        for addr, mnem, reg in indirect:
            report.append(f"- {addr:#x}: {mnem} {reg}")
        report.append("")
    
    # Find all BL targets
    bl_targets = find_bl_targets(insns)
    report.append(f"### Direct Calls (BL): {len(bl_targets)} total")
    report.append("")
    
    # Group by target
    target_counts = defaultdict(list)
    for addr, target in bl_targets:
        if isinstance(target, int):
            target_counts[target].append(addr)
    
    report.append("| Target | Call Count | Notes |")
    report.append("|--------|-----------|-------|")
    for target, callers in sorted(target_counts.items(), key=lambda x: -len(x[1]))[:15]:
        notes = ""
        if target == MEMCPY_FUNC:
            notes = "memcpy"
        report.append(f"| {target:#x} | {len(callers)} | {notes} |")
    report.append("")
    
    # Show first and last 20 instructions for context
    report.append("### First 30 instructions (function prologue and setup):")
    report.append("")
    report.append("```asm")
    for insn in insns[:30]:
        report.append(f"  {insn.address:#010x}: {insn.mnemonic:8s} {insn.op_str}")
    report.append("```")
    report.append("")


def analyze_main_loop(data, report):
    """Section 5: Main processing loop at 0x192C0 (3208 bytes)."""
    report.append("## Section 5: Main Processing Loop (0x192C0, 3208 bytes)")
    report.append("")
    report.append("Likely the main event processor. Saves ALL registers.")
    report.append("")
    
    insns = disasm_range_code_only(data, MAIN_LOOP, MAIN_LOOP_SIZE)
    
    # Find MOVW/MOVT pairs
    pairs = decode_movw_movt_pairs(insns)
    
    peripheral_refs = []
    for key, (movw_addr, movw_val, movt_addr, movt_val, full_val) in pairs.items():
        for paddr, pname in PERIPHERAL_ADDRS.items():
            if full_val == paddr or (full_val & 0xFFFFF000) == (paddr & 0xFFFFF000):
                peripheral_refs.append((movw_addr, full_val, pname))
                break
    
    if peripheral_refs:
        report.append("### Peripheral References via MOVW/MOVT:")
        report.append("")
        for addr, val, name in peripheral_refs:
            report.append(f"- {addr:#x}: {val:#010x} ({name})")
        report.append("")
    
    # Find indirect calls
    indirect = find_indirect_calls(insns)
    report.append(f"### Indirect Calls: {len(indirect)} found")
    report.append("")
    for addr, mnem, reg in indirect:
        report.append(f"- {addr:#x}: {mnem} {reg}")
    report.append("")
    
    # Show prologue
    report.append("### Function prologue:")
    report.append("")
    report.append("```asm")
    for insn in insns[:20]:
        report.append(f"  {insn.address:#010x}: {insn.mnemonic:8s} {insn.op_str}")
    report.append("```")
    report.append("")
    
    # Find all call targets
    bl_targets = find_bl_targets(insns)
    target_counts = defaultdict(list)
    for addr, target in bl_targets:
        if isinstance(target, int):
            target_counts[target].append(addr)
    
    report.append(f"### Function calls: {len(bl_targets)} BL instructions")
    report.append("")
    report.append("Top called functions:")
    report.append("")
    report.append("| Target | Call Count | Notes |")
    report.append("|--------|-----------|-------|")
    for target, callers in sorted(target_counts.items(), key=lambda x: -len(x[1]))[:15]:
        notes = ""
        if target == MEMCPY_FUNC:
            notes = "memcpy"
        elif target == SET_REPORT_HANDLER:
            notes = "SET_REPORT"
        elif target == CONFIG_DISPATCH:
            notes = "config_dispatch"
        report.append(f"| {target:#x} | {len(callers)} | {notes} |")
    report.append("")


def analyze_movw_movt_global(data, report):
    """Section 6: Global search for MOVW/MOVT constructing peripheral addresses."""
    report.append("## Section 6: Global MOVW/MOVT Peripheral Address Search")
    report.append("")
    report.append("Searching entire binary for MOVW/MOVT instruction pairs that construct")
    report.append("known peripheral addresses (NVMC, UICR, SPI, QSPI, etc.)")
    report.append("")
    
    # Disassemble the entire binary with skipdata to handle data sections
    print("  [*] Disassembling entire binary for MOVW/MOVT scan...")
    md = create_disassembler(skipdata=True)
    all_insns = list(md.disasm(data, BASE_ADDR))
    # Filter to real instructions only (remove .byte data entries)
    all_insns = [i for i in all_insns if not i.mnemonic.startswith('.')]
    print(f"  [*] Disassembled {len(all_insns)} instructions total")
    
    # Find all MOVW/MOVT pairs
    pairs = decode_movw_movt_pairs(all_insns)
    
    # Check for peripheral matches
    peripheral_hits = []
    flash_addr_hits = []
    nvmc_hits = []
    
    for key, (movw_addr, movw_val, movt_addr, movt_val, full_val) in pairs.items():
        # Check peripherals
        for paddr, pname in PERIPHERAL_ADDRS.items():
            if full_val == paddr:
                peripheral_hits.append((movw_addr, full_val, pname))
                if "NVMC" in pname:
                    nvmc_hits.append((movw_addr, full_val, pname))
                break
            # Also check specific registers within peripherals
            if (paddr <= full_val < paddr + 0x1000) and "NVMC" in pname:
                nvmc_hits.append((movw_addr, full_val, f"{pname}+{full_val - paddr:#x}"))
                peripheral_hits.append((movw_addr, full_val, f"{pname}+{full_val - paddr:#x}"))
                break
        
        # Check if it references our patch target range
        if PATCH_RANGE_START <= full_val <= PATCH_RANGE_END:
            flash_addr_hits.append((movw_addr, full_val))
    
    if nvmc_hits:
        report.append("### !!! NVMC REFERENCES FOUND !!!")
        report.append("")
        report.append("These are CRITICAL - they indicate flash write capability!")
        report.append("")
        for addr, val, name in nvmc_hits:
            report.append(f"- {addr:#x}: constructs {val:#010x} ({name})")
        report.append("")
    else:
        report.append("### No NVMC references found via MOVW/MOVT")
        report.append("")
        report.append("This confirms flash write operations are NOT done via direct MOVW/MOVT register construction.")
        report.append("Flash access likely goes through Zephyr driver with function pointers in device structs.")
        report.append("")
    
    if flash_addr_hits:
        report.append("### !!! PATCH TARGET RANGE REFERENCES !!!")
        report.append("")
        report.append(f"Addresses in range {PATCH_RANGE_START:#x}-{PATCH_RANGE_END:#x} found:")
        report.append("")
        for addr, val in flash_addr_hits:
            report.append(f"- {addr:#x}: constructs {val:#010x}")
        report.append("")
    else:
        report.append(f"### No references to patch target range ({PATCH_RANGE_START:#x}-{PATCH_RANGE_END:#x})")
        report.append("")
    
    if peripheral_hits:
        report.append("### All Peripheral References via MOVW/MOVT:")
        report.append("")
        report.append("| Address | Value | Peripheral |")
        report.append("|---------|-------|-----------|")
        for addr, val, name in sorted(peripheral_hits):
            report.append(f"| {addr:#x} | {val:#010x} | {name} |")
        report.append("")
    
    # Also look for high addresses that could be memory-mapped
    high_addrs = []
    for key, (movw_addr, movw_val, movt_addr, movt_val, full_val) in pairs.items():
        if full_val >= 0x40000000 and full_val not in [v for _, v, _ in peripheral_hits]:
            high_addrs.append((movw_addr, full_val))
    
    if high_addrs:
        report.append("### Other High Addresses (>= 0x40000000) - Potential Unmapped Peripherals:")
        report.append("")
        for addr, val in sorted(high_addrs)[:30]:
            report.append(f"- {addr:#x}: {val:#010x}")
        report.append("")
    
    return all_insns


def analyze_indirect_call_map(data, all_insns, report):
    """Section 7: Map ALL indirect calls in the entire binary."""
    report.append("## Section 7: Complete Indirect Call Map")
    report.append("")
    report.append("Indirect calls (BLX Rn, BX Rn where Rn != LR) bypass static analysis.")
    report.append("These are the most interesting points for dynamic dispatch / vtable calls.")
    report.append("")
    
    indirect_calls = []
    for insn in all_insns:
        if insn.mnemonic == 'blx' and not insn.op_str.startswith('#'):
            indirect_calls.append((insn.address, 'blx', insn.op_str))
        elif insn.mnemonic == 'bx' and insn.op_str != 'lr':
            indirect_calls.append((insn.address, 'bx', insn.op_str))
    
    report.append(f"### Total indirect calls found: {len(indirect_calls)}")
    report.append("")
    report.append("| Address | Type | Register | Containing Function |")
    report.append("|---------|------|----------|-------------------|")
    
    # Find which function each indirect call belongs to
    functions = find_function_prologues(data)
    func_addrs = sorted([a for a, _ in functions])
    
    for addr, mnem, reg in indirect_calls:
        # Find containing function via binary search
        containing = "unknown"
        for i in range(len(func_addrs) - 1, -1, -1):
            if func_addrs[i] <= addr:
                containing = f"{func_addrs[i]:#x}"
                break
        report.append(f"| {addr:#x} | {mnem} | {reg} | {containing} |")
    report.append("")
    
    # Analyze the specific indirect call at 0x17E2C
    report.append("### Deep Analysis: Indirect Call at 0x17E2C")
    report.append("")
    report.append("This call handles report IDs 0x13 and 0x17. Tracing the dereference chain:")
    report.append("")
    
    # Disassemble around 0x17E2C to see the pointer chain
    context_insns = disasm_at(data, 0x17E10, max_bytes=64)
    report.append("```asm")
    for insn in context_insns:
        report.append(f"  {insn.address:#010x}: {insn.mnemonic:8s} {insn.op_str}")
    report.append("```")
    report.append("")
    report.append("The dereference chain: LDR R0, [PC+x] -> LDR R0, [R0+0x24] -> LDR R0, [R0+0x1C] -> BLX R0")
    report.append("This is a Zephyr device struct -> API -> function pointer pattern.")
    report.append("")


def analyze_zephyr_flash_driver(data, all_insns, report):
    """Section 8: Search for Zephyr flash driver API patterns."""
    report.append("## Section 8: Zephyr Flash Driver API Patterns")
    report.append("")
    report.append("Zephyr's flash driver uses device structs with function pointer tables.")
    report.append("Pattern: device_get_binding() -> dev->api -> api->write/erase/read")
    report.append("")
    report.append("Looking for the characteristic dereference sequences that access flash APIs:")
    report.append("- LDR Rx, [Ry, #offset1]  ; get API struct")
    report.append("- LDR Rx, [Rx, #offset2]  ; get function pointer from API")
    report.append("- BLX Rx                   ; call through function pointer")
    report.append("")
    
    # Find all LDR -> LDR -> BLX sequences
    vtable_patterns = []
    for i in range(len(all_insns) - 5):
        # Look for sequences that load from a struct then call
        seq = all_insns[i:i+6]
        for j in range(len(seq) - 2):
            if (seq[j].mnemonic == 'ldr' and 
                seq[j+1].mnemonic == 'ldr' and
                seq[j+2].mnemonic == 'blx' and
                not seq[j+2].op_str.startswith('#')):
                # Check if the loads dereference in sequence
                vtable_patterns.append((seq[j].address, 
                    f"{seq[j].mnemonic} {seq[j].op_str}",
                    f"{seq[j+1].mnemonic} {seq[j+1].op_str}",
                    f"{seq[j+2].mnemonic} {seq[j+2].op_str}"))
                break
    
    report.append(f"### LDR->LDR->BLX vtable patterns found: {len(vtable_patterns)}")
    report.append("")
    if vtable_patterns:
        report.append("| Address | Load 1 | Load 2 | Call |")
        report.append("|---------|--------|--------|------|")
        for addr, l1, l2, call in vtable_patterns[:30]:
            report.append(f"| {addr:#x} | {l1} | {l2} | {call} |")
        report.append("")
    
    # Look for flash-related string references
    report.append("### Flash-related strings in binary:")
    report.append("")
    
    flash_strings = []
    # Search for known Zephyr flash-related strings
    search_terms = [b'flash', b'FLASH', b'nvmc', b'NVMC', b'spi_nor', b'qspi', 
                    b'erase', b'write_pro', b'img_mgmt', b'mcuboot',
                    b'boot', b'slot', b'swap', b'image']
    
    for term in search_terms:
        pos = 0
        while True:
            idx = data.find(term, pos)
            if idx == -1:
                break
            # Extract surrounding context (printable chars)
            start = max(0, idx - 10)
            end = min(len(data), idx + 40)
            context = data[start:end]
            printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in context)
            flash_strings.append((offset_to_mem(idx), term.decode('ascii', errors='replace'), printable))
            pos = idx + 1
    
    if flash_strings:
        for addr, term, context in flash_strings[:30]:
            report.append(f"- {addr:#x}: `{context}` (matched: '{term}')")
        report.append("")
    else:
        report.append("No flash-related strings found in binary.")
        report.append("")


def analyze_spi_flash_patterns(data, all_insns, report):
    """Section 9: Search for SPI flash access patterns."""
    report.append("## Section 9: SPI Flash Access Patterns")
    report.append("")
    report.append("MCUboot uses an external SPI flash as the secondary/swap slot.")
    report.append("Looking for SPI flash command sequences and QSPI peripheral access.")
    report.append("")
    
    # Search for SPI command byte patterns in immediate values
    spi_cmd_refs = []
    for insn in all_insns:
        if insn.mnemonic in ('mov', 'movs', 'cmp', 'movw'):
            try:
                parts = insn.op_str.split(',')
                if len(parts) >= 2:
                    val_str = parts[-1].strip().replace('#', '')
                    val = int(val_str, 0)
                    if val in SPI_COMMANDS:
                        spi_cmd_refs.append((insn.address, val, SPI_COMMANDS[val], insn.mnemonic))
            except (ValueError, IndexError):
                pass
    
    if spi_cmd_refs:
        report.append("### Potential SPI Flash Commands Referenced:")
        report.append("")
        report.append("| Address | Value | Command | Instruction |")
        report.append("|---------|-------|---------|-------------|")
        for addr, val, cmd, mnem in spi_cmd_refs:
            report.append(f"| {addr:#x} | {val:#04x} | {cmd} | {mnem} |")
        report.append("")
        report.append("NOTE: Small values like 0x02-0x06 are very common and may be false positives.")
        report.append("Focus on 0x9F (JEDEC_ID), 0x20 (SECTOR_ERASE), 0xD8 (BLOCK_ERASE), 0xC7 (CHIP_ERASE).")
        report.append("")
    else:
        report.append("No obvious SPI flash commands found in immediate values.")
        report.append("")
    
    # Check for QSPI peripheral base
    qspi_refs = scan_for_literal_pool_refs(data, 0x4002F000)
    if qspi_refs:
        report.append("### QSPI Peripheral References (literal pool):")
        report.append("")
        for addr in qspi_refs:
            report.append(f"- Literal pool at {addr:#x} contains QSPI base (0x4002F000)")
        report.append("")
    
    # Check for SPI peripheral bases
    for spi_name, spi_addr in [("SPI0", 0x40003000), ("SPI1", 0x40004000), ("SPI2", 0x40023000)]:
        refs = scan_for_literal_pool_refs(data, spi_addr)
        if refs:
            report.append(f"### {spi_name} References (literal pool at {spi_addr:#x}):")
            report.append("")
            for addr in refs:
                report.append(f"- Literal pool at {addr:#x}")
            report.append("")


def analyze_patch_range_refs(data, all_insns, report):
    """Section 10: References to patch target address range 0x24000-0x25FFF."""
    report.append("## Section 10: References to Patch Target Range (0x24000-0x25FFF)")
    report.append("")
    report.append("Our patch modifies addresses 0x24616-0x24631 (file offsets 0x14616-0x14631).")
    report.append("Looking for any code that references this range - could indicate runtime writes.")
    report.append("")
    
    # Search for literal pool entries pointing to this range
    refs_found = []
    target_bytes = struct.pack('<I', 0x24000)
    
    # Search for any 4-byte value in range 0x24000-0x26000 in the binary
    for offset in range(0, len(data) - 3, 4):
        val = struct.unpack_from('<I', data, offset)[0]
        if 0x24000 <= val <= 0x26000:
            mem_addr = offset_to_mem(offset)
            refs_found.append((mem_addr, val))
    
    if refs_found:
        report.append(f"### Found {len(refs_found)} literal pool entries pointing to target range:")
        report.append("")
        report.append("| Pool Address | Points To | Notes |")
        report.append("|-------------|-----------|-------|")
        for addr, val in refs_found:
            notes = ""
            if 0x24616 <= val <= 0x24631:
                notes = "EXACT PATCH LOCATION!"
            report.append(f"| {addr:#x} | {val:#x} | {notes} |")
        report.append("")
    else:
        report.append("No literal pool entries found pointing to the patch target range.")
        report.append("")
    
    # Also check for MOVW/MOVT constructing addresses in this range
    # (Already covered in section 6 but worth highlighting)
    movw_refs = []
    for insn in all_insns:
        if insn.mnemonic == 'movw':
            parts = insn.op_str.split(',')
            if len(parts) == 2:
                try:
                    val = int(parts[1].strip().replace('#', ''), 0)
                    # Low 16 bits of addresses in range
                    if 0x4000 <= val <= 0x6000:
                        movw_refs.append((insn.address, val))
                except ValueError:
                    pass
    
    report.append(f"### MOVW values in range 0x4000-0x6000 (low 16 bits of 0x24000-0x26000):")
    report.append("")
    if movw_refs:
        for addr, val in movw_refs[:20]:
            report.append(f"- {addr:#x}: MOVW with {val:#x}")
    else:
        report.append("None found.")
    report.append("")


def analyze_nvmc_register_patterns(data, report):
    """Section 11: Search for NRF_NVMC register access patterns."""
    report.append("## Section 11: NVMC Register Pattern Search")
    report.append("")
    report.append("NVMC registers for flash operations:")
    report.append("- CONFIG (offset 0x504): 0=ReadOnly, 1=WriteEnable, 2=EraseEnable")
    report.append("- ERASEPAGE (offset 0x508): Write page address to erase")
    report.append("- ERASEALL (offset 0x50C): Write 1 to erase all")
    report.append("- ERASEUICR (offset 0x514): Write 1 to erase UICR")
    report.append("- READY (offset 0x400): Read 1 when operation complete")
    report.append("")
    
    # Search for the NVMC base in literal pools
    nvmc_base = 0x4001E000
    refs = scan_for_literal_pool_refs(data, nvmc_base)
    
    # Also search for NVMC register addresses directly
    nvmc_regs = {
        0x4001E400: "NVMC_READY",
        0x4001E504: "NVMC_CONFIG",
        0x4001E508: "NVMC_ERASEPAGE",
        0x4001E50C: "NVMC_ERASEALL",
        0x4001E514: "NVMC_ERASEUICR",
    }
    
    all_nvmc_refs = []
    for reg_addr, reg_name in nvmc_regs.items():
        found = scan_for_literal_pool_refs(data, reg_addr)
        for addr in found:
            all_nvmc_refs.append((addr, reg_addr, reg_name))
    
    for addr in refs:
        all_nvmc_refs.append((addr, nvmc_base, "NVMC_BASE"))
    
    if all_nvmc_refs:
        report.append("### !!! NVMC REFERENCES IN LITERAL POOLS !!!")
        report.append("")
        for addr, val, name in sorted(all_nvmc_refs):
            report.append(f"- {addr:#x}: {val:#010x} ({name})")
        report.append("")
        
        # Disassemble around each NVMC reference
        for addr, val, name in all_nvmc_refs[:5]:
            report.append(f"#### Context around {addr:#x} ({name}):")
            report.append("")
            # The literal pool is usually after a function, find what loads it
            # Search backwards for LDR instruction that references this pool entry
            search_start = max(0, mem_to_offset(addr) - 512)
            search_end = mem_to_offset(addr)
            insns = disasm_at(data, offset_to_mem(search_start), max_bytes=search_end - search_start + 4)
            
            # Find LDR that points to this literal pool
            for insn in insns:
                if insn.mnemonic == 'ldr' and '[pc' in insn.op_str:
                    # Check if this LDR references our literal pool address
                    # PC-relative offset calculation
                    pass
            
            report.append("```asm")
            # Show a few instructions before the pool location
            ctx_insns = disasm_at(data, addr - 32, max_bytes=64)
            for insn in ctx_insns:
                report.append(f"  {insn.address:#010x}: {insn.mnemonic:8s} {insn.op_str}")
            report.append("```")
            report.append("")
    else:
        report.append("### No NVMC references found in literal pools")
        report.append("")
        report.append("This strongly suggests the application firmware does NOT have direct flash write capability.")
        report.append("Flash operations are handled exclusively by MCUboot (which runs in a different partition).")
        report.append("")
    
    # Check for the magic values used in NVMC CONFIG register
    # CONFIG = 1 (write enable) or 2 (erase enable)
    report.append("### Search for NVMC CONFIG magic values")
    report.append("")
    report.append("If any code writes to NVMC_CONFIG, it would need to set values 1 (WEN) or 2 (EEN).")
    report.append("These are too common as immediate values to be useful as indicators alone.")
    report.append("")


def analyze_func_17da8(data, report):
    """Section 12: Analyze function at 0x17DA8 (called from 36 locations)."""
    report.append("## Section 12: High-Frequency Function 0x17DA8 (36 callers)")
    report.append("")
    report.append("This function is called from 36 locations, making it a critical utility.")
    report.append("")
    
    # Disassemble the function
    insns = disasm_at(data, FUNC_17DA8, max_bytes=256)
    
    report.append("### Disassembly:")
    report.append("")
    report.append("```asm")
    for insn in insns:
        report.append(f"  {insn.address:#010x}: {insn.mnemonic:8s} {insn.op_str}")
        if insn.mnemonic == 'pop' and 'pc' in insn.op_str:
            break
    report.append("```")
    report.append("")
    
    # Analyze what it does
    bl_targets = find_bl_targets(insns)
    indirect = find_indirect_calls(insns)
    
    if bl_targets:
        report.append("### Calls made by this function:")
        report.append("")
        for addr, target in bl_targets:
            if isinstance(target, int):
                report.append(f"- {addr:#x} -> {target:#x}")
            else:
                report.append(f"- {addr:#x} -> {target} (indirect)")
        report.append("")
    
    if indirect:
        report.append("### Indirect calls:")
        report.append("")
        for addr, mnem, reg in indirect:
            report.append(f"- {addr:#x}: {mnem} {reg}")
        report.append("")


def analyze_all_functions_summary(data, report):
    """Section 13: Summary of all functions with flash-related heuristics."""
    report.append("## Section 13: Function Classification (Flash-Capability Heuristics)")
    report.append("")
    report.append("Classifying all functions by likelihood of flash write capability.")
    report.append("Heuristics: contains STR to high addresses, calls indirect functions,")
    report.append("references peripheral regions, or has characteristics of a flash driver.")
    report.append("")
    
    functions = find_function_prologues(data)
    func_addrs = sorted([a for a, _ in functions])
    
    # Calculate function sizes
    func_sizes = []
    for i, addr in enumerate(func_addrs):
        if i + 1 < len(func_addrs):
            size = func_addrs[i + 1] - addr
        else:
            size = len(data) + BASE_ADDR - addr
        func_sizes.append((addr, size))
    
    # Find large functions (> 500 bytes) that we should analyze
    large_funcs = [(addr, size) for addr, size in func_sizes if size > 500]
    
    report.append(f"### Total functions: {len(functions)}")
    report.append(f"### Functions > 500 bytes: {len(large_funcs)}")
    report.append("")
    
    report.append("### Top 20 Largest Functions:")
    report.append("")
    report.append("| Address | Size (bytes) | Notes |")
    report.append("|---------|-------------|-------|")
    for addr, size in sorted(large_funcs, key=lambda x: -x[1])[:20]:
        notes = ""
        if addr == LARGEST_FUNC:
            notes = "Largest - analyzed in Section 4"
        elif addr == MAIN_LOOP:
            notes = "Main loop - analyzed in Section 5"
        elif addr == SET_REPORT_HANDLER:
            notes = "SET_REPORT handler"
        elif addr == CONFIG_DISPATCH:
            notes = "Config dispatch"
        report.append(f"| {addr:#x} | {size} | {notes} |")
    report.append("")


def generate_conclusions(report):
    """Section 14: Conclusions and unexplored paths."""
    report.append("## Section 14: Conclusions and Unexplored Paths")
    report.append("")
    report.append("### Key Findings Summary")
    report.append("")
    report.append("Based on this deeper analysis:")
    report.append("")
    report.append("1. **NVMC Access**: Whether direct NVMC register access exists in the app firmware")
    report.append("2. **Indirect Calls**: Every indirect call (BLX Rn) is a potential path to hidden functionality")
    report.append("3. **Zephyr Flash API**: If the device struct pattern is present, flash writes may be possible through the driver layer")
    report.append("4. **SPI Flash**: External SPI flash access could be used to write to the MCUboot secondary slot")
    report.append("5. **Patch Range References**: Whether the firmware ever references its own code at the patch location")
    report.append("")
    report.append("### Potential New Analysis Vectors")
    report.append("")
    report.append("1. **Flash Driver Analysis**: If the Zephyr flash driver is accessible through indirect calls,")
    report.append("   it may be possible to trigger a flash write through a legitimate API path")
    report.append("2. **SPI Secondary Slot**: Writing a new image to the SPI flash secondary slot could trigger MCUboot swap")
    report.append("3. **Image Swap Trigger**: If MCUboot's image swap can be triggered through app firmware,")
    report.append("   we only need to get our image into the secondary slot")
    report.append("4. **Vendor Update Protocol**: The existing update mechanism in the EXE might have")
    report.append("   a protocol path that writes to secondary slot before signature verification")
    report.append("")


# ===========================================================================
# Main
# ===========================================================================

def main():
    """Run the deeper firmware analysis."""
    # Determine paths
    script_dir = Path(__file__).parent.resolve()
    
    if len(sys.argv) > 1:
        fw_path = Path(sys.argv[1])
    else:
        fw_path = script_dir / "mouse_app_fw.bin"
    
    output_path = script_dir / "FW_DEEPER_ANALYSIS_REPORT.md"
    
    print("=" * 70)
    print("  AJ159 APEX Firmware DEEPER Analysis")
    print("=" * 70)
    print()
    
    # Load firmware
    if not fw_path.exists():
        print(f"ERROR: Firmware file not found: {fw_path}")
        sys.exit(1)
    
    data = fw_path.read_bytes()
    print(f"[+] Loaded firmware: {fw_path} ({len(data)} bytes)")
    
    if len(data) != EXPECTED_SIZE:
        print(f"[!] WARNING: Expected {EXPECTED_SIZE} bytes, got {len(data)}")
    
    # Build report
    report = []
    report.append("# AJ159 APEX Firmware DEEPER Analysis Report")
    report.append("")
    report.append("Generated by `fw_deeper_analysis.py`")
    report.append("")
    report.append("This analysis goes beyond the initial deep analysis to find unexplored paths")
    report.append("for flashing the firmware patch past MCUboot signature verification.")
    report.append("")
    report.append("---")
    report.append("")
    
    # Section 1: Full SET_REPORT handler
    print("[1/13] Disassembling full SET_REPORT handler...")
    analyze_set_report_full(data, report)
    
    # Section 2: Post-validation path
    print("[2/13] Analyzing post-validation path...")
    analyze_validated_path(data, report)
    
    # Section 3: Caller context
    print("[3/13] Analyzing caller context at 0x19AB4...")
    analyze_caller_context(data, report)
    
    # Section 4: Largest function
    print("[4/13] Analyzing largest function (0x262D0, 6480 bytes)...")
    analyze_largest_function(data, report)
    
    # Section 5: Main loop
    print("[5/13] Analyzing main processing loop (0x192C0, 3208 bytes)...")
    analyze_main_loop(data, report)
    
    # Section 6: Global MOVW/MOVT scan
    print("[6/13] Global MOVW/MOVT peripheral address scan (full binary disassembly)...")
    all_insns = analyze_movw_movt_global(data, report)
    
    # Section 7: Indirect call map
    print("[7/13] Mapping all indirect calls...")
    analyze_indirect_call_map(data, all_insns, report)
    
    # Section 8: Zephyr flash driver patterns
    print("[8/13] Searching for Zephyr flash driver API patterns...")
    analyze_zephyr_flash_driver(data, all_insns, report)
    
    # Section 9: SPI flash patterns
    print("[9/13] Searching for SPI flash access patterns...")
    analyze_spi_flash_patterns(data, all_insns, report)
    
    # Section 10: Patch range references
    print("[10/13] Checking references to patch target range...")
    analyze_patch_range_refs(data, all_insns, report)
    
    # Section 11: NVMC register patterns
    print("[11/13] Searching for NVMC register access patterns...")
    analyze_nvmc_register_patterns(data, report)
    
    # Section 12: High-frequency function
    print("[12/13] Analyzing high-frequency function 0x17DA8...")
    analyze_func_17da8(data, report)
    
    # Section 13: Function classification
    print("[13/13] Function classification summary...")
    analyze_all_functions_summary(data, report)
    
    # Section 14: Conclusions
    generate_conclusions(report)
    
    # Write report
    report_text = '\n'.join(report)
    output_path.write_text(report_text)
    
    print()
    print("=" * 70)
    print(f"[+] Report written to: {output_path}")
    print(f"[+] Report size: {len(report_text)} bytes, {len(report)} lines")
    print("=" * 70)


if __name__ == '__main__':
    main()
