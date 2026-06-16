# AJ159 APEX HID Diagnostic Toolkit

## Overview

This toolkit provides tools for analyzing a stack buffer overflow vulnerability in the Ajazz AJ159 APEX gaming mouse firmware. The goal is to achieve arbitrary code execution via USB HID, providing an alternative path past the MCUboot RSA-2048 signature verification that prevents flashing modified firmware.

**Target:** Ajazz AJ159 APEX Gaming Mouse  
**MCU:** nRF52840 (ARM Cortex-M4F, 1MB flash, 256KB RAM)  
**RTOS:** Zephyr  
**Interface:** USB HID Feature Reports (SET_REPORT/GET_REPORT)

## Vulnerability Summary

### The Bug

The SET_REPORT handler at firmware address `0x1C1A8` contains a classic stack buffer overflow:

```
0x1C1A8: PUSH {R0-R7, LR}    ; Save 9 registers (36 bytes) to stack
0x1C1AA: SUB SP, #0x3C        ; Allocate 60 bytes for local buffer
```

The handler receives **64-byte** HID Feature Reports into this **60-byte** stack buffer. This provides a 4-byte overflow directly into saved register R0 on the stack.

### Additional Analysis Surface

Five dangerous `memcpy` sites copy larger amounts to stack buffers:

| Address  | Copy Size | Overflow | Description |
|----------|-----------|----------|-------------|
| 0x12DD4  | 70 bytes  | 10 bytes | Medium overflow |
| 0x14A7A  | 94 bytes  | 34 bytes | Large overflow (can reach LR) |
| 0x1677A  | 64 bytes  | 4 bytes  | Matches report size exactly |
| 0x1E4F0  | 115 bytes | 55 bytes | Massive overflow |
| 0x1EC4C  | 115 bytes | 55 bytes | Massive overflow |

### Why This Matters

- **No stack canaries** - overflow goes undetected
- **No ASLR** - all addresses are fixed and known
- **No XN (execute-never)** - stack memory is executable
- **Known code layout** - firmware binary fully disassembled
- **Safe to test** - MCUboot swap design guarantees device recovery

## Architecture Details

### Memory Map

```
0x00000000 - 0x00010000: MCUboot bootloader (64KB)
0x00010000 - 0x0002C000: Application firmware (~112KB)
0x20000000 - 0x20040000: RAM (256KB, stack + heap + data)
0x40000000+:             Peripherals
```

### Stack Frame at 0x1C1A8

```
High addresses (caller's frame)
+-----------------+
| saved LR        |  <- SP + 92 (return address!)
| saved R7        |  <- SP + 88
| saved R6        |  <- SP + 84
| saved R5        |  <- SP + 80
| saved R4        |  <- SP + 76
| saved R3        |  <- SP + 72
| saved R2        |  <- SP + 68
| saved R1        |  <- SP + 64
| saved R0        |  <- SP + 60  ** OVERFLOW TARGET **
+-----------------+
| local buffer    |  <- SP + 0 to SP + 59 (60 bytes)
| (64 bytes       |
|  written here)  |
+-----------------+
Low addresses (SP after SUB)
```

### Firmware Dispatch Path

1. USB stack receives 64-byte SET_REPORT on Interface 2
2. Handler at `0x1C1A8` copies report to stack buffer
3. Validation gate checks field constraints:
   - `report_id` (byte 0) must be <= 0xEF
   - Stack offsets 0x64, 0x68, 0x80, 0x84 checked against bounds
4. Config dispatch at `0x17DDC` routes by report ID
5. Special dispatch at `0x17E1E` for IDs 0x13, 0x17 (indirect call)
6. Common handler at `0x21D44` sets bit 6 flag (deferred processing)

### Report IDs

| ID   | Type | Dispatch Path |
|------|------|---------------|
| 0x04 | DPI configuration | Standard (0x17DDC) |
| 0x05 | Preferences/RGB | Standard (0x17DDC) |
| 0x06 | Polling rate | Standard (0x17DDC) |
| 0x13 | Vendor (unknown) | Special (0x17E1E, indirect call) |
| 0x14 | Vendor (unknown) | Standard (0x17DDC) |
| 0x15 | Vendor (unknown) | Standard (0x17DDC) |
| 0x16 | Vendor (unknown) | Standard (0x17DDC) |
| 0x17 | Vendor (unknown) | Special (0x17E1E, indirect call) |
| 0x18 | Vendor (unknown) | Standard (0x17DDC) |

## Tools

### 1. hid_deferred_probe.py

**Purpose:** Map the deferred processing path to understand which report IDs and payload structures trigger actual data processing.

```bash
# Basic probe of all known report IDs
python3 hid_deferred_probe.py

# Probe only the special-dispatch IDs (most interesting)
python3 hid_deferred_probe.py --ids 0x13 0x17

# Deep probing with multiple payload variants
python3 hid_deferred_probe.py --deep

# Measure deferred processing timing
python3 hid_deferred_probe.py --timing

# Save results for later analysis
python3 hid_deferred_probe.py --deep --timing --output probe_results.json
```

**What it does:**
- Sends SET_REPORT with each known report ID using structured payloads
- Reads GET_REPORT before and after to detect state changes
- Tests multiple payload variants (minimal, standard, max-valid, incremental)
- Measures timing between SET and GET for deferred processing detection
- Identifies which code paths actually process data beyond validation

### 2. hid_protocol_tester.py

**Purpose:** Trigger crashes via buffer overflow by sending malformed/crafted SET_REPORT payloads.

```bash
# Run all 5 testing strategies
python3 hid_protocol_tester.py --strategy all

# Stack overflow targeting bytes 60-63
python3 hid_protocol_tester.py --strategy overflow

# Report ID sweep with De Bruijn pattern (offset detection)
python3 hid_protocol_tester.py --strategy sweep

# Vendor-specific ID testing (0x13-0x18)
python3 hid_protocol_tester.py --strategy vendor

# Validation gate boundary testing
python3 hid_protocol_tester.py --strategy boundary

# Race condition / queue overflow testing
python3 hid_protocol_tester.py --strategy rapidfire

# Custom options
python3 hid_protocol_tester.py --strategy sweep --start-id 0x13 --end-id 0x18 --delay 10

# Dry run (show payloads without connecting)
python3 hid_protocol_tester.py --dry-run

# Save full log for crash_analyzer.py
python3 hid_protocol_tester.py --strategy all --log test_results.json
```

**Strategies:**

1. **overflow** - Direct stack overflow: crafts bytes 60-63 to corrupt saved R0
2. **sweep** - De Bruijn pattern across all report IDs for offset identification
3. **vendor** - Targeted testing of vendor IDs 0x13-0x18 (least tested paths)
4. **boundary** - Pushes validation gate fields to max/beyond limits
5. **rapidfire** - Sends packets with no delay to trigger race conditions

### 3. crash_analyzer.py

**Purpose:** Detect crashes, analyze crash-inducing payloads, and narrow down the exact bytes that trigger the overflow.

```bash
# Monitor for crashes (use alongside protocol tester in another terminal)
python3 crash_analyzer.py --monitor

# Test a specific payload (hex string)
python3 crash_analyzer.py --payload "13400101AABBCCDDEE..."

# Test and binary-search for critical byte
python3 crash_analyzer.py --payload "13400101..." --bisect

# Replay crashes from test log
python3 crash_analyzer.py --replay-log test_results.json

# Generate analysis report
python3 crash_analyzer.py --payload "13400101..." --report analysis_report.json
```

**Capabilities:**
- Continuous device polling to detect crash moment
- Distinguishes soft crash (watchdog reset), hard crash (boot mode), and hang
- Binary search to narrow down critical byte/bit
- De Bruijn pattern offset identification
- Register value analysis based on overflow position
- Analysis report generation

## Usage Workflow

### Step 1: Probe

Run the deferred probe to understand which report IDs are active:

```bash
python3 hid_deferred_probe.py --deep --timing --output probe.json
```

Look for IDs that:
- Accept SET_REPORT without error
- Show state changes after SET_REPORT
- Have timing differences suggesting deferred processing

### Step 2: Test

Start with targeted testing on responsive IDs:

```bash
# Start with the overflow strategy on discovered responsive IDs
python3 hid_protocol_tester.py --strategy overflow --log test.json

# If no crash, try vendor path testing
python3 hid_protocol_tester.py --strategy vendor --log test_vendor.json

# Aggressive testing
python3 hid_protocol_tester.py --strategy all --delay 5 --log test_all.json
```

### Step 3: Analyze

When a crash is found:

```bash
# Replay and confirm the crash
python3 crash_analyzer.py --replay-log test.json

# Narrow down to the exact byte
python3 crash_analyzer.py --payload "<crash_payload_hex>" --bisect

# Generate full report
python3 crash_analyzer.py --payload "<crash_payload_hex>" --report analysis.json
```

### Step 4: Leverage (if crash found)

Based on crash analysis:

1. **If crash at bytes 60-63 (R0 overwrite):** Control function argument after handler returns
2. **If memcpy path reached:** Larger overflow can reach LR for return address control
3. **If LR controllable:** Direct jump to shellcode on stack (stack is executable)

Shellcode constraints:
- Must be ARM Thumb mode (set LSB of jump address)
- Max 64 bytes in single report (or multi-stage via repeated reports)
- Target: call MCUboot flash write to install firmware patch
- Alternative: disable signature verification in RAM, then DFU normally

## Safety

### MCUboot Recovery Guarantee

The nRF52840 uses MCUboot with a swap-based update design:

- **Slot 0 (primary):** Running firmware
- **Slot 1 (secondary):** Pending update
- MCUboot validates Slot 1 signature before swapping
- If swap fails or new firmware crashes: automatic rollback to Slot 0

This means:
- Testing can NEVER permanently brick the device
- Worst case: watchdog timeout causes reset to boot mode
- Power cycle always recovers to a working state
- Boot mode (PID 0x4025) is a safe fallback state

### Risk Assessment

| Risk | Level | Mitigation |
|------|-------|-----------|
| Device brick | None | MCUboot guarantees recovery |
| Data loss | None | Mouse has no user data |
| USB damage | Negligible | Standard HID traffic |
| Crash loop | Low | Power cycle breaks any loop |

## Decision Tree

```
Start: Can we crash the device via HID?
  |
  +-- YES: Crash found
  |     |
  |     +-- Can we control which register is overwritten?
  |     |     |
  |     |     +-- YES: Register control achieved
  |     |     |     |
  |     |     |     +-- Can we reach LR? (return address)
  |     |     |     |     |
  |     |     |     |     +-- YES: Build ROP chain or jump to shellcode
  |     |     |     |     |        -> CODE EXECUTION ACHIEVED
  |     |     |     |     |
  |     |     |     |     +-- NO: Use R0-R7 control for argument injection
  |     |     |     |              -> Limited control (call known functions)
  |     |     |     |
  |     |     |     +-- NO: Crash is not at controllable offset
  |     |     |           -> Try different report IDs / memcpy paths
  |     |     |
  |     |     +-- NO: Random crash location
  |     |           -> Refine payload, try boundary strategy
  |     |
  |     +-- Is crash in boot mode (hard crash)?
  |           |
  |           +-- YES: Strong indicator of code exec
  |           +-- NO: May be data abort, less useful
  |
  +-- NO: No crash observed
        |
        +-- Device silently ignores invalid data
        |     -> Try different report IDs, timing, memcpy paths
        |
        +-- Device validates all input properly
              -> HID path may not be viable
              -> Fall back to SWD hardware debug (requires soldering)
```

## Prerequisites

```bash
# Install dependencies
pip install hidapi

# Linux: install udev rules (run once)
sudo cp debug_toolkit/99-aj159.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
sudo udevadm trigger

# Verify mouse is connected
lsusb | grep 3151
# Should show: Bus XXX Device XXX: ID 3151:4026
```

## Files

| File | Purpose |
|------|---------|
| `hid_deferred_probe.py` | Map deferred processing paths |
| `hid_protocol_tester.py` | Smart protocol testing with 5 strategies |
| `crash_analyzer.py` | Crash detection and analysis |
| `probe_reports.py` | Basic report ID enumeration (existing) |
| `aj159_debug.py` | General debug toolkit (existing) |
| `tlv_tester.py` | MCUboot TLV variant testing (existing) |
| `99-aj159.rules` | Linux udev rules for non-root access |
