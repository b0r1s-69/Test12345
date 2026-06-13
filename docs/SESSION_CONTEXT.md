# AJ159 APEX - Full Engineering Context

## Project Overview

This repository documents the reverse engineering, diagnosis, and fix of a firmware bug in the Ajazz AJ159 APEX gaming mouse. The bug causes held mouse buttons to release when an onboard macro fires.

## Timeline

1. **Bug identified** - Macro on LMB causes RMB to release when both are pressed simultaneously
2. **Firmware extracted** - Application firmware carved from `ry_upgrade.exe` (MV302 upgrade tool)
3. **Bug located** - Disassembly revealed `STRB` overwrite at `0x024616` instead of OR-merge
4. **Patch created** - 27-byte fix using BL trampoline to code cave with ORRS instruction
5. **Flash attempted** - MCUboot RSA-2048 signature blocks all modified firmware
6. **Loophole discovered** - NORDICKEYBOARD method in ry_upgrade.exe uses raw Nordic OTA (55 AA magic bytes) which bypasses MCUboot RSA verification
7. **Current status** - NORDICKEYBOARD path shows different UI but says "does not require upgrade" because no firmware data is tagged for that method

## Technical Architecture

### Mouse Hardware
- **SoC:** Nordic nRF52840 (ARM Cortex-M4F, 64MHz)
- **Sensor:** PixArt PAW3950
- **Connectivity:** 2.4GHz proprietary, Bluetooth 5.0, USB wired
- **VID:** 0x3151 (RuiYu)
- **Normal PIDs:** varies by connection mode
- **Boot PID:** 0x4025 (enters boot mode for firmware upgrade)

### Firmware Structure
- **Bootloader:** MCUboot with RSA-2048 signature verification
- **App location:** Flash offset 0x10000 (MCUboot slot 0)
- **App size:** 108,608 bytes (+ 512-byte MCUboot header + 336-byte TLV trailer)
- **Image format:** MCUboot (header + image + SHA256 + RSA-2048 signature in TLV)
- **Version:** 1.0.0+76824442 (build number in version field)

### The Bug (Detailed)

At address `0x024616`, the macro playback engine writes button state to the HID report:
```
STRB r1, [r4]      ; report[0] = macro_buttons (OVERWRITES everything)
STRB r0, [r4, #1]  ; report[1] = macro_buttons_ext (OVERWRITES everything)
```

The correct approach (used by physical button processing at `0x024652`):
```
LDRB r0, [r4]      ; Read current state
ANDS r0, mask       ; Clear target bit
ORRS r0, new_bit   ; Set new bit (preserves others)
STRB r0, [r4]      ; Write back
```

### The Fix

27 bytes total:
- 10 bytes at bug site (BL + B + 2x NOP to replace the 4 original instructions)
- 18 bytes at code cave 0x025F36 (LDRB+LDRB+ORRS+STRB for both bytes + BX LR)

### Flash Protocol (ry_upgrade.exe)

The upgrade tool supports multiple methods:
- **MOUSE** - Standard MCUboot OTA with RSA verification (used for PID 0x4025 normally)
- **NORDICKEYBOARD** - Raw Nordic OTA protocol (55 AA magic header) that bypasses MCUboot
- **YZW / YZW24** - Other proprietary methods
- **FLASH** - Direct flash write

The tool reads `resources/support_config.json` to determine which method to use for each VID/PID.

### Loophole Discovery

When we changed the boot entry for PID 4025 from method `MOUSE` to `NORDICKEYBOARD`:
- The tool showed a completely different UI: "DEVICE ID:0 / USBV0 / UPGRADE"
- This confirms the NORDICKEYBOARD code path is active
- BUT it reports "does not require upgrade" because the EXE has no firmware data associated with the NORDICKEYBOARD method for this device
- The EXE likely has an internal mapping: method + device -> firmware blob

### Remaining Work (Loophole Flash)

To flash via the NORDICKEYBOARD loophole:
1. Find where in the EXE the method-to-firmware mapping lives
2. Either patch the EXE to associate our firmware with NORDICKEYBOARD
3. Or patch the version comparison that triggers "does not require upgrade"
4. Or find the firmware blob storage and inject our patched binary

Alternative: Reverse engineer the raw Nordic OTA protocol (55 AA prefix) and write a custom flasher.

## Files and Directories

### /workaround/
Immediate host-side fix using AutoHotkey. Zero risk, works today.

### /firmware_patch/
The actual firmware binary patch and tools to apply it. Requires a way to bypass RSA to flash.

### /debug_toolkit/
USB HID debug tools for communicating with the mouse directly (Python + hidapi).

### /loophole_flash/
The modified ry_upgrade.exe and support_config.json configured to trigger NORDICKEYBOARD method.

### /docs/
Technical documentation, guides, and the Ajazz bug report.
