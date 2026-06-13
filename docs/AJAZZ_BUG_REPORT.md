# Bug Report: Macro Button State Overwrite in AJ159 APEX Firmware

## Summary

The onboard macro playback engine in the AJ159 APEX mouse firmware (MV302, v1.0.0+76824442) contains a critical bug where macro button events **overwrite** physically held buttons instead of OR-merging with them. This causes held buttons (e.g., RMB for aim-down-sights) to release when a macro fires on another button (e.g., LMB rapid-fire).

## Affected Product

- **Mouse:** Ajazz AJ159 APEX
- **Firmware version:** MV302 v1.0.0+76824442
- **Firmware SHA256:** `1c0c5fdd02ce92ed521729a00218f0f86924442`
- **Platform:** Nordic nRF52840 + Zephyr RTOS + MCUboot
- **Firmware SHA256 (full app binary):** `1c0c5fdd02ce92ed521729a00218f0f86920211455b1d51fe9a4455a7a3d8262`

## Steps to Reproduce

1. Assign an onboard macro to Left Mouse Button (e.g., rapid-fire: click, 50ms delay, release)
2. Open any application (game, text editor, etc.)
3. Press and **hold** Right Mouse Button
4. While RMB is held, press LMB to fire the macro
5. **Observed:** RMB releases immediately when the macro fires
6. **Expected:** RMB should remain held throughout the macro execution

## Root Cause Analysis

### Bug Location

**Address:** `0x024616` in the application firmware image (file offset `0x14616`)

### Disassembly of the Bug

```arm
; --- BUGGY CODE PATH (macro button write at 0x024616) ---
; r0 points to the macro event structure
; r4 points to the HID report buttons byte (report[0])

024616:  7941    ldrb r1, [r0, #5]    ; r1 = macro_buttons_byte (e.g., 0x01 for LMB)
024618:  7021    strb r1, [r4]        ; report[0] = r1    <-- BUG: OVERWRITES physical state!
02461A:  7980    ldrb r0, [r0, #6]    ; r0 = macro_buttons_extended
02461C:  7060    strb r0, [r4, #1]    ; report[1] = r0    <-- BUG: OVERWRITES physical state!
```

### Why This is Wrong

The physical button processing code (at `0x024652`) correctly uses read-modify-write with OR/AND operations:

```arm
; --- CORRECT CODE PATH (physical button processing at 0x024652) ---
024652:  7820    ldrb r0, [r4]        ; Read current report byte
024654:  4008    ands r0, r1          ; Clear the target bit position
024656:  4310    orrs r0, r2          ; OR-merge the new button state
024658:  7020    strb r0, [r4]        ; Write back (preserves other buttons)
```

The macro path at `0x024616` uses a bare `STRB` (store byte) which **completely replaces** the report byte with only the macro's button state, discarding any physically held buttons.

### Effect on HID Reports

```
Physical state: RMB held     -> report[0] = 0x02
Macro fires LMB:
  BUG:     report[0] = 0x01  (RMB bit lost, host sees RMB released)
  CORRECT: report[0] = 0x03  (both bits preserved, RMB stays held)
```

## Proposed Fix (27 bytes)

The fix redirects the macro button write through a trampoline to a code cave, where it performs a proper OR-merge before storing.

### Patch Details

**Technique:** Replace the 10-byte bug site with a BL (branch-link) to unused flash space (code cave) at `0x025F36`, which performs LDRB + ORRS + STRB for both bytes, then returns.

### Patched Assembly

**At bug site (0x024616) - 10 bytes:**
```arm
024616:  f001 fc8e   bl   0x025F36     ; Call OR-merge trampoline
02461A:  e002        b    0x024622     ; Skip over padding to continue
02461C:  bf00        nop               ; Padding
02461E:  bf00        nop               ; Padding
```

**Code cave at 0x025F36 - 18 bytes:**
```arm
025F36:  7941    ldrb r1, [r0, #5]    ; Load macro buttons
025F38:  7822    ldrb r2, [r4]        ; Load current physical report[0]
025F3A:  4311    orrs r1, r2          ; OR-merge (THE FIX)
025F3C:  7021    strb r1, [r4]        ; Store merged result
025F3E:  7981    ldrb r1, [r0, #6]    ; Load macro buttons extended
025F40:  7862    ldrb r2, [r4, #1]    ; Load current physical report[1]
025F42:  4311    orrs r1, r2          ; OR-merge
025F44:  7061    strb r1, [r4, #1]    ; Store merged result
025F46:  4770    bx   lr              ; Return to caller
```

### Binary Patch (exact bytes to apply)

```
File offset 0x14616 (8 bytes):
  Original: 41 79 21 70 80 79 60 70
  Patched:  01 F0 8E FC 02 E0 00 BF

File offset 0x1461E (2 bytes):
  Original: 60 70
  Patched:  00 BF

File offset 0x15F36 (18 bytes):
  Original: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  Patched:  41 79 22 78 11 43 21 70 81 79 62 78 11 43 61 70 70 47
```

**Total changes: 27 bytes** out of 108,608 bytes in the application image.

### What You Need To Do

1. Apply the 27 bytes above to the application firmware binary
2. Recompute the SHA-256 hash of the patched image
3. Re-sign the MCUboot image with your RSA-2048 private key
4. Release as a firmware update through your standard OTA/upgrade tool

The code cave region at `0x025F36` has been verified as unused (all zeros in the original firmware). No existing functionality is affected.

## Impact

- **Severity:** High (for gamers using onboard macros)
- **Affected users:** Anyone using onboard macros on buttons while simultaneously holding other mouse buttons
- **Common scenario:** FPS gaming - holding RMB (aim/scope) while firing LMB macro (rapid-fire/recoil control)
- **Workaround available:** Host-side AutoHotkey script that blocks spurious button releases (included in our repository)

## Verification Method

After applying the fix, verify with a USB HID monitor:

1. Hold RMB - observe `0x02` in buttons byte
2. Fire LMB macro while holding RMB
3. **Before fix:** buttons byte shows `0x01` (RMB dropped)
4. **After fix:** buttons byte shows `0x03` (both buttons preserved)

## Contact

This bug was identified through independent firmware reverse engineering by the community. We have a working patched binary available but cannot deploy it due to RSA-2048 signature enforcement in the MCUboot bootloader. Only Ajazz/RuiYu can sign the corrected firmware for end-user deployment.

We are happy to provide:
- The complete patched firmware binary for your verification
- An IPS patch file for automated application
- A Python script that applies and verifies the patch
- Full disassembly context around the bug site

## Repository

All technical details, tools, and the workaround script are available at:
https://github.com/b0r1s-69/Test12345
