# AJ159 APEX - Macro Button Fix

Fixes the onboard macro playback bug on the **Ajazz AJ159 APEX** gaming mouse where held buttons (like RMB) are released when a macro fires.

## The Problem

When you assign an onboard macro to LMB and hold RMB (e.g., aiming in a game), pressing LMB causes RMB to release. This happens because the firmware **overwrites** the HID buttons byte with macro state instead of OR-merging with physical button state.

## Status

| Approach | Status |
|----------|--------|
| Firmware binary patch (27 bytes) | **READY** - patch built, cannot flash due to RSA |
| Flash via NORDICKEYBOARD loophole | **IN PROGRESS** - method discovered, needs EXE patching |
| Bug report to Ajazz | **READY** - full technical details for their firmware team |

## Continuing This Project

This repository uses a two-file system for AI-assisted session continuity:

- **[`CONTEXT_PROMPT.md`](CONTEXT_PROMPT.md)** - Paste into any AI conversation to get full project context
- **[`SESSION_LOG.md`](SESSION_LOG.md)** - Living document tracking current state, findings, and next steps

See `CONTEXT_PROMPT.md` for instructions on how to pick up where the last session left off.

## The Root Cause

At firmware address `0x024616`, the macro engine uses:
```
STRB r1, [r4]      ; report[0] = macro_buttons (OVERWRITES physical state)
```

The correct approach (used by physical button processing):
```
LDRB r0, [r4]      ; Read current state
ORRS r0, r1        ; OR-merge macro buttons with physical
STRB r0, [r4]      ; Write back (preserves held buttons)
```

## The 27-Byte Fix

A trampoline at the bug site redirects to a code cave that performs proper OR-merge:
- **Bug site (0x024616):** BL to code cave + branch to continue
- **Code cave (0x025F36):** LDRB + ORRS + STRB for both button bytes + BX LR

Total: 27 bytes changed out of 108,608. See [`docs/PATCH_README.md`](docs/PATCH_README.md) for full disassembly.

## Repository Structure

```
CONTEXT_PROMPT.md              # AI session prompt - paste to continue project
SESSION_LOG.md                 # Living session state - updated every session

firmware_patch/                # Binary firmware patch (needs RSA bypass to flash)
  mouse_app_fw.bin               Original application firmware
  mouse_app_fw_PATCHED.bin       Patched firmware with macro fix
  macro_button_fix.ips           IPS patch file
  patch_macro_fix.py             Python patcher script
  repack_firmware.py             Re-embed patched FW into upgrade EXE
  ry_upgrade_PATCHED.exe         Patched upgrade tool (blocked by RSA)

debug_toolkit/                 # USB HID debug and flash tools
  aj159_debug.py                 Main debug tool (monitor/probe/set)
  flash_aj159.py                 Flash attempt script
  bruteforce_boot.py             Boot mode brute-force
  enter_boot.py                  Enter boot mode utility
  probe_deep.py                  Deep device probing
  scan_mouse.py                  Mouse scanner
  requirements.txt               Python dependencies (hidapi)
  99-aj159.rules                 Linux udev rules

loophole_flash/                # NORDICKEYBOARD bypass research
  ry_upgrade.exe                 Upgrade tool (with modified config)
  resources/support_config.json  Config with NORDICKEYBOARD for boot PID
  README.md                      Research notes and next steps

docs/                          # Technical documentation
  AJAZZ_BUG_REPORT.md             Professional bug report for Ajazz
  PATCH_README.md                  Full patch technical details
  FLASH_GUIDE_NO_HARDWARE.md       Flashing instructions
  DEBUG_TOOLKIT.md                 Debug toolkit usage guide
  SESSION_CONTEXT.md               Legacy engineering context
```

## Technical Details

- **Target:** AJ159 APEX firmware MV302 (version 1.0.0+76824442)
- **SHA256:** `1c0c5fdd02ce92ed521729a00218f0f86920211455b1d51fe9a4455a7a3d8262`
- **Platform:** Nordic nRF52840 + Zephyr RTOS + MCUboot
- **Bug location:** `0x024616` (file offset `0x14616`)
- **Fix:** BL trampoline to code cave at `0x025F36`
- **Signature:** MCUboot RSA-2048 (blocks unsigned firmware)

## Why Can't We Just Flash It?

The mouse bootloader (MCUboot) enforces RSA-2048 signature verification. Our patched firmware has a valid SHA-256 hash but we do not have Ajazz's private signing key. Three approaches tried:
1. Remove RSA from image TLV - bootloader rejects
2. Update only SHA-256 - bootloader rejects (stale RSA)
3. NORDICKEYBOARD method - bypasses MCUboot but tool says "does not require upgrade"

The NORDICKEYBOARD loophole bypass is the current focus of research. See [`SESSION_LOG.md`](SESSION_LOG.md) for current status and next steps.

## Safety

- The firmware patch modifies ONLY the macro-to-report code path
- MCUboot swap design means failed flash attempts keep the original firmware
- Your settings, pairing, DPI, and macros are preserved

## Credits

- Protocol research: [attack-shark-x11-driver](https://github.com/HarukaYamamoto0/attack-shark-x11-driver) (MIT)
- Firmware analysis and patch development: community reverse engineering
- Official firmware: [a-jazz.com](https://www.a-jazz.com/en/h-col-141.html)

## Disclaimer

Unofficial community modification. Use at your own risk. Not affiliated with Ajazz, Attack Shark, or RuiYu.
