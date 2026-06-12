# AJ159 APEX — Macro Button Fix (Firmware Patch)

Fixes the onboard macro playback bug on the **Ajazz AJ159 APEX** gaming mouse where held buttons (like RMB) are released when a macro fires.

## The Bug

When a macro fires on LMB, it **overwrites** the entire HID buttons byte instead of OR-merging with physically held buttons. Result: your held RMB drops.

## The Fix

A 27-byte binary patch at address `0x024616` in the application firmware (MV302, v1.0.0). Redirects the macro button-write through a trampoline that properly OR-merges macro buttons with physical button state.

```
Before: report[0] = macro_buttons         (OVERWRITES physical!)
After:  report[0] = macro_buttons | physical_buttons  (MERGES correctly)
```

## Quick Start (No Hardware Debugger Needed)

1. Download one of the patched upgrade tools from `firmware_patch/`
2. Connect mouse via USB cable (wired mode)
3. Close all mouse driver software
4. Run the patched `.exe` on Windows
5. Click upgrade for the mouse

**Try in order:**
| File | Strategy |
|------|----------|
| `ry_upgrade_PATCHED.exe` | SHA256 updated, RSA kept (try first) |
| `ry_upgrade_HASHONLY.exe` | SHA256 + KEYHASH, no RSA |
| `ry_upgrade_NOSIG.exe` | SHA256 only, no RSA |

**Safe:** If the bootloader rejects the image, your mouse keeps the original firmware unchanged.

## What's Preserved After Flashing

- 2.4GHz receiver pairing (stored in separate NVS flash region)
- Bluetooth bonds
- DPI / RGB / sleep settings
- Button remapping
- All radio firmware (untouched)

## Repository Structure

```
firmware_patch/          # Patched upgrade tools + firmware binaries
  ry_upgrade_PATCHED.exe    # Try 1st
  ry_upgrade_HASHONLY.exe   # Try 2nd  
  ry_upgrade_NOSIG.exe      # Try 3rd
  mouse_app_fw.bin          # Original firmware (for reference)
  mouse_app_fw_PATCHED.bin  # Patched firmware binary
  macro_button_fix.ips      # IPS patch file
  patch_macro_fix.py        # Python patcher (recreate from source)
  repack_firmware.py        # Re-embed into EXE

debug_toolkit/           # USB HID debug tools (run on YOUR PC)
  aj159_debug.py            # Main debug tool (list/monitor/probe/set-*)
  requirements.txt          # pip install hidapi
  99-aj159.rules            # Linux udev rules

docs/                    # Technical documentation
  FLASH_GUIDE_NO_HARDWARE.md  # Complete flashing instructions
  PATCH_README.md              # Technical patch details + disassembly
  DEBUG_TOOLKIT.md             # Debug toolkit usage guide
```

## Technical Details

- **Target:** AJ159 APEX firmware MV302 (version 1.0.0+76824442)
- **Platform:** Nordic nRF52 + Zephyr RTOS + MCUboot
- **Sensor:** PixArt PAW3950
- **Bug location:** `0x024616` (file offset `0x14616`)
- **Fix:** BL trampoline to code cave at `0x025F36`
- **Changes:** 27 bytes (9 at bug site + 18 in code cave)

## Safety

- The patch modifies ONLY the macro-to-report code path
- No radio, pairing, sensor, or settings code is touched
- MCUboot swap design means failed upgrades keep old firmware
- The patched EXEs have no Authenticode signature (same as original)
- Version-locked: patcher verifies SHA256 before applying

## Credits

- Protocol reverse engineering: [attack-shark-x11-driver](https://github.com/HarukaYamamoto0/attack-shark-x11-driver) (MIT)
- Firmware analysis and patch: Kiro AI-assisted reverse engineering
- Official firmware source: [a-jazz.com](https://www.a-jazz.com/en/h-col-141.html)

## Disclaimer

This is an unofficial community modification. Use at your own risk. Not affiliated with Ajazz, Attack Shark, or RuiYu.
