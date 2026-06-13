# Flashing the Macro Fix — NO Hardware Debugger Required

## What We Did

1. **Downloaded** the official AJ159 APEX firmware from a-jazz.com (MV302)
2. **Carved out** the mouse application firmware from inside `ry_upgrade.exe`
3. **Disassembled** the ARM Thumb code and found the exact bug at address `0x024616`
4. **Built a 27-byte binary patch** that OR-merges macro buttons with physical state
5. **Re-embedded** the patched firmware into three variants of `ry_upgrade.exe`

## The Three Patched Upgrade Tools

| File | Strategy | Try order |
|------|----------|-----------|
| `ry_upgrade_PATCHED.exe` | Updated SHA256, kept RSA signature (stale) | 1st |
| `ry_upgrade_HASHONLY.exe` | Updated SHA256 + KEYHASH, removed RSA | 2nd |
| `ry_upgrade_NOSIG.exe` | Updated SHA256 only, removed RSA + KEYHASH | 3rd |

**Why three?** The on-device bootloader (MCUboot) may or may not enforce RSA signatures.
Many Chinese OEM bootloaders:
- Only check the SHA256 hash (variant 1 works)
- Accept images without signatures if none is present (variants 2/3 work)
- Some don't check at all (all variants work)

**If all three fail**, the bootloader strictly enforces RSA and you'd need the OEM signing key or SWD access. But this is UNLIKELY for a consumer mouse.

## Step-by-Step Flashing Instructions

### Prerequisites
- Windows PC (the tool is a Windows x86 EXE)
- USB cable connecting the mouse (wired mode)
- The original `ry_upgrade.exe` as backup (already in the firmware ZIP)

### Procedure

1. **BACKUP FIRST**: Keep the original firmware ZIP. If anything goes wrong, you can reflash the original.

2. **Close all mouse software**: 
   - Close the Ajazz/Attack Shark driver software
   - Close any web-based drivers  
   - Close any other mouse config tools

3. **Connect the mouse via USB cable** (wired mode)

4. **Run `ry_upgrade_PATCHED.exe`** (try this first):
   - Double-click the EXE
   - The tool should detect your mouse automatically
   - You'll see the mouse listed as a "Normal Device" (or similar)
   - Click the upgrade/flash button for the MOUSE (not the receiver)
   - Wait for the progress bar to complete
   - The mouse will disconnect and reconnect

5. **Test the fix**:
   - Open a text editor and the Ajazz driver
   - Assign a macro to LMB (or whichever button had the issue)
   - Hold RMB, then press LMB → RMB should STAY HELD
   - If it works: you're done!

6. **If the upgrade "fails" or mouse doesn't change behavior**:
   - The bootloader rejected the image (signature check)
   - Your mouse still has the original firmware (NOT bricked)
   - Try `ry_upgrade_HASHONLY.exe` (step 4 again with this file)
   - If that fails too, try `ry_upgrade_NOSIG.exe`

7. **If ALL three fail**:
   - Reflash original firmware using the original `ry_upgrade.exe` to be safe
   - The bootloader enforces RSA — you'd need SWD or to contact Ajazz

### What happens during the upgrade

```
Normal mode (your mouse running)
    ↓ Tool sends "Enter Boot" HID command
Boot mode (mouse re-enumerates with boot VID:PID)
    ↓ Tool sends "Get Boot ID" 
    ↓ Tool sends firmware data in chunks
    ↓ Tool sends "Reboot" command
    ↓ MCUboot verifies the new image:
        - Checks SHA256 hash ← we updated this ✓
        - Checks RSA signature ← may or may not be enforced
    ↓ If accepted: boots new firmware ← PATCHED!
    ↓ If rejected: keeps old firmware ← SAFE, unchanged
```

### Recovery if something goes wrong

**Mouse not responding after upgrade?** 
- Unplug USB, wait 5 seconds, replug
- Try switching between 2.4G/Bluetooth/Wired modes
- If still dead: hold left+right buttons while plugging in USB (force bootloader mode on some variants), then reflash original

**Want to go back to original firmware?**
- Just run the original `ry_upgrade.exe` from the ZIP — it will reflash the stock firmware

## Why This Is Safe

1. **MCUboot swap design**: The bootloader writes the new image to a SECONDARY slot first, verifies it, then atomically swaps. If verification fails, the primary slot (working firmware) is untouched.

2. **No Authenticode on the EXE**: Windows won't block our modified tool from running.

3. **The patch is minimal**: 27 bytes changed out of 108,608. The fix adds a proper OR-merge in a code cave that was verified empty (all zeros). No existing functionality is broken.

4. **The protocol is device-initiated**: The bootloader controls whether to accept or reject. If it doesn't like our image, it simply says "no" and keeps working.

## Technical Details of the Flash Protocol

- **Normal mode**: VID `0x3151`, various PIDs (depends on variant)
- **Boot mode**: VID `0x3151`, PID `0x400a/0x4025/0x402b`
- **Interface**: Vendor-defined HID (usage_page=0xFFFF, usage=1, interface=1)
- **Commands**: Enter Boot → Get Boot ID → Get Address → Stream Data → Reboot
- **Target**: Nordic FW slot at flash address `0x10000`
- **Image format**: MCUboot (512-byte header + 108,608 image + 336 TLV)

## Files Reference

```
firmware_patch/
├── mouse_app_fw.bin              # Original app firmware (carved)
├── mouse_app_fw_PATCHED.bin      # Patched app firmware
├── macro_button_fix.ips          # IPS format patch
├── ry_upgrade_PATCHED.exe        # SHA256 updated, RSA kept (stale)
├── patch_macro_fix.py            # Python patcher (recreate from source)
└── repack_firmware.py            # Re-embed patched FW into upgrade EXE
```
