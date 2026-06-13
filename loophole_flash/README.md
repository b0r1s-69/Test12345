# Loophole Flash - NORDICKEYBOARD Method Bypass

## Discovery

The official `ry_upgrade.exe` tool supports multiple firmware update methods. Normally, the AJ159 APEX uses the `MOUSE` method which goes through MCUboot's RSA-2048 signature verification. However, we discovered that the tool also implements a `NORDICKEYBOARD` method that uses a raw Nordic OTA protocol (identified by `55 AA` magic bytes in the packet header).

This protocol appears to bypass MCUboot entirely, writing directly to flash without RSA signature verification.

## What We Did

1. Modified `resources/support_config.json` to change the boot-mode entry for PID `4025` (the AJ159 APEX in boot mode) from method `MOUSE` to `NORDICKEYBOARD`
2. Put the mouse into boot mode
3. Ran the modified `ry_upgrade.exe`

## What Happened

- The tool showed a **completely different UI** compared to the normal MOUSE method
- Display showed: `DEVICE ID:0 / USBV0 / UPGRADE`
- This confirms the NORDICKEYBOARD code path was activated
- However, it reported **"does not require upgrade"**

## Why It Says "Does Not Require Upgrade"

The tool has an internal mapping between upgrade methods and firmware data blobs. When using NORDICKEYBOARD for PID 4025, it:
1. Successfully connects to the device in boot mode
2. Queries the device version via the Nordic OTA protocol
3. Looks for firmware data tagged for NORDICKEYBOARD + this device
4. Finds nothing (because the EXE was built with firmware data only for the MOUSE method for this PID)
5. Concludes "does not require upgrade"

## Remaining Work

To complete the bypass, one of these approaches is needed:

### Option A: Patch the Version Comparison
Find the x86 code in ry_upgrade.exe that compares device version with available firmware version and patch the comparison to always report "upgrade needed."

### Option B: Inject Firmware Data
Find where the EXE stores firmware blobs (likely in a resource section or appended data) and inject our patched firmware tagged for the NORDICKEYBOARD method.

### Option C: Custom Nordic OTA Flasher
Reverse engineer the raw Nordic OTA protocol (55 AA packet format) and write a standalone Python script that:
1. Puts the mouse in boot mode (via vendor HID command)
2. Connects to the boot-mode HID interface
3. Sends firmware data using the Nordic OTA framing (55 AA + length + data + checksum)
4. Reboots the device

### Option D: Force Flash via Existing Code
Patch the EXE to skip the "does not require upgrade" check and proceed directly to the flash routine with our firmware data injected at the expected location.

## Files in This Directory

| File | Description |
|------|-------------|
| `ry_upgrade.exe` | The original upgrade tool (unmodified EXE, modified config) |
| `resources/support_config.json` | Modified config with NORDICKEYBOARD method for boot PID 4025 |
| `README.md` | This file |

## Protocol Details

### Normal MOUSE Method (blocked by RSA)
```
1. Enter Boot Mode (vendor HID command on interface 1)
2. Device re-enumerates with PID 0x4025
3. Get Boot ID
4. Send MCUboot image (header + app + TLV with SHA256 + RSA sig)
5. MCUboot verifies RSA-2048 signature -> REJECTS our modified image
6. Reboot
```

### NORDICKEYBOARD Method (bypasses RSA)
```
1. Enter Boot Mode (vendor HID command on interface 1)
2. Device re-enumerates with PID 0x4025  
3. Tool sends packets with 55 AA magic header
4. Raw Nordic OTA protocol - writes directly to flash
5. No MCUboot signature verification in this path
6. Reboot
```

## How to Continue This Research

If you want to pick up where we left off:

1. Use a PE disassembler (Ghidra, IDA) to open `ry_upgrade.exe`
2. Search for the string "does not require upgrade" (or Chinese equivalent)
3. Find the comparison that leads to this message
4. Trace back to find where firmware version/data is loaded
5. Patch the comparison or inject firmware data

Key search terms in the binary:
- `55 AA` (Nordic OTA magic)
- `NORDICKEYBOARD` (method string)
- `4025` (boot PID)
- Version strings like `1.0.0`
