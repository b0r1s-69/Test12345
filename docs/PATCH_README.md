# AJ159 APEX Firmware Patch: Macro Button OR-Merge Fix

## The Bug (CONFIRMED via disassembly)

**Location:** `0x024616` in the mouse application firmware (MCUboot image at load address `0x10000`)

**Root cause:** When the macro engine plays back button events, it writes the macro's button byte **directly** to the HID report buffer using `STRB` (store byte), **completely overwriting** whatever physical buttons are currently held.

```
BUG PATH (at 0x024616):
  ldrb r1, [r0, #5]    ; r1 = macro_buttons_byte
  strb r1, [r4]        ; report[0] = macro_buttons  ← OVERWRITES physical!
  ldrb r0, [r0, #6]    ; r0 = macro_buttons_ext
  strb r0, [r4, #1]    ; report[1] = macro_ext      ← OVERWRITES physical!

CORRECT PATH (at 0x024652, used for physical buttons):
  ldrb r0, [r4]        ; read current report byte
  ands r0, mask         ; clear target bit
  orrs r0, new_bit     ; OR-merge the button state
  strb r0, [r4]        ; write back
```

**Effect:** When you hold RMB and fire an LMB macro, the macro path writes `0x01` (LMB only) to report[0], dropping the `0x02` bit (RMB). The host sees RMB released.

---

## The Fix

**Technique:** Trampoline to a code cave. The 10-byte bug site is replaced with a `BL` (branch-link) to a free region at `0x025f36`, which performs the proper OR-merge and returns.

### Patched code:

**At bug site (0x024616):**
```asm
  bl   0x025f36      ; call trampoline (4 bytes)
  b    0x024622      ; skip to exit (2 bytes)
  nop                ; padding (2 bytes)
  nop                ; padding (2 bytes)
```

**Code cave at 0x025f36:**
```asm
  ldrb r1, [r0, #5]  ; macro buttons
  ldrb r2, [r4]      ; current physical report[0]
  orrs r1, r2        ; MERGE (the fix!)
  strb r1, [r4]      ; write merged result
  ldrb r1, [r0, #6]  ; macro buttons ext
  ldrb r2, [r4, #1]  ; current physical report[1]
  orrs r1, r2        ; MERGE
  strb r1, [r4, #1]  ; write merged result
  bx   lr            ; return
```

### Binary diff:
```
File offset 0x14616 (8 bytes):
  BEFORE: 41 79 21 70 80 79 60 70
  AFTER:  01 f0 8e fc 02 e0 00 bf

File offset 0x1461F (1 byte):
  BEFORE: e0
  AFTER:  bf

File offset 0x15F36 (18 bytes):
  BEFORE: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  AFTER:  41 79 22 78 11 43 21 70 81 79 62 78 11 43 61 70 70 47
```

Total: **27 bytes changed** out of 108,608.

---

## Flashing the Patch

### Problem: RSA-2048 Signature

The MCUboot image is **signed with RSA-2048**. The standard `ry_upgrade.exe` tool will **reject** any modified image because the signature no longer matches.

### Options:

#### Option A: SWD/JTAG Flash (Recommended for advanced users)

The nRF52 has an accessible SWD debug port. With a $5 debugger (J-Link, ST-Link, or DAPLink):

1. Connect SWD to the nRF52 inside the mouse (requires opening the shell)
2. Read the full flash as backup: `nrfjprog --readcode backup.hex`
3. Write the patched application at offset 0x10000:
   ```bash
   nrfjprog --program mouse_app_fw_PATCHED.bin --sectorerase --verify --reset \
            --address 0x10000
   ```
4. The bootloader and BLE controller remain untouched.

**Risk:** Low if you have a backup. The bootloader stays intact, so even a bad app image just fails to boot (recoverable via SWD).

#### Option B: Bypass MCUboot signature check

If the MCUboot bootloader on this device has a debug/development mode where signature verification is disabled (check via SWD by reading the bootloader's configuration), you could:
1. Update the SHA256 in the TLV to match the patched image
2. Zero out or remove the RSA signature TLV entry
3. Re-embed in ry_upgrade.exe

This only works if the bootloader was compiled without `MCUBOOT_VALIDATE_PRIMARY_SLOT` or has a hardware-override mechanism.

#### Option C: Sign with the OEM key (not feasible)

Would require Ajazz/RuiYu's private RSA key — not available.

#### Option D: Host-side workaround (no flash needed)

If you cannot open the mouse, a host-side solution (AutoHotkey/evdev script) can intercept the mouse report at the driver level and re-insert the held button state.

---

## Additional Findings (Performance)

### What's already good:
- **No WFI (sleep) in the main loop** — the firmware runs at full polling speed without idle-wait latency
- **Physical button processing uses proper bit-by-bit OR-merge** — no race conditions there
- **Report send is triggered immediately** after button/motion processing (single trigger point at 0x17e00)
- **No unnecessary motion data copies** — sensor X/Y goes straight to report

### Minor observations:
- The physical button processing (7 buttons × 6 instructions = 42 instructions) could theoretically be optimized to ~8 instructions using a single LDRB + AND mask, but the savings (~500ns per report at 64MHz) are negligible vs the 1ms polling interval
- The QDEC (Quadrature Decoder) peripheral at 0x40012000 is referenced — this handles scroll wheel with hardware debouncing (good)
- Firmware uses no encryption (flag 0x20 = RAM_LOAD only)

### The only meaningful bug found: the macro OR-merge issue described above.

---

## Files

| File | Description |
|------|-------------|
| `mouse_app_fw.bin` | Original application firmware (carved from MCUboot image) |
| `mouse_app_fw_PATCHED.bin` | Patched firmware with macro button fix |
| `mouse_app_fw_with_header.bin` | Original with MCUboot header |
| `ble_ctrl_fw.bin` | BLE controller firmware (untouched) |
| `macro_button_fix.ips` | IPS format patch file |
| `patch_macro_fix.py` | Python script to apply the patch |
| `repack_firmware.py` | Script to re-embed in ry_upgrade.exe |

---

## Verification

### Automated Patch Verification (via disassembly)

The patch correctness has been verified programmatically using `debug_toolkit/fw_analyzer.py`:

```bash
python3 debug_toolkit/fw_analyzer.py \
  --original firmware_patch/mouse_app_fw.bin \
  --patched firmware_patch/mouse_app_fw_PATCHED.bin
```

This tool performs:
- Decode of the BL instruction at 0x24616 to confirm it targets the code cave at 0x25F36
- Verification that the code cave region was all-zeros in the original binary (no code overwritten)
- Disassembly of the code cave to confirm OR-merge logic is correctly encoded
- Register usage analysis to confirm only caller-saved registers (R1, R2) are modified
- Full SET_REPORT handler chain analysis confirming no memory safety issues in the firmware

### Hardware Verification (after flashing)

After flashing, test with the debug toolkit:
```bash
python3 aj159_debug.py monitor --vid 0xXXXX --pid 0xYYYY
```

1. Hold RMB → see `0x02` in buttons byte
2. Fire LMB macro while holding RMB → should now see `0x03` (both bits set)
3. Release → `0x00`

Previously step 2 would show `0x01` (RMB dropped). With the patch it shows `0x03`.
