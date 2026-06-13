# AJ159 APEX - Session Log

> **UPDATE THIS FILE at the end of every session.**
> Append a new dated entry at the bottom. Do not delete previous entries.
> This is the living record of project state that `CONTEXT_PROMPT.md` references.

---

## ACTIVE LEADS

### 1. Runtime HID Buffer Overflow Exploitation (HIGH PRIORITY)

**Status:** Not started — the only remaining pure-software path

**Concept:** The running MV302 firmware processes HID config/macro packets via SET_REPORT on the vendor interface. If a buffer overflow exists in the input parser, we can:
1. Gain arbitrary code execution on the nRF52 (no ASLR, no DEP on Cortex-M)
2. From inside the running firmware, disable APPROTECT and/or patch MCUboot's RSA check in internal flash
3. Then flash normally with our working flasher

**What's needed:**
- Full disassembly of the HID SET_REPORT handler (vendor interface, 64-byte feature reports)
- Identify fixed-size buffers, memcpy without bounds check, or stack smash vectors
- Build exploit payload (ARM Thumb-2 shellcode)

### 2. Quick Protocol Tweaks (LOW PRIORITY — longshots)

**Status:** Not yet tested

- **BA FF mode byte:** Try byte[7] values other than 0x46 — might unlock a no-validation mode
- **SHA256-only TLV:** Build image with ONLY SHA256 TLV (no KEYHASH, no RSA) and flash via our tool
- **Corrupted TLV magic:** Replace 0x6907 with 0x0000 or 0xFFFF — force MCUboot error path
- **App-only flash:** Send just the app image (1711 chunks, 109456 bytes) without BLE image

These are all recoverable (mouse boots old firmware or stays in boot mode for reflash).

### 3. Contact Ajazz (FALLBACK)

**Status:** Bug report drafted in `docs/AJAZZ_BUG_REPORT.md`

If all technical paths fail, submit the bug report with full technical details requesting a signed MV303 fix.

---

## BLOCKED PATHS (CONFIRMED DEAD)

| Path | How Killed | Evidence |
|------|-----------|----------|
| NORDICKEYBOARD bypass | Not a separate protocol — "55 AA" is just the enter-boot command | USB capture decode |
| ry_upgrade_PATCHED.exe | MCUboot rejects (RSA mismatch) | Direct test via official tool |
| ry_upgrade_HASHONLY.exe | MCUboot rejects (RSA missing) | Direct test via official tool |
| ry_upgrade_NOSIG.exe | MCUboot rejects (RSA missing) | Direct test via official tool |
| Custom flasher with patched image | MCUboot rejects — mouse stuck in boot, recovered | Direct flash test Session 5 |
| BLE DFU/SMP over BLE | UUID not present in firmware | Binary scan of app + BLE images |
| NVS config toggle | No config strings exist — behavior is hardcoded | Full string dump analysis |
| loophole_flash version tricks | Only controls whether tool sends; device still validates | Tested multiple variants |
| MCUboot trailer forgery | Trailer is OUTPUT of validation, not input | MCUboot source analysis |
| Protected TLV confusion | Circular hash dependency — impossible | MCUboot source analysis |
| Encryption TLV trick | RSA still checked after decryption | MCUboot source analysis |
| Flash wear-out of key storage | Protocol only writes external SPI, not internal flash | Architecture analysis |

---

## KEY FINDINGS (Session 5 — Protocol Decode & Direct Test)

### Complete Boot Protocol (from USB capture)

**Transport:** HID Feature Reports, Report ID 0x00 (implicit — no report ID in descriptor), 64-byte payloads, SET_REPORT/GET_REPORT on USB control endpoint.

**Normal Mode (PID 0x4026, Interface 2):**
```
Get Device ID:  TX [8F 00 00 00 00 00 00 70 00*56]  → RX [8F DB 06 ...] = ID 1755
Get Version:    TX [80 00 00 00 00 00 00 7F 00*56]  → RX [80 02 03 ...] = v302
Enter Boot:     TX [7F 55 AA 55 AA 00 00 82 00*56]  → device reboots to PID 0x4025
```

**Boot Mode (PID 0x4025, Interface 0):**
```
Get Boot ID:    TX [BA FF 00 00 00 00 00 46 00*56]  → RX [AB FF DB 06 ...]
Init Transfer:  TX [BA C0 <chunks_LE16> <size_LE32> 00*56]  → RX [AB C0 <chunks> ...]
Data Stream:    TX [raw 64-byte chunks] x chunk_count  (no framing)
Complete:       TX [BA C2 <chunks_LE16> <checksum_LE32> <size_LE32> 00*50] → RX [AB C2 ...]
```

**Checksum:** Simple sum of ALL data bytes mod 2^32 (NOT CRC32).

**Data blob:** App MCUboot image (109456B) + 0xFF pad to 128KB + BLE MCUboot image (170420B) = 301492 bytes = 4711 chunks.

**Target:** External SPI flash (secondary slot). MCUboot validates after write, copies to primary if RSA passes.

### Why Our Probe Script Failed

The script used Report IDs 0x7F and 0xF8 as HID report IDs. In reality:
- The HID Report ID is **0x00** (implicit, not in descriptor)
- `0x7F` and `0xF8` are the **first byte of the 64-byte payload** (command bytes)
- `device.read()` returned "read error" because the device has NO input report endpoint — it only uses Feature Reports on the control pipe

### RSA Enforcement Confirmed

Direct test: flashed patched image with correct SHA256 but stale RSA → MCUboot rejected → mouse stuck in boot mode → recovered with official tool. This definitively proves RSA-2048 is enforced, not just SHA256.

---

## REPOSITORY STATE

### Clean file structure:
```
firmware_patch/
  mouse_app_fw.bin              # Original firmware (reference)
  mouse_app_fw_PATCHED.bin      # Patched firmware (27 bytes changed)
  macro_button_fix.ips          # IPS patch file
  patch_macro_fix.py            # Python patcher
  repack_firmware.py            # Repack into EXE
  ry_upgrade_PATCHED.exe        # Patched EXE (SHA256 updated, RSA stale)
  aj159_flasher.py              # Custom Python flasher (WORKING protocol)

debug_toolkit/
  aj159_debug.py                # HID debug/config tool
  scan_mouse.py                 # Device scanner
  requirements.txt              # pip install hidapi
  99-aj159.rules                # Linux udev rules

docs/
  PATCH_README.md               # Technical patch details
  FLASH_GUIDE_NO_HARDWARE.md    # Flashing instructions
  DEBUG_TOOLKIT.md              # Debug toolkit usage
  AJAZZ_BUG_REPORT.md           # Draft bug report for Ajazz

CONTEXT_PROMPT.md               # AI session master prompt
SESSION_LOG.md                  # This file
README.md                       # Project overview
```

---

## SESSION HISTORY

### Session 1 — Initial Discovery and Patch Development
- Identified macro button overwrite bug via disassembly
- Developed 27-byte BL trampoline fix
- Created IPS patch and Python patcher
- Attempted MCUboot flash variants (all rejected)

### Session 2 — Flash Bypass Research
- Discovered NORDICKEYBOARD method in support_config.json
- Modified config — different UI activates but "no upgrade needed"
- Created version-bumped EXEs (all still rejected by device)

### Session 3 — Version Bypass Attempts and Tooling
- Built debug toolkit, AutoHotkey workaround (later removed)
- Wrote Ajazz bug report

### Session 4 — Repository Cleanup
- Removed dead-end files, documented everything
- Created CONTEXT_PROMPT.md and SESSION_LOG.md

### Session 5 — Protocol Decode & Direct Flash Test (CURRENT)
- Captured USB traffic with Wireshark/USBPcap during official tool flash
- Fully decoded the boot protocol (BA/AB commands, Feature Reports, byte-sum checksum)
- Built working custom flasher (`aj159_flasher.py`)
- **Successfully communicated with bootloader** — all commands worked perfectly
- **Flashed patched image** — data accepted, checksum verified
- **MCUboot REJECTED** — RSA-2048 enforcement confirmed by direct test
- Mouse recovered with official tool
- Completed deep exploit analysis — ranked remaining vectors
- Updated SESSION_LOG with definitive findings

---

*Next session: Quick protocol tweaks (BA FF mode bytes, stripped TLVs) then runtime HID exploitation research*
