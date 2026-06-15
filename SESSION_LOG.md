# AJ159 APEX - Session Log

> **UPDATE THIS FILE at the end of every session.**
> Append a new dated entry at the bottom. Do not delete previous entries.
> This is the living record of project state that `CONTEXT_PROMPT.md` references.

---

## ACTIVE LEADS

### 1. SWD Hardware Access (MEDIUM PRIORITY)

**Status:** Not attempted -- requires $5 ST-Link V2 clone

**Concept:** Physical debug port access bypasses all software protections. If APPROTECT is not blown (or can be mass-erased), full read/write access to internal flash.

### 2. Contact Ajazz (FALLBACK)

**Status:** Bug report drafted in `docs/AJAZZ_BUG_REPORT.md`

If all technical paths fail, submit the bug report with full technical details requesting a signed MV303 fix.

---

## BLOCKED PATHS (CONFIRMED DEAD)

| Path | How Killed | Evidence |
|------|-----------|----------|
| NORDICKEYBOARD bypass | Not a separate protocol -- "55 AA" is just the enter-boot command | USB capture decode, confirmed Session 5 |
| ry_upgrade_PATCHED.exe | MCUboot rejects (RSA mismatch) | Direct test via official tool |
| ry_upgrade_HASHONLY.exe | MCUboot rejects (RSA missing) | Direct test via official tool |
| ry_upgrade_NOSIG.exe | MCUboot rejects (RSA missing) | Direct test via official tool |
| Custom flasher with patched image | MCUboot rejects -- mouse stuck in boot, recovered | Direct flash test Session 5 |
| BLE DFU/SMP over BLE | UUID not present in firmware (0xFE59 / SMP UUID absent) | Binary scan of app + BLE images |
| NVS config toggle | No config strings exist -- behavior is hardcoded | Full string dump analysis |
| loophole_flash version tricks | Only controls whether tool sends; device still validates | Tested multiple variants |
| MCUboot trailer forgery | Trailer is OUTPUT of validation, not input | MCUboot source analysis |
| Protected TLV confusion | Circular hash dependency -- impossible | MCUboot source analysis |
| Encryption TLV trick | RSA still checked after decryption | MCUboot source analysis |
| Flash wear-out of key storage | Protocol only writes external SPI, not internal flash | Architecture analysis |
| Bootloader hidden commands | ALL 254 BA XX commands brute-forced -- only BA FF/C0/C2 exist | Hardware test Session 6 (boot_bruteforce.py) |
| BA FF mode byte unlock | All 256 values of byte[7] produce identical response | Hardware test Session 6 |
| TLV manipulation bypass | All 9 variants (empty, SHA-only, wrong magic, etc.) accepted by bootloader but REJECTED by MCUboot at boot | Hardware test Session 6 (tlv_fuzzer.py) |
| RSA key recovery | Vendor-specific 2048-bit key (Ajazz/RuiYu), not a Nordic sample key, not crackable | Key extracted from EXE, KEYHASH confirmed |
| Runtime HID Buffer Overflow Exploitation | Deep static analysis of entire SET_REPORT handler chain -- all memcpy lengths hardcoded (5/6/8 bytes), no user-controlled bulk copy to fixed-size buffer | Session 7 disassembly analysis (fw_analyzer.py) |

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
  probe_reports.py              # HID report probing tool
  boot_bruteforce.py            # Bootloader command brute-force (all 254 BA XX)
  extract_pubkey.py             # RSA public key extractor from EXE
  tlv_fuzzer.py                 # MCUboot TLV variant fuzzer (9 attack variants)
  mouse_capture2.pcap           # USB capture (mouse reports only, no flash protocol)
  mouse_capture3.pcap           # USB capture (FULL flash session with control transfers)
  support_config.json           # Ajazz support tool config (NORDICKEYBOARD entry)
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

### Session 5 -- Protocol Decode & Direct Flash Test
- Captured USB traffic with Wireshark/USBPcap during official tool flash
- Fully decoded the boot protocol (BA/AB commands, Feature Reports, byte-sum checksum)
- Built working custom flasher (`aj159_flasher.py`)
- **Successfully communicated with bootloader** -- all commands worked perfectly
- **Flashed patched image** -- data accepted, checksum verified
- **MCUboot REJECTED** -- RSA-2048 enforcement confirmed by direct test
- Mouse recovered with official tool
- Completed deep exploit analysis -- ranked remaining vectors
- Updated SESSION_LOG with definitive findings

### Session 6 -- Deep Analysis, Hardware Brute-Force, and Definitive Path Closure (CURRENT)

#### PCAP Analysis: mouse_capture2.pcap
- Contains ONLY interrupt transfers (mouse HID reports on EP81)
- No control endpoint traffic -- cannot decode flash protocol from this capture
- Device 5 = normal mode mouse (13-byte reports: buttons + XY + wheel + constant `01a9400000` suffix)
- Device 2 = keyboard interface (Delete, Ctrl+Z, Ctrl+C keypresses)
- 10420 reports captured over ~34.5 seconds

#### PCAP Analysis: mouse_capture3.pcap (FULL FLASH SESSION)
- Contains control transfers with complete flash protocol
- **Device 7 = normal mode** (commands: `8F` get_device_id -> ID=0x06DB, `80` get_version -> v302, `7F` enter_boot with magic 55AA55AA)
- **Device 8 = boot mode** (PID 0x4025, VID 0x3151)
- Full flash session decoded:
  - `BA FF` -> `BA C0` (4711 chunks, 301492 bytes) -> 4711 raw data chunks -> `BA C2` (checksum 0x01D0EC6C) -> `AB C2` response with 48 bytes crypto data
- Boot device USB HID descriptor: Usage Page 0xFF01, 64-byte Feature Report, NO report ID
- HID Report Descriptor: 22 bytes (Usage Page 0xFF01, Usage 1, Collection App, 64-byte Feature report)
- `AB C2` response bytes [4:36] = `556cecd0885c84d082f99d83ac190cc4101b326f61272b9e5153e86835c74b43` (NOT a standard hash of anything computable)
- `AB C2` response bytes [36:52] = `a31925ef40de11637bb4f14e856b76d3` (unknown purpose)
- Checksum verified: byte-sum 0x01D0EC6C matches computed value
- Code SHA-256 confirmed: `1c0c5fdd02ce92ed521729a00218f0f86920211455b1d51fe9a4455a7a3d8262`

#### MCUboot Header Analysis
- Magic: 0x96F3B83D (standard MCUboot magic)
- Load address: 0x10000
- Header size: 512 bytes
- Image size: 108608 bytes
- Flags: 0x20
- Version: 1.0.0+76824442

#### MCUboot TLV Extraction
- SHA256: `9ebf3f5fa567a1372c39b1cd1c3abb21cee190650e35433aaf332c20e4ea75e2`
- KEYHASH: `fc5701dc6135e1323847bdc40f04d2e5bee5833b23c29f93593d00018cfa9994`
- RSA2048 signature: 256 bytes
- Hash covers header(512) + code(108608) = 109120 bytes total. Computed SHA matches TLV SHA.

#### Firmware Binary Analysis (mouse_app_fw.bin)
- File mapping: `memory_address = file_offset + 0x10000`
- Vector table at file offset 0x0020 (memory 0x10020): SP=0x2000E867, Reset=0x23659
- Interrupt dispatch uses Zephyr `sw_isr_table` pattern (RAM-based indirect vectors with trampolines at offset 0x0048+)
- Only 7 meaningful strings found:
  - "In Hard Fault Handler"
  - "controller initializing...."
  - " rcl frequence %d"
  - " goon enable" / "goon disable"
  - "RTL:X.XXX-XX0XX_FIRMWARE:1.00A-LCA01"
  - Register dump strings
- Main command processor at 0x1C1A8: `PUSH {R0-R7, LR}; SUB SP, #60` (60-byte stack frame)
- Config dispatch table at 0x17DDC: handles report IDs 0x04, 0x05, 0x06, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18
- All report IDs dispatch to common handler at 0x21D44 (triggers USB IN transfer)
- Enter-boot check at 0x1C26A: `CMP R4, #0x7F`
- Function at 0x17DA8 called from 36 different locations
- **NO NVMC references** (0x4001E000) anywhere in binary -- app cannot write to internal flash
- **NO USBD peripheral references** in literal pools -- all peripheral access via Zephyr driver abstractions
- **NO BLE DFU UUID** (0xFE59) or SMP UUID found
- PID 0x4025 reference found at memory 0x1F29A
- Flash write for the 27-byte patch REQUIRES page erase (bits need 0->1 transitions)
- Two pages affected: 0x24000-0x24FFF and 0x25000-0x25FFF
- Shellcode requirements: ~150 bytes Thumb-2 + 4KB RAM buffer, cannot fit in single 64-byte report

#### RSA Public Key Extraction
- **FOUND** at EXE offset 0x0119B47F in PKCS#1 format (270 bytes DER)
- Modulus (2048 bits): `d106081a18442c18e8fbfdf70da34f1fbbee5ef9aad24b18d35ae96d188019f9...efb14b2c62e1d1c9`
- Exponent: 65537 (0x010001)
- KEYHASH confirmed: `fc5701dc6135e1323847bdc40f04d2e5bee5833b23c29f93593d00018cfa9994`
- **NOT a Nordic SDK sample key** -- vendor-specific (Ajazz/RuiYu)
- KEYHASH found at 2 locations in EXE: 0x011BD38B (app image TLV) and 0x011EC1AF (BLE image TLV)
- Private key NOT in EXE (as expected)

#### Hardware Brute-Force: Bootloader Command Sweep
- ALL 254 `BA XX` commands (excluding C0/C2) return stale `AB FF` response (`abffdb06000000000000000000000000`)
- Only `BA FF` actually updates the response buffer -- all others are ignored
- **Conclusion: Only 3 commands exist (BA FF, BA C0, BA C2). No hidden commands.**

#### Hardware Brute-Force: BA FF Mode Byte Sweep
- All 256 values of byte[7] produce identical `AB FF` response
- No hidden modes or behaviors discovered
- **Conclusion: Mode byte has no effect on bootloader behavior**

#### Hardware Testing: TLV Fuzzing (9 variants)
- Variants tested:
  1. EMPTY_TLV -- no TLV data at all
  2. SHA256_ONLY -- SHA256 hash but no signature
  3. ZERO_LENGTH_TLV -- TLV header with zero length
  4. NO_TLV_MAGIC -- missing 0x6907 magic
  5. WRONG_TLV_MAGIC -- corrupted magic bytes
  6. SHA256_KEYHASH_NO_RSA -- hash + keyhash, no RSA signature
  7. DUPLICATE_SHA256 -- two SHA256 entries
  8. NULL_RSA -- RSA field filled with zeros
  9. ORIGINAL_TLV_WITH_PATCHED_SHA -- correct structure, wrong SHA for patched code
- **All 9 variants received `BA C2` OK** (data transfer accepted by bootloader)
- **BUT: mouse remained in boot mode (PID 0x4025) between ALL variants**
- This proves MCUboot REJECTED every variant at boot time
- The `BA C2` acceptance only confirms data receipt to SPI flash -- MCUboot validation is separate and non-bypassable

#### Definitive Path Status Summary

**DEAD paths (confirmed by hardware testing):**
| Path | Method of Elimination |
|------|----------------------|
| Bootloader hidden commands | Exhaustive brute-force of all 254 BA XX values |
| BA FF mode byte unlock | All 256 byte values tested, all identical |
| TLV manipulation bypass | 9 structural variants all rejected by MCUboot |
| NORDICKEYBOARD bypass | Confirmed dead Session 5 (just the enter-boot command) |
| RSA key recovery | Vendor-specific 2048-bit key, computationally infeasible |
| BLE DFU/SMP | UUIDs not present in firmware binary |
| NVS config toggle | No config strings exist in firmware |

**ALIVE paths (remaining viable approaches):**
| Path | Feasibility | Notes |
|------|-------------|-------|
| Runtime HID exploitation | Medium | Buffer overflow in SET_REPORT handler at 0x1C1A8, 60-byte stack frame |
| SWD hardware access | High (with hardware) | $5 ST-Link V2 clone required |
| Contact Ajazz for signed MV303 fix | High (slow) | Bug report ready in docs/ |

---

*Next session: Deep disassembly of SET_REPORT handler at 0x1C1A8 to identify buffer overflow vectors, or acquire ST-Link V2 for SWD access*

### Session 7 -- Deep Static Analysis of SET_REPORT Handler Chain (Buffer Overflow Definitively Ruled Out)

#### Overview
Performed comprehensive disassembly analysis of the entire SET_REPORT handler chain using capstone (ARM Thumb-2 disassembler). The goal was to identify any buffer overflow or memory corruption vector that could enable arbitrary code execution via HID SET_REPORT packets.

#### Key Finding: NO Classic Buffer Overflow Exists

**CONFIRMED:** The HID SET_REPORT path contains no exploitable buffer overflow.

Evidence:
1. **All memcpy calls use hardcoded lengths** -- found calls with lengths 5, 6, and 8 bytes maximum. No memcpy uses a user-controlled length parameter.
2. **The only computed-length copy** at 0x19D86 is bounded by a lookup table (max value 3*16 = 48 bytes) and copies within the input buffer itself (not to the stack).
3. **Input bytes are parsed individually** via LDRB (Load Register Byte) from fixed offsets -- there is no bulk copy of user data to any fixed-size stack buffer.
4. **60-byte stack frame at 0x1C1A8** (main SET_REPORT handler) -- never overflowed. All writes to this frame use hardcoded offsets and sizes.
5. **92-byte stack frame at 0x192C0** (dispatch handler) -- never overflowed. Same pattern of individual byte reads from fixed offsets.

#### Handler Chain Analysis

The SET_REPORT processing follows this path:
```
USB HID SET_REPORT (64-byte feature report on vendor interface)
  -> Handler at 0x1C1A8 (PUSH {R0-R7, LR}; SUB SP, #60)
    -> Command dispatch by first byte
      -> 0x192C0 (main dispatch, 92-byte frame)
        -> Individual report handlers (0x04, 0x05, 0x06, 0x13-0x18)
          -> memcpy to 0x14D58 with hardcoded lengths only
```

All data paths verified: no user-controlled length ever reaches memcpy, no bulk copy of input to stack.

#### Binary Patch Verification (Automated)

Used `debug_toolkit/fw_analyzer.py` to programmatically verify the 27-byte patch:

- **BL at 0x24616** correctly targets the code cave at **0x25F36** (verified via BL encoding decode)
- **Code cave region** (0x25F36) was confirmed **all-zeros in original binary** -- no existing code overwritten
- **OR-merge logic** at the code cave correctly:
  - Reads macro button byte (`LDRB R1, [R0, #5]`)
  - Reads current physical report (`LDRB R2, [R4]`)
  - OR-merges them (`ORRS R1, R2`)
  - Writes merged result (`STRB R1, [R4]`)
  - Repeats for report[1] (extended buttons byte)
  - Returns via `BX LR`
- **Register safety confirmed**: Only R1 and R2 used as scratch within the BL call (caller-saved per ARM AAPCS), R4 preserved as expected

#### Implications

The Runtime HID Buffer Overflow exploitation path is now definitively blocked. The firmware's SET_REPORT handler is conservatively written with no exploitable memory safety issues. This eliminates the last known pure-software approach to bypassing MCUboot RSA verification.

Remaining viable paths are hardware-based (SWD debug access) or social (contacting Ajazz for a signed fix).

#### Tools Created
- `debug_toolkit/fw_analyzer.py` -- Standalone reproducible analysis tool that performs all of the above verification automatically and outputs structured JSON results

---

## ANALYSIS TOOLS

| Tool | Location | Purpose |
|------|----------|---------|
| fw_analyzer.py | `debug_toolkit/fw_analyzer.py` | Deep static analysis of SET_REPORT handler chain and automated binary patch verification. Uses capstone for ARM Thumb-2 disassembly. Outputs structured JSON report documenting all memcpy calls, stack frame sizes, and patch correctness. |

---

*Next session: Acquire ST-Link V2 for SWD hardware access, or submit bug report to Ajazz*
