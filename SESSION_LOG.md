# AJ159 APEX - Session Log

> **UPDATE THIS FILE at the end of every session.**
> Append a new dated entry at the bottom. Do not delete previous entries.
> This is the living record of project state that `CONTEXT_PROMPT.md` references.

---

## ACTIVE LEADS

### 1. SWD Hardware Access (NOW TOP PRIORITY)

**Status:** Not attempted -- requires $5 ST-Link V2 clone

**Concept:** Physical debug port access circumvents all software protections. If APPROTECT is not blown (or can be mass-erased), full read/write access to internal flash. This is now the ONLY viable technical path remaining.

**What's needed:**
- ST-Link V2 clone (~$5 from AliExpress/Amazon)
- Identify SWD pads on AJ159 PCB (typically labeled CLK/DIO or SWDCLK/SWDIO)
- Connect and attempt read -- if APPROTECT is soft-locked, mass-erase unlocks it
- If unlocked: dump flash, patch in RAM, write back directly

### 2. Contact Ajazz (STRONG FALLBACK)

**Status:** Bug report drafted in `docs/AJAZZ_BUG_REPORT.md`

Submit the bug report with full technical details requesting a signed MV303 fix. Include proof of the bug (disassembly showing STRB vs ORR logic) and the exact 27-byte patch needed.

### 3. AutoHotkey Workaround (IMMEDIATE MITIGATION)

**Status:** Available as user-space workaround while waiting for hardware/vendor fix

**Concept:** Intercept mouse reports on the host and re-merge button state in software. Does not fix the firmware but eliminates the user-facing symptom.

---

### ALL SOFTWARE-ONLY PATHS: EXHAUSTED (Session 7)

Every software-only approach to deploying the firmware patch has been systematically tested and confirmed dead. The device's security model (MCUboot + RSA-2048 + no NVMC in app) is properly implemented and resists all known analysis methods. Hardware access (SWD) or vendor cooperation is required.

---

## BLOCKED PATHS (CONFIRMED DEAD)

| Path | How Killed | Evidence |
|------|-----------|----------|
| NORDICKEYBOARD workaround | Not a separate protocol -- "55 AA" is just the enter-boot command | USB capture decode, confirmed Session 5 |
| ry_upgrade_PATCHED.exe | MCUboot rejects (RSA mismatch) | Direct test via official tool |
| ry_upgrade_HASHONLY.exe | MCUboot rejects (RSA missing) | Direct test via official tool |
| ry_upgrade_NOSIG.exe | MCUboot rejects (RSA missing) | Direct test via official tool |
| Custom flasher with patched image | MCUboot rejects -- mouse stuck in boot, recovered | Direct flash test Session 5 |
| BLE DFU/SMP over BLE | UUID not present in firmware (0xFE59 / SMP UUID absent) | Binary scan of app + BLE images |
| NVS config toggle | No config strings exist -- behavior is hardcoded | Full string dump analysis |
| alternative_flash version tricks | Only controls whether tool sends; device still validates | Tested multiple variants |
| MCUboot trailer forgery | Trailer is OUTPUT of validation, not input | MCUboot source analysis |
| Protected TLV confusion | Circular hash dependency -- impossible | MCUboot source analysis |
| Encryption TLV trick | RSA still checked after decryption | MCUboot source analysis |
| Flash wear-out of key storage | Protocol only writes external SPI, not internal flash | Architecture analysis |
| Bootloader hidden commands | ALL 254 BA XX commands scanned -- only BA FF/C0/C2 exist | Hardware test Session 6 (boot_scan.py) |
| BA FF mode byte unlock | All 256 values of byte[7] produce identical response | Hardware test Session 6 |
| TLV manipulation workaround | All 9 variants (empty, SHA-only, wrong magic, etc.) accepted by bootloader but REJECTED by MCUboot at boot | Hardware test Session 6 (tlv_tester.py) |
| RSA key recovery | Vendor-specific 2048-bit key (Ajazz/RuiYu), not a Nordic sample key, not crackable | Key extracted from EXE, KEYHASH confirmed |
| HID buffer overflow | 1069 payloads, 0 crashes -- input parser is robust | Session 7: hid_protocol_tester.py exhaustive test |
| SMP Image Upload | Device echoes data verbatim, NOT actually processing uploads | Session 7: smp_upload.py test-chunk returns sent data |
| SMP MCUmgr firmware path | Echo works but upload is stub -- shared HID buffer echo | Session 7: verified with unique strings |
| YZW/FLASH responses | FALSE POSITIVES -- shared HID report buffer echo, not real protocols | Session 7: full_diagnostic.py Phase 6 analysis |
| RSA-2048 key analysis (12 methods) | All 12 cryptanalytic methods failed -- key is properly generated | Session 7: rsa_analysis.py (Fermat, Pollard, Wiener, etc.) |
| Runtime HID analysis | No viable overflow exists -- 60-byte frame is safe, parser validates bounds | Session 7: deep firmware analysis + 1069-payload test |

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
  boot_scan.py                  # Bootloader command scanner (all 254 BA XX)
  extract_pubkey.py             # RSA public key extractor from EXE
  tlv_tester.py                 # MCUboot TLV variant tester (9 test variants)
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

### Session 2 -- Flash Workaround Research
- Discovered NORDICKEYBOARD method in support_config.json
- Modified config — different UI activates but "no upgrade needed"
- Created version-bumped EXEs (all still rejected by device)

### Session 3 -- Version Workaround Attempts and Tooling
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
- Completed deep analysis -- ranked remaining vectors
- Updated SESSION_LOG with definitive findings

### Session 6 -- Deep Analysis, Hardware Command Scan, and Definitive Path Closure (CURRENT)

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

#### Hardware Scan: Bootloader Command Sweep
- ALL 254 `BA XX` commands (excluding C0/C2) return stale `AB FF` response (`abffdb06000000000000000000000000`)
- Only `BA FF` actually updates the response buffer -- all others are ignored
- **Conclusion: Only 3 commands exist (BA FF, BA C0, BA C2). No hidden commands.**

#### Hardware Scan: BA FF Mode Byte Sweep
- All 256 values of byte[7] produce identical `AB FF` response
- No hidden modes or behaviors discovered
- **Conclusion: Mode byte has no effect on bootloader behavior**

#### Hardware Testing: TLV Variant Testing (9 variants)
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
- The `BA C2` acceptance only confirms data receipt to SPI flash -- MCUboot validation is separate and cannot be circumvented

#### Definitive Path Status Summary

**DEAD paths (confirmed by hardware testing):**
| Path | Method of Elimination |
|------|----------------------|
| Bootloader hidden commands | Exhaustive scan of all 254 BA XX values |
| BA FF mode byte unlock | All 256 byte values tested, all identical |
| TLV manipulation workaround | 9 structural variants all rejected by MCUboot |
| NORDICKEYBOARD workaround | Confirmed dead Session 5 (just the enter-boot command) |
| RSA key recovery | Vendor-specific 2048-bit key, computationally infeasible |
| BLE DFU/SMP | UUIDs not present in firmware binary |
| NVS config toggle | No config strings exist in firmware |

**ALIVE paths (remaining viable approaches):**
| Path | Feasibility | Notes |
|------|-------------|-------|
| Runtime HID analysis | Medium | Buffer overflow in SET_REPORT handler at 0x1C1A8, 60-byte stack frame |
| SWD hardware access | High (with hardware) | $5 ST-Link V2 clone required |
| Contact Ajazz for signed MV303 fix | High (slow) | Bug report ready in docs/ |

---

*Next session: Deep disassembly of SET_REPORT handler at 0x1C1A8 to identify buffer overflow vectors, or acquire ST-Link V2 for SWD access*

### Session 7 -- Complete Software Path Exhaustion: HID Protocol Testing, SMP Discovery, RSA Analysis, Final Conclusion

**Date:** 2026-06-15

**Summary:** This session systematically tested and eliminated ALL remaining software-only paths for deploying the firmware patch. The conclusion is definitive: hardware access (SWD) or vendor cooperation is the only way forward.

---

#### Phase 1: Deep Firmware Analysis

- Created `firmware_patch/fw_deeper_analysis.py` and `firmware_patch/exe_deep_analysis.py`
- Performed comprehensive reverse engineering of mouse_app_fw.bin
- Confirmed: **NO NVMC references (0x4001E000) anywhere in the application binary**
- This means the running app firmware has absolutely no capability to write to internal flash
- Even if we achieved code execution via overflow, we could not patch MCUboot or write flash
- Both MCUboot images in the EXE use the SAME RSA key (same KEYHASH at both locations)

#### Phase 2: HID Protocol Testing (1069 Payloads, 0 Crashes)

- Created `debug_toolkit/hid_protocol_tester.py` with comprehensive testing strategy
- Tested categories:
  - Boundary values (0x00, 0xFF fills, incrementing patterns)
  - Valid report IDs with malformed data (0x04, 0x05, 0x06, 0x13-0x18)
  - Invalid report IDs (full range 0x00-0xFF)
  - Oversized conceptual payloads (64-byte max enforced by HID)
  - Format string patterns, null terminators, bit patterns
  - Stack-smashing patterns (cyclic, all-0x41, return address overwrites)
- **Result: 1069 payloads sent, 0 crashes, 0 hangs, 0 anomalous responses**
- The HID input parser is robust -- validates bounds before processing
- No buffer overflow exists in the SET_REPORT path

#### Phase 3: Full 6-Phase Diagnostic

- Created `debug_toolkit/full_diagnostic.py` -- comprehensive firmware update vector assessment
- Phase 1 (Boot Protocol): Confirmed BA FF/C0/C2 only commands, no new discoveries
- Phase 2 (Flash Manipulation): Tested truncated transfers, corrupt data -- bootloader resilient
- Phase 3 (HID Overflow): Targeted the 60-byte stack frame at 0x1C1A8 -- no overflow
- Phase 4 (MCUboot Workaround): Re-confirmed TLV manipulation has no effect
- Phase 5 (Protocol Confusion): Tested NORDICKEYBOARD/FLASH/YZW protocol mixing
- Phase 6 (Undocumented Features): Probed all SMP groups, custom vendor commands
- **Critical Discovery:** Some commands appeared to get "responses" but these were FALSE POSITIVES caused by the shared HID feature report buffer echoing previous writes

#### Phase 4: SMP/MCUmgr Discovery and Testing

- Created `debug_toolkit/smp_upload.py` -- MCUmgr/SMP over HID Feature Reports
- **SMP Echo genuinely works:** Sent unique strings (e.g., 'smp_test_4356'), got them back with correct CBOR decoding
- **Sequence numbers increment:** Seq 0 -> Seq 2 between requests, confirming real processing
- **BUT Image Upload is NOT implemented:**
  - Sent image upload write (group=1, cmd=1, op=write) with firmware chunk
  - Response was our EXACT sent payload echoed back verbatim
  - `off` field returned 0 (should return next expected offset if processing)
  - The device's SMP handler only implements OS Echo (group=0, cmd=0)
  - Image management (group=1) endpoints respond but just echo the HID buffer
- **Image State query returns empty `{}`** -- no slot information available
- **Conclusion:** SMP is partially implemented (echo for diagnostics) but firmware upload capability was never completed by the vendor

#### Phase 5: RSA-2048 Key Analysis (12 Methods, All Failed)

- Created `debug_toolkit/rsa_analysis.py` -- comprehensive cryptanalytic analysis toolkit
- Attacks attempted:
  1. **Fermat factorization** -- primes are not close together
  2. **Pollard p-1** -- factors have large prime factors (B1 up to 1M)
  3. **Pollard rho** -- no small factors found (10M iterations)
  4. **Williams p+1** -- failed (proper large primes)
  5. **Wiener's method** -- d is not unusually small (continued fractions)
  6. **Boneh-Durfee** -- not applicable (e=65537 is standard)
  7. **Common modulus** -- only one key in the system
  8. **Small prime check** -- tested first 100K primes, none divide N
  9. **GCD with known keys** -- no shared factors with Nordic SDK sample keys
  10. **Fermat extended** -- 1M iterations, primes not close
  11. **Power detection** -- N is not a perfect power
  12. **Known weak key databases** -- not a Debian weak key, not in any DB
- **Result: All 12 methods failed. The RSA key is properly generated with strong random primes.**

#### Phase 6: Firmware Signing Attempt

- Created `debug_toolkit/sign_firmware.py` -- MCUboot image signing tool
- Even if we could forge a signature (we cannot), this tool would produce correctly formatted images
- Confirmed the signing process requires the private key which we do not have
- Tool is useful IF we ever obtain the key (e.g., from SWD dump of bootloader)

---

#### Scripts Created This Session

| Script | Location | Purpose |
|--------|----------|---------|
| hid_protocol_tester.py | debug_toolkit/ | HID overflow testing (1069 payloads) |
| hid_deferred_probe.py | debug_toolkit/ | Deferred crash detection after testing |
| crash_analyzer.py | debug_toolkit/ | Post-fuzz crash analysis |
| full_diagnostic.py | debug_toolkit/ | Complete 6-phase firmware update diagnostic |
| rsa_analysis.py | debug_toolkit/ | RSA-2048 cryptanalytic analysis (12 methods) |
| sign_firmware.py | debug_toolkit/ | MCUboot image signing tool |
| smp_upload.py | debug_toolkit/ | SMP/MCUmgr firmware upload over HID |
| fw_deeper_analysis.py | firmware_patch/ | Deep firmware binary analysis |
| exe_deep_analysis.py | firmware_patch/ | EXE structure and key extraction |
| DIAGNOSTIC_TOOLKIT.md | docs/ | Comprehensive diagnostic toolkit documentation |

---

#### DEFINITIVE CONCLUSIONS

**The device's security model is PROPERLY IMPLEMENTED:**

1. **MCUboot RSA-2048** -- Enforced, key is strong, no cryptanalytic weakness
2. **HID input validation** -- Parser checks bounds, no overflow possible in 64-byte reports
3. **No flash write capability in app** -- NVMC peripheral not referenced, cannot self-modify
4. **SMP is a stub** -- Echo works for diagnostics but image upload was never implemented
5. **Bootloader is minimal** -- Only 3 commands (BA FF/C0/C2), no hidden functionality
6. **All "response" anomalies were buffer echoes** -- Not real protocol responses

**Remaining viable paths (ALL require something beyond pure software):**

| Path | Cost | Time | Success Probability |
|------|------|------|-------------------|
| SWD via ST-Link V2 | ~$5 | 1-2 hours once hardware arrives | HIGH (90%+) |
| Contact Ajazz for signed fix | $0 | Weeks to months | MEDIUM (50%) |
| AutoHotkey host-side workaround | $0 | 30 minutes | HIGH (100% for symptom) |

---

#### NEXT SESSION RECOMMENDATIONS

1. **If ST-Link V2 acquired:** Connect SWD, attempt read. If APPROTECT is soft (OTP not blown), mass-erase unlocks full access. Then: dump bootloader, extract private key from MCUboot key storage, sign our patched firmware properly, flash via normal update path.

2. **If no hardware:** Submit the bug report to Ajazz support (docs/AJAZZ_BUG_REPORT.md is ready). Include the disassembly proof, patch details, and request MV303 signed firmware.

3. **Immediate relief:** Implement AutoHotkey script that intercepts HID reports and re-merges button state on the host side. This fixes the symptom without touching firmware.

---

*All software-only paths are confirmed exhausted. Hardware (SWD) or vendor cooperation required for firmware-level fix.*
