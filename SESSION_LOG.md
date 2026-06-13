# AJ159 APEX - Session Log

> **UPDATE THIS FILE at the end of every session.**
> Append a new dated entry at the bottom. Do not delete previous entries.
> This is the living record of project state that `CONTEXT_PROMPT.md` references.

---

## LAST SESSION SUMMARY

Completed full reverse engineering of the macro button bug, built a working 27-byte firmware patch, attempted multiple flash methods, and discovered the NORDICKEYBOARD loophole as the most promising path forward. The AutoHotkey host-side workaround was previously implemented but later removed from the repo (deemed unnecessary by the user). Repository was reorganized with proper documentation.

---

## ACTIVE LEADS

### 1. NORDICKEYBOARD Loophole (HIGH PRIORITY)

**Status:** Partially working - code path activates but reports "does not require upgrade"

**What we know:**
- Changing PID 4025's method from `MOUSE` to `NORDICKEYBOARD` in `support_config.json` activates a different UI in `ry_upgrade.exe`
- The tool shows "DEVICE ID:0 / USBV0 / UPGRADE" (different from normal MOUSE UI)
- It reports "does not require upgrade" because no firmware blob is mapped to NORDICKEYBOARD for this device
- The NORDICKEYBOARD method uses 55 AA magic byte headers (raw Nordic OTA)
- This protocol bypasses MCUboot RSA verification entirely

**Next steps:**
- Reverse engineer `ry_upgrade.exe` (Rust + Slint binary) to find where firmware blobs are stored
- Find the version comparison that triggers "does not require upgrade"
- Either inject our firmware data or bypass the version check
- Alternative: write a custom Nordic OTA flasher that speaks the 55 AA protocol directly

### 2. Custom Nordic OTA Flasher (MEDIUM PRIORITY)

**Status:** Not started

**Concept:** Instead of patching the EXE, reverse engineer the raw Nordic OTA protocol and write a standalone Python flasher that sends our patched firmware directly via the 55 AA framing.

**What we need:**
- Capture USB traffic between ry_upgrade.exe and device during a NORDICKEYBOARD flash (need a device that actually uses this method)
- Alternatively, disassemble the NORDICKEYBOARD handler in ry_upgrade.exe to understand packet format
- Implement: enter boot mode -> connect -> send firmware via Nordic OTA -> reboot

### 3. SWD/JTAG Direct Flash (LOW PRIORITY - requires hardware access)

**Status:** Available but requires opening the mouse

**What we know:**
- nRF52840 has SWD debug port
- With a $5 debugger (J-Link, ST-Link, DAPLink), can flash directly to 0x10000
- Bypasses all signature checks
- Risk is low with a flash backup

---

## BLOCKED PATHS

### MCUboot RSA-2048 Signature Bypass (via modified image)

**Status:** DEAD END (without private key or hardware glitching)

**What we tried:**
1. Updated SHA256 only, kept stale RSA signature - bootloader rejects
2. Removed RSA TLV, updated SHA256 + KEYHASH - bootloader rejects
3. Removed both RSA and KEYHASH TLVs - bootloader rejects

**Conclusion:** The on-device MCUboot strictly enforces RSA-2048 signature verification. Cannot bypass through image manipulation alone.

### Version Bump in support_config.json

**Status:** DEAD END

**What we tried:**
- Modified the `usbv` field in support_config.json to force a version mismatch
- Created version-bumped EXEs (v1.0.1)

**Result:** The "does not require upgrade" message persists because the issue is not version comparison - it is that no firmware data exists for the NORDICKEYBOARD method for this device.

---

## OPEN QUESTIONS

1. **Where are firmware blobs stored in ry_upgrade.exe?** Are they in PE resources, appended data, or embedded in the Rust binary's .rodata?
2. **What is the exact 55 AA packet format?** We know the magic bytes but not the full framing (length encoding, sequence numbers, checksum algorithm, chunk size).
3. **Does the nRF52840 in this mouse have APPROTECT enabled?** If not, SWD is trivially accessible. If yes, there are known bypasses (CVE-2020-24659 and similar).
4. **Are there other devices in the RuiYu family that use NORDICKEYBOARD for their primary flash method?** If so, we could capture their traffic to learn the protocol.
5. **Can we find an older firmware version with weaker security?** Maybe an earlier bootloader did not enforce RSA.

---

## DECISIONS MADE

- **AutoHotkey workaround removed** - user decided it was not needed in the repo
- **Focus on NORDICKEYBOARD path** - most promising software-only bypass
- **Firmware patch is FINAL** - the 27-byte fix is correct and complete, only deployment is blocked
- **Repository is public** - all research is open source for community benefit
- **Bug report prepared** - ready to send to Ajazz if the community fix route fails

---

## KEY FINDINGS

### Firmware Analysis
- Bug at 0x024616: STRB overwrites instead of OR-merge
- Fix at 0x025F36: code cave with LDRB+ORRS+STRB for both bytes
- 27 bytes total, verified empty code cave region
- No other significant bugs found in the macro/button processing path
- No WFI in main loop (good - full polling speed)
- Single report send trigger at 0x17E00

### ry_upgrade.exe Analysis
- Rust + Slint GUI application
- Supports ~130 devices via per-chip modules
- Methods: MOUSE, NORDICKEYBOARD, FLASH, YZW, YZW24, BK100, and others
- The NORDICKEYBOARD handler is a completely separate code path from MOUSE
- Version/firmware mapping is internal to the EXE (not just in support_config.json)

### Protocol Knowledge
- Normal mode VID: 0x3151, various PIDs
- Boot mode PID: 0x4025
- Config interface: USB interface 2, feature reports
- Upgrade interface: USB interface 1, vendor HID commands
- Nordic OTA magic: 55 AA prefix on packets
- MCUboot image: 512-byte header + app + TLV (SHA256 + RSA sig)

### Security Posture
- MCUboot RSA-2048 strictly enforced (no debug/dev mode bypass found)
- NORDICKEYBOARD method bypasses MCUboot (writes raw to flash)
- Unknown whether APPROTECT is enabled (affects SWD accessibility)
- No known CVEs specific to this MCUboot build version

---

## SESSION HISTORY

### Session 1 - Initial Discovery and Patch Development
- Identified the macro button overwrite bug via firmware disassembly
- Located bug at 0x024616, developed 27-byte fix using code cave at 0x025F36
- Created IPS patch file and Python patcher script
- Attempted standard MCUboot flash with modified SHA256 - rejected by RSA

### Session 2 - Flash Bypass Research
- Tried multiple MCUboot image modifications (all rejected)
- Discovered NORDICKEYBOARD method in ry_upgrade.exe support_config.json
- Modified config to route PID 4025 through NORDICKEYBOARD
- Confirmed different UI activates but "does not require upgrade"

### Session 3 - Version Bypass Attempts and Tooling
- Created version-bumped EXEs to bypass version check
- Developed debug toolkit (aj159_debug.py and utilities)
- Implemented AutoHotkey host-side workaround
- Wrote professional bug report for Ajazz

### Session 4 - Repository Cleanup
- Removed AutoHotkey workaround (user decision)
- Reorganized repository structure
- Created comprehensive documentation
- Added CONTEXT_PROMPT.md and SESSION_LOG.md for session continuity

---

*Next session: Continue NORDICKEYBOARD exploitation or explore custom Nordic OTA flasher*
