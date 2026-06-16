# AJ159 APEX Firmware Deep Analysis Report

**Binary**: `mouse_app_fw.bin` (108608 bytes)
**Architecture**: ARM Cortex-M4F (Thumb-2, Little-endian)
**SoC**: Nordic nRF52840
**RTOS**: Zephyr
**Load Address**: 0x10000
**SHA-256**: `1c0c5fdd02ce92ed521729a00218f0f86920211455b1d51fe9a4455a7a3d8262`

---

## Section 1: Image Structure

- **File size**: 108608 bytes
- **SHA-256**: `1c0c5fdd02ce92ed521729a00218f0f86920211455b1d51fe9a4455a7a3d8262`
- **Expected SHA-256**: `1c0c5fdd02ce92ed521729a00218f0f86920211455b1d51fe9a4455a7a3d8262`
- **SHA-256 match**: YES
- **First 4 bytes**: `70470020` (BX LR; NOP pattern)
- **MCUboot magic present**: NO

### MCUboot Structure (inferred)

This file does NOT contain an MCUboot header. Based on the flasher code
(`aj159_flasher.py`), the full MCUboot image has the following structure:

| Component | Size | Description |
|-----------|------|-------------|
| MCUboot Header | 512 bytes | Magic, version, flags, load addr, image size |
| Application Code | 108608 bytes | This file (mouse_app_fw.bin) |
| TLV Trailer | 336 bytes | SHA-256, RSA-2048 signature, KEYHASH |
| **Full Image** | **109456** bytes | Header + Code + TLV |

### Expected MCUboot Header Fields (from flasher)
- Magic: 0x96F3B83D
- Load Address: 0x00010000
- Header Size: 512 (0x200)
- IMG_SIZE field: 108608
- Security: RSA-2048 signature in TLV

### TLV Trailer Structure (expected)
| TLV Type | Tag | Length | Purpose |
|----------|-----|--------|---------|
| IMAGE_TLV_SHA256 | 0x10 | 32 | SHA-256 of image |
| IMAGE_TLV_RSA2048 | 0x20 | 256 | RSA-2048 signature |
| IMAGE_TLV_KEYHASH | 0x01 | 32 | SHA-256 of public key |

## Section 2: Memory Map

### Address Mapping

```
File offset 0x00000 -> Memory address 0x10000
File offset 0x1A83F -> Memory address 0x2A83F
Formula: memory_addr = file_offset + 0x10000
```

### Memory Layout

| Region | Start | End | Size | Description |
|--------|-------|-----|------|-------------|
| Code | 0x10000 | 0x2A83F | 108608 | Application firmware |
| RAM | 0x20000000 | 0x2000FFFF | 64KB | SRAM (nRF52840 has 256KB total) |
| Stack | ~0x2000E867 | (grows down) | -- | Initial SP from vector table |

### Vector Table (at file offset 0x0020, memory 0x10020)

| # | Vector | Address | Handler (Thumb) |
|---|--------|---------|-----------------|
| 0 | Initial SP | 0x2000E867 | 0x2000E867 (stack top in RAM) |
| 1 | Reset | 0x00023659 | 0x00023658 (Thumb, file offset 0x13658) |
| 2 | NMI | 0x0002346D | 0x0002346C (Thumb, file offset 0x1346C) |
| 3 | HardFault | 0x000233C9 | 0x000233C8 (Thumb, file offset 0x133C8) |
| 4 | MemManage | 0x000233C1 | 0x000233C0 (Thumb, file offset 0x133C0) |
| 5 | BusFault | 0x00010FA1 | 0x00010FA0 (Thumb, file offset 0x00FA0) |
| 6 | UsageFault | 0x00011001 | 0x00011000 (Thumb, file offset 0x01000) |
| 7 | Reserved_7 | 0x00010F75 | 0x00010F74 (Thumb, file offset 0x00F74) |
| 8 | Reserved_8 | 0x00010F69 | 0x00010F68 (Thumb, file offset 0x00F68) |
| 9 | Reserved_9 | 0x00016FE5 | 0x00016FE4 (Thumb, file offset 0x06FE4) |
| 10 | Reserved_10 | 0x00023781 | 0x00023780 (Thumb, file offset 0x13780) |
| 11 | SVCall | 0x4801B403 | 0x4801B402 (suspicious - may be literal pool data) |
| 12 | DebugMon | 0xBD019001 | 0xBD019000 (suspicious - may be literal pool data) |
| 13 | Reserved_13 | 0x2000EFD5 | 0x2000EFD4 |
| 14 | PendSV | 0x4801B403 | 0x4801B402 (suspicious - may be literal pool data) |
| 15 | SysTick | 0xBD019001 | 0xBD019000 (suspicious - may be literal pool data) |

**Note**: Vectors 11-15 contain values that look like literal pool data
(0x4801B403, 0xBD019001, etc.), suggesting the vector table may be
partially overwritten or these are Zephyr RTOS ISR stubs.

## Section 3: Function Enumeration

**Total function prologues found**: 510

- Narrow PUSH {..., LR}: 510
- Wide PUSH.W {..., LR}: 0

### Top 20 Largest Functions (by distance to next prologue)

| # | Address | Size (bytes) | Registers Saved |
|---|---------|--------------|-----------------|
| 1 | 0x262D0 | 6480 | r1, r4, lr |
| 2 | 0x192C0 | 3208 | r0, r1, r2, r3, r4, r5, r6, r7, lr |
| 3 | 0x1DA64 | 2800 | r4, r5, r6, r7, lr |
| 4 | 0x2800C | 2616 | r4, r5, r6, r7, lr |
| 5 | 0x131E0 | 2360 | r0, r1, r2, r4, r5, r6, r7, lr |
| 6 | 0x12C38 | 1448 | r4, r5, r6, r7, lr |
| 7 | 0x12304 | 1400 | r0, r1, r2, r4, r5, r6, r7, lr |
| 8 | 0x28BBE | 1214 | r4, r5, r6, r7, lr |
| 9 | 0x23850 | 1118 | r3, r4, r5, r6, r7, lr |
| 10 | 0x15A58 | 1116 | r4, r5, r6, r7, lr |
| 11 | 0x108B8 | 1064 | r0, r1, r2, r3, r4, r5, r6, r7, lr |
| 12 | 0x25ECA | 1014 | r4, lr |
| 13 | 0x20A28 | 976 | r4, r5, r6, r7, lr |
| 14 | 0x242A2 | 902 | r0, r1, r2, r3, r4, r5, r6, r7, lr |
| 15 | 0x2A448 | 886 | r4, r5, r6, r7, lr |
| 16 | 0x254FC | 860 | r3, r4, r5, r6, r7, lr |
| 17 | 0x21120 | 844 | r0, r1, r2, r4, r5, r6, r7, lr |
| 18 | 0x141C8 | 836 | r0, r1, r2, r3, r4, r5, r6, r7, lr |
| 19 | 0x11FD4 | 816 | r0, r1, r2, r3, r4, r5, r6, r7, lr |
| 20 | 0x216C4 | 760 | r0, r1, r2, r3, r4, r5, r6, r7, lr |

### Key Known Functions

| Address | Description | Size Est. |
|---------|-------------|-----------|
| 0x1C1A8 | SET_REPORT handler (main HID processor) | 336 bytes |
| 0x17DDC | Config dispatch table | (not at prologue boundary) |
| 0x14D58 | memcpy implementation | (not at prologue boundary) |
| 0x17DA8 | Multi-caller function (36 call sites) | 328 bytes |
| 0x21D44 | Common report handler | (not at prologue boundary) |

### Function Distribution by Memory Region

- 0x10000-0x14000: 66 functions
- 0x14000-0x18000: 86 functions
- 0x18000-0x1C000: 111 functions
- 0x1C000-0x20000: 95 functions
- 0x20000-0x24000: 70 functions
- 0x24000-0x2B000: 82 functions

## Section 4: String Cross-References

**Total strings found (>= 6 chars)**: 322

**Meaningful strings after filtering**: 320

### All Meaningful Strings

| File Offset | Memory Addr | String |
|-------------|-------------|--------|
| 0x0040D | 0x1040D | `$!CAq5!` |
| 0x004A6 | 0x104A6 | ``!HCd!` |
| 0x004EE | 0x104EE | `0!HCd!` |
| 0x00778 | 0x10778 | `In Hard Fault Handler` |
| 0x0088E | 0x1088E | `yA&FnC` |
| 0x00955 | 0x10955 | `"QC09@` |
| 0x00D45 | 0x10D45 | `k!F0h*F` |
| 0x01502 | 0x11502 | `)HDX'F` |
| 0x0152A | 0x1152A | `Ab'F`mT7` |
| 0x0153B | 0x1153B | ` 8` FX0` |
| 0x0163A | 0x1163A | `'J8 `CA` |
| 0x01761 | 0x11761 | `X `(Fp` |
| 0x018AB | 0x118AB | `%* )FACLH` |
| 0x018CE | 0x118CE | `* ECDH)` |
| 0x01929 | 0x11929 | `F*0*1[` |
| 0x01938 | 0x11938 | `+M`F*!hpHC(N` |
| 0x0194E | 0x1194E | `hx*"PC` |
| 0x01960 | 0x11960 | `hx*!HC` |
| 0x0199E | 0x1199E | `hx*!AC` |
| 0x01A2B | 0x11A2B | `] F`0!` |
| 0x01AED | 0x11AED | ` pb0u!` |
| 0x0234F | 0x1234F | `ujFQw<F` |
| 0x0237C | 0x1237C | `(!"FJC` |
| 0x0239C | 0x1239C | `8 !FAC` |
| 0x0244A | 0x1244A | `8 1FAC` |
| 0x026C9 | 0x126C9 | `ra{Aq!{` |
| 0x02721 | 0x12721 | `{ w("!F` |
| 0x02B24 | 0x12B24 | `.F 60{` |
| 0x02B63 | 0x12B63 | ` .t/Oht` |
| 0x032F9 | 0x132F9 | `Y&F 6py` |
| 0x03309 | 0x13309 | `q`z w!F` |
| 0x03333 | 0x13333 | `D68@B=` |
| 0x034EE | 0x134EE | `]MQCiC2v` |
| 0x03616 | 0x13616 | `2F#Ft2@` |
| 0x0368D | 0x1368D | `t0F 0]` |
| 0x037B4 | 0x137B4 | `@!@jGh0{` |
| 0x0388E | 0x1388E | `Aqamry` |
| 0x03C4F | 0x13C4F | `1Hw9Y`1` |
| 0x03DED | 0x13DED | `zht Fp` |
| 0x04114 | 0x14114 | `!F8\,1B` |
| 0x0414A | 0x1414A | ` Fy\,0I` |
| 0x044AE | 0x144AE | `)h@{Ih@` |
| 0x044EA | 0x144EA | `(h@h(`G` |
| 0x04A80 | 0x14A80 | `` DR% ` |
| 0x04BA1 | 0x14BA1 | `U F 0B~` |
| 0x04C0F | 0x14C0F | `Ca`bhx!` |
| 0x04E53 | 0x14E53 | ``IhA`pG` |
| 0x04F75 | 0x14F75 | ` @60ws"` |
| 0x04F89 | 0x14F89 | ` 0u2H'F` |
| 0x05241 | 0x15241 | ` FQ F,0` |

### String References (PC-relative LDR)

- No direct literal pool references found (strings may be accessed via ADR or other means)

## Section 5: SET_REPORT Handler Deep Disassembly

**Address**: 0x1C1A8 (file offset 0xC1A8)

### Stack Frame

```
PUSH {R0-R7, LR}  ; saves 9 registers = 36 bytes
SUB SP, #0x3C      ; allocates 60 bytes of local storage
Total stack frame: 36 + 60 = 96 bytes

Stack layout (after prologue):
  SP+0x00 to SP+0x3B : local variables (60 bytes)
  SP+0x3C to SP+0x5F : saved R0-R7, LR (36 bytes)

Pre-prologue parameters (accessed via adjusted SP):
  [SP+0x74] -> R4 (parameter from caller)
  [SP+0x78] -> R7 (parameter from caller)
  [SP+0x88] -> R6 (parameter from caller)
  [SP+0x3C] -> R0 copy (the saved R0 = report ID)
```

### Full Disassembly

```asm
  0x1C1A8: push     {r0, r1, r2, r3, r4, r5, r6, r7, lr}  ; ENTRY POINT
  0x1C1AA: sub      sp, #0x3c
  0x1C1AC: mov      r5, r1
  0x1C1AE: movs     r0, #0
  0x1C1B0: mov      r1, sp
  0x1C1B2: ldr      r7, [sp, #0x78]
  0x1C1B4: ldr      r6, [sp, #0x88]
  0x1C1B6: ldr      r4, [sp, #0x74]
  0x1C1B8: strb     r0, [r1]
  0x1C1BA: strb     r0, [r1, #4]
  0x1C1BC: ldr      r0, [sp, #0x3c]
  0x1C1BE: cmp      r0, #0xef  ; bounds check: report_id <= 0xEF?
  0x1C1C0: bls      #0x1c1c8
  0x1C1C2: movs     r0, #0x30  ; ERROR: return 0x30
  0x1C1C4: add      sp, #0x4c
  0x1C1C6: pop      {r4, r5, r6, r7, pc}
  0x1C1C8: ldr      r1, [sp, #0x44]
  0x1C1CA: ldr      r2, [pc, #0x124]
  0x1C1CC: subs     r1, #0x20
  0x1C1CE: cmp      r1, r2
  0x1C1D0: bhi      #0x1c1d6
  0x1C1D2: movs     r3, #1
  0x1C1D4: b        #0x1c1d8
  0x1C1D6: movs     r3, #0
  0x1C1D8: ldr      r0, [sp, #0x48]
  0x1C1DA: subs     r0, #0x20
  0x1C1DC: cmp      r0, r2
  0x1C1DE: bhi      #0x1c1f6
  0x1C1E0: cmp      r3, #0
  0x1C1E2: beq      #0x1c1f6
  0x1C1E4: lsls     r2, r5, #0x1d
  0x1C1E6: bpl      #0x1c1ec
  0x1C1E8: lsls     r2, r5, #0x1c
  0x1C1EA: bmi      #0x1c206
  0x1C1EC: ldr      r2, [pc, #0x104]
  0x1C1EE: cmp      r1, r2
  0x1C1F0: bhi      #0x1c1fc
  0x1C1F2: movs     r1, #1
  0x1C1F4: b        #0x1c1fe
  0x1C1F6: movs     r0, #0x12
  0x1C1F8: add      sp, #0x4c
  0x1C1FA: pop      {r4, r5, r6, r7, pc}
  0x1C1FC: movs     r1, #0
  0x1C1FE: cmp      r0, r2
  0x1C200: bhi      #0x1c25c
  0x1C202: cmp      r1, #0
  0x1C204: beq      #0x1c25c
  0x1C206: ldr      r1, [sp, #0x48]
  0x1C208: ldr      r0, [sp, #0x44]
  0x1C20A: cmp      r0, r1
  0x1C20C: bhi      #0x1c1f6
  0x1C20E: ldr      r0, [sp, #0x60]
  0x1C210: lsls     r0, r0, #0x1d
  0x1C212: beq      #0x1c1c2
  0x1C214: lsls     r0, r5, #0x1a
  0x1C216: bmi      #0x1c21e
  0x1C218: ldr      r0, [sp, #0x64]
  0x1C21A: cmp      r0, #3
  0x1C21C: bhi      #0x1c1c2
  0x1C21E: lsls     r0, r5, #0x1d
  0x1C220: bpl      #0x1c228
  0x1C222: ldr      r0, [sp, #0x68]
  0x1C224: cmp      r0, #1
  0x1C226: bhi      #0x1c1c2
  0x1C228: cmp      r7, #1
  0x1C22A: beq      #0x1c230
  0x1C22C: cmp      r7, #3
  0x1C22E: bne      #0x1c1c2
  0x1C230: ldr      r0, [sp, #0x80]
  0x1C232: subs     r0, r0, #1
  0x1C234: cmp      r0, #3
  0x1C236: bhs      #0x1c1c2
  0x1C238: ldr      r0, [sp, #0x84]
  0x1C23A: cmp      r0, #0xf
  0x1C23C: bhi      #0x1c1c2
  0x1C23E: cmp      r6, #0
  0x1C240: beq      #0x1c246
  0x1C242: cmp      r6, #1
  0x1C244: bne      #0x1c1c2
  0x1C246: add      r1, sp, #4
```

### Branch Targets

| From | Target | Condition |
|------|--------|-----------|
| 0x1C1C0 | 0x1C1C8 | bls |
| 0x1C1D0 | 0x1C1D6 | bhi |
| 0x1C1D4 | 0x1C1D8 | b |
| 0x1C1DE | 0x1C1F6 | bhi |
| 0x1C1E2 | 0x1C1F6 | beq |
| 0x1C1E6 | 0x1C1EC | bpl |
| 0x1C1EA | 0x1C206 | bmi |
| 0x1C1F0 | 0x1C1FC | bhi |
| 0x1C1F4 | 0x1C1FE | b |
| 0x1C200 | 0x1C25C | bhi |
| 0x1C204 | 0x1C25C | beq |
| 0x1C20C | 0x1C1F6 | bhi |
| 0x1C212 | 0x1C1C2 | beq |
| 0x1C216 | 0x1C21E | bmi |
| 0x1C21C | 0x1C1C2 | bhi |
| 0x1C220 | 0x1C228 | bpl |
| 0x1C226 | 0x1C1C2 | bhi |
| 0x1C22A | 0x1C230 | beq |
| 0x1C22E | 0x1C1C2 | bne |
| 0x1C236 | 0x1C1C2 | bhs |
| 0x1C23C | 0x1C1C2 | bhi |
| 0x1C240 | 0x1C246 | beq |
| 0x1C244 | 0x1C1C2 | bne |

### Function Calls (BL)

| Call Site | Target | Notes |
|-----------|--------|-------|

### Comparisons (Input Validation)

| Address | Comparison | Purpose |
|---------|------------|---------|
| 0x1C1BE | CMP r0, #0xef | Report ID bounds check (must be <= 0xEF) |
| 0x1C1CE | CMP r1, r2 |  |
| 0x1C1DC | CMP r0, r2 |  |
| 0x1C1E0 | CMP r3, #0 |  |
| 0x1C1EE | CMP r1, r2 |  |
| 0x1C1FE | CMP r0, r2 |  |
| 0x1C202 | CMP r1, #0 |  |
| 0x1C20A | CMP r0, r1 |  |
| 0x1C21A | CMP r0, #3 |  |
| 0x1C224 | CMP r0, #1 |  |
| 0x1C228 | CMP r7, #1 |  |
| 0x1C22C | CMP r7, #3 |  |
| 0x1C234 | CMP r0, #3 |  |
| 0x1C23A | CMP r0, #0xf |  |
| 0x1C23E | CMP r6, #0 |  |
| 0x1C242 | CMP r6, #1 |  |

### Stack Accesses

| Address | Operation | Operands |
|---------|-----------|----------|
| 0x1C1B2 | ldr | r7, [sp, #0x78] |
| 0x1C1B4 | ldr | r6, [sp, #0x88] |
| 0x1C1B6 | ldr | r4, [sp, #0x74] |
| 0x1C1BC | ldr | r0, [sp, #0x3c] |
| 0x1C1C8 | ldr | r1, [sp, #0x44] |
| 0x1C1D8 | ldr | r0, [sp, #0x48] |
| 0x1C206 | ldr | r1, [sp, #0x48] |
| 0x1C208 | ldr | r0, [sp, #0x44] |
| 0x1C20E | ldr | r0, [sp, #0x60] |
| 0x1C218 | ldr | r0, [sp, #0x64] |
| 0x1C222 | ldr | r0, [sp, #0x68] |
| 0x1C230 | ldr | r0, [sp, #0x80] |
| 0x1C238 | ldr | r0, [sp, #0x84] |

## Section 6: Call Graph

Starting from SET_REPORT handler at 0x1C1A8

### Level 1: Direct calls from 0x1C1A8

```
```

### Level 2: Calls from level-1 functions

### Level 3: Calls from level-2 functions (key targets only)

### Callers of SET_REPORT handler (0x1C1A8)

- Called from 0x19AB4

## Section 7: Buffer Operation Analysis

### memcpy function at 0x14D58

```asm
; Custom byte-copy memcpy implementation
  0x14D58: push     {r4}
  0x14D5A: cmp      r2, #0
  0x14D5C: beq      #0x14d8a
  0x14D5E: subs     r3, r0, #1
  0x14D60: subs     r1, r1, #1
  0x14D62: lsls     r4, r2, #0x1f
  0x14D64: beq      #0x14d6e
  0x14D66: ldrb     r4, [r1, #1]
  0x14D68: strb     r4, [r3, #1]
  0x14D6A: adds     r1, r1, #1
  0x14D6C: adds     r3, r3, #1
  0x14D6E: lsrs     r2, r2, #1
  0x14D70: lsls     r2, r2, #0x18
  0x14D72: lsrs     r2, r2, #0x18
  0x14D74: beq      #0x14d8a
  0x14D76: ldrb     r4, [r1, #1]
  0x14D78: strb     r4, [r3, #1]
  0x14D7A: ldrb     r4, [r1, #2]
  0x14D7C: subs     r2, r2, #1
  0x14D7E: strb     r4, [r3, #2]
  0x14D80: adds     r1, r1, #2
  0x14D82: adds     r3, r3, #2
  0x14D84: lsls     r2, r2, #0x18
  0x14D86: lsrs     r2, r2, #0x18
  0x14D88: bne      #0x14d76
```

**Analysis**: This is a custom memcpy that copies R2 bytes from R1 to R0.
It handles the last bit separately (odd/even length optimization).

### All call sites to memcpy (0x14D58)

**Total call sites**: 176

| # | Call Site | Context (preceding instructions) | Length (R2) |
|---|-----------|----------------------------------|-------------|
| 1 | 0x11620 | beq #0x1169c; ldr r0, [pc, #0xc0]; movs r2, #0x10; | 0x10 (16) |
| 2 | 0x1195C |  | unknown |
| 3 | 0x1199A | ldr r7, [pc, #0x50]; movs r2, #6; adds r0, r0, r7; | 0x06 (6) |
| 4 | 0x11C02 | bl #0x14e5a; movs r2, #0x10; mov r1, r6; mov r0, r | 0x10 (16) |
| 5 | 0x1250A | ldrb r1, [r0, #6]; ldr r0, [sp, #4]; movs r2, #6;  | 0x06 (6) |
| 6 | 0x125DA | bne #0x1262e; b #0x12556; movs r2, #0x28; add r1,  | 0x28 (40) |
| 7 | 0x1272A | ldrb r0, [r0, #0xc]; strb r0, [r4, #0x1c]; movs r2 | 0x28 (40) |
| 8 | 0x1278C | ldr r2, [sp, #0xdc]; adds r1, r1, r0; ldr r0, [sp, | from memory (r2, [sp, #0xdc]) |
| 9 | 0x12DD4 | strh r1, [r2, r0]; ldr r0, [r0, #0x3c]; mov r2, r6 | 0x46 (70) |
| 10 | 0x13316 | strb r0, [r4, #0x1c]; mov r1, r4; adds r1, #0xc; s | unknown |
| 11 | 0x135D8 | bne #0x136c8; mov r1, r4; movs r2, #6; adds r1, #0 | 0x06 (6) |
| 12 | 0x136E8 | adds r0, r2, #4; cmp r2, r0; bhi #0x137e0; movs r2 | 0x06 (6) |
| 13 | 0x13702 | b #0x13706; mov r1, r4; movs r2, #6; adds r1, #0x6 | 0x06 (6) |
| 14 | 0x138B6 | cmp r1, r0; bhi #0x139ac; movs r2, #6; mov r1, r3; | 0x06 (6) |
| 15 | 0x13A1E | movs r5, #0x1f; b #0x13b10; movs r2, #6; mov r1, r | 0x06 (6) |
| 16 | 0x13D3E | mov r0, r4; adds r0, #0xc; movs r2, #0x30; ldr r1, | 0x30 (48) |
| 17 | 0x13D78 | strb r0, [r4, #9]; mov r1, r4; movs r2, #6; adds r | 0x06 (6) |
| 18 | 0x13DE4 | cmp r0, #0; beq #0x13df4; movs r2, #0xc; mov r1, r | 0x0C (12) |
| 19 | 0x13E52 | movs r4, #0xc; b #0x13e56; movs r2, #6; mov r1, r5 | 0x06 (6) |
| 20 | 0x13F24 | movs r4, #0xc; b #0x13f28; movs r2, #6; mov r1, r5 | 0x06 (6) |
| 21 | 0x1406E | strh r0, [r5, #0xa]; ldr r1, [r5]; ldrh r2, [r5, # | unknown |
| 22 | 0x14194 | ldr r2, [r0]; adds r3, r2, r1; ldrh r2, [r0, #0xc] | from memory (r2, [r0]) |
| 23 | 0x14222 | ldr r0, [r5]; ldr r1, [r0]; ldr r0, [sp, #4]; adds | unknown |
| 24 | 0x144C6 | ldr r1, [r1, #4]; ldr r2, [r1]; adds r0, r2, r0; l | from memory (r2, [r1]) |
| 25 | 0x14A7A | strh r1, [r2, r0]; ldr r0, [r0, #0x54]; mov r2, r4 | 0x5E (94) |
| 26 | 0x14FC0 | mov r1, r4; mov r0, r4; movs r2, #8; adds r1, #0x9 | 0x08 (8) |
| 27 | 0x15184 | bl #0x14e5a; movs r2, #5; mov r1, r4; mov r0, sp;  | 0x05 (5) |
| 28 | 0x1525C | mov r0, r4; movs r2, #5; ldr r1, [pc, #0x7c]; adds | 0x05 (5) |
| 29 | 0x152C8 | bl #0x17850; movs r2, #0x38; mov r1, r4; mov r0, r | 0x38 (56) |
| 30 | 0x154F8 | cmp r1, #0; beq #0x15500; movs r2, #5; mov r0, r4; | 0x05 (5) |
| 31 | 0x155C6 | movs r2, #6; adds r0, r0, r1; str r0, [r4, #8]; mo | 0x06 (6) |
| 32 | 0x15DA8 | bl #0x14e5a; movs r2, #5; mov r1, r5; mov r0, sp;  | 0x05 (5) |
| 33 | 0x15E0C | cmp r1, r0; bls #0x15d5a; movs r2, #5; add r0, sp, | 0x05 (5) |
| 34 | 0x15ED0 | bl #0x14d8e; movs r2, #5; ldr r1, [pc, #0xb8]; ldr | 0x05 (5) |
| 35 | 0x160E2 | adds r6, #0x80; str r5, [r6, #0x34]; movs r2, #0x3 | 0x38 (56) |
| 36 | 0x1631C | beq #0x163de; ldr r4, [pc, #0xcc]; movs r2, #5; ad | 0x05 (5) |
| 37 | 0x164EA | bl #0x14e5a; movs r2, #6; ldr r1, [pc, #0xc]; mov  | 0x06 (6) |
| 38 | 0x16592 | bl #0x14e5a; movs r2, #8; ldr r1, [pc, #0xc]; mov  | 0x08 (8) |
| 39 | 0x165B6 | bl #0x14e5a; movs r2, #5; ldr r1, [pc, #0xc]; mov  | 0x05 (5) |
| 40 | 0x165DA | bl #0x14e5a; movs r2, #8; ldr r1, [pc, #0xc]; mov  | 0x08 (8) |

### Potentially Dangerous Copies

Copies where length >= 60 bytes (stack frame size) or length from user input:

- **0x12DD4**: copies 70 bytes (>= stack frame of 60)
- **0x14A7A**: copies 94 bytes (>= stack frame of 60)
- **0x1677A**: copies 64 bytes (>= stack frame of 60)
- **0x1E4F0**: copies 115 bytes (>= stack frame of 60)
- **0x1EC4C**: copies 115 bytes (>= stack frame of 60)

## Section 8: Report ID Dispatch

### Config Dispatch at 0x17DDC

```asm
  0x17DDC: cmp      r0, #4  ; REPORT_04
  0x17DDE: beq      #0x17e00
  0x17DE0: cmp      r0, #5  ; REPORT_05
  0x17DE2: beq      #0x17e00
  0x17DE4: cmp      r0, #6  ; REPORT_06
  0x17DE6: beq      #0x17e00
  0x17DE8: cmp      r0, #0x17  ; REPORT_17
  0x17DEA: beq      #0x17e00
  0x17DEC: cmp      r0, #0x18  ; REPORT_18
  0x17DEE: beq      #0x17e00
  0x17DF0: cmp      r0, #0x13  ; REPORT_13
  0x17DF2: beq      #0x17e00
  0x17DF4: cmp      r0, #0x14  ; REPORT_14
  0x17DF6: beq      #0x17e00
  0x17DF8: cmp      r0, #0x15  ; REPORT_15
  0x17DFA: beq      #0x17e00
  0x17DFC: cmp      r0, #0x16  ; REPORT_16
  0x17DFE: bne      #0x17e04
  0x17E00: bl       #0x21d44  ; -> common_handler
  0x17E04: ldrb     r0, [r4, #0x17]
  0x17E06: cmp      r0, #1
  0x17E08: bne      #0x17e16
  0x17E0A: movs     r0, #1
  0x17E0C: bl       #0x16c44
  0x17E10: ldrb     r0, [r4, #0x17]
  0x17E12: cmp      r0, #1
  0x17E14: beq      #0x17e0a
  0x17E16: mov      r4, r7
  0x17E18: adds     r4, #0x40
  0x17E1A: ldrb     r0, [r4, #0x18]
  0x17E1C: movs     r6, #0
  0x17E1E: cmp      r0, #0x17  ; REPORT_17
  0x17E20: beq      #0x17e26
  0x17E22: cmp      r0, #0x13  ; REPORT_13
  0x17E24: bne      #0x17e40
  0x17E26: ldr      r0, [pc, #0xbc]
  0x17E28: ldr      r0, [r0, #0x24]
  0x17E2A: ldr      r0, [r0, #0x1c]
  0x17E2C: blx      r0
  0x17E2E: ldrb     r0, [r4, #0x18]
```

### Dispatch Logic

The dispatch checks report IDs in this order:

| Report ID | Action | Handler |
|-----------|--------|---------|
| 0x04 | BEQ -> common | 0x21D44 |
| 0x05 | BEQ -> common | 0x21D44 |
| 0x06 | BEQ -> common | 0x21D44 |
| 0x17 | BEQ -> common | 0x21D44 |
| 0x18 | BEQ -> common | 0x21D44 |
| 0x13 | BEQ -> common | 0x21D44 |
| 0x14 | BEQ -> common | 0x21D44 |
| 0x15 | BEQ -> common | 0x21D44 |
| 0x16 | BEQ -> common | 0x21D44 |
| Other | BNE (skip) | Falls through |

**Key Finding**: ALL report IDs (0x04-0x06, 0x13-0x18) dispatch to the
same common handler at 0x21D44. The differentiation happens
inside that handler based on the report ID value passed in a register.

### Common Handler at 0x21D44

```asm
  0x21D44: ldr      r1, [pc, #0x10]
  0x21D46: movs     r0, #0
  0x21D48: str      r0, [r1, #0x10]
  0x21D4A: ldr      r0, [pc, #0x10]
  0x21D4C: ldr      r1, [r0, #4]
  0x21D4E: movs     r2, #0x40
  0x21D50: orrs     r1, r2
  0x21D52: str      r1, [r0, #4]
  0x21D54: bx       lr
  0x21D56: movs     r0, r0
```

### Report IDs 0x13-0x18 Analysis

These report IDs are not standard HID report types. Possible purposes:

| Report ID | Possible Function |
|-----------|-------------------|
| 0x13 | Macro configuration / DPI settings |
| 0x14 | LED/RGB configuration |
| 0x15 | Button mapping configuration |
| 0x16 | Profile switching |
| 0x17 | Firmware metadata query |
| 0x18 | Debug/diagnostic interface |

All dispatch to the same handler, suggesting a unified configuration protocol
where the report ID selects the configuration subsystem and the payload
contains the actual command + data.

## Section 9: Stack Frame Overflow Analysis

### SET_REPORT Handler Stack Frame (0x1C1A8)

```
Frame size: 60 bytes (SUB SP, #0x3C)
Saved registers: 36 bytes (PUSH {R0-R7, LR})
Input report: 64 bytes (received from USB HID SET_REPORT)

CRITICAL: Input (64 bytes) > Stack buffer (60 bytes)
```

### SP-Relative Access Map

#### Writes to stack (STR/STRB/STRH with SP)

| Address | Instruction | Operands | Analysis |
|---------|-------------|----------|----------|

#### Reads from stack (LDR/LDRB/LDRH with SP)

| Address | Instruction | Operands | Analysis |
|---------|-------------|----------|----------|
| 0x1C1B2 | ldr | r7, [sp, #0x78] | READS CALLER STACK (parameter) |
| 0x1C1B4 | ldr | r6, [sp, #0x88] | READS CALLER STACK (parameter) |
| 0x1C1B6 | ldr | r4, [sp, #0x74] | READS CALLER STACK (parameter) |
| 0x1C1BC | ldr | r0, [sp, #0x3c] | Reads from saved register area |
| 0x1C1C8 | ldr | r1, [sp, #0x44] | Reads from saved register area |
| 0x1C1D8 | ldr | r0, [sp, #0x48] | Reads from saved register area |
| 0x1C206 | ldr | r1, [sp, #0x48] | Reads from saved register area |
| 0x1C208 | ldr | r0, [sp, #0x44] | Reads from saved register area |
| 0x1C20E | ldr | r0, [sp, #0x60] | READS CALLER STACK (parameter) |
| 0x1C218 | ldr | r0, [sp, #0x64] | READS CALLER STACK (parameter) |
| 0x1C222 | ldr | r0, [sp, #0x68] | READS CALLER STACK (parameter) |
| 0x1C230 | ldr | r0, [sp, #0x80] | READS CALLER STACK (parameter) |
| 0x1C238 | ldr | r0, [sp, #0x84] | READS CALLER STACK (parameter) |
| 0x1C270 | ldr | r0, [sp, #0x8c] | READS CALLER STACK (parameter) |

### Overflow Scenario Analysis

```
Input path:
  1. USB HID SET_REPORT (64 bytes) arrives from host
  2. Zephyr USB stack calls SET_REPORT callback
  3. Handler at 0x1C1A8 receives pointer to 64-byte buffer
  4. Handler allocates only 60 bytes on stack (SUB SP, #0x3C)

Potential overflow conditions:
  - If handler copies full 64 bytes to SP-relative buffer: 4-byte overflow
  - Overflow would corrupt saved R0 (first pushed register)
  - With careful crafting: could overwrite saved LR for ROP

Mitigation factors:
  - CMP R0, #0xEF at entry limits report ID range
  - Various branch paths may not all perform full copies
  - nRF52840 has no ASLR, no XN (execute-never) by default
  - No stack canaries detected in prologue/epilogue
```

### memcpy Calls Within Handler

- No direct memcpy calls found in first 100 instructions of handler
- Buffer copies may happen in sub-functions called via BL

## Section 10: Interface Analysis Summary

### Input Vectors

| Vector | Size | Protocol | Handler |
|--------|------|----------|---------|
| HID SET_REPORT (Feature) | 64 bytes | USB HID | 0x1C1A8 |
| HID GET_REPORT (Feature) | 64 bytes | USB HID | (response only) |
| HID Output Report | Variable | USB HID | Unknown |
| DFU/Boot mode | -- | USB DFU | MCUboot bootloader |

### Trust Boundaries

```
[USB Host (PC)] <-- USB HID --> [nRF52840 Application FW]
                                        |
                                [MCUboot Bootloader]
                                        |
                                [Flash / NVMC]
```

The application firmware trusts USB HID reports from the host.
There is minimal input validation beyond the report ID bounds check.

### Potential Test Vectors

| # | Vector | Risk | Viability | Details |
|---|--------|------|----------------|---------|
| 1 | Stack buffer overflow in SET_REPORT | HIGH | Medium-High | 60-byte stack buffer with 64-byte input. No stack canaries, no ASLR, no XN. |
| 2 | Unvalidated report ID dispatch | MEDIUM | Medium | Report IDs 0x13-0x18 may have less-tested code paths |
| 3 | Enter-boot command (0x7F) | LOW | Low | Requires correct report structure but can force DFU mode |
| 4 | Macro button bug (0x24616) | LOW | N/A | Already patched - data corruption, not code execution |
| 5 | memcpy with user-controlled length | HIGH | Medium | If any sub-handler passes user data length to memcpy |
| 6 | Integer overflow in size calculations | MEDIUM | Low | Would need specific size field parsing bugs |

### Testing Requirements

For stack buffer overflow (Vector #1):

1. **Trigger**: Send HID Feature Report with crafted payload
2. **Control**: Need to reach a code path that copies > 60 bytes to stack
3. **Payload**: Return address overwrite -> jump to code cave or shellcode
4. **Workaround**: MCUboot signature check prevents persistent modification
   unless code execution can write to flash (but no NVMC references found!)

### Key Security Observations

1. **No NVMC references**: The application firmware does NOT directly access
   flash write registers. Flash writes go through MCUboot/bootloader only.
2. **No stack canaries**: PUSH/POP patterns show no canary checks
3. **No ASLR**: Cortex-M4 has fixed memory map
4. **XN depends on MPU config**: Need to check if MPU is configured
5. **Code cave available**: Unused space at 0x25F36 for payload

## Section 11: Peripheral References

### Nordic nRF52840 Peripheral Access

| Peripheral | Base Address | References Found | Locations |
|------------|-------------|------------------|-----------|
| FICR | 0x10000000 | **NONE** |  |
| UICR | 0x10001000 | **NONE** |  |
| POWER | 0x40000000 | **NONE** |  |
| CLOCK | 0x40000000 | **NONE** |  |
| RADIO | 0x40001000 | **NONE** |  |
| UART0 | 0x40002000 | **NONE** |  |
| SPI0 | 0x40003000 | **NONE** |  |
| TWI0 | 0x40003000 | **NONE** |  |
| GPIOTE | 0x40006000 | **NONE** |  |
| TIMER0 | 0x40008000 | **NONE** |  |
| TIMER1 | 0x40009000 | **NONE** |  |
| TIMER2 | 0x4000A000 | **NONE** |  |
| RTC0 | 0x4000B000 | **NONE** |  |
| WDT | 0x40010000 | **NONE** |  |
| RTC1 | 0x40011000 | **NONE** |  |
| PWM0 | 0x4001C000 | **NONE** |  |
| NVMC | 0x4001E000 | **NONE** |  |
| USBD | 0x40027000 | **NONE** |  |
| GPIO_P0 | 0x50000000 | **NONE** |  |
| GPIO_P1 | 0x50000300 | **NONE** |  |
| CRYPTOCELL | 0x5002A000 | **NONE** |  |

### NVMC (Flash Write Controller) Analysis

**CRITICAL FINDING**: No references to NVMC (0x4001E000) found in the
application firmware. This means:

1. The application cannot write to flash directly
2. All flash operations are delegated to the bootloader (MCUboot)
3. Even with arbitrary code execution in the application, it would not
   be possible to directly patch the firmware in flash
4. To achieve persistent modification, would need to:
   a. Chain into the bootloader (which DOES have NVMC access)
   b. Or use DFU protocol to upload a crafted image (still needs valid signature)

### UICR / APPROTECT Analysis

No references to UICR (0x10001000) found. The APPROTECT register
(at UICR+0x208) is not accessed by the application firmware.

### USB Device Controller

USBD (0x40027000) references: 0

## Section 12: Code Cave and Patch Analysis

### Binary Comparison: original vs patched

- Original size: 108608 bytes
- Patched size: 108608 bytes
- Original SHA-256: `1c0c5fdd02ce92ed521729a00218f0f86920211455b1d51fe9a4455a7a3d8262`
- Patched SHA-256: `c4bf6b94d65c1b230af61d0a4bf3978669cf7b2fc9a6672efa7137e61f00538e`

**Total bytes changed**: 27

**Number of changed regions**: 3

### Region 1: File offset 0x14616 - 0x1461D (memory 0x24616 - 0x2461D)
Size: 8 bytes

```
Original: 4179217080796070
Patched:  01f08efc02e000bf
```

#### Original disassembly:
```asm
  0x24616: ldrb     r1, [r0, #5]
  0x24618: strb     r1, [r4]
  0x2461A: ldrb     r0, [r0, #6]
  0x2461C: strb     r0, [r4, #1]
```

#### Patched disassembly:
```asm
  0x24616: bl       #0x25f36
  0x2461A: b        #0x24622
  0x2461C: nop      
```

### Region 2: File offset 0x1461F - 0x1461F (memory 0x2461F - 0x2461F)
Size: 1 bytes

```
Original: e0
Patched:  bf
```

#### Original disassembly:
```asm
```

#### Patched disassembly:
```asm
```

### Region 3: File offset 0x15F36 - 0x15F47 (memory 0x25F36 - 0x25F47)
Size: 18 bytes

```
Original: 000000000000000000000000000000000000
Patched:  417922781143217081796278114361707047
```

#### Original disassembly:
```asm
  0x25F36: movs     r0, r0
  0x25F38: movs     r0, r0
  0x25F3A: movs     r0, r0
  0x25F3C: movs     r0, r0
  0x25F3E: movs     r0, r0
  0x25F40: movs     r0, r0
  0x25F42: movs     r0, r0
  0x25F44: movs     r0, r0
  0x25F46: movs     r0, r0
```

#### Patched disassembly:
```asm
  0x25F36: ldrb     r1, [r0, #5]
  0x25F38: ldrb     r2, [r4]
  0x25F3A: orrs     r1, r2
  0x25F3C: strb     r1, [r4]
  0x25F3E: ldrb     r1, [r0, #6]
  0x25F40: ldrb     r2, [r4, #1]
  0x25F42: orrs     r1, r2
  0x25F44: strb     r1, [r4, #1]
  0x25F46: bx       lr
```

### Patch Purpose

The patch modifies 27 bytes in 3 region(s):

1. **Bug site** (0x24616): Redirects the macro button write through
   a BL (branch-link) to the trampoline in the code cave

2. **Code cave** (0x2461F): OR-merge trampoline that combines
   macro button state with physical button state before writing
   to the HID report buffer
