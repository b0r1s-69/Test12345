# Ajazz AJ159 APEX — firmware notes & HID debug toolkit

A local USB‑HID debugging kit for the **Ajazz AJ159 APEX / PRO / P** and the
sibling **Compx / RuiYu** mouse platform (Attack Shark X11, VGN, Kysona, etc.).

> The cloud workspace has **no physical access** to your mouse. Run everything in
> this folder on the computer where the mouse (or its 2.4 GHz / 8K receiver) is
> plugged in.

---

## 1. What we found in the official firmware

Downloaded from a‑jazz.com: `【AJ159 APEX】_MV302_DV233_Firmware（unzip）.zip`
(~21 MB). It contains **two** updaters, each = `ry_upgrade.exe` + `resources/support_config.json`:

| Tool | Target | Version |
|------|--------|---------|
| `AJ159 APEX（升级鼠标）MV302_固件升级工具` | the **mouse** | firmware **MV302** |
| `8K带屏底座接收器（升级接收器）DV233_固件升级工具` | the **8K screen dock / receiver** | **DV233** |

Static analysis of `ry_upgrade.exe`:

* It's the **"RY Upgrade Tool"** — a **Rust + Slint** GUI app (generic RuiYu OEM
  updater) that supports ~130 different devices via per‑chip modules:
  `nordic_keyboard`, `nordic_dangle`, `bk100` (Beken), `ry5088`, `yc3016a/yc3123`,
  `pan101/pan108`, `yzw24` (2.4G), `flash`, `mled`, `oled`, `touch_screen`.
* The mouse firmware is a **Zephyr RTOS image for a Nordic nRF52‑class SoC**
  (embedded BLE controller strings: `bt_ctlr_hci_driver`, HCI/LMP/advertising,
  `>>> ZEPHYR FATAL ERROR`).
* **Sensor: PixArt PAW3950** (string `uni3950`) — matches the spec sheet (up to
  30K DPI, overclock to 42K on the APEX).
* **Firmware flash layout** the updater targets:

  | Region | Address | Contents |
  |--------|---------|----------|
  | Bootloader / MLED / OLED / TouchScreen / Flash | `0x0` | boot + peripherals |
  | RF FW | `0x5000` | 2.4 GHz radio firmware |
  | **Nordic FW** | `0x10000` | **main BLE/Zephyr application** |

* Vendor upgrade HID commands present in the tool: `Get Verison`, `Get Address`,
  `Get Boot ID`, `Upgrade(`, `Boot Upgrade`.

**Flashing = Windows only.** Use the official `ry_upgrade.exe`. Do **not**
attempt blind DFU writes — wrong image/revision bricks the device.

---

## 2. The runtime config protocol (what this toolkit speaks)

Reverse‑engineered by the community ([attack-shark-x11-driver](https://github.com/HarukaYamamoto0/attack-shark-x11-driver), MIT)
and **re‑validated here** (`selftest`). All config goes to **USB interface 2** as
**HID feature reports** (`SET_REPORT`, `bmRequestType=0x21`, `bRequest=0x09`):

| Setting | Report ID / wValue | Length | Notes |
|---------|--------------------|--------|-------|
| Polling rate | `0x06` / `0x0306` | 9 | `06 09 01 <rate> <0xFF-rate> 00..`; rate: 125→08, 250→04, 500→02, 1000→01 |
| DPI stages | `0x04` / `0x0304` | 56 (52 wired) | 6 stages, DPI→code map, stage mask, BE checksum of bytes 3..49 |
| RGB / sleep / debounce | `0x05` / `0x0305` | 15 (13 wired) | debounce 4–50 ms; checksum = sum(3..10)&0xff |
| Battery (read) | input report | — | autonomous `03 55 40 01 <pct>` on iface 2, **wireless only** |

⚠️ The firmware can **hang if you send config packets too fast** — keep ≥300 ms
between writes (this tool defaults to 300 ms). Recovery: switch to Bluetooth a
few seconds, then back.

---

## 3. Install

```bash
pip install -r requirements.txt        # installs hidapi
# Linux only, for non-root access:
sudo cp 99-aj159.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules && sudo udevadm trigger   # then replug
```

* **Windows:** works out of the box (the mouse uses standard HID).
* **macOS:** `brew install hidapi` if the wheel doesn't bundle it.

---

## 4. Use it

```bash
# 0) Validate the protocol encoders (no hardware needed)
python3 aj159_debug.py selftest

# 1) Find your mouse — note the VID:PID flagged with '*'
python3 aj159_debug.py list

# 2) Inspect interfaces
python3 aj159_debug.py info    --vid 0x3151 --pid 0xXXXX

# 3) Watch raw reports (move/click, change DPI, dock/undock)
python3 aj159_debug.py monitor --vid 0x3151 --pid 0xXXXX

# 4) Read battery (must be in 2.4G/Bluetooth mode)
python3 aj159_debug.py battery --vid 0x3151 --pid 0xXXXX

# 5) Read-only feature-report fingerprint
python3 aj159_debug.py probe   --vid 0x3151 --pid 0xXXXX

# 6) WRITE config (asks for confirmation; add -y to skip)
python3 aj159_debug.py set-polling --vid 0x3151 --pid 0xXXXX --rate 1000
python3 aj159_debug.py set-dpi     --vid 0x3151 --pid 0xXXXX \
        --stages 800 1600 3200 6400 12000 22000 --active 3
python3 aj159_debug.py set-prefs   --vid 0x3151 --pid 0xXXXX --debounce 4 --light static --rgb 255 0 0
```

> Your exact VID:PID may differ from the X11's `0x1d57`. These mice commonly use
> `0x3151` (Compx) in normal mode. Always confirm with `list`, then verify the
> write layout with `monitor`/`probe` before trusting `set-*` on your revision.

---

## 5. Capturing USB traffic (best way to confirm the protocol on YOUR unit)

Run the **official Windows software**, change a setting, and capture what it sends:

* **Windows:** [Wireshark](https://www.wireshark.org/) + **USBPcap**. Filter:
  `usb.transfer_type == 0x02` (control) or `usb.setup.wValue == 0x0304` (DPI) /
  `0x0306` (polling). Look at `SET_REPORT` payloads.
* **Linux:** `sudo modprobe usbmon`, then `sudo wireshark` on the `usbmonX`
  interface (or `tshark -i usbmon1`).
* **macOS:** Wireshark with the USB capture extcap.

Paste any new report layouts back and the encoders here can be extended.

---

## 6. Safety / scope

* Read‑only commands (`list`/`info`/`monitor`/`battery`/`probe`) are safe.
* `set-*` commands write **runtime config only** (DPI/polling/RGB/debounce) —
  they do **not** touch firmware.
* This kit deliberately has **no flasher**. For firmware use the official
  `ry_upgrade.exe` (MV302 mouse / DV233 receiver), following the bundled
  `固件升级操作说明（Firmware Upgrade Operation Instructions).png`.

## Credits
Protocol ported from `attack-shark-x11-driver` (MIT, © HarukaYamamoto0).
Content rephrased/summarized for licensing compliance.
