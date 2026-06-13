# AJ159 APEX Macro Fix - AutoHotkey Workaround

## What This Does

When the AJ159 APEX mouse fires an onboard macro (e.g., on LMB), the firmware bug causes any held buttons (RMB, side buttons) to release. This AutoHotkey script intercepts those spurious release events and blocks them, keeping your held buttons pressed.

**Zero risk. No firmware changes. Works immediately.**

## Requirements

- Windows 10/11
- [AutoHotkey v2.0+](https://www.autohotkey.com/) (free, open source)

## Installation

1. Download and install AutoHotkey v2 from https://www.autohotkey.com/
2. Double-click `macro_fix.ahk` to run the script
3. You will see a mouse icon in your system tray (bottom-right)
4. Test: Hold RMB, fire your macro on LMB - RMB should stay held

## Running at Windows Startup

### Method 1: Startup Folder (Recommended)

1. Press `Win + R`, type `shell:startup`, press Enter
2. Right-click in the folder, select "New > Shortcut"
3. Browse to `macro_fix.ahk` and create the shortcut
4. Done - the script will start every time you log in

### Method 2: Task Scheduler (Advanced)

1. Open Task Scheduler (`taskschd.msc`)
2. Create a new Basic Task
3. Trigger: "When I log on"
4. Action: "Start a program"
5. Program: path to `AutoHotkey64.exe` (typically `C:\Program Files\AutoHotkey\v2\AutoHotkey64.exe`)
6. Arguments: full path to `macro_fix.ahk`
7. Check "Run with highest privileges" if you play games that run as admin

## How It Works

The script hooks mouse button release events at the Windows input level:

1. When Windows receives an "RButton Up" event from the mouse
2. The script checks `GetKeyState("RButton", "P")` - the PHYSICAL state of the button
3. If the physical button is still held down, this is a spurious release caused by the macro bug
4. The script blocks the release event and re-sends a "button down" to maintain the held state
5. If the physical button is actually released, the event passes through normally

This protects ALL mouse buttons (RMB, MMB, Side buttons), not just RMB.

## Tray Menu Options

Right-click the tray icon for options:
- **Toggle Notifications** - Shows a tooltip each time a spurious release is blocked (useful for debugging)
- **Reload** - Restart the script
- **Exit** - Stop the script

## Compatibility

- Works with all games and applications
- No conflicts with the Ajazz/Attack Shark driver software
- Very low CPU usage (event-driven, not polling)
- Does not interfere with normal mouse operation when macros are not firing

## Limitations

- Windows only (Linux users can use evdev-based solutions)
- Requires AutoHotkey to be installed
- Some anti-cheat systems (Vanguard, EAC, BattlEye) may flag AutoHotkey - check your game's policy
- Does not fix the root cause (firmware bug) - just works around it at the OS level

## Troubleshooting

**Script not working in a specific game:**
- Try running AutoHotkey as Administrator
- Some fullscreen exclusive games block input hooks - try borderless windowed mode

**Anti-cheat blocking the script:**
- Check if your game allows AutoHotkey
- The script does NOT automate inputs - it only blocks spurious release events
- Some anti-cheat systems whitelist AHK scripts that dont generate artificial inputs

**Want to verify the script is catching events:**
- Right-click tray icon > Toggle Notifications
- Hold RMB, fire your macro - you should see "Blocked spurious RMB release" tooltip

## Uninstall

1. Right-click the tray icon > Exit (or close via Task Manager)
2. Remove the startup shortcut if you added one
3. Delete the script file
4. Optionally uninstall AutoHotkey
