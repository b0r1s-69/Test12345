; ============================================================================
; AJ159 APEX Macro Button Fix - AutoHotkey Workaround
; ============================================================================
; 
; PROBLEM: When an onboard macro fires on LMB, the mouse firmware overwrites
; the HID buttons byte, causing held buttons (like RMB) to release.
;
; SOLUTION: This script monitors the physical state of RMB. If the firmware
; sends an RButton Up event while the physical button is still held down,
; the script blocks that spurious release and keeps RMB pressed.
;
; REQUIREMENTS: AutoHotkey v2.0+ (https://www.autohotkey.com/)
; USAGE: Double-click this file or add to Windows startup (see README)
;
; ============================================================================

#Requires AutoHotkey v2.0
#SingleInstance Force
Persistent

; --- Configuration ---
; Set to true to show a tray tooltip when a spurious release is blocked
global ShowNotifications := false

; How often to check physical button state (ms) - lower = more responsive
global PollInterval := 1

; --- State tracking ---
global RMB_PhysicallyHeld := false
global BlockingActive := false

; --- Tray menu setup ---
A_IconTip := "AJ159 Macro Fix - Running"
TraySetIcon("Shell32.dll", 44)  ; Mouse icon

tray := A_TrayMenu
tray.Delete()
tray.Add("AJ159 Macro Fix (Running)", (*) => "")
tray.Add()
tray.Add("Toggle Notifications", ToggleNotifications)
tray.Add()
tray.Add("Reload", (*) => Reload())
tray.Add("Exit", (*) => ExitApp())
tray.Default := "AJ159 Macro Fix (Running)"

; --- Hotkeys ---
; Monitor physical RMB press/release using raw input
; The ~ prefix lets the event pass through normally
~RButton::
{
    global RMB_PhysicallyHeld := true
}

~RButton Up::
{
    ; Check if RMB is ACTUALLY physically released
    ; GetKeyState with "P" checks the physical state of the key
    if GetKeyState("RButton", "P")
    {
        ; Physical button is still held - this is a spurious release from the macro bug
        ; Block the release and re-send the down state
        Send("{RButton Down}")
        
        if ShowNotifications
            ToolTip("Blocked spurious RMB release")
        SetTimer(ClearToolTip, -1000)
        
        return  ; Block the Up event
    }
    
    ; Physical button is actually released - allow it
    global RMB_PhysicallyHeld := false
}

; --- Also protect Middle Mouse Button (same bug can affect it) ---
~MButton Up::
{
    if GetKeyState("MButton", "P")
    {
        Send("{MButton Down}")
        return
    }
}

; --- Also protect XButton1 (Back/Side button) ---
~XButton1 Up::
{
    if GetKeyState("XButton1", "P")
    {
        Send("{XButton1 Down}")
        return
    }
}

; --- Also protect XButton2 (Forward/Side button) ---
~XButton2 Up::
{
    if GetKeyState("XButton2", "P")
    {
        Send("{XButton2 Down}")
        return
    }
}

; --- Helper functions ---
ClearToolTip()
{
    ToolTip()
}

ToggleNotifications(*)
{
    global ShowNotifications := !ShowNotifications
    if ShowNotifications
        ToolTip("Notifications: ON")
    else
        ToolTip("Notifications: OFF")
    SetTimer(ClearToolTip, -1500)
}

; --- Startup notification ---
ToolTip("AJ159 Macro Fix Active")
SetTimer(ClearToolTip, -2000)
