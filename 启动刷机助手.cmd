@echo off
title SBE1V1K Flasher GUI
rem ASCII-only launcher: avoids cmd.exe codepage parsing bugs entirely.
rem Elevation is handled inside the PowerShell script (UAC prompt).
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0SBE1V1K-Flasher-GUI.ps1"
if errorlevel 1 (
    echo.
    echo Launch failed. Right-click SBE1V1K-Flasher-GUI.ps1 and try again.
    pause
)
