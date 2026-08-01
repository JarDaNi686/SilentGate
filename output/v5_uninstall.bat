@echo off
:: SilentGate v5.0 - Cleanup Script
echo [CLEANUP] Removing NetworkLocationHelper...
sc stop NetworkLocationHelper >nul 2>&1
sc delete NetworkLocationHelper >nul 2>&1
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\NetworkLocationHelper" /f >nul 2>&1
del /f "%SystemRoot%\System32\NetworkLocationHelper.dll" >nul 2>&1
echo [CLEANUP] Complete - no traces remain
