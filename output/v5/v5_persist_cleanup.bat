@echo off
:: SilentGate v5.0 - Persistence Cleanup
schtasks /Delete /TN "Microsoft\Windows\Network\Windows Network Connectivity Maintenance" /F >nul 2>&1
echo [CLEANUP] Scheduled task removed
