#include <windows.h>
#include <psapi.h>
#include <stdio.h>

int load_driver(const char* path) {
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    SC_HANDLE ex = OpenServiceA(scm, "WinRing0x64", SERVICE_ALL_ACCESS);
    if (ex) {
        SERVICE_STATUS ss;
        ControlService(ex, SERVICE_CONTROL_STOP, &ss);
        DeleteService(ex); CloseServiceHandle(ex); Sleep(500);
    }
    SC_HANDLE svc = CreateServiceA(scm,"WinRing0x64","WinRing0x64",
        SERVICE_ALL_ACCESS,SERVICE_KERNEL_DRIVER,SERVICE_DEMAND_START,
        SERVICE_ERROR_IGNORE,path,NULL,NULL,NULL,NULL,NULL);
    if (!svc) { CloseServiceHandle(scm); return 0; }
    BOOL ok = StartServiceA(svc,0,NULL);
    CloseServiceHandle(svc); CloseServiceHandle(scm);
    return ok;
}

void unload_driver() {
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    SC_HANDLE svc = OpenServiceA(scm,"WinRing0x64",SERVICE_ALL_ACCESS);
    if (svc) {
        SERVICE_STATUS ss;
        ControlService(svc,SERVICE_CONTROL_STOP,&ss);
        Sleep(500); DeleteService(svc); CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);
}

int main() {
    char driver_path[MAX_PATH], exe_dir[MAX_PATH];
    GetModuleFileNameA(NULL, exe_dir, MAX_PATH);
    char* last = strrchr(exe_dir, '\\');
    if (last) *last = '\0';
    snprintf(driver_path, MAX_PATH, "%s\\WinRing0x64.sys", exe_dir);

    load_driver(driver_path);

    HANDLE h = CreateFileA("\\\\.\\WinRing0_1_2_0",
        GENERIC_READ|GENERIC_WRITE, 0, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (h == INVALID_HANDLE_VALUE) {
        printf("Device open failed: %lu\n", GetLastError());
        unload_driver();
        getchar();
        return 1;
    }

    printf("[PROBE] Device opened\n");

    /* Try reading physical memory at address 0x1000 */
    /* WinRing0 read memory IOCTL - try different codes */
    
    DWORD codes[] = {
        CTL_CODE(40000, 0x833, METHOD_BUFFERED, FILE_ANY_ACCESS),
        CTL_CODE(40000, 0x835, METHOD_BUFFERED, FILE_ANY_ACCESS),
        CTL_CODE(40000, 0x837, METHOD_BUFFERED, FILE_ANY_ACCESS),
        CTL_CODE(40000, 0x839, METHOD_BUFFERED, FILE_ANY_ACCESS),
        0x9C402464,  /* Known WinRing0 read mem */
        0x9C402468,  /* Known WinRing0 write mem */
        0x9C402088,  /* Read MSR */
    };

    /* Try read MSR (RDMSR for TSC = MSR 0x10) */
    struct { DWORD index; DWORD eax; DWORD edx; } msr_buf = {0x10, 0, 0};
    
    for (int i = 0; i < 7; i++) {
        DWORD bytes = 0;
        BOOL ok = DeviceIoControl(h, codes[i],
            &msr_buf, sizeof(msr_buf),
            &msr_buf, sizeof(msr_buf),
            &bytes, NULL);
        printf("[PROBE] IOCTL 0x%08X: %s (err=%lu bytes=%lu)\n",
            codes[i], ok?"OK":"FAIL", GetLastError(), bytes);
    }

    CloseHandle(h);
    unload_driver();
    getchar();
    return 0;
}
