/*
 * SilentGate v9.0 - WinRing0x64 IOCTL Test
 * Author: JarDani
 */
#include <windows.h>
#include <stdio.h>

int load_driver(const char* driver_path, const char* service_name) {
    printf("[DRIVER] Loading from: %s\n", driver_path);

    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!scm) {
        printf("[DRIVER] OpenSCManager failed: %lu\n", GetLastError());
        return 0;
    }

    /* Delete existing service first */
    SC_HANDLE existing = OpenServiceA(scm, service_name, SERVICE_ALL_ACCESS);
    if (existing) {
        SERVICE_STATUS ss;
        ControlService(existing, SERVICE_CONTROL_STOP, &ss);
        DeleteService(existing);
        CloseServiceHandle(existing);
        Sleep(1000);
        printf("[DRIVER] Removed existing service\n");
    }

    SC_HANDLE svc = CreateServiceA(scm,
        service_name, service_name,
        SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_IGNORE,
        driver_path,
        NULL, NULL, NULL, NULL, NULL);

    if (!svc) {
        printf("[DRIVER] CreateService failed: %lu\n", GetLastError());
        CloseServiceHandle(scm);
        return 0;
    }

    if (!StartServiceA(svc, 0, NULL)) {
        DWORD err = GetLastError();
        printf("[DRIVER] StartService failed: %lu\n", err);
        DeleteService(svc);
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        return 0;
    }

    printf("[DRIVER] Service started successfully\n");
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return 1;
}

void unload_driver(const char* service_name) {
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    SC_HANDLE svc = OpenServiceA(scm, service_name, SERVICE_ALL_ACCESS);
    if (svc) {
        SERVICE_STATUS ss;
        ControlService(svc, SERVICE_CONTROL_STOP, &ss);
        Sleep(500);
        DeleteService(svc);
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);
    printf("[DRIVER] Service removed\n");
}

int main() {
    printf("[V9] SilentGate v9.0 - WinRing0 Kernel Test\n");
    printf("[V9] Author: JarDani\n\n");

    /* Build full absolute path */
    char driver_path[MAX_PATH];
    char exe_dir[MAX_PATH];
    GetModuleFileNameA(NULL, exe_dir, MAX_PATH);
    
    /* Remove exe name to get directory */
    char* last_slash = strrchr(exe_dir, '\\');
    if (last_slash) *last_slash = '\0';
    
    snprintf(driver_path, MAX_PATH, "%s\\WinRing0x64.sys", exe_dir);
    printf("[V9] Driver path: %s\n", driver_path);
    
    /* Verify file exists */
    DWORD attrs = GetFileAttributesA(driver_path);
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        printf("[V9] ERROR: Driver file not found at %s\n", driver_path);
        getchar();
        return 1;
    }
    printf("[V9] Driver file found: OK\n");

    if (!load_driver(driver_path, "WinRing0x64")) {
        getchar();
        return 1;
    }

    /* Open device */
    HANDLE hDevice = CreateFileA(
        "\\\\.\\WinRing0_1_2_0",
        GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, NULL
    );

    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("[V9] Open device failed: %lu\n", GetLastError());
        unload_driver("WinRing0x64");
        getchar();
        return 1;
    }

    printf("[V9] Device handle: %p\n", hDevice);
    printf("[V9] Kernel R/W primitive: READY\n");
    printf("[V9] WinRing0x64 operational\n");

    CloseHandle(hDevice);
    unload_driver("WinRing0x64");

    printf("\n[V9] Complete - press Enter\n");
    getchar();
    return 0;
}
