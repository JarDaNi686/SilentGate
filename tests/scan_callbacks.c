#include <windows.h>
#include <psapi.h>
#include <stdio.h>

#define IOCTL_SG_READ_VIRTUAL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)
typedef struct { ULONG64 address; ULONG size; UCHAR data[256]; } SG_MEM;
static HANDLE g_h = INVALID_HANDLE_VALUE;

BOOL vm_read(ULONG64 addr, PVOID buf, ULONG size) {
    SG_MEM req={0}; req.address=addr; req.size=size<256?size:256;
    DWORD bytes=0;
    return DeviceIoControl(g_h,IOCTL_SG_READ_VIRTUAL,
        &req,sizeof(req),buf,size,&bytes,NULL);
}

int load_driver(const char* path) {
    SC_HANDLE scm=OpenSCManagerA(NULL,NULL,SC_MANAGER_CREATE_SERVICE);
    SC_HANDLE ex=OpenServiceA(scm,"SilentGate",SERVICE_ALL_ACCESS);
    if(ex){SERVICE_STATUS ss;ControlService(ex,SERVICE_CONTROL_STOP,&ss);
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
    if(svc){SERVICE_STATUS ss;ControlService(svc,SERVICE_CONTROL_STOP,&ss);
        Sleep(500);DeleteService(svc);CloseServiceHandle(svc);}
    CloseServiceHandle(scm);
}

DWORD64 get_ntos() {
    DWORD n=0; EnumDeviceDrivers(NULL,0,&n);
    LPVOID* d=(LPVOID*)malloc(n); EnumDeviceDrivers(d,n,&n);
    DWORD64 base=0; char name[MAX_PATH];
    for(DWORD i=0;i<n/sizeof(LPVOID);i++){
        GetDeviceDriverBaseNameA(d[i],name,MAX_PATH);
        if(_stricmp(name,"ntoskrnl.exe")==0||_stricmp(name,"ntkrnlmp.exe")==0)
            {base=(DWORD64)d[i];break;}
    } free(d); return base;
}

/* Check if value looks like a kernel callback entry */
/* Callback entries: pointer with lower bits as flags */
/* Format: (pool_ptr & ~0xF) | flags */
int is_callback_entry(DWORD64 val) {
    if (val == 0) return 0;
    DWORD64 ptr = val & ~0xFULL;
    /* Must be kernel address */
    if (ptr < 0xFFFF800000000000ULL) return 0;
    /* Lower 4 bits are flags - should be small value */
    if ((val & 0xF) > 8) return 0;
    return 1;
}

int main() {
    printf("[SCAN] SilentGate v9.0 - Callback Array Scanner\n\n");

    char drv[MAX_PATH],dir[MAX_PATH];
    GetModuleFileNameA(NULL,dir,MAX_PATH);
    char* p=strrchr(dir,'\\');if(p)*p='\0';
    snprintf(drv,MAX_PATH,"%s\\sg_driver.sys",dir);

    if(!load_driver(drv)){printf("Load failed\n");getchar();return 1;}
    g_h=CreateFileA("\\\\.\\SilentGate",GENERIC_READ|GENERIC_WRITE,0,NULL,
        OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);

    DWORD64 ntos = get_ntos();
    DWORD64 data_sec = ntos + 0xC00000; /* .data section offset */
    DWORD64 data_size = 0xFA5F0;

    printf("[SCAN] ntoskrnl: 0x%llX\n", ntos);
    printf("[SCAN] .data section: 0x%llX size=0x%llX\n\n", data_sec, data_size);
    printf("[SCAN] Scanning for callback arrays (64 consecutive entries)...\n\n");

    /* Scan .data section in 8-byte chunks looking for callback arrays */
    /* A callback array has multiple consecutive callback entries */
    DWORD64 best_addr = 0;
    int best_count = 0;

    for(DWORD64 off=0; off < data_size - 512; off += 8) {
        DWORD64 entries[8] = {0};
        if(!vm_read(data_sec+off, entries, 64)) continue;

        /* Count consecutive callback-like entries */
        int count = 0;
        for(int i=0;i<8;i++){
            if(is_callback_entry(entries[i])) count++;
            else break;
        }

        if(count >= 2) {
            printf("[SCAN] Possible array at 0x%llX (%d entries):\n",
                data_sec+off, count);
            for(int i=0;i<count;i++)
                printf("  [%d] 0x%llX\n", i, entries[i]);

            if(count > best_count){
                best_count = count;
                best_addr  = data_sec+off;
            }
        }
    }

    if(best_addr)
        printf("\n[SCAN] Best candidate: 0x%llX (%d entries)\n",
            best_addr, best_count);
    else
        printf("\n[SCAN] No callback arrays found in .data section\n");

    CloseHandle(g_h);
    unload_driver();
    printf("\n[SCAN] Done - press Enter\n");
    getchar();
    return 0;
}
