#include <windows.h>
#include <psapi.h>
#include <stdio.h>

#define IOCTL_SG_READ_VIRTUAL  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SG_WRITE_VIRTUAL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS)
typedef struct { ULONG64 address; ULONG size; UCHAR data[256]; } SG_MEM;
static HANDLE g_h = INVALID_HANDLE_VALUE;

BOOL vm_read(ULONG64 addr, PVOID buf, ULONG size) {
    SG_MEM req={0}; req.address=addr; req.size=size<256?size:256;
    DWORD bytes=0;
    return DeviceIoControl(g_h,IOCTL_SG_READ_VIRTUAL,
        &req,sizeof(req),buf,size,&bytes,NULL);
}

BOOL vm_write(ULONG64 addr, PVOID buf, ULONG size) {
    SG_MEM req={0}; req.address=addr; req.size=size<256?size:256;
    if(req.size>0) memcpy(req.data,buf,req.size);
    DWORD bytes=0;
    return DeviceIoControl(g_h,IOCTL_SG_WRITE_VIRTUAL,
        &req,sizeof(req),&req,sizeof(req),&bytes,NULL);
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

/* Find which driver owns a function pointer */
void get_driver_name(DWORD64 func, char* out) {
    strcpy(out, "unknown");
    DWORD n=0; EnumDeviceDrivers(NULL,0,&n);
    LPVOID* d=(LPVOID*)malloc(n); EnumDeviceDrivers(d,n,&n);
    for(DWORD i=0;i<n/sizeof(LPVOID);i++){
        DWORD64 base=(DWORD64)d[i];
        /* Assume max driver size 4MB */
        if(func>=base && func<base+0x400000){
            GetDeviceDriverBaseNameA(d[i],out,MAX_PATH);
            break;
        }
    }
    free(d);
}

int main() {
    printf("[ARRAY] SilentGate v9.0 - Read Callback Array\n\n");

    char drv[MAX_PATH],dir[MAX_PATH];
    GetModuleFileNameA(NULL,dir,MAX_PATH);
    char* p=strrchr(dir,'\\');if(p)*p='\0';
    snprintf(drv,MAX_PATH,"%s\\sg_driver.sys",dir);

    if(!load_driver(drv)){printf("Load failed\n");getchar();return 1;}
    g_h=CreateFileA("\\\\.\\SilentGate",GENERIC_READ|GENERIC_WRITE,0,NULL,
        OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);

    /* The callback array found at LEA +65 */
    DWORD64 array = 0xFFFFF801058EC3E0ULL;
    printf("[ARRAY] Reading callback array at 0x%llX\n\n", array);

    /* Read 64 entries (512 bytes) */
    DWORD64 entries[64]={0};
    if(!vm_read(array, entries, 512)){
        printf("[ARRAY] Read failed: %lu\n", GetLastError());
        CloseHandle(g_h); unload_driver();
        getchar(); return 1;
    }

    printf("[ARRAY] Callback entries:\n");
    int found = 0;
    for(int i=0;i<64;i++){
        if(entries[i]==0) continue;

        /* Decode callback pointer */
        DWORD64 cb_pool = entries[i] & ~0xFULL;
        if(cb_pool < 0xFFFF800000000000ULL) continue;

        /* Read function pointer from callback struct (+8) */
        DWORD64 func=0;
        vm_read(cb_pool+8, &func, 8);

        char dname[MAX_PATH]="unknown";
        if(func) get_driver_name(func, dname);

        printf("[ARRAY] [%d] entry=0x%llX pool=0x%llX func=0x%llX driver=%s\n",
            i, entries[i], cb_pool, func, dname);
        found++;
    }

    if(found==0){
        printf("[ARRAY] No valid callbacks found\n");
        printf("[ARRAY] Raw first 8 entries:\n");
        for(int i=0;i<8;i++)
            printf("  [%d] 0x%llX\n", i, entries[i]);
    }

    printf("\n[ARRAY] Done - press Enter\n");
    getchar();

    CloseHandle(g_h);
    unload_driver();
    return 0;
}
