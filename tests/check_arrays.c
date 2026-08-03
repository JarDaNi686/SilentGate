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

void check_addr(DWORD64 addr, const char* label) {
    printf("\n[CHECK] %s = 0x%llX\n", label, addr);
    DWORD64 entries[8]={0};
    if(!vm_read(addr, entries, 64)){
        printf("[CHECK] Read failed\n"); return;}
    for(int i=0;i<8;i++){
        printf("  [%d] 0x%llX", i, entries[i]);
        /* Check if it looks like a kernel callback entry */
        if(entries[i] > 0xFFFF000000000000ULL && entries[i] != 0xCCCCCCCCCCCCCCCCULL)
            printf(" <- possible callback");
        printf("\n");
    }
}

int main() {
    char drv[MAX_PATH],dir[MAX_PATH];
    GetModuleFileNameA(NULL,dir,MAX_PATH);
    char* p=strrchr(dir,'\\');if(p)*p='\0';
    snprintf(drv,MAX_PATH,"%s\\sg_driver.sys",dir);
    load_driver(drv);

    g_h=CreateFileA("\\\\.\\SilentGate",GENERIC_READ|GENERIC_WRITE,0,NULL,
        OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);

    /* Check all MOV targets from previous dump */
    check_addr(0xFFFFF804268F60F0ULL, "MOV target +36");
    check_addr(0xFFFFF803E9116990ULL, "MOV target +46");
    check_addr(0xFFFFF8040E6124C0ULL, "MOV target +95");
    check_addr(0xFFFFF8040CDC8EFDULL, "MOV target +110");

    CloseHandle(g_h);
    unload_driver();
    getchar();
    return 0;
}
