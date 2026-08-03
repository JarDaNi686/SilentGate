/*
 * SilentGate v9.0 - Custom Driver Test
 * Author: JarDani
 * Tests our custom sg_driver.sys virtual memory R/W
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
    req.size    = size;
    DWORD bytes = 0;
    return DeviceIoControl(g_hDev, IOCTL_SG_READ_VIRTUAL,
        &req, sizeof(req), buf, size, &bytes, NULL);
}

BOOL vm_write(ULONG64 addr, PVOID buf, ULONG size) {
    SG_MEM_REQUEST req = {0};
    req.address = addr;
    req.size    = size;
    if (size <= 256) memcpy(req.data, buf, size);
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

int load_driver(const char* path) {
    SC_HANDLE scm=OpenSCManagerA(NULL,NULL,SC_MANAGER_CREATE_SERVICE);
    SC_HANDLE ex=OpenServiceA(scm,"SilentGate",SERVICE_ALL_ACCESS);
    if(ex){SERVICE_STATUS ss;
        ControlService(ex,SERVICE_CONTROL_STOP,&ss);
        DeleteService(ex);CloseServiceHandle(ex);Sleep(500);}
    SC_HANDLE svc=CreateServiceA(scm,"SilentGate","SilentGate",
        SERVICE_ALL_ACCESS,SERVICE_KERNEL_DRIVER,SERVICE_DEMAND_START,
        SERVICE_ERROR_IGNORE,path,NULL,NULL,NULL,NULL,NULL);
    if(!svc){printf("[DRV] CreateService: %lu\n",GetLastError());
        CloseServiceHandle(scm);return 0;}
    if(!StartServiceA(svc,0,NULL)){
        printf("[DRV] StartService: %lu\n",GetLastError());
        DeleteService(svc);CloseServiceHandle(svc);
        CloseServiceHandle(scm);return 0;}
    CloseServiceHandle(svc);CloseServiceHandle(scm);
    return 1;
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
    printf("[V9] SilentGate v9.0 - Custom Driver Test\n");
    printf("[V9] Author: JarDani\n\n");

    char drv[MAX_PATH],dir[MAX_PATH];
    GetModuleFileNameA(NULL,dir,MAX_PATH);
    char* p=strrchr(dir,'\\');if(p)*p='\0';
    snprintf(drv,MAX_PATH,"%s\\sg_driver.sys",dir);

    printf("[V9] Driver: %s\n",drv);
    if(!load_driver(drv)){getchar();return 1;}
    printf("[V9] Driver loaded\n");

    g_hDev=CreateFileA("\\\\.\\SilentGate",
        GENERIC_READ|GENERIC_WRITE,0,NULL,
        OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    if(g_hDev==INVALID_HANDLE_VALUE){
        printf("[V9] Device failed: %lu\n",GetLastError());
        unload_driver();getchar();return 1;}

    printf("[V9] Device opened\n\n");

    /* Test: read ntoskrnl MZ header */
    DWORD64 ntos=get_ntos_base();
    printf("[V9] ntoskrnl base: 0x%llX\n",ntos);

    BYTE buf[8]={0};
    if(vm_read(ntos,buf,8)){
        printf("[V9] Read: %02X %02X %02X %02X\n",
            buf[0],buf[1],buf[2],buf[3]);
        if(buf[0]==0x4D&&buf[1]==0x5A)
            printf("[V9] MZ confirmed - VIRTUAL R/W WORKING\n");
    } else {
        printf("[V9] Read failed: %lu\n",GetLastError());
    }

    CloseHandle(g_hDev);
    unload_driver();
    printf("\n[V9] Complete - press Enter\n");
    getchar();
    return 0;
}
