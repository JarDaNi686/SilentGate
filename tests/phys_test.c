#include <windows.h>
#include <psapi.h>
#include <stdio.h>

#define OLS_TYPE 40000
#define IOCTL_OLS_READ_MEMORY \
    CTL_CODE(OLS_TYPE, 0x841, METHOD_BUFFERED, FILE_READ_ACCESS)

#pragma pack(push,4)
typedef struct {
    LARGE_INTEGER Address;
    ULONG UnitSize;
    ULONG Count;
} OLS_READ_MEM_INPUT;
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
    printf("[PHYS] WinRing0 Physical Memory Test\n");
    printf("[PHYS] Author: JarDani\n\n");

    char drv[MAX_PATH],dir[MAX_PATH];
    GetModuleFileNameA(NULL,dir,MAX_PATH);
    char* p=strrchr(dir,'\\');if(p)*p='\0';
    snprintf(drv,MAX_PATH,"%s\\WinRing0x64.sys",dir);
    load_driver(drv);

    HANDLE h=CreateFileA("\\\\.\\WinRing0_1_2_0",
        GENERIC_READ|GENERIC_WRITE,0,NULL,
        OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);

    /* Try reading physical addresses with different unit sizes */
    /* UnitSize: 1=byte, 2=word, 4=dword */
    DWORD64 test_addrs[] = {0x1000, 0x2000, 0x5000, 0xA000, 0};
    ULONG unit_sizes[]   = {1, 2, 4, 0};

    for (int a = 0; test_addrs[a]; a++) {
        for (int u = 0; unit_sizes[u]; u++) {
            OLS_READ_MEM_INPUT req = {0};
            req.Address.QuadPart = (LONGLONG)test_addrs[a];
            req.UnitSize = unit_sizes[u];
            req.Count    = 4;

            BYTE out[16] = {0};
            DWORD bytes  = 0;
            BOOL ok = DeviceIoControl(h, IOCTL_OLS_READ_MEMORY,
                &req, sizeof(req), out, sizeof(out), &bytes, NULL);

            if (ok && bytes > 0) {
                printf("[PHYS] addr=0x%llX unit=%lu count=4 -> OK bytes=%lu: ",
                    test_addrs[a], unit_sizes[u], bytes);
                for (DWORD i=0;i<bytes&&i<8;i++) printf("%02X ",out[i]);
                printf("\n");
            }
        }
    }

    CloseHandle(h);
    unload_driver();
    getchar();
    return 0;
}
