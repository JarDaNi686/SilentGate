#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <tlhelp32.h>
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

typedef NTSTATUS (NTAPI *pNtQuerySystemInformation)(
    ULONG, PVOID, ULONG, PULONG);

/* Simple thread info structure */
typedef struct {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    ULONG pad;
    PVOID StartAddress;
    ULONG_PTR ProcessId;
    ULONG_PTR ThreadId;
    LONG Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    ULONG WaitReason;
    ULONG pad2;
} SG_THREAD_INFO;

typedef struct {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    BYTE Reserved1[48];
    UNICODE_STRING ImageName;
    LONG BasePriority;
    ULONG_PTR ProcessId;
    ULONG_PTR InheritedFromProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
    SG_THREAD_INFO Threads[1];
} SG_PROCESS_INFO;

int main() {
    printf("[KTHREAD] SilentGate v9.0 - Find Thread Info\n\n");

    char drv[MAX_PATH],dir[MAX_PATH];
    GetModuleFileNameA(NULL,dir,MAX_PATH);
    char* p=strrchr(dir,'\\');if(p)*p='\0';
    snprintf(drv,MAX_PATH,"%s\\sg_driver.sys",dir);

    if(!load_driver(drv)){printf("Load failed\n");getchar();return 1;}
    g_h=CreateFileA("\\\\.\\SilentGate",GENERIC_READ|GENERIC_WRITE,0,NULL,
        OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);

    DWORD64 ntos=get_ntos();
    printf("[KTHREAD] ntoskrnl: 0x%llX\n\n",ntos);

    /* Get MsMpEng PID */
    HANDLE psnap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    PROCESSENTRY32 pe; pe.dwSize=sizeof(pe);
    DWORD msmpeng_pid=0;
    if(Process32First(psnap,&pe)){
        do{if(_stricmp(pe.szExeFile,"MsMpEng.exe")==0)
            {msmpeng_pid=pe.th32ProcessID;break;}
        }while(Process32Next(psnap,&pe));
    }
    CloseHandle(psnap);
    printf("[KTHREAD] MsMpEng PID: %lu\n\n",msmpeng_pid);

    /* Query system process info */
    HMODULE ntdll=GetModuleHandleA("ntdll.dll");
    pNtQuerySystemInformation NtQSI=
        (pNtQuerySystemInformation)GetProcAddress(ntdll,
        "NtQuerySystemInformation");

    ULONG sz=4*1024*1024;
    PVOID buf=malloc(sz);
    ULONG ret=0;
    NtQSI(5,buf,sz,&ret);

    SG_PROCESS_INFO* spi=(SG_PROCESS_INFO*)buf;
    while(1){
        if(spi->ProcessId==msmpeng_pid){
            printf("[KTHREAD] MsMpEng threads: %lu\n",spi->NumberOfThreads);
            for(ULONG i=0;i<spi->NumberOfThreads&&i<8;i++){
                SG_THREAD_INFO* t=&spi->Threads[i];
                printf("[KTHREAD] TID=%-6llu Start=0x%llX State=%lu\n",
                    (ULONG64)t->ThreadId,
                    (ULONG64)(ULONG_PTR)t->StartAddress,
                    t->ThreadState);
            }
            break;
        }
        if(!spi->NextEntryOffset) break;
        spi=(SG_PROCESS_INFO*)((BYTE*)spi+spi->NextEntryOffset);
    }
    free(buf);

    CloseHandle(g_h);
    unload_driver();
    printf("\n[KTHREAD] Done - press Enter\n");
    getchar();
    return 0;
}
