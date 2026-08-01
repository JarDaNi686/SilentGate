/*
 * SilentGate v5.0 - Minimal Service DLL Diagnostic
 * Tests pure service framework without payload execution
 * Author: JarDani
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsvc.h>

static SERVICE_STATUS        g_status = {0};
static SERVICE_STATUS_HANDLE g_handle = NULL;

static VOID WINAPI sg_control(DWORD ctrl) {
    if (ctrl == SERVICE_CONTROL_STOP) {
        g_status.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(g_handle, &g_status);
    }
}

VOID WINAPI ServiceMain(DWORD argc, LPSTR* argv) {
    g_handle = RegisterServiceCtrlHandlerA("NetworkLocationHelper", sg_control);
    if (!g_handle) return;

    g_status.dwServiceType      = SERVICE_WIN32_SHARE_PROCESS;
    g_status.dwCurrentState     = SERVICE_RUNNING;
    g_status.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    SetServiceStatus(g_handle, &g_status);

    /* Just sleep 10 seconds then stop */
    Sleep(10000);

    g_status.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_handle, &g_status);
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r) {
    if (reason == DLL_PROCESS_ATTACH)
        DisableThreadLibraryCalls(h);
    return TRUE;
}
