#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsvc.h>
#include <stdio.h>

static SERVICE_STATUS        g_status = {0};
static SERVICE_STATUS_HANDLE g_handle = NULL;

static void log_msg(const char* msg) {
    FILE* f = fopen("C:\\sg_debug.txt", "a");
    if(f) { fprintf(f, "%s\n", msg); fclose(f); }
}

static VOID WINAPI sg_control(DWORD ctrl) {
    log_msg("control called");
    if(ctrl == SERVICE_CONTROL_STOP) {
        g_status.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(g_handle, &g_status);
    }
}

VOID WINAPI ServiceMain(DWORD argc, LPSTR* argv) {
    log_msg("ServiceMain entered");

    g_handle = RegisterServiceCtrlHandlerA("NetworkLocationHelper", sg_control);
    log_msg(g_handle ? "handler registered" : "handler FAILED");
    if(!g_handle) return;

    g_status.dwServiceType      = SERVICE_WIN32_SHARE_PROCESS;
    g_status.dwCurrentState     = SERVICE_START_PENDING;
    g_status.dwControlsAccepted = 0;
    g_status.dwWaitHint         = 10000;
    g_status.dwCheckPoint       = 1;
    BOOL r1 = SetServiceStatus(g_handle, &g_status);
    log_msg(r1 ? "START_PENDING reported" : "START_PENDING FAILED");

    g_status.dwCurrentState     = SERVICE_RUNNING;
    g_status.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    g_status.dwWaitHint         = 0;
    g_status.dwCheckPoint       = 0;
    BOOL r2 = SetServiceStatus(g_handle, &g_status);
    log_msg(r2 ? "RUNNING reported" : "RUNNING FAILED");

    log_msg("sleeping 5 seconds");
    Sleep(5000);

    g_status.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_handle, &g_status);
    log_msg("ServiceMain exiting");
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID v) {
    if(r == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        log_msg("DllMain DLL_PROCESS_ATTACH");
    }
    return TRUE;
}
