/*
 * SilentGate - Indirect Syscall Stub
 * ===================================
 * API    : NtOpenProcess
 * SSN    : 38 (0x26)
 * Author : JarDani
 * License: MIT
 *
 * USAGE:
 *   Include this file in your project.
 *   Call SG_NtOpenProcess() instead of NtOpenProcess().
 *   The stub invokes the syscall indirectly via a clean
 *   ntdll gadget — bypassing EDR user-mode hooks.
 *
 * HOW IT WORKS:
 *   1. SSN 38 is loaded into EAX
 *   2. Execution jumps into a clean ntdll syscall stub
 *   3. The syscall instruction executes from ntdll address space
 *   4. EDR sees the call originating from trusted ntdll code
 *   5. The hook on NtOpenProcess is never triggered
 *
 * MITRE ATT&CK: T1055 - Process Injection / T1106 - Native API
 */

#pragma once
#include <windows.h>
#include <winternl.h>

/* Forward declaration of the ASM stub */
extern NTSTATUS SG_NtOpenProcess(
    PHANDLE          ProcessHandle,
    ACCESS_MASK      DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID       ClientId
);

/*
 * Example usage:
 *
 *   PVOID  base = NULL;
 *   SIZE_T size = 4096;
 *
 *   NTSTATUS status = SG_NtOpenProcess(
 *       GetCurrentProcess(),
 *       &base,
 *       0,
 *       &size,
 *       MEM_COMMIT | MEM_RESERVE,
 *       PAGE_READWRITE
 *   );
 *
 *   if (NT_SUCCESS(status)) {
 *       // memory allocated without triggering EDR hook
 *   }
 */
