/*
 * SilentGate - Indirect Syscall Stub
 * ===================================
 * API    : NtWriteVirtualMemory
 * SSN    : 58 (0x3a)
 * Author : JarDan
 * License: MIT
 *
 * USAGE:
 *   Include this file in your project.
 *   Call SG_NtWriteVirtualMemory() instead of NtWriteVirtualMemory().
 *   The stub invokes the syscall indirectly via a clean
 *   ntdll gadget — bypassing EDR user-mode hooks.
 *
 * HOW IT WORKS:
 *   1. SSN 58 is loaded into EAX
 *   2. Execution jumps into a clean ntdll syscall stub
 *   3. The syscall instruction executes from ntdll address space
 *   4. EDR sees the call originating from trusted ntdll code
 *   5. The hook on NtWriteVirtualMemory is never triggered
 *
 * MITRE ATT&CK: T1055 - Process Injection / T1106 - Native API
 */

#pragma once
#include <windows.h>
#include <winternl.h>

/* Forward declaration of the ASM stub */
extern NTSTATUS SG_NtWriteVirtualMemory(
    HANDLE           ProcessHandle,
    PVOID            BaseAddress,
    PVOID            Buffer,
    SIZE_T           NumberOfBytesToWrite,
    PSIZE_T          NumberOfBytesWritten
);

/*
 * Example usage:
 *
 *   PVOID  base = NULL;
 *   SIZE_T size = 4096;
 *
 *   NTSTATUS status = SG_NtWriteVirtualMemory(
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
