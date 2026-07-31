/*
 * SilentGate - Gadget Finder
 * ==========================
 * Locates the clean syscall gadget in ntdll at runtime.
 * Call this ONCE before using SG_NtWriteVirtualMemory().
 */

#include <windows.h>

QWORD SG_NtWriteVirtualMemory_addr = 0;

BOOL SG_Init_NtWriteVirtualMemory() {
    /* Step 1 - Get ntdll base address */
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return FALSE;

    /* Step 2 - Find the function in ntdll exports */
    FARPROC func = GetProcAddress(ntdll, "NtWriteVirtualMemory");
    if (!func) return FALSE;

    /* Step 3 - Scan for syscall + ret (0F 05 C3) */
    BYTE* ptr = (BYTE*)func;
    for (int i = 0; i < 32; i++) {
        if (ptr[i] == 0x0F && ptr[i+1] == 0x05 && ptr[i+2] == 0xC3) {
            /* Found clean syscall gadget */
            SG_NtWriteVirtualMemory_addr = (QWORD)(ptr + i);
            return TRUE;
        }
    }

    return FALSE;  /* gadget not found */
}
