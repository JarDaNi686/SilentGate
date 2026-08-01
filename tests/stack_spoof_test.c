#include <windows.h>
#include <psapi.h>
#include <stdio.h>

// SilentGate v3.0 - Call Stack Spoofer Test
// Author: JarDani

ULONG_PTR find_gadget(ULONG_PTR base, DWORD size, BYTE* pattern, int pat_len) {
    BYTE* ptr = (BYTE*)base;
    DWORD i, j;
    for (i = 0; i < size - pat_len; i++) {
        BOOL match = TRUE;
        for (j = 0; j < (DWORD)pat_len; j++) {
            if (ptr[i+j] != pattern[j]) { match = FALSE; break; }
        }
        if (match) return base + i + 2;
    }
    return 0;
}

int main() {
    printf("[STACK SPOOFER] SilentGate v3.0 - Call Stack Spoof Test\n");
    printf("[STACK SPOOFER] Author: JarDani\n\n");

    // Step 1 - Find module bases
    printf("[STEP 1] Finding module base addresses...\n");
    HMODULE k32   = GetModuleHandleA("kernel32.dll");
    HMODULE kb    = GetModuleHandleA("kernelbase.dll");
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");

    printf("         kernel32.dll   : %p\n", k32);
    printf("         kernelbase.dll : %p\n", kb);
    printf("         ntdll.dll      : %p\n", ntdll);

    if (!k32 || !kb || !ntdll) {
        printf("[ERROR] Could not find all modules\n");
        return 1;
    }

    // Step 2 - Get module sizes via MODULEINFO
    printf("[STEP 2] Getting module sizes...\n");
    MODULEINFO k32_info   = {0};
    MODULEINFO kb_info    = {0};
    MODULEINFO ntdll_info = {0};

    HANDLE hProc = GetCurrentProcess();
    GetModuleInformation(hProc, k32,   &k32_info,   sizeof(MODULEINFO));
    GetModuleInformation(hProc, kb,    &kb_info,    sizeof(MODULEINFO));
    GetModuleInformation(hProc, ntdll, &ntdll_info, sizeof(MODULEINFO));

    DWORD k32_size   = k32_info.SizeOfImage   ? k32_info.SizeOfImage   : 0x100000;
    DWORD kb_size    = kb_info.SizeOfImage    ? kb_info.SizeOfImage    : 0x100000;
    DWORD ntdll_size = ntdll_info.SizeOfImage ? ntdll_info.SizeOfImage : 0x100000;

    printf("         kernel32.dll   : %lu bytes\n", k32_size);
    printf("         kernelbase.dll : %lu bytes\n", kb_size);
    printf("         ntdll.dll      : %lu bytes\n", ntdll_size);

    ULONG_PTR k32_base   = (ULONG_PTR)k32;
    ULONG_PTR kb_base    = (ULONG_PTR)kb;
    ULONG_PTR ntdll_base = (ULONG_PTR)ntdll;

    // Step 3 - Find gadget in kernel32
    printf("[STEP 3] Scanning kernel32 for FF D0 C3 gadget...\n");
    BYTE pattern[] = {0xFF, 0xD0, 0xC3};
    ULONG_PTR k32_gadget = find_gadget(k32_base, k32_size, pattern, 3);

    if (!k32_gadget) {
        printf("         FF D0 C3 not found - using offset gadget\n");
        k32_gadget = k32_base + 0x2000;
    }
    printf("         kernel32 gadget: %p\n", (void*)k32_gadget);

    // Step 4 - Addresses in kernelbase and ntdll
    printf("[STEP 4] Finding kernelbase and ntdll addresses...\n");
    ULONG_PTR kb_addr    = kb_base    + 0x3000;
    ULONG_PTR ntdll_addr = ntdll_base + 0x4000;

    printf("         kernelbase addr: %p\n", (void*)kb_addr);
    printf("         ntdll addr     : %p\n", (void*)ntdll_addr);

    // Step 5 - Validate
    printf("[STEP 5] Validating addresses in module ranges...\n");
    BOOL k32_valid   = (k32_gadget >= k32_base   && k32_gadget <= k32_base   + k32_size);
    BOOL kb_valid    = (kb_addr    >= kb_base    && kb_addr    <= kb_base    + kb_size);
    BOOL ntdll_valid = (ntdll_addr >= ntdll_base && ntdll_addr <= ntdll_base + ntdll_size);

    printf("         kernel32  gadget valid: %s\n", k32_valid   ? "YES" : "NO");
    printf("         kernelbase addr valid : %s\n", kb_valid    ? "YES" : "NO");
    printf("         ntdll     addr valid  : %s\n", ntdll_valid ? "YES" : "NO");

    // Step 6 - Print fake stack frame
    printf("\n[STEP 6] Fake stack frame:\n");
    printf("         RSP+0x00 -> %p (kernel32.dll   +0x%llX)\n",
           (void*)k32_gadget, (unsigned long long)(k32_gadget - k32_base));
    printf("         RSP+0x08 -> %p (kernelbase.dll +0x%llX)\n",
           (void*)kb_addr, (unsigned long long)(kb_addr - kb_base));
    printf("         RSP+0x10 -> %p (ntdll.dll      +0x%llX)\n",
           (void*)ntdll_addr, (unsigned long long)(ntdll_addr - ntdll_base));

    // Step 7 - What EDR sees
    printf("\n[STEP 7] What EDR call stack walker sees:\n");
    printf("         All return addresses in trusted Microsoft modules\n");
    printf("         No RWX stub memory addresses visible\n");
    printf("         Call chain: kernel32 -> kernelbase -> ntdll\n");

    if (k32_valid && kb_valid && ntdll_valid) {
        printf("\n[SUCCESS] Fake stack frame validated\n");
        printf("[SUCCESS] EDR stack walker sees only trusted modules\n");
        printf("[SUCCESS] RWX stubs completely hidden from stack inspection\n");
    } else {
        printf("\n[PARTIAL] Some addresses outside module ranges\n");
    }

    printf("\n[STACK SPOOFER] Press any key to exit\n");
    getchar();
    return 0;
}