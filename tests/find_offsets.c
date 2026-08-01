#include <windows.h>
#include <winternl.h>
#include <stdio.h>

int main() {
    BYTE* peb = (BYTE*)__readgsqword(0x60);
    BYTE* ldr  = *(BYTE**)(peb + 0x18);
    BYTE* head = *(BYTE**)(ldr + 0x20);

    /* Walk to kernel32 */
    BYTE* e = head;
    for (int i = 0; i < 10; i++) {
        e = *(BYTE**)e;  /* flink */
        /* Try every offset from 0x10 to 0x60 for DllBase */
        for (int off = 0x10; off <= 0x60; off += 8) {
            HMODULE base = *(HMODULE*)(e + off);
            if (base == GetModuleHandleA("kernel32.dll")) {
                printf("[FOUND] flink[%d] offset=0x%02X = kernel32 base\n", i, off);
            }
            if (base == GetModuleHandleA("ntdll.dll")) {
                printf("[FOUND] flink[%d] offset=0x%02X = ntdll base\n", i, off);
            }
        }
    }
    getchar();
    return 0;
}
