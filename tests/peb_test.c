#include <windows.h>
#include <winternl.h>
#include <stdio.h>

int main() {
    printf("[PEB] Testing PEB walk on this system\n\n");

    /* Walk PEB module list and print all modules */
    PEB* peb = (PEB*)__readgsqword(0x60);
    PEB_LDR_DATA* ldr = peb->Ldr;
    LIST_ENTRY* head = &ldr->InMemoryOrderModuleList;
    LIST_ENTRY* curr = head->Flink;

    int idx = 0;
    while (curr != head && idx < 10) {
        LDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD(
            curr, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        if (entry->FullDllName.Buffer) {
            printf("[PEB] Module %d: %ls base=%p\n",
                idx,
                entry->FullDllName.Buffer,
                entry->DllBase);
        }
        curr = curr->Flink;
        idx++;
    }

    printf("\n[PEB] kernel32 should be at index 2\n");
    printf("[PEB] If it is at different index - PEB walk needs adjustment\n");
    getchar();
    return 0;
}
