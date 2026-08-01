"""
SilentGate - GENE 5: C Reconstructor Generator
INPUT  : camouflaged matrices + noise vectors + metadata (GENE 4)
OUTPUT : self-contained C library file (no main)
CONTRACT: output feeds into GENE 6 temporal_fragmenter.py
"""

import numpy as np
import json
import os


def matrix_to_c_array(matrix, name):
    flat = matrix.flatten()
    if np.iscomplexobj(flat):
        rv = ", ".join(f"{v.real:.17g}" for v in flat)
        iv = ", ".join(f"{v.imag:.17g}" for v in flat)
        return (f"static const double {name}_real[] = {{{rv}}};\n"
                f"static const double {name}_imag[] = {{{iv}}};\n")
    else:
        v = ", ".join(f"{x:.17g}" for x in flat)
        return f"static const double {name}[] = {{{v}}};\n"


def generate(G_cam, A1_cam, A2_cam, G_noise, A1_noise, A2_noise, metadata):
    rows, cols  = metadata["matrix_shape"]
    coeff_count = metadata["coeff_count"]
    orig_len    = metadata["original_length"]
    padded_len  = metadata["padded_length"]

    G_clean  = (G_cam  - G_noise).real
    A1_clean = A1_cam  - A1_noise
    A2_clean = A2_cam  - A2_noise
    rank     = len(G_clean)

    c_code  = f"""/*
 * SilentGate - Spectral Reconstructor Library
 * Author: JarDani  License: MIT
 * NO main() - library called by GENE7 orchestrator
 */
#include <windows.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#define PI 3.14159265358979323846
#define ORIG_LEN    {orig_len}
#define PADDED_LEN  {padded_len}
#define COEFF_COUNT {coeff_count}
#define ROWS        {rows}
#define COLS        {cols}
#define RANK        {rank}

"""
    c_code += matrix_to_c_array(G_clean,  "sg_G")
    c_code += "\n"
    c_code += matrix_to_c_array(A1_clean, "sg_A1")
    c_code += "\n"
    c_code += matrix_to_c_array(A2_clean, "sg_A2")
    c_code += """
static void idft(double* rr,double* ri,int N,double* or_,double* oi){
    int n,k;
    for(n=0;n<N;n++){
        or_[n]=0;oi[n]=0;
        for(k=0;k<N;k++){
            double a=2.0*PI*k*n/N;
            or_[n]+=rr[k]*cos(a)-ri[k]*sin(a);
            oi[n]+=rr[k]*sin(a)+ri[k]*cos(a);
        }
        or_[n]/=N;oi[n]/=N;
    }
}

static void matmul_c(double* ar,double* ai,int ra,int ca,
                     double* br,double* bi,int rb,int cb,
                     double* cr,double* ci){
    int i,j,k;
    memset(cr,0,ra*cb*sizeof(double));
    memset(ci,0,ra*cb*sizeof(double));
    for(i=0;i<ra;i++) for(k=0;k<ca;k++){
        double are=ar[i*ca+k],aim=ai[i*ca+k];
        for(j=0;j<cb;j++){
            cr[i*cb+j]+=are*br[k*cb+j]-aim*bi[k*cb+j];
            ci[i*cb+j]+=are*bi[k*cb+j]+aim*br[k*cb+j];
        }
    }
}

unsigned char* sg_reconstruct(int* out_len){
    int i,j;
    double* A1s_r=(double*)calloc(ROWS*RANK,sizeof(double));
    double* A1s_i=(double*)calloc(ROWS*RANK,sizeof(double));
    for(i=0;i<ROWS;i++) for(j=0;j<RANK;j++){
        A1s_r[i*RANK+j]=sg_A1_real[i*ROWS+j]*sg_G[j];
        A1s_i[i*RANK+j]=sg_A1_imag[i*ROWS+j]*sg_G[j];
    }
    double* M_r=(double*)calloc(ROWS*COLS,sizeof(double));
    double* M_i=(double*)calloc(ROWS*COLS,sizeof(double));
    matmul_c(A1s_r,A1s_i,ROWS,RANK,
             (double*)sg_A2_real,(double*)sg_A2_imag,RANK,COLS,M_r,M_i);
    free(A1s_r);free(A1s_i);
    double* cr=(double*)calloc(PADDED_LEN,sizeof(double));
    double* ci=(double*)calloc(PADDED_LEN,sizeof(double));
    for(i=0;i<COEFF_COUNT&&i<PADDED_LEN;i++){cr[i]=M_r[i];ci[i]=M_i[i];}
    free(M_r);free(M_i);
    double* rr=(double*)calloc(PADDED_LEN,sizeof(double));
    double* ri=(double*)calloc(PADDED_LEN,sizeof(double));
    idft(cr,ci,PADDED_LEN,rr,ri);
    free(cr);free(ci);
    unsigned char* p=(unsigned char*)malloc(ORIG_LEN);
    for(i=0;i<ORIG_LEN;i++){
        int v=(int)round(rr[i]);
        if(v<0)v=0;if(v>255)v=255;
        p[i]=(unsigned char)v;
    }
    free(rr);free(ri);
    *out_len=ORIG_LEN;
    return p;
}
"""
    return c_code


def save_c_file(c_code, path="output/gene5_reconstructor.c"):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(c_code)


def save_metadata(metadata, path="output/gene5_metadata.json"):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    meta5 = {**metadata, "gene": 5,
              "output_contract": "C library -> GENE6 temporal_fragmenter"}
    with open(path, "w") as f:
        json.dump(meta5, f, indent=2)
    return meta5


if __name__ == "__main__":
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from core.gene1_payload_ingester       import ingest
    from core.gene2_dft_encoder            import encode
    from core.gene3_tensor_splitter        import split
    from core.gene4_eigenvalue_camouflager import camouflage

    test_payload = bytes([0x55,0x48,0x89,0xE5,0x48,0x83,0xEC,0x20,
                          0x48,0x31,0xC9,0x48,0x31,0xC0,0x48,0x83,
                          0xC4,0x28,0xC3])

    arr,meta1    = ingest(test_payload, source_type="bytes")
    coeffs,meta2 = encode(arr, meta1)
    G,A1,A2,meta3= split(coeffs, meta2)
    G_cam,A1_cam,A2_cam,G_n,A1_n,A2_n,meta4 = camouflage(G,A1,A2,meta3)

    c_code = generate(G_cam,A1_cam,A2_cam,G_n,A1_n,A2_n,meta4)
    save_c_file(c_code)
    meta5 = save_metadata(meta4)

    print(f"[GENE 5] OUTPUT : {c_code.count(chr(10))} lines")
    print(f"[GENE 5] main() present: {chr(10)+'int main' in c_code}")
    print(f"[GENE 5] READY  : -> GENE 6")
