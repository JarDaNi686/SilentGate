#include <windows.h>
#include <psapi.h>
#include <stdio.h>

#define IOCTL_SG_READ_VIRTUAL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)
typedef struct { ULONG64 address; ULONG size; UCHAR data[256]; } SG_MEM;
static HANDLE g_h = INVALID_HANDLE_VALUE;

BOOL vm_read(ULONG64 addr, PVOID buf, ULONG size) {
    SG_MEM req={0}; req.address=addr; req.size=size<256?size:256;
    DWORD bytes=0;
    return DeviceIoControl(g_h,IOCTL_SG_READ_VIRTUAL,
        &req,sizeof(req),buf,size,&bytes,NULL);
}

int load_driver(const char* path) {
    SC_HANDLE scm=OpenSCManagerA(NULL,NULL,SC_MANAGER_CREATE_SERVICE);
    SC_HANDLE ex=OpenServiceA(scm,"SilentGate",SERVICE_ALL_ACCESS);
    if(ex){SERVICE_STATUS ss;ControlService(ex,SERVICE_CONTROL_STOP,&ss);
        DeleteService(ex);CloseServiceHandle(ex);Sleep(500);}
    SC_HANDLE svc=CreateServiceA(scm,"SilentGate","SilentGate",
        SERVICE_ALL_ACCESS,SERVICE_KERNEL_DRIVER,SERVICE_DEMAND_START,
        SERVICE_ERROR_IGNORE,path,NULL,NULL,NULL,NULL,NULL);
    if(!svc){CloseServiceHandle(scm);return 0;}
    BOOL ok=StartServiceA(svc,0,NULL);
    CloseServiceHandle(svc);CloseServiceHandle(scm);
    return ok;
}

void unload_driver() {
    SC_HANDLE scm=OpenSCManagerA(NULL,NULL,SC_MANAGER_CREATE_SERVICE);
    SC_HANDLE svc=OpenServiceA(scm,"SilentGate",SERVICE_ALL_ACCESS);
    if(svc){SERVICE_STATUS ss;ControlService(svc,SERVICE_CONTROL_STOP,&ss);
        Sleep(500);DeleteService(svc);CloseServiceHandle(svc);}
    CloseServiceHandle(scm);
}

DWORD64 get_ntos() {
    DWORD n=0; EnumDeviceDrivers(NULL,0,&n);
    LPVOID* d=(LPVOID*)malloc(n); EnumDeviceDrivers(d,n,&n);
    DWORD64 base=0; char name[MAX_PATH];
    for(DWORD i=0;i<n/sizeof(LPVOID);i++){
        GetDeviceDriverBaseNameA(d[i],name,MAX_PATH);
        if(_stricmp(name,"ntoskrnl.exe")==0||_stricmp(name,"ntkrnlmp.exe")==0)
            {base=(DWORD64)d[i];break;}
    } free(d); return base;
}

DWORD64 get_export(DWORD64 base, const char* name) {
    char path[MAX_PATH]; GetSystemDirectoryA(path,MAX_PATH);
    strcat(path,"\\ntoskrnl.exe");
    HMODULE h=LoadLibraryExA(path,NULL,DONT_RESOLVE_DLL_REFERENCES);
    FARPROC f=GetProcAddress(h,name);
    DWORD64 off=(DWORD64)f-(DWORD64)h; FreeLibrary(h);
    return base+off;
}

int main() {
    printf("[FOLLOW] SilentGate v9.0 - Follow CALL chain\n\n");

    char drv[MAX_PATH],dir[MAX_PATH];
    GetModuleFileNameA(NULL,dir,MAX_PATH);
    char* p=strrchr(dir,'\\');if(p)*p='\0';
    snprintf(drv,MAX_PATH,"%s\\sg_driver.sys",dir);

    if(!load_driver(drv)){printf("Load failed\n");getchar();return 1;}
    g_h=CreateFileA("\\\\.\\SilentGate",GENERIC_READ|GENERIC_WRITE,0,NULL,
        OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);

    DWORD64 ntos = get_ntos();
    DWORD64 fn   = get_export(ntos, "PsSetLoadImageNotifyRoutine");

    printf("[FOLLOW] ntoskrnl: 0x%llX\n", ntos);
    printf("[FOLLOW] PsSetLoadImageNotifyRoutine: 0x%llX\n\n", fn);

    /* Read first 16 bytes to find the CALL at offset 6 */
    BYTE buf[16]={0};
    vm_read(fn, buf, 16);

    /* buf[6] = E8 = CALL, offset at buf[7..10] */
    if(buf[6]==0xE8){
        INT32 off = *(INT32*)&buf[7];
        DWORD64 called = fn + 6 + 5 + off;
        printf("[FOLLOW] CALL at +6 -> 0x%llX\n\n", called);

        /* Read 128 bytes of called function */
        BYTE buf2[128]={0};
        vm_read(called, buf2, 128);

        printf("[FOLLOW] Called function bytes:\n");
        for(int i=0;i<128;i++){
            printf("%02X ",buf2[i]);
            if((i+1)%16==0) printf("\n");
        }

        printf("\n[FOLLOW] Patterns in called function:\n");
        for(int i=0;i<120;i++){
            /* LEA */
            if((buf2[i]==0x48||buf2[i]==0x4C||buf2[i]==0x49)&&buf2[i+1]==0x8D){
                INT32 roff=*(INT32*)&buf2[i+3];
                DWORD64 target=called+i+7+roff;
                printf("  +%d: LEA -> 0x%llX\n",i,target);
            }
            /* CALL E8 */
            if(buf2[i]==0xE8){
                INT32 roff=*(INT32*)&buf2[i+1];
                DWORD64 target=called+i+5+roff;
                printf("  +%d: CALL -> 0x%llX\n",i,target);
            }
        }
    }

    CloseHandle(g_h);
    unload_driver();
    printf("\n[FOLLOW] Done - press Enter\n");
    getchar();
    return 0;
}
