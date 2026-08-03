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
    char path[MAX_PATH]; GetSystemDirectoryA(path,MAX_PATH); strcat(path,"\\ntoskrnl.exe");
    HMODULE h=LoadLibraryExA(path,NULL,DONT_RESOLVE_DLL_REFERENCES);
    if(!h) return 0;
    FARPROC f=GetProcAddress(h,name);
    DWORD64 off=(DWORD64)f-(DWORD64)h; FreeLibrary(h);
    return base+off;
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

int main() {
    char drv[MAX_PATH],dir[MAX_PATH];
    GetModuleFileNameA(NULL,dir,MAX_PATH);
    char* p=strrchr(dir,'\\');if(p)*p='\0';
    snprintf(drv,MAX_PATH,"%s\\sg_driver.sys",dir);
    load_driver(drv);

    g_h=CreateFileA("\\\\.\\SilentGate",GENERIC_READ|GENERIC_WRITE,0,NULL,
        OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);

    DWORD64 ntos=get_ntos();
    DWORD64 fn=get_export(ntos,"PsSetLoadImageNotifyRoutine");

    printf("[DUMP] PsSetLoadImageNotifyRoutine at 0x%llX\n", fn);
    printf("[DUMP] First 128 bytes:\n");

    BYTE buf[128]={0};
    vm_read(fn, buf, 128);
    for(int i=0;i<128;i++){
        printf("%02X ",buf[i]);
        if((i+1)%16==0) printf("\n");
    }

    printf("\n[DUMP] Scanning for LEA/MOV patterns:\n");
    for(int i=0;i<120;i++){
        /* E9 = JMP rel32 */
        if(buf[i]==0xE9){
            INT32 off=*(INT32*)&buf[i+1];
            DWORD64 target=fn+i+5+off;
            printf("  +%d: JMP -> 0x%llX\n",i,target);
        }
        /* 48/49/4C 8D = LEA */
        if((buf[i]==0x48||buf[i]==0x49||buf[i]==0x4C)&&buf[i+1]==0x8D){
            INT32 off=*(INT32*)&buf[i+3];
            DWORD64 target=fn+i+7+off;
            printf("  +%d: LEA -> 0x%llX\n",i,target);
        }
        /* 48/49/4C 8B = MOV */
        if((buf[i]==0x48||buf[i]==0x49||buf[i]==0x4C)&&buf[i+1]==0x8B){
            INT32 off=*(INT32*)&buf[i+3];
            DWORD64 target=fn+i+7+off;
            printf("  +%d: MOV -> 0x%llX\n",i,target);
        }
    }

    CloseHandle(g_h);
    unload_driver();
    getchar();
    return 0;
}
