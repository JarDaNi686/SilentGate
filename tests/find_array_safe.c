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

int main() {
    printf("[SAFE] SilentGate v9.0 - Safe Callback Array Finder\n");
    printf("[SAFE] Author: JarDani\n\n");

    char drv[MAX_PATH],dir[MAX_PATH];
    GetModuleFileNameA(NULL,dir,MAX_PATH);
    char* p=strrchr(dir,'\\');if(p)*p='\0';
    snprintf(drv,MAX_PATH,"%s\\sg_driver.sys",dir);
    
    if(!load_driver(drv)){printf("Load failed\n");getchar();return 1;}
    g_h=CreateFileA("\\\\.\\SilentGate",GENERIC_READ|GENERIC_WRITE,0,NULL,
        OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);

    DWORD64 ntos = get_ntos();
    printf("[SAFE] ntoskrnl base: 0x%llX\n\n", ntos);

    /* Load ntoskrnl from disk to find PsSetLoadImageNotifyRoutine offset */
    char ntos_path[MAX_PATH];
    GetSystemDirectoryA(ntos_path, MAX_PATH);
    strcat(ntos_path, "\\ntoskrnl.exe");

    HMODULE disk = LoadLibraryExA(ntos_path, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!disk) { printf("Cannot load ntoskrnl from disk\n"); getchar(); return 1; }

    FARPROC fn = GetProcAddress(disk, "PsSetLoadImageNotifyRoutine");
    DWORD64 fn_offset = (DWORD64)fn - (DWORD64)disk;
    DWORD64 fn_runtime = ntos + fn_offset;

    printf("[SAFE] PsSetLoadImageNotifyRoutine offset: 0x%llX\n", fn_offset);
    printf("[SAFE] PsSetLoadImageNotifyRoutine runtime: 0x%llX\n\n", fn_runtime);

    /* Read disk bytes of function to find callback array offset */
    BYTE* disk_fn = (BYTE*)fn;
    printf("[SAFE] Disk bytes of function:\n");
    for(int i=0;i<64;i++){
        printf("%02X ", disk_fn[i]);
        if((i+1)%16==0) printf("\n");
    }
    printf("\n");

    /* Scan disk bytes for LEA/MOV patterns */
    printf("[SAFE] Patterns in disk image:\n");
    for(int i=0;i<60;i++){
        if((disk_fn[i]==0x48||disk_fn[i]==0x49||disk_fn[i]==0x4C)
            && disk_fn[i+1]==0x8D){
            INT32 off=*(INT32*)&disk_fn[i+3];
            /* This is relative to disk base - convert to offset */
            DWORD64 disk_target = (DWORD64)fn + i + 7 + off;
            DWORD64 array_offset = disk_target - (DWORD64)disk;
            DWORD64 runtime_array = ntos + array_offset;
            printf("  +%d: LEA disk=0x%llX offset=0x%llX runtime=0x%llX\n",
                i, disk_target, array_offset, runtime_array);
        }
        if((disk_fn[i]==0x48||disk_fn[i]==0x49||disk_fn[i]==0x4C)
            && disk_fn[i+1]==0x8D && disk_fn[i+2]==0x05){
            INT32 off=*(INT32*)&disk_fn[i+3];
            DWORD64 disk_target=(DWORD64)fn+i+7+off;
            DWORD64 array_offset=disk_target-(DWORD64)disk;
            DWORD64 runtime_array=ntos+array_offset;
            printf("  +%d: LEA r8d disk=0x%llX runtime=0x%llX\n",
                i, disk_target, runtime_array);
        }
    }

    /* Now safely read just the first entry of callback array */
    /* We know ntoskrnl data section is safe to read */
    /* Scan ntoskrnl .data section for callback pattern */
    printf("\n[SAFE] Scanning ntoskrnl .data section for callbacks...\n");

    /* Read ntoskrnl PE sections from disk */
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)disk;
    IMAGE_NT_HEADERS* nt  = (IMAGE_NT_HEADERS*)((BYTE*)disk + dos->e_lfanew);
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);

    for(WORD s=0; s<nt->FileHeader.NumberOfSections; s++) {
        if(memcmp(sec[s].Name, ".data", 5)==0 ||
           memcmp(sec[s].Name, "ALMOSTRO", 8)==0 ||
           memcmp(sec[s].Name, "NONPAGED", 8)==0) {
            DWORD64 sec_runtime = ntos + sec[s].VirtualAddress;
            printf("[SAFE] Section %s at runtime 0x%llX size=0x%X\n",
                sec[s].Name, sec_runtime, sec[s].Misc.VirtualSize);

            /* Safely read 64 bytes at start of section */
            BYTE buf[64]={0};
            if(vm_read(sec_runtime, buf, 64)){
                printf("[SAFE] First 16 bytes: ");
                for(int i=0;i<16;i++) printf("%02X ",buf[i]);
                printf("\n");
            }
        }
    }

    FreeLibrary(disk);
    CloseHandle(g_h);
    unload_driver();
    printf("\n[SAFE] Done - press Enter\n");
    getchar();
    return 0;
}
