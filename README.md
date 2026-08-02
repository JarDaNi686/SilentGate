# SilentGate

> "Security is not an option. It is a need.
> Like every great thing — it should be open."
> — JarDani

**Advanced EDR Evasion Framework with Mathematical Payload Obfuscation**

[![License: MIT](https://img.shields.io/badge/License-MIT-red.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![Tests](https://img.shields.io/badge/Tests-94%20passed-brightgreen.svg)](tests/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20x64-lightgrey.svg)](README.md)

---

## Proven Results

Tested against real Windows Defender fully enabled:

| Target | Defender | Shell | Detections | UAC |
|--------|----------|-------|------------|-----|
| Windows 10 x64 | Fully ON | Connected | 0 | No |
| Windows 11 x64 | Fully ON | Connected | 0 | No |
| Windows Server 2024 | OFF | Connected | 0 | No |

---

## Seven Version Layers

v1.0 Indirect Syscall Stub Generator
Dynamic SSN resolution by walking ntdll.dll PE export table.
ASCII call stack visualiser. EDR confidence ratings.

v2.0 Defence Layer
Ntdll unhooking. Sleep encryption XOR 256-bit. ETW patching.

v3.0 Evasion Depth
Call stack spoofing. Polymorphic stub mutation.

v4.0 Spectral Payload Decomposition DNA Chain
Seven-gene mathematical pipeline.
DFT frequency domain storage. SVD Tucker decomposition.
Eigenvalue camouflage matching Windows DLL entropy.
Cooley-Tukey FFT O(N log N) reconstruction.
Payload never exists as bytes until nanosecond of execution.

v5.0 Phantom Service Architecture
Windows Service DLL. DNS C2 via svchost. Task Scheduler persistence.

v6.0 NTFS Steganography
Spectral blob hidden in Alternate Data Streams.
Cover file appears empty. Zero detections.

v7.0 Custom TCP Reverse Shell
Hand-written C. No msfvenom. No PowerShell.
PEB walk verified offsets. ROR13 hash API resolution.
Poisson sleep breaks Win10 behavioral ML timing correlation.
Standard user account. No UAC prompt.

---

## Mathematical Foundation

DFT/IDFT     Fourier Analysis      Payload in frequency domain
SVD          Linear Algebra        Three-matrix key splitting
Shannon H    Information Theory    Statistical camouflage
Poisson      Probability Theory    Temporal fragmentation
ROR13        Number Theory         API resolution
Cooley-Tukey Algorithms            O(N log N) reconstruction

---

## Verified API Hashes Windows x64

GetProcAddress      0x7C0DFCAA
LoadLibraryA        0xEC0E4E8E
CreateProcessA      0x16B3FE72
WaitForSingleObject 0xCE05D9AD
WSAStartup          0x3BFCEDCB
WSASocketA          0xADF509D9
connect             0x60AAF9EC
WinExec             0x0E8AFE98

---

## Installation

git clone https://github.com/JarDaNi686/SilentGate.git
cd SilentGate
pip install -r requirements.txt

---

## Honest Limitations

Cannot bypass from user mode:
  PPL protected processes
  Kernel ETW callbacks
  Hardware level monitoring Intel PT
  Hypervisor EDR

---

## Roadmap

v8.0  Galois field GF(2^8) encoding
      Kolmogorov complexity maximisation
      Poincare chaotic map polymorphism

v9.0  Signed kernel driver
      PPL bypass
      Full kernel-mode evasion

---

## MITRE ATT&CK

T1055 T1055.003 T1055.012 T1106 T1562.001 T1562.006
T1027 T1027.002 T1543.003 T1053.005 T1071.004
T1564.004 T1548.002 T1134.001

---

## Author

JarDani — MSc Cyber Security IU International University Berlin

---

## License

MIT — Free for the security community.

Security is not an option. It is a need.
And what the world needs should belong to everyone.
