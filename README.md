# SilentGate

> "Security is not an option. It is a need.
> Like every great thing — it should be open."
> — JarDani

**Indirect Syscall Stub Generator with EDR Evasion Intelligence Layer**

[![License: MIT](https://img.shields.io/badge/License-MIT-red.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Windows%20x64-lightgrey.svg)]()
[![Tests](https://img.shields.io/badge/Tests-30%20passed-brightgreen.svg)]()

---

## What Is SilentGate?

Modern EDR products place hooks inside ntdll.dll.
Every payload that calls a hooked API gets intercepted and killed
before it reaches the kernel.

SilentGate generates indirect syscall stubs that bypass these hooks
by jumping into a clean ntdll gadget — making the syscall appear
to originate from trusted ntdll code rather than your payload.

Unlike every other tool in this space — SilentGate explains everything.

---

## What Makes SilentGate Different

Every existing tool (SysWhispers3, RecycledGate, FreshyCalls) generates
the stub and says nothing. SilentGate does four things no other tool does:

**1 — Dynamic SSN Resolution**
Resolves Syscall Service Numbers at runtime by walking the ntdll.dll
PE export table. No hardcoded lookup tables. Works on any Windows build.

**2 — ASCII Call Stack Visualisation**
Prints a live diagram showing exactly where the EDR hook sits and
exactly where the indirect jump bypasses it.

**3 — Confidence Intelligence Layer**
Rates evasion confidence per EDR product with honest explanation
of what would still catch the technique.

**4 — Defender Perspective**
For every technique, prints what a blue team needs to detect it.
Event IDs, ETW providers, SIEM rules.
Because real red teamers understand both sides.

---

## Supported APIs

These 5 APIs cover the complete shellcode injection chain.
EDR products hook all of them without exception.

| API | Role | SSN (Win10 22H2) |
|-----|------|-----------------|
| NtAllocateVirtualMemory | Allocate memory for shellcode | 24 (0x18) |
| NtWriteVirtualMemory | Write shellcode into memory | 58 (0x3a) |
| NtProtectVirtualMemory | Mark memory as executable | 80 (0x50) |
| NtCreateThreadEx | Create execution thread | 199 (0xc7) |
| NtOpenProcess | Access target process | 38 (0x26) |

---

## Installation

```bash
git clone https://github.com/JarDaNi686/SilentGate.git
cd SilentGate
pip install -r requirements.txt
```

---

## Usage

```bash
# List all supported APIs with EDR context
python3 silentgate.py --list

# Generate stub for one API with full explanation
python3 silentgate.py --api NtAllocateVirtualMemory --explain

# Generate stub and save markdown report
python3 silentgate.py --api NtCreateThreadEx --report

# Generate all 5 APIs with explanation and reports
python3 silentgate.py --all --explain --report
```

---

## Output

For each API SilentGate generates:

```
output/
  stub_NtAllocateVirtualMemory.h
  stub_NtAllocateVirtualMemory.asm
  gadget_NtAllocateVirtualMemory.c
  evasion_report_NtAllocateVirtualMemory.md
```

---

## How It Works

### The Problem

```
ntdll.dll in memory after EDR loads:
NtAllocateVirtualMemory:
  offset +0  | E9 XX XX XX XX | JMP to EDR handler  <- HOOKED
  offset +8  | 0F 05          | syscall
  offset +10 | C3             | ret
```

### The Solution

```
SilentGate resolves SSN at runtime:
  Parses ntdll.dll PE export table
  Reads mov eax instruction at function start
  Extracts SSN = 24 for NtAllocateVirtualMemory

Generates stub:
  mov r10, rcx       Windows x64 ABI
  mov eax, 18h       SSN = 24
  jmp [gadget_addr]  jump to clean ntdll syscall

Result:
  Syscall executes from ntdll address space
  EDR sees trusted origin
  Hook never triggered
  Kernel executes real function
```

---

## MITRE ATT&CK Mapping

| ID | Technique |
|----|-----------|
| TA0005 | Defense Evasion |
| T1055 | Process Injection |
| T1055.003 | Thread Execution Hijacking |
| T1055.012 | Process Hollowing |
| T1106 | Native API |
| T1562.001 | Impair Defenses |
| T1027 | Obfuscated Files or Information |

---

## Running Tests

```bash
python3 -m pytest tests/ -v
```

30 passed in 0.17s

---

## Lab Environment

Built and tested in an isolated lab:

| VM | Role | OS |
|----|------|----|
| kali-attacker | Development | Kali Linux 2024.2 |
| win10-victim | Defender ON | Windows 10 Pro |
| win10-sandbox | Defender OFF | Windows 10 Pro |

Network: Host-Only — completely isolated from internet

---

## Honest Limitations

SilentGate bypasses user-mode EDR hooks. It does NOT bypass:

- Kernel ETW callbacks
- Behavioural correlation detection
- Memory scanning
- Call stack analysis

These limitations are documented in every generated report.
Understanding limitations is part of professional red teaming.

---

## Long Term Vision

```
v1.0  Current  5 APIs, x64, Windows 10/11
               Dynamic SSN resolution
               ASCII visualiser + intelligence layer

v2.0  Expanded API coverage
      x86 support
      Windows Server editions

v3.0  Plugin architecture
      Community contributions
      C2 framework integration
```

---


---

## What SilentGate v1.0 Is and Is Not

**What it is:**

SilentGate is an intelligence-driven indirect syscall stub generator and wrapper.

It resolves real Syscall Service Numbers dynamically from ntdll.dll, generates
ready-to-use C and ASM stub code, explains every decision with MITRE ATT&CK
mapping, rates evasion confidence per EDR product, and provides the defender
perspective for every technique.

**What it is not (yet):**

SilentGate v1.0 does not compile or execute anything automatically. The red
teamer uses the generated stubs and resolved SSN values to build their own
execution wrapper. The tool is a generator and intelligence layer — not an
end-to-end attack framework.

**Lab tested:**

The indirect syscall technique was validated in an isolated lab against
Windows 10 x64 with Windows Defender fully enabled. The baseline direct
API call payload was hard blocked. The SilentGate indirect syscall
implementation produced zero detections across all 4 protection layers.

**v2.0 goal:**

Automate the full pipeline — generate stubs, write the wrapper, compile,
and produce a ready-to-test executable in one command.

---
## Ethical Statement

SilentGate is built for authorised penetration testing,
security research, and education only.

The MIT License and this commitment are permanent.

---

## Author

JarDani

---

## License

MIT — Free for the security community.

Security is not an option. It is a need.
And what the world needs should belong to everyone.
## v4.0 — Spectral Payload Decomposition

Seven-gene DNA chain implementing mathematical payload evasion.
Payload stored as Discrete Fourier Transform coefficients
decomposed via SVD into three factor matrices.
Reconstructed via IDFT at execution time only.
Temporally fragmented via Poisson-scheduled execution.

Tested: windows/x64/exec calc.exe (276 bytes)
Target: Windows 11 with Defender fully enabled
Result: calc.exe opened — zero detections — Protection History empty

No shellcode bytes exist in any file or memory region
until the nanosecond of execution.

