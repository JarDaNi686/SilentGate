# SilentGate v9.0 - Kernel Level EDR Bypass via BYOVD
## Blueprint v1.0
**Author:** JarDani
**Date:** August 2026
**Status:** Blueprint

---

## 1. Core Concept

v8.0 proved mathematical evasion at user level.
v9.0 takes us to Ring 0 — kernel level.

BYOVD = Bring Your Own Vulnerable Driver
We load a legitimate signed driver with a known vulnerability
exploit its kernel R/W primitive
remove EDR kernel callbacks
suspend EDR processes
complete kernel-level silence

---

## 2. Target Driver — RTCore64.sys

CVE-2019-16098
Bundled with MSI Afterburner GPU overclocking tool
Valid Microsoft signature
Exposes arbitrary kernel memory R/W via IOCTL

IOCTL codes:
  0x80002048 — Read kernel memory
  0x8000204C — Write kernel memory

Vulnerable on:
  Windows 10  — blocklist disabled — loads directly
  Windows 11  — HVCI disabled — may load despite policy blocklist

---

## 3. Attack Chain

Stage 1 — Drop and load RTCore64.sys
  Write driver to disk
  Register as service via sc.exe
  Start service — Windows loads it (signed = trusted)

Stage 2 — Establish kernel R/W primitive
  Open handle to \\.\RTCore64
  Send IOCTL 0x80002048 to read kernel memory
  Send IOCTL 0x8000204C to write kernel memory

Stage 3 — Find EDR kernel callbacks
  Locate PsSetLoadImageNotifyRoutine array
  Locate PsSetCreateProcessNotifyRoutine array
  Locate ObRegisterCallbacks table
  These are the EDR's eyes in the kernel

Stage 4 — Remove EDR callbacks
  Zero out callback entries pointing to EDR drivers
  MsMpEng loses its kernel hooks
  ETW-TI provider loses its consumer
  EDR is completely blind

Stage 5 — Suspend EDR processes
  NtSuspendProcess on MsMpEng — now works without PPL
  NtSuspendProcess on MpDefenderCoreService
  NisSrv suspended
  EDR is comatose

Stage 6 — Execute payload
  Deploy sg_loader.exe via our existing chain
  Shell connects to Kali
  Zero detections — EDR cannot see anything

Stage 7 — Cleanup
  Resume EDR processes
  Stop and delete driver service
  Delete driver file
  No forensic trace

---

## 4. Implementation Files

core/v9_driver_loader.py    — drops and loads RTCore64.sys
core/v9_kernel_rw.py        — IOCTL wrapper for kernel R/W
core/v9_callback_eraser.py  — finds and removes EDR callbacks
core/v9_edr_killer.py       — suspends EDR processes
core/v9_orchestrator.py     — chains all four stages

tests/rtcore_test.c         — C test harness for IOCTL
output/v9/rtcore_loader.exe — compiled loader

---

## 5. Kernel Callback Locations

Windows stores notify routines in kernel arrays:
  PspLoadImageNotifyRoutine    — image load callbacks
  PspCreateProcessNotifyRoutine — process creation callbacks
  PspCreateThreadNotifyRoutine  — thread creation callbacks

Each array holds up to 64 entries.
Each entry points to a driver's callback function.
Zero the entry = callback silenced.

Finding array addresses:
  Parse ntoskrnl.exe export table
  Locate PsSetLoadImageNotifyRoutine
  Disassemble to find lea instruction referencing array
  Extract array VA from instruction operand

---

## 6. IOCTL Structure for RTCore64

Read memory:
  struct {
    DWORD pad1[3];
    QWORD address;  // kernel address to read
    DWORD pad2;
    DWORD size;     // bytes to read
    QWORD buffer;   // output buffer address
  }

Write memory:
  struct {
    DWORD pad1[3];
    QWORD address;  // kernel address to write
    DWORD pad2;
    DWORD size;     // bytes to write
    QWORD buffer;   // input buffer address
  }

---

## 7. Platform Notes

Windows 10:
  Blocklist disabled
  RTCore64.sys loads without issue
  Full attack chain works

Windows 11 without HVCI:
  Blocklist policy enabled but not hardware enforced
  RTCore64.sys may load
  Test required

Windows 11 with HVCI:
  Hardware enforced blocklist
  RTCore64.sys blocked
  Requires unblocklisted driver
  Future research

---

## 8. MITRE ATT&CK

T1068   Exploitation for Privilege Escalation
T1562.001 Impair Defenses: Disable or Modify Tools
T1014   Rootkit
T1543.003 Create or Modify System Process: Windows Service

---

## 9. Honest Limitations

Windows 11 with HVCI enabled:
  Hardware enforcement blocks known vulnerable drivers
  Requires driver not on blocklist
  Future work: identify unblocklisted vulnerable driver

Requires Administrator:
  Loading a kernel driver requires admin rights
  Standard user cannot load drivers
  BYOVD is post-exploitation not initial access

---

## Closing

v9.0 is where SilentGate reaches the kernel.
The highest privilege level in Windows.
Below this is only firmware.

— JarDani, August 2026
