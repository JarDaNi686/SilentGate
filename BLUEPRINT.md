# SilentGate
## Indirect Syscall Stub Generator with EDR Evasion Intelligence Layer
### Final Project Blueprint v2.0

**Author:** JarDan
**GitHub:** https://github.com/JarDaNi686/SilentGate
**License:** MIT
**Vision:** A real-world usable tool that happens to also be a portfolio project
**Standard:** Industry-level trusted output — not a shortcut

---

> "Security is not an option. It is a need.
>  Like every great thing — it should be open."
>
> — JarDan, founding principle of SilentGate

---

## 1. Why SilentGate Exists

Modern EDR products hook Windows native APIs inside ntdll.dll.
Every payload that calls those APIs gets intercepted and killed
before it reaches the kernel.

Red teamers currently have three options:

  1. Use existing tools like SysWhispers3 or RecycledGate
     — they generate stubs but explain nothing
     — black box output with no transparency

  2. Write indirect syscall stubs manually from scratch
     — requires deep Windows internals knowledge
     — no guidance, no validation, no context

  3. Use commercial C2 frameworks like Cobalt Strike or Havoc
     — expensive, closed source, already well known to defenders

SilentGate is the fourth option.

It generates indirect syscall stubs AND explains every decision.
It shows the red teamer exactly what is happening, why it works,
where it could fail, and what a defender needs to catch it.

It is transparent. It is educational. It is open.

---

## 2. What Makes SilentGate Different

Every existing tool in this space does ONE thing — generates the stub.

SilentGate does FOUR things no existing tool does together:

  ONE — Dynamic SSN Resolution
        Resolves Syscall Service Numbers at runtime by walking
        the ntdll export table. No hardcoded lookup tables.
        Works correctly across Windows 10, Windows 11, and
        Server editions automatically.

  TWO — ASCII Call Stack Visualisation
        Prints a live diagram in the terminal showing exactly
        where the EDR hook sits and exactly where the indirect
        jump bypasses it. Nobody has built this into a syscall
        tool before.

  THREE — Confidence Intelligence Layer
          After generating the stub, SilentGate rates evasion
          confidence based on known EDR hook behaviours and
          explains specifically what would still catch the technique.
          Honest output. No false promises.

  FOUR — Defender Perspective
         For every technique applied, SilentGate prints what
         a blue teamer needs to detect it. Event IDs, memory
         signatures, behavioural patterns. Shows you think
         in both directions.

---

## 3. The Standard We Build To

This is not a portfolio project.
This is a tool that happens to also be a portfolio project.

  — Every output must be accurate
  — Every claim must be defensible
  — Every confidence rating must be backed by real data
  — Every piece of code must be tested in a real lab
  — No cutting corners
  — No rushing until the current step is solid

---

## 4. Open Source Commitment

SilentGate is released under the MIT License.

Security is infrastructure. Infrastructure belongs to everyone.
The same way Linux is free because the world depends on it,
security knowledge should be free because the world needs it.

---

## 5. Lab Environment

Host Machine
  OS         : Windows 10 / 11 physical laptop
  RAM        : 16 GB
  Hypervisor : VMware Workstation Player

VM 1 — Kali Linux
  Purpose : Development and attack machine
  RAM     : 3 GB
  IP      : 192.168.100.10
  Network : Host-Only isolated

VM 2 — Windows 10 Defender ON
  Purpose : Prove evasion against real Defender
  RAM     : 2 GB
  IP      : 192.168.100.20
  Defender: FULLY ON — never disable

VM 3 — Windows 10 Sandbox
  Purpose : Safe compilation and inspection
  RAM     : 2 GB
  IP      : 192.168.100.30
  Defender: FULLY OFF

---

## 6. The Five Target APIs

API                      Role
NtAllocateVirtualMemory  Allocate memory for shellcode
NtWriteVirtualMemory     Write shellcode into memory
NtProtectVirtualMemory   Mark memory as executable
NtCreateThreadEx         Create thread to execute shellcode
NtOpenProcess            Access target process handle

These five cover the complete shellcode injection chain.
Every modern payload needs at least three of them.
EDR products hook all five without exception.

---

## 7. Technical Flow

Step 1 — API Validator
         Confirms valid Nt* syscall
         Loads EDR hook intelligence for this API
         Prints why defenders target it

Step 2 — Dynamic SSN Resolver
         Walks ntdll.dll export table at runtime
         Extracts real Syscall Service Number
         No hardcoded tables

Step 3 — Stub Generator
         Generates C function signature
         Generates x64 ASM with indirect jump
         Selects clean ntdll gadget as jump target

Step 4 — ASCII Call Stack Visualiser
         Shows exactly where EDR hook sits
         Shows exactly where our jump bypasses it

Step 5 — Intelligence Layer
         Evasion confidence rating with explanation
         Defender perspective output
         MITRE ATT&CK mapping

Step 6 — PoC Generator
         Working C proof of concept
         Compiles with MinGW on Windows
         Tested against real Defender

Step 7 — Report Generator
         Complete evasion_report.md
         Professional engagement ready format

Output
  output/stub_NtAllocateVirtualMemory.c
  output/stub_NtAllocateVirtualMemory.asm
  output/poc_NtAllocateVirtualMemory.c
  output/evasion_report.md

---

## 8. Project Structure

silentgate/
├── BLUEPRINT.md
├── README.md
├── LICENSE
├── requirements.txt
├── silentgate.py
├── core/
│   ├── __init__.py
│   ├── validator.py
│   ├── ssn_resolver.py
│   ├── stub_generator.py
│   ├── visualiser.py
│   ├── intelligence.py
│   ├── poc_generator.py
│   └── reporter.py
├── data/
│   ├── edr_hooks.json
│   ├── mitre_mapping.json
│   └── windows_builds.json
├── output/
│   └── .gitkeep
├── tests/
│   ├── test_validator.py
│   ├── test_ssn_resolver.py
│   ├── test_stub_generator.py
│   └── test_intelligence.py
└── screenshots/

---

## 9. Build Order

Week 1 — Foundation
  GitHub repo and BLUEPRINT pushed
  Project folder structure created
  data/ JSON files built
  core/validator.py working and tested
  core/ssn_resolver.py working and tested

Week 2 — Core Engine
  core/stub_generator.py
  core/visualiser.py
  silentgate.py CLI wired together
  First real test on sandbox VM

Week 3 — Intelligence Layer
  core/intelligence.py
  core/poc_generator.py
  core/reporter.py
  PoC tested against Defender ON

Week 4 — Polish and Publish
  All unit tests written
  README.md community grade documentation
  MIT LICENSE added
  Screenshots captured as evidence
  v1.0.0 release tagged on GitHub

---

## 10. Long Term Vision

v1.0  5 APIs, x64, Windows 10 and 11
      Dynamic SSN resolution
      ASCII visualiser and intelligence layer
      Working PoC tested against real Defender

v2.0  Expanded API coverage
      x86 support added
      Windows Server editions supported
      Automated EDR confidence testing

v3.0  Plugin architecture for community contributions
      Integration with major C2 frameworks
      Security conference presentation
      Published with proper security advisory

---

## 11. MITRE ATT&CK Mapping

TA0005    Defense Evasion        Core purpose of the tool
T1106     Native API             Syscall invocation
T1055     Process Injection      Full injection chain covered
T1562.001 Impair Defenses        Bypassing EDR user mode hooks
T1027     Obfuscated Files       Indirect jump obscures origin

---

## 12. Ground Rules

1. One step at a time
2. Nothing moves until current step works and is tested on VM
3. Every git commit has a meaningful message
4. We learn by building not by reading theory
5. No rushing quality for speed
6. This tool is built to work in the real world

---

## Closing Statement

SilentGate is not a portfolio project.

It is a tool built to a real world standard, released openly
to the security community, with a vision that goes well
beyond any single version.

The person building it made the decision to open source it
for the same reason Linus Torvalds open sourced Linux.

Security is not an option. It is a need.
And what the world needs should belong to everyone.

— JarDan, July 2026
ENDOFFILE
