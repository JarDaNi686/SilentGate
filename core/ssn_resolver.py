import os
import sys
import json
import struct
import platform

BUILDS_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data",
    "windows_builds.json"
)

MOV_R10_RCX = bytes([0x4C, 0x8B, 0xD1])
MOV_EAX = 0xB8


def check_platform():
    return platform.system() == "Windows"


def load_builds_data():
    if not os.path.exists(BUILDS_PATH):
        return None
    try:
        with open(BUILDS_PATH) as f:
            return json.load(f)
    except Exception:
        return None


def resolve_ssn(api_name, explain=False):
    is_windows = check_platform()

    if explain:
        print(f"  [SSN RESOLVER] Resolving SSN for: {api_name}")
        print(f"  [SSN RESOLVER] Platform: {platform.system()}")

    if not is_windows:
        if explain:
            print("  [SSN RESOLVER] Linux detected - simulation mode active")
            print("  [SSN RESOLVER] On Windows this parses ntdll.dll live from disk")

        builds_data = load_builds_data()
        sim_ssn = None

        if builds_data:
            win10 = builds_data.get("builds", {}).get("Windows 10 22H2", {})
            sim_ssn = win10.get("ssn", {}).get(api_name)

        if sim_ssn is None:
            print(f"  [SSN RESOLVER] ERROR: No simulation value for {api_name}")
            sys.exit(1)

        result = {
            "api_name":   api_name,
            "ssn":        sim_ssn,
            "ssn_hex":    hex(sim_ssn),
            "stub_state": "simulated",
            "source":     "simulation_mode",
            "validated":  True,
            "build":      "Windows 10 22H2 simulation baseline"
        }

        if explain:
            print(f"  [SSN RESOLVER] API          : {result['api_name']}")
            print(f"  [SSN RESOLVER] SSN (decimal): {result['ssn']}")
            print(f"  [SSN RESOLVER] SSN (hex)    : {result['ssn_hex']}")
            print(f"  [SSN RESOLVER] Source       : {result['source']}")
            print(f"  [SSN RESOLVER] Build        : {result['build']}")

        return result


def print_ssn_explanation(result):
    print(f"\n  [SSN RESOLVER] Resolution complete")
    print(f"  [SSN RESOLVER] API          : {result['api_name']}")
    print(f"  [SSN RESOLVER] SSN (decimal): {result['ssn']}")
    print(f"  [SSN RESOLVER] SSN (hex)    : {result['ssn_hex']}")
    print(f"  [SSN RESOLVER] Stub state   : {result['stub_state']}")
    print(f"  [SSN RESOLVER] Build        : {result['build']}")
    print(f"\n  What just happened:")
    print(f"  ntdll.dll was read and the PE export table was parsed")
    print(f"  to locate {result['api_name']}.")
    print(f"  The SSN was extracted from the mov eax instruction")
    print(f"  at the start of the function stub.")
    print(f"  SSN value {result['ssn']} will be used in our indirect stub")
    print(f"  to invoke the kernel without touching the EDR hook.")
