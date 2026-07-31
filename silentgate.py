import argparse
import sys
import os

from core.validator     import validate_api, list_supported_apis
from core.ssn_resolver  import resolve_ssn
from core.stub_generator import generate_stub
from core.visualiser    import print_banner, print_full_visualisation
from core.intelligence  import print_intelligence_report
from core.reporter      import generate_and_save
from core.unhooker      import unhook_ntdll, print_unhook_report


def parse_args():
    parser = argparse.ArgumentParser(
        prog="silentgate",
        description="Indirect Syscall Stub Generator — by JarDani",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog='''
Examples:
  python3 silentgate.py --api NtAllocateVirtualMemory --explain
  python3 silentgate.py --api NtCreateThreadEx --report
  python3 silentgate.py --all --explain --report
  python3 silentgate.py --list
        '''
    )
    parser.add_argument("--api",     type=str, help="Target NT API name")
    parser.add_argument("--all",     action="store_true", help="Generate stubs for all 5 supported APIs")
    parser.add_argument("--explain", action="store_true", help="Print detailed explanation of every step")
    parser.add_argument("--report",  action="store_true", help="Save markdown report to output/")
    parser.add_argument("--list",    action="store_true", help="List all supported APIs with EDR context")
    return parser.parse_args()


def run_pipeline(api_name, explain=False, report=False):
    print("\n  " + "=" * 60)
    print("  Processing: " + api_name)
    print("  " + "=" * 60)

    # Step 1 — Validate
    validated   = validate_api(api_name)
    if explain:
        from core.validator import print_validation_result
        print_validation_result(validated)

    # Step 2 — Resolve SSN
    ssn_result  = resolve_ssn(api_name, explain=explain)

    # Step 3 — Generate stubs
    stub_result = generate_stub(api_name, ssn_result, explain=explain)

    # Step 4 — Visualise call stack
    if explain:
        print_full_visualisation(
            api_name,
            ssn_result["ssn"],
            ssn_result["ssn_hex"]
        )

    # Step 5 — Intelligence report
    intel_result = print_intelligence_report(api_name, ssn_result["ssn"])

    # Step 6 — Save report
    if report:
        generate_and_save(api_name, ssn_result, stub_result, intel_result)

    print("\n  [DONE] " + api_name + " complete")
    print("  SSN     : " + str(ssn_result["ssn"]) + " (" + ssn_result["ssn_hex"] + ")")
    print("  Stubs   : output/stub_" + api_name + ".h")
    print("            output/stub_" + api_name + ".asm")
    print("            output/gadget_" + api_name + ".c")
    if report:
        print("  Report  : output/evasion_report_" + api_name + ".md")


def main():
    print_banner()
    args = parse_args()

    # --list
    if args.list:
        list_supported_apis()
        sys.exit(0)

    # Run unhooker first on all operations
    print("  [*] Running ntdll unhooker before operations...")
    unhook_result = unhook_ntdll(explain=args.explain)
    if args.explain:
        print_unhook_report(unhook_result)

    # --all
    if args.all:
        apis = [
            "NtAllocateVirtualMemory",
            "NtWriteVirtualMemory",
            "NtProtectVirtualMemory",
            "NtCreateThreadEx",
            "NtOpenProcess"
        ]
        for api in apis:
            run_pipeline(api, explain=args.explain, report=args.report)
        print("\n  [SILENTGATE] All APIs processed successfully")
        print("  [SILENTGATE] Check output/ directory for generated files")
        sys.exit(0)

    # --api
    if args.api:
        run_pipeline(args.api, explain=args.explain, report=args.report)
        sys.exit(0)

    # No arguments
    print("  No arguments provided.")
    print("  Run: python3 silentgate.py --help")
    sys.exit(1)


if __name__ == "__main__":
    main()