"""
SilentGate - core/visualiser.py
Step 4 of the pipeline: ASCII Call Stack Visualiser

Author  : JarDani
License : MIT
Purpose : Prints a live ASCII diagram showing exactly where
          the EDR hook sits and where our indirect jump bypasses it.
          This is the piece no other syscall tool has built.
"""


def print_banner():
    """Print the SilentGate ASCII banner."""
    print("""
  ███████╗██╗██╗     ███████╗███╗   ██╗████████╗ ██████╗  █████╗ ████████╗███████╗
  ██╔════╝██║██║     ██╔════╝████╗  ██║╚══██╔══╝██╔════╝ ██╔══██╗╚══██╔══╝██╔════╝
  ███████╗██║██║     █████╗  ██╔██╗ ██║   ██║   ██║  ███╗███████║   ██║   █████╗
  ╚════██║██║██║     ██╔══╝  ██║╚██╗██║   ██║   ██║   ██║██╔══██║   ██║   ██╔══╝
  ███████║██║███████╗███████╗██║ ╚████║   ██║   ╚██████╔╝██║  ██║   ██║   ███████╗
  ╚══════╝╚═╝╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝

  Indirect Syscall Stub Generator
  Author  : JarDani
  License : MIT — Free for the security community
  Version : 1.0.0
""")


def print_separator(char="─", width=62):
    """Print a separator line."""
    print(f"  {char * width}")


def visualise_call_stack(api_name, ssn, ssn_hex):
    """
    Print the full ASCII call stack diagram for the given API.
    Shows both the hooked path and the indirect syscall bypass path.
    """

    print(f"""
  ╔══════════════════════════════════════════════════════════════╗
  ║      CALL STACK ANALYSIS                                     ║
  ║      API : {api_name:<49}║
  ║      SSN : {ssn} ({ssn_hex}){" " * (47 - len(str(ssn)) - len(ssn_hex))}║
  ╚══════════════════════════════════════════════════════════════╝
""")

    # ── WITHOUT SilentGate ──────────────────────────────────────
    print("  WITHOUT SilentGate — EDR catches this:")
    print_separator()
    print(f"""
  Your Code
      │
      │  calls {api_name}()
      ▼
  ┌─────────────────────────────────────────────┐
  │  ntdll.dll                                   │
  │                                              │
  │  ┌───────────────────────────────────────┐  │
  │  │  {api_name:<37}│  │
  │  │                                       │  │
  │  │  4C 8B D1        mov r10, rcx         │  │
  │  │  E9 XX XX XX XX  JMP to EDR handler   │◄─┼── EDR HOOK HERE
  │  │                       │               │  │    First 5 bytes
  │  │                       ▼               │  │    replaced with JMP
  │  │            EDR handler runs           │  │
  │  │            inspects arguments         │  │
  │  │            checks memory flags        │  │
  │  │                       │               │  │
  │  │                  KILL / ALERT         │  │
  │  └───────────────────────────────────────┘  │
  └─────────────────────────────────────────────┘
""")

    # ── WITH SilentGate ─────────────────────────────────────────
    print("  WITH SilentGate — EDR misses this:")
    print_separator()
    print(f"""
  Your Code
      │
      │  calls SG_{api_name}()
      ▼
  ┌─────────────────────────────────────────────┐
  │  SilentGate Stub                             │
  │                                              │
  │  mov r10, rcx      ; save first argument    │
  │  mov eax, {ssn_hex:<8}    ; load SSN = {ssn:<10}    │
  │  jmp [gadget_addr] ; jump into ntdll ───────┼──┐
  └─────────────────────────────────────────────┘  │
                                                    │
                                    jumps INTO ntdll │
                                    PAST the hook    │
                                                    ▼
  ┌─────────────────────────────────────────────┐
  │  ntdll.dll                                   │
  │                                              │
  │  ┌───────────────────────────────────────┐  │
  │  │  {api_name:<37}│  │
  │  │                                       │  │
  │  │  [EDR HOOK] ◄─── NEVER TRIGGERED     │  │  ← we skip this
  │  │                                       │  │
  │  │  ...                                  │  │
  │  │  ...                                  │  │
  │  │  0F 05  syscall ◄─────────────────────┼──┘  ← we land HERE
  │  │  C3     ret                           │  │
  │  └───────────────────────────────────────┘  │
  └─────────────────────────────────────────────┘
      │
      │  syscall enters kernel with SSN {ssn}
      ▼
  ┌─────────────────────────────────────────────┐
  │  KERNEL                                      │
  │                                              │
  │  SSDT[{ssn}] → Nt{api_name[2:]:<30}│
  │                                              │
  │  Executes the real kernel function           │
  │  EDR hook was never triggered                │
  │  No alert. No detection. Clean execution.    │
  └─────────────────────────────────────────────┘
""")


def visualise_edr_hook_detail(api_name):
    """
    Print a detailed byte-level view of what EDR does to ntdll.
    Shows the before and after of the hook installation.
    """
    print(f"""
  ╔══════════════════════════════════════════════════════════════╗
  ║  EDR HOOK DETAIL — What happens inside ntdll.dll             ║
  ╚══════════════════════════════════════════════════════════════╝

  BEFORE EDR loads (clean ntdll from disk):
  ──────────────────────────────────────────
  {api_name}:
    offset +0  │ 4C 8B D1        │ mov r10, rcx
    offset +3  │ B8 18 00 00 00  │ mov eax, 0x18
    offset +8  │ 0F 05           │ syscall
    offset +10 │ C3              │ ret

  AFTER EDR loads (ntdll in memory, hook installed):
  ──────────────────────────────────────────────────
  {api_name}:
    offset +0  │ E9 XX XX XX XX  │ JMP to EDR handler  ← PATCHED
    offset +5  │ 00 00 00        │ (overwritten)        ← PATCHED
    offset +8  │ 0F 05           │ syscall              ← STILL HERE
    offset +10 │ C3              │ ret                  ← STILL HERE

  SilentGate jumps directly to offset +8
  The JMP at offset +0 is never executed
  The EDR handler is never reached
""")


def visualise_ssdt(api_name, ssn):
    """
    Print a simplified view of how the kernel uses the SSN
    to find the real function via the SSDT.
    """
    print(f"""
  ╔══════════════════════════════════════════════════════════════╗
  ║  KERNEL — System Service Descriptor Table (SSDT)             ║
  ╚══════════════════════════════════════════════════════════════╝

  When our syscall executes with SSN {ssn}:

  SSDT (kernel memory):
  ┌───────┬──────────────────────────────────────────┐
  │ Index │ Kernel Function                           │
  ├───────┼──────────────────────────────────────────┤
  │  ...  │  ...                                      │
  │  {ssn-1:<5} │  Nt{api_name[2-1 if ssn > 0 else 0:]}...                                   │
  │  {ssn:<5} │  Nt{api_name[2:]:<39}│ ← OUR CALL
  │  {ssn+1:<5} │  Nt...                                   │
  │  ...  │  ...                                      │
  └───────┴──────────────────────────────────────────┘

  The kernel executes the real {api_name}
  with our original arguments intact.
  No EDR involvement. Clean kernel execution.
""")


def print_full_visualisation(api_name, ssn, ssn_hex):
    """
    Print the complete visualisation — all three diagrams.
    Called when --explain flag is active.
    """
    visualise_call_stack(api_name, ssn, ssn_hex)
    visualise_edr_hook_detail(api_name)
    visualise_ssdt(api_name, ssn)
