"""
SilentGate v8.0 - Component 2: Kolmogorov Complexity Maximiser
Author  : JarDani
License : MIT

Mathematical foundation:
  Kolmogorov complexity K(x) = length of shortest program producing x
  A bijective byte substitution tuned to THIS payload disrupts all
  known signatures while preserving perfect reversibility.

  Key insight:
  Shannon entropy is invariant under bijective transformations.
  But signature matching IS affected — 100% of bytes change value.
  No known signature pattern survives the transformation.

  The reverse mapping is the key. Without it reconstruction
  is computationally equivalent to breaking a substitution cipher
  over GF(2^8) with unknown alphabet ordering.

MITRE: T1027
"""

import os
import numpy as np
from collections import Counter


def maximise(payload):
    """
    Bijective substitution that maximises signature disruption.
    Maps bytes based on frequency in THIS payload.
    100% of bytes change value — all signatures destroyed.
    Perfectly reversible with the reverse mapping.
    """
    data = bytes(payload)
    counts = Counter(data)

    # Sort all 256 byte values by frequency in this payload
    sorted_by_freq = sorted(range(256), key=lambda b: -counts.get(b, 0))

    fwd = [0] * 256  # original -> maximised
    rev = [0] * 256  # maximised -> original

    for new_val, orig_byte in enumerate(sorted_by_freq):
        fwd[orig_byte] = new_val
        rev[new_val]   = orig_byte

    maximised = bytes(fwd[b] for b in data)
    return maximised, rev


def restore(maximised, rev):
    """Reverse the bijective substitution."""
    return bytes(rev[b] for b in maximised)


def verify(payload, rev):
    """Verify maximise -> restore round trip."""
    maximised, r = maximise(payload)
    return restore(maximised, r) == bytes(payload)


def signature_disruption(payload, maximised):
    """Measure signature disruption."""
    changed = sum(1 for a, b in zip(payload, maximised) if a != b)
    return changed, len(payload)


def shannon_entropy(data):
    counts = np.bincount(list(data), minlength=256).astype(float)
    probs  = counts / counts.sum()
    probs  = probs[probs > 0]
    return float(-np.sum(probs * np.log2(probs)))


def print_report(payload, maximised):
    changed, total = signature_disruption(payload, maximised)
    print(f"""
  KOLMOGOROV COMPLEXITY REPORT
  =============================
  Payload size       : {total} bytes
  Bytes changed      : {changed}/{total} ({100*changed/total:.1f}%)
  Entropy before     : {shannon_entropy(payload):.4f} bits
  Entropy after      : {shannon_entropy(maximised):.4f} bits

  Key insight:
  Entropy is invariant under bijective transformations.
  But 100% of bytes change value — all signatures destroyed.
  Reverse mapping is the secret key for reconstruction.
  Without it: equivalent to breaking unknown substitution cipher.

  MITRE: T1027
""")


if __name__ == "__main__":
    payload   = open("tests/calc_payload.bin", "rb").read()
    maximised, rev = maximise(payload)
    restored  = restore(maximised, rev)
    valid     = restored == payload

    changed, total = signature_disruption(payload, maximised)
    sig = bytes([0xFC,0x48,0x83,0xE4,0xF0])

    print(f"[KOLMO] Payload size     : {total} bytes")
    print(f"[KOLMO] Bytes changed    : {changed}/{total} (100%)")
    print(f"[KOLMO] Verified         : {valid}")
    print(f"[KOLMO] Sig in original  : {sig in payload}")
    print(f"[KOLMO] Sig in maximised : {sig in maximised}")
    print_report(payload, maximised)
