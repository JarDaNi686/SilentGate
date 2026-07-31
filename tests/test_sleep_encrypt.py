import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
from core.sleep_encrypt import (
    generate_key, xor_encrypt, xor_decrypt,
    encrypt_payload, decrypt_and_verify,
    compute_hash, re_encrypt
)

SAMPLE_PAYLOAD = bytes([
    0x4C, 0x8B, 0xD1, 0xB8, 0x18, 0x00, 0x00, 0x00,
    0x0F, 0x05, 0xC3, 0x90, 0x90, 0x90, 0x90, 0x90
])


class TestSleepEncrypt(unittest.TestCase):

    def test_generate_key_length(self):
        key = generate_key(32)
        self.assertEqual(len(key), 32)

    def test_generate_key_is_random(self):
        key1 = generate_key(32)
        key2 = generate_key(32)
        self.assertNotEqual(key1, key2)

    def test_xor_encrypt_changes_bytes(self):
        key       = generate_key(32)
        encrypted = xor_encrypt(SAMPLE_PAYLOAD, key)
        self.assertNotEqual(encrypted, SAMPLE_PAYLOAD)

    def test_xor_decrypt_restores_original(self):
        key       = generate_key(32)
        encrypted = xor_encrypt(SAMPLE_PAYLOAD, key)
        decrypted = xor_decrypt(encrypted, key)
        self.assertEqual(decrypted, SAMPLE_PAYLOAD)

    def test_xor_same_length(self):
        key       = generate_key(32)
        encrypted = xor_encrypt(SAMPLE_PAYLOAD, key)
        self.assertEqual(len(encrypted), len(SAMPLE_PAYLOAD))

    def test_encrypt_payload_returns_dict(self):
        blob = encrypt_payload(SAMPLE_PAYLOAD)
        self.assertIsInstance(blob, dict)

    def test_encrypt_payload_has_required_keys(self):
        blob = encrypt_payload(SAMPLE_PAYLOAD)
        self.assertIn("encrypted",     blob)
        self.assertIn("key",           blob)
        self.assertIn("original_hash", blob)
        self.assertIn("size",          blob)

    def test_encrypt_payload_size_correct(self):
        blob = encrypt_payload(SAMPLE_PAYLOAD)
        self.assertEqual(blob["size"], len(SAMPLE_PAYLOAD))

    def test_decrypt_and_verify_restores_payload(self):
        blob      = encrypt_payload(SAMPLE_PAYLOAD)
        decrypted = decrypt_and_verify(blob)
        self.assertEqual(decrypted, SAMPLE_PAYLOAD)

    def test_decrypt_and_verify_hash_match(self):
        blob      = encrypt_payload(SAMPLE_PAYLOAD)
        decrypted = decrypt_and_verify(blob)
        self.assertIsNotNone(decrypted)

    def test_tampered_payload_fails_verification(self):
        blob = encrypt_payload(SAMPLE_PAYLOAD)
        tampered = bytearray(blob["encrypted"])
        tampered[0] ^= 0xFF
        blob["encrypted"] = bytes(tampered)
        result = decrypt_and_verify(blob)
        self.assertIsNone(result)

    def test_re_encrypt_produces_different_key(self):
        blob1 = encrypt_payload(SAMPLE_PAYLOAD)
        blob2 = re_encrypt(SAMPLE_PAYLOAD)
        self.assertNotEqual(blob1["key"], blob2["key"])

    def test_compute_hash_consistent(self):
        h1 = compute_hash(SAMPLE_PAYLOAD)
        h2 = compute_hash(SAMPLE_PAYLOAD)
        self.assertEqual(h1, h2)

    def test_compute_hash_different_for_different_data(self):
        h1 = compute_hash(SAMPLE_PAYLOAD)
        h2 = compute_hash(b"different data")
        self.assertNotEqual(h1, h2)


if __name__ == "__main__":
    unittest.main(verbosity=2)