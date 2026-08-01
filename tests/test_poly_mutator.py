import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
from core.poly_mutator import (
    mutate_stub_bytes,
    generate_polymorphic_stubs,
    random_names_for_api,
    random_name,
    mutate_c_source,
    JUNK_INSTRUCTIONS,
    EQUIV_MOV_EAX
)

SAMPLE_SSN = 24
SAMPLE_API = "NtAllocateVirtualMemory"


class TestPolyMutator(unittest.TestCase):

    def test_mutate_stub_returns_bytes(self):
        stub = mutate_stub_bytes(SAMPLE_SSN)
        self.assertIsInstance(stub, bytes)

    def test_mutate_stub_not_empty(self):
        stub = mutate_stub_bytes(SAMPLE_SSN)
        self.assertGreater(len(stub), 0)

    def test_mutate_stub_contains_mov_r10_rcx(self):
        stub = mutate_stub_bytes(SAMPLE_SSN)
        self.assertIn(bytes([0x4C, 0x8B, 0xD1]), stub)

    def test_mutate_stub_contains_jmp_r11(self):
        stub = mutate_stub_bytes(SAMPLE_SSN)
        self.assertIn(bytes([0x41, 0xFF, 0xE3]), stub)

    def test_multiple_mutations_are_unique(self):
        stubs = [mutate_stub_bytes(SAMPLE_SSN) for _ in range(10)]
        unique = len(set(s.hex() for s in stubs))
        self.assertGreater(unique, 1)

    def test_generate_polymorphic_stubs_count(self):
        stubs = generate_polymorphic_stubs(SAMPLE_API, SAMPLE_SSN, count=5)
        self.assertEqual(len(stubs), 5)

    def test_generate_polymorphic_stubs_all_unique(self):
        stubs = generate_polymorphic_stubs(SAMPLE_API, SAMPLE_SSN, count=5)
        unique = len(set(s.hex() for s in stubs))
        self.assertEqual(unique, 5)

    def test_all_stubs_functionally_equivalent(self):
        stubs = generate_polymorphic_stubs(SAMPLE_API, SAMPLE_SSN, count=5)
        for stub in stubs:
            self.assertIn(bytes([0x4C, 0x8B, 0xD1]), stub)
            self.assertIn(bytes([0x41, 0xFF, 0xE3]), stub)

    def test_random_name_length(self):
        name = random_name(length=8)
        self.assertEqual(len(name), 8)

    def test_random_name_with_prefix(self):
        name = random_name(prefix="sg_", length=6)
        self.assertTrue(name.startswith("sg_"))

    def test_random_names_unique(self):
        n1 = random_name(length=8)
        n2 = random_name(length=8)
        self.assertNotEqual(n1, n2)

    def test_random_names_for_api_has_all_keys(self):
        names = random_names_for_api(SAMPLE_API)
        self.assertIn(f"SG_{SAMPLE_API}", names)
        self.assertIn(f"SG_Init_{SAMPLE_API}", names)
        self.assertIn(f"{SAMPLE_API}_addr", names)

    def test_mutate_c_source_replaces_names(self):
        sample_c = f"void SG_{SAMPLE_API}() {{ return; }}"
        mutated, name_map = mutate_c_source(sample_c, SAMPLE_API)
        self.assertNotIn(f"SG_{SAMPLE_API}", mutated)

    def test_junk_instructions_not_empty(self):
        self.assertGreater(len(JUNK_INSTRUCTIONS), 0)

    def test_equiv_mov_eax_not_empty(self):
        self.assertGreater(len(EQUIV_MOV_EAX), 0)

    def test_different_ssns_produce_different_stubs(self):
        stub1 = mutate_stub_bytes(24)
        stub2 = mutate_stub_bytes(58)
        self.assertNotEqual(stub1, stub2)

    def test_stub_minimum_size(self):
        stub = mutate_stub_bytes(SAMPLE_SSN)
        # Minimum: mov r10 rcx (3) + mov eax SSN (3+) + mov r11 (10) + jmp (3) = 19
        self.assertGreaterEqual(len(stub), 19)


if __name__ == "__main__":
    unittest.main(verbosity=2)