import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
from core.ssn_resolver   import resolve_ssn
from core.stub_generator import generate_stub

APIS = [
    "NtAllocateVirtualMemory",
    "NtWriteVirtualMemory",
    "NtProtectVirtualMemory",
    "NtCreateThreadEx",
    "NtOpenProcess"
]


class TestStubGenerator(unittest.TestCase):

    def test_generate_returns_dict(self):
        ssn_result = resolve_ssn("NtAllocateVirtualMemory")
        result     = generate_stub("NtAllocateVirtualMemory", ssn_result)
        self.assertIsInstance(result, dict)

    def test_generate_has_required_keys(self):
        ssn_result = resolve_ssn("NtAllocateVirtualMemory")
        result     = generate_stub("NtAllocateVirtualMemory", ssn_result)
        self.assertIn("api_name",    result)
        self.assertIn("ssn",         result)
        self.assertIn("c_path",      result)
        self.assertIn("asm_path",    result)
        self.assertIn("gadget_path", result)

    def test_output_files_exist(self):
        for api in APIS:
            ssn_result = resolve_ssn(api)
            result     = generate_stub(api, ssn_result)
            self.assertTrue(os.path.exists(result["c_path"]),      f"Missing: {result['c_path']}")
            self.assertTrue(os.path.exists(result["asm_path"]),    f"Missing: {result['asm_path']}")
            self.assertTrue(os.path.exists(result["gadget_path"]), f"Missing: {result['gadget_path']}")

    def test_asm_contains_correct_ssn(self):
        ssn_result = resolve_ssn("NtAllocateVirtualMemory")
        result     = generate_stub("NtAllocateVirtualMemory", ssn_result)
        with open(result["asm_path"]) as f:
            content = f.read()
        self.assertIn("18h", content)

    def test_asm_contains_sg_prefix(self):
        ssn_result = resolve_ssn("NtAllocateVirtualMemory")
        result     = generate_stub("NtAllocateVirtualMemory", ssn_result)
        with open(result["asm_path"]) as f:
            content = f.read()
        self.assertIn("SG_NtAllocateVirtualMemory", content)

    def test_c_header_contains_extern(self):
        ssn_result = resolve_ssn("NtCreateThreadEx")
        result     = generate_stub("NtCreateThreadEx", ssn_result)
        with open(result["c_path"]) as f:
            content = f.read()
        self.assertIn("extern", content)
        self.assertIn("SG_NtCreateThreadEx", content)

    def test_all_apis_generate_successfully(self):
        for api in APIS:
            ssn_result = resolve_ssn(api)
            result     = generate_stub(api, ssn_result)
            self.assertEqual(result["api_name"], api)


if __name__ == "__main__":
    unittest.main(verbosity=2)