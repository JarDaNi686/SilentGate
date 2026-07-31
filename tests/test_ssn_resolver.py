import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
from core.ssn_resolver import resolve_ssn, load_builds_data, check_platform

EXPECTED_SSNS = {
    "NtAllocateVirtualMemory": 24,
    "NtWriteVirtualMemory":    58,
    "NtProtectVirtualMemory":  80,
    "NtCreateThreadEx":       199,
    "NtOpenProcess":           38
}


class TestSSNResolver(unittest.TestCase):

    def test_resolve_returns_dict(self):
        result = resolve_ssn("NtAllocateVirtualMemory")
        self.assertIsInstance(result, dict)

    def test_resolve_has_required_keys(self):
        result = resolve_ssn("NtAllocateVirtualMemory")
        self.assertIn("api_name",   result)
        self.assertIn("ssn",        result)
        self.assertIn("ssn_hex",    result)
        self.assertIn("stub_state", result)
        self.assertIn("source",     result)
        self.assertIn("validated",  result)
        self.assertIn("build",      result)

    def test_all_apis_return_correct_ssn(self):
        for api, expected in EXPECTED_SSNS.items():
            result = resolve_ssn(api)
            self.assertEqual(
                result["ssn"], expected,
                msg=f"{api} expected SSN {expected} got {result['ssn']}"
            )

    def test_ssn_hex_matches_decimal(self):
        result = resolve_ssn("NtAllocateVirtualMemory")
        self.assertEqual(result["ssn_hex"], hex(result["ssn"]))

    def test_ssn_values_are_positive(self):
        for api in EXPECTED_SSNS:
            result = resolve_ssn(api)
            self.assertGreater(result["ssn"], 0)

    def test_ssn_values_are_realistic(self):
        for api in EXPECTED_SSNS:
            result = resolve_ssn(api)
            self.assertLess(result["ssn"], 1000)

    def test_builds_data_loads(self):
        data = load_builds_data()
        self.assertIsNotNone(data)
        self.assertIn("builds", data)


if __name__ == "__main__":
    unittest.main(verbosity=2)