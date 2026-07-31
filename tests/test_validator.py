import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
from core.validator import validate_api, list_supported_apis, SUPPORTED_APIS


class TestValidator(unittest.TestCase):

    def test_valid_api_returns_correct_name(self):
        result = validate_api("NtAllocateVirtualMemory")
        self.assertEqual(result["api_name"], "NtAllocateVirtualMemory")

    def test_valid_api_returns_intelligence(self):
        result = validate_api("NtAllocateVirtualMemory")
        self.assertIn("intelligence", result)
        self.assertIn("description", result["intelligence"])

    def test_all_supported_apis_validate(self):
        for api in SUPPORTED_APIS:
            result = validate_api(api)
            self.assertEqual(result["api_name"], api)

    def test_invalid_api_raises_systemexit(self):
        with self.assertRaises(SystemExit):
            validate_api("CreateFile")

    def test_empty_api_raises_systemexit(self):
        with self.assertRaises(SystemExit):
            validate_api("")

    def test_intelligence_has_required_fields(self):
        result = validate_api("NtCreateThreadEx")
        intel  = result["intelligence"]
        self.assertIn("why_edr_hooks",      intel)
        self.assertIn("hook_location",      intel)
        self.assertIn("what_edr_checks",    intel)
        self.assertIn("defender_event_ids", intel)
        self.assertIn("mitre_id",           intel)
        self.assertIn("evasion_confidence", intel)

    def test_confidence_has_all_edrs(self):
        result = validate_api("NtOpenProcess")
        conf   = result["intelligence"]["evasion_confidence"]
        self.assertIn("windows_defender",  conf)
        self.assertIn("crowdstrike_falcon", conf)
        self.assertIn("sentinelone",        conf)


if __name__ == "__main__":
    unittest.main(verbosity=2)