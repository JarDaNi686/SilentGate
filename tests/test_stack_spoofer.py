import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
from core.stack_spoofer import (
    build_fake_stack_frame,
    get_module_base,
    get_module_size,
    check_platform,
    CALL_RAX_RET_PATTERN,
    RET_PATTERN
)


class TestStackSpoofer(unittest.TestCase):

    def test_build_frame_returns_dict(self):
        result = build_fake_stack_frame()
        self.assertIsInstance(result, dict)

    def test_build_frame_has_required_keys(self):
        result = build_fake_stack_frame()
        self.assertIn("status",          result)
        self.assertIn("kernel32_gadget", result)
        self.assertIn("kernelbase_addr", result)
        self.assertIn("ntdll_addr",      result)
        self.assertIn("validated",       result)

    def test_simulation_mode_on_linux(self):
        if not check_platform():
            result = build_fake_stack_frame()
            self.assertEqual(result["status"], "simulated")

    def test_simulation_has_fake_addresses(self):
        if not check_platform():
            result = build_fake_stack_frame()
            self.assertIn("simulated", result["kernel32_gadget"])
            self.assertIn("simulated", result["kernelbase_addr"])
            self.assertIn("simulated", result["ntdll_addr"])

    def test_platform_check_returns_bool(self):
        result = check_platform()
        self.assertIsInstance(result, bool)

    def test_call_rax_ret_pattern_correct(self):
        self.assertEqual(CALL_RAX_RET_PATTERN, bytes([0xFF, 0xD0, 0xC3]))

    def test_ret_pattern_correct(self):
        self.assertEqual(RET_PATTERN, bytes([0xC3]))

    def test_build_frame_explain_does_not_crash(self):
        try:
            result = build_fake_stack_frame(explain=True)
            self.assertIsNotNone(result)
        except Exception as e:
            self.fail(f"build_fake_stack_frame explain raised: {e}")

    def test_get_module_base_returns_none_on_linux(self):
        if not check_platform():
            result = get_module_base("kernel32.dll")
            self.assertIsNone(result)

    def test_get_module_size_returns_zero_for_none(self):
        result = get_module_size(None)
        self.assertEqual(result, 0)

    def test_windows_finds_all_modules(self):
        if check_platform():
            k32   = get_module_base("kernel32.dll")
            kb    = get_module_base("kernelbase.dll")
            ntdll = get_module_base("ntdll.dll")
            self.assertIsNotNone(k32)
            self.assertIsNotNone(kb)
            self.assertIsNotNone(ntdll)

    def test_windows_frame_validated(self):
        if check_platform():
            result = build_fake_stack_frame()
            self.assertTrue(result["validated"])
            self.assertEqual(result["status"], "success")

    def test_mitre_mapping_present(self):
        result = build_fake_stack_frame()
        self.assertIn("mitre", result)
        self.assertIn("T1055", result.get("mitre", ""))


if __name__ == "__main__":
    unittest.main(verbosity=2)