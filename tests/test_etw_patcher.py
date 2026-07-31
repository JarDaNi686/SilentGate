import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
from core.etw_patcher import (
    patch_etw,
    restore_etw,
    find_etw_event_write,
    check_platform,
    RET_BYTE,
    MOV_R10_RCX_BYTE
)


class TestEtwPatcher(unittest.TestCase):

    def test_patch_returns_dict(self):
        result = patch_etw()
        self.assertIsInstance(result, dict)

    def test_patch_has_required_keys(self):
        result = patch_etw()
        self.assertIn("status",  result)
        self.assertIn("patched", result)

    def test_simulation_mode_on_linux(self):
        if not check_platform():
            result = patch_etw()
            self.assertEqual(result["status"], "simulated")

    def test_simulation_not_patched_on_linux(self):
        if not check_platform():
            result = patch_etw()
            self.assertFalse(result["patched"])

    def test_ret_byte_value(self):
        self.assertEqual(RET_BYTE, 0xC3)

    def test_mov_r10_rcx_byte_value(self):
        self.assertEqual(MOV_R10_RCX_BYTE, 0x4C)

    def test_platform_check_returns_bool(self):
        result = check_platform()
        self.assertIsInstance(result, bool)

    def test_patch_explain_does_not_crash(self):
        try:
            result = patch_etw(explain=True)
            self.assertIsNotNone(result)
        except Exception as e:
            self.fail(f"patch_etw with explain=True raised: {e}")

    def test_find_etw_returns_none_on_linux(self):
        if not check_platform():
            result = find_etw_event_write()
            self.assertIsNone(result)

    def test_patch_byte_in_result(self):
        result = patch_etw()
        self.assertIn("patch_byte", result)

    def test_original_byte_in_result(self):
        result = patch_etw()
        self.assertIn("original_byte", result)

    def test_windows_patch_and_restore(self):
        if check_platform():
            result = patch_etw()
            if result["status"] == "success":
                self.assertTrue(result["patched"])
                restored = restore_etw(MOV_R10_RCX_BYTE)
                self.assertTrue(restored)


if __name__ == "__main__":
    unittest.main(verbosity=2)