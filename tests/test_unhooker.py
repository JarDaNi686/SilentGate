import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
from core.unhooker import (
    unhook_ntdll,
    read_disk_ntdll,
    parse_text_section,
    check_platform
)


class TestUnhooker(unittest.TestCase):

    def test_unhook_returns_dict(self):
        result = unhook_ntdll()
        self.assertIsInstance(result, dict)

    def test_unhook_has_required_keys(self):
        result = unhook_ntdll()
        self.assertIn("status",        result)
        self.assertIn("hooks_found",   result)
        self.assertIn("hooks_removed", result)

    def test_simulation_mode_on_linux(self):
        if not check_platform():
            result = unhook_ntdll()
            self.assertEqual(result["status"], "simulated")

    def test_simulation_hooks_found_zero(self):
        if not check_platform():
            result = unhook_ntdll()
            self.assertEqual(result["hooks_found"], 0)

    def test_disk_ntdll_readable_on_windows(self):
        if check_platform():
            data = read_disk_ntdll()
            self.assertIsNotNone(data)
            self.assertGreater(len(data), 0)
            self.assertEqual(data[:2], b"MZ")

    def test_parse_text_section_with_valid_pe(self):
        if check_platform():
            data = read_disk_ntdll()
            if data:
                section = parse_text_section(data)
                self.assertIsNotNone(section)
                self.assertEqual(section["name"], ".text")
                self.assertGreater(section["raw_size"], 0)
                self.assertGreater(section["rva"], 0)

    def test_platform_check_returns_bool(self):
        result = check_platform()
        self.assertIsInstance(result, bool)

    def test_unhook_explain_does_not_crash(self):
        try:
            result = unhook_ntdll(explain=True)
            self.assertIsNotNone(result)
        except Exception as e:
            self.fail(f"unhook_ntdll with explain=True raised: {e}")


if __name__ == "__main__":
    unittest.main(verbosity=2)