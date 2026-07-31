import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
from core.intelligence import (
    analyse_confidence,
    get_remaining_risks,
    get_defender_perspective,
    get_mitre_mappings,
    get_improvements,
    load_edr_data,
    load_mitre_data
)


class TestIntelligence(unittest.TestCase):

    def test_edr_data_loads(self):
        data = load_edr_data()
        self.assertIsInstance(data, dict)
        self.assertGreater(len(data), 0)

    def test_mitre_data_loads(self):
        data = load_mitre_data()
        self.assertIsInstance(data, dict)

    def test_confidence_has_all_edrs(self):
        edr_data   = load_edr_data()
        confidence = analyse_confidence("NtAllocateVirtualMemory", edr_data)
        self.assertIn("windows_defender",   confidence)
        self.assertIn("crowdstrike_falcon", confidence)
        self.assertIn("sentinelone",        confidence)
        self.assertIn("overall",            confidence)

    def test_confidence_values_in_range(self):
        edr_data   = load_edr_data()
        confidence = analyse_confidence("NtAllocateVirtualMemory", edr_data)
        for key in ["windows_defender", "crowdstrike_falcon", "sentinelone", "overall"]:
            self.assertGreaterEqual(confidence[key], 0)
            self.assertLessEqual(confidence[key], 100)

    def test_risks_returns_list(self):
        edr_data = load_edr_data()
        risks    = get_remaining_risks("NtAllocateVirtualMemory", edr_data)
        self.assertIsInstance(risks, list)
        self.assertGreater(len(risks), 0)

    def test_risks_have_required_fields(self):
        edr_data = load_edr_data()
        risks    = get_remaining_risks("NtAllocateVirtualMemory", edr_data)
        for risk in risks:
            self.assertIn("risk",     risk)
            self.assertIn("detail",   risk)
            self.assertIn("severity", risk)

    def test_detections_returns_list(self):
        edr_data   = load_edr_data()
        detections = get_defender_perspective("NtAllocateVirtualMemory", edr_data)
        self.assertIsInstance(detections, list)
        self.assertGreater(len(detections), 0)

    def test_improvements_returns_list(self):
        improvements = get_improvements()
        self.assertIsInstance(improvements, list)
        self.assertGreater(len(improvements), 0)

    def test_mitre_mappings_for_ntalloc(self):
        mitre_data = load_mitre_data()
        mappings   = get_mitre_mappings("NtAllocateVirtualMemory", mitre_data)
        self.assertIsInstance(mappings, list)
        ids = [m["id"] for m in mappings]
        self.assertIn("T1055", ids)
        self.assertIn("T1106", ids)


if __name__ == "__main__":
    unittest.main(verbosity=2)