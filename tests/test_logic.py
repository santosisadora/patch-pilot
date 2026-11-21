import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from models import Finding
from prioritize import score
from remediate import pick_fix, bump_type

def make(**kw) -> Finding:
    base = dict(cve_id="CVE-0000-0000", package="pkg", installed_version="1.0.0",
                fixed_version="1.0.1", severity="HIGH", asset="app")
    base.update(kw)
    return Finding(**base)

class PrioritizeTests(unittest.TestCase):
    def test_kev_is_p0(self):
        f = make(in_kev=True)
        score(f)
        self.assertEqual(f.priority, "P0")

    def test_high_epss_is_p1(self):
        f = make(epss=0.6)
        score(f)
        self.assertEqual(f.priority, "P1")

    def test_low_risk_is_p3(self):
        f = make(severity="LOW", epss=0.001)
        score(f)
        self.assertEqual(f.priority, "P3")

class RemediateTests(unittest.TestCase):
    def test_prefers_same_major_fix(self):
        self.assertEqual(pick_fix("1.26.4", "1.26.18, 2.0.7"), "1.26.18")

    def test_only_major_fix(self):
        self.assertEqual(pick_fix("2.11.2", "3.1.3"), "3.1.3")

    def test_bump_types(self):
        self.assertEqual(bump_type("1.26.4", "2.0.7"), "major")
        self.assertEqual(bump_type("5.3.1", "5.4"), "minor")
        self.assertEqual(bump_type("2.30.0", "2.30.1"), "patch")

if __name__ == "__main__":
    unittest.main()