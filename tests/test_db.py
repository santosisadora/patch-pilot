import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import db
from models import Finding

class ResolveTests(unittest.TestCase):
    def test_empty_scan_resolves_everything(self):
        with tempfile.TemporaryDirectory() as d:
            db.DB = os.path.join(d, "test.db")
            conn = db.connect()
            try:
                f = Finding(cve_id="CVE-0000-0001", package="pkg", installed_version="1.0",
                            fixed_version="1.1", severity="HIGH", asset="app")
                db.upsert_scan(conn, [f], "2026-11-01")
                db.upsert_scan(conn, [], "2026-11-02", assets={"app"})
                row = conn.execute("SELECT resolved_at FROM findings").fetchone()
                self.assertEqual(row["resolved_at"], "2026-11-02")
            finally:
                conn.close()

if __name__ == "__main__":
    unittest.main()