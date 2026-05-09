from pathlib import Path
import re
import unittest


class DetectionContentTests(unittest.TestCase):
    def test_intel_assessment_contains_required_sections(self):
        content = Path("docs/intel-assessment-dirtyfrag.md").read_text(encoding="utf-8")
        for heading in (
            "## Executive summary",
            "## ATT&CK mapping",
            "## Hunt hypotheses",
            "## Triage guidance",
            "## False-positive considerations",
        ):
            self.assertIn(heading, content)

    def test_sigma_rules_have_unique_ids_and_dirtyfrag_references(self):
        ids = []
        for path in Path("detections/sigma").glob("*.yml"):
            content = path.read_text(encoding="utf-8")
            match = re.search(r"^id: ([0-9a-f-]{36})$", content, re.MULTILINE)
            self.assertIsNotNone(match, f"missing Sigma id in {path}")
            ids.append(match.group(1))
            self.assertIn("Dirty Frag", content)
            self.assertIn("microsoft.com/en-us/security/blog/2026/05/08", content)
        self.assertEqual(len(ids), len(set(ids)))

    def test_kql_hunts_are_separate_and_named(self):
        kql_files = sorted(Path("detections/kql").glob("*.kql"))
        self.assertGreaterEqual(len(kql_files), 3)
        for path in kql_files:
            content = path.read_text(encoding="utf-8")
            self.assertIn("Device", content)
            self.assertIn("DirtyFrag_", content)
            self.assertNotIn("rm -rf", content)

    def test_osquery_pack_is_read_only(self):
        content = Path("detections/osquery/dirtyfrag_exposure.sql").read_text(encoding="utf-8").lower()
        for forbidden in ("delete ", "insert ", "update ", "drop ", "alter "):
            self.assertNotIn(forbidden, content)
        self.assertIn("select", content)


if __name__ == "__main__":
    unittest.main()
