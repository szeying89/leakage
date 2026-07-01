from pathlib import Path
import json
import tempfile
import unittest

from scripts import render_ciso_dashboard


class CisoDashboardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data_path = Path("dashboards/dirtyfrag_ciso_dashboard.json")
        cls.html_path = Path("dashboards/dirtyfrag_ciso_dashboard.html")
        cls.svg_path = Path("dashboards/dirtyfrag_ciso_dashboard.svg")
        cls.data = json.loads(cls.data_path.read_text(encoding="utf-8"))

    def test_dashboard_data_has_required_sections(self):
        for key in (
            "title",
            "risk_posture",
            "kri_cards",
            "priority_asset_segments",
            "workstreams",
            "decision_gates",
            "data_sources",
        ):
            self.assertIn(key, self.data)
        self.assertGreaterEqual(len(self.data["kri_cards"]), 6)
        self.assertGreaterEqual(len(self.data["priority_asset_segments"]), 5)
        self.assertGreaterEqual(len(self.data["decision_gates"]), 4)

    def test_dashboard_targets_ciso_risk_questions(self):
        content = self.html_path.read_text(encoding="utf-8")
        for expected in (
            "Executive risk posture",
            "Key risk indicators",
            "Priority asset segments",
            "Remediation workstreams",
            "CISO decision gates",
            "Required data sources",
        ):
            self.assertIn(expected, content)
        self.assertIn("Dirty Frag", content)
        self.assertIn("post-compromise", content)

    def test_renderer_produces_dashboard_html(self):
        rendered = render_ciso_dashboard.render_dashboard(self.data)
        self.assertIn("<!doctype html>", rendered)
        self.assertIn("Patch and reboot compliance", rendered)
        self.assertIn("This dashboard is defensive", rendered)
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "dashboard.html"
            output.write_text(rendered, encoding="utf-8")
            self.assertTrue(output.read_text(encoding="utf-8").startswith("<!doctype html>"))

    def test_static_dashboard_matches_renderer_output(self):
        rendered = render_ciso_dashboard.render_dashboard(self.data).strip()
        static = self.html_path.read_text(encoding="utf-8").strip()
        self.assertEqual(rendered, static)

    def test_renderer_produces_dashboard_svg_visualization(self):
        rendered = render_ciso_dashboard.render_svg(self.data)
        self.assertIn("<svg", rendered)
        self.assertIn('role="img"', rendered)
        self.assertIn("Executive Dirty Frag CISO dashboard", rendered)
        self.assertIn("Key risk indicators", rendered)
        self.assertIn("CISO decision gates", rendered)
        self.assertIn("Defensive use only", rendered)

    def test_static_svg_matches_renderer_output(self):
        rendered = render_ciso_dashboard.render_svg(self.data).strip()
        static = self.svg_path.read_text(encoding="utf-8").strip()
        self.assertEqual(rendered, static)

    def test_dashboard_is_non_exploitative(self):
        combined = (
            self.html_path.read_text(encoding="utf-8").lower()
            + self.svg_path.read_text(encoding="utf-8").lower()
            + self.data_path.read_text(encoding="utf-8").lower()
        )
        for forbidden in ("payload guidance", "trigger kernel memory corruption", "overwrite /etc/passwd", "spawn a root shell"):
            self.assertNotIn(forbidden, combined)
        self.assertIn("does not include exploit steps", combined)


if __name__ == "__main__":
    unittest.main()
