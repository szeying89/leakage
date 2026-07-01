from pathlib import Path
import json
import unittest

from scripts import render_threat_model


class ThreatModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.model_path = Path("threat_model/dirtyfrag_threat_model.json")
        cls.svg_path = Path("threat_model/dirtyfrag_threat_model.svg")
        cls.mmd_path = Path("threat_model/dirtyfrag_threat_model.mmd")
        cls.doc_path = Path("docs/threat-model-dirtyfrag.md")
        cls.model = json.loads(cls.model_path.read_text(encoding="utf-8"))

    def test_model_has_required_threat_model_sections(self):
        for key in ("title", "scope", "trust_zones", "components", "flows", "threats", "controls", "safety_boundary"):
            self.assertIn(key, self.model)
        self.assertGreaterEqual(len(self.model["trust_zones"]), 5)
        self.assertGreaterEqual(len(self.model["components"]), 10)
        self.assertGreaterEqual(len(self.model["flows"]), 10)
        self.assertEqual({threat["stride"] for threat in self.model["threats"]}, {
            "Spoofing",
            "Tampering",
            "Repudiation",
            "Information Disclosure",
            "Denial of Service",
            "Elevation of Privilege",
        })

    def test_flows_reference_existing_components_and_controls(self):
        component_ids = {component["id"] for component in self.model["components"]}
        control_ids = {control["id"] for control in self.model["controls"]}
        threat_ids = {threat["id"] for threat in self.model["threats"]}
        for flow in self.model["flows"]:
            self.assertIn(flow["source"], component_ids)
            self.assertIn(flow["target"], component_ids)
            for threat_ref in flow["threats"]:
                self.assertIn(threat_ref, threat_ids)
            for control_ref in flow["control_refs"]:
                self.assertTrue(control_ref in control_ids or control_ref in {"shell_access_review", "file_integrity", "staging_hunts", "edr_root_transition", "secrets_rotation", "forensic_triage", "rebuild_decision"})

    def test_render_mermaid_contains_trust_zones_and_controls(self):
        rendered = render_threat_model.render_mermaid(self.model)
        self.assertIn("flowchart LR", rendered)
        self.assertIn("Compromised low-privileged Linux context", rendered)
        self.assertIn("Kernel and module attack surface", rendered)
        self.assertIn("Patch and module controls", rendered)
        self.assertIn("root impact if exploited", rendered)

    def test_static_mermaid_matches_renderer_output(self):
        rendered = render_threat_model.render_mermaid(self.model).strip()
        static = self.mmd_path.read_text(encoding="utf-8").strip()
        self.assertEqual(rendered, static)

    def test_render_svg_is_presentation_ready(self):
        rendered = render_threat_model.render_svg(self.model)
        self.assertIn('<svg xmlns="http://www.w3.org/2000/svg" width="1600" height="900"', rendered)
        self.assertIn("STRIDE risk lens", rendered)
        self.assertIn("Dirty Frag Defensive Threat Model", rendered)
        self.assertIn("Defensive visualization only", rendered)
        for component in self.model["components"]:
            self.assertIn(component["label"], rendered)

    def test_static_svg_matches_renderer_output(self):
        rendered = render_threat_model.render_svg(self.model).strip()
        static = self.svg_path.read_text(encoding="utf-8").strip()
        self.assertEqual(rendered, static)

    def test_document_links_visual_artifacts_and_is_non_exploitative(self):
        content = self.doc_path.read_text(encoding="utf-8")
        for expected in (
            "# Dirty Frag visual threat model",
            "![Dirty Frag visual threat model]",
            "threat_model/dirtyfrag_threat_model.svg",
            "threat_model/dirtyfrag_threat_model.mmd",
            "threat_model/dirtyfrag_threat_model.json",
            "python3 scripts/render_threat_model.py --format svg --output threat_model/dirtyfrag_threat_model.svg",
            "STRIDE assessment summary",
        ):
            self.assertIn(expected, content)
        for forbidden in ("payload guidance", "trigger kernel memory corruption", "spawn a root shell", "overwrite /etc/passwd"):
            self.assertNotIn(forbidden, content.lower())


if __name__ == "__main__":
    unittest.main()
