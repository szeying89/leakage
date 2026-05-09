from pathlib import Path
import json
import unittest


class CisoRiskAssessmentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.content = Path("docs/ciso-risk-assessment-dirtyfrag.md").read_text(encoding="utf-8")

    def test_required_ciso_sections_exist(self):
        for heading in (
            "## Executive decision brief",
            "## CISO risk rating",
            "## Business impact analysis",
            "## Scope and asset prioritization",
            "## Risk scenarios",
            "## Control objectives",
            "## 30/60/90-day action plan",
            "## Board and risk committee reporting language",
            "## Key risk indicators",
            "## Decision matrix",
            "## Residual risk statement",
            "## Embedded CISO dashboard visualization",
        ):
            self.assertIn(heading, self.content)

    def test_assessment_is_defensive_and_non_exploitative(self):
        self.assertIn("post-compromise", self.content)
        self.assertIn("local privilege-escalation", self.content)
        self.assertIn("does not automatically expose", self.content)
        forbidden_phrases = ("trigger kernel memory corruption", "spawn a root shell payload", "overwrite /etc/passwd")
        for phrase in forbidden_phrases:
            self.assertNotIn(phrase, self.content.lower())

    def test_assessment_embeds_ciso_dashboard_visualization(self):
        dashboard = json.loads(Path("dashboards/dirtyfrag_ciso_dashboard.json").read_text(encoding="utf-8"))
        for expected in (
            "### Executive risk posture tiles",
            "### KRI dashboard cards",
            "### Priority asset segment visualization",
            "### Remediation workstream tracker",
            "### CISO decision gate visualization",
            "### Dashboard data feeds",
            "dashboards/dirtyfrag_ciso_dashboard.html",
        ):
            self.assertIn(expected, self.content)
        for card in dashboard["kri_cards"]:
            self.assertIn(card["name"], self.content)
            self.assertIn(card["owner"], self.content)
        for gate in dashboard["decision_gates"]:
            self.assertIn(gate["condition"], self.content)


    def test_assessment_links_to_repository_artifacts(self):
        for artifact in (
            "dirtyfrag_poc.py",
            "docs/attack-path-dirtyfrag.md",
            "docs/intel-assessment-dirtyfrag.md",
            "detections/kql/",
            "detections/sigma/",
            "detections/osquery/",
        ):
            self.assertIn(artifact, self.content)


if __name__ == "__main__":
    unittest.main()
