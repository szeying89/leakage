from pathlib import Path
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
        ):
            self.assertIn(heading, self.content)

    def test_assessment_is_defensive_and_non_exploitative(self):
        self.assertIn("post-compromise", self.content)
        self.assertIn("local privilege-escalation", self.content)
        self.assertIn("does not automatically expose", self.content)
        forbidden_phrases = ("trigger kernel memory corruption", "spawn a root shell payload", "overwrite /etc/passwd")
        for phrase in forbidden_phrases:
            self.assertNotIn(phrase, self.content.lower())

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
