from pathlib import Path
import json
import unittest

from scripts import render_attack_graph


class AttackGraphTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.graph = json.loads(Path("attack_graph/dirtyfrag_attack_graph.json").read_text(encoding="utf-8"))

    def test_graph_nodes_and_edges_are_consistent(self):
        node_ids = {node["id"] for node in self.graph["nodes"]}
        self.assertGreaterEqual(len(node_ids), 8)
        self.assertEqual(len(node_ids), len(self.graph["nodes"]))
        for edge in self.graph["edges"]:
            self.assertIn(edge["source"], node_ids)
            self.assertIn(edge["target"], node_ids)

    def test_graphql_schema_supports_attack_graph_query(self):
        schema = Path("attack_graph/schema.graphql").read_text(encoding="utf-8")
        query = Path("attack_graph/query.graphql").read_text(encoding="utf-8")
        for expected in ("type AttackGraph", "type AttackNode", "type AttackEdge", "dirtyFragAttackGraph"):
            self.assertIn(expected, schema)
        self.assertIn("query DirtyFragAttackGraph", query)
        self.assertIn("dirtyFragAttackGraph", query)

    def test_render_mermaid_contains_expected_path(self):
        rendered = render_attack_graph.render_mermaid(self.graph)
        self.assertIn("flowchart LR", rendered)
        self.assertIn("Initial low-privileged foothold", rendered)
        self.assertIn("Dirty Frag local privilege escalation attempt", rendered)
        self.assertIn("Patch and module controls", rendered)

    def test_static_mermaid_matches_renderer_output(self):
        rendered = render_attack_graph.render_mermaid(self.graph).strip()
        static = Path("attack_graph/dirtyfrag_attack_graph.mmd").read_text(encoding="utf-8").strip()
        self.assertEqual(rendered, static)


if __name__ == "__main__":
    unittest.main()
