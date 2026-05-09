#!/usr/bin/env python3
"""Render the Dirty Frag attack graph JSON to Mermaid or Graphviz DOT."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

NODE_CLASS_BY_KIND = {
    "INITIAL_ACCESS": "access",
    "EXECUTION": "access",
    "EXPOSURE": "risk",
    "PRIVILEGE_ESCALATION": "risk",
    "DEFENSE_EVASION": "impact",
    "CREDENTIAL_ACCESS": "impact",
    "IMPACT": "impact",
    "CONTROL": "control",
    "DETECTION": "control",
}


def safe_mermaid_id(node_id: str) -> str:
    """Return a Mermaid-safe identifier while preserving readable IDs."""

    return re.sub(r"[^A-Za-z0-9_]", "_", node_id)


def load_graph(path: Path) -> dict[str, Any]:
    """Load an attack graph JSON document."""

    return json.loads(path.read_text(encoding="utf-8"))


def render_mermaid(graph: dict[str, Any]) -> str:
    """Render the graph to Mermaid flowchart syntax."""

    node_by_id = {node["id"]: node for node in graph["nodes"]}
    lines = ["flowchart LR"]
    for node in graph["nodes"]:
        lines.append(f'  {safe_mermaid_id(node["id"])}["{node["label"]}"]')
    for edge in graph["edges"]:
        source = safe_mermaid_id(edge["source"])
        target = safe_mermaid_id(edge["target"])
        arrow = "-.->" if edge["kind"] in {"DETECTED_BY", "MITIGATED_BY"} else "-->"
        lines.append(f'  {source} {arrow}|{edge["label"]}| {target}')
    lines.extend(
        [
            "",
            "  classDef access fill:#d8ecff,stroke:#2b6cb0,color:#1a365d",
            "  classDef risk fill:#ffe8cc,stroke:#c05621,color:#7b341e",
            "  classDef impact fill:#fed7d7,stroke:#c53030,color:#742a2a",
            "  classDef control fill:#d9f99d,stroke:#3f6212,color:#365314",
        ]
    )
    classes: dict[str, list[str]] = {"access": [], "risk": [], "impact": [], "control": []}
    for node_id, node in node_by_id.items():
        classes[NODE_CLASS_BY_KIND.get(node["kind"], "risk")].append(safe_mermaid_id(node_id))
    for class_name, node_ids in classes.items():
        if node_ids:
            lines.append(f'  class {",".join(node_ids)} {class_name}')
    return "\n".join(lines) + "\n"


def render_dot(graph: dict[str, Any]) -> str:
    """Render the graph to Graphviz DOT syntax."""

    lines = ["digraph DirtyFragAttackGraph {", "  rankdir=LR;", "  node [shape=box, style=rounded];"]
    for node in graph["nodes"]:
        lines.append(f'  "{node["id"]}" [label="{node["label"]}"];')
    for edge in graph["edges"]:
        style = "dashed" if edge["kind"] in {"DETECTED_BY", "MITIGATED_BY"} else "solid"
        lines.append(f'  "{edge["source"]}" -> "{edge["target"]}" [label="{edge["label"]}", style={style}];')
    lines.append("}")
    return "\n".join(lines) + "\n"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Render the Dirty Frag attack graph.")
    parser.add_argument("--input", type=Path, default=Path("attack_graph/dirtyfrag_attack_graph.json"))
    parser.add_argument("--format", choices=("mermaid", "dot"), default="mermaid")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    graph = load_graph(args.input)
    if args.format == "mermaid":
        print(render_mermaid(graph), end="")
    else:
        print(render_dot(graph), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
