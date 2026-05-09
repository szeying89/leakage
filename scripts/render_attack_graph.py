#!/usr/bin/env python3
"""Render the Dirty Frag attack graph JSON to Mermaid, SVG, or Graphviz DOT."""

from __future__ import annotations

import argparse
import html
import json
import re
from pathlib import Path
from textwrap import wrap
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

SVG_STYLE_BY_CLASS = {
    "access": {"fill": "#d8ecff", "stroke": "#2b6cb0", "text": "#1a365d"},
    "risk": {"fill": "#ffe8cc", "stroke": "#c05621", "text": "#7b341e"},
    "impact": {"fill": "#fed7d7", "stroke": "#c53030", "text": "#742a2a"},
    "control": {"fill": "#d9f99d", "stroke": "#3f6212", "text": "#365314"},
}

SVG_POSITIONS = {
    "n1_external_foothold": (70, 210),
    "n2_interactive_shell": (300, 210),
    "n3_module_exposure": (550, 105),
    "n4_local_artifact_staging": (550, 315),
    "n5_dirtyfrag_lpe_attempt": (820, 210),
    "n6_root_context": (1080, 210),
    "n7_session_and_glpi_tampering": (1330, 105),
    "n8_credential_and_data_access": (1330, 315),
    "n9_patch_and_module_controls": (545, 545),
    "n10_hunting_and_response": (875, 545),
}

CARD_WIDTH = 190
CARD_HEIGHT = 92


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


def _node_class(kind: str) -> str:
    return NODE_CLASS_BY_KIND.get(kind, "risk")


def _svg_card(node: dict[str, Any], x: int, y: int) -> list[str]:
    node_class = _node_class(node["kind"])
    style = SVG_STYLE_BY_CLASS[node_class]
    label_lines = wrap(node["label"], width=22)
    evidence = node.get("evidence", [])
    subtitle = evidence[0] if evidence else node["kind"].replace("_", " ").title()
    subtitle_lines = wrap(subtitle, width=27)[:2]
    lines = [
        f'  <g id="{html.escape(node["id"])}" class="node {node_class}" aria-label="{html.escape(node["label"])}">',
        f'    <title>{html.escape(node["label"])}</title>',
        f'    <rect x="{x}" y="{y}" width="{CARD_WIDTH}" height="{CARD_HEIGHT}" rx="14" fill="{style["fill"]}" stroke="{style["stroke"]}" stroke-width="2"/>',
    ]
    title_y = y + 27
    for index, line in enumerate(label_lines[:2]):
        lines.append(
            f'    <text x="{x + CARD_WIDTH / 2:.0f}" y="{title_y + index * 18}" text-anchor="middle" font-size="15" font-weight="700" fill="{style["text"]}">{html.escape(line)}</text>'
        )
    subtitle_y = y + 64
    for index, line in enumerate(subtitle_lines):
        lines.append(
            f'    <text x="{x + CARD_WIDTH / 2:.0f}" y="{subtitle_y + index * 14}" text-anchor="middle" font-size="11" fill="{style["text"]}">{html.escape(line)}</text>'
        )
    lines.append("  </g>")
    return lines


def _svg_edge(edge: dict[str, Any], positions: dict[str, tuple[int, int]]) -> str:
    sx, sy = positions[edge["source"]]
    tx, ty = positions[edge["target"]]
    source_center = (sx + CARD_WIDTH / 2, sy + CARD_HEIGHT / 2)
    target_center = (tx + CARD_WIDTH / 2, ty + CARD_HEIGHT / 2)
    marker = "url(#arrow-dashed)" if edge["kind"] in {"DETECTED_BY", "MITIGATED_BY"} else "url(#arrow)"
    dash = ' stroke-dasharray="8 8"' if edge["kind"] in {"DETECTED_BY", "MITIGATED_BY"} else ""
    label_x = (source_center[0] + target_center[0]) / 2
    label_y = (source_center[1] + target_center[1]) / 2 - 8
    return (
        f'  <path d="M {source_center[0]:.0f} {source_center[1]:.0f} L {target_center[0]:.0f} {target_center[1]:.0f}" '
        f'fill="none" stroke="#334155" stroke-width="2"{dash} marker-end="{marker}"/>'
        f'\n  <text x="{label_x:.0f}" y="{label_y:.0f}" text-anchor="middle" font-size="10" fill="#334155">{html.escape(edge["kind"].replace("_", " ").title())}</text>'
    )


def render_svg(graph: dict[str, Any]) -> str:
    """Render a 16:9 presentation-ready SVG attack graph."""

    node_by_id = {node["id"]: node for node in graph["nodes"]}
    missing_positions = sorted(set(node_by_id) - set(SVG_POSITIONS))
    if missing_positions:
        raise ValueError(f"Missing SVG positions for nodes: {', '.join(missing_positions)}")

    lines = [
        '<svg xmlns="http://www.w3.org/2000/svg" width="1600" height="900" viewBox="0 0 1600 900" role="img" aria-labelledby="title desc">',
        f'  <title id="title">{html.escape(graph["name"])} presentation attack graph</title>',
        f'  <desc id="desc">{html.escape(graph["summary"])} The diagram is defensive and omits exploit mechanics.</desc>',
        '  <rect width="1600" height="900" fill="#f8fafc"/>',
        '  <text x="70" y="70" font-size="34" font-weight="800" fill="#0f172a">Dirty Frag attack graph</text>',
        '  <text x="70" y="102" font-size="16" fill="#475569">Presentation view: post-compromise escalation path, controls, and detection coverage</text>',
        '  <defs>',
        '    <marker id="arrow" markerWidth="12" markerHeight="12" refX="10" refY="6" orient="auto"><path d="M2,2 L10,6 L2,10 z" fill="#334155"/></marker>',
        '    <marker id="arrow-dashed" markerWidth="12" markerHeight="12" refX="10" refY="6" orient="auto"><path d="M2,2 L10,6 L2,10 z" fill="#64748b"/></marker>',
        '  </defs>',
        '  <text x="70" y="158" font-size="13" font-weight="700" fill="#334155">Legend</text>',
    ]
    legend = [("access", "Access / execution"), ("risk", "Exposure / escalation"), ("impact", "Post-escalation impact"), ("control", "Controls / detection")]
    legend_x = 130
    for node_class, label in legend:
        style = SVG_STYLE_BY_CLASS[node_class]
        lines.append(f'  <rect x="{legend_x}" y="140" width="18" height="18" rx="4" fill="{style["fill"]}" stroke="{style["stroke"]}"/>')
        lines.append(f'  <text x="{legend_x + 26}" y="154" font-size="13" fill="#334155">{html.escape(label)}</text>')
        legend_x += 230

    lines.append('  <g id="edges">')
    for edge in graph["edges"]:
        lines.append(_svg_edge(edge, SVG_POSITIONS))
    lines.append("  </g>")

    lines.append('  <g id="nodes" font-family="Inter, Segoe UI, Arial, sans-serif">')
    for node in graph["nodes"]:
        lines.extend(_svg_card(node, *SVG_POSITIONS[node["id"]]))
    lines.append("  </g>")

    lines.extend(
        [
            '  <rect x="70" y="805" width="1460" height="46" rx="12" fill="#e2e8f0"/>',
            '  <text x="90" y="834" font-size="14" fill="#334155">Defensive use only: use this slide to brief exposure prerequisites, business impact, patch/module controls, and detection coverage. Exploit internals are intentionally excluded.</text>',
            "</svg>",
        ]
    )
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
    parser.add_argument("--format", choices=("mermaid", "dot", "svg"), default="mermaid")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    graph = load_graph(args.input)
    if args.format == "mermaid":
        print(render_mermaid(graph), end="")
    elif args.format == "dot":
        print(render_dot(graph), end="")
    else:
        print(render_svg(graph), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
