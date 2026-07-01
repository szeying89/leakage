#!/usr/bin/env python3
"""Render the Dirty Frag threat model to Mermaid or SVG."""

from __future__ import annotations

import argparse
import html
import json
import re
from pathlib import Path
from textwrap import wrap
from typing import Any

ZONE_POSITIONS = {
    "zone_external": (40, 120, 210, 250),
    "zone_user": (285, 120, 250, 430),
    "zone_kernel": (570, 120, 275, 430),
    "zone_privileged": (880, 120, 260, 430),
    "zone_defender": (40, 590, 1100, 230),
}

COMPONENT_POSITIONS = {
    "external_access": (65, 235),
    "low_priv_execution": (315, 215),
    "local_staging": (315, 380),
    "module_surface": (610, 215),
    "privilege_boundary": (610, 380),
    "root_context": (915, 215),
    "business_assets": (915, 380),
    "preventive_controls": (85, 685),
    "detective_controls": (465, 685),
    "response_controls": (845, 685),
}

KIND_STYLE = {
    "threat_source": {"fill": "#fee2e2", "stroke": "#dc2626", "text": "#7f1d1d"},
    "process": {"fill": "#dbeafe", "stroke": "#2563eb", "text": "#1e3a8a"},
    "data_store": {"fill": "#ede9fe", "stroke": "#7c3aed", "text": "#4c1d95"},
    "attack_surface": {"fill": "#ffedd5", "stroke": "#ea580c", "text": "#7c2d12"},
    "trust_boundary": {"fill": "#fef3c7", "stroke": "#d97706", "text": "#78350f"},
    "privileged_identity": {"fill": "#fecaca", "stroke": "#b91c1c", "text": "#7f1d1d"},
    "business_asset": {"fill": "#fce7f3", "stroke": "#db2777", "text": "#831843"},
    "control": {"fill": "#dcfce7", "stroke": "#16a34a", "text": "#14532d"},
}

RISK_COLOR = {"Critical": "#991b1b", "High": "#dc2626", "Medium": "#d97706", "Low": "#16a34a"}
CARD_WIDTH = 180
CARD_HEIGHT = 94


def safe_id(value: str) -> str:
    """Return a Mermaid-safe identifier."""

    return re.sub(r"[^A-Za-z0-9_]", "_", value)


def load_model(path: Path) -> dict[str, Any]:
    """Load a threat model JSON document."""

    return json.loads(path.read_text(encoding="utf-8"))


def render_mermaid(model: dict[str, Any]) -> str:
    """Render the threat model as a Mermaid flowchart with trust zones."""

    components_by_zone: dict[str, list[dict[str, Any]]] = {zone["id"]: [] for zone in model["trust_zones"]}
    for component in model["components"]:
        components_by_zone[component["zone"]].append(component)

    lines = ["flowchart LR"]
    for zone in model["trust_zones"]:
        lines.append(f'  subgraph {safe_id(zone["id"])}["{zone["label"]}"]')
        for component in components_by_zone[zone["id"]]:
            lines.append(f'    {safe_id(component["id"])}["{component["label"]}"]')
        lines.append("  end")
    for flow in model["flows"]:
        arrow = "-.->" if flow["source"].endswith("controls") else "-->"
        lines.append(f'  {safe_id(flow["source"])} {arrow}|{flow["label"]}| {safe_id(flow["target"])}')
    lines.extend(
        [
            "",
            "  classDef threat fill:#fee2e2,stroke:#dc2626,color:#7f1d1d",
            "  classDef user fill:#dbeafe,stroke:#2563eb,color:#1e3a8a",
            "  classDef kernel fill:#ffedd5,stroke:#ea580c,color:#7c2d12",
            "  classDef asset fill:#fce7f3,stroke:#db2777,color:#831843",
            "  classDef control fill:#dcfce7,stroke:#16a34a,color:#14532d",
        ]
    )
    class_map = {"zone_external": "threat", "zone_user": "user", "zone_kernel": "kernel", "zone_privileged": "asset", "zone_defender": "control"}
    for zone_id, class_name in class_map.items():
        ids = [safe_id(component["id"]) for component in components_by_zone.get(zone_id, [])]
        if ids:
            lines.append(f'  class {",".join(ids)} {class_name}')
    return "\n".join(lines) + "\n"


def _text(x: int, y: int, text: str, size: int = 16, weight: str = "400", fill: str = "#172033", anchor: str = "start") -> str:
    return f'<text x="{x}" y="{y}" font-size="{size}" font-weight="{weight}" fill="{fill}" text-anchor="{anchor}">{html.escape(text)}</text>'


def _zone(zone: dict[str, Any]) -> str:
    x, y, width, height = ZONE_POSITIONS[zone["id"]]
    title_lines = wrap(zone["label"], width=32)
    rendered = [
        f'<rect x="{x}" y="{y}" width="{width}" height="{height}" rx="18" fill="#f8fafc" stroke="#94a3b8" stroke-width="2"/>',
        f'<rect x="{x}" y="{y}" width="{width}" height="42" rx="18" fill="#e2e8f0"/>',
    ]
    for index, line in enumerate(title_lines[:2]):
        rendered.append(_text(x + 16, y + 26 + index * 15, line, 14, "800", "#0f172a"))
    return "\n".join(rendered)


def _component(component: dict[str, Any]) -> str:
    x, y = COMPONENT_POSITIONS[component["id"]]
    style = KIND_STYLE[component["kind"]]
    title_lines = wrap(component["label"], width=21)
    summary_lines = wrap(component["summary"], width=29)[:2]
    lines = [
        f'<g id="{html.escape(component["id"])}" aria-label="{html.escape(component["label"])}">',
        f'  <title>{html.escape(component["summary"])}</title>',
        f'  <rect x="{x}" y="{y}" width="{CARD_WIDTH}" height="{CARD_HEIGHT}" rx="14" fill="{style["fill"]}" stroke="{style["stroke"]}" stroke-width="2"/>',
    ]
    for index, line in enumerate(title_lines[:2]):
        lines.append(_text(x + CARD_WIDTH // 2, y + 26 + index * 17, line, 14, "800", style["text"], "middle"))
    for index, line in enumerate(summary_lines):
        lines.append(_text(x + CARD_WIDTH // 2, y + 64 + index * 13, line, 10, "500", style["text"], "middle"))
    lines.append("</g>")
    return "\n".join(lines)


def _edge(flow: dict[str, Any]) -> str:
    sx, sy = COMPONENT_POSITIONS[flow["source"]]
    tx, ty = COMPONENT_POSITIONS[flow["target"]]
    source_center = (sx + CARD_WIDTH / 2, sy + CARD_HEIGHT / 2)
    target_center = (tx + CARD_WIDTH / 2, ty + CARD_HEIGHT / 2)
    dashed = flow["source"].endswith("controls")
    marker = "url(#arrow-control)" if dashed else "url(#arrow-risk)"
    dash = ' stroke-dasharray="7 7"' if dashed else ""
    label_x = (source_center[0] + target_center[0]) / 2
    label_y = (source_center[1] + target_center[1]) / 2 - 8
    color = "#15803d" if dashed else "#475569"
    return (
        f'<path d="M {source_center[0]:.0f} {source_center[1]:.0f} L {target_center[0]:.0f} {target_center[1]:.0f}" fill="none" stroke="{color}" stroke-width="2"{dash} marker-end="{marker}"/>'
        f'\n{_text(int(label_x), int(label_y), flow["label"], 10, "700", color, "middle")} '
    )


def _threat_panel(model: dict[str, Any]) -> str:
    rows = []
    for index, threat in enumerate(model["threats"]):
        x = 1190
        y = 150 + index * 86
        color = RISK_COLOR.get(threat["risk"], "#64748b")
        rows.append(
            f'''<g aria-label="{html.escape(threat['stride'])} threat">
  <rect x="{x}" y="{y}" width="330" height="68" rx="12" fill="#0f172a" stroke="#334155"/>
  <circle cx="{x + 22}" cy="{y + 24}" r="8" fill="{color}"/>
  {_text(x + 42, y + 27, threat["stride"], 15, "800", "#f8fafc")}
  {_text(x + 42, y + 50, f"Risk: {threat['risk']}", 13, "700", "#cbd5e1")}
</g>'''
        )
    return "\n".join(rows)


def render_svg(model: dict[str, Any]) -> str:
    """Render a slide-ready SVG threat model visualization."""

    expected_components = {component["id"] for component in model["components"]}
    missing_positions = sorted(expected_components - set(COMPONENT_POSITIONS))
    if missing_positions:
        raise ValueError(f"Missing SVG positions for components: {', '.join(missing_positions)}")

    zones = "\n".join(_zone(zone) for zone in model["trust_zones"])
    edges = "\n".join(_edge(flow) for flow in model["flows"])
    components = "\n".join(_component(component) for component in model["components"])
    threats = _threat_panel(model)

    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="1600" height="900" viewBox="0 0 1600 900" role="img" aria-labelledby="title desc">
  <title id="title">{html.escape(model["title"])} visualization</title>
  <desc id="desc">Threat model visualization for Dirty Frag post-compromise Linux privilege-escalation risk using trust zones, data flows, STRIDE threats, and defensive controls.</desc>
  <defs>
    <marker id="arrow-risk" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="#475569"/></marker>
    <marker id="arrow-control" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="#15803d"/></marker>
  </defs>
  <rect width="1600" height="900" fill="#e5e7eb"/>
  {_text(40, 54, model["title"], 32, "900", "#0f172a")}
  {_text(40, 84, f"As of {model['as_of']} | Visual threat model for defender planning", 16, "600", "#334155")}
  {_text(1190, 118, "STRIDE risk lens", 24, "900", "#0f172a")}
  {zones}
  {edges}
  {components}
  <rect x="1180" y="130" width="360" height="560" rx="18" fill="#111827" stroke="#334155"/>
  {threats}
  <rect x="40" y="840" width="1500" height="36" rx="12" fill="#0f172a"/>
  {_text(60, 864, model["safety_boundary"], 14, "700", "#e2e8f0")}
</svg>
'''


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Render the Dirty Frag threat model.")
    parser.add_argument("--input", type=Path, default=Path("threat_model/dirtyfrag_threat_model.json"))
    parser.add_argument("--output", type=Path, default=Path("threat_model/dirtyfrag_threat_model.svg"))
    parser.add_argument("--format", choices=("svg", "mermaid"), default="svg")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    model = load_model(args.input)
    rendered = render_mermaid(model) if args.format == "mermaid" else render_svg(model)
    args.output.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
