#!/usr/bin/env python3
"""Render the Dirty Frag CISO dashboard JSON to self-contained HTML or SVG."""

from __future__ import annotations

import argparse
import html
import json
from pathlib import Path
from typing import Any

STATUS_CLASS = {
    "on-track": "good",
    "in-progress": "warn",
    "needs-data": "warn",
    "not-started": "warn",
    "blocked": "bad",
    "overdue": "bad",
}

STATUS_COLOR = {
    "on-track": "#15803d",
    "in-progress": "#d97706",
    "needs-data": "#d97706",
    "not-started": "#d97706",
    "blocked": "#dc2626",
    "overdue": "#dc2626",
}


def escape(value: object) -> str:
    """HTML/XML-escape a value for safe static rendering."""

    return html.escape(str(value), quote=True)


def load_dashboard(path: Path) -> dict[str, Any]:
    """Load dashboard source data."""

    return json.loads(path.read_text(encoding="utf-8"))


def render_metric_cards(cards: list[dict[str, str]]) -> str:
    rows = []
    for card in cards:
        status = STATUS_CLASS.get(card.get("status", "needs-data"), "warn")
        rows.append(
            f'''<section class="card {status}">
  <h3>{escape(card["name"])}</h3>
  <p class="value">{escape(card["value"])}</p>
  <p><strong>Target:</strong> {escape(card["target"])}</p>
  <p><strong>Owner:</strong> {escape(card["owner"])}</p>
</section>'''
        )
    return "\n".join(rows)


def render_table(items: list[dict[str, str]], columns: list[tuple[str, str]]) -> str:
    header = "".join(f"<th>{escape(label)}</th>" for _, label in columns)
    rows = []
    for item in items:
        cells = "".join(f"<td>{escape(item.get(key, ''))}</td>" for key, _ in columns)
        rows.append(f"<tr>{cells}</tr>")
    return f"<table><thead><tr>{header}</tr></thead><tbody>{''.join(rows)}</tbody></table>"


def render_dashboard(data: dict[str, Any]) -> str:
    """Render dashboard data to a self-contained HTML document."""

    posture = data["risk_posture"]
    asset_table = render_table(
        data["priority_asset_segments"],
        [
            ("segment", "Asset segment"),
            ("business_risk", "Business risk"),
            ("priority", "Priority"),
            ("required_action", "Required action"),
        ],
    )
    workstream_table = render_table(
        data["workstreams"],
        [
            ("name", "Workstream"),
            ("phase", "Phase"),
            ("status", "Status"),
            ("success_measure", "Success measure"),
        ],
    )
    decision_table = render_table(
        data["decision_gates"],
        [("condition", "Condition"), ("decision", "CISO decision")],
    )
    sources = "".join(f"<li>{escape(source)}</li>" for source in data["data_sources"])

    return f'''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{escape(data["title"])}</title>
  <style>
    :root {{ --bg: #0f172a; --panel: #111827; --muted: #cbd5e1; --text: #f8fafc; --good: #166534; --warn: #92400e; --bad: #991b1b; --line: #334155; }}
    body {{ margin: 0; background: var(--bg); color: var(--text); font-family: Arial, sans-serif; line-height: 1.45; }}
    header, main {{ max-width: 1180px; margin: 0 auto; padding: 24px; }}
    header {{ border-bottom: 1px solid var(--line); }}
    h1, h2, h3 {{ margin-top: 0; }}
    .subtitle {{ color: var(--muted); max-width: 920px; }}
    .posture, .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; }}
    .tile, .card {{ background: var(--panel); border: 1px solid var(--line); border-radius: 12px; padding: 16px; }}
    .tile strong, .value {{ display: block; font-size: 1.8rem; margin-top: 6px; }}
    .good {{ border-top: 5px solid var(--good); }} .warn {{ border-top: 5px solid var(--warn); }} .bad {{ border-top: 5px solid var(--bad); }}
    table {{ border-collapse: collapse; width: 100%; background: var(--panel); margin-bottom: 28px; }}
    th, td {{ border: 1px solid var(--line); padding: 10px; text-align: left; vertical-align: top; }}
    th {{ background: #1e293b; }}
    section {{ margin: 28px 0; }}
    .notice {{ border-left: 5px solid #38bdf8; background: #0b1220; padding: 12px 16px; color: var(--muted); }}
  </style>
</head>
<body>
  <header>
    <h1>{escape(data["title"])}</h1>
    <p class="subtitle">As of {escape(data["as_of"])}. {escape(posture["executive_summary"])}</p>
  </header>
  <main>
    <section>
      <h2>Executive risk posture</h2>
      <div class="posture">
        <div class="tile bad"><span>Overall risk</span><strong>{escape(posture["overall_risk"])}</strong></div>
        <div class="tile warn"><span>Likelihood</span><strong>{escape(posture["likelihood"])}</strong></div>
        <div class="tile bad"><span>Impact</span><strong>{escape(posture["impact"])}</strong></div>
        <div class="tile bad"><span>Urgency</span><strong>{escape(posture["urgency"])}</strong></div>
        <div class="tile warn"><span>Confidence</span><strong>{escape(posture["confidence"])}</strong></div>
      </div>
    </section>
    <section>
      <h2>Key risk indicators</h2>
      <div class="cards">{render_metric_cards(data["kri_cards"])}</div>
    </section>
    <section>
      <h2>Priority asset segments</h2>
      {asset_table}
    </section>
    <section>
      <h2>Remediation workstreams</h2>
      {workstream_table}
    </section>
    <section>
      <h2>CISO decision gates</h2>
      {decision_table}
    </section>
    <section>
      <h2>Required data sources</h2>
      <ul>{sources}</ul>
    </section>
    <p class="notice">This dashboard is defensive and executive-facing. It tracks exposure, remediation, detection coverage, and exception governance; it does not include exploit steps or offensive guidance.</p>
  </main>
</body>
</html>
'''


def _svg_text(x: int, y: int, text: str, size: int = 18, weight: str = "400", fill: str = "#e2e8f0") -> str:
    return f'<text x="{x}" y="{y}" font-size="{size}" font-weight="{weight}" fill="{fill}">{escape(text)}</text>'


def _svg_panel(x: int, y: int, width: int, height: int, title: str, accent: str = "#38bdf8") -> str:
    return f'''<rect x="{x}" y="{y}" width="{width}" height="{height}" rx="18" fill="#111827" stroke="#334155"/>
<rect x="{x}" y="{y}" width="{width}" height="8" rx="4" fill="{accent}"/>
{_svg_text(x + 18, y + 36, title, 18, "700", "#f8fafc")}'''


def render_svg(data: dict[str, Any]) -> str:
    """Render dashboard data as a presentation-friendly SVG visualization."""

    posture = data["risk_posture"]
    cards = data["kri_cards"]
    assets = data["priority_asset_segments"]
    workstreams = data["workstreams"]
    gates = data["decision_gates"]

    posture_tiles = []
    for idx, (label, key, color) in enumerate(
        [
            ("Overall risk", "overall_risk", "#dc2626"),
            ("Likelihood", "likelihood", "#d97706"),
            ("Impact", "impact", "#dc2626"),
            ("Urgency", "urgency", "#dc2626"),
            ("Confidence", "confidence", "#d97706"),
        ]
    ):
        x = 50 + idx * 226
        posture_tiles.append(
            f'''<g aria-label="{escape(label)}">
  <rect x="{x}" y="124" width="202" height="92" rx="14" fill="#0b1220" stroke="#334155"/>
  <rect x="{x}" y="124" width="202" height="7" rx="4" fill="{color}"/>
  {_svg_text(x + 16, 158, label, 16, "700", "#cbd5e1")}
  {_svg_text(x + 16, 197, posture[key], 30, "800", "#f8fafc")}
</g>'''
        )

    kri_blocks = []
    for idx, card in enumerate(cards):
        col = idx % 3
        row = idx // 3
        x = 50 + col * 383
        y = 286 + row * 120
        color = STATUS_COLOR.get(card.get("status", "needs-data"), "#d97706")
        kri_blocks.append(
            f'''<g aria-label="KRI {escape(card['name'])}">
  <rect x="{x}" y="{y}" width="348" height="96" rx="12" fill="#0b1220" stroke="#334155"/>
  <circle cx="{x + 24}" cy="{y + 28}" r="8" fill="{color}"/>
  {_svg_text(x + 44, y + 32, card["name"], 17, "700", "#f8fafc")}
  {_svg_text(x + 18, y + 62, f"Value: {card['value']} | Status: {card['status']}", 14, "500", "#cbd5e1")}
  {_svg_text(x + 18, y + 84, f"Owner: {card['owner']}", 13, "400", "#94a3b8")}
</g>'''
        )

    asset_rows = []
    for idx, asset in enumerate(assets[:5]):
        y = 596 + idx * 24
        fill = "#7f1d1d" if asset["priority"] == "Critical" else "#78350f"
        asset_rows.append(
            f'''<g>
  <rect x="62" y="{y}" width="22" height="22" rx="4" fill="{fill}"/>
  {_svg_text(96, y + 17, asset["segment"], 15, "700", "#f8fafc")}
  {_svg_text(352, y + 17, asset["priority"], 14, "700", "#fde68a")}
</g>'''
        )

    workstream_rows = []
    for idx, stream in enumerate(workstreams[:5]):
        y = 596 + idx * 24
        color = STATUS_COLOR.get(stream.get("status", "not-started"), "#d97706")
        workstream_rows.append(
            f'''<g>
  <circle cx="493" cy="{y + 11}" r="8" fill="{color}"/>
  {_svg_text(513, y + 17, stream["name"], 15, "700", "#f8fafc")}
  {_svg_text(742, y + 17, stream["phase"], 13, "500", "#cbd5e1")}
</g>'''
        )

    gate_rows = []
    for idx, gate in enumerate(gates[:4]):
        y = 596 + idx * 34
        gate_rows.append(
            f'''<g>
  <rect x="930" y="{y - 3}" width="24" height="24" rx="12" fill="#1e40af"/>
  {_svg_text(937, y + 16, str(idx + 1), 14, "800", "#eff6ff")}
  {_svg_text(966, y + 10, gate["condition"][:42] + ("..." if len(gate["condition"]) > 42 else ""), 13, "700", "#f8fafc")}
  {_svg_text(966, y + 29, gate["decision"][:39] + ("..." if len(gate["decision"]) > 39 else ""), 12, "400", "#cbd5e1")}
</g>'''
        )

    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="1280" height="720" viewBox="0 0 1280 720" role="img" aria-labelledby="title desc">
  <title id="title">{escape(data["title"])} visualization</title>
  <desc id="desc">Executive Dirty Frag CISO dashboard showing risk posture, KRIs, priority assets, remediation workstreams, and decision gates for defensive risk governance.</desc>
  <rect width="1280" height="720" fill="#0f172a"/>
  {_svg_text(50, 56, data["title"], 32, "800", "#f8fafc")}
  {_svg_text(50, 86, f"As of {data['as_of']} | Defensive executive visualization", 16, "500", "#cbd5e1")}
  {''.join(posture_tiles)}
  {_svg_panel(50, 248, 1130, 282, "Key risk indicators", "#38bdf8")}
  {''.join(kri_blocks)}
  {_svg_panel(50, 552, 385, 138, "Priority assets", "#dc2626")}
  {''.join(asset_rows)}
  {_svg_panel(465, 552, 415, 138, "Remediation workstreams", "#d97706")}
  {''.join(workstream_rows)}
  {_svg_panel(910, 552, 270, 138, "CISO decision gates", "#2563eb")}
  {''.join(gate_rows)}
  <rect x="50" y="698" width="1130" height="1" fill="#334155"/>
  {_svg_text(50, 714, "Defensive use only: tracks exposure, remediation, telemetry, and exceptions; excludes exploit steps and offensive guidance.", 12, "500", "#94a3b8")}
</svg>
'''


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Render the Dirty Frag CISO dashboard.")
    parser.add_argument("--input", type=Path, default=Path("dashboards/dirtyfrag_ciso_dashboard.json"))
    parser.add_argument("--output", type=Path, default=Path("dashboards/dirtyfrag_ciso_dashboard.html"))
    parser.add_argument("--format", choices=("html", "svg"), default="html")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    data = load_dashboard(args.input)
    rendered = render_svg(data) if args.format == "svg" else render_dashboard(data)
    args.output.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
